"""Focused regressions for the upstream routing and critic contracts."""

from __future__ import annotations

import json
import re

import pytest
from pydantic import ValidationError

from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
from asago_scenario_generator.models.obligation_consideration import (
    ObligationSemanticAssessment,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    ObligationRoute,
    StructuralRoutingResponse,
)
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    build_structural_routing_prompts,
)
from asago_scenario_generator.stpa.obligation_aware.provider import (
    ObligationAwareLLMAdapter,
    _routing_provider_payload_type,
    _slot_provider_payload_type,
)
from asago_scenario_generator.stpa.obligation_aware.routing import (
    _ROUTING_RETRY_ERROR_MAX_CHARS,
    _routing_validation_feedback,
    build_neutral_briefs,
    route_obligations,
)
from asago_scenario_generator.stpa.system_model import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.critic import (
    CriticFindings,
    RevisionDelta,
    count_findings,
    has_unjustified_gaps,
    run_completeness_critic,
    run_revision,
)
from tests.helpers.stpa_builders import make_capability_profile
from tests.helpers.obligation_factory import make_plan
from tests.helpers.projection_factory import get_test_raw_pattern
from tests.stpa.sp1_helpers import MockLLMClient
from tests.test_obligation_aware_stpa import (
    _control_structure,
    _controls,
    _loss_analysis,
)
from tests.stpa.test_sp1_critic import (
    _make_control_structure,
)


def _routing_semantics() -> dict[str, str]:
    return {
        "mechanism_assessment": "insufficient_evidence",
        "risk_alignment": "insufficient_evidence",
        "mechanism_rationale": "the required path is not supplied",
        "risk_alignment_rationale": "alignment is not established",
    }


def _brief():
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    return build_neutral_briefs(make_plan(), (pattern,))[0]


def test_routing_schema_cannot_retype_an_obligation_digest():
    expected = "ob:v1:" + "1" * 64
    wire = _routing_provider_payload_type(1, obligation_ids=(expected,))
    route = {
        "obligation_id": "ob:v1:" + "2" * 64,
        "disposition": "unresolved",
        "semantic_assessment": _routing_semantics(),
        "rationale": "No structural route supplied.",
        "evidence": ["Supplied structure"],
    }
    with pytest.raises(ValidationError, match="obligation_id"):
        wire.model_validate({"routes": [route]})
    route["obligation_id"] = expected
    assert wire.model_validate({"routes": [route]}).routes[0].obligation_id == expected


def test_slot_schema_requires_one_exact_constraint_not_concatenated_ids():
    wire = _slot_provider_payload_type(1, 0, constraint_ids=("SC-2", "SC-4", "SC-5"))
    finding = {
        "deviation": "sanitization occurs after downstream processing",
        "hazardous_context": "unprocessed input reaches downstream components",
        "loss_consequence": "unauthorized action",
        "related_hazard_ids": ["H-2"],
        "related_constraint_ids": ['SC-2", "SC-4", "SC-5'],
    }
    payload = {
        "filled_slots": [
            {
                "slot_id": "RESP-1:CA-1-1:WRONG_TIMING",
                "is_na": False,
                "findings": [finding],
            }
        ]
    }
    with pytest.raises(ValidationError, match="related_constraint_ids"):
        wire.model_validate(payload)
    finding["related_constraint_ids"] = ["SC-2"]
    assert wire.model_validate(payload).filled_slots[0].findings[
        0
    ].related_constraint_ids == ("SC-2",)


def test_routing_wire_schema_requires_disposition_specific_fields() -> None:
    """Every provider route branch requires its own rationale and evidence."""
    payload_type = _routing_provider_payload_type(1)
    obligation_id = "ob:v1:" + "0" * 64
    base = {
        "obligation_id": obligation_id,
        "semantic_assessment": _routing_semantics(),
        "evidence": ["evidence is insufficient"],
    }

    with pytest.raises(ValidationError, match="rationale"):
        payload_type.model_validate(
            {"routes": [{**base, "disposition": "unresolved", "rationale": None}]}
        )

    unresolved = payload_type.model_validate(
        {
            "routes": [
                {
                    **base,
                    "disposition": "unresolved",
                    "rationale": "the required system path is not supplied",
                }
            ]
        }
    )
    assert unresolved.routes[0].disposition == "unresolved"

    with pytest.raises(ValidationError, match="slot_ids"):
        payload_type.model_validate(
            {
                "routes": [
                    {
                        **base,
                        "disposition": "targeted",
                        "rationale": "the supplied control path is relevant",
                        "hazard_ids": ["H-1"],
                        "constraint_ids": ["SC-1"],
                    }
                ]
            }
        )

    schema = payload_type.model_json_schema()
    route_items = schema["properties"]["routes"]["items"]
    assert "oneOf" in route_items
    assert "discriminator" in route_items


def test_structural_routing_prompt_examples_validate_as_wire_payloads() -> None:
    """Prompt examples are complete JSON objects accepted by the exact wire model."""
    brief = _brief()
    system_prompt, _ = build_structural_routing_prompts(
        briefs=(brief,),
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
        slots=(),
    )
    blocks = re.findall(r"```json\s*(\{.*?\})\s*```", system_prompt, re.DOTALL)
    assert blocks, "routing system prompt must contain complete JSON examples"
    payload_type = _routing_provider_payload_type(1)
    payloads = [payload_type.model_validate(json.loads(block)) for block in blocks]
    dispositions = {payload.routes[0].disposition for payload in payloads}
    assert {"targeted", "unresolved"} <= dispositions


def test_provider_null_rationale_gets_one_focused_correction(tmp_path) -> None:
    """A null route rationale is corrected once without changing request identity."""
    client = MockLLMClient()
    brief = _brief()
    client.set_response_queue(
        [
            {
                "routes": [
                    {
                        "obligation_id": brief.obligation_id,
                        "disposition": "unresolved",
                        "semantic_assessment": _routing_semantics(),
                        "rationale": None,
                        "evidence": ["evidence is insufficient"],
                    }
                ]
            },
            {
                "routes": [
                    {
                        "obligation_id": brief.obligation_id,
                        "disposition": "unresolved",
                        "semantic_assessment": _routing_semantics(),
                        "rationale": "the required system path is not supplied",
                        "evidence": ["evidence is insufficient"],
                    }
                ]
            },
        ]
    )
    controls = _controls().model_copy(update={"max_batch_size": 1})
    adapter = ObligationAwareLLMAdapter(
        client,
        run_dir=tmp_path,
        controls=controls,
    )

    result = route_obligations(
        adapter,
        briefs=(brief,),
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
        controls=controls,
        max_batch_size=1,
    )

    assert client.call_count == 2
    assert result.routes[0].obligation_id == brief.obligation_id
    assert result.routes[0].rationale
    correction = client.calls[1].user_prompt.lower()
    assert "route rationale" in correction.replace("_", " ")
    assert "non-empty" in correction
    assert brief.obligation_id in correction


def test_routing_identity_mismatch_retry_feedback_names_exact_handles() -> None:
    """A one-character handle mutation remains a validation failure, not a repair."""
    brief = _brief()
    changed = brief.obligation_id[:-1] + (
        "0" if brief.obligation_id[-1] != "0" else "1"
    )

    class MismatchingAdapter:
        def __init__(self) -> None:
            self.feedback: list[str | None] = []

        def route(self, request, *, correction_feedback=None):
            self.feedback.append(correction_feedback)
            route = ObligationRoute(
                obligation_id=changed,
                disposition="unresolved",
                semantic_assessment=ObligationSemanticAssessment(
                    mechanism_assessment="insufficient_evidence",
                    risk_alignment="insufficient_evidence",
                    mapping_strength="direct_curated_pair",
                    mechanism_rationale="the path is not supplied",
                    risk_alignment_rationale="alignment is not established",
                ),
                rationale="the required system path is not supplied",
                evidence=("evidence is insufficient",),
            )
            return StructuralRoutingResponse(
                adapter_kind="fake",
                request_digest=request.semantic_digest,
                routes=(route,),
            )

    adapter = MismatchingAdapter()
    result = route_obligations(
        adapter,
        briefs=(brief,),
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
        controls=_controls(),
        max_batch_size=1,
    )

    assert len(adapter.feedback) == 2
    assert result.routes[0].obligation_id == brief.obligation_id
    assert brief.obligation_id in (adapter.feedback[1] or "")
    assert changed in (adapter.feedback[1] or "")


def test_routing_feedback_covers_disposition_and_bounded_error_details() -> None:
    """Field repair remains specific while validation detail stays bounded."""
    disposition_feedback = _routing_validation_feedback(
        ValueError("route disposition is missing")
    )
    assert "missing_route_disposition" in disposition_feedback

    long_detail = "x" * (_ROUTING_RETRY_ERROR_MAX_CHARS + 100)
    bounded_feedback = _routing_validation_feedback(ValueError(long_detail))
    assert "x" * _ROUTING_RETRY_ERROR_MAX_CHARS + "..." in bounded_feedback


def _critic_gap_dict() -> dict[str, str]:
    return {
        "gap_type": "missing_responsibility",
        "description": "Input validation responsibility is missing.",
        "related_attack_path": "Evidence does not establish a validated input path.",
        "suggested_remedy": "Add a responsibility for input validation.",
    }


def test_critic_absent_unjustified_requires_an_explicit_gap(tmp_path) -> None:
    """The critic gets one correction when an unjustified result has no gap."""
    client = MockLLMClient()
    client.set_response_queue(
        [
            {
                "gaps": [],
                "checklist_results": {"Input validation": "absent_unjustified"},
                "taxonomy_probe_results": {},
            },
            {
                "gaps": [_critic_gap_dict()],
                "checklist_results": {"Input validation": "absent_unjustified"},
                "taxonomy_probe_results": {},
            },
        ]
    )

    findings = run_completeness_critic(
        llm_client=client,
        control_structure=_make_control_structure(),
        capability_profile=make_capability_profile(),
        use_case_text="Test use case",
        run_dir=tmp_path,
    )

    assert client.call_count == 2
    assert len(findings.gaps) == 1
    assert "explicit gap" in client.calls[1].user_prompt.lower()


def test_critic_gap_retry_requires_concept_and_evidence_text(tmp_path) -> None:
    """A blank explicit gap is corrected once at the critic boundary."""
    client = MockLLMClient()
    client.set_response_queue(
        [
            {
                "gaps": [{**_critic_gap_dict(), "description": ""}],
                "checklist_results": {},
                "taxonomy_probe_results": {},
            },
            {
                "gaps": [_critic_gap_dict()],
                "checklist_results": {},
                "taxonomy_probe_results": {},
            },
        ]
    )
    findings = run_completeness_critic(
        llm_client=client,
        control_structure=_make_control_structure(),
        capability_profile=make_capability_profile(),
        use_case_text="Test use case",
        run_dir=tmp_path,
    )
    assert client.call_count == 2
    assert findings.gaps[0].description


def test_critic_absent_unjustified_without_gap_does_not_trigger_revision() -> None:
    """Diagnostic probe statuses alone cannot authorize a revision call."""
    findings = CriticFindings(
        gaps=[],
        checklist_results={"Input validation": "absent_unjustified"},
        taxonomy_probe_results={},
    )

    assert has_unjustified_gaps(findings) is False
    assert count_findings(findings) == 0

    actionable = findings.model_copy(update={"gaps": [_critic_gap_dict()]})
    assert has_unjustified_gaps(actionable) is True
    assert count_findings(actionable) == 1


def test_revision_noop_retains_baseline_and_reports_unresolved_gap(tmp_path) -> None:
    """An empty delta cannot silently resolve an explicit critic gap."""
    client = MockLLMClient()
    client.set_response_for(
        RevisionDelta,
        {
            "new_responsibilities": [],
            "new_controlled_processes": [],
            "new_coordination_links": [],
            "modified_responsibilities": [],
            "dismissed_gaps": [],
        },
    )
    findings = CriticFindings(
        gaps=[_critic_gap_dict()],
        checklist_results={},
        taxonomy_probe_results={},
    )
    original = _make_control_structure()

    revised, warnings = run_revision(
        llm_client=client,
        control_structure=original,
        critic_findings=findings,
        use_case_text="Test use case",
        run_dir=tmp_path,
    )

    assert revised == original
    assert any("no structural change" in warning.lower() for warning in warnings)
    assert any("baseline" in warning.lower() for warning in warnings)


def test_stage1_hazard_framing_separates_attack_context_from_system_state() -> None:
    """Stage 1 distinguishes adversary context from the resulting hazard state."""
    rendered = TemplateLoader(PROMPTS_DIR).render_prompt("stage1a_risk_system.j2")
    lowered = rendered.lower()
    assert (
        "adversary action is selection context, not the grammar of the hazard"
        in lowered
    )
    assert "system state" in lowered
    assert "cause or attack mechanism" in lowered
