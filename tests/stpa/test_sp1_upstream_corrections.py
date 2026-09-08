"""Focused regression tests for the upstream STPA corrections."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from asago_scenario_generator.models.risk_card import RiskCard
from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlActionEffectKind,
    ControlActionTemporality,
    ElementRef,
    ReferenceType,
)
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysisDraft
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    PROMPT_TEMPLATES_DIR,
)
from asago_scenario_generator.stpa.system_model.control_structure import (
    parse_control_element_set_response,
)
from asago_scenario_generator.stpa.system_model.critic import (
    CriticFindings,
    RevisionDelta,
    _validate_revision_dismissed_gaps,
    run_revision,
)
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    diagnose_loss_analysis_semantics,
    derive_loss_analysis,
)
from tests.stpa.sp1_helpers import (
    MockLLMClient,
    valid_gap_draft_dict,
    valid_risk_draft_dict,
)
from tests.stpa.test_revision_delta import _make_control_structure
from asago_scenario_generator.stpa.threat_enum.slot_creation import (
    SlotPlaceholder,
    create_slots,
    is_wrong_duration_eligible,
)


def _findings() -> CriticFindings:
    return CriticFindings(
        gaps=[
            {
                "gap_type": "missing_responsibility",
                "description": "Missing review responsibility",
                "related_attack_path": "An attacker submits crafted input",
                "suggested_remedy": "Add a review responsibility",
            }
        ]
    )


def _empty_delta() -> dict:
    return {
        "new_responsibilities": [],
        "new_controlled_processes": [],
        "new_coordination_links": [],
        "modified_responsibilities": [],
        "dismissed_gaps": [],
    }


def test_revision_delta_is_closed_at_the_wire_boundary() -> None:
    """An unrelated top-level field cannot be silently discarded."""
    payload = _empty_delta()
    payload["control_structure"] = {}

    try:
        RevisionDelta.model_validate(payload)
    except ValidationError as exc:
        assert "control_structure" in str(exc)
    else:  # pragma: no cover - the assertion documents the closed contract
        raise AssertionError("RevisionDelta accepted an unrelated top-level field")


def test_strict_revision_failure_retains_structure_and_is_visible(tmp_path) -> None:
    """A malformed delta carrier fails visibly and retains the original."""
    client = MockLLMClient()
    payload = _empty_delta()
    payload["new_responsibilities"] = {"not": "a list"}
    client.set_response_for(RevisionDelta, payload)
    original = _make_control_structure()

    revised, warnings = run_revision(
        llm_client=client,
        control_structure=original,
        critic_findings=_findings(),
        use_case_text="An attacker submits crafted input.",
        run_dir=tmp_path,
    )

    assert revised == original
    assert any(warning.startswith("Revision failed:") for warning in warnings)
    assert any("new_responsibilities must be a list" in warning for warning in warnings)


def test_revision_dismissed_gap_shape_requires_nonempty_source_text() -> None:
    _validate_revision_dismissed_gaps(["the gap is not supported by the model"])
    with pytest.raises(ValueError, match=r"dismissed_gaps\[0\]"):
        _validate_revision_dismissed_gaps([" "])


def test_gap_prompt_receives_source_separated_deduplicated_losses(tmp_path) -> None:
    """The gap call sees each first-draft loss once in its typed source."""
    risk = valid_risk_draft_dict()
    duplicate = risk["risk_card_losses"][0].copy()
    risk["risk_card_losses"] = []
    risk["use_case_losses"] = [duplicate, duplicate.copy()]

    client = MockLLMClient()
    client.set_response_for(LossAnalysisDraft, [risk, valid_gap_draft_dict()])
    derive_loss_analysis(
        llm_client=client,
        use_case_text="An attacker can inject input.",
        risk_cards=[],
        run_dir=tmp_path,
    )

    gap_prompt = client.calls[1].user_prompt
    assert gap_prompt.count("Unauthorized transaction") == 1


def test_risk_prompt_keeps_complete_semantic_fields_in_compact_view(tmp_path) -> None:
    """Prompt compaction removes duplicate metadata, not reviewed meaning."""
    card = RiskCard(
        risk_id="atlas-compact-1",
        risk_name="A reviewed risk",
        risk_description=(
            "Description begins with context, preserves this middle fact, and "
            "ends with the operational boundary."
        ),
        taxonomy="ibm-risk-atlas",
        confidence=0.9,
        grounding_confidence="high",
        threat="A hidden threat field should stay out of the compact view.",
        vulnerability="A hidden vulnerability field should stay out of the compact view.",
        consequence=(
            "Consequence begins with context, preserves this middle fact, and "
            "ends with the stakeholder harm."
        ),
        impact="A hidden impact field should stay out of the compact view.",
    )
    client = MockLLMClient()
    draft = valid_risk_draft_dict()
    draft["risk_dispositions"][0]["risk_ref"] = "atlas-compact-1"
    draft["risk_card_losses"][0]["source_risk_cards"] = ["atlas-compact-1"]
    client.set_response_for(LossAnalysisDraft, [draft, valid_gap_draft_dict()])

    derive_loss_analysis(
        llm_client=client,
        use_case_text="The complete use-case context remains available.",
        risk_cards=[card],
        run_dir=tmp_path,
    )

    prompt = client.calls[0].user_prompt
    assert "atlas-compact-1" in prompt
    assert card.risk_name in prompt
    assert card.risk_description in prompt
    assert card.consequence in prompt
    assert card.threat not in prompt
    assert card.vulnerability not in prompt
    assert card.impact not in prompt


def test_semantic_diagnostics_are_generic_and_distinguish_context_from_cause() -> None:
    """Diagnostics identify component-failure hazards without domain names."""
    draft = LossAnalysisDraft.model_validate(
        {
            "risk_card_losses": [],
            "use_case_losses": [],
            "hazards": [
                {
                    "hazard_id": "H-1",
                    "description": "The sensor fails",
                    "related_losses": [],
                },
                {
                    "hazard_id": "H-2",
                    "description": "The greenhouse remains above the safe limit",
                    "related_losses": [],
                },
            ],
            "security_constraints": [],
        }
    )

    diagnostics = diagnose_loss_analysis_semantics(
        draft,
        use_case_text="An attacker can manipulate the control input.",
    )

    assert any(item.code == "hazard_not_system_state" for item in diagnostics)
    assert not any(
        item.code == "hazard_not_system_state" and "H-2" in item.message
        for item in diagnostics
    )
    assert not any(
        item.code == "adversarial_relevance_unsubstantiated" for item in diagnostics
    )


def test_semantic_diagnostics_flag_dependency_and_mechanism_hazards() -> None:
    """Cause/dependency and attack-mechanism wording remains visible per hazard."""
    draft = LossAnalysisDraft.model_validate(
        {
            "risk_card_losses": [],
            "use_case_losses": [],
            "hazards": [
                {
                    "hazard_id": "H-6",
                    "description": "Availability is dependent on upstream uptime",
                    "related_losses": [],
                },
                {
                    "hazard_id": "H-7",
                    "description": "Prompt injection reaches the decision path",
                    "related_losses": [],
                },
            ],
            "security_constraints": [],
        }
    )

    diagnostics = diagnose_loss_analysis_semantics(
        draft,
        use_case_text="An attacker can manipulate input.",
    )

    assert any(
        item.code == "hazard_cause_or_dependency" and "H-6" in item.message
        for item in diagnostics
    )
    assert any(
        item.code == "hazard_mechanism_phrasing" and "H-7" in item.message
        for item in diagnostics
    )


def test_component_failure_hazard_gets_one_bounded_semantic_retry(tmp_path) -> None:
    """A semantic hazard failure is visible and recoverable on one retry."""
    bad = valid_risk_draft_dict()
    bad["hazards"][0]["description"] = "The sensor fails"
    corrected = valid_risk_draft_dict()

    client = MockLLMClient()
    client.set_response_for(
        LossAnalysisDraft,
        [bad, corrected, valid_gap_draft_dict()],
    )
    result = derive_loss_analysis(
        llm_client=client,
        use_case_text="An attacker can inject input.",
        risk_cards=[],
        run_dir=tmp_path,
    )

    assert result.hazards[0].description == "The agent executes an unintended payment."
    assert len(client.calls) == 3
    assert "system-level state" in client.calls[1].user_prompt


def test_control_action_typed_effect_and_temporality_are_closed() -> None:
    action = ControlAction(
        ca_id="CA-1-1",
        description="Send a review request",
        target=ElementRef(type=ReferenceType.responsibility, id="RESP-2"),
        temporality="instantaneous",
    )

    assert action.effect_kind is ControlActionEffectKind.agent_message
    assert action.temporality is ControlActionTemporality.instantaneous
    assert action.model_dump(mode="json")["effect_kind"] == "agent_message"

    with pytest.raises(ValidationError, match="effect_kind"):
        ControlAction(
            ca_id="CA-1-1",
            description="Send a review request",
            target=ElementRef(type=ReferenceType.responsibility, id="RESP-2"),
            effect_kind="tool_call",
        )
    with pytest.raises(ValidationError, match="temporality"):
        ControlAction(
            ca_id="CA-1-1",
            description="Send a review request",
            temporality="sometimes",
        )


def test_call2b_preserves_typed_action_fields_and_legacy_omission() -> None:
    responsibilities = [_make_control_structure().responsibilities[0]]
    payload = {
        "control_actions": [
            {
                "ca_id": "CA-1-1",
                "description": "Send a review request",
                "target": {"type": "responsibility", "id": "RESP-1"},
                "effect_kind": "agent_message",
                "temporality": "instantaneous",
            }
        ],
        "feedback": [
            {
                "fb_id": "FB-1-1",
                "description": "Report request state",
                "updates": "PM-1-1",
                "source": {"type": "responsibility", "id": "RESP-1"},
            }
        ],
        "controlled_processes": [],
    }
    parsed = parse_control_element_set_response(
        payload, responsibilities=responsibilities
    )
    action = parsed.control_actions[0]
    assert action.effect_kind is ControlActionEffectKind.agent_message
    assert action.temporality is ControlActionTemporality.instantaneous

    # Missing new fields remain loadable for historical fixtures, while the
    # responsibility-target implication still provides the safe effect kind.
    legacy = {key: value for key, value in payload.items()}
    legacy["control_actions"] = [
        {
            key: value
            for key, value in payload["control_actions"][0].items()
            if key not in {"effect_kind", "temporality"}
        }
    ]
    legacy_action = parse_control_element_set_response(
        legacy, responsibilities=responsibilities
    ).control_actions[0]
    assert legacy_action.effect_kind is ControlActionEffectKind.agent_message
    assert legacy_action.temporality is None


def test_slots_copy_action_temporality_and_gate_duration_by_type() -> None:
    control_structure = _make_control_structure()
    action = control_structure.responsibilities[0].control_actions[0]
    action.temporality = ControlActionTemporality.continuous
    slots = create_slots(control_structure)
    duration = next(slot for slot in slots if slot.uca_type.value == "WRONG_DURATION")
    assert duration.action_temporality is ControlActionTemporality.continuous
    assert is_wrong_duration_eligible(duration)

    instantaneous = SlotPlaceholder(
        slot_id="RESP-1:CA-1-1:WRONG_DURATION",
        responsibility="RESP-1",
        control_action="CA-1-1",
        action_temporality=ControlActionTemporality.instantaneous,
        uca_type=duration.uca_type,
    )
    assert not is_wrong_duration_eligible(instantaneous)


def test_ica_template_uses_meaningful_context_and_loss_example() -> None:
    """The provider example demonstrates a supported STPA loss chain."""
    text = TemplateLoader(PROMPT_TEMPLATES_DIR).render_prompt(
        "synthesis_ica_system.j2",
        requested_slot_count=1,
        requested_consideration_count=1,
    )

    assert "an unreviewed request reaches the protected operation" in text
    assert "the protected operation applies an unauthorized state change" in text
    assert "An authorized omission is not automatically unsafe" in text
    assert "susceptibility claim" in text
    assert "not a\nhazardous state" in text
    assert "asserted consequence" in text
    assert "the supplied hazardous context" not in text
    assert "the supplied loss consequence occurs" not in text
