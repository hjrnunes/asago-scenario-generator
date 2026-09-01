"""Acceptance handlers for obligation-aware prompt meaning and continuity."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from runtime_bootstrap import PROJECT_ROOT
from runtime_shared import World

from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
from asago_scenario_generator.models.obligation_consideration import ObligationRoute
from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    ControlledProcess,
    CoordinationLink,
    CoordinationMechanism,
    ElementRef,
    FeedbackChannel,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
)
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    AnalysisControls,
    IcaDeviationDraft,
    IcaFindingDraft,
    SlotIcaDraft,
)
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    project_obligation_question,
)
from asago_scenario_generator.stpa.obligation_aware.routing import (
    build_neutral_briefs,
    route_obligations,
)
from asago_scenario_generator.stpa.obligation_aware.slot_filling import (
    compile_ica_slot_draft,
)
from asago_scenario_generator.stpa.scenario_prod.bdi_generation import (
    BDIGenerationResult,
)
from asago_scenario_generator.stpa.scenario_prod.context import (
    build_scenario_generation_context,
)
from asago_scenario_generator.stpa.system_model.control_structure import (
    ResponsibilitySet,
    parse_control_element_set_response,
)
from asago_scenario_generator.stpa.threat_enum.slot_creation import create_slots
from asago_scenario_generator.stpa.models.enriched_threat_set import StructuralThreat
from asago_scenario_generator.stpa.infra.prompt_preflight import (
    PromptBudget,
    PromptBudgetExceeded,
    split_prompt_batch,
)
from tests.helpers.obligation_factory import make_plan
from tests.helpers.projection_factory import get_test_raw_pattern


FEATURE_ID = "synthesis_prompt_contracts"
_FIXTURE = Path(PROJECT_ROOT) / "tests/fixtures/stpa-prompt-contract-regressions.yaml"


def _state(world: World) -> dict[str, Any]:
    value = getattr(world, "synthesis_prompt_state", None)
    if value is None:
        value = {}
        world.synthesis_prompt_state = value
    return value


def _structure() -> ControlStructure:
    return ControlStructure(
        controlled_processes=[
            ControlledProcess(cp_id="CP-1", description="Clinical record service")
        ],
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Authorize changes to clinical records",
                security_constraint_refs=["SC-1"],
                process_model_parts=[
                    ProcessModelPart(
                        pm_id="PM-1-1", description="Clinical change approval state"
                    )
                ],
                control_actions=[
                    ControlAction(
                        ca_id="CA-1-1",
                        description="Authorize a clinical record change",
                        target=ElementRef(
                            type=ReferenceType.controlled_process, id="CP-1"
                        ),
                    )
                ],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1",
                        description="Report the committed clinical record change",
                        updates="PM-1-1",
                        source=ElementRef(
                            type=ReferenceType.controlled_process, id="CP-1"
                        ),
                    )
                ],
            )
        ],
    )


def _losses() -> LossAnalysis:
    return LossAnalysis(
        risk_card_losses=[
            Loss(
                loss_id="L-1",
                description="Clinical decisions rely on corrupted patient data",
                provenance=LossProvenance.risk_card,
                source_risk_cards=["risk-clinical-integrity"],
            )
        ],
        use_case_losses=[],
        hazards=[
            Hazard(
                hazard_id="H-1",
                description="An unauthorized clinical record change is accepted",
                related_losses=["L-1"],
            ),
            Hazard(
                hazard_id="H-2",
                description="Integrity-critical clinical data is changed incorrectly",
                related_losses=["L-1"],
            ),
        ],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1",
                description="Only approved clinical changes may be committed",
                related_hazards=["H-1"],
            )
        ],
    )


def _brief():
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    return build_neutral_briefs(make_plan(), (pattern,))[0]


def _h_fixture(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    data = yaml.safe_load(_FIXTURE.read_text(encoding="utf-8"))
    if data.get("schema_version") != "stpa-prompt-contract-regressions-v1":
        return False, "captured prompt regression fixture has the wrong schema"
    world.synthesis_prompt_state = {"fixture": data}
    return True, ""


def _h_malformed_control(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    state = _state(world)
    response = state["fixture"]["control_element_combined_action"]["response"]
    responsibilities = ResponsibilitySet(responsibilities=_structure().responsibilities)
    try:
        parse_control_element_set_response(
            response, responsibilities=responsibilities.responsibilities
        )
    except (TypeError, ValueError) as exc:
        state["control_error"] = str(exc)
        state["control_published"] = False
        state["control_order_inferred"] = False
        return True, ""
    return False, "malformed combined control action was accepted"


def _h_control_rejected(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text
    state = _state(world)
    expected = examples.get(
        "publication_status", "rejected_without_placeholder"
    ).strip()
    actual = (
        "rejected_without_placeholder"
        if state.get("control_error") and state.get("control_published") is False
        else "published_or_unrejected"
    )
    return actual == expected, f"expected {expected!r}, got {actual!r}"


def _h_no_order(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    return (
        (True, "")
        if _state(world).get("control_order_inferred") is False
        else (False, "control-action ownership was inferred from response order")
    )


def _h_project_question(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    question = project_obligation_question(_brief())
    _state(world)["question"] = question
    return True, ""


def _h_no_audit(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    payload = _state(world)["question"].model_dump_json()
    prohibited = ("plan_digest", "semantic_digest", "catalog_pins", "mapping_pins")
    leaked = [item for item in prohibited if item in payload]
    return (False, f"audit-only fields leaked: {leaked}") if leaked else (True, "")


def _h_described(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    question = _state(world)["question"]
    values = (
        question.known_concern.name,
        question.known_concern.description,
        question.reviewed_risk.name,
        question.analyst_instruction,
    )
    return (
        (True, "")
        if all(item and item.strip() for item in values)
        else (False, "a selectable routing identity lacks a description")
    )


def _h_copy_only(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text
    instruction = _state(world)["question"].analyst_instruction.lower()
    expected = examples.get(
        "handle_instruction", "copy unchanged opaque handle"
    ).strip()
    actual = (
        "copy unchanged opaque handle"
        if "copy unchanged" in instruction and "opaque handle" in instruction
        else "missing copy-only guidance"
    )
    return actual == expected, f"expected {expected!r}, got {actual!r}"


def _h_split_batch(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    items = tuple(f"ob-{index}:" + marker * 400 for index, marker in enumerate("abc"))
    budget = PromptBudget(
        context_window=1_024,
        maximum_completion_tokens=128,
        safety_margin=128,
        token_counter=len,
    )
    _state(world)["split_source"] = items
    _state(world)["split_batches"] = split_prompt_batch(items, budget=budget)
    return True, ""


def _h_split_canonical(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text
    state = _state(world)
    flattened = tuple(item for batch in state["split_batches"] for item in batch)
    expected = examples.get("ordering", "canonical_order").strip()
    actual = (
        "canonical_order"
        if flattened == state["split_source"] and len(state["split_batches"]) > 1
        else "changed_order"
    )
    return actual == expected, f"expected {expected!r}, got {actual!r}"


def _h_one_oversized(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    budget = PromptBudget(
        context_window=1_024,
        maximum_completion_tokens=128,
        safety_margin=128,
        token_counter=len,
    )
    state = _state(world)
    state["provider_calls"] = 0
    try:
        split_prompt_batch(("oversized:" + "z" * 900,), budget=budget)
    except PromptBudgetExceeded as exc:
        state["budget_error"] = exc
        return True, ""
    return False, "single oversized routing item was accepted"


def _h_budget_diagnostic(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    error = _state(world).get("budget_error")
    return (
        (True, "")
        if error is not None and error.code == "prompt_budget_exceeded"
        else (False, "prompt budget diagnostic was not retained")
    )


def _h_no_provider_call(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text
    expected = int(examples.get("provider_calls", "0"))
    actual = int(_state(world).get("provider_calls", 0))
    return actual == expected, f"expected {expected} provider calls, got {actual}"


def _h_route_mismatch(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    brief = _brief()
    route = ObligationRoute(
        obligation_id=brief.obligation_id,
        disposition="targeted",
        slot_ids=("RESP-1:CA-1-1:NOT_PROVIDED",),
        hazard_ids=("H-2",),
        constraint_ids=("SC-1",),
        evidence=("captured-mismatch",),
    )

    class Adapter:
        def route(self, request, *, correction_feedback=None):
            del correction_feedback
            return {"request_digest": request.semantic_digest, "routes": (route,)}

    result = route_obligations(
        Adapter(),
        briefs=(brief,),
        loss_analysis=_losses(),
        control_structure=_structure(),
        controls=AnalysisControls(
            model_profile="acceptance",
            model_name="deterministic",
            deadline_seconds=1.0,
            temperature=0.0,
        ),
    )
    _state(world)["route"] = result.routes[0]
    return True, ""


def _h_route_unresolved(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text
    route = _state(world)["route"]
    diagnostic_text = " ".join(item.detail for item in route.diagnostics).lower()
    expected = examples.get("disposition", "unresolved").strip()
    actual = (
        route.disposition
        if "does not govern" in diagnostic_text
        else "missing-governance-diagnostic"
    )
    return actual == expected, f"expected {expected!r}, got {actual!r}"


def _h_no_constraint_substitution(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text, examples
    route = _state(world)["route"]
    return (
        (True, "")
        if not route.constraint_ids
        else (False, "a global constraint was substituted into the invalid route")
    )


def _h_safeguard(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    fixture = _state(world)["fixture"]["safeguard_as_ica"]
    slot = create_slots(_structure())[0]
    draft = SlotIcaDraft(
        slot_id=slot.slot_id,
        is_na=False,
        findings=(
            IcaFindingDraft(
                deviation=IcaDeviationDraft(
                    not_provided_context=fixture["returned_text"]
                ),
                hazardous_context="an unreviewed change reaches the record",
                loss_consequence="clinical decisions use corrupted data",
                related_hazard_ids=("H-1",),
                related_constraint_ids=("SC-1",),
            ),
        ),
    )
    try:
        compile_ica_slot_draft(
            draft,
            slot=slot,
            loss_analysis=_losses(),
            control_structure=_structure(),
        )
    except ValueError as exc:
        _state(world)["safeguard_error"] = str(exc)
        return True, ""
    return False, "safeguard was accepted as unsafe control behavior"


def _h_safeguard_rejected(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    error = _state(world).get("safeguard_error", "").lower()
    return (True, "") if "safeguard" in error else (False, error)


def _h_four_types(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del world, text
    from asago_scenario_generator.stpa.models.ica_enumeration import UCAType

    expected = {
        item.strip()
        for item in examples.get(
            "uca_types", "NOT_PROVIDED, INCORRECT, WRONG_TIMING, WRONG_DURATION"
        ).split(",")
    }
    actual = {item.value for item in UCAType}
    return actual == expected, f"expected {expected!r}, got {actual!r}"


def _h_drift(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    fixture = _state(world)["fixture"]["scenario_mechanism_drift"]
    payload = {
        "defender_vulnerabilities": {"PM-1-1": "approval state can be stale"},
        "attacker_bdi": {
            "beliefs": ["The state can be stale"],
            "desires": [fixture["returned"]["attacker_desire"]],
            "intentions": [fixture["returned"]["attacker_intention"]],
        },
        "causal_factors": [
            {
                "kind": "process_model_flaw",
                "source_id": "PM-1-1",
                "evidence": "The approval state is stale at authorization time.",
            }
        ],
        "ica_text": "Replace the accepted mass-action ICA with a PII concern",
    }
    try:
        BDIGenerationResult.model_validate(payload)
    except ValidationError:
        state = _state(world)
        state["drift_published"] = False
        state["drift_source"] = fixture["source"]
        return True, ""
    return False, "drifting model response replaced accepted scenario authority"


def _h_authority_retained(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    source = _state(world).get("drift_source", {})
    required = ("ica_text", "hazard", "constraint")
    return (
        (True, "")
        if all(source.get(item) for item in required)
        else (False, "source scenario authority was not retained")
    )


def _h_drift_not_published(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text
    expected = int(examples.get("published_scenarios", "0"))
    actual = 0 if _state(world).get("drift_published") is False else 1
    return actual == expected, f"expected {expected} published scenarios, got {actual}"


def _h_missing_factors(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    payload = _state(world)["fixture"]["missing_causal_factors"]["response"]
    try:
        BDIGenerationResult.model_validate(payload)
    except ValidationError:
        state = _state(world)
        state["causal_unresolved"] = True
        state["stage6_published"] = False
        return True, ""
    return False, "causal scenario without factors was accepted"


def _h_causal_unresolved(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text
    expected = examples.get("disposition", "unresolved").strip()
    actual = "unresolved" if _state(world).get("causal_unresolved") else "resolved"
    return actual == expected, f"expected {expected!r}, got {actual!r}"


def _h_no_stage6(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    return (
        (True, "")
        if _state(world).get("stage6_published") is False
        else (False, "Stage 6 artifacts were published without causal evidence")
    )


def _h_ehr_fixture(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    _state(world)["ehr_ready"] = True
    return True, ""


def _h_resolve_constraint(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    if not _state(world).get("ehr_ready"):
        return False, "EHR constraint fixture was not prepared"
    threat = StructuralThreat(
        ica_slot_id="RESP-1:CA-1-1:INCORRECT",
        ica_id="ICA-EHR-1",
        ica_text="The controller authorizes an incorrect clinical record change.",
        hazardous_context="An unapproved change reaches the clinical record.",
        loss_scenario="Clinical decisions rely on corrupted patient data.",
        related_hazards=["H-2"],
        related_constraints=["SC-1"],
    )
    try:
        build_scenario_generation_context(
            threat, _structure(), _losses(), scenario_id="SCN-001"
        )
    except ValueError as exc:
        _state(world)["constraint_error"] = str(exc)
        return True, ""
    return False, "unrelated privacy constraint was selected"


def _h_constraint_closed(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text
    error = _state(world).get("constraint_error", "").lower()
    expected = examples.get("resolution", "fails_closed").strip()
    actual = "fails_closed" if "does not govern" in error else "accepted"
    return actual == expected, f"expected {expected!r}, got {actual!r}"


def _h_gherkin_headings(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Parse provider-owned titles and render them with one heading each."""
    del text, examples
    from asago_scenario_generator.stpa.scenario_prod.gherkin import parse_gherkin_spec

    response = yaml.safe_dump(
        {
            "feature": "Feature: Safe payment orchestration",
            "scenario": "Scenario: Tool-chain exfiltration",
            "given": ["Given PM-1-1 is valid"],
            "when": ["When a request is received"],
            "then_expected": ["Then the system should reject the request"],
            "then_actual": ["But the system approves the request"],
        },
        sort_keys=False,
    )
    spec = parse_gherkin_spec(response)
    if spec is None:
        return False, "provider Gherkin fixture did not parse"
    rendered = spec.to_feature_text()
    _state(world)["gherkin_spec"] = spec
    _state(world)["gherkin_rendered"] = rendered
    return True, ""


def _h_gherkin_titles_normalized(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Verify renderer-owned prefixes were removed from title fields."""
    del text
    spec = _state(world).get("gherkin_spec")
    if spec is None:
        return False, "no parsed provider Gherkin response"
    expected = tuple(
        item.strip()
        for item in examples.get(
            "normalized_titles",
            "Safe payment orchestration, Tool-chain exfiltration",
        ).split(",")
    )
    actual = (spec.feature, spec.scenario)
    return actual == expected, f"expected {expected!r}, got {actual!r}"


def _h_gherkin_heading_count(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Verify a rendered document has exactly one requested heading."""
    del examples
    rendered = _state(world).get("gherkin_rendered", "")
    heading = "Feature:" if "Feature" in text else "Scenario:"
    count = sum(line.startswith(heading + " ") for line in rendered.splitlines())
    return count == 1, f"expected one {heading} heading, found {count}"


def _h_coordination_context(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text, examples
    source = _structure().responsibilities[0]
    target = Responsibility(
        resp_id="RESP-2",
        description="Verify changes against shared clinical policy",
        process_model_parts=[
            ProcessModelPart(pm_id="PM-2-1", description="Shared policy state")
        ],
        control_actions=[
            ControlAction(
                ca_id="CA-2-1",
                description="Verify a clinical record change",
                target=ElementRef(type=ReferenceType.controlled_process, id="CP-2"),
            )
        ],
        feedback_channels=[
            FeedbackChannel(
                fb_id="FB-2-1",
                description="Report policy verification",
                updates="PM-2-1",
                source=ElementRef(type=ReferenceType.controlled_process, id="CP-2"),
            )
        ],
    )
    structure = ControlStructure(
        responsibilities=[source, target],
        controlled_processes=[
            ControlledProcess(cp_id="CP-1", description="Clinical record service"),
            ControlledProcess(cp_id="CP-2", description="Policy verification service"),
        ],
        coordination_links=[
            CoordinationLink(
                link_id="CL-1",
                source="RESP-1",
                target="RESP-2",
                shared_pm="PM-1-1",
                coordination_mechanism=CoordinationMechanism(
                    cm_id="CM-1",
                    description="Synchronize clinical policy state",
                    payload="policy_state",
                ),
                description="Authorization and policy verification coordinate",
            )
        ],
    )
    threat = StructuralThreat(
        ica_slot_id="CL-1:CM-1:INCORRECT",
        ica_id="CL-1:CM-1:INCORRECT:1",
        ica_text="The coordination mechanism transmits an incorrect policy state.",
        hazardous_context="An unapproved policy state reaches authorization.",
        loss_scenario="Clinical decisions rely on corrupted patient data.",
        related_hazards=["H-1"],
        related_constraints=["SC-1"],
    )
    _state(world)["coordination_context"] = build_scenario_generation_context(
        threat, structure, _losses(), scenario_id="SCN-CL-001"
    )
    return True, ""


def _h_coordination_explained(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text
    path = _state(world)["coordination_context"].target_control_path
    coordination = path.coordination_path
    if coordination is None:
        return False, "coordination path was not retained"
    actual = (
        coordination.link_id,
        coordination.coordination_mechanism.element_id,
        coordination.source.element_id,
        coordination.target.element_id,
    )
    expected = tuple(
        item.strip()
        for item in examples.get(
            "coordination_path", "CL-1, CM-1, RESP-1, RESP-2"
        ).split(",")
    )
    return actual == expected, f"expected {expected!r}, got {actual!r}"


def _h_coordination_not_responsibility(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text, examples
    path = _state(world)["coordination_context"].target_control_path
    return (
        (True, "")
        if path.responsibility is None and path.coordination_path is not None
        else (False, "coordination identity was treated as a responsibility")
    )


def register(api: Any) -> None:
    api.set_feature(FEATURE_ID)
    api.register(r"the captured synthesis prompt regressions are available", _h_fixture)
    api.register(
        r"the malformed combined control-action response is validated",
        _h_malformed_control,
    )
    api.register(
        r'the response publication status is ".*"',
        _h_control_rejected,
    )
    api.register(
        r"control-action ownership is not inferred from response order", _h_no_order
    )
    api.register(r"a provider obligation question is projected", _h_project_question)
    api.register(
        r"audit-only provenance is absent from the provider question", _h_no_audit
    )
    api.register(
        r"every selectable routing identity has a plain-language description",
        _h_described,
    )
    api.register(r'the obligation handle instruction is ".*"', _h_copy_only)
    api.register(
        r"a canonical routing batch exceeds the configured prompt budget",
        _h_split_batch,
    )
    api.register(
        r'the routing batch ordering is ".*"',
        _h_split_canonical,
    )
    api.register(
        r"one routing item cannot fit the configured prompt budget", _h_one_oversized
    )
    api.register(
        r"prompt budget exceeded is retained as a local diagnostic",
        _h_budget_diagnostic,
    )
    api.register(r"the provider call count is .*", _h_no_provider_call)
    api.register(
        r"the captured mismatched hazard and constraint are validated",
        _h_route_mismatch,
    )
    api.register(r'the targeted route disposition is ".*"', _h_route_unresolved)
    api.register(r"no global constraint is substituted", _h_no_constraint_substitution)
    api.register(r"the captured safeguard is proposed as an ICA", _h_safeguard)
    api.register(
        r"the safeguard is rejected as unsafe-control behavior", _h_safeguard_rejected
    )
    api.register(r'the unsafe-control type set is ".*"', _h_four_types)
    api.register(r"the captured drifting scenario response is compiled", _h_drift)
    api.register(
        r"the source ICA hazard loss and constraint remain authoritative",
        _h_authority_retained,
    )
    api.register(
        r"the published scenario-realization count is .*",
        _h_drift_not_published,
    )
    api.register(r"the captured response has no causal factors", _h_missing_factors)
    api.register(r'scenario generation disposition is ".*"', _h_causal_unresolved)
    api.register(r"no narrative attack tree or Gherkin is published", _h_no_stage6)
    api.register(
        r"an EHR integrity hazard and an unrelated privacy constraint", _h_ehr_fixture
    )
    api.register(r"the scenario Gherkin constraint is resolved", _h_resolve_constraint)
    api.register(r'governing constraint resolution is ".*"', _h_constraint_closed)
    api.register(
        r"a provider Gherkin response contains renderer-owned Feature and Scenario headings",
        _h_gherkin_headings,
    )
    api.register(
        r'the normalized provider titles are ".*"',
        _h_gherkin_titles_normalized,
    )
    api.register(
        r"the rendered feature has exactly one Feature heading",
        _h_gherkin_heading_count,
    )
    api.register(
        r"the rendered feature has exactly one Scenario heading",
        _h_gherkin_heading_count,
    )
    api.register(
        r"a coordination ICA is projected for scenario generation",
        _h_coordination_context,
    )
    api.register(
        r'the retained coordination identities are ".*"',
        _h_coordination_explained,
    )
    api.register(
        r"no coordination identity is treated as a responsibility",
        _h_coordination_not_responsibility,
    )


__all__ = ["FEATURE_ID", "register"]
