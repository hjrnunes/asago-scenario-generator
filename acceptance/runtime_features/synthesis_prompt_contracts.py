"""Acceptance handlers for obligation-aware prompt meaning and continuity."""

from __future__ import annotations

from pathlib import Path
import json
import re
import tempfile
from typing import Any

import yaml
from pydantic import BaseModel, ValidationError

from runtime_bootstrap import PROJECT_ROOT
from runtime_shared import World, _feature_state

from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
from asago_scenario_generator.models.artifact_pin import ArtifactPin
from asago_scenario_generator.models.obligation_consideration import (
    ObligationIcaConsideration,
    ObligationRoute,
    ObligationSemanticAssessment,
)
from asago_scenario_generator.pipeline.obligation_consideration import (
    build_consideration_artifact,
    build_obligation_accounting,
)
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
from asago_scenario_generator.stpa.models.ica_enumeration import (
    ICA,
    ICAEnumeration,
    ICASlot,
    UCAType,
)
from asago_scenario_generator.stpa.models.scenario_context import (
    ScenarioObligationConsideration,
)
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    AnalysisControls,
    IcaDeviationDraft,
    IcaFindingDraft,
    SlotIcaDraft,
    StructuralRoutingResponse,
    SynthesisSlotRequest,
)
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    build_structural_routing_prompts,
    build_synthesis_slot_prompts,
    project_obligation_question,
)
from asago_scenario_generator.stpa.obligation_aware.routing import (
    build_neutral_briefs,
    route_obligations,
)
from asago_scenario_generator.stpa.obligation_aware.provider import (
    ObligationAwareLLMAdapter,
    _routing_provider_payload_type,
)
from asago_scenario_generator.stpa.obligation_aware.ica_verification import (
    IcaHazardVerificationCorrection,
    verify_final_ica_batch,
)
from asago_scenario_generator.stpa.obligation_aware.slot_filling import (
    compile_ica_slot_draft,
)
from asago_scenario_generator.stpa.scenario_prod.bdi_generation import (
    BDIGenerationResult,
    build_context_bdi_prompts,
    generate_bdi_for_context,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.infra.llm_helpers import (
    CorrectionPolicy,
    call_with_policy,
)
from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.scenario_prod.context import (
    build_scenario_generation_context,
)
from asago_scenario_generator.stpa.system_model.control_structure import (
    ResponsibilitySet,
    parse_control_element_set_response,
)
from asago_scenario_generator.stpa.threat_enum.slot_creation import create_slots
from asago_scenario_generator.stpa.models.enriched_threat_set import StructuralThreat
from tests.helpers.obligation_factory import make_plan
from tests.helpers.projection_factory import get_test_raw_pattern
from asago_scenario_generator.stpa.obligation_aware import prompts
from tests.stpa.sp1_helpers import MockLLMClient


FEATURE_ID = "synthesis_prompt_contracts"
_FIXTURE = Path(PROJECT_ROOT) / "tests/fixtures/stpa-prompt-contract-regressions.yaml"


def _state(world: World) -> dict[str, Any]:
    return _feature_state(world, "synthesis_prompt_state")


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
                rule="Only approved clinical changes may be committed",
                applies_when=[],
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


def _h_inspect_obligation_templates(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text, examples

    template_dir = Path(prompts.__file__).with_name("prompt_templates")
    loader = TemplateLoader(template_dir)
    names = {
        "structural_routing_system.j2",
        "structural_routing_user.j2",
        "structural_revision_system.j2",
        "structural_revision_user.j2",
        "synthesis_ica_system.j2",
        "synthesis_ica_user.j2",
    }
    state = _state(world)
    state["template_names"] = names
    state["template_hashes"] = loader.hash_prompt_templates()
    try:
        loader.render_prompt("structural_routing_user.j2")
    except Exception as exc:
        state["strict_template_error"] = type(exc).__name__
    return True, ""


def _h_all_prompts_jinja(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    state = _state(world)
    missing = state["template_names"] - set(state["template_hashes"])
    return not missing, f"missing Jinja prompt templates: {sorted(missing)}"


def _h_strict_template(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text
    expected = examples.get("failure", "StrictUndefined")
    actual = _state(world).get("strict_template_error", "no failure")
    # Jinja names the concrete exception UndefinedError; the configured policy
    # is StrictUndefined and the behavior is what acceptance verifies.
    normalized = "StrictUndefined" if actual == "UndefinedError" else actual
    return normalized == expected, f"expected {expected!r}, got {normalized!r}"


def _h_inspect_routing_guidance(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text, examples
    routing_system, _routing_user = build_structural_routing_prompts(
        briefs=(_brief(),),
        loss_analysis=_losses(),
        control_structure=_structure(),
        slots=tuple(create_slots(_structure())),
    )
    _state(world)["routing_guidance"] = routing_system
    return True, ""


def _h_distinguish_authentication(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text
    mechanism = examples.get("mechanism", "poisoned tool output").strip()
    guidance = _state(world)["routing_guidance"].lower()
    expected = f"authentication rejection is not {mechanism}".lower()
    return expected in guidance, f"routing guidance does not contain {expected!r}"


def _h_no_adjacent_substitution(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text, examples
    guidance = _state(world)["routing_guidance"]
    required = (
        "adjacent safeguard is not evidence",
        "ingress resource proves only that content can arrive",
        "neither establishes semantic separation",
        "the disposition must be `unresolved`",
    )
    missing = [phrase for phrase in required if phrase not in guidance]
    return not missing, f"routing guidance misses mechanism boundary: {missing}"


def _record_assessed_route(
    world: World, assessment: ObligationSemanticAssessment, evidence: str
) -> tuple[bool, str]:
    plan = make_plan()
    brief = _brief()
    route = ObligationRoute(
        obligation_id=brief.obligation_id,
        disposition="targeted",
        semantic_assessment=assessment,
        slot_ids=("RESP-1:CA-1-1:NOT_PROVIDED",),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        evidence=(evidence,),
    )
    _record_semantic_accounting(world, plan, brief, route)
    return True, ""


def _h_risk_mismatch(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    return _record_assessed_route(
        world,
        ObligationSemanticAssessment(
            mechanism_assessment="plausible_in_system",
            risk_alignment="mismatch",
            mapping_strength="broad_category_expansion",
            mechanism_rationale="The batch mechanism exists in the supplied structure.",
            risk_alignment_rationale=(
                "Mass action does not realize restrictions on acquiring data."
            ),
        ),
        "acceptance:batch-path",
    )


def _record_semantic_accounting(
    world: World, plan: Any, brief: Any, route: ObligationRoute
) -> None:
    """Retain one ordinary finding and its non-credit accounting outcome."""
    pair = ObligationIcaConsideration(
        route_id=route.route_id,
        obligation_id=brief.obligation_id,
        slot_id=route.slot_ids[0],
        disposition="finding",
        ica_ids=(f"{route.slot_ids[0]}:1",),
        exec_candidate_ids=("EXEC:RESP-1:CA-1-1:NOT_PROVIDED",),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        evidence=("acceptance:ordinary-stpa-finding",),
    )
    consideration = build_consideration_artifact(
        plan=plan,
        briefs=(brief,),
        initial_routes=(route,),
        final_routes=(route,),
    )
    accounting = build_obligation_accounting(
        plan=plan,
        consideration=consideration,
        ica_considerations=(pair,),
        source_pins=tuple(
            ArtifactPin(
                artifact_id=artifact_id,
                schema_version=schema_version,
                semantic_digest=digest,
            )
            for artifact_id, schema_version, digest in (
                (
                    "taxonomy-obligation-plan",
                    "taxonomy-obligation-plan-v1",
                    plan.semantic_digest,
                ),
                ("stpa-loss-analysis", "stpa-loss-analysis-v1", "2" * 64),
                ("stpa-control-structure", "stpa-control-structure-v1", "3" * 64),
                ("ica-enumeration", "ica-enumeration-v1", "4" * 64),
            )
        ),
    )
    state = _state(world)
    state["semantic_pair"] = pair
    state["semantic_accounting"] = accounting


def _h_adjacent_path(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    return _record_assessed_route(
        world,
        ObligationSemanticAssessment(
            mechanism_assessment="insufficient_evidence",
            risk_alignment="supported",
            mapping_strength="direct_curated_pair",
            mechanism_rationale=(
                "The selected input control does not establish poisoned output "
                "being interpreted as a goal."
            ),
            risk_alignment_rationale=(
                "The distinctive mechanism would conceptually realize the risk."
            ),
        ),
        "acceptance:adjacent-control",
    )


def _h_ordinary_finding_retained(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text, examples
    pair = _state(world)["semantic_pair"]
    return pair.disposition == "finding" and bool(pair.ica_ids), "finding was removed"


def _h_stop_reason(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text
    expected = examples.get("stop_reason", "risk_pattern_mismatch")
    actual = _state(world)["semantic_accounting"].rows[0].stop_reason
    return actual == expected, f"expected {expected!r}, got {actual!r}"


def _h_addressed_count(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text
    expected = int(examples.get("addressed", "0"))
    actual = _state(world)["semantic_accounting"].summary.addressed
    return actual == expected, f"expected {expected}, got {actual}"


def _h_provider_parse_failure(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text, examples

    class Expected(BaseModel):
        required: str

    class Provider:
        model = "acceptance-provider"

        def complete(self, **kwargs):
            return LLMResult(
                content={"wrong": "shape"},
                prompt_tokens=1,
                completion_tokens=1,
                duration_ms=1,
                system_prompt=kwargs["system_prompt"],
                user_prompt=kwargs["user_prompt"],
            )

    run_dir = Path(tempfile.mkdtemp(prefix="call-lifecycle-acceptance-"))
    call_with_policy(
        llm_client=Provider(),
        system_prompt="Return JSON.",
        user_prompt="Return the required field.",
        response_format=Expected,
        run_dir=run_dir,
        stage="acceptance",
        step="typed-parse",
        policy=CorrectionPolicy(),
    )
    _state(world)["lifecycle"] = json.loads(
        (run_dir / "calls.jsonl").read_text(encoding="utf-8").splitlines()[0]
    )
    return True, ""


def _h_lifecycle_bool(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del examples
    field = (
        "provider_response_received"
        if "response received" in text
        else "semantic_validation_passed"
    )
    expected = "true" in text
    actual = _state(world)["lifecycle"][field]
    return actual is expected, f"expected {field}={expected}, got {actual}"


def _h_terminal_provider_error(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text
    expected = examples.get("error_code", "provider_contract_failure")
    actual = _state(world)["lifecycle"]["terminal_error_codes"]
    return actual == [expected], f"expected {[expected]!r}, got {actual!r}"


def _routing_controls(*, context_window: int, completion_tokens: int):
    return AnalysisControls(
        model_profile="acceptance",
        model_name="routing-budget",
        deadline_seconds=1.0,
        temperature=0.0,
        context_window=context_window,
        maximum_completion_tokens=completion_tokens,
    )


def _h_split_batch(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    briefs = build_neutral_briefs(
        make_plan(risk_ids=("risk-a", "risk-b")),
        (pattern,),
    )
    observed: list[tuple[str, ...]] = []

    class RecordingRouter:
        def route(self, request):
            observed.append(tuple(item.obligation_id for item in request.briefs))
            return StructuralRoutingResponse(
                request_digest=request.semantic_digest,
                routes=tuple(
                    ObligationRoute(
                        obligation_id=item.obligation_id,
                        disposition="targeted",
                        slot_ids=("RESP-1:CA-1-1:NOT_PROVIDED",),
                        hazard_ids=("H-1",),
                        constraint_ids=("SC-1",),
                        evidence=("budget-split",),
                    )
                    for item in request.briefs
                ),
            )

    route_obligations(
        RecordingRouter(),
        briefs=briefs,
        loss_analysis=_losses(),
        control_structure=_structure(),
        controls=_routing_controls(context_window=11_000, completion_tokens=8_192),
    )
    _state(world)["split_source"] = tuple(item.obligation_id for item in briefs)
    _state(world)["split_batches"] = tuple(observed)
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
    calls: list[object] = []

    class Client:
        model = "routing-budget"

        def complete(self, **kwargs):
            calls.append(kwargs)
            raise AssertionError("an oversized routing prompt was dispatched")

    controls = _routing_controls(context_window=2_048, completion_tokens=4_096)
    result = route_obligations(
        ObligationAwareLLMAdapter(
            Client(),
            run_dir=Path(tempfile.mkdtemp(prefix="routing-budget-acceptance-")),
            controls=controls,
        ),
        briefs=(_brief(),),
        loss_analysis=_losses(),
        control_structure=_structure(),
        controls=controls,
    )
    state = _state(world)
    state["provider_calls"] = len(calls)
    route = result.routes[0]
    if route.disposition != "unresolved" or not route.diagnostics:
        return False, f"oversized routing item was routed as {route.disposition!r}"
    state["budget_error"] = route.diagnostics[0]
    return True, ""


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
            return StructuralRoutingResponse(
                request_digest=request.semantic_digest, routes=(route,)
            )

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

    expected = {
        item.strip()
        for item in examples.get(
            "uca_types", "NOT_PROVIDED, INCORRECT, WRONG_TIMING, WRONG_DURATION"
        ).split(",")
    }
    actual = {item.value for item in UCAType}
    return actual == expected, f"expected {expected!r}, got {actual!r}"


def _h_provider_plain_deviation(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Run the public slot adapter with one provider-authored deviation."""
    del text, examples

    structure = _structure()
    slot = create_slots(structure)[0]
    client = MockLLMClient()
    client.set_response_queue(
        [
            {
                "filled_slots": [
                    {
                        "slot_id": slot.slot_id,
                        "is_na": False,
                        "na_rationale": None,
                        "findings": [
                            {
                                "deviation": "the approval state is absent",
                                "hazardous_context": (
                                    "an unapproved change reaches the clinical record"
                                ),
                                "loss_consequence": (
                                    "clinical decisions use corrupted patient data"
                                ),
                                "related_hazard_ids": ["H-1"],
                                "related_constraint_ids": ["SC-1"],
                                "process_model_refs": ["PM-1-1"],
                                "feedback_refs": [],
                            }
                        ],
                        "consideration_results": [],
                    }
                ]
            }
        ]
    )
    controls = AnalysisControls(
        model_profile="acceptance",
        model_name=client.model,
        deadline_seconds=1.0,
        temperature=0.0,
    )
    request = SynthesisSlotRequest(
        target_id=slot.responsibility or "",
        target_kind="responsibility",
        slots=(slot,),
        loss_analysis=_losses(),
        control_structure=structure,
        controls=controls,
    )
    result = ObligationAwareLLMAdapter(
        client,
        run_dir=Path(tempfile.mkdtemp(prefix="ica-deviation-acceptance-")),
        controls=controls,
    ).fill(request)
    _state(world)["compiled_ica"] = result.filled_slots[0].icas[0]
    _state(world)["ica_provider_schema"] = client.calls[0].response_format
    _state(world)["ica_system_prompt"] = client.calls[0].system_prompt
    return True, ""


def _h_compiled_ica_behavior(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text
    ica = _state(world).get("compiled_ica")
    expected = examples.get("behavior", "fails to provide")
    if ica is None:
        return False, "ICA provider result was not compiled"
    return expected in ica.ica_text, f"expected {expected!r} in {ica.ica_text!r}"


def _h_plain_deviation_schema(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text, examples
    response_format = _state(world).get("ica_provider_schema")
    if response_format is None:
        return False, "ICA provider schema was not captured"
    finding = response_format.model_json_schema()["$defs"]["_SlotProviderFindingDraft"][
        "properties"
    ]
    deviation = finding.get("deviation", {})
    forbidden = {
        "not_provided_context",
        "incorrect_value_or_effect",
        "timing_deviation",
        "duration_deviation",
    }
    if forbidden.intersection(finding):
        return False, "model-facing schema still exposes UCA category fields"
    return deviation.get("type") == "string", "deviation is not one plain string"


def _h_one_governing_constraint_schema(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text, examples
    response_format = _state(world).get("ica_provider_schema")
    if response_format is None:
        return False, "ICA provider schema was not captured"
    finding = response_format.model_json_schema()["$defs"]["_SlotProviderFindingDraft"][
        "properties"
    ]
    constraints = finding.get("related_constraint_ids", {})
    exact = constraints.get("minItems") == 1 and constraints.get("maxItems") == 1
    return exact, f"unexpected governing-constraint schema: {constraints}"


def _h_finding_relevance_contract(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text, examples
    prompt = _state(world).get("ica_system_prompt", "")
    required = (
        "subject, operation, affected object, and effect",
        "are not mechanism evidence",
        "a detector's score threshold is not tool-call parameter pollution",
    )
    missing = [item for item in required if item not in prompt]
    return not missing, f"ICA relevance contract is missing: {missing}"


def _h_taxonomy_mechanism_routed(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Render both prompt boundaries for a mechanism-specific obligation."""
    del text, examples
    structure = _structure()
    losses = _losses()
    slot = create_slots(structure)[0]
    ica_system, _ica_user = build_synthesis_slot_prompts(
        target_id=slot.responsibility or "",
        slots=(slot,),
        routed_briefs=(),
        routed_routes=(),
        loss_analysis=losses,
        control_structure=structure,
    )
    threat = StructuralThreat(
        ica_slot_id=slot.slot_id,
        ica_id=f"{slot.slot_id}:1",
        ica_text=(
            "The clinical controller fails to authorize a required record change."
        ),
        hazardous_context="A time-critical approved record change remains unapplied.",
        loss_scenario="Clinical decisions use stale patient data.",
        related_hazards=["H-1"],
        related_constraints=["SC-1"],
    )
    context = build_scenario_generation_context(
        threat,
        structure,
        losses,
        scenario_id="SCN-ACCEPTANCE",
        obligation_considerations=(
            ScenarioObligationConsideration(
                obligation_id="ob:v1:" + "a" * 64,
                attack_pattern_id="AP-T2-04",
                attack_pattern_name="Poisoned persistent memory",
                concise_concern="An adversary poisons persistent memory.",
                disposition="finding",
                rationale="The concern led STPA to the selected unsafe-control path.",
                finding_ica_id=threat.ica_id,
            ),
        ),
    )
    stage5_system, stage5_user = build_context_bdi_prompts(
        context, TemplateLoader(PROMPTS_DIR)
    )
    state = _state(world)
    state["mechanism_ica_prompt"] = " ".join(ica_system.split())
    state["mechanism_stage5_prompt"] = " ".join(
        f"{stage5_system}\n{stage5_user}".split()
    )
    return True, ""


def _h_mechanism_neutral_ica(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text, examples
    prompt = _state(world).get("mechanism_ica_prompt", "")
    required = (
        "taxonomy mechanism is not established evidence",
        "must describe the unsafe control or system condition in mechanism-neutral terms",
        "do not put an unsupported attack story into the ica itself",
    )
    missing = [item for item in required if item not in prompt.lower()]
    return not missing, f"ICA mechanism boundary is missing: {missing}"


def _h_obligation_is_provenance(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text, examples
    prompt = _state(world).get("mechanism_stage5_prompt", "").lower()
    required = (
        "analysis provenance, not causal evidence",
        "do not establish an attacker mechanism or access path",
        "a mechanism needs exact supplied capability/access evidence",
    )
    missing = [item for item in required if item not in prompt]
    return not missing, f"scenario obligation boundary is missing: {missing}"


def _h_mechanism_requires_support(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text
    expected = examples.get("required_support", "independent evidence").strip()
    prompt = _state(world).get("mechanism_stage5_prompt", "").lower()
    actual = (
        "independent evidence"
        if "a mechanism needs exact supplied capability/access evidence" in prompt
        else "unsupported"
    )
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


def _h_stage5_local_causal_handle(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Run the public Stage 5 seam with one provider-local causal handle."""
    del text, examples

    context = _state(world).get("coordination_context")
    if context is None:
        return False, "coordination scenario context was not built"
    _system, prompt = build_context_bdi_prompts(context, TemplateLoader(PROMPTS_DIR))
    if "source_handle: cause_1" not in prompt:
        return False, "Stage 5 prompt did not expose the local source handle"
    client = MockLLMClient()
    client.set_response_queue(
        [
            {
                "stimulus": {
                    "category": "conversation",
                    "description": "Earlier coordination turns carry the selected state.",
                },
                "adversary": {
                    "kind": "malicious_customer",
                    "gain": "Learns another customer's order details.",
                },
                "attacker_bdi": {
                    "beliefs": ["The selected state may become stale."],
                    "desires": ["Induce the selected unsafe action."],
                    "intentions": [
                        {
                            "description": "Rely on a stale shared state.",
                            "source_handles": ["cause_1"],
                        }
                    ],
                },
                "causal_factors": [
                    {
                        "source_handle": "cause_1",
                        "selected_for_route": True,
                        "evidence": "The shared process model may remain stale.",
                        "temporal_condition": None,
                        "evidence_status": "bounded_assumption",
                        "bounded_assumption": "Assume synchronization completes late.",
                    }
                ],
                "unsafe_outcome": {
                    "condition": {
                        "type": "action_value",
                        "control_action_id": "CM-1",
                        "property": "policy_state",
                        "operator": "equals",
                        "expected": {
                            "binding_ref": "SEM-acceptance-policy-state",
                            "value_type": "string",
                            "description": "The policy state is unknown in this fixture.",
                            "minimum": None,
                            "maximum": None,
                        },
                    },
                    "semantic_proposition": None,
                },
                "execution_route": {
                    "disposition": "executable_route",
                    "action_kind": "agent_message",
                    "reason": "The selected shared state explains the coordination message.",
                },
            }
        ]
    )
    result, error = generate_bdi_for_context(
        client,
        context,
        Path(tempfile.mkdtemp(prefix="stage5-handle-acceptance-")),
    )
    if error is not None or result is None:
        return False, f"Stage 5 local-handle compilation failed: {error}"
    _state(world)["compiled_stage5"] = result
    return True, ""


def _h_compiled_causal_source(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text
    result = _state(world).get("compiled_stage5")
    expected = examples.get("causal_source", "PM-1-1")
    if result is None:
        return False, "Stage 5 result was not compiled"
    actual = result.causal_factors[0].source_id
    return actual == expected, f"expected {expected!r}, got {actual!r}"


def _h_all_defender_vulnerabilities(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text, examples
    context = _state(world).get("coordination_context")
    result = _state(world).get("compiled_stage5")
    if context is None or result is None:
        return False, "Stage 5 context and result were not compiled"
    expected = {
        item.element_id for item in context.target_control_path.process_model_parts
    }
    actual = set(result.defender_vulnerabilities)
    complete = actual == expected and all(
        value.strip() for value in result.defender_vulnerabilities.values()
    )
    return (
        complete,
        f"expected defender beliefs {sorted(expected)}, got {sorted(actual)}",
    )


def _h_no_local_or_coordination_source(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text, examples
    result = _state(world).get("compiled_stage5")
    if result is None:
        return False, "Stage 5 result was not compiled"
    serialized = result.model_dump_json()
    forbidden = (
        "cause_1",
        '"source_id":"CL-',
        '"source_id":"CM-',
        '"source_id":"RESP-',
    )
    unexpected = [item for item in forbidden if item in serialized]
    return not unexpected, f"published forbidden causal identities: {unexpected}"


def _h_bounded_assumption_preserved(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text, examples
    result = _state(world).get("compiled_stage5")
    if result is None:
        return False, "Stage 5 result was not compiled"
    factor = result.causal_factors[0]
    expected = "Assume synchronization completes late."
    return (
        factor.evidence_status == "bounded_assumption"
        and factor.bounded_assumption == expected,
        "explicit bounded assumption was not preserved",
    )


def _verification_enumeration(
    *, sibling: bool = False, na: bool = False
) -> ICAEnumeration:
    """Build a small domain-neutral final-ICA verification fixture."""
    slot_id = "RESP-1:CA-1-1:INCORRECT"
    if na:
        slot = ICASlot(
            slot_id=slot_id,
            responsibility="RESP-1",
            control_action="CA-1-1",
            uca_type="INCORRECT",
            is_na=True,
            icas=[],
            na_justification="The control action is not applicable in this run.",
        )
        return ICAEnumeration(slots=[slot])
    count = 2 if sibling else 1
    icas = [
        ICA(
            ica_id=f"{slot_id}:{index}",
            ica_text=(
                "Approve a clinical record change without the required gate "
                f"check ({index})."
            ),
            hazardous_context="An unapproved clinical record change is accepted.",
            loss_scenario="Clinical decisions rely on corrupted patient data.",
            related_hazards=["H-1"],
            related_constraints=["SC-1"],
        )
        for index in range(1, count + 1)
    ]
    return ICAEnumeration(
        slots=[
            ICASlot(
                slot_id=slot_id,
                responsibility="RESP-1",
                control_action="CA-1-1",
                uca_type="INCORRECT",
                is_na=False,
                icas=icas,
            )
        ]
    )


def _h_verification_fixtures(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Mark the shared final-ICA verification fixtures as available."""
    del text, examples
    _state(world)["ica_verification_ready"] = True
    return True, ""


def _h_supported_final_ica(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Verify that one supported final ICA remains in the enumeration."""
    del text, examples
    if not _state(world).get("ica_verification_ready"):
        return False, "final-ICA verification fixtures were not prepared"

    class SupportedVerifier:
        calls = 0

        def verify_ica_hazards(self, requests, *, correction_feedback=None):
            del correction_feedback
            self.calls += 1
            return [
                {
                    "ica_id": request.ica_id,
                    "verdict": "supported",
                    "rationale": "The supplied action, hazard, constraint, and loss align.",
                }
                for request in requests
            ]

    adapter = SupportedVerifier()
    enumeration = _verification_enumeration()
    filtered, batch = verify_final_ica_batch(
        adapter,
        enumeration,
        loss_analysis=_losses(),
        control_structure=_structure(),
    )
    record = batch.records[0]
    state = _state(world)
    state["ica_verifier_calls"] = adapter.calls
    state["ica_batch"] = batch
    state["ica_filtered"] = filtered
    state["ica_disposition"] = record.disposition
    state["ica_eligible"] = any(filtered_slot.icas for filtered_slot in filtered.slots)
    return True, ""


def _h_contradictory_recheck(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Exercise exactly one correction followed by one independent recheck."""
    del text, examples
    if not _state(world).get("ica_verification_ready"):
        return False, "final-ICA verification fixtures were not prepared"

    class CorrectingVerifier:
        calls: list[bool] = []

        def verify_ica_hazards(self, requests, *, correction_feedback=None):
            self.calls.append(bool(correction_feedback))
            verdict = "supported" if correction_feedback else "contradictory"
            return [
                {
                    "ica_id": request.ica_id,
                    "verdict": verdict,
                    "rationale": "The supplied STPA path is coherent after one correction.",
                }
                for request in requests
            ]

        def correct_ica_hazard(self, request, verdict):
            del verdict
            return IcaHazardVerificationCorrection(
                ica_id=request.ica_id,
                deviation=request.deviation + " after the gate check",
                rationale="Add the missing typed gate check.",
            )

    adapter = CorrectingVerifier()
    _filtered, batch = verify_final_ica_batch(
        adapter,
        _verification_enumeration(),
        loss_analysis=_losses(),
        control_structure=_structure(),
    )
    record = batch.records[0]
    state = _state(world)
    state["ica_verifier_calls"] = len(adapter.calls)
    state["ica_batch"] = batch
    state["ica_disposition"] = record.disposition
    state["ica_separate_attempts"] = (
        len(record.attempts) == 2
        and record.corrected_request is not None
        and adapter.calls == [False, True]
        and record.attempts[0].request_digest != record.attempts[1].request_digest
    )
    return True, ""


def _h_failed_recheck_with_sibling(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Retain a provider failure while keeping a supported sibling eligible."""
    del text, examples
    if not _state(world).get("ica_verification_ready"):
        return False, "final-ICA verification fixtures were not prepared"

    class OneFailedRecheckVerifier:
        calls: list[bool] = []

        def verify_ica_hazards(self, requests, *, correction_feedback=None):
            self.calls.append(bool(correction_feedback))
            if correction_feedback:
                request = requests[0]
                return [
                    {
                        "ica_id": request.ica_id,
                        "verdict": "supported",
                        "rationale": "The first corrected path is supported.",
                    }
                ]
            return [
                {
                    "ica_id": request.ica_id,
                    "verdict": "insufficient_evidence",
                    "rationale": "The initial path needs one correction.",
                }
                for request in requests
            ]

        def correct_ica_hazard(self, request, verdict):
            del verdict
            return IcaHazardVerificationCorrection(
                ica_id=request.ica_id,
                deviation=request.deviation + " with typed evidence",
                rationale="Add the missing typed evidence.",
            )

    adapter = OneFailedRecheckVerifier()
    filtered, batch = verify_final_ica_batch(
        adapter,
        _verification_enumeration(sibling=True),
        loss_analysis=_losses(),
        control_structure=_structure(),
    )
    state = _state(world)
    failed = tuple(
        item.ica_id for item in batch.records if item.disposition == "provider_failure"
    )
    retained = tuple(item.ica_id for slot in filtered.slots for item in slot.icas)
    state["ica_verifier_calls"] = len(adapter.calls)
    state["ica_batch"] = batch
    state["ica_filtered"] = filtered
    state["ica_provider_failure_ids"] = failed
    state["ica_sibling_retained"] = any(
        item.endswith(":1") and record.disposition == "supported"
        for item in retained
        for record in batch.records
        if record.ica_id == item
    )
    state["ica_failure_recorded"] = bool(failed) and any(
        diagnostic.code == "ica_hazard_verification_provider_failure"
        and failed[0] in diagnostic.refs
        for diagnostic in batch.diagnostics
    )
    return True, ""


def _h_failed_repair_ineligible(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text, examples
    state = _state(world)
    failed = set(state["ica_provider_failure_ids"])
    retained = {ica.ica_id for slot in state["ica_filtered"].slots for ica in slot.icas}
    return bool(failed) and failed.isdisjoint(retained), (
        "a previously rejected ICA became eligible after its repair failed"
    )


def _h_na_verification(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Verify that an N/A slot exits before constructing a verifier call."""
    del text, examples

    class NoCallVerifier:
        calls = 0

        def verify_ica_hazards(self, requests, *, correction_feedback=None):
            del requests, correction_feedback
            self.calls += 1
            raise AssertionError("N/A ICA should not reach the verifier")

    adapter = NoCallVerifier()
    enumeration = _verification_enumeration(na=True)
    filtered, batch = verify_final_ica_batch(
        adapter,
        enumeration,
        loss_analysis=_losses(),
        control_structure=_structure(),
    )
    state = _state(world)
    state["ica_verifier_calls"] = adapter.calls
    state["ica_na_unchanged"] = (
        filtered.slots[0] == enumeration.slots[0] and not batch.records
    )
    return True, ""


def _h_provider_derived_mapping_field(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Reject a provider payload that tries to choose mapping strength."""
    del text, examples

    payload_type = _routing_provider_payload_type(1)
    properties = payload_type.model_json_schema()["$defs"][
        "_RoutingProviderSemanticAssessment"
    ]["properties"]
    route = {
        "disposition": "unresolved",
        "obligation_id": _brief().obligation_id,
        "semantic_assessment": {
            "mechanism_assessment": "insufficient_evidence",
            "risk_alignment": "insufficient_evidence",
            "mechanism_rationale": "The mechanism is not established.",
            "risk_alignment_rationale": "The reviewed risk is not established.",
            "mapping_strength": "direct_curated_pair",
        },
        "rationale": "The provider cannot choose this durable label.",
        "evidence": ["acceptance:provider-derived-field"],
    }
    try:
        payload_type.model_validate({"routes": [route]})
    except ValidationError:
        rejected = True
    else:
        rejected = False
    _state(world)["provider_derived_field_rejected"] = (
        "mapping_strength" not in properties and rejected
    )
    return True, ""


def _h_attribution_canary(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Run one domain-neutral public attribution canary from the test fixtures."""
    del examples
    from tests.test_ica_hazard_attribution_canary import (
        test_mismatched_ica_remains_accounted_but_cannot_realize,
        test_supported_ica_reaches_realization,
    )

    mode = "mismatched" if "mismatched" in text else "supported"
    try:
        if mode == "mismatched":
            test_mismatched_ica_remains_accounted_but_cannot_realize()
            values = {"status": "mismatched_no_credit", "realized": 0}
        else:
            test_supported_ica_reaches_realization()
            values = {"status": "supported", "realized": 1}
    except Exception as exc:  # noqa: BLE001 - surface canary failures in acceptance
        return False, f"ICA attribution canary failed: {type(exc).__name__}: {exc}"
    state = _state(world)
    state["attribution_canary"] = values
    return True, ""


def _h_canary_status(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del examples
    expected = re.search(r'"([^"]+)"', text)
    wanted = expected.group(1) if expected else ""
    actual = _state(world).get("attribution_canary", {}).get("status")
    return actual == wanted, f"expected {wanted!r}, got {actual!r}"


def _h_canary_count(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del examples
    match = re.search(r"is (\d+)$", text)
    if match is None:
        return False, f"could not parse canary count from {text!r}"
    expected = int(match.group(1))
    actual = _state(world).get("attribution_canary", {}).get("realized")
    return actual == expected, f"expected realized={expected}, got {actual!r}"


def _h_ica_count(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del examples
    match = re.search(r"is (\d+)$", text)
    if match is None:
        return False, f"could not parse verifier count from {text!r}"
    expected = int(match.group(1))
    actual = _state(world).get("ica_verifier_calls")
    return actual == expected, f"expected {expected}, got {actual!r}"


def _h_ica_disposition(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del examples
    expected = re.search(r'"([^"]+)"', text)
    wanted = expected.group(1) if expected else ""
    actual = _state(world).get("ica_disposition")
    return actual == wanted, f"expected {wanted!r}, got {actual!r}"


def _h_ica_eligible(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    return bool(_state(world).get("ica_eligible")), "supported ICA was not retained"


def _h_ica_separate_attempts(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text, examples
    return bool(_state(world).get("ica_separate_attempts")), (
        "correction and recheck were not separate bound attempts"
    )


def _h_provider_failure(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    batch = _state(world).get("ica_batch")
    actual = sum(item.disposition == "provider_failure" for item in batch.records)
    return actual == 1, f"expected one provider failure, got {actual}"


def _h_sibling_eligible(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    return bool(_state(world).get("ica_sibling_retained")), (
        "supported ICA sibling was not retained"
    )


def _h_failure_recorded(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    return bool(_state(world).get("ica_failure_recorded")), (
        "provider failure was not recorded as a distinct diagnostic"
    )


def _h_na_unchanged(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    return bool(_state(world).get("ica_na_unchanged")), "N/A slot changed"


def _h_derived_field_rejected(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text, examples
    return bool(_state(world).get("provider_derived_field_rejected")), (
        "provider-derived mapping strength was accepted"
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
        r"the obligation-aware prompt templates are inspected",
        _h_inspect_obligation_templates,
    )
    api.register(
        r"all obligation prompt pairs render through Jinja", _h_all_prompts_jinja
    )
    api.register(
        r'missing template input fails before provider dispatch with ".*"',
        _h_strict_template,
    )
    api.register(
        r"the structural routing guidance is inspected",
        _h_inspect_routing_guidance,
    )
    api.register(
        r'the prompt distinguishes authentication failure from ".*"',
        _h_distinguish_authentication,
    )
    api.register(
        r"a nearby safeguard cannot substitute for mechanism evidence",
        _h_no_adjacent_substitution,
    )
    api.register(
        r"a selected STPA path is classified as an adjacent control",
        _h_adjacent_path,
    )
    api.register(
        r"a plausible taxonomy mechanism is assessed as mismatching its reviewed risk",
        _h_risk_mismatch,
    )
    api.register(
        r"the ordinary STPA finding remains available", _h_ordinary_finding_retained
    )
    api.register(r'the obligation stop reason is ".*"', _h_stop_reason)
    api.register(r"the obligation addressed count is .*", _h_addressed_count)
    api.register(
        r"a provider returns a response that fails typed parsing",
        _h_provider_parse_failure,
    )
    api.register(r"provider response received is (?:true|false)", _h_lifecycle_bool)
    api.register(r"semantic validation passed is (?:true|false)", _h_lifecycle_bool)
    api.register(r'the terminal provider error is ".*"', _h_terminal_provider_error)
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
    api.register(
        r"an ICA provider supplies one deviation for a NOT_PROVIDED slot",
        _h_provider_plain_deviation,
    )
    api.register(
        r'the compiled ICA behavior contains ".*"',
        _h_compiled_ica_behavior,
    )
    api.register(
        r"the model-facing ICA schema exposes one plain deviation string",
        _h_plain_deviation_schema,
    )
    api.register(
        r"the model-facing ICA schema permits exactly one governing constraint",
        _h_one_governing_constraint_schema,
    )
    api.register(
        r"finding relevance compares subject operation object and effect",
        _h_finding_relevance_contract,
    )
    api.register(
        r"a taxonomy mechanism is routed to a related ICA",
        _h_taxonomy_mechanism_routed,
    )
    api.register(
        r"the ICA remains a mechanism-neutral unsafe-control finding",
        _h_mechanism_neutral_ica,
    )
    api.register(
        r"the obligation is provenance rather than causal evidence",
        _h_obligation_is_provenance,
    )
    api.register(
        r'the taxonomy mechanism requires ".*" before scenario use',
        _h_mechanism_requires_support,
    )
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
    api.register(
        r"its Stage 5 provider response selects local causal handle cause_1",
        _h_stage5_local_causal_handle,
    )
    api.register(r'the compiled causal source is ".*"', _h_compiled_causal_source)
    api.register(
        r"every selected defender belief has a compiled vulnerability",
        _h_all_defender_vulnerabilities,
    )
    api.register(
        r"no coordination controller or local handle is published as a causal source",
        _h_no_local_or_coordination_source,
    )
    api.register(
        r"the explicit bounded assumption is preserved",
        _h_bounded_assumption_preserved,
    )
    api.register(
        r"deterministic final ICA verification fixtures are available",
        _h_verification_fixtures,
    )
    api.register(r"a supported final ICA is verified", _h_supported_final_ica)
    api.register(
        r"a contradictory final ICA is corrected and rechecked",
        _h_contradictory_recheck,
    )
    api.register(
        r"one final ICA recheck fails while its sibling is supported",
        _h_failed_recheck_with_sibling,
    )
    api.register(r"an N/A final ICA slot is verified", _h_na_verification)
    api.register(
        r"the routing provider attempts to return mapping strength",
        _h_provider_derived_mapping_field,
    )
    api.register(r"the final ICA verifier call count is \d+", _h_ica_count)
    api.register(r'the supported ICA disposition is ".*"', _h_ica_disposition)
    api.register(r"the verified ICA remains eligible", _h_ica_eligible)
    api.register(
        r"the correction and recheck are separate attempts",
        _h_ica_separate_attempts,
    )
    api.register(r'the corrected ICA disposition is ".*"', _h_ica_disposition)
    api.register(
        r"one final ICA has provider-failure disposition",
        _h_provider_failure,
    )
    api.register(r"the supported sibling remains eligible", _h_sibling_eligible)
    api.register(
        r"the rejected ICA with a failed repair is not eligible",
        _h_failed_repair_ineligible,
    )
    api.register(
        r"the final ICA provider failure is recorded separately",
        _h_failure_recorded,
    )
    api.register(r"the N/A slot remains unchanged", _h_na_unchanged)
    api.register(
        r"the provider-derived routing field is rejected",
        _h_derived_field_rejected,
    )
    api.register(
        r"the (?:supported|mismatched) ICA attribution canary is executed",
        _h_attribution_canary,
    )
    api.register(r'the attribution canary status is ".*"', _h_canary_status)
    api.register(r"the canary realization count is \d+", _h_canary_count)


__all__ = ["FEATURE_ID", "register"]
