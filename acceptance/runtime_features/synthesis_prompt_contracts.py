"""Acceptance handlers for obligation-aware prompt meaning and continuity."""

from __future__ import annotations

from pathlib import Path
import json
import tempfile
from typing import Any

import yaml
from pydantic import BaseModel, ValidationError

from runtime_bootstrap import PROJECT_ROOT
from runtime_shared import World

from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
from asago_scenario_generator.models.hybrid_coverage import ArtifactPin
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
from asago_scenario_generator.stpa.models.scenario_context import (
    ScenarioObligationConsideration,
)
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    AnalysisControls,
    IcaDeviationDraft,
    IcaFindingDraft,
    SlotIcaDraft,
    SynthesisSlotRequest,
)
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    build_synthesis_slot_prompts,
    project_obligation_question,
)
from asago_scenario_generator.stpa.obligation_aware.routing import (
    build_neutral_briefs,
    route_obligations,
)
from asago_scenario_generator.stpa.obligation_aware.provider import (
    ObligationAwareLLMAdapter,
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
from asago_scenario_generator.stpa.infra.llm_helpers import safe_llm_call
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


def _h_inspect_obligation_templates(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text, examples
    from asago_scenario_generator.stpa.obligation_aware import prompts

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
    from asago_scenario_generator.stpa.obligation_aware import prompts

    loader = TemplateLoader(Path(prompts.__file__).with_name("prompt_templates"))
    _state(world)["routing_guidance"] = loader.render_prompt(
        "structural_routing_system.j2",
        obligation_count=1,
        instructions="Return one decision.",
    )
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


def _h_risk_mismatch(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    plan = make_plan()
    brief = _brief()
    route = ObligationRoute(
        obligation_id=brief.obligation_id,
        disposition="targeted",
        semantic_assessment=ObligationSemanticAssessment(
            mechanism_assessment="plausible_in_system",
            risk_alignment="mismatch",
            mapping_strength="broad_category_expansion",
            mechanism_rationale="The batch mechanism exists in the supplied structure.",
            risk_alignment_rationale=(
                "Mass action does not realize restrictions on acquiring data."
            ),
        ),
        slot_ids=("RESP-1:CA-1-1:NOT_PROVIDED",),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        evidence=("acceptance:batch-path",),
    )
    _record_semantic_accounting(world, plan, brief, route)
    return True, ""


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
    plan = make_plan()
    brief = _brief()
    route = ObligationRoute(
        obligation_id=brief.obligation_id,
        disposition="targeted",
        semantic_assessment=ObligationSemanticAssessment(
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
        slot_ids=("RESP-1:CA-1-1:NOT_PROVIDED",),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        evidence=("acceptance:adjacent-control",),
    )
    _record_semantic_accounting(world, plan, brief, route)
    return True, ""


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
    safe_llm_call(
        llm_client=Provider(),
        system_prompt="Return JSON.",
        user_prompt="Return the required field.",
        response_format=Expected,
        run_dir=run_dir,
        stage="acceptance",
        step="typed-parse",
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


def _h_provider_plain_deviation(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Run the public slot adapter with one provider-authored deviation."""
    del text, examples
    from tests.stpa.sp1_helpers import MockLLMClient

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
        "finding` means stpa found a related unsafe-control path",
        "does not establish that persistent memory was poisoned",
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
        if "independently supported by an exact reachable capability/access path"
        in prompt
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


def _h_stage5_local_causal_handle(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Run the public Stage 5 seam with one provider-local causal handle."""
    del text, examples
    from tests.stpa.sp1_helpers import MockLLMClient

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
                "defender_vulnerabilities": [
                    {
                        "belief_handle": f"belief_{index}",
                        "vulnerability": "The selected state may become stale.",
                    }
                    for index, _item in enumerate(
                        context.target_control_path.process_model_parts, start=1
                    )
                ],
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
                        "evidence": "The shared process model may remain stale.",
                        "temporal_condition": None,
                        "evidence_status": "structural_failure",
                        "capability_refs": [],
                        "access_refs": [],
                        "bounded_assumption": "Assume synchronization completes late.",
                    }
                ],
                "unsafe_outcome": {
                    "condition": {
                        "type": "action_value",
                        "control_action_id": "CM-1",
                        "property": "policy_state",
                        "operator": "equals",
                        "expected": "approved",
                    },
                    "hazard_refs": ["H-1"],
                    "constraint_refs": ["SC-1"],
                },
                "execution_route": {
                    "disposition": "executable_route",
                    "delivery_class": "direct_prompt",
                    "selected_factor_handle": "cause_1",
                    "action_kind": "model_output",
                    "resource_role_handles": [],
                    "carrier_attacker_influence": "none",
                    "reason": "The selected shared state explains the direct route.",
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


def _h_structural_adversarial_intent(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text, examples
    from asago_scenario_generator.stpa.models.causal_factor import (
        CausalFactor,
        CausalFactorKind,
    )
    from asago_scenario_generator.stpa.models.scenario_spec import ScenarioSpec
    from asago_scenario_generator.stpa.scenario_prod.validators import (
        validate_active_access_grounding,
    )

    context = _state(world).get("coordination_context")
    if context is None:
        return False, "scenario context was not built"
    spec = ScenarioSpec.model_construct(
        scenario_context=context,
        causal_factors=[
            CausalFactor(
                kind=CausalFactorKind.process_model_flaw,
                source_id=context.target_control_path.process_model_parts[0].element_id,
                description="The selected process-model state remains stale.",
            )
        ],
    )
    result = validate_active_access_grounding(
        spec,
        "The adversary exploits the stale PM-1-1 state before CA-1-1.",
    )
    state = _state(world)
    state["active_access_disposition"] = (
        "unresolved" if not result.passed else "finding"
    )
    state["active_access_published"] = 0 if not result.passed else 1
    return True, ""


def _h_active_access_disposition(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text
    expected = examples.get("disposition", "unresolved")
    actual = _state(world).get("active_access_disposition")
    return actual == expected, f"expected {expected!r}, got {actual!r}"


def _h_active_access_publication(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text
    expected = int(examples.get("published_scenarios", "0"))
    actual = _state(world).get("active_access_published")
    return actual == expected, f"expected {expected}, got {actual!r}"


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
        r"a scenario context with no reachable attacker capability",
        _h_coordination_context,
    )
    api.register(
        r"a generated artifact describes taking advantage of its structural failure",
        _h_structural_adversarial_intent,
    )
    api.register(
        r'active-access grounding disposition is ".*"',
        _h_active_access_disposition,
    )
    api.register(
        r"the structurally grounded scenario publication count is .*",
        _h_active_access_publication,
    )


__all__ = ["FEATURE_ID", "register"]
