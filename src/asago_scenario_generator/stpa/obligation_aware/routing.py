"""Neutral-brief construction and deterministic structural routing."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import inspect
from typing import Any, Literal

from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
from asago_scenario_generator.models.canonical import compute_framed_digest
from asago_scenario_generator.models.obligation_consideration import (
    ConsiderationCallEvidence,
    ConsiderationDiagnostic,
    NeutralObligationBrief,
    ObligationRoute,
)
from asago_scenario_generator.models.obligation_plan import (
    TaxonomyObligation,
    TaxonomyObligationPlan,
)
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.infra.prompt_preflight import (
    PromptBudget,
    PromptBudgetExceeded,
    resolve_adapter_prompt_budget,
)
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    AnalysisControls,
    StructuralAnalysisAdapter,
    StructuralRoutingRequest,
    StructuralRoutingResponse,
)
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    authoritative_hazard_constraint_pairs,
    build_structural_routing_prompts,
)
from asago_scenario_generator.stpa.threat_enum.slot_creation import (
    SlotPlaceholder,
    create_slots,
)


ROUTING_RESPONSE_DIGEST_DOMAIN = (
    "asago-scenario-generator:stpa-obligation-routing-response:v1"
)
_ROUTING_RETRY_ERROR_MAX_CHARS = 1024
_ROUTING_MAX_COMPLETION_TOKENS = 8192


def _routing_prompt_budget(
    adapter: Any,
    controls: AnalysisControls,
) -> PromptBudget | None:
    """Resolve a routing budget from explicit controls or an adapter client."""
    return resolve_adapter_prompt_budget(
        adapter,
        controls,
        maximum_completion_tokens=_ROUTING_MAX_COMPLETION_TOKENS,
    )


def _budgeted_obligation_batches(
    briefs: Sequence[NeutralObligationBrief],
    *,
    max_batch_size: int,
    budget: PromptBudget | None,
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
    slots: Sequence[SlotPlaceholder],
) -> tuple[tuple[NeutralObligationBrief, ...], ...]:
    """Split routing batches by rendered compact prompt size, preserving order."""
    ordered = tuple(sorted(briefs, key=lambda item: item.obligation_id))
    if budget is None:
        return create_obligation_batches(ordered, max_batch_size)
    batches: list[tuple[NeutralObligationBrief, ...]] = []
    current: list[NeutralObligationBrief] = []

    def fits(values: Sequence[NeutralObligationBrief]) -> bool:
        system, user = build_structural_routing_prompts(
            briefs=values,
            loss_analysis=loss_analysis,
            control_structure=control_structure,
            slots=slots,
        )
        return budget.count(f"{system}\n{user}") <= budget.usable_input_tokens

    for brief in ordered:
        if len(current) >= max_batch_size:
            batches.append(tuple(current))
            current = []
        candidate = (*current, brief)
        if current and not fits(candidate):
            batches.append(tuple(current))
            current = [brief]
        else:
            current = list(candidate)
    if current:
        batches.append(tuple(current))
    return tuple(batches)


def _catalog_map(
    attack_pattern_catalog: Sequence[AttackPattern] | Mapping[str, AttackPattern],
) -> dict[str, AttackPattern]:
    """Index a typed attack-pattern catalog by exact pattern identity."""
    values = (
        attack_pattern_catalog.values()
        if isinstance(attack_pattern_catalog, Mapping)
        else attack_pattern_catalog
    )
    result: dict[str, AttackPattern] = {}
    for pattern in values:
        if not isinstance(pattern, AttackPattern):
            raise TypeError("attack_pattern_catalog must contain AttackPattern values")
        if pattern.id in result:
            raise ValueError(
                f"attack pattern catalog contains duplicate id {pattern.id}"
            )
        result[pattern.id] = pattern
    return result


def _resource_references(row: TaxonomyObligation) -> tuple[Any, ...]:
    """Copy exact typed resource identities without copying candidate records."""
    references: dict[str, Any] = {}
    for candidate in row.candidate_records:
        for binding in candidate.resource_bindings:
            reference = binding.resource_ref
            references[reference.model_dump_json()] = reference
    return tuple(references[key] for key in sorted(references))


def build_neutral_brief(
    plan: TaxonomyObligationPlan,
    row: TaxonomyObligation,
    pattern: AttackPattern,
) -> NeutralObligationBrief:
    """Build one neutral STPA question from one applicable Phase 1 row.

    The brief intentionally contains no canonical chain steps and no
    candidate projection.  Qualification is copied, not used as a filter.
    """
    if not isinstance(plan, TaxonomyObligationPlan):
        raise TypeError("plan must be a TaxonomyObligationPlan")
    if not isinstance(row, TaxonomyObligation):
        raise TypeError("row must be a TaxonomyObligation")
    if row.scope_disposition != "applicable":
        raise ValueError("neutral briefs may only be built for applicable rows")
    if row.attack_pattern_id != pattern.id:
        raise ValueError("brief pattern does not match the obligation row")
    if row.attack_pattern_semantic_digest != pattern.canonical_chain.semantic_digest:
        raise ValueError("brief pattern digest does not match the obligation row")
    return NeutralObligationBrief(
        obligation_id=row.obligation_id,
        risk_ref=row.risk_ref,
        attack_pattern_id=pattern.id,
        attack_pattern_name=pattern.name,
        attack_pattern_description=pattern.description,
        attack_pattern_semantic_digest=pattern.canonical_chain.semantic_digest,
        taxonomy_chain=row.taxonomy_chain,
        prerequisite_capabilities=pattern.prerequisite_capabilities,
        qualification_disposition=row.qualification_disposition,
        applicability_evidence=row.evidence,
        resource_references=_resource_references(row),
        candidate_ids=tuple(item.candidate_id for item in row.candidate_records),
        plan_digest=plan.semantic_digest,
        catalog_pins=plan.catalog_pins,
        mapping_pins=plan.mapping_pins,
    )


def build_neutral_briefs(
    plan: TaxonomyObligationPlan,
    attack_pattern_catalog: Sequence[AttackPattern] | Mapping[str, AttackPattern],
) -> tuple[NeutralObligationBrief, ...]:
    """Build one brief for every applicable obligation in canonical order."""
    if not isinstance(plan, TaxonomyObligationPlan):
        raise TypeError("plan must be a TaxonomyObligationPlan")
    plan.assert_integrity()
    catalog = _catalog_map(attack_pattern_catalog)
    briefs: list[NeutralObligationBrief] = []
    for row in plan.obligations:
        if row.scope_disposition != "applicable":
            continue
        if row.attack_pattern_id is None:
            raise ValueError(
                f"applicable obligation {row.obligation_id} has no pattern"
            )
        pattern = catalog.get(row.attack_pattern_id)
        if pattern is None:
            raise ValueError(
                f"applicable obligation {row.obligation_id} has no catalog pattern"
            )
        briefs.append(build_neutral_brief(plan, row, pattern))
    return tuple(sorted(briefs, key=lambda item: item.obligation_id))


def create_obligation_batches(
    briefs: Sequence[NeutralObligationBrief],
    max_batch_size: int,
) -> tuple[tuple[NeutralObligationBrief, ...], ...]:
    """Partition briefs into stable, canonical batches."""
    if type(max_batch_size) is not int:
        raise TypeError("max_batch_size must be an integer")
    if max_batch_size <= 0:
        raise ValueError("max_batch_size must be positive")
    ordered = tuple(sorted(briefs, key=lambda item: item.obligation_id))
    if any(not isinstance(item, NeutralObligationBrief) for item in ordered):
        raise TypeError("briefs must contain NeutralObligationBrief values")
    ids = tuple(item.obligation_id for item in ordered)
    if len(ids) != len(set(ids)):
        raise ValueError("briefs must contain unique obligation IDs")
    return tuple(
        tuple(ordered[index : index + max_batch_size])
        for index in range(0, len(ordered), max_batch_size)
    )


def _default_controls(
    controls: AnalysisControls | None,
    max_batch_size: int,
) -> AnalysisControls:
    """Resolve controls without changing the caller's immutable controls."""
    if controls is None:
        return AnalysisControls(
            model_profile="synthesis",
            model_name="caller-supplied",
            deadline_seconds=300.0,
            temperature=0.4,
            max_batch_size=max_batch_size,
        )
    if not isinstance(controls, AnalysisControls):
        raise TypeError("controls must be AnalysisControls")
    if controls.max_batch_size == max_batch_size:
        return controls
    return controls.model_copy(update={"max_batch_size": max_batch_size})


def _slot_inventory(
    control_structure: ControlStructure,
    slots: Sequence[SlotPlaceholder] | None,
) -> tuple[SlotPlaceholder, ...]:
    """Return the deterministic final-structure slot inventory."""
    values = (
        tuple(slots) if slots is not None else tuple(create_slots(control_structure))
    )
    if any(not hasattr(item, "slot_id") for item in values):
        raise TypeError("slots must contain STPA slot models")
    ordered = tuple(sorted(values, key=lambda item: item.slot_id))
    if len({item.slot_id for item in ordered}) != len(ordered):
        raise ValueError("slot inventory contains duplicate slot IDs")
    return ordered


def _reference_sets(
    control_structure: ControlStructure,
    loss_analysis: LossAnalysis,
    slots: Sequence[SlotPlaceholder],
) -> dict[str, set[str]]:
    """Build exact namespaces accepted by structural routing."""
    return {
        "slot": {item.slot_id for item in slots},
        "hazard": {item.hazard_id for item in loss_analysis.hazards},
        "constraint": {
            item.constraint_id for item in loss_analysis.security_constraints
        }
        | {
            item.rc_id
            for responsibility in control_structure.responsibilities
            for item in responsibility.responsibility_constraints
        },
        "controller": {item.resp_id for item in control_structure.responsibilities}
        | {item.link_id for item in control_structure.coordination_links},
        "responsibility": {item.resp_id for item in control_structure.responsibilities},
        "action": {
            item.ca_id
            for responsibility in control_structure.responsibilities
            for item in responsibility.control_actions
        }
        | {
            item.coordination_mechanism.cm_id
            for item in control_structure.coordination_links
        },
        "pm": {
            item.pm_id
            for responsibility in control_structure.responsibilities
            for item in responsibility.process_model_parts
        },
        "fb": {
            item.fb_id
            for responsibility in control_structure.responsibilities
            for item in responsibility.feedback_channels
        },
        "cp": {item.cp_id for item in control_structure.controlled_processes},
        "link": {item.link_id for item in control_structure.coordination_links},
    }


def _validate_route(
    route: ObligationRoute,
    expected_obligation_id: str,
    references: dict[str, set[str]],
    *,
    loss_analysis: LossAnalysis | None = None,
    control_structure: ControlStructure | None = None,
    slots: Sequence[SlotPlaceholder] = (),
) -> None:
    """Reject unknown or structurally incompatible route identities.

    Namespace membership is necessary but not sufficient: a targeted route is
    accepted only when its authoritative slot proves the owner/action/process
    path and the selected hazard/constraint graph proves a loss-preserving
    relationship.  The optional keyword arguments preserve the narrow helper's
    historical call shape for direct tests and compatibility callers.
    """
    if route.obligation_id != expected_obligation_id:
        raise ValueError("routing response contains an unexpected obligation ID")
    fields = (
        ("slot_ids", "slot"),
        ("hazard_ids", "hazard"),
        ("constraint_ids", "constraint"),
        ("controller_ids", "controller"),
        ("responsibility_ids", "responsibility"),
        ("control_action_ids", "action"),
        ("process_model_part_ids", "pm"),
        ("feedback_channel_ids", "fb"),
        ("controlled_process_ids", "cp"),
        ("coordination_link_ids", "link"),
    )
    for field_name, namespace in fields:
        unknown = set(getattr(route, field_name)) - references[namespace]
        if unknown:
            raise ValueError(
                f"route {route.obligation_id} references unknown {namespace} IDs: "
                + ", ".join(sorted(unknown))
            )
    if (
        route.disposition != "targeted"
        or loss_analysis is None
        or control_structure is None
    ):
        return
    _validate_targeted_route(
        route,
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        slots=slots,
    )


def _validate_targeted_route(
    route: ObligationRoute,
    *,
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
    slots: Sequence[SlotPlaceholder],
) -> None:
    """Prove owner/action/process and hazard/loss/constraint relationships."""
    path = _infer_targeted_path(route, control_structure, slots)
    _validate_route_path(route, path)
    _validate_route_hazards(route, loss_analysis)
    _validate_route_constraints(route, loss_analysis)


def _infer_targeted_path(
    route: ObligationRoute,
    control_structure: ControlStructure,
    slots: Sequence[SlotPlaceholder],
) -> tuple[set[str], set[str], set[str], set[str], set[str], set[str], set[str]]:
    """Infer all structural namespaces from the route's selected slots."""
    slot_by_id = {item.slot_id: item for item in slots}
    selected_slots = tuple(slot_by_id[item] for item in route.slot_ids)
    if not selected_slots:
        raise ValueError("targeted route requires a non-empty selected slot path")

    responsibilities = {
        item.resp_id: item for item in control_structure.responsibilities
    }
    processes = {item.cp_id: item for item in control_structure.controlled_processes}
    links = {item.link_id: item for item in control_structure.coordination_links}
    inferred_controllers: set[str] = set()
    inferred_responsibilities: set[str] = set()
    inferred_actions: set[str] = set()
    inferred_processes: set[str] = set()
    inferred_links: set[str] = set()
    inferred_process_models: set[str] = set()
    inferred_feedback: set[str] = set()

    for slot in selected_slots:
        inferred_actions.add(slot.control_action)
        if slot.responsibility is not None:
            responsibility = responsibilities.get(slot.responsibility)
            if responsibility is None:
                raise ValueError(
                    f"slot {slot.slot_id} has unknown owning responsibility "
                    f"{slot.responsibility}"
                )
            action = next(
                (
                    item
                    for item in responsibility.control_actions
                    if item.ca_id == slot.control_action
                ),
                None,
            )
            if action is None:
                raise ValueError(
                    f"slot {slot.slot_id} action {slot.control_action} is not owned "
                    f"by responsibility {slot.responsibility}"
                )
            if (
                action.target is None
                or action.target.type.value != "controlled_process"
            ):
                raise ValueError(
                    f"action {action.ca_id} has no controlled-process target for "
                    "the selected route"
                )
            if action.target.id not in processes:
                raise ValueError(
                    f"action {action.ca_id} targets unknown controlled process "
                    f"{action.target.id}"
                )
            inferred_controllers.add(slot.responsibility)
            inferred_responsibilities.add(slot.responsibility)
            inferred_processes.add(action.target.id)
            inferred_process_models.update(
                item.pm_id for item in responsibility.process_model_parts
            )
            inferred_feedback.update(
                item.fb_id for item in responsibility.feedback_channels
            )
        elif slot.coordination_link is not None:
            link = links.get(slot.coordination_link)
            if link is None:
                raise ValueError(
                    f"slot {slot.slot_id} has unknown coordination link "
                    f"{slot.coordination_link}"
                )
            if link.coordination_mechanism.cm_id != slot.control_action:
                raise ValueError(
                    f"slot {slot.slot_id} action {slot.control_action} is not the "
                    "coordination mechanism for its link"
                )
            # A coordination slot is targeted through the source
            # responsibility that issues the coordination mechanism.  The
            # CL identity is a path reference, not a responsibility/controller
            # identity; keeping it in ``controller_ids`` made valid provider
            # routes such as ``controller_ids=[link.source]`` fail closed.
            inferred_controllers.add(link.source)
            inferred_links.add(link.link_id)
            inferred_responsibilities.update((link.source, link.target))
            inferred_process_models.add(link.shared_pm)
        else:
            raise ValueError(f"slot {slot.slot_id} has no owner or coordination path")

    return (
        inferred_controllers,
        inferred_responsibilities,
        inferred_actions,
        inferred_processes,
        inferred_links,
        inferred_process_models,
        inferred_feedback,
    )


def _validate_route_path(
    route: ObligationRoute,
    path: tuple[set[str], set[str], set[str], set[str], set[str], set[str], set[str]],
) -> None:
    """Check optional route namespaces against the slot-derived path."""
    (
        inferred_controllers,
        inferred_responsibilities,
        inferred_actions,
        inferred_processes,
        inferred_links,
        inferred_process_models,
        inferred_feedback,
    ) = path

    _require_exact_or_empty(
        route.controller_ids,
        inferred_controllers,
        "controller",
    )
    _require_exact_or_empty(
        route.responsibility_ids,
        inferred_responsibilities,
        "responsibility owner",
    )
    _require_exact_or_empty(
        route.control_action_ids, inferred_actions, "control action"
    )
    _require_exact_or_empty(
        route.controlled_process_ids,
        inferred_processes,
        "controlled process",
    )
    _require_exact_or_empty(
        route.coordination_link_ids,
        inferred_links,
        "coordination link",
    )
    if set(route.process_model_part_ids) - inferred_process_models:
        raise ValueError(
            "route process-model references are outside the selected owner/path"
        )
    if set(route.feedback_channel_ids) - inferred_feedback:
        raise ValueError(
            "route feedback references are outside the selected owner/path"
        )


def _validate_route_hazards(
    route: ObligationRoute,
    loss_analysis: LossAnalysis,
) -> None:
    """Prove each selected hazard retains a known loss relationship."""
    hazards = {item.hazard_id: item for item in loss_analysis.hazards}
    losses = {
        item.loss_id: item
        for item in (*loss_analysis.risk_card_losses, *loss_analysis.use_case_losses)
    }
    selected_hazards = [hazards[item] for item in route.hazard_ids]
    for hazard in selected_hazards:
        if not hazard.related_losses:
            raise ValueError(
                f"hazard {hazard.hazard_id} has no related loss; route cannot "
                "prove the selected loss relationship"
            )
        if any(loss_id not in losses for loss_id in hazard.related_losses):
            raise ValueError(f"hazard {hazard.hazard_id} references an unknown loss")


def _validate_route_constraints(
    route: ObligationRoute,
    loss_analysis: LossAnalysis,
) -> None:
    """Prove selected constraints govern at least one selected hazard."""
    constraints = {
        item.constraint_id: item for item in loss_analysis.security_constraints
    }
    selected_hazard_ids = set(route.hazard_ids)
    for constraint_id in route.constraint_ids:
        constraint = constraints.get(constraint_id)
        if constraint is None:
            raise ValueError(
                f"constraint {constraint_id} is not a security constraint with "
                "hazard relationships"
            )
        governed = selected_hazard_ids.intersection(constraint.related_hazards)
        if not governed:
            allowed_pairs = tuple(
                f"{allowed_constraint_id} -> {allowed_hazard_id}"
                for allowed_constraint_id, allowed_hazard_id in (
                    authoritative_hazard_constraint_pairs(loss_analysis)
                )
                if allowed_constraint_id == constraint_id
            )
            raise ValueError(
                f"constraint {constraint_id} does not govern selected hazard(s) "
                + ", ".join(sorted(selected_hazard_ids))
                + "; allowed hazard/constraint pair(s): "
                + (", ".join(allowed_pairs) if allowed_pairs else "<none>")
            )


def _require_exact_or_empty(
    supplied: Sequence[str],
    inferred: set[str],
    label: str,
) -> None:
    """Validate an optional route namespace against its slot-derived set."""
    if supplied and set(supplied) != inferred:
        raise ValueError(
            f"route {label} references do not match the selected slot path "
            f"(expected={sorted(inferred)}, actual={sorted(supplied)})"
        )


def _request_for_batch(
    batch: Sequence[NeutralObligationBrief],
    *,
    batch_index: int,
    purpose: Literal["initial", "recheck"],
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
    slots: Sequence[SlotPlaceholder],
    controls: AnalysisControls,
) -> StructuralRoutingRequest:
    """Build one content-addressed routing request."""
    return StructuralRoutingRequest(
        batch_id=f"{purpose}-batch-{batch_index + 1}",
        purpose=purpose,
        briefs=tuple(batch),
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        slots=tuple(slots),
        controls=controls,
    )


def _adapter_method(adapter: Any, names: tuple[str, ...]) -> Any:
    """Resolve a named adapter stage while allowing deterministic fakes."""
    for name in names:
        method = getattr(adapter, name, None)
        if callable(method):
            return method
    raise TypeError("structural adapter must provide one of " + ", ".join(names))


def _call_with_optional_feedback(
    method: Any,
    request: Any,
    feedback: str | None,
) -> Any:
    """Pass one bounded schema correction when a fake accepts it."""
    if feedback is None:
        return method(request)
    try:
        parameters = inspect.signature(method).parameters
    except (TypeError, ValueError):
        return method(request)
    if "correction_feedback" in parameters:
        return method(request, correction_feedback=feedback)
    if "feedback" in parameters:
        return method(request, feedback=feedback)
    return method(request)


def _routing_validation_feedback(error: BaseException) -> str:
    """Describe the prior local failure without replaying provider formatting."""
    detail = " ".join(str(error).replace("\r", " ").replace("\n", " ").split())
    if len(detail) > _ROUTING_RETRY_ERROR_MAX_CHARS:
        detail = detail[:_ROUTING_RETRY_ERROR_MAX_CHARS].rstrip() + "..."
    return (
        "The previous response failed local validation. Correct only the invalid "
        "fields using this exact local validation error: "
        f"{type(error).__name__}: {detail}. "
        "Use only the exact typed hazard/constraint pair(s) named by this error; "
        "do not infer pairings from descriptions. "
        "Return exactly one route for every supplied obligation ID and preserve "
        "exact STPA identities."
    )


def _coerce_response(
    raw: Any, request: StructuralRoutingRequest
) -> StructuralRoutingResponse:
    """Normalize typed, mapping, or sequence fake responses."""
    if isinstance(raw, StructuralRoutingResponse):
        return raw
    if isinstance(raw, Mapping):
        return StructuralRoutingResponse.model_validate(raw)
    if isinstance(raw, Sequence) and not isinstance(raw, (str, bytes, bytearray)):
        return StructuralRoutingResponse(
            request_digest=request.semantic_digest,
            routes=tuple(raw),
        )
    raise TypeError("structural adapter returned an unsupported response")


def _call_evidence(
    response: StructuralRoutingResponse,
    request: StructuralRoutingRequest,
    attempts: int,
    *,
    outcome: Literal["accepted", "unresolved", "technical_failure"] = "accepted",
) -> ConsiderationCallEvidence:
    """Build shared call evidence for one routing batch."""
    response_digest = response.response_digest or compute_framed_digest(
        ROUTING_RESPONSE_DIGEST_DOMAIN,
        response.model_dump(mode="json"),
    )
    return ConsiderationCallEvidence(
        call_id=f"stpa-route:{request.batch_id}",
        request_digest=request.semantic_digest,
        response_digest=response_digest,
        model_profile=request.controls.model_profile,
        model_name=request.controls.model_name,
        attempt_count=attempts,
        outcome=outcome,
    )


def _unresolved_routes(
    request: StructuralRoutingRequest,
    error: BaseException,
) -> tuple[ObligationRoute, ...]:
    """Retain every obligation when a batch exhausts bounded validation."""
    detail = f"{type(error).__name__}: {error}"
    diagnostic_code = (
        "prompt_budget_exceeded"
        if isinstance(error, PromptBudgetExceeded)
        else "routing_validation_failed"
    )
    diagnostic = ConsiderationDiagnostic(
        code=diagnostic_code,
        detail=detail,
        obligation_ids=tuple(item.obligation_id for item in request.briefs),
        refs=(request.batch_id,),
    )
    return tuple(
        ObligationRoute(
            obligation_id=brief.obligation_id,
            disposition="unresolved",
            rationale="Structural routing response could not be validated.",
            evidence=("routing-validation",),
            diagnostics=(diagnostic,),
        )
        for brief in request.briefs
    )


@dataclass(frozen=True, slots=True)
class RoutingRunResult:
    """Deterministic result of one initial or recheck routing pass."""

    briefs: tuple[NeutralObligationBrief, ...]
    routes: tuple[ObligationRoute, ...]
    requests: tuple[StructuralRoutingRequest, ...]
    call_evidence: tuple[ConsiderationCallEvidence, ...]
    diagnostics: tuple[str, ...] = ()

    @property
    def initial_routes(self) -> tuple[ObligationRoute, ...]:
        """Compatibility alias for callers naming the first pass."""
        return self.routes

    @property
    def final_routes(self) -> tuple[ObligationRoute, ...]:
        """Compatibility alias for callers naming a complete pass final."""
        return self.routes

    @property
    def rechecked_routes(self) -> tuple[ObligationRoute, ...]:
        """Compatibility alias for callers naming a recheck pass."""
        return self.routes


def _resolve_routing_briefs(
    plan: TaxonomyObligationPlan | None,
    attack_pattern_catalog: Sequence[AttackPattern]
    | Mapping[str, AttackPattern]
    | None,
    briefs: Sequence[NeutralObligationBrief] | None,
) -> tuple[NeutralObligationBrief, ...]:
    """Resolve either caller-supplied briefs or a typed plan/catalog pair."""
    if briefs is None:
        if plan is None or attack_pattern_catalog is None:
            raise TypeError(
                "plan and attack_pattern_catalog are required when briefs are omitted"
            )
        return build_neutral_briefs(plan, attack_pattern_catalog)
    values = tuple(briefs)
    if any(not isinstance(item, NeutralObligationBrief) for item in values):
        raise TypeError("briefs must contain NeutralObligationBrief values")
    return tuple(sorted(values, key=lambda item: item.obligation_id))


def _route_batch(
    adapter: StructuralAnalysisAdapter,
    batch: Sequence[NeutralObligationBrief],
    *,
    batch_index: int,
    purpose: Literal["initial", "recheck"],
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
    slots: Sequence[SlotPlaceholder],
    controls: AnalysisControls,
    references: dict[str, set[str]],
) -> tuple[
    StructuralRoutingRequest,
    tuple[ObligationRoute, ...],
    ConsiderationCallEvidence,
    str | None,
]:
    """Execute and locally validate one bounded routing batch."""
    request = _request_for_batch(
        batch,
        batch_index=batch_index,
        purpose=purpose,
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        slots=slots,
        controls=controls,
    )
    method = _adapter_method(adapter, ("route", "route_obligations", "analyze"))
    response: StructuralRoutingResponse | None = None
    error: BaseException | None = None
    attempts = 0
    for attempt in range(controls.validation_retries + 1):
        attempts = attempt + 1
        try:
            raw = _call_with_optional_feedback(
                method,
                request,
                None if attempt == 0 else _routing_validation_feedback(error),
            )
            candidate = _coerce_response(raw, request)
            if candidate.request_digest != request.semantic_digest:
                raise ValueError("routing response is bound to another request")
            expected_ids = {item.obligation_id for item in batch}
            actual_ids = {item.obligation_id for item in candidate.routes}
            if actual_ids != expected_ids or len(candidate.routes) != len(batch):
                raise ValueError(
                    "routing response must account for every batch obligation exactly once"
                )
            for route in candidate.routes:
                _validate_route(
                    route,
                    route.obligation_id,
                    references,
                    loss_analysis=loss_analysis,
                    control_structure=control_structure,
                    slots=slots,
                )
            response = candidate
            break
        except PromptBudgetExceeded as exc:
            error = exc
            break
        except (TypeError, ValueError) as exc:
            error = exc
    if response is None:
        assert error is not None
        detail = (
            f"{request.batch_id} exhausted validation: {type(error).__name__}: {error}"
        )
        evidence = ConsiderationCallEvidence(
            call_id=f"stpa-route:{request.batch_id}",
            request_digest=request.semantic_digest,
            model_profile=request.controls.model_profile,
            model_name=request.controls.model_name,
            attempt_count=attempts,
            outcome="unresolved",
        )
        return request, _unresolved_routes(request, error), evidence, detail
    return request, response.routes, _call_evidence(response, request, attempts), None


def route_obligations(
    adapter: StructuralAnalysisAdapter,
    *,
    plan: TaxonomyObligationPlan | None = None,
    attack_pattern_catalog: Sequence[AttackPattern]
    | Mapping[str, AttackPattern]
    | None = None,
    briefs: Sequence[NeutralObligationBrief] | None = None,
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
    slots: Sequence[SlotPlaceholder] | None = None,
    controls: AnalysisControls | None = None,
    max_batch_size: int | None = None,
    purpose: Literal["initial", "recheck"] = "initial",
) -> RoutingRunResult:
    """Route every applicable brief exactly once in canonical batches."""
    if not isinstance(loss_analysis, LossAnalysis):
        raise TypeError("loss_analysis must be a LossAnalysis")
    if not isinstance(control_structure, ControlStructure):
        raise TypeError("control_structure must be a ControlStructure")
    briefs_tuple = _resolve_routing_briefs(plan, attack_pattern_catalog, briefs)
    if not briefs_tuple:
        return RoutingRunResult((), (), (), (), ())
    if max_batch_size is None:
        max_batch_size = controls.max_batch_size if controls is not None else 8
    effective_controls = _default_controls(controls, max_batch_size)
    inventory = _slot_inventory(control_structure, slots)
    batches = _budgeted_obligation_batches(
        briefs_tuple,
        max_batch_size=max_batch_size,
        budget=_routing_prompt_budget(adapter, effective_controls),
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        slots=inventory,
    )
    references = _reference_sets(control_structure, loss_analysis, inventory)
    requests: list[StructuralRoutingRequest] = []
    routes: list[ObligationRoute] = []
    evidence: list[ConsiderationCallEvidence] = []
    diagnostics: list[str] = []

    for batch_index, batch in enumerate(batches):
        request, batch_routes, batch_evidence, diagnostic = _route_batch(
            adapter,
            batch,
            batch_index=batch_index,
            purpose=purpose,
            loss_analysis=loss_analysis,
            control_structure=control_structure,
            slots=inventory,
            controls=effective_controls,
            references=references,
        )
        requests.append(request)
        routes.extend(batch_routes)
        evidence.append(batch_evidence)
        if diagnostic is not None:
            diagnostics.append(diagnostic)

    ordered_routes = tuple(sorted(routes, key=lambda item: item.obligation_id))
    if len(ordered_routes) != len(briefs_tuple):
        raise AssertionError("routing pass did not retain one result per brief")
    return RoutingRunResult(
        briefs=briefs_tuple,
        routes=ordered_routes,
        requests=tuple(requests),
        call_evidence=tuple(evidence),
        diagnostics=tuple(sorted(diagnostics)),
    )


def recheck_obligations(
    adapter: StructuralAnalysisAdapter,
    *,
    briefs: Sequence[NeutralObligationBrief],
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
    slots: Sequence[SlotPlaceholder] | None = None,
    controls: AnalysisControls | None = None,
    max_batch_size: int | None = None,
) -> RoutingRunResult:
    """Run one bounded, complete recheck against the final structure."""
    return route_obligations(
        adapter,
        briefs=briefs,
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        slots=slots,
        controls=controls,
        max_batch_size=max_batch_size,
        purpose="recheck",
    )


__all__ = [
    "RoutingRunResult",
    "build_neutral_brief",
    "build_neutral_briefs",
    "create_obligation_batches",
    "recheck_obligations",
    "route_obligations",
]
