"""Synthesis-specific ICA slot routing and filling."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import re
from typing import Any, Literal

from asago_scenario_generator.models.canonical import compute_framed_digest
from asago_scenario_generator.models.obligation_consideration import (
    ConsiderationCallEvidence,
    ConsiderationDiagnostic,
    NeutralObligationBrief,
    ObligationIcaConsideration,
    ObligationRoute,
)
from asago_scenario_generator.stpa.infra.prompt_preflight import (
    PromptBudget,
    PromptBudgetExceeded,
    PromptContractError,
    resolve_adapter_prompt_budget,
)
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.execution_envelope import candidate_id_for
from asago_scenario_generator.stpa.models.ica_enumeration import (
    ICA,
    ICAEnumeration,
    ICASlot,
    UCAType,
)
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    AnalysisControls,
    IcaFindingDraft,
    ObligationIcaDraft,
    SlotIcaDraft,
    SlotProviderEntry,
    SlotAnalysisAdapter,
    SynthesisSlotFillResult,
    SynthesisSlotRequest,
    SynthesisSlotResponse,
)
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    build_synthesis_slot_prompts,
)
from asago_scenario_generator.stpa.threat_enum.slot_creation import (
    SlotPlaceholder,
    create_slots,
)


SLOT_RESPONSE_DIGEST_DOMAIN = (
    "asago-scenario-generator:stpa-obligation-slot-response:v1"
)
_SYNTHESIS_SLOT_MAX_COMPLETION_TOKENS = 8192


def _slot_prompt_budget(
    adapter: Any,
    controls: AnalysisControls,
) -> PromptBudget | None:
    """Resolve the target-call budget from controls, adapter, or its client."""
    return resolve_adapter_prompt_budget(
        adapter,
        controls,
        maximum_completion_tokens=_SYNTHESIS_SLOT_MAX_COMPLETION_TOKENS,
    )


def _slot_request_with_parts(
    request: SynthesisSlotRequest,
    *,
    slots: Sequence[SlotPlaceholder],
    routes: Sequence[ObligationRoute],
) -> SynthesisSlotRequest:
    """Build a new digest-bound target request for one deterministic part."""
    route_ids = {route.obligation_id for route in routes}
    briefs = tuple(
        brief for brief in request.routed_briefs if brief.obligation_id in route_ids
    )
    return SynthesisSlotRequest(
        target_id=request.target_id,
        target_kind=request.target_kind,
        slots=tuple(slots),
        routed_briefs=briefs,
        routed_routes=tuple(routes),
        loss_analysis=request.loss_analysis,
        control_structure=request.control_structure,
        controls=request.controls,
    )


def _slot_request_fits(
    request: SynthesisSlotRequest,
    budget: PromptBudget,
) -> bool:
    """Check the exact rendered target prompt against its input budget."""
    system_prompt, user_prompt = build_synthesis_slot_prompts(
        target_id=request.target_id,
        slots=request.slots,
        routed_briefs=request.routed_briefs,
        routed_routes=request.routed_routes,
        loss_analysis=request.loss_analysis,
        control_structure=request.control_structure,
    )
    return budget.count(f"{system_prompt}\n{user_prompt}") <= budget.usable_input_tokens


def _split_target_routes(
    request: SynthesisSlotRequest,
    budget: PromptBudget,
) -> tuple[SynthesisSlotRequest, ...] | None:
    """Greedily split routed obligations while retaining every target slot."""
    if not request.routed_routes:
        return None
    parts: list[SynthesisSlotRequest] = []
    current: list[ObligationRoute] = []
    for route in request.routed_routes:
        candidate_routes = (*current, route)
        candidate = _slot_request_with_parts(
            request,
            slots=request.slots,
            routes=candidate_routes,
        )
        if current and not _slot_request_fits(candidate, budget):
            parts.append(
                _slot_request_with_parts(
                    request,
                    slots=request.slots,
                    routes=current,
                )
            )
            current = [route]
            candidate_routes = (route,)
            candidate = _slot_request_with_parts(
                request,
                slots=request.slots,
                routes=current,
            )
        if not _slot_request_fits(candidate, budget):
            # A single routed obligation plus the complete slot analysis is
            # indivisible at this seam.  Leave it to provider preflight so the
            # precise typed budget failure is retained.
            return None
        current = list(candidate_routes)
    if current:
        parts.append(
            _slot_request_with_parts(
                request,
                slots=request.slots,
                routes=current,
            )
        )
    return tuple(parts) if len(parts) > 1 else None


def _split_unrouted_slots(
    request: SynthesisSlotRequest,
    budget: PromptBudget,
) -> tuple[SynthesisSlotRequest, ...] | None:
    """Split an unrouted target by slots when the whole slot set is too large."""
    if request.routed_routes:
        return None
    parts: list[SynthesisSlotRequest] = []
    current: list[SlotPlaceholder] = []
    for slot in request.slots:
        candidate_slots = (*current, slot)
        candidate = _slot_request_with_parts(
            request,
            slots=candidate_slots,
            routes=(),
        )
        if current and not _slot_request_fits(candidate, budget):
            parts.append(_slot_request_with_parts(request, slots=current, routes=()))
            current = [slot]
            candidate_slots = (slot,)
            candidate = _slot_request_with_parts(
                request,
                slots=current,
                routes=(),
            )
        if not _slot_request_fits(candidate, budget):
            return None
        current = list(candidate_slots)
    if current:
        parts.append(_slot_request_with_parts(request, slots=current, routes=()))
    return tuple(parts) if len(parts) > 1 else None


def _budgeted_synthesis_slot_requests(
    adapter: Any,
    requests: Sequence[SynthesisSlotRequest],
) -> tuple[SynthesisSlotRequest, ...]:
    """Return bounded target requests that fit at exact request seams."""
    result: list[SynthesisSlotRequest] = []
    for request in requests:
        slot_requests = tuple(
            _slot_request_with_parts(
                request,
                slots=(slot,),
                routes=tuple(
                    route
                    for route in request.routed_routes
                    if slot.slot_id in route.slot_ids
                ),
            )
            for slot in request.slots
        )
        route_limit = request.controls.max_batch_size
        bounded: list[SynthesisSlotRequest] = []
        for slot_request in slot_requests:
            routes = slot_request.routed_routes
            if routes and len(routes) > route_limit:
                bounded.extend(
                    _slot_request_with_parts(
                        slot_request,
                        slots=slot_request.slots,
                        routes=routes[start : start + route_limit],
                    )
                    for start in range(0, len(routes), route_limit)
                )
            else:
                bounded.append(slot_request)
        for candidate in bounded:
            budget = _slot_prompt_budget(adapter, candidate.controls)
            if budget is None or _slot_request_fits(candidate, budget):
                result.append(candidate)
                continue
            split = _split_target_routes(candidate, budget)
            if split is None:
                split = _split_unrouted_slots(candidate, budget)
            result.extend(split or (candidate,))
    return tuple(result)


def final_slot_universe(
    control_structure: ControlStructure,
) -> tuple[SlotPlaceholder, ...]:
    """Derive the complete ordinary and coordination slot universe."""
    return tuple(sorted(create_slots(control_structure), key=lambda item: item.slot_id))


def _target_for_slot(
    slot: SlotPlaceholder,
) -> tuple[str, Literal["responsibility", "coordination_link"]]:
    """Return the exact provider target for one slot."""
    if slot.responsibility is not None and slot.coordination_link is None:
        return slot.responsibility, "responsibility"
    if slot.coordination_link is not None and slot.responsibility is None:
        return slot.coordination_link, "coordination_link"
    raise ValueError(f"slot {slot.slot_id} must identify exactly one target")


def _group_slots(
    slots: Sequence[SlotPlaceholder],
) -> tuple[
    tuple[
        str, Literal["responsibility", "coordination_link"], tuple[SlotPlaceholder, ...]
    ],
    ...,
]:
    """Group final slots by responsibility or coordination link deterministically."""
    grouped: dict[tuple[str, str], list[SlotPlaceholder]] = {}
    for slot in slots:
        target, kind = _target_for_slot(slot)
        grouped.setdefault((target, kind), []).append(slot)
    return tuple(
        (target, kind, tuple(sorted(values, key=lambda item: item.slot_id)))
        for (target, kind), values in sorted(grouped.items())
    )  # type: ignore[misc]


def _routed_for_target(
    target_slots: Sequence[SlotPlaceholder],
    briefs: Sequence[NeutralObligationBrief],
    routes: Sequence[ObligationRoute],
) -> tuple[tuple[NeutralObligationBrief, ...], tuple[ObligationRoute, ...]]:
    """Select only briefs whose final targeted route names this target's slots."""
    target_slot_ids = {slot.slot_id for slot in target_slots}
    brief_by_id = {brief.obligation_id: brief for brief in briefs}
    selected: list[tuple[NeutralObligationBrief, ObligationRoute]] = []
    for route in routes:
        if route.disposition != "targeted":
            continue
        if not target_slot_ids.intersection(route.slot_ids):
            continue
        brief = brief_by_id.get(route.obligation_id)
        if brief is None:
            raise ValueError(f"route {route.obligation_id} has no neutral brief")
        selected.append((brief, route))
    selected.sort(key=lambda item: item[0].obligation_id)
    return tuple(item[0] for item in selected), tuple(item[1] for item in selected)


def build_synthesis_slot_requests(
    *,
    briefs: Sequence[NeutralObligationBrief],
    routes: Sequence[ObligationRoute],
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
    controls: AnalysisControls | None = None,
) -> tuple[SynthesisSlotRequest, ...]:
    """Build one target request for every final target, including empty routes."""
    slots = final_slot_universe(control_structure)
    slot_ids = {slot.slot_id for slot in slots}
    for route in routes:
        unknown = set(route.slot_ids) - slot_ids
        if unknown:
            raise ValueError(
                f"route {route.obligation_id} references unknown final slots: "
                + ", ".join(sorted(unknown))
            )
    if controls is None:
        controls = AnalysisControls(
            model_profile="synthesis",
            model_name="caller-supplied",
            deadline_seconds=300.0,
            temperature=0.4,
        )
    requests: list[SynthesisSlotRequest] = []
    for target, target_kind, target_slots in _group_slots(slots):
        routed_briefs, routed_routes = _routed_for_target(target_slots, briefs, routes)
        requests.append(
            SynthesisSlotRequest(
                target_id=target,
                target_kind=target_kind,
                slots=target_slots,
                routed_briefs=routed_briefs,
                routed_routes=routed_routes,
                loss_analysis=loss_analysis,
                control_structure=control_structure,
                controls=controls,
            )
        )
    return tuple(requests)


def _adapter_method(adapter: Any) -> Any:
    """Resolve the explicit slot analysis method."""
    for name in ("fill", "fill_slots", "analyze_slots", "analyze"):
        method = getattr(adapter, name, None)
        if callable(method):
            return method
    raise TypeError(
        "slot adapter must provide fill, fill_slots, analyze_slots, or analyze"
    )


def _coerce_response(raw: Any, request: SynthesisSlotRequest) -> SynthesisSlotResponse:
    """Normalize typed, mapping, or direct slot-sequence responses."""
    if isinstance(raw, SynthesisSlotResponse):
        return raw
    if isinstance(raw, Mapping):
        return SynthesisSlotResponse.model_validate(raw)
    if isinstance(raw, Sequence) and not isinstance(raw, (str, bytes, bytearray)):
        return SynthesisSlotResponse(
            request_digest=request.semantic_digest,
            filled_slots=tuple(raw),
        )
    raise TypeError("slot adapter returned an unsupported response")


def _fallback_slot(slot: SlotPlaceholder, detail: str) -> ICASlot:
    """Fill a failed ordinary slot with explicit structural N/A evidence."""
    return ICASlot(
        slot_id=slot.slot_id,
        responsibility=slot.responsibility,
        coordination_link=slot.coordination_link,
        control_action=slot.control_action,
        uca_type=slot.uca_type,
        is_na=True,
        na_justification=detail,
    )


def _slot_matches(value: ICASlot, expected: SlotPlaceholder) -> bool:
    """Require exact slot identity and target metadata."""
    return (
        value.slot_id == expected.slot_id
        and value.responsibility == expected.responsibility
        and value.coordination_link == expected.coordination_link
        and value.control_action == expected.control_action
        and value.uca_type == expected.uca_type
    )


def _slot_authority(
    slot: SlotPlaceholder,
    control_structure: ControlStructure,
) -> tuple[str, str, str | None, set[str], set[str]]:
    """Return authoritative owner/action prose and valid PM/FB references."""
    if slot.responsibility is not None:
        return _responsibility_authority(slot, control_structure)
    if slot.coordination_link is not None:
        return _coordination_authority(slot, control_structure)
    raise ValueError(f"slot {slot.slot_id} has no authoritative owner")


def _responsibility_authority(
    slot: SlotPlaceholder,
    control_structure: ControlStructure,
) -> tuple[str, str, str | None, set[str], set[str]]:
    """Resolve an ordinary slot through its owning responsibility."""
    responsibility = next(
        (
            item
            for item in control_structure.responsibilities
            if item.resp_id == slot.responsibility
        ),
        None,
    )
    if responsibility is None:
        raise ValueError(f"slot {slot.slot_id} has unknown responsibility")
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
            f"slot {slot.slot_id} action is not owned by its responsibility"
        )
    return (
        responsibility.description,
        action.description,
        action.target.id if action.target is not None else None,
        {item.pm_id for item in responsibility.process_model_parts},
        {item.fb_id for item in responsibility.feedback_channels},
    )


def _coordination_authority(
    slot: SlotPlaceholder,
    control_structure: ControlStructure,
) -> tuple[str, str, str | None, set[str], set[str]]:
    """Resolve a coordination slot through its exact link and mechanism."""
    link = next(
        (
            item
            for item in control_structure.coordination_links
            if item.link_id == slot.coordination_link
        ),
        None,
    )
    if link is None:
        raise ValueError(f"slot {slot.slot_id} has unknown coordination link")
    if link.coordination_mechanism.cm_id != slot.control_action:
        raise ValueError(
            f"slot {slot.slot_id} action does not match coordination mechanism"
        )
    source = next(
        item
        for item in control_structure.responsibilities
        if item.resp_id == link.source
    )
    return (
        f"{source.description} (coordinating with {link.target})",
        link.coordination_mechanism.description,
        None,
        {link.shared_pm},
        set(),
    )


def _looks_like_safeguard(text: str) -> bool:
    """Detect recommendation-shaped text without using it as sole ICA semantics."""
    normalized = " ".join(text.lower().strip().split())
    if not normalized:
        return True
    imperative_prefixes = (
        "implement ",
        "add ",
        "ensure ",
        "enable ",
        "configure ",
        "enforce ",
        "use ",
        "require ",
        "provide ",
        "apply ",
        "maintain ",
    )
    return normalized.startswith(imperative_prefixes)


def _has_continuing_behavior(action_description: str, deviation: str) -> bool:
    """Require explicit evidence before a WRONG_DURATION finding."""
    text = f"{action_description} {deviation}".lower()
    return any(
        marker in text
        for marker in (
            "continuous",
            "continuously",
            "ongoing",
            "persistent",
            "remains",
            "remain valid",
            "for too long",
            "for too short",
            "duration",
            "until",
            "while",
            "session",
            "rate limit",
            "monitor",
            "stream",
        )
    )


def _compile_finding(
    finding: IcaFindingDraft,
    *,
    slot: SlotPlaceholder,
    owner_description: str,
    action_description: str,
    valid_process_models: set[str],
    valid_feedback: set[str],
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
    index: int,
) -> ICA:
    """Validate and compile one typed provider finding into an authoritative ICA."""
    _validate_finding_semantics(
        finding,
        slot=slot,
        action_description=action_description,
        valid_process_models=valid_process_models,
        valid_feedback=valid_feedback,
        loss_analysis=loss_analysis,
    )
    behavior = _finding_behavior(slot, action_description, finding.deviation.text)
    text = f"{owner_description} {behavior}."
    return ICA(
        ica_id=f"provider-finding-{index}",
        ica_text=text,
        hazardous_context=finding.hazardous_context.strip(),
        loss_scenario=finding.loss_consequence.strip(),
        related_hazards=list(finding.related_hazard_ids),
        related_constraints=list(finding.related_constraint_ids),
        quality_warnings=_deviation_quality_warnings(
            finding.deviation.text, action_description
        ),
    )


def _deviation_quality_warnings(deviation: str, action_description: str) -> list[str]:
    """Return non-blocking diagnostics for human-facing ICA prose."""
    text = deviation.strip()
    details = _deviation_style_codes(text, action_description)
    return ["ica_prose_quality_warning", *details] if details else []


def _deviation_style_codes(text: str, action_description: str) -> list[str]:
    """Evaluate each independent presentation-only rule."""
    checks = (
        (len(text.split()) > 32, "ica_deviation_over_32_words"),
        (len(text) > 220, "ica_deviation_over_220_characters"),
        (_contains_example(text), "ica_deviation_contains_example"),
        (
            _shares_substantial_phrase(text, action_description),
            "ica_deviation_repeats_action",
        ),
    )
    return [code for matched, code in checks if matched]


def _contains_example(text: str) -> bool:
    """Recognize common example-introducing phrases."""
    lowered = text.casefold()
    return any(marker in lowered for marker in ("such as", "e.g.", "for example"))


def _shares_substantial_phrase(left: str, right: str) -> bool:
    """Detect repeated four-word phrases after conservative normalization."""

    def phrases(value: str) -> set[tuple[str, ...]]:
        words = tuple(
            item
            for item in re.sub(r"[^a-z0-9]+", " ", value.casefold()).split()
            if item
        )
        return {words[index : index + 4] for index in range(max(0, len(words) - 3))}

    return bool(phrases(left).intersection(phrases(right)))


def _validate_finding_semantics(
    finding: IcaFindingDraft,
    *,
    slot: SlotPlaceholder,
    action_description: str,
    valid_process_models: set[str],
    valid_feedback: set[str],
    loss_analysis: LossAnalysis,
) -> None:
    """Validate type-specific prose and every referenced STPA identity."""
    _validate_finding_type(finding, slot, action_description)
    _validate_finding_references(
        finding,
        valid_process_models=valid_process_models,
        valid_feedback=valid_feedback,
        loss_analysis=loss_analysis,
    )


def _validate_finding_type(
    finding: IcaFindingDraft,
    slot: SlotPlaceholder,
    action_description: str,
) -> None:
    """Validate the one UCA-specific deviation field and its wording."""
    expected_field = {
        UCAType.not_provided: "not_provided_context",
        UCAType.incorrect: "incorrect_value_or_effect",
        UCAType.wrong_timing: "timing_deviation",
        UCAType.wrong_duration: "duration_deviation",
    }[slot.uca_type]
    if finding.deviation.field_name != expected_field:
        raise ValueError(
            f"{slot.uca_type.value} requires the {expected_field} deviation field"
        )
    deviation = finding.deviation.text.strip()
    if _looks_like_safeguard(deviation):
        raise ValueError(
            "finding describes a safeguard rather than unsafe control behavior"
        )
    if slot.uca_type is UCAType.wrong_duration and not _has_continuing_behavior(
        action_description, deviation
    ):
        raise ValueError(
            "WRONG_DURATION requires explicit continuing behavior for the action"
        )


def _validate_finding_references(
    finding: IcaFindingDraft,
    *,
    valid_process_models: set[str],
    valid_feedback: set[str],
    loss_analysis: LossAnalysis,
) -> None:
    """Validate hazard, constraint, process-model, and feedback references."""
    hazard_ids = {item.hazard_id for item in loss_analysis.hazards}
    unknown_hazards = set(finding.related_hazard_ids) - hazard_ids
    if unknown_hazards:
        raise ValueError(
            "finding references unknown hazards: " + ", ".join(sorted(unknown_hazards))
        )
    constraints = {
        item.constraint_id: item for item in loss_analysis.security_constraints
    }
    unknown_constraints = set(finding.related_constraint_ids) - set(constraints)
    if unknown_constraints:
        raise ValueError(
            "finding references unknown security constraints: "
            + ", ".join(sorted(unknown_constraints))
        )
    selected_hazards = set(finding.related_hazard_ids)
    for constraint_id in finding.related_constraint_ids:
        if not selected_hazards.intersection(
            constraints[constraint_id].related_hazards
        ):
            raise ValueError(
                f"constraint {constraint_id} does not govern the finding hazards"
            )
    unknown_pm = set(finding.process_model_refs) - valid_process_models
    if unknown_pm:
        raise ValueError(
            "finding references process-model parts outside the target: "
            + ", ".join(sorted(unknown_pm))
        )
    unknown_fb = set(finding.feedback_refs) - valid_feedback
    if unknown_fb:
        raise ValueError(
            "finding references feedback channels outside the target: "
            + ", ".join(sorted(unknown_fb))
        )


def _finding_behavior(
    slot: SlotPlaceholder,
    action_description: str,
    deviation: str,
) -> str:
    """Render unsafe-control behavior around authoritative action identity."""
    # Include the authoritative action in every compiled ICA. The model may
    # describe the deviation, but it cannot substitute another control path.
    if slot.uca_type is UCAType.not_provided:
        behavior = f"fails to provide '{action_description}' when {deviation}"
    elif slot.uca_type is UCAType.incorrect:
        behavior = f"provides '{action_description}' with an unsafe value/effect because {deviation}"
    elif slot.uca_type is UCAType.wrong_timing:
        behavior = f"provides '{action_description}' at an unsafe time or order because {deviation}"
    else:
        behavior = f"provides '{action_description}' for an unsafe duration because {deviation}"
    return behavior


def compile_ica_slot_draft(
    draft: SlotIcaDraft,
    *,
    slot: SlotPlaceholder,
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
) -> ICASlot:
    """Compile one structured slot draft against authoritative STPA records."""
    if not isinstance(draft, SlotIcaDraft):
        raise TypeError("draft must be a SlotIcaDraft")
    if draft.slot_id != slot.slot_id:
        raise ValueError("ICA draft is bound to another slot")
    owner_description, action_description, _target_process, pm_ids, fb_ids = (
        _slot_authority(slot, control_structure)
    )
    if draft.is_na:
        return ICASlot(
            slot_id=slot.slot_id,
            responsibility=slot.responsibility,
            coordination_link=slot.coordination_link,
            control_action=slot.control_action,
            uca_type=slot.uca_type,
            is_na=True,
            na_justification=draft.na_rationale,
        )
    compiled = [
        _compile_finding(
            finding,
            slot=slot,
            owner_description=owner_description,
            action_description=action_description,
            valid_process_models=pm_ids,
            valid_feedback=fb_ids,
            loss_analysis=loss_analysis,
            control_structure=control_structure,
            index=index,
        )
        for index, finding in enumerate(draft.findings, start=1)
    ]
    return ICASlot(
        slot_id=slot.slot_id,
        responsibility=slot.responsibility,
        coordination_link=slot.coordination_link,
        control_action=slot.control_action,
        uca_type=slot.uca_type,
        is_na=False,
        icas=compiled,
    ).aligned()


def _compile_legacy_slot(
    value: ICASlot,
    *,
    slot: SlotPlaceholder,
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
) -> ICASlot:
    """Adapt the historical final-slot shape while enforcing new semantics."""
    if not _slot_matches(value, slot):
        raise ValueError(f"slot {slot.slot_id} changed its authoritative identity")
    owner_description, action_description, _target_process, _pm_ids, _fb_ids = (
        _slot_authority(slot, control_structure)
    )
    hazard_ids = {item.hazard_id for item in loss_analysis.hazards}
    constraint_ids = {item.constraint_id for item in loss_analysis.security_constraints}
    compiled: list[ICA] = []
    for ica in value.icas:
        if set(ica.related_hazards) - hazard_ids:
            raise ValueError("legacy ICA references an unknown hazard")
        if set(ica.related_constraints) - constraint_ids:
            raise ValueError("legacy ICA references an unknown constraint")
        if _looks_like_safeguard(ica.ica_text):
            raise ValueError(
                "finding describes a safeguard rather than unsafe control behavior"
            )
        text = ica.ica_text.strip()
        if owner_description not in text or action_description not in text:
            text = f"{owner_description} issues '{action_description}': {text}"
        # Preserve the provider-local label until consideration evidence has
        # selected this exact ICA; the enclosing fill seam aligns positions to
        # canonical slot-relative IDs.
        compiled.append(ica.model_copy(update={"ica_text": text}))
    if value.is_na:
        return value
    if not compiled:
        raise ValueError("non-N/A slot requires at least one compiled finding")
    # Keep provider-local ICA labels until the pair adapter has selected them;
    # the enclosing fill seam aligns positions to canonical ``slot:N`` IDs.
    return value.model_copy(update={"icas": compiled})


def compile_slot_provider_entry(
    value: SlotProviderEntry,
    *,
    slot: SlotPlaceholder,
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
) -> ICASlot:
    """Compile either a strict draft or a legacy provider slot entry."""
    if isinstance(value, SlotIcaDraft):
        return compile_ica_slot_draft(
            value,
            slot=slot,
            loss_analysis=loss_analysis,
            control_structure=control_structure,
        )
    if isinstance(value, ICASlot):
        return _compile_legacy_slot(
            value,
            slot=slot,
            loss_analysis=loss_analysis,
            control_structure=control_structure,
        )
    raise TypeError("provider slot entry must be ICASlot or SlotIcaDraft")


def _canonical_exec(slot: SlotPlaceholder) -> str:
    """Derive the exact EXEC identity for an ordinary or coordination slot."""
    controller = slot.responsibility or slot.coordination_link
    if controller is None:
        raise ValueError(f"slot {slot.slot_id} has no controller")
    return candidate_id_for(controller, slot.control_action, slot.uca_type)


def _unresolved_pair(
    route: ObligationRoute,
    slot: SlotPlaceholder,
    detail: str,
    *,
    call_ref: str | None = None,
) -> ObligationIcaConsideration:
    """Create typed unresolved pair evidence without inventing findings."""
    refs = () if call_ref is None else (call_ref,)
    return ObligationIcaConsideration(
        route_id=route.route_id,
        obligation_id=route.obligation_id,
        slot_id=slot.slot_id,
        disposition="unresolved",
        evidence=("slot-analysis-validation",),
        model_call_refs=refs,
        rationale=detail,
        diagnostics=(
            ConsiderationDiagnostic(
                code="slot_pair_unresolved",
                detail=detail,
                obligation_ids=(route.obligation_id,),
                refs=(route.route_id, slot.slot_id),
            ),
        ),
    )


def _draft_considerations(
    response: SynthesisSlotResponse,
    request: SynthesisSlotRequest,
    compiled_slots: Mapping[str, ICASlot],
) -> tuple[ObligationIcaConsideration, ...]:
    """Materialize nested structured consideration results from slot drafts."""
    routes = {
        (route.obligation_id, slot_id): route
        for route in request.routed_routes
        for slot_id in route.slot_ids
    }
    values: list[ObligationIcaConsideration] = []
    for entry in response.filled_slots:
        if not isinstance(entry, SlotIcaDraft):
            continue
        slot = compiled_slots.get(entry.slot_id)
        if slot is None:
            continue
        for result in entry.consideration_results:
            route = routes.get((result.obligation_handle, entry.slot_id))
            if route is None:
                raise ValueError(
                    "structured consideration references an obligation/slot "
                    "that is not routed to this target"
                )
            values.append(_draft_consideration(result, route, slot))
    return tuple(values)


def _draft_consideration(
    result: ObligationIcaDraft,
    route: ObligationRoute,
    slot: ICASlot,
) -> ObligationIcaConsideration:
    """Compile one structured model disposition into exact slot evidence."""
    if result.disposition == "finding":
        return _draft_finding_consideration(result, route, slot)
    if result.disposition == "proposed_not_applicable":
        if not slot.is_na:
            raise ValueError("proposed non-applicability requires an N/A slot draft")
        return ObligationIcaConsideration(
            route_id=route.route_id,
            obligation_id=route.obligation_id,
            slot_id=slot.slot_id,
            disposition="proposed_not_applicable",
            evidence=("provider-structured-consideration",),
            structural_inventory_complete=True,
            rationale=result.rationale,
        )
    return ObligationIcaConsideration(
        route_id=route.route_id,
        obligation_id=route.obligation_id,
        slot_id=slot.slot_id,
        disposition="unresolved",
        evidence=("provider-structured-consideration",),
        rationale=result.rationale,
    )


def _draft_finding_consideration(
    result: ObligationIcaDraft,
    route: ObligationRoute,
    slot: ICASlot,
) -> ObligationIcaConsideration:
    """Compile a finding disposition and copy exact selected ICA references."""
    if any(index >= len(slot.icas) for index in result.finding_indexes):
        raise ValueError("structured consideration finding index is outside its slot")
    selected = tuple(slot.icas[index] for index in result.finding_indexes)
    controller = slot.responsibility or slot.coordination_link
    if controller is None:
        raise ValueError(f"slot {slot.slot_id} has no controller")
    return ObligationIcaConsideration(
        route_id=route.route_id,
        obligation_id=route.obligation_id,
        slot_id=slot.slot_id,
        disposition="finding",
        ica_ids=tuple(item.ica_id for item in selected),
        exec_candidate_ids=(
            candidate_id_for(controller, slot.control_action, slot.uca_type),
        ),
        hazard_ids=tuple(
            sorted(
                {hazard_id for item in selected for hazard_id in item.related_hazards}
            )
        ),
        constraint_ids=tuple(
            sorted(
                {
                    constraint_id
                    for item in selected
                    for constraint_id in item.related_constraints
                }
            )
        ),
        evidence=("provider-structured-consideration",),
        rationale=result.rationale,
    )


def _record_request_unresolved(
    request: SynthesisSlotRequest,
    expected: Mapping[str, SlotPlaceholder],
    detail: str,
    *,
    response: SynthesisSlotResponse | None,
    all_filled: dict[str, ICASlot],
    all_pairs: list[ObligationIcaConsideration],
    evidence: list[ConsiderationCallEvidence],
    diagnostics: list[ConsiderationDiagnostic],
    call_ref: str | None = None,
    successful_slots: set[str] | None = None,
    error: BaseException | None = None,
) -> None:
    """Retain one failed target request as unresolved local evidence."""
    diagnostic_code = (
        "prompt_budget_exceeded"
        if isinstance(error, PromptBudgetExceeded)
        else "prompt_contract_invalid"
        if isinstance(error, PromptContractError)
        else "slot_response_unresolved"
    )
    diagnostics.append(
        ConsiderationDiagnostic(
            code=diagnostic_code,
            detail=detail,
            refs=(request.target_id,),
        )
    )
    for slot in request.slots:
        if successful_slots is None or slot.slot_id not in successful_slots:
            all_filled[slot.slot_id] = _fallback_slot(slot, detail)
    call_ref = call_ref or f"stpa-slot:{request.target_id}"
    response_digest = None
    if response is not None:
        response_digest = response.response_digest or compute_framed_digest(
            SLOT_RESPONSE_DIGEST_DOMAIN,
            response.model_dump(mode="json"),
        )
    evidence.append(
        ConsiderationCallEvidence(
            call_id=call_ref,
            request_digest=request.semantic_digest,
            response_digest=response_digest,
            model_profile=request.controls.model_profile,
            model_name=request.controls.model_name,
            attempt_count=1,
            outcome="unresolved",
        )
    )
    for route in request.routed_routes:
        for slot_id in sorted(set(route.slot_ids).intersection(expected)):
            all_pairs.append(
                _unresolved_pair(
                    route,
                    expected[slot_id],
                    detail,
                    call_ref=call_ref,
                )
            )


def _validate_pair(
    pair: ObligationIcaConsideration,
    route: ObligationRoute,
    slot: SlotPlaceholder,
    filled: Mapping[str, ICASlot],
) -> ObligationIcaConsideration:
    """Validate one provider pair against the exact route and filled slot."""
    if pair.route_id != route.route_id or pair.obligation_id != route.obligation_id:
        raise ValueError("slot evidence is bound to another route")
    if pair.slot_id != slot.slot_id:
        raise ValueError("slot evidence is bound to another slot")
    if pair.disposition == "finding":
        _validate_finding_pair(pair, slot, filled)
    elif pair.disposition == "proposed_not_applicable":
        _validate_non_applicable_pair(pair, slot, filled)
    elif pair.ica_ids or pair.exec_candidate_ids:
        raise ValueError("unresolved evidence cannot retain findings")
    return pair


def _validate_finding_pair(
    pair: ObligationIcaConsideration,
    slot: SlotPlaceholder,
    filled: Mapping[str, ICASlot],
) -> None:
    """Validate finding evidence against the selected slot ICAs."""
    if pair.exec_candidate_ids != (_canonical_exec(slot),):
        raise ValueError("finding evidence must use the slot's canonical EXEC identity")
    value = filled.get(slot.slot_id)
    if value is None or value.is_na:
        raise ValueError("finding evidence requires a non-N/A filled slot")
    ica_ids = {item.ica_id for item in value.icas}
    if not set(pair.ica_ids).issubset(ica_ids):
        raise ValueError("finding evidence references an ICA outside its slot")
    referenced = tuple(item for item in value.icas if item.ica_id in pair.ica_ids)
    expected_hazards = {
        hazard_id for item in referenced for hazard_id in item.related_hazards
    }
    expected_constraints = {
        constraint_id
        for item in referenced
        for constraint_id in item.related_constraints
    }
    if set(pair.hazard_ids) != expected_hazards:
        raise ValueError(
            "finding evidence hazards must exactly match its referenced ICAs"
        )
    if set(pair.constraint_ids) != expected_constraints:
        raise ValueError(
            "finding evidence constraints must exactly match its referenced ICAs"
        )


def _validate_non_applicable_pair(
    pair: ObligationIcaConsideration,
    slot: SlotPlaceholder,
    filled: Mapping[str, ICASlot],
) -> None:
    """Validate complete structural evidence for a proposed N/A pair."""
    value = filled.get(slot.slot_id)
    if value is None or not value.is_na:
        raise ValueError("non-applicability evidence requires an N/A filled slot")
    if not pair.structural_inventory_complete:
        raise ValueError("non-applicability evidence must attest complete inventory")


@dataclass(frozen=True, slots=True)
class SlotFillRunResult:
    """Final slot enumeration, pair evidence, and target requests."""

    result: SynthesisSlotFillResult

    @property
    def ica_enumeration(self) -> ICAEnumeration:
        """Expose the final deterministic enumeration."""
        return self.result.ica_enumeration

    @property
    def considerations(self) -> tuple[ObligationIcaConsideration, ...]:
        """Expose exact obligation/slot evidence."""
        return self.result.considerations


def fill_synthesis_slots(
    adapter: SlotAnalysisAdapter,
    *,
    briefs: Sequence[NeutralObligationBrief],
    routes: Sequence[ObligationRoute],
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
    controls: AnalysisControls | None = None,
) -> SlotFillRunResult:
    """Fill all final slots, sending each target only its routed briefs."""
    requests = build_synthesis_slot_requests(
        briefs=briefs,
        routes=routes,
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        controls=controls,
    )
    requests = _budgeted_synthesis_slot_requests(adapter, requests)
    method = _adapter_method(adapter)
    all_filled: dict[str, ICASlot] = {}
    successful_slots: set[str] = set()
    all_pairs: list[ObligationIcaConsideration] = []
    evidence: list[ConsiderationCallEvidence] = []
    diagnostics: list[ConsiderationDiagnostic] = []

    target_totals: dict[str, int] = {}
    for request in requests:
        target_totals[request.target_id] = target_totals.get(request.target_id, 0) + 1
    target_parts: dict[str, int] = {}

    for request in requests:
        expected = {slot.slot_id: slot for slot in request.slots}
        target_parts[request.target_id] = target_parts.get(request.target_id, 0) + 1
        call_ref = (
            f"stpa-slot:{request.target_id}"
            if target_totals[request.target_id] == 1
            else f"stpa-slot:{request.target_id}:part-{target_parts[request.target_id]}"
        )
        response: SynthesisSlotResponse | None = None
        error: Exception | None = None
        try:
            response = _coerce_response(method(request), request)
            if response.request_digest != request.semantic_digest:
                raise ValueError("slot response is bound to another request")
        except Exception as exc:  # noqa: BLE001 - retain request-local failures
            error = exc
        if error is not None:
            detail = (
                f"Slot response could not be validated: {type(error).__name__}: {error}"
            )
            _record_request_unresolved(
                request,
                expected,
                detail,
                response=response,
                all_filled=all_filled,
                all_pairs=all_pairs,
                evidence=evidence,
                diagnostics=diagnostics,
                call_ref=call_ref,
                successful_slots=successful_slots,
                error=error,
            )
            continue

        assert response is not None
        by_id: dict[str, ICASlot] = {}
        compile_error: Exception | None = None
        for value in response.filled_slots:
            slot_id = getattr(value, "slot_id", None)
            expected_slot = expected.get(slot_id)
            if expected_slot is None:
                diagnostics.append(
                    ConsiderationDiagnostic(
                        code="unexpected_slot_identity",
                        detail=f"Response for {request.target_id} contained an unexpected slot {slot_id}",
                        refs=(request.target_id, str(slot_id)),
                    )
                )
                continue
            if slot_id in by_id:
                diagnostics.append(
                    ConsiderationDiagnostic(
                        code="duplicate_slot_identity",
                        detail=f"Response for {request.target_id} repeated slot {slot_id}",
                        refs=(request.target_id, slot_id),
                    )
                )
                continue
            try:
                by_id[slot_id] = compile_slot_provider_entry(
                    value,
                    slot=expected_slot,
                    loss_analysis=loss_analysis,
                    control_structure=control_structure,
                ).aligned()
            except (TypeError, ValueError) as exc:
                compile_error = exc
                break
        if compile_error is not None:
            detail = (
                "Slot response failed typed ICA draft validation: "
                f"{type(compile_error).__name__}: {compile_error}"
            )
            _record_request_unresolved(
                request,
                expected,
                detail,
                response=response,
                all_filled=all_filled,
                all_pairs=all_pairs,
                evidence=evidence,
                diagnostics=diagnostics,
                call_ref=call_ref,
                successful_slots=successful_slots,
                error=compile_error,
            )
            continue
        conflicting_slots = tuple(
            sorted(
                slot_id
                for slot_id, value in by_id.items()
                if slot_id in successful_slots and all_filled[slot_id] != value
            )
        )
        if conflicting_slots:
            detail = (
                "Repeated obligation batch changed the authoritative ICA findings "
                "for slot(s): " + ", ".join(conflicting_slots)
            )
            _record_request_unresolved(
                request,
                expected,
                detail,
                response=response,
                all_filled=all_filled,
                all_pairs=all_pairs,
                evidence=evidence,
                diagnostics=diagnostics,
                call_ref=call_ref,
                successful_slots=successful_slots,
                error=ValueError(detail),
            )
            continue
        for slot in request.slots:
            if slot.slot_id in successful_slots:
                continue
            all_filled[slot.slot_id] = by_id.get(
                slot.slot_id,
                _fallback_slot(
                    slot, "No valid slot result was returned by the bounded adapter."
                ),
            )

        # Validate ICA references at the request boundary so one malformed
        # target cannot abort the entire synthesis after other targets have
        # already been retained.  A failed target is represented uniformly
        # as N/A slots plus unresolved routed pairs below.
        try:
            request_enumeration = ICAEnumeration(
                slots=[all_filled[slot.slot_id] for slot in request.slots]
            )
            request_enumeration.validate_against(loss_analysis, control_structure)
        except Exception as exc:  # noqa: BLE001 - retain request-local failures
            detail = (
                "Slot response failed exact STPA reference validation: "
                f"{type(exc).__name__}: {exc}"
            )
            _record_request_unresolved(
                request,
                expected,
                detail,
                response=response,
                all_filled=all_filled,
                all_pairs=all_pairs,
                evidence=evidence,
                diagnostics=diagnostics,
                call_ref=call_ref,
                successful_slots=successful_slots,
                error=exc,
            )
            continue

        successful_slots.update(by_id)

        structured_pairs = _draft_considerations(
            response,
            request,
            all_filled,
        )
        pair_by_key = {
            (pair.obligation_id, pair.slot_id): pair
            for pair in (*response.considerations, *structured_pairs)
        }
        response_digest = response.response_digest or compute_framed_digest(
            SLOT_RESPONSE_DIGEST_DOMAIN,
            response.model_dump(mode="json"),
        )
        evidence.append(
            ConsiderationCallEvidence(
                call_id=call_ref,
                request_digest=request.semantic_digest,
                response_digest=response_digest,
                model_profile=request.controls.model_profile,
                model_name=request.controls.model_name,
                attempt_count=1,
                outcome="accepted",
            )
        )
        for route in request.routed_routes:
            for slot_id in sorted(set(route.slot_ids).intersection(expected)):
                slot = expected[slot_id]
                pair = pair_by_key.get((route.obligation_id, slot_id))
                if pair is None:
                    all_pairs.append(
                        _unresolved_pair(
                            route,
                            slot,
                            "Routed obligation/slot pair was not returned by the adapter.",
                            call_ref=call_ref,
                        )
                    )
                    continue
                try:
                    all_pairs.append(_validate_pair(pair, route, slot, all_filled))
                except (TypeError, ValueError) as exc:
                    all_pairs.append(
                        _unresolved_pair(
                            route,
                            slot,
                            f"Routed pair failed exact validation: {type(exc).__name__}: {exc}",
                            call_ref=call_ref,
                        )
                    )

    ordered_slots = tuple(all_filled[key] for key in sorted(all_filled))
    enumeration = ICAEnumeration(slots=list(ordered_slots))
    enumeration.validate_against(loss_analysis, control_structure)
    final = SynthesisSlotFillResult(
        ica_enumeration=enumeration,
        considerations=tuple(all_pairs),
        requests=requests,
        call_evidence=tuple(evidence),
        diagnostics=tuple(diagnostics),
    )
    return SlotFillRunResult(result=final)


# Public spellings used by synthesis callers.
fill_synthesis_specific_icas = fill_synthesis_slots
fill_slots = fill_synthesis_slots


__all__ = [
    "SlotFillRunResult",
    "build_synthesis_slot_requests",
    "compile_ica_slot_draft",
    "compile_slot_provider_entry",
    "fill_slots",
    "fill_synthesis_slots",
    "fill_synthesis_specific_icas",
    "final_slot_universe",
]
