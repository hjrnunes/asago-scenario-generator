"""Synthesis-specific ICA slot routing and filling."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
import re
from typing import Any, Literal, cast

from asago_scenario_generator.models.ica_merge import IcaMerge, IcaMergedFinding
from asago_scenario_generator.models.mechanism_suggestion import (
    MechanismIcaConsideration,
    MechanismSuggestion,
)
from asago_scenario_generator.models.obligation_consideration import (
    REQUEST_REJECTION_REPEATED,
    REQUEST_SCHEMA_REJECTED,
    SLOT_PROMPT_BUDGET_EXCEEDED,
    SLOT_PROVIDER_CONTRACT_FAILED,
    ConsiderationCallEvidence,
    ConsiderationDiagnostic,
    NeutralObligationBrief,
    ObligationIcaConsideration,
    ObligationRoute,
)
from asago_scenario_generator.stpa.infra.llm_helpers import (
    count_requests,
    is_provider_contract_failure,
)
from asago_scenario_generator.stpa.infra.provider_record import (
    SIZE_LIMIT_TEXT,
    rejection_digest,
)
from asago_scenario_generator.stpa.infra.prompt_preflight import (
    PromptBudget,
    PromptBudgetExceeded,
    PromptContractError,
    resolve_adapter_prompt_budget,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlStructure,
    control_action_context_rows,
)
from asago_scenario_generator.stpa.models.ica_enumeration import (
    ICA,
    ICAEnumeration,
    ICASlot,
    UCAType,
    candidate_id_for,
)
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.obligation_aware.calls import call_evidence
from asago_scenario_generator.stpa.obligation_aware.inverted_omission import (
    withhold_inverted_omissions,
)
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    DEVIATION_FIELD_BY_UCA_TYPE,
    AnalysisControls,
    IcaFindingDraft,
    ObligationIcaDraft,
    SlotIcaDraft,
    SlotProviderEntry,
    SlotAnalysisAdapter,
    SlotFillFailure,
    SlotLoss,
    SynthesisSlotFillResult,
    SynthesisSlotRequest,
    SynthesisSlotResponse,
    default_synthesis_controls,
)
from asago_scenario_generator.stpa.obligation_aware.stpa_index import (
    SlotPath,
    StpaIndex,
    build_stpa_index,
)
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    build_synthesis_slot_prompts,
    local_obligation_handles,
)
from asago_scenario_generator.stpa.threat_enum.slot_creation import (
    SlotPlaceholder,
    create_slots,
    is_wrong_duration_eligible,
    requires_provider_slot_analysis,
)


SLOT_RESPONSE_DIGEST_DOMAIN = (
    "asago-scenario-generator:stpa-obligation-slot-response:v1"
)
_SYNTHESIS_SLOT_MAX_COMPLETION_TOKENS = 8192
# The parts of a provider's rejection of the response schema; see
# ``is_request_schema_rejection``.
_SCHEMA_PARAM = re.compile(r"response_format(?:$|[.\[])")
_SCHEMA_CODES = frozenset({"invalid_json_schema", "invalid_schema"})
# A field of the error body as the SDK error's text shows it, which is all a
# replayed error keeps of the body.
_BODY_FIELD = re.compile(r"[\'\"](param|code)[\'\"]: ?[\'\"]([^\'\"]+)[\'\"]")
_SIZE_VETO = SIZE_LIMIT_TEXT
_SCHEMA_NOUN = r"\b(?:schema|json_schema|response_format)\b"
_REJECTION_WORD = (
    r"\b(?:compil\w*|invalid|unsupported|not supported|not valid"
    r"|(?:cannot|can't|could not|unable to|failed to) (?:be )?(?:parse|convert)\w*)\b"
)
# At most three words between the schema noun and the rejection word.
_NEAR = r"\W+(?:\w+\W+){0,3}?"
_SCHEMA_REJECTION_TEXT = re.compile(
    f"{_REJECTION_WORD}{_NEAR}{_SCHEMA_NOUN}|{_SCHEMA_NOUN}{_NEAR}{_REJECTION_WORD}",
    re.IGNORECASE,
)
_WRONG_DURATION_NA_JUSTIFICATION = (
    "The authoritative action temporality is not continuous or bounded_duration."
)


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
    mechanism_suggestions: Sequence[MechanismSuggestion] = (),
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
        mechanism_suggestions=tuple(mechanism_suggestions),
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
        mechanism_suggestions=request.mechanism_suggestions,
    )
    return budget.count(f"{system_prompt}\n{user_prompt}") <= budget.usable_input_tokens


def _split_target_routes(
    request: SynthesisSlotRequest,
    budget: PromptBudget,
) -> tuple[SynthesisSlotRequest, ...] | None:
    """Greedily split routed obligations while retaining every target slot.

    Routes are taken in the order of their local handles, which follows
    ``obligation_order_key``, so renaming obligation IDs keeps the parts.
    """
    if not request.routed_routes:
        return None
    handles = local_obligation_handles(
        request.routed_routes,
        {brief.obligation_id: brief for brief in request.routed_briefs},
    )
    rank = {obligation_id: index for index, obligation_id in enumerate(handles)}
    parts: list[SynthesisSlotRequest] = []
    current: list[ObligationRoute] = []
    for route in sorted(
        request.routed_routes, key=lambda item: rank[item.obligation_id]
    ):
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


def _budgeted_synthesis_slot_requests(
    adapter: Any,
    requests: Sequence[SynthesisSlotRequest],
) -> tuple[SynthesisSlotRequest, ...]:
    """Return bounded target requests that fit at exact request seams."""
    result: list[SynthesisSlotRequest] = []
    for request in requests:
        for slot_request in _single_slot_requests(request):
            result.extend(_budgeted_candidates(adapter, slot_request))
    return tuple(result)


def _single_slot_requests(
    request: SynthesisSlotRequest,
) -> tuple[SynthesisSlotRequest, ...]:
    return tuple(
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


def _budgeted_candidates(
    adapter: Any, candidate: SynthesisSlotRequest
) -> tuple[SynthesisSlotRequest, ...]:
    budget = _slot_prompt_budget(adapter, candidate.controls)
    if budget is None or _slot_request_fits(candidate, budget):
        return (candidate,)
    return _split_target_routes(candidate, budget) or (candidate,)


def _attach_mechanism_suggestions(
    adapter: Any,
    requests: Sequence[SynthesisSlotRequest],
    suggestions: Sequence[MechanismSuggestion],
) -> tuple[tuple[SynthesisSlotRequest, ...], tuple[MechanismSuggestion, ...]]:
    """Give each slot's suggestions to the first request that carries the slot.

    The requests are already split to fit their budget without suggestions,
    so a suggestion never moves a routed obligation to another part or
    removes a slot's own hazards.  A request whose prompt would no longer fit
    with them is sent without them, and they are returned as dropped.
    """
    by_slot: dict[str, list[MechanismSuggestion]] = {}
    for item in suggestions:
        by_slot.setdefault(item.slot_id, []).append(item)
    result: list[SynthesisSlotRequest] = []
    dropped: list[MechanismSuggestion] = []
    for request in requests:
        wanted = tuple(
            item for slot in request.slots for item in by_slot.pop(slot.slot_id, ())
        )
        if not wanted:
            result.append(request)
            continue
        candidate = _slot_request_with_parts(
            request,
            slots=request.slots,
            routes=request.routed_routes,
            mechanism_suggestions=wanted,
        )
        budget = _slot_prompt_budget(adapter, candidate.controls)
        if budget is not None and not _slot_request_fits(candidate, budget):
            dropped.extend(wanted)
            result.append(request)
            continue
        result.append(candidate)
    if by_slot:
        raise ValueError(
            "mechanism suggestions name slots no request carries: "
            + ", ".join(sorted(by_slot))
        )
    return tuple(result), tuple(dropped)


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


def _has_provider_slot(request: SynthesisSlotRequest) -> bool:
    """Return whether a request lists a slot only the provider can decide.

    A request without one is already answered by the local N/A fill, so the
    provider never sees it.  Its call reference stays allocated, which keeps
    the references of the other parts of the target stable.
    """
    return any(requires_provider_slot_analysis(slot) for slot in request.slots)


def _duration_inapplicable_slot(slot: SlotPlaceholder) -> ICASlot:
    """Materialize the canonical structural N/A for an ineligible duration."""
    return ICASlot(
        slot_id=slot.slot_id,
        responsibility=slot.responsibility,
        coordination_link=slot.coordination_link,
        control_action=slot.control_action,
        action_temporality=slot.action_temporality,
        uca_type=slot.uca_type,
        is_na=True,
        na_justification=_WRONG_DURATION_NA_JUSTIFICATION,
    )


def _duration_inapplicable_pair(
    route: ObligationRoute,
    slot: SlotPlaceholder,
) -> ObligationIcaConsideration:
    """Record deterministic N/A evidence for a routed duration slot."""
    return ObligationIcaConsideration(
        route_id=route.route_id,
        obligation_id=route.obligation_id,
        slot_id=slot.slot_id,
        disposition="proposed_not_applicable",
        evidence=("typed-action-temporality",),
        structural_inventory_complete=True,
        rationale=_WRONG_DURATION_NA_JUSTIFICATION,
    )


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
        controls = default_synthesis_controls()
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


def _typed_response(raw: Any) -> SynthesisSlotResponse:
    """Accept only the typed slot response the adapter contract names."""
    if isinstance(raw, SynthesisSlotResponse):
        return raw
    raise TypeError("slot adapter returned an unsupported response")


def _fallback_slot(slot: SlotPlaceholder, detail: str) -> ICASlot:
    """Retain a failed ordinary slot as unresolved, never as justified N/A."""
    return ICASlot(
        slot_id=slot.slot_id,
        responsibility=slot.responsibility,
        coordination_link=slot.coordination_link,
        control_action=slot.control_action,
        action_temporality=slot.action_temporality,
        uca_type=slot.uca_type,
        is_na=False,
        unresolved_reason=detail,
    )


def _slot_matches(value: ICASlot, expected: SlotPlaceholder) -> bool:
    """Require exact slot identity and target metadata."""
    return (
        value.slot_id == expected.slot_id
        and value.responsibility == expected.responsibility
        and value.coordination_link == expected.coordination_link
        and value.control_action == expected.control_action
        and (
            value.action_temporality is None
            or value.action_temporality == expected.action_temporality
        )
        and value.uca_type == expected.uca_type
    )


def _validate_compiled_slot(
    value: ICASlot,
    *,
    expected: SlotPlaceholder,
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
) -> None:
    """Validate a canonical slot without rewriting provider-authored prose.

    Provider responses have already crossed the strict draft compiler.  The
    outer fill seam still owns a second, read-only integrity check: exact slot
    identity and every canonical ICA hazard/constraint reference must remain
    bound to the request's authoritative artifacts.  It never recompiles the
    slot, because recompiling could rewrite compiler-owned prose.
    """
    if not _slot_matches(value, expected):
        raise ValueError(f"slot {expected.slot_id} changed its authoritative identity")
    if value.is_na:
        _require_na_rationale(expected.slot_id, value.na_justification)
    ICAEnumeration(slots=[value]).validate_against(loss_analysis, control_structure)


def _require_na_rationale(slot_id: str, rationale: str | None) -> None:
    """Require a present, non-blank N/A rationale; its meaning is the model's."""
    if rationale is None or not rationale.strip():
        raise ValueError(f"N/A slot {slot_id} requires a non-empty na_rationale")


def _slot_authority(
    slot: SlotPlaceholder,
    index: StpaIndex,
) -> tuple[str, str, str | None, set[str], set[str]]:
    """Return authoritative owner/action prose and valid PM/FB references."""
    if slot.responsibility is not None:
        return _responsibility_authority(slot, index.slot_path(slot))
    if slot.coordination_link is not None:
        return _coordination_authority(slot, index.slot_path(slot))
    raise ValueError(f"slot {slot.slot_id} has no authoritative owner")


def _responsibility_authority(
    slot: SlotPlaceholder,
    resolved: SlotPath,
) -> tuple[str, str, str | None, set[str], set[str]]:
    """Resolve an ordinary slot through its owning responsibility."""
    responsibility, action = resolved.owner, resolved.action
    if responsibility is None:
        raise ValueError(f"slot {slot.slot_id} has unknown responsibility")
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
    resolved: SlotPath,
) -> tuple[str, str, str | None, set[str], set[str]]:
    """Resolve a coordination slot through its exact link and mechanism."""
    link, source = resolved.link, resolved.owner
    if link is None:
        raise ValueError(f"slot {slot.slot_id} has unknown coordination link")
    if link.coordination_mechanism.cm_id != slot.control_action:
        raise ValueError(
            f"slot {slot.slot_id} action does not match coordination mechanism"
        )
    if source is None:
        # A link whose source is missing was never a valid control structure;
        # the bare StopIteration is the failure callers have always seen.
        raise StopIteration
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
    context = _finding_context(finding, slot=slot, control_structure=control_structure)
    return ICA(
        context_row=finding.context_row,
        process_model_context=context,
        ica_id=f"provider-finding-{index}",
        ica_text=text,
        deviation=finding.deviation.text,
        hazardous_context=finding.hazardous_context.strip(),
        loss_scenario=finding.loss_consequence.strip(),
        related_hazards=list(finding.related_hazard_ids),
        related_constraints=list(finding.related_constraint_ids),
        quality_warnings=_deviation_quality_warnings(
            finding.deviation.text, action_description
        ),
    )


def _merge_key(finding: IcaFindingDraft) -> tuple[str, str, str]:
    """Return the text a finding shares with its copies, as compiled."""
    return (
        finding.deviation.text.strip(),
        finding.hazardous_context.strip(),
        finding.loss_consequence.strip(),
    )


def _finding_groups(
    findings: Sequence[IcaFindingDraft],
) -> tuple[tuple[int, ...], ...]:
    """Group as-written finding indexes by shared key, in first-written order."""
    grouped: dict[tuple[str, str, str], list[int]] = {}
    for index, finding in enumerate(findings):
        grouped.setdefault(_merge_key(finding), []).append(index)
    return tuple(tuple(indexes) for indexes in grouped.values())


def _ordered_union(groups: Iterable[Iterable[str]]) -> tuple[str, ...]:
    """Join reference lists without repeats, in written order."""
    return tuple(dict.fromkeys(item for group in groups for item in group))


def _merged_finding(group: Sequence[IcaFindingDraft]) -> IcaFindingDraft:
    """Fold copies into the first finding with the union of their references."""
    first = group[0]
    if len(group) == 1:
        return first
    return IcaFindingDraft(
        deviation=first.deviation,
        hazardous_context=first.hazardous_context,
        loss_consequence=first.loss_consequence,
        related_hazard_ids=_ordered_union(f.related_hazard_ids for f in group),
        related_constraint_ids=_ordered_union(f.related_constraint_ids for f in group),
        process_model_refs=_ordered_union(f.process_model_refs for f in group),
        feedback_refs=_ordered_union(f.feedback_refs for f in group),
        context_row=first.context_row,
    )


def _remapped_result(
    result: ObligationIcaDraft, merged_index: Mapping[int, int]
) -> ObligationIcaDraft:
    """Point a result's finding indexes at the merged findings, once each."""
    if not result.finding_indexes:
        return result
    return ObligationIcaDraft(
        obligation_handle=result.obligation_handle,
        disposition=result.disposition,
        finding_indexes=tuple(
            dict.fromkeys(merged_index[index] for index in result.finding_indexes)
        ),
        rationale=result.rationale,
    )


def merge_equal_findings(
    draft: SlotIcaDraft,
) -> tuple[SlotIcaDraft, tuple[tuple[int, ...], ...]]:
    """Merge findings of one slot that share deviation, context, and consequence.

    A model may write one finding per unsafe context row, or one per pair, that
    differ in nothing else; each would compile to its own ICA and its own
    downstream requests.  The merged finding keeps the first finding's text and
    row and the union of the references, and each consideration result moves to
    the merged indexes.  Return the merged draft and, for each merged finding,
    the as-written indexes it stands for.  A draft with nothing to merge comes
    back unchanged.  Every merged object is built through validation.
    """
    if draft.is_na:
        return draft, ()
    groups = _finding_groups(draft.findings)
    if len(groups) == len(draft.findings):
        return draft, groups
    merged_index = {index: m for m, group in enumerate(groups) for index in group}
    return (
        SlotIcaDraft(
            slot_id=draft.slot_id,
            is_na=draft.is_na,
            na_rationale=draft.na_rationale,
            findings=tuple(
                _merged_finding([draft.findings[index] for index in group])
                for group in groups
            ),
            consideration_results=tuple(
                _remapped_result(result, merged_index)
                for result in draft.consideration_results
            ),
        ),
        groups,
    )


def ica_merge_entries(
    target_id: str,
    slot_id: str,
    written: SlotIcaDraft,
    groups: Sequence[Sequence[int]],
    ica_ids: Sequence[str],
) -> tuple[IcaMerge, ...]:
    """Record each merged group of a slot with the ICA it became.

    *groups* are the as-written indexes of each merged finding and *ica_ids*
    the ICA each compiled from; *written* is the draft before the merge.
    """
    return tuple(
        IcaMerge(
            target_id=target_id,
            slot_id=slot_id,
            ica_id=ica_id,
            findings=tuple(
                _merged_finding_record(index, written.findings[index])
                for index in group
            ),
        )
        for group, ica_id in zip(groups, ica_ids, strict=True)
        if len(group) > 1
    )


def _merged_finding_record(index: int, finding: IcaFindingDraft) -> IcaMergedFinding:
    return IcaMergedFinding(
        finding_index=index,
        context_row=finding.context_row,
        related_hazard_ids=finding.related_hazard_ids,
        related_constraint_ids=finding.related_constraint_ids,
    )


def _finding_context(
    finding: IcaFindingDraft,
    *,
    slot: SlotPlaceholder,
    control_structure: ControlStructure,
) -> dict[str, str] | None:
    """Resolve a cited context row of the slot's own control action."""
    if finding.context_row is None:
        return None
    rows = {
        row.row_id: row
        for row in control_action_context_rows(control_structure, slot.control_action)
    }
    row = rows.get(finding.context_row)
    if row is None:
        listed = ", ".join(rows) or "none"
        raise ValueError(
            f"finding cites context row {finding.context_row!r}, which is not a row "
            f"of {slot.control_action}'s context table (its rows: {listed})"
        )
    return dict(row.assignments)


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
    expected_field = DEVIATION_FIELD_BY_UCA_TYPE[slot.uca_type]
    if finding.deviation.field_name != expected_field:
        raise ValueError(
            f"{slot.uca_type.value} requires the {expected_field} deviation field"
        )
    deviation = finding.deviation.text.strip()
    if _looks_like_safeguard(deviation):
        raise ValueError(
            "finding describes a safeguard rather than unsafe control behavior"
        )
    if slot.uca_type is UCAType.wrong_duration and not is_wrong_duration_eligible(slot):
        raise ValueError(
            "WRONG_DURATION requires continuous or bounded_duration action temporality"
        )


def _validate_finding_references(
    finding: IcaFindingDraft,
    *,
    valid_process_models: set[str],
    valid_feedback: set[str],
    loss_analysis: LossAnalysis,
) -> None:
    """Validate hazard, constraint, process-model, and feedback references."""
    errors = finding_reference_errors(
        finding,
        valid_process_models=valid_process_models,
        valid_feedback=valid_feedback,
        loss_analysis=loss_analysis,
    )
    if errors:
        raise ValueError(errors[0])


def finding_reference_errors(
    finding: IcaFindingDraft,
    *,
    valid_process_models: set[str],
    valid_feedback: set[str],
    loss_analysis: LossAnalysis,
) -> list[str]:
    """List every broken reference of *finding*, each with what it may cite."""
    return [
        *_governance_errors(finding, loss_analysis),
        *_scope_errors(finding, valid_process_models, valid_feedback),
    ]


def _governance_errors(
    finding: IcaFindingDraft, loss_analysis: LossAnalysis
) -> list[str]:
    """List unknown hazards and constraints and each non-governing constraint."""
    hazard_ids = {item.hazard_id for item in loss_analysis.hazards}
    constraints = {
        item.constraint_id: item for item in loss_analysis.security_constraints
    }
    errors: list[str] = []
    unknown_hazards = set(finding.related_hazard_ids) - hazard_ids
    if unknown_hazards:
        errors.append(
            "finding references unknown hazards: " + ", ".join(sorted(unknown_hazards))
        )
    unknown_constraints = set(finding.related_constraint_ids) - set(constraints)
    if unknown_constraints:
        errors.append(
            "finding references unknown security constraints: "
            + ", ".join(sorted(unknown_constraints))
        )
    selected_hazards = set(finding.related_hazard_ids)
    for constraint_id in finding.related_constraint_ids:
        governed = constraints.get(constraint_id)
        if governed is not None and not selected_hazards.intersection(
            governed.related_hazards
        ):
            errors.append(
                f"constraint {constraint_id} does not govern the finding hazards "
                f"({constraint_id} governs {', '.join(governed.related_hazards)})"
            )
    return errors


def _scope_errors(
    finding: IcaFindingDraft, valid_process_models: set[str], valid_feedback: set[str]
) -> list[str]:
    """List process-model parts and feedback channels outside the target."""
    errors: list[str] = []
    for kind, cited, valid in (
        ("process-model parts", finding.process_model_refs, valid_process_models),
        ("feedback channels", finding.feedback_refs, valid_feedback),
    ):
        outside = set(cited) - valid
        if outside:
            errors.append(
                f"finding references {kind} outside the target: "
                f"{', '.join(sorted(outside))} ({_citable(valid)})"
            )
    return errors


def _citable(valid: set[str]) -> str:
    if not valid:
        return "the slot may cite none"
    return "the slot may cite " + ", ".join(sorted(valid))


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
        _slot_authority(slot, build_stpa_index(control_structure))
    )
    if draft.is_na:
        _require_na_rationale(slot.slot_id, draft.na_rationale)
        return ICASlot(
            slot_id=slot.slot_id,
            responsibility=slot.responsibility,
            coordination_link=slot.coordination_link,
            control_action=slot.control_action,
            action_temporality=slot.action_temporality,
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
        action_temporality=slot.action_temporality,
        uca_type=slot.uca_type,
        is_na=False,
        icas=compiled,
    ).aligned()


def compile_slot_provider_entry(
    value: SlotProviderEntry,
    *,
    slot: SlotPlaceholder,
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
) -> ICASlot:
    """Compile one strict provider slot draft."""
    if not isinstance(value, SlotIcaDraft):
        raise TypeError("provider slot entry must be a SlotIcaDraft")
    return compile_ica_slot_draft(
        value,
        slot=slot,
        loss_analysis=loss_analysis,
        control_structure=control_structure,
    )


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
    code: str = "slot_pair_unresolved",
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
                code=code,
                detail=detail,
                obligation_ids=(route.obligation_id,),
                refs=(route.route_id, slot.slot_id),
            ),
        ),
    )


def _unresolved_mechanism_pair(
    suggestion: MechanismSuggestion,
    detail: str,
    *,
    call_ref: str | None = None,
    code: str = "slot_pair_unresolved",
) -> MechanismIcaConsideration:
    """Record a suggestion whose slot gave it no valid result."""
    refs = () if call_ref is None else (call_ref,)
    return MechanismIcaConsideration(
        suggestion_id=str(suggestion.suggestion_id),
        mechanism_id=suggestion.mechanism_id,
        slot_id=suggestion.slot_id,
        disposition="unresolved",
        evidence=("slot-analysis-validation",),
        model_call_refs=refs,
        rationale=detail,
        diagnostics=(
            ConsiderationDiagnostic(
                code=code,
                detail=detail,
                refs=(str(suggestion.suggestion_id), suggestion.slot_id),
            ),
        ),
    )


def _draft_considerations(
    filled_slots: Iterable[SlotProviderEntry],
    request: SynthesisSlotRequest,
    compiled_slots: Mapping[str, ICASlot],
) -> tuple[ObligationIcaConsideration, ...]:
    """Materialize nested structured consideration results from slot drafts."""
    routes = {
        (route.obligation_id, slot_id): route
        for route in request.routed_routes
        for slot_id in route.slot_ids
    }
    suggestion_ids = {item.suggestion_id for item in request.mechanism_suggestions}
    values: list[ObligationIcaConsideration] = []
    for entry in filled_slots:
        if not isinstance(entry, SlotIcaDraft):
            continue
        slot = compiled_slots.get(entry.slot_id)
        if slot is None:
            continue
        for result in entry.consideration_results:
            if result.obligation_handle in suggestion_ids:
                continue
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
    return ObligationIcaConsideration(
        route_id=route.route_id,
        obligation_id=route.obligation_id,
        **_draft_result_fields(result, slot),
    )


def _draft_mechanism_considerations(
    filled_slots: Iterable[SlotProviderEntry],
    request: SynthesisSlotRequest,
    compiled_slots: Mapping[str, ICASlot],
) -> tuple[MechanismIcaConsideration, ...]:
    """Materialize the results a slot draft gives its mechanism suggestions.

    A result is keyed by the suggestion ID that its local handle resolves to;
    a key that is no suggestion of this slot belongs to an obligation.
    """
    suggestions = {
        (item.suggestion_id, item.slot_id): item
        for item in request.mechanism_suggestions
    }
    values: list[MechanismIcaConsideration] = []
    for entry in filled_slots:
        if not isinstance(entry, SlotIcaDraft):
            continue
        slot = compiled_slots.get(entry.slot_id)
        if slot is None:
            continue
        for result in entry.consideration_results:
            suggestion = suggestions.get((result.obligation_handle, entry.slot_id))
            if suggestion is not None:
                values.append(
                    MechanismIcaConsideration(
                        suggestion_id=str(suggestion.suggestion_id),
                        mechanism_id=suggestion.mechanism_id,
                        **_draft_result_fields(result, slot),
                    )
                )
    return tuple(values)


def _draft_result_fields(result: ObligationIcaDraft, slot: ICASlot) -> dict[str, Any]:
    """The slot evidence of one structured result, for either result kind."""
    if result.disposition == "finding":
        return _draft_finding_fields(result, slot)
    if result.disposition == "proposed_not_applicable":
        if not slot.is_na:
            raise ValueError("proposed non-applicability requires an N/A slot draft")
        return {
            "slot_id": slot.slot_id,
            "disposition": "proposed_not_applicable",
            "evidence": ("provider-structured-consideration",),
            "structural_inventory_complete": True,
            "rationale": result.rationale,
        }
    return {
        "slot_id": slot.slot_id,
        "disposition": "unresolved",
        "evidence": ("provider-structured-consideration",),
        "rationale": result.rationale,
    }


def _reference_union(icas: Iterable[ICA], attr: str) -> set[str]:
    return {reference for item in icas for reference in getattr(item, attr)}


def _draft_finding_fields(result: ObligationIcaDraft, slot: ICASlot) -> dict[str, Any]:
    """Compile a finding disposition and copy exact selected ICA references."""
    if any(index >= len(slot.icas) for index in result.finding_indexes):
        raise ValueError("structured consideration finding index is outside its slot")
    selected = tuple(slot.icas[index] for index in result.finding_indexes)
    controller = slot.responsibility or slot.coordination_link
    if controller is None:
        raise ValueError(f"slot {slot.slot_id} has no controller")
    return {
        "slot_id": slot.slot_id,
        "disposition": "finding",
        "ica_ids": tuple(item.ica_id for item in selected),
        "exec_candidate_ids": (
            candidate_id_for(controller, slot.control_action, slot.uca_type),
        ),
        "hazard_ids": tuple(sorted(_reference_union(selected, "related_hazards"))),
        "constraint_ids": tuple(
            sorted(_reference_union(selected, "related_constraints"))
        ),
        "evidence": ("provider-structured-consideration",),
        "rationale": result.rationale,
    }


def _prompt_budget_exceeded(error: BaseException | None) -> bool:
    """Tell whether a request failed because its prompt budget rejected it.

    The provider adapter's own preflight raises the budget failure itself; a
    rejection inside the provider call reaches slot filling as the cause.
    """
    return error is not None and (
        isinstance(error, PromptBudgetExceeded)
        or isinstance(error.__cause__, PromptBudgetExceeded)
    )


def is_request_schema_rejection(error: BaseException | None) -> bool:
    """Tell whether the provider rejected a request for its response schema.

    Every slot request of one fill carries a schema built the same way, so a
    provider that rejects one rejects each of them alike.  Only an HTTP 400
    can be such a rejection; each 400 in the error's cause chain is judged by
    these steps, the first that applies deciding:

    1. Structured body fields.  ``param`` naming the response format
       (``response_format``, or a part of it such as ``response_format.type``)
       or ``code`` ``invalid_json_schema`` or ``invalid_schema`` is a
       rejection; ``param`` naming any other parameter is not.  The fields
       come from the SDK error or, for a replayed error that keeps no body,
       from the body as its recorded text shows it.
    2. Size veto.  Text that speaks of a context length or window, tokens, or
       a maximum length is not a rejection, wherever in the text it does.
    3. Text.  A schema noun (``schema``, ``json_schema``, ``response_format``
       and its dotted parts) within three words of a rejection word (compile
       or compilation, invalid, unsupported, not supported, not valid, or
       cannot, could not, unable to, or failed to parse or convert, also
       passive), in either order, is a rejection.

    Any other 400, a 5xx, or a local failure is a per-slot failure.  The
    provider adapter raises its call failure as the cause, and a 400 may wrap
    the provider's own rejection, so a 400 judged not a rejection does not end
    the walk.
    """
    while error is not None:
        if getattr(error, "status_code", None) == 400 and _rejects_schema(error):
            return True
        error = error.__cause__
    return False


def _rejects_schema(error: BaseException) -> bool:
    """Apply the steps of ``is_request_schema_rejection`` to one HTTP 400."""
    text = str(error)
    recorded = dict(_BODY_FIELD.findall(text))
    param, code = (
        getattr(error, name, None) or recorded.get(name) for name in ("param", "code")
    )
    if isinstance(param, str) and _SCHEMA_PARAM.match(param):
        return True
    if code in _SCHEMA_CODES:
        return True
    if param:
        return False
    if _SIZE_VETO.search(text):
        return False
    return _SCHEMA_REJECTION_TEXT.search(text) is not None


def repeatable_rejection(error: BaseException | None) -> str | None:
    """Identify the HTTP 400 a slot request failed with, for the backstop.

    When two consecutive slot requests get the same HTTP 400 reply and the
    classifier of ``is_request_schema_rejection`` flags neither, the fill
    stops after the second.  The identity is ``rejection_digest`` of the
    first 400 in the error's cause chain: the SHA-256 of its full error text,
    which for an SDK error holds the reply body, so replies that differ
    anywhere, redacted parts or text past the call log's cut included, do
    not match.  A replay compares the digests its recording holds.  A schema
    rejection, which stops the fill on its own, a request its prompt budget
    rejected, and a 400 whose full text the size veto of
    ``is_request_schema_rejection`` marks as a context-length reply give
    ``None``: they keep their own handling.
    """
    if _prompt_budget_exceeded(error) or is_request_schema_rejection(error):
        return None
    while error is not None:
        if getattr(error, "status_code", None) == 400:
            return rejection_digest(error)
        error = error.__cause__
    return None


def _unresolved_diagnostic_code(error: BaseException | None) -> str:
    """Map a request failure to its stable local diagnostic code."""
    if _prompt_budget_exceeded(error):
        return "prompt_budget_exceeded"
    if isinstance(error, PromptContractError):
        return "prompt_contract_invalid"
    if is_request_schema_rejection(error):
        return REQUEST_SCHEMA_REJECTED
    return "slot_response_unresolved"


def _lost_slot_error_class(error: BaseException | None) -> str:
    """Name a lost slot by its exception class, or by the fill's stop."""
    if error is None:
        return "unknown"
    if is_request_schema_rejection(error):
        return REQUEST_SCHEMA_REJECTED
    return type(error).__name__


def _unresolved_pair_code(error: BaseException | None) -> str:
    """Name why a failed request leaves its routed pairs unresolved.

    A request its prompt budget rejected was never sent. The provider adapter
    raises its call failure as the cause. A cause the call log records as
    ``provider_contract_failure``, such as a reply cut off at its completion
    cap that no longer decodes, marks a provider contract failure; every other
    failure leaves the pairs analytically unresolved.
    """
    if _prompt_budget_exceeded(error):
        return SLOT_PROMPT_BUDGET_EXCEEDED
    if error is not None and is_provider_contract_failure(error.__cause__):
        return SLOT_PROVIDER_CONTRACT_FAILED
    return "slot_pair_unresolved"


def _record_unresolved_slot_fallbacks(
    request: SynthesisSlotRequest,
    detail: str,
    *,
    all_filled: dict[str, ICASlot],
    successful_slots: set[str] | None,
    lost: dict[str, SlotLoss] | None = None,
    error_class: str = "unknown",
    call_ref: str = "",
) -> None:
    """Materialize unresolved provider slots as typed unresolved values."""
    for slot in request.slots:
        slot_id = slot.slot_id
        if not requires_provider_slot_analysis(slot):
            continue
        if successful_slots is not None and slot_id in successful_slots:
            continue
        all_filled[slot_id] = _fallback_slot(slot, detail)
        if lost is not None:
            lost[slot_id] = SlotLoss(
                slot_id=slot_id,
                target_id=request.target_id,
                error_class=error_class,
                call_id=call_ref,
            )


def _record_unresolved_pairs(
    request: SynthesisSlotRequest,
    expected: Mapping[str, SlotPlaceholder],
    detail: str,
    *,
    all_pairs: list[ObligationIcaConsideration],
    call_ref: str,
    code: str = "slot_pair_unresolved",
) -> None:
    """Retain unresolved evidence for each routed, provider-owned slot."""
    for route in request.routed_routes:
        for slot_id in sorted(set(route.slot_ids).intersection(expected)):
            slot = expected[slot_id]
            if not requires_provider_slot_analysis(slot):
                continue
            all_pairs.append(
                _unresolved_pair(route, slot, detail, call_ref=call_ref, code=code)
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
    requests_sent: int,
    lost: dict[str, SlotLoss] | None = None,
    mechanism_pairs: list[MechanismIcaConsideration] | None = None,
    stop_code: str | None = None,
) -> None:
    """Retain one failed target request as unresolved local evidence.

    *stop_code* names the failure that stopped the fill at or before this
    request; it replaces the code the error alone would give.
    """
    diagnostics.append(
        ConsiderationDiagnostic(
            code=stop_code or _unresolved_diagnostic_code(error),
            detail=detail,
            refs=(request.target_id,),
        )
    )
    call_ref = call_ref or f"stpa-slot:{request.target_id}"
    _record_unresolved_slot_fallbacks(
        request,
        detail,
        all_filled=all_filled,
        successful_slots=successful_slots,
        lost=lost,
        error_class=stop_code or _lost_slot_error_class(error),
        call_ref=call_ref,
    )
    evidence.append(
        call_evidence(
            call_ref,
            requests_sent,
            "unresolved",
            request_digest=request.semantic_digest,
            controls=request.controls,
            response=response,
            digest_domain=SLOT_RESPONSE_DIGEST_DOMAIN,
        )
    )
    _record_unresolved_pairs(
        request,
        expected,
        detail,
        all_pairs=all_pairs,
        call_ref=call_ref,
        code=_unresolved_pair_code(error),
    )
    if mechanism_pairs is not None:
        mechanism_pairs.extend(
            _unresolved_mechanism_pair(
                item, detail, call_ref=call_ref, code=_unresolved_pair_code(error)
            )
            for item in request.mechanism_suggestions
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
    _validate_pair_finding_references(pair, value)


def _validate_pair_finding_references(
    pair: ObligationIcaConsideration, value: ICASlot
) -> None:
    referenced = tuple(item for item in value.icas if item.ica_id in pair.ica_ids)
    if set(pair.hazard_ids) != _reference_union(referenced, "related_hazards"):
        raise ValueError(
            "finding evidence hazards must exactly match its referenced ICAs"
        )
    if set(pair.constraint_ids) != _reference_union(referenced, "related_constraints"):
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


def _validate_mechanism_pair(
    pair: MechanismIcaConsideration,
    suggestion: MechanismSuggestion,
    slot: SlotPlaceholder,
    filled: Mapping[str, ICASlot],
) -> MechanismIcaConsideration:
    """Validate one suggestion's result as a routed pair is validated."""
    if pair.suggestion_id != suggestion.suggestion_id:
        raise ValueError("slot evidence is bound to another mechanism suggestion")
    if pair.slot_id != slot.slot_id:
        raise ValueError("slot evidence is bound to another slot")
    if pair.disposition == "finding":
        _validate_finding_pair(pair, slot, filled)
    elif pair.disposition == "proposed_not_applicable":
        _validate_non_applicable_pair(pair, slot, filled)
    elif pair.ica_ids or pair.exec_candidate_ids:
        raise ValueError("unresolved evidence cannot retain findings")
    return pair


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

    @property
    def mechanism_considerations(self) -> tuple[MechanismIcaConsideration, ...]:
        """Expose each mechanism suggestion's slot result, apart from obligations."""
        return self.result.mechanism_considerations

    @property
    def ica_hazard_verification(self) -> Any | None:
        """Expose the independent final-ICA semantic verification batch."""
        return self.result.ica_hazard_verification

    @property
    def lost_slots(self) -> tuple[SlotLoss, ...]:
        """Expose the provider-owned slots that ended unresolved."""
        return self.result.lost_slots

    @property
    def fill_failure(self) -> SlotFillFailure | None:
        """Expose the failure that stopped the fill, if one did."""
        return self.result.fill_failure

    @property
    def ica_merges(self) -> tuple[IcaMerge, ...]:
        """Expose the findings merged into one ICA while slots compiled."""
        return self.result.ica_merges

    @property
    def call_evidence(self) -> tuple[Any, ...]:
        """Expose slot and independent-verifier call evidence together."""
        values = list(self.result.call_evidence)
        verification = self.result.ica_hazard_verification
        values.extend(getattr(verification, "call_evidence", ()) or ())
        return tuple(values)

    @property
    def diagnostics(self) -> tuple[Any, ...]:
        """Expose slot and independent-verifier diagnostics together."""
        values = list(self.result.diagnostics)
        verification = self.result.ica_hazard_verification
        values.extend(getattr(verification, "diagnostics", ()) or ())
        return tuple(values)


@dataclass(slots=True)
class _SlotFillState:
    """Mutable accumulator for one bounded slot-fill run."""

    all_filled: dict[str, ICASlot]
    successful_slots: set[str]
    all_pairs: list[ObligationIcaConsideration]
    evidence: list[ConsiderationCallEvidence]
    diagnostics: list[ConsiderationDiagnostic]
    requests_sent: int = 0  # for the target request being processed
    # The ``repeatable_rejection`` identity of the last request sent, if any.
    last_rejection: str | None = None
    lost: dict[str, SlotLoss] = field(default_factory=dict)
    ica_merges: list[IcaMerge] = field(default_factory=list)
    mechanism_pairs: list[MechanismIcaConsideration] = field(default_factory=list)


def _initial_slot_fill_state(
    routes: Sequence[ObligationRoute],
    slots: Sequence[SlotPlaceholder],
) -> tuple[dict[str, SlotPlaceholder], _SlotFillState]:
    """Seed deterministic duration outcomes and routed evidence."""
    slot_by_id = {slot.slot_id: slot for slot in slots}
    all_filled = _duration_inapplicable_slots(slots)
    all_pairs = _duration_inapplicable_pairs(routes, slot_by_id)
    return slot_by_id, _SlotFillState(
        all_filled=all_filled,
        successful_slots=set(),
        all_pairs=all_pairs,
        evidence=[],
        diagnostics=[],
    )


def _duration_inapplicable_slots(
    slots: Sequence[SlotPlaceholder],
) -> dict[str, ICASlot]:
    """Materialize every deterministic duration N/A in a target map."""
    return {
        slot.slot_id: _duration_inapplicable_slot(slot)
        for slot in slots
        if not requires_provider_slot_analysis(slot)
    }


def _duration_inapplicable_pairs(
    routes: Sequence[ObligationRoute],
    slot_by_id: Mapping[str, SlotPlaceholder],
) -> list[ObligationIcaConsideration]:
    """Collect routed evidence for deterministic duration N/A slots."""
    all_pairs: list[ObligationIcaConsideration] = []
    for route in routes:
        if route.disposition != "targeted":
            continue
        for slot_id in sorted(set(route.slot_ids)):
            slot = slot_by_id[slot_id]
            if not requires_provider_slot_analysis(slot):
                all_pairs.append(_duration_inapplicable_pair(route, slot))
    return all_pairs


def _request_totals(
    requests: Sequence[SynthesisSlotRequest],
) -> dict[str, int]:
    """Count budget-split requests per target for stable call IDs."""
    totals: dict[str, int] = {}
    for request in requests:
        totals[request.target_id] = totals.get(request.target_id, 0) + 1
    return totals


def _request_call_ref(
    request: SynthesisSlotRequest,
    target_totals: Mapping[str, int],
    target_parts: dict[str, int],
) -> str:
    """Allocate the deterministic call reference for one request part."""
    target_parts[request.target_id] = target_parts.get(request.target_id, 0) + 1
    if target_totals[request.target_id] == 1:
        return f"stpa-slot:{request.target_id}"
    return f"stpa-slot:{request.target_id}:part-{target_parts[request.target_id]}"


def _coerce_request_response(
    method: Any,
    request: SynthesisSlotRequest,
) -> tuple[SynthesisSlotResponse | None, Exception | None]:
    """Call one provider target and retain request-binding failures locally."""
    try:
        response = _typed_response(method(request))
        if response.request_digest != request.semantic_digest:
            raise ValueError("slot response is bound to another request")
    except Exception as exc:  # noqa: BLE001 - retain request-local failures
        return None, exc
    return response, None


def _compile_response_entry(
    value: Any,
    *,
    request: SynthesisSlotRequest,
    expected: Mapping[str, SlotPlaceholder],
    by_id: Mapping[str, ICASlot],
    diagnostics: list[ConsiderationDiagnostic],
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
    provider_compiled: bool,
) -> tuple[str, ICASlot] | None:
    """Compile one response entry or record its non-fatal identity issue.

    Named provider adapters return canonical ``ICASlot`` values after the
    provider seam has compiled the strict draft, so provider entries are only
    checked for their exact binding and aligned once.  Fake adapters return
    ``SlotIcaDraft`` entries, which are compiled here.
    """
    slot_id = getattr(value, "slot_id", None)
    expected_slot = expected.get(slot_id)
    if expected_slot is None:
        diagnostics.append(
            ConsiderationDiagnostic(
                code="unexpected_slot_identity",
                detail=(
                    f"Response for {request.target_id} contained an unexpected slot "
                    f"{slot_id}"
                ),
                refs=(request.target_id, str(slot_id)),
            )
        )
        return None
    if slot_id in by_id:
        diagnostics.append(
            ConsiderationDiagnostic(
                code="duplicate_slot_identity",
                detail=f"Response for {request.target_id} repeated slot {slot_id}",
                refs=(request.target_id, slot_id),
            )
        )
        return None
    if not requires_provider_slot_analysis(expected_slot):
        return None
    if provider_compiled:
        if not isinstance(value, ICASlot):
            raise TypeError("provider response must contain compiled ICASlot values")
        _validate_compiled_slot(
            value,
            expected=expected_slot,
            loss_analysis=loss_analysis,
            control_structure=control_structure,
        )
        compiled = value.aligned()
    else:
        compiled = compile_slot_provider_entry(
            value,
            slot=expected_slot,
            loss_analysis=loss_analysis,
            control_structure=control_structure,
        ).aligned()
    return slot_id, compiled


def _compile_response_slots(
    response: SynthesisSlotResponse,
    *,
    request: SynthesisSlotRequest,
    expected: Mapping[str, SlotPlaceholder],
    diagnostics: list[ConsiderationDiagnostic],
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
) -> tuple[dict[str, ICASlot], Exception | None]:
    """Compile all provider slot entries while retaining local failures."""
    by_id: dict[str, ICASlot] = {}
    for value in response.filled_slots:
        try:
            compiled = _compile_response_entry(
                value,
                request=request,
                expected=expected,
                by_id=by_id,
                diagnostics=diagnostics,
                loss_analysis=loss_analysis,
                control_structure=control_structure,
                provider_compiled=response.adapter_kind == "provider",
            )
        except (TypeError, ValueError) as exc:
            return by_id, exc
        if compiled is not None:
            slot_id, slot = compiled
            by_id[slot_id] = slot
    return by_id, None


def _expected_slot_map(
    request: SynthesisSlotRequest,
) -> dict[str, SlotPlaceholder]:
    """Index one request's authoritative slots by their exact identities."""
    return {slot.slot_id: slot for slot in request.slots}


def _later_part_fills(
    by_id: Mapping[str, ICASlot],
    state: _SlotFillState,
) -> dict[str, ICASlot]:
    """Find slots a later part filled differently from the accepted fill.

    The first accepted part's fill of a slot stays authoritative: earlier
    parts' pairs already cite its ICA identifiers, and request order makes the
    choice deterministic.
    """
    return {
        slot_id: value
        for slot_id, value in by_id.items()
        if slot_id in state.successful_slots and state.all_filled[slot_id] != value
    }


def _ica_content(ica: ICA) -> ICA:
    """Return an ICA without its slot-relative identifier."""
    return ica.model_copy(update={"ica_id": ""})


def _rebind_pair(
    pair: ObligationIcaConsideration,
    part: ICASlot | None,
    authoritative: ICASlot | None,
) -> ObligationIcaConsideration:
    """Re-express a later part's finding on the authoritative fill's ICA ids.

    A later part numbers its own ICAs, so its identifiers mean nothing in the
    authoritative fill.  An ICA with identical content in the authoritative fill
    is the same finding; any other ICA has no counterpart and fails the pair.
    """
    if part is None or authoritative is None or pair.disposition != "finding":
        return pair
    own = {ica.ica_id: _ica_content(ica) for ica in part.icas}
    counterpart = {
        _ica_content(ica).model_dump_json(): ica.ica_id for ica in authoritative.icas
    }
    mapped: list[str] = []
    for ica_id in pair.ica_ids:
        found = (
            counterpart.get(own[ica_id].model_dump_json()) if ica_id in own else None
        )
        if found is None:
            raise ValueError(
                f"finding evidence references ICA {ica_id} that the slot's "
                "authoritative fill does not contain"
            )
        if found not in mapped:
            mapped.append(found)
    return pair.model_copy(update={"ica_ids": tuple(mapped)})


def _fill_missing_request_slots(
    request: SynthesisSlotRequest,
    by_id: Mapping[str, ICASlot],
    state: _SlotFillState,
    call_ref: str,
) -> None:
    """Fill provider-owned slots omitted by a successful response."""
    for slot in request.slots:
        if slot.slot_id in state.successful_slots:
            continue
        if not requires_provider_slot_analysis(slot):
            continue
        returned = by_id.get(slot.slot_id)
        if returned is None:
            state.lost[slot.slot_id] = SlotLoss(
                slot_id=slot.slot_id,
                target_id=request.target_id,
                error_class="slot_omitted_from_response",
                call_id=call_ref,
            )
            returned = _fallback_slot(
                slot, "No valid slot result was returned by the bounded adapter."
            )
        state.all_filled[slot.slot_id] = returned


def _validate_request_slots(
    request: SynthesisSlotRequest,
    state: _SlotFillState,
    *,
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
) -> Exception | None:
    """Validate one target's assembled slots without aborting other targets."""
    try:
        request_enumeration = ICAEnumeration(
            slots=[state.all_filled[slot.slot_id] for slot in request.slots]
        )
        request_enumeration.validate_against(loss_analysis, control_structure)
    except Exception as exc:  # noqa: BLE001 - retain request-local failures
        return exc
    return None


def _routed_provider_slot_ids(
    route: ObligationRoute,
    expected: Mapping[str, SlotPlaceholder],
) -> tuple[str, ...]:
    """Return routed slot IDs whose analysis remains provider-owned."""
    return tuple(
        sorted(
            slot_id
            for slot_id in set(route.slot_ids).intersection(expected)
            if requires_provider_slot_analysis(expected[slot_id])
        )
    )


def _record_request_failure(
    request: SynthesisSlotRequest,
    expected: Mapping[str, SlotPlaceholder],
    response: SynthesisSlotResponse | None,
    detail: str,
    *,
    state: _SlotFillState,
    call_ref: str,
    error: BaseException,
    stop_code: str | None = None,
) -> None:
    """Record a request-local failure through the common unresolved seam."""
    _record_request_unresolved(
        request,
        expected,
        detail,
        response=response,
        all_filled=state.all_filled,
        all_pairs=state.all_pairs,
        evidence=state.evidence,
        diagnostics=state.diagnostics,
        call_ref=call_ref,
        successful_slots=state.successful_slots,
        error=error,
        requests_sent=state.requests_sent,
        lost=state.lost,
        mechanism_pairs=state.mechanism_pairs,
        stop_code=stop_code,
    )


def _record_routed_pair(
    route: ObligationRoute,
    slot_id: str,
    expected: Mapping[str, SlotPlaceholder],
    pair_by_key: Mapping[tuple[str, str], ObligationIcaConsideration],
    *,
    call_ref: str,
    state: _SlotFillState,
    part_fills: Mapping[str, ICASlot],
) -> None:
    """Validate or retain unresolved evidence for one routed pair."""
    slot = expected[slot_id]
    pair = pair_by_key.get((route.obligation_id, slot_id))
    if pair is None:
        state.all_pairs.append(
            _unresolved_pair(
                route,
                slot,
                "Routed obligation/slot pair was not returned by the adapter.",
                call_ref=call_ref,
            )
        )
        return
    try:
        pair = _rebind_pair(
            pair, part_fills.get(slot_id), state.all_filled.get(slot_id)
        )
        state.all_pairs.append(_validate_pair(pair, route, slot, state.all_filled))
    except (TypeError, ValueError) as exc:
        state.all_pairs.append(
            _unresolved_pair(
                route,
                slot,
                f"Routed pair failed exact validation: {type(exc).__name__}: {exc}",
                call_ref=call_ref,
            )
        )


def _record_request_pairs(
    request: SynthesisSlotRequest,
    expected: Mapping[str, SlotPlaceholder],
    pair_by_key: Mapping[tuple[str, str], ObligationIcaConsideration],
    *,
    call_ref: str,
    state: _SlotFillState,
    part_fills: Mapping[str, ICASlot],
) -> None:
    """Validate each provider-owned slot pair in a successful request."""
    for route in request.routed_routes:
        for slot_id in _routed_provider_slot_ids(route, expected):
            _record_routed_pair(
                route,
                slot_id,
                expected,
                pair_by_key,
                call_ref=call_ref,
                state=state,
                part_fills=part_fills,
            )


def _record_response_error(
    request: SynthesisSlotRequest,
    expected: Mapping[str, SlotPlaceholder],
    response: SynthesisSlotResponse | None,
    response_error: Exception | None,
    *,
    state: _SlotFillState,
    call_ref: str,
    stop_code: str | None = None,
) -> bool:
    """Record a provider-call failure and report whether processing should stop."""
    if response_error is None:
        return False
    _record_request_failure(
        request,
        expected,
        response,
        f"Slot response could not be validated: {type(response_error).__name__}: {response_error}",
        state=state,
        call_ref=call_ref,
        error=response_error,
        stop_code=stop_code,
    )
    return True


def _process_valid_response(
    response: SynthesisSlotResponse,
    request: SynthesisSlotRequest,
    expected: Mapping[str, SlotPlaceholder],
    *,
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
    state: _SlotFillState,
    call_ref: str,
) -> None:
    """Compile, validate, and accept one request after response coercion."""
    by_id, compile_error = _compile_response_slots(
        response,
        request=request,
        expected=expected,
        diagnostics=state.diagnostics,
        loss_analysis=loss_analysis,
        control_structure=control_structure,
    )
    if compile_error is not None:
        _record_request_failure(
            request,
            expected,
            response,
            "Slot response failed typed ICA draft validation: "
            f"{type(compile_error).__name__}: {compile_error}",
            state=state,
            call_ref=call_ref,
            error=compile_error,
        )
        return
    part_fills = _later_part_fills(by_id, state)
    _fill_missing_request_slots(request, by_id, state, call_ref)
    validation_error = _validate_request_slots(
        request,
        state,
        loss_analysis=loss_analysis,
        control_structure=control_structure,
    )
    if validation_error is not None:
        _record_request_failure(
            request,
            expected,
            response,
            "Slot response failed exact STPA reference validation: "
            f"{type(validation_error).__name__}: {validation_error}",
            state=state,
            call_ref=call_ref,
            error=validation_error,
        )
        return
    # A later part's fill of a slot never replaces the first accepted fill, so
    # only a slot's first accepted fill brings its merges.
    state.ica_merges.extend(
        merge
        for merge in response.ica_merges
        if merge.slot_id not in state.successful_slots
    )
    state.successful_slots.update(by_id)
    _record_accepted_request(
        response,
        request,
        by_id,
        call_ref=call_ref,
        state=state,
        part_fills=part_fills,
    )


def _record_accepted_request(
    response: SynthesisSlotResponse,
    request: SynthesisSlotRequest,
    by_id: Mapping[str, ICASlot],
    *,
    call_ref: str,
    state: _SlotFillState,
    part_fills: Mapping[str, ICASlot],
) -> None:
    """Record accepted response evidence and validate each routed pair.

    Finding indexes in the response refer to the response's own fill, so the
    structured pairs compile against ``by_id`` before they move to the
    authoritative fill.
    """
    structured_pairs = _draft_considerations(
        response.filled_slots, request, {**state.all_filled, **by_id}
    )
    pair_by_key = {
        (pair.obligation_id, pair.slot_id): pair
        for pair in (*response.considerations, *structured_pairs)
    }
    state.evidence.append(
        call_evidence(
            call_ref,
            state.requests_sent,
            "accepted",
            request_digest=request.semantic_digest,
            controls=request.controls,
            response=response,
            digest_domain=SLOT_RESPONSE_DIGEST_DOMAIN,
        )
    )
    _record_request_pairs(
        request,
        {slot.slot_id: slot for slot in request.slots},
        pair_by_key,
        call_ref=call_ref,
        state=state,
        part_fills=part_fills,
    )
    _record_mechanism_pairs(response, request, by_id, call_ref=call_ref, state=state)


def _record_mechanism_pairs(
    response: SynthesisSlotResponse,
    request: SynthesisSlotRequest,
    by_id: Mapping[str, ICASlot],
    *,
    call_ref: str,
    state: _SlotFillState,
) -> None:
    """Validate each suggestion's result, or retain it as unresolved.

    Suggestions ride only on a slot's first request, so its accepted fill is
    the slot's authoritative fill and the results need no rebinding.
    """
    if not request.mechanism_suggestions:
        return
    try:
        structured = _draft_mechanism_considerations(
            response.filled_slots, request, {**state.all_filled, **by_id}
        )
    except (TypeError, ValueError) as exc:
        detail = (
            f"Mechanism results failed exact validation: {type(exc).__name__}: {exc}"
        )
        state.mechanism_pairs.extend(
            _unresolved_mechanism_pair(item, detail, call_ref=call_ref)
            for item in request.mechanism_suggestions
        )
        return
    by_key = {
        (pair.suggestion_id, pair.slot_id): pair
        for pair in (*response.mechanism_considerations, *structured)
    }
    expected = _expected_slot_map(request)
    for suggestion in request.mechanism_suggestions:
        pair = by_key.get((str(suggestion.suggestion_id), suggestion.slot_id))
        if pair is None:
            state.mechanism_pairs.append(
                _unresolved_mechanism_pair(
                    suggestion,
                    "Mechanism suggestion/slot pair was not returned by the adapter.",
                    call_ref=call_ref,
                )
            )
            continue
        try:
            state.mechanism_pairs.append(
                _validate_mechanism_pair(
                    pair, suggestion, expected[suggestion.slot_id], state.all_filled
                )
            )
        except (TypeError, ValueError) as exc:
            state.mechanism_pairs.append(
                _unresolved_mechanism_pair(
                    suggestion,
                    "Mechanism pair failed exact validation: "
                    f"{type(exc).__name__}: {exc}",
                    call_ref=call_ref,
                )
            )


def _process_slot_request(
    method: Any,
    request: SynthesisSlotRequest,
    *,
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
    state: _SlotFillState,
    call_ref: str,
) -> _FillStop | None:
    """Process one bounded target request and retain all local failures.

    Return the stop when the provider rejected the request schema, or gave
    this request the same HTTP 400 reply as the one before it; every other
    failure stays local to this request.
    """
    expected = _expected_slot_map(request)
    with count_requests() as sent:
        response, response_error = _coerce_request_response(method, request)
    state.requests_sent = sent.requests
    stop_code = _stop_code(response_error, state)
    if _record_response_error(
        request,
        expected,
        response,
        response_error,
        state=state,
        call_ref=call_ref,
        stop_code=stop_code,
    ):
        if stop_code is not None:
            return _FillStop(stop_code, cast(Exception, response_error), call_ref)
        return None
    response = cast(SynthesisSlotResponse, response)
    _process_valid_response(
        response,
        request,
        expected,
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        state=state,
        call_ref=call_ref,
    )
    return None


@dataclass(frozen=True)
class _FillStop:
    """The rejection that stopped the fill, and the request it answered."""

    code: str
    error: BaseException
    call_ref: str


def _stop_code(error: BaseException | None, state: _SlotFillState) -> str | None:
    """Name the stop a request's failure makes, and track the repeated 400.

    A schema rejection stops the fill at once.  Otherwise a
    ``repeatable_rejection`` identity equal to the previous request's stops
    it; any other outcome, a success included, leaves no rejection to repeat.
    Consecutive means consecutive outcomes as the fill sees them, after the
    client's one transport retry, so a 5xx retried into a 400 counts as that
    400.
    """
    if is_request_schema_rejection(error):
        state.last_rejection = None
        return REQUEST_SCHEMA_REJECTED
    rejection = repeatable_rejection(error)
    repeated = rejection is not None and rejection == state.last_rejection
    state.last_rejection = rejection
    return REQUEST_REJECTION_REPEATED if repeated else None


_UNSENT_CAUSES = {
    REQUEST_SCHEMA_REJECTED: (
        "the provider rejected the request schema of {ref}, and it rejects "
        "every slot request alike"
    ),
    REQUEST_REJECTION_REPEATED: (
        "the provider gave {ref} the same HTTP 400 reply as the slot request before it"
    ),
}


def _record_unsent_request(
    request: SynthesisSlotRequest,
    stop: _FillStop,
    *,
    state: _SlotFillState,
    call_ref: str,
) -> None:
    """Leave a request the fill stopped before sending unresolved."""
    state.requests_sent = 0
    cause = _UNSENT_CAUSES[stop.code].format(ref=stop.call_ref)
    _record_request_failure(
        request,
        _expected_slot_map(request),
        None,
        f"Slot request not sent: {cause}.",
        state=state,
        call_ref=call_ref,
        error=stop.error,
        stop_code=stop.code,
    )


def fill_synthesis_slots(
    adapter: SlotAnalysisAdapter,
    *,
    briefs: Sequence[NeutralObligationBrief],
    routes: Sequence[ObligationRoute],
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
    controls: AnalysisControls | None = None,
    mechanism_suggestions: Sequence[MechanismSuggestion] = (),
) -> SlotFillRunResult:
    """Fill all final slots, sending each target only its routed briefs.

    Each verified mechanism suggestion rides on the first request of its
    slot, beside that slot's own hazards and routed obligations, and gets
    exactly one result.  Without suggestions every request is unchanged.
    """
    requests = build_synthesis_slot_requests(
        briefs=briefs,
        routes=routes,
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        controls=controls,
    )
    requests = _budgeted_synthesis_slot_requests(adapter, requests)
    requests, dropped = _attach_mechanism_suggestions(
        adapter, requests, mechanism_suggestions
    )
    method = adapter.fill
    all_slots = final_slot_universe(control_structure)
    _slot_by_id, state = _initial_slot_fill_state(routes, all_slots)
    state.mechanism_pairs.extend(
        _unresolved_mechanism_pair(
            item,
            "The slot request could not carry this mechanism suggestion within "
            "its prompt budget.",
            code=SLOT_PROMPT_BUDGET_EXCEEDED,
        )
        for item in dropped
    )
    target_totals = _request_totals(requests)
    target_parts: dict[str, int] = {}
    stop: _FillStop | None = None
    unsent = 0

    for request in requests:
        call_ref = _request_call_ref(request, target_totals, target_parts)
        if not _has_provider_slot(request):
            continue
        if stop is not None:
            # After a stop the fill sends no further request.
            _record_unsent_request(request, stop, state=state, call_ref=call_ref)
            unsent += 1
            continue
        stop = _process_slot_request(
            method,
            request,
            loss_analysis=loss_analysis,
            control_structure=control_structure,
            state=state,
            call_ref=call_ref,
        )

    withhold_inverted_omissions(
        state.all_filled, state.all_pairs, state.mechanism_pairs, state.diagnostics
    )
    ordered_slots = tuple(state.all_filled[key] for key in sorted(state.all_filled))
    enumeration = ICAEnumeration(slots=list(ordered_slots))
    enumeration.validate_against(loss_analysis, control_structure)
    final = SynthesisSlotFillResult(
        ica_enumeration=enumeration,
        considerations=tuple(state.all_pairs),
        requests=requests,
        call_evidence=tuple(state.evidence),
        diagnostics=tuple(state.diagnostics),
        lost_slots=tuple(state.lost.values()),
        ica_merges=tuple(state.ica_merges),
        mechanism_considerations=tuple(state.mechanism_pairs),
        fill_failure=(
            None
            if stop is None
            else SlotFillFailure(
                code=stop.code, call_id=stop.call_ref, unsent_requests=unsent
            )
        ),
    )
    return SlotFillRunResult(result=final)


__all__ = [
    "REQUEST_REJECTION_REPEATED",
    "REQUEST_SCHEMA_REJECTED",
    "SlotFillRunResult",
    "build_synthesis_slot_requests",
    "compile_ica_slot_draft",
    "compile_slot_provider_entry",
    "fill_synthesis_slots",
    "final_slot_universe",
    "ica_merge_entries",
    "is_request_schema_rejection",
    "merge_equal_findings",
    "repeatable_rejection",
]
