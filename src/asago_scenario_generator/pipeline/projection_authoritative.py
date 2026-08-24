"""Authoritative candidate projection, qualification, and bounded allocation.

The authoritative projection boundary's deterministic machinery:
qualification of raw catalogue records, source-influence and ingress
allocation, pattern-state assembly, and the bounded lazy allocator.
Extracted from ``pipeline.projection`` so the projection models, readiness
gate, and combination machinery stay independently mutation-scoped.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from asago_scenario_generator.models.attack_pattern import (
    AttackPattern,
    CanonicalAttackChain,
    CanonicalResourceReference,
    EntryPointResourceReference,
    StepOmission,
    TaxonomyResolver,
    validate_attack_pattern,
)
from asago_scenario_generator.pipeline.projection import (
    CapabilityFactSnapshot,
    ProjectedCandidate,
    ProjectionBudget,
    ProjectionIssue,
    ProjectionLimitation,
    _PatternProjectionState,
    _build_candidate_from_combination,
    _canonical_json,
    _content_pin,
    _count_compatible_combinations,
    _evaluate_preconditions,
    _evaluate_projection_conditions,
    _iter_compatible_combinations,
    _normalize_semantic_order,
    _pattern_pin,
    _references_for_slot,
    _resource_id,
)


def _resolve_projection_budget(
    budget: ProjectionBudget | None,
) -> ProjectionBudget:
    """Return the caller budget, or a default projection budget."""
    return budget or ProjectionBudget()


def _catalog_content_pin(
    qualified: list[tuple[AttackPattern, str]],
) -> str:
    """Pin the ordered, deduplicated qualified pattern catalog."""
    return _content_pin(
        "asago-scenario-generator:authoritative-catalog:v1",
        [pattern_pin for _, pattern_pin in qualified],
    )


def _sorted_emitted_candidates(
    by_identity: dict[str, ProjectedCandidate],
) -> tuple[ProjectedCandidate, ...]:
    """Return emitted candidates ordered by candidate id."""
    return tuple(by_identity[key] for key in sorted(by_identity))


def _infeasibility_key(item: ProjectionIssue) -> tuple[Any, ...]:
    """Return the deterministic ordering key for an infeasibility."""
    return (
        item.pattern_id,
        item.code,
        item.step_id or "",
        item.slot_id or "",
    )


def _sorted_infeasibilities(
    issues: list[ProjectionIssue],
) -> tuple[ProjectionIssue, ...]:
    """Return deduplicated infeasibilities in deterministic order."""
    return tuple(sorted(_dedupe_projection_issues(issues), key=_infeasibility_key))


def _limitation_key(item: ProjectionLimitation) -> tuple[str, str]:
    """Return the deterministic ordering key for a limitation."""
    return (item.pattern_id, item.code)


def _sorted_limitations(
    limitations: list[ProjectionLimitation],
) -> tuple[ProjectionLimitation, ...]:
    """Return limitations in deterministic order."""
    return tuple(sorted(limitations, key=_limitation_key))


def _authoritative_records_type_check(records: Any) -> None:
    """Reject non-sequence record inputs up front."""
    if not isinstance(records, Sequence) or isinstance(records, (str, bytes, dict)):
        raise TypeError("authoritative projection requires a sequence of raw records")


def _qualify_authoritative_pattern(
    raw: Any,
    taxonomy_resolver: TaxonomyResolver,
) -> tuple[AttackPattern, str]:
    """Qualify one raw canonical-chain record into a pinned pattern."""
    if not isinstance(raw, dict) or "canonical_chain" not in raw:
        raise ValueError(
            "authoritative projection requires qualified canonical-chain records; "
            "legacy catalogue records are isolated"
        )
    try:
        pattern = validate_attack_pattern(raw, taxonomy_resolver)
        pattern = AttackPattern.model_validate(
            _normalize_semantic_order(pattern.model_dump(mode="json"))
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"authoritative attack pattern qualification failed: {exc}"
        ) from exc
    return pattern, _pattern_pin(pattern)


def _resolve_qualified_patterns(
    qualified: list[tuple[AttackPattern, str]],
) -> list[tuple[AttackPattern, str]]:
    """Detect conflicting duplicate pattern ids and sort by pattern id."""
    by_pattern: dict[str, tuple[AttackPattern, str]] = {}
    for item in qualified:
        pattern, pattern_pin = item
        previous = by_pattern.get(pattern.id)
        if previous is not None and previous[1] != pattern_pin:
            raise ValueError("conflicting authoritative records share one pattern id")
        by_pattern[pattern.id] = item
    return [by_pattern[key] for key in sorted(by_pattern)]


def _qualify_authoritative_records(
    records: Sequence[dict[str, Any]],
    taxonomy_resolver: TaxonomyResolver,
) -> list[tuple[AttackPattern, str]]:
    """Qualify every raw record and resolve duplicates deterministically."""
    return _resolve_qualified_patterns(
        [_qualify_authoritative_pattern(raw, taxonomy_resolver) for raw in records]
    )


def _profile_compatibility_gaps(
    pattern: AttackPattern,
    snapshot: CapabilityFactSnapshot,
) -> tuple[list[str], list[str], bool]:
    """Return (missing zones, missing KC codes, any-satisfied flag)."""
    prerequisites = pattern.prerequisite_capabilities
    missing_zones = sorted(
        set(prerequisites.min_zones) - set(snapshot.profile.zones_active)
    )
    kc_requires = prerequisites.kc_requires
    profile_kc = set(snapshot.profile.kc_subcodes)
    missing_all = sorted(set(kc_requires.all) - profile_kc) if kc_requires else []
    any_satisfied = (
        not kc_requires
        or not kc_requires.any
        or bool(set(kc_requires.any) & profile_kc)
    )
    return missing_zones, missing_all, any_satisfied


def _incompatible_profile_issue(
    pattern: AttackPattern,
    missing_zones: list[str],
    missing_all: list[str],
    any_satisfied: bool,
    kc_requires: Any,
) -> ProjectionIssue:
    """Build the incompatible_profile issue with a joined detail list."""
    details = []
    if missing_zones:
        details.append(f"missing zones: {', '.join(missing_zones)}")
    if missing_all:
        details.append(f"missing required KC codes: {', '.join(missing_all)}")
    if not any_satisfied and kc_requires:
        details.append(
            "requires any KC code from: " + ", ".join(sorted(kc_requires.any))
        )
    return ProjectionIssue(
        code="incompatible_profile",
        pattern_id=pattern.id,
        detail="; ".join(details),
    )


def _profile_gate_failure_issue(
    pattern: AttackPattern,
    snapshot: CapabilityFactSnapshot,
) -> ProjectionIssue | None:
    """Return the profile gate issue, or None when the profile fits."""
    missing_zones, missing_all, any_satisfied = _profile_compatibility_gaps(
        pattern, snapshot
    )
    if missing_zones or missing_all or not any_satisfied:
        return _incompatible_profile_issue(
            pattern,
            missing_zones,
            missing_all,
            any_satisfied,
            pattern.prerequisite_capabilities.kc_requires,
        )
    return None


def _results_contain_unknown(results: Any) -> bool:
    """True when any evaluated result is unresolved."""
    return any(item.result == "unknown" for item in results)


def _results_contain_false(results: Any) -> bool:
    """True when any evaluated result is false."""
    return any(item.result == "false" for item in results)


def _unresolved_condition_issue(
    pattern: AttackPattern,
    condition_results: Any,
) -> ProjectionIssue:
    """Build the unresolved_condition issue for projection conditions."""
    first_unknown = next(item for item in condition_results if item.result == "unknown")
    return ProjectionIssue(
        code="unresolved_condition",
        pattern_id=pattern.id,
        step_id=first_unknown.condition_step_id,
        detail="one or more authoritative condition facts are unresolved",
        condition_results=condition_results,
    )


def _unresolved_precondition_issue(
    pattern: AttackPattern,
    condition_results: Any,
    precondition_results: Any,
) -> ProjectionIssue:
    """Build the unresolved_condition issue for selected-step preconditions."""
    first_unknown = next(
        item for item in precondition_results if item.result == "unknown"
    )
    return ProjectionIssue(
        code="unresolved_condition",
        pattern_id=pattern.id,
        step_id=first_unknown.step_id,
        detail="one or more selected-step preconditions are unresolved",
        condition_results=condition_results,
        precondition_results=precondition_results,
    )


def _false_precondition_issue(
    pattern: AttackPattern,
    condition_results: Any,
    precondition_results: Any,
) -> ProjectionIssue:
    """Build the precondition_not_satisfied issue."""
    first_false = next(item for item in precondition_results if item.result == "false")
    return ProjectionIssue(
        code="precondition_not_satisfied",
        pattern_id=pattern.id,
        step_id=first_false.step_id,
        detail="one or more selected-step preconditions are false",
        condition_results=condition_results,
        precondition_results=precondition_results,
    )


def _inapplicable_projection_issue(
    pattern: AttackPattern,
    condition_results: Any,
) -> ProjectionIssue:
    """Build the inapplicable_projection issue."""
    return ProjectionIssue(
        code="inapplicable_projection",
        pattern_id=pattern.id,
        detail=(
            "condition results omit the terminal outcome or every "
            "attacker-controlled step"
        ),
        condition_results=condition_results,
    )


def _select_conditionally_required_steps(
    chain: CanonicalAttackChain,
    result_by_step: dict[str, str],
) -> tuple[str, ...]:
    """Select required steps plus conditional steps evaluated true."""
    return tuple(
        step.step_id
        for step in chain.steps
        if step.requirement == "required" or result_by_step[step.step_id] == "true"
    )


def _projection_is_applicable(
    chain: CanonicalAttackChain,
    selected: tuple[str, ...],
) -> bool:
    """True when selected steps reach the terminal outcome with an
    attacker-controlled step."""
    if chain.steps[-1].step_id not in selected:
        return False
    return any(
        step.attacker_controlled and step.step_id in set(selected)
        for step in chain.steps
    )


def _omitted_conditional_steps(
    chain: CanonicalAttackChain,
    result_by_step: dict[str, str],
) -> tuple[StepOmission, ...]:
    """Return omissions for conditional steps evaluated false."""
    return tuple(
        StepOmission(step_id=step.step_id, reason="condition_false")
        for step in chain.steps
        if step.requirement == "conditional" and result_by_step[step.step_id] == "false"
    )


def _precondition_results_or_none(
    pattern: AttackPattern,
    selected: tuple[str, ...],
    snapshot: CapabilityFactSnapshot,
    condition_results: Any,
    issues: list[ProjectionIssue],
) -> Any:
    """Return precondition results, or None after recording a gate issue."""
    precondition_results = _evaluate_preconditions(pattern, selected, snapshot)
    if _results_contain_unknown(precondition_results):
        issues.append(
            _unresolved_precondition_issue(
                pattern, condition_results, precondition_results
            )
        )
        return None
    if _results_contain_false(precondition_results):
        issues.append(
            _false_precondition_issue(pattern, condition_results, precondition_results)
        )
        return None
    return precondition_results


def _profile_and_condition_gate(
    pattern: AttackPattern,
    snapshot: CapabilityFactSnapshot,
    issues: list[ProjectionIssue],
) -> Any:
    """Return condition results, or None after recording a gate issue."""
    profile_issue = _profile_gate_failure_issue(pattern, snapshot)
    if profile_issue is not None:
        issues.append(profile_issue)
        return None
    condition_results = _evaluate_projection_conditions(pattern, snapshot)
    if _results_contain_unknown(condition_results):
        issues.append(_unresolved_condition_issue(pattern, condition_results))
        return None
    return condition_results


def _qualified_condition_state(
    pattern: AttackPattern,
    snapshot: CapabilityFactSnapshot,
    chain: CanonicalAttackChain,
    issues: list[ProjectionIssue],
) -> Any:
    """Run gate checks and return (conditions, selected, omissions,
    preconditions), or None after recording the failing issue."""
    condition_results = _profile_and_condition_gate(pattern, snapshot, issues)
    if condition_results is None:
        return None
    result_by_step = {item.condition_step_id: item.result for item in condition_results}
    selected = _select_conditionally_required_steps(chain, result_by_step)
    if not _projection_is_applicable(chain, selected):
        issues.append(_inapplicable_projection_issue(pattern, condition_results))
        return None
    omissions = _omitted_conditional_steps(chain, result_by_step)
    precondition_results = _precondition_results_or_none(
        pattern, selected, snapshot, condition_results, issues
    )
    if precondition_results is None:
        return None
    return condition_results, selected, omissions, precondition_results


def _ingress_slot_index(chain: CanonicalAttackChain) -> int:
    """Return the chain resource slot index of the initial ingress."""
    return next(
        index
        for index, slot in enumerate(chain.resource_slots)
        if slot.slot_id == chain.initial_ingress_slot_id
    )


def _gather_slot_options(
    chain: CanonicalAttackChain,
    snapshot: CapabilityFactSnapshot,
) -> tuple[list[tuple[CanonicalResourceReference, ...]], list[Any]]:
    """Return per-slot option sets plus any slots with no options."""
    option_sets: list[tuple[CanonicalResourceReference, ...]] = []
    missing_slots = []
    for slot in chain.resource_slots:
        options = _references_for_slot(
            slot,
            snapshot,
            initial_ingress=slot.slot_id == chain.initial_ingress_slot_id,
        )
        option_sets.append(options)
        if not options:
            missing_slots.append(slot)
    return option_sets, missing_slots


def _source_influence_relation_links(
    chain: CanonicalAttackChain,
    selected: tuple[str, ...],
) -> list[Any]:
    """Return source_influence links over selected chain steps."""
    return [
        link
        for step in chain.steps
        if step.step_id in set(selected)
        for link in step.resource_links
        if link.role == "source_influence"
    ]


def _relation_slot_ids(relation_links: list[Any]) -> set[str]:
    """Return slot ids implicated by source-influence relation links."""
    return (
        {link.slot_id for link in relation_links}
        | {str(link.trust_boundary_slot_id) for link in relation_links}
        | {str(link.target_ingress_slot_id) for link in relation_links}
    )


def _source_influence_relation_state(
    chain: CanonicalAttackChain,
    selected: tuple[str, ...],
) -> tuple[list[Any], set[str], bool]:
    """Return (relation links, implicated slot ids, explicit-id flag)."""
    relation_links = _source_influence_relation_links(chain, selected)
    relation_slot_ids = _relation_slot_ids(relation_links)
    relation_has_explicit_ids = any(
        item.allowed_resource_ids
        for item in chain.resource_slots
        if item.slot_id in relation_slot_ids
    )
    return relation_links, relation_slot_ids, relation_has_explicit_ids


def _check_simple_missing_slot(
    slot: Any,
    relation_slot_ids: set[str],
    relation_has_explicit_ids: bool,
    pattern: AttackPattern,
) -> ProjectionIssue | None:
    """Return the simple missing-resource issue, or None for relation slots."""
    if slot.slot_id not in relation_slot_ids or not relation_has_explicit_ids:
        return ProjectionIssue(
            code="missing_compatible_resource",
            pattern_id=pattern.id,
            slot_id=slot.slot_id,
            detail=f"no compatible canonical {slot.kind} resource for slot",
        )
    return None


def _slot_by_id(chain: CanonicalAttackChain, slot_id: str) -> Any:
    """Return the chain resource slot with the given id."""
    return next(item for item in chain.resource_slots if item.slot_id == slot_id)


def _source_influence_target_id(
    link: Any,
    chain: CanonicalAttackChain,
    option_sets: list[tuple[CanonicalResourceReference, ...]],
    ingress_index: int,
) -> Any:
    """Return the relation target ingress id, from ingress options or
    explicit allowed ids."""
    ingress_options = option_sets[ingress_index] if option_sets else ()
    if not ingress_options:
        allowed_ids = next(
            (
                item.allowed_resource_ids
                for item in chain.resource_slots
                if item.slot_id == str(link.target_ingress_slot_id)
            ),
            (),
        )
        return next(iter(allowed_ids), None)
    return _resource_id(ingress_options[0])


def _source_influence_failure_issue(
    pattern: AttackPattern,
    slot: Any,
    link: Any,
    chain: CanonicalAttackChain,
    option_sets: list[tuple[CanonicalResourceReference, ...]],
    ingress_index: int,
    snapshot: CapabilityFactSnapshot,
) -> ProjectionIssue:
    """Build the source_influence_relation_infeasible issue."""
    source_slot = _slot_by_id(chain, link.slot_id)
    target_id = _source_influence_target_id(link, chain, option_sets, ingress_index)
    target = (
        snapshot.profile.resolve_entry_point(target_id)
        if isinstance(target_id, str)
        else None
    )
    boundary_slot = _slot_by_id(chain, str(link.trust_boundary_slot_id))
    return ProjectionIssue(
        code="source_influence_relation_infeasible",
        pattern_id=pattern.id,
        slot_id=slot.slot_id,
        detail="source-influence relation resource is not reviewed",
        source_id=next(iter(source_slot.allowed_resource_ids), None),
        boundary_id=next(iter(boundary_slot.allowed_resource_ids), None),
        target_ingress_id=target_id,
        canonical_ingress_id=target_id,
        expected_target_zone=(
            target.effective_ingress_zone if target is not None else None
        ),
        actual_boundary_zones="unreviewed",
        expected_source_kind=(link.source_identity_kind or source_slot.kind),
        actual_binding_kind=source_slot.kind,
        guidance=("Review the explicit ingress_zone or trust-boundary declaration."),
    )


def _record_missing_slot_issues(
    pattern: AttackPattern,
    chain: CanonicalAttackChain,
    snapshot: CapabilityFactSnapshot,
    selected: tuple[str, ...],
    option_sets: list[tuple[CanonicalResourceReference, ...]],
    ingress_index: int,
    missing_slots: list[Any],
    issues: list[ProjectionIssue],
) -> None:
    """Record missing-resource or infeasible relation issues per slot."""
    relation_links, relation_slot_ids, relation_has_explicit_ids = (
        _source_influence_relation_state(chain, selected)
    )
    for slot in missing_slots:
        simple_issue = _check_simple_missing_slot(
            slot, relation_slot_ids, relation_has_explicit_ids, pattern
        )
        if simple_issue is not None:
            issues.append(simple_issue)
            continue
        issues.append(
            _source_influence_failure_issue(
                pattern,
                slot,
                relation_links[0],
                chain,
                option_sets,
                ingress_index,
                snapshot,
            )
        )


def _direct_ingress_options(
    ingress_options: tuple[CanonicalResourceReference, ...],
    snapshot: CapabilityFactSnapshot,
) -> tuple[CanonicalResourceReference, ...]:
    """Return directly controllable entry-point options."""
    return tuple(
        option
        for option in ingress_options
        if isinstance(option, EntryPointResourceReference)
        and snapshot.profile.resolve_entry_point(
            option.entry_point_id
        ).effective_controllability
        == "direct"
    )


def _has_source_influence_activation(
    chain: CanonicalAttackChain,
    selected: tuple[str, ...],
) -> bool:
    """True when a selected step links source influence to the ingress."""
    selected_set = set(selected)
    return any(
        link.role == "source_influence"
        and link.target_ingress_slot_id == chain.initial_ingress_slot_id
        for step in chain.steps
        if step.step_id in selected_set
        for link in step.resource_links
    )


def _has_direct_ingress_activation(
    chain: CanonicalAttackChain,
    selected: tuple[str, ...],
) -> bool:
    """True when a selected step links direct ingress to the ingress."""
    selected_set = set(selected)
    return any(
        link.role == "ingress" and link.slot_id == chain.initial_ingress_slot_id
        for step in chain.steps
        if step.step_id in selected_set
        for link in step.resource_links
    )


def _no_activation_violation(
    has_source_influence_activation: bool,
    has_direct_ingress_activation: bool,
) -> str | None:
    """Return the activation violation detail, or None when valid."""
    if not has_source_influence_activation and not has_direct_ingress_activation:
        return (
            "no activation mechanism (ingress or source_influence) among selected steps"
        )
    if has_source_influence_activation and has_direct_ingress_activation:
        return (
            "contradictory activation: selected steps contain both "
            "direct ingress and source_influence links to the "
            "initial ingress"
        )
    return None


def _resolve_ingress_activation(
    chain: CanonicalAttackChain,
    option_sets: list[tuple[CanonicalResourceReference, ...]],
    ingress_index: int,
    selected: tuple[str, ...],
    pattern: AttackPattern,
    snapshot: CapabilityFactSnapshot,
    issues: list[ProjectionIssue],
) -> bool:
    """Resolve the activation mode and pin ingress options.

    Returns True when projection may proceed; False when the pattern is
    rejected (issue recorded) or activation is infeasible (silent skip).
    """
    direct_ingress_options = _direct_ingress_options(
        option_sets[ingress_index], snapshot
    )
    has_source_influence_activation = _has_source_influence_activation(chain, selected)
    has_direct_ingress_activation = _has_direct_ingress_activation(chain, selected)
    violation_detail = _no_activation_violation(
        has_source_influence_activation, has_direct_ingress_activation
    )
    if violation_detail is not None:
        issues.append(
            ProjectionIssue(
                code="unsupported_requirement_derivation",
                pattern_id=pattern.id,
                detail=violation_detail,
            )
        )
        return False
    if has_source_influence_activation:
        return bool(option_sets[ingress_index])
    if len(direct_ingress_options) != len(option_sets[ingress_index]):
        issues.append(
            ProjectionIssue(
                code="unsupported_requirement_derivation",
                pattern_id=pattern.id,
                detail=(
                    "indirect ingress requires explicit upstream-source and "
                    "trust-boundary linkage"
                ),
            )
        )
    if not direct_ingress_options:
        return False
    option_sets[ingress_index] = direct_ingress_options
    return True


def _zero_bindings_issue(
    pattern: AttackPattern,
    chain: CanonicalAttackChain,
) -> ProjectionIssue:
    """Build the distinctness-constrained missing-resource issue."""
    constrained_slot = next(
        slot for slot in chain.resource_slots if slot.distinct_from_slot_ids
    )
    return ProjectionIssue(
        code="missing_compatible_resource",
        pattern_id=pattern.id,
        slot_id=constrained_slot.slot_id,
        detail=(
            "no concrete resource assignment satisfies explicit "
            "per-slot distinctness constraints"
        ),
    )


def _assemble_pattern_state(
    pattern: AttackPattern,
    pattern_pin: str,
    snapshot: CapabilityFactSnapshot,
    catalog_pin: str,
    chain: CanonicalAttackChain,
    condition_results: Any,
    selected: tuple[str, ...],
    omissions: tuple[StepOmission, ...],
    precondition_results: Any,
    candidate_groups: list[_PatternProjectionState],
    issues: list[ProjectionIssue],
) -> bool:
    """Enqueue the pattern's lazy projection state when slot gates pass."""
    ingress_index = _ingress_slot_index(chain)
    option_sets, missing_slots = _gather_slot_options(chain, snapshot)
    if missing_slots:
        _record_missing_slot_issues(
            pattern,
            chain,
            snapshot,
            selected,
            option_sets,
            ingress_index,
            missing_slots,
            issues,
        )
        return False
    if not _resolve_ingress_activation(
        chain, option_sets, ingress_index, selected, pattern, snapshot, issues
    ):
        return False
    total_bindings = _count_compatible_combinations(
        chain.resource_slots, tuple(option_sets)
    )
    if total_bindings == 0:
        issues.append(_zero_bindings_issue(pattern, chain))
        return False
    combination_iter = _iter_compatible_combinations(
        chain.resource_slots, tuple(option_sets)
    )
    candidate_groups.append(
        _PatternProjectionState(
            pattern_id=pattern.id,
            chain=chain,
            selected=selected,
            condition_results=condition_results,
            omissions=omissions,
            option_sets=tuple(option_sets),
            total_bindings=total_bindings,
            catalog_pin=catalog_pin,
            pattern_pin=pattern_pin,
            precondition_results=precondition_results,
            combination_iter=combination_iter,
            snapshot=snapshot,
        )
    )
    return True


def _project_authoritative_pattern(
    pattern: AttackPattern,
    pattern_pin: str,
    snapshot: CapabilityFactSnapshot,
    catalog_pin: str,
    candidate_groups: list[_PatternProjectionState],
    issues: list[ProjectionIssue],
) -> bool:
    """Qualify one pattern and enqueue its lazy projection state."""
    chain = pattern.canonical_chain
    qualified_state = _qualified_condition_state(pattern, snapshot, chain, issues)
    if qualified_state is None:
        return False
    condition_results, selected, omissions, precondition_results = qualified_state
    return _assemble_pattern_state(
        pattern,
        pattern_pin,
        snapshot,
        catalog_pin,
        chain,
        condition_results,
        selected,
        omissions,
        precondition_results,
        candidate_groups,
        issues,
    )


def _target_ingress_reference(
    state: _PatternProjectionState,
    ingress_index: int,
    target_id: str,
) -> Any:
    """Return the entry-point reference for a coverage target, if any."""
    return next(
        (
            ref
            for ref in state.option_sets[ingress_index]
            if isinstance(ref, EntryPointResourceReference)
            and ref.entry_point_id == target_id
        ),
        None,
    )


def _dedupe_projection_issues(
    issues: list[ProjectionIssue],
) -> Any:
    """Deduplicate issues by canonical JSON content, preserving last."""
    return {
        _canonical_json(issue.model_dump(mode="json")): issue for issue in issues
    }.values()


class _AuthoritativeCandidateAllocator:
    """Bounded, lazy candidate allocation for an authoritative batch.

    Every derivation consumes exactly one work unit, including structural
    rejects; no helper scans an iterator.  Candidates discovered during
    target reservation are kept pending so a later variant fill cannot
    silently discard a feasible candidate.
    """

    def __init__(
        self,
        budget: ProjectionBudget,
        candidate_groups: list[_PatternProjectionState],
        issues: list[ProjectionIssue],
        coverage_target_ids: set[str] | None,
    ) -> None:
        self.budget = budget
        self.candidate_groups = candidate_groups
        self.issues = issues
        self.coverage_target_ids = coverage_target_ids
        self.by_identity: dict[str, ProjectedCandidate] = {}
        self.pending: list[tuple[int, ProjectedCandidate]] = []
        self.emitted_by_group = [0] * len(candidate_groups)
        self.derived_candidate_ids: list[set[str]] = [set() for _ in candidate_groups]
        self.work_used = 0
        self.work_exhausted = False
        self.pending_index = 0
        self.target_to_first_candidate: dict[str, tuple[int, ProjectedCandidate]] = {}
        self.unresolved_targets: set[str] = set()

    def derive_one(
        self,
        group_index: int,
        iterator: Any,
    ) -> tuple[ProjectedCandidate | None, bool, bool]:
        """Derive at most one combination.

        Returns ``(candidate, is_unique, exhausted)``.  A candidate reached
        through both a target-pinned iterator and the generic iterator is
        one derived candidate, not two budget-truncated candidates.
        """
        if self.work_used >= self.budget.max_derivation_work:
            self.work_exhausted = True
            return None, False, True
        try:
            resources = next(iterator)
        except StopIteration:
            return None, False, True
        self.work_used += 1
        return self._build_derived_candidate(group_index, resources)

    def _build_derived_candidate(
        self,
        group_index: int,
        resources: tuple[CanonicalResourceReference, ...],
    ) -> tuple[ProjectedCandidate | None, bool, bool]:
        """Build one candidate from a combination and record the issue."""
        state = self.candidate_groups[group_index]
        candidate, issue = _build_candidate_from_combination(
            state.pattern_id,
            state.chain,
            state.selected,
            state.condition_results,
            state.omissions,
            resources,
            state.catalog_pin,
            state.pattern_pin,
            state.precondition_results,
            state.snapshot,
        )
        if issue is not None:
            self.issues.append(issue)
        if candidate is None:
            return None, False, False
        is_unique = (
            candidate.candidate_id not in self.derived_candidate_ids[group_index]
        )
        if is_unique:
            self.derived_candidate_ids[group_index].add(candidate.candidate_id)
            state.generated.append(candidate)
        return candidate, is_unique, False

    def emit(self, group_index: int, candidate: ProjectedCandidate) -> None:
        """Emit a candidate under the identity and budget guards."""
        previous = self.by_identity.get(candidate.candidate_id)
        if previous is not None and previous != candidate:
            raise ValueError("candidate-v2 identity collision")
        if previous is None and len(self.by_identity) < self.budget.max_candidates:
            self.by_identity[candidate.candidate_id] = candidate
            self.emitted_by_group[group_index] += 1

    def reserve_coverage_targets(self) -> None:
        """Reserve one feasible candidate per sorted coverage target."""
        if not self.coverage_target_ids:
            return
        for target_id in sorted(self.coverage_target_ids):
            self._reserve_one_target(target_id)

    def _reserve_target_iteration(
        self,
        target_id: str,
        group_index: int,
        target_iter: Any,
    ) -> tuple[bool, bool]:
        """Run one derivation of a target-pinned iterator.

        Returns ``(stop, found)``; ``stop`` mirrors the original break
        conditions (work exhausted / candidate / exhausted).
        """
        candidate, is_unique, exhausted = self.derive_one(group_index, target_iter)
        if self.work_exhausted:
            return True, False
        if candidate is not None:
            if is_unique:
                self.pending.append((group_index, candidate))
            self.target_to_first_candidate[target_id] = (
                group_index,
                candidate,
            )
            return True, True
        if exhausted:
            return True, False
        return False, False

    def _reserve_target_from_group(
        self,
        target_id: str,
        group_index: int,
        state: _PatternProjectionState,
    ) -> tuple[bool, bool]:
        """Reserve the target from one group; returns ``(stop, found)``."""
        ingress_index = _ingress_slot_index(state.chain)
        target_ref = _target_ingress_reference(state, ingress_index, target_id)
        if target_ref is None:
            return False, False
        target_options = list(state.option_sets)
        target_options[ingress_index] = (target_ref,)
        target_iter = iter(
            _iter_compatible_combinations(
                state.chain.resource_slots, tuple(target_options)
            )
        )
        while True:
            stop, found = self._reserve_target_iteration(
                target_id, group_index, target_iter
            )
            if stop:
                return True, found

    def _reserve_one_target(self, target_id: str) -> None:
        """Reserve one target across groups; mark unresolved when missed."""
        target_found = False
        for group_index, state in enumerate(self.candidate_groups):
            stop, found = self._reserve_target_from_group(target_id, group_index, state)
            if stop:
                target_found = found
                break
        if not target_found:
            self.unresolved_targets.add(target_id)

    def emit_reserved_targets(self) -> None:
        """Emit the first reserved candidate per coverage target."""
        for target_id in sorted(self.target_to_first_candidate):
            group_index, candidate = self.target_to_first_candidate[target_id]
            self.emit(group_index, candidate)

    def infeasible_coverage_targets(self) -> tuple[str, ...]:
        """Return targets with no feasible derivation (unless work
        exhausted)."""
        if not self.coverage_target_ids:
            return ()
        if self.work_exhausted:
            return ()
        return tuple(sorted(self.unresolved_targets))

    def unknown_coverage_targets(self) -> set[str]:
        """Return targets whose feasibility is unknown after work
        exhaustion."""
        if not self.coverage_target_ids:
            return set()
        if self.work_exhausted:
            return set(self.unresolved_targets)
        return set()

    def unreserved_targets(self) -> tuple[str, ...]:
        """Return targets without an emitted reserved candidate."""
        if not self.coverage_target_ids:
            return ()
        emitted_target_ids = {
            candidate.canonical_ingress.entry_point_id
            for candidate in self.by_identity.values()
        }
        unreserved = (
            set(self.target_to_first_candidate) | self.unknown_coverage_targets()
        ) - emitted_target_ids
        return tuple(sorted(unreserved))

    def emit_pending(self) -> None:
        """Emit every already-derived pending candidate first."""
        pending_index = 0
        while (
            pending_index < len(self.pending)
            and len(self.by_identity) < self.budget.max_candidates
        ):
            group_index, candidate = self.pending[pending_index]
            pending_index += 1
            self.emit(group_index, candidate)
        self.pending_index = pending_index

    def fill_round_robin(self) -> None:
        """Fill remaining budget with round-robin variant derivation."""
        while (
            len(self.by_identity) < self.budget.max_candidates
            and not self.work_exhausted
        ):
            progressed = self._round_robin_pass()
            if not progressed:
                break

    def _round_robin_pass(self) -> bool:
        """Run one round-robin pass; True when any derivation progressed."""
        progressed = False
        for group_index, state in enumerate(self.candidate_groups):
            if self._round_robin_derive(state, group_index):
                progressed = True
            if (
                len(self.by_identity) >= self.budget.max_candidates
                or self.work_exhausted
            ):
                break
        return progressed

    def _round_robin_derive(
        self, state: _PatternProjectionState, group_index: int
    ) -> bool:
        """Derive one variant; True when the pass should keep going."""
        candidate, _, exhausted = self.derive_one(group_index, state._iter)
        if candidate is not None:
            self.emit(group_index, candidate)
            return True
        return not exhausted

    def probe_truncation(self) -> None:
        """Run a single bounded probe to confirm output truncation."""
        if not self._probe_eligible():
            return
        for group_index, state in enumerate(self.candidate_groups):
            if self._probe_derive(group_index, state):
                break

    def _probe_eligible(self) -> bool:
        """True when outputs are full and no pending candidates remain."""
        return (
            len(self.by_identity) >= self.budget.max_candidates
            and not self.pending[self.pending_index :]
        )

    def _probe_derive(self, group_index: int, state: _PatternProjectionState) -> bool:
        """Derive one probe candidate; True when the probe should stop."""
        candidate, is_unique, _ = self.derive_one(group_index, state._iter)
        return (candidate is not None and is_unique) or self.work_exhausted

    def build_limitations(self) -> list[ProjectionLimitation]:
        """Build budget and derivation-work limitations per group."""
        limitations = []
        for group_index, state in enumerate(self.candidate_groups):
            if state.emitted > self.emitted_by_group[group_index]:
                limitations.append(
                    ProjectionLimitation(
                        code="candidate_budget_exhausted",
                        pattern_id=state.pattern_id,
                        total_compatible_bindings=state.total_bindings,
                        emitted_bindings=self.emitted_by_group[group_index],
                    )
                )
        if self.work_exhausted:
            limitations.extend(
                ProjectionLimitation(
                    code="derivation_work_exhausted",
                    pattern_id=state.pattern_id,
                    total_compatible_bindings=state.total_bindings,
                    emitted_bindings=self.emitted_by_group[group_index],
                )
                for group_index, state in enumerate(self.candidate_groups)
            )
        return limitations
