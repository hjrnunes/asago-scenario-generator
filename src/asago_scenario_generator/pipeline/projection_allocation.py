"""Pattern-state assembly and ingress allocation for authoritative projection."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from asago_scenario_generator.models.attack_pattern_chain import (
    AttackPattern,
    CanonicalAttackChain,
)
from asago_scenario_generator.models.attack_pattern_contracts import (
    ConditionEvaluationResult,
)
from asago_scenario_generator.models.attack_pattern_projection import (
    CanonicalResourceReference,
    EntryPointResourceReference,
    StepOmission,
)
from asago_scenario_generator.pipeline.projection_contracts import (
    CapabilityFactSnapshot,
    PreconditionEvaluationResult,
    ProjectedCandidate,
    ProjectionIssue,
    _resource_id,
)
from asago_scenario_generator.pipeline.projection_qualification import (
    _qualified_condition_state,
)
from asago_scenario_generator.pipeline.projection_resources import (
    _count_compatible_combinations,
    _iter_compatible_combinations,
    _references_for_slot,
)


@dataclass
class _PatternProjectionState:
    """Lazy per-pattern state shared by qualification and allocation."""

    pattern_id: str
    chain: CanonicalAttackChain
    selected: tuple[str, ...]
    condition_results: tuple[ConditionEvaluationResult, ...]
    omissions: tuple[StepOmission, ...]
    option_sets: tuple[tuple[CanonicalResourceReference, ...], ...]
    total_bindings: int
    catalog_pin: str
    pattern_pin: str
    precondition_results: tuple[PreconditionEvaluationResult, ...]
    combination_iter: Iterable[tuple[CanonicalResourceReference, ...]]
    snapshot: Any
    generated: list[ProjectedCandidate] = field(default_factory=list)
    iterator_exhausted: bool = False
    _iter: Any = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self._iter is None:
            object.__setattr__(self, "_iter", iter(self.combination_iter))

    def next_candidate(self, issues: list | None = None) -> ProjectedCandidate | None:
        """Build the next feasible candidate without materializing combinations."""
        if self.iterator_exhausted:
            return None
        from asago_scenario_generator.pipeline.projection_candidates import (
            _build_candidate_from_combination,
        )

        for resources in self._iter:
            candidate, issue = _build_candidate_from_combination(
                self.pattern_id,
                self.chain,
                self.selected,
                self.condition_results,
                self.omissions,
                resources,
                self.catalog_pin,
                self.pattern_pin,
                self.precondition_results,
                self.snapshot,
            )
            if issue is not None and issues is not None:
                issues.append(issue)
            if candidate is not None:
                self.generated.append(candidate)
                return candidate
        self.iterator_exhausted = True
        return None

    @property
    def emitted(self) -> int:
        return len(self.generated)

    @property
    def feasible_remaining(self) -> bool:
        return not self.iterator_exhausted


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
