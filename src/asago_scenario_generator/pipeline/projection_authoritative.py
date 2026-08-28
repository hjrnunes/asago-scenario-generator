"""Authoritative projection orchestration below the public migration façade."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from asago_scenario_generator.models.attack_pattern_contracts import TaxonomyResolver
from asago_scenario_generator.pipeline.projection_contracts import (
    AuthoritativeProjectionObservation,
    CapabilityFactSnapshot,
    ProjectionBatch,
    ProjectionBudget,
    ProjectionIssue,
    ProjectionQualificationTrace,
    RejectedProjectionCandidate,
    _rejected_candidate_v2_id,
)

from asago_scenario_generator.pipeline.projection_allocation import (  # noqa: F401
    _PatternProjectionState,
    _assemble_pattern_state,
    _check_simple_missing_slot,
    _direct_ingress_options,
    _gather_slot_options,
    _has_direct_ingress_activation,
    _has_source_influence_activation,
    _ingress_slot_index,
    _no_activation_violation,
    _project_authoritative_pattern,
    _record_missing_slot_issues,
    _relation_slot_ids,
    _resolve_ingress_activation,
    _slot_by_id,
    _source_influence_failure_issue,
    _source_influence_relation_links,
    _source_influence_relation_state,
    _source_influence_target_id,
    _target_ingress_reference,
    _zero_bindings_issue,
)
from asago_scenario_generator.pipeline.projection_allocator import (  # noqa: F401
    _AuthoritativeCandidateAllocator,
)
from asago_scenario_generator.pipeline.projection_qualification import (  # noqa: F401
    _authoritative_records_type_check,
    _catalog_content_pin,
    compute_authoritative_catalog_pin,
    _dedupe_projection_issues,
    _false_precondition_issue,
    _inapplicable_projection_issue,
    _incompatible_profile_issue,
    _infeasibility_key,
    _limitation_key,
    _profile_compatibility_gaps,
    _profile_and_condition_gate,
    _profile_gate_failure_issue,
    _precondition_results_or_none,
    _projection_is_applicable,
    _qualify_authoritative_pattern,
    _qualify_authoritative_records,
    _qualified_condition_state as _qualified_condition_state_from_qualification,
    _resolve_projection_budget,
    _resolve_qualified_patterns,
    _results_contain_false,
    _results_contain_unknown,
    _select_conditionally_required_steps,
    _sorted_emitted_candidates,
    _sorted_infeasibilities,
    _sorted_limitations,
    _unresolved_condition_issue,
    _unresolved_precondition_issue,
    _omitted_conditional_steps,
)

_qualified_condition_state = _qualified_condition_state_from_qualification


def _derived_candidates(
    allocator: _AuthoritativeCandidateAllocator,
) -> tuple[Any, ...]:
    """Return built candidates, failing closed on candidate digest collisions."""
    by_identity: dict[str, Any] = {}
    for state in allocator.candidate_groups:
        for candidate in state.generated:
            previous = by_identity.get(candidate.candidate_id)
            if previous is not None and previous != candidate:
                raise ValueError("candidate-v2 identity collision")
            by_identity[candidate.candidate_id] = candidate
    return _sorted_emitted_candidates(by_identity)


def _qualification_traces(
    candidate_groups: list[_PatternProjectionState],
) -> tuple[ProjectionQualificationTrace, ...]:
    """Copy typed condition and precondition results from qualified states."""
    return tuple(
        ProjectionQualificationTrace(
            pattern_id=state.pattern_id,
            condition_results=state.condition_results,
            precondition_results=state.precondition_results,
        )
        for state in sorted(candidate_groups, key=lambda item: item.pattern_id)
    )


_REJECTED_PROJECTION_CODES = frozenset(
    {
        "missing_compatible_resource",
        "unsupported_requirement_derivation",
        "inapplicable_projection",
        "source_influence_relation_infeasible",
    }
)


def _issue_rejected_candidate(issue: ProjectionIssue) -> RejectedProjectionCandidate:
    """Represent an aggregate projection issue as a stable rejected record."""
    return RejectedProjectionCandidate(
        candidate_id=_rejected_candidate_v2_id(issue.pattern_id, issue),
        pattern_id=issue.pattern_id,
        reason=issue.detail,
        issue=issue,
    )


def _issue_rejections(
    issues: list[ProjectionIssue],
    existing_issue_keys: set[str],
) -> list[RejectedProjectionCandidate]:
    """Build issue-only rejects not already represented concretely."""
    return [
        _issue_rejected_candidate(issue)
        for issue in _sorted_infeasibilities(issues)
        if issue.code in _REJECTED_PROJECTION_CODES
        and issue.model_dump_json() not in existing_issue_keys
    ]


def _deduplicate_rejected_candidates(
    candidates: list[RejectedProjectionCandidate],
) -> tuple[RejectedProjectionCandidate, ...]:
    """Collapse equivalent rejects while rejecting identity collisions."""
    by_identity: dict[str, RejectedProjectionCandidate] = {}
    for candidate in candidates:
        previous = by_identity.get(candidate.candidate_id)
        if previous is not None and previous != candidate:
            raise ValueError("rejected candidate-v2 identity collision")
        by_identity[candidate.candidate_id] = candidate
    return tuple(by_identity[key] for key in sorted(by_identity))


def _rejected_candidates(
    issues: list[ProjectionIssue],
    allocator: _AuthoritativeCandidateAllocator,
) -> tuple[RejectedProjectionCandidate, ...]:
    """Return concrete rejects plus issue-only rejects in deterministic order."""
    rejected = list(allocator.rejected_candidates)
    existing_issue_keys = {item.issue.model_dump_json() for item in rejected}
    rejected.extend(_issue_rejections(issues, existing_issue_keys))
    return _deduplicate_rejected_candidates(rejected)


def _qualified_projection_groups(
    records: Sequence[dict[str, Any]],
    taxonomy_resolver: TaxonomyResolver,
    snapshot: CapabilityFactSnapshot,
) -> tuple[list[_PatternProjectionState], list[ProjectionIssue]]:
    """Qualify records and project every pattern into allocator state."""
    qualified = _qualify_authoritative_records(records, taxonomy_resolver)
    catalog_pin = _catalog_content_pin(qualified)
    candidate_groups: list[_PatternProjectionState] = []
    issues: list[ProjectionIssue] = []
    for pattern, pattern_pin in qualified:
        _project_authoritative_pattern(
            pattern,
            pattern_pin,
            snapshot,
            catalog_pin,
            candidate_groups,
            issues,
        )
    return candidate_groups, issues


def _allocate_authoritative_batch(
    resolved_budget: ProjectionBudget,
    candidate_groups: list[_PatternProjectionState],
    issues: list[ProjectionIssue],
    coverage_target_ids: set[str] | None,
    snapshot: CapabilityFactSnapshot,
) -> tuple[_AuthoritativeCandidateAllocator, ProjectionBatch]:
    """Run the public allocator and snapshot its generation-facing batch."""
    allocator = _AuthoritativeCandidateAllocator(
        resolved_budget,
        candidate_groups,
        issues,
        coverage_target_ids,
        # Establish the generation-facing result with the exact public
        # allocation stop conditions.  Observation-only tail collection is
        # performed after this snapshot so it cannot change batch limits.
        retain_deferred=False,
    )
    allocator.reserve_coverage_targets()
    allocator.emit_reserved_targets()
    allocator.emit_pending()
    allocator.fill_round_robin()
    allocator.probe_truncation()
    batch = ProjectionBatch(
        capability_fact_snapshot_digest=snapshot.snapshot_digest,
        candidates=_sorted_emitted_candidates(allocator.by_identity),
        infeasibilities=_sorted_infeasibilities(issues),
        limitations=_sorted_limitations(allocator.build_limitations()),
        unreserved_coverage_targets=allocator.unreserved_targets(),
        infeasible_coverage_targets=allocator.infeasible_coverage_targets(),
    )
    return allocator, batch


def _deferred_projection_candidates(
    allocator: _AuthoritativeCandidateAllocator,
    batch: ProjectionBatch,
    retain_deferred: bool,
) -> tuple[Any, ...]:
    """Continue bounded derivation and return only non-emitted candidates."""
    if retain_deferred and not allocator.work_exhausted:
        # Continue from the same iterators only for truthful, bounded
        # observation.  ``batch`` above is deliberately immutable and already
        # reflects the established public API's limits and issue inventory.
        allocator.retain_deferred = True
        allocator.fill_round_robin()
    emitted_ids = {candidate.candidate_id for candidate in batch.candidates}
    return tuple(
        candidate
        for candidate in _derived_candidates(allocator)
        if candidate.candidate_id not in emitted_ids
    )


def _project_authoritative_observation(
    records: Sequence[dict[str, Any]],
    taxonomy_resolver: TaxonomyResolver,
    snapshot: CapabilityFactSnapshot,
    *,
    budget: ProjectionBudget | None,
    coverage_target_ids: set[str] | None,
    retain_deferred: bool,
) -> AuthoritativeProjectionObservation:
    """Run one authoritative projection with an optional observation tail."""
    _authoritative_records_type_check(records)
    resolved_budget = _resolve_projection_budget(budget)
    snapshot.assert_integrity()
    candidate_groups, issues = _qualified_projection_groups(
        records, taxonomy_resolver, snapshot
    )
    allocator, batch = _allocate_authoritative_batch(
        resolved_budget,
        candidate_groups,
        issues,
        coverage_target_ids,
        snapshot,
    )
    deferred = _deferred_projection_candidates(allocator, batch, retain_deferred)
    return AuthoritativeProjectionObservation(
        batch=batch,
        deferred_candidates=deferred,
        rejected_candidates=_rejected_candidates(issues, allocator),
        qualification_traces=_qualification_traces(candidate_groups),
    )


def project_authoritative_candidate_observations(
    records: Sequence[dict[str, Any]],
    taxonomy_resolver: TaxonomyResolver,
    snapshot: CapabilityFactSnapshot,
    *,
    budget: ProjectionBudget | None = None,
) -> AuthoritativeProjectionObservation:
    """Return bounded candidate and qualification evidence for planning.

    Candidate emission remains capped by ``max_candidates``.  Once that cap
    fills, derivation continues lazily only until the existing
    ``max_derivation_work`` limit so every returned deferred identity and
    binding is an actually validated candidate.
    """
    return _project_authoritative_observation(
        records,
        taxonomy_resolver,
        snapshot,
        budget=budget,
        coverage_target_ids=None,
        retain_deferred=True,
    )
