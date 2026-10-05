"""Authoritative projection orchestration for the obligation planner."""

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

from asago_scenario_generator.pipeline.projection_allocation import (
    _PatternProjectionState,
    _project_authoritative_pattern,
)
from asago_scenario_generator.pipeline.projection_allocator import (
    _AuthoritativeCandidateAllocator,
)
from asago_scenario_generator.pipeline.projection_qualification import (
    _authoritative_records_type_check,
    _catalog_content_pin,
    _qualify_authoritative_records,
    _resolve_projection_budget,
    _sorted_emitted_candidates,
    _sorted_infeasibilities,
    _sorted_limitations,
)


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
        "unsupported_resource_operation",
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
    snapshot: CapabilityFactSnapshot,
) -> tuple[_AuthoritativeCandidateAllocator, ProjectionBatch]:
    """Run the public allocator and snapshot its generation-facing batch."""
    allocator = _AuthoritativeCandidateAllocator(
        resolved_budget,
        candidate_groups,
        issues,
        # Establish the generation-facing result with the exact public
        # allocation stop conditions.  Observation-only tail collection is
        # performed after this snapshot so it cannot change batch limits.
        retain_deferred=False,
    )
    allocator.fill_round_robin()
    allocator.probe_truncation()
    batch = ProjectionBatch(
        capability_fact_snapshot_digest=snapshot.snapshot_digest,
        candidates=_sorted_emitted_candidates(allocator.by_identity),
        infeasibilities=_sorted_infeasibilities(issues),
        limitations=_sorted_limitations(allocator.build_limitations()),
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
    retain_deferred: bool,
) -> AuthoritativeProjectionObservation:
    """Run one authoritative projection with an optional observation tail."""
    _authoritative_records_type_check(records)
    resolved_budget = _resolve_projection_budget(budget)
    snapshot.assert_integrity()
    candidate_groups, issues = _qualified_projection_groups(
        records,
        taxonomy_resolver,
        snapshot,
    )
    allocator, batch = _allocate_authoritative_batch(
        resolved_budget,
        candidate_groups,
        issues,
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
    binding is an actually validated candidate.  Tool and integration slots
    bind only resources that support every required operation.
    """
    return _project_authoritative_observation(
        records,
        taxonomy_resolver,
        snapshot,
        budget=budget,
        retain_deferred=True,
    )
