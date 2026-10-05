"""Bounded, lazy candidate allocation for authoritative projection."""

from __future__ import annotations

from typing import Any

from asago_scenario_generator.models.attack_pattern_projection import (
    CanonicalResourceReference,
    EntryPointResourceReference,
)
from asago_scenario_generator.pipeline.projection_contracts import (
    ProjectedCandidate,
    ProjectionBudget,
    ProjectionIssue,
    ProjectionLimitation,
    RejectedProjectionCandidate,
    _rejected_candidate_v2_id,
)
from asago_scenario_generator.pipeline.projection_allocation import (
    _PatternProjectionState,
)
from asago_scenario_generator.pipeline.projection_candidates import (
    _bindings_for_combination,
    _build_candidate_from_combination,
)


class _AuthoritativeCandidateAllocator:
    """Bounded, lazy candidate allocation for an authoritative batch.

    Every derivation consumes exactly one work unit, including structural
    rejects; no helper scans an iterator.
    """

    def __init__(
        self,
        budget: ProjectionBudget,
        candidate_groups: list[_PatternProjectionState],
        issues: list[ProjectionIssue],
        *,
        retain_deferred: bool = False,
    ) -> None:
        self.budget = budget
        self.candidate_groups = candidate_groups
        self.issues = issues
        self.retain_deferred = retain_deferred
        self.by_identity: dict[str, ProjectedCandidate] = {}
        self.emitted_by_group = [0] * len(candidate_groups)
        self.derived_candidate_ids: list[set[str]] = [set() for _ in candidate_groups]
        self.work_used = 0
        self.work_exhausted = False
        self.rejected_candidates: list[RejectedProjectionCandidate] = []

    def derive_one(
        self,
        group_index: int,
        iterator: Any,
    ) -> tuple[ProjectedCandidate | None, bool, bool]:
        """Derive at most one combination.

        Returns ``(candidate, is_unique, exhausted)``.
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
            self._record_rejected_candidate(group_index, resources, issue)
        if candidate is None:
            return None, False, False
        is_unique = (
            candidate.candidate_id not in self.derived_candidate_ids[group_index]
        )
        if is_unique:
            self.derived_candidate_ids[group_index].add(candidate.candidate_id)
            state.generated.append(candidate)
        return candidate, is_unique, False

    def _record_rejected_candidate(
        self,
        group_index: int,
        resources: tuple[CanonicalResourceReference, ...],
        issue: ProjectionIssue,
    ) -> None:
        """Retain one concrete rejected combination for observation consumers."""
        state = self.candidate_groups[group_index]
        bindings = _bindings_for_combination(state.chain, resources)
        ingress = next(
            (
                binding.resource_ref
                for binding in bindings
                if binding.slot_id == state.chain.initial_ingress_slot_id
                and isinstance(binding.resource_ref, EntryPointResourceReference)
            ),
            None,
        )
        self.rejected_candidates.append(
            RejectedProjectionCandidate(
                candidate_id=_rejected_candidate_v2_id(
                    state.pattern_id, issue, bindings
                ),
                pattern_id=state.pattern_id,
                canonical_ingress=ingress,
                resource_bindings=bindings,
                reason=issue.detail,
                issue=issue,
            )
        )

    def emit(self, group_index: int, candidate: ProjectedCandidate) -> None:
        """Emit a candidate under the identity and budget guards."""
        previous = self.by_identity.get(candidate.candidate_id)
        if previous is not None and previous != candidate:
            raise ValueError("candidate-v2 identity collision")
        if previous is None and len(self.by_identity) < self.budget.max_candidates:
            self.by_identity[candidate.candidate_id] = candidate
            self.emitted_by_group[group_index] += 1

    def fill_round_robin(self) -> None:
        """Fill outputs and optionally observe deferred variants within work."""
        while (
            self.retain_deferred or len(self.by_identity) < self.budget.max_candidates
        ) and not self.work_exhausted:
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
                not self.retain_deferred
                and len(self.by_identity) >= self.budget.max_candidates
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
        """True when outputs are full."""
        return len(self.by_identity) >= self.budget.max_candidates

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
