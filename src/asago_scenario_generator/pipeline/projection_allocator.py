"""Bounded, lazy candidate allocation for authoritative projection."""

from __future__ import annotations

from typing import Any

from asago_scenario_generator.models.attack_pattern_projection import (
    CanonicalResourceReference,
)
from asago_scenario_generator.pipeline.projection_contracts import (
    ProjectedCandidate,
    ProjectionBudget,
    ProjectionIssue,
    ProjectionLimitation,
)
from asago_scenario_generator.pipeline.projection_allocation import (
    _PatternProjectionState,
    _ingress_slot_index,
    _target_ingress_reference,
)
from asago_scenario_generator.pipeline.projection_candidates import (
    _build_candidate_from_combination,
)
from asago_scenario_generator.pipeline.projection_resources import (
    _iter_compatible_combinations,
)


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
