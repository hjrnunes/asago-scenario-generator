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
    _ingress_slot_index,
    _target_ingress_reference,
)
from asago_scenario_generator.pipeline.projection_candidates import (
    _bindings_for_combination,
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
        *,
        retain_deferred: bool = False,
    ) -> None:
        self.budget = budget
        self.candidate_groups = candidate_groups
        self.issues = issues
        self.coverage_target_ids = coverage_target_ids
        self.retain_deferred = retain_deferred
        self.by_identity: dict[str, ProjectedCandidate] = {}
        self.pending: list[tuple[int, ProjectedCandidate]] = []
        self.emitted_by_group = [0] * len(candidate_groups)
        self.derived_candidate_ids: list[set[str]] = [set() for _ in candidate_groups]
        self.work_used = 0
        self.work_exhausted = False
        self.pending_index = 0
        self.target_to_first_candidate: dict[str, tuple[int, ProjectedCandidate]] = {}
        self.unresolved_targets: set[str] = set()
        self.rejected_candidates: list[RejectedProjectionCandidate] = []

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


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-28T16:11:04Z","module_hash":"d0f7b35eb51ce18244bd7a3431939927577d8b975da25d5f7157ec06dfb23303","source_sha256":"b2f0e671fe5ce9400fe12db5af87838dc875e27ad884a1a649a9819cc7d6b789","functions":[{"id":"func/_AuthoritativeCandidateAllocator.__init__","name":"__init__","line":42,"end_line":65,"hash":"8ee72d31c75c09de6d3b3a05932bbc97d11f8c85eceecc762801996777cedca5"},{"id":"func/_AuthoritativeCandidateAllocator.derive_one","name":"derive_one","line":67,"end_line":86,"hash":"70a306b3323d2fccdac404e5dee592c06a8ea380f40a7ae2914bbf1e2052f924"},{"id":"func/_AuthoritativeCandidateAllocator._build_derived_candidate","name":"_build_derived_candidate","line":88,"end_line":118,"hash":"e06d4381f624da66718f76cbb908a758cec475cb2573f4ca59382c641c1d7cd8"},{"id":"func/_AuthoritativeCandidateAllocator._record_rejected_candidate","name":"_record_rejected_candidate","line":120,"end_line":149,"hash":"54f6285c951cec2d576c74b4dbd40f35dd1d9b3cd78a3891a19c85e018b8a4a1"},{"id":"func/_AuthoritativeCandidateAllocator.emit","name":"emit","line":151,"end_line":158,"hash":"f68fb981ce80b256cd053c6ad2ab78d7fac294663d3109b2521f6e65a527f6ef"},{"id":"func/_AuthoritativeCandidateAllocator.reserve_coverage_targets","name":"reserve_coverage_targets","line":160,"end_line":165,"hash":"dba6e170a700d00c8d9ebeb7327f50e521d5c776ab45cedd4e861da82d678935"},{"id":"func/_AuthoritativeCandidateAllocator._reserve_target_iteration","name":"_reserve_target_iteration","line":167,"end_line":191,"hash":"7d7553cafdad9622c558e13986a547189bf39140023e02c7d421448547847a2a"},{"id":"func/_AuthoritativeCandidateAllocator._reserve_target_from_group","name":"_reserve_target_from_group","line":193,"end_line":216,"hash":"12c75f147d3534769e839766b35b92f4ea66cbf812b1f54fbbba89a2079d5dce"},{"id":"func/_AuthoritativeCandidateAllocator._reserve_one_target","name":"_reserve_one_target","line":218,"end_line":227,"hash":"b685ae37b63f91bc48751eae32b0ab05f9423752862efb92ae2818101cdef29c"},{"id":"func/_AuthoritativeCandidateAllocator.emit_reserved_targets","name":"emit_reserved_targets","line":229,"end_line":233,"hash":"d9328f3f625098744747f2e9df4921ff4ba0325eac05622f594587b2ce9a6417"},{"id":"func/_AuthoritativeCandidateAllocator.infeasible_coverage_targets","name":"infeasible_coverage_targets","line":235,"end_line":242,"hash":"9c80097b6a3903535a86cc141fa19d3d961491e0d9bcfbb744f4d21c3d4733e2"},{"id":"func/_AuthoritativeCandidateAllocator.unknown_coverage_targets","name":"unknown_coverage_targets","line":244,"end_line":251,"hash":"f7841c36449601e789a5983b60e54d782ae79ed4afed80231fe21480fdb1cfff"},{"id":"func/_AuthoritativeCandidateAllocator.unreserved_targets","name":"unreserved_targets","line":253,"end_line":264,"hash":"4c5af12ccc4fa4a7b82d22b29a20302bbf5b16781832d7c7dd0e36f90dfa5579"},{"id":"func/_AuthoritativeCandidateAllocator.emit_pending","name":"emit_pending","line":266,"end_line":276,"hash":"6f7f2cf78bc9a578f12585ff71558b2451441eb5326f4e6f977f0b0f77ff7673"},{"id":"func/_AuthoritativeCandidateAllocator.fill_round_robin","name":"fill_round_robin","line":278,"end_line":285,"hash":"19bb2290e6adaeea3284127665a3a458f792a819360106e0719263aff8f4549b"},{"id":"func/_AuthoritativeCandidateAllocator._round_robin_pass","name":"_round_robin_pass","line":287,"end_line":299,"hash":"8827d4c01295e0e990ebab0cfe1313ebd4a03af660081800b2e465b20f874695"},{"id":"func/_AuthoritativeCandidateAllocator._round_robin_derive","name":"_round_robin_derive","line":301,"end_line":309,"hash":"2f06e7a9a75dcf132c6ab3ea943f9e3d30d77880cabb20ea01122b82a9855dcc"},{"id":"func/_AuthoritativeCandidateAllocator.probe_truncation","name":"probe_truncation","line":311,"end_line":317,"hash":"34afa1191b69abbe3059df3bbf1dcaa51d18105ff0ddee175c8edc91f8a5f4d9"},{"id":"func/_AuthoritativeCandidateAllocator._probe_eligible","name":"_probe_eligible","line":319,"end_line":324,"hash":"0923987bd8937bff197ebe7809294eda242fb7bfecfc7151c56e3f95a0ae5f31"},{"id":"func/_AuthoritativeCandidateAllocator._probe_derive","name":"_probe_derive","line":326,"end_line":329,"hash":"d05cef366c3087629b0523a0b0cdc0de5c0b21011b23f526c64f865cb7e65505"},{"id":"func/_AuthoritativeCandidateAllocator.build_limitations","name":"build_limitations","line":331,"end_line":354,"hash":"f6a426e491d6bac4506024785fceb73f0c7e123e4be4b3285e08b472e79fa0ec"}]}
# mutate4py-manifest-end
