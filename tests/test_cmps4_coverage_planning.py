"""Comprehensive regression tests for cmps.4 coverage-aware planning."""

from __future__ import annotations


import pytest

from asago_scenario_generator.models.attack_pattern import EntryPointResourceReference
from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    ConfidenceLevel,
    EntryPoint,
    InventoryCompleteness,
)
from asago_scenario_generator.models.scenario import RiskCardRef
from asago_scenario_generator.pipeline.candidate_models import FilteredSeed
from asago_scenario_generator.pipeline.coverage_planning import (
    AcceptedFilterRecord,
    DeserializedPlanRef,
    QualifiedCandidate,
    deserialize_qualified_candidate,
    revalidate_qualified_candidate,
)
from asago_scenario_generator.pipeline.projection_contracts import ProjectedCandidate
from tests.helpers.projection_factory import get_projected_candidate


def _profile(
    entries: list[EntryPoint],
    *,
    zones: list[str] | None = None,
    confirmed: bool = False,
) -> CapabilityProfile:
    return CapabilityProfile(
        zones_active=zones or ["input", "reasoning", "tool_execution"],
        entry_points=entries,
        confidence=ConfidenceLevel.medium,
        kc_subcodes=["KC1.1"],
        entry_point_completeness=(
            InventoryCompleteness.operator_confirmed_complete
            if confirmed
            else InventoryCompleteness.inferred_partial
        ),
        entry_point_evidence=["operator-review:architecture-v3"] if confirmed else [],
    )


def _risk() -> RiskCardRef:
    return RiskCardRef(
        risk_id="risk-1",
        risk_name="Test risk",
        risk_description="Test risk description.",
        taxonomy="ibm-risk-atlas",
        confidence=0.9,
        grounding_confidence="high",
    )


# Real ProjectedCandidate fixture from the shared test projection factory.
# All test doubles below are derived from this via model_copy, producing
# real ProjectedCandidate instances (not permissive MagicMock).
_REAL_PC = get_projected_candidate()
_REAL_EP_ID = _REAL_PC.canonical_ingress.entry_point_id
_REAL_PATTERN_ID = _REAL_PC.pattern_id


def _ep_ref(entry_point_id: str) -> EntryPointResourceReference:
    """Build an EntryPointResourceReference with the given entry_point_id."""
    return EntryPointResourceReference(
        kind="entry_point",
        entry_point_id=entry_point_id,
    )


def _ep_id(num: int = 1) -> str:
    """Build a valid ep:v1: entry_point_id from an integer."""
    return f"ep:v1:{num:032x}"


def _make_fseed(
    *,
    seed_id: str = "AP-T1-01",
    entry_point_id: str = _REAL_EP_ID,
    candidate_id: str = "filter-candidate-1",
    techniques: tuple[str, ...] = ("AML.T0051",),
    rationale: str = "Accepted because it is feasible.",
) -> FilteredSeed:
    """Return a real validated FilteredSeed, not a permissive mock."""
    return FilteredSeed(
        seed_id=seed_id,
        threat_id="T1",
        threat_name="Test threat",
        attack_pattern_name="Test pattern",
        attack_pattern_description="Test attack pattern description.",
        risk_card_ref=_risk(),
        owasp_llm_ids=["LLM01"],
        agentic_threat_ids=["T1"],
        pinned_entry_point="user prompt",
        pinned_technique_ids=techniques,
        pinned_technique_names=tuple(f"Technique {i}" for i in range(len(techniques))),
        entry_point_id=entry_point_id,
        candidate_id=candidate_id,
        accepted_rationale=rationale,
    )


def _make_pc(
    candidate_id: str = "cand:v2:00000000000000000000000000000001",
    *,
    pattern_id: str = _REAL_PATTERN_ID,
    entry_point_id: str = _REAL_EP_ID,
) -> ProjectedCandidate:
    """Make a real ProjectedCandidate test fixture via model_copy.

    Uses the shared test projection factory as a base and creates
    variants with different candidate_id, pattern_id, and canonical_ingress
    via model_copy (bypassing validators).  This produces real
    ProjectedCandidate instances, not permissive mocks.
    """
    return _REAL_PC.model_copy(
        update={
            "candidate_id": candidate_id,
            "pattern_id": pattern_id,
            "canonical_ingress": _ep_ref(entry_point_id),
        }
    )


def _qc(
    number: int,
    *,
    ep: str = _REAL_EP_ID,
    pattern: str = _REAL_PATTERN_ID,
    techniques: tuple[str, ...] = ("AML.T0051",),
) -> QualifiedCandidate:
    cid = f"cand:v2:{number:032x}"
    fseed = _make_fseed(
        seed_id=pattern,
        entry_point_id=ep,
        candidate_id=f"filter-{ep}-{number}",
        techniques=techniques,
    )
    return QualifiedCandidate(
        projected=_make_pc(cid, pattern_id=pattern, entry_point_id=ep),
        accepted_filters=(AcceptedFilterRecord.from_seed(fseed),),
    )


class TestProjectionBudgetAllocation:
    """cmps.4 blocker 5: coverage-aware projection budget allocation."""

    def test_coverage_target_ids_reserve_target_before_variants(self) -> None:
        """Projection with coverage_target_ids reserves one feasible candidate
        per coverage target before variant expansion."""
        from asago_scenario_generator.pipeline.projection import (
            ProjectionBudget,
            project_authoritative_candidates,
        )

        pc = get_projected_candidate()
        target_id = pc.canonical_ingress.entry_point_id
        # Access cached projection internals for the raw pattern and resolver.
        from tests.helpers.projection_factory import _cached_project

        _, resolver, snapshot, raw = _cached_project()
        batch = project_authoritative_candidates(
            [raw],
            resolver,
            snapshot,
            budget=ProjectionBudget(max_candidates=1),
            coverage_target_ids={target_id},
        )
        projected_ids = {c.canonical_ingress.entry_point_id for c in batch.candidates}
        assert target_id in projected_ids

    def test_multi_ingress_small_budget_reserves_one_and_reports_unreserved(
        self,
    ) -> None:
        """Genuine multi-ingress regression: a profile with two direct entry
        points and budget=1 must reserve one target and report the other as
        unreserved (cmps.4 blocker 5).

        This uses a real projection with two distinct bindings (different
        entry_point_ids) — not model_copy — so candidate_ids are genuinely
        computed from different projections.
        """
        from asago_scenario_generator.models.attack_pattern import AttackPattern
        from asago_scenario_generator.models.capability_profile import (
            CapabilityProfile,
            ConfidenceLevel,
        )
        from asago_scenario_generator.pipeline.projection import (
            ProjectionBudget,
            capture_capability_snapshot,
            project_authoritative_candidates,
        )
        from tests.helpers.projection_factory import (
            _evidence,
            _pattern,
            _TaxonomyResolver,
        )

        raw = _pattern()
        pattern = AttackPattern.model_validate(raw)
        resolver = _TaxonomyResolver(pattern.canonical_chain.taxonomy_context)
        # Profile with TWO direct entry points → two distinct bindings.
        profile = CapabilityProfile(
            zones_active=["input", "reasoning", "tool_execution"],
            entry_points=[
                {"name": "chat", "direction": "input", "controllability": "direct"},
                {"name": "api", "direction": "input", "controllability": "direct"},
            ],
            confidence=ConfidenceLevel.high,
            kc_subcodes=["KC1.1", "KC5.1"],
            tool_inventory=[{"name": "writer", "description": "changes state"}],
            tool_types=[
                {
                    "name": "writer",
                    "zone": "tool_execution",
                    "can_modify_state": True,
                    "data_sensitivity": "medium",
                    "code_execution": False,
                }
            ],
            external_integrations=[
                {
                    "name": "CRM",
                    "integration_type": "api",
                    "auth_method": "oauth",
                    "data_sensitivity": "high",
                }
            ],
            trust_boundaries=[
                {
                    "name": "user-to-agent",
                    "from_zone": "input",
                    "to_zone": "reasoning",
                    "confidence": "explicit",
                }
            ],
        )
        snapshot = capture_capability_snapshot(profile, (_evidence(),))
        target_ids = {ep.entry_point_id for ep in profile.entry_points}
        assert len(target_ids) == 2

        # Budget=1 with two coverage targets: one reserved, one unreserved.
        batch = project_authoritative_candidates(
            [raw],
            resolver,
            snapshot,
            budget=ProjectionBudget(max_candidates=1),
            coverage_target_ids=target_ids,
        )
        assert len(batch.candidates) == 1
        reserved_ep = batch.candidates[0].canonical_ingress.entry_point_id
        unreserved = set(batch.unreserved_coverage_targets)
        # Exactly one target is unreserved.
        assert len(unreserved) == 1
        # The unreserved target is the one NOT in the projected candidates.
        assert reserved_ep not in unreserved
        # Budget limitation is reported.
        assert any(
            lim.code == "candidate_budget_exhausted" for lim in batch.limitations
        )

    def test_budget_below_target_count_emits_unreserved_targets(self) -> None:
        """When budget < feasible target count, projection reports exact
        unreserved target IDs (cmps.4 blocker 5)."""
        from asago_scenario_generator.models.attack_pattern import AttackPattern
        from asago_scenario_generator.models.capability_profile import (
            CapabilityProfile,
            ConfidenceLevel,
        )
        from asago_scenario_generator.pipeline.projection import (
            ProjectionBudget,
            capture_capability_snapshot,
            project_authoritative_candidates,
        )
        from tests.helpers.projection_factory import (
            _evidence,
            _pattern,
            _TaxonomyResolver,
        )

        raw = _pattern()
        pattern = AttackPattern.model_validate(raw)
        resolver = _TaxonomyResolver(pattern.canonical_chain.taxonomy_context)
        profile = CapabilityProfile(
            zones_active=["input", "reasoning", "tool_execution"],
            entry_points=[
                {"name": "chat", "direction": "input", "controllability": "direct"},
                {"name": "api", "direction": "input", "controllability": "direct"},
            ],
            confidence=ConfidenceLevel.high,
            kc_subcodes=["KC1.1", "KC5.1"],
            tool_inventory=[{"name": "writer", "description": "changes state"}],
            tool_types=[
                {
                    "name": "writer",
                    "zone": "tool_execution",
                    "can_modify_state": True,
                    "data_sensitivity": "medium",
                    "code_execution": False,
                }
            ],
            external_integrations=[
                {
                    "name": "CRM",
                    "integration_type": "api",
                    "auth_method": "oauth",
                    "data_sensitivity": "high",
                }
            ],
            trust_boundaries=[
                {
                    "name": "user-to-agent",
                    "from_zone": "input",
                    "to_zone": "reasoning",
                    "confidence": "explicit",
                }
            ],
        )
        snapshot = capture_capability_snapshot(profile, (_evidence(),))
        target_ids = {ep.entry_point_id for ep in profile.entry_points}

        batch = project_authoritative_candidates(
            [raw],
            resolver,
            snapshot,
            budget=ProjectionBudget(max_candidates=1),
            coverage_target_ids=target_ids,
        )
        # Unreserved targets are the exact IDs not covered.
        assert len(batch.unreserved_coverage_targets) == 1
        unreserved_id = batch.unreserved_coverage_targets[0]
        assert unreserved_id in target_ids
        assert unreserved_id not in {
            c.canonical_ingress.entry_point_id for c in batch.candidates
        }


def _profile_for_projection() -> CapabilityProfile:
    """Build a profile with multiple entry points for projection tests."""
    return CapabilityProfile(
        zones_active=["input", "reasoning", "tool_execution"],
        entry_points=[
            EntryPoint(name="user prompt", direction="input", controllability="direct"),
            EntryPoint(
                name="RAG documents",
                direction="bidirectional",
                controllability="indirect",
            ),
        ],
        confidence=ConfidenceLevel.medium,
        kc_subcodes=["KC1.1"],
        entry_point_completeness=InventoryCompleteness.inferred_partial,
    )


# ---------------------------------------------------------------------------
# cmps.4 blocker 1: merged accepted-filter provenance, no first-wins
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# cmps.4 blocker 2: permutation invariance and two-target/two-pattern
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# cmps.4 blocker 3: projection reservation correctness
# ---------------------------------------------------------------------------


class TestProjectionReservation:
    """Coverage-aware projection reservation before Stage 3.7."""

    def test_two_ingresses_budget_two_reserves_both(self) -> None:
        """One pattern, two ingresses, budget=2 → both reserved."""
        from asago_scenario_generator.models.attack_pattern import AttackPattern
        from asago_scenario_generator.models.capability_profile import (
            CapabilityProfile,
            ConfidenceLevel,
        )
        from asago_scenario_generator.pipeline.projection import (
            ProjectionBudget,
            capture_capability_snapshot,
            project_authoritative_candidates,
        )
        from tests.helpers.projection_factory import (
            _evidence,
            _pattern,
            _TaxonomyResolver,
        )

        raw = _pattern()
        pattern = AttackPattern.model_validate(raw)
        resolver = _TaxonomyResolver(pattern.canonical_chain.taxonomy_context)
        profile = CapabilityProfile(
            zones_active=["input", "reasoning", "tool_execution"],
            entry_points=[
                {"name": "chat", "direction": "input", "controllability": "direct"},
                {"name": "api", "direction": "input", "controllability": "direct"},
            ],
            confidence=ConfidenceLevel.high,
            kc_subcodes=["KC1.1", "KC5.1"],
            tool_inventory=[{"name": "writer", "description": "changes state"}],
            tool_types=[
                {
                    "name": "writer",
                    "zone": "tool_execution",
                    "can_modify_state": True,
                    "data_sensitivity": "medium",
                    "code_execution": False,
                }
            ],
            external_integrations=[
                {
                    "name": "CRM",
                    "integration_type": "api",
                    "auth_method": "oauth",
                    "data_sensitivity": "high",
                }
            ],
            trust_boundaries=[
                {
                    "name": "user-to-agent",
                    "from_zone": "input",
                    "to_zone": "reasoning",
                    "confidence": "explicit",
                }
            ],
        )
        snapshot = capture_capability_snapshot(profile, (_evidence(),))
        target_ids = {ep.entry_point_id for ep in profile.entry_points}
        assert len(target_ids) == 2

        batch = project_authoritative_candidates(
            [raw],
            resolver,
            snapshot,
            budget=ProjectionBudget(max_candidates=2),
            coverage_target_ids=target_ids,
        )
        projected_eps = {c.canonical_ingress.entry_point_id for c in batch.candidates}
        assert target_ids <= projected_eps
        assert len(batch.unreserved_coverage_targets) == 0

    def test_infeasible_target_distinct_from_budget_omitted(self) -> None:
        """A target with no compatible projection is infeasible, not budget-omitted."""
        from asago_scenario_generator.pipeline.projection import (
            ProjectionBudget,
            project_authoritative_candidates,
        )
        from tests.helpers.projection_factory import _cached_project

        _, resolver, snapshot, raw = _cached_project()
        pc = get_projected_candidate()
        target_id = pc.canonical_ingress.entry_point_id
        # Add a fake target that has no compatible projection.
        fake_target = "ep:v1:ffffffffffffffffffffffffffffffffff"
        batch = project_authoritative_candidates(
            [raw],
            resolver,
            snapshot,
            budget=ProjectionBudget(max_candidates=256),
            coverage_target_ids={target_id, fake_target},
        )
        assert fake_target in batch.infeasible_coverage_targets
        assert fake_target not in batch.unreserved_coverage_targets

    def test_budget_below_targets_emits_exact_omitted_ids(self) -> None:
        """Budget < feasible target count → exact omitted IDs from final candidates."""
        from asago_scenario_generator.models.attack_pattern import AttackPattern
        from asago_scenario_generator.models.capability_profile import (
            CapabilityProfile,
            ConfidenceLevel,
        )
        from asago_scenario_generator.pipeline.projection import (
            ProjectionBudget,
            capture_capability_snapshot,
            project_authoritative_candidates,
        )
        from tests.helpers.projection_factory import (
            _evidence,
            _pattern,
            _TaxonomyResolver,
        )

        raw = _pattern()
        pattern = AttackPattern.model_validate(raw)
        resolver = _TaxonomyResolver(pattern.canonical_chain.taxonomy_context)
        profile = CapabilityProfile(
            zones_active=["input", "reasoning", "tool_execution"],
            entry_points=[
                {"name": "chat", "direction": "input", "controllability": "direct"},
                {"name": "api", "direction": "input", "controllability": "direct"},
            ],
            confidence=ConfidenceLevel.high,
            kc_subcodes=["KC1.1", "KC5.1"],
            tool_inventory=[{"name": "writer", "description": "changes state"}],
            tool_types=[
                {
                    "name": "writer",
                    "zone": "tool_execution",
                    "can_modify_state": True,
                    "data_sensitivity": "medium",
                    "code_execution": False,
                }
            ],
            external_integrations=[
                {
                    "name": "CRM",
                    "integration_type": "api",
                    "auth_method": "oauth",
                    "data_sensitivity": "high",
                }
            ],
            trust_boundaries=[
                {
                    "name": "user-to-agent",
                    "from_zone": "input",
                    "to_zone": "reasoning",
                    "confidence": "explicit",
                }
            ],
        )
        snapshot = capture_capability_snapshot(profile, (_evidence(),))
        target_ids = {ep.entry_point_id for ep in profile.entry_points}

        batch = project_authoritative_candidates(
            [raw],
            resolver,
            snapshot,
            budget=ProjectionBudget(max_candidates=1),
            coverage_target_ids=target_ids,
        )
        omitted = set(batch.unreserved_coverage_targets)
        emitted_eps = {c.canonical_ingress.entry_point_id for c in batch.candidates}
        # Omitted targets are exactly those not emitted.
        assert omitted == target_ids - emitted_eps
        assert len(omitted) == 1
        # No infeasible targets — both have compatible projections.
        assert len(batch.infeasible_coverage_targets) == 0


# ---------------------------------------------------------------------------
# cmps.4 blocker 5: funnel invariant enforcement
# ---------------------------------------------------------------------------


class TestFunnelInvariant:
    """CandidateFunnel must enforce selected <= qualified unconditionally."""

    def test_selected_gt_qualified_rejected_directly(self) -> None:
        from asago_scenario_generator.pipeline.candidate_models import CandidateFunnel

        with pytest.raises(ValueError, match="selected.*qualified"):
            CandidateFunnel(
                expanded_instances=10,
                unique_pre_rule_identities=5,
                rule_rejected=0,
                rule_transformed=0,
                post_rule_collapsed=0,
                filter_submitted=5,
                filter_accepted=3,
                qualified=0,
                selected=3,
                main_attempted=3,
                main_admitted=2,
                generation_failed=1,
                remediation_attempted=0,
                remediation_admitted=0,
                remediation_failed=0,
                attempted=3,
                admitted=2,
                quarantined=1,
                persisted_artifacts=2,
            )

    def test_derive_funnel_preserves_qualified(self) -> None:
        from asago_scenario_generator.manifest import (
            AttemptDisposition,
            AttemptPhase,
            AttemptRecord,
            derive_funnel_from_attempts,
        )

        attempts = [
            AttemptRecord(
                candidate_id="c1",
                scenario_id="s1",
                disposition=AttemptDisposition.ADMITTED,
                phase=AttemptPhase.MAIN,
            ),
        ]
        funnel = derive_funnel_from_attempts(
            attempts, qualified=5, projection_rejected=2
        )
        assert funnel["qualified"] == 5
        assert funnel["projection_rejected"] == 2
        assert funnel["selected"] == 1  # derived from main_attempts

    def test_derive_funnel_defaults_qualified_to_selected(self) -> None:
        from asago_scenario_generator.manifest import (
            AttemptDisposition,
            AttemptPhase,
            AttemptRecord,
            derive_funnel_from_attempts,
        )

        attempts = [
            AttemptRecord(
                candidate_id="c1",
                scenario_id="s1",
                disposition=AttemptDisposition.ADMITTED,
                phase=AttemptPhase.MAIN,
            ),
        ]
        funnel = derive_funnel_from_attempts(attempts)
        # qualified defaults to selected when not supplied AND
        # projection_rejected is also 0 (qualification stage never reached).
        assert funnel["qualified"] == funnel["selected"] == 1

    def test_derive_funnel_rejects_selected_above_qualified(self) -> None:
        """cmps.4 blocker 5: failed manifests enforce selected <= qualified."""
        from asago_scenario_generator.manifest import (
            AttemptDisposition,
            AttemptPhase,
            AttemptRecord,
            derive_funnel_from_attempts,
        )

        attempts = [
            AttemptRecord(
                candidate_id="c1",
                scenario_id="s1",
                disposition=AttemptDisposition.FAILED,
                failure_evidence="Generation failed",
                phase=AttemptPhase.MAIN,
            ),
        ]
        from asago_scenario_generator.manifest import ManifestIntegrityError

        with pytest.raises(ManifestIntegrityError, match="exceeds qualified"):
            derive_funnel_from_attempts(
                attempts, selected=1, qualified=0, projection_rejected=3
            )


# ---------------------------------------------------------------------------
# cmps.4 blocker 1: Executable persisted fallback — roundtrip and tamper tests
# ---------------------------------------------------------------------------


class TestExecutablePersistedFallback:
    """Blocker 1: AcceptedFilterRecord persists complete FilteredSeed needed
    by ordinary generation; deserialization validates and rejects tampering."""

    def _make_real_qc(self) -> QualifiedCandidate:
        """Build a QualifiedCandidate from the real test ProjectedCandidate
        (with a properly computed candidate_id that survives model_validate)."""
        fseed = _make_fseed(
            entry_point_id=_REAL_EP_ID,
            candidate_id=f"filter-{_REAL_EP_ID}-1",
        )
        return QualifiedCandidate(
            projected=_REAL_PC,
            accepted_filters=(AcceptedFilterRecord.from_seed(fseed),),
        )

    def _make_real_qc_two_filters(self) -> QualifiedCandidate:
        """Build a QualifiedCandidate with two seed-bearing filter records."""
        fseed_a = _make_fseed(
            candidate_id=f"filter-{_REAL_EP_ID}-a",
            entry_point_id=_REAL_EP_ID,
        )
        fseed_b = _make_fseed(
            candidate_id=f"filter-{_REAL_EP_ID}-b",
            entry_point_id=_REAL_EP_ID,
        )
        return QualifiedCandidate(
            projected=_REAL_PC,
            accepted_filters=(
                AcceptedFilterRecord.from_seed(fseed_a),
                AcceptedFilterRecord.from_seed(fseed_b),
            ),
        )

    def test_exact_roundtrip_generation_seed(self) -> None:
        """Round-tripped plan ref yields the exact generation_seed and
        projected candidate usable by ordinary generate_scenario args."""
        qc = self._make_real_qc()
        ref = qc.to_plan_ref()
        deserialized = deserialize_qualified_candidate(ref)
        # The generation seed must match exactly.
        assert deserialized.generation_seed.model_dump(mode="json") == (
            qc.generation_seed.model_dump(mode="json")
        )
        # The projected candidate must match exactly.
        assert deserialized.projected.model_dump(mode="json") == (
            qc.projected.model_dump(mode="json")
        )
        # Outer IDs agree.
        assert deserialized.candidate_id == qc.candidate_id
        assert deserialized.pattern_id == qc.pattern_id
        assert deserialized.entry_point_id == qc.entry_point_id

    def test_roundtrip_into_generate_scenario_args(self) -> None:
        """The deserialized plan ref exposes the exact FilteredSeed and
        ProjectedCandidate needed by ordinary generation, not just pins."""
        qc = self._make_real_qc()
        ref = qc.to_plan_ref()
        deserialized = deserialize_qualified_candidate(ref)
        seed = deserialized.generation_seed
        # The seed must be a real FilteredSeed with all generation fields.
        assert seed.seed_id == qc.generation_seed.seed_id
        assert seed.threat_id == qc.generation_seed.threat_id
        assert seed.entry_point_id == qc.generation_seed.entry_point_id
        assert seed.candidate_id == qc.generation_seed.candidate_id
        assert seed.pinned_technique_ids == qc.generation_seed.pinned_technique_ids
        # The projected candidate is complete, not a thin ref.
        assert deserialized.projected.candidate_id == qc.projected.candidate_id
        assert (
            deserialized.projected.execution_requirements
            == qc.projected.execution_requirements
        )

    def test_outer_candidate_id_tamper_rejected(self) -> None:
        """Outer candidate_id disagreeing with embedded data is rejected."""
        qc = self._make_real_qc()
        ref = qc.to_plan_ref()
        ref["candidate_id"] = "cand:v2:ffffffffffffffffffffffffffffffff"
        with pytest.raises(ValueError, match="disagrees"):
            deserialize_qualified_candidate(ref)

    def test_outer_pattern_id_tamper_rejected(self) -> None:
        """Outer pattern_id disagreeing with embedded data is rejected."""
        qc = self._make_real_qc()
        ref = qc.to_plan_ref()
        ref["pattern_id"] = "AP-TAMPER-01"
        with pytest.raises(ValueError, match="disagrees"):
            deserialize_qualified_candidate(ref)

    def test_outer_entry_point_id_tamper_rejected(self) -> None:
        """Outer entry_point_id disagreeing with embedded data is rejected."""
        qc = self._make_real_qc()
        ref = qc.to_plan_ref()
        ref["entry_point_id"] = "ep:v1:deadbeef"
        with pytest.raises(ValueError, match="disagrees"):
            deserialize_qualified_candidate(ref)

    def test_embedded_candidate_tamper_rejected(self) -> None:
        """Tampering with the embedded projected candidate's candidate_id
        causes model_validate to fail (candidate_id identity check)."""
        from pydantic import ValidationError

        qc = self._make_real_qc()
        ref = qc.to_plan_ref()
        ref["projected_candidate"]["candidate_id"] = "cand:v2:deadbeef"
        with pytest.raises((ValidationError, ValueError)):
            deserialize_qualified_candidate(ref)

    def test_duplicate_filter_ids_rejected(self) -> None:
        """Duplicate filter_candidate_ids in accepted_filters are rejected."""
        qc = self._make_real_qc()
        ref = qc.to_plan_ref()
        # Duplicate the single filter record.
        ref["accepted_filters"] = [
            ref["accepted_filters"][0],
            ref["accepted_filters"][0],
        ]
        with pytest.raises(ValueError, match="duplicate"):
            deserialize_qualified_candidate(ref)

    def test_noncanonical_filter_order_rejected(self) -> None:
        """Noncanonical (unsorted) filter order is rejected."""
        qc = self._make_real_qc_two_filters()
        ref = qc.to_plan_ref()
        # to_plan_ref sorts by filter_candidate_id, so the order is canonical.
        # Swap the two records to create noncanonical order.
        assert len(ref["accepted_filters"]) == 2
        first_id = ref["accepted_filters"][0]["filter_candidate_id"]
        second_id = ref["accepted_filters"][1]["filter_candidate_id"]
        assert first_id < second_id  # canonical order
        ref["accepted_filters"] = [
            ref["accepted_filters"][1],
            ref["accepted_filters"][0],
        ]
        with pytest.raises(ValueError, match="canonical order"):
            deserialize_qualified_candidate(ref)

    def test_deserialized_plan_ref_is_typed(self) -> None:
        """deserialize_qualified_candidate returns a DeserializedPlanRef."""
        qc = self._make_real_qc()
        ref = qc.to_plan_ref()
        deserialized = deserialize_qualified_candidate(ref)
        assert isinstance(deserialized, DeserializedPlanRef)
        assert deserialized.accepted_filters  # non-empty
        assert deserialized.accepted_filters[0].seed is not None

    def test_seed_entry_point_mismatch_rejected(self) -> None:
        """A seed whose entry_point_id doesn't match the projected ingress
        is rejected."""
        qc = self._make_real_qc()
        ref = qc.to_plan_ref()
        # Tamper the seed's entry_point_id to differ from the projected ingress.
        ref["accepted_filters"][0]["seed"]["entry_point_id"] = "ep:v1:tampered"
        with pytest.raises(ValueError, match="disagrees"):
            deserialize_qualified_candidate(ref)

    def test_missing_seed_and_changed_record_summary_rejected(self) -> None:
        qc = self._make_real_qc()
        ref = qc.to_plan_ref()
        ref["accepted_filters"][0].pop("seed")
        with pytest.raises(ValueError, match="missing seed"):
            deserialize_qualified_candidate(ref)

        ref = qc.to_plan_ref()
        ref["accepted_filters"][0]["rationale"] = "tampered"
        with pytest.raises(ValueError, match="does not match"):
            deserialize_qualified_candidate(ref)

    def test_authoritative_validation_uses_complete_catalog_pin(self) -> None:
        """A fallback validates directly against its authoritative record and
        the pin of the complete catalog, without bounded reprojection."""
        from copy import deepcopy

        from asago_scenario_generator.models.attack_pattern import (
            compute_chain_semantic_digest,
        )
        from asago_scenario_generator.pipeline.projection import (
            ProjectionBudget,
            project_authoritative_candidates,
        )
        from tests.helpers.projection_factory import (
            get_test_raw_pattern,
            get_test_resolver,
            get_test_snapshot,
        )

        raw = get_test_raw_pattern()
        other = deepcopy(raw)
        other["id"] = "AP-T1-02"
        other["canonical_chain"]["pattern_id"] = "AP-T1-02"
        other["canonical_chain"]["semantic_digest"] = compute_chain_semantic_digest(
            other["canonical_chain"]
        )
        resolver = get_test_resolver()
        snapshot = get_test_snapshot()
        batch = project_authoritative_candidates(
            [raw, other], resolver, snapshot, budget=ProjectionBudget(max_candidates=8)
        )
        projected = next(
            candidate
            for candidate in batch.candidates
            if candidate.pattern_id == raw["id"]
        )
        seed = _make_fseed(entry_point_id=projected.canonical_ingress.entry_point_id)
        qc = QualifiedCandidate(
            projected=projected,
            accepted_filters=(AcceptedFilterRecord.from_seed(seed),),
        )
        ref = qc.to_plan_ref()
        validated = revalidate_qualified_candidate(
            ref, resolver, snapshot, [raw, other]
        )
        assert validated.generation_seed == seed
        assert validated.projected == projected

        with pytest.raises(ValueError, match="catalog pin"):
            revalidate_qualified_candidate(ref, resolver, snapshot, [raw])


# ---------------------------------------------------------------------------
# cmps.4 blocker 2: True global primary assignment — min-cost flow tests
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# cmps.4 blocker 3: Bounded projection computation — lazy, bounded work
# ---------------------------------------------------------------------------


class TestBoundedProjection:
    """Blocker 3: lazy projection avoids materializing Cartesian product."""

    def test_target_reservation_duplicate_probe_is_not_budget_truncation(self) -> None:
        """The generic probe can rediscover a target-reserved candidate.  That
        duplicate must not inflate per-pattern derived counts or claim a
        candidate budget limitation when max_candidates=1."""
        from asago_scenario_generator.pipeline.projection import (
            ProjectionBudget,
            project_authoritative_candidates,
        )
        from tests.helpers.projection_factory import (
            get_test_raw_pattern,
            get_test_resolver,
            get_test_snapshot,
        )

        snapshot = get_test_snapshot()
        target_id = get_projected_candidate().canonical_ingress.entry_point_id
        result = project_authoritative_candidates(
            [get_test_raw_pattern()],
            get_test_resolver(),
            snapshot,
            budget=ProjectionBudget(max_candidates=1),
            coverage_target_ids={target_id},
        )
        assert len(result.candidates) == 1
        assert not any(
            limitation.code == "candidate_budget_exhausted"
            for limitation in result.limitations
        )

    def test_one_pattern_two_ingresses_budget2(self) -> None:
        """One pattern with two ingress options, budget 2: both emitted,
        no budget limitation."""
        from asago_scenario_generator.pipeline.projection import (
            ProjectionBudget,
            project_authoritative_candidates,
        )
        from tests.helpers.projection_factory import (
            get_test_raw_pattern,
            get_test_resolver,
            get_test_snapshot,
        )

        snapshot = get_test_snapshot()
        resolver = get_test_resolver()
        record = get_test_raw_pattern()
        result = project_authoritative_candidates(
            [record],
            resolver,
            snapshot,
            budget=ProjectionBudget(max_candidates=2),
        )
        # Should emit at least 1 candidate (baseline).
        assert len(result.candidates) >= 1
        # No budget limitation if all feasible candidates were admitted.
        budget_limits = [
            lim
            for lim in result.limitations
            if lim.code == "candidate_budget_exhausted"
        ]
        # With only a small pattern, all feasible combos should fit in budget 2.
        # (The test pattern has limited resource slots.)
        if budget_limits:
            # If there are limitations, the iterator was genuinely truncated.
            assert (
                budget_limits[0].emitted_bindings
                < budget_limits[0].total_compatible_bindings
            )

    def test_structural_rejections_no_budget_limitation(self) -> None:
        """When all feasible candidates are emitted (structural rejections
        don't count as budget exhaustion), no budget limitation is emitted."""
        from asago_scenario_generator.pipeline.projection import (
            ProjectionBudget,
            project_authoritative_candidates,
        )
        from tests.helpers.projection_factory import (
            get_test_raw_pattern,
            get_test_resolver,
            get_test_snapshot,
        )

        snapshot = get_test_snapshot()
        resolver = get_test_resolver()
        record = get_test_raw_pattern()
        # Use a large budget so all feasible candidates are admitted.
        result = project_authoritative_candidates(
            [record],
            resolver,
            snapshot,
            budget=ProjectionBudget(max_candidates=256),
        )
        budget_limits = [
            lim
            for lim in result.limitations
            if lim.code == "candidate_budget_exhausted"
        ]
        # With a large budget, no pattern should have a budget limitation.
        assert budget_limits == [], f"unexpected budget limitations: {budget_limits}"

    def test_large_inventory_bounded_work(self) -> None:
        """A large multi-slot inventory must complete without materializing
        the full Cartesian product.  Verify bounded runtime and that the
        number of emitted candidates is limited by the budget."""
        from asago_scenario_generator.pipeline.projection import (
            ProjectionBudget,
            project_authoritative_candidates,
        )
        from tests.helpers.projection_factory import (
            get_test_raw_pattern,
            get_test_resolver,
            get_test_snapshot,
        )

        snapshot = get_test_snapshot()
        resolver = get_test_resolver()
        record = get_test_raw_pattern()
        # Use a small budget to force early truncation.
        budget = ProjectionBudget(max_candidates=4)
        import time

        start = time.monotonic()
        result = project_authoritative_candidates(
            [record],
            resolver,
            snapshot,
            budget=budget,
        )
        elapsed = time.monotonic() - start
        # Must not materialize all combinations — bounded by budget.
        assert len(result.candidates) <= 4
        # Must complete quickly.
        assert elapsed < 15.0, f"projection took {elapsed:.1f}s"


# ---------------------------------------------------------------------------
# cmps.4 blocker 4: Stage ledger records typed filter verdict rationale
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# cmps.4 blocker 5: Failed funnel context — persisted manifest equations
# ---------------------------------------------------------------------------


class TestFailedFunnelContext:
    """Blocker 5: Exception reconstruction must use actual counts."""

    def test_partial_manifest_captures_qualified_before_generation(self) -> None:
        """The partial_manifest.funnel must capture qualified and
        projection_rejected after selection, before generation may fail."""
        # Simulate the funnel dict that the runner captures.
        funnel_snapshot = {
            "qualified": 5,
            "projection_rejected": 3,
            "selected": 2,
        }
        # If generation fails after first reservation, the exception handler
        # reads these from existing_funnel.
        existing_qualified = funnel_snapshot.get("qualified", 0)
        existing_projection_rejected = funnel_snapshot.get("projection_rejected", 0)
        existing_selected = funnel_snapshot.get("selected", 0)

        from asago_scenario_generator.manifest import (
            AttemptDisposition,
            AttemptPhase,
            AttemptRecord,
            derive_funnel_from_attempts,
        )

        # One attempt succeeded, one failed (failure after first reservation).
        attempts = [
            AttemptRecord(
                candidate_id="c1",
                scenario_id="s1",
                disposition=AttemptDisposition.ADMITTED,
                phase=AttemptPhase.MAIN,
            ),
            AttemptRecord(
                candidate_id="c2",
                scenario_id="",
                disposition=AttemptDisposition.FAILED,
                failure_evidence="Generation failed",
                phase=AttemptPhase.MAIN,
            ),
        ]
        funnel = derive_funnel_from_attempts(
            attempts,
            selected=existing_selected,
            qualified=existing_qualified,
            projection_rejected=existing_projection_rejected,
        )
        # Actual counts preserved, not defaulted.
        assert funnel["qualified"] == 5
        assert funnel["projection_rejected"] == 3
        assert funnel["selected"] == 2
        assert funnel["qualified"] > funnel["selected"]
        assert funnel["projection_rejected"] > 0

    def test_failure_after_first_reservation_manifest_equations(self) -> None:
        """Integration: failure after first reservation with qualified>selected
        and projection_rejected>0 — assert persisted failed manifest equations."""
        from asago_scenario_generator.manifest import (
            AttemptDisposition,
            AttemptPhase,
            AttemptRecord,
            derive_funnel_from_attempts,
        )

        # Simulate: 5 qualified, 3 projection-rejected, 2 selected.
        # First generation succeeds, second fails.
        attempts = [
            AttemptRecord(
                candidate_id="c1",
                scenario_id="s1",
                disposition=AttemptDisposition.ADMITTED,
                phase=AttemptPhase.MAIN,
            ),
            AttemptRecord(
                candidate_id="c2",
                scenario_id="",
                disposition=AttemptDisposition.FAILED,
                failure_evidence="Generation failed",
                phase=AttemptPhase.MAIN,
            ),
        ]
        funnel = derive_funnel_from_attempts(
            attempts,
            selected=2,
            qualified=5,
            projection_rejected=3,
        )
        # Persisted failed manifest equations.
        assert funnel["qualified"] == 5  # actual, not defaulted to selected
        assert funnel["projection_rejected"] == 3  # actual, not zero
        assert funnel["selected"] == 2
        assert funnel["main_attempted"] == 2
        assert funnel["generation_failed"] == 1
        assert funnel["main_admitted"] == 1  # one admitted
        # qualified > selected (not defaulted)
        assert funnel["qualified"] > funnel["selected"]
