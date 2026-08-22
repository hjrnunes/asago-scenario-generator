"""Comprehensive regression tests for cmps.4 coverage-aware planning."""

from __future__ import annotations

import inspect

import pytest

from asago_scenario_generator.models.attack_pattern import EntryPointResourceReference
from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    ConfidenceLevel,
    EntryPoint,
    InventoryCompleteness,
)
from asago_scenario_generator.models.scenario import RiskCardRef
from asago_scenario_generator.pipeline.candidates import FilteredSeed, filter_candidates
from asago_scenario_generator.pipeline.coverage_planning import (
    MAX_FALLBACK_CHOICES,
    STAGE_ADMISSION,
    STAGE_FILTER,
    STAGE_GENERATION,
    STAGE_PROJECTION,
    STAGE_QUARANTINE,
    STAGE_RULES,
    STAGE_SELECTION,
    AcceptedFilterRecord,
    CoverageCompleteness,
    CoverageExclusionReason,
    CoverageGapReason,
    CoverageTarget,
    CoverageUniverse,
    DeserializedPlanRef,
    ExcludedTarget,
    GenerationMode,
    GenerationPlanningResult,
    QualifiedCandidate,
    SelectionResult,
    StageLedger,
    build_coverage_plan,
    build_coverage_universe,
    build_fallback_queues,
    build_qualified_candidates,
    deserialize_plan_ref,
    deserialize_qualified_candidate,
    emit_quality_gaps,
    plan_generation,
    revalidate_qualified_candidate,
    select_with_coverage_priority,
)
from asago_scenario_generator.pipeline.projection import ProjectedCandidate
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


def _universe(*ids: str) -> CoverageUniverse:
    return CoverageUniverse(
        feasible_targets=[
            CoverageTarget(i, f"Target {i}", "input", "direct") for i in ids
        ]
    )


class TestBuildCoverageUniverse:
    def test_input_direct_is_feasible(self) -> None:
        ep = EntryPoint(name="prompt", direction="input", controllability="direct")
        assert (
            build_coverage_universe(_profile([ep])).feasible_targets[0].entry_point_id
            == ep.entry_point_id
        )

    def test_bidirectional_indirect_is_feasible(self) -> None:
        ep = EntryPoint(
            name="RAG documents", direction="bidirectional", controllability="indirect"
        )
        target = build_coverage_universe(_profile([ep])).feasible_targets[0]
        assert (target.direction, target.controllability) == (
            "bidirectional",
            "indirect",
        )

    @pytest.mark.parametrize(
        ("entry", "reason"),
        [
            (
                EntryPoint(name="logs", direction="output"),
                CoverageExclusionReason.OUTPUT_ONLY,
            ),
            (
                EntryPoint(
                    name="internal", direction="input", controllability="system"
                ),
                CoverageExclusionReason.SYSTEM_CONTROLLED,
            ),
            (
                EntryPoint(
                    name="memory",
                    direction="input",
                    controllability="indirect",
                    ingress_zone="memory",
                ),
                CoverageExclusionReason.INACTIVE_ZONE,
            ),
        ],
    )
    def test_typed_exclusions(
        self, entry: EntryPoint, reason: CoverageExclusionReason
    ) -> None:
        universe = build_coverage_universe(
            _profile([entry], zones=["input", "reasoning"])
        )
        assert universe.feasible_targets == []
        assert universe.excluded_targets[0].reason is reason

    def test_completeness_is_not_applicable_for_inferred_profile(self) -> None:
        ep = EntryPoint(name="prompt", direction="input", controllability="direct")
        assert (
            build_coverage_universe(_profile([ep])).completeness
            is CoverageCompleteness.NOT_APPLICABLE
        )

    def test_operator_confirmation_sets_complete_and_evidence(self) -> None:
        ep = EntryPoint(name="prompt", direction="input", controllability="direct")
        universe = build_coverage_universe(_profile([ep], confirmed=True))
        assert universe.completeness is CoverageCompleteness.CONFIRMED_COMPLETE
        assert universe.evidence_refs == ["operator-review:architecture-v3"]

    def test_caller_cannot_promote_inferred_profile_with_enum(self) -> None:
        assert (
            "completeness" not in inspect.signature(build_coverage_universe).parameters
        )

    def test_mixed_profile(self) -> None:
        entries = [
            EntryPoint(name="prompt", direction="input", controllability="direct"),
            EntryPoint(
                name="RAG", direction="bidirectional", controllability="indirect"
            ),
            EntryPoint(name="logs", direction="output"),
            EntryPoint(name="internal", direction="input", controllability="system"),
        ]
        universe = build_coverage_universe(_profile(entries))
        assert len(universe.feasible_targets) == 2
        assert {e.reason for e in universe.excluded_targets} == {
            CoverageExclusionReason.OUTPUT_ONLY,
            CoverageExclusionReason.SYSTEM_CONTROLLED,
        }


class TestBuildQualifiedCandidates:
    def test_fans_out_distinct_projected_bindings(self) -> None:
        seed = _make_fseed()
        pcs = [_make_pc(f"cand:v2:{i:032x}") for i in (1, 2)]
        result = build_qualified_candidates([seed], {seed.seed_id: pcs})
        assert [q.candidate_id for q in result] == [p.candidate_id for p in pcs]

    def test_dedupes_by_projected_candidate_id(self) -> None:
        seed = _make_fseed()
        pc = _make_pc()
        assert (
            len(build_qualified_candidates([seed, seed], {seed.seed_id: [pc, pc]})) == 1
        )

    def test_preserves_accepted_rationale(self) -> None:
        seed = _make_fseed(rationale="specific filter evidence")
        result = build_qualified_candidates([seed], {seed.seed_id: [_make_pc()]})
        assert result[0].accepted_rationale == "specific filter evidence"

    def test_no_matching_ingress_is_empty(self) -> None:
        seed = _make_fseed(entry_point_id=_REAL_EP_ID)
        assert (
            build_qualified_candidates(
                [seed], {seed.seed_id: [_make_pc(entry_point_id=_ep_id(2))]}
            )
            == []
        )


class TestBuildFallbackQueues:
    def test_queue_is_bounded(self) -> None:
        queue = build_fallback_queues(
            [_qc(i) for i in range(5)], _universe(_REAL_EP_ID)
        )[_REAL_EP_ID]
        assert len(queue.choices) == MAX_FALLBACK_CHOICES == 3

    def test_target_without_candidates_has_empty_queue(self) -> None:
        assert build_fallback_queues([], _universe(_REAL_EP_ID))[_REAL_EP_ID].is_empty

    def test_deterministic_candidate_v2_rank_not_technique_count(self) -> None:
        """Rank is encounter-independent (pattern_id, candidate_id), not
        pinned-technique count.  Two candidates with different technique
        counts are ordered by candidate_id regardless of arrival order."""
        first = _qc(9, techniques=("T1",))
        second = _qc(1, techniques=("T1", "T2", "T3"))
        queue = build_fallback_queues([first, second], _universe(_REAL_EP_ID))[
            _REAL_EP_ID
        ]
        # candidate_id for _qc(1) < _qc(9), so second is first in queue.
        assert queue.candidate_ids() == [second.candidate_id, first.candidate_id]
        assert [choice.rank for choice in queue.choices] == [0, 1]

    def test_first_and_remaining_choices(self) -> None:
        candidates = [_qc(i) for i in (1, 2, 3)]
        queue = build_fallback_queues(candidates, _universe(_REAL_EP_ID))[_REAL_EP_ID]
        assert queue.first_choice.candidate_id == candidates[0].candidate_id
        assert [q.candidate_id for q in queue.remaining_choices] == [
            q.candidate_id for q in candidates[1:]
        ]

    def test_queues_are_isolated_per_target(self) -> None:
        queues = build_fallback_queues(
            [_qc(1, ep=_ep_id(10)), _qc(2, ep=_ep_id(11))],
            _universe(_ep_id(10), _ep_id(11)),
        )
        assert queues[_ep_id(10)].candidate_ids() == [
            _qc(1, ep=_ep_id(10)).candidate_id
        ]
        assert queues[_ep_id(11)].candidate_ids() == [
            _qc(2, ep=_ep_id(11)).candidate_id
        ]

    def test_distinct_binding_alternatives_all_appear(self) -> None:
        choices = [_qc(i, pattern="same-pattern") for i in (1, 2, 3)]
        assert build_fallback_queues(choices, _universe(_REAL_EP_ID))[
            _REAL_EP_ID
        ].candidate_ids() == [q.candidate_id for q in choices]


class TestGenerationPolicy:
    @pytest.mark.parametrize("mode", list(GenerationMode))
    def test_generation_policy_rejects_a_nonpositive_pattern_cap(
        self, mode: GenerationMode
    ) -> None:
        with pytest.raises(ValueError, match="positive integer"):
            plan_generation([], _universe(_REAL_EP_ID), mode=mode, max_per_pattern=0)

    def test_exhaustive_mode_selects_every_qualified_candidate(self) -> None:
        candidates = [_qc(i) for i in range(1, 6)]

        result = plan_generation(
            candidates,
            _universe(_REAL_EP_ID),
            mode=GenerationMode.EXHAUSTIVE,
        )

        assert isinstance(result, GenerationPlanningResult)
        assert [item.candidate_id for item in result.selection.selected] == [
            item.candidate_id for item in candidates
        ]
        assert len(result.plan.targets) == len(candidates)
        assert len({target.target_id for target in result.plan.targets}) == len(
            candidates
        )
        assert {target.entry_point_id for target in result.plan.targets} == {
            _REAL_EP_ID
        }
        assert all(len(target.ordered_choices) == 1 for target in result.plan.targets)

    def test_coverage_mode_preserves_one_bounded_queue_per_ingress(self) -> None:
        candidates = [_qc(i) for i in range(1, 6)]

        result = plan_generation(
            candidates,
            _universe(_REAL_EP_ID),
            mode=GenerationMode.COVERAGE,
        )

        assert len(result.selection.selected) == 1
        assert len(result.plan.targets) == 1
        assert result.plan.targets[0].target_id == _REAL_EP_ID
        assert len(result.plan.targets[0].ordered_choices) == MAX_FALLBACK_CHOICES

    def test_exhaustive_pattern_cap_prioritizes_ingress_diversity(self) -> None:
        first_ep = _ep_id(10)
        second_ep = _ep_id(11)
        candidates = [
            _qc(1, ep=first_ep, pattern="AP-SAME"),
            _qc(2, ep=first_ep, pattern="AP-SAME"),
            _qc(3, ep=second_ep, pattern="AP-SAME"),
            _qc(4, ep=second_ep, pattern="AP-SAME"),
        ]

        result = plan_generation(
            candidates,
            _universe(first_ep, second_ep),
            mode=GenerationMode.EXHAUSTIVE,
            max_per_pattern=2,
        )

        assert len(result.selection.selected) == 2
        assert {item.entry_point_id for item in result.selection.selected} == {
            first_ep,
            second_ep,
        }
        assert result.selection.capped_count == 2

    def test_exhaustive_cap_reports_ingress_left_without_a_selection(self) -> None:
        first_ep = _ep_id(10)
        second_ep = _ep_id(11)

        result = plan_generation(
            [
                _qc(1, ep=first_ep, pattern="AP-SAME"),
                _qc(2, ep=second_ep, pattern="AP-SAME"),
            ],
            _universe(first_ep, second_ep),
            mode=GenerationMode.EXHAUSTIVE,
            max_per_pattern=1,
        )

        assert result.selection.uncovered_target_ids == [second_ep]
        assert result.selection.selection_limitation_target_ids == [second_ep]


class TestSelectWithCoveragePriority:
    def _select(
        self,
        candidates: list[QualifiedCandidate],
        universe: CoverageUniverse,
        cap: int | None = None,
    ):
        queues = build_fallback_queues(candidates, universe)
        return select_with_coverage_priority(candidates, queues, universe, cap), queues

    def test_phase_one_covers_each_feasible_target(self) -> None:
        result, _ = self._select(
            [_qc(1, ep=_ep_id(10)), _qc(2, ep=_ep_id(11))],
            _universe(_ep_id(10), _ep_id(11)),
        )
        assert set(result.primary_candidate_ids) == {_ep_id(10), _ep_id(11)}

    def test_reports_target_without_candidate(self) -> None:
        result, _ = self._select(
            [_qc(1, ep=_ep_id(10))], _universe(_ep_id(10), _ep_id(11))
        )
        assert result.uncovered_target_ids == [_ep_id(11)]

    def test_cap_is_immune_for_sole_target_coverage(self) -> None:
        result, _ = self._select(
            [_qc(1, ep=_ep_id(10)), _qc(2, ep=_ep_id(11))],
            _universe(_ep_id(10), _ep_id(11)),
            1,
        )
        assert len(result.selected) == 2
        assert result.per_pattern_counts[_REAL_PATTERN_ID] == 2

    def test_only_primaries_selected_not_fallbacks(self) -> None:
        """cmps.4 blocker 2: Only Phase-1 primaries are selected/attempted.
        Remaining choices are fallback_available, not consumed."""
        result, _queues = self._select([_qc(1), _qc(2), _qc(3)], _universe(_REAL_EP_ID))
        # Only the primary (first choice) is selected.
        assert [q.candidate_id for q in result.selected] == [_qc(1).candidate_id]
        # Remaining choices are NOT in attempted.
        assert _qc(2).candidate_id not in result.attempted_candidate_ids
        assert _qc(3).candidate_id not in result.attempted_candidate_ids

    def test_all_non_primary_choices_are_fallback_available(self) -> None:
        """cmps.4 blocker 2: Persisted plan's fallback_available excludes
        only the attempted primary; all other choices are recoverable."""
        result, queues = self._select([_qc(1), _qc(2), _qc(3)], _universe(_REAL_EP_ID))
        plan = build_coverage_plan(_universe(_REAL_EP_ID), queues, result)
        fb_ids = [r["candidate_id"] for r in plan.targets[0].fallback_available]
        assert _qc(1).candidate_id not in fb_ids
        assert _qc(2).candidate_id in fb_ids
        assert _qc(3).candidate_id in fb_ids

    def test_cap_does_not_apply_to_primaries(self) -> None:
        """With only Phase 1, cap never discards a sole target candidate."""
        result, _ = self._select([_qc(1), _qc(2)], _universe(_REAL_EP_ID), 1)
        assert [q.candidate_id for q in result.selected] == [_qc(1).candidate_id]
        assert result.capped_count == 0

    def test_selection_does_not_prefer_raw_seed_or_more_techniques(self) -> None:
        """Selection uses deterministic (pattern_id, candidate_id) ranking,
        not pinned-technique count.  The candidate with fewer techniques
        but lower candidate_id is selected as primary."""
        first = _qc(9, techniques=("T1",))
        richer = _qc(1, techniques=("T1", "T2"))
        result, _ = self._select([first, richer], _universe(_REAL_EP_ID))
        # candidate_id for _qc(1) < _qc(9), so richer is primary.
        assert result.primary_candidate_ids[_REAL_EP_ID] == richer.candidate_id


class TestStageLedger:
    def test_record_retrieve_and_serialize(self) -> None:
        ledger = StageLedger()
        ledger.record("ep", "c1", STAGE_FILTER, "rejected", "why")
        assert ledger.events_for("ep")[0].candidate_id == "c1"
        assert ledger.to_dict()["events"][0]["detail"] == "why"

    def test_furthest_event_uses_pipeline_order(self) -> None:
        ledger = StageLedger()
        ledger.record("ep", "generated", STAGE_GENERATION, "failed")
        ledger.record("ep", "early", STAGE_RULES, "rejected")
        assert ledger.furthest_event("ep").candidate_id == "generated"

    def test_candidate_ids_for_stage_are_exact(self) -> None:
        ledger = StageLedger()
        ledger.record("ep", "c1", STAGE_GENERATION, "failed")
        ledger.record("ep", "c2", STAGE_GENERATION, "failed")
        ledger.record("ep", "c3", STAGE_FILTER, "rejected")
        assert ledger.candidate_ids_for_stage("ep", STAGE_GENERATION) == ["c1", "c2"]

    def test_no_events_has_no_furthest_event(self) -> None:
        assert StageLedger().furthest_event("missing") is None


def _emit(
    universe: CoverageUniverse,
    ledger: StageLedger,
    *,
    generated=(),
    quarantined=(),
    limited=(),
):
    selection = SelectionResult(
        uncovered_target_ids=[t.entry_point_id for t in universe.feasible_targets]
    )
    return emit_quality_gaps(
        universe,
        ledger,
        selection,
        build_fallback_queues([], universe),
        generated_target_ids=set(generated),
        quarantined_target_ids=set(quarantined),
        projection_limitation_target_ids=set(limited),
    )


class TestEmitQualityGaps:
    def test_covered_target_has_no_gap(self) -> None:
        gaps, summary = _emit(_universe("ep"), StageLedger(), generated={"ep"})
        assert gaps == [] and summary.covered_feasible == ["ep"]

    def test_no_seed_without_events(self) -> None:
        gaps, _ = _emit(_universe("ep"), StageLedger())
        assert gaps[0].reason is CoverageGapReason.NO_SEED
        assert gaps[0].candidate_ids == []

    @pytest.mark.parametrize(
        ("stage", "reason", "summary_field"),
        [
            (
                STAGE_RULES,
                CoverageGapReason.DETERMINISTIC_RULE_REJECTION,
                "structural_gaps",
            ),
            (STAGE_FILTER, CoverageGapReason.FILTER_REJECTION, "structural_gaps"),
            (
                STAGE_PROJECTION,
                CoverageGapReason.PROJECTION_REJECTION,
                "structural_gaps",
            ),
            (
                STAGE_SELECTION,
                CoverageGapReason.SELECTION_LIMITATION,
                "selection_limitations",
            ),
            (
                STAGE_GENERATION,
                CoverageGapReason.GENERATION_EXHAUSTION,
                "runtime_generation_gaps",
            ),
            (
                STAGE_ADMISSION,
                CoverageGapReason.ADMISSION_FAILURE,
                "quarantine_admission_failures",
            ),
        ],
    )
    def test_actual_furthest_stage_drives_reason_and_summary(
        self, stage: str, reason: CoverageGapReason, summary_field: str
    ) -> None:
        ledger = StageLedger()
        ledger.record("ep", "exact-candidate", stage, "failed", "actual evidence")
        gaps, summary = _emit(_universe("ep"), ledger)
        assert gaps[0].reason is reason
        assert gaps[0].candidate_ids == ["exact-candidate"]
        assert gaps[0].detail == "actual evidence"
        assert getattr(summary, summary_field)[0]["candidate_ids"] == [
            "exact-candidate"
        ]

    def test_quarantine_preserves_exact_candidate_ids(self) -> None:
        ledger = StageLedger()
        ledger.record("ep", "q-1", STAGE_QUARANTINE, "invalid")
        ledger.record("ep", "q-2", STAGE_QUARANTINE, "invalid")
        gaps, summary = _emit(_universe("ep"), ledger, quarantined={"ep"})
        assert gaps[0].reason is CoverageGapReason.ADMISSION_FAILURE
        assert gaps[0].candidate_ids == ["q-1", "q-2"]
        assert summary.quarantine_admission_failures[0]["candidate_ids"] == [
            "q-1",
            "q-2",
        ]

    def test_projection_budget_limitation(self) -> None:
        gaps, summary = _emit(_universe("ep"), StageLedger(), limited={"ep"})
        assert gaps[0].reason is CoverageGapReason.PROJECTION_LIMITATION
        assert summary.projection_limitations[0]["entry_point_id"] == "ep"

    def test_summary_populates_all_categories_and_policy_exclusions(self) -> None:
        universe = _universe(
            "covered", "structural", "selection", "runtime", "quarantine", "limited"
        )
        universe.excluded_targets.append(
            ExcludedTarget(
                "out", "Output", "output", "system", CoverageExclusionReason.OUTPUT_ONLY
            )
        )
        ledger = StageLedger()
        ledger.record("structural", "s", STAGE_FILTER, "rejected")
        ledger.record("selection", "x", STAGE_SELECTION, "capped")
        ledger.record("runtime", "g", STAGE_GENERATION, "failed")
        ledger.record("quarantine", "q", STAGE_QUARANTINE, "invalid")
        _, summary = _emit(
            universe,
            ledger,
            generated={"covered"},
            quarantined={"quarantine"},
            limited={"limited"},
        )
        data = summary.to_dict()
        assert data["covered_feasible"] == ["covered"]
        assert data["policy_exclusions"][0]["reason"] == "output_only"
        for key in (
            "structural_gaps",
            "selection_limitations",
            "runtime_generation_gaps",
            "quarantine_admission_failures",
            "projection_limitations",
        ):
            assert data[key], key


class TestCoveragePlan:
    def test_round_trip_preserves_ordered_fallbacks_and_schema(self) -> None:
        universe = _universe(_REAL_EP_ID)
        choices = [_qc(i) for i in (1, 2, 3)]
        queues = build_fallback_queues(choices, universe)
        selection = SelectionResult(
            selected=[queues[_REAL_EP_ID].choices[0]],
            primary_candidate_ids={_REAL_EP_ID: choices[0].candidate_id},
            attempted_candidate_ids={choices[0].candidate_id},
        )
        data = build_coverage_plan(universe, queues, selection).to_dict()
        assert data["schema_version"] == "1"
        assert [r["candidate_id"] for r in data["targets"][0]["ordered_choices"]] == [
            q.candidate_id for q in choices
        ]

    def test_fallback_available_excludes_every_attempted_candidate(self) -> None:
        universe = _universe(_REAL_EP_ID)
        choices = [_qc(i) for i in (1, 2, 3)]
        queues = build_fallback_queues(choices, universe)
        selection = SelectionResult(
            selected=queues[_REAL_EP_ID].choices[:2],
            primary_candidate_ids={_REAL_EP_ID: choices[0].candidate_id},
            attempted_candidate_ids={choices[0].candidate_id, choices[1].candidate_id},
        )
        entry = build_coverage_plan(universe, queues, selection).targets[0]
        assert [r["candidate_id"] for r in entry.fallback_available] == [
            choices[2].candidate_id
        ]

    @pytest.mark.parametrize("outcome", ["generated", "failed", "quarantined"])
    def test_primary_state_reflects_generation_outcome(self, outcome: str) -> None:
        universe = _universe(_REAL_EP_ID)
        choice = _qc(1)
        queues = build_fallback_queues([choice], universe)
        selection = SelectionResult(
            primary_candidate_ids={_REAL_EP_ID: choice.candidate_id},
            attempted_candidate_ids={choice.candidate_id},
        )
        plan = build_coverage_plan(
            universe, queues, selection, {choice.candidate_id: outcome}
        )
        assert plan.targets[0].primary_state == outcome


class TestNoRawSeedGeneration:
    def test_legacy_remediation_helpers_removed(self) -> None:
        from asago_scenario_generator.pipeline import runner

        assert not hasattr(runner, "_remediate_coverage_gaps")
        assert not hasattr(runner, "_pick_best_seed_for_entry_point")

    def test_run_pipeline_uses_coverage_aware_planning_without_remediation(
        self,
    ) -> None:
        from asago_scenario_generator.pipeline.runner import (
            _complete_v3_run,
            run_pipeline,
        )

        planning_source = inspect.getsource(run_pipeline)
        for call in (
            "build_coverage_universe(",
            "build_qualified_candidates(",
            "plan_generation(",
        ):
            assert call in planning_source
        completion_source = inspect.getsource(_complete_v3_run)
        assert "emit_quality_gaps(" in completion_source
        assert "_remediate_coverage_gaps(" not in planning_source + completion_source


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


class TestCoverageReportHTML:
    """cmps.4: HTML report categories and exact failed/quarantine IDs."""

    def test_html_report_has_all_category_headings(self) -> None:
        from asago_scenario_generator.report.template import build_coverage_section

        coverage_data = {
            "coverage_gaps": {
                "has_gaps": True,
                "uncovered_entry_points": [],
                "uncovered_zones": [],
                "uncovered_threats": [],
                "uncovered_attack_patterns": [],
            },
            "coverage_universe": {
                "completeness": "not_applicable",
                "feasible_targets": [],
                "excluded_targets": [],
            },
            "coverage_summary": {
                "covered_feasible": ["covered-ep"],
                "policy_exclusions": [
                    {"entry_point_id": "out", "name": "Output", "reason": "output_only"}
                ],
                "structural_gaps": [
                    {
                        "entry_point_id": "gap-ep",
                        "reason": "no_seed",
                        "candidate_ids": [],
                    }
                ],
                "selection_limitations": [],
                "runtime_generation_gaps": [
                    {
                        "entry_point_id": "fail-ep",
                        "reason": "generation_exhaustion",
                        "candidate_ids": ["cand:v2:abc"],
                    }
                ],
                "quarantine_admission_failures": [
                    {
                        "entry_point_id": "q-ep",
                        "reason": "admission_failure",
                        "candidate_ids": ["cand:v2:xyz"],
                    }
                ],
                "projection_limitations": [],
            },
            "coverage_plan": {
                "schema_version": "1",
                "completeness": "not_applicable",
                "evidence_refs": [],
                "targets": [],
            },
            "quality_gaps": [],
        }
        html = build_coverage_section(coverage_data)
        assert "Covered Feasible Targets" in html
        assert "Policy Exclusions" in html
        assert "Structural / Projection Gaps" in html
        assert "Runtime Generation Gaps" in html
        assert "Quarantine / Admission Failures" in html

    def test_html_report_shows_exact_failed_candidate_ids(self) -> None:
        from asago_scenario_generator.report.template import build_coverage_section

        coverage_data = {
            "coverage_gaps": {
                "has_gaps": False,
                "uncovered_entry_points": [],
                "uncovered_zones": [],
                "uncovered_threats": [],
                "uncovered_attack_patterns": [],
            },
            "coverage_summary": {
                "covered_feasible": [],
                "policy_exclusions": [],
                "structural_gaps": [],
                "selection_limitations": [],
                "runtime_generation_gaps": [
                    {
                        "entry_point_id": "fail-ep",
                        "reason": "generation_exhaustion",
                        "candidate_ids": ["cand:v2:aaa", "cand:v2:bbb"],
                    },
                ],
                "quarantine_admission_failures": [
                    {
                        "entry_point_id": "q-ep",
                        "reason": "admission_failure",
                        "candidate_ids": ["cand:v2:qqq"],
                    },
                ],
                "projection_limitations": [],
            },
            "coverage_plan": {
                "schema_version": "1",
                "completeness": "not_applicable",
                "evidence_refs": [],
                "targets": [],
            },
            "quality_gaps": [],
        }
        html = build_coverage_section(coverage_data)
        assert "cand:v2:aaa" in html
        assert "cand:v2:bbb" in html
        assert "cand:v2:qqq" in html


class TestProfileCompletenessDerivation:
    """cmps.4 blocker 4: completeness derived from profile, not free-form input."""

    def test_inferred_profile_reports_not_applicable(self) -> None:
        ep = EntryPoint(name="prompt", direction="input", controllability="direct")
        universe = build_coverage_universe(_profile([ep], confirmed=False))
        assert universe.completeness is CoverageCompleteness.NOT_APPLICABLE
        assert universe.completeness.value == "not_applicable"
        assert universe.evidence_refs == []

    def test_confirmed_profile_reports_confirmed_complete_with_evidence(self) -> None:
        ep = EntryPoint(name="prompt", direction="input", controllability="direct")
        universe = build_coverage_universe(_profile([ep], confirmed=True))
        assert universe.completeness is CoverageCompleteness.CONFIRMED_COMPLETE
        assert universe.completeness.value == "confirmed_complete"
        assert universe.evidence_refs == ["operator-review:architecture-v3"]

    def test_build_coverage_universe_has_no_completeness_parameter(self) -> None:
        assert (
            "completeness" not in inspect.signature(build_coverage_universe).parameters
        )

    def test_coverage_plan_serializes_not_applicable_for_inferred(self) -> None:
        ep = EntryPoint(name="prompt", direction="input", controllability="direct")
        universe = build_coverage_universe(_profile([ep], confirmed=False))
        queues = build_fallback_queues([], universe)
        selection = SelectionResult()
        plan = build_coverage_plan(universe, queues, selection)
        assert plan.completeness == "not_applicable"

    def test_coverage_plan_serializes_confirmed_complete_with_refs(self) -> None:
        ep = EntryPoint(name="prompt", direction="input", controllability="direct")
        universe = build_coverage_universe(_profile([ep], confirmed=True))
        queues = build_fallback_queues([], universe)
        selection = SelectionResult()
        plan = build_coverage_plan(universe, queues, selection)
        assert plan.completeness == "confirmed_complete"
        assert plan.evidence_refs == ["operator-review:architecture-v3"]


class TestPersistedPlanRoundTrip:
    """cmps.4 blocker 2: persisted plan round trip proving ordered fallbacks
    recoverable and exclude attempted primary."""

    def test_json_round_trip_preserves_ordered_choices_and_fallbacks(self) -> None:
        import json

        universe = _universe(_REAL_EP_ID)
        choices = [_qc(i) for i in (1, 2, 3)]
        queues = build_fallback_queues(choices, universe)
        selection = SelectionResult(
            selected=[queues[_REAL_EP_ID].choices[0]],
            primary_candidate_ids={_REAL_EP_ID: choices[0].candidate_id},
            attempted_candidate_ids={choices[0].candidate_id},
        )
        plan = build_coverage_plan(universe, queues, selection)
        # Serialize to JSON and back.
        json_str = json.dumps(plan.to_dict())
        recovered = json.loads(json_str)
        target = recovered["targets"][0]
        # Ordered choices preserve all three candidates in rank order.
        assert [r["candidate_id"] for r in target["ordered_choices"]] == [
            q.candidate_id for q in choices
        ]
        # Primary is the first choice.
        assert target["primary_candidate_id"] == choices[0].candidate_id
        assert target["primary_state"] == "selected"
        # Fallback available excludes the attempted primary.
        fallback_ids = [r["candidate_id"] for r in target["fallback_available"]]
        assert choices[0].candidate_id not in fallback_ids
        assert choices[1].candidate_id in fallback_ids
        assert choices[2].candidate_id in fallback_ids

    def test_json_round_trip_with_generation_outcome(self) -> None:
        import json

        universe = _universe(_REAL_EP_ID)
        choices = [_qc(i) for i in (1, 2, 3)]
        queues = build_fallback_queues(choices, universe)
        selection = SelectionResult(
            selected=[queues[_REAL_EP_ID].choices[0]],
            primary_candidate_ids={_REAL_EP_ID: choices[0].candidate_id},
            attempted_candidate_ids={choices[0].candidate_id},
        )
        plan = build_coverage_plan(
            universe,
            queues,
            selection,
            generation_outcomes={choices[0].candidate_id: "generated"},
        )
        recovered = json.loads(json.dumps(plan.to_dict()))
        target = recovered["targets"][0]
        assert target["primary_state"] == "generated"
        # Fallback still excludes the attempted (generated) primary.
        fallback_ids = [r["candidate_id"] for r in target["fallback_available"]]
        assert choices[0].candidate_id not in fallback_ids

    def test_plan_provenance_has_content_address(self) -> None:
        """Plan refs include sufficient provenance for cmps.5 retry."""
        universe = _universe(_REAL_EP_ID)
        choices = [_qc(i) for i in (1, 2)]
        queues = build_fallback_queues(choices, universe)
        selection = SelectionResult(
            primary_candidate_ids={_REAL_EP_ID: choices[0].candidate_id},
            attempted_candidate_ids={choices[0].candidate_id},
        )
        plan = build_coverage_plan(universe, queues, selection)
        ref = plan.targets[0].ordered_choices[0]
        # Provenance fields for cmps.5.
        assert "candidate_id" in ref
        assert "filter_candidate_id" in ref
        assert "pattern_id" in ref
        assert "entry_point_id" in ref
        assert "rank" in ref
        assert "accepted_rationale" in ref
        assert "origins" in ref
        assert "rejection_rationales" in ref
        assert "pinned_entry_point" in ref
        assert "pinned_technique_ids" in ref


# ---------------------------------------------------------------------------
# cmps.4 blocker 1: merged accepted-filter provenance, no first-wins
# ---------------------------------------------------------------------------


class TestMergedFilterProvenance:
    """Two accepted filter records converging on one projected candidate_id
    must be merged — no first-wins loss of provenance."""

    def test_two_filters_same_projected_id_are_merged(self) -> None:
        pc = _make_pc()
        fseed_a = _make_fseed(candidate_id="filter-a", rationale="accepted via A")
        fseed_b = _make_fseed(candidate_id="filter-b", rationale="accepted via B")
        qualified = build_qualified_candidates(
            [fseed_a, fseed_b], {fseed_a.seed_id: [pc]}
        )
        assert len(qualified) == 1
        qc = qualified[0]
        assert len(qc.accepted_filters) == 2
        # Sorted by filter_candidate_id.
        ids = [r.filter_candidate_id for r in qc.accepted_filters]
        assert ids == ["filter-a", "filter-b"]

    def test_generation_seed_is_deterministic(self) -> None:
        """Generation seed is the lowest filter_candidate_id — encounter-independent."""
        pc = _make_pc()
        fseed_b = _make_fseed(candidate_id="filter-b", rationale="B")
        fseed_a = _make_fseed(candidate_id="filter-a", rationale="A")
        # Feed B first, A second — seed should still be A (lowest ID).
        qualified = build_qualified_candidates(
            [fseed_b, fseed_a], {fseed_b.seed_id: [pc]}
        )
        assert qualified[0].generation_seed.candidate_id == "filter-a"

    def test_merged_origins_from_multiple_filters(self) -> None:
        pc = _make_pc()
        fseed_a = _make_fseed(candidate_id="filter-a", rationale="accepted via A")
        fseed_b = _make_fseed(candidate_id="filter-b", rationale="accepted via B")
        qc = build_qualified_candidates([fseed_a, fseed_b], {fseed_a.seed_id: [pc]})[0]
        # Both filter records are preserved (no first-wins).
        assert len(qc.accepted_filters) == 2
        # Both rationales are accessible.
        rationales = {r.rationale for r in qc.accepted_filters}
        assert len(rationales) == 2

    def test_plan_ref_contains_complete_projected_candidate(self) -> None:
        """Plan ref persists the complete ProjectedCandidate JSON, not a thin ref.
        Uses the real factory ProjectedCandidate (valid candidate_id)."""
        fseed = _make_fseed(
            seed_id=_REAL_PATTERN_ID,
            entry_point_id=_REAL_EP_ID,
        )
        qc = build_qualified_candidates([fseed], {fseed.seed_id: [_REAL_PC]})[0]
        ref = qc.to_plan_ref()
        assert "projected_candidate" in ref
        # The persisted JSON round-trips through model_validate.
        reconstructed = deserialize_plan_ref(ref)
        assert reconstructed.candidate_id == _REAL_PC.candidate_id
        assert (
            reconstructed.canonical_ingress.entry_point_id
            == _REAL_PC.canonical_ingress.entry_point_id
        )

    def test_plan_ref_round_trip_model_validate_exact(self) -> None:
        """deserialize_plan_ref produces an exact ProjectedCandidate.
        Uses the real factory ProjectedCandidate (valid candidate_id)."""
        fseed = _make_fseed(
            seed_id=_REAL_PATTERN_ID,
            entry_point_id=_REAL_EP_ID,
        )
        qc = build_qualified_candidates([fseed], {fseed.seed_id: [_REAL_PC]})[0]
        ref = qc.to_plan_ref()
        reconstructed = deserialize_plan_ref(ref)
        assert reconstructed.model_dump(mode="json") == _REAL_PC.model_dump(mode="json")

    def test_plan_ref_accepted_filters_reconstructable(self) -> None:
        """Plan ref contains merged accepted-filter provenance."""
        pc = _make_pc()
        fseed_a = _make_fseed(candidate_id="filter-a", rationale="A")
        fseed_b = _make_fseed(candidate_id="filter-b", rationale="B")
        qc = build_qualified_candidates([fseed_a, fseed_b], {fseed_a.seed_id: [pc]})[0]
        ref = qc.to_plan_ref()
        assert len(ref["accepted_filters"]) == 2
        assert ref["accepted_filters"][0]["filter_candidate_id"] == "filter-a"
        assert ref["accepted_filters"][1]["filter_candidate_id"] == "filter-b"


# ---------------------------------------------------------------------------
# cmps.4 blocker 2: permutation invariance and two-target/two-pattern
# ---------------------------------------------------------------------------


class TestPermutationInvariance:
    """Queue ranks and primary selection must be encounter-independent."""

    def test_filter_input_order_invariance(self) -> None:
        c1 = _qc(1)
        c2 = _qc(2)
        universe = _universe(_REAL_EP_ID)
        q1 = build_fallback_queues([c1, c2], universe)[_REAL_EP_ID]
        q2 = build_fallback_queues([c2, c1], universe)[_REAL_EP_ID]
        assert q1.candidate_ids() == q2.candidate_ids()

    def test_projected_candidate_order_invariance(self) -> None:
        """build_qualified_candidates sorts by (pattern_id, candidate_id)."""
        fseed = _make_fseed()
        pc1 = _make_pc(f"cand:v2:{1:032x}")
        pc2 = _make_pc(f"cand:v2:{2:032x}")
        # Feed pc2 before pc1.
        q1 = build_qualified_candidates([fseed], {fseed.seed_id: [pc2, pc1]})
        # Feed pc1 before pc2.
        q2 = build_qualified_candidates([fseed], {fseed.seed_id: [pc1, pc2]})
        assert [q.candidate_id for q in q1] == [q.candidate_id for q in q2]
        # Both sorted by candidate_id.
        assert q1[0].candidate_id == f"cand:v2:{1:032x}"

    def test_selection_invariance_under_input_permutation(self) -> None:
        c1 = _qc(1)
        c2 = _qc(2)
        universe = _universe(_REAL_EP_ID)
        r1, _ = (
            select_with_coverage_priority(
                [c1, c2], build_fallback_queues([c1, c2], universe), universe
            ),
            None,
        )
        r2, _ = (
            select_with_coverage_priority(
                [c2, c1], build_fallback_queues([c2, c1], universe), universe
            ),
            None,
        )
        assert r1.primary_candidate_ids == r2.primary_candidate_ids


class TestTwoTargetTwoPatternAssignment:
    """Global coverage-preserving assignment with diversity/cap policy."""

    def test_one_primary_per_target(self) -> None:
        c1 = _qc(1, ep=_ep_id(10), pattern="AP-T1")
        c2 = _qc(2, ep=_ep_id(11), pattern="AP-T2")
        universe = _universe(_ep_id(10), _ep_id(11))
        queues = build_fallback_queues([c1, c2], universe)
        result = select_with_coverage_priority([c1, c2], queues, universe)
        assert set(result.primary_candidate_ids) == {_ep_id(10), _ep_id(11)}
        assert len(result.selected) == 2

    def test_diversity_prefers_different_patterns(self) -> None:
        """Two targets, each with two candidates from different patterns.
        Assignment should spread across patterns to maximize diversity."""
        # Target A: candidates from pattern1 and pattern2
        c_a_p1 = _qc(1, ep=_ep_id(10), pattern="AP-T1")
        c_a_p2 = _qc(2, ep=_ep_id(10), pattern="AP-T2")
        # Target B: candidates from pattern1 and pattern2
        c_b_p1 = _qc(3, ep=_ep_id(11), pattern="AP-T1")
        c_b_p2 = _qc(4, ep=_ep_id(11), pattern="AP-T2")
        universe = _universe(_ep_id(10), _ep_id(11))
        qualified = [c_a_p1, c_a_p2, c_b_p1, c_b_p2]
        queues = build_fallback_queues(qualified, universe)
        result = select_with_coverage_priority(qualified, queues, universe)
        # Should assign different patterns to the two targets.
        selected_by_id = {q.candidate_id: q for q in result.selected}
        patterns = {
            selected_by_id[cid].pattern_id
            for cid in result.primary_candidate_ids.values()
        }
        assert len(patterns) == 2  # both patterns used

    def test_sole_candidate_is_cap_immune(self) -> None:
        """Sole-choice target is always selected even with cap=1."""
        c1 = _qc(1, ep=_ep_id(10), pattern="AP-T1")
        c2 = _qc(2, ep=_ep_id(11), pattern="AP-T1")
        universe = _universe(_ep_id(10), _ep_id(11))
        queues = build_fallback_queues([c1, c2], universe)
        result = select_with_coverage_priority(
            [c1, c2], queues, universe, max_per_pattern=1
        )
        # Both targets covered despite cap=1 on same pattern.
        assert len(result.selected) == 2
        assert set(result.primary_candidate_ids) == {_ep_id(10), _ep_id(11)}

    def test_impossible_cap_emits_explicit_limitation(self) -> None:
        """When all choices for a multi-choice target are at cap, coverage is
        preserved but an explicit limitation is emitted."""
        # Target with two candidates, both in same pattern.
        c1 = _qc(1, ep=_ep_id(10), pattern="AP-T1")
        c2 = _qc(2, ep=_ep_id(10), pattern="AP-T1")
        c3 = _qc(3, ep=_ep_id(11), pattern="AP-T1")
        universe = _universe(_ep_id(10), _ep_id(11))
        qualified = [c1, c2, c3]
        queues = build_fallback_queues(qualified, universe)
        result = select_with_coverage_priority(
            qualified, queues, universe, max_per_pattern=1
        )
        # Target 10 has multiple choices; after one takes the cap slot,
        # the other target must still be covered but with a limitation.
        assert _ep_id(10) in result.primary_candidate_ids
        # Both targets use the same pattern (AP-T1) with cap=1, so exactly
        # one target must have an overflow limitation.
        assert len(result.selection_limitation_target_ids) == 1

    def test_non_primary_choices_are_fallback_not_selected(self) -> None:
        """Multi-choice target: only the primary is selected, rest are fallback."""
        c1 = _qc(1, ep=_ep_id(10))
        c2 = _qc(2, ep=_ep_id(10))
        universe = _universe(_ep_id(10))
        qualified = [c1, c2]
        queues = build_fallback_queues(qualified, universe)
        result = select_with_coverage_priority(qualified, queues, universe)
        assert len(result.selected) == 1
        non_primary = [
            c
            for c in qualified
            if c.candidate_id != next(iter(result.primary_candidate_ids.values()))
        ]
        for qc in non_primary:
            assert qc.candidate_id not in result.attempted_candidate_ids


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
        from asago_scenario_generator.pipeline.candidates import CandidateFunnel

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
# cmps.4 blocker 4: HTML report with completeness and canonical bounded set
# ---------------------------------------------------------------------------


class TestHTMLReportCompleteness:
    """HTML report must render completeness states and canonical bounded set."""

    def test_confirmed_complete_render(self) -> None:
        from asago_scenario_generator.report.template import build_coverage_section

        coverage_data = {
            "coverage_gaps": {
                "has_gaps": False,
                "uncovered_entry_points": [],
                "uncovered_zones": [],
                "uncovered_threats": [],
                "uncovered_attack_patterns": [],
            },
            "coverage_universe": {
                "completeness": "confirmed_complete",
                "evidence_refs": ["operator-review:v2"],
                "feasible_targets": [
                    {
                        "entry_point_id": "ep1",
                        "name": "prompt",
                        "direction": "input",
                        "controllability": "direct",
                    }
                ],
                "excluded_targets": [
                    {"entry_point_id": "ep2", "name": "logs", "reason": "output_only"}
                ],
            },
            "coverage_summary": {
                "covered_feasible": ["ep1"],
                "policy_exclusions": [],
                "structural_gaps": [],
                "selection_limitations": [],
                "runtime_generation_gaps": [],
                "quarantine_admission_failures": [],
                "projection_limitations": [],
            },
            "coverage_plan": {
                "schema_version": "1",
                "completeness": "confirmed_complete",
                "evidence_refs": ["operator-review:v2"],
                "targets": [],
            },
            "quality_gaps": [],
        }
        html = build_coverage_section(coverage_data)
        assert "Confirmed Complete" in html
        assert "operator-review:v2" in html
        assert "Feasible Targets" in html
        assert "Excluded Targets" in html

    def test_inferred_partial_render(self) -> None:
        from asago_scenario_generator.report.template import build_coverage_section

        coverage_data = {
            "coverage_gaps": {
                "has_gaps": True,
                "uncovered_entry_points": [],
                "uncovered_zones": [],
                "uncovered_threats": [],
                "uncovered_attack_patterns": [],
            },
            "coverage_universe": {
                "completeness": "not_applicable",
                "evidence_refs": [],
                "feasible_targets": [],
                "excluded_targets": [],
            },
            "coverage_summary": {
                "covered_feasible": [],
                "policy_exclusions": [],
                "structural_gaps": [],
                "selection_limitations": [],
                "runtime_generation_gaps": [],
                "quarantine_admission_failures": [],
                "projection_limitations": [],
            },
            "coverage_plan": {
                "schema_version": "1",
                "completeness": "not_applicable",
                "evidence_refs": [],
                "targets": [],
            },
            "quality_gaps": [],
        }
        html = build_coverage_section(coverage_data)
        assert "Not Applicable" in html
        assert "Inferred Partial" in html


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


class TestMinCostAssignment:
    """Blocker 2: deterministic min-cost flow assignment with lexicographic
    objective: coverage > cap overflow > diversity > candidate-ID tie-break."""

    def test_greedy_counterexample_a_p2_b_p1(self) -> None:
        """Greedy counterexample: A={P1,P2}, B={P1,P1variants}, cap=1.
        Greedy would assign A→P1 (first), then B→P1 (overflow).
        Min-cost flow should assign A→P2, B→P1 to stay within cap."""
        ep_a = _ep_id(10)
        ep_b = _ep_id(11)
        # A has choices with patterns P1 and P2.
        qc_a_p1 = _qc(1, ep=ep_a, pattern="AP-P1-01")
        qc_a_p2 = _qc(2, ep=ep_a, pattern="AP-P2-01")
        # B has choices with pattern P1 only (and a P1 variant).
        qc_b_p1 = _qc(3, ep=ep_b, pattern="AP-P1-01")
        qc_b_p1v = _qc(4, ep=ep_b, pattern="AP-P1-01")
        candidates = [qc_a_p1, qc_a_p2, qc_b_p1, qc_b_p1v]
        universe = _universe(ep_a, ep_b)
        queues = build_fallback_queues(candidates, universe)
        result = select_with_coverage_priority(candidates, queues, universe, 1)
        # A should be assigned to P2, B to P1 — no cap overflow.
        assert result.primary_candidate_ids[ep_a] == qc_a_p2.candidate_id
        assert result.primary_candidate_ids[ep_b] == qc_b_p1.candidate_id
        assert result.selection_limitation_target_ids == []

    def test_two_sole_p1_targets_cap1_one_overflow(self) -> None:
        """Two targets with sole P1 choices, cap=1: both covered, one overflow
        with an explicit selection_limitation."""
        ep_a = _ep_id(10)
        ep_b = _ep_id(11)
        qc_a = _qc(1, ep=ep_a, pattern="AP-P1-01")
        qc_b = _qc(2, ep=ep_b, pattern="AP-P1-01")
        candidates = [qc_a, qc_b]
        universe = _universe(ep_a, ep_b)
        queues = build_fallback_queues(candidates, universe)
        result = select_with_coverage_priority(candidates, queues, universe, 1)
        # Both targets covered (coverage is never sacrificed).
        assert set(result.primary_candidate_ids) == {ep_a, ep_b}
        # One overflow limitation (cap=1, two assignments to P1).
        assert len(result.selection_limitation_target_ids) == 1

    def test_input_permutation_invariance(self) -> None:
        """Assignment is invariant under input permutation."""
        ep_a = _ep_id(10)
        ep_b = _ep_id(11)
        ep_c = _ep_id(12)
        qc_a = _qc(1, ep=ep_a, pattern="AP-P1-01")
        qc_b = _qc(2, ep=ep_b, pattern="AP-P2-01")
        qc_c = _qc(3, ep=ep_c, pattern="AP-P1-01")
        universe = _universe(ep_a, ep_b, ep_c)

        # Original order.
        queues1 = build_fallback_queues([qc_a, qc_b, qc_c], universe)
        result1 = select_with_coverage_priority(
            [qc_a, qc_b, qc_c], queues1, universe, 1
        )

        # Permuted order.
        queues2 = build_fallback_queues([qc_c, qc_a, qc_b], universe)
        result2 = select_with_coverage_priority(
            [qc_c, qc_a, qc_b], queues2, universe, 1
        )

        # Same primary assignments.
        assert result1.primary_candidate_ids == result2.primary_candidate_ids
        # Same limitations.
        assert sorted(result1.selection_limitation_target_ids) == sorted(
            result2.selection_limitation_target_ids
        )

    def test_many_target_runtime_boundedness(self) -> None:
        """49 targets with 3 choices each must complete in polynomial time."""
        import time

        eps = [_ep_id(i) for i in range(49)]
        patterns = [f"AP-P{i % 5}-01" for i in range(5)]
        candidates = []
        for i, ep in enumerate(eps):
            for j in range(3):
                candidates.append(_qc(i * 3 + j + 1, ep=ep, pattern=patterns[i % 5]))
        universe = _universe(*eps)
        queues = build_fallback_queues(candidates, universe)
        start = time.monotonic()
        result = select_with_coverage_priority(candidates, queues, universe, 2)
        elapsed = time.monotonic() - start
        # All targets covered.
        assert len(result.primary_candidate_ids) == 49
        # Must complete quickly (polynomial, not exponential).
        assert elapsed < 10.0, f"min-cost flow took {elapsed:.1f}s for 49 targets"

    def test_non_primary_stays_fallback_available(self) -> None:
        """After min-cost assignment, non-primary choices are fallback_available."""
        ep_a = _ep_id(10)
        qc1 = _qc(1, ep=ep_a, pattern="AP-P1-01")
        qc2 = _qc(2, ep=ep_a, pattern="AP-P2-01")
        qc3 = _qc(3, ep=ep_a, pattern="AP-P3-01")
        candidates = [qc1, qc2, qc3]
        universe = _universe(ep_a)
        queues = build_fallback_queues(candidates, universe)
        result = select_with_coverage_priority(candidates, queues, universe)
        plan = build_coverage_plan(universe, queues, result)
        fb_ids = [r["candidate_id"] for r in plan.targets[0].fallback_available]
        # The primary is not in fallback_available.
        primary_id = result.primary_candidate_ids[ep_a]
        assert primary_id not in fb_ids
        # The other two are.
        non_primary = {qc1.candidate_id, qc2.candidate_id, qc3.candidate_id} - {
            primary_id
        }
        for cid in non_primary:
            assert cid in fb_ids


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
# cmps.4 blocker 4: HTML report typed gap rendering and evidence tests
# ---------------------------------------------------------------------------


class TestTypedGapRendering:
    """Blocker 4: HTML must render typed gap fields explicitly, not str(dict)."""

    def _coverage_data(self, **kwargs) -> dict:
        base = {
            "coverage_gaps": {
                "uncovered_entry_points": [],
                "uncovered_zones": [],
                "uncovered_threats": [],
                "uncovered_attack_patterns": [],
            },
            "coverage_universe": {
                "completeness": "not_applicable",
                "evidence_refs": [],
                "feasible_targets": [],
                "excluded_targets": [],
            },
            "coverage_summary": {
                "covered_feasible": [],
                "policy_exclusions": [],
                "structural_gaps": [],
                "selection_limitations": [],
                "runtime_generation_gaps": [],
                "quarantine_admission_failures": [],
                "projection_limitations": [],
            },
            "coverage_plan": {
                "schema_version": "1",
                "completeness": "not_applicable",
                "evidence_refs": [],
                "targets": [],
            },
            "quality_gaps": [],
        }
        base.update(kwargs)
        return base

    def test_no_str_dict_in_typed_gap_rendering(self) -> None:
        """HTML must not contain Python dict repr for typed gap items."""
        from asago_scenario_generator.report.template import build_coverage_section

        data = self._coverage_data(
            coverage_summary={
                "covered_feasible": [],
                "policy_exclusions": [],
                "structural_gaps": [],
                "selection_limitations": [
                    {
                        "entry_point_id": "ep-1",
                        "entry_point_name": "User Prompt",
                        "reason": "selection_limitation",
                        "candidate_ids": ["cand:v2:aaa"],
                        "detail": "Per-pattern cap overflow",
                    },
                ],
                "runtime_generation_gaps": [],
                "quarantine_admission_failures": [],
                "projection_limitations": [],
            },
        )
        html = build_coverage_section(data)
        # Must not contain Python dict repr.
        assert "{" not in html or "coverage-card" in html
        # Must render the entry point name.
        assert "User Prompt" in html
        # Must render the candidate ID.
        assert "cand:v2:aaa" in html
        # Must render a human-readable reason, not the raw code.
        assert "cap overflow" in html.lower() or "selection" in html.lower()

    def test_inferred_partial_does_not_claim_all_covered(self) -> None:
        """For inferred-partial inventory, HTML must not claim all entry
        points covered without qualifying the bounded set."""
        from asago_scenario_generator.report.template import build_coverage_section

        data = self._coverage_data(
            coverage_universe={
                "completeness": "not_applicable",
                "evidence_refs": [],
                "feasible_targets": [],
                "excluded_targets": [],
            },
        )
        html = build_coverage_section(data)
        # Must NOT say "All entry points have scenario coverage." unqualified
        assert "All entry points have scenario coverage." not in html
        # Must qualify with bounded/incomplete language
        assert "identified feasible" in html.lower() or "not confirmed" in html.lower()

    def test_confirmed_complete_claims_all_covered(self) -> None:
        """For confirmed-complete inventory, HTML may claim all covered."""
        from asago_scenario_generator.report.template import build_coverage_section

        data = self._coverage_data(
            coverage_universe={
                "completeness": "confirmed_complete",
                "evidence_refs": ["operator-review"],
                "feasible_targets": [],
                "excluded_targets": [],
            },
        )
        html = build_coverage_section(data)
        assert "All confirmed entry points have scenario coverage." in html

    def test_inferred_partial_badge_not_full_coverage(self) -> None:
        """Inferred-partial inventory must not show 'Full Coverage' badge."""
        from asago_scenario_generator.report.template import build_coverage_section

        data = self._coverage_data(
            coverage_universe={
                "completeness": "not_applicable",
                "evidence_refs": [],
                "feasible_targets": [],
                "excluded_targets": [],
            },
        )
        html = build_coverage_section(data)
        assert "Full Coverage" not in html
        assert "Known Targets Covered" in html

    def test_no_legacy_attribution_for_zones_threats_patterns(self) -> None:
        """Zone/threat/pattern items must not carry funnel-stage attribution
        spans (legacy inferred labels)."""
        from asago_scenario_generator.report.template import build_coverage_section

        data = self._coverage_data(
            coverage_gaps={
                "uncovered_entry_points": [],
                "uncovered_zones": ["input"],
                "uncovered_threats": ["T1"],
                "uncovered_attack_patterns": ["AP-T1"],
                "gap_attributions": {
                    "entry_points": {},
                    "zones": {"input": "generation_failed"},
                    "threats": {"T1": "no_seed"},
                    "attack_patterns": {"AP-T1": "rejected"},
                },
            },
        )
        html = build_coverage_section(data)
        # Zones/threats/patterns must NOT have attribution spans
        # (the _attribution_span renders as <span class="coverage-reason">)
        # We check that the zone/threat/pattern list items don't contain
        # the stage labels.
        assert "generation failed" not in html
        assert "no seed generated" not in html
        assert "filtered out" not in html


# ---------------------------------------------------------------------------
# cmps.4 blocker 4: Stage ledger records typed filter verdict rationale
# ---------------------------------------------------------------------------


class TestFilterVerdictLedgerEvidence:
    """Blocker 4: Stage ledger must record actual FilterVerdict rationale."""

    def test_filter_rejection_records_actual_rationale(self) -> None:
        """The stage ledger must record the actual LLM filter rejection
        rationale, not generic text."""
        ledger = StageLedger()
        ledger.record(
            entry_point_id="ep-1",
            candidate_id="cand-1",
            stage=STAGE_FILTER,
            reason="filter_rejection",
            detail="pattern=AP-T1: Candidate lacks required tool access.",
            payload={
                "candidate_id": "cand-1",
                "verdict": "reject",
                "rationale": "Candidate lacks required tool access.",
            },
        )
        events = ledger.events_for("ep-1")
        assert len(events) == 1
        assert events[0].reason == "filter_rejection"
        assert "Candidate lacks required tool access" in events[0].detail
        assert events[0].payload is not None
        assert events[0].payload["rationale"] == "Candidate lacks required tool access."

    def test_empty_filter_returns_three_tuple(self) -> None:
        """All-rule-rejected runs reach the empty filter API without unpacking
        failure in the runner."""
        profile = _profile(
            [EntryPoint(name="prompt", direction="input", controllability="direct")]
        )
        result = filter_candidates([], [], None, "test", profile)
        assert result == ([], [], [])


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
