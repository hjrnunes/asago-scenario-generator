"""Direct branch tests for the decomposed coverage-planning helpers.

The decomposition split the over-complex coverage-planning functions
(``_solve_min_cost_assignment``, ``select_with_coverage_priority``,
``build_coverage_plan``, ``plan_generation``, ``emit_quality_gaps``,
``deserialize_qualified_candidate``, ``revalidate_qualified_candidate``,
``QualifiedCandidate.to_plan_ref``, ``build_coverage_universe``) into
single-purpose helpers.  Every helper below gets unit tests covering each
branch; the public-API behaviour is covered by
``test_cmps4_coverage_planning.py``.
"""

from __future__ import annotations

from collections import deque

import pytest

from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    ConfidenceLevel,
    EntryPoint,
    InventoryCompleteness,
)
from asago_scenario_generator.models.scenario import RiskCardRef
from asago_scenario_generator.pipeline.candidate_models import (
    CandidateOrigin,
    FilteredSeed,
    RejectionRecord,
)
from asago_scenario_generator.pipeline.coverage_planning import (
    STAGE_FILTER,
    STAGE_GENERATION,
    STAGE_QUARANTINE,
    AcceptedFilterRecord,
    CoverageCompleteness,
    CoverageExclusionReason,
    CoverageTarget,
    CoverageUniverse,
    ExcludedTarget,
    QualifiedCandidate,
    SelectionResult,
    StageLedger,
    TargetFallbackQueue,
    _best_candidate_per_target_pattern,
    _build_primary_selection,
    _cap_limited_target_ids,
    _categorize_furthest_gap,
    _collect_pattern_index,
    _convex_pattern_cost,
    _derive_selection_limitations,
    _deserialize_filter_records,
    _exclusion_from_entry,
    _exhaustive_target_entries,
    _expected_authoritative_pin,
    _find_trusted_record,
    _first_filter_summary,
    _flowing_pattern_edge,
    _furthest_stage_gap,
    _merge_deduped,
    _no_candidate_selection,
    _no_evidence_gap,
    _normalize_gap_sets,
    _plan_entry_for_target,
    _policy_exclusion_dicts,
    _projection_limitation_gap,
    _quarantine_gap,
    _record_ledger_gap,
    _round_robin_within_pattern,
    _spfa_shortest_path,
    _target_choice_lists,
    _target_from_entry,
    _uncovered_exhaustive_entries,
    _uncovered_target_ids,
    _universe_completeness,
    _verify_canonical_filter_ids,
    _verify_outer_identity,
    _verify_seed_ingress_agreement,
)
from asago_scenario_generator.pipeline.projection_contracts import ProjectedCandidate
from tests.helpers.projection_factory import get_projected_candidate

_REAL_PC = get_projected_candidate()
_REAL_EP_ID = _REAL_PC.canonical_ingress.entry_point_id
_REAL_PATTERN_ID = _REAL_PC.pattern_id


def _risk() -> RiskCardRef:
    return RiskCardRef(
        risk_id="risk-1",
        risk_name="Test risk",
        risk_description="Test risk description.",
        taxonomy="ibm-risk-atlas",
        confidence=0.9,
        grounding_confidence="high",
    )


def _fseed(
    *,
    candidate_id: str = "filter-candidate-1",
    origins: list[CandidateOrigin] | None = None,
    rejections: list[RejectionRecord] | None = None,
    pinned_entry_point: str = "user prompt",
    entry_point_id: str = _REAL_EP_ID,
) -> FilteredSeed:
    return FilteredSeed(
        seed_id=_REAL_PATTERN_ID,
        threat_id="T1",
        threat_name="Test threat",
        attack_pattern_name="Test pattern",
        attack_pattern_description="Test attack pattern description.",
        risk_card_ref=_risk(),
        owasp_llm_ids=["LLM01"],
        agentic_threat_ids=["T1"],
        pinned_entry_point=pinned_entry_point,
        pinned_technique_ids=("AML.T0051",),
        pinned_technique_names=("Technique 1",),
        entry_point_id=entry_point_id,
        candidate_id=candidate_id,
        origins=origins or [],
        rejection_rationales=rejections or [],
    )


def _origin(source_candidate_id: str = "src-1") -> CandidateOrigin:
    return CandidateOrigin(
        source_candidate_id=source_candidate_id,
        original_technique_ids=("AML.T0051",),
        transform_stage="expansion",
    )


def _rejection(candidate_id: str = "rejected-1") -> RejectionRecord:
    return RejectionRecord(
        candidate_id=candidate_id,
        entry_point="user prompt",
        atlas_technique_ids=("AML.T0051",),
        rationale="rejected by rules",
    )


def _record(
    candidate_id: str,
    *,
    origins: list[CandidateOrigin] | None = None,
    rejections: list[RejectionRecord] | None = None,
    pinned_entry_point: str = "user prompt",
) -> AcceptedFilterRecord:
    return AcceptedFilterRecord.from_seed(
        _fseed(
            candidate_id=candidate_id,
            origins=origins,
            rejections=rejections,
            pinned_entry_point=pinned_entry_point,
        )
    )


def _pc(
    candidate_id: str = "cand:v2:00000000000000000000000000000001",
    pattern_id: str = _REAL_PATTERN_ID,
) -> ProjectedCandidate:
    return _REAL_PC.model_copy(
        update={
            "candidate_id": candidate_id,
            "pattern_id": pattern_id,
            "canonical_ingress": _REAL_PC.canonical_ingress,
        }
    )


def _qc(number: int, pattern: str = _REAL_PATTERN_ID) -> QualifiedCandidate:
    cid = f"cand:v2:{number:032x}"
    return QualifiedCandidate(
        projected=_pc(cid, pattern_id=pattern),
        accepted_filters=(_record(f"filter-{number}"),),
    )


def _target(ep_id: str = "ep:v1:00000000000000000000000000000001") -> CoverageTarget:
    return CoverageTarget(ep_id, f"Target {ep_id}", "input", "direct")


# ---------------------------------------------------------------------------
# to_plan_ref helpers
# ---------------------------------------------------------------------------


class TestMergeDeduped:
    def test_merges_distinct_items_across_records(self) -> None:
        records = (
            _record("filter-a", origins=[_origin("src-1")]),
            _record("filter-b", origins=[_origin("src-2")]),
        )
        merged = _merge_deduped(records, lambda r: r.origins)
        assert [o.source_candidate_id for o in merged] == ["src-1", "src-2"]

    def test_deduplicates_identical_items(self) -> None:
        records = (
            _record("filter-a", origins=[_origin("src-1")]),
            _record("filter-b", origins=[_origin("src-1")]),
        )
        merged = _merge_deduped(records, lambda r: r.origins)
        assert [o.source_candidate_id for o in merged] == ["src-1"]

    def test_merges_rejection_rationales(self) -> None:
        records = (
            _record("filter-a", rejections=[_rejection("r-1")]),
            _record("filter-b", rejections=[_rejection("r-2")]),
        )
        merged = _merge_deduped(records, lambda r: r.rejection_rationales)
        assert [r.candidate_id for r in merged] == ["r-1", "r-2"]

    def test_empty_input(self) -> None:
        assert _merge_deduped((), lambda r: r.origins) == []


class TestFirstFilterSummary:
    def test_empty_records_defaults_pins(self) -> None:
        assert _first_filter_summary(()) == {
            "pinned_entry_point": "",
            "pinned_technique_ids": [],
            "pinned_technique_names": [],
        }

    def test_summarizes_first_record(self) -> None:
        first = _record("filter-a", pinned_entry_point="user prompt")
        second = _record("filter-b", pinned_entry_point="other prompt")
        summary = _first_filter_summary((first, second))
        assert summary["pinned_entry_point"] == "user prompt"
        assert summary["pinned_technique_ids"] == ["AML.T0051"]


# ---------------------------------------------------------------------------
# Coverage universe helpers
# ---------------------------------------------------------------------------


class TestUniverseEntryHelpers:
    def test_target_from_entry(self) -> None:
        ep = EntryPoint(name="prompt", direction="input", controllability="direct")
        target = _target_from_entry(ep)
        assert target.entry_point_id == ep.entry_point_id
        assert (target.direction, target.controllability) == ("input", "direct")

    def test_exclusion_from_entry(self) -> None:
        ep = EntryPoint(name="logs", direction="output")
        excluded = _exclusion_from_entry(ep, CoverageExclusionReason.OUTPUT_ONLY)
        assert excluded.reason is CoverageExclusionReason.OUTPUT_ONLY
        assert excluded.name == "logs"

    def test_universe_completeness_inferred(self) -> None:
        profile = CapabilityProfile(
            zones_active=["input"],
            entry_points=[EntryPoint(name="prompt", direction="input", controllability="direct")],
            confidence=ConfidenceLevel.medium,
            kc_subcodes=["KC1.1"],
            entry_point_completeness=InventoryCompleteness.inferred_partial,
        )
        completeness, evidence = _universe_completeness(profile)
        assert completeness is CoverageCompleteness.NOT_APPLICABLE
        assert evidence == []

    def test_universe_completeness_confirmed_filters_blank_evidence(self) -> None:
        profile = CapabilityProfile(
            zones_active=["input"],
            entry_points=[EntryPoint(name="prompt", direction="input", controllability="direct")],
            confidence=ConfidenceLevel.medium,
            kc_subcodes=["KC1.1"],
            entry_point_completeness=InventoryCompleteness.operator_confirmed_complete,
            entry_point_evidence=["operator-review:v2", "  ", ""],
        )
        completeness, evidence = _universe_completeness(profile)
        assert completeness is CoverageCompleteness.CONFIRMED_COMPLETE
        assert evidence == ["operator-review:v2"]


# ---------------------------------------------------------------------------
# Min-cost flow solver helpers
# ---------------------------------------------------------------------------


class TestMinCostFlowHelpers:
    def _choices_map(self) -> dict[str, list[QualifiedCandidate]]:
        return {
            "ep-a": [_qc(1, pattern="AP-1"), _qc(2, pattern="AP-2")],
            "ep-b": [_qc(3, pattern="AP-1")],
        }

    def test_collect_pattern_index_sorted(self) -> None:
        all_patterns, pattern_idx = _collect_pattern_index(self._choices_map())
        assert all_patterns == ["AP-1", "AP-2"]
        assert pattern_idx == {"AP-1": 0, "AP-2": 1}

    def test_best_candidate_per_target_pattern_keeps_lowest_candidate_id(self) -> None:
        lower = _qc(1, pattern="AP-1")
        higher = _qc(5, pattern="AP-1")
        best = _best_candidate_per_target_pattern(
            ["ep-a"], {"ep-a": [higher, lower]}
        )
        assert best[("ep-a", "AP-1")].candidate_id == lower.candidate_id

    @pytest.mark.parametrize(
        ("k", "cap", "scale", "penalty", "expected"),
        [
            (0, 1, 5, 9, 0),  # first unit: no cap overflow
            (1, 1, 5, 9, 50),  # at cap: concentration + overflow penalty
            (2, 1, 5, 9, 55),  # over cap: k*scale + penalty*scale
            (3, None, 5, 9, 15),  # no cap: never penalized
        ],
    )
    def test_convex_pattern_cost(
        self, k: int, cap: int | None, scale: int, penalty: int, expected: int
    ) -> None:
        assert _convex_pattern_cost(k, cap, scale, penalty) == expected

    def test_add_edge_and_flowing_pattern_edge(self) -> None:
        from asago_scenario_generator.pipeline.coverage_planning import add_edge

        graph: list[list[list[int]]] = [[], [], []]
        add_edge(graph, 0, 1, 1, 3)
        assert graph[0][0][:3] == [1, 1, 3]
        assert graph[1][0][:3] == [0, 0, -3]
        # N=1, M=1: pattern node is 1+N=2.  The target's forward edge
        # (node 1 -> node 2) is at graph[1][1].
        add_edge(graph, 1, 2, 1, 0)
        pattern_edge = graph[1][1]
        assert _flowing_pattern_edge(pattern_edge, 1, 1) is False  # cap still 1
        pattern_edge[1] = 0  # flow consumed
        assert _flowing_pattern_edge(pattern_edge, 1, 1) is True
        # With N=2 the pattern range starts at 3: node 2 is out of range.
        assert _flowing_pattern_edge(pattern_edge, 2, 1) is False

    def test_spfa_shortest_path_finds_parents(self) -> None:
        from asago_scenario_generator.pipeline.coverage_planning import add_edge

        graph: list[list[list[int]]] = [[], [], []]
        add_edge(graph, 0, 1, 1, 2)
        add_edge(graph, 1, 2, 1, 0)
        parents, edges = _spfa_shortest_path(graph, 0, 2, 3)
        assert parents is not None
        assert parents[2] == 1
        # The forward edge 1->2 is the second edge in graph[1].
        assert edges[2] == 1

    def test_spfa_shortest_path_returns_none_when_sink_unreachable(self) -> None:
        graph: list[list[list[int]]] = [[], [], []]
        # No edges at all: sink unreachable.
        assert _spfa_shortest_path(graph, 0, 2, 3) is None

    def test_spfa_handles_relaxation_queue(self) -> None:
        """The in-queue guard is exercised by a graph where the same node is
        relaxed more than once (negative-cost reverse edges)."""
        from asago_scenario_generator.pipeline.coverage_planning import add_edge

        graph: list[list[list[int]]] = [[], [], []]
        add_edge(graph, 0, 1, 1, 5)
        add_edge(graph, 1, 0, 0, -5)
        add_edge(graph, 1, 2, 1, 1)
        add_edge(graph, 2, 1, 0, -1)
        parents, _ = _spfa_shortest_path(graph, 0, 2, 3)
        assert parents is not None
        assert parents[2] == 1


class TestExtractAssignment:
    def test_extract_assignment_picks_flowing_pattern_edges(self) -> None:
        from asago_scenario_generator.pipeline.coverage_planning import (
            _extract_assignment,
            add_edge,
        )

        target_ids = ["ep-a"]
        all_patterns = ["AP-1"]
        best = {("ep-a", "AP-1"): _qc(1, pattern="AP-1")}
        graph: list[list[list[int]]] = [[], [], []]
        add_edge(graph, 0, 1, 1, 0)  # source -> target
        add_edge(graph, 1, 2, 1, 0)  # target -> pattern (node 2)
        graph[1][1][1] = 0  # flow consumed -> flowing edge

        assignment = _extract_assignment(graph, 1, 1, target_ids, all_patterns, best)
        assert assignment["ep-a"].pattern_id == "AP-1"

    def test_extract_assignment_skips_nonflowing_edges(self) -> None:
        from asago_scenario_generator.pipeline.coverage_planning import (
            _extract_assignment,
            add_edge,
        )

        target_ids = ["ep-a"]
        best = {("ep-a", "AP-1"): _qc(1, pattern="AP-1")}
        graph: list[list[list[int]]] = [[], [], []]
        add_edge(graph, 0, 1, 1, 0)
        add_edge(graph, 1, 2, 1, 0)  # still full capacity -> no flow

        assignment = _extract_assignment(graph, 1, 1, target_ids, ["AP-1"], best)
        assert assignment == {}

    def test_augment_path_updates_capacities(self) -> None:
        from asago_scenario_generator.pipeline.coverage_planning import (
            _augment_path,
            add_edge,
        )

        graph: list[list[list[int]]] = [[], [], []]
        add_edge(graph, 0, 1, 1, 0)
        add_edge(graph, 1, 2, 1, 0)
        _augment_path(graph, 0, 2, [0, 0, 1], [0, 0, 0])
        assert graph[0][0][1] == 0  # forward capacity consumed
        assert graph[1][0][1] == 0
        assert graph[2][0][1] == 1  # reverse capacity restored


class TestSolverUnreachableSink:
    def test_solver_breaks_cleanly_when_sink_unreachable(self) -> None:
        """A target whose pattern edges were never added yields no assignment
        instead of hanging — the SPFA None path is exercised end to end."""
        from asago_scenario_generator.pipeline.coverage_planning import (
            _solve_min_cost_assignment,
        )

        # Choices map references a pattern, but the network build adds the
        # edges; to force unreachable, use an empty choices map for a target.
        assignment = _solve_min_cost_assignment([], {}, None)
        assert assignment == {}


# ---------------------------------------------------------------------------
# Selection helpers
# ---------------------------------------------------------------------------


class TestSelectionHelpers:
    def test_target_choice_lists_skips_missing_and_empty_queues(self) -> None:
        queues = {
            "ep-a": TargetFallbackQueue("ep-a", [_qc(1)]),
            "ep-b": TargetFallbackQueue("ep-b", []),
        }
        targets = [_target("ep-a"), _target("ep-b"), _target("ep-c")]
        result = _target_choice_lists(targets, queues)
        assert [ep for ep, _ in result] == ["ep-a"]

    def test_no_candidate_selection_marks_all_uncovered(self) -> None:
        result = _no_candidate_selection([_target("ep-a"), _target("ep-b")])
        assert result.uncovered_target_ids == ["ep-a", "ep-b"]
        assert result.selected == []

    def test_build_primary_selection_deduplicates_shared_candidate(self) -> None:
        shared = _qc(1)
        assignment = {"ep-a": shared, "ep-b": shared}
        selected, selected_ids, primary_ids = _build_primary_selection(assignment)
        assert len(selected) == 1  # one candidate serving two targets
        assert selected_ids == {shared.candidate_id}
        assert primary_ids == {"ep-a": shared.candidate_id, "ep-b": shared.candidate_id}

    def test_build_primary_selection_ranks_in_target_order(self) -> None:
        first, second = _qc(1), _qc(2)
        selected, _, _ = _build_primary_selection({"ep-b": second, "ep-a": first})
        assert [q.rank for q in selected] == [0, 1]
        assert selected[0].candidate_id == first.candidate_id

    def test_derive_selection_limitations_no_cap(self) -> None:
        assignment = {"ep-a": _qc(1, pattern="AP-1")}
        assert _derive_selection_limitations(assignment, None) == []

    def test_derive_selection_limitations_in_cap(self) -> None:
        assignment = {"ep-a": _qc(1, pattern="AP-1"), "ep-b": _qc(2, pattern="AP-2")}
        assert _derive_selection_limitations(assignment, 1) == []

    def test_derive_selection_limitations_over_cap(self) -> None:
        assignment = {
            "ep-a": _qc(1, pattern="AP-1"),
            "ep-b": _qc(2, pattern="AP-1"),
            "ep-c": _qc(3, pattern="AP-1"),
        }
        # Sorted target order: first max_per_pattern (1) in-cap, rest overflow.
        assert _derive_selection_limitations(assignment, 1) == ["ep-b", "ep-c"]


# ---------------------------------------------------------------------------
# Round-robin exhaustive selection helpers
# ---------------------------------------------------------------------------


class TestRoundRobinSelection:
    def test_round_robin_spreads_across_ingresses(self) -> None:
        by_ingress = {
            "ep-a": [_qc(1), _qc(2)],
            "ep-b": [_qc(3), _qc(4)],
        }
        selected = _round_robin_within_pattern(by_ingress, 2)
        # One per ingress in the first pass: ep-a then ep-b by sorted id.
        assert [q.candidate_id for q in selected] == [
            _qc(1).candidate_id,
            _qc(3).candidate_id,
        ]

    def test_round_robin_stops_when_no_ingress_progresses(self) -> None:
        by_ingress = {"ep-a": [_qc(1)]}
        selected = _round_robin_within_pattern(by_ingress, 3)
        assert [q.candidate_id for q in selected] == [_qc(1).candidate_id]

    def test_round_robin_respects_cap(self) -> None:
        by_ingress = {"ep-a": [_qc(1), _qc(2), _qc(3)]}
        assert len(_round_robin_within_pattern(by_ingress, 2)) == 2


class TestExhaustivePlanHelpers:
    def test_exhaustive_target_entries_one_choice_per_candidate(self) -> None:
        target_names = {_REAL_EP_ID: "Prompt"}
        queues, entries, primaries = _exhaustive_target_entries(
            [_qc(1), _qc(2)], target_names
        )
        assert len(queues) == 2
        assert all(len(q.choices) == 1 for q in queues.values())
        assert [e.entry_point_name for e in entries] == ["Prompt", "Prompt"]
        assert len(primaries) == 2

    def test_uncovered_exhaustive_entries_empty_queue_entries(self) -> None:
        universe = CoverageUniverse(feasible_targets=[_target("ep-a"), _target("ep-b")])
        queues, entries = _uncovered_exhaustive_entries(["ep-b"], universe)
        assert list(queues) == ["ep-b"]
        assert entries[0].primary_state == "uncovered"
        assert entries[0].ordered_choices == []

    def test_cap_limited_target_ids_only_queue_bearing(self) -> None:
        queues = {
            "ep-a": TargetFallbackQueue("ep-a", [_qc(1)]),
            "ep-b": TargetFallbackQueue("ep-b", []),
        }
        assert _cap_limited_target_ids(["ep-a", "ep-b"], queues) == ["ep-a"]


# ---------------------------------------------------------------------------
# Coverage plan entry helpers
# ---------------------------------------------------------------------------


class TestPlanEntryForTarget:
    def test_entry_without_queue_and_primary(self) -> None:
        entry = _plan_entry_for_target(_target("ep-a"), None, None, set(), {})
        assert entry.primary_candidate_id is None
        assert entry.primary_state == "uncovered"
        assert entry.ordered_choices == []
        assert entry.fallback_available == []

    def test_entry_state_from_outcomes(self) -> None:
        choice = _qc(1)
        queue = TargetFallbackQueue("ep-a", [choice])
        entry = _plan_entry_for_target(
            _target("ep-a"),
            queue,
            choice.candidate_id,
            {choice.candidate_id},
            {choice.candidate_id: "failed"},
        )
        assert entry.primary_state == "failed"
        assert entry.fallback_available == []

    def test_entry_default_state_selected_and_fallback_excludes_attempted(
        self,
    ) -> None:
        first, second = _qc(1), _qc(2)
        queue = TargetFallbackQueue("ep-a", [first, second])
        entry = _plan_entry_for_target(
            _target("ep-a"),
            queue,
            first.candidate_id,
            {first.candidate_id},
            {},
        )
        assert entry.primary_state == "selected"
        assert [r["candidate_id"] for r in entry.fallback_available] == [
            second.candidate_id
        ]


# ---------------------------------------------------------------------------
# emit_quality_gaps helpers
# ---------------------------------------------------------------------------


class TestQualityGapHelpers:
    def test_quarantine_gap_uses_quarantine_ids(self) -> None:
        ledger = StageLedger()
        ledger.record("ep-a", "q-1", STAGE_QUARANTINE, "invalid")
        gap = _quarantine_gap(_target("ep-a"), ledger)
        assert gap.candidate_ids == ["q-1"]

    def test_quarantine_gap_falls_back_to_generation_ids(self) -> None:
        ledger = StageLedger()
        ledger.record("ep-a", "g-1", STAGE_GENERATION, "failed")
        gap = _quarantine_gap(_target("ep-a"), ledger)
        assert gap.candidate_ids == ["g-1"]

    def test_projection_limitation_gap(self) -> None:
        gap = _projection_limitation_gap(_target("ep-a"))
        assert gap.reason.value == "projection_limitation"
        assert gap.candidate_ids == []

    def test_furthest_stage_gap_none_without_events(self) -> None:
        assert _furthest_stage_gap(_target("ep-a"), StageLedger()) is None

    def test_furthest_stage_gap_uses_furthest_event(self) -> None:
        ledger = StageLedger()
        ledger.record("ep-a", "early", STAGE_FILTER, "rejected", "why")
        gap, furthest = _furthest_stage_gap(_target("ep-a"), ledger)
        assert furthest.stage == STAGE_FILTER
        assert gap.candidate_ids == ["early"]
        assert gap.detail == "why"

    def test_no_evidence_gap_uncovered_detail(self) -> None:
        gap = _no_evidence_gap(_target("ep-a"), uncovered=True)
        assert "No seed or candidate" in gap.detail

    def test_no_evidence_gap_no_evidence_detail(self) -> None:
        gap = _no_evidence_gap(_target("ep-a"), uncovered=False)
        assert "No stage evidence" in gap.detail

    @pytest.mark.parametrize(
        ("stage", "target_list"),
        [
            ("rules", "structural"),
            ("filter", "structural"),
            ("projection", "structural"),
            ("selection", "selection"),
            ("generation", "runtime"),
            ("admission", "quarantine"),
            ("quarantine", "quarantine"),
        ],
    )
    def test_categorize_furthest_gap_routes_lists(
        self, stage: str, target_list: str
    ) -> None:
        from asago_scenario_generator.pipeline.coverage_planning import (
            CoverageGapReason,
            QualityGap,
            StageEvent,
        )

        gap = QualityGap(
            entry_point_id="ep-a",
            entry_point_name="Target",
            reason=CoverageGapReason.NO_SEED,
        )
        event = StageEvent(
            entry_point_id="ep-a", candidate_id="c", stage=stage, reason="r"
        )
        structural: list[dict] = []
        selection: list[dict] = []
        runtime: list[dict] = []
        quarantine: list[dict] = []
        _categorize_furthest_gap(
            event, gap, structural, selection, runtime, quarantine
        )
        lists = {
            "structural": structural,
            "selection": selection,
            "runtime": runtime,
            "quarantine": quarantine,
        }
        assert lists[target_list] == [gap.to_dict()]
        assert sum(len(v) for v in lists.values()) == 1

    def test_policy_exclusion_dicts(self) -> None:
        universe = CoverageUniverse(
            excluded_targets=[
                ExcludedTarget(
                    "out", "Output", "output", "system", CoverageExclusionReason.OUTPUT_ONLY
                )
            ]
        )
        assert _policy_exclusion_dicts(universe) == [
            {"entry_point_id": "out", "name": "Output", "reason": "output_only"}
        ]


# ---------------------------------------------------------------------------
# Deserialization / revalidation helpers
# ---------------------------------------------------------------------------


class TestDeserializationHelpers:
    def test_verify_outer_identity_rejects_each_field(self) -> None:
        pc = _pc()
        ref = {
            "candidate_id": "tampered",
            "pattern_id": pc.pattern_id,
            "entry_point_id": pc.canonical_ingress.entry_point_id,
        }
        with pytest.raises(ValueError, match="candidate_id"):
            _verify_outer_identity(ref, pc)
        ref = {
            "candidate_id": pc.candidate_id,
            "pattern_id": "AP-TAMPER-01",
            "entry_point_id": pc.canonical_ingress.entry_point_id,
        }
        with pytest.raises(ValueError, match="pattern_id"):
            _verify_outer_identity(ref, pc)
        ref = {
            "candidate_id": pc.candidate_id,
            "pattern_id": pc.pattern_id,
            "entry_point_id": "ep:v1:tampered",
        }
        with pytest.raises(ValueError, match="entry_point_id"):
            _verify_outer_identity(ref, pc)

    def test_verify_outer_identity_passes_when_agreeing(self) -> None:
        pc = _pc()
        _verify_outer_identity(
            {
                "candidate_id": pc.candidate_id,
                "pattern_id": pc.pattern_id,
                "entry_point_id": pc.canonical_ingress.entry_point_id,
            },
            pc,
        )

    def test_deserialize_filter_records_rejects_empty(self) -> None:
        with pytest.raises(ValueError, match="no accepted filter records"):
            _deserialize_filter_records([])

    def test_deserialize_filter_records_rejects_seedless_record(self) -> None:
        raw = _record("filter-a").to_dict()
        raw.pop("seed")
        with pytest.raises(ValueError, match="missing seed"):
            _deserialize_filter_records([raw])

    def test_deserialize_filter_records_rejects_summary_drift(self) -> None:
        raw = _record("filter-a").to_dict()
        raw["rationale"] = "tampered"
        with pytest.raises(ValueError, match="does not match"):
            _deserialize_filter_records([raw])

    def test_deserialize_filter_records_round_trips(self) -> None:
        records = _deserialize_filter_records([_record("filter-a").to_dict()])
        assert records[0].filter_candidate_id == "filter-a"

    def test_verify_canonical_filter_ids_rejects_duplicates(self) -> None:
        with pytest.raises(ValueError, match="duplicate"):
            _verify_canonical_filter_ids([_record("a"), _record("a")])

    def test_verify_canonical_filter_ids_rejects_order(self) -> None:
        with pytest.raises(ValueError, match="canonical order"):
            _verify_canonical_filter_ids([_record("b"), _record("a")])

    def test_verify_canonical_filter_ids_passes(self) -> None:
        _verify_canonical_filter_ids([_record("a"), _record("b")])

    def test_verify_seed_ingress_agreement(self) -> None:
        pc = _pc()
        record = _record("filter-a")
        _verify_seed_ingress_agreement([record], pc)
        mismatched = AcceptedFilterRecord(
            filter_candidate_id="filter-b",
            rationale="",
            seed=_fseed(
                candidate_id="filter-b",
                entry_point_id="ep:v1:ffffffffffffffffffffffffffffffff",
            ),
        )
        with pytest.raises(ValueError, match="disagrees"):
            _verify_seed_ingress_agreement([mismatched], pc)


class TestRevalidationHelpers:
    def test_find_trusted_record(self) -> None:
        catalog = [{"id": "AP-1"}, {"id": "AP-2"}]
        assert _find_trusted_record(catalog, "AP-2") == {"id": "AP-2"}
        assert _find_trusted_record(catalog, "AP-9") is None

    def test_expected_authoritative_pin_supplied(self) -> None:
        assert _expected_authoritative_pin([], None, "pin-1") == "pin-1"

    def test_expected_authoritative_pin_computed(self) -> None:
        from tests.helpers.projection_factory import (
            get_test_raw_pattern,
            get_test_resolver,
        )

        catalog = [get_test_raw_pattern()]
        resolver = get_test_resolver()
        result = _expected_authoritative_pin(catalog, resolver, None)
        assert result is not None
        # Supplying the computed pin short-circuits recomputation.
        assert _expected_authoritative_pin(catalog, resolver, result) == result


# ---------------------------------------------------------------------------
# QualifiedCandidate / SelectionResult plumbing
# ---------------------------------------------------------------------------


class TestSelectionResultPlumbing:
    def test_selection_result_reused_by_helpers(self) -> None:
        result = SelectionResult(
            selected=[_qc(1)],
            uncovered_target_ids=["ep-b"],
            primary_candidate_ids={"ep-a": _qc(1).candidate_id},
            attempted_candidate_ids={_qc(1).candidate_id},
        )
        assert result.selected[0].candidate_id == _qc(1).candidate_id
        assert result.uncovered_target_ids == ["ep-b"]


# ---------------------------------------------------------------------------
# Uncovered-target derivation / gap-set normalization helpers
# ---------------------------------------------------------------------------


class TestUncoveredTargetIds:
    def test_filters_targets_without_primary_assignment(self) -> None:
        targets = [_target("ep-a"), _target("ep-b"), _target("ep-c")]
        assert _uncovered_target_ids(targets, {"ep-a": "cand-1"}) == ["ep-b", "ep-c"]

    def test_empty_primary_map_keeps_all_targets(self) -> None:
        targets = [_target("ep-a"), _target("ep-b")]
        assert _uncovered_target_ids(targets, {}) == ["ep-a", "ep-b"]


class TestNormalizeGapSets:
    def test_defaults_missing_sets_to_empty(self) -> None:
        assert _normalize_gap_sets(None, None, None) == (set(), set(), set())

    def test_keeps_supplied_sets(self) -> None:
        assert _normalize_gap_sets({"a"}, None, {"b"}) == ({"a"}, set(), {"b"})


class TestRecordLedgerGap:
    def _result(self) -> SelectionResult:
        return SelectionResult(
            selected=[],
            uncovered_target_ids=["ep-a"],
            primary_candidate_ids={},
            attempted_candidate_ids=set(),
        )

    def test_records_furthest_event_gap(self) -> None:
        ledger = StageLedger()
        ledger.record("ep-a", "c-1", STAGE_FILTER, "rejected", "why")
        gaps: list = []
        structural: list = []
        selection: list = []
        runtime: list = []
        quarantine: list = []
        _record_ledger_gap(
            _target("ep-a"),
            ledger,
            self._result(),
            gaps,
            structural,
            selection,
            runtime,
            quarantine,
        )
        assert [g.candidate_ids for g in gaps] == [["c-1"]]
        assert structural == [gaps[0].to_dict()]
        assert selection == runtime == quarantine == []

    def test_records_no_evidence_gap_for_uncovered_target(self) -> None:
        gaps: list = []
        structural: list = []
        _record_ledger_gap(
            _target("ep-a"),
            StageLedger(),
            self._result(),
            gaps,
            structural,
            [],
            [],
            [],
        )
        assert gaps[0].reason.value == "no_seed"
        assert "No seed or candidate" in gaps[0].detail
        assert structural == [gaps[0].to_dict()]

    def test_select_with_coverage_priority_no_candidate_queues(self) -> None:
        from asago_scenario_generator.pipeline.coverage_planning import (
            select_with_coverage_priority,
        )

        universe = CoverageUniverse(
            feasible_targets=[_target("ep-a"), _target("ep-b")]
        )
        result = select_with_coverage_priority([], {}, universe)
        assert result.selected == []
        assert result.uncovered_target_ids == ["ep-a", "ep-b"]
