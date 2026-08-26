"""Mutation hardening tests for coverage_planning_flow.py graph helpers.

Targets the surviving mutants identified by mutate4py on the min-cost
flow / SPFA / assignment helpers.  Each test pins an exact arithmetic or
boundary behaviour that a surviving mutant would flip:

* ``_build_flow_network`` — node count, sink index, source->target edge
  targets/capacities/costs, and the computed ``concentration_scale`` and
  ``cap_overflow_penalty`` reflected in pattern->sink edge costs.
* ``_relax_node`` / ``_spfa_shortest_path`` — capacity guard, boolean
  connective, distance arithmetic, strict-vs-non-strict comparison,
  in-queue initialization, parent initialization, and list-multiplication.
* ``_extract_assignment`` — the ``1 + target_index`` node offset.
* ``_solve_min_cost_assignment`` — the ``total_flow`` initial value and
  the ``path is None`` break guard.

The fixtures mirror ``tests/test_coverage_planning_helpers.py`` so the
``QualifiedCandidate`` objects carry valid ``candidate_id`` / ``pattern_id``
properties used by the flow helpers.
"""

from __future__ import annotations

from collections import deque

import pytest

import asago_scenario_generator.pipeline.coverage_planning_flow as flow_module
from asago_scenario_generator.models.scenario import RiskCardRef
from asago_scenario_generator.pipeline.candidate_models import FilteredSeed
from asago_scenario_generator.pipeline.coverage_planning import (
    AcceptedFilterRecord,
    QualifiedCandidate,
)
from asago_scenario_generator.pipeline.coverage_planning_flow import (
    _build_flow_network,
    _extract_assignment,
    _relax_node,
    _solve_min_cost_assignment,
    _spfa_shortest_path,
    add_edge,
)
from asago_scenario_generator.pipeline.projection_contracts import ProjectedCandidate
from tests.helpers.projection_factory import get_projected_candidate

_REAL_PC = get_projected_candidate()
_REAL_EP_ID = _REAL_PC.canonical_ingress.entry_point_id
_REAL_PATTERN_ID = _REAL_PC.pattern_id


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


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
        origins=[],
        rejection_rationales=[],
    )


def _record(candidate_id: str) -> AcceptedFilterRecord:
    return AcceptedFilterRecord.from_seed(_fseed(candidate_id=candidate_id))


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


def _network_inputs(
    target_ids: list[str],
    choices: dict[str, list[QualifiedCandidate]],
    max_per_pattern: int | None,
):
    """Build the inputs that ``_build_flow_network`` expects."""
    from asago_scenario_generator.pipeline.coverage_planning_flow import (
        _best_candidate_per_target_pattern,
        _collect_pattern_index,
    )

    all_patterns, pattern_idx = _collect_pattern_index(choices)
    best_per_tp = _best_candidate_per_target_pattern(target_ids, choices)
    target_count = len(target_ids)
    pattern_count = len(all_patterns)
    return {
        "target_ids": target_ids,
        "target_choices_map": choices,
        "best_per_tp": best_per_tp,
        "pattern_idx": pattern_idx,
        "max_per_pattern": max_per_pattern,
        "target_count": target_count,
        "pattern_count": pattern_count,
        "all_patterns": all_patterns,
    }


# ---------------------------------------------------------------------------
# _build_flow_network
# ---------------------------------------------------------------------------


class TestBuildFlowNetworkStructure:
    """Pin the node-count, sink index, and source->target edge geometry."""

    def test_graph_has_exact_node_count(self) -> None:
        # N=2 targets, M=1 pattern -> 2+1+2 = 5 nodes.
        choices = {
            "ep-a": [_qc(1, pattern="AP-1")],
            "ep-b": [_qc(2, pattern="AP-1")],
        }
        inputs = _network_inputs(["ep-a", "ep-b"], choices, None)
        graph, _source, _sink = _build_flow_network(**_graph_kwargs(inputs))
        assert len(graph) == 2 + 1 + 2

    def test_sink_index_is_last_node(self) -> None:
        # N=2, M=1 -> sink = 2 + 1 + 1 = 4.
        choices = {
            "ep-a": [_qc(1, pattern="AP-1")],
            "ep-b": [_qc(2, pattern="AP-1")],
        }
        inputs = _network_inputs(["ep-a", "ep-b"], choices, None)
        _graph, _source, sink = _build_flow_network(**_graph_kwargs(inputs))
        assert sink == 2 + 1 + 1

    def test_sink_index_uses_pattern_count(self) -> None:
        # Distinct N and M so a ``+ -> -`` on the sink formula is caught.
        # N=1 target, M=2 patterns -> sink = 1 + 2 + 1 = 4.
        choices = {
            "ep-a": [_qc(1, pattern="AP-1"), _qc(3, pattern="AP-2")],
        }
        inputs = _network_inputs(["ep-a"], choices, None)
        _graph, _source, sink = _build_flow_network(**_graph_kwargs(inputs))
        assert sink == 1 + 2 + 1
        assert len(_graph) == 1 + 2 + 2

    def test_source_is_zero(self) -> None:
        choices = {"ep-a": [_qc(1, pattern="AP-1")]}
        inputs = _network_inputs(["ep-a"], choices, None)
        _graph, source, _sink = _build_flow_network(**_graph_kwargs(inputs))
        assert source == 0

    def test_source_target_edges_target_nodes_one_to_n(self) -> None:
        # source->target edges must land on nodes 1..N (not 0..N-1).
        choices = {
            "ep-a": [_qc(1, pattern="AP-1")],
            "ep-b": [_qc(2, pattern="AP-1")],
        }
        inputs = _network_inputs(["ep-a", "ep-b"], choices, None)
        graph, source, _sink = _build_flow_network(**_graph_kwargs(inputs))
        forward_targets = [e[0] for e in graph[source] if e[1] == 1]
        assert forward_targets == [1, 2]

    def test_source_target_edges_have_unit_capacity_and_zero_cost(self) -> None:
        choices = {
            "ep-a": [_qc(1, pattern="AP-1")],
            "ep-b": [_qc(2, pattern="AP-1")],
        }
        inputs = _network_inputs(["ep-a", "ep-b"], choices, None)
        graph, source, _sink = _build_flow_network(**_graph_kwargs(inputs))
        for edge in graph[source]:
            if edge[1] == 1:  # forward capacity
                assert edge[1] == 1
                assert edge[2] == 0


class TestBuildFlowNetworkCosts:
    """Pin concentration_scale and cap_overflow_penalty via edge costs."""

    def test_concentration_scale_reflected_in_second_pattern_sink_edge(
        self,
    ) -> None:
        # N=2 -> concentration_scale = 2*2 + 1 = 5.  With no cap, the
        # second pattern->sink unit (flow_index=1) costs 1*scale = 5.
        choices = {
            "ep-a": [_qc(1, pattern="AP-1")],
            "ep-b": [_qc(2, pattern="AP-1")],
        }
        inputs = _network_inputs(["ep-a", "ep-b"], choices, None)
        graph, _source, sink = _build_flow_network(**_graph_kwargs(inputs))
        pattern_node = 1 + 2 + 0  # 1 + target_count + pattern_index
        sink_costs = sorted(
            edge[2] for edge in graph[pattern_node] if edge[0] == sink and edge[1] == 1
        )
        # flow_index 0 -> cost 0, flow_index 1 -> cost 5.
        assert sink_costs == [0, 5]

    def test_cap_overflow_penalty_reflected_when_cap_exceeded(self) -> None:
        # N=2, max_per_pattern=1 -> scale=5, penalty=2*2+1=5.
        # flow_index 1 (k=1 >= cap=1): cost = 1*5 + 5*5 = 30.
        choices = {
            "ep-a": [_qc(1, pattern="AP-1")],
            "ep-b": [_qc(2, pattern="AP-1")],
        }
        inputs = _network_inputs(["ep-a", "ep-b"], choices, max_per_pattern=1)
        graph, _source, sink = _build_flow_network(**_graph_kwargs(inputs))
        pattern_node = 1 + 2 + 0
        sink_costs = sorted(
            edge[2] for edge in graph[pattern_node] if edge[0] == sink and edge[1] == 1
        )
        assert sink_costs == [0, 30]

    def test_penalty_uses_square_of_target_count(self) -> None:
        # N=3 -> penalty = 3*3 + 1 = 10, scale = 2*3 + 1 = 7.
        # flow_index 1 with cap=1: cost = 1*7 + 10*7 = 77.
        choices = {
            "ep-a": [_qc(1, pattern="AP-1")],
            "ep-b": [_qc(2, pattern="AP-1")],
            "ep-c": [_qc(3, pattern="AP-1")],
        }
        inputs = _network_inputs(
            ["ep-a", "ep-b", "ep-c"], choices, max_per_pattern=1
        )
        graph, _source, sink = _build_flow_network(**_graph_kwargs(inputs))
        pattern_node = 1 + 3 + 0
        sink_costs = sorted(
            edge[2] for edge in graph[pattern_node] if edge[0] == sink and edge[1] == 1
        )
        # flow_index 0 -> 0, flow_index 1 -> 77, flow_index 2 -> 2*7 + 10*7 = 84
        assert sink_costs == [0, 77, 84]


def _graph_kwargs(inputs: dict) -> dict:
    return {
        "target_ids": inputs["target_ids"],
        "target_choices_map": inputs["target_choices_map"],
        "best_per_tp": inputs["best_per_tp"],
        "pattern_idx": inputs["pattern_idx"],
        "max_per_pattern": inputs["max_per_pattern"],
        "target_count": inputs["target_count"],
        "pattern_count": inputs["pattern_count"],
    }


# ---------------------------------------------------------------------------
# _relax_node / _spfa_shortest_path
# ---------------------------------------------------------------------------


class TestSpfaCapacityGuard:
    """``capacity > 0`` must skip zero-capacity (reverse) edges."""

    def test_cap_one_edges_are_traversed(self) -> None:
        # All forward edges have capacity 1; the path must be found.
        # Mutant ``capacity > 0 -> > 1`` skips cap-1 edges -> None.
        graph: list[list[list[int]]] = [[], [], []]
        add_edge(graph, 0, 1, 1, 0)
        add_edge(graph, 1, 2, 1, 0)
        result = _spfa_shortest_path(graph, 0, 2, 3)
        assert result is not None
        parents, _edges = result
        assert parents[2] == 1

    def test_zero_capacity_reverse_edge_does_not_supply_shorter_path(self) -> None:
        # 0->1 (cap1 cost5), 0->2 (cap1 cost100), 2->1 (cap1 cost0).
        # The reverse edge 1->2 (cap0, cost0) must NOT let node 2 be
        # "reached" through node 1.  Correct shortest path to 2 is the
        # direct 0->2 edge, so parents[2] == 0.
        # Mutants ``capacity > 0 -> >= 0`` and ``and -> or`` traverse the
        # zero-cap reverse edge and corrupt parents[2] to 1.
        graph: list[list[list[int]]] = [[], [], []]
        add_edge(graph, 0, 1, 1, 5)
        add_edge(graph, 0, 2, 1, 100)
        add_edge(graph, 2, 1, 1, 0)
        result = _spfa_shortest_path(graph, 0, 2, 3)
        assert result is not None
        parents, _edges = result
        assert parents[2] == 0


class TestSpfaDistanceArithmetic:
    """``distances[node] + cost`` must add, not subtract."""

    def test_two_hop_cheaper_path_is_preferred(self) -> None:
        # 0->1 (cost5), 1->2 (cost5) => path cost 10.
        # 0->2 (cost100) => direct cost 100.
        # Shortest path to 2 is via node 1, so parents[2] == 1.
        # Mutant ``+ -> -`` flips distances to negatives and makes the
        # direct edge (cost -100) appear "shorter" -> parents[2] == 0.
        graph: list[list[list[int]]] = [[], [], []]
        add_edge(graph, 0, 1, 1, 5)
        add_edge(graph, 1, 2, 1, 5)
        add_edge(graph, 0, 2, 1, 100)
        result = _spfa_shortest_path(graph, 0, 2, 3)
        assert result is not None
        parents, _edges = result
        assert parents[2] == 1


class TestSpfaStrictComparison:
    """``<`` must not update on equal distances."""

    def test_equal_distance_does_not_overwrite_parent(self) -> None:
        # 0->1 (cost5), 0->2 (cost5), 2->1 (cost0).
        # Direct 0->1 and indirect 0->2->1 both cost 5.  With strict ``<``
        # the direct edge wins (parents[1] == 0).  Mutant ``< -> <=``
        # overwrites parents[1] to 2.
        graph: list[list[list[int]]] = [[], [], []]
        add_edge(graph, 0, 1, 1, 5)
        add_edge(graph, 0, 2, 1, 5)
        add_edge(graph, 2, 1, 1, 0)
        result = _spfa_shortest_path(graph, 0, 1, 3)
        assert result is not None
        parents, _edges = result
        assert parents[1] == 0


class TestSpfaInitialization:
    """Pin ``in_queue`` and parent-list initialization."""

    def test_in_queue_false_initialization_allows_propagation(self) -> None:
        # Mutant ``[False] * node_count -> [False] / node_count`` raises
        # TypeError; mutant ``in_queue = [False] -> [True]`` marks every
        # node as queued so neighbours are never enqueued and the sink
        # stays unreachable -> None.
        graph: list[list[list[int]]] = [[], [], []]
        add_edge(graph, 0, 1, 1, 0)
        add_edge(graph, 1, 2, 1, 0)
        result = _spfa_shortest_path(graph, 0, 2, 3)
        assert result is not None

    def test_unreachable_node_parent_is_minus_one(self) -> None:
        # Mutant ``parent_node = [-1] -> [0]`` (1 -> 0) leaves unreachable
        # nodes with parent 0 instead of -1.
        graph: list[list[list[int]]] = [[], [], []]
        add_edge(graph, 0, 1, 1, 0)
        result = _spfa_shortest_path(graph, 0, 1, 3)
        assert result is not None
        parents, _edges = result
        assert parents[2] == -1
        assert _edges[2] == -1

    def test_unreachable_sink_returns_none(self) -> None:
        graph: list[list[list[int]]] = [[], [], []]
        assert _spfa_shortest_path(graph, 0, 2, 3) is None

    def test_dequeued_node_is_requeued_after_shorter_path(self) -> None:
        # Node 1 is dequeued first with distance 10, then node 2 finds a
        # shorter path to it with distance -4.  Clearing ``in_queue[1]``
        # after dequeue is required for node 1 to run again and improve the
        # sink from node 3's distance 5 to node 1's distance -4.
        # Mutant ``in_queue[node] = False -> True`` leaves node 1 marked as
        # queued and returns node 3 as the sink parent.
        graph: list[list[list[int]]] = [[], [], [], [], []]
        add_edge(graph, 0, 1, 1, 10)
        add_edge(graph, 0, 2, 1, 1)
        add_edge(graph, 0, 3, 1, 5)
        add_edge(graph, 1, 4, 1, 0)
        add_edge(graph, 2, 1, 1, -5)
        add_edge(graph, 3, 4, 1, 0)
        result = _spfa_shortest_path(graph, 0, 4, 5)
        assert result is not None
        parents, _edges = result
        assert parents[4] == 1


class TestRelaxNodeDirect:
    """Drive ``_relax_node`` directly to pin its side effects."""

    def test_relax_updates_distance_parent_and_queue(self) -> None:
        graph: list[list[list[int]]] = [[], [], []]
        add_edge(graph, 0, 1, 1, 7)
        distances: list[float] = [0.0, float("inf"), float("inf")]
        in_queue = [False, False, False]
        queue: deque[int] = deque()
        parent_node = [-1, -1, -1]
        parent_edge = [-1, -1, -1]
        _relax_node(graph, 0, distances, in_queue, queue, parent_node, parent_edge)
        assert distances[1] == 7
        assert parent_node[1] == 0
        assert parent_edge[1] == 0
        assert in_queue[1] is True
        assert list(queue) == [1]

    def test_relax_skips_zero_capacity_edge(self) -> None:
        # The reverse edge 1->0 has capacity 0; relaxing node 1 must not
        # touch node 0's distance/parent.  Mutants ``>= 0`` / ``or`` would.
        graph: list[list[list[int]]] = [[], [], []]
        add_edge(graph, 0, 1, 1, 5)  # reverse 1->0 cap0 cost-5
        distances: list[float] = [0.0, 5.0, float("inf")]
        in_queue = [False, False, False]
        queue: deque[int] = deque()
        parent_node = [-1, 0, -1]
        parent_edge = [-1, 0, -1]
        _relax_node(graph, 1, distances, in_queue, queue, parent_node, parent_edge)
        # Node 0 must be untouched.
        assert distances[0] == 0.0
        assert parent_node[0] == -1
        assert parent_edge[0] == -1
        assert list(queue) == []

    def test_relax_strict_less_than_does_not_update_on_equal(self) -> None:
        # 0->1 cost5; distances[1] already 5.  Relaxing node 0 must NOT
        # overwrite parent[1] (5 < 5 is False).  Mutant ``< -> <=`` would.
        graph: list[list[list[int]]] = [[], [], []]
        add_edge(graph, 0, 1, 1, 5)
        distances: list[float] = [0.0, 5.0, float("inf")]
        in_queue = [False, False, False]
        queue: deque[int] = deque()
        parent_node = [-1, 7, -1]  # pre-set parent to detect overwrite
        parent_edge = [-1, 9, -1]
        _relax_node(graph, 0, distances, in_queue, queue, parent_node, parent_edge)
        assert parent_node[1] == 7
        assert parent_edge[1] == 9
        assert distances[1] == 5.0
        assert list(queue) == []


# ---------------------------------------------------------------------------
# _extract_assignment
# ---------------------------------------------------------------------------


class TestExtractAssignmentOffset:
    """``graph[1 + target_index]`` must index the target's own edges."""

    def test_two_targets_both_assigned(self) -> None:
        # N=2, M=1.  Both targets carry flow to the single pattern.
        # Mutant ``1 + target_index -> 1 - target_index`` reads graph[0]
        # (source edges) for target_index 1 and finds no flowing pattern
        # edge -> only target 0 is assigned.
        target_ids = ["ep-a", "ep-b"]
        all_patterns = ["AP-1"]
        best = {
            ("ep-a", "AP-1"): _qc(1, pattern="AP-1"),
            ("ep-b", "AP-1"): _qc(2, pattern="AP-1"),
        }
        # Nodes: 0 source, 1 target-a, 2 target-b, 3 pattern, 4 sink.
        graph: list[list[list[int]]] = [[] for _ in range(5)]
        add_edge(graph, 0, 1, 1, 0)
        add_edge(graph, 0, 2, 1, 0)
        add_edge(graph, 1, 3, 1, 0)
        add_edge(graph, 2, 3, 1, 0)
        add_edge(graph, 3, 4, 2, 0)
        # Mark both target->pattern edges as carrying flow (cap consumed).
        graph[1][1][1] = 0  # target-a -> pattern
        graph[2][1][1] = 0  # target-b -> pattern
        assignment = _extract_assignment(
            graph, 2, 1, target_ids, all_patterns, best
        )
        assert set(assignment.keys()) == {"ep-a", "ep-b"}
        assert assignment["ep-a"].pattern_id == "AP-1"
        assert assignment["ep-b"].pattern_id == "AP-1"

    def test_single_target_assigned(self) -> None:
        target_ids = ["ep-a"]
        all_patterns = ["AP-1"]
        best = {("ep-a", "AP-1"): _qc(1, pattern="AP-1")}
        graph: list[list[list[int]]] = [[] for _ in range(3)]
        add_edge(graph, 0, 1, 1, 0)
        add_edge(graph, 1, 2, 1, 0)
        graph[1][1][1] = 0  # flow consumed
        assignment = _extract_assignment(graph, 1, 1, target_ids, all_patterns, best)
        assert assignment == {"ep-a": best[("ep-a", "AP-1")]}

    def test_no_flow_yields_empty_assignment(self) -> None:
        target_ids = ["ep-a"]
        best = {("ep-a", "AP-1"): _qc(1, pattern="AP-1")}
        graph: list[list[list[int]]] = [[] for _ in range(3)]
        add_edge(graph, 0, 1, 1, 0)
        add_edge(graph, 1, 2, 1, 0)  # cap still 1 -> no flow
        assignment = _extract_assignment(graph, 1, 1, target_ids, ["AP-1"], best)
        assert assignment == {}


# ---------------------------------------------------------------------------
# _solve_min_cost_assignment
# ---------------------------------------------------------------------------


class TestSolverFlowControl:
    """Pin ``total_flow`` initialization and the ``path is None`` break."""

    def test_single_target_is_assigned(self) -> None:
        # Mutant ``total_flow = 0 -> 1`` makes ``while 1 < 1`` false, so
        # no augmenting path is pushed and the assignment is empty.
        choices = {"ep-a": [_qc(1, pattern="AP-1")]}
        assignment = _solve_min_cost_assignment(["ep-a"], choices, None)
        assert "ep-a" in assignment
        assert assignment["ep-a"].pattern_id == "AP-1"

    def test_two_targets_both_assigned(self) -> None:
        # Mutant ``path is None -> is not None`` breaks after the first
        # augmenting path, leaving the second target unassigned.
        choices = {
            "ep-a": [_qc(1, pattern="AP-1")],
            "ep-b": [_qc(2, pattern="AP-2")],
        }
        assignment = _solve_min_cost_assignment(["ep-a", "ep-b"], choices, None)
        assert set(assignment.keys()) == {"ep-a", "ep-b"}

    def test_empty_targets_returns_empty(self) -> None:
        assert _solve_min_cost_assignment([], {}, None) == {}

    def test_three_targets_all_assigned(self) -> None:
        choices = {
            "ep-a": [_qc(1, pattern="AP-1")],
            "ep-b": [_qc(2, pattern="AP-2")],
            "ep-c": [_qc(3, pattern="AP-3")],
        }
        assignment = _solve_min_cost_assignment(
            ["ep-a", "ep-b", "ep-c"], choices, None
        )
        assert set(assignment.keys()) == {"ep-a", "ep-b", "ep-c"}

    def test_solver_stops_after_one_path_per_target(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Keep returning an augmenting path and make augmentation observable
        # without changing the graph.  A one-target solve must still call
        # augmentation exactly once.  This catches total_flow starting at
        # one, a non-strict loop bound, and a missing flow increment without
        # relying on an unbounded mutant run.
        augment_calls = 0

        def fake_shortest_path(
            _graph: list[list[list[int]]],
            _source: int,
            _sink: int,
            node_count: int,
        ) -> tuple[list[int], list[int]]:
            return [-1] * node_count, [-1] * node_count

        def fake_augment(
            _graph: list[list[list[int]]],
            _source: int,
            _sink: int,
            _parent_node: list[int],
            _parent_edge_idx: list[int],
        ) -> None:
            nonlocal augment_calls
            augment_calls += 1
            assert augment_calls == 1

        monkeypatch.setattr(
            flow_module, "_spfa_shortest_path", fake_shortest_path
        )
        monkeypatch.setattr(flow_module, "_augment_path", fake_augment)
        assignment = _solve_min_cost_assignment(
            ["ep-a"], {"ep-a": [_qc(1, pattern="AP-1")]}, None
        )
        assert assignment == {}
        assert augment_calls == 1


class TestSolverConcentration:
    """The convex pattern costs must spread targets across patterns."""

    def test_two_targets_two_patterns_are_spread(self) -> None:
        # Both targets can use either pattern.  Concentration minimization
        # (convex pattern->sink costs) must assign one target per pattern
        # rather than concentrating both on one pattern.
        choices = {
            "ep-a": [_qc(1, pattern="AP-1"), _qc(3, pattern="AP-2")],
            "ep-b": [_qc(2, pattern="AP-1"), _qc(4, pattern="AP-2")],
        }
        assignment = _solve_min_cost_assignment(["ep-a", "ep-b"], choices, None)
        assert set(assignment.keys()) == {"ep-a", "ep-b"}
        used_patterns = {qc.pattern_id for qc in assignment.values()}
        assert used_patterns == {"AP-1", "AP-2"}

    def test_candidate_id_tiebreak_picks_lowest(self) -> None:
        # Two candidates for the same (target, pattern); the solver must
        # pick the lowest candidate_id via the tie-break rank.
        low = _qc(1, pattern="AP-1")
        high = _qc(9, pattern="AP-1")
        choices = {"ep-a": [high, low]}
        assignment = _solve_min_cost_assignment(["ep-a"], choices, None)
        assert assignment["ep-a"].candidate_id == low.candidate_id

    def test_cap_limits_concentration(self) -> None:
        # With max_per_pattern=1 and two targets sharing one pattern, the
        # overflow penalty is high but flow is still permitted, so both
        # targets are assigned to the single available pattern.
        choices = {
            "ep-a": [_qc(1, pattern="AP-1")],
            "ep-b": [_qc(2, pattern="AP-1")],
        }
        assignment = _solve_min_cost_assignment(
            ["ep-a", "ep-b"], choices, max_per_pattern=1
        )
        assert set(assignment.keys()) == {"ep-a", "ep-b"}
        assert assignment["ep-a"].pattern_id == "AP-1"
        assert assignment["ep-b"].pattern_id == "AP-1"
