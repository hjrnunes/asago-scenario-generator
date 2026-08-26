"""Min-cost flow helpers for coverage-aware candidate selection."""

from __future__ import annotations

from collections import deque
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from asago_scenario_generator.pipeline.coverage_planning import QualifiedCandidate


def add_edge(graph: list[list[list[int]]], u: int, v: int, cap: int, cost: int) -> None:
    """Add a directed edge with capacity and cost, plus its reverse edge."""
    graph[u].append([v, cap, cost, len(graph[v])])
    graph[v].append([u, 0, -cost, len(graph[u]) - 1])


def _collect_pattern_index(
    target_choices_map: dict[str, list[QualifiedCandidate]],
) -> tuple[list[str], dict[str, int]]:
    """Collect the sorted unique pattern IDs and their node offsets."""
    all_patterns = sorted(
        {qc.pattern_id for choices in target_choices_map.values() for qc in choices}
    )
    pattern_idx = {p: i for i, p in enumerate(all_patterns)}
    return all_patterns, pattern_idx


def _best_candidate_per_target_pattern(
    target_ids: list[str],
    target_choices_map: dict[str, list[QualifiedCandidate]],
) -> dict[tuple[str, str], QualifiedCandidate]:
    """For each (target, pattern) pair, pick the lowest candidate_id candidate."""
    best_per_tp: dict[tuple[str, str], QualifiedCandidate] = {}
    for t_id in target_ids:
        for qc in target_choices_map[t_id]:
            key = (t_id, qc.pattern_id)
            if (
                key not in best_per_tp
                or qc.candidate_id < best_per_tp[key].candidate_id
            ):
                best_per_tp[key] = qc
    return best_per_tp


def _convex_pattern_cost(
    k: int,
    max_per_pattern: int | None,
    concentration_scale: int,
    cap_overflow_penalty: int,
) -> int:
    """Cost of the k-th flow unit into one pattern.

    The k-th unit (0-indexed) costs ``k * concentration_scale``, plus
    ``cap_overflow_penalty * concentration_scale`` when the per-pattern
    cap is exceeded — minimizing concentration, then cap overflow.
    """
    base_cost = k * concentration_scale
    if max_per_pattern is not None and k >= max_per_pattern:
        base_cost += cap_overflow_penalty * concentration_scale
    return base_cost


def _add_target_pattern_edges(
    graph: list[list[list[int]]],
    target_ids: list[str],
    target_choices_map: dict[str, list[QualifiedCandidate]],
    best_per_tp: dict[tuple[str, str], QualifiedCandidate],
    pattern_idx: dict[str, int],
    target_count: int,
) -> None:
    """Connect each target to its patterns with candidate-ID tie-break ranks."""
    for target_index, target_id in enumerate(target_ids):
        target_patterns = sorted(
            {qc.pattern_id for qc in target_choices_map[target_id]},
            key=lambda pattern_id: best_per_tp[(target_id, pattern_id)].candidate_id,
        )
        for rank, pattern_id in enumerate(target_patterns):
            pattern_index = pattern_idx[pattern_id]
            add_edge(
                graph,
                1 + target_index,
                1 + target_count + pattern_index,
                1,
                rank,
            )


def _add_pattern_sink_edges(
    graph: list[list[list[int]]],
    target_count: int,
    pattern_count: int,
    sink: int,
    max_per_pattern: int | None,
    concentration_scale: int,
    cap_overflow_penalty: int,
) -> None:
    """Connect each pattern to the sink with convex per-unit costs."""
    for pattern_index in range(pattern_count):
        for flow_index in range(target_count):
            cost = _convex_pattern_cost(
                flow_index,
                max_per_pattern,
                concentration_scale,
                cap_overflow_penalty,
            )
            add_edge(
                graph,
                1 + target_count + pattern_index,
                sink,
                1,
                cost,
            )


def _build_flow_network(
    target_ids: list[str],
    target_choices_map: dict[str, list[QualifiedCandidate]],
    best_per_tp: dict[tuple[str, str], QualifiedCandidate],
    pattern_idx: dict[str, int],
    max_per_pattern: int | None,
    target_count: int,
    pattern_count: int,
) -> tuple[list[list[list[int]]], int, int]:
    """Build the bipartite min-cost flow network.

    Nodes: 0=source, 1..N=targets, N+1..N+M=patterns, N+M+1=sink.
    Edge shape: ``[to, capacity, cost, rev_index]``.
    """
    source = 0
    sink = target_count + pattern_count + 1
    graph: list[list[list[int]]] = [[] for _ in range(target_count + pattern_count + 2)]

    for target_index in range(target_count):
        add_edge(graph, source, 1 + target_index, 1, 0)
    _add_target_pattern_edges(
        graph,
        target_ids,
        target_choices_map,
        best_per_tp,
        pattern_idx,
        target_count,
    )
    concentration_scale = 2 * target_count + 1  # > max total tie-break (2*N)
    cap_overflow_penalty = target_count * target_count + 1
    _add_pattern_sink_edges(
        graph,
        target_count,
        pattern_count,
        sink,
        max_per_pattern,
        concentration_scale,
        cap_overflow_penalty,
    )
    return graph, source, sink


def _relax_node(
    graph: list[list[list[int]]],
    node: int,
    distances: list[float],
    in_queue: list[bool],
    queue: deque[int],
    parent_node: list[int],
    parent_edge_idx: list[int],
) -> None:
    """Relax every residual edge leaving ``node`` (one SPFA step)."""
    for edge_index, edge in enumerate(graph[node]):
        next_node, capacity, cost, _ = edge
        if capacity > 0 and distances[node] + cost < distances[next_node]:
            distances[next_node] = distances[node] + cost
            parent_node[next_node] = node
            parent_edge_idx[next_node] = edge_index
            if not in_queue[next_node]:
                queue.append(next_node)
                in_queue[next_node] = True


def _spfa_shortest_path(
    graph: list[list[list[int]]],
    source: int,
    sink: int,
    node_count: int,
) -> tuple[list[int], list[int]] | None:
    """Find a shortest augmenting path with SPFA / Bellman-Ford.

    Returns ``(parent_node, parent_edge_idx)``, or None when the sink is
    unreachable through residual edges.
    """
    distances = [float("inf")] * node_count
    distances[source] = 0
    in_queue = [False] * node_count
    in_queue[source] = True
    queue: deque[int] = deque([source])
    parent_node = [-1] * node_count
    parent_edge_idx = [-1] * node_count

    while queue:
        node = queue.popleft()
        in_queue[node] = False
        _relax_node(
            graph,
            node,
            distances,
            in_queue,
            queue,
            parent_node,
            parent_edge_idx,
        )

    if distances[sink] == float("inf"):
        return None
    return parent_node, parent_edge_idx


def _augment_path(
    graph: list[list[list[int]]],
    source: int,
    sink: int,
    parent_node: list[int],
    parent_edge_idx: list[int],
) -> None:
    """Push one unit of flow along the recorded parent path."""
    node = sink
    while node != source:
        previous_node = parent_node[node]
        edge_index = parent_edge_idx[node]
        graph[previous_node][edge_index][1] -= 1
        reverse_index = graph[previous_node][edge_index][3]
        graph[node][reverse_index][1] += 1
        node = previous_node


def _flowing_pattern_edge(
    edge: list[int], target_count: int, pattern_count: int
) -> bool:
    """Return whether a target edge carries flow into a pattern node."""
    node = edge[0]
    return 1 + target_count <= node <= target_count + pattern_count and edge[1] == 0


def _extract_assignment(
    graph: list[list[list[int]]],
    target_count: int,
    pattern_count: int,
    target_ids: list[str],
    all_patterns: list[str],
    best_per_tp: dict[tuple[str, str], QualifiedCandidate],
) -> dict[str, QualifiedCandidate]:
    """Extract the assignment from target-to-pattern edges carrying flow."""
    assignment: dict[str, QualifiedCandidate] = {}
    for target_index, target_id in enumerate(target_ids):
        for edge in graph[1 + target_index]:
            if _flowing_pattern_edge(edge, target_count, pattern_count):
                pattern_index = edge[0] - 1 - target_count
                pattern_id = all_patterns[pattern_index]
                assignment[target_id] = best_per_tp[(target_id, pattern_id)]
                break
    return assignment


def _solve_min_cost_assignment(
    target_ids: list[str],
    target_choices_map: dict[str, list[QualifiedCandidate]],
    max_per_pattern: int | None,
) -> dict[str, QualifiedCandidate]:
    """Solve global primary assignment via min-cost flow.

    Builds a bipartite flow network: source → targets → patterns → sink.
    Pattern-to-sink edges have convex costs that minimize concentration and
    cap overflow. Target-to-pattern edges provide canonical candidate-ID
    tie-breaking.

    Complexity: O(N² · (N+M) · E) where N = targets, M = patterns,
    E = edges. Polynomial and feasible for ~49 targets.
    """
    target_count = len(target_ids)
    if target_count == 0:
        return {}

    all_patterns, pattern_idx = _collect_pattern_index(target_choices_map)
    pattern_count = len(all_patterns)
    best_per_tp = _best_candidate_per_target_pattern(target_ids, target_choices_map)
    graph, source, sink = _build_flow_network(
        target_ids,
        target_choices_map,
        best_per_tp,
        pattern_idx,
        max_per_pattern,
        target_count,
        pattern_count,
    )

    total_flow = 0
    node_count = target_count + pattern_count + 2
    while total_flow < target_count:
        path = _spfa_shortest_path(graph, source, sink, node_count)
        if path is None:
            break
        parent_node, parent_edge_idx = path
        _augment_path(graph, source, sink, parent_node, parent_edge_idx)
        total_flow += 1

    return _extract_assignment(
        graph,
        target_count,
        pattern_count,
        target_ids,
        all_patterns,
        best_per_tp,
    )
