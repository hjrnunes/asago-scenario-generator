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
    distances[source] = 0.0
    in_queue = [False] * node_count
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


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-26T13:49:23Z","module_hash":"4f89f079cfb9961b106efebcae5f7e22847a2b9b9be1c1a4de06c1858a2e8c61","source_sha256":"9e71e54b48f5ec6bbcdec9654061e134a9ac3713782ab8b743c9fd12a0cca13b","functions":[{"id":"func/add_edge","name":"add_edge","line":12,"end_line":15,"hash":"7b4d0a9b1032f745758e638504d061c79988891ab8f3354114fa7da289be4828"},{"id":"func/_collect_pattern_index","name":"_collect_pattern_index","line":18,"end_line":26,"hash":"8e93ffefd351b081b1a3bac7b968a162e285550d18ad061469611a69ec883efe"},{"id":"func/_best_candidate_per_target_pattern","name":"_best_candidate_per_target_pattern","line":29,"end_line":43,"hash":"987dfa10754a1e89e6041da60274ad63b9297ab990247846175e52f2548910bd"},{"id":"func/_convex_pattern_cost","name":"_convex_pattern_cost","line":46,"end_line":61,"hash":"b9cb63dc8f84c07624bb2c2982d75e1ba02571381eb411bd5959fe5856da8ef2"},{"id":"func/_add_target_pattern_edges","name":"_add_target_pattern_edges","line":64,"end_line":86,"hash":"19a4e9b7794f9233c546e642addbd7ed5485d3e3ff610a9baa13bc133ec88bb8"},{"id":"func/_add_pattern_sink_edges","name":"_add_pattern_sink_edges","line":89,"end_line":113,"hash":"bfd842296e4d8bdeea7602d8ccc907de112efdd59d0bfd082457a821afb2e3d7"},{"id":"func/_build_flow_network","name":"_build_flow_network","line":116,"end_line":155,"hash":"46a79ddd32d926ec7bcc7cf14e22761b7bcc2513c11db47886495e056def3131"},{"id":"func/_relax_node","name":"_relax_node","line":158,"end_line":176,"hash":"d9c1dae17d393330ae38aaa54cf88a5193c2339f7defb8960d8de8e80ecb2b3a"},{"id":"func/_spfa_shortest_path","name":"_spfa_shortest_path","line":179,"end_line":212,"hash":"67f4127a7623c86efb7b38eac8ca8d0af8d8543b1f5dcf262b33c962f869dcc6"},{"id":"func/_augment_path","name":"_augment_path","line":215,"end_line":230,"hash":"208d88cb4f24560bcf799e1c524085b339d6546199c617c0b2a0769f9e10a360"},{"id":"func/_flowing_pattern_edge","name":"_flowing_pattern_edge","line":233,"end_line":238,"hash":"03d18156a3ffffe2906dc7e8224843cf2987199ef4d4270d40f5b6289eecbef4"},{"id":"func/_extract_assignment","name":"_extract_assignment","line":241,"end_line":258,"hash":"73c6851bb59a211387c023eed3189525da0e0a671d8862544bbe7814782a320c"},{"id":"func/_solve_min_cost_assignment","name":"_solve_min_cost_assignment","line":261,"end_line":310,"hash":"746a62ae483127701064f2f99aaba3ec8bc20fc7ec8bce52bd6e1e43f88c4ec5"}]}
# mutate4py-manifest-end
