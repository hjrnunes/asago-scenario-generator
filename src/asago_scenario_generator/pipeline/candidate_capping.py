"""Filtered-seed capping and deduplication implementations."""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Sequence

from asago_scenario_generator.pipeline.candidate_models import (
    CandidateOrigin,
    FilteredSeed,
    StageRecord,
    _canonicalize_and_dedup_origins,
    _non_provenance_conflicts,
)

logger = logging.getLogger("asago_scenario_generator.pipeline.candidates")

# ---------------------------------------------------------------------------
# Post-filter: cap scenarios per attack pattern
# ---------------------------------------------------------------------------


def cap_scenarios_per_pattern(
    filtered_seeds: Sequence[FilteredSeed],
    max_per_pattern: int,
    stage_records: list[StageRecord] | None = None,
) -> list[FilteredSeed]:
    """Cap the number of filtered seeds per attack pattern (seed_id).

    When a group exceeds ``max_per_pattern``, seeds are selected using
    greedy marginal coverage that balances both technique and entry-point
    diversity.

    At each selection step the candidate with the highest score is picked::

        score = (count of technique IDs NOT yet covered by selected set)
              + (1 if entry point NOT yet seen in selected set)

    Ties are broken by technique-combo size (prefer larger combos), then
    by original encounter order (lower index wins).

    This ensures dual-technique candidates float to the top early (more
    new technique ground), while single-technique candidates fill
    entry-point diversity once technique coverage is saturated.

    A warning is logged for every capped group.

    Args:
        filtered_seeds: Output of :func:`filter_candidates`.
        max_per_pattern: Maximum number of seeds to keep per ``seed_id``.

    Returns:
        A new list of :class:`FilteredSeed` with groups truncated as needed.
    """
    if max_per_pattern < 1:
        raise ValueError("max_per_pattern must be >= 1")

    # Group by seed_id (attack pattern), preserving encounter order.
    groups: dict[str, list[FilteredSeed]] = defaultdict(list)
    for fs in filtered_seeds:
        groups[fs.seed_id].append(fs)

    result: list[FilteredSeed] = []
    for seed_id, group in groups.items():
        if len(group) <= max_per_pattern:
            result.extend(group)
            continue

        selected = _greedy_coverage_selection(group, max_per_pattern)

        logger.warning(
            "Capped %s from %d to %d scenarios (--max-scenarios-per-pattern)",
            seed_id,
            len(group),
            len(selected),
        )
        result.extend(selected)

    # Canonicalize and deduplicate after capping — although capping
    # selects a subset, canonicalization ensures no duplicate identities
    # persist through the selection transform.
    pre_dedup_count = len(result)
    result = _dedup_filtered_seeds(result)
    if stage_records is not None:
        stage_records.append(
            StageRecord(
                stage="capping",
                input_count=pre_dedup_count,
                output_count=len(result),
                collapsed_count=pre_dedup_count - len(result),
            )
        )

    return result


def _greedy_coverage_selection(
    group: list[FilteredSeed], max_per_pattern: int
) -> list[FilteredSeed]:
    """Greedy marginal-coverage selection over one over-cap group."""
    covered_techniques: set[str] = set()
    seen_entry_points: set[str] = set()
    selected: list[FilteredSeed] = []
    remaining_indices: list[int] = list(range(len(group)))

    while len(selected) < max_per_pattern and remaining_indices:
        best_idx = max(
            remaining_indices,
            key=lambda idx: _marginal_score(
                group[idx], covered_techniques, seen_entry_points, idx
            ),
        )
        chosen = group[best_idx]
        selected.append(chosen)
        covered_techniques.update(chosen.pinned_technique_ids)
        seen_entry_points.add(chosen.entry_point_id)
        remaining_indices.remove(best_idx)

    return selected


def _marginal_score(
    fs: FilteredSeed,
    covered_techniques: set[str],
    seen_entry_points: set[str],
    idx: int,
) -> tuple[int, int, int]:
    """(marginal coverage, combo size, -index) score tuple."""
    new_techniques = sum(
        1 for t in fs.pinned_technique_ids if t not in covered_techniques
    )
    new_entry_point = 1 if fs.entry_point_id not in seen_entry_points else 0
    marginal = new_techniques + new_entry_point
    combo_size = len(fs.pinned_technique_ids)
    # Score tuple: (marginal coverage, combo size, -index for stable ordering)
    return (marginal, combo_size, -idx)


def _dedup_filtered_seeds(
    filtered_seeds: list[FilteredSeed],
) -> list[FilteredSeed]:
    """Deduplicate FilteredSeeds by canonical identity.

    Groups by ``(seed_id, entry_point_id, sorted unique pinned_technique_ids)``
    and merges origins when duplicates are found.
    """
    if not filtered_seeds:
        return []

    groups: dict[tuple[str, str, tuple[str, ...]], list[FilteredSeed]] = defaultdict(
        list
    )
    for fs in filtered_seeds:
        groups[_filtered_seed_key(fs)].append(fs)

    result: list[FilteredSeed] = []
    for group in groups.values():
        if len(group) == 1:
            result.append(group[0])
            continue
        result.append(_merged_filtered_seed(group))

    return result


def _filtered_seed_key(fs: FilteredSeed) -> tuple[str, str, tuple[str, ...]]:
    """Canonical dedup identity of one filtered seed."""
    return (
        fs.seed_id,
        fs.entry_point_id,
        tuple(sorted(set(fs.pinned_technique_ids))),
    )


def _merged_filtered_seed(group: list[FilteredSeed]) -> FilteredSeed:
    """Merge duplicate filtered seeds: canonical origins, conflict-free."""
    all_origins: list[CandidateOrigin] = []
    for fs in group:
        all_origins.extend(fs.origins)
    unique_origins = _canonicalize_and_dedup_origins(all_origins)
    template, *others = group
    _non_provenance_conflicts(template, others, _FILTERED_NON_PROV_FIELDS)
    return template.model_copy(update={"origins": unique_origins})


_FILTERED_NON_PROV_FIELDS = (
    "seed_id",
    "threat_id",
    "threat_name",
    "attack_pattern_name",
    "attack_pattern_description",
    "entry_point_id",
    "risk_card_ref",
    "owasp_llm_ids",
    "agentic_threat_ids",
)


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-26T20:57:36Z","module_hash":"8599b9c4c52badb6fc56bf3cb10adb36433c2ebd06d0e155b89fa7dd819e1d62","source_sha256":"f056a42ba84fc313400a182af2f70ac72c69133c7254a60a04a831624162d006","functions":[{"id":"func/cap_scenarios_per_pattern","name":"cap_scenarios_per_pattern","line":24,"end_line":95,"hash":"83c6d7e338873295ab4b2bafc84532cee06e6fb0568a00861af3e2172831054a"},{"id":"func/_greedy_coverage_selection","name":"_greedy_coverage_selection","line":98,"end_line":120,"hash":"d96c993ad22db57b7be4f87000be0b5b08a1f9a4d1fb3d2ad86ecdb70b3b2156"},{"id":"func/_marginal_score","name":"_marginal_score","line":123,"end_line":137,"hash":"7d61f929f1a7ae24e2e70992080ffa13ced969736b9b6e2ef456b34b9d9a10ea"},{"id":"func/_dedup_filtered_seeds","name":"_dedup_filtered_seeds","line":140,"end_line":164,"hash":"5aac85a792c474d656183673cdb405815951415df6d3380e06dbd82792962c56"},{"id":"func/_filtered_seed_key","name":"_filtered_seed_key","line":167,"end_line":173,"hash":"7b9560358e188f7e90a20ebda4c3847952092fc8ca4c654acc99f9ccd01d8800"},{"id":"func/_merged_filtered_seed","name":"_merged_filtered_seed","line":176,"end_line":184,"hash":"6431558cc6a7576aaafd90d607768bded97b169be7eae76d28fb6c679cd96243"}]}
# mutate4py-manifest-end
