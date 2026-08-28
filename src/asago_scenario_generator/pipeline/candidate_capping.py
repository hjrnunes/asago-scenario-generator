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
