"""Coverage analysis for Stage 4 (deterministic, no LLM calls).

Partitions the ICA slots:
- **Structural coverage** — total / non-N/A / N/A / coverage rate
- **By ICA type** — count of non-N/A ICAs per UCA type
- **By controller** — count of non-N/A ICAs per responsibility / coordination link
"""

from __future__ import annotations

from asago_scenario_generator.stpa.models.enriched_threat_set import CoverageAnalysis
from asago_scenario_generator.stpa.models.ica_enumeration import ICASlot, UCAType

__all__ = ["compute_coverage"]


def compute_coverage(slots: list[ICASlot]) -> CoverageAnalysis:
    """Compute coverage analysis from the ICA slots.

    Args:
        slots: All ICA slots (responsibility + coordination link).

    Returns:
        A :class:`CoverageAnalysis` with the slot partitions.
    """
    total_slots = len(slots)
    na_count = sum(1 for s in slots if s.is_na)
    non_na_count = total_slots - na_count

    structural_coverage = {
        "total_slots": total_slots,
        "non_na": non_na_count,
        "na": na_count,
        "coverage_rate": non_na_count / total_slots if total_slots else 0.0,
    }

    return CoverageAnalysis(
        structural_coverage=structural_coverage,
        by_ica_type=_partition_by_ica_type(slots),
        by_controller=_partition_by_controller(slots),
    )


def _partition_by_ica_type(slots: list[ICASlot]) -> dict[str, int]:
    """Count non-N/A ICAs per UCA type."""
    counts: dict[str, int] = {}
    for uca_type in UCAType:
        counts[uca_type.value] = 0
    for slot in slots:
        if slot.is_na:
            continue
        ica_count = len(slot.icas)
        counts[slot.uca_type.value] = counts.get(slot.uca_type.value, 0) + ica_count
    return counts


def _partition_by_controller(slots: list[ICASlot]) -> dict[str, int]:
    """Count non-N/A ICAs per controller (responsibility or coordination link)."""
    counts: dict[str, int] = {}
    for slot in slots:
        if slot.is_na:
            continue
        controller = slot.responsibility or slot.coordination_link or "UNKNOWN"
        ica_count = len(slot.icas)
        counts[controller] = counts.get(controller, 0) + ica_count
    return counts
