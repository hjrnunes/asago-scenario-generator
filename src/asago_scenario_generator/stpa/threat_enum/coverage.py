"""Coverage analysis for Stage 4 (deterministic, no LLM calls).

Computes a three-way partition of ICA slots:
- **Structural coverage** — total / non-N/A / N/A / coverage rate
- **By ICA type** — count of non-N/A ICAs per UCA type
- **By controller** — count of non-N/A ICAs per responsibility / coordination link
- **Catalog correspondence** — mapped vs unmapped vs catalog-only

Also computes two slot-level eval metrics:
- **Structural consideration** — fraction of slots considered
- **N/A quality** — fraction of N/A justifications citing a structural property
"""

from __future__ import annotations

from asago_scenario_generator.stpa.models.enriched_threat_set import (
    CoverageAnalysis,
    StructuralThreat,
)
from asago_scenario_generator.stpa.models.ica_enumeration import ICASlot, UCAType

from .catalog_data import OWASP_AGENTIC_THREAT_IDS
from .na_quality import check_structural_keywords

__all__ = [
    "compute_coverage",
    "metric_structural_consideration",
    "metric_na_quality",
]


def compute_coverage(
    slots: list[ICASlot],
    structural_threats: list[StructuralThreat],
    na_reconciliation_flags: list[str] | None = None,
) -> CoverageAnalysis:
    """Compute coverage analysis from slots and enriched threats.

    Args:
        slots: All ICA slots (responsibility + coordination link).
        structural_threats: Enriched structural threats (non-N/A ICAs).
        na_reconciliation_flags: Flags from N/A reconciliation.

    Returns:
        A :class:`CoverageAnalysis` with all partitions and metrics.
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

    by_ica_type = _partition_by_ica_type(slots)
    by_controller = _partition_by_controller(slots)

    catalog_correspondence = _compute_catalog_correspondence(structural_threats)

    uncovered_owasp_threats, uncovered_reason = _compute_uncovered_owasp(
        structural_threats
    )

    structural_consideration = metric_structural_consideration(slots)
    na_quality = metric_na_quality(slots)

    return CoverageAnalysis(
        structural_coverage=structural_coverage,
        by_ica_type=by_ica_type,
        by_controller=by_controller,
        catalog_correspondence=catalog_correspondence,
        na_reconciliation_flags=na_reconciliation_flags or [],
        uncovered_owasp_threats=uncovered_owasp_threats,
        uncovered_reason=uncovered_reason,
        structural_consideration=structural_consideration,
        na_quality=na_quality,
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


def _compute_catalog_correspondence(
    structural_threats: list[StructuralThreat],
) -> dict[str, int]:
    """Compute catalog correspondence: mapped vs unmapped vs catalog-only."""
    with_match = sum(1 for t in structural_threats if t.catalog_mappings)
    unmapped = sum(1 for t in structural_threats if not t.catalog_mappings)
    return {
        "structural_with_match": with_match,
        "structural_unmapped": unmapped,
        "catalog_only_supplements": 0,
    }


def _compute_uncovered_owasp(
    structural_threats: list[StructuralThreat],
) -> tuple[list[str], str | None]:
    """Find OWASP Agentic threats with no structural or catalog correspondent."""
    covered_ids = _collect_covered_owasp_ids(structural_threats)
    uncovered = [tid for tid in OWASP_AGENTIC_THREAT_IDS if tid not in covered_ids]

    if not uncovered:
        return [], None
    return uncovered, "No structural slot matched these OWASP agentic threats"


def _collect_covered_owasp_ids(
    structural_threats: list[StructuralThreat],
) -> set[str]:
    """Collect all OWASP Agentic threat IDs covered by structural threats."""
    covered_ids: set[str] = set()
    for threat in structural_threats:
        for mapping in threat.catalog_mappings:
            if mapping.catalog == "OWASP_AGENTIC":
                covered_ids.add(mapping.id)
    return covered_ids


def _is_slot_considered(slot: ICASlot) -> bool:
    """Return True if a slot has ICAs or a justified N/A."""
    return bool(slot.icas) or (
        slot.is_na and check_structural_keywords(slot.na_justification)
    )


def metric_structural_consideration(slots: list[ICASlot]) -> dict:
    """Compute what fraction of slots were considered.

    A slot is "considered" if it has either ICAs or a justified N/A.

    Args:
        slots: All ICA slots.

    Returns:
        A dict with ``total_slots``, ``considered``, ``rate``,
        ``by_ica_type``, and ``by_responsibility``.
    """
    total = len(slots)
    considered = sum(1 for s in slots if _is_slot_considered(s))
    return {
        "total_slots": total,
        "considered": considered,
        "rate": considered / total if total else 0.0,
        "by_ica_type": _breakdown_by_type(slots, _is_slot_considered),
        "by_responsibility": _breakdown_by_resp(slots, _is_slot_considered),
    }


def metric_na_quality(slots: list[ICASlot]) -> dict:
    """Compute fraction of N/A justifications citing a structural property.

    Args:
        slots: All ICA slots.

    Returns:
        A dict with ``na_count``, ``quality_count``, and ``quality_rate``.
        If there are no N/A slots, ``quality_rate`` is ``None``.
    """
    na_slots = [s for s in slots if s.is_na]
    if not na_slots:
        return {"na_count": 0, "quality_rate": None}
    quality_count = sum(
        1 for s in na_slots if check_structural_keywords(s.na_justification)
    )
    return {
        "na_count": len(na_slots),
        "quality_count": quality_count,
        "quality_rate": quality_count / len(na_slots),
    }


def _breakdown_by_type(
    slots: list[ICASlot],
    predicate,
) -> dict[str, int]:
    """Break down considered slots by ICA type."""
    counts: dict[str, int] = {}
    for uca_type in UCAType:
        counts[uca_type.value] = 0
    for slot in slots:
        if predicate(slot):
            counts[slot.uca_type.value] = counts.get(slot.uca_type.value, 0) + 1
    return counts


def _breakdown_by_resp(
    slots: list[ICASlot],
    predicate,
) -> dict[str, int]:
    """Break down considered slots by responsibility."""
    counts: dict[str, int] = {}
    for slot in slots:
        if not predicate(slot):
            continue
        controller = slot.responsibility or slot.coordination_link or "UNKNOWN"
        counts[controller] = counts.get(controller, 0) + 1
    return counts
