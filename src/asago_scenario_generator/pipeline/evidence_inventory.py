"""Published evidence-model status for the run's supplied inputs.

The operation inventory follows the execution target profile: without one it
is ``unknown``, never empty. Conflicting supplied facts follow the same
discipline: both values stay visible with their sources and a conflict
marking; nothing silently adopts one reading.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

#: Manifest marking carried beside every published conflict.
CONFLICT_MARKING = "conflict_unresolved"


class EvidenceInventoryStatus(BaseModel):
    """Deterministic, published operation inventory status for one run."""

    model_config = ConfigDict(frozen=True)

    operation_inventory_status: Literal["unknown", "supplied"] = "unknown"
    operation_inventory_count: int | None = None


def classify_evidence_inventory(
    *,
    execution_target_profile: Any,
) -> EvidenceInventoryStatus:
    """Classify the run's operation inventory from its execution target profile."""
    operations = getattr(execution_target_profile, "resources", None)
    operation_count = (
        sum(len(getattr(r, "operations", ()) or ()) for r in operations)
        if operations
        else 0
    )
    return EvidenceInventoryStatus(
        operation_inventory_status="supplied" if operations else "unknown",
        operation_inventory_count=operation_count if operations else None,
    )


def conflicting_fact_readings(qualification_facts: Any) -> list[dict[str, Any]]:
    """Return one published record per contradictory supplied fact.

    Each record retains every supplied reading with its value and source
    under an explicit conflict marking. Facts the supplier marked
    contradictory without retained readings still appear, with the marking
    and no invented value.
    """
    if qualification_facts is None:
        return []
    facts = getattr(qualification_facts, "facts", None) or {}
    conflicts: list[dict[str, Any]] = []
    for key in sorted(facts):
        fact = facts[key]
        if getattr(fact, "status", None) != "contradictory":
            continue
        reference = getattr(fact, "fact", None)
        readings = [
            {"value": reading.value, "source": reading.source}
            for reading in (getattr(fact, "readings", ()) or ())
        ]
        conflicts.append(
            {
                "fact": reference.model_dump(mode="json") if reference else key,
                "status": "contradictory",
                "readings": readings,
                "marking": CONFLICT_MARKING,
            }
        )
    return conflicts
