"""Published evidence-model status for the supplied inventories.

The evidence model distinguishes three inventory states that a naive
artifact would conflate:

- ``unknown`` — no inventory was supplied, or the supplied profile declares
  its inventory unknown. Stage 1 inference establishes presence, never
  absence, so a derived profile with no observed tools is also unknown.
- ``explicitly_empty`` — a caller supplied a profile whose tool inventory is
  explicitly empty.
- ``supplied`` — a caller supplied a non-empty inventory.

The synthesis manifest publishes this classification so a reviewer can see
the difference between "nothing was supplied" and "the target has no tools".
Conflicting supplied facts follow the same discipline: both values stay
visible with their sources and a conflict marking; nothing silently adopts
one reading.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

#: Manifest marking carried beside every published conflict.
CONFLICT_MARKING = "conflict_unresolved"


class EvidenceInventoryStatus(BaseModel):
    """Deterministic, published inventory status for one run."""

    model_config = ConfigDict(frozen=True)

    tool_inventory_status: Literal["unknown", "explicitly_empty", "supplied"]
    tool_inventory_count: int | None = None
    tool_inventory_completeness: str | None = None
    operation_inventory_status: Literal["unknown", "supplied"] = "unknown"
    operation_inventory_count: int | None = None
    note: str = ""


def classify_evidence_inventory(
    *,
    profile_supplied: bool,
    capability_profile: Any,
    execution_target_profile: Any,
) -> EvidenceInventoryStatus:
    """Classify the run's supplied tool and operation inventories.

    ``profile_supplied`` is True when the caller supplied the capability
    profile (file or typed snapshot) and False when Stage 1b derived it. A
    derived profile never establishes that the target has no tools, so its
    empty observed inventory stays unknown.
    """
    inventory = getattr(capability_profile, "tool_inventory", None)
    completeness = getattr(capability_profile, "tool_inventory_completeness", None)

    if not profile_supplied:
        status: Literal["unknown", "explicitly_empty", "supplied"] = "unknown"
        count = None
        note = (
            "No capability profile was supplied; the Stage 1 inference "
            "establishes presence, never absence, so the tool inventory is "
            "recorded as unknown (distinct from an explicitly supplied "
            "empty inventory)."
        )
    elif inventory is None:
        status = "unknown"
        count = None
        note = (
            "The supplied capability profile declares its tool inventory "
            "unknown rather than empty."
        )
    elif len(inventory) == 0:
        status = "explicitly_empty"
        count = 0
        note = (
            "The supplied capability profile declares an explicitly empty "
            "tool inventory, which is distinct from an unknown inventory."
        )
    else:
        status = "supplied"
        count = len(inventory)
        note = "The supplied capability profile names its tool inventory."

    operations = getattr(execution_target_profile, "resources", None)
    operation_count = (
        sum(len(getattr(r, "operations", ()) or ()) for r in operations)
        if operations
        else 0
    )
    return EvidenceInventoryStatus(
        tool_inventory_status=status,
        tool_inventory_count=count,
        tool_inventory_completeness=(
            getattr(completeness, "value", completeness)
            if completeness is not None
            else None
        ),
        operation_inventory_status="supplied" if operations else "unknown",
        operation_inventory_count=operation_count if operations else None,
        note=note,
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
