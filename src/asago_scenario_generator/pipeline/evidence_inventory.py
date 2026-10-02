"""Published evidence-model status for the run's inventories.

The synthesis run always derives its capability profile through Stage 1
inference, which establishes presence, never absence. The tool inventory is
therefore always published as ``unknown``, never as empty. The status
vocabulary keeps ``explicitly_empty`` and ``supplied`` so the published
contract still distinguishes "nothing was supplied" from "the target has no
tools". The operation inventory follows the execution target profile.
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
    capability_profile: Any,
    execution_target_profile: Any,
) -> EvidenceInventoryStatus:
    """Classify the run's tool and operation inventories.

    The capability profile is always derived by Stage 1 inference. A derived
    profile never establishes that the target has no tools, so its tool
    inventory stays unknown whatever it lists.
    """
    completeness = getattr(capability_profile, "tool_inventory_completeness", None)

    operations = getattr(execution_target_profile, "resources", None)
    operation_count = (
        sum(len(getattr(r, "operations", ()) or ()) for r in operations)
        if operations
        else 0
    )
    return EvidenceInventoryStatus(
        tool_inventory_status="unknown",
        tool_inventory_count=None,
        tool_inventory_completeness=(
            getattr(completeness, "value", completeness)
            if completeness is not None
            else None
        ),
        operation_inventory_status="supplied" if operations else "unknown",
        operation_inventory_count=operation_count if operations else None,
        note=(
            "No capability profile was supplied; the Stage 1 inference "
            "establishes presence, never absence, so the tool inventory is "
            "recorded as unknown (distinct from an explicitly supplied "
            "empty inventory)."
        ),
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
