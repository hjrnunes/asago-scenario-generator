"""Stage 4 — structural threat list (deterministic, no LLM calls).

Turns the ICA enumeration into the list of structural threats that feeds
scenario production, one per ICA in a slot that is not N/A, in slot order,
and counts the slots. A threat carries the ICA text and its hazard and
constraint links, and no ATLAS or OWASP label.
"""

from __future__ import annotations

from asago_scenario_generator.stpa.models.enriched_threat_set import (
    EnrichedThreatSet,
    StructuralThreat,
)
from asago_scenario_generator.stpa.models.ica_enumeration import (
    ICA,
    ICAEnumeration,
    ICASlot,
)

from .coverage import compute_coverage

__all__ = ["enrich_threats"]


def enrich_threats(ica_enumeration: ICAEnumeration) -> EnrichedThreatSet:
    """Build the structural threat list and slot coverage from an ICA enumeration.

    Args:
        ica_enumeration: The ICA enumeration from Stage 3.

    Returns:
        An :class:`EnrichedThreatSet` with one structural threat per ICA of
        each non-N/A slot and the slot coverage counts.
    """
    structural_threats = [
        _build_structural_threat(slot, ica)
        for slot in ica_enumeration.slots
        if not slot.is_na
        for ica in slot.icas
    ]
    return EnrichedThreatSet(
        structural_threats=structural_threats,
        coverage_analysis=compute_coverage(ica_enumeration.slots),
    )


def _build_structural_threat(slot: ICASlot, ica: ICA) -> StructuralThreat:
    """Build a StructuralThreat from a slot and its ICA."""
    return StructuralThreat(
        ica_slot_id=slot.slot_id,
        provenance="structural",
        ica_id=ica.ica_id,
        ica_text=ica.ica_text,
        hazardous_context=ica.hazardous_context,
        loss_scenario=ica.loss_scenario,
        related_hazards=ica.related_hazards,
        related_constraints=ica.related_constraints,
    )
