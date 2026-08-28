"""Stage 4 — Catalog enrichment (deterministic, no LLM calls).

For each non-N/A ICA, checks whether known OWASP or ATLAS entries
describe the same or similar attack. For each N/A slot, performs an
applicability check: does any catalog technique map to this
``(control_action, UCA_type)`` pair?

Three outcomes:
1. **Mapped** — ICA corresponds to one or more known techniques.
2. **Unmapped** — no catalog correspondent found.
3. **N/A reconciliation** — a catalog technique maps to a slot
   declared N/A (contradiction signal).
"""

from __future__ import annotations

from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.enriched_threat_set import (
    EnrichedThreatSet,
    StructuralThreat,
)
from asago_scenario_generator.stpa.models.ica_enumeration import (
    ICA,
    ICAEnumeration,
    ICASlot,
    UCAType,
)

from .catalog_data import match_catalog
from .coverage import compute_coverage

__all__ = [
    "enrich_threats",
    "reconcile_na_slots",
    "UCA_TYPE_DESCRIPTIONS",
]

# Human-readable descriptions for each UCA type, used in N/A reconciliation.
UCA_TYPE_DESCRIPTIONS: dict[UCAType, str] = {
    UCAType.not_provided: "control action not provided when needed",
    UCAType.incorrect: "control action provided with incorrect value or context",
    UCAType.wrong_timing: "control action provided at wrong time",
    UCAType.wrong_duration: "control action provided for wrong duration",
}


def enrich_threats(
    ica_enumeration: ICAEnumeration,
    control_structure: ControlStructure,
) -> EnrichedThreatSet:
    """Build an enriched threat set from an ICA enumeration.

    For each non-N/A ICA across all slots, creates a
    :class:`StructuralThreat` with catalog mappings. Then runs N/A
    reconciliation and coverage analysis.

    Args:
        ica_enumeration: The ICA enumeration from Stage 3.
        control_structure: The control structure for N/A reconciliation
            context.

    Returns:
        An :class:`EnrichedThreatSet` with structural threats and
        coverage analysis.
    """
    structural_threats: list[StructuralThreat] = []

    for slot in ica_enumeration.slots:
        if slot.is_na:
            continue
        for ica in slot.icas:
            threat = _build_structural_threat(slot, ica)
            structural_threats.append(threat)

    na_reconciliation_flags = reconcile_na_slots(
        ica_enumeration.slots, control_structure
    )

    coverage_analysis = compute_coverage(
        ica_enumeration.slots, structural_threats, na_reconciliation_flags
    )

    return EnrichedThreatSet(
        structural_threats=structural_threats,
        coverage_analysis=coverage_analysis,
    )


def reconcile_na_slots(
    slots: list[ICASlot],
    control_structure: ControlStructure,
) -> list[str]:
    """Flag N/A slots where catalog techniques suggest applicability.

    For each N/A slot, builds a context string from the control action
    description, UCA type description, and N/A justification, then runs
    catalog matching. If a catalog technique maps, flags a contradiction.

    Args:
        slots: All ICA slots.
        control_structure: The control structure for control action
            description lookup.

    Returns:
        A list of flag messages, one per contradiction.
    """
    ca_lookup = _build_ca_description_lookup(control_structure)
    flags: list[str] = []

    for slot in slots:
        if not slot.is_na:
            continue
        ca_desc = ca_lookup.get(slot.control_action, slot.control_action)
        uca_desc = UCA_TYPE_DESCRIPTIONS.get(slot.uca_type, "")
        context = f"{ca_desc} {uca_desc} {slot.na_justification or ''}"
        mappings = match_catalog(context, "")
        if mappings:
            matched_ids = [m.id for m in mappings]
            flags.append(
                f"{slot.slot_id}: declared N/A but catalog matched "
                f"{matched_ids} — contradiction"
            )

    return flags


def _build_structural_threat(slot: ICASlot, ica: ICA) -> StructuralThreat:
    """Build a StructuralThreat from a slot and its ICA."""
    mappings = match_catalog(ica.ica_text, ica.loss_scenario)
    return StructuralThreat(
        ica_slot_id=slot.slot_id,
        provenance="structural",
        ica_id=ica.ica_id,
        ica_text=ica.ica_text,
        hazardous_context=ica.hazardous_context,
        loss_scenario=ica.loss_scenario,
        related_hazards=ica.related_hazards,
        related_constraints=ica.related_constraints,
        catalog_mappings=mappings,
        na_reconciliation_flag=False,
    )


def _build_ca_description_lookup(
    control_structure: ControlStructure,
) -> dict[str, str]:
    """Build a lookup dict from ca_id/cm_id to description."""
    lookup: dict[str, str] = {}
    for resp in control_structure.responsibilities:
        for ca in resp.control_actions:
            lookup[ca.ca_id] = ca.description
    for link in control_structure.coordination_links:
        lookup[link.coordination_mechanism.cm_id] = (
            link.coordination_mechanism.description
        )
    return lookup
