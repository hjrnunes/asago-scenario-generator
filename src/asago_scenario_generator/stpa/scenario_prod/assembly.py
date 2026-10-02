"""Assemble ScenarioEnvelope from components.

Combines the ScenarioSpec, narrative, attack tree, and Gherkin spec
into a ScenarioEnvelope with faceting metadata.  When a capability
profile and control structure are provided, the envelope is enriched
with ``system_context`` and ``consumer_hints`` blocks.
"""

from __future__ import annotations


from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.stpa.models.control_structure import (
    ControlStructure,
)
from asago_scenario_generator.stpa.models.scenario_envelope import (
    ConsumerHints,
    GherkinSpec,
    ScenarioEnvelope,
    SystemContext,
)
from asago_scenario_generator.stpa.models.scenario_spec import ScenarioSpec

from .enrichment import compute_consumer_hints, compute_system_context

__all__ = ["assemble_envelope"]


def assemble_envelope(
    scenario_id: str,
    scenario_spec: ScenarioSpec,
    narrative: str,
    attack_tree: dict,
    gherkin_spec: GherkinSpec,
    gherkin_raw: str = "",
    capability_profile: CapabilityProfile | None = None,
    control_structure: ControlStructure | None = None,
    primary_attack_zone: str | None = None,
) -> ScenarioEnvelope:
    """Assemble a ScenarioEnvelope from its components.

    When *capability_profile* and *control_structure* are both provided,
    the envelope is enriched with ``system_context`` and
    ``consumer_hints`` blocks computed deterministically (no LLM calls).
    When either is ``None``, both enrichment blocks are left as ``None``
    (backward compatibility).

    Args:
        scenario_id: The scenario ID (must match scenario_spec.scenario_id).
        scenario_spec: The scenario specification from Stage 5.
        narrative: The Stage 6 summary narrative text.
        attack_tree: The Stage 6 summary attack tree dict.
        gherkin_spec: The Stage 6 summary structured Gherkin spec.
        gherkin_raw: The Stage 6 summary Gherkin feature text.
        capability_profile: Optional SP1 capability profile for enrichment.
        control_structure: Optional SP1 control structure for enrichment.
        primary_attack_zone: Optional primary attack zone for consumer
            hints.  Defaults to ``"input"`` when enrichment is active
            but no zone is specified.

    Returns:
        A :class:`ScenarioEnvelope`.
    """
    system_context: SystemContext | None = None
    consumer_hints: ConsumerHints | None = None

    if capability_profile is not None and control_structure is not None:
        system_context = compute_system_context(
            capability_profile, control_structure, scenario_spec
        )
        zone = primary_attack_zone if primary_attack_zone is not None else "input"
        consumer_hints = compute_consumer_hints(
            capability_profile=capability_profile,
            attack_tree=attack_tree,
            narrative=narrative,
            primary_attack_zone=zone,
        )

    return ScenarioEnvelope(
        scenario_id=scenario_id,
        scenario_spec=scenario_spec,
        narrative=narrative,
        attack_tree=attack_tree,
        gherkin_spec=gherkin_spec,
        gherkin_raw=gherkin_raw,
        target_responsibility=scenario_spec.target_controller,
        ica_type=scenario_spec.ica_type,
        catalog_mappings=scenario_spec.catalog_context,
        provenance=scenario_spec.threat_source.provenance,
        system_context=system_context,
        consumer_hints=consumer_hints,
    )
