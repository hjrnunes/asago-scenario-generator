"""The Stage 5 assembly authority, built the way the stage runner builds it."""

from __future__ import annotations

from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.enriched_threat_set import StructuralThreat
from asago_scenario_generator.stpa.models.scenario_context import (
    ScenarioGenerationContext,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.assemble import (
    ScenarioAssembly,
    parse_ica_slot_id,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.defender import (
    populate_defender_bdi,
)


def stage5_assembly(
    context: ScenarioGenerationContext,
    threat: StructuralThreat,
    control_structure: ControlStructure,
) -> ScenarioAssembly:
    """Return the authority a context built from ``threat`` assembles against.

    The scenario index comes from the context's ``SCN-NNN`` identity, so a
    context with any other identity cannot assemble.
    """
    controller = parse_ica_slot_id(threat.ica_slot_id)["controller"]
    scenario_id = context.scenario_identity.scenario_id
    return ScenarioAssembly(
        populate_defender_bdi(control_structure, controller, context.constraints),
        threat,
        control_structure,
        int(scenario_id.removeprefix("SCN-")) - 1,
    )
