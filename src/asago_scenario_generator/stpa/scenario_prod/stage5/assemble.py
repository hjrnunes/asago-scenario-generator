"""Deterministic assembly of the ScenarioSpec from compiled Stage 5 output."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from asago_scenario_generator.stpa.models.causal_factor import (
    CausalFactor,
    validate_factor_sources,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlStructure,
)
from asago_scenario_generator.stpa.models.enriched_threat_set import StructuralThreat
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.models.scenario_context import (
    ScenarioGenerationContext,
    validate_factor_evidence,
)
from asago_scenario_generator.stpa.models.scenario_spec import (
    DefenderBDI,
    ScenarioSpec,
    ThreatSource,
)
from .wire import (
    CausalFactorDeclaration,
)


def generate_scenario_id(index: int = 0) -> str:
    """Generate a deterministic scenario ID.

    Args:
        index: Zero-based scenario index.

    Returns:
        A scenario ID in the format ``SCN-NNN`` (zero-padded).
    """
    return f"SCN-{index + 1:03d}"


def parse_ica_slot_id(slot_id: str) -> dict[str, str]:
    """Parse an ICA slot ID into its components.

    Supports two identity shapes:
    - ``RESP-X:CA-Y:TYPE-Z`` (responsibility slot)
    - ``CL-X:CM-Y:TYPE-Z`` (coordination link slot)
    - either shape with a fourth explicit action-temporality component

    Args:
        slot_id: The ICA slot ID string.

    Returns:
        A dict with keys ``controller``, ``control_action``, and ``ica_type``.
    """
    parts = slot_id.split(":")
    if len(parts) not in {3, 4} or any(not part for part in parts):
        raise ValueError(f"Invalid ICA slot ID format: {slot_id}")
    return {
        "controller": parts[0],
        "control_action": parts[1],
        "ica_type": parts[2],
    }


@dataclass(frozen=True)
class ScenarioAssembly:
    """The deterministic authority one Stage 5 draft compiles against.

    Assembly writes the compiled vulnerability annotations into
    ``defender_bdi`` in place.
    """

    defender_bdi: DefenderBDI
    threat: StructuralThreat
    control_structure: ControlStructure
    scenario_index: int


class ScenarioAssemblyError(ValueError):
    """The deterministic authority rejected a compiled Stage 5 draft."""


def assemble_scenario_spec(
    assembly: ScenarioAssembly,
    scenario_context: ScenarioGenerationContext,
    *,
    defender_vulnerabilities: Mapping[str, str],
    causal_factors: Sequence[CausalFactorDeclaration],
    **compiled_fields: Any,
) -> ScenarioSpec:
    """Assemble a ScenarioSpec from compiled Stage 5 output.

    The defender BDI IDs are NOT trusted from the provider: the deterministic
    values are kept, and vulnerabilities attach by matching the original
    ``pm_id`` values. Declared causal factors keep their declared order,
    evidence, and temporal conditions; every factor reference is validated
    against the control structure and the selected control path, so
    unbacked structural presence never invents a factor. The context is the
    only authority for the hazard and constraint lineage.

    ``compiled_fields`` are the remaining provider-derived ScenarioSpec
    fields, passed through unchanged.

    Raises:
        ScenarioAssemblyError: When the authority rejects the compiled draft.
    """
    try:
        return _assemble(
            assembly,
            scenario_context,
            defender_vulnerabilities,
            causal_factors,
            compiled_fields,
        )
    except ValueError as exc:
        raise ScenarioAssemblyError(str(exc)) from exc


def _assemble(
    assembly: ScenarioAssembly,
    context: ScenarioGenerationContext,
    defender_vulnerabilities: Mapping[str, str],
    declarations: Sequence[CausalFactorDeclaration],
    compiled_fields: Mapping[str, Any],
) -> ScenarioSpec:
    threat = assembly.threat
    slot_parts = parse_ica_slot_id(threat.ica_slot_id)
    _validate_context_matches_threat(context, threat, assembly.scenario_index)
    _merge_defender_vulnerabilities(assembly.defender_bdi, defender_vulnerabilities)
    causal_factors = _materialize_causal_factors(declarations)
    _validate_assembled_factors(causal_factors, assembly.control_structure, context)
    return ScenarioSpec(
        scenario_id=generate_scenario_id(assembly.scenario_index),
        threat_source=ThreatSource(
            ica_slot_id=threat.ica_slot_id,
            provenance=threat.provenance,
            ica_id=threat.ica_id,
        ),
        target_controller=slot_parts["controller"],
        target_control_action=slot_parts["control_action"],
        ica_type=UCAType(slot_parts["ica_type"]),
        defender_bdi=assembly.defender_bdi,
        catalog_context=threat.catalog_mappings,
        loss_scenario=threat.loss_scenario,
        causal_factors=causal_factors,
        unsafe_outcome_hazard_refs=[item.hazard_id for item in context.hazards],
        unsafe_outcome_constraint_refs=[
            item.constraint_id for item in context.constraints
        ],
        scenario_context=context,
        **compiled_fields,
    )


def _validate_context_matches_threat(
    context: ScenarioGenerationContext,
    threat: StructuralThreat,
    scenario_index: int,
) -> None:
    """Reject an attempt to assemble provider output under different authority."""
    if _context_threat_identity(context) != _threat_identity(threat, scenario_index):
        raise ValueError("scenario context does not match selected structural threat")


def _context_threat_identity(
    context: ScenarioGenerationContext,
) -> tuple[str, str | None, str, str, str, str]:
    """Return the context identity fields used for threat pinning."""
    identity = context.scenario_identity
    return (
        identity.scenario_id,
        identity.ica_id,
        identity.ica_slot_id,
        context.ica.exact_ica_text,
        context.ica.hazardous_context,
        context.ica.loss_consequence,
    )


def _threat_identity(
    threat: StructuralThreat,
    scenario_index: int,
) -> tuple[str, str | None, str, str, str, str]:
    """Return the threat identity in the context comparison order."""
    return (
        generate_scenario_id(scenario_index),
        threat.ica_id,
        threat.ica_slot_id,
        threat.ica_text,
        threat.hazardous_context,
        threat.loss_scenario,
    )


def _merge_defender_vulnerabilities(
    defender_bdi: DefenderBDI,
    vulnerabilities: Mapping[str, str],
) -> None:
    """Attach compiled vulnerability prose to deterministic belief IDs."""
    for belief in defender_bdi.beliefs:
        belief.vulnerability = vulnerabilities.get(belief.pm_id, "")


def _materialize_causal_factors(
    declarations: Sequence[CausalFactorDeclaration],
) -> list[CausalFactor]:
    """Compile the declared Stage 5 factor records without inference."""
    return [
        CausalFactor(
            kind=declaration.kind,
            source_id=declaration.source_id,
            description=declaration.evidence,
            evidence_status=declaration.evidence_status,
            capability_refs=declaration.capability_refs,
            access_refs=declaration.access_refs,
            bounded_assumption=declaration.bounded_assumption,
            temporal_condition=declaration.temporal_condition,
        )
        for declaration in declarations
    ]


def _validate_assembled_factors(
    causal_factors: list[CausalFactor],
    control_structure: ControlStructure,
    context: ScenarioGenerationContext,
) -> None:
    """Validate factor references against the structure and the context."""
    validate_factor_sources(control_structure, causal_factors)
    validate_factor_evidence(context, causal_factors)
    _validate_context_factor_sources(context, causal_factors)


def _validate_context_factor_sources(
    context: ScenarioGenerationContext,
    causal_factors: list[CausalFactor],
) -> None:
    """Keep every declared cause inside the selected control-path slice."""
    path = context.target_control_path
    allowed = {
        *(item.element_id for item in path.process_model_parts),
        *(item.element_id for item in path.feedback),
        path.control_action.action_id,
        *(item.action_id for item in path.related_control_actions),
    }
    for factor in causal_factors:
        if factor.source_id not in allowed:
            raise ValueError(
                f"Causal factor source {factor.source_id!r} is outside the "
                "selected scenario control path."
            )
