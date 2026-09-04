"""Assemble ScenarioEnvelope from components.

Combines the ScenarioSpec, narrative, attack tree, and Gherkin spec
into a ScenarioEnvelope with faceting metadata.  When a capability
profile and control structure are provided, the envelope is enriched
with ``system_context`` and ``consumer_hints`` blocks.

Also assembles post-SP3 platform-neutral candidate execution envelopes
from structural STPA findings, optionally with their deterministic
temporal action vector.
"""

from __future__ import annotations

from collections.abc import Sequence

from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.stpa.models.causal_factor import (
    CausalFactor,
    validate_factor_sources,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    Responsibility,
)
from asago_scenario_generator.stpa.models.execution_envelope import (
    CandidateExecutionEnvelope,
    candidate_id_for,
    uca_ref_for,
)
from asago_scenario_generator.stpa.models.execution_projection_v2 import (
    ExecutionProjectionV2,
)
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.models.scenario_envelope import (
    ConsumerHints,
    GherkinSpec,
    ScenarioEnvelope,
    SystemContext,
)
from asago_scenario_generator.stpa.models.scenario_spec import ScenarioSpec

from .enrichment import compute_consumer_hints, compute_system_context
from .narrative import derive_temporal_action_vector

__all__ = ["assemble_envelope", "assemble_candidate_envelope"]


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
    execution_projection: ExecutionProjectionV2 | None = None,
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
        narrative: The attack narrative text from Stage 6 Call A.
        attack_tree: The attack tree dict from Stage 6 Call B.
        gherkin_spec: The structured Gherkin spec from Stage 6 Call C.
        gherkin_raw: The raw Gherkin text from Stage 6 Call C.
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
            execution_projection=execution_projection,
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


def _find_responsibility(
    control_structure: ControlStructure,
    controller_id: str,
) -> Responsibility:
    """Look up a responsibility by identifier, raising ValueError when absent."""
    for responsibility in control_structure.responsibilities:
        if responsibility.resp_id == controller_id:
            return responsibility
    raise ValueError(f"Control structure has no responsibility '{controller_id}'.")


def _find_control_action(
    responsibility: Responsibility,
    control_action_id: str,
) -> ControlAction:
    """Look up a control action on a responsibility, raising ValueError."""
    for control_action in responsibility.control_actions:
        if control_action.ca_id == control_action_id:
            return control_action
    raise ValueError(
        f"Responsibility {responsibility.resp_id} has no control action "
        f"'{control_action_id}'."
    )


def assemble_candidate_envelope(
    control_structure: ControlStructure,
    *,
    controller_id: str,
    control_action_id: str,
    uca_type: UCAType,
    causal_factors: Sequence[CausalFactor] | None = None,
    derive_temporal_vector: bool = False,
    ica_id: str | None = None,
    scenario_id: str | None = None,
) -> CandidateExecutionEnvelope:
    """Assemble a platform-neutral candidate execution envelope.

    Maps an unsafe control action and its structural causal factors onto
    a canonical :class:`CandidateExecutionEnvelope`.  The controller and
    control action are resolved against *control_structure* (raising
    ``ValueError`` for unknown identifiers), and every causal factor
    source is validated against the matching PM/FB/CA namespace.

    When *derive_temporal_vector* is true, the deterministic temporal
    action vector is derived from the causal factors and linked to the
    envelope's canonical candidate identifier.  When false, the envelope
    carries no temporal vector (backward compatible default).

    Args:
        control_structure: The control structure the findings come from.
        controller_id: The owning responsibility identifier (RESP-N).
        control_action_id: The targeted control action (CA-X-Y).
        uca_type: The unsafe control action type.
        causal_factors: The mapped structural causal factors in
            causal-factor order.  Defaults to no factors.
        derive_temporal_vector: Whether to derive and link the temporal
            action vector (default: ``False``).

    Returns:
        A :class:`CandidateExecutionEnvelope`.
    """
    if controller_id.startswith("CL-"):
        action_description = _coordination_mechanism_description(
            control_structure, controller_id, control_action_id
        )
    else:
        responsibility = _find_responsibility(control_structure, controller_id)
        control_action = _find_control_action(responsibility, control_action_id)
        action_description = control_action.description
    factors = list(causal_factors or [])
    validate_factor_sources(control_structure, factors)

    temporal_vector = None
    if derive_temporal_vector:
        temporal_vector = derive_temporal_action_vector(
            factors,
            controller_id=controller_id,
            control_action_id=control_action_id,
            uca_type=uca_type,
        )

    return CandidateExecutionEnvelope(
        candidate_id=candidate_id_for(controller_id, control_action_id, uca_type),
        controller_id=controller_id,
        control_action_id=control_action_id,
        control_action_description=action_description,
        uca_type=uca_type,
        uca_ref=uca_ref_for(controller_id, control_action_id, uca_type),
        causal_factors=factors,
        temporal_vector=temporal_vector,
        ica_id=ica_id,
        scenario_id=scenario_id,
    )


def _coordination_mechanism_description(
    control_structure: ControlStructure,
    link_id: str,
    mechanism_id: str,
) -> str:
    """Resolve one exact CL/CM pair for an execution envelope."""
    links = [
        item for item in control_structure.coordination_links if item.link_id == link_id
    ]
    if len(links) != 1:
        raise ValueError(
            f"Control structure has no exact coordination link '{link_id}'."
        )
    link = links[0]
    if link.coordination_mechanism.cm_id != mechanism_id:
        raise ValueError(
            f"Coordination link '{link_id}' has no coordination mechanism '{mechanism_id}'."
        )
    return link.coordination_mechanism.description
