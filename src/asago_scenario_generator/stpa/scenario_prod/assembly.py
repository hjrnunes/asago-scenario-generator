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
    responsibility = _find_responsibility(control_structure, controller_id)
    control_action = _find_control_action(responsibility, control_action_id)
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
        control_action_description=control_action.description,
        uca_type=uca_type,
        uca_ref=uca_ref_for(controller_id, control_action_id, uca_type),
        causal_factors=factors,
        temporal_vector=temporal_vector,
        ica_id=ica_id,
        scenario_id=scenario_id,
    )


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-20T10:32:41Z","module_hash":"9445b37b8d9ca755ac4adbbf0959982f453cf1c27ccf79bb3a885945dd06e623","functions":[{"id":"func/assemble_envelope","name":"assemble_envelope","line":45,"end_line":108,"hash":"85e02f9cc6ea6fd619fe565c6899f1abf9c7c29156f3cb8c2df9ac260a986bb0"},{"id":"func/_find_responsibility","name":"_find_responsibility","line":119,"end_line":127,"hash":"e5703d4d5b4be900fd9355108c681ddd49aed0de8250c8b928164f6473a4cea2"},{"id":"func/_find_control_action","name":"_find_control_action","line":130,"end_line":141,"hash":"c5685f93bc5ab728882771670354914868b8d33ee3e132ea87ea3e8ee17fc1dd"},{"id":"func/_collect_source_ids","name":"_collect_source_ids","line":144,"end_line":160,"hash":"4a249f24587d61575b7675765c66188f9430fb14a4b3502810407e69b8b5fb12"},{"id":"func/_validate_causal_factor_sources","name":"_validate_causal_factor_sources","line":163,"end_line":177,"hash":"ae97e621767c3377e0737c996d44193cbdcbf14f153a076aecf1fe83fa824afe"},{"id":"func/assemble_candidate_envelope","name":"assemble_candidate_envelope","line":180,"end_line":238,"hash":"0c59a72323985446a12e22307f51ee28c875dbb9f1742cd49d7ad17fea5d67de"}]}
# mutate4py-manifest-end
