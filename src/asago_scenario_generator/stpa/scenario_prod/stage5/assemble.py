"""Deterministic assembly of the ScenarioSpec from a Stage 5 result."""

from __future__ import annotations

from collections.abc import Sequence
from asago_scenario_generator.stpa.models.causal_factor import (
    CausalFactor,
    validate_factor_sources,
)
from asago_scenario_generator.stpa.models.semantic_conditions import (
    SemanticCondition,
)
from asago_scenario_generator.stpa.models.execution_classification import (
    SemanticExecutionContract,
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
    BDIGenerationResult,
)
from .validate import (
    _validate_unsafe_outcome_for_target,
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


def assemble_scenario_spec(
    defender_bdi: DefenderBDI,
    llm_result: BDIGenerationResult,
    threat: StructuralThreat,
    control_structure: ControlStructure,
    scenario_index: int = 0,
    *,
    scenario_context: ScenarioGenerationContext | None = None,
) -> ScenarioSpec:
    """Assemble a ScenarioSpec from the defender BDI and LLM result.

    Merges vulnerability annotations into the defender BDI and combines
    with the attacker BDI. The defender BDI IDs are NOT trusted from the
    LLM — the original deterministic values are used, and vulnerabilities
    are extracted by matching to the original pm_id values.

    Declared causal factors are selected in declared order with their
    evidence descriptions and optional timing; every factor reference is
    validated against the control structure (a ``ValueError`` names the
    invalid causal-factor reference) so unbacked structural presence
    never invents a factor.

    Args:
        defender_bdi: Pre-populated defender BDI (will be mutated in place).
        llm_result: The LLM generation result.
        threat: The structural threat.
        control_structure: The full control structure.
        scenario_index: Zero-based index for scenario ID generation.

    Returns:
        A :class:`ScenarioSpec`.
    """
    slot_parts = parse_ica_slot_id(threat.ica_slot_id)
    _validate_optional_assembly_context(scenario_context, threat, scenario_index)
    _merge_defender_vulnerabilities(defender_bdi, llm_result)
    causal_factors = _materialize_causal_factors(llm_result)
    _validate_assembled_factors(causal_factors, control_structure, scenario_context)
    # The normal semantics-only wire materializes no contract and no
    # executable condition, so the contract validator does not apply to it.
    # An executable condition marks a historical execution-designed
    # assembly, which must retain its exact contract; a hybrid result (no
    # condition but a supplied contract) keeps the delivery/basis checks.
    if _carries_execution_design(llm_result) or (
        llm_result.execution_contract is not None
    ):
        _validate_assembled_execution_contract(
            llm_result.execution_contract,
            causal_factors,
            scenario_context,
        )
    unsafe_condition = _validated_unsafe_condition(
        llm_result, UCAType(slot_parts["ica_type"]), slot_parts["control_action"]
    )
    if scenario_context is not None:
        # Context is the only authoritative source for selected consequence
        # lineage.  The contextual provider wire carries descriptions only;
        # deterministic assembly derives the exact IDs here.
        hazard_refs = [item.hazard_id for item in scenario_context.hazards]
        constraint_refs = [item.constraint_id for item in scenario_context.constraints]
    else:
        hazard_refs, constraint_refs = _unsafe_outcome_refs(llm_result, threat)

    return ScenarioSpec(
        scenario_id=generate_scenario_id(scenario_index),
        threat_source=ThreatSource(
            ica_slot_id=threat.ica_slot_id,
            provenance=threat.provenance,
            ica_id=threat.ica_id,
        ),
        target_controller=slot_parts["controller"],
        target_control_action=slot_parts["control_action"],
        ica_type=UCAType(slot_parts["ica_type"]),
        defender_bdi=defender_bdi,
        attacker_bdi=llm_result.attacker_bdi,
        catalog_context=threat.catalog_mappings,
        loss_scenario=threat.loss_scenario,
        causal_factors=causal_factors,
        unsafe_outcome_condition=unsafe_condition,
        unsafe_outcome_semantic_proposition=(
            llm_result.unsafe_outcome.semantic_proposition
            if llm_result.unsafe_outcome is not None
            else None
        ),
        unsafe_outcome_hazard_refs=hazard_refs,
        unsafe_outcome_constraint_refs=constraint_refs,
        scenario_context=scenario_context,
        execution_contract=llm_result.execution_contract,
        adversary=llm_result.adversary,
        observation_criteria=llm_result.observation_criteria,
        observation_assessment=llm_result.observation_assessment,
        observation_contract_id=llm_result.observation_contract_id,
        observation_contract_digest=llm_result.observation_contract_digest,
        safe_observable_outcome=llm_result.safe_observable_outcome,
        discriminating_condition=llm_result.discriminating_condition,
        condition_check=llm_result.condition_check,
        condition_omitted_reason=llm_result.condition_omitted_reason,
        tool_call_condition_status=llm_result.tool_call_condition_status,
        tool_call_condition=llm_result.tool_call_condition,
    )


def _carries_execution_design(llm_result: BDIGenerationResult) -> bool:
    """Return True when the result materialized an executable outcome condition.

    The normal semantics-only wire materializes ``condition=None`` and no
    execution contract.  An executable condition marks a historical
    execution-designed assembly, which must retain its exact contract.
    """
    return (
        llm_result.unsafe_outcome is not None
        and llm_result.unsafe_outcome.condition is not None
    )


def _validate_assembled_execution_contract(
    contract: SemanticExecutionContract | None,
    causal_factors: Sequence[CausalFactor],
    context: ScenarioGenerationContext | None,
) -> None:
    """Require execution-designed contextual assembly to retain its contract.

    The normal product wire requests no execution design, so its
    semantics-only assembly (no contract, no executable condition) never
    reaches this validator.  An execution-designed contextual assembly
    without a contract is a historical-path bug and fails closed; a supplied
    contract (historical execution callers) still must retain an exact
    delivery/factor binding.
    """
    if context is None:
        return
    if contract is None:
        raise ValueError("corrected Stage 5 output must include execution_contract")
    _validate_assembled_delivery_factor(contract, causal_factors)


def _validate_assembled_delivery_factor(
    contract: SemanticExecutionContract,
    causal_factors: Sequence[CausalFactor],
) -> None:
    """Require a contextual delivery to bind to one assembled factor."""
    if contract.delivery is None:
        return
    factor_ids = {
        f"CF-{index}" for index, _factor in enumerate(causal_factors, start=1)
    }
    if contract.delivery.factor_id not in factor_ids:
        raise ValueError(
            "execution contract delivery factor_id must resolve to a declared factor"
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


def _validate_optional_assembly_context(
    context: ScenarioGenerationContext | None,
    threat: StructuralThreat,
    scenario_index: int,
) -> None:
    """Validate a supplied scenario context before compiling provider output."""
    if context is not None:
        _validate_context_matches_threat(context, threat, scenario_index)


def _merge_defender_vulnerabilities(
    defender_bdi: DefenderBDI,
    llm_result: BDIGenerationResult,
) -> None:
    """Attach provider vulnerability prose to deterministic belief IDs."""
    for belief in defender_bdi.beliefs:
        belief.vulnerability = llm_result.defender_vulnerabilities.get(belief.pm_id, "")


def _materialize_causal_factors(
    llm_result: BDIGenerationResult,
) -> list[CausalFactor]:
    """Compile the declared Stage 5 factor records without inference."""
    return [
        CausalFactor(
            kind=declaration.kind,
            source_id=declaration.source_id,
            description=declaration.evidence,
            declared_timing=declaration.timing,
            evidence_status=declaration.evidence_status,
            capability_refs=declaration.capability_refs,
            access_refs=declaration.access_refs,
            bounded_assumption=declaration.bounded_assumption,
            temporal_condition=declaration.temporal_condition,
            mechanism=declaration.mechanism,
        )
        for declaration in llm_result.causal_factors
    ]


def _validate_assembled_factors(
    causal_factors: list[CausalFactor],
    control_structure: ControlStructure,
    context: ScenarioGenerationContext | None,
) -> None:
    """Validate factor references against structure and optional context."""
    validate_factor_sources(control_structure, causal_factors)
    if context is None:
        return
    validate_factor_evidence(context, causal_factors)
    _validate_context_factor_sources(context, causal_factors)


def _validated_unsafe_condition(
    llm_result: BDIGenerationResult,
    uca_type: UCAType,
    control_action_id: str,
) -> SemanticCondition | None:
    """Validate and return the provider's typed unsafe condition when present.

    The normal product wire materializes no executable condition, so an
    absent condition is the expected normal shape; a supplied condition keeps
    its exact UCA-family validation for historical callers.
    """
    outcome = llm_result.unsafe_outcome
    if outcome is None or outcome.condition is None:
        return None
    _validate_unsafe_outcome_for_target(outcome, uca_type, control_action_id)
    return outcome.condition


def _unsafe_outcome_refs(
    llm_result: BDIGenerationResult,
    threat: StructuralThreat,
) -> tuple[list[str], list[str]]:
    """Use validated provider refs or the threat's authoritative fallback refs."""
    outcome = llm_result.unsafe_outcome
    if outcome is None:
        return list(threat.related_hazards), list(threat.related_constraints)
    return list(outcome.hazard_refs), list(outcome.constraint_refs)


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
