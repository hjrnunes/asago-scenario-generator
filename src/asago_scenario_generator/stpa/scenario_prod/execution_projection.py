"""Preparation and standalone validation for STPA execution projections.

This module is the producer's deep public seam.  It is intentionally the only
place that translates the inward ``ScenarioSpec``/``ControlStructure`` graph
into the closed v2/v3 wire models and the only place that turns a validated
projection into a Stage 6 alignment view.

The legacy proposition-only branch builds ``stpa-execution-projection-v2``
documents exactly as before.  ``prepare_execution_projection(structured_omission=True)``
builds a ``stpa-execution-projection-v3`` document, assembling the closed
structured omission-evidence carrier from the spec's authoring-side basis and
the projection's own source pins.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from asago_scenario_generator.models.canonical import compute_framed_digest
from asago_scenario_generator.models.target_realization import (
    TargetOperationReference,
    TargetRealizationDisposition,
    TargetRealizationResult,
)
from asago_scenario_generator.stpa.models.causal_factor import (
    CausalFactor,
    validate_factor_sources,
)
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.execution_envelope import (
    AbsenceConstraint,
    DelayConstraint,
    DurationConstraint,
    OrderingConstraint,
    WindowConstraint,
    parse_declared_timing,
)
from asago_scenario_generator.stpa.models.execution_projection_v2 import (
    AdversarialStimulusRequirement,
    ExecutionCausalFactor,
    ExecutionProjectionV2,
    ExecutionProjectionValidationResult,
    ExecutionRequirements,
    ExecutionRunIdentity,
    ExecutionSourcePins,
    ExecutionStep,
    ExecutionStepKind,
    ExecutionTraceRefs,
    ProjectionValidationCode,
    ProjectionValidationViolation,
    UnsafeOutcome,
)
from asago_scenario_generator.stpa.models.execution_projection_v3 import (
    PROJECTION_V3_SCHEMA_VERSION,
    AdversarialStimulusRequirementV3,
    ExecutionProjectionV3,
    UnsafeOutcomeV3,
)
from asago_scenario_generator.stpa.models.omission_evidence import (
    OmissionEvidence,
    SOURCE_ATTESTATION_FRAME,
)
from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionActionKind,
    ExecutionDeliveryClass,
    ExecutionResourceKind,
    ExecutionResourcePurpose,
    ExecutionResourceRequirement,
    SemanticExecutionContract,
    ExecutionTargetProfile,
)
from asago_scenario_generator.stpa.models.scenario_context import (
    ScenarioGenerationContext,
)
from asago_scenario_generator.stpa.models.scenario_spec import ScenarioSpec
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.models.semantic_conditions import (
    AbsenceCondition,
    ActionPresenceCondition,
    ActionValueCondition,
    DelayCondition,
    DurationCondition,
    OrderingCondition,
    SemanticCondition,
    WindowCondition,
    contains_binding_placeholder,
    normalize_semantic_proposition,
)

from .execution_classification import classify_scenario_execution
from .outcome_grounding import scope_temporal_condition_bindings


_RUNTIME_KEYS = frozenset(
    {
        "runtime",
        "runtime_observation",
        "runtime_observations",
        "observation",
        "observations",
        "platform",
        "platform_binding",
        "tool_name",
        "tool_names",
        "endpoint",
        "prompt_role",
        "detector",
    }
)
_TOP_LEVEL_FIELDS = frozenset(
    {
        "schema_version",
        "run_id",
        "scenario_id",
        "candidate_id",
        "ica_slot_id",
        "ica_id",
        "controller_id",
        "control_action_id",
        "uca_type",
        "causal_factors",
        "steps",
        "unsafe_outcome",
        "stimulus_requirements",
        "execution_requirements",
        "execution_contract",
        "execution_classification",
        "trace_refs",
        "semantic_digest",
    }
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ExecutionProjectionPreparationError(ValueError):
    """Typed failure raised when a spec cannot become a v2/v3 projection."""

    def __init__(
        self,
        message: str,
        violations: Sequence[ProjectionValidationViolation] = (),
    ) -> None:
        super().__init__(message)
        self.violations = tuple(violations)


@dataclass(frozen=True)
class ValidatedExecutionProjection:
    """Immutable projection plus the exact bytes and Stage 6 alignment view.

    ``projection`` carries either the legacy v2 document or the structured
    v3 document; every accessor is attribute-based and version-neutral.
    """

    projection: ExecutionProjectionV2 | ExecutionProjectionV3
    canonical_json_bytes: bytes
    semantic_digest: str
    alignment_view: str
    source_identities: tuple[str, ...]

    @property
    def execution_requirements(self) -> ExecutionRequirements:
        """Return the neutral requirements owned by the projection."""
        return self.projection.execution_requirements


def prepare_execution_projection(
    spec: ScenarioSpec,
    control_structure: ControlStructure,
    run_identity: ExecutionRunIdentity,
    *,
    execution_contract: SemanticExecutionContract | None = None,
    target_profile: ExecutionTargetProfile | None = None,
    target_realization: TargetRealizationResult | None = None,
    structured_omission: bool = False,
    observation_snapshot_digest: str | None = None,
) -> ValidatedExecutionProjection:
    """Validate and freeze one contextual ``ScenarioSpec`` as execution intent.

    No provider or runtime work occurs in this function.  All factor and
    condition identities are checked against the exact control structure
    before the immutable digest-bearing value is returned.

    ``structured_omission`` selects the wire version: ``False`` (the default)
    builds the legacy v2 projection byte-identically to the historical
    behavior, while ``True`` builds a v3 projection that carries the closed
    structured omission-evidence carrier on action-absence outcomes.  The
    ``observation_snapshot_digest`` is the run's validated
    ``TargetObservationSnapshot.content_digest`` used to cross-check the
    carrier's snapshot pin; it is never embedded in the projection itself.
    """
    _validate_prepare_types(
        spec,
        control_structure,
        run_identity,
        execution_contract,
        target_profile,
        target_realization,
    )
    context = _validate_prepare_authority(spec, control_structure)
    factors = _build_projection_factors(spec.causal_factors)
    hazard_refs, constraint_refs = _outcome_refs(spec, context)
    contract = execution_contract or spec.execution_contract
    if execution_contract is not None and spec.execution_contract is not None:
        if execution_contract != spec.execution_contract:
            raise ExecutionProjectionPreparationError(
                "explicit execution contract does not match scenario contract"
            )
    if contract is None:
        raise ExecutionProjectionPreparationError(
            "contextual v2 projection requires an explicit Stage 5 execution contract"
        )
    _validate_target_realization(contract, spec, target_profile, target_realization)
    build = _build_projection_v3 if structured_omission else _build_projection
    projection = build(
        spec,
        control_structure,
        context,
        run_identity,
        factors,
        hazard_refs,
        constraint_refs,
        contract,
        target_profile,
        target_realization,
        observation_snapshot_digest,
    )
    return _freeze_validated_projection(projection)


def _validate_prepare_types(
    spec: ScenarioSpec,
    control_structure: ControlStructure,
    run_identity: ExecutionRunIdentity,
    execution_contract: SemanticExecutionContract | None,
    target_profile: ExecutionTargetProfile | None,
    target_realization: TargetRealizationResult | None,
) -> None:
    if not isinstance(spec, ScenarioSpec):
        raise ExecutionProjectionPreparationError("spec must be a ScenarioSpec")
    if not isinstance(control_structure, ControlStructure):
        raise ExecutionProjectionPreparationError(
            "control_structure must be a ControlStructure"
        )
    if not isinstance(run_identity, ExecutionRunIdentity):
        raise ExecutionProjectionPreparationError(
            "run_identity must be an ExecutionRunIdentity"
        )
    if execution_contract is not None and not isinstance(
        execution_contract, SemanticExecutionContract
    ):
        raise ExecutionProjectionPreparationError(
            "execution_contract must be a SemanticExecutionContract"
        )
    if target_profile is not None and not isinstance(
        target_profile, ExecutionTargetProfile
    ):
        raise ExecutionProjectionPreparationError(
            "target_profile must be an ExecutionTargetProfile"
        )
    if target_realization is not None and not isinstance(
        target_realization, TargetRealizationResult
    ):
        raise ExecutionProjectionPreparationError(
            "target_realization must be a TargetRealizationResult"
        )


def _validate_target_realization(
    contract: SemanticExecutionContract,
    spec: ScenarioSpec,
    target_profile: ExecutionTargetProfile | None,
    target_realization: TargetRealizationResult | None,
) -> None:
    """Close exact target selections over their profile and realization authority."""
    exact_requirements = tuple(
        item
        for item in contract.resource_requirements
        if item.exact_resource_id is not None
    )
    authority = _validate_target_authority_pair(
        target_profile,
        target_realization,
        exact_requirements=bool(exact_requirements),
    )
    if authority is None or not exact_requirements:
        return
    _, realization = authority
    selected = _selected_target_operation(realization, spec.target_control_action)
    _validate_exact_target_requirements(exact_requirements, selected)


def _validate_target_authority_pair(
    target_profile: ExecutionTargetProfile | None,
    target_realization: TargetRealizationResult | None,
    *,
    exact_requirements: bool,
) -> tuple[ExecutionTargetProfile, TargetRealizationResult] | None:
    """Validate the optional target lineage before producing any projection."""
    if (target_profile is None) != (target_realization is None):
        raise ExecutionProjectionPreparationError(
            "target_profile and target_realization must be supplied together"
        )
    if target_profile is None or target_realization is None:
        if exact_requirements:
            raise ExecutionProjectionPreparationError(
                "exact target requirements require profile and target realization"
            )
        return None
    target_profile.assert_integrity()
    target_realization.assert_integrity()
    if target_realization.profile_digest != target_profile.semantic_digest:
        raise ExecutionProjectionPreparationError(
            "target realization profile pin does not match target profile"
        )
    return target_profile, target_realization


def _selected_target_operation(
    realization: TargetRealizationResult,
    control_action_id: str,
) -> TargetOperationReference:
    """Return the exact supported operation for a baseline or derived action."""
    baseline = tuple(
        item.selected_operation
        for item in realization.rows
        if item.control_action_id == control_action_id
        and item.disposition is TargetRealizationDisposition.supported
        and item.selected_operation is not None
    )
    derived = tuple(
        record.operation_ref
        for record in realization.operation_records
        if record.target_derived_control_action_id == control_action_id
        and record.disposition is TargetRealizationDisposition.supported
    )
    selected = baseline + derived
    if not selected:
        raise ExecutionProjectionPreparationError(
            "exact target requirements require a supported realization row"
        )
    if len(selected) != 1:
        raise ExecutionProjectionPreparationError(
            "exact target requirements resolve to conflicting target operations"
        )
    return selected[0]


def _validate_exact_target_requirements(
    requirements: Sequence[ExecutionResourceRequirement],
    selected: TargetOperationReference,
) -> None:
    """Require every exact contract requirement to match the selected operation."""
    if any(
        item.exact_resource_id != selected.resource_id
        or item.operation != selected.operation_id
        for item in requirements
    ):
        raise ExecutionProjectionPreparationError(
            "execution contract target operation does not match target realization"
        )


def _validate_prepare_authority(
    spec: ScenarioSpec,
    control_structure: ControlStructure,
) -> ScenarioGenerationContext:
    _validate_spec_structure(spec, control_structure)
    context = spec.scenario_context
    if context is None:
        raise ExecutionProjectionPreparationError(
            "v2 projection requires an intact ScenarioGenerationContext"
        )
    _validate_context_authority(context)
    _validate_contextual_spec_content(spec)
    return context


def _validate_spec_structure(
    spec: ScenarioSpec,
    control_structure: ControlStructure,
) -> None:
    try:
        spec.validate_against(control_structure)
    except (ValueError, ValidationError) as exc:
        raise ExecutionProjectionPreparationError(
            f"scenario spec is not structurally valid: {exc}"
        ) from exc


def _validate_context_authority(context: ScenarioGenerationContext) -> None:
    try:
        # Re-parse the serialized value so callers cannot bypass the context's
        # digest/relationship validators with ``model_construct``.
        ScenarioGenerationContext.model_validate(context.model_dump(mode="json"))
    except (ValueError, ValidationError) as exc:
        raise ExecutionProjectionPreparationError(
            f"scenario context is not intact: {exc}"
        ) from exc
    pin_kinds = {item.source_kind for item in context.source_pins}
    expected = {
        "structural_threat",
        "control_path",
        "loss_relationships",
        "capabilities",
    }
    if pin_kinds != expected:
        raise ExecutionProjectionPreparationError(
            "scenario context must carry the complete source-pin set"
        )


def _validate_contextual_spec_content(spec: ScenarioSpec) -> None:
    if not spec.causal_factors:
        raise ExecutionProjectionPreparationError(
            "contextual v2 projection requires at least one causal factor"
        )
    if spec.unsafe_outcome_condition is None:
        raise ExecutionProjectionPreparationError(
            "contextual v2 projection requires a non-null unsafe outcome condition"
        )
    if not spec.threat_source.ica_id:
        raise ExecutionProjectionPreparationError(
            "v2 projection requires a concrete ICA identity"
        )
    contract = spec.execution_contract
    if contract is None:
        return
    if contract.action_kind is ExecutionActionKind.model_output:
        try:
            normalize_semantic_proposition(
                spec.unsafe_outcome_semantic_proposition,
                required=True,
            )
        except ValueError as exc:
            raise ExecutionProjectionPreparationError(str(exc)) from exc
        if spec.ica_type is UCAType.incorrect:
            condition = spec.unsafe_outcome_condition
            if not (
                isinstance(condition, ActionValueCondition)
                and condition.property == "semantic_proposition"
                and condition.operator == "equals"
                and type(condition.expected) is bool
                and condition.expected is True
            ):
                raise ExecutionProjectionPreparationError(
                    "model_output INCORRECT scenarios require the fixed "
                    "semantic-proposition condition"
                )
    elif spec.unsafe_outcome_semantic_proposition is not None:
        try:
            normalize_semantic_proposition(
                spec.unsafe_outcome_semantic_proposition,
                required=True,
            )
        except ValueError as exc:
            raise ExecutionProjectionPreparationError(str(exc)) from exc


def _build_projection_factors(
    causal_factors: Sequence[CausalFactor],
) -> tuple[ExecutionCausalFactor, ...]:
    conditions = _factor_conditions(causal_factors)
    return tuple(
        ExecutionCausalFactor(
            factor_id=f"CF-{index}",
            order=index,
            kind=factor.kind,
            structural_source_id=factor.source_id,
            description=factor.description,
            evidence_status=factor.evidence_status,
            capability_refs=tuple(factor.capability_refs),
            access_refs=tuple(factor.access_refs),
            bounded_assumption=factor.bounded_assumption,
            temporal_condition=(
                scope_temporal_condition_bindings(
                    conditions[index - 1], f"factor-{index}"
                )
                if conditions[index - 1] is not None
                else None
            ),
        )
        for index, factor in enumerate(causal_factors, start=1)
    )


def _build_projection(
    spec: ScenarioSpec,
    control_structure: ControlStructure,
    context: ScenarioGenerationContext,
    run_identity: ExecutionRunIdentity,
    factors: tuple[ExecutionCausalFactor, ...],
    hazard_refs: tuple[str, ...],
    constraint_refs: tuple[str, ...],
    execution_contract: SemanticExecutionContract,
    target_profile: ExecutionTargetProfile | None,
    target_realization: TargetRealizationResult | None,
    observation_snapshot_digest: str | None = None,
) -> ExecutionProjectionV2:
    del observation_snapshot_digest  # v2 never carries the omission carrier
    steps = _build_projection_steps(factors, spec.target_control_action)
    outcome = _build_unsafe_outcome(spec, hazard_refs, constraint_refs)
    classification = classify_scenario_execution(
        execution_contract,
        outcome,
        target_profile,
    )
    return ExecutionProjectionV2(
        run_id=run_identity.run_id,
        scenario_id=spec.scenario_id,
        candidate_id=(
            f"EXEC:{spec.target_controller}:{spec.target_control_action}:"
            f"{spec.ica_type.value}"
        ),
        ica_slot_id=spec.threat_source.ica_slot_id,
        ica_id=spec.threat_source.ica_id or "",
        controller_id=spec.target_controller,
        control_action_id=spec.target_control_action,
        uca_type=spec.ica_type,
        causal_factors=factors,
        steps=steps,
        unsafe_outcome=outcome,
        stimulus_requirements=_stimulus_requirements(spec, factors, execution_contract),
        execution_requirements=_execution_requirements(
            spec, factors, context, execution_contract
        ),
        execution_contract=execution_contract,
        execution_classification=classification,
        trace_refs=_trace_refs(
            spec,
            control_structure,
            context,
            hazard_refs,
            constraint_refs,
            target_profile,
            target_realization,
        ),
    )


def _build_projection_v3(
    spec: ScenarioSpec,
    control_structure: ControlStructure,
    context: ScenarioGenerationContext,
    run_identity: ExecutionRunIdentity,
    factors: tuple[ExecutionCausalFactor, ...],
    hazard_refs: tuple[str, ...],
    constraint_refs: tuple[str, ...],
    execution_contract: SemanticExecutionContract,
    target_profile: ExecutionTargetProfile | None,
    target_realization: TargetRealizationResult | None,
    observation_snapshot_digest: str | None,
) -> ExecutionProjectionV3:
    """Mirror the v2 build with the v3 carrier and prepared-text deltas."""
    steps = _build_projection_steps(factors, spec.target_control_action)
    stimulus_requirements = _stimulus_requirements_v3(
        spec,
        factors,
        execution_contract,
    )
    trace_refs = _trace_refs(
        spec,
        control_structure,
        context,
        hazard_refs,
        constraint_refs,
        target_profile,
        target_realization,
    )
    carrier = _v3_omission_carrier(
        spec,
        stimulus=(stimulus_requirements[0] if stimulus_requirements else None),
        source_pins=trace_refs.source_pins,
        observation_snapshot_digest=observation_snapshot_digest,
    )
    outcome = _build_unsafe_outcome_v3(spec, hazard_refs, constraint_refs, carrier)
    classification = classify_scenario_execution(
        execution_contract,
        outcome,
        target_profile,
    )
    return ExecutionProjectionV3(
        run_id=run_identity.run_id,
        scenario_id=spec.scenario_id,
        candidate_id=(
            f"EXEC:{spec.target_controller}:{spec.target_control_action}:"
            f"{spec.ica_type.value}"
        ),
        ica_slot_id=spec.threat_source.ica_slot_id,
        ica_id=spec.threat_source.ica_id or "",
        controller_id=spec.target_controller,
        control_action_id=spec.target_control_action,
        uca_type=spec.ica_type,
        causal_factors=factors,
        steps=steps,
        unsafe_outcome=outcome,
        stimulus_requirements=stimulus_requirements,
        execution_requirements=_execution_requirements(
            spec, factors, context, execution_contract
        ),
        execution_contract=execution_contract,
        execution_classification=classification,
        trace_refs=trace_refs,
    )


def _stimulus_requirements(
    spec: ScenarioSpec,
    factors: Sequence[ExecutionCausalFactor],
    execution_contract: SemanticExecutionContract,
) -> tuple[AdversarialStimulusRequirement, ...]:
    if execution_contract.disposition.value == "analytical_only":
        return ()
    turns = spec.stimulus_turns
    if turns is not None:
        intent = "\n".join(turn.text for turn in turns)
    else:
        intent = "; ".join(
            item.strip() for item in spec.attacker_bdi.intentions if item.strip()
        )
    desired_effect = "; ".join(
        item.strip() for item in spec.attacker_bdi.desires if item.strip()
    )
    if not intent or not desired_effect:
        raise ExecutionProjectionPreparationError(
            "contextual execution projection requires attacker intent and desired effect"
        )
    return (
        AdversarialStimulusRequirement(
            stimulus_id="STIM-1",
            intent=intent,
            desired_effect=desired_effect,
            delivery_class=execution_contract.delivery.delivery_class,
            factor_id=execution_contract.delivery.factor_id,
            source_role=execution_contract.delivery.source_role,
            carrier_requirement_id=execution_contract.delivery.carrier_requirement_id,
            turns=turns,
        ),
    )


def _build_projection_steps(
    factors: Sequence[ExecutionCausalFactor], control_action_id: str
) -> tuple[ExecutionStep, ...]:
    factor_steps = tuple(
        ExecutionStep(
            step_id=f"S-{index}",
            order=index,
            kind=ExecutionStepKind.causal_factor,
            factor_id=factor.factor_id,
            structural_source_id=factor.structural_source_id,
        )
        for index, factor in enumerate(factors, start=1)
    )
    final_step = ExecutionStep(
        step_id=f"S-{len(factors) + 1}",
        order=len(factors) + 1,
        kind=ExecutionStepKind.unsafe_control_action,
        structural_source_id=control_action_id,
    )
    return factor_steps + (final_step,)


def _build_unsafe_outcome(
    spec: ScenarioSpec,
    hazard_refs: tuple[str, ...],
    constraint_refs: tuple[str, ...],
) -> UnsafeOutcome:
    condition = spec.unsafe_outcome_condition
    if condition is None:
        raise ExecutionProjectionPreparationError(
            "contextual v2 projection requires a non-null unsafe outcome condition"
        )
    condition = scope_temporal_condition_bindings(condition, "outcome")
    return UnsafeOutcome(
        outcome_id="OUTCOME-1",
        control_action_id=spec.target_control_action,
        uca_type=spec.ica_type,
        condition=condition,
        semantic_proposition=spec.unsafe_outcome_semantic_proposition,
        semantic_binding_required=contains_binding_placeholder(condition),
        hazard_refs=hazard_refs,
        constraint_refs=constraint_refs,
    )


def _build_unsafe_outcome_v3(
    spec: ScenarioSpec,
    hazard_refs: tuple[str, ...],
    constraint_refs: tuple[str, ...],
    carrier: tuple[OmissionEvidence, str] | None,
) -> UnsafeOutcomeV3:
    """Mirror the v2 outcome build with the optional omission carrier."""
    condition = spec.unsafe_outcome_condition
    if condition is None:
        raise ExecutionProjectionPreparationError(
            "contextual v3 projection requires a non-null unsafe outcome condition"
        )
    condition = scope_temporal_condition_bindings(condition, "outcome")
    carrier_evidence, carrier_digest = carrier if carrier is not None else (None, None)
    return UnsafeOutcomeV3(
        outcome_id="OUTCOME-1",
        control_action_id=spec.target_control_action,
        uca_type=spec.ica_type,
        condition=condition,
        semantic_proposition=spec.unsafe_outcome_semantic_proposition,
        semantic_binding_required=contains_binding_placeholder(condition),
        hazard_refs=hazard_refs,
        constraint_refs=constraint_refs,
        omission_evidence=carrier_evidence,
        omission_evidence_digest=carrier_digest,
    )


def _stimulus_requirements_v3(
    spec: ScenarioSpec,
    factors: Sequence[ExecutionCausalFactor],
    execution_contract: SemanticExecutionContract,
) -> tuple[AdversarialStimulusRequirementV3, ...]:
    """Build the v3 stimulus route with its exact prepared delivery text."""
    if execution_contract.disposition.value == "analytical_only":
        return ()
    turns = spec.stimulus_turns
    if turns is not None:
        intent = "\n".join(turn.text for turn in turns)
    else:
        intent = "; ".join(
            item.strip() for item in spec.attacker_bdi.intentions if item.strip()
        )
    desired_effect = "; ".join(
        item.strip() for item in spec.attacker_bdi.desires if item.strip()
    )
    if not intent or not desired_effect:
        raise ExecutionProjectionPreparationError(
            "contextual execution projection requires attacker intent and desired effect"
        )
    delivery = execution_contract.delivery
    try:
        requirement = AdversarialStimulusRequirementV3(
            stimulus_id="STIM-1",
            intent=intent,
            desired_effect=desired_effect,
            delivery_class=delivery.delivery_class,
            factor_id=delivery.factor_id,
            source_role=delivery.source_role,
            carrier_requirement_id=delivery.carrier_requirement_id,
            turns=turns,
            prepared_user_text=(
                spec.prepared_user_text
                if delivery.delivery_class is ExecutionDeliveryClass.direct_prompt
                else None
            ),
        )
    except (ValidationError, ValueError) as exc:
        message = str(exc)
        if "prepared_user_text" in message:
            raise ExecutionProjectionPreparationError(
                f"prepared_text_mismatch: {message}"
            ) from exc
        raise ExecutionProjectionPreparationError(message) from exc
    return (requirement,)


def _v3_omission_carrier(
    spec: ScenarioSpec,
    *,
    stimulus: AdversarialStimulusRequirementV3 | None,
    source_pins: ExecutionSourcePins,
    observation_snapshot_digest: str | None,
) -> tuple[OmissionEvidence, str] | None:
    """Assemble the closed carrier from the basis and the projection pins.

    Every cross-check fails closed with a message prefixed by the mapped
    ``ProjectionValidationCode`` name; the derived carrier digest is computed
    by the closed model and never trusted from a caller.
    """
    basis = spec.omission_evidence_basis
    condition = spec.unsafe_outcome_condition
    is_action_absence = (
        isinstance(condition, ActionPresenceCondition)
        and condition.expected == "not_provided"
    )
    if basis is None:
        if is_action_absence:
            raise ExecutionProjectionPreparationError(
                "omission_evidence_missing: a structured v3 projection requires "
                "an omission evidence basis on its action-presence outcome"
            )
        return None
    if not is_action_absence:
        raise ExecutionProjectionPreparationError(
            "omission_evidence_unexpected: an omission evidence basis is only "
            "valid on a not-provided action-presence outcome"
        )
    if stimulus is None:
        raise ExecutionProjectionPreparationError(
            "stimulus_delivery_mismatch: the omission carrier has no published "
            "stimulus requirement to bind to"
        )
    if (
        basis.delivery.stimulus_id != stimulus.stimulus_id
        or basis.delivery.delivery_class != stimulus.delivery_class.value
    ):
        raise ExecutionProjectionPreparationError(
            "stimulus_delivery_mismatch: the omission basis delivery "
            f"({basis.delivery.stimulus_id}, {basis.delivery.delivery_class}) "
            "does not match the published stimulus requirement "
            f"({stimulus.stimulus_id}, {stimulus.delivery_class.value})"
        )
    _check_v3_prepared_text(basis, stimulus)
    _check_v3_snapshot(basis, observation_snapshot_digest)
    try:
        carrier = basis.to_carrier(source_pins)
    except (ValidationError, ValueError) as exc:
        raise ExecutionProjectionPreparationError(
            f"omission_evidence_invalid: the closed carrier rejected the "
            f"authoring basis: {exc}"
        ) from exc
    return carrier, carrier.compute_carrier_digest()


def _check_v3_prepared_text(
    basis: Any,
    stimulus: AdversarialStimulusRequirementV3,
) -> None:
    """Re-verify every stimulus quotation against the exact delivery text."""
    stimulus_entries = [entry for entry in basis.evidence if entry.source == "stimulus"]
    if stimulus.delivery_class is ExecutionDeliveryClass.direct_prompt:
        prepared = stimulus.prepared_user_text
        if prepared is None:
            raise ExecutionProjectionPreparationError(
                "prepared_text_mismatch: a direct_prompt carrier requires the "
                "exact prepared user text"
            )
        recomputed = compute_framed_digest(SOURCE_ATTESTATION_FRAME, prepared)
        if recomputed != basis.delivery.prepared_user_text_digest:
            raise ExecutionProjectionPreparationError(
                "prepared_text_mismatch: the recomputed prepared_user_text_digest "
                "does not match the omission basis delivery"
            )
        for entry in stimulus_entries:
            if entry.quote not in prepared:
                raise ExecutionProjectionPreparationError(
                    "prepared_text_mismatch: stimulus evidence quote "
                    f"{entry.quote!r} is not a substring of the prepared user text"
                )
        return
    turns = stimulus.turns or ()
    for entry in stimulus_entries:
        if entry.delivery_turn_ordinal > len(turns):
            raise ExecutionProjectionPreparationError(
                "prepared_text_mismatch: stimulus evidence cites turn "
                f"{entry.delivery_turn_ordinal}, beyond the "
                f"{len(turns)} published conversation turn(s)"
            )
        turn = turns[entry.delivery_turn_ordinal - 1]
        if entry.quote not in turn.text:
            raise ExecutionProjectionPreparationError(
                "prepared_text_mismatch: stimulus evidence quote "
                f"{entry.quote!r} is not a substring of the referenced "
                f"conversation turn {turn.turn_id}"
            )


def _check_v3_snapshot(
    basis: Any,
    observation_snapshot_digest: str | None,
) -> None:
    """Cross-check the carrier snapshot pin against the run's snapshot."""
    if observation_snapshot_digest is None:
        return
    cites_snapshot = any(
        entry.source in ("state_fact", "observation") for entry in basis.evidence
    )
    if (
        cites_snapshot
        and basis.observation_snapshot_digest != observation_snapshot_digest
    ):
        raise ExecutionProjectionPreparationError(
            "snapshot_digest_mismatch: the omission basis snapshot digest does "
            "not match the run's target observation snapshot"
        )


def _freeze_validated_projection(
    projection: ExecutionProjectionV2 | ExecutionProjectionV3,
) -> ValidatedExecutionProjection:
    return ValidatedExecutionProjection(
        projection=projection,
        canonical_json_bytes=projection.canonical_json_bytes(),
        semantic_digest=projection.semantic_digest
        or projection.compute_semantic_digest(),
        alignment_view=render_execution_projection_alignment(projection),
        source_identities=_projection_source_identities(projection),
    )


def _projection_source_identities(
    projection: ExecutionProjectionV2 | ExecutionProjectionV3,
) -> tuple[str, ...]:
    return (
        projection.scenario_id,
        projection.candidate_id,
        projection.ica_slot_id,
        projection.ica_id,
        *(factor.structural_source_id for factor in projection.causal_factors),
        projection.control_action_id,
    )


def _factor_conditions(
    factors: Sequence[CausalFactor],
) -> tuple[SemanticCondition | None, ...]:
    """Use typed provider conditions, with a single legacy timing conversion."""
    conditions: list[SemanticCondition | None] = []
    for factor in factors:
        if factor.temporal_condition is not None:
            conditions.append(factor.temporal_condition)
            continue
        constraint = parse_declared_timing(factor.declared_timing, factor.source_id)
        conditions.append(_semantic_condition_from_legacy(constraint, factor.source_id))
    return tuple(conditions)


def _semantic_condition_from_legacy(
    constraint: Any,
    source_id: str,
) -> SemanticCondition | None:
    if isinstance(constraint, OrderingConstraint):
        return _legacy_ordering_condition(constraint)
    if isinstance(constraint, DelayConstraint):
        return _legacy_delay_condition(constraint, source_id)
    if isinstance(constraint, DurationConstraint):
        return _legacy_duration_condition(constraint, source_id)
    if isinstance(constraint, WindowConstraint):
        return _legacy_window_condition(constraint, source_id)
    if isinstance(constraint, AbsenceConstraint):
        return _legacy_absence_condition(constraint, source_id)
    return None


def _legacy_ordering_condition(constraint: OrderingConstraint) -> OrderingCondition:
    return OrderingCondition(
        reference_step_id=constraint.reference,
        relation=constraint.ordering,
    )


def _legacy_delay_condition(
    constraint: DelayConstraint, source_id: str
) -> DelayCondition:
    return DelayCondition(reference_ref=source_id, delay_ms=constraint.delay_ms)


def _legacy_duration_condition(
    constraint: DurationConstraint, source_id: str
) -> DurationCondition:
    return DurationCondition(
        reference_ref=source_id,
        duration_ms=constraint.duration_s * 1000,
    )


def _legacy_window_condition(
    constraint: WindowConstraint, source_id: str
) -> WindowCondition:
    return WindowCondition(
        reference_ref=source_id,
        window_from_ms=constraint.window_from_ms,
        window_to_ms=constraint.window_to_ms,
    )


def _legacy_absence_condition(
    constraint: AbsenceConstraint, source_id: str
) -> AbsenceCondition | None:
    if not constraint.reference.startswith("S-"):
        return None
    return AbsenceCondition(reference_ref=source_id, until_step_id=constraint.reference)


def _outcome_refs(
    spec: ScenarioSpec,
    context: ScenarioGenerationContext | None,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    hazards = tuple(spec.unsafe_outcome_hazard_refs)
    constraints = tuple(spec.unsafe_outcome_constraint_refs)
    if context is None:
        return tuple(dict.fromkeys(hazards)), tuple(dict.fromkeys(constraints))
    return _resolve_outcome_refs_against_context(hazards, constraints, context)


def _resolve_outcome_refs_against_context(
    hazards: tuple[str, ...],
    constraints: tuple[str, ...],
    context: ScenarioGenerationContext,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    expected_hazards = tuple(item.hazard_id for item in context.hazards)
    expected_constraints = tuple(item.constraint_id for item in context.constraints)
    if not hazards:
        raise ExecutionProjectionPreparationError(
            "unsafe outcome hazard_refs cannot be empty for a contextual projection"
        )
    if not constraints:
        raise ExecutionProjectionPreparationError(
            "unsafe outcome constraint_refs cannot be empty for a contextual projection"
        )
    if len(hazards) != len(set(hazards)):
        raise ExecutionProjectionPreparationError(
            "unsafe outcome hazard_refs must contain unique IDs"
        )
    if len(constraints) != len(set(constraints)):
        raise ExecutionProjectionPreparationError(
            "unsafe outcome constraint_refs must contain unique IDs"
        )
    if hazards != expected_hazards:
        raise ExecutionProjectionPreparationError(
            "unsafe outcome hazard_refs must exactly equal scenario context"
        )
    if constraints != expected_constraints:
        raise ExecutionProjectionPreparationError(
            "unsafe outcome constraint_refs must exactly equal scenario context"
        )
    return hazards, constraints


def _execution_requirements(
    spec: ScenarioSpec,
    factors: Sequence[ExecutionCausalFactor],
    context: ScenarioGenerationContext | None,
    execution_contract: SemanticExecutionContract,
) -> ExecutionRequirements:
    conditions = _projection_conditions(spec, factors)
    categories = _required_surface_categories(conditions, execution_contract)
    return ExecutionRequirements(
        requires_multi_turn=_has_condition_type(
            conditions, {"ordering", "delay", "duration", "window", "absence"}
        )
        or execution_contract.delivery is not None
        and execution_contract.delivery.delivery_class
        is ExecutionDeliveryClass.conversation_context,
        requires_tool_execution=_requires_tool_execution(execution_contract),
        requires_persistent_state="persistent_data" in categories,
        requires_multi_agent=_requires_multi_agent(context, execution_contract),
        requires_real_clock=_has_condition_type(
            conditions, {"delay", "duration", "window"}
        ),
        requires_state_observation=(
            _has_condition_type(conditions, {"state_value"})
            or execution_contract.action_kind is ExecutionActionKind.state_change
        ),
        required_surface_categories=tuple(categories),
    )


def _requires_tool_execution(contract: SemanticExecutionContract) -> bool:
    """Derive tool execution from explicit semantic resources, never prose."""
    return any(
        ExecutionResourceKind.tool in requirement.acceptable_resource_kinds
        or requirement.purpose is ExecutionResourcePurpose.target_action
        for requirement in contract.resource_requirements
    ) or contract.action_kind in {
        ExecutionActionKind.tool_call,
        ExecutionActionKind.environment_action,
    }


def _projection_conditions(
    spec: ScenarioSpec,
    factors: Sequence[ExecutionCausalFactor],
) -> tuple[SemanticCondition, ...]:
    factor_conditions = tuple(
        factor.temporal_condition
        for factor in factors
        if factor.temporal_condition is not None
    )
    if spec.unsafe_outcome_condition is None:
        return factor_conditions
    return factor_conditions + (spec.unsafe_outcome_condition,)


def _required_surface_categories(
    conditions: Sequence[SemanticCondition],
    contract: SemanticExecutionContract | None = None,
) -> list[str]:
    categories = ["external_input"]
    if _has_condition_type(conditions, {"state_value"}):
        categories.append("persistent_data")
    if contract is not None and contract.delivery is not None:
        categories = _append_surface_category(
            categories,
            {
                ExecutionDeliveryClass.direct_prompt: "external_input",
                ExecutionDeliveryClass.conversation_context: "external_input",
                ExecutionDeliveryClass.indirect_content: "tool_result",
            }[contract.delivery.delivery_class],
        )
    if contract is not None:
        categories = _append_surface_category(
            categories,
            {
                ExecutionActionKind.tool_call: "tool_definition",
                ExecutionActionKind.state_change: "persistent_data",
                ExecutionActionKind.agent_message: "agent_message",
                ExecutionActionKind.environment_action: "environment_event",
            }.get(contract.action_kind),
        )
    return categories


def _append_surface_category(categories: list[str], category: str | None) -> list[str]:
    """Append one semantic surface once, retaining deterministic order."""
    if category is not None and category not in categories:
        categories.append(category)
    return categories


def _has_condition_type(
    conditions: Sequence[SemanticCondition], types: set[str]
) -> bool:
    return any(condition.type in types for condition in conditions)


def _requires_multi_agent(
    context: ScenarioGenerationContext | None,
    contract: SemanticExecutionContract | None = None,
) -> bool:
    return bool(
        contract is not None
        and contract.action_kind is ExecutionActionKind.agent_message
    ) or bool(
        context is not None
        and context.target_control_path.coordination_path is not None
    )


def _trace_refs(
    spec: ScenarioSpec,
    control_structure: ControlStructure,
    context: ScenarioGenerationContext,
    hazard_refs: Sequence[str],
    constraint_refs: Sequence[str],
    target_profile: ExecutionTargetProfile | None,
    target_realization: TargetRealizationResult | None,
) -> ExecutionTraceRefs:
    """Build the exact structural and target lineage references."""
    return ExecutionTraceRefs(
        obligation_ids=tuple(
            item.obligation_id for item in context.obligation_considerations
        ),
        attack_pattern_ids=tuple(
            item.attack_pattern_id for item in context.obligation_considerations
        ),
        loss_ids=tuple(item.loss_id for item in context.losses),
        hazard_ids=tuple(hazard_refs),
        constraint_ids=tuple(constraint_refs),
        source_pins=_trace_source_pins(
            control_structure,
            context,
            target_profile,
            target_realization,
        ),
    )


def _trace_source_pins(
    control_structure: ControlStructure,
    context: ScenarioGenerationContext,
    target_profile: ExecutionTargetProfile | None,
    target_realization: TargetRealizationResult | None,
) -> ExecutionSourcePins:
    """Build source pins from the exact authorities used by the projection."""
    context_pins = {
        item.source_kind: item.semantic_digest for item in context.source_pins
    }
    return ExecutionSourcePins(
        control_structure=compute_framed_digest(
            "stpa-control-structure-v1", control_structure.model_dump(mode="json")
        ),
        loss_analysis=context_pins["loss_relationships"],
        ica_enumeration=context_pins["structural_threat"],
        scenario_context=context.context_digest,
        execution_target_profile=(
            target_profile.semantic_digest if target_profile is not None else None
        ),
        target_realization=(
            target_realization.semantic_digest
            if target_realization is not None
            else None
        ),
    )


def render_execution_projection_alignment(
    projection: ExecutionProjectionV2 | ExecutionProjectionV3,
) -> str:
    """Render the ordered semantic references Stage 6 must realize."""
    lines = [
        "Ordered causal projection:",
        f"Projection ID: {projection.candidate_id}",
        f"UCA reference: {projection.ica_slot_id}",
        "References are semantic structural IDs; their meanings are supplied "
        "in the scenario evidence.",
    ]
    lines.extend(
        f"- order={step.order} step_ref={step.step_id} kind={step.kind.value} "
        f"factor_ref={step.factor_id or 'none'} "
        f"source_ref={step.structural_source_id}"
        for step in projection.steps
    )
    lines.append(
        "The last row is the fixed unsafe control action; do not add or reorder rows."
    )
    return "\n".join(lines)


def validate_execution_projection(
    payload: Any,
    *,
    control_structure: ControlStructure | None = None,
    expected_run_id: str | None = None,
    expected_scenario_id: str | None = None,
) -> ExecutionProjectionValidationResult:
    """Standalone, model-first validation returning typed violations only."""
    if not isinstance(payload, Mapping):
        return _invalid(
            ProjectionValidationCode.container_type_mismatch,
            "$",
            "projection must be a JSON object",
        )
    violations = _projection_preflight_violations(payload)
    if violations:
        return ExecutionProjectionValidationResult(
            valid=False, violations=tuple(violations)
        )
    return _validate_projection_model(
        payload,
        control_structure=control_structure,
        expected_run_id=expected_run_id,
        expected_scenario_id=expected_scenario_id,
    )


def _projection_preflight_violations(
    payload: Mapping[str, Any],
) -> list[ProjectionValidationViolation]:
    violations = _runtime_observation_violations(payload)
    violations.extend(_projection_header_violations(payload))
    return violations


def _runtime_observation_violations(
    payload: Mapping[str, Any],
) -> list[ProjectionValidationViolation]:
    if not _contains_runtime_key(payload):
        return []
    return [
        _violation(
            ProjectionValidationCode.runtime_observation_forbidden,
            _first_runtime_path(payload),
            "runtime/platform observations are not part of v2 projection",
        )
    ]


def _projection_header_violations(
    payload: Mapping[str, Any],
) -> list[ProjectionValidationViolation]:
    violations = _unknown_top_level_violations(payload)
    violations.extend(_missing_top_level_violations(payload))
    violations.extend(_schema_version_violations(payload))
    violations.extend(_persisted_digest_violations(payload))
    return violations


def _unknown_top_level_violations(
    payload: Mapping[str, Any],
) -> list[ProjectionValidationViolation]:
    unknown = sorted(set(payload) - _TOP_LEVEL_FIELDS)
    if not unknown:
        return []
    field = unknown[0]
    return [
        _violation(
            ProjectionValidationCode.unexpected_field,
            str(field),
            f"unknown top-level field {field!r}",
        )
    ]


def _missing_top_level_violations(
    payload: Mapping[str, Any],
) -> list[ProjectionValidationViolation]:
    missing = sorted(_TOP_LEVEL_FIELDS - set(payload))
    if not missing:
        return []
    field = missing[0]
    return [
        _violation(
            ProjectionValidationCode.required_field_missing,
            field,
            f"required field {field!r} is missing",
        )
    ]


def _schema_version_violations(
    payload: Mapping[str, Any],
) -> list[ProjectionValidationViolation]:
    if payload.get("schema_version") == "stpa-execution-projection-v2":
        return []
    return [
        _violation(
            ProjectionValidationCode.schema_version_mismatch,
            "schema_version",
            "schema_version must be stpa-execution-projection-v2",
        )
    ]


def _persisted_digest_violations(
    payload: Mapping[str, Any],
) -> list[ProjectionValidationViolation]:
    if isinstance(payload.get("semantic_digest"), str):
        return []
    return [
        _violation(
            ProjectionValidationCode.required_field_missing,
            "semantic_digest",
            "persisted projections require a semantic_digest string",
        )
    ]


def _validate_projection_model(
    payload: Mapping[str, Any],
    *,
    control_structure: ControlStructure | None,
    expected_run_id: str | None,
    expected_scenario_id: str | None,
) -> ExecutionProjectionValidationResult:
    try:
        projection = ExecutionProjectionV2.model_validate(payload)
    except ValidationError as exc:
        return ExecutionProjectionValidationResult(
            valid=False,
            violations=tuple(_validation_errors(exc)),
        )
    violations = _projection_identity_violations(
        projection, expected_run_id, expected_scenario_id
    )
    if control_structure is not None:
        violations.extend(
            _validate_against_control_structure(projection, control_structure)
        )
    if violations:
        return ExecutionProjectionValidationResult(
            valid=False, violations=tuple(violations)
        )
    return ExecutionProjectionValidationResult(valid=True, projection=projection)


def _projection_identity_violations(
    projection: ExecutionProjectionV2,
    expected_run_id: str | None,
    expected_scenario_id: str | None,
) -> list[ProjectionValidationViolation]:
    violations: list[ProjectionValidationViolation] = []
    if expected_run_id is not None and projection.run_id != expected_run_id:
        violations.append(
            _violation(
                ProjectionValidationCode.identity_mismatch,
                "run_id",
                "run_id does not match the expected enclosing run",
            )
        )
    if (
        expected_scenario_id is not None
        and projection.scenario_id != expected_scenario_id
    ):
        violations.append(
            _violation(
                ProjectionValidationCode.identity_mismatch,
                "scenario_id",
                "scenario_id does not match the expected scenario",
            )
        )
    return violations


def parse_execution_projection(
    payload: Any,
    *,
    control_structure: ControlStructure | None = None,
    expected_run_id: str | None = None,
    expected_scenario_id: str | None = None,
) -> ExecutionProjectionValidationResult:
    """Parse JSON-compatible data through the standalone v2 validator."""
    return validate_execution_projection(
        payload,
        control_structure=control_structure,
        expected_run_id=expected_run_id,
        expected_scenario_id=expected_scenario_id,
    )


def validate_execution_projection_v3(
    payload: Any,
    *,
    control_structure: ControlStructure | None = None,
    expected_run_id: str | None = None,
    expected_scenario_id: str | None = None,
    observation_snapshot_digest: str | None = None,
) -> tuple[ProjectionValidationCode, ...]:
    """Standalone v3 verification: typed codes in deterministic order.

    An empty tuple means the persisted ``stpa-execution-projection-v3``
    document is valid.  The checks mirror the v2 verifier — runtime keys,
    closed top-level fields, schema version, and the required persisted
    ``semantic_digest`` validated against the v3 digest frame — and add the
    structured omission-carrier checks.  Codes are deduplicated in first
    failure order.
    """
    violations = _v3_projection_violations(
        payload,
        control_structure=control_structure,
        expected_run_id=expected_run_id,
        expected_scenario_id=expected_scenario_id,
        observation_snapshot_digest=observation_snapshot_digest,
    )
    codes: list[ProjectionValidationCode] = []
    for violation in violations:
        if violation.code not in codes:
            codes.append(violation.code)
    return tuple(codes)


def _v3_projection_violations(
    payload: Any,
    *,
    control_structure: ControlStructure | None,
    expected_run_id: str | None,
    expected_scenario_id: str | None,
    observation_snapshot_digest: str | None,
) -> list[ProjectionValidationViolation]:
    if not isinstance(payload, Mapping):
        return [
            _violation(
                ProjectionValidationCode.container_type_mismatch,
                "$",
                "projection must be a JSON object",
            )
        ]
    violations = _v3_header_violations(payload)
    if violations:
        return violations
    violations.extend(_v3_carrier_violations(payload, observation_snapshot_digest))
    if violations:
        return violations
    try:
        projection = ExecutionProjectionV3.model_validate(payload)
    except ValidationError as exc:
        return _v3_validation_errors(exc)
    violations.extend(
        _projection_identity_violations(
            projection, expected_run_id, expected_scenario_id
        )
    )
    if control_structure is not None:
        violations.extend(
            _validate_against_control_structure(projection, control_structure)
        )
    return violations


def _v3_header_violations(
    payload: Mapping[str, Any],
) -> list[ProjectionValidationViolation]:
    """Mirror the v2 preflight header checks against the v3 contract."""
    violations = _runtime_observation_violations(payload)
    violations.extend(_unknown_top_level_violations(payload))
    violations.extend(_missing_top_level_violations(payload))
    if payload.get("schema_version") != PROJECTION_V3_SCHEMA_VERSION:
        violations.append(
            _violation(
                ProjectionValidationCode.schema_version_mismatch,
                "schema_version",
                f"schema_version must be {PROJECTION_V3_SCHEMA_VERSION}",
            )
        )
    if not isinstance(payload.get("semantic_digest"), str):
        violations.append(
            _violation(
                ProjectionValidationCode.required_field_missing,
                "semantic_digest",
                "persisted projections require a semantic_digest string",
            )
        )
    return violations


def _v3_carrier_violations(
    payload: Mapping[str, Any],
    observation_snapshot_digest: str | None,
) -> list[ProjectionValidationViolation]:
    """Check the omission carrier's presence, digest, and delivery binding."""
    outcome = payload.get("unsafe_outcome")
    if not isinstance(outcome, Mapping):
        # The model validation layer reports the structural defect.
        return []
    condition = outcome.get("condition")
    is_action_absence = (
        isinstance(condition, Mapping)
        and condition.get("type") == "action_presence"
        and condition.get("expected") == "not_provided"
    )
    carrier_raw = outcome.get("omission_evidence")
    digest_raw = outcome.get("omission_evidence_digest")
    if carrier_raw is None:
        if is_action_absence:
            return [
                _violation(
                    ProjectionValidationCode.omission_evidence_missing,
                    "unsafe_outcome.omission_evidence",
                    "action-presence outcomes require omission_evidence",
                )
            ]
        return []
    if not is_action_absence:
        return [
            _violation(
                ProjectionValidationCode.omission_evidence_unexpected,
                "unsafe_outcome.omission_evidence",
                "omission_evidence is allowed only on action-presence outcomes",
            )
        ]
    try:
        carrier = OmissionEvidence.model_validate(carrier_raw)
    except (ValidationError, ValueError) as exc:
        return [
            _violation(
                ProjectionValidationCode.omission_evidence_invalid,
                "unsafe_outcome.omission_evidence",
                str(exc),
            )
        ]
    violations: list[ProjectionValidationViolation] = []
    if not isinstance(digest_raw, str) or (
        digest_raw != carrier.compute_carrier_digest()
    ):
        violations.append(
            _violation(
                ProjectionValidationCode.omission_evidence_digest_mismatch,
                "unsafe_outcome.omission_evidence_digest",
                "omission_evidence_digest does not match the carrier content",
            )
        )
    violations.extend(_v3_carrier_delivery_violations(carrier, payload))
    violations.extend(
        _v3_carrier_snapshot_violations(carrier, observation_snapshot_digest)
    )
    return violations


def _v3_carrier_delivery_violations(
    carrier: OmissionEvidence,
    payload: Mapping[str, Any],
) -> list[ProjectionValidationViolation]:
    """Bind the carrier delivery to one published stimulus requirement."""
    raw_requirements = payload.get("stimulus_requirements")
    if not isinstance(raw_requirements, Sequence) or isinstance(
        raw_requirements, (str, bytes, bytearray)
    ):
        return []
    parsed: list[AdversarialStimulusRequirementV3] = []
    for item in raw_requirements:
        if not isinstance(item, Mapping):
            return []
        try:
            parsed.append(AdversarialStimulusRequirementV3.model_validate(item))
        except (ValidationError, ValueError):
            # Structural stimulus defects are reported by the model layer.
            return []
    if len(parsed) != 1:
        return [
            _violation(
                ProjectionValidationCode.stimulus_delivery_mismatch,
                "unsafe_outcome.omission_evidence.delivery",
                "the omission carrier delivery requires exactly one published "
                "stimulus requirement",
            )
        ]
    stimulus = parsed[0]
    violations: list[ProjectionValidationViolation] = []
    if (
        carrier.delivery.stimulus_id != stimulus.stimulus_id
        or carrier.delivery.delivery_class != stimulus.delivery_class.value
    ):
        return [
            _violation(
                ProjectionValidationCode.stimulus_delivery_mismatch,
                "unsafe_outcome.omission_evidence.delivery",
                "carrier stimulus identity does not match the published "
                "stimulus requirement",
            )
        ]
    stimulus_entries = [
        entry for entry in carrier.evidence if entry.source == "stimulus"
    ]
    if stimulus.delivery_class is ExecutionDeliveryClass.direct_prompt:
        prepared = stimulus.prepared_user_text
        if prepared is None or not isinstance(prepared, str):
            return [
                _violation(
                    ProjectionValidationCode.prepared_text_mismatch,
                    "unsafe_outcome.omission_evidence.delivery",
                    "a direct_prompt carrier requires the exact prepared user text",
                )
            ]
        if compute_framed_digest(SOURCE_ATTESTATION_FRAME, prepared) != (
            carrier.delivery.prepared_user_text_digest
        ):
            violations.append(
                _violation(
                    ProjectionValidationCode.prepared_text_mismatch,
                    "unsafe_outcome.omission_evidence.delivery.prepared_user_text_digest",
                    "prepared_user_text_digest does not match the published "
                    "prepared text",
                )
            )
        for entry in stimulus_entries:
            if entry.quote not in prepared:
                violations.append(
                    _violation(
                        ProjectionValidationCode.prepared_text_mismatch,
                        "unsafe_outcome.omission_evidence.evidence",
                        "stimulus evidence quote is not a substring of the "
                        "published prepared text",
                    )
                )
        return violations
    turns = stimulus.turns or ()
    for entry in stimulus_entries:
        if entry.delivery_turn_ordinal > len(turns):
            violations.append(
                _violation(
                    ProjectionValidationCode.prepared_text_mismatch,
                    "unsafe_outcome.omission_evidence.evidence",
                    "stimulus evidence cites a turn beyond the published "
                    "conversation turns",
                )
            )
            continue
        turn = turns[entry.delivery_turn_ordinal - 1]
        if entry.turn_id != turn.turn_id:
            violations.append(
                _violation(
                    ProjectionValidationCode.stimulus_delivery_mismatch,
                    "unsafe_outcome.omission_evidence.evidence",
                    "stimulus evidence turn identity does not match the "
                    "published conversation turn",
                )
            )
        if entry.quote not in turn.text:
            violations.append(
                _violation(
                    ProjectionValidationCode.prepared_text_mismatch,
                    "unsafe_outcome.omission_evidence.evidence",
                    "stimulus evidence quote is not a substring of the "
                    "referenced conversation turn",
                )
            )
    return violations


def _v3_carrier_snapshot_violations(
    carrier: OmissionEvidence,
    observation_snapshot_digest: str | None,
) -> list[ProjectionValidationViolation]:
    if observation_snapshot_digest is None:
        return []
    cites_snapshot = any(
        entry.source in ("state_fact", "observation") for entry in carrier.evidence
    )
    if cites_snapshot and (
        carrier.observation_snapshot_digest != observation_snapshot_digest
    ):
        return [
            _violation(
                ProjectionValidationCode.snapshot_digest_mismatch,
                "unsafe_outcome.omission_evidence.observation_snapshot_digest",
                "carrier snapshot digest does not match the supplied target "
                "observation snapshot",
            )
        ]
    return []


def _v3_validation_errors(
    exc: ValidationError,
) -> list[ProjectionValidationViolation]:
    return [
        _v3_error_violation(error)
        for error in sorted(
            exc.errors(), key=lambda item: tuple(str(part) for part in item["loc"])
        )
    ]


def _v3_error_violation(error: Mapping[str, Any]) -> ProjectionValidationViolation:
    loc = error["loc"]
    path = ".".join(str(part) for part in loc) or "$"
    message = str(error.get("msg", "invalid value"))
    return _violation(_v3_validation_code(path, message), path, message)


def _v3_validation_code(path: str, message: str) -> ProjectionValidationCode:
    """Map v3 model failures, with the omission deltas ahead of the v2 rules."""
    lowered = message.lower()
    if "omission_evidence" in lowered or "omission_evidence" in path:
        if (
            "does not match the carrier content" in lowered
            or "omission_evidence_digest" in path
        ):
            return ProjectionValidationCode.omission_evidence_digest_mismatch
        if "require omission_evidence" in lowered:
            return ProjectionValidationCode.omission_evidence_missing
        if "allowed only on action-presence" in lowered:
            return ProjectionValidationCode.omission_evidence_unexpected
        return ProjectionValidationCode.omission_evidence_invalid
    if "prepared_user_text" in lowered or "prepared_user_text" in path:
        return ProjectionValidationCode.prepared_text_mismatch
    if (
        "observation_snapshot_digest" in lowered
        or "observation_snapshot_digest" in path
    ):
        return ProjectionValidationCode.snapshot_digest_mismatch
    return _validation_code(path, lowered)


def _validate_against_control_structure(
    projection: ExecutionProjectionV2 | ExecutionProjectionV3,
    control_structure: ControlStructure,
) -> list[ProjectionValidationViolation]:
    violations: list[ProjectionValidationViolation] = []
    try:
        validate_factor_sources(
            control_structure,
            [
                CausalFactor(
                    kind=factor.kind,
                    source_id=factor.structural_source_id,
                    description=factor.description,
                    evidence_status=factor.evidence_status,
                    capability_refs=factor.capability_refs,
                    access_refs=factor.access_refs,
                    bounded_assumption=factor.bounded_assumption,
                )
                for factor in projection.causal_factors
            ],
        )
    except (ValueError, ValidationError) as exc:
        violations.append(
            _violation(
                ProjectionValidationCode.factor_reference_mismatch,
                "causal_factors",
                str(exc),
            )
        )
    if projection.trace_refs.source_pins.control_structure != compute_framed_digest(
        "stpa-control-structure-v1", control_structure.model_dump(mode="json")
    ):
        violations.append(
            _violation(
                ProjectionValidationCode.source_pin_mismatch,
                "trace_refs.source_pins.control_structure",
                "control_structure source pin does not match supplied authority",
            )
        )
    return violations


def _validation_errors(exc: ValidationError) -> list[ProjectionValidationViolation]:
    return [
        _error_violation(error)
        for error in sorted(
            exc.errors(), key=lambda item: tuple(str(part) for part in item["loc"])
        )
    ]


def _error_violation(error: Mapping[str, Any]) -> ProjectionValidationViolation:
    loc = error["loc"]
    path = ".".join(str(part) for part in loc) or "$"
    message = str(error.get("msg", "invalid value"))
    return _violation(_validation_code(path, message), path, message)


def _validation_code(path: str, message: str) -> ProjectionValidationCode:
    lowered = message.lower()
    rules = (
        (
            _is_classification_error,
            ProjectionValidationCode.execution_classification_mismatch,
        ),
        (_is_binding_error, ProjectionValidationCode.semantic_binding_state_mismatch),
        (_is_digest_error, ProjectionValidationCode.semantic_digest_mismatch),
        (_is_compatible_error, ProjectionValidationCode.uca_condition_incompatible),
        (
            _is_condition_reference_error,
            ProjectionValidationCode.condition_reference_mismatch,
        ),
        (_is_condition_type_error, ProjectionValidationCode.condition_type_mismatch),
        (_is_condition_error, ProjectionValidationCode.condition_value_invalid),
        (_is_stimulus_error, ProjectionValidationCode.stimulus_field_mismatch),
        (_is_step_error, ProjectionValidationCode.step_mapping_mismatch),
        (_is_factor_order_error, ProjectionValidationCode.factor_order_mismatch),
        (_is_factor_error, ProjectionValidationCode.factor_reference_mismatch),
        (_is_identity_error, ProjectionValidationCode.identity_mismatch),
    )
    for matches, code in rules:
        if matches(path, lowered):
            return code
    return ProjectionValidationCode.condition_field_mismatch


def _is_classification_error(path: str, message: str) -> bool:
    """Map projection/classification cross-field failures to one stable code."""
    return "execution_classification" in path or "classification" in message


def _is_binding_error(path: str, message: str) -> bool:
    return (
        "semantic_binding_required" in path
        or "placeholder" in message
        or "binding references" in message
    )


def _is_digest_error(path: str, message: str) -> bool:
    return "semantic_digest" in path or "digest" in message


def _is_compatible_error(path: str, message: str) -> bool:
    return "condition" in path and "compatible" in message


def _is_condition_reference_error(path: str, message: str) -> bool:
    return ("condition" in path and "reference" in message) or (
        "condition reference" in message
    )


def _is_condition_type_error(path: str, message: str) -> bool:
    return "condition" in path and "type" in message


def _is_condition_error(path: str, message: str) -> bool:
    del message
    return "condition" in path


def _is_stimulus_error(path: str, message: str) -> bool:
    """Map stimulus-route cross-field failures to one stable code."""
    return "stimulus" in path or "turn" in message


def _is_step_error(path: str, message: str) -> bool:
    return "step" in path or "mapping" in message


def _is_factor_order_error(path: str, message: str) -> bool:
    return "factor" in path and ("order" in message or "canonical" in message)


def _is_factor_error(path: str, message: str) -> bool:
    del message
    return "factor" in path


def _is_identity_error(path: str, message: str) -> bool:
    return "candidate" in message or "identity" in message or "ica" in message


def _contains_runtime_key(value: Any) -> bool:
    if isinstance(value, Mapping):
        return _runtime_mapping_contains(value)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return _runtime_sequence_contains(value)
    return False


def _runtime_mapping_contains(value: Mapping[Any, Any]) -> bool:
    return any(
        key in _RUNTIME_KEYS or _contains_runtime_key(item)
        for key, item in value.items()
    )


def _runtime_sequence_contains(value: Sequence[Any]) -> bool:
    return any(_contains_runtime_key(item) for item in value)


def _first_runtime_path(value: Any, path: str = "") -> str:
    if isinstance(value, Mapping):
        return _first_runtime_mapping_path(value, path)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return _first_runtime_sequence_path(value, path)
    return ""


def _first_runtime_mapping_path(value: Mapping[Any, Any], path: str) -> str:
    for key in sorted(value):
        child_path = f"{path}.{key}" if path else str(key)
        if key in _RUNTIME_KEYS:
            return child_path
        found = _first_runtime_path(value[key], child_path)
        if found:
            return found
    return ""


def _first_runtime_sequence_path(value: Sequence[Any], path: str) -> str:
    for index, item in enumerate(value):
        found = _first_runtime_path(item, f"{path}[{index}]")
        if found:
            return found
    return ""


def _violation(
    code: ProjectionValidationCode,
    path: str,
    detail: str,
) -> ProjectionValidationViolation:
    return ProjectionValidationViolation(code=code, path=path or "$", detail=detail)


def _invalid(
    code: ProjectionValidationCode,
    path: str,
    detail: str,
) -> ExecutionProjectionValidationResult:
    return ExecutionProjectionValidationResult(
        valid=False,
        violations=(_violation(code, path, detail),),
    )


__all__ = [
    "ExecutionProjectionPreparationError",
    "ValidatedExecutionProjection",
    "parse_execution_projection",
    "prepare_execution_projection",
    "render_execution_projection_alignment",
    "validate_execution_projection",
    "validate_execution_projection_v3",
]
