"""Preparation and standalone validation for STPA execution projection v2.

This module is the producer's deep public seam.  It is intentionally the only
place that translates the inward ``ScenarioSpec``/``ControlStructure`` graph
into the closed v2 wire model and the only place that turns a validated
projection into a Stage 6 alignment view.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from asago_scenario_generator.models.canonical import compute_framed_digest
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
from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionActionKind,
    ExecutionResourceKind,
    ExecutionResourcePurpose,
    SemanticExecutionContract,
    ExecutionTargetProfile,
)
from asago_scenario_generator.stpa.models.scenario_context import (
    ScenarioGenerationContext,
)
from asago_scenario_generator.stpa.models.scenario_spec import ScenarioSpec
from asago_scenario_generator.stpa.models.semantic_conditions import (
    AbsenceCondition,
    DelayCondition,
    DurationCondition,
    OrderingCondition,
    SemanticCondition,
    WindowCondition,
    contains_binding_placeholder,
)

from .execution_classification import classify_scenario_execution


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
    """Typed failure raised when a spec cannot become a v2 projection."""

    def __init__(
        self,
        message: str,
        violations: Sequence[ProjectionValidationViolation] = (),
    ) -> None:
        super().__init__(message)
        self.violations = tuple(violations)


@dataclass(frozen=True)
class ValidatedExecutionProjection:
    """Immutable projection plus the exact bytes and Stage 6 alignment view."""

    projection: ExecutionProjectionV2
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
) -> ValidatedExecutionProjection:
    """Validate and freeze one contextual ``ScenarioSpec`` as v2 intent.

    No provider or runtime work occurs in this function.  All factor and
    condition identities are checked against the exact control structure
    before the immutable digest-bearing value is returned.
    """
    _validate_prepare_types(
        spec,
        control_structure,
        run_identity,
        execution_contract,
        target_profile,
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
    projection = _build_projection(
        spec,
        control_structure,
        context,
        run_identity,
        factors,
        hazard_refs,
        constraint_refs,
        contract,
        target_profile,
    )
    return _freeze_validated_projection(projection)


def _validate_prepare_types(
    spec: ScenarioSpec,
    control_structure: ControlStructure,
    run_identity: ExecutionRunIdentity,
    execution_contract: SemanticExecutionContract | None,
    target_profile: ExecutionTargetProfile | None,
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
            temporal_condition=conditions[index - 1],
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
) -> ExecutionProjectionV2:
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
            spec, control_structure, context, hazard_refs, constraint_refs
        ),
    )


def _stimulus_requirements(
    spec: ScenarioSpec,
    factors: Sequence[ExecutionCausalFactor],
    execution_contract: SemanticExecutionContract,
) -> tuple[AdversarialStimulusRequirement, ...]:
    if execution_contract.disposition.value == "analytical_only":
        return ()
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
    return UnsafeOutcome(
        outcome_id="OUTCOME-1",
        control_action_id=spec.target_control_action,
        uca_type=spec.ica_type,
        condition=condition,
        semantic_binding_required=contains_binding_placeholder(condition),
        hazard_refs=hazard_refs,
        constraint_refs=constraint_refs,
    )


def _freeze_validated_projection(
    projection: ExecutionProjectionV2,
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
    projection: ExecutionProjectionV2,
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
    hazards = tuple(dict.fromkeys(spec.unsafe_outcome_hazard_refs))
    constraints = tuple(dict.fromkeys(spec.unsafe_outcome_constraint_refs))
    if context is None:
        return hazards, constraints
    return _resolve_outcome_refs_against_context(hazards, constraints, context)


def _resolve_outcome_refs_against_context(
    hazards: tuple[str, ...],
    constraints: tuple[str, ...],
    context: ScenarioGenerationContext,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    context_hazards = {item.hazard_id for item in context.hazards}
    context_constraints = {item.constraint_id for item in context.constraints}
    resolved_hazards, resolved_constraints = _default_outcome_refs(
        hazards, constraints, context
    )
    _require_context_refs(resolved_hazards, context_hazards, "hazard")
    _require_context_refs(resolved_constraints, context_constraints, "constraint")
    return resolved_hazards, resolved_constraints


def _default_outcome_refs(
    hazards: tuple[str, ...],
    constraints: tuple[str, ...],
    context: ScenarioGenerationContext,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    return (
        hazards or tuple(item.hazard_id for item in context.hazards),
        constraints or tuple(item.constraint_id for item in context.constraints),
    )


def _require_context_refs(
    refs: tuple[str, ...], valid_refs: set[str], label: str
) -> None:
    if set(refs) <= valid_refs:
        return
    raise ExecutionProjectionPreparationError(
        f"unsafe outcome {label}_refs do not resolve to scenario context"
    )


def _execution_requirements(
    spec: ScenarioSpec,
    factors: Sequence[ExecutionCausalFactor],
    context: ScenarioGenerationContext | None,
    execution_contract: SemanticExecutionContract,
) -> ExecutionRequirements:
    conditions = _projection_conditions(spec, factors)
    categories = _required_surface_categories(conditions)
    return ExecutionRequirements(
        requires_multi_turn=_has_condition_type(
            conditions, {"ordering", "delay", "duration", "window", "absence"}
        ),
        requires_tool_execution=_requires_tool_execution(execution_contract),
        requires_persistent_state="persistent_data" in categories,
        requires_multi_agent=_requires_multi_agent(context),
        requires_real_clock=_has_condition_type(
            conditions, {"delay", "duration", "window"}
        ),
        requires_state_observation=_has_condition_type(conditions, {"state_value"}),
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
) -> list[str]:
    categories = ["external_input"]
    if _has_condition_type(conditions, {"state_value"}):
        categories.append("persistent_data")
    return categories


def _has_condition_type(
    conditions: Sequence[SemanticCondition], types: set[str]
) -> bool:
    return any(condition.type in types for condition in conditions)


def _requires_multi_agent(context: ScenarioGenerationContext | None) -> bool:
    return bool(
        context is not None
        and context.target_control_path.coordination_path is not None
    )


def _trace_refs(
    spec: ScenarioSpec,
    control_structure: ControlStructure,
    context: ScenarioGenerationContext,
    hazard_refs: Sequence[str],
    constraint_refs: Sequence[str],
) -> ExecutionTraceRefs:
    context_pins = {
        item.source_kind: item.semantic_digest for item in context.source_pins
    }
    source_pins = ExecutionSourcePins(
        control_structure=compute_framed_digest(
            "stpa-control-structure-v1", control_structure.model_dump(mode="json")
        ),
        loss_analysis=context_pins["loss_relationships"],
        ica_enumeration=context_pins["structural_threat"],
        scenario_context=context.context_digest,
    )
    considerations = context.obligation_considerations if context is not None else ()
    return ExecutionTraceRefs(
        obligation_ids=tuple(item.obligation_id for item in considerations),
        attack_pattern_ids=tuple(item.attack_pattern_id for item in considerations),
        loss_ids=tuple(item.loss_id for item in context.losses),
        hazard_ids=tuple(hazard_refs),
        constraint_ids=tuple(constraint_refs),
        source_pins=source_pins,
    )


def render_execution_projection_alignment(projection: ExecutionProjectionV2) -> str:
    """Render a deterministic Stage 6 view derived only from the projection."""
    lines = [
        f"projection_schema: {projection.schema_version}",
        f"semantic_digest: {projection.semantic_digest}",
        f"scenario_id: {projection.scenario_id}",
        f"candidate_id: {projection.candidate_id}",
        "steps:",
    ]
    lines.extend(
        f"- {step.step_id} order={step.order} kind={step.kind.value} "
        f"factor_id={step.factor_id or 'null'} source={step.structural_source_id}"
        for step in projection.steps
    )
    lines.extend(
        [
            f"unsafe_outcome: {projection.unsafe_outcome.outcome_id}",
            f"unsafe_condition_type: {projection.unsafe_outcome.condition.type}",
            "causal_factors:",
        ]
    )
    lines.extend(
        f"- {factor.factor_id} order={factor.order} kind={factor.kind.value} "
        f"source={factor.structural_source_id} temporal_condition="
        f"{factor.temporal_condition.type if factor.temporal_condition else 'null'}"
        for factor in projection.causal_factors
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


def _validate_against_control_structure(
    projection: ExecutionProjectionV2,
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
]
