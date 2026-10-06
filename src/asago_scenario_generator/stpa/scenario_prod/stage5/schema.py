"""Request-specific Stage 5 response schemas."""

from __future__ import annotations

from functools import lru_cache
from collections.abc import Mapping, Sequence
from typing import Annotated, Any, Literal, Union
from pydantic import (
    BaseModel,
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
    conlist,
    create_model,
)
from asago_scenario_generator.models.target_realization import (
    TargetOperationObservation,
)
from asago_scenario_generator.stpa.models.causal_factor import (
    CausalFactorKind,
)
from asago_scenario_generator.stpa.models.semantic_conditions import (
    SemanticBindingPlaceholder,
    SemanticBindingValueType,
    SemanticValue,
)
from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionActionKind,
)
from asago_scenario_generator.stpa.observation_contract import (
    SafeObservableOutcome,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlActionTemporality,
)
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.models.scenario_context import (
    ScenarioGenerationContext,
)
from asago_scenario_generator.stpa.discriminating_condition import (
    DiscriminatingCondition,
)
from .wire import (
    AnalyticalOnlyRouteSelection,
    _CausalSourceChoice,
    _ContextAbsenceConditionWire,
    _ContextAbsenceTemporalWire,
    _ContextActionPresenceConditionWire,
    _ContextActionValueConditionWire,
    _ContextAttackerBDIDraft,
    _ContextAttackerIntentionDraft,
    _ContextBDIProviderPayload,
    _ContextCausalFactorWireBase,
    _ContextDelayConditionWire,
    _ContextDelayTemporalWire,
    _ContextDurationConditionWire,
    _ContextDurationTemporalWire,
    _ContextExecutableRouteDraft,
    _ContextNonBlankText,
    _ContextOrderingConditionWire,
    _ContextOrderingTemporalWire,
    _ContextScenarioSemanticsPayload,
    _ContextSemanticFactorWireBase,
    _ContextSemanticOutcomeDraft,
    _ContextStateValueConditionWire,
    _ContextStimulusDraft,
    _ContextTemporalConditionWire,
    _ContextUnsafeOutcomeDraft,
    _ContextWindowConditionWire,
    _ContextWindowTemporalWire,
    _ObservationCriterionDraft,
)
from .sources import (
    _action_duration_eligible,
    _action_temporality,
)


def _context_provider_schema_kwargs(
    context: ScenarioGenerationContext,
    choices: Sequence[_CausalSourceChoice],
    *,
    target_operation: TargetOperationObservation | None = None,
) -> dict[str, object]:
    """Return exact authority used to close the contextual provider schema."""
    action = context.target_control_path.control_action
    action_id = action.action_id
    source_ids = tuple(choice.source_id for choice in choices)
    condition_refs = tuple(dict.fromkeys((action_id, *source_ids)))
    return {
        "target_action_id": action_id,
        "uca_type": context.ica.uca_type,
        "state_subject_refs": tuple(
            choice.handle
            for choice in choices
            if choice.kind is CausalFactorKind.process_model_flaw
        ),
        "temporal_reference_handles": (
            "target_action",
            *(choice.handle for choice in choices),
        ),
        "condition_reference_refs": condition_refs,
        "condition_step_refs": tuple(
            # The final projected step is the selected target action.  An
            # outcome ordering must compare that action with a distinct
            # declared factor step; the self-reference is rejected again
            # during materialization, but it must not be offered by the
            # provider schema.
            f"S-{index}"
            for index in range(1, len(choices) + 1)
        ),
        "duration_eligible": _action_duration_eligible(action),
        "action_temporality": _action_temporality(action),
        "observed_argument_specs": _target_operation_argument_specs(target_operation),
    }


def _target_operation_argument_specs(
    operation: TargetOperationObservation | None,
) -> tuple[tuple[str, str], ...]:
    """Return deterministic scalar argument paths from one exact operation."""
    if operation is None:
        return ()
    specs: dict[str, str] = {}

    def visit(node: object, prefix: str) -> None:
        if not isinstance(node, Mapping):
            return
        declared_type = node.get("type")
        if declared_type in {"string", "integer", "number", "boolean"}:
            specs[prefix] = declared_type
            return
        properties = node.get("properties")
        if isinstance(properties, Mapping):
            for name in sorted(properties):
                path = f"{prefix}.{name}" if prefix else str(name)
                visit(properties[name], path)
            return
        if prefix:
            # Preserve an observed argument with an incomplete schema as a
            # generic scalar rather than inventing its business type.
            specs[prefix] = "any"

    visit(operation.input_schema, "")
    return tuple(sorted(specs.items()))


def _context_outcome_temporal_wire_types(
    choice_count: int,
    temporal_handle_type: Any,
    temporal_handles: Sequence[str],
    handles: tuple[str, ...],
    *,
    duration_eligible: bool,
    uca_type: UCAType | None,
    action_temporality: ControlActionTemporality | None,
) -> dict[str, type[BaseModel]]:
    # Factor timing must follow the action's established temporality.  A
    # WRONG_DURATION outcome is different: when that fact is not supplied,
    # retain the branch with a typed unresolved scalar instead of silently
    # removing the obligation or inventing a duration.
    outcome_temporal_types = _context_temporal_wire_types(
        choice_count,
        temporal_handle_type,
        temporal_handles,
        duration_eligible=duration_eligible,
        ordering_reference_handles=handles,
        model_prefix="_ContextOutcomeTemporal",
    )
    duration_unknown = action_temporality in {
        None,
        ControlActionTemporality.unknown,
    }
    if (
        uca_type is UCAType.wrong_duration
        and "duration" not in outcome_temporal_types
        and duration_unknown
    ):
        outcome_temporal_types = _context_temporal_wire_types(
            choice_count,
            temporal_handle_type,
            temporal_handles,
            duration_eligible=True,
            ordering_reference_handles=handles,
            model_prefix="_ContextOutcomeTemporal",
        )
    return outcome_temporal_types


def _temporal_unsafe_condition_types(
    outcome_temporal_types: Mapping[str, type[BaseModel]],
    uca_type: UCAType,
    *,
    condition_reference_refs: tuple[str, ...],
    condition_step_refs: tuple[str, ...],
) -> dict[str, type[BaseModel]]:
    branches = (
        {"duration"}
        if uca_type is UCAType.wrong_duration
        else {"ordering", "delay", "window", "absence"}
    )
    return {
        name: model
        for name, model in outcome_temporal_types.items()
        if name in branches
        and _context_unsafe_condition_branch_is_available(
            name,
            condition_reference_refs=condition_reference_refs,
            condition_step_refs=condition_step_refs,
        )
    }


@lru_cache(maxsize=64)
def _context_bdi_provider_wire_types(
    choice_count: int,
    expected_action_kind: ExecutionActionKind | None = None,
    *,
    target_action_id: str | None = None,
    uca_type: UCAType | None = None,
    state_subject_refs: tuple[str, ...] = (),
    temporal_reference_handles: tuple[str, ...] = (),
    condition_reference_refs: tuple[str, ...] = (),
    condition_step_refs: tuple[str, ...] = (),
    duration_eligible: bool = False,
    action_temporality: ControlActionTemporality | None = None,
    observed_argument_specs: tuple[tuple[str, str], ...] = (),
) -> dict[str, type[BaseModel]]:
    """Build the strict provider wire types for one exact request.

    The public/inward models intentionally retain compatibility defaults.  A
    contextual provider response instead uses this request-specific factory so
    every discriminator is required and each conditional branch contains only
    its meaningful fields.
    """
    _require_positive_schema_count(choice_count, "choice_count")
    handles = tuple(f"cause_{index}" for index in range(1, choice_count + 1))
    handle_type = Literal.__getitem__(handles)
    temporal_handles = temporal_reference_handles or ("target_action", *handles)
    temporal_handle_type = Literal.__getitem__(tuple(temporal_handles))

    temporal_types = _context_temporal_wire_types(
        choice_count,
        temporal_handle_type,
        temporal_handles,
        duration_eligible=duration_eligible,
    )
    outcome_temporal_types = _context_outcome_temporal_wire_types(
        choice_count,
        temporal_handle_type,
        temporal_handles,
        handles,
        duration_eligible=duration_eligible,
        uca_type=uca_type,
        action_temporality=action_temporality,
    )
    temporal_union = _discriminated_union(tuple(temporal_types.values()), "type")
    factor_types = _context_causal_factor_wire_types(
        choice_count,
        handle_type,
        temporal_union,
    )
    factor_union = _discriminated_union(tuple(factor_types.values()), "evidence_status")

    source_handle_list = conlist(handle_type, min_length=1)
    intention_type = create_model(
        f"_ContextAttackerIntentionDraft{choice_count}",
        __base__=_ContextAttackerIntentionDraft,
        source_handles=(source_handle_list, ...),
    )
    attacker_type = create_model(
        f"_ContextAttackerBDIDraft{choice_count}",
        __base__=_ContextAttackerBDIDraft,
        desires=(list[_ContextNonBlankText], ...),
        intentions=(list[intention_type], ...),
    )
    factor_list = conlist(factor_union, min_length=1)
    unsafe_condition_types = _context_unsafe_condition_wire_types(
        choice_count,
        uca_type=uca_type,
        expected_action_kind=expected_action_kind,
        target_action_id=target_action_id,
        state_subject_refs=state_subject_refs,
        condition_reference_refs=condition_reference_refs,
        condition_step_refs=condition_step_refs,
        duration_eligible=duration_eligible,
        observed_argument_specs=observed_argument_specs,
    )
    if uca_type in {UCAType.wrong_timing, UCAType.wrong_duration}:
        unsafe_condition_types = _temporal_unsafe_condition_types(
            outcome_temporal_types,
            uca_type,
            condition_reference_refs=condition_reference_refs,
            condition_step_refs=condition_step_refs,
        )
    if not unsafe_condition_types:
        raise ValueError(
            "selected UCA has no provider unsafe-condition branch supported by the request"
        )
    unsafe_condition_union = _discriminated_union(
        tuple(unsafe_condition_types.values()), "type"
    )
    unsafe_outcome_type = create_model(
        f"_ContextUnsafeOutcomeDraft{choice_count}",
        __base__=_ContextUnsafeOutcomeDraft,
        condition=(unsafe_condition_union, ...),
        semantic_proposition=(StrictStr | None, Field(max_length=600)),
    )
    route_type, executable_route_type, analytical_route_type = (
        _context_route_wire_types(
            choice_count,
            expected_action_kind,
        )
    )
    payload_type = create_model(
        f"_ContextBDIProviderPayload{choice_count}",
        __base__=_ContextBDIProviderPayload,
        stimulus=(_ContextStimulusDraft, ...),
        attacker_bdi=(attacker_type, ...),
        causal_factors=(factor_list, ...),
        unsafe_outcome=(unsafe_outcome_type, ...),
        execution_route=(route_type, ...),
    )
    return {
        "payload": payload_type,
        "temporal": create_model(
            f"_ContextTemporalConditionDraft{choice_count}",
            __base__=_ContextTemporalConditionWire,
            # A discriminated union is represented by its annotation below;
            # this marker is returned for prompt/schema fixture helpers only.
        ),
        **factor_types,
        **temporal_types,
        **unsafe_condition_types,
        "unsafe_outcome": unsafe_outcome_type,
        "executable_route": executable_route_type,
        "analytical_route": analytical_route_type,
    }


def _context_route_wire_types(
    choice_count: int,
    expected_action_kind: ExecutionActionKind | None,
) -> tuple[object, object, type[BaseModel]]:
    """Build the closed provider route union for one request."""
    route_fields: dict[str, tuple[object, object]] = {
        "disposition": (Literal["executable_route"], ...),
    }
    if expected_action_kind is not None:
        exact_action_kind = Literal.__getitem__((expected_action_kind,))
        route_fields["action_kind"] = (exact_action_kind, ...)
    executable_route_type: object = create_model(
        f"_ExecutableRouteSelection{choice_count}",
        __base__=_ContextExecutableRouteDraft,
        **route_fields,
    )
    executable_route_union = executable_route_type
    analytical_route_type = create_model(
        f"_AnalyticalOnlyRouteSelection{choice_count}",
        __base__=AnalyticalOnlyRouteSelection,
        disposition=(Literal["analytical_only"], ...),
    )
    route_type = (
        _discriminated_union(
            (executable_route_union, analytical_route_type), "disposition"
        )
        if executable_route_union is not None
        else analytical_route_type
    )
    return (
        route_type,
        executable_route_type,
        analytical_route_type,
    )


@lru_cache(maxsize=64)
def _context_bdi_provider_payload_type(
    choice_count: int,
    expected_action_kind: ExecutionActionKind | None = None,
    *,
    target_action_id: str | None = None,
    uca_type: UCAType | None = None,
    state_subject_refs: tuple[str, ...] = (),
    temporal_reference_handles: tuple[str, ...] = (),
    condition_reference_refs: tuple[str, ...] = (),
    condition_step_refs: tuple[str, ...] = (),
    duration_eligible: bool = False,
    action_temporality: ControlActionTemporality | None = None,
    observed_argument_specs: tuple[tuple[str, str], ...] = (),
) -> type[BaseModel]:
    """Return one strict response schema over request-local provider handles."""
    return _context_bdi_provider_wire_types(
        choice_count,
        expected_action_kind,
        target_action_id=target_action_id,
        uca_type=uca_type,
        state_subject_refs=state_subject_refs,
        temporal_reference_handles=temporal_reference_handles,
        condition_reference_refs=condition_reference_refs,
        condition_step_refs=condition_step_refs,
        duration_eligible=duration_eligible,
        action_temporality=action_temporality,
        observed_argument_specs=observed_argument_specs,
    )["payload"]


@lru_cache(maxsize=64)
def _scenario_semantics_payload_type(
    choice_count: int,
    *,
    duration_eligible: bool = False,
    observation_criteria_required: bool = False,
    condition_references_supplied: bool = False,
) -> type[BaseModel]:
    """Return the normal-path response schema: semantics and evidence only.

    The payload closes the request-local causal handles to the exact supplied
    choices and keeps the evidence-status branches, but exposes no stimulus,
    execution route, factor-route binding or unsafe-outcome condition.
    """
    _require_positive_schema_count(choice_count, "choice_count")
    handles = tuple(f"cause_{index}" for index in range(1, choice_count + 1))
    handle_type = Literal.__getitem__(handles)
    temporal_handles = ("target_action", *handles)
    temporal_handle_type = Literal.__getitem__(temporal_handles)
    temporal_types = _context_temporal_wire_types(
        choice_count,
        temporal_handle_type,
        temporal_handles,
        duration_eligible=duration_eligible,
    )
    temporal_union = _discriminated_union(tuple(temporal_types.values()), "type")
    factor_types = _context_causal_factor_wire_types(
        choice_count,
        handle_type,
        temporal_union,
        base=_ContextSemanticFactorWireBase,
        model_prefix="_ContextSemantic",
    )
    factor_union = _discriminated_union(tuple(factor_types.values()), "evidence_status")
    source_handle_list = conlist(handle_type, min_length=1)
    intention_type = create_model(
        f"_ContextSemanticIntentionDraft{choice_count}",
        __base__=_ContextAttackerIntentionDraft,
        source_handles=(source_handle_list, ...),
    )
    attacker_type = create_model(
        f"_ContextSemanticAttackerBDIDraft{choice_count}",
        __base__=_ContextAttackerBDIDraft,
        desires=(list[_ContextNonBlankText], ...),
        intentions=(list[intention_type], ...),
    )
    outcome_type: type[BaseModel] = _ContextSemanticOutcomeDraft
    if observation_criteria_required:
        # The condition key is required (nullable) only when the request
        # supplies operations or observations it could reference.
        condition_field: dict[str, object] = (
            {"discriminating_condition": (DiscriminatingCondition | None, ...)}
            if condition_references_supplied
            else {}
        )
        outcome_type = create_model(
            f"_ContextSemanticOutcomeDraft{choice_count}",
            __base__=_ContextSemanticOutcomeDraft,
            observation_criteria=(
                conlist(_ObservationCriterionDraft, min_length=1),
                ...,
            ),
            safe_observable_outcome=(SafeObservableOutcome, ...),
            **condition_field,
        )
    return create_model(
        f"_ContextScenarioSemanticsPayload{choice_count}",
        __base__=_ContextScenarioSemanticsPayload,
        attacker_bdi=(attacker_type, ...),
        causal_factors=(conlist(factor_union, min_length=1), ...),
        unsafe_outcome=(outcome_type, ...),
    )


def _discriminated_union(
    models: tuple[type[BaseModel], ...], discriminator: str
) -> object:
    """Return an annotated union with a required discriminator."""
    return Annotated[Union[models], Field(discriminator=discriminator)]


def _context_temporal_wire_types(
    choice_count: int,
    handle_type: object,
    handles: tuple[str, ...],
    *,
    duration_eligible: bool,
    ordering_reference_handles: tuple[str, ...] | None = None,
    model_prefix: str = "_ContextTemporal",
) -> dict[str, type[BaseModel]]:
    """Create exact request-local temporal branches for causal factors."""
    branch_specs: list[
        tuple[str, type[BaseModel], dict[str, tuple[object, object]]]
    ] = [
        (
            "ordering",
            _ContextOrderingTemporalWire,
            {
                "reference_handle": (handle_type, ...),
            },
        ),
        (
            "delay",
            _ContextDelayTemporalWire,
            {
                "reference_handle": (handle_type, ...),
            },
        ),
        (
            "window",
            _ContextWindowTemporalWire,
            {
                "reference_handle": (handle_type, ...),
            },
        ),
        (
            "absence",
            _ContextAbsenceTemporalWire,
            {
                "reference_handle": (handle_type, ...),
                "until_step_handle": (handle_type, ...),
            },
        ),
    ]
    if duration_eligible:
        branch_specs.insert(
            2,
            (
                "duration",
                _ContextDurationTemporalWire,
                {
                    "reference_handle": (handle_type, ...),
                },
            ),
        )
    result: dict[str, type[BaseModel]] = {}
    for branch, base, fields in branch_specs:
        if branch == "ordering" and ordering_reference_handles is not None:
            fields = {
                **fields,
                "reference_handle": (
                    Literal.__getitem__((*ordering_reference_handles, "target_action")),
                    Field(
                        ...,
                        json_schema_extra={
                            "enum": list(ordering_reference_handles),
                        },
                    ),
                ),
            }
        fields = {
            "type": (Literal.__getitem__((branch,)), ...),
            **fields,
        }
        result[branch] = create_model(
            f"{model_prefix}{branch.title().replace('_', '')}Draft{choice_count}",
            __base__=base,
            **fields,
        )
    return result


def _context_causal_factor_wire_types(
    choice_count: int,
    handle_type: object,
    temporal_union: object,
    *,
    base: type[BaseModel] = _ContextCausalFactorWireBase,
    model_prefix: str = "_Context",
) -> dict[str, type[BaseModel]]:
    """Create evidence-status branches with status-specific requirements."""
    nonempty_refs = conlist(StrictStr, min_length=1)
    common = {
        "source_handle": (handle_type, ...),
        "temporal_condition": (temporal_union | None, ...),
    }
    return {
        "structural_failure": create_model(
            f"{model_prefix}CausalFactorDraft{choice_count}",
            __base__=base,
            **common,
            evidence_status=(Literal["structural_failure"], ...),
        ),
        "reachable_capability": create_model(
            f"{model_prefix}ReachableCausalFactorDraft{choice_count}",
            __base__=base,
            **common,
            evidence_status=(Literal["reachable_capability"], ...),
            capability_refs=(nonempty_refs, ...),
            access_refs=(nonempty_refs, ...),
        ),
        "bounded_assumption": create_model(
            f"{model_prefix}BoundedCausalFactorDraft{choice_count}",
            __base__=base,
            **common,
            evidence_status=(Literal["bounded_assumption"], ...),
            bounded_assumption=(StrictStr, Field(min_length=1)),
        ),
    }


def _context_unsafe_condition_branch_names(
    uca_type: UCAType | None,
    *,
    expected_action_kind: ExecutionActionKind | None,
    state_subject_refs: tuple[str, ...],
    duration_eligible: bool,
    allowed_branches: tuple[str, ...],
) -> tuple[str, ...]:
    """Select condition families permitted by the request authority."""
    by_uca = {
        UCAType.not_provided: ("action_presence",),
        UCAType.incorrect: ("action_value", "state_value"),
        UCAType.wrong_timing: ("ordering", "delay", "window", "absence"),
        UCAType.wrong_duration: ("duration",),
    }
    branches = list(by_uca.get(uca_type, allowed_branches))
    if (
        uca_type is UCAType.incorrect
        and expected_action_kind is ExecutionActionKind.model_output
    ):
        branches = ["action_value"]
    if uca_type is UCAType.incorrect and not state_subject_refs:
        branches = [item for item in branches if item != "state_value"]
    if not branches:
        raise ValueError(
            "selected UCA has no supported provider unsafe-condition branch"
        )
    return tuple(branches)


def _context_unsafe_condition_branch_is_available(
    branch: str,
    *,
    condition_reference_refs: tuple[str, ...],
    condition_step_refs: tuple[str, ...],
) -> bool:
    """Check whether a branch has the references needed to be request-valid."""
    if branch == "ordering":
        return bool(condition_step_refs)
    if branch in {"delay", "duration", "window", "absence"}:
        return bool(condition_reference_refs)
    return True


def _context_unsafe_condition_branch_fields(
    branch: str,
    *,
    expected_action_kind: ExecutionActionKind | None,
    target_action_id: str | None,
    state_subject_refs: tuple[str, ...],
    condition_reference_refs: tuple[str, ...],
    condition_step_refs: tuple[str, ...],
) -> dict[str, tuple[object, object]]:
    """Build exact request-local fields for one unsafe condition branch."""
    fields: dict[str, tuple[object, object]] = {
        "type": (Literal.__getitem__((branch,)), ...),
    }
    if branch in {"action_presence", "action_value"}:
        fields["control_action_id"] = (
            Literal.__getitem__((target_action_id,)) if target_action_id else StrictStr,
            ...,
        )
    if (
        branch == "action_value"
        and expected_action_kind is ExecutionActionKind.model_output
    ):
        fields["property"] = (Literal["semantic_proposition"], ...)
        fields["operator"] = (Literal["equals"], ...)
        fields["expected"] = (Literal[True], ...)
    for field_name, field_branches, refs in (
        ("subject_ref", {"state_value"}, state_subject_refs),
        (
            "reference_ref",
            {"delay", "duration", "window", "absence"},
            condition_reference_refs,
        ),
        ("reference_step_id", {"ordering"}, condition_step_refs),
    ):
        if branch in field_branches and refs:
            fields[field_name] = (Literal.__getitem__(refs), ...)
    return fields


def _context_unsafe_condition_wire_types(
    choice_count: int,
    *,
    uca_type: UCAType | None,
    expected_action_kind: ExecutionActionKind | None = None,
    target_action_id: str | None,
    state_subject_refs: tuple[str, ...],
    condition_reference_refs: tuple[str, ...],
    condition_step_refs: tuple[str, ...],
    duration_eligible: bool,
    observed_argument_specs: tuple[tuple[str, str], ...] = (),
) -> dict[str, type[BaseModel]]:
    """Create only condition families permitted by this request's authority."""
    allowed: dict[str, type[BaseModel]] = {
        "action_presence": _ContextActionPresenceConditionWire,
        "action_value": _ContextActionValueConditionWire,
        "state_value": _ContextStateValueConditionWire,
        "ordering": _ContextOrderingConditionWire,
        "delay": _ContextDelayConditionWire,
        "duration": _ContextDurationConditionWire,
        "window": _ContextWindowConditionWire,
        "absence": _ContextAbsenceConditionWire,
    }
    branches = _context_unsafe_condition_branch_names(
        uca_type,
        expected_action_kind=expected_action_kind,
        state_subject_refs=state_subject_refs,
        duration_eligible=duration_eligible,
        allowed_branches=tuple(allowed),
    )
    result: dict[str, type[BaseModel]] = {}
    for branch in branches:
        if not _context_unsafe_condition_branch_is_available(
            branch,
            condition_reference_refs=condition_reference_refs,
            condition_step_refs=condition_step_refs,
        ):
            continue
        base = allowed[branch]
        fields = _context_unsafe_condition_branch_fields(
            branch,
            expected_action_kind=expected_action_kind,
            target_action_id=target_action_id,
            state_subject_refs=state_subject_refs,
            condition_reference_refs=condition_reference_refs,
            condition_step_refs=condition_step_refs,
        )
        result[branch] = create_model(
            f"_ContextUnsafe{branch.title().replace('_', '')}Condition{choice_count}",
            __base__=base,
            **fields,
        )
    if (
        "action_value" in result
        and observed_argument_specs
        and expected_action_kind is not ExecutionActionKind.model_output
    ):
        result["action_value"] = _context_action_value_condition_union(
            choice_count,
            target_action_id,
            observed_argument_specs,
        )
    return result


def _context_action_value_condition_union(
    choice_count: int,
    target_action_id: str | None,
    observed_argument_specs: tuple[tuple[str, str], ...],
) -> object:
    """Close action-value properties and scalar types to one target schema."""
    condition_types: list[type[BaseModel]] = []
    for index, (property_name, value_type) in enumerate(
        observed_argument_specs, start=1
    ):
        expected_type = _context_observed_argument_value_type(
            choice_count,
            index,
            value_type,
        )
        fields: dict[str, tuple[object, object]] = {
            "type": (Literal["action_value"], ...),
            "control_action_id": (
                Literal.__getitem__((target_action_id,))
                if target_action_id
                else StrictStr,
                ...,
            ),
            "property": (Literal.__getitem__((property_name,)), ...),
            "operator": (
                Literal.__getitem__(
                    (
                        "equals",
                        "not_equals",
                        "contains",
                        "not_contains",
                        "greater_than",
                        "greater_than_or_equal",
                        "less_than",
                        "less_than_or_equal",
                    )
                ),
                ...,
            ),
            "expected": (expected_type, ...),
        }
        condition_types.append(
            create_model(
                f"_ContextUnsafeActionValue{choice_count}Argument{index}",
                __base__=_ContextActionValueConditionWire,
                **fields,
            )
        )
    return _discriminated_union(tuple(condition_types), "property")


def _context_observed_argument_value_type(
    choice_count: int,
    argument_index: int,
    value_type: str,
) -> object:
    """Return a scalar-or-typed-placeholder annotation for one argument."""
    if value_type == "any":
        return SemanticValue
    placeholder_value_type = SemanticBindingValueType(value_type)
    placeholder_type = create_model(
        f"_ContextArgument{choice_count}Binding{argument_index}",
        __base__=SemanticBindingPlaceholder,
        # Use the enum member, rather than its serialized string, so the
        # inherited placeholder bounds validator sees the specialized type.
        value_type=(Literal.__getitem__((placeholder_value_type,)), ...),
    )
    scalar_type: object = {
        "string": StrictStr,
        "integer": StrictInt,
        "number": Union[StrictInt, StrictFloat],
        "boolean": StrictBool,
    }[value_type]
    return Union[placeholder_type, scalar_type]


def _require_positive_schema_count(value: int, name: str) -> None:
    """Reject booleans and non-positive dynamic-schema counts."""
    if type(value) is not int or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
