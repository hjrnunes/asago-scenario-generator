"""Request-specific Stage 5 response schemas."""

from __future__ import annotations

from functools import lru_cache
from typing import Annotated, Any, Literal, Union
from pydantic import (
    BaseModel,
    Field,
    StrictStr,
    conlist,
    create_model,
)
from asago_scenario_generator.stpa.observation_contract import (
    FailureCall,
    SafeObservableOutcome,
)
from asago_scenario_generator.request_schema import string_enum
from asago_scenario_generator.stpa.discriminating_condition import (
    ArgumentOperand,
    ArgumentValueSelection,
    DiscriminatingCondition,
    NotCalledComparison,
    OrderComparison,
)
from .wire import (
    _ContextAbsenceTemporalWire,
    _ContextAttackerBDIDraft,
    _ContextAttackerIntentionDraft,
    _ContextDelayTemporalWire,
    _ContextDurationTemporalWire,
    _ContextNonBlankText,
    _ContextOrderingTemporalWire,
    _ContextScenarioSemanticsPayload,
    _ContextSemanticFactorWireBase,
    _ContextSemanticOutcomeDraft,
    _ContextWindowTemporalWire,
    _ObservationCriterionDraft,
)


@lru_cache(maxsize=64)
def _scenario_semantics_payload_type(
    choice_count: int,
    *,
    duration_eligible: bool = False,
    observation_criteria_required: bool = False,
    condition_references_supplied: bool = False,
    failure_call_supported: bool = False,
    condition_operations: tuple[str, ...] = (),
) -> type[BaseModel]:
    """Return the normal-path response schema: semantics and evidence only.

    The payload closes the request-local causal handles to the exact supplied
    choices and keeps the evidence-status branches, but exposes no stimulus,
    execution route, factor-route binding or unsafe-outcome condition.
    ``failure_call_supported`` adds the required, nullable ``failure_call``
    of the failure criterion, which the prompt explains only when the
    contract captures tool calls. ``condition_operations`` closes every
    operation name of the discriminating condition to the request's operation
    inventory (:func:`_with_condition_operations`).
    """
    _require_positive_schema_count(choice_count, "choice_count")
    suffix = f"{choice_count}"
    handles = tuple(f"cause_{index}" for index in range(1, choice_count + 1))
    handle_type = Literal.__getitem__(handles)
    temporal_handles = ("target_action", *handles)
    temporal_handle_type = Literal.__getitem__(temporal_handles)
    temporal_types = _context_temporal_wire_types(
        choice_count, temporal_handle_type, duration_eligible=duration_eligible
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
        f"_ContextSemanticIntentionDraft{suffix}",
        __base__=_ContextAttackerIntentionDraft,
        source_handles=(source_handle_list, ...),
    )
    attacker_type = create_model(
        f"_ContextSemanticAttackerBDIDraft{suffix}",
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
        # Required and nullable: the reply states the failure call, or null
        # when the failure is not a call of one inventory operation.
        failure_call_field: dict[str, object] = (
            {"failure_call": (FailureCall | None, ...)}
            if failure_call_supported
            else {}
        )
        outcome_type = create_model(
            f"_ContextSemanticOutcomeDraft{suffix}",
            __base__=_ContextSemanticOutcomeDraft,
            observation_criteria=(
                conlist(_ObservationCriterionDraft, min_length=1),
                ...,
            ),
            safe_observable_outcome=(SafeObservableOutcome, ...),
            **failure_call_field,
            **condition_field,
        )
    payload_type = create_model(
        f"_ContextScenarioSemanticsPayload{suffix}",
        __base__=_ContextScenarioSemanticsPayload,
        attacker_bdi=(attacker_type, ...),
        causal_factors=(conlist(factor_union, min_length=1), ...),
        unsafe_outcome=(outcome_type, ...),
    )
    condition_offered = observation_criteria_required and condition_references_supplied
    if condition_offered and condition_operations:
        return _with_condition_operations(payload_type, condition_operations)
    return payload_type


# Each condition model and its fields that name an operation of the inventory.
_CONDITION_OPERATION_FIELDS: tuple[tuple[type[BaseModel], tuple[str, ...]], ...] = (
    (ArgumentOperand, ("operation",)),
    (OrderComparison, ("operation", "requires_prior")),
    (NotCalledComparison, ("operation",)),
    (ArgumentValueSelection, ("operation",)),
)


def _with_condition_operations(
    model: type[BaseModel], operations: tuple[str, ...]
) -> type[BaseModel]:
    """Return a subclass whose schema closes condition operations to ``operations``.

    A guided decoder samples any string an open field allows. In the flat
    comparison object the nullable fields of the other branches follow
    ``operation``, so a reply that closes the comparison early writes the
    closing characters into the name. The enum keeps the reply inside the
    inventory. Only the schema changes: a reply still parses with any name,
    so the condition check rejects one outside the inventory with its exact
    correction.
    """

    def model_json_schema(cls: type[BaseModel], *args: Any, **kwargs: Any):
        schema = super(closed, cls).model_json_schema(*args, **kwargs)
        definitions = schema["$defs"]
        for condition_model, names in _CONDITION_OPERATION_FIELDS:
            properties = definitions[condition_model.__name__]["properties"]
            for name in names:
                _close_string(properties[name], operations)
        return schema

    closed = type(
        model.__name__,
        (model,),
        {
            "__module__": model.__module__,
            "__qualname__": model.__qualname__,
            "model_json_schema": classmethod(model_json_schema),
        },
    )
    return closed


def _close_string(field: dict[str, Any], operations: tuple[str, ...]) -> None:
    """Add the enum to a string field, or to the string branch of a nullable one."""

    branches = field.get("anyOf", [field])
    [string] = [branch for branch in branches if branch.get("type") == "string"]
    string_enum(operations)(string)


def _discriminated_union(
    models: tuple[type[BaseModel], ...], discriminator: str
) -> object:
    """Return an annotated union with a required discriminator."""
    return Annotated[Union[models], Field(discriminator=discriminator)]


def _context_temporal_wire_types(
    choice_count: int,
    handle_type: object,
    *,
    duration_eligible: bool,
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
        fields = {
            "type": (Literal.__getitem__((branch,)), ...),
            **fields,
        }
        result[branch] = create_model(
            f"_ContextTemporal{branch.title().replace('_', '')}Draft{choice_count}",
            __base__=base,
            **fields,
        )
    return result


def _context_causal_factor_wire_types(
    choice_count: int,
    handle_type: object,
    temporal_union: object,
    *,
    base: type[BaseModel],
    model_prefix: str,
) -> dict[str, type[BaseModel]]:
    """Create evidence-status branches with status-specific requirements."""
    nonempty_refs = conlist(StrictStr, min_length=1)
    suffix = f"{choice_count}"
    common = {
        "source_handle": (handle_type, ...),
        "temporal_condition": (temporal_union | None, ...),
    }
    return {
        "structural_failure": create_model(
            f"{model_prefix}CausalFactorDraft{suffix}",
            __base__=base,
            **common,
            evidence_status=(Literal["structural_failure"], ...),
        ),
        "reachable_capability": create_model(
            f"{model_prefix}ReachableCausalFactorDraft{suffix}",
            __base__=base,
            **common,
            evidence_status=(Literal["reachable_capability"], ...),
            capability_refs=(nonempty_refs, ...),
            access_refs=(nonempty_refs, ...),
        ),
        "bounded_assumption": create_model(
            f"{model_prefix}BoundedCausalFactorDraft{suffix}",
            __base__=base,
            **common,
            evidence_status=(Literal["bounded_assumption"], ...),
            bounded_assumption=(StrictStr, Field(min_length=1)),
        ),
    }


def _require_positive_schema_count(value: int, name: str) -> None:
    """Reject booleans and non-positive dynamic-schema counts."""
    if type(value) is not int or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
