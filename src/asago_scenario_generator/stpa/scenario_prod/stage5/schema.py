"""Request-specific Stage 5 response schemas."""

from __future__ import annotations

from functools import lru_cache
from typing import Annotated, Literal, Union
from pydantic import (
    BaseModel,
    Field,
    StrictStr,
    conlist,
    create_model,
)
from asago_scenario_generator.stpa.observation_contract import (
    SafeObservableOutcome,
)
from asago_scenario_generator.stpa.discriminating_condition import (
    DiscriminatingCondition,
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
    base: type[BaseModel],
    model_prefix: str,
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


def _require_positive_schema_count(value: int, name: str) -> None:
    """Reject booleans and non-positive dynamic-schema counts."""
    if type(value) is not int or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
