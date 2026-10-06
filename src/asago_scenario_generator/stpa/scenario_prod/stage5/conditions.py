"""Temporal and provider condition construction for Stage 5 drafts."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from pydantic import (
    BaseModel,
)
from asago_scenario_generator.stpa.scenario_prod.outcome_grounding import (
    scope_temporal_placeholder,
)
from asago_scenario_generator.stpa.models.semantic_conditions import (
    AbsenceCondition,
    ActionPresenceCondition,
    ActionValueCondition,
    DelayCondition,
    DurationCondition,
    OrderingCondition,
    SemanticBindingPlaceholder,
    SemanticCondition,
    SemanticValue,
    StateValueCondition,
    WindowCondition,
)
from asago_scenario_generator.stpa.models.scenario_context import (
    ScenarioGenerationContext,
)
from .wire import (
    _CausalSourceChoice,
    _ContextStateValueConditionWire,
    _ContextTemporalConditionWire,
)


_PROVIDER_PLACEHOLDER_REF = re.compile(r"^SEM-[A-Za-z0-9._-]+$")


def _normalize_legacy_temporal_fields(payload: dict[str, object]) -> None:
    """Translate old canonical temporal field names into local draft names."""
    factors = payload.get("causal_factors")
    if not isinstance(factors, Sequence) or isinstance(factors, (str, bytes)):
        return
    for factor in factors:
        _normalize_legacy_temporal_factor(factor)


def _normalize_legacy_temporal_factor(factor: object) -> None:
    """Normalize one historical factor mapping in place when possible."""
    if not isinstance(factor, Mapping):
        return
    temporal = factor.get("temporal_condition")
    if not isinstance(temporal, Mapping):
        return
    normalized = dict(temporal)
    _copy_first_legacy_temporal_field(
        normalized,
        "reference_handle",
        (
            "reference_ref",
            "reference_step_id",
            "reference_step_handle",
            "source_handle",
        ),
    )
    _copy_first_legacy_temporal_field(
        normalized,
        "until_step_handle",
        ("until_step_id", "until_step"),
    )
    if isinstance(factor, dict):
        factor["temporal_condition"] = normalized


def _copy_first_legacy_temporal_field(
    values: dict[str, object],
    target_name: str,
    legacy_names: Sequence[str],
) -> None:
    """Copy and remove the first matching historical temporal field."""
    if target_name in values:
        return
    for old_name in legacy_names:
        if old_name in values:
            values[target_name] = values.pop(old_name)
            return


def _resolve_temporal_condition(
    draft: _ContextTemporalConditionWire | SemanticCondition | None,
    factor_handle: str,
    choices: Sequence[_CausalSourceChoice],
    context: ScenarioGenerationContext,
    *,
    factor_order: Mapping[str, int] | None = None,
    binding_scope: str = "condition",
) -> SemanticCondition | None:
    """Resolve one provider temporal draft into a canonical condition.

    ``factor_order`` is the declaration order used by the later execution
    projection (``S-1`` … ``S-N`` and the final UCA step).  Structural IDs are
    accepted only as a compatibility path when they are already present in
    this exact selected context; no provider-authored identity is invented.
    """
    if draft is None:
        return None
    if not isinstance(draft, _ContextTemporalConditionWire):
        # Direct callers may already hold a canonical condition.  It has
        # already passed the structural-reference validators and remains
        # compatible with the historical non-contextual path.
        return draft
    by_handle = {choice.handle: choice for choice in choices}
    factor_order = factor_order or {factor_handle: 1}
    reference_handle = draft.reference_handle
    if reference_handle is None:
        raise ValueError("temporal condition requires a reference_handle")
    resolved_reference = _temporal_structural_reference_for_draft(
        draft, reference_handle, by_handle, choices, context
    )
    return _build_temporal_condition(
        draft,
        reference_handle,
        resolved_reference,
        factor_order,
        by_handle,
        binding_scope,
    )


def _temporal_structural_reference(
    handle: str,
    by_handle: Mapping[str, _CausalSourceChoice],
    choices: Sequence[_CausalSourceChoice],
    context: ScenarioGenerationContext,
) -> str:
    """Resolve a local structural temporal reference to an exact ID."""
    if handle == "target_action":
        return context.target_control_path.control_action.action_id
    if handle in by_handle:
        return by_handle[handle].source_id
    if handle in {choice.source_id for choice in choices}:
        return handle
    raise ValueError(
        "temporal reference_handle must name a supplied target_action or cause handle"
    )


def _temporal_structural_reference_for_draft(
    draft: _ContextTemporalConditionWire,
    reference_handle: str,
    by_handle: Mapping[str, _CausalSourceChoice],
    choices: Sequence[_CausalSourceChoice],
    context: ScenarioGenerationContext,
) -> str | None:
    """Resolve only condition families that carry a structural reference."""
    if draft.type == "ordering":
        return None
    return _temporal_structural_reference(reference_handle, by_handle, choices, context)


def _temporal_step_index(handle: str) -> int | None:
    """Parse one explicitly named local step, if its prefix is recognized."""
    if handle.startswith("step_"):
        prefix = "step_"
    elif handle.startswith("S-"):
        prefix = "S-"
    else:
        return None
    try:
        return int(handle.removeprefix(prefix))
    except ValueError as exc:
        raise ValueError("temporal step reference is malformed") from exc


def _temporal_step_reference(
    handle: str,
    factor_order: Mapping[str, int],
    by_handle: Mapping[str, _CausalSourceChoice],
) -> str:
    """Resolve a local step reference without inventing undeclared steps."""
    if handle == "target_action":
        return f"S-{len(factor_order) + 1}"
    if handle in factor_order:
        return f"S-{factor_order[handle]}"
    if handle in by_handle:
        raise ValueError("temporal step reference must name a declared causal factor")
    index = _temporal_step_index(handle)
    if index is not None and 1 <= index <= len(factor_order) + 1:
        return f"S-{index}"
    raise ValueError(
        "temporal step reference must name target_action or a declared cause handle"
    )


def _build_temporal_condition(
    draft: _ContextTemporalConditionWire,
    reference_handle: str,
    resolved_reference: str | None,
    factor_order: Mapping[str, int],
    by_handle: Mapping[str, _CausalSourceChoice],
    binding_scope: str,
) -> SemanticCondition:
    """Construct one canonical semantic condition from resolved references."""
    if draft.type == "ordering":
        reference_step = _temporal_step_reference(
            reference_handle, factor_order, by_handle
        )
        if (
            binding_scope == "outcome"
            and reference_step == f"S-{len(factor_order) + 1}"
        ):
            raise ValueError(
                "unsafe outcome ordering cannot compare the target action with itself; "
                "name a distinct declared reference event without inventing one"
            )
        return OrderingCondition(
            reference_step_id=reference_step,
            relation=draft.relation,  # type: ignore[arg-type]
        )
    if draft.type == "delay":
        return DelayCondition(
            reference_ref=resolved_reference,
            delay_ms=_coerce_temporal_value(draft.delay_ms, "delay_ms", binding_scope),
        )
    if draft.type in {"duration", "window"}:
        return _build_duration_or_window_condition(
            draft, resolved_reference, binding_scope
        )
    if draft.type == "absence":
        return AbsenceCondition(
            reference_ref=resolved_reference,
            until_step_id=_temporal_step_reference(
                draft.until_step_handle or "", factor_order, by_handle
            ),
        )
    raise ValueError(f"unsupported temporal condition type: {draft.type}")


def _build_duration_or_window_condition(
    draft: _ContextTemporalConditionWire,
    resolved_reference: str | None,
    binding_scope: str,
) -> SemanticCondition:
    """Build the bounded temporal families sharing one structural reference."""
    if draft.type == "duration":
        return DurationCondition(
            reference_ref=resolved_reference,  # type: ignore[arg-type]
            duration_ms=_coerce_temporal_value(
                draft.duration_ms, "duration_ms", binding_scope
            ),
        )
    return WindowCondition(
        reference_ref=resolved_reference,  # type: ignore[arg-type]
        window_from_ms=_coerce_temporal_value(
            draft.window_from_ms, "window_from_ms", binding_scope
        ),
        window_to_ms=_coerce_temporal_value(
            draft.window_to_ms, "window_to_ms", binding_scope
        ),
    )


def _coerce_temporal_value(
    value: SemanticValue | None,
    field_name: str,
    binding_scope: str,
) -> SemanticValue:
    """Normalize a provider's shorthand temporal placeholder to the typed form."""
    if isinstance(value, str) and _PROVIDER_PLACEHOLDER_REF.fullmatch(value):
        value = SemanticBindingPlaceholder(
            binding_ref=value,
            value_type="integer",
            description=(
                f"Unresolved {field_name} value; bind it from supplied time evidence."
            ),
        )
    if isinstance(value, SemanticBindingPlaceholder):
        value = scope_temporal_placeholder(
            value,
            binding_scope,
            field_name.removesuffix("_ms"),
        )
    if value is None:
        raise ValueError(
            f"{field_name} is required for the selected temporal condition"
        )
    return value


def _resolve_state_value_subject(
    condition: object,
    choices: Sequence[_CausalSourceChoice],
) -> object:
    """Resolve the state-condition copy field from an explained local handle."""
    if not isinstance(condition, _ContextStateValueConditionWire):
        return condition
    source_ids = {choice.handle: choice.source_id for choice in choices}
    payload = condition.model_dump(mode="python")
    payload["subject_ref"] = source_ids.get(
        condition.subject_ref, condition.subject_ref
    )
    # Canonical references remain supported for existing internal callers;
    # the provider wire schema allows only the explained request-local handles.
    return StateValueCondition.model_validate(payload)


def _materialize_provider_condition(value: object) -> SemanticCondition:
    """Convert a strict provider-wire condition into the inward value model."""
    if isinstance(
        value,
        (
            OrderingCondition,
            DelayCondition,
            DurationCondition,
            WindowCondition,
            AbsenceCondition,
            ActionValueCondition,
            StateValueCondition,
            ActionPresenceCondition,
        ),
    ):
        return value
    if not isinstance(value, BaseModel):
        raise TypeError("unsafe_outcome condition must be a provider-wire model")
    models = {
        "ordering": OrderingCondition,
        "delay": DelayCondition,
        "duration": DurationCondition,
        "window": WindowCondition,
        "absence": AbsenceCondition,
        "action_presence": ActionPresenceCondition,
        "action_value": ActionValueCondition,
        "state_value": StateValueCondition,
    }
    condition_type = getattr(value, "type", None)
    model = models.get(condition_type)
    if model is None:
        raise ValueError(
            f"unsupported provider unsafe condition type: {condition_type}"
        )
    return model.model_validate(value.model_dump(mode="json"))
