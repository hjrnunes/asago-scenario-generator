"""Causal-source choices and the control-action, stimulus, and delivery facts Stage 5 reads."""

from __future__ import annotations

from asago_scenario_generator.models.target_realization import (
    TargetOperationObservation,
)
from asago_scenario_generator.stpa.models.causal_factor import (
    CausalFactorKind,
)
from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionActionKind,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlActionTemporality,
)
from asago_scenario_generator.stpa.models.scenario_context import (
    DescribedControlAction,
    ScenarioGenerationContext,
)
from ..context import execution_implementation_kind
from .wire import (
    _CausalSourceChoice,
)


# Keep the mapping here, at the Stage 5 boundary, so a provider cannot turn
# free-form action prose into an execution classification.
_ACTION_EFFECT_KINDS: dict[str, ExecutionActionKind] = {
    "model_output": ExecutionActionKind.model_output,
    "tool_call": ExecutionActionKind.tool_call,
    "state_change": ExecutionActionKind.state_change,
    "agent_message": ExecutionActionKind.agent_message,
    "environment_action": ExecutionActionKind.environment_action,
}


_UNTRUSTED_SOURCE_KINDS = frozenset(
    {"user_message", "conversation_history", "retrieved_content"}
)


def _context_expected_action_kind(
    context: ScenarioGenerationContext,
    target_operation: TargetOperationObservation | None = None,
) -> ExecutionActionKind | None:
    """Return the fixed typed action kind expected by the provider route."""
    implementation_kind = execution_implementation_kind(
        context.target_control_path.control_action,
        target_operation,
    )
    if implementation_kind is None:
        return None
    return _ACTION_EFFECT_KINDS[implementation_kind.value]


def _action_temporality(action: object) -> ControlActionTemporality | None:
    """Return typed action temporality, preserving explicit uncertainty."""
    value = getattr(action, "temporality", None)
    try:
        return ControlActionTemporality(value)
    except (TypeError, ValueError):
        return None


def _action_duration_eligible(action: object) -> bool:
    """Return whether typed action temporality permits a duration condition."""
    temporality = _action_temporality(action)
    return temporality in {
        ControlActionTemporality.continuous,
        ControlActionTemporality.bounded_duration,
    }


def _typed_control_action_target_kind(action: DescribedControlAction) -> str | None:
    """Return the normalized typed target kind."""
    return _normalize_typed_value(action.target_kind)


def _typed_control_action_effect(action: DescribedControlAction) -> str | None:
    """Return the normalized typed effect, if one is supplied."""
    return _normalize_typed_value(action.effect_kind)


def _normalize_typed_value(value: object | None) -> str | None:
    """Normalize an enum or string value without interpreting free text."""
    raw = getattr(value, "value", value)
    if not isinstance(raw, str):
        return None
    return raw.strip().lower().replace("-", "_").replace(" ", "_") or None


def _causal_source_choices(
    context: ScenarioGenerationContext,
) -> tuple[_CausalSourceChoice, ...]:
    """Project the selected path into request-local executable source choices."""
    path = context.target_control_path
    feedback_source_kinds = {
        item.element_id: item.source_kind for item in path.feedback
    }
    candidates: list[tuple[CausalFactorKind, str, str]] = []
    candidates.extend(
        (CausalFactorKind.process_model_flaw, item.element_id, item.description)
        for item in path.process_model_parts
    )
    for item in path.feedback:
        candidates.extend(
            (
                (CausalFactorKind.feedback_delay, item.element_id, item.description),
                (CausalFactorKind.sensor_anomaly, item.element_id, item.description),
            )
        )
    actions = (path.control_action, *path.related_control_actions)
    candidates.extend(
        (CausalFactorKind.actuator_anomaly, item.action_id, item.description)
        for item in actions
        if item.action_id.startswith("CA-")
    )
    unique = tuple(dict.fromkeys(candidates))
    return tuple(
        _CausalSourceChoice(
            handle=f"cause_{index}",
            kind=kind,
            source_id=source_id,
            description=description,
            source_kind=(
                feedback_source_kinds.get(source_id)
                if kind
                in {CausalFactorKind.feedback_delay, CausalFactorKind.sensor_anomaly}
                else None
            ),
        )
        for index, (kind, source_id, description) in enumerate(unique, start=1)
    )
