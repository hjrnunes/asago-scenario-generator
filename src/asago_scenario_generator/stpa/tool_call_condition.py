"""Bound tool-call condition and its binding status (``tool_call_condition`` v1).

A :class:`ToolCallCondition` is the ready-to-evaluate form of a scenario's
discriminating condition: every observed fact is already resolved, so the
comparisons hold only ``argument`` and ``literal`` operands. The Garak
detector ``toolcall.ToolCallCondition`` evaluates it against captured tool
calls. :class:`ToolCallConditionStatus` records whether binding produced one
and, when not, why the scenario cannot be executed against it.

This module is a leaf: it defines closed shapes only. Binding lives in
``stpa.scenario_prod.tool_call_binding``.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal, Union

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    StrictStr,
    field_validator,
    model_serializer,
    model_validator,
)

from asago_scenario_generator.stpa.discriminating_condition import (
    ComparisonOperator,
)

TOOL_CALL_CONDITION_BOUND = "bound"
TOOL_CALL_CONDITION_NOT_EXECUTABLE = "not_executable"
REASON_BOUND = "bound"
REASON_NO_CONDITION = "no_condition"
REASON_CONDITION_PROBLEM = "condition_problem"
REASON_STATE_ONLY = "state_only"
REASON_PRECONDITION_FAILED = "precondition_failed"
REASON_PRECONDITION_UNKNOWN = "precondition_unknown"
REASON_UNRESOLVED_FACT = "unresolved_fact"
NOT_EXECUTABLE_REASONS = (
    REASON_NO_CONDITION,
    REASON_CONDITION_PROBLEM,
    REASON_STATE_ONLY,
    REASON_PRECONDITION_FAILED,
    REASON_PRECONDITION_UNKNOWN,
    REASON_UNRESOLVED_FACT,
)

ToolCallConditionReason = Literal[
    "bound",
    "no_condition",
    "condition_problem",
    "state_only",
    "precondition_failed",
    "precondition_unknown",
    "unresolved_fact",
]


class _ClosedModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _nonblank(value: str, label: str) -> str:
    if not value.strip():
        raise ValueError(f"{label} must not be blank")
    return value


class ToolCallArgumentOperand(_ClosedModel):
    """The named argument of the call assigned to ``operation``."""

    source: Literal["argument"]
    operation: StrictStr = Field(min_length=1)
    argument: StrictStr = Field(min_length=1)


class ToolCallLiteralOperand(_ClosedModel):
    """A resolved value; any JSON value, including null."""

    source: Literal["literal"]
    value: JsonValue

    # Handoffs are dumped with ``exclude_none``; a null literal keeps its key.
    @model_serializer(mode="plain")
    def _serialize(self) -> dict[str, Any]:
        return {"source": self.source, "value": self.value}


ToolCallOperand = Annotated[
    Union[ToolCallArgumentOperand, ToolCallLiteralOperand],
    Field(discriminator="source"),
]


class ToolCallValueComparison(_ClosedModel):
    """``left op right`` over the assigned call's arguments and literals."""

    kind: Literal["value"]
    left: ToolCallOperand
    op: ComparisonOperator
    right: ToolCallOperand

    @model_validator(mode="after")
    def validate_argument_side(self) -> "ToolCallValueComparison":
        """Require at least one argument operand."""

        if not any(
            isinstance(side, ToolCallArgumentOperand)
            for side in (self.left, self.right)
        ):
            raise ValueError("a value comparison needs an argument operand")
        return self


class ToolCallWhere(_ClosedModel):
    """One argument equality that scopes a ``not_called`` comparison."""

    argument: StrictStr = Field(min_length=1)
    value: JsonValue

    @model_serializer(mode="plain")
    def _serialize(self) -> dict[str, Any]:
        return {"argument": self.argument, "value": self.value}


class ToolCallNotCalledComparison(_ClosedModel):
    """No call to ``operation`` whose arguments match every ``where`` item."""

    kind: Literal["not_called"]
    operation: StrictStr = Field(min_length=1)
    where: list[ToolCallWhere] = Field(default_factory=list)


class ToolCallOrderComparison(_ClosedModel):
    """``operation`` has no earlier ``requires_prior`` call (on the same argument)."""

    kind: Literal["order"]
    operation: StrictStr = Field(min_length=1)
    requires_prior: StrictStr = Field(min_length=1)
    same_argument: StrictStr | None = Field(default=None, min_length=1)

    @model_serializer(mode="plain")
    def _serialize(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "operation": self.operation,
            "requires_prior": self.requires_prior,
            "same_argument": self.same_argument,
        }


ToolCallComparison = Annotated[
    Union[
        ToolCallValueComparison,
        ToolCallNotCalledComparison,
        ToolCallOrderComparison,
    ],
    Field(discriminator="kind"),
]


class ToolCallCondition(_ClosedModel):
    """Every comparison must hold for the condition to hold."""

    comparisons: list[ToolCallComparison] = Field(min_length=1)


class ToolCallConditionStatus(_ClosedModel):
    """Whether the scenario's condition bound, and why not when it did not."""

    status: Literal["bound", "not_executable"]
    reason: ToolCallConditionReason
    detail: StrictStr = Field(min_length=1)

    @field_validator("detail")
    @classmethod
    def _detail(cls, value: str) -> str:
        return _nonblank(value, "tool_call_condition_status.detail")

    @model_validator(mode="after")
    def validate_reason(self) -> "ToolCallConditionStatus":
        """Pair ``bound`` with reason ``bound`` and nothing else."""

        if (self.status == TOOL_CALL_CONDITION_BOUND) != (self.reason == REASON_BOUND):
            raise ValueError(
                "tool_call_condition_status reason is 'bound' exactly when "
                "status is 'bound'"
            )
        return self


__all__ = [
    "NOT_EXECUTABLE_REASONS",
    "REASON_BOUND",
    "REASON_CONDITION_PROBLEM",
    "REASON_NO_CONDITION",
    "REASON_PRECONDITION_FAILED",
    "REASON_PRECONDITION_UNKNOWN",
    "REASON_STATE_ONLY",
    "REASON_UNRESOLVED_FACT",
    "TOOL_CALL_CONDITION_BOUND",
    "TOOL_CALL_CONDITION_NOT_EXECUTABLE",
    "ToolCallArgumentOperand",
    "ToolCallComparison",
    "ToolCallCondition",
    "ToolCallConditionReason",
    "ToolCallConditionStatus",
    "ToolCallLiteralOperand",
    "ToolCallNotCalledComparison",
    "ToolCallOperand",
    "ToolCallOrderComparison",
    "ToolCallValueComparison",
    "ToolCallWhere",
]
