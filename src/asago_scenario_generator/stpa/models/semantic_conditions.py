"""Neutral, closed semantic-condition value objects.

This leaf is shared by Stage 5 and the v2 execution projection.  It imports
neither the STPA orchestration models nor provider/persistence code, which
keeps the provider response contract typed without creating a model cycle.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping, Sequence
from enum import Enum
from typing import Annotated, Any, Literal, Union

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
    model_validator,
)


_STRUCTURAL_REFERENCE = re.compile(r"^(?:PM|FB|CA|CM)-\d+(?:-\d+)?$|^S-\d+$")
_FACTOR_REFERENCE = re.compile(r"^(?:PM|FB|CA)-\d+(?:-\d+)?$")
_ACTION_REFERENCE = re.compile(r"^(?:CA|CM)-\d+(?:-\d+)?$")


class ClosedSemanticModel(BaseModel):
    """Immutable closed model used by every condition variant."""

    # JSON enum discriminators still need to accept their canonical string
    # values; every scalar value union below is explicitly Strict* instead.
    model_config = ConfigDict(extra="forbid", frozen=True)


class SemanticBindingValueType(str, Enum):
    """Scalar types that an operator may bind without changing condition shape."""

    integer = "integer"
    number = "number"
    string = "string"
    boolean = "boolean"


class SemanticBindingPlaceholder(ClosedSemanticModel):
    """A typed value absent from producer evidence."""

    binding_ref: StrictStr = Field(min_length=1, pattern=r"^SEM-[A-Za-z0-9._-]+$")
    value_type: SemanticBindingValueType
    description: StrictStr = Field(min_length=1)
    minimum: StrictInt | StrictFloat | None = None
    maximum: StrictInt | StrictFloat | None = None

    @model_validator(mode="after")
    def validate_bounds(self) -> "SemanticBindingPlaceholder":
        if self.value_type is SemanticBindingValueType.integer:
            _validate_integer_bounds(self.minimum, self.maximum)
        elif self.value_type is SemanticBindingValueType.number:
            _validate_number_bounds(self.minimum, self.maximum)
        else:
            _reject_bounds_for_non_numeric_type(self.minimum, self.maximum)
        _validate_non_negative_bounds(self.minimum, self.maximum)
        _validate_bound_order(self.minimum, self.maximum)
        return self


SemanticLiteral = Union[StrictStr, StrictInt, StrictFloat, StrictBool]
SemanticValue = Union[SemanticBindingPlaceholder, SemanticLiteral]


class OrderingCondition(ClosedSemanticModel):
    """A relation between an action and an exported projected step."""

    type: Literal["ordering"] = "ordering"
    reference_step_id: StrictStr = Field(min_length=1, pattern=r"^S-\d+$")
    relation: Literal["before", "after"]


class DelayCondition(ClosedSemanticModel):
    """A non-negative feedback delay in integer milliseconds."""

    type: Literal["delay"] = "delay"
    reference_ref: StrictStr = Field(min_length=1)
    delay_ms: SemanticValue

    @model_validator(mode="after")
    def validate_condition(self) -> "DelayCondition":
        _validate_structural_reference(self.reference_ref, "reference_ref")
        _validate_time_value(self.delay_ms, "delay_ms")
        return self


class DurationCondition(ClosedSemanticModel):
    """A non-negative action duration in integer milliseconds."""

    type: Literal["duration"] = "duration"
    reference_ref: StrictStr = Field(min_length=1)
    duration_ms: SemanticValue

    @model_validator(mode="after")
    def validate_condition(self) -> "DurationCondition":
        _validate_structural_reference(self.reference_ref, "reference_ref")
        _validate_time_value(self.duration_ms, "duration_ms")
        return self


class WindowCondition(ClosedSemanticModel):
    """An ordered timing window in integer milliseconds."""

    type: Literal["window"] = "window"
    reference_ref: StrictStr = Field(min_length=1)
    window_from_ms: SemanticValue
    window_to_ms: SemanticValue

    @model_validator(mode="after")
    def validate_condition(self) -> "WindowCondition":
        _validate_structural_reference(self.reference_ref, "reference_ref")
        _validate_time_value(self.window_from_ms, "window_from_ms")
        _validate_time_value(self.window_to_ms, "window_to_ms")
        if not isinstance(
            self.window_from_ms, SemanticBindingPlaceholder
        ) and not isinstance(self.window_to_ms, SemanticBindingPlaceholder):
            if self.window_from_ms > self.window_to_ms:  # type: ignore[operator]
                raise ValueError("window_from_ms must not exceed window_to_ms")
        return self


class AbsenceCondition(ClosedSemanticModel):
    """A structural signal remains absent until an exported step."""

    type: Literal["absence"] = "absence"
    reference_ref: StrictStr = Field(min_length=1)
    until_step_id: StrictStr = Field(min_length=1, pattern=r"^S-\d+$")

    @model_validator(mode="after")
    def validate_condition(self) -> "AbsenceCondition":
        _validate_structural_reference(self.reference_ref, "reference_ref")
        return self


class ActionPresenceCondition(ClosedSemanticModel):
    """The selected action is absent when required."""

    type: Literal["action_presence"] = "action_presence"
    control_action_id: StrictStr = Field(min_length=1)
    expected: Literal["not_provided"] = "not_provided"

    @model_validator(mode="after")
    def validate_condition(self) -> "ActionPresenceCondition":
        _validate_action_reference(self.control_action_id)
        return self


SemanticOperator = Literal[
    "equals",
    "not_equals",
    "contains",
    "not_contains",
    "greater_than",
    "greater_than_or_equal",
    "less_than",
    "less_than_or_equal",
]


class ActionValueCondition(ClosedSemanticModel):
    """The action's semantic property has an expected value."""

    type: Literal["action_value"] = "action_value"
    control_action_id: StrictStr = Field(min_length=1)
    property: StrictStr = Field(min_length=1)
    operator: SemanticOperator
    expected: SemanticValue

    @model_validator(mode="after")
    def validate_condition(self) -> "ActionValueCondition":
        _validate_action_reference(self.control_action_id)
        _validate_scalar(self.expected, "expected")
        return self


class StateValueCondition(ClosedSemanticModel):
    """A structural state subject has an expected semantic value."""

    type: Literal["state_value"] = "state_value"
    subject_ref: StrictStr = Field(min_length=1)
    property: StrictStr = Field(min_length=1)
    operator: SemanticOperator
    expected: SemanticValue

    @model_validator(mode="after")
    def validate_condition(self) -> "StateValueCondition":
        _validate_structural_reference(self.subject_ref, "subject_ref")
        _validate_scalar(self.expected, "expected")
        return self


SemanticCondition = Annotated[
    Union[
        OrderingCondition,
        DelayCondition,
        DurationCondition,
        WindowCondition,
        AbsenceCondition,
        ActionPresenceCondition,
        ActionValueCondition,
        StateValueCondition,
    ],
    Field(discriminator="type"),
]


def _validate_structural_reference(value: str, field_name: str) -> None:
    if not _STRUCTURAL_REFERENCE.fullmatch(value):
        raise ValueError(f"{field_name} must resolve to a PM/FB/CA/CM/S structural ID")


def _validate_action_reference(value: str) -> None:
    if not _ACTION_REFERENCE.fullmatch(value):
        raise ValueError("control_action_id must be a canonical CA-* or CM-* ID")


def _validate_scalar(value: SemanticValue, field_name: str) -> None:
    if isinstance(value, SemanticBindingPlaceholder):
        return
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError(f"{field_name} must be finite")
    if not isinstance(value, (str, int, float, bool)) or value is None:
        raise ValueError(f"{field_name} must be a literal scalar or typed placeholder")


def _validate_time_value(value: SemanticValue, field_name: str) -> None:
    _validate_scalar(value, field_name)
    if isinstance(value, SemanticBindingPlaceholder):
        if value.value_type not in (
            SemanticBindingValueType.integer,
            SemanticBindingValueType.number,
        ):
            raise ValueError(f"{field_name} placeholder must be numeric")
        return
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(
            f"{field_name} must be a non-negative integer number of milliseconds"
        )
    if value < 0:
        raise ValueError(f"{field_name} must be non-negative")


def _validate_integer_bounds(
    minimum: StrictInt | StrictFloat | None,
    maximum: StrictInt | StrictFloat | None,
) -> None:
    """Require integer-compatible bounds for an integer placeholder."""
    _validate_integer_bound("minimum", minimum)
    _validate_integer_bound("maximum", maximum)


def _validate_integer_bound(name: str, value: StrictInt | StrictFloat | None) -> None:
    if value is not None and (isinstance(value, bool) or not isinstance(value, int)):
        raise ValueError(f"{name} must be an integer for an integer binding")


def _validate_number_bounds(
    minimum: StrictInt | StrictFloat | None,
    maximum: StrictInt | StrictFloat | None,
) -> None:
    """Require finite numeric bounds for a number placeholder."""
    _validate_number_bound("minimum", minimum)
    _validate_number_bound("maximum", maximum)


def _validate_number_bound(name: str, value: StrictInt | StrictFloat | None) -> None:
    if value is not None and isinstance(value, bool):
        raise ValueError(f"{name} must be numeric for a number binding")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError(f"{name} must be finite")


def _reject_bounds_for_non_numeric_type(
    minimum: StrictInt | StrictFloat | None,
    maximum: StrictInt | StrictFloat | None,
) -> None:
    if minimum is not None or maximum is not None:
        raise ValueError("string and boolean bindings cannot declare numeric bounds")


def _validate_non_negative_bounds(
    minimum: StrictInt | StrictFloat | None,
    maximum: StrictInt | StrictFloat | None,
) -> None:
    _validate_non_negative_bound("minimum", minimum)
    _validate_non_negative_bound("maximum", maximum)


def _validate_non_negative_bound(
    name: str, value: StrictInt | StrictFloat | None
) -> None:
    if value is not None and value < 0:
        raise ValueError(f"binding {name} must be non-negative")


def _validate_bound_order(
    minimum: StrictInt | StrictFloat | None,
    maximum: StrictInt | StrictFloat | None,
) -> None:
    if minimum is not None and maximum is not None and minimum > maximum:
        raise ValueError("binding minimum must not exceed maximum")


def contains_binding_placeholder(value: Any) -> bool:
    """Return whether a semantic condition tree contains a typed placeholder."""
    if isinstance(value, SemanticBindingPlaceholder):
        return True
    if isinstance(value, BaseModel):
        return _contains_in_model(value)
    if isinstance(value, Mapping):
        return _contains_in_mapping(value)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return _contains_in_sequence(value)
    return False


def _contains_in_model(value: BaseModel) -> bool:
    """Walk live model values so placeholders survive before serialization."""
    return any(contains_binding_placeholder(item) for item in value.__dict__.values())


def _contains_in_mapping(value: Mapping[Any, Any]) -> bool:
    return any(contains_binding_placeholder(item) for item in value.values())


def _contains_in_sequence(value: Sequence[Any]) -> bool:
    return any(contains_binding_placeholder(item) for item in value)


def collect_binding_refs(value: Any) -> tuple[str, ...]:
    """Collect binding references in deterministic semantic traversal order."""
    refs: list[str] = []

    def visit(node: Any) -> None:
        if isinstance(node, SemanticBindingPlaceholder):
            refs.append(node.binding_ref)
        elif isinstance(node, BaseModel):
            _visit_model(node, visit)
        elif isinstance(node, Mapping):
            _visit_mapping(node, visit)
        elif isinstance(node, Sequence) and not isinstance(
            node, (str, bytes, bytearray)
        ):
            _visit_sequence(node, visit)

    visit(value)
    return tuple(refs)


def _visit_model(node: BaseModel, visit: Any) -> None:
    for key in sorted(node.__dict__):
        visit(node.__dict__[key])


def _visit_mapping(node: Mapping[Any, Any], visit: Any) -> None:
    for key in sorted(node):
        visit(node[key])


def _visit_sequence(node: Sequence[Any], visit: Any) -> None:
    for item in node:
        visit(item)


__all__ = [
    "AbsenceCondition",
    "ActionPresenceCondition",
    "ActionValueCondition",
    "ClosedSemanticModel",
    "DelayCondition",
    "DurationCondition",
    "OrderingCondition",
    "SemanticBindingPlaceholder",
    "SemanticBindingValueType",
    "SemanticCondition",
    "SemanticLiteral",
    "SemanticOperator",
    "SemanticValue",
    "StateValueCondition",
    "WindowCondition",
    "collect_binding_refs",
    "contains_binding_placeholder",
]
