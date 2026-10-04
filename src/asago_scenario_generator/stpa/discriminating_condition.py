"""Structured condition that separates unsafe from safe scenario behavior.

Stage 5 authors a :class:`DiscriminatingCondition` for every executable
scenario that has target facts to reference. The statement is one plain
sentence; the comparisons restate it over operation arguments, observed
target facts, literals, call ordering, or an operation that is never called
(an omission); the record selection names the
observed record the test should act on, or says explicitly that none is
available. Deterministic code owns :class:`ConditionCheck`, the evaluation of
those comparisons against the observed values.

This module is a leaf: it defines closed shapes only. Reference resolution
and evaluation live in ``stpa.scenario_prod.condition_check``.
"""

from __future__ import annotations

import json
import re
from typing import Annotated, Literal, Union

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
    field_validator,
    model_validator,
)

CONDITION_STATEMENT_MAX_LENGTH = 400
# Same plain-text rules as ``semantic_conditions.normalize_semantic_proposition``.
# Copied rather than imported: importing ``stpa.models`` here closes an import
# cycle through ``scenario_spec``.
_STRUCTURAL_ID = re.compile(
    r"\b(?:PM|FB|CA|CM|CL|CP|RESP|H|L|SC|CF|SEM|REQ|OUTCOME|EXEC|SCN)-[A-Za-z0-9._-]+\b"
)
_URL = re.compile(r"\b(?:https?|ftp)://|\bwww\.", re.IGNORECASE)
MAX_CONDITION_COMPARISONS = 6
MAX_ARGUMENT_VALUES = 8

ComparisonOperator = Literal["eq", "ne", "gt", "ge", "lt", "le", "in", "not_in"]
ComparisonResult = Literal["satisfied", "violated", "not_checkable"]
ORDERED_OPERATORS = frozenset({"gt", "ge", "lt", "le"})
MEMBERSHIP_OPERATORS = frozenset({"in", "not_in"})

LiteralScalar = Union[StrictBool, StrictInt, StrictFloat, StrictStr]


class _ClosedModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _nonblank(value: str, label: str) -> str:
    stripped = value.strip()
    if not stripped:
        raise ValueError(f"{label} must not be blank")
    return stripped


class ArgumentOperand(_ClosedModel):
    """An argument of one observed operation, valued at request time."""

    source: Literal["argument"]
    operation: StrictStr = Field(min_length=1)
    argument: StrictStr = Field(min_length=1)

    @field_validator("operation", "argument")
    @classmethod
    def _strip(cls, value: str) -> str:
        return _nonblank(value, "argument operand reference")


class FactOperand(_ClosedModel):
    """One supplied target-observation fact path."""

    source: Literal["fact"]
    path: StrictStr = Field(min_length=1)

    @field_validator("path")
    @classmethod
    def _strip(cls, value: str) -> str:
        return _nonblank(value, "fact operand path")


class LiteralOperand(_ClosedModel):
    """A literal value; a list is allowed only as the right side of in/not_in."""

    source: Literal["literal"]
    value: LiteralScalar | list[LiteralScalar]


Operand = Annotated[
    Union[ArgumentOperand, FactOperand, LiteralOperand],
    Field(discriminator="source"),
]


class ValueComparison(_ClosedModel):
    """``left op right`` holds when the behavior is unsafe."""

    kind: Literal["value"]
    left: Operand
    op: ComparisonOperator
    right: Operand

    @model_validator(mode="after")
    def validate_literal_shapes(self) -> "ValueComparison":
        """Reject literal shapes that no operator can compare."""

        _check_literal_sides(self.left, self.right)
        _check_literal_list_operator(self.right, self.op)
        if self.op in ORDERED_OPERATORS:
            for side, operand in (("left", self.left), ("right", self.right)):
                if isinstance(operand, LiteralOperand) and not _is_number(
                    operand.value
                ):
                    raise ValueError(f"op {self.op} requires a numeric {side} literal")
        return self


class OrderComparison(_ClosedModel):
    """``operation`` is called without a prior call to ``requires_prior``."""

    kind: Literal["order"]
    operation: StrictStr = Field(min_length=1)
    requires_prior: StrictStr = Field(min_length=1)
    same_argument: StrictStr | None = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def validate_distinct_operations(self) -> "OrderComparison":
        """An operation cannot be its own prerequisite."""

        if self.operation.strip() == self.requires_prior.strip():
            raise ValueError("order comparison requires two distinct operations")
        return self


class NotCalledComparison(_ClosedModel):
    """The behavior is unsafe when ``operation`` is never called (an omission)."""

    kind: Literal["not_called"]
    operation: StrictStr = Field(min_length=1)

    @field_validator("operation")
    @classmethod
    def _strip(cls, value: str) -> str:
        return _nonblank(value, "not_called operation")


Comparison = Annotated[
    Union[ValueComparison, OrderComparison, NotCalledComparison],
    Field(discriminator="kind"),
]


class ArgumentValueSelection(_ClosedModel):
    """The observed fact whose value the test would use for one argument."""

    operation: StrictStr = Field(min_length=1)
    argument: StrictStr = Field(min_length=1)
    path: StrictStr = Field(min_length=1)


class ObservedRecordSelection(_ClosedModel):
    """An observed record that meets the condition."""

    status: Literal["observed"]
    record_path: StrictStr = Field(min_length=1)
    argument_values: list[ArgumentValueSelection] = Field(
        default_factory=list, max_length=MAX_ARGUMENT_VALUES
    )

    @model_validator(mode="after")
    def validate_unique_arguments(self) -> "ObservedRecordSelection":
        """Select at most one observed value per operation argument."""

        keys = [(item.operation, item.argument) for item in self.argument_values]
        if len(keys) != len(set(keys)):
            raise ValueError(
                "record_selection.argument_values must name each operation "
                "argument once"
            )
        return self


class UnavailableRecordSelection(_ClosedModel):
    """No observed record meets the condition; downstream supplies one."""

    status: Literal["unavailable"]
    reason: StrictStr = Field(min_length=1, max_length=CONDITION_STATEMENT_MAX_LENGTH)

    @field_validator("reason")
    @classmethod
    def _strip(cls, value: str) -> str:
        return _nonblank(value, "record_selection.reason")


RecordSelection = Annotated[
    Union[ObservedRecordSelection, UnavailableRecordSelection],
    Field(discriminator="status"),
]


class DiscriminatingCondition(_ClosedModel):
    """The model-authored condition that makes the behavior unsafe."""

    statement: StrictStr = Field(
        min_length=1, max_length=CONDITION_STATEMENT_MAX_LENGTH
    )
    comparisons: list[Comparison] = Field(
        min_length=1, max_length=MAX_CONDITION_COMPARISONS
    )
    record_selection: RecordSelection

    @field_validator("statement")
    @classmethod
    def _normalize_statement(cls, value: str) -> str:
        statement = _nonblank(value, "discriminating_condition.statement")
        if "\n" in statement or "\r" in statement:
            raise ValueError("discriminating_condition.statement must be one line")
        if _URL.search(statement):
            raise ValueError(
                "discriminating_condition.statement must not contain a URL"
            )
        if _STRUCTURAL_ID.search(statement):
            raise ValueError(
                "discriminating_condition.statement must not contain structural "
                "identifiers"
            )
        return statement


class ComparisonCheck(_ClosedModel):
    """Code-owned evaluation of one comparison."""

    index: StrictInt = Field(ge=0)
    result: ComparisonResult
    reason: StrictStr = Field(min_length=1)


class ConditionCheck(_ClosedModel):
    """Code-owned evaluation of a discriminating condition.

    ``violated`` when any comparison is violated; ``satisfied`` when at
    least one comparison is satisfied and none is violated; otherwise
    ``not_checkable``.
    """

    status: ComparisonResult
    comparisons: list[ComparisonCheck] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_status(self) -> "ConditionCheck":
        """Keep the overall status derived from the per-comparison results."""

        if self.status != overall_condition_status(
            [item.result for item in self.comparisons]
        ):
            raise ValueError("condition_check status does not match its comparisons")
        return self


def overall_condition_status(results: list[ComparisonResult]) -> ComparisonResult:
    """Combine per-comparison results into one status."""

    if "violated" in results:
        return "violated"
    if "satisfied" in results:
        return "satisfied"
    return "not_checkable"


def canonical_comparisons(condition: DiscriminatingCondition) -> str:
    """Return the order-independent canonical JSON of the comparisons.

    The statement and record selection are excluded: two scenarios with the
    same comparisons test the same condition even when phrased differently
    or aimed at different records.
    """

    items = sorted(
        json.dumps(
            item.model_dump(mode="json", exclude_none=True),
            sort_keys=True,
            separators=(",", ":"),
        )
        for item in condition.comparisons
    )
    return "[" + ",".join(items) + "]"


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _check_literal_sides(left: Operand, right: Operand) -> None:
    if isinstance(left, LiteralOperand) and isinstance(right, LiteralOperand):
        raise ValueError(
            "a value comparison needs at least one argument or fact operand; "
            "two literals do not depend on the scenario"
        )
    if isinstance(left, LiteralOperand) and isinstance(left.value, list):
        raise ValueError("a literal list is allowed only as the right operand")


def _check_literal_list_operator(right: Operand, op: str) -> None:
    right_list = isinstance(right, LiteralOperand) and isinstance(right.value, list)
    if right_list and op not in MEMBERSHIP_OPERATORS:
        raise ValueError(f"a literal list requires op in or not_in, not {op}")
    if (
        op in MEMBERSHIP_OPERATORS
        and isinstance(right, LiteralOperand)
        and not right_list
    ):
        raise ValueError(f"op {op} requires a list on the right")


__all__ = [
    "ArgumentOperand",
    "ArgumentValueSelection",
    "CONDITION_STATEMENT_MAX_LENGTH",
    "Comparison",
    "ComparisonCheck",
    "ComparisonOperator",
    "ComparisonResult",
    "ConditionCheck",
    "DiscriminatingCondition",
    "FactOperand",
    "LiteralOperand",
    "MEMBERSHIP_OPERATORS",
    "NotCalledComparison",
    "ORDERED_OPERATORS",
    "ObservedRecordSelection",
    "Operand",
    "OrderComparison",
    "RecordSelection",
    "UnavailableRecordSelection",
    "ValueComparison",
    "canonical_comparisons",
    "overall_condition_status",
]
