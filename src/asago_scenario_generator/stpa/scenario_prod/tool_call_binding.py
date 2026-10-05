"""Bind a checked discriminating condition to a Garak tool-call condition.

Binding resolves every observed fact up front, so the bound condition holds
only ``argument`` and ``literal`` operands. State predicates (``value``
comparisons with no argument operand) are evaluated here and never reach the
detector. The semantics are the arm 1 evaluator's, which the
``tool_call_condition`` v1 contract fixes:

- A condition with no behavioral part (no ``not_called``, no ``order``, no
  ``value`` with an argument operand, no observed record-selection target)
  is not executable (``state_only``); an unknown comparison kind is a
  ``condition_problem``.
- A false state predicate gives ``precondition_failed``. It wins over every
  later outcome, because arm 1 returns before reading call-level parts.
- A fact operand in a call-level comparison becomes a literal; an unresolved
  one gives ``unresolved_fact``, which wins over an unknown state predicate.
- An unknown state predicate with none false gives ``precondition_unknown``.
- An observed record selection adds, per argument value, a ``where`` item on
  every ``not_called`` comparison of its operation, or else an ``eq``
  comparison appended after the condition's own comparisons.

Facts are the producer's target-observation fact values
(:func:`~asago_scenario_generator.stpa.scenario_prod.condition_check.target_observation_fact_values`).
Comparisons use arm 1's truth rules (:func:`compare`), which differ from the
Stage 5 check's stricter ones on mixed-type operands.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from asago_scenario_generator.stpa.discriminating_condition import (
    DiscriminatingCondition,
)
from asago_scenario_generator.stpa.scenario_prod.condition_check import resolve_fact
from asago_scenario_generator.stpa.tool_call_condition import (
    REASON_BOUND,
    REASON_CONDITION_PROBLEM,
    REASON_NO_CONDITION,
    REASON_PRECONDITION_FAILED,
    REASON_PRECONDITION_UNKNOWN,
    REASON_STATE_ONLY,
    REASON_UNRESOLVED_FACT,
    TOOL_CALL_CONDITION_BOUND,
    TOOL_CALL_CONDITION_NOT_EXECUTABLE,
    ToolCallCondition,
    ToolCallConditionStatus,
)

Truth = bool | None

_UNRESOLVED = object()


@dataclass(frozen=True)
class ToolCallBinding:
    """The binding status and, when bound, the condition."""

    status: ToolCallConditionStatus
    condition: ToolCallCondition | None = None


@dataclass(frozen=True)
class _Structure:
    has_condition: bool
    operations: tuple[str, ...] = ()
    not_called: tuple[str, ...] = ()
    static_comparisons: tuple[tuple[int, Mapping[str, Any]], ...] = ()
    problems: tuple[str, ...] = ()

    @property
    def behavioral(self) -> bool:
        return bool(self.operations or self.not_called)


class _UnresolvedFact(Exception):
    def __init__(self, path: str) -> None:
        super().__init__(path)
        self.path = path


def bind_tool_call_condition(
    condition: DiscriminatingCondition | Mapping[str, Any] | None,
    fact_values: Mapping[str, object],
    *,
    condition_omitted_reason: str | None = None,
) -> ToolCallBinding:
    """Bind *condition* against *fact_values*; see the module docstring."""

    raw = (
        condition.model_dump(mode="json")
        if isinstance(condition, DiscriminatingCondition)
        else condition
    )
    structure = _analyze(raw)
    if not structure.has_condition:
        detail = "the handoff publishes no discriminating condition"
        if condition_omitted_reason:
            detail = f"{detail}: {condition_omitted_reason}"
        return _not_executable(REASON_NO_CONDITION, detail)
    assert isinstance(raw, Mapping)
    if structure.problems:
        return _not_executable(REASON_CONDITION_PROBLEM, structure.problems[0])
    if not structure.behavioral:
        return _not_executable(
            REASON_STATE_ONLY,
            "the condition holds only state predicates, so it names no "
            "observable behavior",
        )

    statics = [
        (index, _static(item, fact_values))
        for index, item in structure.static_comparisons
    ]
    false = [index for index, truth in statics if truth is False]
    if false:
        return _not_executable(
            REASON_PRECONDITION_FAILED,
            f"state predicate comparisons[{false[0]}] is false in the target state",
        )
    try:
        comparisons = _call_comparisons(raw, fact_values)
    except _UnresolvedFact as error:
        return _not_executable(
            REASON_UNRESOLVED_FACT, f"unresolved fact operand {error.path!r}"
        )
    comparisons = _apply_selection(comparisons, raw, fact_values)
    unknown = [index for index, truth in statics if truth is None]
    if unknown:
        return _not_executable(
            REASON_PRECONDITION_UNKNOWN,
            f"state predicate comparisons[{unknown[0]}] is unknown in the target "
            "state and none is false",
        )
    return ToolCallBinding(
        ToolCallConditionStatus(
            status=TOOL_CALL_CONDITION_BOUND,
            reason=REASON_BOUND,
            detail="every fact operand resolved and every state predicate holds",
        ),
        ToolCallCondition.model_validate({"comparisons": comparisons}),
    )


def _not_executable(reason: str, detail: str) -> ToolCallBinding:
    return ToolCallBinding(
        ToolCallConditionStatus(
            status=TOOL_CALL_CONDITION_NOT_EXECUTABLE, reason=reason, detail=detail
        )
    )


def _analyze(raw: Mapping[str, Any] | None) -> _Structure:
    """Split a condition into behavior parts and state predicates (arm 1)."""

    if not isinstance(raw, Mapping):
        return _Structure(has_condition=False)
    operations: list[str] = []
    not_called: list[str] = []
    static: list[tuple[int, Mapping[str, Any]]] = []
    problems: list[str] = []
    for index, comparison in enumerate(raw.get("comparisons") or []):
        kind = comparison.get("kind")
        if kind == "not_called":
            not_called.append(comparison["operation"])
        elif kind == "order":
            operations.append(comparison["operation"])
        elif kind == "value":
            used = [
                side["operation"]
                for side in (comparison["left"], comparison["right"])
                if side.get("source") == "argument"
            ]
            if used:
                operations.extend(used)
            else:
                static.append((index, comparison))
        else:
            problems.append(f"unknown comparison kind {kind!r}")
    for item in _observed_argument_values(raw):
        if item["operation"] not in not_called:
            operations.append(item["operation"])
    return _Structure(
        has_condition=True,
        operations=tuple(dict.fromkeys(operations)),
        not_called=tuple(dict.fromkeys(not_called)),
        static_comparisons=tuple(static),
        problems=tuple(problems),
    )


def _observed_argument_values(raw: Mapping[str, Any]) -> Iterable[Mapping[str, Any]]:
    selection = raw.get("record_selection")
    if not isinstance(selection, Mapping) or selection.get("status") != "observed":
        return ()
    return selection.get("argument_values") or ()


def _static(comparison: Mapping[str, Any], fact_values: Mapping[str, object]) -> Truth:
    left = _static_operand(comparison["left"], fact_values)
    right = _static_operand(comparison["right"], fact_values)
    return compare(comparison["op"], left, right)


def _static_operand(
    operand: Mapping[str, Any], fact_values: Mapping[str, object]
) -> Any:
    source = operand.get("source")
    if source == "literal":
        return operand["value"]
    if source == "fact":
        found, value = resolve_fact(fact_values, operand["path"])
        return value if found else _UNRESOLVED
    return _UNRESOLVED


def _call_comparisons(
    raw: Mapping[str, Any], fact_values: Mapping[str, object]
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for item in raw.get("comparisons") or []:
        kind = item["kind"]
        if kind == "not_called":
            out.append(
                {"kind": "not_called", "operation": item["operation"], "where": []}
            )
        elif kind == "order":
            out.append(
                {
                    "kind": "order",
                    "operation": item["operation"],
                    "requires_prior": item["requires_prior"],
                    "same_argument": item.get("same_argument"),
                }
            )
        elif any(item[side].get("source") == "argument" for side in ("left", "right")):
            out.append(
                {
                    "kind": "value",
                    "left": _call_operand(item["left"], fact_values),
                    "op": item["op"],
                    "right": _call_operand(item["right"], fact_values),
                }
            )
    return out


def _call_operand(
    operand: Mapping[str, Any], fact_values: Mapping[str, object]
) -> dict[str, Any]:
    source = operand.get("source")
    if source == "argument":
        return {
            "source": "argument",
            "operation": operand["operation"],
            "argument": operand["argument"],
        }
    if source == "literal":
        return {"source": "literal", "value": operand["value"]}
    if source == "fact":
        found, value = resolve_fact(fact_values, operand["path"])
        if not found:
            raise _UnresolvedFact(operand["path"])
        return {"source": "literal", "value": value}
    raise _UnresolvedFact(f"<{source}>")


def selection_wanted_value(path: str, fact_values: Mapping[str, object]) -> Any:
    """Return the value a selection path names: its scalar, else its last segment."""

    found, value = resolve_fact(fact_values, path)
    if found and not isinstance(value, (Mapping, list)):
        return value
    return path.rsplit(".", 1)[-1]


def _apply_selection(
    comparisons: list[dict[str, Any]],
    raw: Mapping[str, Any],
    fact_values: Mapping[str, object],
) -> list[dict[str, Any]]:
    not_called = {
        item["operation"] for item in comparisons if item["kind"] == "not_called"
    }
    appended: list[dict[str, Any]] = []
    for item in _observed_argument_values(raw):
        wanted = selection_wanted_value(item["path"], fact_values)
        if item["operation"] in not_called:
            for comparison in comparisons:
                if (
                    comparison["kind"] == "not_called"
                    and comparison["operation"] == item["operation"]
                ):
                    comparison["where"].append(
                        {"argument": item["argument"], "value": wanted}
                    )
        else:
            appended.append(
                {
                    "kind": "value",
                    "left": {
                        "source": "argument",
                        "operation": item["operation"],
                        "argument": item["argument"],
                    },
                    "op": "eq",
                    "right": {"source": "literal", "value": wanted},
                }
            )
    return comparisons + appended


def compare(op: str, left: Any, right: Any) -> Truth:
    """Compare two resolved operands with arm 1's three-valued rules."""

    if left is _UNRESOLVED or right is _UNRESOLVED:
        return None
    if op in {"in", "not_in"}:
        if not isinstance(right, list):
            return None
        elements = left if isinstance(left, list) else [left]
        member = any(
            _equal(element, item) is True for element in elements for item in right
        )
        return member if op == "in" else not member
    if op in {"eq", "ne"}:
        return _equal(left, right) if op == "eq" else not _equal(left, right)
    a, b = _number(left), _number(right)
    if a is None or b is None:
        return None
    return {"gt": a > b, "ge": a >= b, "lt": a < b, "le": a <= b}.get(op)


def _equal(left: Any, right: Any) -> bool:
    if isinstance(left, bool) != isinstance(right, bool):
        return False
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        return float(left) == float(right)
    return bool(left == right)


def _number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


__all__ = [
    "ToolCallBinding",
    "bind_tool_call_condition",
    "compare",
    "selection_wanted_value",
]
