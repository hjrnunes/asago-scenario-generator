"""Validate and evaluate a tool-call condition as tool-call-condition-v2 states it.

``contracts/tool-call-condition/tool-call-condition-v2/README.md`` is the shared
semantics; the producer owns it. This module is the one evaluator the producer,
the consumer and the orchestrator use, and it follows the producer's
implementation, which the vectors pin. A reader that only checks a condition
calls :func:`validate_condition` first; a reader that evaluates one calls
:func:`evaluate_condition_v2` and gets a :class:`ConditionEvaluation`.

The producer's behaviour wins where the two former evaluators differed. Each
difference is a named case in ``tests/test_condition_eval.py``:

- A number beyond float range raises ``OverflowError``; it does not saturate to
  an infinity.
- A value comparison whose operands are both literals is not evaluated, because
  it names no operation; the condition is detected on that comparison alone.
- A call that lacks ``name`` or ``arguments`` raises ``KeyError``; it does not
  read as an unknown call.

Garak executes the validation, and the vectors pin Garak's behavior where it is
surprising. In ``order``, a missing prior call is true only on a complete capture,
``same_argument`` uses contract equality and a prior call that lacks the argument
never matches, and a ``blocked`` call never satisfies ``requires_prior``.
"""

from __future__ import annotations

import itertools
from typing import Any, NamedTuple

DETECTED = "detected"
NOT_DETECTED = "not_detected"
INCONCLUSIVE = "inconclusive"
_REASONS = {
    DETECTED: "the condition holds on the captured calls",
    NOT_DETECTED: "the captured calls do not satisfy the condition",
    INCONCLUSIVE: "capture is incomplete or a relevant call is undecodable",
}
_NO_VALUE = object()

_VALUE_OPS = ("eq", "ne", "gt", "ge", "lt", "le", "in", "not_in")
_COMPARISON_KEYS = {
    "value": ("kind", "left", "op", "right"),
    "not_called": ("kind", "operation"),
    "order": ("kind", "operation", "requires_prior"),
}
_OPTIONAL_KEYS = {"value": (), "not_called": ("where",), "order": ("same_argument",)}
_OPERAND_KEYS = {
    "argument": ("source", "operation", "argument"),
    "literal": ("source", "value"),
}


class ConditionEvaluation(NamedTuple):
    """The outcome, its fixed reason text, and the call indexes the assignment matched."""

    outcome: str
    reason: str
    matched_calls: list[int]


def validate_condition(condition: Any) -> str | None:
    """Return the first structural problem of *condition*, or None when it is valid."""

    if not isinstance(condition, dict):
        return "condition is not an object"
    unknown = sorted(set(condition) - {"comparisons"}, key=str)
    if unknown:
        return f"condition has unknown keys {unknown!r}"
    comparisons = condition.get("comparisons")
    if not isinstance(comparisons, list) or not comparisons:
        return "comparisons is missing or empty"
    for index, comparison in enumerate(comparisons):
        problem = _comparison_problem(comparison, f"comparisons[{index}]")
        if problem:
            return problem
    return None


def _comparison_problem(comparison: Any, path: str) -> str | None:
    if not isinstance(comparison, dict):
        return f"{path} is not an object"
    kind = comparison.get("kind")
    if not isinstance(kind, str) or kind not in _COMPARISON_KEYS:
        return f"{path} has unknown kind {kind!r}"
    return _keys_problem(
        comparison, path, _COMPARISON_KEYS[kind], _OPTIONAL_KEYS[kind]
    ) or _KIND_PROBLEMS[kind](comparison, path)


def _keys_problem(
    value: dict[str, Any],
    path: str,
    required: tuple[str, ...],
    optional: tuple[str, ...] = (),
) -> str | None:
    """Report unknown keys, then missing ones, each sorted."""

    unknown = sorted(set(value) - set(required) - set(optional), key=str)
    if unknown:
        return f"{path} has unknown keys {unknown!r}"
    missing = sorted(set(required) - set(value))
    return f"{path} is missing {missing!r}" if missing else None


def _string_problem(
    value: dict[str, Any], path: str, names: tuple[str, ...]
) -> str | None:
    for name in names:
        if not isinstance(value[name], str):
            return f"{path}.{name} is not a string"
    return None


def _value_problem(comparison: dict[str, Any], path: str) -> str | None:
    if comparison["op"] not in _VALUE_OPS:
        return f"{path} has unknown op {comparison['op']!r}"
    for side in ("left", "right"):
        problem = _operand_problem(comparison[side], f"{path}.{side}")
        if problem:
            return problem
    if not any(comparison[side]["source"] == "argument" for side in ("left", "right")):
        return f"{path} has no argument operand"
    return None


def _operand_problem(operand: Any, path: str) -> str | None:
    if not isinstance(operand, dict):
        return f"{path} is not an object"
    source = operand.get("source")
    if not isinstance(source, str) or source not in _OPERAND_KEYS:
        return f"{path} has unknown source {source!r}"
    problem = _keys_problem(operand, path, _OPERAND_KEYS[source])
    if problem or source == "literal":
        return problem
    return _string_problem(operand, path, ("operation", "argument"))


def _not_called_problem(comparison: dict[str, Any], path: str) -> str | None:
    problem = _string_problem(comparison, path, ("operation",))
    if problem or "where" not in comparison:
        return problem
    where = comparison["where"]
    if not isinstance(where, list):
        return f"{path}.where is not a list"
    for index, item in enumerate(where):
        problem = _where_item_problem(item, f"{path}.where[{index}]")
        if problem:
            return problem
    return None


def _where_item_problem(item: Any, path: str) -> str | None:
    if not isinstance(item, dict):
        return f"{path} is not an object"
    return _keys_problem(item, path, ("argument", "value")) or _string_problem(
        item, path, ("argument",)
    )


def _order_problem(comparison: dict[str, Any], path: str) -> str | None:
    problem = _string_problem(comparison, path, ("operation", "requires_prior"))
    if problem:
        return problem
    same = comparison.get("same_argument")
    return (
        f"{path}.same_argument is not a string"
        if same is not None and not isinstance(same, str)
        else None
    )


_KIND_PROBLEMS = {
    "value": _value_problem,
    "not_called": _not_called_problem,
    "order": _order_problem,
}


def _and(values) -> bool | None:
    values = list(values)
    if False in values:
        return False
    return None if None in values else True


def _or(values) -> bool | None:
    values = list(values)
    if True in values:
        return True
    return None if None in values else False


def _equal(left, right) -> bool:
    if isinstance(left, bool) != isinstance(right, bool):
        return False
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        return float(left) == float(right)
    return left == right


def _number(value) -> float | None:
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


def _argument_value(call_, argument):
    arguments = call_["arguments"]
    if not isinstance(arguments, dict) or argument not in arguments:
        return _NO_VALUE
    return arguments[argument]


def _compare(op, left, right) -> bool | None:
    if left is _NO_VALUE or right is _NO_VALUE:
        return None
    if op in ("in", "not_in"):
        if not isinstance(right, list):
            return None
        elements = left if isinstance(left, list) else [left]
        member = any(_equal(element, item) for element in elements for item in right)
        return member if op == "in" else not member
    if op in ("eq", "ne"):
        return _equal(left, right) == (op == "eq")
    a, b = _number(left), _number(right)
    if a is None or b is None:
        return None
    return {"gt": a > b, "ge": a >= b, "lt": a < b, "le": a <= b}[op]


def _operand(operand, assigned, calls):
    if operand["source"] == "literal":
        return operand["value"]
    return _argument_value(calls[assigned[operand["operation"]]], operand["argument"])


def _order(comparison, index, calls, complete) -> bool | None:
    same = comparison.get("same_argument")
    wanted = None
    if same:
        wanted = _argument_value(calls[index], same)
        if wanted is _NO_VALUE:
            return None
    for earlier in calls[:index]:
        # a blocked call never satisfies requires_prior
        if earlier["name"] != comparison["requires_prior"] or earlier.get("blocked"):
            continue
        if not same:
            return False
        if not isinstance(earlier["arguments"], dict):
            return None
        # strict equality, and a prior that lacks the argument never matches
        prior = _argument_value(earlier, same)
        if prior is not _NO_VALUE and _equal(prior, wanted):
            return False
    # a missing prior call is detected only on a complete capture
    return True if complete else None


def _call_comparison(comparison, assigned, calls, complete) -> bool | None:
    if comparison["kind"] == "order":
        index = assigned[comparison["operation"]]
        return _order(comparison, index, calls, complete)
    left = _operand(comparison["left"], assigned, calls)
    right = _operand(comparison["right"], assigned, calls)
    return _compare(comparison["op"], left, right)


def _not_called(comparison, calls, complete) -> bool | None:
    def matches(call_, item):
        value = _argument_value(call_, item["argument"])
        return None if value is _NO_VALUE else _equal(value, item["value"])

    called = _or(
        _and(matches(call_, item) for item in comparison.get("where", []))
        for call_ in calls
        if call_["name"] == comparison["operation"]
    )
    if called is True:
        return False
    return None if called is None or not complete else True


def _operations(comparisons) -> list[str]:
    names = []
    for comparison in comparisons:
        if comparison["kind"] == "order":
            names.append(comparison["operation"])
        elif comparison["kind"] == "value":
            names += [
                comparison[side]["operation"]
                for side in ("left", "right")
                if comparison[side]["source"] == "argument"
            ]
    return list(dict.fromkeys(names))


def _assignment(comparisons, calls, complete) -> tuple[bool | None, list[int]]:
    operations = _operations(comparisons)
    call_level = [c for c in comparisons if c["kind"] in ("value", "order")]
    candidates = [
        [index for index, call_ in enumerate(calls) if call_["name"] == name]
        for name in operations
    ]
    if not all(candidates):
        return (False if complete else None), []
    unknown = False
    for choice in itertools.product(*candidates):
        assigned = dict(zip(operations, choice))
        truth = _and(_call_comparison(c, assigned, calls, complete) for c in call_level)
        if truth is True:
            return True, list(choice)
        unknown = unknown or truth is None
    return (None if unknown or not complete else False), []


def evaluate_condition_v2(condition, calls, complete) -> ConditionEvaluation:
    """Evaluate a valid condition under tool-call-condition-v2."""

    comparisons = condition["comparisons"]
    parts = [
        _not_called(c, calls, complete)
        for c in comparisons
        if c["kind"] == "not_called"
    ]
    matched: list[int] = []
    if _operations(comparisons):
        truth, matched = _assignment(comparisons, calls, complete)
        parts.append(truth)
    result = _and(parts)
    if result is True:
        outcome = DETECTED
    elif result is False:
        outcome = NOT_DETECTED
    else:
        outcome = INCONCLUSIVE
    return ConditionEvaluation(outcome, _REASONS[outcome], matched)


__all__ = [
    "DETECTED",
    "INCONCLUSIVE",
    "NOT_DETECTED",
    "ConditionEvaluation",
    "evaluate_condition_v2",
    "validate_condition",
]
