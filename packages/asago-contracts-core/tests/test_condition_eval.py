"""One evaluator, the producer's behaviour, and a named case for every difference.

The two former evaluators disagreed on malformed values and on numbers beyond
float range. The producer's behaviour wins; each difference is a case below.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from asago_contracts_core import (
    DETECTED,
    NOT_DETECTED,
    ConditionEvaluation,
    evaluate_condition_v2,
    validate_condition,
)

VECTORS = (
    Path(__file__).resolve().parent
    / "data"
    / "tool-call-condition"
    / "tool-call-condition-v2"
    / "vectors"
)
EVALUATE = json.loads((VECTORS / "evaluate.json").read_text(encoding="utf-8"))[
    "vectors"
]
VALIDATE = json.loads((VECTORS / "validate.json").read_text(encoding="utf-8"))[
    "vectors"
]


def _argument(operation: str, argument: str) -> dict[str, str]:
    return {"source": "argument", "operation": operation, "argument": argument}


def _literal(value: Any) -> dict[str, Any]:
    return {"source": "literal", "value": value}


def _value(left: Any, op: str, right: Any) -> dict[str, Any]:
    return {"kind": "value", "left": left, "op": op, "right": right}


def _condition(*comparisons: dict[str, Any]) -> dict[str, Any]:
    return {"comparisons": list(comparisons)}


def _call(name: str, **arguments: Any) -> dict[str, Any]:
    return {"name": name, "arguments": arguments}


_CALL = _condition(_value(_argument("withdraw", "amount"), "gt", _literal(5)))
_NOT_CALLED = _condition(
    {
        "kind": "not_called",
        "operation": "delete",
        "where": [{"argument": "account_id", "value": 10**400}],
    }
)
_ORDER = _condition(
    {
        "kind": "order",
        "operation": "withdraw",
        "requires_prior": "balance",
        "same_argument": "account_id",
    }
)
_LITERAL_COMPARISON = _condition(_value(_literal(2), "gt", _literal(1)))
_LITERAL_MEMBERSHIP = _condition(_value(_literal("a"), "in", _literal(5)))
_LITERAL_BOOL_NUMBER = _condition(_value(_literal(True), "eq", _literal(1)))

#: Every way the two former evaluators differed, named by the difference it pins.
DIFFERENCES: dict[str, tuple[dict[str, Any], list[dict[str, Any]], bool, Any]] = {
    "argument-value-beyond-float-range": (
        _CALL,
        [_call("withdraw", amount=10**400)],
        True,
        OverflowError,
    ),
    "literal-value-beyond-float-range": (
        _condition(_value(_argument("withdraw", "amount"), "lt", _literal(10**400))),
        [_call("withdraw", amount=1)],
        True,
        OverflowError,
    ),
    "membership-value-beyond-float-range": (
        _condition(_value(_argument("withdraw", "amount"), "in", _literal([10**400]))),
        [_call("withdraw", amount=1)],
        True,
        OverflowError,
    ),
    "not-called-where-value-beyond-float-range": (
        _NOT_CALLED,
        [_call("delete", account_id=1)],
        True,
        OverflowError,
    ),
    "two-literal-comparison-is-not-evaluated": (
        _LITERAL_COMPARISON,
        [],
        True,
        (DETECTED, "the condition holds on the captured calls", []),
    ),
    "two-literal-membership-right-is-not-a-list": (
        _LITERAL_MEMBERSHIP,
        [],
        True,
        (DETECTED, "the condition holds on the captured calls", []),
    ),
    "two-literal-bool-versus-number": (
        _LITERAL_BOOL_NUMBER,
        [],
        True,
        (DETECTED, "the condition holds on the captured calls", []),
    ),
    "call-without-arguments-raises": (_CALL, [{"name": "withdraw"}], True, KeyError),
    "call-without-name-raises": (
        _CALL,
        [{"arguments": {"amount": 10}}],
        True,
        KeyError,
    ),
    "not-called-call-without-name-raises": (
        _NOT_CALLED,
        [{"arguments": {"account_id": 1}}],
        True,
        KeyError,
    ),
    "order-same-argument-without-arguments-raises": (
        _ORDER,
        [{"name": "balance"}, _call("withdraw", account_id="A")],
        True,
        KeyError,
    ),
}


@pytest.mark.parametrize("case", DIFFERENCES.values(), ids=list(DIFFERENCES))
def test_each_evaluator_difference_pins_the_producer_behaviour(
    case: tuple[dict[str, Any], list[dict[str, Any]], bool, Any],
) -> None:
    condition, calls, complete, expected = case
    if isinstance(expected, type) and issubclass(expected, Exception):
        with pytest.raises(expected):
            evaluate_condition_v2(condition, calls, complete)
        return
    assert evaluate_condition_v2(condition, calls, complete) == expected


def test_a_plain_condition_still_reads_as_before() -> None:
    result = evaluate_condition_v2(_CALL, [_call("withdraw", amount=10)], True)
    assert result == ("detected", "the condition holds on the captured calls", [0])
    assert isinstance(result, ConditionEvaluation)
    assert result.outcome == "detected"
    assert result.matched_calls == [0]
    assert evaluate_condition_v2(_CALL, [_call("withdraw", amount=1)], True) == (
        NOT_DETECTED,
        "the captured calls do not satisfy the condition",
        [],
    )


def test_a_condition_without_an_argument_operand_is_refused() -> None:
    assert validate_condition(_LITERAL_COMPARISON) == (
        "comparisons[0] has no argument operand"
    )
    assert validate_condition(_CALL) is None


@pytest.mark.parametrize("vector", EVALUATE, ids=lambda vector: vector["id"])
def test_every_v2_evaluate_vector_holds(vector: dict[str, Any]) -> None:
    assert evaluate_condition_v2(
        vector["condition"], vector["calls"], vector["complete"]
    ) == (vector["outcome"], vector["reason"], vector["matched_calls"])


@pytest.mark.parametrize("vector", VALIDATE, ids=lambda vector: vector["id"])
def test_every_v2_validate_vector_holds(vector: dict[str, Any]) -> None:
    assert (validate_condition(vector["condition"]) is None) == vector["valid"]
