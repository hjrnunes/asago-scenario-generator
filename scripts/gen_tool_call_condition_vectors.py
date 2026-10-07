#!/usr/bin/env python3
"""Regenerate the tool-call-condition-v1 test vectors from Garak's own functions.

    python3 scripts/gen_tool_call_condition_vectors.py \\
        --garak-checkout <Garak checkout> --garak-python <Garak interpreter> [--check]

The script holds only inputs (conditions, calls, completeness) and needs only
the standard library. A child process started with the Garak interpreter runs
``validate_condition`` and ``evaluate_condition`` on the inputs; every expected
value comes from that run. The checkout must be at ``REVISION``.

Without ``--check`` the script writes ``vectors/validate.json``,
``vectors/evaluate.json``, and ``CONTRACT.lock``. With ``--check`` it
regenerates the same content in memory, writes nothing, and exits 1 when a
committed file differs. Downstream repositories mirror the files byte for byte.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

REVISION = "877932916b7b3e1148171a49b97eeb75a44c9b39"
CONTRACT = "tool-call-condition"
VERSION = "tool-call-condition-v1"
AUTHORITY = "asago-scenario-generator"
ROOT = Path(__file__).resolve().parents[1] / "data/contracts" / CONTRACT
VECTOR_DIR = ROOT / VERSION / "vectors"
VECTOR_FUNCTIONS = {
    "validate.json": "validate_condition",
    "evaluate.json": "evaluate_condition",
}
# Garak's VALUE_OPS; the worker asserts that the checkout agrees.
VALUE_OPS = ("eq", "ne", "gt", "ge", "lt", "le", "in", "not_in")

_UNSET = object()
Adder = Callable[..., None]


def arg(operation, argument):
    return {"source": "argument", "operation": operation, "argument": argument}


def lit(value):
    return {"source": "literal", "value": value}


def val(left, op, right):
    return {"kind": "value", "left": left, "op": op, "right": right}


def nc(operation, where=_UNSET):
    comparison = {"kind": "not_called", "operation": operation}
    if where is not _UNSET:
        comparison["where"] = where
    return comparison


def wh(argument, value):
    return {"argument": argument, "value": value}


def order(operation, prior, same=_UNSET):
    comparison = {"kind": "order", "operation": operation, "requires_prior": prior}
    if same is not _UNSET:
        comparison["same_argument"] = same
    return comparison


def cond(*comparisons):
    return {"comparisons": list(comparisons)}


def call(name, arguments=None):
    return {"name": name, "arguments": arguments}


# --- validate vectors -------------------------------------------------------

VAL = val(arg("a", "x"), "eq", lit(1))
NC = nc("a")
ORD = order("b", "a")


def bad(**changes):
    return {**VAL, **changes}


def validate_inputs() -> list[tuple[str, object]]:
    out: list[tuple[str, object]] = []

    def add(vector_id, condition):
        out.append((vector_id, condition))

    # valid conditions
    for op in VALUE_OPS:
        add(f"valid.value-op-{op}", cond(val(arg("a", "x"), op, lit(1))))
    add("valid.value-literal-left", cond(val(lit(1), "eq", arg("a", "x"))))
    add("valid.value-two-arguments", cond(val(arg("a", "x"), "lt", arg("b", "y"))))
    add("valid.value-same-operation", cond(val(arg("a", "x"), "lt", arg("a", "y"))))
    for label, literal in (
        ("null", None),
        ("bool", True),
        ("int", 3),
        ("float", 2.5),
        ("string", "s"),
        ("list", [1, "a"]),
        ("object", {"k": 1}),
    ):
        add(f"valid.literal-{label}", cond(val(arg("a", "x"), "eq", lit(literal))))
    add(
        "valid.empty-names", cond(val(arg("", ""), "eq", lit(1)), nc(""), order("", ""))
    )
    add("valid.not-called-without-where", cond(nc("a")))
    add("valid.not-called-empty-where", cond(nc("a", [])))
    add("valid.not-called-one-where", cond(nc("a", [wh("x", 1)])))
    add(
        "valid.not-called-several-where",
        cond(nc("a", [wh("x", None), wh("y", [1]), wh("z", {"k": 1}), wh("x", 2)])),
    )
    add("valid.order-plain", cond(order("b", "a")))
    add("valid.order-same-argument", cond(order("b", "a", "id")))
    add("valid.order-same-argument-null", cond(order("b", "a", None)))
    add("valid.order-same-argument-empty", cond(order("b", "a", "")))
    add("valid.all-kinds", cond(VAL, NC, ORD))
    add("valid.repeated-kind", cond(VAL, VAL, NC, NC))

    # condition and comparisons list
    for label, condition in (
        ("null", None),
        ("list", []),
        ("string", "x"),
        ("number", 1),
        ("bool", True),
    ):
        add(f"invalid.root-{label}", condition)
    add("invalid.root-empty-object", {})
    add("invalid.root-unknown-key", {"comparisons": [VAL], "extra": 1})
    add("invalid.root-unknown-keys-sorted", {"comparisons": [VAL], "z": 1, "b": 2})
    add("invalid.root-unknown-key-before-missing", {"extra": 1})
    add("invalid.comparisons-null", {"comparisons": None})
    add("invalid.comparisons-empty", {"comparisons": []})
    add("invalid.comparisons-object", {"comparisons": {}})
    add("invalid.comparisons-string", {"comparisons": "x"})
    add("invalid.comparison-null", cond(None))
    add("invalid.comparison-string", cond("x"))
    add("invalid.comparison-list", cond([]))
    add("invalid.comparison-index", cond(VAL, {"kind": "nope"}))
    add("invalid.first-problem-wins", cond({"kind": "nope"}, {"kind": "other"}))

    # kind
    add("invalid.kind-missing", cond({}))
    add("invalid.kind-null", cond({"kind": None}))
    add("invalid.kind-unknown", cond({"kind": "x"}))
    add("invalid.kind-case", cond({"kind": "Value"}))
    add("invalid.kind-number", cond({"kind": 5}))
    add("invalid.kind-bool", cond({"kind": True}))

    # value comparison
    add("invalid.value-missing-everything", cond({"kind": "value"}))
    add("invalid.value-missing-op", cond({k: v for k, v in VAL.items() if k != "op"}))
    add(
        "invalid.value-missing-left",
        cond({k: v for k, v in VAL.items() if k != "left"}),
    )
    add(
        "invalid.value-missing-right",
        cond({k: v for k, v in VAL.items() if k != "right"}),
    )
    add("invalid.value-unknown-key", cond(bad(where=[])))
    add("invalid.value-unknown-key-before-missing", cond({**VAL, "x": 1, "op": 1}))
    add(
        "invalid.value-unknown-before-missing",
        cond({"kind": "value", "left": VAL["left"], "extra": 1}),
    )
    add("invalid.value-op-unknown", cond(bad(op="contains")))
    add("invalid.value-op-case", cond(bad(op="EQ")))
    add("invalid.value-op-null", cond(bad(op=None)))
    add("invalid.value-op-number", cond(bad(op=5)))
    add("invalid.value-op-list", cond(bad(op=[])))
    add("invalid.value-op-before-operands", cond(bad(op="x", left="y")))
    for side in ("left", "right"):
        add(f"invalid.value-{side}-null", cond(bad(**{side: None})))
        add(f"invalid.value-{side}-string", cond(bad(**{side: "x"})))
        add(f"invalid.value-{side}-list", cond(bad(**{side: []})))
    add("invalid.value-left-checked-before-right", cond(bad(left="x", right=3)))
    add("invalid.value-right-source-unknown", cond(bad(right={"source": "fact"})))
    add("invalid.value-nested-index", cond(VAL, bad(right=None)))

    # operand
    add("invalid.operand-source-missing", cond(bad(left={})))
    add(
        "invalid.operand-source-unknown",
        cond(bad(left={"source": "fact", "path": "p"})),
    )
    add("invalid.operand-source-null", cond(bad(left={"source": None})))
    add("invalid.operand-source-number", cond(bad(left={"source": 5})))
    add(
        "invalid.operand-argument-missing-argument",
        cond(bad(left={"source": "argument", "operation": "a"})),
    )
    add(
        "invalid.operand-argument-missing-operation",
        cond(bad(left={"source": "argument", "argument": "x"})),
    )
    add("invalid.operand-argument-missing-both", cond(bad(left={"source": "argument"})))
    add(
        "invalid.operand-argument-unknown-key",
        cond(bad(left={**arg("a", "x"), "value": 1})),
    )
    add(
        "invalid.operand-argument-unknown-before-missing",
        cond(bad(left={"source": "argument", "value": 1})),
    )
    add("invalid.operand-argument-operation-number", cond(bad(left=arg(5, "x"))))
    add("invalid.operand-argument-operation-null", cond(bad(left=arg(None, "x"))))
    add("invalid.operand-argument-argument-number", cond(bad(left=arg("a", 5))))
    add("invalid.operand-argument-argument-list", cond(bad(left=arg("a", ["x"]))))
    add("invalid.operand-argument-operation-before-argument", cond(bad(left=arg(5, 5))))
    add("invalid.operand-literal-missing-value", cond(bad(right={"source": "literal"})))
    add(
        "invalid.operand-literal-unknown-key",
        cond(bad(right={"source": "literal", "value": 1, "operation": "a"})),
    )
    add(
        "invalid.operand-literal-argument-fields",
        cond(bad(right={"source": "literal", "operation": "a", "argument": "x"})),
    )
    add("invalid.operand-right-error-path", cond(bad(right={"source": "x"})))
    add("invalid.value-two-literals", cond(bad(left=lit(1))))
    add(
        "invalid.value-two-literals-null-values",
        cond(bad(left=lit(None), right=lit(None))),
    )

    # not_called
    add("invalid.not-called-missing-operation", cond({"kind": "not_called"}))
    add("invalid.not-called-unknown-key", cond({**NC, "requires_prior": "a"}))
    add("invalid.not-called-same-argument", cond({**NC, "same_argument": "x"}))
    add("invalid.not-called-operation-number", cond(nc(5)))
    add("invalid.not-called-operation-null", cond(nc(None)))
    add("invalid.not-called-where-null", cond(nc("a", None)))
    add("invalid.not-called-where-object", cond(nc("a", {})))
    add("invalid.not-called-where-string", cond(nc("a", "x")))
    add("invalid.not-called-operation-before-where", cond(nc(5, None)))
    add("invalid.not-called-where-item-null", cond(nc("a", [None])))
    add("invalid.not-called-where-item-string", cond(nc("a", ["x"])))
    add("invalid.not-called-where-item-list", cond(nc("a", [[]])))
    add(
        "invalid.not-called-where-item-missing-value",
        cond(nc("a", [{"argument": "x"}])),
    )
    add("invalid.not-called-where-item-missing-argument", cond(nc("a", [{"value": 1}])))
    add("invalid.not-called-where-item-missing-both", cond(nc("a", [{}])))
    add(
        "invalid.not-called-where-item-unknown-key",
        cond(nc("a", [{"argument": "x", "value": 1, "op": "eq"}])),
    )
    add("invalid.not-called-where-item-argument-number", cond(nc("a", [wh(5, 1)])))
    add("invalid.not-called-where-item-argument-null", cond(nc("a", [wh(None, 1)])))
    add("invalid.not-called-where-second-item", cond(nc("a", [wh("x", 1), None])))
    add(
        "invalid.not-called-where-path-index",
        cond(VAL, nc("a", [wh("x", 1), wh(1, 1)])),
    )

    # order
    add(
        "invalid.order-missing-operation",
        cond({"kind": "order", "requires_prior": "a"}),
    )
    add(
        "invalid.order-missing-requires-prior",
        cond({"kind": "order", "operation": "b"}),
    )
    add("invalid.order-missing-both", cond({"kind": "order"}))
    add("invalid.order-unknown-key-where", cond({**ORD, "where": []}))
    add("invalid.order-unknown-key-left", cond({**ORD, "left": lit(1)}))
    add("invalid.order-operation-number", cond(order(5, "a")))
    add("invalid.order-requires-prior-number", cond(order("b", 5)))
    add("invalid.order-requires-prior-null", cond(order("b", None)))
    add("invalid.order-same-argument-number", cond(order("b", "a", 5)))
    add("invalid.order-same-argument-bool", cond(order("b", "a", False)))
    add("invalid.order-same-argument-list", cond(order("b", "a", ["id"])))
    add("invalid.order-operation-before-requires-prior", cond(order(5, 5)))
    add("invalid.order-requires-prior-before-same-argument", cond(order("b", 5, 5)))
    return out


# --- evaluate vectors -------------------------------------------------------

COMPARE_OPS = ("eq", "ne", "gt", "ge", "lt", "le")

# (label, left, right): left is an argument value, right a literal
PAIRS = [
    ("int-equal", 3, 3),
    ("int-float-equal", 3, 3.0),
    ("int-less", 3, 4),
    ("int-greater", 4, 3),
    ("zero-float-zero", 0, 0.0),
    ("float-less", 1.5, 2.5),
    ("str-equal", "a", "a"),
    ("str-different", "a", "b"),
    ("int-str-numeric", 3, "3"),
    ("numstr-numstr-numeric-order", "10", "9"),
    ("numstr-int", "10", 9),
    ("numstr-exponent", "1e3", 1000),
    ("numstr-padded", " 7 ", 7),
    ("numstr-hex", "0x10", 16),
    ("numstr-underscore", "1_0", 10),
    ("numstr-nan", "nan", 1),
    ("numstr-inf", "inf", 1),
    ("str-empty-int", "", 0),
    ("str-nonnumeric-int", "abc", 1),
    ("bool-true-int", True, 1),
    ("bool-true-true", True, True),
    ("bool-true-false", True, False),
    ("int-bool-true", 1, True),
    ("null-null", None, None),
    ("null-int", None, 0),
    ("list-equal", [1, 2], [1, 2]),
    ("list-reordered", [1, 2], [2, 1]),
    ("list-nested-bool-int", [True], [1]),
    ("list-int-float", [1], [1.0]),
    ("object-equal", {"a": 1}, {"a": 1}),
    ("object-different", {"a": 1}, {"a": 2}),
    ("list-scalar", [1], 1),
    ("object-int", {"a": 1}, 1),
]

SWAPPED_PAIRS = [
    "int-less",
    "int-greater",
    "int-equal",
    "numstr-int",
    "str-nonnumeric-int",
    "bool-true-int",
]

# (label, left, right) for in / not_in
MEMBERSHIP = [
    ("scalar-hit", "a", ["a", "b"]),
    ("scalar-miss", "c", ["a", "b"]),
    ("empty-right", "a", []),
    ("int-float", 1, [1.0]),
    ("int-bool", 1, [True]),
    ("bool-int", True, [1]),
    ("null-hit", None, [None]),
    ("int-str", 1, ["1"]),
    ("list-some-hit", ["a", "c"], ["a", "b"]),
    ("list-no-hit", ["c", "d"], ["a", "b"]),
    ("list-empty", [], ["a"]),
    ("list-whole-in-nested", [1, 2], [[1, 2]]),
    ("list-element-in-nested", [1], [[1]]),
    ("right-string", "a", "a"),
    ("right-null", "a", None),
    ("right-object", "a", {"a": 1}),
    ("object-hit", {"a": 1}, [{"a": 1}]),
]


def _compare_inputs(add: Adder) -> None:
    one = lambda value: [call("a", {"x": value})]  # noqa: E731

    pairs = {label: (left, right) for label, left, right in PAIRS}
    for op in COMPARE_OPS:
        for label, left, right in PAIRS:
            add(
                f"compare.{op}.{label}",
                cond(val(arg("a", "x"), op, lit(right))),
                one(left),
            )
        for label in SWAPPED_PAIRS:
            left, right = pairs[label]
            add(
                f"compare.{op}.literal-left.{label}",
                cond(val(lit(left), op, arg("a", "x"))),
                one(right),
            )
    for op in ("in", "not_in"):
        for label, left, right in MEMBERSHIP:
            add(
                f"compare.{op}.{label}",
                cond(val(arg("a", "x"), op, lit(right))),
                one(left),
            )
        add(
            f"compare.{op}.literal-list-left",
            cond(val(lit(["a", "b"]), op, arg("a", "x"))),
            one("a"),
        )
        add(
            f"compare.{op}.two-operations-hit",
            cond(val(arg("a", "x"), op, arg("b", "y"))),
            [call("a", {"x": "p"}), call("b", {"y": ["p", "q"]})],
        )
        add(
            f"compare.{op}.two-operations-miss",
            cond(val(arg("a", "x"), op, arg("b", "y"))),
            [call("a", {"x": "z"}), call("b", {"y": ["p", "q"]})],
        )
        add(
            f"compare.{op}.two-operations-right-scalar",
            cond(val(arg("a", "x"), op, arg("b", "y"))),
            [call("a", {"x": "p"}), call("b", {"y": "p"})],
        )
    add(
        "compare.gt.two-operations",
        cond(val(arg("a", "x"), "gt", arg("b", "y"))),
        [call("a", {"x": "10"}), call("b", {"y": 9})],
    )
    add(
        "compare.eq.two-operations-bool-int",
        cond(val(arg("a", "x"), "eq", arg("b", "y"))),
        [call("a", {"x": True}), call("b", {"y": 1})],
    )


def _unresolved_inputs(add: Adder) -> None:
    for op, right in (("eq", 1), ("gt", 1), ("in", [1]), ("not_in", [1])):
        add(
            f"unresolved.{op}.argument-missing",
            cond(val(arg("a", "x"), op, lit(right))),
            [call("a", {"y": 1})],
        )
    add(
        "unresolved.eq.argument-missing-right",
        cond(val(lit(1), "eq", arg("a", "x"))),
        [call("a", {})],
    )
    for label, arguments in (
        ("null", None),
        ("list", [1]),
        ("number", 5),
        ("string", "x"),
        ("true", True),
    ):
        add(
            f"unresolved.arguments-{label}",
            cond(val(arg("a", "x"), "eq", lit(1))),
            [call("a", arguments)],
        )
    add(
        "unresolved.arguments-null-incomplete",
        cond(val(arg("a", "x"), "eq", lit(1))),
        [call("a", None)],
        False,
    )
    add(
        "unresolved.eq.one-of-two-operands",
        cond(val(arg("a", "x"), "eq", arg("b", "y"))),
        [call("a", {"x": 1}), call("b", {"z": 1})],
    )
    add(
        "unresolved.eq.null-value-present",
        cond(val(arg("a", "x"), "eq", lit(None))),
        [call("a", {"x": None})],
    )
    add(
        "unresolved.ne.null-value-present",
        cond(val(arg("a", "x"), "ne", lit(1))),
        [call("a", {"x": None})],
    )
    add(
        "unresolved.gt.null-value-present",
        cond(val(arg("a", "x"), "gt", lit(1))),
        [call("a", {"x": None})],
    )
    add(
        "unresolved.argument-name-case",
        cond(val(arg("a", "X"), "eq", lit(1))),
        [call("a", {"x": 1})],
    )
    add(
        "unresolved.operation-name-case",
        cond(val(arg("A", "x"), "eq", lit(1))),
        [call("a", {"x": 1})],
    )


def _completeness_inputs(add: Adder) -> None:
    true_case = (cond(val(arg("a", "x"), "eq", lit(1))), [call("a", {"x": 1})])
    false_case = (cond(val(arg("a", "x"), "eq", lit(1))), [call("a", {"x": 2})])
    none_case = (cond(val(arg("a", "x"), "eq", lit(1))), [call("a", {})])
    for label, (condition, calls) in (
        ("true", true_case),
        ("false", false_case),
        ("unknown", none_case),
    ):
        for complete in (True, False):
            add(
                f"completeness.value-{label}.complete-{str(complete).lower()}",
                condition,
                calls,
                complete,
            )
    for complete in (True, False):
        flag = str(complete).lower()
        add(
            f"completeness.no-calls.complete-{flag}",
            cond(val(arg("a", "x"), "eq", lit(1))),
            [],
            complete,
        )
        add(
            f"completeness.other-calls-only.complete-{flag}",
            cond(val(arg("a", "x"), "eq", lit(1))),
            [call("b", {"x": 1})],
            complete,
        )
        add(
            f"completeness.not-called-no-calls.complete-{flag}",
            cond(nc("a")),
            [],
            complete,
        )
        add(
            f"completeness.not-called-other-calls.complete-{flag}",
            cond(nc("a")),
            [call("b", {})],
            complete,
        )
        add(
            f"completeness.not-called-called.complete-{flag}",
            cond(nc("a")),
            [call("a", {})],
            complete,
        )
        add(
            f"completeness.order-clean.complete-{flag}",
            cond(order("b", "a")),
            [call("b", {})],
            complete,
        )
        add(
            f"completeness.order-violated.complete-{flag}",
            cond(order("b", "a")),
            [call("a", {}), call("b", {})],
            complete,
        )


def _assignment_inputs(add: Adder) -> None:
    cx = cond(val(arg("a", "x"), "eq", lit(1)))
    add("assign.second-call-satisfies", cx, [call("a", {"x": 2}), call("a", {"x": 1})])
    add("assign.first-call-satisfies", cx, [call("a", {"x": 1}), call("a", {"x": 2})])
    add("assign.first-unknown-second-true", cx, [call("a", {}), call("a", {"x": 1})])
    add("assign.first-unknown-second-false", cx, [call("a", {}), call("a", {"x": 2})])
    add(
        "assign.first-unknown-second-false-incomplete",
        cx,
        [call("a", {}), call("a", {"x": 2})],
        False,
    )
    add("assign.all-false", cx, [call("a", {"x": 2}), call("a", {"x": 3})])
    add(
        "assign.all-false-incomplete",
        cx,
        [call("a", {"x": 2}), call("a", {"x": 3})],
        False,
    )
    add(
        "assign.true-among-other-operations",
        cx,
        [
            call("z", {"x": 1}),
            call("a", {"x": 2}),
            call(None, {"x": 1}),
            call("a", {"x": 1}),
        ],
    )
    add("assign.call-without-name", cx, [call(None, {"x": 1})])
    cross = cond(val(arg("a", "x"), "eq", arg("b", "y")))
    add(
        "assign.two-operations-second-pair",
        cross,
        [call("a", {"x": 1}), call("a", {"x": 2}), call("b", {"y": 2})],
    )
    add(
        "assign.two-operations-no-pair",
        cross,
        [call("a", {"x": 1}), call("a", {"x": 2}), call("b", {"y": 3})],
    )
    add(
        "assign.two-operations-first-pair-wins",
        cross,
        [
            call("a", {"x": 1}),
            call("b", {"y": 1}),
            call("a", {"x": 1}),
            call("b", {"y": 1}),
        ],
    )
    add(
        "assign.two-operations-unknown-then-true",
        cross,
        [call("a", {"x": 1}), call("b", {}), call("b", {"y": 1})],
    )
    add(
        "assign.matched-follows-operation-first-use",
        cond(val(arg("b", "y"), "eq", arg("a", "x"))),
        [call("a", {"x": 1}), call("b", {"y": 1})],
    )
    add(
        "assign.one-call-per-operation",
        cond(val(arg("a", "x"), "eq", lit(1)), val(arg("a", "y"), "eq", lit(2))),
        [call("a", {"x": 1, "y": 0}), call("a", {"x": 0, "y": 2})],
    )
    add(
        "assign.one-call-per-operation-satisfied",
        cond(val(arg("a", "x"), "eq", lit(1)), val(arg("a", "y"), "eq", lit(2))),
        [call("a", {"x": 1, "y": 0}), call("a", {"x": 1, "y": 2})],
    )
    add(
        "assign.same-operation-both-sides",
        cond(val(arg("a", "x"), "lt", arg("a", "y"))),
        [call("a", {"x": 5, "y": 1}), call("a", {"x": 1, "y": 5})],
    )
    add(
        "assign.three-operations",
        cond(
            val(arg("a", "x"), "eq", arg("b", "y")),
            val(arg("b", "y"), "eq", arg("c", "z")),
        ),
        [call("a", {"x": 1}), call("b", {"y": 1}), call("c", {"z": 1})],
    )
    add(
        "assign.three-operations-order-of-calls",
        cond(
            val(arg("a", "x"), "eq", arg("b", "y")),
            val(arg("b", "y"), "eq", arg("c", "z")),
        ),
        [call("c", {"z": 1}), call("b", {"y": 1}), call("a", {"x": 1})],
    )
    add(
        "assign.second-comparison-false",
        cond(val(arg("a", "x"), "eq", lit(1)), val(arg("a", "y"), "eq", lit(1))),
        [call("a", {"x": 1, "y": 2})],
    )
    add(
        "assign.second-comparison-unknown",
        cond(val(arg("a", "x"), "eq", lit(1)), val(arg("a", "y"), "eq", lit(1))),
        [call("a", {"x": 1})],
    )
    add(
        "assign.first-false-second-unknown",
        cond(val(arg("a", "x"), "eq", lit(1)), val(arg("a", "y"), "eq", lit(1))),
        [call("a", {"x": 2})],
    )
    add(
        "assign.operation-only-in-order-missing", cond(order("b", "a")), [call("a", {})]
    )
    add(
        "assign.operation-only-in-order-missing-incomplete",
        cond(order("b", "a")),
        [call("a", {})],
        False,
    )
    add(
        "assign.value-and-order-missing-operation",
        cond(val(arg("a", "x"), "eq", lit(1)), order("b", "a")),
        [call("a", {"x": 1})],
    )


def _not_called_inputs(add: Adder) -> None:
    add("not-called.no-calls", cond(nc("a")), [])
    add("not-called.called", cond(nc("a")), [call("a", {})])
    add(
        "not-called.called-with-undecodable-arguments", cond(nc("a")), [call("a", None)]
    )
    add("not-called.called-incomplete", cond(nc("a")), [call("a", {})], False)
    add("not-called.other-operation", cond(nc("a")), [call("b", {})])
    add("not-called.empty-where-called", cond(nc("a", [])), [call("a", {})])
    add("not-called.where-matches", cond(nc("a", [wh("k", 1)])), [call("a", {"k": 1})])
    add("not-called.where-mismatch", cond(nc("a", [wh("k", 1)])), [call("a", {"k": 2})])
    add(
        "not-called.where-mismatch-incomplete",
        cond(nc("a", [wh("k", 1)])),
        [call("a", {"k": 2})],
        False,
    )
    add(
        "not-called.where-argument-missing",
        cond(nc("a", [wh("k", 1)])),
        [call("a", {})],
    )
    add(
        "not-called.where-undecodable-arguments",
        cond(nc("a", [wh("k", 1)])),
        [call("a", None)],
    )
    add(
        "not-called.where-undecodable-arguments-list",
        cond(nc("a", [wh("k", 1)])),
        [call("a", [1])],
    )
    add(
        "not-called.where-unknown-then-match",
        cond(nc("a", [wh("k", 1)])),
        [call("a", {}), call("a", {"k": 1})],
    )
    add(
        "not-called.where-unknown-then-mismatch",
        cond(nc("a", [wh("k", 1)])),
        [call("a", {}), call("a", {"k": 2})],
    )
    add(
        "not-called.where-mismatch-then-unknown",
        cond(nc("a", [wh("k", 1)])),
        [call("a", {"k": 2}), call("a", {})],
    )
    add(
        "not-called.where-other-operation-matches",
        cond(nc("a", [wh("k", 1)])),
        [call("b", {"k": 1})],
    )
    add(
        "not-called.where-all-items-match",
        cond(nc("a", [wh("k", 1), wh("m", 2)])),
        [call("a", {"k": 1, "m": 2})],
    )
    add(
        "not-called.where-one-item-mismatch",
        cond(nc("a", [wh("k", 1), wh("m", 2)])),
        [call("a", {"k": 1, "m": 3})],
    )
    add(
        "not-called.where-mismatch-and-unknown-item",
        cond(nc("a", [wh("k", 1), wh("m", 2)])),
        [call("a", {"k": 2})],
    )
    add(
        "not-called.where-match-and-unknown-item",
        cond(nc("a", [wh("k", 1), wh("m", 2)])),
        [call("a", {"k": 1})],
    )
    add(
        "not-called.where-null-value",
        cond(nc("a", [wh("k", None)])),
        [call("a", {"k": None})],
    )
    for label, left, right in (
        ("int-float", 1, 1.0),
        ("bool-int", True, 1),
        ("int-bool", 1, True),
        ("str-int", "1", 1),
        ("list-equal", [1], [1]),
        ("list-nested-bool-int", [True], [1]),
        ("object-equal", {"k": 1}, {"k": 1}),
        ("object-different", {"k": 1}, {"k": 2}),
    ):
        add(
            f"not-called.where-equality.{label}",
            cond(nc("a", [wh("k", right)])),
            [call("a", {"k": left})],
        )
    add(
        "not-called.two-comparisons-one-called", cond(nc("a"), nc("b")), [call("b", {})]
    )
    add(
        "not-called.two-comparisons-none-called",
        cond(nc("a"), nc("b")),
        [call("c", {})],
    )
    add(
        "not-called.two-comparisons-false-and-unknown",
        cond(nc("a"), nc("b", [wh("k", 1)])),
        [call("a", {}), call("b", None)],
    )
    add(
        "not-called.two-comparisons-true-and-unknown",
        cond(nc("a"), nc("b", [wh("k", 1)])),
        [call("b", None)],
    )
    add(
        "not-called.where-scoped-to-operation",
        cond(nc("a", [wh("k", 1)]), nc("b", [wh("k", 2)])),
        [call("a", {"k": 2}), call("b", {"k": 1})],
    )


def _order_inputs(add: Adder) -> None:
    add("order.no-prior", cond(order("b", "a")), [call("b", {})])
    add("order.prior-before", cond(order("b", "a")), [call("a", {}), call("b", {})])
    add("order.prior-after", cond(order("b", "a")), [call("b", {}), call("a", {})])
    add(
        "order.prior-before-with-gap",
        cond(order("b", "a")),
        [call("a", {}), call("c", {}), call("b", {})],
    )
    add(
        "order.unrelated-call-before",
        cond(order("b", "a")),
        [call("c", {}), call("b", {})],
    )
    add(
        "order.unrelated-call-before-prior",
        cond(order("b", "a")),
        [call("c", {}), call("a", {}), call("b", {})],
    )
    add(
        "order.same-argument-unrelated-call-before",
        cond(order("b", "a", "id")),
        [call("c", {"id": 1}), call("b", {"id": 1})],
    )
    add(
        "order.prior-undecodable-without-same-argument",
        cond(order("b", "a")),
        [call("a", None), call("b", {})],
    )
    add(
        "order.same-argument-prior-same",
        cond(order("b", "a", "id")),
        [call("a", {"id": 1}), call("b", {"id": 1})],
    )
    add(
        "order.same-argument-prior-different",
        cond(order("b", "a", "id")),
        [call("a", {"id": 2}), call("b", {"id": 1})],
    )
    add(
        "order.same-argument-prior-after",
        cond(order("b", "a", "id")),
        [call("b", {"id": 1}), call("a", {"id": 1})],
    )
    add(
        "order.same-argument-no-prior",
        cond(order("b", "a", "id")),
        [call("b", {"id": 1})],
    )
    add(
        "order.same-argument-missing-on-operation",
        cond(order("b", "a", "id")),
        [call("a", {"id": 1}), call("b", {})],
    )
    add(
        "order.same-argument-operation-undecodable",
        cond(order("b", "a", "id")),
        [call("a", {"id": 1}), call("b", None)],
    )
    add(
        "order.same-argument-operation-undecodable-no-prior",
        cond(order("b", "a", "id")),
        [call("b", None)],
    )
    add(
        "order.same-argument-prior-undecodable",
        cond(order("b", "a", "id")),
        [call("a", None), call("b", {"id": 1})],
    )
    add(
        "order.same-argument-prior-missing-argument",
        cond(order("b", "a", "id")),
        [call("a", {}), call("b", {"id": 1})],
    )
    add(
        "order.same-argument-null-both-missing-on-prior",
        cond(order("b", "a", "id")),
        [call("a", {}), call("b", {"id": None})],
    )
    add(
        "order.same-argument-null-both",
        cond(order("b", "a", "id")),
        [call("a", {"id": None}), call("b", {"id": None})],
    )
    add(
        "order.same-argument-different-then-same",
        cond(order("b", "a", "id")),
        [call("a", {"id": 2}), call("a", {"id": 1}), call("b", {"id": 1})],
    )
    add(
        "order.same-argument-same-then-undecodable",
        cond(order("b", "a", "id")),
        [call("a", {"id": 1}), call("a", None), call("b", {"id": 1})],
    )
    add(
        "order.same-argument-undecodable-then-same",
        cond(order("b", "a", "id")),
        [call("a", None), call("a", {"id": 1}), call("b", {"id": 1})],
    )
    add(
        "order.same-argument-int-float",
        cond(order("b", "a", "id")),
        [call("a", {"id": 1.0}), call("b", {"id": 1})],
    )
    add(
        "order.same-argument-bool-int",
        cond(order("b", "a", "id")),
        [call("a", {"id": True}), call("b", {"id": 1})],
    )
    add(
        "order.same-argument-str-int",
        cond(order("b", "a", "id")),
        [call("a", {"id": "1"}), call("b", {"id": 1})],
    )
    add(
        "order.same-argument-list",
        cond(order("b", "a", "id")),
        [call("a", {"id": [1]}), call("b", {"id": [1]})],
    )
    add(
        "order.same-argument-null-field",
        cond(order("b", "a", None)),
        [call("a", {"id": 1}), call("b", {"id": 2})],
    )
    add(
        "order.same-argument-empty-string",
        cond(order("b", "a", "")),
        [call("a", {"id": 1}), call("b", {"id": 2})],
    )
    add(
        "order.same-argument-empty-string-key",
        cond(order("b", "a", "")),
        [call("a", {"": 1}), call("b", {"": 2})],
    )
    add("order.operation-missing", cond(order("b", "a")), [call("a", {})])
    add(
        "order.second-operation-call-clean",
        cond(order("b", "a")),
        [call("b", {}), call("a", {}), call("b", {})],
    )
    add(
        "order.second-operation-call-clean-first-violates",
        cond(order("b", "a")),
        [call("a", {}), call("b", {}), call("b", {})],
    )
    add(
        "order.operation-is-prior",
        cond(order("a", "a")),
        [call("a", {}), call("a", {})],
    )
    add("order.operation-is-prior-single", cond(order("a", "a")), [call("a", {})])
    add(
        "order.same-argument-prior-undecodable-incomplete",
        cond(order("b", "a", "id")),
        [call("a", None), call("b", {"id": 1})],
        False,
    )


def _shared_operation_inputs(add: Adder) -> None:
    add(
        "combine.value-and-order-satisfied",
        cond(val(arg("b", "x"), "eq", lit(1)), order("b", "a")),
        [call("b", {"x": 1})],
    )
    add(
        "combine.value-and-order-order-violated",
        cond(val(arg("b", "x"), "eq", lit(1)), order("b", "a")),
        [call("a", {}), call("b", {"x": 1})],
    )
    add(
        "combine.order-selects-other-call-of-operation",
        cond(val(arg("b", "x"), "eq", lit(1)), order("b", "a")),
        [call("b", {"x": 1}), call("a", {}), call("b", {"x": 2})],
    )
    add(
        "combine.order-then-value-second-call",
        cond(order("b", "a"), val(arg("b", "x"), "eq", lit(1))),
        [call("a", {}), call("b", {"x": 2}), call("b", {"x": 1})],
    )


def _not_called_combinations_inputs(add: Adder) -> None:
    not_called_cases = {
        "true": (nc("z", [wh("k", 1)]), []),
        "false": (nc("z", [wh("k", 1)]), [call("z", {"k": 1})]),
        "unknown": (nc("z", [wh("k", 1)]), [call("z", None)]),
    }
    call_cases = {
        "true": (val(arg("a", "x"), "eq", lit(1)), [call("a", {"x": 1})]),
        "false": (val(arg("a", "x"), "eq", lit(1)), [call("a", {"x": 2})]),
        "unknown": (val(arg("a", "x"), "eq", lit(1)), [call("a", {})]),
    }
    for (nc_label, (nc_comparison, nc_calls)), (
        call_label,
        (value, value_calls),
    ) in itertools.product(not_called_cases.items(), call_cases.items()):
        add(
            f"combine.not-called-{nc_label}.value-{call_label}",
            cond(nc_comparison, value),
            value_calls + nc_calls,
        )
        add(
            f"combine.not-called-{nc_label}.value-{call_label}.incomplete",
            cond(nc_comparison, value),
            value_calls + nc_calls,
            False,
        )
    add(
        "combine.not-called-after-value",
        cond(val(arg("a", "x"), "eq", lit(1)), nc("z")),
        [call("a", {"x": 1})],
    )
    add("combine.not-called-and-order", cond(nc("z"), order("b", "a")), [call("b", {})])
    add(
        "combine.not-called-and-order-violated",
        cond(nc("z"), order("b", "a")),
        [call("a", {}), call("b", {})],
    )
    add(
        "combine.not-called-same-operation-as-value",
        cond(val(arg("a", "x"), "eq", lit(1)), nc("a")),
        [call("a", {"x": 1})],
    )
    add(
        "combine.all-kinds-detected",
        cond(val(arg("a", "x"), "eq", lit(1)), nc("z"), order("b", "c")),
        [call("a", {"x": 1}), call("b", {})],
    )
    add(
        "combine.all-kinds-order-violated",
        cond(val(arg("a", "x"), "eq", lit(1)), nc("z"), order("b", "a")),
        [call("a", {"x": 1}), call("b", {})],
    )


def evaluate_inputs() -> list[tuple[str, object, list, bool]]:
    out: list[tuple[str, object, list, bool]] = []

    def add(vector_id, condition, calls, complete=True):
        out.append((vector_id, condition, calls, complete))

    for section in (
        _compare_inputs,
        _unresolved_inputs,
        _completeness_inputs,
        _assignment_inputs,
        _not_called_inputs,
        _order_inputs,
        _shared_operation_inputs,
        _not_called_combinations_inputs,
    ):
        section(add)
    return out


# --- results from Garak -----------------------------------------------------


def compute_validate(toolcall: Any, inputs: list) -> list[dict]:
    vectors = []
    for vector_id, condition in inputs:
        error = toolcall.validate_condition(condition)
        vectors.append(
            {
                "id": vector_id,
                "condition": condition,
                "valid": error is None,
                "error": error,
            }
        )
    return vectors


def compute_evaluate(toolcall: Any, inputs: list) -> list[dict]:
    vectors = []
    for vector_id, condition, calls, complete in inputs:
        assert toolcall.validate_condition(condition) is None, vector_id
        outcome, reason, matched = toolcall.evaluate_condition(
            condition, calls, complete
        )
        vectors.append(
            {
                "id": vector_id,
                "condition": condition,
                "calls": calls,
                "complete": complete,
                "outcome": outcome,
                "reason": reason,
                "matched_calls": matched,
            }
        )
    return vectors


def probe_crashes(toolcall: Any) -> list[str]:
    """Name each known input that makes Garak raise; the vectors exclude them."""

    found = []
    probes = {
        "kind is a list": cond({"kind": []}),
        "kind is an object": cond({"kind": {}}),
        "source is a list": cond(bad(left={"source": []})),
        "source is an object": cond(bad(left={"source": {}})),
    }
    for label, condition in probes.items():
        try:
            toolcall.validate_condition(condition)
        except Exception as error:  # noqa: BLE001 - probing for any crash
            found.append(f"validate_condition raises {type(error).__name__}: {label}")
    try:
        toolcall.evaluate_condition(
            cond(val(arg("a", "x"), "eq", lit(1))), [call("a", {"x": 10**400})], True
        )
    except Exception as error:  # noqa: BLE001
        found.append(f"evaluate_condition raises {type(error).__name__}: huge integer")
    return found


def worker() -> None:
    """Run inside the Garak interpreter: print the computed results as one JSON line."""

    from garak.detectors import toolcall

    assert toolcall.VALUE_OPS == VALUE_OPS, (
        "Garak's VALUE_OPS differ from this script's"
    )
    result = {
        "validate": compute_validate(toolcall, validate_inputs()),
        "evaluate": compute_evaluate(toolcall, evaluate_inputs()),
        "crashes": probe_crashes(toolcall),
    }
    print(json.dumps(result))


def checkout_problem(checkout: Path) -> str | None:
    """Return why the checkout cannot be the revision of record, or ``None``."""

    def git(*args: str) -> str:
        return subprocess.run(
            ["git", "-C", str(checkout), *args],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()

    head = git("rev-parse", "HEAD")
    if head != REVISION:
        return f"Garak checkout is at {head}, expected {REVISION}"
    if git("status", "--porcelain", "--untracked-files=no", "--", "garak"):
        return "Garak checkout has uncommitted changes under garak/"
    return None


def run_garak(garak_python: Path, checkout: Path) -> dict[str, Any]:
    problem = checkout_problem(checkout)
    if problem:
        raise SystemExit(problem)
    env = {**os.environ, "PYTHONPATH": str(checkout), "PYTHONDONTWRITEBYTECODE": "1"}
    done = subprocess.run(
        [str(garak_python), str(Path(__file__).resolve()), "--worker"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if done.returncode:
        sys.stderr.write(done.stderr)
        raise SystemExit(done.returncode)
    return json.loads(done.stdout.strip().splitlines()[-1])


# --- files ------------------------------------------------------------------


def dump(function: str, vectors: list[dict]) -> str:
    ids = [vector["id"] for vector in vectors]
    assert len(ids) == len(set(ids)), "duplicate vector ids"
    head = [
        ("contract", CONTRACT),
        ("version", VERSION),
        (
            "implementation",
            {
                "repository": "garak",
                "revision": REVISION,
                "module": "garak/detectors/toolcall.py",
                "function": function,
            },
        ),
    ]
    lines = ["{"]
    lines += [f'  "{key}": {json.dumps(value)},' for key, value in head]
    lines.append('  "vectors": [')
    lines += [
        "    " + json.dumps(vector) + ("," if index < len(vectors) - 1 else "")
        for index, vector in enumerate(vectors)
    ]
    lines += ["  ]", "}"]
    return "\n".join(lines) + "\n"


def lock_text(root: Path, vector_texts: dict[Path, str]) -> str:
    """Render CONTRACT.lock for the files under ``root``.

    A path in ``vector_texts`` is digested from that text instead of from disk.
    """

    files = {}
    for path in sorted(root.rglob("*"), key=lambda p: p.relative_to(root).as_posix()):
        if not path.is_file() or path.name == "CONTRACT.lock":
            continue
        payload = (
            vector_texts[path].encode() if path in vector_texts else path.read_bytes()
        )
        files[path.relative_to(root).as_posix()] = hashlib.sha256(payload).hexdigest()
    lock = {
        "authority": AUTHORITY,
        "contract": CONTRACT,
        "files": files,
        "version": VERSION,
    }
    return json.dumps(lock, indent=2) + "\n"


def planned_files(root: Path, computed: dict[str, Any]) -> dict[Path, str]:
    """Every file the script owns under ``root``, with its content."""

    vector_dir = root / VERSION / "vectors"
    planned = {
        vector_dir / name: dump(function, computed[name.removesuffix(".json")])
        for name, function in VECTOR_FUNCTIONS.items()
    }
    planned[root / "CONTRACT.lock"] = lock_text(root, planned)
    return planned


def stale_files(planned: dict[Path, str]) -> list[Path]:
    """The planned paths whose content on disk differs or is missing."""

    return [
        path
        for path, text in planned.items()
        if not path.is_file() or path.read_bytes() != text.encode()
    ]


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--garak-checkout", type=Path, help="Garak checkout at REVISION"
    )
    parser.add_argument(
        "--garak-python", type=Path, help="interpreter with Garak's dependencies"
    )
    parser.add_argument(
        "--check", action="store_true", help="write nothing; exit 1 on a difference"
    )
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if not args.worker and not (args.garak_checkout and args.garak_python):
        parser.error("--garak-checkout and --garak-python are required")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.worker:
        worker()
        return 0
    computed = run_garak(args.garak_python, args.garak_checkout)
    for line in computed["crashes"]:
        print("CRASH (excluded from the vectors):", line, file=sys.stderr)
    planned = planned_files(ROOT, computed)
    stale = stale_files(planned)
    if args.check:
        for path in stale:
            print("DIFFERS", path.relative_to(ROOT))
        print(f"{len(stale)} of {len(planned)} files differ")
        return 1 if stale else 0
    for path in stale:
        path.write_text(planned[path], encoding="utf-8")
    print(f"validate vectors: {len(computed['validate'])}")
    print(f"evaluate vectors: {len(computed['evaluate'])}")
    print(f"{len(stale)} of {len(planned)} files written")
    return 0


if __name__ == "__main__":
    sys.exit(main())
