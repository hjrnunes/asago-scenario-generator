"""Tests for the producer-owned ``tool-call-condition`` contract.

The contract's vectors hold the results of Garak's ``validate_condition`` and
``evaluate_condition``; Garak's own tests run them against the code. These
tests check what the producer can check offline: the lock, the schema against
the validate vectors, the shape of the vectors, and that every condition the
binder produces satisfies the schema.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from asago_scenario_generator.stpa.scenario_prod.condition_check import (
    target_observation_fact_values,
)
from asago_scenario_generator.stpa.scenario_prod.target_observations import (
    TargetObservationSnapshot,
)
from asago_scenario_generator.stpa.scenario_prod.tool_call_binding import (
    bind_tool_call_condition,
)

DATA = Path(__file__).resolve().parents[2] / "data/contracts"
CONTRACT_ROOT = DATA / "tool-call-condition"
KIT = CONTRACT_ROOT / "tool-call-condition-v1"
HANDOFF_V3_VALID = DATA / "scenario-handoff/handoff-v3/valid"

VALUE_OPS = ("eq", "ne", "gt", "ge", "lt", "le", "in", "not_in")
OUTCOME_REASONS = {
    "detected": "the condition holds on the captured calls",
    "not_detected": "the captured calls do not satisfy the condition",
    "inconclusive": "capture is incomplete or a relevant call is undecodable",
}


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


SCHEMA = _load(KIT / "schema.json")
VALIDATOR = Draft202012Validator(SCHEMA)
VALIDATE = _load(KIT / "vectors/validate.json")["vectors"]
EVALUATE = _load(KIT / "vectors/evaluate.json")["vectors"]


def _schema_errors(condition: Any) -> list[str]:
    return [error.message for error in VALIDATOR.iter_errors(condition)]


def test_lock_records_every_contract_file_digest() -> None:
    lock = _load(CONTRACT_ROOT / "CONTRACT.lock")
    assert lock["contract"] == "tool-call-condition"
    assert lock["authority"] == "asago-scenario-generator"
    assert lock["version"] == "tool-call-condition-v1"
    on_disk = {
        path.relative_to(CONTRACT_ROOT).as_posix()
        for path in CONTRACT_ROOT.rglob("*")
        if path.is_file() and path.name != "CONTRACT.lock"
    }
    assert set(lock["files"]) == on_disk
    assert on_disk == {
        "tool-call-condition-v1/README.md",
        "tool-call-condition-v1/schema.json",
        "tool-call-condition-v1/vectors/evaluate.json",
        "tool-call-condition-v1/vectors/validate.json",
    }
    for relative, expected in lock["files"].items():
        payload = (CONTRACT_ROOT / relative).read_bytes()
        assert hashlib.sha256(payload).hexdigest() == expected, relative


def test_schema_is_a_valid_draft_2020_12_schema() -> None:
    Draft202012Validator.check_schema(SCHEMA)


def test_vector_ids_are_unique_within_each_file() -> None:
    for vectors in (VALIDATE, EVALUATE):
        ids = [vector["id"] for vector in vectors]
        assert len(ids) == len(set(ids))


@pytest.mark.parametrize("vector", VALIDATE, ids=lambda vector: vector["id"])
def test_schema_agrees_with_every_validate_vector(vector: dict[str, Any]) -> None:
    assert vector["valid"] == (vector["error"] is None)
    assert (not _schema_errors(vector["condition"])) == vector["valid"]


def test_validate_vectors_exercise_every_rule_family() -> None:
    errors = [vector["error"] for vector in VALIDATE if vector["error"]]
    families = [
        r"^condition is not an object$",
        r"^condition has unknown keys \[",
        r"^comparisons is missing or empty$",
        r"is not an object$",
        r"has unknown kind ",
        r"has unknown keys \[",
        r"is missing \[",
        r"has unknown op ",
        r"has unknown source ",
        r"has no argument operand$",
        r"is not a string$",
        r"is not a list$",
    ]
    for family in families:
        assert any(re.search(family, error) for error in errors), family
    valid = [vector["condition"] for vector in VALIDATE if vector["valid"]]
    comparisons = [item for condition in valid for item in condition["comparisons"]]
    assert {item["kind"] for item in comparisons} == {"value", "not_called", "order"}
    assert {item["op"] for item in comparisons if item["kind"] == "value"} == set(
        VALUE_OPS
    )


def test_evaluate_vector_conditions_satisfy_the_schema() -> None:
    rejected = [
        vector["id"] for vector in EVALUATE if _schema_errors(vector["condition"])
    ]
    assert rejected == []


def test_evaluate_vector_results_are_well_formed() -> None:
    malformed = []
    for vector in EVALUATE:
        calls = vector["calls"]
        matched = vector["matched_calls"]
        good = (
            OUTCOME_REASONS.get(vector["outcome"]) == vector["reason"]
            and isinstance(vector["complete"], bool)
            and all(set(call) == {"name", "arguments"} for call in calls)
            and all(
                isinstance(index, int) and 0 <= index < len(calls) for index in matched
            )
            and len(set(matched)) == len(matched)
        )
        if not good:
            malformed.append(vector["id"])
    assert malformed == []


def test_evaluate_vectors_cover_every_outcome_with_and_without_completeness() -> None:
    seen = {(vector["outcome"], vector["complete"]) for vector in EVALUATE}
    assert seen == {
        (outcome, complete) for outcome in OUTCOME_REASONS for complete in (True, False)
    }
    ops = {
        item["op"]
        for vector in EVALUATE
        for item in vector["condition"]["comparisons"]
        if item["kind"] == "value"
    }
    assert ops == set(VALUE_OPS)


# --- conditions the binder produces ----------------------------------------

FACTS = target_observation_fact_values(
    TargetObservationSnapshot.from_runtime_context(
        {
            "target_profile_digest": "0" * 64,
            "state": {
                "authenticated_customer_id": "CUST001",
                "limit": 100,
                "flags": ["a", "b"],
                "orders": {
                    "ORD-104": {"customer_id": "CUST001", "amount": 50.0},
                    "ORD-201": {"customer_id": "CUST002", "amount": 10.0},
                },
            },
        }
    )
)


def _arg(operation: str, argument: str) -> dict[str, str]:
    return {"source": "argument", "operation": operation, "argument": argument}


def _fact(path: str) -> dict[str, str]:
    return {"source": "fact", "path": path}


def _literal(value: Any) -> dict[str, Any]:
    return {"source": "literal", "value": value}


def _value(left: Any, op: str, right: Any) -> dict[str, Any]:
    return {"kind": "value", "left": left, "op": op, "right": right}


def _scenario(comparisons: list[dict[str, Any]], *selection: dict[str, str]) -> dict:
    return {
        "statement": "s",
        "comparisons": comparisons,
        "record_selection": (
            {
                "status": "observed",
                "record_path": "TARGET-STATE.orders",
                "argument_values": list(selection),
            }
            if selection
            else {"status": "unavailable", "reason": "none"}
        ),
    }


def _select(operation: str, argument: str, path: str) -> dict[str, str]:
    return {"operation": operation, "argument": argument, "path": path}


BOUND_CASES: dict[str, dict[str, Any]] = {
    **{
        f"value-op-{op}": _scenario(
            [_value(_arg("refund", "amount"), op, _literal([5] if "in" in op else 5))]
        )
        for op in VALUE_OPS
    },
    "literal-null": _scenario([_value(_arg("refund", "note"), "eq", _literal(None))]),
    "two-arguments": _scenario(
        [_value(_arg("refund", "amount"), "le", _arg("order", "total"))]
    ),
    "fact-becomes-literal": _scenario(
        [
            _value(
                _arg("get_account", "customer_id"),
                "ne",
                _fact("TARGET-STATE.authenticated_customer_id"),
            ),
            _value(_fact("TARGET-STATE.flags"), "in", _arg("get_account", "flags")),
        ]
    ),
    "not-called": _scenario([{"kind": "not_called", "operation": "escalate"}]),
    "not-called-scoped-by-selection": _scenario(
        [{"kind": "not_called", "operation": "lookup_order"}],
        _select("lookup_order", "order_id", "TARGET-STATE.orders.ORD-201"),
    ),
    "not-called-scoped-by-scalar-selection": _scenario(
        [{"kind": "not_called", "operation": "set_limit"}],
        _select("set_limit", "limit", "TARGET-STATE.limit"),
    ),
    "order": _scenario(
        [{"kind": "order", "operation": "pay", "requires_prior": "lookup"}]
    ),
    "order-same-argument": _scenario(
        [
            {
                "kind": "order",
                "operation": "refund",
                "requires_prior": "lookup",
                "same_argument": "order_id",
            }
        ]
    ),
    "selection-appends-an-eq": _scenario(
        [_value(_arg("refund", "amount"), "gt", _literal(5))],
        _select("refund", "order_id", "TARGET-STATE.orders.ORD-201"),
    ),
    "selection-on-an-object-path": _scenario(
        [], _select("refund", "order_id", "TARGET-STATE.orders.ORD-104")
    ),
    "true-state-predicate-is-dropped": _scenario(
        [
            _value(_fact("TARGET-STATE.limit"), "ge", _literal(50)),
            {"kind": "not_called", "operation": "escalate"},
        ]
    ),
    "every-kind": _scenario(
        [
            _value(_arg("refund", "amount"), "gt", _literal(5)),
            {"kind": "not_called", "operation": "escalate"},
            {"kind": "order", "operation": "refund", "requires_prior": "lookup"},
        ],
        _select("refund", "order_id", "TARGET-STATE.orders.ORD-201"),
    ),
}


@pytest.mark.parametrize("case", list(BOUND_CASES))
def test_bound_condition_satisfies_the_schema(case: str) -> None:
    bound = bind_tool_call_condition(BOUND_CASES[case], FACTS)
    assert bound.status.status == "bound", bound.status.detail
    assert bound.condition is not None
    condition = bound.condition.model_dump(mode="json", exclude_none=True)
    assert _schema_errors(condition) == []


@pytest.mark.parametrize(
    "fixture", sorted(HANDOFF_V3_VALID.glob("*.json")), ids=lambda path: path.name
)
def test_handoff_v3_fixture_condition_satisfies_the_schema(fixture: Path) -> None:
    payload = _load(fixture)
    if payload["tool_call_condition_status"]["status"] != "bound":
        assert "tool_call_condition" not in payload
        return
    assert _schema_errors(payload["tool_call_condition"]) == []
