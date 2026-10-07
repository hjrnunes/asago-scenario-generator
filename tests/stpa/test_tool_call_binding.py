"""Offline tests for binding a discriminating condition to a tool-call condition.

The first group ports every case of the reference binder's tests
(``asago-orch`` ``tests/experiments/test_bind.py``); the reference statuses map
to v3 statuses as the scenario-handoff-v3 contract table states. Facts come
from the producer's own target-observation fact values.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from asago_scenario_generator.stpa.discriminating_condition import (
    DiscriminatingCondition,
)
from asago_scenario_generator.stpa.scenario_prod.condition_check import (
    target_observation_fact_values,
)
from asago_scenario_generator.stpa.scenario_prod.target_observations import (
    TargetObservationSnapshot,
)
from asago_scenario_generator.stpa.scenario_prod.tool_call_binding import (
    bind_tool_call_condition,
    compare,
)
from asago_scenario_generator.stpa.tool_call_condition import (
    NOT_EXECUTABLE_REASONS,
    ToolCallCondition,
    ToolCallConditionStatus,
)

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


def handoff(
    comparisons: list[dict[str, Any]], *selection: dict[str, str]
) -> dict[str, Any]:
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


def bind(condition: Any):
    return bind_tool_call_condition(condition, FACTS)


def spec(condition: Any) -> dict[str, Any] | None:
    bound = bind(condition)
    if bound.condition is None:
        return None
    return bound.condition.model_dump(mode="json", exclude_none=True)


def reason(condition: Any) -> str:
    return bind(condition).status.reason


def arg(operation: str, argument: str) -> dict[str, str]:
    return {"source": "argument", "operation": operation, "argument": argument}


def fact(path: str) -> dict[str, str]:
    return {"source": "fact", "path": path}


def literal(value: Any) -> dict[str, Any]:
    return {"source": "literal", "value": value}


def value(left: Any, op: str, right: Any) -> dict[str, Any]:
    return {"kind": "value", "left": left, "op": op, "right": right}


def not_called(operation: str) -> dict[str, str]:
    return {"kind": "not_called", "operation": operation}


def item(operation: str, argument: str, path: str) -> dict[str, str]:
    return {"operation": operation, "argument": argument, "path": path}


def eq_literal(operation: str, argument: str, wanted: Any) -> dict[str, Any]:
    return {
        "kind": "value",
        "left": arg(operation, argument),
        "op": "eq",
        "right": literal(wanted),
    }


ESCALATE_ONLY = {
    "comparisons": [{"kind": "not_called", "operation": "escalate", "where": []}]
}


# --- ported reference cases ---------------------------------------------------


def test_not_called_alone_binds_with_an_empty_where() -> None:
    result = bind(handoff([not_called("escalate")]))
    assert result.status.status == "bound"
    assert result.status.reason == "bound"
    assert spec(handoff([not_called("escalate")])) == ESCALATE_ONLY


def test_selection_on_a_not_called_operation_scopes_every_such_comparison() -> None:
    scenario = handoff(
        [not_called("lookup_order"), not_called("lookup_order"), not_called("other")],
        item("lookup_order", "order_id", "TARGET-STATE.orders.ORD-201"),
    )
    where = [{"argument": "order_id", "value": "ORD-201"}]
    assert spec(scenario) == {
        "comparisons": [
            {"kind": "not_called", "operation": "lookup_order", "where": where},
            {"kind": "not_called", "operation": "lookup_order", "where": where},
            {"kind": "not_called", "operation": "other", "where": []},
        ]
    }


def test_selection_on_another_operation_appends_an_eq_after_own_comparisons() -> None:
    scenario = handoff(
        [value(arg("refund", "amount"), "gt", literal(5)), not_called("escalate")],
        item("refund", "order_id", "TARGET-STATE.orders.ORD-201"),
    )
    assert spec(scenario) == {
        "comparisons": [
            value(arg("refund", "amount"), "gt", literal(5)),
            {"kind": "not_called", "operation": "escalate", "where": []},
            eq_literal("refund", "order_id", "ORD-201"),
        ]
    }


@pytest.mark.parametrize(
    ("path", "wanted"),
    [
        # A scalar path binds its resolved value.
        ("TARGET-STATE.orders.ORD-201.customer_id", "CUST002"),
        ("TARGET-STATE.limit", 100),
        # An object, a list, or an unresolved path binds its last segment.
        ("TARGET-STATE.orders.ORD-104", "ORD-104"),
        ("TARGET-STATE.flags", "flags"),
        ("TARGET-STATE.orders.ORD-999", "ORD-999"),
    ],
)
def test_selection_wanted_value_is_scalar_or_last_segment(
    path: str, wanted: Any
) -> None:
    assert spec(handoff([], item("refund", "x", path))) == {
        "comparisons": [eq_literal("refund", "x", wanted)]
    }


def test_selection_alone_is_a_behavioral_part() -> None:
    scenario = handoff([], item("refund", "order_id", "TARGET-STATE.orders.ORD-104"))
    assert bind(scenario).status.status == "bound"


def test_fact_operands_in_call_comparisons_become_literals() -> None:
    scenario = handoff(
        [
            value(
                arg("get_account", "customer_id"),
                "ne",
                fact("TARGET-STATE.authenticated_customer_id"),
            ),
            value(fact("TARGET-STATE.flags"), "in", arg("get_account", "flags")),
        ]
    )
    assert spec(scenario) == {
        "comparisons": [
            value(arg("get_account", "customer_id"), "ne", literal("CUST001")),
            value(literal(["a", "b"]), "in", arg("get_account", "flags")),
        ]
    }


def test_unresolved_fact_in_a_call_comparison_is_unbindable() -> None:
    scenario = handoff(
        [value(arg("refund", "order_id"), "eq", fact("TARGET-STATE.orders.ORD-9.id"))]
    )
    result = bind(scenario)
    assert result.status.status == "not_executable"
    assert result.status.reason == "unresolved_fact"
    assert result.condition is None
    assert "TARGET-STATE.orders.ORD-9.id" in result.status.detail


def test_unknown_operand_source_is_unbindable() -> None:
    scenario = handoff([value(arg("refund", "x"), "eq", {"source": "snapshot"})])
    assert reason(scenario) == "unresolved_fact"


def test_true_state_predicates_are_dropped() -> None:
    scenario = handoff(
        [
            value(fact("TARGET-STATE.limit"), "ge", literal(50)),
            not_called("escalate"),
        ]
    )
    assert reason(scenario) == "bound"
    assert spec(scenario) == ESCALATE_ONLY


def test_false_state_predicate_fails_the_precondition() -> None:
    scenario = handoff(
        [
            value(fact("TARGET-STATE.limit"), "lt", literal(50)),
            value(fact("TARGET-STATE.orders.ORD-9.id"), "eq", literal("x")),
            not_called("escalate"),
        ]
    )
    result = bind(scenario)
    assert result.status.reason == "precondition_failed"
    assert result.condition is None


def test_unknown_state_predicate_is_not_executable() -> None:
    # The reference binder keeps a spec for ``precondition_unknown``; v3
    # publishes a condition only when bound, so none is emitted.
    scenario = handoff(
        [
            value(fact("TARGET-STATE.orders.ORD-9.id"), "eq", literal("x")),
            value(fact("TARGET-STATE.limit"), "eq", literal(100)),
            not_called("escalate"),
        ]
    )
    result = bind(scenario)
    assert result.status.status == "not_executable"
    assert result.status.reason == "precondition_unknown"
    assert result.condition is None


def test_false_predicate_wins_over_unbindable_and_unbindable_over_unknown() -> None:
    unresolved_call = value(arg("refund", "x"), "eq", fact("TARGET-STATE.nope"))
    unknown_static = value(fact("TARGET-STATE.nope"), "eq", literal(1))
    false_static = value(fact("TARGET-STATE.limit"), "eq", literal(1))
    assert reason(handoff([unresolved_call, false_static])) == "precondition_failed"
    assert reason(handoff([unresolved_call, unknown_static])) == "unresolved_fact"


def test_order_is_copied_with_an_optional_same_argument() -> None:
    scenario = handoff(
        [
            {
                "kind": "order",
                "operation": "refund",
                "requires_prior": "lookup",
                "same_argument": "order_id",
            },
            {"kind": "order", "operation": "pay", "requires_prior": "lookup"},
        ]
    )
    assert spec(scenario) == {
        "comparisons": [
            {
                "kind": "order",
                "operation": "refund",
                "requires_prior": "lookup",
                "same_argument": "order_id",
            },
            {
                "kind": "order",
                "operation": "pay",
                "requires_prior": "lookup",
                "same_argument": None,
            },
        ]
    }


@pytest.mark.parametrize(
    ("scenario", "expected_reason", "detail"),
    [
        (None, "no_condition", "the handoff publishes no discriminating condition"),
        (
            handoff([{"kind": "sometimes"}, not_called("escalate")]),
            "condition_problem",
            "unknown comparison kind 'sometimes'",
        ),
        (
            handoff([value(fact("TARGET-STATE.limit"), "eq", literal(100))]),
            "state_only",
            "the condition holds only state predicates, "
            "so it names no observable behavior",
        ),
        (handoff([]), "state_only", None),
    ],
)
def test_abstains_without_a_behavioral_part(
    scenario: Any, expected_reason: str, detail: str | None
) -> None:
    result = bind(scenario)
    assert result.status.status == "not_executable"
    assert result.status.reason == expected_reason
    assert result.condition is None
    if detail is not None:
        assert result.status.detail == detail


def test_unavailable_selection_adds_nothing() -> None:
    scenario = handoff([not_called("escalate")])
    scenario["record_selection"] = {
        "status": "unavailable",
        "argument_values": [item("refund", "x", "TARGET-STATE.limit")],
    }
    assert spec(scenario) == ESCALATE_ONLY


def test_bound_status_carries_status_reason_and_detail() -> None:
    result = bind(handoff([not_called("escalate")]))
    assert result.status.model_dump(mode="json") == {
        "status": "bound",
        "reason": "bound",
        "detail": result.status.detail,
    }
    assert result.status.detail.strip()


# --- producer cases -----------------------------------------------------------


REASON_CASES: dict[str, Any] = {
    "no_condition": None,
    "condition_problem": handoff([{"kind": "sometimes"}, not_called("escalate")]),
    "state_only": handoff([value(fact("TARGET-STATE.limit"), "eq", literal(100))]),
    "precondition_failed": handoff(
        [value(fact("TARGET-STATE.limit"), "lt", literal(50)), not_called("escalate")]
    ),
    "precondition_unknown": handoff(
        [value(fact("TARGET-STATE.nope"), "eq", literal(1)), not_called("escalate")]
    ),
    "unresolved_fact": handoff(
        [value(arg("refund", "x"), "eq", fact("TARGET-STATE.nope"))]
    ),
}


def test_reason_cases_cover_every_not_executable_reason() -> None:
    assert set(REASON_CASES) == set(NOT_EXECUTABLE_REASONS)


@pytest.mark.parametrize(("expected", "scenario"), list(REASON_CASES.items()))
def test_every_not_executable_reason_has_no_condition_and_a_detail(
    expected: str, scenario: Any
) -> None:
    result = bind(scenario)
    assert result.status.status == "not_executable"
    assert result.status.reason == expected
    assert result.status.detail.strip()
    assert result.condition is None


def test_omitted_condition_reason_is_carried_into_the_detail() -> None:
    result = bind_tool_call_condition(
        None, FACTS, condition_omitted_reason="The condition failed validation."
    )
    assert result.status.reason == "no_condition"
    assert result.status.detail.endswith("The condition failed validation.")


def test_unresolved_detail_names_the_fact_path() -> None:
    detail = bind(REASON_CASES["unresolved_fact"]).status.detail
    assert "'TARGET-STATE.nope'" in detail


def test_failed_and_unknown_details_name_the_comparison_index() -> None:
    assert "comparisons[0]" in bind(REASON_CASES["precondition_failed"]).status.detail
    assert "comparisons[0]" in bind(REASON_CASES["precondition_unknown"]).status.detail


def test_a_checked_condition_model_binds_like_its_json_form() -> None:
    raw = handoff(
        [
            value(arg("refund", "amount"), "gt", literal(5)),
            {"kind": "order", "operation": "refund", "requires_prior": "lookup"},
        ],
        item("refund", "order_id", "TARGET-STATE.orders.ORD-201"),
    )
    raw["record_selection"]["record_path"] = "TARGET-STATE.orders.ORD-201"
    model = DiscriminatingCondition.model_validate(raw)
    assert bind(model) == bind(raw)
    assert bind(model).status.reason == "bound"


def test_ambiguous_fact_paths_do_not_resolve() -> None:
    ambiguous = target_observation_fact_values(
        TargetObservationSnapshot.from_runtime_context(
            {
                "target_profile_digest": "0" * 64,
                "state": {"limit": 1},
                "read_observations": [
                    {
                        "profile_digest": "0" * 64,
                        "status": {"transport": "verified", "content": "untrusted"},
                        "arguments": {"id": "A"},
                        "result": {"structuredContent": {"arguments": {"id": "B"}}},
                    }
                ],
            }
        )
    )
    condition = handoff(
        [value(arg("refund", "x"), "eq", fact("TARGET-READ-001.arguments.id"))]
    )
    assert bind_tool_call_condition(condition, ambiguous).status.reason == (
        "unresolved_fact"
    )


def test_a_null_fact_value_binds_as_a_null_literal() -> None:
    facts = {"TARGET-STATE.closed_at": None}
    condition = handoff(
        [value(arg("refund", "closed_at"), "eq", fact("TARGET-STATE.closed_at"))]
    )
    bound = bind_tool_call_condition(condition, facts).condition
    assert bound is not None
    dumped = bound.model_dump(mode="json", exclude_none=True)
    assert dumped["comparisons"][0]["right"] == {"source": "literal", "value": None}


@pytest.mark.parametrize(
    ("op", "left", "right", "expected"),
    [
        # Arm 1 rules: numbers compare as floats, strings parse as numbers,
        # booleans are never numbers, and a list left side is element-wise.
        ("eq", 1, 1.0, True),
        ("eq", True, 1, False),
        ("gt", "600", 500, True),
        ("gt", True, 0, None),
        ("in", ["a", "z"], ["a"], True),
        ("not_in", "a", ["a"], False),
        ("in", "a", "a", None),
        ("ne", "x", "y", True),
    ],
)
def test_compare_uses_arm_one_truth_rules(
    op: str, left: Any, right: Any, expected: Any
) -> None:
    assert compare(op, left, right) is expected


@pytest.mark.parametrize(
    "payload",
    [
        {"comparisons": []},
        {"comparisons": [value(literal(1), "eq", literal(2))]},
        {"comparisons": [value(arg("a", "b"), "eq", fact("TARGET-STATE.x"))]},
        {"comparisons": [{"kind": "sometimes"}]},
        {"comparisons": [not_called("a")], "extra": 1},
    ],
)
def test_tool_call_condition_rejects_invalid_shapes(payload: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        ToolCallCondition.model_validate(payload)


@pytest.mark.parametrize(
    ("status", "reason_code"),
    [("bound", "no_condition"), ("not_executable", "bound")],
)
def test_status_pairs_bound_only_with_reason_bound(
    status: str, reason_code: str
) -> None:
    with pytest.raises(ValidationError):
        ToolCallConditionStatus(status=status, reason=reason_code, detail="d")


def test_status_rejects_a_blank_detail() -> None:
    with pytest.raises(ValidationError):
        ToolCallConditionStatus(status="bound", reason="bound", detail="  ")


# --- the session subject is not behavior ----------------------------------------


SESSION_ONLY_DETAIL = (
    "the condition's only comparisons restate the session subject, so it "
    "names no observable behavior"
)


@pytest.mark.parametrize(
    "scenario",
    [
        handoff([], item("refund", "owner", "TARGET-STATE.orders.ORD-104.customer_id")),
        handoff([eq_literal("refund", "customer_id", "CUST001")]),
        handoff(
            [
                value(
                    arg("refund", "customer_id"),
                    "eq",
                    fact("TARGET-STATE.authenticated_customer_id"),
                )
            ]
        ),
        handoff(
            [
                value(literal("CUST001"), "eq", arg("refund", "customer_id")),
                value(fact("TARGET-STATE.limit"), "eq", literal(100)),
            ],
            item("refund", "owner", "TARGET-STATE.orders.ORD-104.customer_id"),
        ),
        handoff(
            [value(fact("TARGET-STATE.limit"), "lt", literal(50))],
            item("refund", "owner", "TARGET-STATE.orders.ORD-104.customer_id"),
        ),
    ],
    ids=[
        "selection",
        "argument-eq",
        "argument-eq-session-fact",
        "both-with-true-predicate",
        "false-predicate",
    ],
)
def test_a_condition_that_only_equals_the_session_subject_is_state_only(
    scenario: Any,
) -> None:
    result = bind(scenario)

    assert result.status.status == "not_executable"
    assert result.status.reason == "state_only"
    assert result.status.detail == SESSION_ONLY_DETAIL
    assert result.condition is None


@pytest.mark.parametrize(
    "scenario",
    [
        handoff(
            [not_called("escalate")],
            item("refund", "owner", "TARGET-STATE.orders.ORD-104.customer_id"),
        ),
        handoff(
            [],
            item("escalate", "owner", "TARGET-STATE.orders.ORD-104.customer_id"),
        )
        | {"comparisons": [not_called("escalate")]},
        handoff([eq_literal("refund", "customer_id", "CUST002")]),
        handoff([value(arg("refund", "customer_id"), "ne", literal("CUST001"))]),
        handoff(
            [
                value(arg("refund", "amount"), "gt", literal(5)),
                eq_literal("refund", "customer_id", "CUST001"),
            ]
        ),
        handoff([], item("refund", "owner", "TARGET-STATE.orders.ORD-201.customer_id")),
    ],
    ids=[
        "not-called",
        "selection-scopes-not-called",
        "another-subject",
        "ne",
        "other-behavior",
        "selection-of-another-record",
    ],
)
def test_a_session_comparison_next_to_other_behavior_still_binds(
    scenario: Any,
) -> None:
    assert bind(scenario).status.status == "bound"


def test_the_session_comparison_stays_in_a_bound_condition() -> None:
    scenario = handoff(
        [value(arg("refund", "amount"), "gt", literal(5))],
        item("refund", "owner", "TARGET-STATE.orders.ORD-104.customer_id"),
    )

    assert spec(scenario) == {
        "comparisons": [
            value(arg("refund", "amount"), "gt", literal(5)),
            eq_literal("refund", "owner", "CUST001"),
        ]
    }


def test_without_a_session_subject_an_equality_is_behavior() -> None:
    facts = {"TARGET-STATE.orders.ORD-1.customer_id": "CUST001"}

    result = bind_tool_call_condition(
        handoff([eq_literal("refund", "customer_id", "CUST001")]), facts
    )

    assert result.status.status == "bound"
