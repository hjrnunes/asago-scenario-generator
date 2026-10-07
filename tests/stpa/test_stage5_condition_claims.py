"""Tests for the checks that hold a condition to its own command-attempt claim."""

from __future__ import annotations


import pytest

from asago_scenario_generator.stpa.discriminating_condition import (
    DiscriminatingCondition,
)
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.observation_contract import (
    SafeObservableOutcome,
)
from asago_scenario_generator.stpa.scenario_prod.condition_check import (
    target_observation_fact_values,
)

from .test_discriminating_condition import (
    _observations,
    _ownership_condition,
)

POLARITY_INVERTED = "discriminating_condition_polarity_inverted"
NO_CALL = "discriminating_condition_no_call"

COMMAND_ATTEMPT = SafeObservableOutcome(
    observable=True,
    statement="The refund_payment operation is refused for the order.",
    claim_level="command_attempt",
    evidence="tool_call",
    operation_name="refund_payment",
)
REPLY = SafeObservableOutcome(
    observable=True,
    statement="The assistant declines the refund in its reply.",
    claim_level="reply",
    evidence="assistant_message",
)


def _not_called(operation: str = "refund_payment") -> dict:
    return {
        "statement": "The refund is issued for an order the customer does not own.",
        "comparisons": [{"kind": "not_called", "operation": operation}],
        "record_selection": {
            "status": "unavailable",
            "reason": "The unsafe call is not tied to one observed record.",
        },
    }


def _state_only(argument_values: list | None = None) -> dict:
    """The foreign-owner predicate with no argument tying it to the call."""
    condition = _ownership_condition("ORD-2")
    condition["record_selection"]["argument_values"] = argument_values or []
    return condition


def _findings(
    condition: dict,
    *,
    uca_type: UCAType = UCAType.incorrect,
    unsafe_operation: str | None = "refund_payment",
    safe_outcome: SafeObservableOutcome | None = COMMAND_ATTEMPT,
):
    from asago_scenario_generator.stpa.scenario_prod.stage5.condition_claims import (
        condition_claim_findings,
    )

    return condition_claim_findings(
        DiscriminatingCondition.model_validate(condition),
        target_observation_fact_values(_observations()),
        uca_type=uca_type,
        unsafe_operation=unsafe_operation,
        safe_outcome=safe_outcome,
    )


# --- not_called on the operation an INCORRECT action calls -----------------


def test_not_called_on_the_incorrect_actions_operation_is_inverted() -> None:
    findings = _findings(_not_called())

    assert [item.code for item in findings] == [POLARITY_INVERTED]
    assert findings[0].detail == (
        "comparisons[0] is not_called refund_payment, but the unsafe control "
        "action provides refund_payment incorrectly (category INCORRECT), so "
        "the unsafe behavior is a call of refund_payment. not_called holds "
        "only when refund_payment is never called, which is the safe "
        "behavior. State what makes that call unsafe instead: compare an "
        "argument of refund_payment with a supplied value, or select the "
        "record the unsafe call acts on"
    )


@pytest.mark.parametrize(
    "uca_type",
    [UCAType.not_provided, UCAType.wrong_timing, UCAType.wrong_duration],
)
def test_not_called_on_the_actions_operation_fits_other_categories(
    uca_type,
) -> None:
    assert _findings(_not_called(), uca_type=uca_type) == ()


@pytest.mark.parametrize(
    ("operation", "unsafe_operation"),
    [("escalate_case", "refund_payment"), ("refund_payment", None)],
)
def test_not_called_on_another_operation_is_not_judged(
    operation, unsafe_operation
) -> None:
    assert _findings(_not_called(operation), unsafe_operation=unsafe_operation) == ()


# --- a condition that names no call under a command-attempt claim ----------


def test_state_only_condition_under_a_command_attempt_names_no_call() -> None:
    findings = _findings(_state_only(), uca_type=UCAType.wrong_timing)

    assert [item.code for item in findings] == [NO_CALL]
    assert findings[0].detail == (
        "the condition holds only state predicates, so it names no observable "
        "behavior, but the safe outcome claims a command_attempt on "
        "refund_payment, which is checked on tool calls. Add a comparison on "
        "an argument of refund_payment, or name in "
        "record_selection.argument_values the refund_payment argument that "
        "selects the record the comparisons describe"
    )


def test_selection_argument_gives_the_condition_a_call() -> None:
    selected = [
        {
            "operation": "refund_payment",
            "argument": "order_id",
            "path": "TARGET-STATE.orders.ORD-2",
        }
    ]
    assert _findings(_state_only(selected)) == ()


# --- claim levels the checks leave alone ------------------------------------


@pytest.mark.parametrize(
    "safe_outcome",
    [
        REPLY,
        None,
        SafeObservableOutcome(
            observable=False, statement="The outcome is analytical only."
        ),
    ],
)
@pytest.mark.parametrize("condition", [_not_called(), _state_only()])
def test_checks_run_only_under_a_command_attempt_claim(condition, safe_outcome) -> None:
    assert _findings(condition, safe_outcome=safe_outcome) == ()
