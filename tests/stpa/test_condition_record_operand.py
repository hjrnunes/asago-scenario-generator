"""A condition never compares a call argument with a whole record.

A call argument carries a value (an ID, a number, a word); a record fact is
an object, so no call can equal it. The check rejects the comparison through
the correction path even when the argument stays request-dependent and the
comparison could otherwise only be judged at execution time.
"""

from __future__ import annotations

import pytest

from asago_scenario_generator.stpa.scenario_prod.condition_check import (
    condition_failure_message,
)
from tests.helpers.discriminating_condition import _check, _universe


def _argument_versus_fact(path: str, op: str = "eq") -> dict:
    return {
        "statement": "The refunded order belongs to another customer.",
        "comparisons": [
            {
                "kind": "value",
                "left": {
                    "source": "argument",
                    "operation": "refund_payment",
                    "argument": "order_id",
                },
                "op": op,
                "right": {"source": "fact", "path": path},
            }
        ],
        "record_selection": {
            "status": "unavailable",
            "reason": "The order is chosen by the request.",
        },
    }


@pytest.mark.parametrize("op", ["eq", "ne"])
def test_an_argument_compared_with_a_record_fact_is_rejected(op: str) -> None:
    assert isinstance(_universe().fact_values["TARGET-STATE.orders.ORD-2"], dict)

    outcome = _check(_argument_versus_fact("TARGET-STATE.orders.ORD-2", op))

    assert outcome.check is None
    assert outcome.reference_errors == (
        f"comparisons[0] compares argument refund_payment.order_id {op} fact "
        "TARGET-STATE.orders.ORD-2, a whole record, which no call argument "
        'can equal. Compare the argument with the record\'s key as a literal ("ORD-2") '
        "or one of the record's fields (TARGET-STATE.orders.ORD-2.<field>)",
    )
    message = condition_failure_message(outcome)
    assert message is not None
    assert message.startswith("discriminating_condition_check_failed:")


def test_an_argument_compared_with_a_record_field_stays_checkable() -> None:
    outcome = _check(_argument_versus_fact("TARGET-STATE.orders.ORD-2.amount"))

    assert outcome.reference_errors == ()
    assert outcome.check is not None
    assert outcome.check.comparisons[0].result == "not_checkable"
