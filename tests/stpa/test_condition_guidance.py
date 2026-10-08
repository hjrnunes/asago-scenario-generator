"""Stage 5 guidance for testable, correctly grounded conditions.

The fixed wording sits in ``tests/phrases/stage5_context_*.yaml`` and
``tests/phrases/stage2_call2a_system.yaml``. These tests pin the hints built
from a condition family and the correction messages.
"""

from __future__ import annotations

from asago_scenario_generator.stpa.scenario_prod.condition_check import (
    condition_failure_message,
)
from asago_scenario_generator.stpa.scenario_prod.condition_family import (
    ConditionFamily,
    derive_condition_families,
    family_prompt_view,
)

from .test_condition_family import EDIT, OPS, _index, _kind, _request, _state
from .test_discriminating_condition import _check


def _flat(text: str) -> str:
    return " ".join(text.split())


def _stage5(family: ConditionFamily | None = None) -> tuple[str, str]:
    system, user = _request(family)
    return _flat(system), _flat(user)


# --- item 1: argument_values in bounded comparisons ------------------------


def test_bound_family_records_the_record_selecting_argument() -> None:
    (family,) = _kind(
        derive_condition_families(EDIT, OPS, _index(_state())),
        "bound",
    )
    assert family.argument == "price"
    assert family.record_argument == "widget_id"
    assert family_prompt_view(family)["record_argument"] == "widget_id"
    assert family.as_log()["record_argument"] == "widget_id"


def test_bound_hint_says_which_argument_goes_in_argument_values() -> None:
    family = ConditionFamily(
        kind="bound",
        operation="update_gadget",
        argument="quantity",
        argument_role="value",
        record_argument="gadget_id",
        field_paths=("TARGET-STATE.gadgets.<record_key>.list_price",),
    )
    _, user = _stage5(family)
    assert (
        "`gadget_id` selects the record: map `gadget_id`, not `quantity`, in "
        "`argument_values`, and compare `quantity` as an argument operand."
    ) in user


def test_key_mapped_value_argument_gets_a_targeted_correction() -> None:
    outcome = _check(
        {
            "statement": "The refund amount exceeds the order amount.",
            "comparisons": [
                {
                    "kind": "value",
                    "left": {
                        "source": "argument",
                        "operation": "refund_payment",
                        "argument": "amount",
                    },
                    "op": "gt",
                    "right": {
                        "source": "fact",
                        "path": "TARGET-STATE.orders.ORD-2.amount",
                    },
                }
            ],
            "record_selection": {
                "status": "observed",
                "record_path": "TARGET-STATE.orders.ORD-2",
                "argument_values": [
                    {
                        "operation": "refund_payment",
                        "argument": "amount",
                        "path": "TARGET-STATE.orders.ORD-2",
                    }
                ],
            },
        }
    )
    message = condition_failure_message(outcome)
    assert message is not None
    assert "op gt requires numeric operands" in message
    assert (
        "record_selection.argument_values maps refund_payment.amount to the "
        "record key of TARGET-STATE.orders.ORD-2; list there only the argument "
        "that selects the record, and leave a compared value argument out so "
        "it stays request-dependent"
    ) in message


def test_selector_mapped_bounded_comparison_stays_request_dependent() -> None:
    outcome = _check(
        {
            "statement": "The refund amount exceeds the order amount.",
            "comparisons": [
                {
                    "kind": "value",
                    "left": {
                        "source": "argument",
                        "operation": "refund_payment",
                        "argument": "amount",
                    },
                    "op": "gt",
                    "right": {
                        "source": "fact",
                        "path": "TARGET-STATE.orders.ORD-2.amount",
                    },
                }
            ],
            "record_selection": {
                "status": "observed",
                "record_path": "TARGET-STATE.orders.ORD-2",
                "argument_values": [
                    {
                        "operation": "refund_payment",
                        "argument": "order_id",
                        "path": "TARGET-STATE.orders.ORD-2",
                    }
                ],
            },
        }
    )
    assert outcome.failures == ()
    assert outcome.check is not None
    assert [item.result for item in outcome.check.comparisons] == ["not_checkable"]


# --- item 5: party rules compare supplied state ----------------------------


def test_prior_read_hint_defers_to_supplied_party_fields() -> None:
    family = ConditionFamily(
        kind="prior_read",
        operation="update_gadget",
        argument="gadget_id",
        prior_operation="get_gadget",
        same_argument="gadget_id",
    )
    _, user = _stage5(family)
    assert (
        "Use this order only if the rule is about call sequence; if it is about "
        "who owns or is party to the record and those fields are supplied, "
        "compare them instead."
    ) in user
