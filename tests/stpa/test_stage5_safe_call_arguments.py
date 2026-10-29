"""The safe outcome's optional call arguments: shape, Stage 5 checks, publication."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from asago_scenario_generator.stpa.observation_contract import (
    SafeObservableOutcome,
    default_observation_contract,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.generate import (
    generate_bdi_for_context,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.validate import (
    _analytical_only_safe_outcome,
)
from tests.helpers.normal_authoring_wire import (
    _target_operation,
    _wrong_timing_assembly,
    _wrong_timing_context,
)
from tests.helpers.stage5_safe_outcome import (
    _command_attempt_payload,
    _nested_observations,
)
from tests.stpa.sp1_helpers import MockLLMClient

CODE = "safe_outcome_call_argument_not_supplied"
COMMAND = {
    "observable": True,
    "statement": "The assistant refunds the order the customer owns.",
    "claim_level": "command_attempt",
    "evidence": "tool_call",
    "operation_name": "refund_payment",
}


def _outcome(**changes: object) -> SafeObservableOutcome:
    return SafeObservableOutcome.model_validate({**COMMAND, **changes})


def test_call_arguments_are_typed_scalars_named_once() -> None:
    outcome = _outcome(
        call_arguments=[
            {"argument": "order_id", "value": "ORD-104"},
            {"argument": "amount", "value": 12.5},
            {"argument": "notify", "value": True},
        ]
    )

    assert [(item.argument, item.value) for item in outcome.call_arguments] == [
        ("order_id", "ORD-104"),
        ("amount", 12.5),
        ("notify", True),
    ]
    with pytest.raises(ValidationError, match="each argument once"):
        _outcome(
            call_arguments=[
                {"argument": "order_id", "value": "ORD-104"},
                {"argument": "order_id", "value": "ORD-105"},
            ]
        )
    for value in (None, ["ORD-104"], {"id": "ORD-104"}):
        with pytest.raises(ValidationError):
            _outcome(call_arguments=[{"argument": "order_id", "value": value}])
    with pytest.raises(ValidationError, match="must not be blank"):
        _outcome(call_arguments=[{"argument": " ", "value": "ORD-104"}])


def test_call_arguments_need_a_command_attempt_on_an_operation() -> None:
    arguments = [{"argument": "order_id", "value": "ORD-104"}]

    with pytest.raises(ValidationError, match="require claim_level command_attempt"):
        SafeObservableOutcome.model_validate(
            {
                "observable": True,
                "statement": "The assistant replies with the refund policy.",
                "claim_level": "reply",
                "evidence": "assistant_message",
                "call_arguments": arguments,
            }
        )
    with pytest.raises(ValidationError, match="analytical-only"):
        SafeObservableOutcome.model_validate(
            {
                "observable": False,
                "statement": "No capture shows the refund.",
                "call_arguments": arguments,
            }
        )


def test_absent_or_empty_call_arguments_leave_the_dump_unchanged() -> None:
    plain = _outcome()

    assert _outcome(call_arguments=[]) == plain
    assert _outcome(call_arguments=None) == plain
    assert "call_arguments" not in plain.model_dump(mode="json")


def test_analytical_only_clears_the_call_arguments() -> None:
    outcome = _outcome(call_arguments=[{"argument": "order_id", "value": "ORD-104"}])
    normalizations: list = []

    cleared = _analytical_only_safe_outcome(outcome, normalizations)

    assert cleared.call_arguments is None
    changed = {item.field: item for item in normalizations}
    assert changed["safe_observable_outcome.call_arguments"].normalized is None


def _generate(tmp_path, *payloads):
    client = MockLLMClient()
    client.set_response_queue(list(payloads))
    context = _wrong_timing_context()
    result = generate_bdi_for_context(
        client,
        context,
        tmp_path,
        observation_contract=default_observation_contract(),
        assembly=_wrong_timing_assembly(context),
        target_operation=_target_operation(),
        target_observations=_nested_observations(),
    )
    return client, result


def _payload(arguments: list[dict] | None) -> dict:
    payload = _command_attempt_payload(["TARGET-STATE"], [])
    if arguments is not None:
        payload["unsafe_outcome"]["safe_observable_outcome"]["call_arguments"] = (
            arguments
        )
    return payload


def test_stage5_publishes_supplied_call_arguments(tmp_path) -> None:
    arguments = [
        {"argument": "order_id", "value": "ORD-104"},
        {"argument": "amount", "value": 20},
    ]

    client, (result, error) = _generate(tmp_path, _payload(arguments))

    assert error is None
    assert len(client.calls) == 1
    dumped = result.model_dump(mode="json")["safe_observable_outcome"]
    assert dumped["call_arguments"] == arguments


def test_a_spec_without_call_arguments_omits_the_field(tmp_path) -> None:
    client, (result, error) = _generate(tmp_path, _payload(None))

    assert error is None
    assert result.safe_observable_outcome.call_arguments is None
    assert (
        "call_arguments"
        not in result.model_dump(mode="json")["safe_observable_outcome"]
    )


@pytest.mark.parametrize(
    ("argument", "problem"),
    [
        (
            {"argument": "customer_id", "value": "ORD-104"},
            "'customer_id' is not a parameter of refund_payment "
            "(parameters: amount, order_id)",
        ),
        (
            {"argument": "amount", "value": "20"},
            "'amount' value '20' does not have the declared type number",
        ),
        (
            {"argument": "order_id", "value": 104},
            "'order_id' value 104 does not have the declared type string",
        ),
        (
            {"argument": "order_id", "value": "ORD-999"},
            "'order_id' value 'ORD-999' is not a value the request supplies",
        ),
    ],
)
def test_an_unsupplied_call_argument_goes_through_the_correction(
    tmp_path, argument, problem
) -> None:
    bad = _payload([argument])
    good = _payload([{"argument": "order_id", "value": "ORD-104"}])

    client, (result, error) = _generate(tmp_path, bad, good)

    assert error is None
    assert len(client.calls) == 2
    retry_prompt = client.calls[1].user_prompt
    assert f"- {CODE}:" in retry_prompt
    assert problem in retry_prompt
    assert "set call_arguments to null when the safe behavior is that the call" in (
        " ".join(retry_prompt.split())
    )
    assert [item.value for item in result.safe_observable_outcome.call_arguments] == [
        "ORD-104"
    ]
