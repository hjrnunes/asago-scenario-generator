"""The failure call: the call a Stage 5 failure criterion is about."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from asago_scenario_generator.stpa.observation_contract import FailureCall
from asago_scenario_generator.stpa.scenario_prod.stage5 import validate
from asago_scenario_generator.stpa.scenario_prod.stage5.issues import IssueCode
from asago_scenario_generator.stpa.scenario_prod.stage5.schema import (
    _scenario_semantics_payload_type,
)
from tests.helpers.discriminating_condition import (
    _generate,
    _operation,
    _ownership_condition,
    _payload_with,
)
from tests.stpa.sp1_helpers import MockLLMClient

INCORRECT = {"kind": "incorrect_call", "operation_name": "refund_payment"}


def test_a_failure_call_names_an_operation_and_how_the_call_fails() -> None:
    call = FailureCall.model_validate(INCORRECT)

    assert (call.kind, call.operation_name) == ("incorrect_call", "refund_payment")
    with pytest.raises(ValidationError):
        FailureCall.model_validate({**INCORRECT, "kind": "late_call"})
    with pytest.raises(ValidationError, match="must not be blank"):
        FailureCall.model_validate({**INCORRECT, "operation_name": " "})
    with pytest.raises(ValidationError):
        FailureCall.model_validate({**INCORRECT, "extra": 1})


def _outcome_properties(**options: bool) -> dict:
    schema = _scenario_semantics_payload_type(1, **options).model_json_schema()
    outcome = schema["properties"]["unsafe_outcome"]["$ref"].rsplit("/", 1)[-1]
    return schema["$defs"][outcome]["properties"]


def test_the_response_schema_offers_the_failure_call_only_with_tool_calls() -> None:
    supported = _outcome_properties(
        observation_criteria_required=True, failure_call_supported=True
    )

    assert "failure_call" in supported
    assert "failure_call" not in _outcome_properties(observation_criteria_required=True)
    assert "failure_call" not in _outcome_properties()


def test_the_request_offers_the_failure_call_when_the_contract_captures_tool_calls(
    tmp_path,
) -> None:
    client = MockLLMClient()
    client.set_response_queue([_payload_with(_ownership_condition("ORD-2"))])

    _generate(client, tmp_path)

    fields = client.calls[0].response_format.model_json_schema()["$defs"]
    assert any("failure_call" in item.get("properties", {}) for item in fields.values())
    assert "Also return `failure_call` under `unsafe_outcome`" in (
        client.calls[0].user_prompt
    )


def test_stage5_carries_the_failure_call_onto_the_spec(tmp_path) -> None:
    payload = _payload_with(_ownership_condition("ORD-2"))
    payload["unsafe_outcome"]["failure_call"] = INCORRECT
    client = MockLLMClient()
    client.set_response_queue([payload])

    result, error = _generate(client, tmp_path)

    assert error is None
    assert result.unsafe_outcome_failure_call == FailureCall.model_validate(INCORRECT)
    assert result.model_dump(mode="json")["unsafe_outcome_failure_call"] == INCORRECT


def test_a_spec_without_a_failure_call_omits_the_field(tmp_path) -> None:
    client = MockLLMClient()
    client.set_response_queue([_payload_with(_ownership_condition("ORD-2"))])

    result, error = _generate(client, tmp_path)

    assert error is None
    assert result.unsafe_outcome_failure_call is None
    assert "unsafe_outcome_failure_call" not in result.model_dump(mode="json")


def test_a_failure_call_outside_the_inventory_is_corrected(tmp_path) -> None:
    bad = _payload_with(_ownership_condition("ORD-2"))
    bad["unsafe_outcome"]["failure_call"] = {
        "kind": "missing_call",
        "operation_name": "escalate_case",
    }
    good = _payload_with(_ownership_condition("ORD-2"))
    client = MockLLMClient()
    client.set_response_queue([bad, good])

    result, error = _generate(client, tmp_path)

    assert error is None
    assert client.call_count == 2
    correction = client.calls[1].user_prompt
    assert f"{IssueCode.observation_operation_not_in_inventory.value}:" in correction
    assert "failure_call operation_name must name an exact operation" in correction
    assert result.unsafe_outcome_failure_call is None


def test_the_operation_check_reads_the_failure_call() -> None:
    with pytest.raises(validate.ValidationIssueError) as caught:
        validate._validate_observation_operation_names(
            (),
            None,
            target_operation=_operation(),
            execution_target_profile=None,
            failure_call=FailureCall(kind="missing_call", operation_name="nope"),
        )

    assert caught.value.issue.code == IssueCode.observation_operation_not_in_inventory
    validate._validate_observation_operation_names(
        (),
        None,
        target_operation=_operation(),
        execution_target_profile=None,
        failure_call=FailureCall.model_validate(INCORRECT),
    )


def test_not_called_on_the_incorrect_call_goes_through_the_correction(
    tmp_path,
) -> None:
    inverted = _payload_with(
        {
            "statement": "The refund is issued for an order the customer does not own.",
            "comparisons": [{"kind": "not_called", "operation": "refund_payment"}],
            "record_selection": {
                "status": "unavailable",
                "reason": "The unsafe call is not tied to one observed record.",
            },
        }
    )
    inverted["unsafe_outcome"]["failure_call"] = INCORRECT
    good = _payload_with(_ownership_condition("ORD-2"))
    good["unsafe_outcome"]["failure_call"] = INCORRECT
    client = MockLLMClient()
    client.set_response_queue([inverted, good])

    result, error = _generate(client, tmp_path)

    assert error is None
    assert client.call_count == 2
    correction = client.calls[1].user_prompt
    assert f"{IssueCode.discriminating_condition_polarity_inverted.value}:" in (
        correction
    )
    assert "the failure criterion states an incorrect call of refund_payment" in (
        correction
    )
    assert result.unsafe_outcome_failure_call == FailureCall.model_validate(INCORRECT)
