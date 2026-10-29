"""A Stage 5 reply names only operations of the target's inventory.

The fixture reproduces a reply shape seen from a guided decoder: the request
schema left a ``not_called`` operation an open string, and in the flat
comparison object the nullable fields of the other branches follow
``operation``. The reply closed the comparison inside the string, so the
operation came back as ``"open_ticket}], "``. A schema enum keeps a guided
reply inside the inventory; the condition check still rejects any name outside
it with the exact correction. The failure call and the observation criteria
name an operation of the same inventory and are closed the same way.
"""

from __future__ import annotations

import copy
import json

import jsonschema
import pytest
import yaml

from asago_scenario_generator.stpa.infra.llm import _json_schema_response_format
from asago_scenario_generator.stpa.scenario_prod.stage5.prior_reply import (
    without_unknown_operations,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.schema import (
    _scenario_semantics_payload_type,
)
from tests.helpers.discriminating_condition import _generate, _payload_with
from tests.stpa.condition_prompt_fixture import (
    TOOLS,
    realistic_observations,
    realistic_profile,
)
from tests.stpa.sp1_helpers import MockLLMClient
from tests.stpa.test_stage5_failure_call_observability import _focal_operation

INVENTORY = sorted(TOOLS)
MALFORMED = "open_ticket}], "
MISSING_TICKET = {"kind": "missing_call", "operation_name": "open_ticket"}
CHECK_FAILED = "discriminating_condition_check_failed"
UNKNOWN_FAILURE_CALL = (
    "failure_call operation_name must name an exact operation from the "
    "supplied inventory, or failure_call must be null"
)
UNKNOWN_CRITERION = (
    "observation criterion operation_name must name an exact operation from "
    "the supplied inventory"
)
# The decoded operation is stripped, so the error names it without the space.
UNKNOWN_OPERATION = (
    f"comparisons[0] names operation {MALFORMED.strip()!r}, which is not in the "
    f"supplied operation inventory (available: {', '.join(INVENTORY)})"
)


def _flat_not_called(operation: str) -> dict:
    """A ``not_called`` comparison in the flat request form, as decoded."""
    return {
        "kind": "not_called",
        "left": None,
        "op": None,
        "right": None,
        "operation": operation,
        "requires_prior": None,
        "same_argument": None,
    }


def _flat_condition(*operations: str) -> dict:
    return {
        "statement": "The required ticket is never opened for the gadget.",
        "comparisons": [_flat_not_called(name) for name in operations],
        "record_selection": {
            "status": "unavailable",
            "record_path": None,
            "argument_values": None,
            "reason": "The failure is a missing call, not a call on a record.",
        },
    }


def _condition(*operations: str) -> dict:
    return {
        "statement": "The required ticket is never opened for the gadget.",
        "comparisons": [
            {"kind": "not_called", "operation": name} for name in operations
        ],
        "record_selection": {
            "status": "unavailable",
            "reason": "The failure is a missing call, not a call on a record.",
        },
    }


def _missing_ticket_payload(condition: dict) -> dict:
    payload = _payload_with(condition)
    outcome = payload["unsafe_outcome"]
    outcome["observation_criteria"] = [
        {
            "criterion_id": "observation_1",
            "outcome": "The open_ticket operation is not called for the gadget.",
            "observable": True,
            "claim_level": "command_attempt",
            "evidence": "tool_call",
            "operation_name": "open_ticket",
            "reason": "The assistant sees the fault but omits the required call.",
        }
    ]
    outcome["safe_observable_outcome"] = {
        "observable": True,
        "statement": "The assistant opens a ticket for the faulty gadget.",
        "claim_level": "command_attempt",
        "evidence": "tool_call",
        "operation_name": "open_ticket",
    }
    outcome["failure_call"] = dict(MISSING_TICKET)
    return payload


def _client(*payloads: dict) -> MockLLMClient:
    client = MockLLMClient()
    client.set_response_queue([copy.deepcopy(item) for item in payloads])
    return client


def _profile_generate(client: MockLLMClient, tmp_path):
    profile = realistic_profile()
    return _generate(
        client,
        tmp_path,
        target_operation=_focal_operation(),
        execution_target_profile=profile,
        target_observations=realistic_observations(profile),
    )


def _sent_schema(client: MockLLMClient, index: int = 0) -> dict:
    """The JSON schema the client sends for one recorded call."""
    response_format = client.calls[index].response_format
    return _json_schema_response_format(response_format)["json_schema"]["schema"]


def _condition_validator(schema: dict) -> jsonschema.Draft202012Validator:
    outcome = schema["properties"]["unsafe_outcome"]
    if "$ref" in outcome:
        outcome = schema["$defs"][outcome["$ref"].rsplit("/", 1)[-1]]
    [condition] = [
        option
        for option in outcome["properties"]["discriminating_condition"]["anyOf"]
        if option != {"type": "null"}
    ]
    return jsonschema.Draft202012Validator(
        {**condition, "$defs": schema.get("$defs", {})}
    )


def _outcome_definition(schema: dict, name: str) -> dict:
    """The definition of one ``unsafe_outcome`` property, nullable or not."""
    outcome = schema["properties"]["unsafe_outcome"]
    if "$ref" in outcome:
        outcome = schema["$defs"][outcome["$ref"].rsplit("/", 1)[-1]]
    field = outcome["properties"][name]
    if field.get("type") == "array":
        field = field["items"]
    [option] = [
        branch for branch in field.get("anyOf", [field]) if branch != {"type": "null"}
    ]
    return schema["$defs"][option["$ref"].rsplit("/", 1)[-1]]


def _validator_of(schema: dict, name: str) -> jsonschema.Draft202012Validator:
    return jsonschema.Draft202012Validator(
        {**_outcome_definition(schema, name), "$defs": schema.get("$defs", {})}
    )


def _shown_reply(prompt: str) -> dict:
    """The prior reply a correction prompt shows, decoded."""
    _, after = prompt.split("Prior structured response to correct in place:\n```json\n")
    shown, _ = after.split("\n```", 1)
    return json.loads(shown)


def _normalizations(tmp_path) -> list[dict]:
    [path] = (tmp_path / "stage5-normalizations").glob("*.yaml")
    return yaml.safe_load(path.read_text(encoding="utf-8"))["normalizations"]


def test_the_sent_schema_rejects_the_recorded_malformed_not_called_operation(
    tmp_path,
) -> None:
    client = _client(_missing_ticket_payload(_condition("open_ticket")))

    _profile_generate(client, tmp_path)

    validator = _condition_validator(_sent_schema(client))
    validator.validate(_flat_condition("open_ticket"))
    with pytest.raises(jsonschema.ValidationError) as caught:
        validator.validate(_flat_condition(MALFORMED))
    # The flat comparison makes ``operation`` nullable: its string branch
    # carries the enum.
    assert caught.value.instance == MALFORMED
    assert [
        (item.validator, item.validator_value)
        for item in caught.value.context
        if item.validator == "enum"
    ] == [("enum", INVENTORY)]


def test_the_sent_schema_rejects_a_malformed_failure_call_and_criterion_operation(
    tmp_path,
) -> None:
    client = _client(_missing_ticket_payload(_condition("open_ticket")))

    _profile_generate(client, tmp_path)

    schema = _sent_schema(client)
    failure_call = _validator_of(schema, "failure_call")
    failure_call.validate(MISSING_TICKET)
    with pytest.raises(jsonschema.ValidationError) as caught:
        failure_call.validate({**MISSING_TICKET, "operation_name": MALFORMED})
    assert (caught.value.validator, caught.value.validator_value) == (
        "enum",
        INVENTORY,
    )
    criterion = _validator_of(schema, "observation_criteria")
    [observed] = _missing_ticket_payload(_condition("open_ticket"))["unsafe_outcome"][
        "observation_criteria"
    ]
    criterion.validate(observed)
    criterion.validate({**observed, "operation_name": None})
    with pytest.raises(jsonschema.ValidationError) as caught:
        criterion.validate({**observed, "operation_name": MALFORMED})
    # ``operation_name`` is nullable: its string branch carries the enum.
    assert [
        (item.validator, item.validator_value)
        for item in caught.value.context
        if item.validator == "enum"
    ] == [("enum", INVENTORY)]


def test_every_operation_field_is_closed_to_the_inventory() -> None:
    operations = ("open_ticket", "update_gadget")
    payload_type = _scenario_semantics_payload_type(
        1,
        observation_criteria_required=True,
        condition_references_supplied=True,
        failure_call_supported=True,
        operations=operations,
    )
    defs = payload_type.model_json_schema()["$defs"]

    closed = {
        (name, field): defs[name]["properties"][field].get("enum")
        for name, field in (
            ("NotCalledComparison", "operation"),
            ("OrderComparison", "operation"),
            ("OrderComparison", "requires_prior"),
            ("ArgumentOperand", "operation"),
            ("ArgumentValueSelection", "operation"),
            ("FailureCall", "operation_name"),
        )
    }
    assert closed == dict.fromkeys(closed, list(operations))
    criterion = defs["_ObservationCriterionDraft"]["properties"]["operation_name"]
    assert criterion["anyOf"] == [
        {"minLength": 1, "type": "string", "enum": list(operations)},
        {"type": "null"},
    ]


def test_the_failure_call_and_criteria_are_closed_without_a_condition() -> None:
    operations = ("open_ticket", "update_gadget")
    defs = _scenario_semantics_payload_type(
        1,
        observation_criteria_required=True,
        failure_call_supported=True,
        operations=operations,
    ).model_json_schema()["$defs"]

    assert "NotCalledComparison" not in defs
    assert defs["FailureCall"]["properties"]["operation_name"]["enum"] == list(
        operations
    )
    criterion = defs["_ObservationCriterionDraft"]["properties"]["operation_name"]
    assert criterion["anyOf"][0]["enum"] == list(operations)


def test_a_reply_parse_still_accepts_any_operation_for_the_exact_check() -> None:
    payload_type = _scenario_semantics_payload_type(
        1,
        observation_criteria_required=True,
        condition_references_supplied=True,
        failure_call_supported=True,
        operations=("open_ticket",),
    )
    payload = _missing_ticket_payload(_condition(MALFORMED))
    payload["unsafe_outcome"]["failure_call"]["operation_name"] = MALFORMED
    payload["unsafe_outcome"]["observation_criteria"][0]["operation_name"] = MALFORMED
    payload["causal_factors"] = payload["causal_factors"][:1]
    payload["causal_factors"][0]["source_handle"] = "cause_1"
    for intention in payload["attacker_bdi"]["intentions"]:
        intention["source_handles"] = ["cause_1"]

    draft = payload_type.model_validate(payload)

    [comparison] = draft.unsafe_outcome.discriminating_condition.comparisons
    assert comparison.operation == MALFORMED.strip()
    assert draft.unsafe_outcome.failure_call.operation_name == MALFORMED.strip()
    [criterion] = draft.unsafe_outcome.observation_criteria
    assert criterion.operation_name == MALFORMED
    # A correction shows the parsed reply without the refused names.
    shown = without_unknown_operations(draft, ("open_ticket",))["unsafe_outcome"]
    [comparison] = shown["discriminating_condition"]["comparisons"]
    assert comparison["operation"] is None
    assert shown["failure_call"]["operation_name"] is None
    assert shown["observation_criteria"][0]["operation_name"] is None
    assert (
        comparison is not draft.unsafe_outcome.discriminating_condition.comparisons[0]
    )
    assert draft.unsafe_outcome.failure_call.operation_name == MALFORMED.strip()


def test_without_operations_the_schema_is_unchanged() -> None:
    options = {
        "observation_criteria_required": True,
        "condition_references_supplied": True,
        "failure_call_supported": True,
    }
    plain = _scenario_semantics_payload_type(1, **options).model_json_schema()

    assert (
        _scenario_semantics_payload_type(
            1, **options, operations=()
        ).model_json_schema()
        == plain
    )
    assert (
        "enum" not in plain["$defs"]["NotCalledComparison"]["properties"]["operation"]
    )
    assert "enum" not in plain["$defs"]["FailureCall"]["properties"]["operation_name"]


def test_a_malformed_operation_is_corrected_with_the_exact_inventory_error(
    tmp_path,
) -> None:
    client = _client(
        _missing_ticket_payload(_condition(MALFORMED)),
        _missing_ticket_payload(_condition("open_ticket")),
    )

    result, error = _profile_generate(client, tmp_path)

    assert error is None
    assert client.call_count == 2
    correction = client.calls[1].user_prompt
    assert f"{CHECK_FAILED}:" in correction
    assert UNKNOWN_OPERATION in correction
    # The prior reply is shown with the refused name replaced by null, so the
    # correction cannot copy it; the exact error above still names it.
    shown = _shown_reply(correction)
    [comparison] = shown["unsafe_outcome"]["discriminating_condition"]["comparisons"]
    assert comparison == {"kind": "not_called", "operation": None}
    expected = _missing_ticket_payload(_condition("open_ticket"))
    expected["unsafe_outcome"]["discriminating_condition"]["comparisons"][0][
        "operation"
    ] = None
    assert shown == expected
    # The correction is sent with the same closed schema.
    assert _sent_schema(client, 1) == _sent_schema(client, 0)
    assert result.discriminating_condition is not None
    [comparison] = result.discriminating_condition.comparisons
    assert comparison.operation == "open_ticket"


def test_a_malformed_operation_the_corrections_keep_is_a_recorded_failure(
    tmp_path,
) -> None:
    # The recorded corrections kept the malformed comparison and appended a
    # well-formed one; code neither strips the bad comparison nor keeps it.
    first = _missing_ticket_payload(_condition(MALFORMED))
    kept = _missing_ticket_payload(_condition(MALFORMED, "open_ticket"))
    client = _client(first, kept, kept)

    result, error = _profile_generate(client, tmp_path)

    assert error is None
    assert client.call_count == 3
    # Both corrections show the prior reply without the refused name.
    for call in client.calls[1:]:
        shown = _shown_reply(call.user_prompt)
        comparisons = shown["unsafe_outcome"]["discriminating_condition"]["comparisons"]
        assert MALFORMED not in json.dumps(shown)
        assert comparisons[0] == {"kind": "not_called", "operation": None}
    assert _shown_reply(client.calls[2].user_prompt)["unsafe_outcome"][
        "discriminating_condition"
    ]["comparisons"][1] == {"kind": "not_called", "operation": "open_ticket"}
    assert result.discriminating_condition is None
    assert result.condition_omitted_reason.startswith(
        "The discriminating condition failed validation after two corrections "
        f"({CHECK_FAILED});"
    )
    [removal, *_] = _normalizations(tmp_path)
    assert removal["field"] == "discriminating_condition"
    assert removal["normalized"] is None
    assert removal["reason"] == f"condition_dropped_failure_call:{CHECK_FAILED}"
    assert [item["operation"] for item in removal["original"]["comparisons"]] == [
        MALFORMED,
        "open_ticket",
    ]


@pytest.mark.parametrize(
    ("field", "error"),
    [("failure_call", UNKNOWN_FAILURE_CALL), ("criterion", UNKNOWN_CRITERION)],
)
def test_a_malformed_outcome_operation_is_corrected_with_the_exact_error(
    tmp_path, field: str, error: str
) -> None:
    malformed = _missing_ticket_payload(_condition("open_ticket"))
    outcome = malformed["unsafe_outcome"]
    if field == "failure_call":
        outcome["failure_call"]["operation_name"] = MALFORMED
    else:
        outcome["observation_criteria"][0]["operation_name"] = MALFORMED
    client = _client(malformed, _missing_ticket_payload(_condition("open_ticket")))

    result, failure = _profile_generate(client, tmp_path)

    assert failure is None
    assert client.call_count == 2
    assert error in client.calls[1].user_prompt
    shown = _shown_reply(client.calls[1].user_prompt)["unsafe_outcome"]
    if field == "failure_call":
        assert shown["failure_call"] == {"kind": "missing_call", "operation_name": None}
    else:
        assert shown["observation_criteria"][0]["operation_name"] is None
    assert _sent_schema(client, 1) == _sent_schema(client, 0)
    assert result.discriminating_condition is not None


def test_a_reply_inside_the_inventory_is_shown_as_it_came(tmp_path) -> None:
    # A semantic condition failure: every name is in the inventory.
    wrong = _missing_ticket_payload(_condition("open_ticket"))
    wrong["unsafe_outcome"]["discriminating_condition"]["comparisons"] = [
        {"kind": "order", "operation": "open_ticket", "requires_prior": "open_ticket"}
    ]
    client = _client(wrong, _missing_ticket_payload(_condition("open_ticket")))

    _profile_generate(client, tmp_path)

    assert client.call_count == 2
    assert (
        "Prior structured response to correct in place:\n```json\n"
        f"{json.dumps(wrong)}\n```"
    ) in client.calls[1].user_prompt


def test_the_shown_reply_nulls_each_name_outside_the_inventory() -> None:
    def operand(operation):
        return {
            "source": "argument",
            "operation": operation,
            "argument": "gadget_id",
            "path": None,
            "value": None,
        }

    reply = {
        "unsafe_outcome": {
            "discriminating_condition": {
                "comparisons": [
                    {
                        "kind": "value",
                        "left": operand("update_gadget"),
                        "op": "ne",
                        "right": operand("update_gadget}],"),
                        "operation": None,
                        "requires_prior": None,
                    },
                    {
                        "kind": "order",
                        "operation": "update_gadget",
                        "requires_prior": " get_gadget",
                    },
                    {"kind": "order", "operation": "x", "requires_prior": "y"},
                ],
                "record_selection": {
                    "status": "observed",
                    "argument_values": [
                        {"operation": "open_ticket", "argument": "a"},
                        {"operation": 'open_ticket"}', "argument": "a"},
                    ],
                },
            },
            "failure_call": {"kind": "incorrect_call", "operation_name": "nope"},
            "observation_criteria": [
                {"criterion_id": "c1", "operation_name": None},
                {"criterion_id": "c2", "operation_name": "get_gadget"},
                {"criterion_id": "c3", "operation_name": "get_gadget},"},
            ],
            "safe_observable_outcome": {"operation_name": "unchecked"},
        }
    }

    shown = without_unknown_operations(json.dumps(reply), INVENTORY)

    outcome = shown["unsafe_outcome"]
    first, second, third = outcome["discriminating_condition"]["comparisons"]
    assert first["left"]["operation"] == "update_gadget"
    assert first["right"]["operation"] is None
    # A name the check accepts once stripped is kept as written.
    assert second["requires_prior"] == " get_gadget"
    assert (third["operation"], third["requires_prior"]) == (None, None)
    values = outcome["discriminating_condition"]["record_selection"]["argument_values"]
    assert [item["operation"] for item in values] == ["open_ticket", None]
    assert outcome["failure_call"]["operation_name"] is None
    assert [item["operation_name"] for item in outcome["observation_criteria"]] == [
        None,
        "get_gadget",
        None,
    ]
    assert outcome["safe_observable_outcome"] == {"operation_name": "unchecked"}
    # The reply itself is left unchanged.
    assert reply["unsafe_outcome"]["failure_call"]["operation_name"] == "nope"


@pytest.mark.parametrize(
    "content",
    [
        {"unsafe_outcome": {"failure_call": {"operation_name": "open_ticket"}}},
        '{"unsafe_outcome": {"failure_call": {"operation_name": "open_ticket"}}}',
        "not json",
        ["unsafe_outcome"],
        None,
    ],
)
def test_a_reply_with_nothing_to_null_is_returned_as_it_came(content) -> None:
    assert without_unknown_operations(content, INVENTORY) is content
