"""A Stage 5 condition names only operations of the target's inventory.

The fixture reproduces a reply shape seen from a guided decoder: the request
schema left a ``not_called`` operation an open string, and in the flat
comparison object the nullable fields of the other branches follow
``operation``. The reply closed the comparison inside the string, so the
operation came back as ``"open_ticket}], "``. A schema enum keeps a guided
reply inside the inventory; the condition check still rejects any name outside
it with the exact correction.
"""

from __future__ import annotations

import copy

import jsonschema
import pytest
import yaml

from asago_scenario_generator.stpa.infra.llm import _json_schema_response_format
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
    outcome["failure_call"] = MISSING_TICKET
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


def test_every_condition_operation_field_is_closed_to_the_inventory() -> None:
    operations = ("open_ticket", "update_gadget")
    payload_type = _scenario_semantics_payload_type(
        1,
        observation_criteria_required=True,
        condition_references_supplied=True,
        failure_call_supported=True,
        condition_operations=operations,
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
        )
    }
    assert closed == dict.fromkeys(closed, list(operations))


def test_a_reply_parse_still_accepts_any_operation_for_the_exact_check() -> None:
    payload_type = _scenario_semantics_payload_type(
        1,
        observation_criteria_required=True,
        condition_references_supplied=True,
        failure_call_supported=True,
        condition_operations=("open_ticket",),
    )
    payload = _missing_ticket_payload(_condition(MALFORMED))
    payload["causal_factors"] = payload["causal_factors"][:1]
    payload["causal_factors"][0]["source_handle"] = "cause_1"
    for intention in payload["attacker_bdi"]["intentions"]:
        intention["source_handles"] = ["cause_1"]

    draft = payload_type.model_validate(payload)

    [comparison] = draft.unsafe_outcome.discriminating_condition.comparisons
    assert comparison.operation == MALFORMED.strip()


def test_without_operations_the_condition_schema_is_unchanged() -> None:
    options = {
        "observation_criteria_required": True,
        "condition_references_supplied": True,
        "failure_call_supported": True,
    }
    plain = _scenario_semantics_payload_type(1, **options).model_json_schema()

    assert (
        _scenario_semantics_payload_type(
            1, **options, condition_operations=()
        ).model_json_schema()
        == plain
    )
    assert (
        "enum" not in plain["$defs"]["NotCalledComparison"]["properties"]["operation"]
    )


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
