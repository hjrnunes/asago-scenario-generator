"""A map reply naming an operation outside the offered list earns one correction.

The correction covers this failure only.  A schema or parser failure of the
map reply, and a valid reply, behave as before.  The fixture is the recorded
CA-3-3 reply of the L1 occiai-r1 rerun (request 79 of the b8-glm batch), whose
``selected_operation.resource_id`` carries JSON punctuation.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from asago_scenario_generator.models.target_realization import (
    TargetRealizationDisposition,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.target_realization import (
    TargetRealizationLlmInterpreter,
)
from asago_scenario_generator.stpa.target_realization.provider import (
    PROMPTS_DIR,
    TargetRealizationDraft,
    _yaml,
)
from tests.helpers.calls_log import read_calls_jsonl
from tests.stpa.sp1_helpers import MockLLMClient

_FIXTURE = json.loads(
    (
        Path(__file__).resolve().parents[1]
        / "fixtures"
        / "unit_loss"
        / "l1-occiai-r1-unoffered-operation.json"
    ).read_text(encoding="utf-8")
)
_ASK = {"resource_id": "mcp:mini:ask", "operation_id": "ask"}
_SEND = {"resource_id": "mcp:mini:send", "operation_id": "send"}
_GARBLED = {"resource_id": "mcp:mini:ask},", "operation_id": "ask"}
_ACTION = {
    "control_action_id": "CA-1-1",
    "controller_id": "RESP-1",
    "description": "Answer the question.",
    "effect_kind": "agent_message",
    "temporality": "discrete",
}
_OPERATIONS = tuple(
    {**operation, "description": "An operation.", "argument_names": []}
    for operation in (_ASK, _SEND)
)
_CORRECTION_MARKER = "Exact validation error from the prior response:"


def _reply(selected=None, candidates=(), disposition="supported") -> dict:
    reply = {
        "control_action_id": "CA-1-1",
        "disposition": disposition,
        "candidate_operations": list(candidates),
        "evidence_refs": [],
        "rationale": "Reply.",
    }
    if selected is not None:
        reply["selected_operation"] = selected
    return reply


def _verified() -> dict:
    return {
        "decision": "verified",
        "detail": "The operation realizes the action.",
        "effect_match": "exact",
        "recipient_match": "exact",
        "completion_match": "established",
    }


def _run(tmp_path, replies, action=_ACTION, operations=_OPERATIONS):
    client = MockLLMClient()
    client.set_response_queue(list(replies))
    adapter = TargetRealizationLlmInterpreter(client, tmp_path, temperature=0.4)
    return client, adapter, lambda: adapter(action=action, operations=operations)


def _map_calls(client):
    return [
        call for call in client.calls if call.response_format is TargetRealizationDraft
    ]


@pytest.mark.parametrize(
    "first",
    (
        _reply(selected=_GARBLED),
        _reply(selected=_ASK, candidates=[_ASK, _GARBLED]),
        _reply(candidates=[_GARBLED], disposition="ambiguous"),
        _reply(selected=_ASK, candidates=[_ASK, {**_ASK, "operation_id": "send"}]),
    ),
    ids=["selected", "candidate", "candidate-without-selection", "mixed-pair"],
)
def test_unoffered_identity_is_corrected_with_one_more_request(tmp_path, first):
    corrected = _reply(candidates=[_ASK, _SEND], disposition="ambiguous")
    client, _adapter, call = _run(tmp_path, [first, corrected])

    response = call()

    assert len(client.calls) == 2
    assert response.disposition is TargetRealizationDisposition.ambiguous
    assert [item.identity for item in response.candidate_operations] == [
        (_ASK["resource_id"], _ASK["operation_id"]),
        (_SEND["resource_id"], _SEND["operation_id"]),
    ]


def test_corrected_supported_reply_continues_to_verification(tmp_path):
    client, _adapter, call = _run(
        tmp_path,
        [_reply(selected=_GARBLED), _reply(selected=_ASK), _verified()],
    )

    response = call()

    assert len(_map_calls(client)) == 2
    assert len(client.calls) == 3
    assert response.selected_operation is not None
    assert response.selected_operation.identity == ("mcp:mini:ask", "ask")
    assert response.verifier is not None and response.verifier.status == "verified"


def test_correction_request_separates_instruction_prior_reply_and_identities(tmp_path):
    client, adapter, call = _run(
        tmp_path,
        [_reply(selected=_GARBLED), _reply(candidates=[], disposition="unmapped")],
    )

    call()

    first, second = client.calls
    original = first.user_prompt
    assert second.user_prompt.startswith(original)
    assert second.system_prompt == first.system_prompt
    suffix = second.user_prompt[len(original) :]
    instruction = TemplateLoader(PROMPTS_DIR).render_prompt(
        "realize_inventory_correction.j2"
    )
    assert suffix.startswith("\n\n" + instruction)
    before_error, error = suffix.split(_CORRECTION_MARKER)
    assert "mcp:mini:ask}," not in instruction
    assert "mcp:mini:ask}," in before_error
    assert "Prior structured response to correct in place:" in before_error
    assert json.dumps("mcp:mini:ask},") in error
    assert json.dumps("ask") in error
    assert "ValidationError" not in error
    assert "Expected response schema" not in suffix
    assert second.response_format is first.response_format
    assert second.temperature == first.temperature
    assert second.max_completion_tokens == first.max_completion_tokens


def test_correction_names_every_offending_identity_once(tmp_path):
    other = {"resource_id": "mcp:mini:gone", "operation_id": "gone"}
    client, _adapter, call = _run(
        tmp_path,
        [
            _reply(selected=_GARBLED, candidates=[_GARBLED, other]),
            _reply(disposition="unmapped"),
        ],
    )

    call()

    error = client.calls[1].user_prompt.split(_CORRECTION_MARKER)[1]
    assert error.count(json.dumps("mcp:mini:ask},")) == 2
    assert error.count(json.dumps("mcp:mini:gone")) == 1
    assert "selected_operation" in error
    assert "candidate_operations" in error


def test_correction_attempts_are_logged_in_order(tmp_path):
    _client, _adapter, call = _run(
        tmp_path,
        [_reply(selected=_GARBLED), _reply(disposition="unmapped")],
    )

    call()

    entries = read_calls_jsonl(tmp_path)
    assert [entry["step"] for entry in entries] == [
        "target_realization:map_control_action"
    ] * 2
    assert [entry["attempt_number"] for entry in entries] == [1, 2]
    assert [entry["success"] for entry in entries] == [False, True]
    assert entries[0]["failure_class"] == "answered_semantic_failure"


def test_second_unoffered_reply_ends_the_unit_and_says_it_was_corrected(tmp_path):
    client, _adapter, call = _run(
        tmp_path,
        [_reply(selected=_GARBLED), _reply(selected=_GARBLED)],
    )

    with pytest.raises(ValueError, match="after one correction") as raised:
        call()

    assert len(client.calls) == 2
    assert json.dumps("mcp:mini:ask},") in str(raised.value)


def test_corrected_reply_failing_otherwise_ends_the_unit_with_the_correction_named(
    tmp_path,
):
    client, _adapter, call = _run(
        tmp_path,
        [_reply(selected=_GARBLED), {"control_action_id": "CA-1-1"}],
    )

    with pytest.raises(ValueError, match="after one correction"):
        call()

    assert len(client.calls) == 2


@pytest.mark.parametrize(
    "first",
    (
        {"control_action_id": "CA-1-1", "disposition": "maybe"},
        "THIS IS NOT JSON{{{",
    ),
    ids=["schema", "parser"],
)
def test_other_map_failures_get_no_correction(tmp_path, first):
    client, _adapter, call = _run(tmp_path, [first])

    with pytest.raises(
        ValueError, match="target realization provider failed"
    ) as raised:
        call()

    assert "correction" not in str(raised.value)
    assert len(client.calls) == 1


def test_valid_reply_sends_one_request_with_unchanged_bytes(tmp_path):
    client, adapter, call = _run(tmp_path, [_reply(selected=_ASK), _verified()])

    response = call()

    assert response.selected_operation is not None
    assert len(client.calls) == 2
    loader = TemplateLoader(PROMPTS_DIR)
    assert client.calls[0].system_prompt == loader.render_prompt("realize_system.j2")
    assert client.calls[0].user_prompt == loader.render_prompt(
        "realize_user.j2",
        action_yaml=_yaml(_ACTION),
        operations_yaml=_yaml(_OPERATIONS),
    )
    assert _CORRECTION_MARKER not in client.calls[0].user_prompt


def test_recorded_reply_with_punctuated_resource_id_is_corrected_once(tmp_path):
    action = {**_ACTION, "control_action_id": _FIXTURE["control_action_id"]}
    operations = tuple(
        {**operation, "description": "An operation.", "argument_names": []}
        for operation in _FIXTURE["offered_operations"]
    )
    ask = _FIXTURE["offered_operations"][0]
    corrected = {
        "control_action_id": _FIXTURE["control_action_id"],
        "disposition": "supported",
        "selected_operation": ask,
        "evidence_refs": [],
        "rationale": "The offered operation answers and refuses.",
    }
    client, _adapter, call = _run(
        tmp_path,
        [_FIXTURE["reply_content"], corrected, _verified()],
        action=action,
        operations=operations,
    )

    response = call()

    assert len(_map_calls(client)) == 2
    assert response.selected_operation is not None
    assert response.selected_operation.identity == (
        ask["resource_id"],
        ask["operation_id"],
    )
    error = client.calls[1].user_prompt.split(_CORRECTION_MARKER)[1]
    assert json.dumps("mcp:miniocciai:ask_clinical_question},") in error
    assert json.dumps("ask_clinical_question") in error
    assert _FIXTURE["reply_content"] in client.calls[1].user_prompt
