"""A command attempt whose condition fails twice earns a second correction."""

from __future__ import annotations

import copy
import json

import pytest
import yaml

from tests.helpers.calls_log import read_calls_jsonl
from tests.helpers.discriminating_condition import (
    _placeholder_payload,
    _generate,
    _ownership_condition,
    _payload_with,
)
from tests.stpa.sp1_helpers import MockLLMClient

CHECK_FAILED = "discriminating_condition_check_failed"
LITERAL_UNSUPPORTED = "discriminating_condition_literal_unsupported"
PRIOR_BLOCK = "Prior structured response to correct in place:\n```json\n"
ERROR_BLOCK = "\n\nExact validation error from the prior response:\n"

REPLY_CRITERION = {
    "criterion_id": "said",
    "outcome": "The assistant tells the customer the refund went through.",
    "observable": True,
    "claim_level": "reply",
    "evidence": "assistant_message",
    "reason": "The runtime captures assistant messages.",
}


class LengthFinishReasonError(Exception):
    """Stands in for the SDK's structured-output length error by name."""


def _failing_check() -> dict:
    """A command attempt whose condition fails with ``CHECK_FAILED``."""
    return _payload_with(_ownership_condition("ORD-1"))


def _failing_literal() -> dict:
    """A command attempt whose condition fails with ``LITERAL_UNSUPPORTED``."""
    return _placeholder_payload()


def _passing() -> dict:
    return _payload_with(_ownership_condition("ORD-2"))


def _client(*replies) -> MockLLMClient:
    client = MockLLMClient()
    client.set_response_queue([copy.deepcopy(reply) for reply in replies])
    return client


def _section(prompt: str, head: str, tail: str) -> str:
    start = prompt.index(head) + len(head)
    return prompt[start : prompt.index(tail, start)]


def _attempts(run_dir) -> list[int]:
    return [
        entry["attempt_number"]
        for entry in read_calls_jsonl(run_dir)
        if entry.get("stage") == "stage_5" and entry.get("step") == "bdi_generation"
    ]


def _normalizations(run_dir) -> list[dict]:
    [path] = (run_dir / "stage5-normalizations").glob("*.yaml")
    return yaml.safe_load(path.read_text(encoding="utf-8"))["normalizations"]


def _note_code(result) -> str:
    note = result.condition_omitted_reason
    return note[note.index("(") + 1 : note.index(")")]


def test_a_condition_that_fails_twice_on_a_command_attempt_sends_a_third_request(
    tmp_path,
) -> None:
    client = _client(_failing_check(), _failing_literal(), _passing())

    result, error = _generate(client, tmp_path)

    assert error is None
    assert result is not None
    assert client.call_count == 3
    assert _attempts(tmp_path) == [1, 2, 3]


def test_a_passing_third_reply_publishes_with_its_condition(tmp_path) -> None:
    client = _client(_failing_check(), _failing_literal(), _passing())

    result, error = _generate(client, tmp_path)

    assert error is None
    assert result is not None
    assert result.discriminating_condition is not None
    assert result.condition_omitted_reason is None
    assert result.safe_observable_outcome.claim_level == "command_attempt"
    assert result.observation_assessment.disposition == "executable"
    assert not (tmp_path / "stage5-normalizations").exists()


def test_the_third_request_is_what_a_second_validation_retry_would_send(
    tmp_path,
) -> None:
    client = _client(_failing_check(), _failing_check(), _failing_check())

    _generate(client, tmp_path)

    second, third = client.calls[1], client.calls[2]
    assert third.user_prompt == second.user_prompt
    assert third.system_prompt == second.system_prompt
    assert third.temperature == second.temperature
    assert third.max_completion_tokens == second.max_completion_tokens


def test_the_third_request_carries_the_second_reply_and_the_second_failure(
    tmp_path,
) -> None:
    first, second = _failing_check(), _failing_literal()
    client = _client(first, second, _failing_check())

    _generate(client, tmp_path)

    original = client.calls[0].user_prompt
    third = client.calls[2].user_prompt
    assert third.startswith(original)
    assert third.count(PRIOR_BLOCK) == 1
    prior = json.loads(_section(third, PRIOR_BLOCK, "\n```"))
    sent = prior["unsafe_outcome"]["discriminating_condition"]["comparisons"]
    assert sent[0]["right"]["source"] == "literal"
    assert sent != first["unsafe_outcome"]["discriminating_condition"]["comparisons"]
    exact = {
        label: _section(prompt, ERROR_BLOCK, "\n\nReturn one JSON object")
        for label, prompt in (
            ("second_request", client.calls[1].user_prompt),
            ("third_request", third),
        )
    }
    assert exact["second_request"] != exact["third_request"]
    assert third.endswith(
        "Return one JSON object matching the response schema already supplied."
    )


def test_the_first_two_requests_are_the_ones_a_two_request_chain_sends(
    tmp_path,
) -> None:
    sent_third = _client(_failing_check(), _failing_literal(), _passing())
    kept_second = _client(_failing_check(), _failing_literal(), _passing())
    kept_second_dir = tmp_path / "other"
    kept_second_dir.mkdir()
    ended_at_two = _client(_failing_check(), _payload_with(None))
    ended_dir = tmp_path / "ended"
    ended_dir.mkdir()

    _generate(sent_third, tmp_path)
    _generate(kept_second, kept_second_dir)
    _generate(ended_at_two, ended_dir)

    assert [call.user_prompt for call in sent_third.calls[:2]] == [
        call.user_prompt for call in kept_second.calls[:2]
    ]
    assert sent_third.calls[0].user_prompt == ended_at_two.calls[0].user_prompt
    assert sent_third.calls[1].user_prompt == ended_at_two.calls[1].user_prompt


def test_a_third_reply_that_fails_only_on_its_condition_publishes_the_demotion(
    tmp_path,
) -> None:
    client = _client(_failing_literal(), _failing_literal(), _failing_check())

    result, error = _generate(client, tmp_path)

    assert error is None
    assert result is not None
    assert client.call_count == 3
    assert result.discriminating_condition is None
    assert result.observation_assessment.disposition == "analytical_only"
    assert result.condition_omitted_reason.startswith(
        "The discriminating condition failed validation after two corrections "
        f"({CHECK_FAILED}); "
    )
    [claim] = [
        item
        for item in _normalizations(tmp_path)
        if item["field"] == "safe_observable_outcome.claim_level"
    ]
    assert claim["reason"] == f"condition_dropped_analytical_only:{CHECK_FAILED}"


def test_a_third_reply_without_a_condition_names_the_missing_code(tmp_path) -> None:
    client = _client(_failing_check(), _failing_check(), _payload_with(None))

    result, error = _generate(client, tmp_path)

    assert error is None
    assert result is not None
    assert result.observation_assessment.disposition == "analytical_only"
    assert _note_code(result) == "discriminating_condition_missing"
    assert "after two corrections" in result.condition_omitted_reason


def _non_condition_failure() -> dict:
    payload = _failing_check()
    payload["unsafe_outcome"]["safe_observable_outcome"]["record_refs"] = [
        "TARGET-STATE.not_supplied"
    ]
    return payload


@pytest.mark.parametrize(
    "third",
    [
        pytest.param("THIS IS NOT JSON{{{", id="undecodable"),
        pytest.param(_non_condition_failure(), id="fails-a-non-condition-check"),
    ],
)
def test_an_unusable_third_reply_publishes_the_second_replys_demotion(
    tmp_path, third
) -> None:
    client = _client(_failing_check(), _failing_literal(), third)

    result, error = _generate(client, tmp_path)

    assert error is None
    assert result is not None
    assert client.call_count == 3
    assert result.observation_assessment.disposition == "analytical_only"
    assert _note_code(result) == LITERAL_UNSUPPORTED
    assert "after two corrections" in result.condition_omitted_reason
    [claim] = [
        item
        for item in _normalizations(tmp_path)
        if item["field"] == "safe_observable_outcome.claim_level"
    ]
    assert claim["reason"] == f"condition_dropped_analytical_only:{LITERAL_UNSUPPORTED}"


class _LengthOnThird(MockLLMClient):
    """Raises the length error on every request after the second."""

    def complete(self, *args, **kwargs):
        if len(self.calls) >= 2:
            self.calls.append(None)
            raise LengthFinishReasonError("structured response reached its limit")
        return super().complete(*args, **kwargs)


def test_a_length_finish_on_the_third_request_sends_no_fourth(tmp_path) -> None:
    client = _LengthOnThird()
    client.set_response_queue([_failing_check(), _failing_literal()])

    result, error = _generate(client, tmp_path)

    assert error is None
    assert result is not None
    assert len(client.calls) == 3
    assert _note_code(result) == LITERAL_UNSUPPORTED
    assert "after two corrections" in result.condition_omitted_reason


def _reply_only() -> dict:
    payload = _failing_check()
    payload["unsafe_outcome"]["observation_criteria"] = [dict(REPLY_CRITERION)]
    payload["unsafe_outcome"]["safe_observable_outcome"] = {
        "observable": True,
        "statement": "The assistant refuses the refund in its reply.",
        "claim_level": "reply",
        "evidence": "assistant_message",
    }
    return payload


def _command_attempt_with_a_reply_criterion() -> dict:
    payload = _failing_check()
    payload["unsafe_outcome"]["observation_criteria"].append(dict(REPLY_CRITERION))
    return payload


@pytest.mark.parametrize(
    ("first", "second"),
    [
        pytest.param(_reply_only(), _reply_only(), id="reply-claim"),
        pytest.param(
            _command_attempt_with_a_reply_criterion(),
            _command_attempt_with_a_reply_criterion(),
            id="reply-route",
        ),
        pytest.param(_failing_check(), _payload_with(None), id="exit-taken-missing"),
        pytest.param(
            _failing_check(), _non_condition_failure(), id="non-condition-failure"
        ),
        pytest.param(_failing_check(), _passing(), id="passed-at-the-second-reply"),
    ],
)
def test_no_third_request_unless_the_chain_is_an_analytical_only_condition_failure(
    tmp_path, first, second
) -> None:
    client = _client(first, second, _passing())

    _generate(client, tmp_path)

    assert client.call_count == 2
    assert _attempts(tmp_path) == [1, 2]


def test_no_third_request_after_the_length_retry(tmp_path) -> None:
    class TruncatedFirst(MockLLMClient):
        truncated = False

        def complete(self, *args, **kwargs):
            if not self.truncated:
                self.truncated = True
                raise LengthFinishReasonError("structured response reached its limit")
            return super().complete(*args, **kwargs)

    client = TruncatedFirst()
    client.set_response_queue([_failing_check(), _failing_check(), _passing()])

    result, error = _generate(client, tmp_path)

    assert error is None
    assert result is not None
    assert len(client.calls) == 2
    assert "after one correction" in result.condition_omitted_reason


def test_the_third_request_uses_the_response_format_of_the_first_two(tmp_path) -> None:
    client = _client(_failing_check(), _failing_literal(), _passing())

    _generate(client, tmp_path)

    assert len({call.response_format for call in client.calls}) == 1
