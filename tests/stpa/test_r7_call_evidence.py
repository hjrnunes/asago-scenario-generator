"""R7 call-evidence regressions for offline provider adapters."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import BaseModel

from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.infra.llm_helpers import (
    CorrectionPolicy,
    MissingCompletionBudget,
    _decode_json_text_with_evidence,
    _provider_response_usage,
    call_with_policy,
    log_llm_call_failure,
)
from asago_scenario_generator.stpa.infra.manifest_helpers import count_calls_by_stage
from tests.helpers.calls_log import read_calls_jsonl


class _Payload(BaseModel):
    value: int


class _QueueClient:
    model = "offline-test-model"

    def __init__(self, responses: list[Any]) -> None:
        self._responses = iter(responses)

    def complete(self, **_: Any) -> LLMResult:
        content = next(self._responses)
        return LLMResult(
            content=content,
            prompt_tokens=11,
            completion_tokens=7,
            duration_ms=3,
        )


class _FailingClient:
    model = "offline-test-model"

    def complete(self, **_: Any) -> LLMResult:
        raise RuntimeError("provider unavailable")


class _SecretFailingClient:
    model = "offline-test-model"

    def complete(self, **_: Any) -> LLMResult:
        raise RuntimeError("POST https://private.example/v1 token=sk-secret-value")


def _entries(run_dir: Path) -> list[dict[str, Any]]:
    return read_calls_jsonl(run_dir)


def _call(
    tmp_path: Path,
    client: Any,
    *,
    json_decode_retries: int = 0,
    result_validator: Any = None,
    allow_unvalidated: bool = False,
) -> tuple[_Payload | None, str | None]:
    outcome = call_with_policy(
        llm_client=client,
        system_prompt="system",
        user_prompt="user",
        response_format=_Payload,
        run_dir=tmp_path,
        stage="stage_test",
        step="evidence",
        result_validator=result_validator,
        allow_unvalidated=allow_unvalidated,
        policy=CorrectionPolicy(json_retries=json_decode_retries),
    )
    parsed, error = outcome.value, outcome.error
    return parsed, error


def test_success_keeps_raw_response_separate_from_cleaned_response(
    tmp_path: Path,
) -> None:
    raw = '```json\n{"value": 1}\n```'

    parsed, error = _call(tmp_path, _QueueClient([raw]))

    assert error is None
    assert parsed == _Payload(value=1)
    entry = _entries(tmp_path)[0]
    assert entry["raw_response"] == raw
    assert entry["cleaned_response"] == {"value": 1}
    assert entry["raw_response_pin"]
    assert entry["cleaned_response_pin"]
    assert [item["name"] for item in entry["cleanup_transformations"]] == [
        "markdown_fence_removal",
        "plain_json_decode",
    ]
    assert all(
        item["input_pin"] and item["output_pin"]
        for item in entry["cleanup_transformations"]
    )


def test_combined_cleanup_is_ordered_and_pinned(tmp_path: Path) -> None:
    raw = '```json\n{"value": 1,}\n```'

    parsed, error = _call(tmp_path, _QueueClient([raw]))

    assert error is None
    assert parsed == _Payload(value=1)
    transformation_names = [
        item["name"] for item in _entries(tmp_path)[0]["cleanup_transformations"]
    ]
    assert transformation_names == [
        "markdown_fence_removal",
        "trailing_comma_repair",
        "plain_json_decode",
    ]


def test_provider_failure_marks_usage_unavailable(tmp_path: Path) -> None:
    parsed, error = _call(tmp_path, _FailingClient())

    assert parsed is None
    assert error == "RuntimeError: provider unavailable"
    entry = _entries(tmp_path)[0]
    assert entry["provider_response_received"] is False
    assert entry["failure_class"] == "provider_failure"
    assert entry["usage"]["status"] == "unavailable"
    assert entry["usage"]["prompt_tokens"] is None
    assert entry["usage"]["completion_tokens"] is None


class _NoCompletionBudgetClient:
    """A configured client (it has a context window) with no completion cap."""

    model = "offline-test-model"
    context_window = 8192

    def __init__(self) -> None:
        self.requests = 0

    def complete(self, **_: Any) -> LLMResult:
        self.requests += 1
        return LLMResult(
            content='{"value": 4}', prompt_tokens=1, completion_tokens=1, duration_ms=1
        )


def test_missing_completion_budget_is_not_logged_as_a_provider_failure(
    tmp_path: Path,
) -> None:
    client = _NoCompletionBudgetClient()

    parsed, error = _call(tmp_path, client)

    assert parsed is None
    assert error == (
        "MissingCompletionBudget: configured model must declare max_completion_tokens"
    )
    assert client.requests == 0
    entry = _entries(tmp_path)[0]
    assert entry["provider_response_received"] is False
    assert entry["failure_class"] == "configuration_failure"


def test_missing_completion_budget_is_still_a_value_error() -> None:
    assert issubclass(MissingCompletionBudget, ValueError)


def test_explicit_completion_cap_replaces_the_missing_client_budget(
    tmp_path: Path,
) -> None:
    client = _NoCompletionBudgetClient()

    outcome = call_with_policy(
        llm_client=client,
        system_prompt="system",
        user_prompt="user",
        response_format=_Payload,
        run_dir=tmp_path,
        stage="stage_test",
        step="evidence",
        max_completion_tokens=512,
        policy=CorrectionPolicy(),
    )

    assert outcome.value == _Payload(value=4)
    assert client.requests == 1


def test_failure_evidence_redacts_connection_material(tmp_path: Path) -> None:
    _, error = _call(tmp_path, _SecretFailingClient())

    assert "private.example" not in (error or "")
    entry = _entries(tmp_path)[0]
    assert "private.example" not in entry["error"]
    assert "sk-secret-value" not in entry["error"]


def test_answered_semantic_failure_is_not_provider_failure(tmp_path: Path) -> None:
    def reject(_: _Payload) -> None:
        raise ValueError("stage rule rejected the answer")

    parsed, error = _call(
        tmp_path,
        _QueueClient(['{"value": 1}']),
        result_validator=reject,
    )

    assert parsed is None
    assert error == "ValueError: stage rule rejected the answer"
    entry = _entries(tmp_path)[0]
    assert entry["provider_response_received"] is True
    assert entry["failure_class"] == "answered_semantic_failure"
    assert entry["usage"]["status"] == "reported"
    assert entry["usage"]["prompt_tokens"] == 11
    assert entry["usage"]["completion_tokens"] == 7


def test_retry_attempts_have_distinct_identity_and_raw_evidence(tmp_path: Path) -> None:
    first = "{malformed"
    second = '{"value": 2}'

    parsed, error = _call(
        tmp_path,
        _QueueClient([first, second]),
        json_decode_retries=1,
    )

    assert error is None
    assert parsed == _Payload(value=2)
    entries = _entries(tmp_path)
    assert len(entries) == 2
    assert entries[0]["attempt_id"] != entries[1]["attempt_id"]
    assert entries[0]["raw_response"] == first
    assert entries[1]["raw_response"] == second
    assert entries[0]["failure_class"] == "answered_malformed"


def test_absent_provider_usage_is_unavailable_not_zero() -> None:
    assert _provider_response_usage(SimpleNamespace(usage=None)) == (None, None)
    assert _provider_response_usage(SimpleNamespace()) == (None, None)


def test_short_malformed_text_records_no_fence_removal() -> None:
    with pytest.raises(json.JSONDecodeError):
        _decode_json_text_with_evidence("{malformed")


def test_count_calls_by_stage_without_log_is_empty(tmp_path: Path) -> None:
    assert count_calls_by_stage(tmp_path) == {}


def test_count_calls_by_stage_sums_absent_and_present_token_counters(
    tmp_path: Path,
) -> None:
    entries = [
        {"stage": "s1", "prompt_tokens": None, "completion_tokens": None},
        {"stage": "s1", "prompt_tokens": 5, "completion_tokens": 2},
        {"stage": "s2"},
    ]
    (tmp_path / "calls.jsonl").write_text(
        "\n".join(json.dumps(entry) for entry in entries) + "\n",
        encoding="utf-8",
    )

    counts = count_calls_by_stage(tmp_path)

    assert counts == {
        "s1": {"call_count": 2, "total_tokens": 7},
        "s2": {"call_count": 1, "total_tokens": 0},
    }


class _WindowedClient:
    """A configured-profile client (it declares a context window)."""

    model = "offline-test-model"
    context_window = 32768
    max_completion_tokens = 8192

    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail

    def complete(self, **_: Any) -> LLMResult:
        if self.fail:
            raise RuntimeError("provider unavailable")
        return LLMResult(
            content={"value": 1}, prompt_tokens=11, completion_tokens=7, duration_ms=3
        )


def _log_one_call(
    run_dir: Path, client: _WindowedClient, *, step: str, user_prompt: str
) -> None:
    call_with_policy(
        llm_client=client,
        system_prompt="system",
        user_prompt=user_prompt,
        response_format=_Payload,
        run_dir=run_dir,
        stage="s",
        step=step,
        policy=CorrectionPolicy(),
    )


def test_count_calls_by_stage_counts_requests_sent_not_log_entries(
    tmp_path: Path,
) -> None:
    """Every kind of entry the producer logs is counted by whether it was sent."""
    _log_one_call(tmp_path, _WindowedClient(), step="answered", user_prompt="Reply.")
    _log_one_call(
        tmp_path, _WindowedClient(fail=True), step="transport", user_prompt="Reply."
    )
    _log_one_call(
        tmp_path,
        _WindowedClient(),
        step="blocked",
        user_prompt="Neutralized use-case sentence. " * 4200,
    )
    log_llm_call_failure(
        "offline-test-model",
        tmp_path,
        "s",
        "assemble",
        "ValueError: preflight rejected the prompt",
        system_prompt="system",
        user_prompt="Reply.",
    )
    entries = read_calls_jsonl(tmp_path)
    assert [item["step"] for item in entries] == [
        "answered",
        "transport",
        "blocked",
        "assemble",
    ]

    counts = count_calls_by_stage(tmp_path)

    assert counts["s"]["call_count"] == 2
    assert counts["s"]["total_tokens"] == 18


def test_a_stage_with_only_blocked_entries_reports_zero_calls(tmp_path: Path) -> None:
    _log_one_call(
        tmp_path,
        _WindowedClient(),
        step="blocked",
        user_prompt="Neutralized use-case sentence. " * 4200,
    )

    assert count_calls_by_stage(tmp_path) == {"s": {"call_count": 0, "total_tokens": 0}}
