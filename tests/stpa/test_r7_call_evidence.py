"""R7 call-evidence regressions for offline provider adapters."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.infra.llm_helpers import safe_llm_call


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


class _CompatibilityClient:
    model = "offline-test-model"

    def __init__(self) -> None:
        self.calls = 0

    def complete(self, **kwargs: Any) -> LLMResult:
        self.calls += 1
        if "allow_unvalidated" in kwargs:
            raise TypeError("unexpected keyword argument 'allow_unvalidated'")
        return LLMResult(
            content='{"value": 3}',
            prompt_tokens=2,
            completion_tokens=1,
            duration_ms=1,
        )


class _CompatibilityFailureClient(_CompatibilityClient):
    def complete(self, **kwargs: Any) -> LLMResult:
        self.calls += 1
        if "allow_unvalidated" in kwargs:
            raise TypeError("unexpected keyword argument 'allow_unvalidated'")
        raise RuntimeError("provider unavailable")


def _entries(run_dir: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in (run_dir / "calls.jsonl").read_text(encoding="utf-8").splitlines()
    ]


def _call(
    tmp_path: Path,
    client: Any,
    *,
    json_decode_retries: int = 0,
    result_validator: Any = None,
    allow_unvalidated: bool = False,
) -> tuple[_Payload | None, str | None]:
    parsed, _, error = safe_llm_call(
        llm_client=client,
        system_prompt="system",
        user_prompt="user",
        response_format=_Payload,
        run_dir=tmp_path,
        stage="stage_test",
        step="evidence",
        json_decode_retries=json_decode_retries,
        result_validator=result_validator,
        allow_unvalidated=allow_unvalidated,
    )
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


def test_compatibility_fallback_is_explicit_without_duplicate_provider_evidence(
    tmp_path: Path,
) -> None:
    client = _CompatibilityClient()

    parsed, error = _call(tmp_path, client, allow_unvalidated=True)

    assert error is None
    assert parsed == _Payload(value=3)
    entries = _entries(tmp_path)
    assert len(entries) == 1
    assert client.calls == 2
    assert entries[0]["request_controls"]["compatibility_fallback"] is True


def test_failed_compatibility_fallback_keeps_one_typed_attempt(
    tmp_path: Path,
) -> None:
    client = _CompatibilityFailureClient()

    parsed, error = _call(tmp_path, client, allow_unvalidated=True)

    assert parsed is None
    assert error == "RuntimeError: provider unavailable"
    entries = _entries(tmp_path)
    assert len(entries) == 1
    assert entries[0]["failure_class"] == "provider_failure"
    assert entries[0]["request_controls"]["compatibility_fallback"] is True
