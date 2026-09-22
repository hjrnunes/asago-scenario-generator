from __future__ import annotations

from frozen_judge_transport import request_judge


class _Message:
    def __init__(self, content: str) -> None:
        self.content = content


class _Choice:
    def __init__(self, content: str) -> None:
        self.message = _Message(content)
        self.finish_reason = "stop"


class _Usage:
    prompt_tokens = 12
    completion_tokens = 7
    total_tokens = 19


class _Response:
    id = "response-7"
    usage = _Usage()

    def __init__(self, content: str) -> None:
        self.choices = [_Choice(content)]


def test_transport_persists_raw_response_and_controls_before_parse() -> None:
    persisted: list[dict] = []
    calls: list[dict] = []

    def create(**kwargs):
        calls.append(kwargs)
        return _Response('{"verdict":"unresolved","evidence_refs":[]}')

    result = request_judge(
        "system",
        "user",
        model="wire-model",
        completion_create=create,
        persist=persisted.append,
    )

    assert result.status == "parsed"
    assert result.parsed == {"verdict": "unresolved", "evidence_refs": []}
    assert result.raw_response == b'{"verdict":"unresolved","evidence_refs":[]}'
    assert persisted[0]["raw_response_base64"]
    assert persisted[0]["raw_response"] == (
        '{"verdict":"unresolved","evidence_refs":[]}'
    )
    assert persisted[0]["parsed"] is None
    assert persisted[0]["system_prompt"] == "system"
    assert persisted[0]["user_prompt"] == "user"
    assert persisted[0]["response_id"] == "response-7"
    assert persisted[0]["finish_reason"] == "stop"
    assert persisted[0]["usage"] == {
        "prompt_tokens": 12,
        "completion_tokens": 7,
        "total_tokens": 19,
    }
    assert persisted[0]["controls"] == {
        "temperature": 0.0,
        "thinking_enabled": False,
        "max_completion_tokens": 512,
        "timeout_seconds": 180.0,
        "max_retries": 0,
    }
    assert calls[0]["extra_body"] == {
        "chat_template_kwargs": {"enable_thinking": False}
    }


def test_transport_preserves_raw_answer_when_json_parsing_fails() -> None:
    persisted: list[dict] = []
    raw = b'{"verdict":'

    result = request_judge(
        "system",
        "user",
        model="wire-model",
        completion_create=lambda **_kwargs: _Response(raw.decode()),
        persist=persisted.append,
    )

    assert result.status == "parse_failed"
    assert result.failure is not None
    assert result.raw_response == raw
    assert result.parsed is None
    assert persisted[0]["raw_response"] == '{"verdict":'
    assert persisted[0]["raw_response_base64"] == "eyJ2ZXJkaWN0Ijo="
    assert "parsed" not in persisted[0] or persisted[0]["parsed"] is None


def test_transport_records_transport_failure_without_fabricating_json() -> None:
    persisted: list[dict] = []

    def fail(**_kwargs):
        raise TimeoutError("provider timeout")

    result = request_judge(
        "system",
        "user",
        model="wire-model",
        completion_create=fail,
        persist=persisted.append,
    )

    assert result.status == "transport_failed"
    assert result.parsed is None
    assert result.raw_response == b""
    assert result.failure == "TimeoutError: provider timeout"
    assert persisted[0]["raw_response_base64"] == ""
    assert "usage" not in persisted[0]
