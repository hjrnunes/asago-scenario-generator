"""One recorded retry after a transport error, at the single provider seam."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import openai
import pytest
from openai.types.chat import ChatCompletion

from asago_scenario_generator.stpa.infra import transport_retry
from asago_scenario_generator.stpa.infra.llm_helpers import (
    CorrectionPolicy,
    call_with_policy,
)
from asago_scenario_generator.stpa.infra.provider_record import (
    RECORD_FILENAME,
    CallIdentity,
    ReplayIncompleteError,
    call_identity,
    provider_call_session,
)
from tests.stpa.test_provider_call_record import (
    _Answer,
    _answer,
    _client,
    _completion,
    _http_response,
    _Provider,
    _records,
)

_REQUEST = httpx.Request("POST", "https://provider.invalid/v1/chat")


def _connection_error() -> openai.APIConnectionError:
    return openai.APIConnectionError(message="connection reset", request=_REQUEST)


def _status_error(status: int) -> openai.APIStatusError:
    if status == 429:
        return openai.RateLimitError(
            "slow down", response=_http_response(429), body=None
        )
    if status >= 500:
        return openai.InternalServerError(
            "upstream failed", response=_http_response(status), body=None
        )
    return openai.BadRequestError(
        "bad request", response=_http_response(status), body=None
    )


def _failing_then(*failures: BaseException) -> _Provider:
    """Raise each failure in turn, then answer."""
    pending = list(failures)

    def respond(**kwargs: Any) -> ChatCompletion:
        if pending:
            raise pending.pop(0)
        return _answer()

    return _Provider(respond)


def _complete(client: Any) -> Any:
    return client.complete("s", "u", response_format=_Answer)


@pytest.mark.parametrize(
    "failure",
    [_connection_error(), _status_error(502), _status_error(500)],
    ids=["connection", "502", "500"],
)
def test_a_transport_error_is_retried_once_and_the_success_is_returned(
    failure: BaseException,
) -> None:
    provider = _failing_then(failure)

    result = _complete(_client(provider))

    assert result.content == _Answer(answer="42")
    assert len(provider.requests) == 2


@pytest.mark.parametrize(
    "failure",
    [_connection_error(), _status_error(503)],
    ids=["connection", "503"],
)
def test_two_transport_errors_surface_after_exactly_two_requests(
    failure: BaseException,
) -> None:
    provider = _failing_then(failure, failure)

    with pytest.raises(type(failure)):
        _complete(_client(provider))

    assert len(provider.requests) == 2


@pytest.mark.parametrize(
    "failure",
    [
        openai.APITimeoutError(request=_REQUEST),
        _status_error(400),
        _status_error(429),
        _status_error(404),
    ],
    ids=["timeout", "400", "429", "404"],
)
def test_other_provider_errors_are_never_retried(failure: BaseException) -> None:
    provider = _failing_then(failure)

    with pytest.raises(type(failure)):
        _complete(_client(provider))

    assert len(provider.requests) == 1


def test_a_response_that_fails_validation_is_not_retried(tmp_path: Path) -> None:
    provider = _Provider(lambda **_: _completion('{"wrong": 1}'))

    outcome = _call(_client(provider), tmp_path)

    assert outcome.error is not None
    assert len(provider.requests) == 1
    assert outcome.calls == 1


def test_the_retry_waits_the_fixed_delay_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    slept: list[float] = []
    monkeypatch.setattr(transport_retry, "_sleep", slept.append)
    monkeypatch.setattr(transport_retry, "RETRY_DELAY_SECONDS", 0.75)

    _complete(_client(_failing_then(_connection_error())))

    assert slept == [0.75]


def test_the_default_delay_is_short() -> None:
    assert 0 <= transport_retry.DEFAULT_RETRY_DELAY_SECONDS <= 2


def test_the_sdk_client_keeps_its_own_retries_off() -> None:
    assert _client()._client.max_retries == 0


def test_the_service_tier_fallback_keeps_its_own_rule() -> None:
    def tiered(**kwargs: Any) -> ChatCompletion:
        if kwargs.get("service_tier") == "flex":
            raise _status_error(429)
        return _answer()

    provider = _Provider(tiered)
    client = _client(provider, service_tier="flex", service_tier_fallback="default")

    result = _complete(client)

    assert result.request_controls["service_tier_fallback_used"] is True
    assert [r.get("service_tier") for r in provider.requests] == ["flex", "default"]


# --- the retry is recorded ---------------------------------------------------


def test_both_attempts_are_recorded_and_the_retry_names_the_failure(
    tmp_path: Path,
) -> None:
    provider = _failing_then(_status_error(502))
    with provider_call_session(record_dir=tmp_path) as session:
        _complete(_client(provider, session=session))

    failed, retried = _records(tmp_path)
    assert failed["outcome"] == "error"
    assert failed["error"]["type"] == "InternalServerError"
    assert failed["error"]["status_code"] == 502
    assert "retry_of" not in failed
    assert retried["outcome"] == "response"
    assert retried["retry_of"] == {"type": "InternalServerError", "status_code": 502}
    assert failed["request_sha256"] == retried["request_sha256"]
    assert [failed["sequence"], retried["sequence"]] == [1, 2]


def test_a_connection_error_is_recorded_without_a_status(tmp_path: Path) -> None:
    with provider_call_session(record_dir=tmp_path) as session:
        _complete(_client(_failing_then(_connection_error()), session=session))

    _, retried = _records(tmp_path)
    assert retried["retry_of"] == {"type": "APIConnectionError", "status_code": None}


def test_a_record_without_a_retry_has_no_retry_field(tmp_path: Path) -> None:
    with provider_call_session(record_dir=tmp_path) as session:
        _complete(_client(_Provider(_answer), session=session))

    (record,) = _records(tmp_path)
    assert "retry_of" not in record


def test_two_failures_are_recorded_as_a_failure_and_a_failed_retry(
    tmp_path: Path,
) -> None:
    failure = _connection_error()
    with provider_call_session(record_dir=tmp_path) as session:
        with pytest.raises(openai.APIConnectionError):
            _complete(_client(_failing_then(failure, failure), session=session))

    first, second = _records(tmp_path)
    assert (first["outcome"], second["outcome"]) == ("error", "error")
    assert "retry_of" not in first
    assert second["retry_of"]["type"] == "APIConnectionError"


def test_a_local_rejection_is_recorded_on_the_retry(tmp_path: Path) -> None:
    pending = [_status_error(502)]

    def respond(**_: Any) -> ChatCompletion:
        if pending:
            raise pending.pop(0)
        return _completion(None, finish_reason="length")

    with provider_call_session(record_dir=tmp_path) as session:
        with pytest.raises(Exception):
            _complete(_client(_Provider(respond), session=session))

    failed, retried = _records(tmp_path)
    assert failed["local_rejection"] is None
    assert retried["local_rejection"] is not None


# --- replay ------------------------------------------------------------------


def _identity() -> CallIdentity:
    return CallIdentity(stage="stage_x", step="call_answer", scenario_id="SCN-1")


def _stable(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    volatile = {"timestamp", "duration_ms"}
    return [{k: v for k, v in r.items() if k not in volatile} for r in records]


@pytest.mark.parametrize(
    "failure",
    [_connection_error(), _status_error(502)],
    ids=["connection", "502"],
)
def test_a_recording_with_a_retry_replays_identically(
    tmp_path: Path, failure: BaseException
) -> None:
    recorded = tmp_path / "recorded"
    with provider_call_session(record_dir=recorded) as session:
        with call_identity(_identity()):
            live = _complete(_client(_failing_then(failure), session=session))

    replayed = tmp_path / "replayed"
    with provider_call_session(record_dir=replayed, replay_dir=recorded) as session:
        with call_identity(_identity()):
            again = _complete(_client(None, base_url=None, session=session))

    assert again.content == live.content
    assert _stable(_records(replayed)) == _stable(_records(recorded))


def test_a_recording_with_two_failures_replays_the_same_error(
    tmp_path: Path,
) -> None:
    failure = _status_error(503)
    recorded = tmp_path / "recorded"
    with provider_call_session(record_dir=recorded) as session:
        with pytest.raises(openai.InternalServerError):
            _complete(_client(_failing_then(failure, failure), session=session))

    replayed = tmp_path / "replayed"
    with provider_call_session(record_dir=replayed, replay_dir=recorded) as session:
        with pytest.raises(openai.InternalServerError):
            _complete(_client(None, base_url=None, session=session))

    assert _stable(_records(replayed)) == _stable(_records(recorded))


def test_replay_does_not_pause_for_the_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recorded = tmp_path / "recorded"
    with provider_call_session(record_dir=recorded) as session:
        _complete(_client(_failing_then(_connection_error()), session=session))

    slept: list[float] = []
    monkeypatch.setattr(transport_retry, "_sleep", slept.append)
    with provider_call_session(
        record_dir=tmp_path / "replayed", replay_dir=recorded
    ) as session:
        _complete(_client(None, base_url=None, session=session))

    assert slept == []


def _write_recording(directory: Path, records: list[dict[str, Any]]) -> None:
    directory.mkdir(parents=True)
    (directory / RECORD_FILENAME).write_text(
        "".join(json.dumps(record) + "\n" for record in records), encoding="utf-8"
    )


def _recorded_failure_without_retry(tmp_path: Path) -> Path:
    """A recording made before the retry existed: one 502, no second attempt."""
    source = tmp_path / "source"
    with provider_call_session(record_dir=source) as session:
        with pytest.raises(openai.InternalServerError):
            # Two failures give two records; keep only the first, as an old
            # recording would hold.
            failure = _status_error(502)
            _complete(_client(_failing_then(failure, failure), session=session))
    first = _records(source)[0]
    old = tmp_path / "old"
    _write_recording(old, [first])
    return old


def test_a_recorded_failure_without_a_retry_replays_without_one(
    tmp_path: Path,
) -> None:
    old = _recorded_failure_without_retry(tmp_path)

    replayed = tmp_path / "replayed"
    with provider_call_session(record_dir=replayed, replay_dir=old) as session:
        with pytest.raises(openai.InternalServerError):
            _complete(_client(None, base_url=None, session=session))

    (record,) = _records(replayed)
    assert record["outcome"] == "error"
    assert "retry_of" not in record


def test_a_replay_that_asks_for_more_requests_than_recorded_still_fails(
    tmp_path: Path,
) -> None:
    recorded = tmp_path / "recorded"
    with provider_call_session(record_dir=recorded) as session:
        _complete(_client(_Provider(_answer), session=session))

    with pytest.raises(ReplayIncompleteError):
        with provider_call_session(
            record_dir=tmp_path / "replayed", replay_dir=recorded
        ) as session:
            client = _client(None, base_url=None, session=session)
            _complete(client)
            with pytest.raises(Exception):
                client.complete("s", "another", response_format=_Answer)


def _call(client: Any, tmp_path: Path) -> Any:
    return call_with_policy(
        llm_client=client,
        system_prompt="s",
        user_prompt="u",
        response_format=_Answer,
        run_dir=tmp_path,
        stage="stage_x",
        step="call_answer",
        policy=CorrectionPolicy(),
    )
