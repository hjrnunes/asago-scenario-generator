"""Per-request provider record and replay.

The record has to be sufficient for a later change to prove that a refactor
leaves a run unchanged, so the central test runs the real SP1 pipeline against
a scripted provider, replays it from the record, and compares every output.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import openai
import pytest
from openai.types.chat import ChatCompletion
from pydantic import BaseModel

from asago_scenario_generator.stpa.infra.llm import LLMClient
from asago_scenario_generator.stpa.infra.llm_helpers import safe_llm_call
from asago_scenario_generator.stpa.infra.provider_record import (
    RECORD_FILENAME,
    CallIdentity,
    ReplayedProviderError,
    ReplayIncompleteError,
    ReplayMissError,
    _rebuild_error,
    _response_body,
    call_identity,
    canonical_request,
    provider_call_session,
    request_digest,
    active_provider_session,
)
from asago_scenario_generator.stpa.system_model.run import run_sp1
from tests.stpa.sp1_helpers import (
    MockLLMClient,
    make_risk_cards,
    setup_sp1_mock_client,
)
from unittest.mock import patch
from typer.testing import CliRunner
from asago_scenario_generator.cli import app

ENDPOINT = "http://fake-endpoint.invalid/v1"
SECRET = "sk-test-secret-value"
HEADER_SECRET = "header-secret-value"


class _Answer(BaseModel):
    answer: str


def _completion(
    content: str | None,
    *,
    finish_reason: str = "stop",
    response_id: str = "chatcmpl-test-1",
) -> ChatCompletion:
    return ChatCompletion.model_validate(
        {
            "id": response_id,
            "object": "chat.completion",
            "created": 1_700_000_000,
            "model": "served-model-name",
            "choices": [
                {
                    "index": 0,
                    "finish_reason": finish_reason,
                    "message": {"role": "assistant", "content": content},
                }
            ],
            "usage": {
                "prompt_tokens": 11,
                "completion_tokens": 7,
                "total_tokens": 18,
            },
        }
    )


class _Provider:
    """Stand-in for the OpenAI SDK client: one scripted function per request."""

    def __init__(self, respond: Any) -> None:
        self.respond = respond
        self.requests: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        completions = SimpleNamespace(create=self._create)
        self.chat = SimpleNamespace(completions=completions)

    def _create(self, **kwargs: Any) -> ChatCompletion:
        with self._lock:
            self.requests.append(kwargs)
        return self.respond(**kwargs)


def _client(provider: _Provider | None = None, **overrides: Any) -> LLMClient:
    settings: dict[str, Any] = {
        "base_url": ENDPOINT,
        "api_key": SECRET,
        "model": "scripted-model",
        "extra_headers": {"X-Auth": HEADER_SECRET},
        "temperature": 0.4,
        "max_completion_tokens": 2048,
    }
    settings.update(overrides)
    client = LLMClient(**settings)
    if provider is not None:
        client._client = provider
    return client


def _records(directory: Path) -> list[dict[str, Any]]:
    path = directory / RECORD_FILENAME
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def _answer(**kwargs: Any) -> ChatCompletion:
    return _completion('{"answer": "42"}')


def test_record_holds_request_response_and_identity(tmp_path: Path) -> None:
    provider = _Provider(_answer)
    with provider_call_session(record_dir=tmp_path):
        model, _result, error = safe_llm_call(
            llm_client=_client(provider),
            system_prompt="You answer.",
            user_prompt="What is the answer?",
            response_format=_Answer,
            run_dir=tmp_path,
            stage="stage_x",
            step="call_answer",
            slot_id="SLOT-1",
            scenario_id="SCN-9",
        )

    assert error is None and model == _Answer(answer="42")
    (record,) = _records(tmp_path)
    assert record["kind"] == "provider-call-record-v1"
    assert record["sequence"] == 1
    assert record["identity"] == {
        "stage": "stage_x",
        "step": "call_answer",
        "slot_id": "SLOT-1",
        "scenario_id": "SCN-9",
        "attempt_number": 1,
    }
    request = record["request"]
    assert request["model"] == "scripted-model"
    assert request["messages"] == [
        {"role": "system", "content": "You answer."},
        {"role": "user", "content": "What is the answer?"},
    ]
    assert request["parameters"]["temperature"] == 0.4
    assert request["parameters"]["max_completion_tokens"] == 2048
    assert request["parameters"]["response_format"]["json_schema"]["name"] == "_Answer"
    assert record["request_sha256"] == request_digest(request)
    assert record["outcome"] == "response"
    response = record["response"]
    assert response["finish_reason"] == "stop"
    assert response["id"] == "chatcmpl-test-1"
    assert response["model"] == "served-model-name"
    assert response["usage"]["total_tokens"] == 18
    assert response["body"]["choices"][0]["message"]["content"] == '{"answer": "42"}'


def test_connection_material_is_never_recorded(tmp_path: Path) -> None:
    provider = _Provider(_answer)
    with provider_call_session(record_dir=tmp_path):
        safe_llm_call(
            llm_client=_client(provider),
            system_prompt="s",
            user_prompt="u",
            response_format=_Answer,
            run_dir=tmp_path,
            stage="stage_x",
            step="call_answer",
        )

    text = (tmp_path / RECORD_FILENAME).read_text()
    for forbidden in (ENDPOINT, "fake-endpoint", SECRET, HEADER_SECRET, "X-Auth"):
        assert forbidden not in text


def test_provider_failure_is_recorded_with_a_redacted_error(tmp_path: Path) -> None:
    def fail(**kwargs: Any) -> ChatCompletion:
        raise TimeoutError(f"timed out calling {ENDPOINT} api_key={SECRET}")

    with provider_call_session(record_dir=tmp_path):
        _model, _result, error = safe_llm_call(
            llm_client=_client(_Provider(fail)),
            system_prompt="s",
            user_prompt="u",
            response_format=_Answer,
            run_dir=tmp_path,
            stage="stage_x",
            step="call_answer",
        )

    assert error is not None
    (record,) = _records(tmp_path)
    assert record["outcome"] == "error"
    assert record["response"] is None
    assert record["error"]["type"] == "TimeoutError"
    assert SECRET not in record["error"]["message"]
    assert "fake-endpoint" not in record["error"]["message"]


def test_a_response_the_client_rejects_is_recorded_with_the_rejection(
    tmp_path: Path,
) -> None:
    truncated = _Provider(lambda **_: _completion(None, finish_reason="length"))
    with provider_call_session(record_dir=tmp_path):
        _model, _result, error = safe_llm_call(
            llm_client=_client(truncated),
            system_prompt="s",
            user_prompt="u",
            response_format=_Answer,
            run_dir=tmp_path,
            stage="stage_x",
            step="call_answer",
        )

    assert error is not None
    (record,) = _records(tmp_path)
    assert record["outcome"] == "response"
    assert record["response"]["finish_reason"] == "length"
    assert record["local_rejection"]["type"] == "LengthFinishReasonError"


def test_replay_serves_by_digest_and_reports_requests_it_cannot_match(
    tmp_path: Path,
) -> None:
    recorded = tmp_path / "recorded"
    with provider_call_session(record_dir=recorded):
        for prompt in ("first", "second"):
            _client(_Provider(_answer)).complete("s", prompt, response_format=_Answer)

    replayed = tmp_path / "replayed"
    with pytest.raises(ReplayIncompleteError):
        with provider_call_session(record_dir=replayed, replay_dir=recorded) as session:
            client = _client(None, base_url=None)
            # Out-of-order lookup works because matching is by digest.
            assert client.complete("s", "second", response_format=_Answer)
            assert client.complete("s", "first", response_format=_Answer)
            with pytest.raises(ReplayMissError):
                client.complete("s", "never recorded", response_format=_Answer)
            assert session.replayer is not None
            assert session.replayer.unused() == []
            assert len(session.replayer.unmatched) == 1


def _identity(scenario_id: str, attempt: int = 1) -> CallIdentity:
    return CallIdentity(
        stage="stage_x",
        step="call_answer",
        scenario_id=scenario_id,
        attempt_number=attempt,
    )


def _answers_in_turn(*answers: str) -> _Provider:
    pending = list(answers)
    return _Provider(lambda **_: _completion(json.dumps({"answer": pending.pop(0)})))


def test_identical_requests_replay_to_their_own_caller_regardless_of_order(
    tmp_path: Path,
) -> None:
    recorded = tmp_path / "recorded"
    provider = _answers_in_turn("for A", "for B")
    with provider_call_session(record_dir=recorded):
        client = _client(provider)
        for scenario in ("SCN-A", "SCN-B"):
            with call_identity(_identity(scenario)):
                client.complete("s", "same question", response_format=_Answer)
    digests = {record["request_sha256"] for record in _records(recorded)}
    assert len(digests) == 1, "the two requests must be byte-identical"

    for run in range(5):
        answers: dict[str, str] = {}
        b_done = threading.Event()

        def ask(scenario: str, wait: threading.Event | None) -> None:
            if wait is not None:
                wait.wait(timeout=5)
            with call_identity(_identity(scenario)):
                result = client.complete("s", "same question", response_format=_Answer)
            answers[scenario] = result.content.answer
            if scenario == "SCN-B":
                b_done.set()

        with provider_call_session(
            record_dir=tmp_path / f"replayed-{run}", replay_dir=recorded
        ):
            client = _client(None, base_url=None)
            # B asks first, so a digest-only queue would hand it A's response.
            threads = [
                threading.Thread(target=ask, args=("SCN-A", b_done)),
                threading.Thread(target=ask, args=("SCN-B", None)),
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

        assert answers == {"SCN-A": "for A", "SCN-B": "for B"}


def test_repeated_identical_requests_replay_in_recorded_order(tmp_path: Path) -> None:
    recorded = tmp_path / "recorded"
    with provider_call_session(record_dir=recorded):
        client = _client(_answers_in_turn("first", "second"))
        with call_identity(_identity("SCN-A")):
            client.complete("s", "q", response_format=_Answer)
            client.complete("s", "q", response_format=_Answer)

    with provider_call_session(record_dir=tmp_path / "replayed", replay_dir=recorded):
        client = _client(None, base_url=None)
        with call_identity(_identity("SCN-A")):
            assert client.complete("s", "q", response_format=_Answer).content == (
                _Answer(answer="first")
            )
            assert client.complete("s", "q", response_format=_Answer).content == (
                _Answer(answer="second")
            )


def test_a_request_issued_under_another_identity_is_a_replay_miss(
    tmp_path: Path,
) -> None:
    recorded = tmp_path / "recorded"
    with provider_call_session(record_dir=recorded):
        with call_identity(_identity("SCN-A")):
            _client(_Provider(_answer)).complete("s", "q", response_format=_Answer)

    with pytest.raises(ReplayIncompleteError):
        with provider_call_session(
            record_dir=tmp_path / "replayed", replay_dir=recorded
        ):
            with call_identity(_identity("SCN-A", attempt=2)):
                with pytest.raises(ReplayMissError):
                    _client(None, base_url=None).complete(
                        "s", "q", response_format=_Answer
                    )


def _http_response(status: int) -> httpx.Response:
    return httpx.Response(
        status, request=httpx.Request("POST", "https://provider.invalid/v1/chat")
    )


def _live_errors() -> list[BaseException]:
    request = httpx.Request("POST", "https://provider.invalid/v1/chat")
    return [
        openai.RateLimitError("slow down", response=_http_response(429), body=None),
        openai.InternalServerError(
            "upstream failed", response=_http_response(500), body=None
        ),
        openai.BadRequestError(
            "context too long", response=_http_response(400), body=None
        ),
        openai.APITimeoutError(request=request),
        openai.APIConnectionError(message="connection reset", request=request),
        TimeoutError("timed out"),
        ConnectionError("refused"),
    ]


@pytest.mark.parametrize("live", _live_errors(), ids=lambda e: type(e).__name__)
def test_a_recorded_provider_error_replays_as_the_live_error_class(
    tmp_path: Path, live: BaseException
) -> None:
    def fail(**_: Any) -> ChatCompletion:
        raise live

    recorded = tmp_path / "recorded"
    with provider_call_session(record_dir=recorded):
        with pytest.raises(type(live)):
            _client(_Provider(fail)).complete("s", "q", response_format=_Answer)

    with provider_call_session(record_dir=tmp_path / "replayed", replay_dir=recorded):
        with pytest.raises(Exception) as caught:
            _client(None, base_url=None).complete("s", "q", response_format=_Answer)

    replayed = caught.value
    assert type(replayed) is type(live)
    assert str(replayed) == str(live)
    assert getattr(replayed, "status_code", None) == getattr(live, "status_code", None)
    (original,) = _records(recorded)
    (again,) = _records(tmp_path / "replayed")
    assert again["error"] == original["error"]


def test_an_unknown_recorded_error_class_replays_as_a_replayed_provider_error(
    tmp_path: Path,
) -> None:
    class VendorQuirk(Exception):
        pass

    def fail(**_: Any) -> ChatCompletion:
        raise VendorQuirk("odd")

    recorded = tmp_path / "recorded"
    with provider_call_session(record_dir=recorded):
        with pytest.raises(VendorQuirk):
            _client(_Provider(fail)).complete("s", "q", response_format=_Answer)

    with provider_call_session(record_dir=tmp_path / "replayed", replay_dir=recorded):
        with pytest.raises(ReplayedProviderError) as caught:
            _client(None, base_url=None).complete("s", "q", response_format=_Answer)
    assert caught.value.recorded_type == "VendorQuirk"
    assert _records(tmp_path / "replayed")[0]["error"] == _records(recorded)[0]["error"]


def test_a_recorded_rate_limit_replays_through_the_service_tier_fallback(
    tmp_path: Path,
) -> None:
    def tiered(**kwargs: Any) -> ChatCompletion:
        if kwargs.get("service_tier") == "flex":
            raise openai.RateLimitError("busy", response=_http_response(429), body=None)
        return _answer()

    tiers = {"service_tier": "flex", "service_tier_fallback": "default"}
    recorded = tmp_path / "recorded"
    with provider_call_session(record_dir=recorded):
        live = _client(_Provider(tiered), **tiers).complete(
            "s", "q", response_format=_Answer
        )

    with provider_call_session(record_dir=tmp_path / "replayed", replay_dir=recorded):
        replayed = _client(None, base_url=None, **tiers).complete(
            "s", "q", response_format=_Answer
        )

    assert live.request_controls["service_tier_fallback_used"] is True
    assert replayed.content == live.content
    assert replayed.request_controls == live.request_controls


def test_replay_directory_must_differ_from_record_directory(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="differ"):
        with provider_call_session(record_dir=tmp_path, replay_dir=tmp_path):
            pass


def test_run_synthesis_records_into_its_output_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from asago_scenario_generator.pipeline import synthesis

    seen: dict[str, Any] = {}

    def fake_body(inputs: Any, adapters: Any) -> str:
        seen["session"] = active_provider_session()
        return "result"

    monkeypatch.setattr(synthesis, "_run_synthesis", fake_body)
    output_dir = tmp_path / "out"
    inputs = synthesis.SynthesisInputs(use_case="a system", output_dir=output_dir)

    assert synthesis.run_synthesis(inputs, None) == "result"
    assert seen["session"].record_dir == output_dir
    assert not seen["session"].replaying
    assert active_provider_session() is None


def test_run_command_threads_replay_calls_to_the_inputs(tmp_path: Path) -> None:
    for name in ("risk.json", "facts.json", "mapping.tsv", "profiles.yaml"):
        (tmp_path / name).write_text("{}", encoding="utf-8")
    captured: list[Any] = []

    def capture(inputs: Any, adapter: Any) -> SimpleNamespace:
        captured.append(inputs)
        return SimpleNamespace(
            output_dir=tmp_path,
            artifact_paths={"taxonomy-obligation-plan.yaml": tmp_path / "p.yaml"},
            report_path=None,
            run_status="completed",
        )

    with (
        patch(
            "asago_scenario_generator.data.loaders.load_reviewed_risk_extraction",
            return_value=(),
        ),
        patch(
            "asago_scenario_generator.pipeline.synthesis.run_synthesis",
            side_effect=capture,
        ),
    ):
        result = CliRunner().invoke(
            app,
            [
                "generate",
                "--use-case",
                "a system",
                "--risk-extraction",
                str(tmp_path / "risk.json"),
                "--qualification-facts",
                str(tmp_path / "facts.json"),
                "--sssom",
                str(tmp_path / "mapping.tsv"),
                "--profiles-file",
                str(tmp_path / "profiles.yaml"),
                "--output-dir",
                str(tmp_path / "out"),
                "--replay-calls",
                str(tmp_path / "earlier-run"),
            ],
        )

    assert result.exit_code == 0, result.output
    assert captured[0].replay_calls_dir == tmp_path / "earlier-run"


# --- the sufficiency proof -------------------------------------------------


class _ScriptedSP1Provider(_Provider):
    """Answers each request from the shared SP1 mock, keyed by response class.

    The SDK request carries only a schema name (or ``json_object``), so the
    wrapper installed by :func:`_remember_response_format` supplies the class.
    """

    def __init__(self, mock: MockLLMClient) -> None:
        self.mock = mock
        self.current = threading.local()
        super().__init__(self._answer_from_mock)

    def _answer_from_mock(self, **kwargs: Any) -> ChatCompletion:
        system, user = kwargs["messages"]
        result = self.mock.complete(
            system_prompt=system["content"],
            user_prompt=user["content"],
            response_format=getattr(self.current, "response_format", None),
        )
        content = result.content
        if isinstance(content, BaseModel):
            content = content.model_dump_json()
        elif not isinstance(content, str):
            content = json.dumps(content)
        return _completion(content)


def _remember_response_format(
    monkeypatch: pytest.MonkeyPatch, provider: _ScriptedSP1Provider
) -> None:
    original = LLMClient.complete

    def complete(
        self: LLMClient, system_prompt, user_prompt, response_format=None, **kw
    ):
        provider.current.response_format = response_format
        return original(self, system_prompt, user_prompt, response_format, **kw)

    monkeypatch.setattr(LLMClient, "complete", complete)


_VOLATILE_KEYS = {"timestamp", "duration_ms", "created_at", "run_id", "run_dir"}


def _mask(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: "<volatile>" if key in _VOLATILE_KEYS else _mask(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_mask(item) for item in value]
    return value


def _comparable(path: Path) -> Any:
    """Return bytes, or masked content for files that carry run-time stamps."""
    if path.name.endswith(".jsonl"):
        return [_mask(json.loads(line)) for line in path.read_text().splitlines()]
    if path.name == "run-manifest.yaml":
        import yaml

        return _mask(yaml.safe_load(path.read_text()))
    return path.read_bytes()


def _run_sp1_slice(run_dir: Path, client: LLMClient) -> None:
    result = run_sp1(
        llm_client=client,
        use_case_text="Test use case",
        risk_cards=make_risk_cards(),
        run_dir=run_dir,
    )
    assert result.control_structure is not None


def test_recorded_sp1_run_replays_to_identical_outputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL", raising=False)
    provider = _ScriptedSP1Provider(setup_sp1_mock_client())
    _remember_response_format(monkeypatch, provider)

    first = tmp_path / "first"
    with provider_call_session(record_dir=first):
        _run_sp1_slice(first, _client(provider))
    assert provider.requests, "the scripted provider was never called"
    sent = len(provider.requests)

    second = tmp_path / "second"
    with provider_call_session(record_dir=second, replay_dir=first) as session:
        # Same settings as the recorded run; the SDK client is never used, and
        # the unreachable endpoint would fail the run if replay called it.
        _run_sp1_slice(second, _client(None))
        assert session.replayer is not None
        assert session.replayer.unmatched == []
        assert session.replayer.unused() == []

    assert len(provider.requests) == sent, "replay reached the provider"
    first_files = {p.relative_to(first) for p in first.rglob("*") if p.is_file()}
    second_files = {p.relative_to(second) for p in second.rglob("*") if p.is_file()}
    assert first_files == second_files
    assert Path("loss-analysis.yaml") in first_files
    assert Path(RECORD_FILENAME) in first_files
    for relative in sorted(first_files):
        assert _comparable(first / relative) == _comparable(second / relative), relative

    recorded = _records(first)
    assert len(recorded) == sent
    assert [r["request_sha256"] for r in recorded] == [
        r["request_sha256"] for r in _records(second)
    ]
    assert all(r["identity"] is not None for r in recorded)

    per_call = (first / RECORD_FILENAME).stat().st_size / sent
    print(
        f"\nprovider-calls.jsonl: {sent} calls, "
        f"{(first / RECORD_FILENAME).stat().st_size} bytes, {per_call:.0f} bytes/call"
    )


def test_canonical_request_converts_every_argument_to_json_data() -> None:
    request = canonical_request(
        "chat",
        {
            "model": "m",
            "messages": ({"role": "user", "content": "q"},),
            "response_format": _Answer,
            "seed_answer": _Answer(answer="a"),
            "metadata": {1: [None, 2.5, True], "path": Path("x/y")},
        },
    )

    assert request["messages"] == [{"role": "user", "content": "q"}]
    assert request["parameters"]["response_format"]["pydantic_model"] == "_Answer"
    assert request["parameters"]["seed_answer"] == {"answer": "a"}
    assert request["parameters"]["metadata"] == {"1": [None, 2.5, True], "path": "x/y"}


@pytest.mark.parametrize(
    ("response", "expected_choices"),
    [
        (
            SimpleNamespace(
                id="r-1",
                model="m",
                choices=[
                    SimpleNamespace(
                        finish_reason="stop", message=SimpleNamespace(content="hi")
                    )
                ],
                usage={"total_tokens": 3},
            ),
            [{"finish_reason": "stop", "message": {"content": "hi"}}],
        ),
        (
            SimpleNamespace(
                id="r-1", model="m", choices=None, usage={"total_tokens": 3}
            ),
            [],
        ),
    ],
    ids=["one-choice", "no-choices"],
)
def test_response_body_reads_sdk_like_objects_attribute_by_attribute(
    response: Any, expected_choices: list[Any]
) -> None:
    assert _response_body(response) == {
        "id": "r-1",
        "model": "m",
        "choices": expected_choices,
        "usage": {"total_tokens": 3},
    }


@pytest.mark.parametrize(
    "error",
    [
        {"type": "RateLimitError", "message": "busy", "status_code": None},
        {"type": "RateLimitError", "message": "busy", "status_code": "not-a-code"},
        {"type": "APIError", "message": "busy"},
        {"type": "TimeoutError", "message": "busy", "status_code": 504},
    ],
    ids=[
        "status-error-without-code",
        "unbuildable",
        "base-api-error",
        "builtin-with-code",
    ],
)
def test_a_recorded_error_that_cannot_be_rebuilt_replays_generically(
    error: dict[str, Any],
) -> None:
    rebuilt = _rebuild_error(error)

    assert type(rebuilt) is ReplayedProviderError
    assert rebuilt.recorded_type == error["type"]
