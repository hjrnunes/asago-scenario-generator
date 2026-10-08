"""Offline regression tests for OpenAI reasoning-profile behavior."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import httpx
import pytest
from openai import RateLimitError
from pydantic import BaseModel

from tests.helpers.calls_log import read_calls_jsonl
from asago_scenario_generator.model_profiles import reasoning_completion_cap
from asago_scenario_generator.stpa.infra.llm import LLMClient
from asago_scenario_generator.stpa.infra.llm_helpers import (
    CorrectionPolicy,
    call_with_policy,
)


class _NestedModel(BaseModel):
    name: str
    count: int = 3


class _ProfileResponse(BaseModel):
    required: str
    nested: _NestedModel
    optional: str = "default"
    maybe: _NestedModel | None = None
    items: list[_NestedModel] = []
    maybe_items: list[_NestedModel] | None = None
    maybe_map: dict[str, _NestedModel] | None = None


def _response(
    content: str = '{"required":"ok","nested":{"name":"n","count":null}}',
    *,
    finish_reason: str = "stop",
    reasoning_tokens: int | None = None,
) -> SimpleNamespace:
    details = (
        SimpleNamespace(reasoning_tokens=reasoning_tokens)
        if reasoning_tokens is not None
        else None
    )
    usage = SimpleNamespace(
        prompt_tokens=11,
        completion_tokens=7,
        completion_tokens_details=details,
    )
    return SimpleNamespace(
        choices=[
            SimpleNamespace(
                finish_reason=finish_reason,
                message=SimpleNamespace(content=content, parsed=None),
            )
        ],
        usage=usage,
    )


def _rate_limit(status: int = 429) -> RateLimitError:
    request = httpx.Request("POST", "https://api.openai.com/v1/chat/completions")
    return RateLimitError(
        "rate limited",
        response=httpx.Response(status, request=request),
        body={"error": {"message": "rate limited"}},
    )


def _infra_client(**kwargs) -> LLMClient:
    with patch("asago_scenario_generator.stpa.infra.llm.OpenAI"):
        client = LLMClient(base_url="https://api.openai.com/v1", **kwargs)
    client._client = MagicMock()
    return client


def test_existing_sampling_kwargs_remain_byte_identical() -> None:
    """A legacy local profile keeps the pre-profile request shape."""
    client = _infra_client(top_p=0.9, top_k=40, seed=123, enable_thinking=False)

    assert client._build_extra_kwargs(8192, 0.4) == {
        "temperature": 0.4,
        "max_completion_tokens": 8192,
        "top_p": 0.9,
        "seed": 123,
        "extra_body": {
            "top_k": 40,
            "chat_template_kwargs": {"enable_thinking": False},
        },
    }


def test_reasoning_and_service_tier_are_top_level_request_kwargs() -> None:
    client = _infra_client(
        reasoning_effort="medium",
        service_tier="flex",
    )
    client._client.chat.completions.create.return_value = _response(
        '{"required":"ok","nested":{"name":"n"}}'
    )

    client.complete("system", "user", response_format=_ProfileResponse)

    sent = client._client.chat.completions.create.call_args.kwargs
    assert sent["reasoning_effort"] == "medium"
    assert sent["service_tier"] == "flex"


@pytest.mark.parametrize(
    ("requested", "profile_cap", "effort", "expected"),
    [
        (8192, 32000, "medium", 32000),
        (64000, 32000, "medium", 64000),
        (None, 32000, "medium", 32000),
        (8192, 32000, None, 8192),
        (None, 8192, None, None),
        (8192, None, "medium", 8192),
    ],
)
def test_reasoning_completion_cap(requested, profile_cap, effort, expected) -> None:
    assert (
        reasoning_completion_cap(
            requested, profile_cap=profile_cap, reasoning_effort=effort
        )
        == expected
    )


def test_reasoning_profile_raises_call_site_cap() -> None:
    client = _infra_client(max_completion_tokens=32000, reasoning_effort="medium")
    client._client.chat.completions.create.return_value = _response("text")
    client.complete("system", "user", max_completion_tokens=8192)
    sent = client._client.chat.completions.create.call_args.kwargs
    assert sent["max_completion_tokens"] == 32000


def test_call_site_cap_wins_without_reasoning_effort() -> None:
    client = _infra_client(max_completion_tokens=32000)
    client._client.chat.completions.create.return_value = _response("text")
    client.complete("system", "user", max_completion_tokens=8192)
    sent = client._client.chat.completions.create.call_args.kwargs
    assert sent["max_completion_tokens"] == 8192


def test_sampling_controls_false_drops_all_sampling_overrides() -> None:
    client = _infra_client(
        temperature=0.2,
        top_p=0.1,
        top_k=2,
        seed=8,
        enable_thinking=True,
        sampling_controls=False,
    )
    client._client.chat.completions.create.return_value = _response("text")

    client.complete("system", "user", temperature=0.0)

    sent = client._client.chat.completions.create.call_args.kwargs
    assert not {
        "temperature",
        "top_p",
        "top_k",
        "seed",
        "chat_template_kwargs",
    } & set(sent)
    assert "extra_body" not in sent


def test_service_tier_fallback_retries_once_and_records_usage() -> None:
    client = _infra_client(
        service_tier="flex",
        service_tier_fallback="default",
    )
    client._client.chat.completions.create.side_effect = [
        _rate_limit(),
        _response('{"required":"ok","nested":{"name":"n"}}'),
    ]

    result = client.complete("system", "user", response_format=_ProfileResponse)

    calls = client._client.chat.completions.create.call_args_list
    assert len(calls) == 2
    assert calls[0].kwargs["service_tier"] == "flex"
    assert calls[1].kwargs["service_tier"] == "default"
    assert result.request_controls["service_tier_fallback_used"] is True
    assert result.request_controls["service_tier_original"] == "flex"
    assert result.request_controls["service_tier_fallback"] == "default"


@pytest.mark.parametrize(
    ("kwargs", "error"),
    [
        ({"service_tier_fallback": "default"}, _rate_limit()),
        ({"service_tier": "flex"}, _rate_limit()),
    ],
)
def test_service_tier_fallback_is_not_used_without_a_429_pair(kwargs, error) -> None:
    client = _infra_client(**kwargs)
    client._client.chat.completions.create.side_effect = error

    with pytest.raises(RateLimitError):
        client.complete("system", "user")

    assert client._client.chat.completions.create.call_count == 1


def test_a_5xx_gets_the_transport_retry_on_the_same_tier_not_the_fallback() -> None:
    client = _infra_client(service_tier="flex", service_tier_fallback="default")
    client._client.chat.completions.create.side_effect = _rate_limit(500)

    with pytest.raises(RateLimitError):
        client.complete("system", "user")

    calls = client._client.chat.completions.create.call_args_list
    assert [call.kwargs["service_tier"] for call in calls] == ["flex", "flex"]


def test_strict_json_schema_true_fails_at_client_construction() -> None:
    with pytest.raises(ValueError, match="strict_json_schema"):
        _infra_client(strict_json_schema=True)


@pytest.mark.parametrize("value", [None, False])
def test_strict_json_schema_false_is_accepted_and_recorded_as_false(value) -> None:
    client = _infra_client(strict_json_schema=value)
    client._client.chat.completions.create.return_value = _response(
        '{"required":"ok","nested":{"name":"n"}}'
    )

    result = client.complete("system", "user", response_format=_ProfileResponse)

    sent = client._client.chat.completions.create.call_args.kwargs
    assert sent["response_format"]["json_schema"]["strict"] is True
    assert "default" in str(sent["response_format"]["json_schema"]["schema"])
    assert result.request_controls["strict_json_schema"] is False


def test_non_strict_schema_uses_original_schema_and_local_validation() -> None:
    client = _infra_client(json_schema_strict=False)
    client._client.chat.completions.create.return_value = _response(
        '{"required":"ok","nested":{"name":"n"}}'
    )

    result = client.complete("system", "user", response_format=_ProfileResponse)

    sent = client._client.chat.completions.create.call_args.kwargs
    assert sent["response_format"] == {
        "type": "json_schema",
        "json_schema": {
            "name": "_ProfileResponse",
            "strict": False,
            "schema": _ProfileResponse.model_json_schema(),
        },
    }
    assert result.content == _ProfileResponse(
        required="ok",
        nested=_NestedModel(name="n"),
    )
    assert result.raw_response == '{"required":"ok","nested":{"name":"n"}}'
    assert result.request_controls["json_schema_strict"] is False


def test_non_strict_schema_does_not_accept_invalid_local_content(tmp_path) -> None:
    client = _infra_client(json_schema_strict=False)
    client._client.chat.completions.create.return_value = _response(
        '{"required":"ok","nested":{"name":"n"},"optional":null}'
    )

    outcome = call_with_policy(
        llm_client=client,
        system_prompt="system",
        user_prompt="user",
        response_format=_ProfileResponse,
        run_dir=tmp_path,
        stage="test",
        step="non_strict_validation",
        policy=CorrectionPolicy(),
    )
    result, provider_result, error = outcome.value, outcome.result, outcome.error

    assert result is None
    assert provider_result is not None
    assert error is not None
    assert "optional" in error


def test_openrouter_keeps_json_object_compatibility_for_structured_calls() -> None:
    client = _infra_client()
    client.base_url = "https://openrouter.ai/api/v1"
    client._client.chat.completions.create.return_value = _response(
        '{"required":"ok","nested":{"name":"n"}}'
    )

    result = client.complete("system", "user", response_format=_ProfileResponse)

    sent = client._client.chat.completions.create.call_args.kwargs
    assert sent["response_format"] == {"type": "json_object"}
    assert isinstance(result.content, str)


def test_reasoning_length_failure_is_logged_with_reasoning_usage(tmp_path) -> None:
    client = _infra_client(
        reasoning_effort="medium",
        service_tier="flex",
        max_completion_tokens=32,
    )
    client._client.chat.completions.create.return_value = _response(
        "",
        finish_reason="length",
        reasoning_tokens=29,
    )

    outcome = call_with_policy(
        llm_client=client,
        system_prompt="system",
        user_prompt="user",
        response_format=_ProfileResponse,
        run_dir=tmp_path,
        stage="test",
        step="reasoning",
        policy=CorrectionPolicy(),
    )
    result, error = outcome.value, outcome.error

    assert result is None
    assert error is not None
    entry = read_calls_jsonl(tmp_path)[0]
    assert entry["usage"]["completion_tokens_details"]["reasoning_tokens"] == 29
    assert entry["provider_response_received"] is True


def test_stpa_nonempty_length_content_keeps_historical_handling() -> None:
    client = _infra_client()
    client._client.chat.completions.create.return_value = _response(
        '{"required":"ok","nested":{"name":"n"}}',
        finish_reason="length",
    )

    result = client.complete("system", "user", response_format=_ProfileResponse)

    assert result.content == _ProfileResponse(
        required="ok",
        nested=_NestedModel(name="n"),
    )
