"""LLM adapter completion-length normalization tests."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from asago_scenario_generator.llm.client import (
    CompletionLengthError,
    LLMClient,
    LLMResult,
)


def _client() -> LLMClient:
    instance = LLMClient(base_url="http://test-endpoint.invalid")
    instance._client = MagicMock()
    return instance


def _usage(prompt_tokens: int, completion_tokens: int) -> MagicMock:
    return MagicMock(prompt_tokens=prompt_tokens, completion_tokens=completion_tokens)


def test_unstructured_stop_response_returns_content_and_usage() -> None:
    client = _client()
    response = MagicMock()
    response.choices[0].message.content = "raw text"
    response.choices[0].finish_reason = "stop"
    response.usage = _usage(7, 9)
    client._client.chat.completions.create.return_value = response

    result = client.complete(system_prompt="system", user_prompt="user")

    assert isinstance(result, LLMResult)
    assert result.content == "raw text"
    assert result.prompt_tokens == 7
    assert result.completion_tokens == 9
    assert result.duration_ms >= 0
    client._client.chat.completions.create.assert_called_once()
    assert client._client.beta.chat.completions.parse.call_count == 0


def test_unstructured_response_without_usage_degrades_to_zero() -> None:
    client = _client()
    response = MagicMock()
    response.choices[0].message.content = "raw text"
    response.choices[0].finish_reason = "stop"
    response.usage = None
    client._client.chat.completions.create.return_value = response

    result = client.complete(system_prompt="system", user_prompt="user")

    assert result.prompt_tokens == 0
    assert result.completion_tokens == 0


def test_unstructured_length_finish_reason_raises_typed_error() -> None:
    client = _client()
    response = MagicMock()
    response.choices[0].message.content = "truncated"
    response.choices[0].finish_reason = "length"
    response.usage = _usage(31, 16)
    client._client.chat.completions.create.return_value = response

    with pytest.raises(CompletionLengthError) as raised:
        client.complete(system_prompt="system", user_prompt="user")

    assert raised.value.finish_reason == "length"
    assert raised.value.prompt_tokens == 31
    assert raised.value.completion_tokens == 16
    assert client._client.chat.completions.create.call_count == 1


def test_unstructured_length_without_usage_degrades_to_zero() -> None:
    client = _client()
    response = MagicMock()
    response.choices[0].message.content = "truncated"
    response.choices[0].finish_reason = "length"
    response.usage = None
    client._client.chat.completions.create.return_value = response

    with pytest.raises(CompletionLengthError) as raised:
        client.complete(system_prompt="system", user_prompt="user")

    assert raised.value.prompt_tokens == 0
    assert raised.value.completion_tokens == 0


def test_structured_sdk_length_error_is_normalized_typed() -> None:
    from openai import LengthFinishReasonError

    client = _client()
    client._client.beta.chat.completions.parse.side_effect = LengthFinishReasonError(
        completion=MagicMock(usage=_usage(41, 22))
    )

    with pytest.raises(CompletionLengthError) as raised:
        client.complete(
            system_prompt="system",
            user_prompt="user",
            response_format=MagicMock,
        )

    assert raised.value.finish_reason == "length"
    assert raised.value.prompt_tokens == 41
    assert raised.value.completion_tokens == 22
    client._client.beta.chat.completions.parse.assert_called_once()
    assert client._client.chat.completions.create.call_count == 0


def test_explicit_completion_limit_is_forwarded_to_the_provider() -> None:
    client = _client()
    response = MagicMock()
    response.choices[0].message.content = "raw text"
    response.choices[0].finish_reason = "stop"
    response.usage = _usage(1, 1)
    client._client.chat.completions.create.return_value = response

    client.complete(
        system_prompt="system", user_prompt="user", max_completion_tokens=16384
    )

    kwargs = client._client.chat.completions.create.call_args.kwargs
    assert kwargs["max_completion_tokens"] == 16384
    assert kwargs["model"] == "gemma-3n-e4b-it"


def test_client_requires_a_configured_endpoint(monkeypatch) -> None:
    monkeypatch.delenv("ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL", raising=False)

    with pytest.raises(ValueError, match="No LLM endpoint configured"):
        LLMClient(base_url=None)


def test_structured_response_returns_parsed_content() -> None:
    client = _client()
    parsed = object()
    response = MagicMock()
    response.choices[0].message.parsed = parsed
    response.choices[0].finish_reason = "stop"
    response.usage = _usage(4, 2)
    client._client.beta.chat.completions.parse.return_value = response

    result = client.complete(
        system_prompt="system", user_prompt="user", response_format=MagicMock
    )

    assert result.content is parsed
    assert result.prompt_tokens == 4
    assert result.completion_tokens == 2
    client._client.beta.chat.completions.parse.assert_called_once()
    assert client._client.chat.completions.create.call_count == 0
