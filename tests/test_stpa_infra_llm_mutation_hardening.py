"""Mutation hardening tests for ``asago_scenario_generator.stpa.infra.llm``.

Targets the surviving mutants identified by mutate4py on the STPA
infrastructure LLM client. Each test pins a behaviour that would break
if the corresponding mutant were applied.
"""

from __future__ import annotations

import os
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from pydantic import BaseModel

from asago_scenario_generator.stpa.infra.llm import (
    LLMClient,
    _apply_legacy_json_fallback,
    _guided_json_enabled,
    _guided_json_extra_body,
    _resolve_api_key,
    _resolve_base_url,
    _resolve_model,
    _top_k_extra_body,
)


# -- shared fixtures ------------------------------------------------------


class _Schema(BaseModel):
    """A trivial pydantic model used as a ``response_format`` stand-in."""

    value: str


def _make_client(**kwargs) -> LLMClient:
    """Build an ``LLMClient`` with a mocked OpenAI SDK transport.

    All environment-driven resolution is bypassed by passing explicit
    constructor arguments; the underlying ``OpenAI`` client is replaced
    with a ``MagicMock`` so no network call can escape.
    """
    base_url = kwargs.pop("base_url", "http://test-endpoint.invalid")
    client = LLMClient(base_url=base_url, api_key="test-key", model="test-model", **kwargs)
    client._client = MagicMock()
    return client


# -- _resolve_base_url ---------------------------------------------------


class TestResolveBaseUrl:
    def test_explicit_wins_over_env(self) -> None:
        with patch.dict(os.environ, {"ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL": "http://env.invalid"}):
            assert _resolve_base_url("http://explicit.invalid") == "http://explicit.invalid"

    def test_env_used_when_explicit_none(self) -> None:
        with patch.dict(os.environ, {"ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL": "http://env.invalid"}):
            assert _resolve_base_url(None) == "http://env.invalid"

    def test_none_when_both_unset(self) -> None:
        env = {k: v for k, v in os.environ.items()
               if k != "ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL"}
        with patch.dict(os.environ, env, clear=True):
            assert _resolve_base_url(None) is None


# -- _resolve_api_key -----------------------------------------------------


class TestResolveApiKey:
    def test_explicit_wins_over_default(self) -> None:
        env = {k: v for k, v in os.environ.items()
               if k != "ASAGO_SCENARIO_GENERATOR_API_KEY"}
        with patch.dict(os.environ, env, clear=True):
            assert _resolve_api_key("mykey") == "mykey"

    def test_env_used_when_explicit_none(self) -> None:
        with patch.dict(os.environ, {"ASAGO_SCENARIO_GENERATOR_API_KEY": "envkey"}):
            assert _resolve_api_key(None) == "envkey"

    def test_default_unused_when_explicit_none_and_env_unset(self) -> None:
        env = {k: v for k, v in os.environ.items()
               if k != "ASAGO_SCENARIO_GENERATOR_API_KEY"}
        with patch.dict(os.environ, env, clear=True):
            assert _resolve_api_key(None) == "unused"


# -- _resolve_model ------------------------------------------------------


class TestResolveModel:
    def test_explicit_wins_over_default(self) -> None:
        env = {k: v for k, v in os.environ.items()
               if k != "ASAGO_SCENARIO_GENERATOR_MODEL_NAME"}
        with patch.dict(os.environ, env, clear=True):
            assert _resolve_model("mymodel") == "mymodel"

    def test_env_used_when_explicit_none(self) -> None:
        with patch.dict(os.environ, {"ASAGO_SCENARIO_GENERATOR_MODEL_NAME": "envmodel"}):
            assert _resolve_model(None) == "envmodel"

    def test_default_when_explicit_none_and_env_unset(self) -> None:
        env = {k: v for k, v in os.environ.items()
               if k != "ASAGO_SCENARIO_GENERATOR_MODEL_NAME"}
        with patch.dict(os.environ, env, clear=True):
            assert _resolve_model(None) == "gemma-3n-e4b-it"


# -- _guided_json_enabled ------------------------------------------------


class TestGuidedJsonEnabled:
    def test_all_true_returns_true(self) -> None:
        assert _guided_json_enabled(True, True, _Schema) is True

    def test_none_response_format_returns_false(self) -> None:
        assert _guided_json_enabled(True, True, None) is False

    def test_use_false_returns_false(self) -> None:
        assert _guided_json_enabled(False, True, _Schema) is False

    def test_allow_false_returns_false(self) -> None:
        assert _guided_json_enabled(True, False, _Schema) is False

    def test_all_false_returns_false(self) -> None:
        assert _guided_json_enabled(False, False, None) is False


# -- _apply_legacy_json_fallback -----------------------------------------


class TestApplyLegacyJsonFallback:
    def test_sets_key_when_all_conditions(self) -> None:
        extra: dict = {}
        _apply_legacy_json_fallback(extra, True, _Schema, False)
        assert extra == {"response_format": {"type": "json_object"}}

    def test_no_set_when_response_format_none(self) -> None:
        extra: dict = {}
        _apply_legacy_json_fallback(extra, True, None, False)
        assert extra == {}

    def test_no_set_when_allow_false(self) -> None:
        extra: dict = {}
        _apply_legacy_json_fallback(extra, False, _Schema, False)
        assert extra == {}

    def test_no_set_when_use_guided_true(self) -> None:
        extra: dict = {}
        _apply_legacy_json_fallback(extra, True, _Schema, True)
        assert extra == {}

    def test_no_set_when_all_false(self) -> None:
        extra: dict = {}
        _apply_legacy_json_fallback(extra, False, None, True)
        assert extra == {}


# -- _top_k_extra_body ----------------------------------------------------


class TestTopKExtraBody:
    def test_none_returns_empty(self) -> None:
        assert _top_k_extra_body(None) == {}

    def test_value_returns_dict(self) -> None:
        assert _top_k_extra_body(5) == {"top_k": 5}


# -- _guided_json_extra_body ---------------------------------------------


class TestGuidedJsonExtraBody:
    def test_returns_schema_when_enabled(self) -> None:
        result = _guided_json_extra_body(True, _Schema)
        assert result == {"guided_json": _Schema.model_json_schema()}

    def test_empty_when_no_response_format(self) -> None:
        assert _guided_json_extra_body(True, None) == {}

    def test_empty_when_disabled(self) -> None:
        assert _guided_json_extra_body(False, _Schema) == {}

    def test_empty_when_both_false(self) -> None:
        assert _guided_json_extra_body(False, None) == {}


# -- LLMClient._build_extra_kwargs ---------------------------------------


class TestBuildExtraKwargs:
    def test_max_tokens_set_when_provided(self) -> None:
        client = _make_client()
        kwargs = client._build_extra_kwargs(100, 0.5)
        assert kwargs["max_completion_tokens"] == 100

    def test_max_tokens_omitted_when_none(self) -> None:
        client = _make_client()
        kwargs = client._build_extra_kwargs(None, 0.5)
        assert "max_completion_tokens" not in kwargs

    def test_top_p_set_when_provided(self) -> None:
        client = _make_client(top_p=0.5)
        kwargs = client._build_extra_kwargs(None, 0.5)
        assert kwargs["top_p"] == 0.5

    def test_top_p_omitted_when_none(self) -> None:
        client = _make_client(top_p=None)
        kwargs = client._build_extra_kwargs(None, 0.5)
        assert "top_p" not in kwargs

    def test_temperature_always_set(self) -> None:
        client = _make_client()
        kwargs = client._build_extra_kwargs(None, 0.7)
        assert kwargs["temperature"] == 0.7

    def test_extra_body_includes_top_k(self) -> None:
        client = _make_client(top_k=10)
        kwargs = client._build_extra_kwargs(None, 0.5)
        assert kwargs["extra_body"] == {"top_k": 10}

    def test_extra_body_includes_guided_json(self) -> None:
        client = _make_client()
        kwargs = client._build_extra_kwargs(None, 0.5, _Schema, use_guided_json=True)
        assert kwargs["extra_body"] == {"guided_json": _Schema.model_json_schema()}

    def test_no_extra_body_when_empty(self) -> None:
        client = _make_client()
        kwargs = client._build_extra_kwargs(None, 0.5)
        assert "extra_body" not in kwargs


# -- LLMClient._request_completion ---------------------------------------


def _parse_response(parsed: object) -> MagicMock:
    response = MagicMock()
    response.choices = [SimpleNamespace(message=SimpleNamespace(parsed=parsed, content="raw"))]
    return response


def _create_response(content: str) -> MagicMock:
    response = MagicMock()
    response.usage = SimpleNamespace(prompt_tokens=3, completion_tokens=4)
    response.choices = [SimpleNamespace(message=SimpleNamespace(content=content))]
    return response


class TestRequestCompletion:
    def test_parse_branch_returns_parsed(self) -> None:
        client = _make_client()
        client._client.beta.chat.completions.parse.return_value = _parse_response("parsed-content")
        response, content = client._request_completion(
            [{"role": "user", "content": "hi"}], _Schema, {}, allow_unvalidated=False
        )
        assert content == "parsed-content"
        client._client.beta.chat.completions.parse.assert_called_once()
        client._client.chat.completions.create.assert_not_called()

    def test_create_branch_when_allow_unvalidated(self) -> None:
        client = _make_client()
        client._client.chat.completions.create.return_value = _create_response("raw-text")
        response, content = client._request_completion(
            [{"role": "user", "content": "hi"}], _Schema, {}, allow_unvalidated=True
        )
        assert content == "raw-text"
        client._client.chat.completions.create.assert_called_once()
        client._client.beta.chat.completions.parse.assert_not_called()

    def test_create_branch_when_no_response_format(self) -> None:
        client = _make_client()
        client._client.chat.completions.create.return_value = _create_response("raw-text")
        response, content = client._request_completion(
            [{"role": "user", "content": "hi"}], None, {}, allow_unvalidated=False
        )
        assert content == "raw-text"
        client._client.chat.completions.create.assert_called_once()
        client._client.beta.chat.completions.parse.assert_not_called()

    def test_create_branch_when_no_response_format_unvalidated(self) -> None:
        client = _make_client()
        client._client.chat.completions.create.return_value = _create_response("raw-text")
        response, content = client._request_completion(
            [{"role": "user", "content": "hi"}], None, {}, allow_unvalidated=True
        )
        assert content == "raw-text"
        client._client.chat.completions.create.assert_called_once()
        client._client.beta.chat.completions.parse.assert_not_called()

    def test_parse_branch_uses_first_choice(self) -> None:
        """Mutant ``choices[0] -> choices[1]`` must raise on a single choice."""
        client = _make_client()
        client._client.beta.chat.completions.parse.return_value = _parse_response("parsed")
        response, content = client._request_completion(
            [{"role": "user", "content": "hi"}], _Schema, {}, allow_unvalidated=False
        )
        assert content == "parsed"

    def test_create_branch_uses_first_choice(self) -> None:
        """Mutant ``choices[0] -> choices[1]`` must raise on a single choice."""
        client = _make_client()
        client._client.chat.completions.create.return_value = _create_response("raw")
        response, content = client._request_completion(
            [{"role": "user", "content": "hi"}], None, {}, allow_unvalidated=False
        )
        assert content == "raw"


class TestComplete:
    def test_explicit_controls_override_client_defaults(self) -> None:
        """Explicit max tokens and temperature must reach the provider call."""
        client = _make_client(max_completion_tokens=200, temperature=0.2)
        client._client.chat.completions.create.return_value = _create_response("raw")

        with patch(
            "asago_scenario_generator.stpa.infra.llm.time.perf_counter_ns",
            side_effect=[1_000_000_000, 1_123_000_000],
        ):
            result = client.complete(
                "system",
                "user",
                max_completion_tokens=100,
                temperature=0.7,
            )

        kwargs = client._client.chat.completions.create.call_args.kwargs
        assert kwargs["max_completion_tokens"] == 100
        assert kwargs["temperature"] == 0.7
        assert result.duration_ms == 123
