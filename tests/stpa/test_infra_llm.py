"""Tests for STPA infra LLM client (InfraLLM-01 through InfraLLM-07)."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from pydantic import BaseModel

from asago_scenario_generator.stpa.infra.llm import (
    LLMClient,
    LLMResult,
    _apply_legacy_json_fallback,
    _guided_json_enabled,
    _json_schema_response_format,
    _prompt_messages,
    _resolve_api_key,
    _resolve_base_url,
    _resolve_model,
    _thinking_extra_body,
    _token_usage,
    _top_k_extra_body,
)


class _OpenRouterPayload(BaseModel):
    exact_field: str


class TestInfraLLMClient:
    """LLM client construction and configuration."""

    def test_llm_01_resolves_base_url_from_env(self, monkeypatch):
        """InfraLLM-01: base_url resolved from ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL."""
        monkeypatch.setenv(
            "ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL", "http://test:8080"
        )
        monkeypatch.delenv("ASAGO_SCENARIO_GENERATOR_API_KEY", raising=False)
        client = LLMClient()
        assert client.base_url == "http://test:8080"

    def test_llm_02_resolves_model_from_env(self, monkeypatch):
        """InfraLLM-02: model name resolved from ASAGO_SCENARIO_GENERATOR_MODEL_NAME."""
        monkeypatch.setenv("ASAGO_SCENARIO_GENERATOR_MODEL_NAME", "test-model")
        client = LLMClient(base_url="http://test:8080")
        assert client.model == "test-model"

    def test_llm_03_explicit_args_override_env(self, monkeypatch):
        """InfraLLM-03: explicit args override environment variables."""
        monkeypatch.setenv("ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL", "http://env:8080")
        client = LLMClient(base_url="http://explicit:8080", model="explicit-model")
        assert client.base_url == "http://explicit:8080"
        assert client.model == "explicit-model"

    def test_llm_04_without_base_url_raises_value_error(self, monkeypatch):
        """InfraLLM-04: no base_url raises ValueError with expected message."""
        monkeypatch.delenv("ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL", raising=False)
        with pytest.raises(ValueError, match="No LLM endpoint configured"):
            LLMClient()

    def test_llm_05_auto_injects_openrouter_headers(self, monkeypatch):
        """InfraLLM-05: OpenRouter base_url triggers default header injection."""
        monkeypatch.delenv("ASAGO_SCENARIO_GENERATOR_EXTRA_HEADERS", raising=False)
        client = LLMClient(base_url="https://openrouter.ai/api/v1")
        assert client.extra_headers is not None
        assert "HTTP-Referer" in client.extra_headers
        assert "X-Title" in client.extra_headers

    def test_llm_06_default_temperature_is_0_4(self, monkeypatch):
        """InfraLLM-06: default temperature is 0.4."""
        monkeypatch.delenv("ASAGO_SCENARIO_GENERATOR_TEMPERATURE", raising=False)
        client = LLMClient(base_url="http://test:8080")
        assert client.temperature == 0.4

    def test_llm_06a_explicit_max_tokens_override_env(self, monkeypatch):
        """InfraLLM-06a: explicit max_completion_tokens overrides env var."""
        monkeypatch.setenv("ASAGO_SCENARIO_GENERATOR_MAX_COMPLETION_TOKENS", "2000")
        client = LLMClient(base_url="http://test:8080", max_completion_tokens=500)
        assert client.max_completion_tokens == 500

    def test_llm_06b_max_tokens_from_env_when_not_explicit(self, monkeypatch):
        """InfraLLM-06b: max_completion_tokens resolved from env when not explicit."""
        monkeypatch.setenv("ASAGO_SCENARIO_GENERATOR_MAX_COMPLETION_TOKENS", "2000")
        client = LLMClient(base_url="http://test:8080")
        assert client.max_completion_tokens == 2000

    def test_llm_06c_max_tokens_none_when_unspecified(self, monkeypatch):
        """InfraLLM-06c: max_completion_tokens is None when not specified."""
        monkeypatch.delenv(
            "ASAGO_SCENARIO_GENERATOR_MAX_COMPLETION_TOKENS", raising=False
        )
        client = LLMClient(base_url="http://test:8080")
        assert client.max_completion_tokens is None


class TestInfraLLMResult:
    """LLMResult data model."""

    def test_llm_07_result_carries_content_and_telemetry(self):
        """InfraLLM-07: LLMResult carries content and usage telemetry."""
        result = LLMResult(
            content="text",
            prompt_tokens=100,
            completion_tokens=50,
            duration_ms=5000,
        )
        assert result.content == "text"
        assert result.prompt_tokens == 100
        assert result.completion_tokens == 50
        assert result.duration_ms == 5000


class TestInfraLLMComplete:
    """LLMClient.complete method with mocked OpenAI client."""

    def _make_mock_client(
        self,
        content="response",
        prompt_tokens=100,
        completion_tokens=50,
        usage="default",
    ):
        """Build a mock OpenAI client with a canned response."""
        client = LLMClient(base_url="http://test:8080", model="test-model")

        mock_msg = MagicMock()
        mock_msg.content = content

        mock_choice = MagicMock()
        mock_choice.message = mock_msg

        mock_response = MagicMock()
        mock_response.choices = [mock_choice]
        if usage == "default":
            mock_response.usage = MagicMock(
                prompt_tokens=prompt_tokens, completion_tokens=completion_tokens
            )
        elif usage is None:
            mock_response.usage = None
        else:
            mock_response.usage = usage

        client._client = MagicMock()
        client._client.chat.completions.create.return_value = mock_response
        return client

    def test_complete_unstructured_returns_content(self):
        """Complete without response_format returns plain content."""
        client = self._make_mock_client(content="hello world")
        result = client.complete("system", "user")
        assert result.content == "hello world"
        assert result.system_prompt == "system"
        assert result.user_prompt == "user"
        assert result.duration_ms >= 0
        assert result.duration_ms < 60000

    def test_strict_completion_rejects_a_non_pydantic_response_format(self):
        """A strict structured request needs a Pydantic schema; none is sent."""
        client = self._make_mock_client()

        with pytest.raises(TypeError, match="Pydantic model class"):
            client.complete("system", "user", response_format=dict)

        assert not client._client.method_calls

    def test_complete_allow_unvalidated_uses_raw_content(self):
        """Unvalidated structured calls return raw JSON for post-processing."""
        client = self._make_mock_client(content='{"key": "value"}')
        result = client.complete(
            "system",
            "user",
            response_format=dict,
            allow_unvalidated=True,
        )
        assert result.content == '{"key": "value"}'
        assert client._client.chat.completions.create.called
        assert client._client.chat.completions.create.call_args.kwargs[
            "response_format"
        ] == {"type": "json_object"}

    def test_qwen_controls_use_supported_request_body(self):
        """Thinking and strict output use the vLLM-supported request fields."""
        client = self._make_mock_client(content='{"exact_field": "value"}')
        client.enable_thinking = False
        client.use_guided_decoding = True

        client.complete(
            "system",
            "user",
            response_format=_OpenRouterPayload,
            allow_unvalidated=True,
        )

        sent = client._client.chat.completions.create.call_args.kwargs
        assert sent["extra_body"] == {
            "chat_template_kwargs": {"enable_thinking": False}
        }
        assert sent["response_format"]["type"] == "json_schema"
        assert "guided_json" not in sent["extra_body"]

    def test_gemma_compatible_request_omits_thinking_control(self):
        """Profiles without the switch keep their existing request shape."""
        client = self._make_mock_client(content="response")
        client.top_k = 64

        client.complete("system", "user")

        sent = client._client.chat.completions.create.call_args.kwargs
        assert sent["extra_body"] == {"top_k": 64}
        assert "chat_template_kwargs" not in sent["extra_body"]

    def test_openrouter_structured_completion_uses_json_object_compatibility(self):
        """OpenRouter structured output uses JSON-object mode."""
        client = self._make_mock_client(content='{"key": "value"}')
        client.base_url = "https://openrouter.ai/api/v1"

        result = client.complete("system", "user", response_format=dict)

        assert result.content == '{"key": "value"}'
        assert client._client.chat.completions.create.call_args.kwargs[
            "response_format"
        ] == {"type": "json_object"}

    def test_openrouter_structured_prompt_carries_exact_schema(self):
        """Portable JSON mode still gives the model the exact field contract."""
        client = self._make_mock_client(content='{"exact_field": "value"}')
        client.base_url = "https://openrouter.ai/api/v1"

        result = client.complete("system", "user", response_format=_OpenRouterPayload)

        sent_user_prompt = client._client.chat.completions.create.call_args.kwargs[
            "messages"
        ][1]["content"]
        assert "Use the property names exactly as written" in sent_user_prompt
        assert '"exact_field"' in sent_user_prompt
        assert result.user_prompt == sent_user_prompt

    def test_complete_passes_effective_max_tokens(self):
        """Complete passes max_completion_tokens to the API."""
        client = self._make_mock_client()
        client.complete("s", "u", max_completion_tokens=500)
        call_kwargs = client._client.chat.completions.create.call_args
        assert call_kwargs.kwargs["max_completion_tokens"] == 500

    def test_complete_passes_effective_temperature(self):
        """Complete passes temperature to the API."""
        client = self._make_mock_client()
        client.complete("s", "u", temperature=0.9)
        call_kwargs = client._client.chat.completions.create.call_args
        assert call_kwargs.kwargs["temperature"] == 0.9

    def test_complete_uses_default_max_tokens_when_not_explicit(self):
        """Complete uses self.max_completion_tokens when not passed explicitly."""
        client = self._make_mock_client()
        client.max_completion_tokens = 2000
        client.complete("s", "u")
        call_kwargs = client._client.chat.completions.create.call_args
        assert call_kwargs.kwargs["max_completion_tokens"] == 2000

    def test_complete_omits_max_tokens_when_none(self):
        """Complete omits max_completion_tokens when both explicit and default are None."""
        client = self._make_mock_client()
        client.max_completion_tokens = None
        client.complete("s", "u")
        call_kwargs = client._client.chat.completions.create.call_args
        assert "max_completion_tokens" not in call_kwargs.kwargs

    def test_complete_returns_telemetry_from_usage(self):
        """Complete returns prompt_tokens and completion_tokens from usage."""
        client = self._make_mock_client(
            usage=MagicMock(prompt_tokens=200, completion_tokens=100)
        )
        result = client.complete("s", "u")
        assert result.prompt_tokens == 200
        assert result.completion_tokens == 100

    def test_complete_handles_missing_usage(self):
        """Complete preserves missing provider usage as unavailable."""
        client = self._make_mock_client(usage=None)
        result = client.complete("s", "u")
        assert result.prompt_tokens is None
        assert result.completion_tokens is None


class TestInfraLLMHelpers:
    """Decomposed request plumbing helpers (InfraLLM-H01 onward)."""

    def test_prompt_messages_builds_pair(self):
        """_prompt_messages returns the standard system+user pair."""
        assert _prompt_messages("sys", "usr") == [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "usr"},
        ]

    @pytest.mark.parametrize(
        ("use_guided", "allow_unvalidated", "schema", "expected"),
        [
            (True, True, _OpenRouterPayload, True),
            (True, True, None, False),
            (False, True, _OpenRouterPayload, False),
            (True, False, _OpenRouterPayload, False),
            (False, False, None, False),
        ],
        ids=["all_three", "no_schema", "no_decoding", "validated", "none"],
    )
    def test_guided_json_enabled_requires_all_three(
        self, use_guided, allow_unvalidated, schema, expected
    ):
        """_guided_json_enabled needs decoding, unvalidated, and a schema."""
        assert _guided_json_enabled(use_guided, allow_unvalidated, schema) is expected

    @pytest.mark.parametrize(
        ("allow_unvalidated", "schema", "use_guided", "expected"),
        [
            (
                True,
                _OpenRouterPayload,
                False,
                {"response_format": {"type": "json_object"}},
            ),
            (
                True,
                _OpenRouterPayload,
                True,
                {"response_format": _json_schema_response_format(_OpenRouterPayload)},
            ),
            (True, None, False, {}),
            (False, _OpenRouterPayload, False, {}),
            (False, None, True, {}),
        ],
        ids=[
            "json_object",
            "json_schema_when_guided",
            "no_schema",
            "validated",
            "none",
        ],
    )
    def test_apply_legacy_json_fallback(
        self, allow_unvalidated, schema, use_guided, expected
    ):
        """The fallback adds a response format only for unvalidated structured calls."""
        kwargs: dict = {}
        _apply_legacy_json_fallback(kwargs, allow_unvalidated, schema, use_guided)
        assert kwargs == expected

    def test_token_usage_normalizes_missing_usage(self):
        """_token_usage falls back to an unavailable token record."""
        usage = _token_usage(type("R", (), {"usage": None})())
        assert usage.prompt_tokens is None
        assert usage.completion_tokens is None

    def test_token_usage_preserves_usage(self):
        """_token_usage returns the response's own usage record."""
        response = type("R", (), {"usage": type("U", (), {"prompt_tokens": 1})})()
        assert _token_usage(response).prompt_tokens == 1

    def test_top_k_extra_body(self):
        """_top_k_extra_body maps top_k into extra_body entries."""
        assert _top_k_extra_body(40) == {"top_k": 40}
        assert _top_k_extra_body(None) == {}

    def test_json_schema_response_format(self):
        """Strict output uses response_format rather than legacy guided_json."""

        class _Model(BaseModel):
            val: int

        body = _json_schema_response_format(_Model)
        assert body["type"] == "json_schema"
        assert body["json_schema"]["schema"] == _Model.model_json_schema()

    def test_thinking_extra_body_is_profile_scoped(self):
        assert _thinking_extra_body(False) == {
            "chat_template_kwargs": {"enable_thinking": False}
        }
        assert _thinking_extra_body(None) == {}


_BASE_URL_ENV = "ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL"
_API_KEY_ENV = "ASAGO_SCENARIO_GENERATOR_API_KEY"
_MODEL_ENV = "ASAGO_SCENARIO_GENERATOR_MODEL_NAME"


@pytest.mark.parametrize(
    ("resolver", "env_var", "explicit", "env_value", "expected"),
    [
        (
            _resolve_base_url,
            _BASE_URL_ENV,
            "http://explicit.invalid",
            "http://env.invalid",
            "http://explicit.invalid",
        ),
        (
            _resolve_base_url,
            _BASE_URL_ENV,
            None,
            "http://env.invalid",
            "http://env.invalid",
        ),
        (_resolve_base_url, _BASE_URL_ENV, None, None, None),
        (_resolve_api_key, _API_KEY_ENV, "mykey", "envkey", "mykey"),
        (_resolve_api_key, _API_KEY_ENV, None, "envkey", "envkey"),
        (_resolve_api_key, _API_KEY_ENV, None, None, "unused"),
        (_resolve_model, _MODEL_ENV, "mymodel", "envmodel", "mymodel"),
        (_resolve_model, _MODEL_ENV, None, "envmodel", "envmodel"),
        (_resolve_model, _MODEL_ENV, None, None, "gemma-3n-e4b-it"),
    ],
    ids=[
        "base_url_explicit",
        "base_url_env",
        "base_url_unset",
        "api_key_explicit",
        "api_key_env",
        "api_key_default",
        "model_explicit",
        "model_env",
        "model_default",
    ],
)
def test_setting_resolution_order(
    monkeypatch, resolver, env_var, explicit, env_value, expected
):
    """An explicit argument beats the environment, which beats the default."""
    if env_value is None:
        monkeypatch.delenv(env_var, raising=False)
    else:
        monkeypatch.setenv(env_var, env_value)
    assert resolver(explicit) == expected


class _Schema(BaseModel):
    value: str


def _make_client(**kwargs) -> LLMClient:
    """An LLMClient whose OpenAI transport is a MagicMock, so no request can escape."""
    client = LLMClient(
        base_url="http://test-endpoint.invalid",
        api_key="test-key",
        model="test-model",
        **kwargs,
    )
    client._client = MagicMock()
    return client


def _create_response(content: str) -> MagicMock:
    response = MagicMock()
    response.usage = SimpleNamespace(prompt_tokens=3, completion_tokens=4)
    response.choices = [SimpleNamespace(message=SimpleNamespace(content=content))]
    return response


@pytest.mark.parametrize(
    ("client_args", "call_args", "call_kwargs", "present", "absent"),
    [
        ({}, (100, 0.5), {}, {"max_completion_tokens": 100}, ()),
        ({}, (None, 0.5), {}, {}, ("max_completion_tokens",)),
        ({"top_p": 0.5}, (None, 0.5), {}, {"top_p": 0.5}, ()),
        ({"top_p": None}, (None, 0.5), {}, {}, ("top_p",)),
        ({}, (None, 0.7), {}, {"temperature": 0.7}, ()),
        ({"top_k": 10}, (None, 0.5), {}, {"extra_body": {"top_k": 10}}, ()),
        ({}, (None, 0.5), {}, {}, ("extra_body",)),
        (
            {},
            (None, 0.5),
            {"response_format": _Schema, "use_guided_json": True},
            {},
            ("extra_body",),
        ),
    ],
    ids=[
        "max_tokens_set",
        "max_tokens_omitted",
        "top_p_set",
        "top_p_omitted",
        "temperature_always_set",
        "top_k_in_extra_body",
        "no_extra_body_when_empty",
        "guided_schema_not_in_extra_body",
    ],
)
def test_build_extra_kwargs(client_args, call_args, call_kwargs, present, absent):
    """Each optional control reaches the request only when it is set."""
    kwargs = _make_client(**client_args)._build_extra_kwargs(*call_args, **call_kwargs)
    for key, value in present.items():
        assert kwargs[key] == value
    for key in absent:
        assert key not in kwargs


@pytest.mark.parametrize(
    ("response_format", "allow_unvalidated", "content", "strict_schema"),
    [
        (_Schema, False, '{"value":"parsed-content"}', True),
        (_Schema, True, "raw-text", False),
        (None, False, "raw-text", False),
        (None, True, "raw-text", False),
    ],
    ids=["strict_schema", "unvalidated", "no_format", "no_format_unvalidated"],
)
def test_request_completion_always_uses_create_and_the_first_choice(
    response_format, allow_unvalidated, content, strict_schema
):
    """Every branch goes through chat.completions.create and returns choices[0]."""
    client = _make_client()
    client._client.chat.completions.create.return_value = _create_response(content)

    _, returned = client._request_completion(
        [{"role": "user", "content": "hi"}],
        response_format,
        {},
        allow_unvalidated=allow_unvalidated,
    )

    assert returned == content
    client._client.chat.completions.create.assert_called_once()
    if strict_schema:
        sent = client._client.chat.completions.create.call_args.kwargs
        assert sent["response_format"] == _json_schema_response_format(_Schema)


def test_explicit_controls_override_client_defaults():
    """Explicit max tokens and temperature reach the provider call and the duration is recorded."""
    client = _make_client(max_completion_tokens=200, temperature=0.2)
    client._client.chat.completions.create.return_value = _create_response("raw")

    with patch(
        "asago_scenario_generator.stpa.infra.llm.time.perf_counter_ns",
        side_effect=[1_000_000_000, 1_123_000_000],
    ):
        result = client.complete(
            "system", "user", max_completion_tokens=100, temperature=0.7
        )

    sent = client._client.chat.completions.create.call_args.kwargs
    assert sent["max_completion_tokens"] == 100
    assert sent["temperature"] == 0.7
    assert result.duration_ms == 123
