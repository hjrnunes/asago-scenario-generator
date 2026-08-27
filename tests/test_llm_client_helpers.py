"""Focused unit tests for the decomposed LLM client helpers."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from pydantic import BaseModel

from asago_scenario_generator.llm.client import (
    _choice_content,
    _completion_extra_kwargs,
    _decoded_json_value,
    _effective_temperature,
    _inject_openrouter_defaults,
    _is_plain_scalar,
    _is_pydantic_model_schema,
    _json_env_headers,
    _openai_client,
    _plain_mapping,
    _plain_object,
    _plain_sequence,
    _plain_value,
    _prompt_messages,
    _raise_if_unstructured_length,
    _recover_complete_structured_partial,
    _recover_length_failure,
    _recoverable_input,
    _request_completion,
    _request_controls,
    _require_base_url,
    _resolve_api_key_arg,
    _resolve_base_url_arg,
    _resolve_max_tokens_arg,
    _resolve_model_arg,
    _resolve_temperature_arg,
    _response_schema_label,
    _usage_counts,
    _validated_recovered,
)


class _FixtureModel(BaseModel):
    value: str


class TestResolveArgs:
    """Constructor-argument resolution from explicit values and the environment."""

    def test_base_url_explicit_wins_over_env(self, monkeypatch) -> None:
        monkeypatch.setenv("ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL", "http://env")
        assert _resolve_base_url_arg("http://explicit") == "http://explicit"

    def test_base_url_from_env(self, monkeypatch) -> None:
        monkeypatch.setenv("ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL", "http://env")
        assert _resolve_base_url_arg(None) == "http://env"

    def test_base_url_none_when_unset(self, monkeypatch) -> None:
        monkeypatch.delenv("ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL", raising=False)
        assert _resolve_base_url_arg(None) is None

    def test_api_key_explicit_wins_over_env(self, monkeypatch) -> None:
        monkeypatch.setenv("ASAGO_SCENARIO_GENERATOR_API_KEY", "env-key")
        assert _resolve_api_key_arg("explicit-key") == "explicit-key"

    def test_api_key_from_env(self, monkeypatch) -> None:
        monkeypatch.setenv("ASAGO_SCENARIO_GENERATOR_API_KEY", "env-key")
        assert _resolve_api_key_arg(None) == "env-key"

    def test_api_key_defaults_to_unused(self, monkeypatch) -> None:
        monkeypatch.delenv("ASAGO_SCENARIO_GENERATOR_API_KEY", raising=False)
        assert _resolve_api_key_arg(None) == "unused"

    def test_model_explicit_wins_over_env(self, monkeypatch) -> None:
        monkeypatch.setenv("ASAGO_SCENARIO_GENERATOR_MODEL_NAME", "env-model")
        assert _resolve_model_arg("explicit-model") == "explicit-model"

    def test_model_from_env(self, monkeypatch) -> None:
        monkeypatch.setenv("ASAGO_SCENARIO_GENERATOR_MODEL_NAME", "env-model")
        assert _resolve_model_arg(None) == "env-model"

    def test_model_default_name(self, monkeypatch) -> None:
        monkeypatch.delenv("ASAGO_SCENARIO_GENERATOR_MODEL_NAME", raising=False)
        assert _resolve_model_arg(None) == "gemma-3n-e4b-it"

    def test_max_tokens_explicit_wins_over_env(self, monkeypatch) -> None:
        monkeypatch.setenv("ASAGO_SCENARIO_GENERATOR_MAX_COMPLETION_TOKENS", "2000")
        assert _resolve_max_tokens_arg(500) == 500

    def test_max_tokens_from_env(self, monkeypatch) -> None:
        monkeypatch.setenv("ASAGO_SCENARIO_GENERATOR_MAX_COMPLETION_TOKENS", "2000")
        assert _resolve_max_tokens_arg(None) == 2000

    def test_max_tokens_none_when_unset(self, monkeypatch) -> None:
        monkeypatch.delenv(
            "ASAGO_SCENARIO_GENERATOR_MAX_COMPLETION_TOKENS", raising=False
        )
        assert _resolve_max_tokens_arg(None) is None

    def test_temperature_explicit_wins_over_env(self, monkeypatch) -> None:
        monkeypatch.setenv("ASAGO_SCENARIO_GENERATOR_TEMPERATURE", "0.9")
        assert _resolve_temperature_arg(0.2) == 0.2

    def test_temperature_from_env(self, monkeypatch) -> None:
        monkeypatch.setenv("ASAGO_SCENARIO_GENERATOR_TEMPERATURE", "0.9")
        assert _resolve_temperature_arg(None) == 0.9

    def test_temperature_default(self, monkeypatch) -> None:
        monkeypatch.delenv("ASAGO_SCENARIO_GENERATOR_TEMPERATURE", raising=False)
        assert _resolve_temperature_arg(None) == 0.4


class TestClientConstruction:
    """Endpoint guard and OpenAI client construction."""

    def test_require_base_url_accepts_configured(self) -> None:
        _require_base_url("http://endpoint")  # must not raise

    def test_require_base_url_rejects_none(self) -> None:
        with pytest.raises(ValueError, match="No LLM endpoint configured"):
            _require_base_url(None)

    def test_require_base_url_rejects_empty(self) -> None:
        with pytest.raises(ValueError, match="No LLM endpoint configured"):
            _require_base_url("")

    def test_openai_client_passes_headers_and_base_url(self) -> None:
        with patch("asago_scenario_generator.llm.client.OpenAI") as factory:
            _openai_client("http://endpoint", "key", {"X-A": "1"}, None)
        factory.assert_called_once_with(
            base_url="http://endpoint",
            api_key="key",
            default_headers={"X-A": "1"},
            timeout=300.0,
            max_retries=0,
        )

    def test_openai_client_omits_headers_when_none(self) -> None:
        with patch("asago_scenario_generator.llm.client.OpenAI") as factory:
            _openai_client("http://endpoint", "key", None, None)
        factory.assert_called_once_with(
            base_url="http://endpoint",
            api_key="key",
            default_headers=None,
            timeout=300.0,
            max_retries=0,
        )

    def test_openai_client_forwards_timeout(self) -> None:
        with patch("asago_scenario_generator.llm.client.OpenAI") as factory:
            _openai_client("http://endpoint", "key", None, 30.0)
        assert factory.call_args.kwargs["timeout"] == 30.0
        assert factory.call_args.kwargs["max_retries"] == 0


class TestHeaders:
    """Environment-header parsing and OpenRouter defaults."""

    def test_json_env_headers_parses(self, monkeypatch) -> None:
        monkeypatch.setenv("ASAGO_SCENARIO_GENERATOR_EXTRA_HEADERS", '{"X-A":"1"}')
        assert _json_env_headers("ASAGO_SCENARIO_GENERATOR_EXTRA_HEADERS") == {
            "X-A": "1"
        }

    def test_json_env_headers_empty_when_unset(self, monkeypatch) -> None:
        monkeypatch.delenv("ASAGO_SCENARIO_GENERATOR_EXTRA_HEADERS", raising=False)
        assert _json_env_headers("ASAGO_SCENARIO_GENERATOR_EXTRA_HEADERS") == {}

    def test_inject_openrouter_defaults_fills_missing_keys(self) -> None:
        merged = {"X-A": "1"}
        _inject_openrouter_defaults(
            merged, "https://openrouter.ai/api/v1", {"X-B": "2"}
        )
        assert merged == {"X-A": "1", "X-B": "2"}

    def test_inject_openrouter_defaults_keeps_explicit(self) -> None:
        merged = {"X-B": "explicit"}
        _inject_openrouter_defaults(
            merged, "https://openrouter.ai/api/v1", {"X-B": "2"}
        )
        assert merged == {"X-B": "explicit"}

    def test_inject_openrouter_defaults_skips_non_openrouter(self) -> None:
        merged = {}
        _inject_openrouter_defaults(merged, "http://other", {"X-B": "2"})
        assert merged == {}


class TestPlainValue:
    """Telemetry object to JSON-compatible value conversion."""

    def test_is_plain_scalar_accepts_json_types(self) -> None:
        for value in (None, "s", 1, 1.5, True):
            assert _is_plain_scalar(value) is True

    def test_is_plain_scalar_rejects_containers(self) -> None:
        for value in ([], {}, object()):
            assert _is_plain_scalar(value) is False

    def test_plain_mapping_stringifies_keys(self) -> None:
        assert _plain_mapping({1: "one"}) == {"1": "one"}

    def test_plain_sequence_recurses(self) -> None:
        assert _plain_sequence([1, {"k": 2}]) == [1, {"k": 2}]

    def test_plain_object_uses_public_dict(self) -> None:
        obj = SimpleNamespace(public="kept", _private="dropped")
        assert _plain_object(obj) == {"public": "kept"}

    def test_plain_object_scalar_without_dict(self) -> None:
        obj = object()
        assert _plain_object(obj) == str(obj)

    def test_plain_value_recurses_through_mixed_shapes(self) -> None:
        obj = SimpleNamespace(tag="x", _skip="s")
        value = _plain_value({"items": [obj, {"n": 1}], "flag": True})
        assert value == {"items": [{"tag": "x"}, {"n": 1}], "flag": True}

    def test_usage_counts_tolerates_none(self) -> None:
        assert _usage_counts(None) == (0, 0)

    def test_usage_counts_reads_token_fields(self) -> None:
        usage = SimpleNamespace(prompt_tokens=3, completion_tokens=4)
        assert _usage_counts(usage) == (3, 4)


class TestRecoveryHelpers:
    """Structured partial recovery decomposition."""

    def test_is_pydantic_model_schema_true(self) -> None:
        assert _is_pydantic_model_schema(_FixtureModel) is True

    def test_is_pydantic_model_schema_false_for_non_schema(self) -> None:
        assert _is_pydantic_model_schema(dict) is False

    def test_is_pydantic_model_schema_tolerates_unsubclassable(self) -> None:
        assert _is_pydantic_model_schema(42) is False  # type: ignore[arg-type]

    def test_decoded_json_value_decodes_leading_value(self) -> None:
        assert _decoded_json_value('{"a":1} rest') == ({"a": 1}, 7)

    def test_decoded_json_value_none_for_invalid(self) -> None:
        assert _decoded_json_value('{"a":') is None

    def test_validated_recovered_returns_model(self) -> None:
        result = _validated_recovered({"value": "ok"}, _FixtureModel)
        assert isinstance(result, _FixtureModel)
        assert result.value == "ok"

    def test_validated_recovered_none_for_invalid(self) -> None:
        assert _validated_recovered({"wrong": 1}, _FixtureModel) is None

    def test_recoverable_input_requires_str_and_schema(self) -> None:
        assert _recoverable_input('{"a":1}', _FixtureModel) is True
        assert _recoverable_input({"a": 1}, _FixtureModel) is False
        assert _recoverable_input('{"a":1}', None) is False
        assert _recoverable_input('{"a":1}', dict) is False

    def test_recover_complete_partial_returns_model(self) -> None:
        result = _recover_complete_structured_partial(
            '{"value":"done"}\n   ', _FixtureModel
        )
        assert isinstance(result, _FixtureModel)
        assert result.value == "done"

    def test_recover_complete_partial_fails_closed(self) -> None:
        for partial in (
            '{"value":',
            '{"value":"done"} trailing',
            '{"wrong":1}',
            "not json",
            None,
        ):
            assert _recover_complete_structured_partial(partial, _FixtureModel) is None

    def test_recover_complete_partial_requires_schema(self) -> None:
        assert _recover_complete_structured_partial('{"a":1}', dict) is None
        assert _recover_complete_structured_partial('{"a":1}', None) is None


class TestRequestHelpers:
    """Completion request plumbing."""

    def test_response_schema_label_none_for_unstructured(self) -> None:
        assert _response_schema_label(None) is None

    def test_response_schema_label_compact_v1(self) -> None:
        class CompactResult(BaseModel):
            value: str

        assert _response_schema_label(CompactResult) == "compact-v1"

    def test_response_schema_label_standard(self) -> None:
        assert _response_schema_label(_FixtureModel) == "standard"

    def test_effective_temperature_prefers_explicit(self) -> None:
        assert _effective_temperature(0.9, 0.4) == 0.9
        assert _effective_temperature(None, 0.4) == 0.4

    def test_prompt_messages_builds_pair(self) -> None:
        assert _prompt_messages("sys", "usr") == [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "usr"},
        ]

    def test_completion_extra_kwargs_includes_all_controls(self) -> None:
        kwargs = _completion_extra_kwargs(100, 0.7, 0.9, 40)
        assert kwargs == {
            "temperature": 0.7,
            "max_completion_tokens": 100,
            "top_p": 0.9,
            "extra_body": {"top_k": 40},
        }

    def test_completion_extra_kwargs_omits_none_controls(self) -> None:
        assert _completion_extra_kwargs(None, 0.7, None, None) == {"temperature": 0.7}

    def test_request_controls_reports_recovery(self) -> None:
        controls = _request_controls(_FixtureModel, 4096, 8192, 0.4, 0.9, 40, True)
        assert controls["response_schema"] == "standard"
        assert controls["max_completion_tokens"] == 4096
        assert controls["transport_token_cap"] == 8192
        assert controls["temperature"] == 0.4
        assert controls["top_p"] == 0.9
        assert controls["top_k"] == 40
        assert controls["structured_whitespace_recovered"] is True

    def test_request_completion_structured_uses_parse(self) -> None:
        client = MagicMock()
        parsed = object()
        client.beta.chat.completions.parse.return_value = SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(parsed=parsed))]
        )
        response, content = _request_completion(client, "model", [], _FixtureModel, {})
        assert content is parsed
        assert client.chat.completions.create.call_count == 0

    def test_request_completion_unstructured_uses_create(self) -> None:
        client = MagicMock()
        client.chat.completions.create.return_value = SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="text"))]
        )
        response, content = _request_completion(client, "model", [], None, {})
        assert content == "text"
        assert client.beta.chat.completions.parse.call_count == 0

    def test_recover_length_failure_returns_recovered(self) -> None:
        from openai import LengthFinishReasonError

        completion = SimpleNamespace(
            usage=MagicMock(),
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(content='{"value":"ok"}  '),
                    finish_reason="length",
                )
            ],
        )
        exc = LengthFinishReasonError(completion=completion)
        response, content, recovered = _recover_length_failure(exc, _FixtureModel)
        assert isinstance(content, _FixtureModel)
        assert content.value == "ok"
        assert recovered is True
        assert response is completion

    def test_recover_length_failure_raises_when_not_recoverable(self) -> None:
        from openai import LengthFinishReasonError

        completion = SimpleNamespace(
            usage=MagicMock(),
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(content="truncated"),
                    finish_reason="length",
                )
            ],
        )
        exc = LengthFinishReasonError(completion=completion)
        with pytest.raises(Exception, match="length"):
            _recover_length_failure(exc, _FixtureModel)

    def test_raise_if_unstructured_length_raises(self) -> None:
        response = SimpleNamespace(
            usage=MagicMock(),
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(content="truncated"),
                    finish_reason="length",
                )
            ],
        )
        with pytest.raises(Exception, match="length"):
            _raise_if_unstructured_length(response, None)

    def test_raise_if_unstructured_length_ignores_structured(self) -> None:
        response = SimpleNamespace(
            usage=MagicMock(),
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(content="truncated"),
                    finish_reason="length",
                )
            ],
        )
        _raise_if_unstructured_length(response, _FixtureModel)  # must not raise

    def test_choice_content_tolerates_missing_choice(self) -> None:
        assert _choice_content(SimpleNamespace(choices=[])) is None
