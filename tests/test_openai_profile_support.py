"""Offline regression tests for OpenAI reasoning-profile behavior."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import httpx
import pytest
from openai import RateLimitError
from pydantic import BaseModel

from asago_scenario_generator.llm.client import LLMClient as LegacyLLMClient
from asago_scenario_generator.pipeline.model_configuration import (
    resolve_effective_model_config,
)
from asago_scenario_generator.stpa.infra.llm import LLMClient
from asago_scenario_generator.stpa.infra.llm_helpers import safe_llm_call
from asago_scenario_generator.strict_schema import (
    strip_null_fields,
    to_openai_strict_schema,
)
from asago_scenario_generator.stpa.scenario_prod.authoring_wire import (
    CurrentAuthoringResponse,
)
from asago_scenario_generator.stpa.scenario_prod.bdi_generation import (
    _ContextBDIProviderPayload,
)
from asago_scenario_generator.stpa.target_realization.provider import (
    TargetRealizationDraft,
    TargetRealizationExtensionProviderResponse,
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


def _walk(schema: object):
    if isinstance(schema, dict):
        yield schema
        for value in schema.values():
            yield from _walk(value)
    elif isinstance(schema, list):
        for value in schema:
            yield from _walk(value)


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
        (
            {"service_tier": "flex", "service_tier_fallback": "default"},
            _rate_limit(500),
        ),
    ],
)
def test_service_tier_fallback_is_not_used_without_a_429_pair(kwargs, error) -> None:
    client = _infra_client(**kwargs)
    client._client.chat.completions.create.side_effect = error

    with pytest.raises(RateLimitError):
        client.complete("system", "user")

    assert client._client.chat.completions.create.call_count == 1


def test_strict_schema_request_and_null_round_trip() -> None:
    client = _infra_client(strict_json_schema=True)
    client._client.chat.completions.create.return_value = _response()

    result = client.complete("system", "user", response_format=_ProfileResponse)

    sent = client._client.chat.completions.create.call_args.kwargs
    schema = sent["response_format"]["json_schema"]["schema"]
    assert sent["response_format"]["type"] == "json_schema"
    assert sent["response_format"]["json_schema"]["strict"] is True
    assert set(schema["required"]) == set(schema["properties"])
    assert "null" in str(schema["properties"]["optional"])
    assert result.content == _ProfileResponse(
        required="ok",
        nested=_NestedModel(name="n"),
    )


def test_openrouter_keeps_json_object_compatibility_when_strict_is_enabled() -> None:
    client = _infra_client(strict_json_schema=True)
    client.base_url = "https://openrouter.ai/api/v1"
    client._client.chat.completions.create.return_value = _response(
        '{"required":"ok","nested":{"name":"n"}}'
    )

    result = client.complete("system", "user", response_format=_ProfileResponse)

    sent = client._client.chat.completions.create.call_args.kwargs
    assert sent["response_format"] == {"type": "json_object"}
    assert isinstance(result.content, str)


@pytest.mark.parametrize(
    "model",
    [
        TargetRealizationDraft,
        TargetRealizationExtensionProviderResponse,
        _ContextBDIProviderPayload,
        CurrentAuthoringResponse,
    ],
)
def test_real_producer_models_convert_to_openai_strict_schema(model) -> None:
    schema = to_openai_strict_schema(model)

    for node in _walk(schema):
        assert "default" not in node
        assert "oneOf" not in node
        assert "allOf" not in node
        if node.get("type") == "object":
            assert node["additionalProperties"] is False
            assert set(node.get("required", ())) == set(node.get("properties", ()))


def test_null_stripping_recurses_through_nested_models_and_list_items() -> None:
    raw = {
        "required": "ok",
        "nested": {"name": "n", "count": None},
        "optional": None,
        "maybe": {"name": "m", "count": None},
        "items": [{"name": "i", "count": None}],
        "maybe_items": [{"name": "mi", "count": None}],
        "maybe_map": {"entry": {"name": "mm", "count": None}},
    }

    stripped = strip_null_fields(raw, _ProfileResponse)

    assert stripped == {
        "required": "ok",
        "nested": {"name": "n"},
        "maybe": {"name": "m"},
        "items": [{"name": "i"}],
        "maybe_items": [{"name": "mi"}],
        "maybe_map": {"entry": {"name": "mm"}},
    }
    assert _ProfileResponse.model_validate(stripped).nested.count == 3


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

    result, _, error = safe_llm_call(
        llm_client=client,
        system_prompt="system",
        user_prompt="user",
        response_format=_ProfileResponse,
        run_dir=tmp_path,
        stage="test",
        step="reasoning",
    )

    assert result is None
    assert error is not None
    entry = json.loads((tmp_path / "calls.jsonl").read_text().splitlines()[0])
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


def test_legacy_config_does_not_forward_profile_seed() -> None:
    config = resolve_effective_model_config(
        environ={"ASAGO_SCENARIO_GENERATOR_SEED": "0"},
    )

    assert config.seed == 0
    assert "seed" not in config.client_kwargs()


def test_legacy_client_uses_strict_schema_and_sampling_controls() -> None:
    with patch("asago_scenario_generator.llm.client.OpenAI"):
        client = LegacyLLMClient(
            base_url="https://api.openai.com/v1",
            strict_json_schema=True,
            sampling_controls=False,
            reasoning_effort="medium",
            service_tier="flex",
        )
    client._client = MagicMock()
    client._client.chat.completions.create.return_value = _response()

    client.complete("system", "user", response_format=_ProfileResponse, temperature=0)

    sent = client._client.chat.completions.create.call_args.kwargs
    assert sent["reasoning_effort"] == "medium"
    assert sent["service_tier"] == "flex"
    assert "temperature" not in sent
    assert "seed" not in sent
    assert sent["response_format"]["json_schema"]["strict"] is True
