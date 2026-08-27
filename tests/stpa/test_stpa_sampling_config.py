"""Regression tests for equivalent STPA sampling configuration routes."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from asago_scenario_generator.stpa.infra.llm import LLMClient
from asago_scenario_generator.stpa.pipeline.llm_config import (
    resolve_llm_client_from_env,
    resolve_llm_client_from_profile,
)

_KEY = "api_" + "key"
_SAMPLING_FIELDS = (
    "max_completion_tokens",
    "temperature",
    "top_p",
    "top_k",
    "use_guided_decoding",
    "timeout",
)


def _write_gemma_profile(path: Path) -> Path:
    path.write_text(
        yaml.safe_dump(
            {
                "gemma": {
                    "base_url": "http://fixture.invalid/v1",
                    "model": "gemma-fixture",
                    _KEY: "unused",
                    "max_completion_tokens": 16384,
                    "temperature": 1.0,
                    "top_p": 0.95,
                    "top_k": 64,
                    "use_guided_decoding": True,
                    "timeout": 45.0,
                }
            }
        ),
        encoding="utf-8",
    )
    return path


def test_profile_and_environment_routes_resolve_equivalent_sampling(
    tmp_path, monkeypatch
) -> None:
    """The successful Gemma profile can be represented entirely by env vars."""
    profiles = _write_gemma_profile(tmp_path / "profiles.yaml")
    profile_client, _ = resolve_llm_client_from_profile(str(profiles), "gemma")

    monkeypatch.setenv(
        "ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL", "http://fixture.invalid/v1"
    )
    monkeypatch.setenv("ASAGO_SCENARIO_GENERATOR_MODEL_NAME", "gemma-fixture")
    monkeypatch.setenv("ASAGO_SCENARIO_GENERATOR_API_KEY", "unused")
    monkeypatch.setenv("ASAGO_SCENARIO_GENERATOR_MAX_COMPLETION_TOKENS", "16384")
    monkeypatch.setenv("ASAGO_SCENARIO_GENERATOR_TEMPERATURE", "1.0")
    monkeypatch.setenv("ASAGO_SCENARIO_GENERATOR_TOP_P", "0.95")
    monkeypatch.setenv("ASAGO_SCENARIO_GENERATOR_TOP_K", "64")
    monkeypatch.setenv("ASAGO_SCENARIO_GENERATOR_USE_GUIDED_DECODING", "true")
    monkeypatch.setenv("ASAGO_SCENARIO_GENERATOR_TIMEOUT", "45")

    env_client = resolve_llm_client_from_env()

    assert env_client.base_url == profile_client.base_url
    assert env_client.model == profile_client.model
    assert {field: getattr(env_client, field) for field in _SAMPLING_FIELDS} == {
        field: getattr(profile_client, field) for field in _SAMPLING_FIELDS
    }


def test_explicit_sampling_arguments_override_environment(monkeypatch) -> None:
    monkeypatch.setenv("ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL", "http://env.invalid")
    monkeypatch.setenv("ASAGO_SCENARIO_GENERATOR_MAX_COMPLETION_TOKENS", "2048")
    monkeypatch.setenv("ASAGO_SCENARIO_GENERATOR_TEMPERATURE", "0.2")
    monkeypatch.setenv("ASAGO_SCENARIO_GENERATOR_TOP_P", "0.3")
    monkeypatch.setenv("ASAGO_SCENARIO_GENERATOR_TOP_K", "8")
    monkeypatch.setenv("ASAGO_SCENARIO_GENERATOR_USE_GUIDED_DECODING", "true")
    monkeypatch.setenv("ASAGO_SCENARIO_GENERATOR_TIMEOUT", "9")

    client = LLMClient(
        max_completion_tokens=16384,
        temperature=1.0,
        top_p=0.95,
        top_k=64,
        use_guided_decoding=False,
        timeout=45,
    )

    assert client.max_completion_tokens == 16384
    assert client.temperature == 1.0
    assert client.top_p == 0.95
    assert client.top_k == 64
    assert client.use_guided_decoding is False
    assert client.timeout == 45.0


def test_stpa_client_has_a_default_deadline_and_no_hidden_sdk_retries(
    monkeypatch,
) -> None:
    monkeypatch.setenv("ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL", "http://env.invalid")

    with patch("asago_scenario_generator.stpa.infra.llm.OpenAI") as factory:
        client = resolve_llm_client_from_env()

    assert client.timeout == 300.0
    assert factory.call_args.kwargs["timeout"] == 300.0
    assert factory.call_args.kwargs["max_retries"] == 0


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("ASAGO_SCENARIO_GENERATOR_MAX_COMPLETION_TOKENS", "many"),
        ("ASAGO_SCENARIO_GENERATOR_TEMPERATURE", "warm"),
        ("ASAGO_SCENARIO_GENERATOR_TOP_P", "almost-all"),
        ("ASAGO_SCENARIO_GENERATOR_TOP_K", "several"),
        ("ASAGO_SCENARIO_GENERATOR_USE_GUIDED_DECODING", "sometimes"),
        ("ASAGO_SCENARIO_GENERATOR_TIMEOUT", "forever"),
        ("ASAGO_SCENARIO_GENERATOR_TIMEOUT", "0"),
    ],
)
def test_invalid_environment_sampling_fails_preflight_with_field_name(
    monkeypatch, name: str, value: str
) -> None:
    monkeypatch.setenv("ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL", "http://env.invalid")
    monkeypatch.setenv(name, value)

    with pytest.raises(ValueError, match=name):
        resolve_llm_client_from_env()
