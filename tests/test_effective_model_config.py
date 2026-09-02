"""Effective non-STPA model configuration and provenance contracts."""

from __future__ import annotations

import json
from pathlib import Path
import pytest
import yaml

from asago_scenario_generator.manifest import ModelConfig
from asago_scenario_generator.pipeline.model_configuration import (
    ConfigSource,
    resolve_effective_model_config,
)


def test_cli_overrides_profile_which_overrides_environment_and_defaults(
    tmp_path: Path,
) -> None:
    profiles_file = tmp_path / "profiles.yaml"
    profiles_file.write_text(
        yaml.safe_dump(
            {
                "gemma": {
                    "base_url": "https://profile.example/v1",
                    "model": "profile-model",
                    "api_key": "profile-secret",
                    "max_completion_tokens": 8192,
                    "temperature": 0.2,
                    "top_p": 0.9,
                    "top_k": 40,
                    "timeout": 75.0,
                    "headers": {"Authorization": "profile-header-secret"},
                }
            }
        ),
        encoding="utf-8",
    )

    effective = resolve_effective_model_config(
        model_profile="gemma",
        profiles_file=profiles_file,
        model="cli-model",
        api_key="cli-secret",
        environ={
            "ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL": "https://env.example/v1",
            "ASAGO_SCENARIO_GENERATOR_MODEL_NAME": "env-model",
            "ASAGO_SCENARIO_GENERATOR_API_KEY": "env-secret",
            "ASAGO_SCENARIO_GENERATOR_TEMPERATURE": "0.8",
        },
    )

    assert effective.model == "cli-model"
    assert effective.base_url == "https://profile.example/v1"
    assert effective.api_key == "cli-secret"
    assert effective.temperature == 0.2
    assert effective.max_completion_tokens == 8192
    assert effective.top_p == 0.9
    assert effective.top_k == 40
    assert effective.timeout == 75.0
    assert effective.sources["model"] is ConfigSource.cli
    assert effective.sources["base_url"] is ConfigSource.profile
    assert effective.sources["temperature"] is ConfigSource.profile

    public_json = json.dumps(effective.public_controls(), sort_keys=True)
    assert "cli-secret" not in public_json
    assert "profile-secret" not in public_json
    assert "profile-header-secret" not in public_json
    assert "api_key" not in public_json
    assert effective.public_controls()["header_names"] == ["Authorization"]


def test_request_timeout_is_bounded_by_default() -> None:
    effective = resolve_effective_model_config(environ={})

    assert effective.timeout == 300.0
    assert effective.sources["timeout"] is ConfigSource.application_default


def test_offline_provenance_accepts_an_absent_base_url() -> None:
    config = ModelConfig(model="fixture", base_url=None, temperature=0.4)

    assert config.base_url is None


def test_explicit_environment_mapping_is_used_instead_of_process_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ASAGO_SCENARIO_GENERATOR_MODEL_NAME", "process-model")

    effective = resolve_effective_model_config(
        environ={"ASAGO_SCENARIO_GENERATOR_MODEL_NAME": "call-model"}
    )

    assert effective.model == "call-model"
    assert effective.sources["model"] is ConfigSource.environment


def test_missing_environment_mapping_reads_process_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ASAGO_SCENARIO_GENERATOR_MODEL_NAME", "process-model")

    effective = resolve_effective_model_config()

    assert effective.model == "process-model"
    assert effective.sources["model"] is ConfigSource.environment
