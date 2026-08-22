"""Effective non-STPA model configuration and provenance contracts."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import yaml
from typer.testing import CliRunner

from asago_scenario_generator.cli import app
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


@pytest.mark.parametrize(
    ("generation_mode_args", "expected_generation_mode"),
    [([], "exhaustive"), (["--generation-mode", "coverage"], "coverage")],
)
def test_generate_cli_forwards_named_model_profile(
    tmp_path: Path,
    generation_mode_args: list[str],
    expected_generation_mode: str,
) -> None:
    risk = tmp_path / "risk.json"
    sssom = tmp_path / "mapping.tsv"
    profiles = tmp_path / "profiles.yaml"
    risk.write_text("[]", encoding="utf-8")
    sssom.write_text("", encoding="utf-8")
    profiles.write_text("gemma: {}", encoding="utf-8")
    result = SimpleNamespace(
        manifest_status=SimpleNamespace(value="completed"),
        admitted_count=1,
        quarantined_count=0,
        failed_count=0,
        scenarios=[object()],
        seeds=[object()],
        governance_only_count=0,
        run_dir=tmp_path / "run",
    )

    with patch(
        "asago_scenario_generator.pipeline.runner.run_pipeline", return_value=result
    ) as run:
        cli_result = CliRunner().invoke(
            app,
            [
                "generate",
                "--use-case",
                "fixture",
                "--risk-extraction",
                str(risk),
                "--sssom",
                str(sssom),
                "--model-profile",
                "gemma",
                "--profiles-file",
                str(profiles),
                "--presentation-fallback",
                "forbid",
                *generation_mode_args,
            ],
        )

    assert cli_result.exit_code == 0, cli_result.output
    assert run.call_args.kwargs["model_profile"] == "gemma"
    assert run.call_args.kwargs["profiles_file"] == profiles
    assert run.call_args.kwargs["presentation_fallback"] == "forbid"
    assert run.call_args.kwargs["generation_mode"] == expected_generation_mode


def test_offline_provenance_accepts_an_absent_base_url() -> None:
    config = ModelConfig(model="fixture", base_url=None, temperature=0.4)

    assert config.base_url is None
