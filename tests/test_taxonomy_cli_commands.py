"""Unit tests for retained taxonomy preparation commands."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from asago_scenario_generator.cli import app

runner = CliRunner()


def _write(path: Path, text: str = "fixture") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


@pytest.mark.parametrize(
    ("option", "label"),
    [
        ("--risk-extraction", "risk-extraction file"),
        ("--sssom", "SSSOM file"),
        ("--profile", "capability profile file"),
    ],
)
def test_projection_preflight_rejects_missing_required_input(
    tmp_path: Path, option: str, label: str
) -> None:
    valid = _write(tmp_path / "inputs" / "valid.yaml")
    missing = tmp_path / "missing" / "input.dat"
    args = [
        "projection-preflight",
        "--use-case",
        "A chatbot",
        "--risk-extraction",
        str(valid),
        "--sssom",
        str(valid),
        "--profile",
        str(valid),
    ]
    args[args.index(option) + 1] = str(missing)

    with patch(
        "asago_scenario_generator.pipeline.preflight.run_projection_preflight"
    ) as mock_run:
        result = runner.invoke(app, args)

    assert result.exit_code == 1
    assert f"Error: {label} not found: {missing}" in result.stderr
    assert result.stdout == ""
    mock_run.assert_not_called()


def test_validate_catalog_qualification_rejects_missing_artifact(
    tmp_path: Path,
) -> None:
    missing = tmp_path / "missing" / "matrix.yaml"

    result = runner.invoke(
        app, ["validate-catalog-qualification", str(missing), "--contract", "matrix"]
    )

    assert result.exit_code == 1
    assert result.stderr.startswith("Error:")


def test_validate_catalog_qualification_rejects_invalid_artifact(
    tmp_path: Path,
) -> None:
    artifact = _write(tmp_path / "corrupt.yaml", "not a: [valid contract")

    result = runner.invoke(
        app, ["validate-catalog-qualification", str(artifact), "--contract", "matrix"]
    )

    assert result.exit_code == 1
    assert result.stderr.startswith("Error:")


def test_validate_catalog_qualification_rejects_unknown_contract(
    tmp_path: Path,
) -> None:
    artifact = _write(tmp_path / "matrix.yaml", "schema_version: 1")

    result = runner.invoke(
        app,
        ["validate-catalog-qualification", str(artifact), "--contract", "invalid"],
    )

    assert result.exit_code == 1
    assert "Error: contract must be matrix, campaign, or report" in result.stderr


def test_projection_preflight_prints_json_report(tmp_path: Path) -> None:
    risk = _write(tmp_path / "inputs" / "risk-extraction.json", "{}")
    sssom = _write(tmp_path / "inputs" / "sssom.tsv")
    profile = _write(
        tmp_path / "inputs" / "capability-profile.yaml", "zones_active: []"
    )
    outcome = SimpleNamespace(
        model_dump=lambda mode: {
            "readiness": {"ready": True, "missing_facts": [], "required_facts": []},
            "fact_states": [],
            "facts_template": [],
            "explicit_facts_source": False,
        }
    )

    with patch(
        "asago_scenario_generator.pipeline.preflight.run_projection_preflight",
        return_value=outcome,
    ) as mock_run:
        result = runner.invoke(
            app,
            [
                "projection-preflight",
                "--use-case",
                "A chatbot",
                "--risk-extraction",
                str(risk),
                "--sssom",
                str(sssom),
                "--profile",
                str(profile),
            ],
        )

    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert parsed["readiness"]["ready"] is True
    assert parsed["explicit_facts_source"] is False
    mock_run.assert_called_once()
