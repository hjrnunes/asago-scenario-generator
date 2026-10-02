"""Unit tests for retained taxonomy preparation commands."""

from __future__ import annotations

from pathlib import Path

from tests.cli_helpers import PlainCliRunner

from asago_scenario_generator.cli import app

runner = PlainCliRunner()


def _write(path: Path, text: str = "fixture") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path




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


