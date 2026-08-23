"""Unit tests for the taxonomy CLI command contracts feature.

These tests pin the up-front path validation and the success-path wiring
of the public taxonomy/risk CLI commands from
``features/taxonomy_cli_commands.feature``.  Pipeline work is mocked at
the public runner/report/eval/preflight ports so no LLM endpoint is
contacted and no pipeline code runs.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import yaml
from typer.testing import CliRunner

from asago_scenario_generator.cli import app

runner = CliRunner()


def _write(path: Path, text: str = "fixture") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# generate: up-front input validation (Taxonomy CLI commands 01-02)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("option", "label"),
    [
        ("--risk-extraction", "risk-extraction file"),
        ("--sssom", "SSSOM file"),
    ],
)
def test_generate_rejects_missing_required_input(
    tmp_path: Path, option: str, label: str
) -> None:
    """A missing required generate input fails on stderr before pipeline work."""
    valid = _write(tmp_path / "inputs" / "valid.tsv")
    missing = tmp_path / "missing" / "input.dat"
    args = [
        "generate",
        "--use-case",
        "A chatbot",
        "--risk-extraction",
        str(valid),
        "--sssom",
        str(valid),
    ]
    args[args.index(option) + 1] = str(missing)

    with patch("asago_scenario_generator.pipeline.runner.run_pipeline") as mock_run:
        result = runner.invoke(app, args)

    assert result.exit_code == 1
    assert f"Error: {label} not found: {missing}" in result.stderr
    mock_run.assert_not_called()


def test_generate_rejects_missing_at_file_use_case(tmp_path: Path) -> None:
    """A missing @file use-case reference fails before any pipeline work."""
    valid = _write(tmp_path / "inputs" / "valid.tsv")
    missing_ref = tmp_path / "missing" / "use-case.txt"

    with patch("asago_scenario_generator.pipeline.runner.run_pipeline") as mock_run:
        result = runner.invoke(
            app,
            [
                "generate",
                "--use-case",
                f"@{missing_ref}",
                "--risk-extraction",
                str(valid),
                "--sssom",
                str(valid),
            ],
        )

    assert result.exit_code == 1
    assert f"Error: use-case file not found: {missing_ref}" in result.stderr
    mock_run.assert_not_called()


# ---------------------------------------------------------------------------
# projection-preflight: input validation (Taxonomy CLI commands 03)
# ---------------------------------------------------------------------------


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
    """Each missing required preflight input fails on stderr with exit 1."""
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


# ---------------------------------------------------------------------------
# validate-catalog-qualification (Taxonomy CLI commands 04)
# ---------------------------------------------------------------------------


def test_validate_catalog_qualification_rejects_missing_artifact(
    tmp_path: Path,
) -> None:
    """A missing artifact path is rejected on stderr with exit 1."""
    missing = tmp_path / "missing" / "matrix.yaml"
    result = runner.invoke(
        app, ["validate-catalog-qualification", str(missing), "--contract", "matrix"]
    )
    assert result.exit_code == 1
    assert result.stderr.startswith("Error:")
    assert result.stdout == ""


def test_validate_catalog_qualification_rejects_invalid_artifact(
    tmp_path: Path,
) -> None:
    """Artifact content that is not a valid qualification contract is rejected."""
    artifact = _write(tmp_path / "corrupt.yaml", "not a: [valid contract")
    result = runner.invoke(
        app, ["validate-catalog-qualification", str(artifact), "--contract", "matrix"]
    )
    assert result.exit_code == 1
    assert result.stderr.startswith("Error:")
    assert result.stdout == ""


def test_validate_catalog_qualification_rejects_unknown_contract(
    tmp_path: Path,
) -> None:
    """An unsupported contract option is rejected without reading the artifact."""
    artifact = _write(tmp_path / "matrix.yaml", "schema_version: 1")
    result = runner.invoke(
        app,
        ["validate-catalog-qualification", str(artifact), "--contract", "invalid"],
    )
    assert result.exit_code == 1
    assert "Error: contract must be matrix, campaign, or report" in result.stderr
    assert result.stdout == ""


# ---------------------------------------------------------------------------
# report and eval: missing run directory (Taxonomy CLI commands 05)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("command", ["report", "eval"])
def test_command_rejects_missing_run_directory(tmp_path: Path, command: str) -> None:
    """report and eval reject a run directory that does not exist."""
    missing = tmp_path / "missing" / "run"
    result = runner.invoke(app, [command, "--output-dir", str(missing)])
    assert result.exit_code == 1
    assert f"Error: directory not found: {missing}" in result.stderr


# ---------------------------------------------------------------------------
# report (Taxonomy CLI commands 06-07)
# ---------------------------------------------------------------------------


def test_report_rejects_output_inside_run_directory(tmp_path: Path) -> None:
    """The report output destination must not be inside the run directory."""
    run_dir = tmp_path / "run"
    _write(run_dir / "run-manifest.yaml", "status: completed")
    inside = run_dir / "injected.html"

    with (
        patch("asago_scenario_generator.manifest.find_run_dir", return_value=run_dir),
        patch("asago_scenario_generator.report.data.load_report_data"),
        patch("asago_scenario_generator.report.generator.generate_report") as mock_gen,
    ):
        result = runner.invoke(
            app,
            ["report", "--output-dir", str(run_dir), "--output", str(inside)],
        )

    assert result.exit_code == 1
    assert "inside the immutable run directory" in result.stderr
    mock_gen.assert_not_called()
    assert not inside.exists()
    # The immutable run directory is left byte-for-byte unchanged.
    assert (run_dir / "run-manifest.yaml").read_text(encoding="utf-8") == (
        "status: completed"
    )


def test_report_writes_artifact_outside_run_directory(tmp_path: Path) -> None:
    """report writes the HTML artifact outside the run directory and announces it."""
    run_dir = tmp_path / "run"
    _write(run_dir / "run-manifest.yaml", "status: completed")
    output = tmp_path / "custom-report.html"

    def _write_report(data, out_dir: Path) -> Path:
        path = Path(out_dir) / "report.html"
        path.write_text("<html>report</html>", encoding="utf-8")
        return path

    with (
        patch("asago_scenario_generator.manifest.find_run_dir", return_value=run_dir),
        patch("asago_scenario_generator.report.data.load_report_data", return_value={}),
        patch(
            "asago_scenario_generator.report.generator.generate_report",
            side_effect=_write_report,
        ),
    ):
        result = runner.invoke(
            app,
            ["report", "--output-dir", str(run_dir), "--output", str(output)],
        )

    assert result.exit_code == 0
    assert f"Report written to {output}" in result.stdout
    assert output.read_text(encoding="utf-8") == "<html>report</html>"


# ---------------------------------------------------------------------------
# eval (Taxonomy CLI commands 08)
# ---------------------------------------------------------------------------


def _scorecard() -> dict:
    return {
        "run_id": "run-fixture",
        "schema_version": 1,
        "manifest_version": "v3",
        "scenario_count": 2,
        "feature_file_count": 1,
        "presence_coverage": 1.0,
        "qualification": "qualified",
    }


@pytest.mark.parametrize(
    ("format", "loader"),
    [
        ("yaml", yaml.safe_load),
        ("json", json.loads),
    ],
)
def test_eval_prints_scorecard(tmp_path: Path, format: str, loader) -> None:
    """eval prints the scorecard in the requested format on stdout."""
    run_dir = tmp_path / "run"
    _write(run_dir / "run-manifest.yaml", "status: completed")

    with patch(
        "asago_scenario_generator.eval.runner.run_evaluation",
        return_value=_scorecard(),
    ):
        result = runner.invoke(
            app, ["eval", "--output-dir", str(run_dir), "--format", format]
        )

    assert result.exit_code == 0
    parsed = loader(result.stdout)
    assert parsed["run_id"] == "run-fixture"
    assert parsed["scenario_count"] == 2
    assert "Run directory" not in result.stdout


# ---------------------------------------------------------------------------
# profile (Taxonomy CLI commands 09)
# ---------------------------------------------------------------------------


def test_profile_writes_capability_profile(tmp_path: Path) -> None:
    """profile writes the capability profile YAML and announces the path."""
    output = tmp_path / "fixtures" / "capability-profile.yaml"
    profile = SimpleNamespace(
        model_dump=lambda mode: {
            "zones_active": ["input", "reasoning"],
            "entry_points": [{"name": "chat", "direction": "input"}],
            "confidence": "high",
            "kc_subcodes": ["KC1.1"],
        }
    )
    llm_result = SimpleNamespace(prompt_tokens=10, completion_tokens=5, duration_ms=42)

    with patch(
        "asago_scenario_generator.pipeline.runner.run_profile_only",
        return_value=(profile, llm_result),
    ) as mock_run:
        result = runner.invoke(
            app, ["profile", "--use-case", "A chatbot", "--output", str(output)]
        )

    assert result.exit_code == 0
    assert f"Profile written to {output}" in result.stdout
    parsed = yaml.safe_load(output.read_text(encoding="utf-8"))
    assert parsed["entry_points"][0]["name"] == "chat"
    mock_run.assert_called_once()


# ---------------------------------------------------------------------------
# projection-preflight success report (Taxonomy CLI commands 10)
# ---------------------------------------------------------------------------


def test_projection_preflight_prints_json_report(tmp_path: Path) -> None:
    """projection-preflight prints a JSON requirements report on stdout."""
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
    assert {
        "readiness",
        "fact_states",
        "facts_template",
        "explicit_facts_source",
    } <= set(parsed)
    assert parsed["readiness"]["ready"] is True
    assert parsed["explicit_facts_source"] is False
    mock_run.assert_called_once()
