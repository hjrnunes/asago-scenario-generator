"""Hardening tests for the retained STPA and preparation CLI surfaces."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from typer.testing import CliRunner

from asago_scenario_generator.cli import _VERSION, app

runner = CliRunner()


def _write(path: Path, text: str = "fixture") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_bare_invocation_prints_version_banner() -> None:
    result = runner.invoke(app, [])

    assert result.exit_code == 0
    assert (
        f"asago-scenario-generator v{_VERSION} — use --help for commands"
        in result.stdout
    )


def test_validate_stpa_projection_rejects_non_object_on_stderr(
    tmp_path: Path,
) -> None:
    artifact = _write(tmp_path / "projection.json", "[]")

    result = runner.invoke(app, ["validate-stpa-projection", str(artifact)])

    assert result.exit_code == 1
    assert result.stderr.startswith("Error:")
    assert result.stdout == ""


def test_stpa_run_reports_first_abort_error_on_stderr(tmp_path: Path) -> None:
    result_obj = SimpleNamespace(
        stage_errors=[
            "stopping pipeline: missing loss-analysis",
            "stopping pipeline: missing control structure",
        ]
    )

    with patch(
        "asago_scenario_generator.stpa.pipeline.run_stpa_pipeline",
        return_value=result_obj,
    ):
        result = runner.invoke(
            app,
            [
                "stpa-run",
                "--use-case",
                str(_write(tmp_path / "use-case.txt", "My system")),
                "--risk-extraction",
                str(_write(tmp_path / "risk-extraction.json")),
                "--output-dir",
                str(tmp_path / "out"),
            ],
        )

    assert result.exit_code == 1
    assert "Error: stopping pipeline: missing loss-analysis" in result.stderr
    assert "missing control structure" not in result.stderr
    assert "Advanced baseline STPA run" in result.stdout


def test_stpa_report_rejects_missing_output_dir(tmp_path: Path) -> None:
    missing = tmp_path / "missing" / "run"

    result = runner.invoke(app, ["stpa-report", "--output-dir", str(missing)])

    assert result.exit_code == 1
    assert f"Error: output directory not found: {missing}" in result.stderr


def test_stpa_report_writes_and_announces(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    output = tmp_path / "stpa-report.html"

    def _write_report(out_dir: Path, out: Path | None) -> Path:
        out_dir.mkdir(parents=True, exist_ok=True)
        assert out is not None
        out.write_text("<html>stpa</html>", encoding="utf-8")
        return out

    with patch(
        "asago_scenario_generator.stpa.report.generate_report",
        side_effect=_write_report,
    ):
        result = runner.invoke(
            app,
            [
                "stpa-report",
                "--output-dir",
                str(run_dir),
                "--output",
                str(output),
            ],
        )

    assert result.exit_code == 0
    assert f"STPA report written to: {output}" in result.stdout
    assert output.read_text(encoding="utf-8") == "<html>stpa</html>"


def test_stpa_report_failure_reported_on_stderr(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    with patch(
        "asago_scenario_generator.stpa.report.generate_report",
        side_effect=RuntimeError("boom"),
    ):
        result = runner.invoke(app, ["stpa-report", "--output-dir", str(run_dir)])

    assert result.exit_code == 1
    assert "Error: boom" in result.stderr


def test_projection_preflight_rejects_optional_input(tmp_path: Path) -> None:
    risk = _write(tmp_path / "inputs" / "risk-extraction.json", "{}")
    sssom = _write(tmp_path / "inputs" / "sssom.tsv")
    profile = _write(tmp_path / "inputs" / "capability-profile.yaml", "{}")
    missing = tmp_path / "missing" / "facts.yaml"

    with patch(
        "asago_scenario_generator.pipeline.preflight.run_projection_preflight"
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
                "--qualification-facts",
                str(missing),
            ],
        )

    assert result.exit_code == 1
    assert f"Error: qualification facts file not found: {missing}" in result.stderr
    mock_run.assert_not_called()


def test_projection_preflight_writes_facts_template(tmp_path: Path) -> None:
    risk = _write(tmp_path / "inputs" / "risk-extraction.json", "{}")
    sssom = _write(tmp_path / "inputs" / "sssom.tsv")
    profile = _write(tmp_path / "inputs" / "capability-profile.yaml", "{}")
    template = tmp_path / "fixtures" / "facts-template.yaml"
    outcome = SimpleNamespace(
        model_dump=lambda mode: {
            "readiness": {"ready": True, "missing_facts": [], "required_facts": []},
            "fact_states": [],
            "facts_template": [],
            "explicit_facts_source": False,
        }
    )

    with (
        patch(
            "asago_scenario_generator.pipeline.preflight.run_projection_preflight",
            return_value=outcome,
        ),
        patch(
            "asago_scenario_generator.pipeline.preflight.write_facts_template"
        ) as mock_template,
    ):
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
                "--facts-template",
                str(template),
            ],
        )

    assert result.exit_code == 0
    mock_template.assert_called_once()
    assert json.loads(result.stdout)["readiness"]["ready"] is True


def test_stpa_run_succeeds_without_abort_errors(tmp_path: Path) -> None:
    result_obj = SimpleNamespace(stage_errors=["stage 3 degraded"])

    with patch(
        "asago_scenario_generator.stpa.pipeline.run_stpa_pipeline",
        return_value=result_obj,
    ):
        result = runner.invoke(
            app,
            [
                "stpa-run",
                "--use-case",
                str(_write(tmp_path / "use-case.txt", "My system")),
                "--risk-extraction",
                str(_write(tmp_path / "risk-extraction.json")),
                "--output-dir",
                str(tmp_path / "out"),
            ],
        )

    assert result.exit_code == 0
    assert "Advanced baseline STPA run" in result.stdout
