"""Hardening tests for CLI behaviours mutation testing exposed.

Each test kills a surviving mutant in ``src/asago_scenario_generator/cli``:
catch-all error handlers must re-raise ``typer.Exit`` with its own exit
code, banners and errors must land on their documented streams, output
parents must be created where the command promises, and optional inputs
must keep their validation.
"""

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
    """Running the CLI with no command still prints the version banner."""
    result = runner.invoke(app, [])
    assert result.exit_code == 0
    assert (
        f"asago-scenario-generator v{_VERSION} — use --help for commands"
        in result.stdout
    )


def test_generate_banner_prints_on_stdout(tmp_path: Path) -> None:
    """The generate banner is announced on stdout even when validation fails."""
    missing = tmp_path / "missing" / "risk-extraction.json"
    valid = _write(tmp_path / "inputs" / "sssom.tsv")

    with patch("asago_scenario_generator.pipeline.runner.run_pipeline") as mock_run:
        result = runner.invoke(
            app,
            [
                "generate",
                "--use-case",
                "A chatbot",
                "--risk-extraction",
                str(missing),
                "--sssom",
                str(valid),
            ],
        )

    assert result.exit_code == 1
    assert f"asago-scenario-generator v{_VERSION} — generate" in result.stdout
    mock_run.assert_not_called()


def test_generate_validates_model_profiles_file(tmp_path: Path) -> None:
    """--model-profile still requires a readable model-profiles file."""
    valid = _write(tmp_path / "inputs" / "valid.tsv")
    missing = tmp_path / "missing" / "profiles.yaml"

    with patch("asago_scenario_generator.pipeline.runner.run_pipeline") as mock_run:
        result = runner.invoke(
            app,
            [
                "generate",
                "--use-case",
                "A chatbot",
                "--risk-extraction",
                str(valid),
                "--sssom",
                str(valid),
                "--model-profile",
                "fast",
                "--profiles-file",
                str(missing),
            ],
        )

    assert result.exit_code == 1
    assert f"Error: model profiles file not found: {missing}" in result.stderr
    mock_run.assert_not_called()


def test_profile_writes_into_existing_parent_directory(tmp_path: Path) -> None:
    """profile logs and writes the profile when the output parent exists."""
    out_dir = tmp_path / "fixtures"
    out_dir.mkdir()
    output = out_dir / "capability-profile.yaml"
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
    assert (out_dir / "pipeline.log").exists()
    mock_run.assert_called_once()


def test_report_writes_to_nested_output_directory(tmp_path: Path) -> None:
    """report creates missing output parents before generating."""
    run_dir = tmp_path / "run"
    _write(run_dir / "run-manifest.yaml", "status: completed")
    output = tmp_path / "deep" / "nested" / "report.html"

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
            app, ["report", "--output-dir", str(run_dir), "--output", str(output)]
        )

    assert result.exit_code == 0
    assert f"Report written to {output}" in result.stdout
    assert output.read_text(encoding="utf-8") == "<html>report</html>"


def test_report_failure_is_reported_on_stderr(tmp_path: Path) -> None:
    """Errors raised while building the report are reported on stderr."""
    run_dir = tmp_path / "run"
    _write(run_dir / "run-manifest.yaml", "status: completed")

    with patch(
        "asago_scenario_generator.manifest.find_run_dir",
        side_effect=RuntimeError("boom"),
    ):
        result = runner.invoke(app, ["report", "--output-dir", str(run_dir)])

    assert result.exit_code == 1
    assert "Error: boom" in result.stderr


def test_validate_stpa_projection_rejects_non_object_on_stderr(
    tmp_path: Path,
) -> None:
    """A non-object projection payload is rejected on stderr with exit 1."""
    artifact = _write(tmp_path / "projection.json", "[]")
    result = runner.invoke(app, ["validate-stpa-projection", str(artifact)])
    assert result.exit_code == 1
    assert result.stderr.startswith("Error:")
    assert result.stdout == ""


def test_stpa_run_reports_first_abort_error_on_stderr(tmp_path: Path) -> None:
    """stpa-run announces the first pipeline-stopping error on stderr."""
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


def _pipeline_result(status: str = "completed") -> SimpleNamespace:
    """Build a mock pipeline result for the generate command."""
    return SimpleNamespace(
        manifest_status=SimpleNamespace(value=status),
        admitted_count=2,
        quarantined_count=0,
        failed_count=0,
        scenarios=["scn-1"],
        seeds=["scn-1", "scn-2"],
        governance_only_count=0,
        run_dir="output/run-fixture",
    )


def _generate_args(tmp_path: Path) -> list[str]:
    """Build valid generate arguments backed by fixture files."""
    valid = _write(tmp_path / "inputs" / "valid.tsv")
    return [
        "generate",
        "--use-case",
        "A chatbot",
        "--risk-extraction",
        str(valid),
        "--sssom",
        str(valid),
    ]


def test_generate_successful_pipeline_exits_zero(tmp_path: Path) -> None:
    """A completed pipeline run prints the summary and exits with code 0."""
    with patch(
        "asago_scenario_generator.pipeline.runner.run_pipeline",
        return_value=_pipeline_result(),
    ) as mock_run:
        result = runner.invoke(app, _generate_args(tmp_path))

    assert result.exit_code == 0
    assert "Pipeline complete." in result.stdout
    assert "Manifest status:      completed" in result.stdout
    mock_run.assert_called_once()


def test_generate_error_status_exits_one(tmp_path: Path) -> None:
    """A completed-with-errors pipeline run exits with code 1."""
    with patch(
        "asago_scenario_generator.pipeline.runner.run_pipeline",
        return_value=_pipeline_result(status="completed_with_errors"),
    ):
        result = runner.invoke(app, _generate_args(tmp_path))

    assert result.exit_code == 1
    assert "Pipeline completed with errors." in result.stdout


def test_generate_rejects_unknown_presentation_fallback(tmp_path: Path) -> None:
    """An unsupported presentation-fallback value is rejected up front."""
    with patch("asago_scenario_generator.pipeline.runner.run_pipeline") as mock_run:
        result = runner.invoke(
            app, [*_generate_args(tmp_path), "--presentation-fallback", "maybe"]
        )

    assert result.exit_code != 0
    assert "must be 'allow' or 'forbid'" in result.stderr
    mock_run.assert_not_called()


def test_generate_validates_optional_cross_taxonomy_input(tmp_path: Path) -> None:
    """A supplied optional cross-taxonomy input is validated like the rest."""
    missing = tmp_path / "missing" / "cross-taxonomy.yaml"

    with patch("asago_scenario_generator.pipeline.runner.run_pipeline") as mock_run:
        result = runner.invoke(
            app, [*_generate_args(tmp_path), "--cross-taxonomy", str(missing)]
        )

    assert result.exit_code == 1
    assert f"Error: cross-taxonomy file not found: {missing}" in result.stderr
    mock_run.assert_not_called()


def test_stpa_report_rejects_missing_output_dir(tmp_path: Path) -> None:
    """stpa-report rejects a missing output directory on stderr."""
    missing = tmp_path / "missing" / "run"
    result = runner.invoke(app, ["stpa-report", "--output-dir", str(missing)])
    assert result.exit_code == 1
    assert f"Error: output directory not found: {missing}" in result.stderr


def test_stpa_report_writes_and_announces(tmp_path: Path) -> None:
    """stpa-report writes the HTML report and announces its path."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    output = tmp_path / "stpa-report.html"

    def _write_report(out_dir: Path, out: Path | None) -> Path:
        out_dir.mkdir(parents=True, exist_ok=True)
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
    """Errors raised while generating the STPA report go to stderr."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    with patch(
        "asago_scenario_generator.stpa.report.generate_report",
        side_effect=RuntimeError("boom"),
    ):
        result = runner.invoke(app, ["stpa-report", "--output-dir", str(run_dir)])

    assert result.exit_code == 1
    assert "Error: boom" in result.stderr


def test_profile_prints_yaml_to_stdout_without_output(tmp_path: Path) -> None:
    """profile without --output prints the profile YAML on stdout."""
    profile = SimpleNamespace(
        model_dump=lambda mode: {
            "zones_active": ["input", "reasoning"],
            "entry_points": [{"name": "chat", "direction": "input"}],
        }
    )
    llm_result = SimpleNamespace(prompt_tokens=10, completion_tokens=5, duration_ms=42)

    with patch(
        "asago_scenario_generator.pipeline.runner.run_profile_only",
        return_value=(profile, llm_result),
    ):
        result = runner.invoke(app, ["profile", "--use-case", "A chatbot"])

    assert result.exit_code == 0
    assert "zones_active" in result.stdout
    assert "LLM tokens: 10 prompt" in result.stdout


def test_profile_failure_reported_on_stderr(tmp_path: Path) -> None:
    """Errors raised while profiling go to stderr with exit 1."""
    with patch(
        "asago_scenario_generator.pipeline.runner.run_profile_only",
        side_effect=RuntimeError("boom"),
    ):
        result = runner.invoke(app, ["profile", "--use-case", "A chatbot"])

    assert result.exit_code == 1
    assert "Error: boom" in result.stderr


def test_report_emits_html_to_stdout(tmp_path: Path) -> None:
    """report without --output emits the rendered HTML on stdout."""
    run_dir = tmp_path / "run"
    _write(run_dir / "run-manifest.yaml", "status: completed")

    def _write_report(data, out_dir: Path) -> Path:
        path = Path(out_dir) / "report.html"
        path.write_text("<html>stdout report</html>", encoding="utf-8")
        return path

    with (
        patch("asago_scenario_generator.manifest.find_run_dir", return_value=run_dir),
        patch("asago_scenario_generator.report.data.load_report_data", return_value={}),
        patch(
            "asago_scenario_generator.report.generator.generate_report",
            side_effect=_write_report,
        ),
    ):
        result = runner.invoke(app, ["report", "--output-dir", str(run_dir)])

    assert result.exit_code == 0
    assert "<html>stdout report</html>" in result.stdout


def test_eval_failure_reported_on_stderr(tmp_path: Path) -> None:
    """Errors raised while evaluating go to stderr with exit 1."""
    run_dir = tmp_path / "run"
    _write(run_dir / "run-manifest.yaml", "status: completed")

    with patch(
        "asago_scenario_generator.eval.runner.run_evaluation",
        side_effect=RuntimeError("boom"),
    ):
        result = runner.invoke(app, ["eval", "--output-dir", str(run_dir)])

    assert result.exit_code == 1
    assert "Error: boom" in result.stderr


def test_projection_preflight_rejects_optional_input(tmp_path: Path) -> None:
    """A supplied optional preflight input is validated like the rest."""
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
    """projection-preflight writes the facts template when requested."""
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
    """stpa-run exits 0 when the pipeline only reports degrade-level errors."""
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
    assert result.stdout == ""
