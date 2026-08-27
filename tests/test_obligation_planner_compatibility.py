"""Focused unit tests verifying obligation planner compatibility with existing workflows."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from asago_scenario_generator.cli import app

runner = CliRunner()


def test_obligation_planner_does_not_affect_default_io(tmp_path: Path) -> None:
    """Verify that importing or using obligation planner does not alter existing pipeline defaults."""
    from asago_scenario_generator.pipeline import io

    # write_threat_surface and write_capability_profile should not write obligation plans
    assert not hasattr(io, "DEFAULT_WRITE_OBLIGATION_PLAN")


def test_generate_and_stpa_run_help_omit_obligation_planner_flags() -> None:
    """Default generate and stpa-run surfaces do not grow obligation-planner flags."""
    generate = runner.invoke(app, ["generate", "--help"])
    stpa_run = runner.invoke(app, ["stpa-run", "--help"])

    assert generate.exit_code == 0
    assert stpa_run.exit_code == 0
    assert "obligation" not in generate.stdout.lower()
    assert "obligation" not in stpa_run.stdout.lower()
