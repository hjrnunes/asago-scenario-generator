"""Focused unit tests for system resource map compatibility."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from asago_scenario_generator.cli import app

runner = CliRunner()


def test_system_resource_map_does_not_modify_default_io(tmp_path: Path) -> None:
    from asago_scenario_generator.pipeline import io

    assert not hasattr(io, "DEFAULT_WRITE_RESOURCE_MAP")


def test_generate_and_stpa_run_help_omit_resource_map_flags() -> None:
    """Default generate and stpa-run surfaces do not grow resource-map flags."""
    generate = runner.invoke(app, ["generate", "--help"])
    stpa_run = runner.invoke(app, ["stpa-run", "--help"])

    assert generate.exit_code == 0
    assert stpa_run.exit_code == 0
    assert "resource-map" not in generate.stdout.lower()
    assert "resource map" not in generate.stdout.lower()
    assert "resource-map" not in stpa_run.stdout.lower()
    assert "resource map" not in stpa_run.stdout.lower()
