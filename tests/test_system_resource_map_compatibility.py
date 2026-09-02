"""Focused unit tests for system resource map compatibility."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from asago_scenario_generator.cli import app

runner = CliRunner()


def test_system_resource_map_does_not_modify_default_io(tmp_path: Path) -> None:
    from asago_scenario_generator.pipeline import io

    assert not hasattr(io, "DEFAULT_WRITE_RESOURCE_MAP")


def test_run_and_stpa_run_help_omit_manual_resource_map_flags() -> None:
    """Neither STPA execution command accepts a caller-substituted map flag."""
    product_run = runner.invoke(app, ["run", "--help"])
    stpa_run = runner.invoke(app, ["stpa-run", "--help"])

    assert product_run.exit_code == 0
    assert stpa_run.exit_code == 0
    assert "resource-map" not in product_run.stdout.lower()
    assert "resource-map" not in stpa_run.stdout.lower()
