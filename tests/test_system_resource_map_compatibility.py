"""Focused unit tests for system resource map compatibility."""

from __future__ import annotations

from tests.cli_helpers import PlainCliRunner

from asago_scenario_generator.cli import app

runner = PlainCliRunner()


def test_generate_help_omits_manual_resource_map_flags() -> None:
    """The product command accepts no caller-substituted map flag."""
    product_run = runner.invoke(app, ["generate", "--help"])

    assert product_run.exit_code == 0
    assert "resource-map" not in product_run.stdout.lower()
