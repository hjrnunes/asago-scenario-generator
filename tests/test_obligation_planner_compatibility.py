"""Compatibility tests for the planner and standalone diagnostic STPA."""

from __future__ import annotations

from typer.testing import CliRunner

from asago_scenario_generator.cli import app
from tests.helpers.obligation_factory import make_plan

runner = CliRunner()


def test_stpa_run_help_omits_obligation_planner_flags() -> None:
    """Standalone diagnostic STPA does not pretend to include obligations."""
    stpa_run = runner.invoke(app, ["stpa-run", "--help"])

    assert stpa_run.exit_code == 0
    assert "obligation-planner" not in stpa_run.stdout.lower()


def test_standalone_plan_has_no_provider_or_generation_counters() -> None:
    """Phase 1 remains observational and does not claim generation activity."""
    plan = make_plan()
    payload = plan.model_dump(mode="json")

    assert "network_calls" not in payload
    assert "model_calls" not in payload
    assert "generation_inputs_digest" not in payload
