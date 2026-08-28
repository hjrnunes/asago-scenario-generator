"""Compatibility tests for keeping the peer generation surfaces unchanged."""

from __future__ import annotations

from typer.testing import CliRunner

from asago_scenario_generator.cli import app
from tests.helpers.obligation_factory import make_plan

runner = CliRunner()


def test_obligation_planner_does_not_add_default_io_side_effects() -> None:
    """Importing the planner does not change existing pipeline output defaults."""
    from asago_scenario_generator.pipeline import io

    assert not hasattr(io, "DEFAULT_WRITE_OBLIGATION_PLAN")


def test_generate_and_stpa_run_help_omit_obligation_planner_flags() -> None:
    """The peer taxonomy/risk and STPA commands retain their public surfaces."""
    generate = runner.invoke(app, ["generate", "--help"])
    stpa_run = runner.invoke(app, ["stpa-run", "--help"])

    assert generate.exit_code == 0
    assert stpa_run.exit_code == 0
    assert "obligation" not in generate.stdout.lower()
    assert "obligation" not in stpa_run.stdout.lower()


def test_standalone_plan_has_no_provider_or_generation_counters() -> None:
    """Phase 1 remains observational and does not claim generation activity."""
    plan = make_plan()
    payload = plan.model_dump(mode="json")

    assert "network_calls" not in payload
    assert "model_calls" not in payload
    assert "generation_inputs_digest" not in payload
