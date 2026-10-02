"""Compatibility tests for the planner and standalone diagnostic STPA."""

from __future__ import annotations

from tests.cli_helpers import PlainCliRunner

from tests.helpers.obligation_factory import make_plan

runner = PlainCliRunner()




def test_standalone_plan_has_no_provider_or_generation_counters() -> None:
    """Phase 1 remains observational and does not claim generation activity."""
    plan = make_plan()
    payload = plan.model_dump(mode="json")

    assert "network_calls" not in payload
    assert "model_calls" not in payload
    assert "generation_inputs_digest" not in payload
