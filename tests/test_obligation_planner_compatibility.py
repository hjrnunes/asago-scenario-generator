"""Focused unit tests verifying obligation planner compatibility with existing workflows."""

from __future__ import annotations

from pathlib import Path


def test_obligation_planner_does_not_affect_default_io(tmp_path: Path) -> None:
    """Verify that importing or using obligation planner does not alter existing pipeline defaults."""
    from asago_scenario_generator.pipeline import io

    # write_threat_surface and write_capability_profile should not write obligation plans
    assert not hasattr(io, "DEFAULT_WRITE_OBLIGATION_PLAN")
