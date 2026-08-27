"""Focused unit tests for system resource map compatibility."""

from __future__ import annotations

from pathlib import Path


def test_system_resource_map_does_not_modify_default_io(tmp_path: Path) -> None:
    from asago_scenario_generator.pipeline import io

    assert not hasattr(io, "DEFAULT_WRITE_RESOURCE_MAP")
