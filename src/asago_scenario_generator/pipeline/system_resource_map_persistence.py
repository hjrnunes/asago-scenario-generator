"""Atomic YAML persistence adapter for the Phase 2 resource map."""

from __future__ import annotations

from pathlib import Path

from asago_scenario_generator.manifest import atomic_write_text
from asago_scenario_generator.models.system_resource_map import SystemResourceMap

SYSTEM_RESOURCE_MAP_FILENAME = "system-resource-map.yaml"


def write_system_resource_map(
    output_dir: Path,
    resource_map: SystemResourceMap,
) -> Path:
    """Validate, atomically write, reload, and compare one resource map."""
    resource_map.assert_integrity()
    target = Path(output_dir) / SYSTEM_RESOURCE_MAP_FILENAME
    atomic_write_text(target, resource_map.to_yaml())
    loaded = SystemResourceMap.from_yaml(target.read_text(encoding="utf-8"))
    if loaded != resource_map:
        raise ValueError("persisted system resource map failed round-trip equality")
    return target


__all__ = [
    "SYSTEM_RESOURCE_MAP_FILENAME",
    "write_system_resource_map",
]
