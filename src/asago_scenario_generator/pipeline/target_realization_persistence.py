"""Atomic persistence for the target-realization artifact."""

from __future__ import annotations

from pathlib import Path

from asago_scenario_generator.manifest import write_text_atomically
from asago_scenario_generator.models.target_realization import (
    TargetRealizationResult,
)


TARGET_REALIZATION_FILENAME = "target-realization.yaml"


def write_target_realization(
    output_dir: Path,
    artifact: TargetRealizationResult,
) -> Path:
    """Atomically publish and verify one target-realization artifact."""
    if not isinstance(artifact, TargetRealizationResult):
        raise TypeError("artifact must be a TargetRealizationResult")
    artifact.assert_integrity()
    output_dir = Path(output_dir)
    path = output_dir / TARGET_REALIZATION_FILENAME
    write_text_atomically(path, artifact.to_yaml())
    reloaded = TargetRealizationResult.from_yaml(path.read_text(encoding="utf-8"))
    if reloaded != artifact:
        raise ValueError("persisted target realization failed round-trip equality")
    return path


persist_target_realization = write_target_realization


__all__ = [
    "TARGET_REALIZATION_FILENAME",
    "persist_target_realization",
    "write_target_realization",
]
