"""Atomic persistence for the Phase 4 hybrid projection-set artifact."""

from __future__ import annotations

from pathlib import Path

from asago_scenario_generator.manifest import atomic_write_text
from asago_scenario_generator.models.hybrid_scenario_projection import (
    HybridScenarioProjectionSet,
)


HYBRID_SCENARIO_PROJECTION_SET_FILENAME = "hybrid-scenario-projection-set.yaml"


def write_hybrid_scenario_projection_set(
    output_dir: Path,
    projection_set: HybridScenarioProjectionSet,
) -> Path:
    """Atomically publish one intact projection set and verify its reload."""
    projection_set.assert_integrity()
    serialized = projection_set.to_yaml()

    # Check the closed parser before touching the destination.  This keeps a
    # serialization or model-load discrepancy from publishing anything.
    preloaded = HybridScenarioProjectionSet.from_yaml(serialized)
    _verify_round_trip(projection_set, preloaded, serialized)

    target = Path(output_dir) / HYBRID_SCENARIO_PROJECTION_SET_FILENAME
    atomic_write_text(target, serialized)

    loaded = read_hybrid_scenario_projection_set(target)
    _verify_round_trip(projection_set, loaded, serialized)
    if target.read_bytes() != serialized.encode("utf-8"):
        raise ValueError(
            "persisted hybrid projection set differs from canonical YAML bytes"
        )
    return target


def read_hybrid_scenario_projection_set(
    path: Path,
) -> HybridScenarioProjectionSet:
    """Read and integrity-check the normative projection-set YAML artifact."""
    candidate = Path(path)
    if candidate.name != HYBRID_SCENARIO_PROJECTION_SET_FILENAME:
        raise ValueError(
            f"expected {HYBRID_SCENARIO_PROJECTION_SET_FILENAME}, got {candidate.name}"
        )
    return HybridScenarioProjectionSet.from_yaml(candidate.read_bytes())


def _verify_round_trip(
    expected: HybridScenarioProjectionSet,
    loaded: HybridScenarioProjectionSet,
    serialized: str,
) -> None:
    """Require digest, value equality, and canonical bytes to survive reload."""
    if loaded.semantic_digest != expected.semantic_digest:
        raise ValueError("persisted hybrid projection set digest changed on round-trip")
    if loaded != expected:
        raise ValueError("persisted hybrid projection set failed round-trip equality")
    if loaded.to_yaml() != serialized:
        raise ValueError(
            "persisted hybrid projection set differs from canonical serialization"
        )


__all__ = [
    "HYBRID_SCENARIO_PROJECTION_SET_FILENAME",
    "read_hybrid_scenario_projection_set",
    "write_hybrid_scenario_projection_set",
]
