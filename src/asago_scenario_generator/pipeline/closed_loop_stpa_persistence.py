"""Atomic persistence for one bounded Phase 3 closed-loop STPA run."""

from __future__ import annotations

from pathlib import Path

from asago_scenario_generator.manifest import atomic_write_text
from asago_scenario_generator.models.closed_loop_stpa import ClosedLoopStpaRun


STPA_CLOSED_LOOP_RUN_FILENAME = "stpa-obligation-closed-loop-run.yaml"


def write_closed_loop_stpa_run(output_dir: Path, run: ClosedLoopStpaRun) -> Path:
    """Validate, atomically publish, reload, and compare one closed-loop run."""
    run.assert_integrity()
    target = Path(output_dir) / STPA_CLOSED_LOOP_RUN_FILENAME
    atomic_write_text(target, run.to_yaml())
    loaded = ClosedLoopStpaRun.from_yaml(target.read_bytes())
    if loaded != run:
        raise ValueError("persisted closed-loop STPA run changed on round-trip")
    return target


def read_closed_loop_stpa_run(path: Path) -> ClosedLoopStpaRun:
    """Read one normative closed-loop run without repair."""
    candidate = Path(path)
    if candidate.name != STPA_CLOSED_LOOP_RUN_FILENAME:
        raise ValueError(
            f"expected {STPA_CLOSED_LOOP_RUN_FILENAME}, got {candidate.name}"
        )
    return ClosedLoopStpaRun.from_yaml(candidate.read_bytes())


__all__ = [
    "STPA_CLOSED_LOOP_RUN_FILENAME",
    "read_closed_loop_stpa_run",
    "write_closed_loop_stpa_run",
]
