"""Read the ``calls.jsonl`` log that a run directory holds."""

from __future__ import annotations

from pathlib import Path

from asago_scenario_generator.stpa.infra.call_log import read_call_entries


def read_calls_jsonl(run_dir: Path) -> list[dict]:
    """Return the entries of ``run_dir/calls.jsonl``, or ``[]`` if absent.

    Publication events are folded into the entries they mark.
    """
    return read_call_entries(run_dir) or []


def stage1a_steps(run_dir: Path) -> list[str]:
    """Return the step names that Stage 1a logged, in call order."""
    return [
        entry["step"]
        for entry in read_calls_jsonl(run_dir)
        if entry["stage"] == "stage_1a"
    ]
