"""Read the ``calls.jsonl`` log that a run directory holds."""

from __future__ import annotations

import json
from pathlib import Path

from asago_scenario_generator.stpa.infra.call_log import jsonl_lines


def read_calls_jsonl(run_dir: Path) -> list[dict]:
    """Return the parsed entries of ``run_dir/calls.jsonl``, or ``[]`` if absent."""
    calls_file = run_dir / "calls.jsonl"
    if not calls_file.exists():
        return []
    return [
        json.loads(line) for line in jsonl_lines(calls_file.read_text(encoding="utf-8"))
    ]


def stage1a_steps(run_dir: Path) -> list[str]:
    """Return the step names that Stage 1a logged, in call order."""
    return [
        entry["step"]
        for entry in read_calls_jsonl(run_dir)
        if entry["stage"] == "stage_1a"
    ]
