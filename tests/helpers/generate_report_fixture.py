"""A trimmed generate output directory to render reports from.

``tests/fixtures/generate_report/klarna-r1`` holds eight scenarios of a recorded
klarna run with the sidecars the report reads; ``calls.jsonl`` has no prompt or
response text. Tests copy it before changing it.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import yaml

FIXTURE = Path(__file__).parent.parent / "fixtures" / "generate_report" / "klarna-r1"
SCENARIOS = "SCN-001 SCN-002 SCN-003 SCN-004 SCN-006 SCN-011 SCN-012 SCN-023".split()


def copy_run(tmp_path: Path) -> Path:
    """Copy the fixture into *tmp_path* and return the copy."""
    target = tmp_path / "output"
    shutil.copytree(FIXTURE, target)
    return target


def edit_yaml(path: Path, change: Any) -> None:
    """Load a YAML file, let *change* mutate the value in place, and save it."""
    value = yaml.safe_load(path.read_text())
    change(value)
    path.write_text(yaml.safe_dump(value, sort_keys=False, allow_unicode=True))


def edit_calls(output: Path, change: Any) -> None:
    """Let *change* mutate the list of call records, then save ``calls.jsonl``."""
    path = output / "calls.jsonl"
    calls = [json.loads(line) for line in path.read_text().splitlines()]
    change(calls)
    path.write_text("".join(json.dumps(call) + "\n" for call in calls))
