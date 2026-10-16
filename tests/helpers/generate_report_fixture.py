"""A trimmed generate output directory to render reports from.

The fixture under ``tests/fixtures/generate_report`` holds eight scenarios of a
recorded MiniKlarna run with the sidecars the report reads; ``calls.jsonl`` has
no prompt or response text. Tests copy it before changing it.
"""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import Any

import yaml

from asago_scenario_generator.report_kit import read_metrics
from asago_scenario_generator.stpa.infra.call_log import jsonl_lines

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
    calls = [json.loads(line) for line in jsonl_lines(path.read_text())]
    change(calls)
    path.write_text("".join(json.dumps(call) + "\n" for call in calls))


def metrics(html: str) -> dict[str, int]:
    """Return the integer value of each metric a rendered section declares."""
    return {k: int(v["value"]) for k, v in read_metrics(html).items()}


def body_rows(html: str, table_id: str) -> int:
    """Count the rows with data cells in the table whose id is *table_id*."""
    table = re.search(rf'<table[^>]*id="{table_id}".*?</table>', html, re.S).group(0)
    return len(re.findall(r"<tr[^>]*>\s*<td", table))
