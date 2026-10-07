"""Named-fixture handlers replace APS-incompatible step data tables."""

from __future__ import annotations

import json
import sys
from pathlib import Path

_PROJECT_ROOT = next(
    p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file()
)
_ACCEPTANCE_DIR = _PROJECT_ROOT / "acceptance"
sys.path.insert(0, str(_ACCEPTANCE_DIR))

from acceptance_runtime import execute_step  # noqa: E402
from runtime_shared import World  # noqa: E402


def _run(text: str, examples: dict | None = None) -> World:
    world = World()
    ok, output = execute_step(world, {"keyword": "Given", "text": text}, examples or {})
    assert ok, output
    return world


def test_standard_four_call_fixture_writes_four_jsonl_entries():
    world = _run("the standard four-call calls.jsonl fixture")
    entries = [
        json.loads(line) for line in world.calls_jsonl_path.read_text().splitlines()
    ]

    assert [entry["step"] for entry in entries] == [
        "call_1a_losses",
        "call_1b_profile",
        "call_2a_responsibilities",
        "call_2_requirements",
    ]
    assert entries[3]["success"] is False
    assert entries[3]["error"] == "timeout exceeded"


def test_two_successful_call_fixture_writes_two_jsonl_entries():
    world = _run("a two-successful-call calls.jsonl fixture")
    entries = [
        json.loads(line) for line in world.calls_jsonl_path.read_text().splitlines()
    ]

    assert [entry["stage"] for entry in entries] == ["stage_1a", "stage_2"]
    assert all(entry["success"] is True for entry in entries)
