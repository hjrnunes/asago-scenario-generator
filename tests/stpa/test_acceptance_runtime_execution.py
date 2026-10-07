"""Unit contracts for IR execution: example isolation and outcome reporting."""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

import pytest

_PROJECT_ROOT = next(
    path
    for path in Path(__file__).resolve().parents
    if (path / "pyproject.toml").is_file()
)
sys.path.insert(0, str(_PROJECT_ROOT / "acceptance"))

import acceptance_runtime  # noqa: E402

_BACKGROUND = "background observes its world"
_MUTATE = "first example changes its state"
_SCENARIO = "scenario observes its world"
_PASSING = "supported passing step"
_ENV_NAME = "ACCEPTANCE_RUNTIME_EXECUTION_TEST"


def _ir(steps: list[str], *, background=(), examples=()) -> dict:
    return {
        "name": "contract",
        "background": [{"keyword": "Given", "text": text} for text in background],
        "scenarios": [
            {
                "name": "contract",
                "steps": [{"keyword": "Then", "text": text} for text in steps],
                "examples": list(examples),
            }
        ],
    }


def _write(directory: Path, payload: dict, name: str = "fixture.json") -> str:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


def _install(monkeypatch, handlers: dict[str, object]) -> None:
    monkeypatch.setattr(
        acceptance_runtime,
        "STEP_PATTERNS",
        [
            (re.compile(f"^{re.escape(text)}$", re.IGNORECASE), handler, None)
            for text, handler in handlers.items()
        ],
    )


@pytest.mark.parametrize("first_result", ["passes", "fails"])
def test_each_example_gets_a_fresh_world_and_the_original_environment(
    tmp_path: Path, monkeypatch, first_result: str
) -> None:
    monkeypatch.delenv(_ENV_NAME, raising=False)
    observed: dict[str, dict] = {}

    def background(world, text, examples):
        world.token = object()
        observed.setdefault(examples["row"], {})["background"] = world.token
        observed[examples["row"]]["environment"] = os.environ.get(_ENV_NAME)
        return True, ""

    def mutate(world, text, examples):
        if examples["row"] == "first":
            world.dirty = True
            os.environ[_ENV_NAME] = "changed-by-first-example"
        return True, ""

    def scenario(world, text, examples):
        observed[examples["row"]]["scenario"] = getattr(world, "token", None)
        observed[examples["row"]]["dirty"] = hasattr(world, "dirty")
        return not (examples["row"] == "first" and first_result == "fails"), "injected"

    _install(
        monkeypatch, {_BACKGROUND: background, _MUTATE: mutate, _SCENARIO: scenario}
    )
    path = _write(
        tmp_path / "acceptance-refresh",
        _ir(
            [_MUTATE, _SCENARIO],
            background=[_BACKGROUND],
            examples=[{"row": "first"}, {"row": "second"}],
        ),
        "nested.json",
    )
    environment_before = dict(os.environ)

    with acceptance_runtime.execution_feature("enclosing"):
        passed, output = acceptance_runtime.execute_ir(path)
        assert acceptance_runtime._CURRENT_EXECUTION_FEATURE == "enclosing"

    assert passed is (first_result == "passes")
    assert output.count("example_") == 2
    for row in ("first", "second"):
        assert observed[row]["scenario"] is observed[row]["background"]
    assert observed["first"]["background"] is not observed["second"]["background"]
    assert observed["second"]["environment"] is None
    assert observed["second"]["dirty"] is False
    assert dict(os.environ) == environment_before


@pytest.mark.parametrize(
    ("steps", "handlers", "passed", "status"),
    [
        ([_PASSING], {_PASSING: lambda w, t, e: (True, "")}, True, "PASS"),
        (["unsupported contract step"], {}, False, "FAIL"),
    ],
    ids=["supported-passing-step", "unsupported-step"],
)
def test_execution_reports_each_outcome_without_conflation(
    tmp_path: Path, monkeypatch, steps, handlers, passed: bool, status: str
) -> None:
    _install(monkeypatch, handlers)

    result, output = acceptance_runtime.execute_ir(_write(tmp_path, _ir(steps)))

    assert result is passed
    assert output.splitlines()[0].startswith(f"{status} contract/example_1")
