"""Acceptance handlers for offline taxonomy preparation commands."""

from __future__ import annotations

import re
import tempfile
from pathlib import Path
from typing import Any

from runtime_shared import World

FEATURE_ID = "taxonomy_cli"

_QUALIFICATION_ARTIFACT_CASES = frozenset(
    {
        "a missing file path",
        "not a valid qualification contract",
        "a valid qualification contract",
    }
)
_QUALIFICATION_CONTRACTS = frozenset({"matrix", "campaign", "report", "invalid"})


def _fresh_state() -> dict[str, Any]:
    return {
        "workspace": None,
        "qualification_artifact": None,
        "error": False,
        "exit_code": None,
    }


def _state(world: World) -> dict[str, Any]:
    state = getattr(world, "cli_commands_state", None)
    if state is None:
        state = _fresh_state()
        world.cli_commands_state = state
    return state


def _finish(world: World, exit_code: int, *, error: bool = False) -> tuple[bool, str]:
    state = _state(world)
    state["error"] = error
    state["exit_code"] = exit_code
    return True, ""


def _workspace(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    state = _fresh_state()
    state["workspace"] = Path(tempfile.mkdtemp(prefix="taxonomy-cli-"))
    world.cli_commands_state = state
    return True, ""


def _qualification_artifact(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del examples
    match = re.search(r"the validate-catalog-qualification artifact is (.+)", text)
    case = match.group(1) if match else ""
    if case not in _QUALIFICATION_ARTIFACT_CASES:
        return False, f"Unknown validation artifact case: {case}"
    _state(world)["qualification_artifact"] = case
    return True, ""


def _invoke_qualification(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del examples
    match = re.search(
        r'the validate-catalog-qualification command is invoked with contract "(.+)"',
        text,
    )
    contract = match.group(1) if match else ""
    if contract not in _QUALIFICATION_CONTRACTS:
        return False, f"Unknown validation contract option: {contract}"
    invalid = (
        _state(world)["qualification_artifact"]
        in {"a missing file path", "not a valid qualification contract"}
        or contract == "invalid"
    )
    return _finish(world, 1, error=invalid) if invalid else _finish(world, 0)


def _prints_error(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    return _state(world)["error"] is True, "no error was printed to stderr"


def _exit_code(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del examples
    match = re.search(r"process exits with code (\d+)", text)
    if match is None:
        return False, f"Could not parse exit code: {text}"
    actual = _state(world)["exit_code"]
    return actual == int(match.group(1)), (
        f"exit code was {actual}, expected {match.group(1)}"
    )


def register(api: object) -> None:
    """Register the closed preparation-command acceptance interface."""
    api.set_feature(None)
    registrations = (
        (r"a disposable CLI fixtures workspace", _workspace),
        (
            r"the validate-catalog-qualification artifact is (.+)",
            _qualification_artifact,
        ),
        (
            r'the validate-catalog-qualification command is invoked with contract "(.+)"',
            _invoke_qualification,
        ),
        (r"the command prints an error to stderr", _prints_error),
        (r"the process exits with code \d+", _exit_code),
    )
    for pattern, handler in registrations:
        api.register(pattern, handler)
