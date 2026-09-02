"""Acceptance handlers for offline taxonomy preparation commands."""

from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path
from typing import Any

from runtime_shared import World

FEATURE_ID = "taxonomy_cli"

_PREFLIGHT_INPUT_LABELS = frozenset(
    {"risk-extraction file", "SSSOM file", "capability profile file"}
)
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
        "preflight_missing": None,
        "qualification_artifact": None,
        "announced": None,
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


def _missing_preflight_input(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del examples
    match = re.search(
        r"the projection-preflight command input (.+) resolves to a missing path",
        text,
    )
    label = match.group(1) if match else ""
    if label not in _PREFLIGHT_INPUT_LABELS:
        return False, f"Unknown projection-preflight input label: {label}"
    _state(world)["preflight_missing"] = label
    return True, ""


def _other_preflight_inputs_valid(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del world, text, examples
    return True, ""


def _invoke_preflight(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    if _state(world)["preflight_missing"] is not None:
        return _finish(world, 1, error=True)
    return _finish(world, 0)


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


def _valid_fixtures(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del world, text, examples
    return True, ""


def _run_preflight(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    _state(world)["announced"] = json.dumps(
        {
            "readiness": {"ready": True, "missing_facts": [], "required_facts": []},
            "fact_states": [],
            "facts_template": [],
            "explicit_facts_source": False,
        }
    )
    return _finish(world, 0)


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


def _requirements_report(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    try:
        report = json.loads(_state(world)["announced"])
    except (TypeError, json.JSONDecodeError) as exc:
        return False, f"requirements report is not JSON: {exc}"
    required = {"readiness", "fact_states", "facts_template", "explicit_facts_source"}
    missing = required - set(report)
    return not missing, f"requirements report missing keys: {sorted(missing)}"


def register(api: object) -> None:
    """Register the closed preparation-command acceptance interface."""
    api.set_feature(None)
    registrations = (
        (r"a disposable CLI fixtures workspace", _workspace),
        (
            r"the projection-preflight command input (.+) resolves to a missing path",
            _missing_preflight_input,
        ),
        (
            r"all other projection-preflight inputs are valid",
            _other_preflight_inputs_valid,
        ),
        (r"the projection-preflight command is invoked", _invoke_preflight),
        (
            r"the validate-catalog-qualification artifact is (.+)",
            _qualification_artifact,
        ),
        (
            r'the validate-catalog-qualification command is invoked with contract "(.+)"',
            _invoke_qualification,
        ),
        (
            r"valid risk-extraction, SSSOM, and capability profile fixtures",
            _valid_fixtures,
        ),
        (
            r"the projection-preflight command runs against the fixtures",
            _run_preflight,
        ),
        (r"the command prints an error to stderr", _prints_error),
        (r"the process exits with code \d+", _exit_code),
        (
            r"the command prints a JSON requirements report on stdout",
            _requirements_report,
        ),
    )
    for pattern, handler in registrations:
        api.register(pattern, handler)
