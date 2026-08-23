"""Deterministic acceptance handlers for the taxonomy CLI command contracts.

Models the up-front path-validation and success wiring of the public
taxonomy/risk CLI commands from ``features/taxonomy_cli_commands.feature``.
The handlers simulate the command outcomes in-world without subprocesses or
LLM endpoints; the end-to-end child-process verification lives in the QA
suite (``acceptance/qa/taxonomy_risk/cli_commands.md``).
"""

from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path
from typing import Any

import yaml
from runtime_shared import World

from runtime_features.taxonomy_risk import _taxonomy_state

FEATURE_ID = "taxonomy_cli"


def _fresh_cli_state() -> dict[str, Any]:
    """Return an empty CLI contract state for a scenario."""
    return {
        "workspace": None,
        "generate_missing": None,
        "preflight_missing": None,
        "vcq_artifact_case": None,
        "missing_run_dir_command": None,
        "report_dest": None,
        "scorecard_format": None,
        "announced": None,
        "error": False,
        "exit_code": None,
    }


def _cli_state(world: World) -> dict[str, Any]:
    """Return the scenario-local CLI contract state, creating it when needed."""
    state = getattr(world, "cli_commands_state", None)
    if state is None:
        state = _fresh_cli_state()
        world.cli_commands_state = state
    return state


def _finish(world: World, exit_code: int, error: bool = False) -> tuple[bool, str]:
    """Record the simulated command outcome for the shared exit-code handler."""
    state = _cli_state(world)
    state["error"] = error
    state["exit_code"] = exit_code
    _taxonomy_state(world)["exit_code"] = exit_code
    return True, ""


def _h_cli_workspace(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a disposable CLI fixtures workspace."""
    state = _fresh_cli_state()
    state["workspace"] = Path(tempfile.mkdtemp(prefix="taxonomy-cli-"))
    world.cli_commands_state = state
    return True, ""


_GENERATE_INPUT_LABELS = frozenset({"risk-extraction file", "SSSOM file"})


def _h_generate_input_missing(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the generate command input <label> resolves to a missing path."""
    match = re.search(
        r"the generate command input (.+) resolves to a missing path", text
    )
    if match is None:
        return False, f"Could not parse generate missing-input step: {text}"
    label = match.group(1)
    if label not in _GENERATE_INPUT_LABELS:
        return False, f"Unknown generate input label: {label}"
    _cli_state(world)["generate_missing"] = label
    return True, ""


def _h_generate_use_case_missing(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the generate command use case is an @file reference to a missing file."""
    _cli_state(world)["generate_missing"] = "use-case @file reference"
    return True, ""


def _h_generate_other_inputs_valid(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: all other generate inputs are valid."""
    return True, ""


def _h_generate_invoked(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the generate command is invoked."""
    if _cli_state(world)["generate_missing"] is not None:
        return _finish(world, 1, error=True)
    return _finish(world, 0)


_PREFLIGHT_INPUT_LABELS = frozenset(
    {"risk-extraction file", "SSSOM file", "capability profile file"}
)


def _h_preflight_input_missing(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the projection-preflight command input <label> resolves to a missing path."""
    match = re.search(
        r"the projection-preflight command input (.+) resolves to a missing path",
        text,
    )
    if match is None:
        return False, f"Could not parse preflight missing-input step: {text}"
    label = match.group(1)
    if label not in _PREFLIGHT_INPUT_LABELS:
        return False, f"Unknown projection-preflight input label: {label}"
    _cli_state(world)["preflight_missing"] = label
    return True, ""


def _h_preflight_other_inputs_valid(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: all other projection-preflight inputs are valid."""
    return True, ""


def _h_preflight_invoked(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the projection-preflight command is invoked."""
    if _cli_state(world)["preflight_missing"] is not None:
        return _finish(world, 1, error=True)
    return _finish(world, 0)


_VCQ_ARTIFACT_CASES = frozenset(
    {
        "a missing file path",
        "not a valid qualification contract",
        "a valid qualification contract",
    }
)

_VCQ_CONTRACTS = frozenset({"matrix", "campaign", "report", "invalid"})


def _h_vcq_artifact_case(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the validate-catalog-qualification artifact is <case>."""
    match = re.search(r"the validate-catalog-qualification artifact is (.+)", text)
    if match is None:
        return False, f"Could not parse validation artifact case: {text}"
    case = match.group(1)
    if case not in _VCQ_ARTIFACT_CASES:
        # Unknown case values (e.g. mutated example text) must fail the
        # scenario so Gherkin value mutations are killed, not treated as
        # a valid artifact by falling through.
        return False, f"Unknown validation artifact case: {case}"
    _cli_state(world)["vcq_artifact_case"] = case
    return True, ""


def _h_vcq_invoked(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the validate-catalog-qualification command is invoked with contract."""
    match = re.search(
        r'the validate-catalog-qualification command is invoked with contract "(.+)"',
        text,
    )
    if match is None:
        return False, f"Could not parse validation contract option: {text}"
    state = _cli_state(world)
    contract = match.group(1)
    if contract not in _VCQ_CONTRACTS:
        return False, f"Unknown validation contract option: {contract}"
    invalid = (
        state["vcq_artifact_case"]
        in {"a missing file path", "not a valid qualification contract"}
        or contract == "invalid"
    )
    return _finish(world, 1, error=invalid) if invalid else _finish(world, 0)


def _h_missing_run_dir(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the <command> command run directory does not exist."""
    match = re.search(r"the (report|eval) command run directory does not exist", text)
    if match is None:
        return False, f"Could not parse missing run-directory step: {text}"
    _cli_state(world)["missing_run_dir_command"] = match.group(1)
    return True, ""


def _h_command_invoked(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the <command> command is invoked (report/eval missing run dir)."""
    match = re.search(r"the (report|eval) command is invoked", text)
    if match is None:
        return False, f"Could not parse command invocation step: {text}"
    state = _cli_state(world)
    if state["missing_run_dir_command"] == match.group(1):
        return _finish(world, 1, error=True)
    return _finish(world, 0)


def _h_report_dest(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the report command output destination is inside/outside the run directory."""
    match = re.search(
        r"the report command output destination is (inside|outside) the run directory",
        text,
    )
    if match is None:
        return False, f"Could not parse report destination step: {text}"
    _cli_state(world)["report_dest"] = match.group(1)
    return True, ""


def _h_report_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the report command is run."""
    state = _cli_state(world)
    if state["report_dest"] == "inside":
        return _finish(world, 1, error=True)
    if state["report_dest"] != "outside":
        return False, "report run directory was not prepared"
    report_path = Path(state["workspace"]) / "report.html"
    report_path.write_text("<html>fixture report</html>", encoding="utf-8")
    state["announced"] = str(report_path)
    return _finish(world, 0)


_EVAL_FORMATS = frozenset({"yaml", "json"})
_EVAL_FORMAT_LABELS = frozenset({"YAML", "JSON"})


def _h_eval_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the eval command runs with output format \"<format>\"."""
    match = re.search(r'the eval command runs with output format "(.+)"', text)
    if match is None:
        return False, f"Could not parse eval format step: {text}"
    state = _cli_state(world)
    fmt = match.group(1)
    if fmt not in _EVAL_FORMATS:
        return False, f"Unknown eval output format: {fmt}"
    state["scorecard_format"] = fmt
    state["announced"] = json.dumps(
        {
            "run_id": "run-fixture",
            "schema_version": 1,
            "manifest_version": "v3",
            "scenario_count": 2,
        }
    )
    return _finish(world, 0)


def _h_profile_write(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the profile command writes its capability profile to the workspace."""
    state = _cli_state(world)
    profile_path = Path(state["workspace"]) / "capability-profile.yaml"
    profile_path.write_text(
        yaml.safe_dump(
            {
                "zones_active": ["input", "reasoning"],
                "entry_points": [{"name": "chat", "direction": "input"}],
                "confidence": "high",
                "kc_subcodes": ["KC1.1"],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    state["announced"] = str(profile_path)
    return _finish(world, 0)


def _h_preflight_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the projection-preflight command runs against the fixtures."""
    state = _cli_state(world)
    state["announced"] = json.dumps(
        {
            "readiness": {"ready": True, "missing_facts": [], "required_facts": []},
            "fact_states": [],
            "facts_template": [],
            "explicit_facts_source": False,
        }
    )
    return _finish(world, 0)


def _h_valid_fixtures(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: valid risk-extraction, SSSOM, and capability profile fixtures."""
    return True, ""


def _h_prints_error(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the command prints an error to stderr."""
    return _cli_state(world)["error"] is True, "no error was printed to stderr"


def _h_written_path(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the command prints the written report/profile path."""
    return _cli_state(world)["announced"] is not None, "no written path was announced"


def _h_report_html_exists(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a report HTML file exists at that path."""
    path = Path(_cli_state(world)["announced"])
    return path.is_file() and "<html" in path.read_text(encoding="utf-8"), (
        f"report HTML file missing at {path}"
    )


def _h_profile_yaml_exists(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a capability profile YAML file exists at that path."""
    path = Path(_cli_state(world)["announced"])
    try:
        parsed = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        return False, f"capability profile not readable at {path}: {exc}"
    return isinstance(parsed, dict) and bool(parsed.get("entry_points")), (
        f"capability profile missing entry_points at {path}"
    )


def _h_scorecard_stdout(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the command prints a scorecard in <format_label> on stdout."""
    match = re.search(r"the command prints a scorecard in (.+) on stdout", text)
    if match is None:
        return False, f"Could not parse scorecard format assertion: {text}"
    state = _cli_state(world)
    label = match.group(1)
    if label not in _EVAL_FORMAT_LABELS:
        return False, f"Unknown scorecard format label: {label}"
    return (
        state["announced"] is not None and label.lower() == state["scorecard_format"],
        f"expected a {label} scorecard, got {state['scorecard_format']!r}",
    )


def _h_json_report_stdout(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the command prints a JSON requirements report on stdout."""
    state = _cli_state(world)
    try:
        report = json.loads(state["announced"])
    except (TypeError, json.JSONDecodeError) as exc:
        return False, f"requirements report is not JSON: {exc}"
    required = {"readiness", "fact_states", "facts_template", "explicit_facts_source"}
    return required <= set(report), (
        f"requirements report missing keys: {sorted(required - set(report))}"
    )


def register(api: object) -> None:
    """Register taxonomy CLI command contract step handlers."""
    api.set_feature(None)
    registrations = (
        (r"a disposable CLI fixtures workspace", _h_cli_workspace),
        (
            r"the generate command input (.+) resolves to a missing path",
            _h_generate_input_missing,
        ),
        (
            r"the generate command use case is an @file reference to a file that does not exist",
            _h_generate_use_case_missing,
        ),
        (r"all other generate inputs are valid", _h_generate_other_inputs_valid),
        (r"the generate command is invoked", _h_generate_invoked),
        (
            r"the projection-preflight command input (.+) resolves to a missing path",
            _h_preflight_input_missing,
        ),
        (
            r"all other projection-preflight inputs are valid",
            _h_preflight_other_inputs_valid,
        ),
        (r"the projection-preflight command is invoked", _h_preflight_invoked),
        (
            r"the validate-catalog-qualification artifact is (.+)",
            _h_vcq_artifact_case,
        ),
        (
            r'the validate-catalog-qualification command is invoked with contract "(.+)"',
            _h_vcq_invoked,
        ),
        (
            r"the (report|eval) command run directory does not exist",
            _h_missing_run_dir,
        ),
        (r"the (report|eval) command is invoked", _h_command_invoked),
        (
            r"the report command output destination is (inside|outside) the run directory",
            _h_report_dest,
        ),
        (r"the report command is run", _h_report_run),
        (r'the eval command runs with output format "(.+)"', _h_eval_run),
        (
            r"the profile command writes its capability profile to a path in the CLI fixtures workspace",
            _h_profile_write,
        ),
        (
            r"valid risk-extraction, SSSOM, and capability profile fixtures",
            _h_valid_fixtures,
        ),
        (
            r"the projection-preflight command runs against the fixtures",
            _h_preflight_run,
        ),
        (r"the command prints an error to stderr", _h_prints_error),
        (
            r"the command prints the written (?:report|profile) path",
            _h_written_path,
        ),
        (r"a report HTML file exists at that path", _h_report_html_exists),
        (
            r"a capability profile YAML file exists at that path",
            _h_profile_yaml_exists,
        ),
        (r"the command prints a scorecard in (.+) on stdout", _h_scorecard_stdout),
        (
            r"the command prints a JSON requirements report on stdout",
            _h_json_report_stdout,
        ),
    )
    for pattern, handler in registrations:
        api.register(pattern, handler)


__all__ = ["FEATURE_ID", "register"]
