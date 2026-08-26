"""Acceptance handlers for the explicit live-LLM opt-in marker."""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

from live_llm_opt_in import LIVE_LLM_ACCEPTANCE_MARKER, LIVE_LLM_SKIP_REASON
from runtime_shared import World


_ENDPOINT_VARIABLES = (
    "ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL",
    "OPENAI_BASE_URL",
    "OPENAI_API_KEY",
    "ASAGO_SCENARIO_GENERATOR_API_KEY",
)
_FIXTURE_STATE_STACK: list[dict[str, Any]] = []


def _h_live_llm_marker(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle a marker after the runtime has authorized live execution."""
    return True, ""


def _h_fixture_background(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Prepare the deterministic fixture used by the opt-in feature."""
    world.acceptance_fixture_live_count = 1
    return True, ""


def _h_fixture_live_count(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Add a second live scenario to the isolated fixture."""
    world.acceptance_fixture_live_count = 2
    return True, ""


def _h_pipeline_env_value(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Set the exact opt-in value requested by an acceptance scenario."""
    match = re.search(r'ASAGO_SCENARIO_GENERATOR_QA_PIPELINE is "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse pipeline opt-in value: {text}"
    os.environ["ASAGO_SCENARIO_GENERATOR_QA_PIPELINE"] = match.group(1)
    return True, ""


def _h_pipeline_env_unset(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Remove the live acceptance opt-in variable."""
    os.environ.pop("ASAGO_SCENARIO_GENERATOR_QA_PIPELINE", None)
    return True, ""


def _h_pipeline_env_observed(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Verify an outline's expected opt-in value reached the environment."""
    match = re.search(r'live-LLM opt-in value is observed as "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse expected pipeline opt-in value: {text}"
    actual = os.environ.get("ASAGO_SCENARIO_GENERATOR_QA_PIPELINE")
    expected = match.group(1)
    return actual == expected, f"expected opt-in value {expected!r}, got {actual!r}"


def _h_endpoint_configured(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Configure harmless endpoint values for the isolated fixture."""
    os.environ["ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL"] = "http://127.0.0.1:9/v1"
    os.environ["ASAGO_SCENARIO_GENERATOR_API_KEY"] = "acceptance-fixture-key"
    return True, ""


def _h_endpoint_unset(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Remove every endpoint credential accepted by the pipeline adapter."""
    for name in _ENDPOINT_VARIABLES:
        os.environ.pop(name, None)
    return True, ""


def _endpoint_configured() -> bool:
    """Return whether the pipeline can discover at least one endpoint value."""
    return any(os.environ.get(name) for name in _ENDPOINT_VARIABLES)


def _empty_fixture_state() -> dict[str, Any]:
    """Return a fresh isolated-fixture observation record."""
    return {
        "deterministic_count": 0,
        "live_attempted": 0,
        "live_executed": 0,
        "live_environments": [],
        "live_fixture_dirs": [],
        "live_output_dirs": [],
        "foreign_output_observations": [],
    }


def _current_fixture_state() -> dict[str, Any]:
    """Return the innermost isolated fixture's mutable observation record."""
    if not _FIXTURE_STATE_STACK:
        raise RuntimeError("no isolated fixture is executing")
    return _FIXTURE_STATE_STACK[-1]


def _fixture_scenario(name: str, live: bool = False) -> dict[str, Any]:
    steps = []
    if live:
        steps.append({"keyword": "Given", "text": LIVE_LLM_ACCEPTANCE_MARKER})
        steps.append({"keyword": "When", "text": "acceptance fixture live step"})
    else:
        steps.append(
            {"keyword": "Given", "text": "acceptance fixture deterministic step"}
        )
    return {"name": name, "steps": steps, "examples": []}


def _execute_fixture(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Execute a fresh temporary fixture and retain observable results."""
    import acceptance_runtime

    execute_ir = acceptance_runtime.execute_ir

    fixture_dir = Path(tempfile.mkdtemp(prefix="acceptance-live-fixture-"))
    live_count = getattr(world, "acceptance_fixture_live_count", 1)
    scenarios = [_fixture_scenario("deterministic")]
    scenarios.extend(
        _fixture_scenario("live" if index == 1 else f"live-{index}", live=True)
        for index in range(1, live_count + 1)
    )
    fixture_path = fixture_dir / "fixture.json"
    fixture_path.write_text(
        json.dumps({"name": "isolated fixture", "scenarios": scenarios}),
        encoding="utf-8",
    )
    original_environment = dict(os.environ)
    state = _empty_fixture_state()
    _FIXTURE_STATE_STACK.append(state)
    try:
        passed, output = execute_ir(str(fixture_path))
        world.acceptance_fixture_state = {
            key: list(value) if isinstance(value, list) else value
            for key, value in state.items()
        }
    finally:
        _FIXTURE_STATE_STACK.pop()
    world.acceptance_result = passed
    world.acceptance_output = output
    world.acceptance_original_environment = original_environment
    output_dirs = world.acceptance_fixture_state.get("live_output_dirs", [])
    world.acceptance_status_detail = (
        f"fixture={fixture_dir} "
        f"output={','.join(str(path) for path in output_dirs) or 'none'}"
    )
    return True, ""


def _h_fixture_deterministic(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Record execution of the deterministic fixture scenario."""
    _current_fixture_state()["deterministic_count"] += 1
    return True, ""


def _h_fixture_live(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Run the isolated live fixture step without contacting an endpoint."""
    state = _current_fixture_state()
    state["live_attempted"] += 1
    state["live_environments"].append(dict(os.environ))
    previous_fixture_dirs = list(state["live_fixture_dirs"])
    previous_output_dirs = list(state["live_output_dirs"])
    fixture_dir = Path(tempfile.mkdtemp(prefix="acceptance-live-scenario-fixture-"))
    output_dir = fixture_dir / "output"
    output_dir.mkdir()
    observed_foreign = fixture_dir in previous_fixture_dirs or any(
        output_dir == other
        or output_dir.is_relative_to(other)
        or other.is_relative_to(fixture_dir)
        for other in previous_output_dirs
    )
    state["live_fixture_dirs"].append(fixture_dir)
    state["live_output_dirs"].append(output_dir)
    state["foreign_output_observations"].append(observed_foreign)
    (output_dir / "output.txt").write_text("fixture output\n", encoding="utf-8")
    if not _endpoint_configured():
        return (
            False,
            "LLM endpoint not configured (live acceptance scenario requires LLM)",
        )
    state["live_executed"] += 1
    return True, ""


def _state(world: World) -> dict[str, Any]:
    """Return the last isolated fixture's state."""
    return getattr(world, "acceptance_fixture_state", {})


def _output(world: World) -> str:
    """Return the last isolated fixture's status output."""
    return getattr(world, "acceptance_output", "")


def _h_deterministic_executed(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return (
        _state(world).get("deterministic_count") == 1,
        "deterministic scenario was not executed",
    )


def _h_live_not_executed(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return (
        _state(world).get("live_executed", 0) == 0,
        "live scenario was executed",
    )


def _h_live_executed(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return (
        _state(world).get("live_executed", 0) >= 1,
        "live scenario was not executed",
    )


def _h_live_reported_skipped(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    expected = f"SKIP live/example_1: {LIVE_LLM_SKIP_REASON}"
    output = _output(world)
    return expected in output, f"missing skip report: {output}"


def _h_live_reported_passed(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    output = _output(world)
    return "PASS live/example_1" in output, f"missing pass report: {output}"


def _h_live_attempted(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return (
        _state(world).get("live_attempted", 0) >= 1,
        "live scenario was not attempted",
    )


def _h_live_failed_endpoint(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    output = _output(world)
    expected = "LLM endpoint not configured"
    return expected in output, f"missing endpoint failure: {output}"


def _h_acceptance_result(world: World, text: str, examples: dict) -> tuple[bool, str]:
    expected = "succeeds" in text.lower()
    actual = bool(getattr(world, "acceptance_result", False))
    return actual == expected, f"expected acceptance result {expected}, got {actual}"


def _h_original_environment(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    original = getattr(world, "acceptance_original_environment", {})
    environments = _state(world).get("live_environments", [])
    return (
        bool(environments)
        and all(environment == original for environment in environments),
        "live scenarios did not receive the original process environment",
    )


def _h_distinct_fixture_dirs(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    directories = _state(world).get("live_fixture_dirs", [])
    return (
        len(directories) == len(set(directories)) == 2,
        f"live fixture directories were not distinct: {directories}",
    )


def _h_no_foreign_outputs(world: World, text: str, examples: dict) -> tuple[bool, str]:
    observations = _state(world).get("foreign_output_observations", [])
    return (
        len(observations) == 2 and not any(observations),
        "a live scenario observed another scenario's output files",
    )


FEATURE_ID = "acceptance_live_opt_in"


def register(api: object) -> None:
    """Register the live-LLM opt-in marker as a global step."""
    api.set_feature(None)
    api.register(
        rf"^{re.escape(LIVE_LLM_ACCEPTANCE_MARKER)}$",
        _h_live_llm_marker,
    )
    api.register(
        r"an isolated acceptance fixture with one deterministic scenario and one live-LLM scenario",
        _h_fixture_background,
    )
    api.register(
        r"the isolated acceptance fixture contains two live-LLM scenarios",
        _h_fixture_live_count,
    )
    api.register(
        r'ASAGO_SCENARIO_GENERATOR_QA_PIPELINE is "([^"]+)"',
        _h_pipeline_env_value,
    )
    api.register(
        r"ASAGO_SCENARIO_GENERATOR_QA_PIPELINE is unset",
        _h_pipeline_env_unset,
    )
    api.register(
        r'live-LLM opt-in value is observed as "([^"]+)"',
        _h_pipeline_env_observed,
    )
    api.register(r"live LLM endpoint variables are configured", _h_endpoint_configured)
    api.register(r"live LLM endpoint variables are unset", _h_endpoint_unset)
    api.register(r"the isolated acceptance fixture is executed", _execute_fixture)
    api.register(r"acceptance fixture deterministic step", _h_fixture_deterministic)
    api.register(r"acceptance fixture live step", _h_fixture_live)
    api.register(r"the deterministic scenario is executed", _h_deterministic_executed)
    api.register(r"the live-LLM scenario is not executed", _h_live_not_executed)
    api.register(r"the live-LLM scenario is executed", _h_live_executed)
    api.register(
        r'the live-LLM scenario is reported as skipped because ASAGO_SCENARIO_GENERATOR_QA_PIPELINE is not "1"',
        _h_live_reported_skipped,
    )
    api.register(
        r"the live-LLM scenario is reported as passed", _h_live_reported_passed
    )
    api.register(r"the live-LLM scenario is attempted", _h_live_attempted)
    api.register(
        r"the live-LLM scenario fails with an endpoint-not-configured message",
        _h_live_failed_endpoint,
    )
    api.register(r"the acceptance result (succeeds|fails)", _h_acceptance_result)
    api.register(
        r"each scenario receives the original process environment",
        _h_original_environment,
    )
    api.register(
        r"each scenario uses a distinct temporary fixture directory",
        _h_distinct_fixture_dirs,
    )
    api.register(
        r"neither scenario can observe the other scenario's output files",
        _h_no_foreign_outputs,
    )
