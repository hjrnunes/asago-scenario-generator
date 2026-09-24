"""Acceptance step handlers for the run-output HTML visualization."""

from __future__ import annotations

import re
import tempfile
from pathlib import Path
from typing import Any

from runtime_shared import World

from asago_scenario_generator.report.run_visualizer import (
    OUTPUT_FILENAME,
    render_run_visual,
)

FEATURE_ID = "run_visualization"

_PAYLOAD = "<script>alert(1)</script>"


def _state(world: World) -> dict[str, Any]:
    state = getattr(world, "run_visualization_state", None)
    if state is None:
        state = {}
        world.run_visualization_state = state
    return state


def _synthetic_run_dir() -> Path:
    from tests.report.test_run_visualizer import _make_run

    directory = Path(tempfile.mkdtemp(prefix="run-viz-")) / "run"
    _make_run(directory)
    return directory


def _make_full_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
    _state(world)["run_dir"] = _synthetic_run_dir()
    return True, ""


def _render(world: World, text: str, examples: dict) -> tuple[bool, str]:
    state = _state(world)
    run_dir = state.get("run_dir")
    if run_dir is None:
        return False, "No run directory set"
    try:
        state["output"] = render_run_visual(Path(run_dir))
    except Exception as exc:
        return False, f"rendering failed: {exc}"
    return True, ""


def _default_path(world: World, text: str, examples: dict) -> tuple[bool, str]:
    output = _state(world).get("output")
    if output is None:
        return False, "No rendered output"
    if Path(output).name != OUTPUT_FILENAME:
        return False, f"unexpected output name {output}"
    return True, ""


def _read_html(state: dict[str, Any]) -> str:
    output = state.get("output")
    if output is None:
        return ""
    return Path(output).read_text(encoding="utf-8")


def _self_contained(world: World, text: str, examples: dict) -> tuple[bool, str]:
    html = _read_html(_state(world))
    if "<style>" not in html or "<script>" not in html:
        return False, "missing inline CSS or JS"
    if "http://" in html or "https://" in html or 'rel="stylesheet"' in html:
        return False, "external reference found"
    return True, ""


def _scenario_card(world: World, text: str, examples: dict) -> tuple[bool, str]:
    html = _read_html(_state(world))
    match = re.search(r'scenario "([^"]+)"', text)
    scenario_id = match.group(1) if match else "SCN-001"
    for probe in (scenario_id, "direct_prompt", "PROCESS_MODEL_FLAW"):
        if probe not in html:
            return False, f"missing {probe!r} in scenario card"
    return True, ""


def _raw_includes(world: World, text: str, examples: dict) -> tuple[bool, str]:
    html = _read_html(_state(world))
    match = re.search(r'includes "([^"]+)"', text)
    relative = match.group(1) if match else ""
    if relative not in html:
        return False, f"raw artifacts section missing {relative!r}"
    return True, ""


def _escaped_payload(world: World, text: str, examples: dict) -> tuple[bool, str]:
    html = _read_html(_state(world))
    if _PAYLOAD in html:
        return False, "unescaped script payload present"
    if html.count("&lt;script&gt;alert(1)&lt;/script&gt;") < 2:
        return False, "escaped payload not rendered"
    return True, ""


def _manifest_only_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
    directory = Path(tempfile.mkdtemp(prefix="run-viz-")) / "run"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "run-manifest.yaml").write_text(
        "run_id: synthesis-manifest-only\n", encoding="utf-8"
    )
    _state(world)["run_dir"] = directory
    return True, ""


def _absent_notes(world: World, text: str, examples: dict) -> tuple[bool, str]:
    html = _read_html(_state(world))
    if html.count("Not present in this run directory.") < 8:
        return False, "expected absent-artifact notes"
    return True, ""


def _cli_invoke(world: World, text: str, examples: dict) -> tuple[bool, str]:
    from typer.testing import CliRunner

    from asago_scenario_generator.cli import app

    state = _state(world)
    state["run_dir"] = _synthetic_run_dir()
    result = CliRunner().invoke(app, ["render-run", "--run-dir", str(state["run_dir"])])
    state["cli_result"] = result
    return True, ""


def _cli_success(world: World, text: str, examples: dict) -> tuple[bool, str]:
    state = _state(world)
    result = state.get("cli_result")
    if result is None:
        return False, "CLI was not invoked"
    if result.exit_code != 0:
        return False, f"CLI exit code {result.exit_code}: {result.output}"
    expected = Path(state["run_dir"]) / OUTPUT_FILENAME
    if not expected.exists():
        return False, "CLI did not write the default output path"
    return True, ""


def register(api) -> None:
    """Register handlers in the isolated acceptance registry."""
    registrations = (
        (r"^a synthetic run directory with artifacts$", _make_full_run),
        (r"^the run directory is rendered$", _render),
        (r"^the visualization exists at the default output path$", _default_path),
        (
            r"^the HTML contains inline CSS and no external stylesheet$",
            _self_contained,
        ),
        (
            r'^the HTML shows scenario "([^"]+)" with its execution route$',
            _scenario_card,
        ),
        (
            r'^the raw artifacts section includes "([^"]+)"$',
            _raw_includes,
        ),
        (r"^the HTML escapes the injected script payload$", _escaped_payload),
        (r"^a run directory with only a manifest$", _manifest_only_run),
        (r"^the visualization records absent-artifact notes$", _absent_notes),
        (r"^the render-run CLI is invoked$", _cli_invoke),
        (r"^the CLI succeeds and writes the visualization$", _cli_success),
    )
    for pattern, handler in registrations:
        api.register(pattern, handler)


__all__ = ["FEATURE_ID", "register"]
