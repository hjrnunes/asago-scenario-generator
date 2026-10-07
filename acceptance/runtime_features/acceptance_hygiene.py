"""Acceptance step handlers for the acceptance hygiene gate."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from runtime_shared import PROJECT_ROOT, World
from snapshot import artifact_paths, snapshot_layout
from registry import StepTable

step = StepTable()


def _read(path: str) -> str:
    return (PROJECT_ROOT / path).read_text(encoding="utf-8")


def _run(*args: str) -> tuple[bool, str]:
    result = subprocess.run(
        args,
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode == 0, result.stdout + result.stderr


@step(r"the project quality entry point is available")
def _h_ready(world: World, text: str, examples: dict) -> tuple[bool, str]:
    path = PROJECT_ROOT / "scripts" / "quality.sh"
    if not path.is_file():
        return False, f"Missing quality entry point: {path}"
    world.ahg_quality = path.read_text(encoding="utf-8")
    return True, ""


@step(r"the quality script is invoked")
def _h_quality(world: World, text: str, examples: dict) -> tuple[bool, str]:
    world.ahg_quality = _read("scripts/quality.sh")
    return True, ""


@step(r"Ruff (check|format check) runs against (src|acceptance)")
def _h_ruff_cmd(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r"Ruff (check|format check) runs against (src|acceptance)", text)
    if not match:
        return False, f"Could not parse Ruff assertion: {text}"
    action, target = match.groups()
    command = (
        "uv run ruff check src acceptance"
        if action == "check"
        else "uv run ruff format --check src acceptance"
    )
    body = getattr(world, "ahg_quality", "")
    if command not in body:
        return False, f"Missing command for {target}: {command}"
    return True, ""


@step(r"the acceptance test entry point is invoked with --test")
def _h_acceptance(world: World, text: str, examples: dict) -> tuple[bool, str]:
    world.ahg_acceptance = _read("scripts/acceptance.sh")
    return True, ""


@step(r"the hygiene gate runs before generated acceptance tests")
def _h_gate_first(world: World, text: str, examples: dict) -> tuple[bool, str]:
    body = getattr(world, "ahg_acceptance", "")
    gate = body.find('"$root/scripts/quality.sh"')
    tests = body.find("exec uv run pytest")
    if gate < 0 or tests < 0 or gate >= tests:
        return False, "The hygiene gate does not precede generated acceptance tests"
    return True, ""


@step(r"generated acceptance tests are not executed if the hygiene gate fails")
def _h_gate_stop(world: World, text: str, examples: dict) -> tuple[bool, str]:
    body = getattr(world, "ahg_acceptance", "")
    if "set -euo pipefail" not in body:
        return False, "Acceptance entry point does not stop after a gate failure"
    return _h_gate_first(world, text, examples)


@step(r"Ruff check on acceptance reports zero findings")
def _h_ruff_clean(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return _run("uv", "run", "ruff", "check", "acceptance")


@step(r"Ruff format check on acceptance reports zero files needing reformatting")
def _h_ruff_fmt(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return _run("uv", "run", "ruff", "format", "--check", "acceptance")


def _config() -> dict[str, str]:
    found: dict[str, str] = {}
    for line in _read("config/swarmforge.env").splitlines():
        match = re.match(r'(SWARMFORGE_(?:CRAP|DRY|MUTATION)_CMD)="(.*)"', line)
        if match:
            found[match.group(1)] = match.group(2)
    return found


@step(r"the configured (CRAP|DRY|mutation) command targets src")
def _h_scope(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r"configured (CRAP|DRY|mutation) command targets src", text)
    if not match:
        return False, f"Could not parse scope assertion: {text}"
    name = match.group(1).upper()
    command = _config().get(f"SWARMFORGE_{name}_CMD", "")
    if "src/" not in command and "./src" not in command:
        return False, f"{name} command does not target src: {command}"
    return True, ""


@step(r"acceptance handlers are not included in CRAP DRY or mutation scope")
def _h_no_scope(world: World, text: str, examples: dict) -> tuple[bool, str]:
    commands = _config().values()
    if any("acceptance" in command for command in commands):
        return False, "Acceptance appears in CRAP, DRY, or mutation scope"
    return True, ""


@step(r"the acceptance runtime manifest is loaded")
def _h_manifest(world: World, text: str, examples: dict) -> tuple[bool, str]:
    import runtime_manifest

    world.ahg_modules = runtime_manifest.load_modules()
    return True, ""


@step(r"every runtime feature module is importable")
def _h_modules(world: World, text: str, examples: dict) -> tuple[bool, str]:
    import runtime_manifest

    modules = getattr(world, "ahg_modules", ())
    if tuple(module.FEATURE_ID for module in modules) != runtime_manifest.MODULES:
        return False, "Runtime feature manifest is incomplete"
    return True, ""


@step(r"every registered handler has a valid step pattern")
@step(r"handler registration does not raise")
def _h_patterns(world: World, text: str, examples: dict) -> tuple[bool, str]:
    from acceptance_runtime import STEP_PATTERNS

    if not STEP_PATTERNS or any(not pattern.pattern for pattern, _, _ in STEP_PATTERNS):
        return False, "Runtime registry contains an invalid step pattern"
    return True, ""


@step(r"features map to build/acceptance/ir")
def _h_map_ir(world: World, text: str, examples: dict) -> tuple[bool, str]:
    paths = artifact_paths("features/group/example.feature")
    expected = "build/acceptance/ir/group/example.json"
    return (paths.ir_path == expected, f"Unexpected IR path: {paths.ir_path}")


@step(r"build/acceptance/ir maps to build/acceptance/generated")
def _h_map_test(world: World, text: str, examples: dict) -> tuple[bool, str]:
    paths = artifact_paths("features/group/example.feature")
    expected = "build/acceptance/generated/example_acceptance_test.py"
    return (
        paths.test_path == expected,
        f"Unexpected generated path: {paths.test_path}",
    )


@step(r"build/acceptance/generated contains metadata with relative paths")
def _h_meta(world: World, text: str, examples: dict) -> tuple[bool, str]:
    root = PROJECT_ROOT / snapshot_layout().metadata_dir
    files = sorted(root.glob("*.json"))
    if not files:
        return False, f"No generated metadata found in {root}"
    for path in files:
        data = json.loads(path.read_text(encoding="utf-8"))
        for field in ("feature_path", "ir_path"):
            value = str(data.get(field, ""))
            if not value or Path(value).is_absolute():
                return False, f"Metadata path is not relative in {path.name}"
    return True, ""


@step(r"no generated artifacts are committed to git")
def _h_untracked(world: World, text: str, examples: dict) -> tuple[bool, str]:
    result = subprocess.run(
        ["git", "ls-files", "build/acceptance"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return False, result.stderr
    if result.stdout.strip():
        return False, f"Tracked generated artifacts: {result.stdout.strip()}"
    return True, ""


FEATURE_ID = "acceptance_hygiene"


register = step.register
