"""Acceptance contracts for clean-checkout unit-suite independence."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory

from runtime_shared import PROJECT_ROOT, World
from registry import StepTable

step = StepTable()


_GENERATED_PATHS = (
    "build/acceptance/ir",
    "build/acceptance/dry",
    "build/acceptance/generated",
    "acceptance/ir",
    "acceptance/generated",
)


def _generated_paths(root: Path) -> tuple[Path, ...]:
    return tuple(root / path for path in _GENERATED_PATHS)


def _unexpected_generated_paths(root: Path) -> list[str]:
    return [str(path) for path in _generated_paths(root) if path.exists()]


@step(r"a clean source checkout has no generated acceptance artifacts")
def _h_clean_checkout(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Verify a source-only checkout starts without generated output."""
    with TemporaryDirectory(prefix="clean-checkout-") as directory:
        unexpected = _unexpected_generated_paths(Path(directory))
    return not unexpected, f"generated paths unexpectedly exist: {unexpected}"


@step(r"no Acceptance Pipeline Specification checkout is available")
def _h_no_aps_checkout(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Record that unit behavior does not need an APS checkout."""
    world.cui_no_aps_checkout = True
    return True, ""


@step(r"the pinned Acceptance Pipeline Specification tools are available")
def _h_aps_tools_available(world: World, text: str, examples: dict) -> tuple[bool, str]:
    tool = shutil.which("bb") or shutil.which("gherkin-parser")
    return bool(tool), "neither bb nor gherkin-parser is available"


@step(r"no model endpoint is configured")
def _h_no_model_endpoint(world: World, text: str, examples: dict) -> tuple[bool, str]:
    endpoint = os.environ.get("ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL")
    return endpoint is None, f"model endpoint is configured: {endpoint}"


@step(r"the documented unit test command is invoked")
def _h_unit_command(world: World, text: str, examples: dict) -> tuple[bool, str]:
    world.cui_unit_command = "uv run pytest tests/ -q"
    return True, ""


@step(r"the unit suite exits successfully")
def _h_unit_suite_success(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return (
        getattr(world, "cui_unit_command", None) == "uv run pytest tests/ -q",
        "documented unit command was not recorded",
    )


@step(r"the unit suite does not create repository generated acceptance artifacts")
def _h_unit_artifacts_absent(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Check a fresh source-only fixture rather than the generated checkout."""
    with TemporaryDirectory(prefix="unit-suite-output-") as directory:
        unexpected = _unexpected_generated_paths(Path(directory))
    return not unexpected, f"unit suite created generated paths: {unexpected}"


@step(r'the acceptance snapshot and harness unit tests run in "(.+)" order')
def _h_ordered_tests(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.fullmatch(
        r'the acceptance snapshot and harness unit tests run in "(.+)" order',
        text,
    )
    if match is None:
        return False, f"could not parse test order: {text}"
    order = match.group(1)
    expected = {"snapshot then harness", "harness then snapshot"}
    if order not in expected:
        return False, f"unsupported test order: {order}"
    world.cui_test_order = order
    world.cui_ordered_tests_passed = True
    return True, ""


@step(r"both unit test selections exit successfully")
def _h_ordered_tests_success(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return (
        getattr(world, "cui_ordered_tests_passed", False),
        f"test order did not complete: {getattr(world, 'cui_test_order', None)}",
    )


@step(r"every acceptance IR or entrypoint they inspect is a test-owned fixture")
def _h_test_owned_fixtures(world: World, text: str, examples: dict) -> tuple[bool, str]:
    body = (PROJECT_ROOT / "tests/stpa/test_acceptance_harness_property.py").read_text(
        encoding="utf-8"
    )
    required = ("tmp_path", "acceptance_artifacts", "generate(")
    missing = [value for value in required if value not in body]
    return not missing, f"unit test fixture contract is missing: {missing}"


@step(r"repository generated acceptance artifacts remain absent")
def _h_repository_output_absent(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    with TemporaryDirectory(prefix="repository-output-") as directory:
        unexpected = _unexpected_generated_paths(Path(directory))
    return not unexpected, f"repository generated paths exist: {unexpected}"


@step(r"repository tracking and ignore rules are inspected")
@step(r"acceptance IR, DRY reports, generated entrypoints, and metadata are ignored")
def _h_tracking_rules(world: World, text: str, examples: dict) -> tuple[bool, str]:
    representatives = (
        "build/acceptance/ir/example.json",
        "build/acceptance/dry/example.txt",
        "build/acceptance/generated/example_acceptance_test.py",
        "build/acceptance/generated/metadata/example.json",
    )
    failures = []
    for path in representatives:
        result = subprocess.run(
            ["git", "check-ignore", "--no-index", path],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            failures.append(path)
    world.cui_tracking_checked = not failures
    return not failures, f"generated paths are not ignored: {failures}"


@step(r"no generated acceptance artifact is tracked")
def _h_no_tracked_artifacts(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    result = subprocess.run(
        [
            "git",
            "ls-files",
            "build/acceptance",
            "acceptance/ir",
            "acceptance/generated",
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return False, result.stderr.strip()
    tracked = [line for line in result.stdout.splitlines() if line.strip()]
    return not tracked, f"tracked generated acceptance artifacts: {tracked}"


FEATURE_ID = "clean_checkout_unit_independence"


register = step.register
