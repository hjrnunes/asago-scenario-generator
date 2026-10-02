"""Stable facade for the acceptance runtime registry and executor."""

from __future__ import annotations

import json
import re
import sys
import traceback
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from pydantic import ValidationError
from lifecycle import restore_environment, run_steps, scenario_context
from registry import (
    RegistrationAPI as _RegistrationAPI,
    RegistrationStage as _RegistrationStage,
    find_pattern_conflicts as _find_pattern_conflicts,
    publish as _publish_registry,
    resolve_handler,
    track_registration,
)
from runtime_features.sp1_revision import (
    _h_rev_revision_run as _retained_rev_revision_run,
)
from runtime_shared import (
    _GDStageError,
    _h_sp1_rev_run as _retained_sp1_rev_run,
    _resolve_value,
)
from runtime_world import World

STEP_PATTERNS: list[tuple[Any, Any, str | None]] = []
_CURRENT_REGISTRATION_FEATURE: str | None = None
_CURRENT_EXECUTION_FEATURE: str | None = None
_REGISTERED_PATTERN_KEYS: set[tuple[str, str, str | None]] = set()


def _set_feature(tag: str | None) -> None:
    """Set the feature tag for subsequent _register_first calls."""
    global _CURRENT_REGISTRATION_FEATURE
    _CURRENT_REGISTRATION_FEATURE = tag


def _track_registration(pattern: str, handler: Any, feature_tag: str | None) -> None:
    """Compatibility wrapper around the isolated registry seam."""
    track_registration(_REGISTERED_PATTERN_KEYS, pattern, handler, feature_tag)


def _register(pattern: str, handler: Any) -> None:
    _track_registration(pattern, handler, None)
    STEP_PATTERNS.append((re.compile(pattern, re.IGNORECASE), handler, None))


def _register_first(pattern: str, handler: Any) -> None:
    """Register a pattern at the front of the list (higher priority).

    The pattern is tagged with the current registration feature (set via
    _set_feature). During execution, tagged patterns only match when the
    current IR file's feature matches, preventing cross-feature hijacking.
    """
    _track_registration(pattern, handler, _CURRENT_REGISTRATION_FEATURE)
    STEP_PATTERNS.insert(
        0,
        (re.compile(pattern, re.IGNORECASE), handler, _CURRENT_REGISTRATION_FEATURE),
    )


def find_pattern_conflicts(
    step_texts: list[str],
) -> list[tuple[str, str, str]]:
    return _find_pattern_conflicts(STEP_PATTERNS, step_texts)


def _publish(stage: _RegistrationStage) -> None:
    """Compatibility wrapper that publishes into the facade's registry."""
    _publish_registry(stage, STEP_PATTERNS, _REGISTERED_PATTERN_KEYS)


def _load_feature_registry() -> None:
    """Validate, stage, and atomically publish all feature registrations."""
    import runtime_manifest

    stage = _RegistrationStage()
    api = _RegistrationAPI(stage)
    modules = runtime_manifest.load_modules()
    runtime_manifest.register_all(api, modules)
    _publish(stage)


def execute_step(world: World, step: dict, examples: dict) -> tuple[bool, str]:
    """Execute a single step against the world.

    If a handler raises ValidationError or ValueError during model
    construction, the error is stored in world.validation_error and
    the step is considered successful (the error is an expected outcome
    that will be checked by a subsequent 'Then' step).
    """
    keyword = step.get("keyword", "")
    raw_text = step.get("text", "")
    text = _resolve_value(raw_text, examples)
    # Store data table (if any) in world so handlers can access it
    world.current_data_table = step.get("data_table")

    try:
        handler = resolve_handler(STEP_PATTERNS, text, _CURRENT_EXECUTION_FEATURE)
        if handler is not None:
            return handler(world, text, examples)

        return False, f"Unsupported step: {keyword} {text}"
    except (ValidationError, ValueError, _GDStageError) as e:
        world.validation_error = e
        return True, ""


# Feature-tag derivation lookup tables for _derive_feature_tag.
# Directory-part to tag mapping (checked first, higher priority).
_PATH_PART_TAGS: dict[str, str] = {
    "acceptance-refresh": "acceptance_refresh",
}

# Exact-stem to tag mapping (checked after path parts).
_STEM_TAGS: dict[str, str] = {
    "class-b-decisions": "shadow_cleanup",
    "duplicate-assertion": "shadow_cleanup",
    "no-shadowing-invariant": "shadow_cleanup",
    "registration-priority": "shadow_cleanup",
}

# Stem-prefix to tag mapping (checked after exact stems).
_STEM_PREFIX_TAGS: tuple[tuple[str, str], ...] = (
    ("sp2_", "sp2"),
    ("sp3_", "sp3"),
    ("sp3-", "sp3"),
    ("stage6_", "sp3"),
)


def _derive_feature_tag(ir_path: str) -> str | None:
    """Derive a feature tag from the IR filename.

    Returns a feature tag for sub-project-specific IR files, or None for
    foundation/boundary/SP1 features whose handlers should remain global.
    """
    path = Path(ir_path)
    stem = path.stem
    for part in path.parts:
        if part in _PATH_PART_TAGS:
            return _PATH_PART_TAGS[part]
    if stem in _STEM_TAGS:
        return _STEM_TAGS[stem]
    for prefix, tag in _STEM_PREFIX_TAGS:
        if stem.startswith(prefix):
            return tag
    return None


def _scenario_examples(scenario: dict[str, Any]) -> list[dict]:
    return scenario.get("examples") or [{}]


_restore_environment = restore_environment


@contextmanager
def execution_feature(tag: str | None):
    """Temporarily set the feature tag and restore its enclosing value."""
    global _CURRENT_EXECUTION_FEATURE
    previous = _CURRENT_EXECUTION_FEATURE
    _CURRENT_EXECUTION_FEATURE = tag
    try:
        yield
    finally:
        _CURRENT_EXECUTION_FEATURE = previous


def _status_detail(world: World, separator: str) -> str:
    detail = getattr(world, "acceptance_status_detail", "")
    return f"{separator}{detail}" if detail else ""


def _execute_example(
    background_steps: list[dict],
    scenario_steps: list[dict],
    example: dict,
    exec_name: str,
) -> tuple[bool, str]:
    with scenario_context() as context:
        background_result = run_steps(
            context.world,
            background_steps,
            example,
            execute_step,
            kind="background",
        )
        if not background_result.passed:
            suffix = _status_detail(context.world, " (")
            if suffix:
                suffix += ")"
            return (
                False,
                f"FAIL {exec_name}: background step failed: "
                f"{background_result.error}{suffix}",
            )

        scenario_result = run_steps(
            context.world,
            scenario_steps,
            example,
            execute_step,
            kind="scenario",
        )
        if not scenario_result.passed:
            suffix = _status_detail(context.world, " (")
            if suffix:
                suffix += ")"
            return (
                False,
                f"FAIL {exec_name}: {scenario_result.error}{suffix}",
            )
        suffix = _status_detail(context.world, ": ")
        return True, f"PASS {exec_name}{suffix}"


def execute_ir(ir_path: str) -> tuple[bool, str]:
    """Execute all scenarios in a JSON IR file.

    Returns (all_passed, output).
    """
    with execution_feature(_derive_feature_tag(ir_path)):
        with open(ir_path) as f:
            ir = json.load(f)

        background_steps = ir.get("background", [])
        scenarios = ir.get("scenarios", [])

        output_lines: list[str] = []
        all_passed = True

        for s_idx, scenario in enumerate(scenarios):
            scenario_name = scenario.get("name", f"scenario_{s_idx}")
            steps = scenario.get("steps", [])
            examples = _scenario_examples(scenario)

            for e_idx, example in enumerate(examples):
                exec_name = f"{scenario_name}/example_{e_idx + 1}"
                passed, line = _execute_example(
                    background_steps,
                    steps,
                    example,
                    exec_name,
                )
                output_lines.append(line)
                all_passed = all_passed and passed

        return all_passed, "\n".join(output_lines)


_load_feature_registry()


def _h_rev_revision_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Delegate the retained revision handler through the stable facade."""
    return _retained_rev_revision_run(world, text, examples)


def _h_sp1_rev_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Delegate the retained SP1 revision helper through the stable facade."""
    return _retained_sp1_rev_run(world, text, examples)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: acceptance_runtime.py <ir-path>", file=sys.stderr)
        sys.exit(2)
    try:
        all_passed, output = execute_ir(sys.argv[1])
        print(output)
        sys.exit(0 if all_passed else 1)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)

__all__ = [
    "execute_ir",
    "execute_step",
    "STEP_PATTERNS",
    "_REGISTERED_PATTERN_KEYS",
    "_track_registration",
    "_register",
    "_register_first",
    "_set_feature",
    "_derive_feature_tag",
    "find_pattern_conflicts",
    "World",
    "_h_rev_revision_run",
    "_h_sp1_rev_run",
]
