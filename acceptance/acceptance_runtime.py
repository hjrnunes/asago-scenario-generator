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
from live_llm_opt_in import (
    LIVE_LLM_ACCEPTANCE_MARKER,
    LIVE_LLM_SKIP_REASON,
    live_llm_acceptance_authorized,
    scenario_requires_live_llm_acceptance,
)
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
    "taxonomy_threat_surface_derivation": "taxonomy_threat_surface",
    "taxonomy_report_rendering": "taxonomy_report",
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


def _requires_live_llm_acceptance(
    scenario: dict[str, Any],
    background: list[Any] | None = None,
) -> bool:
    """Return whether a scenario explicitly opts into live LLM execution."""
    return scenario_requires_live_llm_acceptance(scenario, background)


def _scenario_examples(scenario: dict[str, Any]) -> list[dict]:
    return scenario.get("examples") or [{}]


def _should_skip_live_scenario(
    scenario: dict[str, Any],
    background_steps: list[Any],
) -> bool:
    return (
        _requires_live_llm_acceptance(scenario, background_steps)
        and not live_llm_acceptance_authorized()
    )


_restore_environment = restore_environment


def current_execution_feature() -> str | None:
    """Return the feature tag currently being executed."""
    return _CURRENT_EXECUTION_FEATURE


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
                if _should_skip_live_scenario(scenario, background_steps):
                    output_lines.append(f"SKIP {exec_name}: {LIVE_LLM_SKIP_REASON}")
                    continue

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
    "LIVE_LLM_ACCEPTANCE_MARKER",
    "_requires_live_llm_acceptance",
    "find_pattern_conflicts",
    "World",
    "_h_rev_revision_run",
    "_h_sp1_rev_run",
]


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-12T15:43:08Z","module_hash":"d0ae498ad37eb82b6a824ec80f63bce558ffa2bc089d60709928b64be1e86049","functions":[{"id":"func/_set_feature","name":"_set_feature","line":26,"end_line":29,"hash":"6307fdf988bdf8ef9e6620b405b9eca7ba2028dff6c7a5bd3d220edfa3975ee2"},{"id":"func/_track_registration","name":"_track_registration","line":31,"end_line":50,"hash":"21b345163f92f536420dc54662adc5a979f1796b0bca9ddb86f617082b9f33db"},{"id":"func/_register","name":"_register","line":52,"end_line":54,"hash":"621dccde5ade32f9a17ae728f6240b43411697ba0ec69aa77b49bc8e361c1efc"},{"id":"func/_register_first","name":"_register_first","line":56,"end_line":67,"hash":"ac3c07fdf5cf781afde46378e7a152633ec0eb9ef101b7617494083460744b13"},{"id":"func/find_pattern_conflicts","name":"find_pattern_conflicts","line":69,"end_line":110,"hash":"548ff4468b558151822519db20b2c42c67b60dde77bb9cb9b0ba438d5d44c8ac"},{"id":"func/_RegistrationStage.__init__","name":"__init__","line":115,"end_line":119,"hash":"299fb1374f4d1549d2837b7099f8ce2074169cc78495f30c2f591b971cf8f28f"},{"id":"func/_RegistrationStage.add","name":"add","line":121,"end_line":134,"hash":"6eb1ccc8149c3636a4c4c7a40133ea4ec3d23ba8dea627de140f1df802dc2838"},{"id":"func/_RegistrationAPI.__init__","name":"__init__","line":139,"end_line":149,"hash":"eda33bd4782e797b5dc9719264b358ebb94f24deda3549e0dc658ad0a4691724"},{"id":"func/_RegistrationAPI.set_feature","name":"set_feature","line":151,"end_line":152,"hash":"a61fb63997ba750de8bf852a88155fe4cb15ca570243c6b43e2291b49347562c"},{"id":"func/_RegistrationAPI.register","name":"register","line":154,"end_line":155,"hash":"a6cf0272c5b9b352ca241aa1423362024355650fe461bad45c19fd788d894110"},{"id":"func/_RegistrationAPI.register_first","name":"register_first","line":157,"end_line":158,"hash":"bea45c1ea22bf46e8228dc0f549636d7edca5d19d9a2ca6062fc6b3b79fb9064"},{"id":"func/_RegistrationAPI.install_handlers","name":"install_handlers","line":160,"end_line":164,"hash":"b9a443437180fd498d16c61b3aba9ab6456ad2d1437fb1f900726e723c8583ba"},{"id":"func/_publish","name":"_publish","line":166,"end_line":176,"hash":"23b0a131a6002a21604210b75c4f260c0f7c7baf8f5bbeca040115cd68ff1d7e"},{"id":"func/_load_feature_registry","name":"_load_feature_registry","line":178,"end_line":187,"hash":"cbe0828a96a9e45e1495d75bbe970ca8f605315aa0b4f0b609a5b38df0bd79a9"},{"id":"func/execute_step","name":"execute_step","line":189,"end_line":216,"hash":"6e9fff2458c8d0a5739d1b4aa41b04e99add51616c383f8be95a661bcfda1408"},{"id":"func/_derive_feature_tag","name":"_derive_feature_tag","line":234,"end_line":248,"hash":"0fe8e05005ed9082edf036d256f56a0c98d4aaa615a9756d8b5e0c869676b836"},{"id":"func/execute_ir","name":"execute_ir","line":250,"end_line":297,"hash":"e7171fb4cb57641167c157f9172b6516833b596155c21ab86a7056ff335f8a2c"},{"id":"func/_h_rev_revision_run","name":"_h_rev_revision_run","line":301,"end_line":303,"hash":"8b4b2b38def806c5cfaf68bd7c99e84d1e0993d1e249ce35c14cc514ea12c678"},{"id":"func/_h_sp1_rev_run","name":"_h_sp1_rev_run","line":305,"end_line":307,"hash":"c2b0f394788947fd5f67c76104a89b1e64d9723e6f22b87ad466e5efbaa6467f"}]}
# mutate4py-manifest-end
