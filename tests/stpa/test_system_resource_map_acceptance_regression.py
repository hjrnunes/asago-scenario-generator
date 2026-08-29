"""Regression tests for the Task 2 acceptance registration seam."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = next(
    path
    for path in Path(__file__).resolve().parents
    if (path / "pyproject.toml").is_file()
)
ACCEPTANCE = ROOT / "acceptance"
if str(ACCEPTANCE) not in sys.path:
    sys.path.insert(0, str(ACCEPTANCE))

from acceptance_runtime import STEP_PATTERNS, resolve_handler  # noqa: E402


def _task2_handlers() -> set[object]:
    return {
        handler
        for _pattern, handler, _feature in STEP_PATTERNS
        if getattr(handler, "__module__", "") == "runtime_features.system_resource_map"
    }


def test_resource_map_validation_steps_do_not_shadow_global_validation_steps() -> None:
    """Task 2 assertions must not capture another feature's generic steps."""
    task2_handlers = _task2_handlers()

    assert resolve_handler(STEP_PATTERNS, "the resource map passes validation") in (
        task2_handlers
    )
    assert resolve_handler(STEP_PATTERNS, "the resource map fails validation") in (
        task2_handlers
    )
    assert resolve_handler(STEP_PATTERNS, "validation succeeds") not in task2_handlers
    assert resolve_handler(STEP_PATTERNS, "validation fails") not in task2_handlers
