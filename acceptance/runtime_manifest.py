"""Deterministic, validated manifest for acceptance runtime features."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

RUNTIME_ROOT = str(Path(__file__).resolve().parent)
if RUNTIME_ROOT not in sys.path:
    sys.path.insert(0, RUNTIME_ROOT)

MODULES = (
    "foundation",
    "infrastructure",
    "models",
    "sp1",
    "sp1_revision",
    "parallel_llm",
    "stage2",
    "sp2",
    "sp3",
    "sp3_prompt_remediation",
    "stage1_split",
    "acceptance_refresh",
    "critic_revision_fix",
    "shadow_cleanup",
    "llm_helper_failure_defenses",
    "acceptance_hygiene",
    "acceptance_live_opt_in",
    "acceptance_framework_refactor",
    "clean_checkout_unit_independence",
    "acceptance_pipeline_preservation",
    "nullable_usage",
    "taxonomy_risk",
    "taxonomy_cli",
    "taxonomy_threat_surface",
    "taxonomy_report",
    "taxonomy_report_sections",
    "taxonomy_obligation_planner",
    "system_resource_map",
    "correspondence",
    "hybrid_coverage_assessment",
    "stpa_challenge_ledger",
    "stpa_challenge_analysis",
    "closed_loop_stpa",
    "stpa",
    "phase4_task1_hybrid_projection",
    "hybrid_scenario_projection",
)


def _validate_module(name: str, module: ModuleType) -> None:
    """Validate a single feature module's identity and register callable."""
    if getattr(module, "FEATURE_ID", None) != name:
        raise RuntimeError(f"runtime feature {name} has invalid FEATURE_ID")
    register = getattr(module, "register", None)
    if not callable(register):
        raise RuntimeError(f"runtime feature {name} does not expose register(api)")


def load_modules() -> tuple[ModuleType, ...]:
    """Load and validate the complete feature manifest before registration."""
    if len(MODULES) != len(set(MODULES)):
        raise RuntimeError("runtime feature manifest contains duplicate modules")
    expected = set(__import__("runtime_features").__all__)
    if set(MODULES) != expected:
        missing = sorted(expected - set(MODULES))
        omitted = sorted(set(MODULES) - expected)
        raise RuntimeError(
            f"runtime feature manifest mismatch: missing={missing}, omitted={omitted}"
        )
    modules = tuple(
        importlib.import_module(f"runtime_features.{name}") for name in MODULES
    )
    for name, module in zip(MODULES, modules):
        _validate_module(name, module)
    return modules


def register_one(api: Any, name: str, module: ModuleType) -> None:
    """Register one validated feature module, wrapping failures."""
    if getattr(module, "FEATURE_ID", None) != name:
        raise RuntimeError(f"runtime feature order mismatch at {name}")
    try:
        module.register(api)
    except Exception as exc:
        raise RuntimeError(
            f"runtime feature {name} registration failed: {exc}"
        ) from exc


_register_one = register_one


def register_all(api: Any, modules: tuple[ModuleType, ...] | None = None) -> None:
    """Invoke each validated feature registration exactly once."""
    selected = load_modules() if modules is None else modules
    if len(selected) != len(MODULES):
        raise RuntimeError("runtime feature registration set is incomplete")
    for name, module in zip(MODULES, selected):
        register_one(api, name, module)
