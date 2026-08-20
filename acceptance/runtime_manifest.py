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
    "stpa",
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


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-12T15:44:24Z","module_hash":"995dc1770db0dbe5bb294afb36072e6e08241613031c13752107d4fabc8391e5","functions":[{"id":"func/_validate_module","name":"_validate_module","line":27,"end_line":33,"hash":"b04bb0f432ca3879bec77223eb14e97367d8c54127beaaca19ec66644ea80483"},{"id":"func/load_modules","name":"load_modules","line":36,"end_line":48,"hash":"d931c44b91b732541db286ece733d73a9212a1ef4b272b0b845eeaa1e4197b64"},{"id":"func/_register_one","name":"_register_one","line":51,"end_line":60,"hash":"7b84e1e6aa81923854153303701f739d0e5b3c1279116a6ffdc9d21ff90ee9ce"},{"id":"func/register_all","name":"register_all","line":63,"end_line":69,"hash":"2baccb463f0f9a273a6ce509e3b08c56592b3dd12651e0b058aed0c47c7bf823"}]}
# mutate4py-manifest-end
