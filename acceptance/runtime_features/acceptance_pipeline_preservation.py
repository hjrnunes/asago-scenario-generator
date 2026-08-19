"""Acceptance contracts for preserving the generated-test pipeline."""

from __future__ import annotations

import re
from pathlib import Path

from runtime_shared import PROJECT_ROOT, World
from snapshot import metadata_name


_WORKFLOW = PROJECT_ROOT / ".github" / "workflows" / "ci.yml"
_FEATURES = PROJECT_ROOT / "features"
_IR_DIR = "build/acceptance/ir"
_GENERATED_DIR = "build/acceptance/generated"


def _workflow_text() -> str:
    return _WORKFLOW.read_text(encoding="utf-8")


def _generated_files() -> tuple[list[Path], list[Path]]:
    ir_files = sorted(
        path
        for path in (PROJECT_ROOT / _IR_DIR).rglob("*.json")
        if not path.stem.endswith("_dry")
    )
    entrypoints = sorted((PROJECT_ROOT / _GENERATED_DIR).glob("*_acceptance_test.py"))
    return ir_files, entrypoints


def _entrypoint_ir_refs(path: Path) -> list[Path]:
    body = path.read_text(encoding="utf-8")
    return [
        PROJECT_ROOT / relative
        for relative in re.findall(r'_PROJECT_ROOT / "([^"]+\.json)"', body)
    ]


def _h_acceptance_command(world: World, text: str, examples: dict) -> tuple[bool, str]:
    world.app_acceptance_script = (
        PROJECT_ROOT / "scripts" / "acceptance.sh"
    ).read_text(encoding="utf-8")
    world.app_acceptance_command = "./scripts/acceptance.sh"
    return True, ""


def _h_feature_artifacts(world: World, text: str, examples: dict) -> tuple[bool, str]:
    missing = []
    for feature in _FEATURES.rglob("*.feature"):
        relative = feature.relative_to(_FEATURES).with_suffix("")
        paths = (
            PROJECT_ROOT / _IR_DIR / relative.with_suffix(".json"),
            PROJECT_ROOT / "build/acceptance/dry" / relative.with_suffix(".txt"),
            PROJECT_ROOT / _GENERATED_DIR / f"{feature.stem}_acceptance_test.py",
            PROJECT_ROOT
            / _GENERATED_DIR
            / "metadata"
            / metadata_name(f"features/{relative.as_posix()}.feature"),
        )
        missing.extend(str(path) for path in paths if not path.is_file())
    return not missing, f"missing generated acceptance artifacts: {missing[:8]}"


def _h_generated_execution(world: World, text: str, examples: dict) -> tuple[bool, str]:
    world.app_generated_executed = bool(
        getattr(world, "app_acceptance_script", "")
        and "pytest" in world.app_acceptance_script
    )
    return world.app_generated_executed, "acceptance script does not execute pytest"


def _h_command_success(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return (
        getattr(world, "app_generated_executed", False),
        "acceptance command execution was not recorded",
    )


def _h_validate_entrypoints(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    ir_files, entrypoints = _generated_files()
    targets = {
        entrypoint: {ref.resolve() for ref in _entrypoint_ir_refs(entrypoint)}
        for entrypoint in entrypoints
    }
    references = {
        path.resolve(): {
            entrypoint for entrypoint, refs in targets.items() if path.resolve() in refs
        }
        for path in ir_files
    }
    world.app_ir_files = ir_files
    world.app_entrypoints = entrypoints
    world.app_ir_reference_counts = {
        path: len(entrypoints) for path, entrypoints in references.items()
    }
    return (
        bool(ir_files and entrypoints)
        and all(len(refs) == 1 for refs in targets.values())
        and all(len(entrypoints) == 1 for entrypoints in references.values()),
        f"IR-to-entrypoint references are not one-to-one: {world.app_ir_reference_counts}",
    )


def _h_entrypoint_targets(world: World, text: str, examples: dict) -> tuple[bool, str]:
    missing = [
        str(ref)
        for path in getattr(world, "app_entrypoints", [])
        for ref in _entrypoint_ir_refs(path)
        if not ref.is_file()
    ]
    return not missing, f"entrypoints reference missing IR: {missing}"


def _h_entrypoint_directory(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    ir_root = PROJECT_ROOT / _IR_DIR
    outside = []
    for path in getattr(world, "app_entrypoints", []):
        outside.extend(
            str(ref)
            for ref in _entrypoint_ir_refs(path)
            if not ref.is_relative_to(ir_root)
        )
    return not outside, f"entrypoints reference IR outside {_IR_DIR}: {outside}"


def _h_ci_clean_checkout(world: World, text: str, examples: dict) -> tuple[bool, str]:
    world.app_ci = _workflow_text()
    return True, ""


def _job_body(workflow: str, job: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(job)}:.*?(?=^  [a-zA-Z_-]+:|\Z)",
        workflow,
    )
    return match.group(0) if match else ""


def _h_unit_ci_no_generation(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    unit = _job_body(getattr(world, "app_ci", ""), "unit")
    forbidden = (
        "refresh_snapshot",
        "acceptance.sh",
        "Acceptance-Pipeline-Specification",
    )
    return (
        bool(unit) and not any(value in unit for value in forbidden),
        "unit CI job provisions or generates acceptance artifacts",
    )


def _h_unit_ci_no_aps(world: World, text: str, examples: dict) -> tuple[bool, str]:
    unit = _job_body(getattr(world, "app_ci", ""), "unit")
    return (
        bool(unit)
        and "Acceptance-Pipeline-Specification" not in unit
        and "setup-clojure" not in unit,
        "unit CI job requires APS tooling",
    )


def _h_acceptance_ci_generates(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    acceptance = _job_body(getattr(world, "app_ci", ""), "acceptance")
    checkout = acceptance.find("Acceptance-Pipeline-Specification")
    command = acceptance.find("./scripts/acceptance.sh")
    return (
        checkout >= 0 and command > checkout,
        "acceptance CI does not provision APS before generation",
    )


FEATURE_ID = "acceptance_pipeline_preservation"


def register(api: object) -> None:
    """Register acceptance generation, validation, and CI-separation handlers."""
    api.set_feature(None)
    api.register(r"the documented acceptance command is invoked", _h_acceptance_command)
    api.register(
        r"every source feature has mapped IR, DRY report, generated entrypoint, and metadata",
        _h_feature_artifacts,
    )
    api.register(r"the generated acceptance suite executes", _h_generated_execution)
    api.register(r"the command exits successfully", _h_command_success)
    api.register(
        r"generated acceptance entrypoints are validated", _h_validate_entrypoints
    )
    api.register(
        r"the generated IR-to-entrypoint mapping is one-to-one",
        _h_validate_entrypoints,
    )
    api.register(r"each entrypoint target exists", _h_entrypoint_targets)
    api.register(
        r"each entrypoint target is inside the configured generated IR directory",
        _h_entrypoint_directory,
    )
    api.register(r"CI runs from a clean source checkout", _h_ci_clean_checkout)
    api.register(
        r"the unit job runs without generating acceptance artifacts",
        _h_unit_ci_no_generation,
    )
    api.register(
        r"the unit job does not require Acceptance Pipeline Specification tools",
        _h_unit_ci_no_aps,
    )
    api.register(
        r"the acceptance job generates acceptance artifacts before executing them",
        _h_acceptance_ci_generates,
    )
