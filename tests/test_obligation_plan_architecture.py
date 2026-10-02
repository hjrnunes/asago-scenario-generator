"""Architecture guards for the typed obligation-plan contract split."""

from __future__ import annotations

import ast
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent / "src" / "asago_scenario_generator"

_PACKAGE_ROOT = "asago_scenario_generator"
_OUTPUT_MODULE = "asago_scenario_generator.models.obligation_plan"
_INPUT_MODULE = "asago_scenario_generator.pipeline.obligation_contracts"
_PLANNER_MODULE = "asago_scenario_generator.pipeline.obligation_planner"
_PERSISTENCE_MODULE = "asago_scenario_generator.pipeline.obligation_persistence"

_SHARED_OUTPUT_LEAVES = {
    "asago_scenario_generator.models.attack_pattern_contracts",
    "asago_scenario_generator.models.attack_pattern_projection",
    "asago_scenario_generator.models.canonical",
}
_PLANNER_DEPENDENCIES = {
    _PACKAGE_ROOT + ".pipeline",
    _OUTPUT_MODULE,
    _INPUT_MODULE,
    "asago_scenario_generator.models.attack_pattern_chain",
    "asago_scenario_generator.models.attack_pattern_contracts",
    "asago_scenario_generator.models.attack_pattern",
    "asago_scenario_generator.models.canonical",
    "asago_scenario_generator.pipeline.projection_authoritative",
    "asago_scenario_generator.pipeline.projection_contracts",
    "asago_scenario_generator.pipeline.projection_qualification",
}


def _imported_modules(path: Path) -> set[str]:
    """Return absolute module names imported by a source file."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
    return modules


def _in_package(modules: set[str]) -> set[str]:
    """Filter imported modules down to the application package."""
    return {
        module
        for module in modules
        if module == _PACKAGE_ROOT or module.startswith(_PACKAGE_ROOT + ".")
    }


def test_persisted_output_depends_only_on_shared_contract_leaves() -> None:
    """The persisted model cannot depend on pipeline or adapter layers."""
    imports = _in_package(_imported_modules(SRC_DIR / "models" / "obligation_plan.py"))

    assert imports <= _SHARED_OUTPUT_LEAVES, (
        f"{_OUTPUT_MODULE} must depend only on shared leaves, got {sorted(imports)}"
    )


def test_typed_input_contract_stays_inward() -> None:
    """Input contracts stay below the planner and delivery adapter layers."""
    imports = _in_package(
        _imported_modules(SRC_DIR / "pipeline" / "obligation_contracts.py")
    )

    # Shared typed leaves may be reused by the input contract.  The boundary
    # under test is directional: input definitions must not reach the planner,
    # persistence, or CLI adapters that consume them.
    assert _PLANNER_MODULE not in imports
    assert _PERSISTENCE_MODULE not in imports
    assert not any(module.startswith(f"{_PACKAGE_ROOT}.cli") for module in imports)


def test_planner_depends_on_input_output_and_authoritative_projection_leaves() -> None:
    """The planner may use domain/projection contracts but never delivery code."""
    imports = _in_package(
        _imported_modules(SRC_DIR / "pipeline" / "obligation_planner.py")
    )

    assert imports <= _PLANNER_DEPENDENCIES, (
        f"{_PLANNER_MODULE} has out-of-layer imports: {sorted(imports)}"
    )
    assert _INPUT_MODULE in imports
    assert _OUTPUT_MODULE in imports


def test_core_planner_code_does_not_import_cli() -> None:
    """Core models and planning do not depend on public delivery adapters."""
    for relative in (
        ("models", "obligation_plan.py"),
        ("pipeline", "obligation_contracts.py"),
        ("pipeline", "obligation_planner.py"),
        ("pipeline", "obligation_persistence.py"),
    ):
        imports = _imported_modules(SRC_DIR.joinpath(*relative))
        violations = [
            module
            for module in imports
            if module == f"{_PACKAGE_ROOT}.cli"
            or module.startswith(f"{_PACKAGE_ROOT}.cli.")
        ]
        assert not violations, (
            f"{'/'.join(relative)} imports CLI modules: {sorted(violations)}"
        )


def test_persistence_depends_inward_on_core() -> None:
    """The persistence adapter consumes the typed plan output inward."""
    persistence_imports = _in_package(
        _imported_modules(SRC_DIR / "pipeline" / "obligation_persistence.py")
    )

    assert _OUTPUT_MODULE in persistence_imports
    assert _INPUT_MODULE not in persistence_imports
    assert not any(
        module.startswith(f"{_PACKAGE_ROOT}.cli") for module in persistence_imports
    )
