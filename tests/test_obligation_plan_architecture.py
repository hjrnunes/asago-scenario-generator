"""Architecture guards for the obligation-plan contract split.

These tests lock the dependency-inward shape of the obligation planner:

1. ``models.obligation_plan`` is a contract leaf: it imports nothing from
   the application package.
2. ``pipeline.obligation_planner`` consumes only that contract leaf inside
   the package; it never reaches IO-near modules.
3. Core planner code never depends on the CLI, while the CLI adapter
   depends inward on the contract leaf and the planner.
"""

from __future__ import annotations

import ast
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent / "src" / "asago_scenario_generator"

_PACKAGE_ROOT = "asago_scenario_generator"
_CONTRACT_MODULE = "asago_scenario_generator.models.obligation_plan"
_PLANNER_MODULE = "asago_scenario_generator.pipeline.obligation_planner"


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


def test_contract_leaf_imports_no_application_modules() -> None:
    """The plan contracts stay a leaf: no application imports at all."""
    imports = _imported_modules(SRC_DIR / "models" / "obligation_plan.py")
    violations = _in_package(imports)
    assert not violations, (
        f"{_CONTRACT_MODULE} imports application modules: {sorted(violations)}"
    )


def test_planner_imports_only_the_contract_leaf() -> None:
    """The planner depends inward on the plan contracts and nothing else."""
    imports = _in_package(
        _imported_modules(SRC_DIR / "pipeline" / "obligation_planner.py")
    )
    assert imports == {_CONTRACT_MODULE}, (
        f"{_PLANNER_MODULE} must import only {_CONTRACT_MODULE}, got {sorted(imports)}"
    )


def test_core_planner_code_does_not_import_the_cli() -> None:
    """Delivery details never leak into the contract leaf or the planner."""
    for relative in (("models", "obligation_plan.py"), ("pipeline", "obligation_planner.py")):
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


def test_cli_adapter_depends_inward_on_core() -> None:
    """The CLI adapter consumes the contract leaf and the planner."""
    imports = _in_package(_imported_modules(SRC_DIR / "cli" / "obligation.py"))
    assert _CONTRACT_MODULE in imports, (
        f"cli.obligation must import {_CONTRACT_MODULE}"
    )
    assert _PLANNER_MODULE in imports, (
        f"cli.obligation must import {_PLANNER_MODULE}"
    )
