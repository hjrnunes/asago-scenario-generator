"""Architecture guards for the scenario-validation split."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

PIPELINE_DIR = (
    Path(__file__).resolve().parent.parent
    / "src"
    / "asago_scenario_generator"
    / "pipeline"
)

_FACADE_MODULE = "asago_scenario_generator.pipeline.validation"
_FORBIDDEN_IO_NEAR_PREFIXES = (
    "asago_scenario_generator.llm",
    "asago_scenario_generator.prompts",
    "asago_scenario_generator.manifest",
    "asago_scenario_generator.report",
    "asago_scenario_generator.cli",
    "asago_scenario_generator.stpa",
    "asago_scenario_generator.pipeline.generate.actor",
    "asago_scenario_generator.pipeline.generate.narrative",
    "asago_scenario_generator.pipeline.generate.assembly",
    "asago_scenario_generator.pipeline.validation",
)
_VALIDATION_LEAVES = (
    "validation_common.py",
    "validation_goal.py",
    "validation_insider.py",
    "validation_parsimony.py",
    "validation_phantom.py",
    "validation_provenance.py",
    "validation_semantic.py",
    "validation_semantic_actions.py",
    "validation_semantic_scope.py",
    "validation_structure.py",
)


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


class TestValidationLeavesDependInward:
    """Responsibility modules stay free of the public validation façade."""

    @pytest.mark.parametrize("module_name", _VALIDATION_LEAVES)
    def test_leaf_does_not_import_validation_facade(self, module_name: str) -> None:
        """Each validation leaf stays inward of the compatibility façade."""
        imports = _imported_modules(PIPELINE_DIR / module_name)
        assert _FACADE_MODULE not in imports, (
            f"{module_name} must not import the public validation façade"
        )
        assert not any(imp.startswith(_FACADE_MODULE + ".") for imp in imports)

    @pytest.mark.parametrize("module_name", _VALIDATION_LEAVES)
    def test_leaf_does_not_import_io_near_modules(self, module_name: str) -> None:
        """Validation leaves stay free of IO, prompts, UI, and STPA."""
        imports = _imported_modules(PIPELINE_DIR / module_name)
        violations = [
            imp
            for imp in imports
            if any(
                imp == forbidden or imp.startswith(forbidden + ".")
                for forbidden in _FORBIDDEN_IO_NEAR_PREFIXES
            )
        ]
        assert not violations, (
            f"{module_name} imports IO-near modules: {sorted(violations)}"
        )
