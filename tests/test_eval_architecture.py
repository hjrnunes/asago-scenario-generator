"""Architecture guards for the deterministic evaluation split."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

EVAL_DIR = (
    Path(__file__).resolve().parent.parent
    / "src"
    / "asago_scenario_generator"
    / "eval"
)

_FORBIDDEN_IO_NEAR_PREFIXES = (
    "asago_scenario_generator.llm",
    "asago_scenario_generator.prompts",
    "asago_scenario_generator.cli",
    "asago_scenario_generator.stpa",
    "asago_scenario_generator.pipeline.persistence",
    "asago_scenario_generator.pipeline.finalization_gates",
    "asago_scenario_generator.pipeline.finalization",
)
_METRIC_LEAVES = (
    "consistency.py",
    "diversity.py",
    "gherkin.py",
    "grounding.py",
    "plausibility.py",
    "scorecard.py",
    "versioned_metrics.py",
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


class TestEvalLeavesDependInward:
    """Metric modules stay off persistence and finalization façades."""

    @pytest.mark.parametrize("module_name", _METRIC_LEAVES)
    def test_leaf_does_not_import_io_near_modules(self, module_name: str) -> None:
        """Each eval leaf stays free of IO-near and façade modules."""
        imports = _imported_modules(EVAL_DIR / module_name)
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

    def test_versioned_metrics_imports_inward_record_leaves(self) -> None:
        """Authoritative v3 metrics consume persistence records, not the façade."""
        imports = _imported_modules(EVAL_DIR / "versioned_metrics.py")
        assert (
            "asago_scenario_generator.pipeline.finalization_gate_contracts"
            in imports
        )
        assert "asago_scenario_generator.pipeline.persistence_journal" in imports
        assert "asago_scenario_generator.pipeline.persistence_plan" in imports
        assert "asago_scenario_generator.eval.scorecard" in imports
