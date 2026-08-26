"""Architecture guards for the coverage-planning leaf split.

Universe construction and min-cost assignment stay off the candidates and
projection façades. Queue construction consumes candidate and projection
contracts inward.
"""

from __future__ import annotations

import ast
from pathlib import Path

PIPELINE_DIR = (
    Path(__file__).resolve().parent.parent
    / "src"
    / "asago_scenario_generator"
    / "pipeline"
)

_CANDIDATE_FACADE = "asago_scenario_generator.pipeline.candidates"
_PROJECTION_FACADE = "asago_scenario_generator.pipeline.projection"
_FORBIDDEN_IO_NEAR_PREFIXES = (
    "asago_scenario_generator.llm",
    "asago_scenario_generator.prompts",
    "asago_scenario_generator.manifest",
    "asago_scenario_generator.report",
    "asago_scenario_generator.cli",
    "asago_scenario_generator.stpa",
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


class TestCoveragePlanningLeavesStayOffFacades:
    """Universe and flow helpers stay free of IO and public façades."""

    _MODULES = (
        "coverage_planning_universe.py",
        "coverage_planning_flow.py",
    )

    def test_leaves_do_not_import_io_or_facades(self) -> None:
        """These helpers stay off prompts, LLM, candidates, and projection."""
        forbidden = {
            _CANDIDATE_FACADE,
            _PROJECTION_FACADE,
            *_FORBIDDEN_IO_NEAR_PREFIXES,
        }
        for module in self._MODULES:
            imports = _imported_modules(PIPELINE_DIR / module)
            violations = [
                imp
                for imp in imports
                if any(
                    imp == item or imp.startswith(item + ".")
                    for item in forbidden
                )
            ]
            assert not violations, (
                f"{module} imports forbidden modules: {sorted(violations)}"
            )


class TestCoveragePlanningDependsInward:
    """Queue construction consumes contract leaves, not candidate/projection façades."""

    def test_planning_imports_candidate_and_projection_contracts(self) -> None:
        """The planner reaches identity types through inward contract leaves."""
        imports = _imported_modules(PIPELINE_DIR / "coverage_planning.py")
        assert "asago_scenario_generator.pipeline.candidate_models" in imports
        assert "asago_scenario_generator.pipeline.projection_contracts" in imports
        assert _CANDIDATE_FACADE not in imports
        assert not any(
            imp.startswith(_CANDIDATE_FACADE + ".") for imp in imports
        )
