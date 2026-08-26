"""Architecture guards for the candidate-pipeline contract split."""

from __future__ import annotations

import ast
import importlib
from pathlib import Path

import pytest

PIPELINE_DIR = (
    Path(__file__).resolve().parent.parent
    / "src"
    / "asago_scenario_generator"
    / "pipeline"
)

_MODELS_MODULE = "asago_scenario_generator.pipeline.candidate_models"
_FACADE_MODULE = "asago_scenario_generator.pipeline.candidates"
_IMPLEMENTATION_MODULES = {
    "asago_scenario_generator.pipeline.candidates",
    "asago_scenario_generator.pipeline.candidate_capping",
    "asago_scenario_generator.pipeline.candidate_expansion",
    "asago_scenario_generator.pipeline.candidate_filter",
    "asago_scenario_generator.pipeline.candidate_rules",
}
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


class TestCandidateModelsLeaf:
    """Identity and wire models stay free of orchestration and IO."""

    def test_models_import_cleanly(self) -> None:
        """The models leaf can be imported without the candidate façade."""
        module = importlib.import_module(_MODELS_MODULE)
        assert module.compute_candidate_id is not None
        assert module.CandidateTriple is not None

    def test_models_do_not_import_implementation_modules(self) -> None:
        """Models must not reach expansion, filter, rules, or the façade."""
        imports = _imported_modules(PIPELINE_DIR / "candidate_models.py")
        violations = sorted(imports & _IMPLEMENTATION_MODULES)
        assert not violations, (
            f"candidate_models imports implementation modules: {violations}"
        )

    def test_models_do_not_import_io_near_modules(self) -> None:
        """The models leaf stays free of IO, prompts, UI, and STPA."""
        imports = _imported_modules(PIPELINE_DIR / "candidate_models.py")
        violations = [
            imp
            for imp in imports
            if any(
                imp == forbidden or imp.startswith(forbidden + ".")
                for forbidden in _FORBIDDEN_IO_NEAR_PREFIXES
            )
        ]
        assert not violations, (
            f"candidate_models imports IO-near modules: {sorted(violations)}"
        )


class TestCandidateAdaptersDependInward:
    """Implementation adapters depend on the models leaf, not the façade."""

    @pytest.mark.parametrize(
        "module_name",
        (
            "candidate_capping.py",
            "candidate_expansion.py",
            "candidate_filter.py",
            "candidate_rules.py",
            "coverage_planning.py",
            "coverage_planning_flow.py",
            "coverage_planning_universe.py",
            "io.py",
        ),
    )
    def test_adapter_does_not_import_candidates_facade(self, module_name: str) -> None:
        """Adapters must not import the public candidates façade."""
        imports = _imported_modules(PIPELINE_DIR / module_name)
        assert _FACADE_MODULE not in imports, (
            f"{module_name} must not import the public candidates façade"
        )
        assert not any(imp.startswith(_FACADE_MODULE + ".") for imp in imports)

    @pytest.mark.parametrize(
        "module_name",
        (
            "candidate_capping.py",
            "candidate_expansion.py",
            "candidate_filter.py",
            "candidate_rules.py",
            "coverage_planning.py",
            "io.py",
        ),
    )
    def test_adapter_imports_models_leaf(self, module_name: str) -> None:
        """Each adapter reaches shared types through the models leaf."""
        imports = _imported_modules(PIPELINE_DIR / module_name)
        assert _MODELS_MODULE in imports, f"{module_name} must import {_MODELS_MODULE}"


class TestCandidateCappingDependsInward:
    """Capping consumes origin helpers from the models leaf, not expansion."""

    def test_capping_does_not_import_expansion_privates(self) -> None:
        """Filtered-seed merge stays off expansion implementation helpers."""
        imports = _imported_modules(PIPELINE_DIR / "candidate_capping.py")
        assert "asago_scenario_generator.pipeline.candidate_expansion" not in imports
        assert _MODELS_MODULE in imports


class TestRunnerAndPreflightDependInward:
    """Orchestration consumes candidate leaves, not the public façade."""

    @pytest.mark.parametrize(
        "module_name",
        (
            "preflight.py",
            "runner.py",
            "runner_run.py",
        ),
    )
    def test_orchestrator_does_not_import_candidates_facade(
        self, module_name: str
    ) -> None:
        """Preflight and runner reach identity through inward leaves."""
        imports = _imported_modules(PIPELINE_DIR / module_name)
        assert _FACADE_MODULE not in imports, (
            f"{module_name} must not import the public candidates façade"
        )
        assert not any(imp.startswith(_FACADE_MODULE + ".") for imp in imports)
