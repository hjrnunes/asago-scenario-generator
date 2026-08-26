"""Architecture guards for the authoritative projection contract leaf.

These tests lock the dependency-inward split after the projection package
was decomposed out of the former monolithic ``projection.py``:

1. ``projection_contracts`` is a leaf: it imports domain models and stdlib
   only, never projection implementation modules or the public façade.
2. Domain persistence (``models.projection_envelope``) depends on that
   contract leaf, not on the projection façade or allocation machinery.
3. Implementation adapters depend inward on the contract leaf.
"""

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
MODELS_DIR = (
    Path(__file__).resolve().parent.parent
    / "src"
    / "asago_scenario_generator"
    / "models"
)

_CONTRACT_MODULE = "asago_scenario_generator.pipeline.projection_contracts"
_FACADE_MODULE = "asago_scenario_generator.pipeline.projection"
_IMPLEMENTATION_MODULES = {
    "asago_scenario_generator.pipeline.projection",
    "asago_scenario_generator.pipeline.projection_allocation",
    "asago_scenario_generator.pipeline.projection_allocator",
    "asago_scenario_generator.pipeline.projection_authoritative",
    "asago_scenario_generator.pipeline.projection_candidates",
    "asago_scenario_generator.pipeline.projection_drift",
    "asago_scenario_generator.pipeline.projection_qualification",
    "asago_scenario_generator.pipeline.projection_realizations",
    "asago_scenario_generator.pipeline.projection_relations",
    "asago_scenario_generator.pipeline.projection_requirements",
    "asago_scenario_generator.pipeline.projection_resources",
    "asago_scenario_generator.pipeline.projection_semantics",
    "asago_scenario_generator.pipeline.projection_snapshot",
    "asago_scenario_generator.pipeline.projection_validation",
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


class TestProjectionContractLeaf:
    """The contract module stays a dependency-inward leaf."""

    def test_contracts_import_cleanly(self) -> None:
        """The leaf can be imported without pulling implementation modules."""
        module = importlib.import_module(_CONTRACT_MODULE)
        assert module.ProjectedCandidate is not None
        assert module.CapabilityFactSnapshot is not None

    def test_contracts_do_not_import_implementation_modules(self) -> None:
        """Contracts must not reach allocation, resources, or the façade."""
        imports = _imported_modules(PIPELINE_DIR / "projection_contracts.py")
        violations = sorted(imports & _IMPLEMENTATION_MODULES)
        assert not violations, (
            "projection_contracts imports implementation modules: "
            f"{violations}"
        )

    def test_contracts_do_not_import_io_near_modules(self) -> None:
        """The contract leaf stays free of IO, prompts, UI, and STPA."""
        imports = _imported_modules(PIPELINE_DIR / "projection_contracts.py")
        violations = [
            imp
            for imp in imports
            if any(
                imp == forbidden or imp.startswith(forbidden + ".")
                for forbidden in _FORBIDDEN_IO_NEAR_PREFIXES
            )
        ]
        assert not violations, (
            "projection_contracts imports IO-near modules: "
            f"{sorted(violations)}"
        )


class TestProjectionEnvelopeDependsInward:
    """Domain persistence consumes the contract leaf, not the façade."""

    def test_envelope_does_not_import_projection_facade(self) -> None:
        """Envelope validation must not pull the public projection façade."""
        imports = _imported_modules(MODELS_DIR / "projection_envelope.py")
        assert _FACADE_MODULE not in imports
        assert not any(
            imp.startswith(_FACADE_MODULE + ".") for imp in imports
        )
        assert _CONTRACT_MODULE in imports


class TestProjectionAdaptersDependInward:
    """Implementation adapters depend on the contract leaf."""

    @pytest.mark.parametrize(
        "module_name",
        (
            "projection_resources.py",
            "projection_requirements.py",
            "projection_qualification.py",
            "projection_candidates.py",
            "projection_relations.py",
            "projection_allocation.py",
            "projection_allocator.py",
            "projection_drift.py",
            "projection_snapshot.py",
            "projection_validation.py",
        ),
    )
    def test_adapter_imports_contract_leaf(self, module_name: str) -> None:
        """Each adapter reaches shared types through the contract leaf."""
        imports = _imported_modules(PIPELINE_DIR / module_name)
        assert _CONTRACT_MODULE in imports, (
            f"{module_name} must import {_CONTRACT_MODULE}"
        )
        assert _FACADE_MODULE not in imports, (
            f"{module_name} must not import the public projection façade"
        )


class TestProjectionCheckLeavesStayOffTheFacade:
    """Traceability check modules stay inward of the public façade."""

    @pytest.mark.parametrize(
        "module_name",
        (
            "projection_drift.py",
            "projection_realizations.py",
            "projection_semantics.py",
            "projection_validation.py",
            "technique_scopes.py",
            "coverage_planning_universe.py",
            "coverage_planning_flow.py",
        ),
    )
    def test_check_leaf_does_not_import_projection_facade(
        self, module_name: str
    ) -> None:
        """Drift, realization, and semantic checks stay off the façade."""
        imports = _imported_modules(PIPELINE_DIR / module_name)
        assert _FACADE_MODULE not in imports, (
            f"{module_name} must not import the public projection façade"
        )
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
