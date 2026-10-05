"""Architecture guards for the authoritative projection contract leaf.

These tests lock the dependency-inward split after the projection package
was decomposed out of the former monolithic ``projection.py``:

1. ``projection_contracts`` is a leaf: it imports domain models and stdlib
   only, never projection implementation modules.
2. Implementation adapters depend inward on the contract leaf.
"""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest
from tests.helpers.architecture import imported_modules

PIPELINE_DIR = (
    Path(__file__).resolve().parent.parent
    / "src"
    / "asago_scenario_generator"
    / "pipeline"
)

_CONTRACT_MODULE = "asago_scenario_generator.pipeline.projection_contracts"
_IMPLEMENTATION_MODULES = {
    "asago_scenario_generator.pipeline.projection_allocation",
    "asago_scenario_generator.pipeline.projection_allocator",
    "asago_scenario_generator.pipeline.projection_authoritative",
    "asago_scenario_generator.pipeline.projection_candidates",
    "asago_scenario_generator.pipeline.projection_qualification",
    "asago_scenario_generator.pipeline.projection_relations",
    "asago_scenario_generator.pipeline.projection_requirements",
    "asago_scenario_generator.pipeline.projection_resources",
}
_FORBIDDEN_IO_NEAR_PREFIXES = (
    "asago_scenario_generator.prompts",
    "asago_scenario_generator.manifest",
    "asago_scenario_generator.report",
    "asago_scenario_generator.cli",
    "asago_scenario_generator.stpa",
)


class TestProjectionContractLeaf:
    """The contract module stays a dependency-inward leaf."""

    def test_contracts_import_cleanly(self) -> None:
        """The leaf can be imported without pulling implementation modules."""
        module = importlib.import_module(_CONTRACT_MODULE)
        assert module.ProjectedCandidate is not None
        assert module.CapabilityFactSnapshot is not None

    def test_contracts_do_not_import_implementation_modules(self) -> None:
        """Contracts must not reach allocation or resources."""
        imports = imported_modules(PIPELINE_DIR / "projection_contracts.py")
        violations = sorted(imports & _IMPLEMENTATION_MODULES)
        assert not violations, (
            f"projection_contracts imports implementation modules: {violations}"
        )

    def test_contracts_do_not_import_io_near_modules(self) -> None:
        """The contract leaf stays free of IO, prompts, UI, and STPA."""
        imports = imported_modules(PIPELINE_DIR / "projection_contracts.py")
        violations = [
            imp
            for imp in imports
            if any(
                imp == forbidden or imp.startswith(forbidden + ".")
                for forbidden in _FORBIDDEN_IO_NEAR_PREFIXES
            )
        ]
        assert not violations, (
            f"projection_contracts imports IO-near modules: {sorted(violations)}"
        )


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
        ),
    )
    def test_adapter_imports_contract_leaf(self, module_name: str) -> None:
        """Each adapter reaches shared types through the contract leaf."""
        imports = imported_modules(PIPELINE_DIR / module_name)
        assert _CONTRACT_MODULE in imports, (
            f"{module_name} must import {_CONTRACT_MODULE}"
        )
