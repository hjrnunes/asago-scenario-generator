"""Architecture guards for the inward finalization contract leaf.

These tests lock the dependency-inward split after the cleaner decomposed
finalization, admission, gates, and persistence:

1. ``finalization_contracts`` is a leaf: it never imports the lifecycle
   controller, admission/gates, persistence, or IO-near modules.
2. Persistence adapters and durable records depend inward on that leaf,
   never on the public ``pipeline.finalization`` façade.
3. Admission and gates consume the same contract leaf.
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

_CONTRACT_MODULE = "asago_scenario_generator.pipeline.finalization_contracts"
_FACADE_MODULE = "asago_scenario_generator.pipeline.finalization"
_IMPLEMENTATION_MODULES = {
    "asago_scenario_generator.pipeline.finalization",
    "asago_scenario_generator.pipeline.finalization_admission",
    "asago_scenario_generator.pipeline.finalization_gates",
    "asago_scenario_generator.pipeline.runner",
    "asago_scenario_generator.pipeline.runner_finalization",
    "asago_scenario_generator.pipeline.runner_run",
    "asago_scenario_generator.pipeline.runner_resume",
    "asago_scenario_generator.pipeline.persistence",
    "asago_scenario_generator.pipeline.persistence_validation",
}
_FORBIDDEN_IO_NEAR_PREFIXES = (
    "asago_scenario_generator.llm",
    "asago_scenario_generator.prompts",
    "asago_scenario_generator.manifest",
    "asago_scenario_generator.report",
    "asago_scenario_generator.cli",
    "asago_scenario_generator.stpa",
)
_PERSISTENCE_ADAPTERS = (
    "persistence_common.py",
    "persistence_models.py",
    "persistence_artifacts.py",
    "persistence_decisions.py",
    "persistence_journal.py",
    "persistence_adapter_core.py",
    "persistence_adapter_events.py",
    "persistence_adapter_evidence.py",
    "persistence_adapter_admission.py",
    "persistence_adapter_terminal.py",
    "persistence_adapter_terminal_methods.py",
    "persistence_validation.py",
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


class TestFinalizationContractLeaf:
    """The contract module stays a dependency-inward leaf."""

    def test_contracts_import_cleanly(self) -> None:
        """The leaf can be imported without pulling the lifecycle controller."""
        module = importlib.import_module(_CONTRACT_MODULE)
        assert module.GeneratedStage is not None
        assert module.CandidateTerminalStatus is not None
        assert module.ordered_target_choice_refs is not None

    def test_contracts_do_not_import_implementation_modules(self) -> None:
        """Contracts must not reach admission, gates, runner, or persistence."""
        imports = _imported_modules(PIPELINE_DIR / "finalization_contracts.py")
        violations = sorted(imports & _IMPLEMENTATION_MODULES)
        assert not violations, (
            "finalization_contracts imports implementation modules: "
            f"{violations}"
        )

    def test_contracts_do_not_import_io_near_modules(self) -> None:
        """The contract leaf stays free of IO, prompts, UI, and STPA."""
        imports = _imported_modules(PIPELINE_DIR / "finalization_contracts.py")
        violations = [
            imp
            for imp in imports
            if any(
                imp == forbidden or imp.startswith(forbidden + ".")
                for forbidden in _FORBIDDEN_IO_NEAR_PREFIXES
            )
        ]
        assert not violations, (
            "finalization_contracts imports IO-near modules: "
            f"{sorted(violations)}"
        )


class TestFinalizationAdaptersDependInward:
    """Admission, gates, and persistence depend on the contract leaf."""

    @pytest.mark.parametrize(
        "module_name",
        (
            "finalization_admission.py",
            "finalization_gates.py",
            "finalization_gate_contracts.py",
            "finalization_parsimony.py",
            "finalization_prebehavior.py",
            "finalization_runtime.py",
            "finalization_snapshots.py",
            *_PERSISTENCE_ADAPTERS,
        ),
    )
    def test_adapter_does_not_import_finalization_facade(
        self, module_name: str
    ) -> None:
        """Adapters reach shared types through the contract leaf."""
        imports = _imported_modules(PIPELINE_DIR / module_name)
        assert _FACADE_MODULE not in imports, (
            f"{module_name} must not import the public finalization façade"
        )
        assert not any(
            imp.startswith(_FACADE_MODULE + ".") for imp in imports
        ), f"{module_name} must not import the public finalization façade"

    @pytest.mark.parametrize(
        "module_name",
        (
            "finalization_admission.py",
            "finalization_gates.py",
            "finalization_gate_contracts.py",
            "finalization_parsimony.py",
            "finalization_prebehavior.py",
            "finalization_runtime.py",
            "persistence_models.py",
            "persistence_artifacts.py",
            "persistence_decisions.py",
            "persistence_journal.py",
            "persistence_adapter_core.py",
            "persistence_adapter_events.py",
            "persistence_adapter_evidence.py",
            "persistence_adapter_admission.py",
            "persistence_adapter_terminal.py",
            "persistence_adapter_terminal_methods.py",
            "persistence_validation.py",
        ),
    )
    def test_adapter_imports_contract_leaf(self, module_name: str) -> None:
        """Each adapter that needs lifecycle types imports the contract leaf."""
        imports = _imported_modules(PIPELINE_DIR / module_name)
        assert _CONTRACT_MODULE in imports, (
            f"{module_name} must import {_CONTRACT_MODULE}"
        )


class TestPersistenceCanonicalEncoderDependsInward:
    """Durable encoding uses the projection contract, not the façade."""

    def test_persistence_common_does_not_import_projection_facade(self) -> None:
        """Canonical persistence encoding must not pull projection machinery."""
        imports = _imported_modules(PIPELINE_DIR / "persistence_common.py")
        assert "asago_scenario_generator.pipeline.projection" not in imports
        assert (
            "asago_scenario_generator.pipeline.projection_contracts" in imports
        )

    def test_persistence_validation_does_not_import_persistence_facade(
        self,
    ) -> None:
        """Inventory validation depends on record modules, not the façade."""
        imports = _imported_modules(PIPELINE_DIR / "persistence_validation.py")
        assert "asago_scenario_generator.pipeline.persistence" not in imports
        assert "asago_scenario_generator.pipeline.projection" not in imports


class TestPrebehaviorDependsInward:
    """Pre-behavior gates consume contract leaves, not generate façades."""

    def test_prebehavior_does_not_import_generate_facades(self) -> None:
        """Ownership and realization gates stay off the IO-near façades."""
        imports = _imported_modules(PIPELINE_DIR / "finalization_prebehavior.py")
        assert "asago_scenario_generator.pipeline.generate.narrative" not in imports
        assert "asago_scenario_generator.pipeline.generate.assembly" not in imports
        assert (
            "asago_scenario_generator.pipeline.generate.narrative_access" in imports
        )
        assert "asago_scenario_generator.pipeline.projection_block" in imports
