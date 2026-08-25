"""Architecture guards for the authoritative attack-pattern split."""

from __future__ import annotations

import ast
import importlib
from pathlib import Path

import pytest

MODELS_DIR = (
    Path(__file__).resolve().parent.parent
    / "src"
    / "asago_scenario_generator"
    / "models"
)
DATA_DIR = (
    Path(__file__).resolve().parent.parent
    / "src"
    / "asago_scenario_generator"
    / "data"
)

_FACADE_MODULE = "asago_scenario_generator.models.attack_pattern"
_FORBIDDEN_IO_NEAR_PREFIXES = (
    "asago_scenario_generator.llm",
    "asago_scenario_generator.prompts",
    "asago_scenario_generator.manifest",
    "asago_scenario_generator.report",
    "asago_scenario_generator.cli",
    "asago_scenario_generator.stpa",
    "asago_scenario_generator.pipeline",
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


class TestAttackPatternLeaves:
    """Responsibility modules stay free of the public façade and IO."""

    @pytest.mark.parametrize(
        "module_name",
        (
            "attack_pattern_contracts.py",
            "attack_pattern_digests.py",
            "attack_pattern_chain.py",
            "attack_pattern_projection.py",
            "attack_pattern_validation.py",
        ),
    )
    def test_leaf_does_not_import_facade_or_io(self, module_name: str) -> None:
        """Each responsibility module stays inward and offline."""
        imports = _imported_modules(MODELS_DIR / module_name)
        assert _FACADE_MODULE not in imports, (
            f"{module_name} must not import the public attack-pattern façade"
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

    def test_digests_import_cleanly(self) -> None:
        """Digest helpers can be imported without the façade."""
        module = importlib.import_module(
            "asago_scenario_generator.models.attack_pattern_digests"
        )
        assert module._canonical_json is not None
        assert module.compute_chain_semantic_digest is not None


class TestCatalogLineageSnapshotLeaf:
    """Source-catalog pinning stays independent of the public lineage loader."""

    def test_snapshot_does_not_import_lineage_loader(self) -> None:
        """The snapshot module must not depend on the public lineage façade."""
        imports = _imported_modules(DATA_DIR / "catalog_lineage_snapshot.py")
        assert "asago_scenario_generator.data.catalog_lineage" not in imports
        assert "asago_scenario_generator.data.canonical" in imports

    def test_snapshot_does_not_import_io_near_modules(self) -> None:
        """Snapshot pinning stays free of pipeline, prompts, and UI."""
        imports = _imported_modules(DATA_DIR / "catalog_lineage_snapshot.py")
        violations = [
            imp
            for imp in imports
            if any(
                imp == forbidden or imp.startswith(forbidden + ".")
                for forbidden in _FORBIDDEN_IO_NEAR_PREFIXES
            )
        ]
        assert not violations, (
            "catalog_lineage_snapshot imports IO-near modules: "
            f"{sorted(violations)}"
        )
