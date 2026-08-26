"""Architecture guards for the inward narrative-access leaf."""

from __future__ import annotations

import ast
from pathlib import Path

PIPELINE_DIR = (
    Path(__file__).resolve().parent.parent
    / "src"
    / "asago_scenario_generator"
    / "pipeline"
)
GENERATE_DIR = PIPELINE_DIR / "generate"
TESTS_DIR = Path(__file__).resolve().parent
ACCEPTANCE_DIR = TESTS_DIR.parent / "acceptance"

_NARRATIVE_FACADE = "asago_scenario_generator.pipeline.generate.narrative"
_NARRATIVE_ACCESS = "asago_scenario_generator.pipeline.generate.narrative_access"
_NARRATIVE_SEMANTICS = "asago_scenario_generator.pipeline.generate.narrative_semantics"
_LEAF_HELPERS_ON_NARRATIVE = frozenset(
    {
        "MAX_NARRATIVE_STEPS",
        "NARRATIVE_CONNECTOR_STEPS",
        "validate_narrative_access_realization",
        "compile_narrative_draft",
        "create_narrative_draft_model",
        "create_narrative_draft_v3_model",
        "NarrativeDraftContext",
        "NarrativeDraftV2",
        "NarrativeDraftV3",
        "NarrativeProjectedStep",
        "NarrativeSemanticDraftError",
        "_derive_zone_sequence",
    }
)

_FORBIDDEN_IO_NEAR_PREFIXES = (
    "asago_scenario_generator.llm",
    "asago_scenario_generator.prompts",
    "asago_scenario_generator.manifest",
    "asago_scenario_generator.report",
    "asago_scenario_generator.cli",
    "asago_scenario_generator.stpa",
    "asago_scenario_generator.pipeline.generate.narrative",
    "asago_scenario_generator.pipeline.generate.assembly",
    "asago_scenario_generator.pipeline.generate.actor",
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


def _imported_names(path: Path, module: str) -> set[str]:
    """Return names imported from *module* in a source file."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == module:
            names.update(alias.name for alias in node.names)
    return names


class TestNarrativeAccessLeaf:
    """The leaf stays free of IO-near generate façades."""

    def test_leaf_does_not_import_io_near_modules(self) -> None:
        """Narrative access policy stays inward and offline."""
        imports = _imported_modules(GENERATE_DIR / "narrative_access.py")
        violations = [
            imp
            for imp in imports
            if any(
                imp == forbidden or imp.startswith(forbidden + ".")
                for forbidden in _FORBIDDEN_IO_NEAR_PREFIXES
            )
        ]
        assert not violations, (
            f"narrative_access imports IO-near modules: {sorted(violations)}"
        )


class TestNarrativeSemanticsLeaf:
    """Semantic draft compilation stays off the narrative façade."""

    _ALLOWED_GENERATE_SIBLINGS = {
        "asago_scenario_generator.pipeline.generate.canonical_projection",
        "asago_scenario_generator.pipeline.generate.narrative_access",
    }

    def test_leaf_does_not_import_io_near_modules(self) -> None:
        """Narrative draft contracts stay inward and offline."""
        imports = _imported_modules(GENERATE_DIR / "narrative_semantics.py")
        violations = [
            imp
            for imp in imports
            if any(
                imp == forbidden or imp.startswith(forbidden + ".")
                for forbidden in _FORBIDDEN_IO_NEAR_PREFIXES
            )
        ]
        assert not violations, (
            f"narrative_semantics imports IO-near modules: {sorted(violations)}"
        )

    def test_leaf_reaches_only_inward_generate_siblings(self) -> None:
        """The compiler may couple to access bounds and projection semantics."""
        imports = _imported_modules(GENERATE_DIR / "narrative_semantics.py")
        siblings = {
            imp
            for imp in imports
            if imp.startswith("asago_scenario_generator.pipeline.generate.")
        }
        assert siblings <= self._ALLOWED_GENERATE_SIBLINGS, (
            f"narrative_semantics reaches orchestration siblings: {sorted(siblings)}"
        )


class TestNarrativeConsumersDependInward:
    """Tests and acceptance consume access and draft leaves, not the façade."""

    _CONSUMERS = (
        GENERATE_DIR / "__init__.py",
        TESTS_DIR / "test_cmps6_narrative_realization.py",
        TESTS_DIR / "test_cmps6_third_correction.py",
        TESTS_DIR / "test_source_influence_relation.py",
        TESTS_DIR / "test_semantic_stage_evidence.py",
        TESTS_DIR / "test_semantic_actor_narrative.py",
        TESTS_DIR / "test_narrative_outside_boundaries.py",
        ACCEPTANCE_DIR / "runtime_features" / "taxonomy_risk.py",
    )

    def test_consumers_import_leaf_helpers_from_leaves(self) -> None:
        """Leaf helpers stay off the IO-near narrative façade."""
        for path in self._CONSUMERS:
            leaked = (
                _imported_names(path, _NARRATIVE_FACADE) & _LEAF_HELPERS_ON_NARRATIVE
            )
            assert not leaked, (
                f"{path.name} imports leaf helpers from narrative.py: "
                f"{sorted(leaked)}"
            )

    def test_package_reexport_imports_zone_sequence_from_semantics(self) -> None:
        """Historical package re-export reaches the semantics leaf."""
        names = _imported_names(GENERATE_DIR / "__init__.py", _NARRATIVE_SEMANTICS)
        assert "_derive_zone_sequence" in names
        facade_names = _imported_names(GENERATE_DIR / "__init__.py", _NARRATIVE_FACADE)
        assert "_derive_zone_sequence" not in facade_names

    def test_prebehavior_imports_access_leaf_not_narrative_facade(self) -> None:
        """Pre-behavior gates reach step bounds through the access leaf."""
        imports = _imported_modules(PIPELINE_DIR / "finalization_prebehavior.py")
        assert _NARRATIVE_ACCESS in imports
        assert _NARRATIVE_FACADE not in imports


class TestProjectionBlockLeaf:
    """Projection-envelope construction stays off the assembly façade."""

    def test_leaf_does_not_import_generate_assembly(self) -> None:
        """Sidecar derivation does not pull envelope I/O."""
        imports = _imported_modules(PIPELINE_DIR / "projection_block.py")
        assert "asago_scenario_generator.pipeline.generate.assembly" not in imports
        assert "asago_scenario_generator.pipeline.generate.narrative" not in imports
        violations = [
            imp
            for imp in imports
            if any(
                imp == forbidden or imp.startswith(forbidden + ".")
                for forbidden in _FORBIDDEN_IO_NEAR_PREFIXES
            )
        ]
        assert not violations, (
            f"projection_block imports IO-near modules: {sorted(violations)}"
        )
