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
            "narrative_access imports IO-near modules: "
            f"{sorted(violations)}"
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
            "narrative_semantics imports IO-near modules: "
            f"{sorted(violations)}"
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
            "narrative_semantics reaches orchestration siblings: "
            f"{sorted(siblings)}"
        )


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
            "projection_block imports IO-near modules: "
            f"{sorted(violations)}"
        )
