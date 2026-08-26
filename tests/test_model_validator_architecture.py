"""Architecture guards for model validators and capability admission.

Realization derivation and the projection envelope consume attack-pattern
leaves plus ``pipeline.projection_contracts``. Admission assessment
depends inward on those models, not the projection façade.
"""

from __future__ import annotations

import ast
from pathlib import Path

MODELS_DIR = (
    Path(__file__).resolve().parent.parent
    / "src"
    / "asago_scenario_generator"
    / "models"
)
PIPELINE_DIR = (
    Path(__file__).resolve().parent.parent
    / "src"
    / "asago_scenario_generator"
    / "pipeline"
)

_ATTACK_PATTERN_FACADE = "asago_scenario_generator.models.attack_pattern"
_PROJECTION_FACADE = "asago_scenario_generator.pipeline.projection"
_FINALIZATION_FACADE = "asago_scenario_generator.pipeline.finalization"
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


def _violations(imports: set[str], forbidden: tuple[str, ...]) -> list[str]:
    return sorted(
        imp
        for imp in imports
        if any(imp == item or imp.startswith(item + ".") for item in forbidden)
    )


class TestRealizationAndEnvelopeStayOffFacades:
    """Canonical realization and envelope models stay inward of façades."""

    _MODULES = (
        MODELS_DIR / "realization.py",
        MODELS_DIR / "projection_envelope.py",
        MODELS_DIR / "complexity.py",
    )

    def test_leaves_do_not_import_io_or_facades(self) -> None:
        """These models stay off prompts, LLM, and public façades."""
        forbidden = (
            _ATTACK_PATTERN_FACADE,
            _PROJECTION_FACADE,
            _FINALIZATION_FACADE,
            *_FORBIDDEN_IO_NEAR_PREFIXES,
        )
        for path in self._MODULES:
            imports = _imported_modules(path)
            found = _violations(imports, forbidden)
            assert not found, f"{path.name} imports forbidden modules: {found}"

    def test_envelope_imports_projection_contracts(self) -> None:
        """The envelope block reaches identity types through the contract leaf."""
        imports = _imported_modules(MODELS_DIR / "projection_envelope.py")
        assert "asago_scenario_generator.pipeline.projection_contracts" in imports
        assert "asago_scenario_generator.models.attack_pattern_projection" in imports
        assert "asago_scenario_generator.models.attack_pattern_contracts" in imports

    def test_realization_imports_attack_pattern_leaves(self) -> None:
        """Realization derivation consumes resource-reference leaves, not the façade."""
        imports = _imported_modules(MODELS_DIR / "realization.py")
        assert "asago_scenario_generator.models.attack_pattern_projection" in imports


class TestAdmissionDependsInward:
    """Reviewed complexity assessment consumes contracts, not façades."""

    def test_pipeline_complexity_imports_projection_contracts(self) -> None:
        """Admission reaches candidate types through the inward contract leaf."""
        imports = _imported_modules(PIPELINE_DIR / "complexity.py")
        assert "asago_scenario_generator.pipeline.projection_contracts" in imports
        assert "asago_scenario_generator.models.complexity" in imports
        forbidden = (
            _PROJECTION_FACADE,
            _FINALIZATION_FACADE,
            *_FORBIDDEN_IO_NEAR_PREFIXES,
        )
        found = _violations(imports, forbidden)
        assert not found, f"pipeline.complexity imports forbidden modules: {found}"
