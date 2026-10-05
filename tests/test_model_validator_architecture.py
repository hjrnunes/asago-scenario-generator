"""Architecture guards for model validators and capability admission.

Realization derivation and complexity models consume attack-pattern leaves,
not the attack-pattern or finalization façades.
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

_ATTACK_PATTERN_FACADE = "asago_scenario_generator.models.attack_pattern"
_FINALIZATION_FACADE = "asago_scenario_generator.pipeline.finalization"
_FORBIDDEN_IO_NEAR_PREFIXES = (
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


class TestRealizationAndComplexityStayOffFacades:
    """Canonical realization and complexity models stay inward of façades."""

    _MODULES = (
        MODELS_DIR / "realization.py",
        MODELS_DIR / "complexity.py",
    )

    def test_leaves_do_not_import_io_or_facades(self) -> None:
        """These models stay off prompts, LLM, and public façades."""
        forbidden = (
            _ATTACK_PATTERN_FACADE,
            _FINALIZATION_FACADE,
            *_FORBIDDEN_IO_NEAR_PREFIXES,
        )
        for path in self._MODULES:
            imports = _imported_modules(path)
            found = _violations(imports, forbidden)
            assert not found, f"{path.name} imports forbidden modules: {found}"

    def test_realization_imports_attack_pattern_leaves(self) -> None:
        """Realization derivation consumes resource-reference leaves, not the façade."""
        imports = _imported_modules(MODELS_DIR / "realization.py")
        assert "asago_scenario_generator.models.attack_pattern_projection" in imports
