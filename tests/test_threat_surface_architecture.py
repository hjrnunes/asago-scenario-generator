"""Architecture guard tests for the taxonomy threat-surface boundary.

These tests enforce structural invariants that are easy to regress:

1. **Contract home**: ``ThreatSurface``/``ThreatSurfaceEntry`` and
   ``ThreatScope``/``ThreatScopeEntry``/``OutOfScopeEntry`` live in the
   model layer.

2. **Model leaves**: The threat-surface and threat-scope contracts must
   not import from ``pipeline`` or ``data`` — they are the stable
   shapes that lower-level logic produces and higher-level policy
   consumes.

3. **Dependency direction**: ``data`` (taxonomy/gating layer) must not
   import from ``pipeline``, and the gating module must not import
   IO-near modules (``manifest``, ``llm``, ``report``, ``stpa``).

4. **No import cycles**: The threat-surface dependency chain imports
   cleanly.

"""

from __future__ import annotations

import ast
import importlib
from pathlib import Path

import pytest

SRC_ROOT = (
    Path(__file__).resolve().parent.parent
    / "src"
    / "asago_scenario_generator"
)
MODELS_DIR = SRC_ROOT / "models"
DATA_DIR = SRC_ROOT / "data"

# IO-near / framework modules that taxonomy derivation logic must never import.
_FORBIDDEN_IO_NEAR_PREFIXES = (
    "asago_scenario_generator.manifest",
    "asago_scenario_generator.llm",
    "asago_scenario_generator.prompts",
    "asago_scenario_generator.report",
    "asago_scenario_generator.cli",
    "asago_scenario_generator.stpa",
)



def _extract_imports(file_path: Path) -> list[str]:
    """Return fully-qualified module names imported in *file_path*."""
    source = file_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(file_path))
    imports: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.append(node.module)

    return imports


class TestThreatSurfaceContractHome:
    """The surface/scope shapes live in models, not in algorithm modules."""

    def test_models_define_the_contracts(self):
        """ThreatSurface and ThreatScope are defined in the model layer."""
        from asago_scenario_generator.models.threat_surface import (
            ThreatSurface,
            ThreatSurfaceEntry,
        )
        from asago_scenario_generator.models.threat_scope import (
            OutOfScopeEntry,
            ThreatScope,
            ThreatScopeEntry,
        )

        assert ThreatSurface.__module__ == (
            "asago_scenario_generator.models.threat_surface"
        )
        assert ThreatSurfaceEntry.__module__ == (
            "asago_scenario_generator.models.threat_surface"
        )
        assert ThreatScope.__module__ == "asago_scenario_generator.models.threat_scope"
        assert ThreatScopeEntry.__module__ == (
            "asago_scenario_generator.models.threat_scope"
        )
        assert OutOfScopeEntry.__module__ == (
            "asago_scenario_generator.models.threat_scope"
        )

    def test_algorithm_modules_do_not_define_the_contracts(self):
        """data.threat_gating no longer defines shapes."""
        gating_source = (DATA_DIR / "threat_gating.py").read_text(encoding="utf-8")
        assert "class ThreatScope(" not in gating_source
        assert "class ThreatScopeEntry(" not in gating_source
        assert "class OutOfScopeEntry(" not in gating_source


class TestContractModelsAreLeaves:
    """The threat-surface/scope contracts import only models + pydantic."""

    @pytest.mark.parametrize(
        "module_name",
        ["threat_surface", "threat_scope"],
    )
    def test_contract_imports_stay_in_models_layer(self, module_name):
        path = MODELS_DIR / f"{module_name}.py"
        imports = _extract_imports(path)
        allowed_prefixes = (
            "asago_scenario_generator.models",
            "pydantic",
            "typing",
            "__future__",
        )
        violations = [
            imp
            for imp in imports
            if not any(imp.startswith(p) or imp == p for p in allowed_prefixes)
        ]
        assert not violations, (
            f"models/{module_name}.py imports non-model modules: {violations}"
        )


class TestThreatSurfaceDependencyDirection:
    """Derivation modules follow the models ← data ← pipeline layering."""

    def test_data_does_not_import_pipeline(self):
        """The taxonomy/gating layer must never import pipeline modules."""
        violations: list[str] = []
        for path in sorted(DATA_DIR.glob("*.py")):
            if path.name == "__init__.py":
                continue
            for imp in _extract_imports(path):
                if imp.startswith("asago_scenario_generator.pipeline"):
                    violations.append(f"{path.name}: imports '{imp}'")
        assert not violations, (
            "data/ imports pipeline modules (dependency-direction "
            "violation):\n" + "\n".join(violations)
        )

    def test_derivation_modules_do_not_import_io_near_modules(self):
        """data.threat_gating stays free of IO/framework."""
        for path in (DATA_DIR / "threat_gating.py",):
            for imp in _extract_imports(path):
                for forbidden in _FORBIDDEN_IO_NEAR_PREFIXES:
                    assert not (
                        imp == forbidden or imp.startswith(forbidden + ".")
                    ), f"{path.name}: imports forbidden IO-near module '{imp}'"

    def test_threat_surface_model_imports_no_algorithm(self):
        """models/threat_surface.py must not import data or pipeline."""
        imports = _extract_imports(MODELS_DIR / "threat_surface.py")
        assert not any(
            imp.startswith("asago_scenario_generator.data")
            or imp.startswith("asago_scenario_generator.pipeline")
            for imp in imports
        )


class TestThreatSurfaceNoImportCycles:
    """The threat-surface dependency chain imports without cycles."""

    @pytest.mark.parametrize(
        "module_name",
        [
            "asago_scenario_generator.models.threat_surface",
            "asago_scenario_generator.models.threat_scope",
            "asago_scenario_generator.data.threat_gating",
        ],
    )
    def test_module_imports_cleanly(self, module_name):
        mod = importlib.import_module(module_name)
        assert mod is not None
