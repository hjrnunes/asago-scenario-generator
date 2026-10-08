"""Architecture guard tests for the STPA pipeline package.

The package holds the model-client configuration shared by the STPA stages.
The guards enforce three structural invariants:

1. **Dependency direction**: ``pipeline/`` may import from lower-level
   modules (``system_model``, ``threat_enum``, ``scenario_prod``, ``infra``,
   ``models``, and ``data``). Lower-level modules must never import from
   ``pipeline/``.
2. **No CLI coupling**: ``pipeline/`` must not import from
   ``asago_scenario_generator.cli``; the CLI is a delivery layer above it.
3. **No import cycles**: the package imports without circular dependency
   errors.
"""

from __future__ import annotations

import ast
import importlib
from pathlib import Path

import pytest

PIPELINE_DIR = (
    Path(__file__).resolve().parent.parent.parent
    / "src"
    / "asago_scenario_generator"
    / "stpa"
    / "pipeline"
)
LLM_CONFIG_PATH = PIPELINE_DIR / "llm_config.py"
STPA_ROOT = PIPELINE_DIR.parent

_ALLOWED_PREFIXES = (
    "asago_scenario_generator.stpa.system_model",
    "asago_scenario_generator.stpa.threat_enum",
    "asago_scenario_generator.stpa.scenario_prod",
    "asago_scenario_generator.stpa.infra",
    "asago_scenario_generator.stpa.pipeline",
    "asago_scenario_generator.stpa.models",
    "asago_scenario_generator.models",
    "asago_scenario_generator.model_profiles",
    "asago_scenario_generator.data",
)


def _extract_imports(file_path: Path) -> list[str]:
    """Return fully-qualified module names imported in *file_path*."""
    source = file_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(file_path))
    imports: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.append(node.module)
    return imports


def test_llm_config_imports_allowed_modules_only() -> None:
    """llm_config.py imports only from allowed lower-level modules."""
    violations = [
        imp
        for imp in _extract_imports(LLM_CONFIG_PATH)
        if imp.startswith("asago_scenario_generator.")
        and not imp.startswith(_ALLOWED_PREFIXES)
    ]
    assert not violations, f"llm_config.py imports from forbidden modules: {violations}"


def test_pipeline_does_not_import_cli() -> None:
    """pipeline/ must never import from asago_scenario_generator.cli."""
    for py_file in sorted(PIPELINE_DIR.glob("*.py")):
        violations = [
            imp
            for imp in _extract_imports(py_file)
            if imp.startswith("asago_scenario_generator.cli")
        ]
        assert not violations, f"{py_file.name} imports from cli: {violations}"


@pytest.mark.parametrize(
    "subdir", ["system_model", "threat_enum", "scenario_prod", "infra"]
)
def test_lower_level_modules_do_not_import_pipeline(subdir: str) -> None:
    """Lower-level STPA packages must not import from pipeline/."""
    for py_file in sorted((STPA_ROOT / subdir).rglob("*.py")):
        violations = [
            imp
            for imp in _extract_imports(py_file)
            if "asago_scenario_generator.stpa.pipeline" in imp
        ]
        assert not violations, (
            f"{subdir}/{py_file.name} imports from pipeline (forbidden): {violations}"
        )


def test_llm_config_imports_without_cycles() -> None:
    """Importing the package and llm_config.py succeeds."""
    importlib.import_module("asago_scenario_generator.stpa.pipeline")
    module = importlib.import_module(
        "asago_scenario_generator.stpa.pipeline.llm_config"
    )
    assert hasattr(module, "resolve_llm_client")
