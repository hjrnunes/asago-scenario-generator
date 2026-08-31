"""Dependency-direction guards for the Phase 4 Task 1 seam."""

from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODEL_FILES = (
    ROOT / "src/asago_scenario_generator/models/hybrid_scenario_projection.py",
    ROOT / "src/asago_scenario_generator/models/hybrid_projection_inputs.py",
    ROOT / "src/asago_scenario_generator/models/candidate_materialization.py",
)
PIPELINE = ROOT / "src/asago_scenario_generator/pipeline/hybrid_scenario_projection.py"


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
    return modules


def test_inward_models_do_not_import_pipeline_or_runtime_dependencies() -> None:
    forbidden = (
        "asago_scenario_generator.pipeline",
        "asago_scenario_generator.cli",
        "asago_scenario_generator.report",
        "asago_scenario_generator.llm",
        "asago_scenario_generator.prompts",
        "asago_scenario_generator.stpa.pipeline",
        "requests",
        "httpx",
        "openai",
        "socket",
    )
    violations = {
        f"{path.name}: {module}"
        for path in MODEL_FILES
        for module in _imports(path)
        if any(module == root or module.startswith(root + ".") for root in forbidden)
    }
    assert not violations


def test_outer_adapter_is_the_only_phase4_pipeline_module() -> None:
    imports = _imports(PIPELINE)
    assert "asago_scenario_generator.models.hybrid_scenario_projection" in imports
    assert "asago_scenario_generator.pipeline.hybrid_scenario_projection" not in imports
