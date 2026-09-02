"""Dependency and workflow-preservation checks for Phase 3 Task 1."""

from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).parents[1]
MODEL = ROOT / "src/asago_scenario_generator/models/challenge_ledger.py"
PIPELINE = ROOT / "src/asago_scenario_generator/pipeline/challenge_ledger.py"
PERSISTENCE = (
    ROOT / "src/asago_scenario_generator/pipeline/challenge_ledger_persistence.py"
)
STPA_RUNNER = ROOT / "src/asago_scenario_generator/stpa/pipeline/runner.py"


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {
        node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
    } | {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }


def test_challenge_domain_and_planning_are_offline_and_io_free() -> None:
    """Only the persistence adapter may perform filesystem publication."""
    model_imports = _imports(MODEL)
    pipeline_imports = _imports(PIPELINE)
    forbidden = {"openai", "socket", "httpx", "requests"}

    assert not (model_imports & forbidden)
    assert not (pipeline_imports & forbidden)
    assert "pathlib" not in model_imports
    assert "pathlib" not in pipeline_imports
    assert "asago_scenario_generator.manifest" not in pipeline_imports
    assert "asago_scenario_generator.manifest" in _imports(PERSISTENCE)


def test_stpa_runner_does_not_depend_on_phase3() -> None:
    """Task 1 cannot become a hidden requirement of the standalone runner."""
    imports = _imports(STPA_RUNNER)
    assert all("challenge_ledger" not in name for name in imports)


def test_model_does_not_import_implementation_or_stpa_runner_modules() -> None:
    """The ledger is a closed artifact model, not orchestration."""
    imports = _imports(MODEL)
    assert all(".pipeline.challenge_ledger" not in name for name in imports)
    assert all("stpa.pipeline" not in name for name in imports)
