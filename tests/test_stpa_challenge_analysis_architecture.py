"""Dependency and workflow-preservation checks for Phase 3 Task 2."""

from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).parents[1]
MODEL = ROOT / "src/asago_scenario_generator/models/challenge_analysis.py"
ANALYSIS = ROOT / "src/asago_scenario_generator/pipeline/challenge_analysis.py"
LEDGER = ROOT / "src/asago_scenario_generator/pipeline/challenge_ledger.py"
LEDGER_PERSISTENCE = (
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


def test_analysis_contract_and_preflight_are_io_free() -> None:
    """Task 2 returns values; Task 3 will decide filesystem placement."""
    forbidden = {"openai", "socket", "httpx", "requests", "pathlib"}

    assert not (_imports(MODEL) & forbidden)
    assert not (_imports(ANALYSIS) & forbidden)


def test_offline_ledger_does_not_depend_on_provider_capable_analysis() -> None:
    """Selection and persistence remain usable without the adapter boundary."""
    for path in (LEDGER, LEDGER_PERSISTENCE):
        assert all("challenge_analysis" not in name for name in _imports(path))


def test_stpa_runner_does_not_import_phase3_analysis() -> None:
    """The standalone STPA runner retains its existing dependency graph."""
    imports = _imports(STPA_RUNNER)
    assert all("challenge_analysis" not in name for name in imports)
    assert all("challenge_ledger" not in name for name in imports)


def test_analysis_never_imports_stpa_runner_or_provider_infrastructure() -> None:
    """A caller-supplied factory is the sole provider construction boundary."""
    imports = _imports(ANALYSIS)

    assert all("stpa.pipeline" not in name for name in imports)
    assert all("stpa.infra" not in name for name in imports)
