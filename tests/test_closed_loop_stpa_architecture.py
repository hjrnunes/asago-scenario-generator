"""Dependency tests for the Phase 3 closed-loop composition boundary."""

from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).parents[1]
MODEL = ROOT / "src/asago_scenario_generator/models/closed_loop_stpa.py"
COMPOSITION = ROOT / "src/asago_scenario_generator/pipeline/closed_loop_stpa.py"
PERSISTENCE = (
    ROOT / "src/asago_scenario_generator/pipeline/closed_loop_stpa_persistence.py"
)


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    return imported


def test_closed_loop_model_and_composition_keep_io_and_provider_infrastructure_outward() -> (
    None
):
    """The aggregate stays inward and composition constructs no concrete client."""
    model_imports = _imports(MODEL)
    composition_imports = _imports(COMPOSITION)

    assert all(".pipeline" not in name for name in model_imports)
    assert all("persistence" not in name for name in composition_imports)
    assert all("runner" not in name for name in composition_imports)
    assert all(
        "openai" not in name and ".llm" not in name for name in composition_imports
    )


def test_persistence_depends_on_the_closed_model_not_composition() -> None:
    """Atomic publication is an outward adapter, not orchestration behavior."""
    imports = _imports(PERSISTENCE)

    assert "asago_scenario_generator.models.closed_loop_stpa" in imports
    assert all("pipeline.closed_loop_stpa" not in name for name in imports)


def test_existing_generation_and_stpa_surfaces_do_not_import_phase3_composition() -> (
    None
):
    """Ordinary workflows neither read nor require the new run record."""
    roots = (
        ROOT / "src/asago_scenario_generator/pipeline/generate",
        ROOT / "src/asago_scenario_generator/stpa",
        ROOT / "src/asago_scenario_generator/cli",
    )
    for root in roots:
        for path in root.rglob("*.py"):
            assert all("closed_loop_stpa" not in name for name in _imports(path))


def test_composition_accepts_no_taxonomy_scenario_or_hybrid_generation_input() -> None:
    """Old taxonomy envelopes cannot enter through an unnamed fallback seam."""
    tree = ast.parse(COMPOSITION.read_text(encoding="utf-8"))
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "run_closed_loop_stpa"
    )
    argument_names = {
        argument.arg for argument in (*function.args.args, *function.args.kwonlyargs)
    }

    assert "taxonomy_scenarios" not in argument_names
    assert "scenario_observations" not in argument_names
    assert "hybrid_generator" not in argument_names
