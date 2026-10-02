"""Dependency-direction tests for the observational hybrid assessment."""

from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PIPELINE = ROOT / "src/asago_scenario_generator/pipeline/hybrid_coverage.py"
MODEL = ROOT / "src/asago_scenario_generator/models/hybrid_coverage.py"


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
    return modules


def test_assessor_depends_only_on_upstream_models_and_contract_leaves() -> None:
    """The pure assessor does not import either generation implementation."""
    imports = _imports(PIPELINE)
    forbidden = (
        "asago_scenario_generator.pipeline.generate",
        "asago_scenario_generator.stpa.pipeline",
        "asago_scenario_generator.llm",
        "asago_scenario_generator.cli",
    )
    assert not any(
        imported == prefix or imported.startswith(prefix + ".")
        for imported in imports
        for prefix in forbidden
    )


def test_domain_model_does_not_import_assessment_engine() -> None:
    """The domain model remains upstream of the pure seam."""
    assert "asago_scenario_generator.pipeline.hybrid_coverage" not in _imports(MODEL)


def test_hybrid_modules_have_no_network_or_model_client_imports() -> None:
    """Deterministic assessment cannot construct a provider or contact a socket."""
    forbidden_roots = {"httpx", "requests", "socket", "urllib", "openai"}
    for path in (PIPELINE, MODEL):
        roots = {item.split(".", maxsplit=1)[0] for item in _imports(path)}
        assert roots.isdisjoint(forbidden_roots)
