"""Acceptance and independent-artifact checks for Phase 4 Task 3."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


ROOT = next(
    path
    for path in Path(__file__).resolve().parents
    if (path / "pyproject.toml").is_file()
)
FEATURE = ROOT / "features" / "hybrid_scenario_projection.feature"
QA = ROOT / "acceptance" / "qa" / "taxonomy_risk" / "hybrid_scenario_projection.py"


def test_complete_projection_feature_is_registered_with_runtime() -> None:
    """The feature has a runtime module and remains in the manifest."""
    acceptance_root = ROOT / "acceptance"
    sys.path.insert(0, str(acceptance_root))
    import runtime_manifest

    modules = runtime_manifest.load_modules()

    assert "hybrid_scenario_projection" in runtime_manifest.MODULES
    assert any(module.FEATURE_ID == "hybrid_scenario_projection" for module in modules)


def test_complete_projection_feature_keeps_the_task3_contract_cases() -> None:
    """The compact feature names each externally visible Task 3 gate."""
    text = FEATURE.read_text(encoding="utf-8")

    for phrase in (
        "the committed projection artifact round-trips atomically",
        "the fixed bridge table only accepts exact endpoint kinds",
        "two ICA identities sharing one EXEC remain distinct projections",
        "relation-local omissions remain typed and traceable",
        "every exclusion reason is a closed typed contract value",
        "Phase 3 challenge history cannot promote a new projection",
        "ordinary workflow compatibility remains delegated to its existing gate",
        "mixed projection and exclusion identities are fully accounted",
        "the adversarial projection corpus fails closed",
        "malformed source graphs fail before composition",
        "source digest defects are fatal, not relation-local exclusions",
        "input order cannot change canonical output",
        "the committed fixture is bookkeeping evidence only",
    ):
        assert phrase in text


def test_independent_projection_artifact_qa_passes_without_app_imports() -> None:
    """The external reader validates the committed fixture independently."""
    environment = os.environ.copy()
    environment.pop("ASAGO_SCENARIO_GENERATOR_QA_PIPELINE", None)
    result = subprocess.run(
        [sys.executable, str(QA)],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    for check in (
        "all projection records independently verified",
        "exact no-overlap identity accounting",
        "valid mixed projection/exclusion accounting",
        "substituted candidate artifact rejected",
        "nonprojectable candidate remains excluded",
        "cross-candidate binding artifact rejected",
        "related-resource relation remains excluded",
        "full source-pin tamper rejected",
        "Phase 2 matrices remain byte-identical",
        "base fixture exclusion limitation is explicit",
    ):
        assert f"[PASS] {check}" in result.stdout
    assert "failed" in result.stdout
    assert "0 failed" in result.stdout


def test_independent_qa_has_no_single_record_assumptions() -> None:
    """The independent reader must walk every projection and bridge record."""
    source = QA.read_text(encoding="utf-8")

    for single_record_lookup in (
        '["projections"][0]',
        '["bridge_links"][0]',
        '["evidence"][0]',
    ):
        assert single_record_lookup not in source
