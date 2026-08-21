"""CLI tests for ``validate-stpa-projection``."""

from __future__ import annotations

import json

import yaml
from typer.testing import CliRunner

from asago_scenario_generator.cli import app
from asago_scenario_generator.stpa.models.causal_factor import CausalFactorKind
from asago_scenario_generator.stpa.models.execution_envelope import CausalFactor
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.scenario_prod.assembly import (
    assemble_candidate_envelope,
)
from asago_scenario_generator.stpa.scenario_prod.projection import (
    SCHEMA_VERSION,
    export_projection_json,
)
from tests.stpa.helpers import make_minimal_control_structure

runner = CliRunner()


def _projection_payload() -> dict:
    envelope = assemble_candidate_envelope(
        make_minimal_control_structure(),
        controller_id="RESP-1",
        control_action_id="CA-1-1",
        uca_type=UCAType.wrong_timing,
        causal_factors=[
            CausalFactor(
                kind=CausalFactorKind.process_model_flaw,
                source_id="PM-1-1",
                description="model diverges",
            )
        ],
        derive_temporal_vector=True,
        ica_id="RESP-1:CA-1-1:WRONG_TIMING:1",
        scenario_id="SCN-001",
    )
    return json.loads(export_projection_json(envelope))


def test_validate_stpa_projection_accepts_valid_export(tmp_path):
    """A canonical export is valid through the public CLI."""
    path = tmp_path / "SCN-001.projection.json"
    path.write_text(json.dumps(_projection_payload()), encoding="utf-8")
    result = runner.invoke(app, ["validate-stpa-projection", str(path)])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["valid"] is True
    assert payload["violations"] == []


def test_validate_stpa_projection_rejects_missing_causal_factors(tmp_path):
    """Absent causal_factors fails closed with a typed missing-key code."""
    payload = _projection_payload()
    payload.pop("causal_factors")
    path = tmp_path / "missing.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    result = runner.invoke(app, ["validate-stpa-projection", str(path)])
    assert result.exit_code == 1
    body = json.loads(result.stdout)
    assert body["valid"] is False
    assert any(
        violation["code"] == "causal_factors_missing"
        and violation["element_id"] == "causal_factors"
        for violation in body["violations"]
    )


def test_validate_stpa_projection_accepts_present_empty_lists(tmp_path):
    """Present-empty vectors remain a valid empty projection."""
    payload = _projection_payload()
    payload["causal_factors"] = []
    payload["assertions"] = []
    payload["steps"] = []
    payload["uca_constraint"] = None
    path = tmp_path / "empty.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    result = runner.invoke(app, ["validate-stpa-projection", str(path)])
    assert result.exit_code == 0, result.output
    body = json.loads(result.stdout)
    assert body["valid"] is True


def test_validate_stpa_projection_rejects_missing_file(tmp_path):
    """A missing artifact is reported through the CLI, not treated as empty."""
    missing = tmp_path / "absent.projection.json"
    result = runner.invoke(app, ["validate-stpa-projection", str(missing)])
    assert result.exit_code == 1
    assert "not found" in result.output


def test_validate_stpa_projection_reads_yaml(tmp_path):
    """YAML exports use the same public validation command."""
    payload = _projection_payload()
    path = tmp_path / "SCN-001.projection.yaml"
    path.write_text(yaml.safe_dump(payload), encoding="utf-8")
    result = runner.invoke(app, ["validate-stpa-projection", str(path)])
    assert result.exit_code == 0, result.output
    body = json.loads(result.stdout)
    assert body["valid"] is True
    assert payload["schema_version"] == SCHEMA_VERSION


def test_validate_stpa_projection_rejects_non_object_payload(tmp_path):
    """A JSON array is malformed, not a valid empty projection."""
    path = tmp_path / "list.json"
    path.write_text("[]", encoding="utf-8")
    result = runner.invoke(app, ["validate-stpa-projection", str(path)])
    assert result.exit_code == 1
    assert "must be a JSON or YAML object" in result.output
