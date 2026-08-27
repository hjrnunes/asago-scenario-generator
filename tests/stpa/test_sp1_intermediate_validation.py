"""Regression tests for semantically empty Stage 2 intermediate outputs.

These tests replay the empty ``RequirementSet`` and ``ResponsibilitySet``
shapes observed in the Klarna run.  They exercise the SP1 orchestration and
the assembly boundary without contacting a model endpoint.
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest
import yaml
from pydantic import ValidationError

from asago_scenario_generator.stpa.infra.llm_helpers import StageError
from asago_scenario_generator.stpa.pipeline.runner import run_stpa_pipeline
from asago_scenario_generator.stpa.system_model.control_structure import (
    ControlElementSet,
    RequirementSet,
    ResponsibilitySet,
    _assemble_with_fallback,
)
from asago_scenario_generator.stpa.system_model.run import run_sp1
from tests.stpa.sp1_helpers import (
    make_risk_cards,
    read_calls_jsonl,
    setup_sp1_mock_client,
)


@pytest.mark.parametrize(
    ("model_class", "field_name"),
    [
        (RequirementSet, "requirements"),
        (ResponsibilitySet, "responsibilities"),
    ],
)
def test_stage2_intermediate_sets_reject_empty_values(model_class, field_name):
    """Empty intermediate sets are not semantically usable Stage 2 outputs."""
    with pytest.raises(ValidationError, match=field_name):
        model_class(**{field_name: []})


def test_empty_requirements_are_logged_and_preserve_sp1_artifacts(tmp_path):
    """An empty Call 1 result becomes a structured SP1 failure."""
    client = setup_sp1_mock_client()
    client.set_response_for(RequirementSet, {"requirements": []})

    result = run_sp1(
        llm_client=client,
        use_case_text="Test use case",
        risk_cards=make_risk_cards(),
        run_dir=tmp_path,
    )

    assert result.control_structure is None
    assert any("call_1_requirements" in error for error in result.stage_errors)
    assert (tmp_path / "loss-analysis.yaml").exists()
    assert (tmp_path / "capability-profile.yaml").exists()

    calls = read_calls_jsonl(tmp_path)
    failed = [entry for entry in calls if entry["step"] == "call_1_requirements"]
    assert len(failed) == 2
    assert all(entry["success"] is False for entry in failed)
    manifest = yaml.safe_load((tmp_path / "run-manifest.yaml").read_text())
    assert any("call_1_requirements" in error for error in manifest["stage_errors"])


def test_empty_responsibilities_are_logged_and_do_not_escape_validation_error(
    tmp_path,
):
    """An empty tolerant Call 2a result does not crash the SP1 run."""
    client = setup_sp1_mock_client()
    client.set_response_for(ResponsibilitySet, {"responsibilities": []})

    result = run_sp1(
        llm_client=client,
        use_case_text="Test use case",
        risk_cards=make_risk_cards(),
        run_dir=tmp_path,
    )

    assert result.control_structure is None
    assert any("call_2a_responsibilities" in error for error in result.stage_errors)

    calls = read_calls_jsonl(tmp_path)
    failed = [entry for entry in calls if entry["step"] == "call_2a_responsibilities"]
    assert len(failed) == 2
    assert all(entry["success"] is False for entry in failed)
    assert (tmp_path / "run-manifest.yaml").exists()


def test_pipeline_contains_empty_stage2_failure_and_preserves_manifest(tmp_path):
    """The public STPA runner returns diagnostics instead of a traceback."""
    use_case = tmp_path / "use-case.txt"
    use_case.write_text("Test use case", encoding="utf-8")
    risk_extraction = tmp_path / "risk-extraction.json"
    risk_extraction.write_text(
        json.dumps(
            {
                "risks": [
                    {
                        "risk_id": "atlas-001",
                        "risk_name": "Prompt injection",
                        "risk_description": "Risk of prompt injection",
                        "taxonomy": "ibm-risk-atlas",
                        "confidence": 0.9,
                        "grounding_confidence": "high",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    output_dir = tmp_path / "output"
    client = setup_sp1_mock_client()
    client.set_response_for(RequirementSet, {"requirements": []})

    with patch(
        "asago_scenario_generator.stpa.pipeline.runner.resolve_llm_client",
        return_value=(client, None),
    ):
        result = run_stpa_pipeline(
            use_case_path=str(use_case),
            risk_extraction_path=str(risk_extraction),
            output_dir=output_dir,
        )

    assert result.report_path is None
    assert any("call_1_requirements" in error for error in result.stage_errors)
    assert any("control-structure.yaml" in error for error in result.stage_errors)
    manifest = yaml.safe_load((output_dir / "run-manifest.yaml").read_text())
    assert manifest["stage_errors"] == result.stage_errors
    assert (output_dir / "calls.jsonl").exists()


def test_unrecoverable_assembly_fallback_is_contained_as_stage_error(tmp_path):
    """An exhausted fallback raises StageError instead of raw ValidationError."""
    empty_responsibilities = ResponsibilitySet.model_construct(responsibilities=[])

    with pytest.raises(StageError, match="assemble_control_structure"):
        _assemble_with_fallback(
            empty_responsibilities,
            ControlElementSet(),
            tmp_path,
            "test-model",
        )

    calls = read_calls_jsonl(tmp_path)
    failed = [entry for entry in calls if entry["step"] == "assemble_control_structure"]
    assert len(failed) == 1
    assert failed[0]["success"] is False
