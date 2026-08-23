"""Tests for the --profile flag that supplies a pre-built capability profile."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def output_dir(tmp_path: Path) -> Path:
    return tmp_path / "pipeline-output"


@pytest.fixture
def valid_profile_data() -> dict:
    """Minimal valid CapabilityProfile payload."""
    return {
        "zones_active": ["input", "reasoning", "tool_execution"],
        "entry_points": ["chat input [input]", "file upload [input]"],
        "confidence": "high",
        "kc_subcodes": ["KC1.1", "KC6.1.1"],
        "tool_inventory": [{"name": "test_tool", "description": "A test tool"}],
    }


@pytest.fixture
def valid_profile_path(tmp_path: Path, valid_profile_data: dict) -> Path:
    p = tmp_path / "capability-profile.yaml"
    p.write_text(yaml.dump(valid_profile_data), encoding="utf-8")
    return p


@pytest.fixture
def dummy_inputs(tmp_path: Path) -> tuple[Path, Path]:
    """Create dummy risk-extraction and SSSOM files."""
    risk_path = tmp_path / "risk.json"
    risk_path.write_text("[]")
    sssom_path = tmp_path / "sssom.tsv"
    sssom_path.write_text("")
    return risk_path, sssom_path


# ---------------------------------------------------------------------------
# Test: valid profile skips inference
# ---------------------------------------------------------------------------


@patch("asago_scenario_generator.report.generator.generate_report")
@patch("asago_scenario_generator.pipeline.runner.write_coverage_report")
@patch("asago_scenario_generator.pipeline.runner.analyze_attacker_diversity")
@patch("asago_scenario_generator.pipeline.runner.analyze_coverage_gaps")
@patch("asago_scenario_generator.pipeline.runner.expand_seeds", return_value=[])
@patch("asago_scenario_generator.pipeline.runner.determine_threat_surface")
@patch("asago_scenario_generator.pipeline.runner.validate_risk_card_coherence")
@patch("asago_scenario_generator.pipeline.runner.load_risk_extraction", return_value=[])
@patch("asago_scenario_generator.pipeline.runner.infer_capability_profile")
def test_profile_flag_skips_inference(
    mock_infer,
    mock_load,
    mock_coherence,
    mock_threats,
    mock_seeds,
    mock_gaps,
    mock_diversity,
    mock_coverage_report,
    mock_report,
    valid_profile_path: Path,
    valid_profile_data: dict,
    output_dir: Path,
    dummy_inputs: tuple[Path, Path],
    offline_llm: None,
) -> None:
    """Supplying a valid profile YAML should skip LLM inference entirely."""
    from asago_scenario_generator.pipeline.runner import run_pipeline
    from asago_scenario_generator.models import ThreatSurface

    coherence = MagicMock()
    coherence.has_warnings = False
    mock_coherence.return_value = coherence

    mock_threats.return_value = ThreatSurface(entries=[], governance_only=[])

    gaps = MagicMock()
    gaps.uncovered_entry_points = []
    mock_gaps.return_value = gaps
    mock_diversity.return_value = None

    # Side effects that actually write files so strict inventory passes.
    def _write_coverage(cov_gaps, out_dir, attacker_div=None, **kwargs):
        (Path(out_dir) / "coverage-gaps.json").write_text('{"coverage_gaps":{}}')

    def _write_report(data, out_dir):
        p = Path(out_dir) / "report.html"
        p.write_text("<html>mock</html>")
        return p

    mock_coverage_report.side_effect = _write_coverage
    mock_report.side_effect = _write_report

    risk_path, sssom_path = dummy_inputs

    result = run_pipeline(
        use_case="A billing chatbot",
        risk_extraction_path=risk_path,
        sssom_path=sssom_path,
        output_dir=output_dir,
        profile_path=valid_profile_path,
    )

    # infer_capability_profile must NOT have been called
    mock_infer.assert_not_called()

    # Profile values must match the supplied YAML
    assert result.capability_profile.zones_active == valid_profile_data["zones_active"]
    assert [
        ep.name for ep in result.capability_profile.entry_points
    ] == valid_profile_data["entry_points"]
    assert (
        result.capability_profile.confidence.value == valid_profile_data["confidence"]
    )


# ---------------------------------------------------------------------------
# Test: invalid profile YAML raises a validation error
# ---------------------------------------------------------------------------


def test_invalid_profile_raises_validation_error(tmp_path: Path) -> None:
    """A profile YAML missing required fields should fail with a Pydantic error."""
    from pydantic import ValidationError

    from asago_scenario_generator.models.capability_profile import CapabilityProfile

    bad_data = {"zones_active": ["input", "reasoning"]}  # missing required fields
    bad_path = tmp_path / "bad-profile.yaml"
    bad_path.write_text(yaml.dump(bad_data), encoding="utf-8")

    loaded = yaml.safe_load(bad_path.read_text(encoding="utf-8"))
    with pytest.raises(ValidationError):
        CapabilityProfile(**loaded)


# ---------------------------------------------------------------------------
# Test: profile is written to output dir even when supplied externally
# ---------------------------------------------------------------------------


@patch("asago_scenario_generator.report.generator.generate_report")
@patch("asago_scenario_generator.pipeline.runner.write_coverage_report")
@patch("asago_scenario_generator.pipeline.runner.analyze_attacker_diversity")
@patch("asago_scenario_generator.pipeline.runner.analyze_coverage_gaps")
@patch("asago_scenario_generator.pipeline.runner.expand_seeds", return_value=[])
@patch("asago_scenario_generator.pipeline.runner.determine_threat_surface")
@patch("asago_scenario_generator.pipeline.runner.validate_risk_card_coherence")
@patch("asago_scenario_generator.pipeline.runner.load_risk_extraction", return_value=[])
@patch("asago_scenario_generator.pipeline.runner.infer_capability_profile")
def test_profile_written_to_output_dir(
    mock_infer,
    mock_load,
    mock_coherence,
    mock_threats,
    mock_seeds,
    mock_gaps,
    mock_diversity,
    mock_coverage_report,
    mock_report,
    valid_profile_path: Path,
    valid_profile_data: dict,
    output_dir: Path,
    dummy_inputs: tuple[Path, Path],
    offline_llm: None,
) -> None:
    """The profile must be written to output_dir even when supplied via --profile."""
    from asago_scenario_generator.pipeline.runner import run_pipeline
    from asago_scenario_generator.models import ThreatSurface

    coherence = MagicMock()
    coherence.has_warnings = False
    mock_coherence.return_value = coherence

    mock_threats.return_value = ThreatSurface(entries=[], governance_only=[])

    gaps = MagicMock()
    gaps.uncovered_entry_points = []
    mock_gaps.return_value = gaps
    mock_diversity.return_value = None

    # Side effects that actually write files so strict inventory passes.
    def _write_coverage(cov_gaps, out_dir, attacker_div=None, **kwargs):
        (Path(out_dir) / "coverage-gaps.json").write_text('{"coverage_gaps":{}}')

    def _write_report(data, out_dir):
        p = Path(out_dir) / "report.html"
        p.write_text("<html>mock</html>")
        return p

    mock_coverage_report.side_effect = _write_coverage
    mock_report.side_effect = _write_report

    risk_path, sssom_path = dummy_inputs

    result = run_pipeline(
        use_case="A billing chatbot",
        risk_extraction_path=risk_path,
        sssom_path=sssom_path,
        output_dir=output_dir,
        profile_path=valid_profile_path,
    )

    output_profile = result.run_dir / "capability-profile.yaml"
    assert output_profile.exists(), (
        "capability-profile.yaml should be written to run_dir"
    )

    written = yaml.safe_load(output_profile.read_text(encoding="utf-8"))
    assert written["zones_active"] == valid_profile_data["zones_active"]
    # Serialized entry_points are now dicts with name and direction keys
    written_ep_names = [ep["name"] for ep in written["entry_points"]]
    assert written_ep_names == valid_profile_data["entry_points"]
