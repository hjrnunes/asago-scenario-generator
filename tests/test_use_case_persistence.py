"""Test that run_pipeline persists the use-case description to output_dir."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def output_dir(tmp_path: Path) -> Path:
    return tmp_path / "pipeline-output"


@patch("asago_scenario_generator.report.generator.generate_report")
@patch("asago_scenario_generator.pipeline.runner.write_coverage_report")
@patch("asago_scenario_generator.pipeline.runner.analyze_attacker_diversity")
@patch("asago_scenario_generator.pipeline.runner.analyze_coverage_gaps")
@patch("asago_scenario_generator.pipeline.runner.expand_seeds", return_value=[])
@patch("asago_scenario_generator.pipeline.runner.determine_threat_surface")
@patch("asago_scenario_generator.pipeline.runner.validate_risk_card_coherence")
@patch("asago_scenario_generator.pipeline.runner.load_risk_extraction", return_value=[])
@patch("asago_scenario_generator.pipeline.runner.infer_capability_profile")
def test_use_case_written_to_output_dir(
    mock_profile,
    mock_load,
    mock_coherence,
    mock_threats,
    mock_seeds,
    mock_gaps,
    mock_diversity,
    mock_coverage_report,
    mock_report,
    output_dir: Path,
    tmp_path: Path,
    offline_llm: None,
) -> None:
    """run_pipeline should write use-case.txt with the exact use-case text."""
    from asago_scenario_generator.models.capability_profile import CapabilityProfile
    from asago_scenario_generator.models import ThreatSurface

    # Minimal stubs so the pipeline doesn't blow up.
    profile = CapabilityProfile(
        zones_active=["input", "reasoning"],
        entry_points=["ep-1"],
        confidence="high",
        kc_subcodes=["KC1.1"],
    )
    from asago_scenario_generator.llm.client import LLMResult

    llm_result = LLMResult(
        content="mock",
        prompt_tokens=10,
        completion_tokens=20,
        duration_ms=100,
        system_prompt="system",
        user_prompt="user",
    )
    mock_profile.return_value = (profile, llm_result)

    coherence = MagicMock()
    coherence.has_warnings = False
    mock_coherence.return_value = coherence

    threat_surface = ThreatSurface(entries=[], governance_only=[])
    mock_threats.return_value = threat_surface

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

    use_case_text = "An AI chatbot that helps customers with billing inquiries"

    # Create dummy input files the pipeline expects.
    risk_path = tmp_path / "risk.json"
    risk_path.write_text("[]")
    sssom_path = tmp_path / "sssom.tsv"
    sssom_path.write_text("")

    from asago_scenario_generator.pipeline.runner import run_pipeline

    result = run_pipeline(
        use_case=use_case_text,
        risk_extraction_path=risk_path,
        sssom_path=sssom_path,
        output_dir=output_dir,
    )

    use_case_file = result.run_dir / "use-case.txt"
    assert use_case_file.exists(), "use-case.txt should be created in run_dir"
    assert use_case_file.read_text() == use_case_text
