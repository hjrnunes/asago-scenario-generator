"""Atomic YAML persistence for the hybrid coverage assessment."""

from __future__ import annotations

from pathlib import Path

from asago_scenario_generator.manifest import atomic_write_text
from asago_scenario_generator.models.hybrid_coverage import HybridCoverageAssessment

HYBRID_COVERAGE_ASSESSMENT_FILENAME = "hybrid-coverage-assessment.yaml"


def write_hybrid_coverage_assessment(
    output_dir: Path,
    assessment: HybridCoverageAssessment,
) -> Path:
    """Validate, atomically publish, reload, and compare one assessment."""
    assessment.assert_integrity()
    target = Path(output_dir) / HYBRID_COVERAGE_ASSESSMENT_FILENAME
    atomic_write_text(target, assessment.to_yaml())
    loaded = HybridCoverageAssessment.from_yaml(target.read_bytes())
    if loaded != assessment:
        raise ValueError("persisted hybrid coverage assessment changed on round-trip")
    return target


__all__ = [
    "HYBRID_COVERAGE_ASSESSMENT_FILENAME",
    "write_hybrid_coverage_assessment",
]
