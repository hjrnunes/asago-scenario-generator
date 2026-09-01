"""Atomic persistence adapters for synthesis consideration and accounting."""

from __future__ import annotations

from pathlib import Path

from asago_scenario_generator.manifest import atomic_write_text
from asago_scenario_generator.models.obligation_accounting import ObligationAccounting
from asago_scenario_generator.models.obligation_consideration import (
    ObligationConsideration,
)
from asago_scenario_generator.models.scenario_realization import (
    ScenarioRealizationAssessment,
)


CONSIDERATION_FILENAME = "obligation-consideration.yaml"
ACCOUNTING_FILENAME = "obligation-accounting.yaml"
SCENARIO_REALIZATION_FILENAME = "scenario-realization.yaml"


def write_obligation_consideration(
    output_dir: Path,
    artifact: ObligationConsideration,
) -> Path:
    """Validate, atomically publish, reload, and compare consideration."""
    if not isinstance(artifact, ObligationConsideration):
        raise TypeError("artifact must be an ObligationConsideration")
    artifact.assert_integrity()
    target = Path(output_dir) / CONSIDERATION_FILENAME
    atomic_write_text(target, artifact.to_yaml())
    loaded = ObligationConsideration.from_yaml(target.read_bytes())
    if loaded != artifact:
        raise ValueError("persisted obligation consideration changed on round-trip")
    return target


def read_obligation_consideration(path: Path) -> ObligationConsideration:
    """Read and integrity-check one consideration artifact."""
    candidate = Path(path)
    if candidate.name != CONSIDERATION_FILENAME:
        raise ValueError(f"expected {CONSIDERATION_FILENAME}, got {candidate.name}")
    return ObligationConsideration.from_yaml(candidate.read_bytes())


def write_obligation_accounting(
    output_dir: Path,
    artifact: ObligationAccounting,
) -> Path:
    """Validate, atomically publish, reload, and compare accounting."""
    if not isinstance(artifact, ObligationAccounting):
        raise TypeError("artifact must be an ObligationAccounting")
    artifact.assert_integrity()
    target = Path(output_dir) / ACCOUNTING_FILENAME
    atomic_write_text(target, artifact.to_yaml())
    loaded = ObligationAccounting.from_yaml(target.read_bytes())
    if loaded != artifact:
        raise ValueError("persisted obligation accounting changed on round-trip")
    return target


def read_obligation_accounting(path: Path) -> ObligationAccounting:
    """Read and integrity-check one accounting artifact."""
    candidate = Path(path)
    if candidate.name != ACCOUNTING_FILENAME:
        raise ValueError(f"expected {ACCOUNTING_FILENAME}, got {candidate.name}")
    return ObligationAccounting.from_yaml(candidate.read_bytes())


def write_scenario_realization(
    output_dir: Path,
    artifact: ScenarioRealizationAssessment,
) -> Path:
    """Validate, atomically publish, reload, and compare realization evidence."""
    if not isinstance(artifact, ScenarioRealizationAssessment):
        raise TypeError("artifact must be a ScenarioRealizationAssessment")
    artifact.assert_integrity()
    target = Path(output_dir) / SCENARIO_REALIZATION_FILENAME
    atomic_write_text(target, artifact.to_yaml())
    loaded = ScenarioRealizationAssessment.from_yaml(target.read_bytes())
    if loaded != artifact:
        raise ValueError("persisted scenario realization changed on round-trip")
    return target


def read_scenario_realization(path: Path) -> ScenarioRealizationAssessment:
    """Read and integrity-check one scenario-realization artifact."""
    candidate = Path(path)
    if candidate.name != SCENARIO_REALIZATION_FILENAME:
        raise ValueError(
            f"expected {SCENARIO_REALIZATION_FILENAME}, got {candidate.name}"
        )
    return ScenarioRealizationAssessment.from_yaml(candidate.read_bytes())


persist_obligation_consideration = write_obligation_consideration
persist_obligation_accounting = write_obligation_accounting
persist_scenario_realization = write_scenario_realization


__all__ = [
    "ACCOUNTING_FILENAME",
    "CONSIDERATION_FILENAME",
    "SCENARIO_REALIZATION_FILENAME",
    "persist_obligation_accounting",
    "persist_obligation_consideration",
    "persist_scenario_realization",
    "read_obligation_accounting",
    "read_obligation_consideration",
    "read_scenario_realization",
    "write_obligation_accounting",
    "write_obligation_consideration",
    "write_scenario_realization",
]
