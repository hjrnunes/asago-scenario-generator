"""The owner-accepted Stage 1a measurement input.

``data/gold/miniklarna/loss-analysis-pinned.yaml`` is the v6 graph after the
documented alternatives-merge correction (spec, "Pinned graph correction",
2026-09-08).  Measurement runs consume it through ``--loss-analysis``, so its
identity, validity, and gate status are part of the measurement contract.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import yaml

from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.system_model.loss_analysis_gates import (
    check_hazard_graph_density,
    load_behavior_classes,
)

PINNED_PATH = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "gold"
    / "miniklarna"
    / "loss-analysis-pinned.yaml"
)

# The corrected graph digest recorded in the spec.  The file is serialized
# with the project's ``write_yaml``, so its byte sha256 equals that digest.
PINNED_DIGEST = "6e127482ffcfd0d38b474e4518264c6e81c509a2c4d123f6de11d6f6e7069046"


def _load() -> LossAnalysis:
    payload = yaml.safe_load(PINNED_PATH.read_text(encoding="utf-8"))
    return LossAnalysis.model_validate(payload)


def test_pinned_file_digest_matches_the_recorded_constant() -> None:
    assert hashlib.sha256(PINNED_PATH.read_bytes()).hexdigest() == PINNED_DIGEST


def test_pinned_file_loads_as_a_loss_analysis() -> None:
    analysis = _load()
    assert len(analysis.risk_dispositions) == 49
    assert len(analysis.hazards) == len(analysis.security_constraints) == 9


def test_pinned_graph_passes_the_density_gate_offline() -> None:
    analysis = _load()
    report = check_hazard_graph_density(analysis, load_behavior_classes())
    assert report.passed, report.failing_checks


def test_pinned_constraints_merge_alternatives_into_one_condition() -> None:
    analysis = _load()
    for constraint in analysis.security_constraints:
        assert len(constraint.applies_when) <= 2, (
            f"{constraint.constraint_id} lists "
            f"{len(constraint.applies_when)} applies_when conditions"
        )
