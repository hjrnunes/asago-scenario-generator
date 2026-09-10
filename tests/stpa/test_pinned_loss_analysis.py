"""The owner-accepted Stage 1a measurement input.

``data/gold/miniklarna/loss-analysis-pinned.yaml`` is the v6 graph after the
documented alternatives-merge correction (spec, "Pinned graph correction",
2026-09-08), revised on 2026-09-10 to carry the owner-accepted obligation
entries and reviewed direction stamps (owner ruling Q30(a); benchmark input
revision).  Measurement runs consume it through ``--loss-analysis``, so its
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

# The graph digest recorded in the spec.  The file is serialized
# with the project's ``write_yaml``, so its byte sha256 equals that digest.
# 2026-09-10 revision: obligation entries + reviewed direction stamps added
# (owner ruling Q30(a)); prior digest
# 6e127482ffcfd0d38b474e4518264c6e81c509a2c4d123f6de11d6f6e7069046.
# Same-day realignment: SC-6/O2 residual and SC-8/O2 behavior wording
# restored to the frozen v3 review text verbatim (implementation
# verification, option3-implementation-verify); intermediate digest
# 6182fe88dc12c9330fad032a527519c9311a062b384cc74df65232368a300407.
PINNED_DIGEST = "82f4b77a80950936ed5da50f79a1f36727eb8777278b332b359662435a09e43b"


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


def test_pinned_graph_carries_the_reviewed_obligation_entries() -> None:
    """Owner ruling Q30(a): every constraint carries reviewed entries."""
    analysis = _load()
    expected_directions = {
        "SC-1": "forbidden",
        "SC-2": "forbidden",
        "SC-3": "forbidden",
        "SC-4": "forbidden",
        "SC-5": "forbidden",
        "SC-6": "forbidden",
        "SC-7": "required",
        # The R-SC-8 amendment adds a required entry beside the forbidden
        # one, so SC-8's direction is mixed.
        "SC-8": "mixed",
        "SC-9": "required",
    }
    for constraint in analysis.security_constraints:
        assert constraint.direction_authority == "reviewed"
        assert constraint.reviewed_by == "owner"
        assert constraint.obligations, constraint.constraint_id
        assert (
            constraint.failure_direction
            == expected_directions[constraint.constraint_id]
        )
