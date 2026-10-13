"""Order guard for the attack-pattern IDs a capability profile puts in scope.

The fixtures are the capability profiles the Klarna, Airbnb and OccAI replay
units record. The expected lists are literal: the order is threat declaration
order, then catalog order within a threat, and it feeds the taxonomy inputs.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from asago_scenario_generator.data.threat_gating import determine_threat_scope
from asago_scenario_generator.models.capability_profile import CapabilityProfile

FIXTURES = Path(__file__).parent / "fixtures" / "threat_gating"

EXPECTED = {
    "klarna": [
        "AP-T2-01", "AP-T2-02", "AP-T2-03", "AP-T2-06",
        "AP-T3-04", "AP-T3-05", "AP-T3-06", "AP-T3-02",
        "AP-T4-01", "AP-T4-03",
        "AP-T5-05",
        "AP-T6-08", "AP-T6-09", "AP-T6-10",
        "AP-T6-01", "AP-T6-02", "AP-T6-03", "AP-T6-04", "AP-T6-05",
        "AP-T9-01", "AP-T9-05",
        "AP-T10-01",
        "AP-T15-01", "AP-T15-02",
    ],
    "airbnb": [
        "AP-T2-01", "AP-T2-02", "AP-T2-03", "AP-T2-06",
        "AP-T3-04", "AP-T3-05", "AP-T3-06", "AP-T3-02",
        "AP-T4-01", "AP-T4-03",
        "AP-T5-05",
        "AP-T6-08", "AP-T6-09", "AP-T6-10",
        "AP-T6-01", "AP-T6-02", "AP-T6-03", "AP-T6-04", "AP-T6-05",
        "AP-T8-01",
        "AP-T9-01", "AP-T9-05",
        "AP-T15-01", "AP-T15-02",
    ],
    "occiai": [
        "AP-T2-01", "AP-T2-02", "AP-T2-03", "AP-T2-06",
        "AP-T3-04", "AP-T3-05", "AP-T3-06",
        "AP-T5-05",
        "AP-T6-08", "AP-T6-09", "AP-T6-10",
        "AP-T6-01", "AP-T6-02", "AP-T6-03", "AP-T6-04", "AP-T6-05",
        "AP-T8-01",
        "AP-T10-01",
        "AP-T15-01", "AP-T15-02",
    ],
}  # fmt: skip


def _in_scope_pattern_ids(profile: CapabilityProfile) -> list[str]:
    return [
        pattern_id
        for entry in determine_threat_scope(profile).in_scope
        for pattern_id in entry.attack_pattern_ids
    ]


@pytest.mark.parametrize("target", sorted(EXPECTED))
def test_in_scope_pattern_ids_keep_their_recorded_order(target: str) -> None:
    profile = CapabilityProfile.model_validate(
        yaml.safe_load((FIXTURES / f"{target}-capability-profile.yaml").read_text())
    )

    assert _in_scope_pattern_ids(profile) == EXPECTED[target]
