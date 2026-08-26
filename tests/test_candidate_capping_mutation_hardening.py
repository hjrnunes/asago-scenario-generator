"""Focused adversarial coverage for candidate capping."""

from __future__ import annotations

import pytest

from asago_scenario_generator.pipeline.candidates import cap_scenarios_per_pattern
from tests.test_cap_scenarios_per_pattern import _make_filtered_seed


def test_exact_cap_preserves_encounter_order() -> None:
    """A group exactly at the cap must bypass greedy reordering."""
    first = _make_filtered_seed(
        pinned_entry_point="ep1",
        pinned_technique_ids=("AML.T0051",),
    )
    second = _make_filtered_seed(
        pinned_entry_point="ep2",
        pinned_technique_ids=("AML.T0051", "AML.T0054"),
    )

    assert cap_scenarios_per_pattern([first, second], 2) == [first, second]


def test_dedup_rejects_conflicting_non_provenance_metadata() -> None:
    """Converged identities must not silently select one metadata record."""
    first = _make_filtered_seed(
        threat_id="T7",
        pinned_entry_point="ep1",
        pinned_technique_ids=("AML.T0051",),
    )
    second = _make_filtered_seed(
        threat_id="T8",
        pinned_entry_point="ep1",
        pinned_technique_ids=("AML.T0051",),
    )

    with pytest.raises(ValueError, match="Conflicting non-provenance metadata"):
        cap_scenarios_per_pattern([first, second], 2)
