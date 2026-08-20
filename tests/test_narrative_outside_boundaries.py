"""Tests for narrative representation of activity outside the assessed boundary.

Covers stage-specific narrative boundary-zone enforcement, the active
narrative zone helper for consumers (coverage, priority, faceting, tree
skeleton fallback), and outside-preserving zone-sequence derivation
(taxonomy narrative outside boundaries).
"""

from __future__ import annotations

import pytest

from asago_scenario_generator.models.scenario import NarrativeLayer, NarrativeStep
from asago_scenario_generator.pipeline.generate.priority import (
    _continuous_zone_score,
    _heuristic_attack_complexity,
    _heuristic_risk_likelihood,
)
from asago_scenario_generator.pipeline.generate.tree import _build_tree_skeleton
from asago_scenario_generator.pipeline.generate.zones import (
    active_narrative_zones,
    enforce_narrative_projection_zones,
)

ACTIVE = ["input", "reasoning", "tool_execution"]

BOUNDARY_BY_ID = {
    "attacker.prepare": "outside",
    "attacker.deliver": "crossing",
    "attacker.observe": "outside",
    "system.transform": "inside",
    "system.impact": "inside",
}


def _narrative_step(
    number: int,
    zone: str,
    projected_step_ids: tuple[str, ...],
) -> NarrativeStep:
    return NarrativeStep(
        step_number=number,
        zone=zone,
        action="action",
        effect="effect",
        projected_step_ids=projected_step_ids,
    )


def _narrative(steps: list[NarrativeStep], zone_sequence: list[str]) -> NarrativeLayer:
    return NarrativeLayer(
        title="Test",
        summary="Summary",
        entry_point="entry",
        zone_sequence=zone_sequence,
        steps=steps,
    )


# ---------------------------------------------------------------------------
# Feature 01 / 02: accepted outside mappings
# ---------------------------------------------------------------------------


class TestAcceptedNarrativeZones:
    @pytest.mark.parametrize(
        ("step_id", "boundary_position", "narrative_zone"),
        [
            ("attacker.prepare", "outside", "outside"),
            ("attacker.deliver", "crossing", "input"),
            ("system.transform", "inside", "reasoning"),
        ],
    )
    def test_accepts_stage_specific_narrative_boundary_rule(
        self, step_id, boundary_position, narrative_zone
    ):
        narrative = _narrative(
            [_narrative_step(1, narrative_zone, (step_id,))], [narrative_zone]
        )
        result = enforce_narrative_projection_zones(
            narrative, ACTIVE, {step_id: boundary_position}
        )
        assert result is narrative
        assert result.steps[0].zone == narrative_zone
        assert result.steps[0].projected_step_ids == (step_id,)

    def test_combines_only_outside_steps_under_outside_zone(self):
        narrative = _narrative(
            [
                _narrative_step(
                    1, "outside", ("attacker.observe", "attacker.prepare")
                )
            ],
            ["outside"],
        )
        result = enforce_narrative_projection_zones(narrative, ACTIVE, BOUNDARY_BY_ID)
        assert result is narrative
        assert result.steps[0].zone == "outside"
        assert result.steps[0].projected_step_ids == (
            "attacker.observe",
            "attacker.prepare",
        )


# ---------------------------------------------------------------------------
# Feature 03: rejected boundary and active-zone mismatches
# ---------------------------------------------------------------------------


class TestRejectedNarrativeZones:
    @pytest.mark.parametrize(
        ("projected_step_ids", "boundary_positions", "narrative_zone", "reason"),
        [
            (
                ("attacker.prepare", "system.transform"),
                ("outside", "inside"),
                "outside",
                "mixed boundary positions",
            ),
            (
                ("attacker.prepare", "system.transform"),
                ("outside", "inside"),
                "input",
                "mixed boundary positions",
            ),
            (("system.transform",), ("inside",), "outside", "inside step outside"),
            (("attacker.deliver",), ("crossing",), "outside", "crossing step outside"),
            (("attacker.prepare",), ("outside",), "input", "outside step active zone"),
            (
                ("system.transform",),
                ("inside",),
                "memory",
                "inactive Schneider zone",
            ),
        ],
    )
    def test_rejects_boundary_and_active_zone_mismatches(
        self, projected_step_ids, boundary_positions, narrative_zone, reason
    ):
        boundary_by_id = dict(zip(projected_step_ids, boundary_positions))
        narrative = _narrative(
            [_narrative_step(1, narrative_zone, projected_step_ids)],
            [narrative_zone],
        )
        with pytest.raises(ValueError, match="projection-zone") as excinfo:
            enforce_narrative_projection_zones(narrative, ACTIVE, boundary_by_id)
        assert reason in str(excinfo.value)

    def test_no_narrative_step_is_removed_renumbered_or_remapped(self):
        narrative = _narrative(
            [_narrative_step(1, "outside", ("system.transform",))], ["outside"]
        )
        with pytest.raises(ValueError):
            enforce_narrative_projection_zones(narrative, ACTIVE, BOUNDARY_BY_ID)
        # Original narrative is untouched: same zones, ids, and step numbers.
        assert [s.step_number for s in narrative.steps] == [1]
        assert narrative.steps[0].zone == "outside"
        assert narrative.steps[0].projected_step_ids == ("system.transform",)


# ---------------------------------------------------------------------------
# Feature 04: outside traversal order is preserved in the derived sequence
# ---------------------------------------------------------------------------


class TestZoneSequenceDerivation:
    def test_derived_zone_sequence_preserves_outside_traversal(self):
        from asago_scenario_generator.pipeline.generate.narrative import (
            _derive_zone_sequence,
        )

        steps = [
            _narrative_step(1, "outside", ("attacker.prepare",)),
            _narrative_step(2, "outside", ("attacker.observe",)),
            _narrative_step(3, "input", ("attacker.deliver",)),
            _narrative_step(4, "outside", ("attacker.prepare",)),
            _narrative_step(5, "reasoning", ("system.transform",)),
        ]
        assert _derive_zone_sequence(steps) == [
            "outside",
            "input",
            "outside",
            "reasoning",
        ]


# ---------------------------------------------------------------------------
# Feature 05: outside is excluded from active-zone consumers
# ---------------------------------------------------------------------------


class TestActiveZoneConsumers:
    def test_active_narrative_zones_excludes_outside(self):
        assert active_narrative_zones(
            ["outside", "input", "outside", "reasoning"]
        ) == ["input", "reasoning"]

    def test_priority_zone_signals_use_distinct_active_zones_and_traversal_length(
        self,
    ):
        narrative = _narrative(
            [
                _narrative_step(1, "outside", ("attacker.prepare",)),
                _narrative_step(2, "input", ("attacker.deliver",)),
                _narrative_step(3, "outside", ("attacker.observe",)),
                _narrative_step(4, "reasoning", ("system.transform",)),
            ],
            ["outside", "input", "outside", "reasoning"],
        )
        assert len(set(active_narrative_zones(narrative.zone_sequence))) == 2
        assert len(active_narrative_zones(narrative.zone_sequence)) == 2

    def test_risk_likelihood_ignores_outside_traversal(self):
        narrative = _narrative(
            [_narrative_step(1, "outside", ("attacker.prepare",))],
            ["outside"],
        )
        assert _heuristic_risk_likelihood(narrative) == "low"

    def test_continuous_zone_score_ignores_outside_traversal(self):
        narrative = _narrative(
            [
                _narrative_step(1, "outside", ("attacker.prepare",)),
                _narrative_step(2, "input", ("attacker.deliver",)),
                _narrative_step(3, "outside", ("attacker.observe",)),
                _narrative_step(4, "reasoning", ("system.transform",)),
            ],
            ["outside", "input", "outside", "reasoning"],
        )
        score = _continuous_zone_score(narrative)
        assert score > 0
        # Distinct active zones = 2 => breadth 0.4; active length = 2.
        assert score == pytest.approx(0.7 * (2 / 5.0) + 0.3 * (2 / 10.0))

    def test_attack_complexity_fallback_ignores_outside_traversal(self):
        narrative = _narrative(
            [
                _narrative_step(1, "outside", ("attacker.prepare",)),
                _narrative_step(2, "reasoning", ("system.transform",)),
            ],
            ["outside", "reasoning"],
        )
        # Only one active zone => low complexity fallback.
        from asago_scenario_generator.models.scenario import AttackComplexity

        assert _heuristic_attack_complexity(None, narrative) == AttackComplexity.low


# ---------------------------------------------------------------------------
# Feature 06: tree skeleton fallback uses the first active narrative zone
# ---------------------------------------------------------------------------


class TestTreeSkeletonFallback:
    def test_mandatory_leaf_fallback_uses_first_active_zone(self):
        narrative = _narrative(
            [
                _narrative_step(1, "outside", ("attacker.prepare",)),
                _narrative_step(2, "outside", ("attacker.observe",)),
                _narrative_step(3, "reasoning", ("system.transform",)),
            ],
            ["outside", "outside", "reasoning"],
        )
        skeleton = _build_tree_skeleton(
            narrative,
            pinned_technique_ids=["AML.T0001"],
            pinned_technique_names=["Unmatched technique"],
        )
        assert skeleton[0]["zone"] == "reasoning"
        assert skeleton[0]["zone"] != "outside"
