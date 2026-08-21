"""Tests for compute_minimum_capability_level (estu bead).

Covers:
- R1: Supply chain / training technique -> advanced
- R2: Multi-technique escalation -> intermediate (with chain pair exception)
- R3: System EP access floor -> intermediate
- R4: Indirect EP + adversarial-only threat -> intermediate (with T2 exception)
- Rule stacking: highest floor wins
- Integration: preferred_capability_level override when below floor
"""

from __future__ import annotations

import pytest

from asago_scenario_generator.pipeline.generate import (
    CHAIN_TECHNIQUE_PAIRS,
    _ADVERSARIAL_ONLY_THREATS,
    _CAPABILITY_ORDER,
    _max_capability_level,
    compute_minimum_capability_level,
)
from asago_scenario_generator.prompts import render_prompt


# ---------------------------------------------------------------------------
# R1: Supply chain / training technique -> advanced
# ---------------------------------------------------------------------------


class TestR1SupplyChainTraining:
    """R1: Any pinned technique with target_layer in (supply_chain, training)
    triggers minimum_capability_level = advanced."""

    def test_supply_chain_technique_triggers_advanced(self):
        # AML.T0010 has target_layer = "supply_chain"
        result = compute_minimum_capability_level(
            ["AML.T0010"], "direct", "T7"
        )
        assert result == "advanced"

    def test_training_technique_triggers_advanced(self):
        # AML.T0020 has target_layer = "training"
        result = compute_minimum_capability_level(
            ["AML.T0020"], "direct", "T7"
        )
        assert result == "advanced"

    def test_supply_chain_second_technique_triggers(self):
        # AML.T0048 has target_layer = "supply_chain"
        result = compute_minimum_capability_level(
            ["AML.T0053", "AML.T0048"], "direct", "T7"
        )
        assert result == "advanced"

    def test_normal_technique_no_r1_trigger(self):
        # AML.T0053 has target_layer = None
        result = compute_minimum_capability_level(
            ["AML.T0053"], "direct", "T2"
        )
        assert result == "novice"

    def test_unknown_technique_no_r1_trigger(self):
        result = compute_minimum_capability_level(
            ["UNKNOWN.T9999"], "direct", "T2"
        )
        assert result == "novice"


# ---------------------------------------------------------------------------
# R2: Multi-technique escalation -> intermediate
# ---------------------------------------------------------------------------


class TestR2MultiTechniqueEscalation:
    """R2: 2+ pinned techniques trigger intermediate, unless the pair
    is in CHAIN_TECHNIQUE_PAIRS."""

    def test_two_techniques_triggers_intermediate(self):
        result = compute_minimum_capability_level(
            ["AML.T0053", "AML.T0054"], "direct", "T7"
        )
        assert result == "intermediate"

    def test_three_techniques_triggers_intermediate(self):
        result = compute_minimum_capability_level(
            ["AML.T0053", "AML.T0054", "AML.T0056"], "direct", "T7"
        )
        assert result == "intermediate"

    def test_single_technique_no_r2_trigger(self):
        result = compute_minimum_capability_level(
            ["AML.T0053"], "direct", "T2"
        )
        assert result == "novice"

    def test_chain_pair_exception_no_trigger(self):
        # AML.T0051.001 + AML.T0067 is a chain pair
        result = compute_minimum_capability_level(
            ["AML.T0051.001", "AML.T0067"], "direct", "T2"
        )
        assert result == "novice"

    def test_chain_pair_reversed_no_trigger(self):
        # Order should not matter
        result = compute_minimum_capability_level(
            ["AML.T0067", "AML.T0051.001"], "direct", "T2"
        )
        assert result == "novice"

    def test_chain_pair_T0066_T0057(self):
        result = compute_minimum_capability_level(
            ["AML.T0066", "AML.T0057"], "direct", "T2"
        )
        assert result == "novice"

    def test_chain_pair_T0070_T0057(self):
        result = compute_minimum_capability_level(
            ["AML.T0070", "AML.T0057"], "direct", "T2"
        )
        assert result == "novice"

    def test_chain_pair_only_exempts_two_technique_seeds(self):
        # 3 techniques that include a chain pair still triggers R2
        result = compute_minimum_capability_level(
            ["AML.T0051.001", "AML.T0067", "AML.T0053"], "direct", "T2"
        )
        assert result == "intermediate"

    def test_empty_techniques_no_r2_trigger(self):
        result = compute_minimum_capability_level([], "direct", "T2")
        assert result == "novice"

    def test_none_techniques_no_r2_trigger(self):
        result = compute_minimum_capability_level(None, "direct", "T2")
        assert result == "novice"


# ---------------------------------------------------------------------------
# R3: System EP access floor -> intermediate
# ---------------------------------------------------------------------------


class TestR3SystemEP:
    """R3: EP controllability == system triggers intermediate."""

    def test_system_ep_triggers_intermediate(self):
        result = compute_minimum_capability_level(
            ["AML.T0053"], "system", "T2"
        )
        assert result == "intermediate"

    def test_direct_ep_no_r3_trigger(self):
        result = compute_minimum_capability_level(
            ["AML.T0053"], "direct", "T2"
        )
        assert result == "novice"

    def test_indirect_ep_no_r3_trigger(self):
        result = compute_minimum_capability_level(
            ["AML.T0053"], "indirect", "T2"
        )
        assert result == "novice"

    def test_none_ep_no_r3_trigger(self):
        result = compute_minimum_capability_level(
            ["AML.T0053"], None, "T2"
        )
        assert result == "novice"


# ---------------------------------------------------------------------------
# R4: Indirect EP + adversarial-only threat -> intermediate
# ---------------------------------------------------------------------------


class TestR4IndirectAdversarial:
    """R4: EP controllability == indirect AND threat in adversarial-only set
    (except T2) triggers intermediate."""

    def test_indirect_adversarial_triggers_intermediate(self):
        result = compute_minimum_capability_level(
            ["AML.T0053"], "indirect", "T3"
        )
        assert result == "intermediate"

    def test_indirect_t7_triggers_intermediate(self):
        result = compute_minimum_capability_level(
            ["AML.T0053"], "indirect", "T7"
        )
        assert result == "intermediate"

    def test_indirect_t2_exception_no_trigger(self):
        # T2 is explicitly excluded from R4
        result = compute_minimum_capability_level(
            ["AML.T0053"], "indirect", "T2"
        )
        assert result == "novice"

    def test_indirect_non_adversarial_no_trigger(self):
        # T2 is not adversarial-only
        result = compute_minimum_capability_level(
            ["AML.T0053"], "indirect", "T2"
        )
        assert result == "novice"

    def test_direct_adversarial_no_r4_trigger(self):
        # R4 requires indirect EP
        result = compute_minimum_capability_level(
            ["AML.T0053"], "direct", "T3"
        )
        assert result == "novice"

    @pytest.mark.parametrize("threat_id", list(_ADVERSARIAL_ONLY_THREATS - {"T3"}))
    def test_all_adversarial_threats_except_t2(self, threat_id: str):
        if threat_id == "T2":
            pytest.skip("T2 is exempted")
        result = compute_minimum_capability_level(
            ["AML.T0053"], "indirect", threat_id
        )
        assert result == "intermediate"


# ---------------------------------------------------------------------------
# Rule stacking: highest floor wins
# ---------------------------------------------------------------------------


class TestRuleStacking:
    """Multiple rules fire; highest minimum wins."""

    def test_r1_beats_r2(self):
        # R1 (advanced) + R2 (intermediate) -> advanced
        result = compute_minimum_capability_level(
            ["AML.T0010", "AML.T0053"], "direct", "T7"
        )
        assert result == "advanced"

    def test_r1_beats_r3(self):
        # R1 (advanced) + R3 (intermediate) -> advanced
        result = compute_minimum_capability_level(
            ["AML.T0020"], "system", "T7"
        )
        assert result == "advanced"

    def test_r2_and_r3_same_level(self):
        # R2 (intermediate) + R3 (intermediate) -> intermediate
        result = compute_minimum_capability_level(
            ["AML.T0053", "AML.T0054"], "system", "T2"
        )
        assert result == "intermediate"

    def test_r3_and_r4_same_level(self):
        # R3 (intermediate) + R4 would need system+indirect which is
        # contradictory, so test R2+R4
        result = compute_minimum_capability_level(
            ["AML.T0053", "AML.T0054"], "indirect", "T7"
        )
        assert result == "intermediate"

    def test_no_rules_fire(self):
        # Single technique, direct EP, non-adversarial threat
        result = compute_minimum_capability_level(
            ["AML.T0053"], "direct", "T2"
        )
        assert result == "novice"


# ---------------------------------------------------------------------------
# _max_capability_level helper
# ---------------------------------------------------------------------------


class TestMaxCapabilityLevel:
    def test_novice_vs_intermediate(self):
        assert _max_capability_level("novice", "intermediate") == "intermediate"

    def test_advanced_vs_intermediate(self):
        assert _max_capability_level("advanced", "intermediate") == "advanced"

    def test_expert_vs_advanced(self):
        assert _max_capability_level("expert", "advanced") == "expert"

    def test_same_level(self):
        assert _max_capability_level("intermediate", "intermediate") == "intermediate"

    @pytest.mark.parametrize(
        ("first", "second"),
        [("unknown", "novice"), ("novice", "unknown")],
    )
    def test_unknown_level_defaults_to_novice(self, first, second):
        assert _max_capability_level(first, second) == "novice"


# ---------------------------------------------------------------------------
# Prompt template integration
# ---------------------------------------------------------------------------


class TestCapabilityLevelPromptConstraint:
    """The call0_user.j2 template includes the capability level constraint
    when minimum > novice."""

    # Minimal user-prompt context needed to render call0_user.j2
    _USER_CTX: dict = {
        "use_case": "test",
        "seed": type("S", (), {
            "attack_pattern_name": "X",
            "attack_pattern_description": "X",
            "threat_name": "X",
            "threat_description": "X",
        })(),
        "profile": type("P", (), {
            "zones_active": ["input"],
            "entry_points": [],
        })(),
        "kc_definitions": "",
        "tool_inventory": [],
        "ontology_context": "",
        "pinned_entry_point": None,
        "pinned_entry_point_direction": None,
        "pinned_technique_count": 1,
        "technique_context": "",
        "technique_framing_0": "",
        "goal_section": "",
        "diversity_section": "",
        "compatible_actor_types": [],
    }

    def test_intermediate_floor_appears_in_prompt(self):
        ctx = {**self._USER_CTX, "minimum_capability_level": "intermediate"}
        prompt = render_prompt("call0_user.j2", **ctx)
        assert "Capability Level Constraint" in prompt
        assert '"intermediate"' in prompt

    def test_advanced_floor_appears_in_prompt(self):
        ctx = {**self._USER_CTX, "minimum_capability_level": "advanced"}
        prompt = render_prompt("call0_user.j2", **ctx)
        assert "Capability Level Constraint" in prompt
        assert '"advanced"' in prompt

    def test_novice_floor_not_shown(self):
        ctx = {**self._USER_CTX, "minimum_capability_level": "novice"}
        prompt = render_prompt("call0_user.j2", **ctx)
        assert "Capability Level Constraint" not in prompt

    def test_none_floor_not_shown(self):
        ctx = {**self._USER_CTX, "minimum_capability_level": None}
        prompt = render_prompt("call0_user.j2", **ctx)
        assert "Capability Level Constraint" not in prompt

    def test_default_no_floor(self):
        """Backward compat: no minimum_capability_level kwarg still works."""
        ctx = {**self._USER_CTX}
        ctx.pop("minimum_capability_level", None)
        prompt = render_prompt("call0_user.j2", **ctx)
        assert "Capability Level Constraint" not in prompt


# ---------------------------------------------------------------------------
# CHAIN_TECHNIQUE_PAIRS constant integrity
# ---------------------------------------------------------------------------


class TestChainTechniquePairs:
    def test_all_pairs_are_tuples_of_two(self):
        for pair in CHAIN_TECHNIQUE_PAIRS:
            assert isinstance(pair, tuple)
            assert len(pair) == 2

    def test_initial_pairs_present(self):
        assert ("AML.T0051.001", "AML.T0067") in CHAIN_TECHNIQUE_PAIRS
        assert ("AML.T0066", "AML.T0057") in CHAIN_TECHNIQUE_PAIRS
        assert ("AML.T0070", "AML.T0057") in CHAIN_TECHNIQUE_PAIRS


# ---------------------------------------------------------------------------
# Adversarial/negative tests
# ---------------------------------------------------------------------------


class TestNegativeCases:
    """Adversarial and edge cases that should NOT trigger floors."""

    def test_r1_normal_technique_no_floor(self):
        # AML.T0053 has no target_layer
        assert compute_minimum_capability_level(
            ["AML.T0053"], "direct", "T2"
        ) == "novice"

    def test_r2_chain_pair_bypasses(self):
        # Known chain pair bypasses R2
        assert compute_minimum_capability_level(
            ["AML.T0051.001", "AML.T0067"], "direct", "T2"
        ) == "novice"

    def test_r4_t2_exception(self):
        # T2 is explicitly exempted from R4
        assert compute_minimum_capability_level(
            ["AML.T0053"], "indirect", "T2"
        ) == "novice"

    def test_r4_direct_ep_not_triggered(self):
        # R4 requires indirect EP
        assert compute_minimum_capability_level(
            ["AML.T0053"], "direct", "T15"
        ) == "novice"

    def test_r3_non_system_ep(self):
        # R3 only triggers on system
        assert compute_minimum_capability_level(
            ["AML.T0053"], "direct", "T2"
        ) == "novice"

    def test_tuple_technique_ids_accepted(self):
        """Function accepts tuple as well as list for technique IDs."""
        result = compute_minimum_capability_level(
            ("AML.T0053", "AML.T0054"), "direct", "T2"
        )
        assert result == "intermediate"
