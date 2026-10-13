"""Tests for threat gating.

Covers:
  - which threats a profile's KC sub-codes and HITL flag put in scope
  - the kc_requires gate that drops attack patterns within an in-scope threat
  - the shipped catalog gates every min_zones pattern with kc_requires

The order of the returned IDs is pinned in test_threat_scope_order_guard.py.
"""

from __future__ import annotations

import pytest

from asago_scenario_generator.data.loaders import load_attack_patterns
from asago_scenario_generator.data.threat_gating import (
    _kc_requires_met,
    in_scope_attack_pattern_ids,
)
from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    ToolInventoryEntry,
)


def _profile(kc_subcodes: list[str]) -> CapabilityProfile:
    return CapabilityProfile(
        zones_active=["input", "reasoning"],
        entry_points=["user input (zone 1)"],
        confidence="medium",
        kc_subcodes=kc_subcodes,
        tool_inventory=[
            ToolInventoryEntry(name="test_tool", description="A test tool")
        ],
    )


def _threats_in_scope(kc_subcodes: list[str]) -> set[str]:
    """The threat IDs that keep at least one pattern for these sub-codes."""
    return {
        pattern_id.split("-")[1]
        for pattern_id in in_scope_attack_pattern_ids(_profile(kc_subcodes))
    }


def _gated(kc_requires: dict) -> dict:
    return {"prerequisite_capabilities": {"kc_requires": kc_requires}}


class TestThreatsInScope:
    """KC sub-codes enable threats through kc-threat-mapping.yaml."""

    def test_a_language_model_alone_scopes_the_baseline_threats(self):
        assert _threats_in_scope(["KC1.1"]) == {"T5", "T6"}

    def test_limited_api_access_does_not_enable_t11(self):
        threats = _threats_in_scope(["KC1.1", "KC6.1.1"])

        assert "T2" in threats
        assert "T11" not in threats

    def test_extensive_code_execution_enables_t11(self):
        assert "T11" in _threats_in_scope(["KC1.1", "KC6.2.2"])

    def test_hitl_enables_t10_without_a_multi_agent_code(self):
        assert "T10" in _threats_in_scope(["KC1.1", "KCX-HITL"])
        assert "T10" not in _threats_in_scope(["KC1.1"])

    def test_a_threat_enabled_by_no_code_keeps_none_of_its_patterns(self):
        assert "T12" not in _threats_in_scope(["KC1.1"])


class TestKcRequiresGate:
    """The kc_requires gate: one overlap for ``any``, every code for ``all``."""

    @pytest.mark.parametrize(
        ("kc_requires", "profile_kcs", "expected"),
        [
            ({"any": ["KC6.2.2"]}, {"KC1.1", "KC6.2.2"}, True),
            ({"any": ["KC6.2.2"]}, {"KC1.1", "KC6.1.1"}, False),
            ({"all": ["KC2.3", "KC5.1"]}, {"KC1.1", "KC2.3", "KC5.1"}, True),
            ({"all": ["KC2.3", "KC5.1"]}, {"KC1.1", "KC2.3"}, False),
            (
                {"any": ["KC6.2.2", "KC6.4"], "all": ["KC2.3"]},
                {"KC2.3", "KC6.2.2"},
                True,
            ),
            ({"any": ["KC6.2.2"], "all": ["KC2.3"]}, {"KC6.2.2"}, False),
            # AP-T2-05 needs KCX-VSTORE and KC6.3.3.
            (
                {"all": ["KCX-VSTORE"], "any": ["KC6.3.3"]},
                {"KC6.3.3", "KCX-VSTORE"},
                True,
            ),
            ({"all": ["KCX-VSTORE"], "any": ["KC6.3.3"]}, {"KC6.3.3"}, False),
            # AP-T1-04 needs KCX-SHMEM and KC4.4 or KC4.6.
            ({"all": ["KCX-SHMEM"], "any": ["KC4.4", "KC4.6"]}, {"KC4.4"}, False),
        ],
    )
    def test_any_and_all_lists_gate_a_pattern(self, kc_requires, profile_kcs, expected):
        assert _kc_requires_met(_gated(kc_requires), profile_kcs) is expected

    @pytest.mark.parametrize(
        "pattern",
        [
            {"id": "AP-T9-99"},
            {"id": "AP-T9-99", "prerequisite_capabilities": {}},
            {"id": "AP-T9-99", "prerequisite_capabilities": {"min_zones": ["memory"]}},
        ],
        ids=["no_prerequisites", "empty_prerequisites", "min_zones_only"],
    )
    def test_a_pattern_without_kc_requires_always_passes(self, pattern):
        assert _kc_requires_met(pattern, set()) is True

    def test_min_zones_does_not_affect_the_gate(self):
        pattern = {
            "prerequisite_capabilities": {
                "min_zones": ["input", "reasoning", "tool_execution"],
                "kc_requires": {"any": ["KC6.2.2"]},
            }
        }

        assert _kc_requires_met(pattern, {"KC1.1", "KC6.2.2"}) is True

    def test_no_shipped_pattern_relies_solely_on_min_zones(self):
        """Every shipped pattern with min_zones also has kc_requires."""
        for pid, pattern in load_attack_patterns().items():
            prereqs = pattern.get("prerequisite_capabilities")
            if not prereqs or not prereqs.get("min_zones"):
                continue
            assert prereqs.get("kc_requires"), (
                f"{pid} has min_zones as its ONLY gate; it would pass ungated"
            )
