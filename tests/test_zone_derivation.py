"""Tests for derive_zones_from_kc() and zone/flag derivation on models.

Covers:
  - Zone derivation from KC sub-codes (pure function)
  - Zone derivation on Stage1Profile.to_capability_profile()
  - Zone derivation on CapabilityProfile (model_validator)
  - Boolean flag computation from KC sub-codes (computed_field)
  - Consistency with kc-threat-mapping.yaml taxonomy data
"""

from __future__ import annotations

from pathlib import Path

import yaml

from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    Stage1Profile,
    ToolInventoryEntry,
    VALID_KC_SUBCODES,
    derive_zones_from_kc,
)

_TEST_TOOL_INVENTORY = [ToolInventoryEntry(name="test_tool", description="A test tool")]


# ---------------------------------------------------------------------------
# derive_zones_from_kc unit tests
# ---------------------------------------------------------------------------


class TestDeriveZonesBasic:
    """Minimal KC set produces baseline zones."""

    def test_derive_zones_basic(self):
        """KC1.1 alone -> ['input', 'reasoning']."""
        result = derive_zones_from_kc(["KC1.1"])
        assert result == ["input", "reasoning"]

    def test_derive_zones_empty_list(self):
        """Empty KC list still returns baseline zones."""
        result = derive_zones_from_kc([])
        assert result == ["input", "reasoning"]

    def test_derive_zones_kc3_stays_baseline(self):
        """KC3.* codes don't add zones beyond baseline."""
        result = derive_zones_from_kc(["KC1.1", "KC3.1", "KC3.2"])
        assert result == ["input", "reasoning"]


class TestDeriveZonesMemory:
    """KC4.3-KC4.6 activate the memory zone; KC4.1/KC4.2 do not."""

    def test_derive_zones_with_memory(self):
        """KC4.4 (cross-agent, cross-session) -> includes 'memory'."""
        result = derive_zones_from_kc(["KC1.1", "KC4.4"])
        assert "memory" in result

    def test_derive_zones_session_memory_no_zone_kc4_1(self):
        """KC4.1 (in-agent session-only) -> no 'memory' zone."""
        result = derive_zones_from_kc(["KC1.1", "KC4.1"])
        assert "memory" not in result
        assert result == ["input", "reasoning"]

    def test_derive_zones_session_memory_no_zone_kc4_2(self):
        """KC4.2 (cross-agent session-only) -> no 'memory' zone."""
        result = derive_zones_from_kc(["KC1.1", "KC4.2"])
        assert "memory" not in result
        assert result == ["input", "reasoning"]

    def test_derive_zones_kc4_3_activates_memory(self):
        """KC4.3 (in-agent cross-session) -> includes 'memory'."""
        result = derive_zones_from_kc(["KC1.1", "KC4.3"])
        assert "memory" in result

    def test_derive_zones_kc4_5_activates_memory(self):
        """KC4.5 (in-agent cross-user) -> includes 'memory'."""
        result = derive_zones_from_kc(["KC1.1", "KC4.5"])
        assert "memory" in result

    def test_derive_zones_kc4_6_activates_memory(self):
        """KC4.6 (cross-agent cross-user) -> includes 'memory'."""
        result = derive_zones_from_kc(["KC1.1", "KC4.6"])
        assert "memory" in result


class TestDeriveZonesToolExecution:
    """KC5.* and KC6.* activate tool_execution zone."""

    def test_derive_zones_kc5(self):
        """KC5.1 -> includes 'tool_execution'."""
        result = derive_zones_from_kc(["KC1.1", "KC5.1"])
        assert "tool_execution" in result

    def test_derive_zones_kc6(self):
        """KC6.2.2 -> includes 'tool_execution'."""
        result = derive_zones_from_kc(["KC1.1", "KC6.2.2"])
        assert "tool_execution" in result

    def test_derive_zones_kc6_all_variants(self):
        """All KC6 sub-codes activate tool_execution."""
        kc6_codes = [c for c in sorted(VALID_KC_SUBCODES) if c.startswith("KC6.")]
        for code in kc6_codes:
            result = derive_zones_from_kc(["KC1.1", code])
            assert "tool_execution" in result, f"{code} should activate tool_execution"


class TestDeriveZonesInterAgent:
    """KC2.3 activates inter_agent zone."""

    def test_derive_zones_inter_agent(self):
        """KC2.3 -> includes 'inter_agent'."""
        result = derive_zones_from_kc(["KC1.1", "KC2.3"])
        assert "inter_agent" in result

    def test_derive_zones_kc2_1_no_inter_agent(self):
        """KC2.1 (predefined workflows) -> no 'inter_agent'."""
        result = derive_zones_from_kc(["KC1.1", "KC2.1"])
        assert "inter_agent" not in result

    def test_derive_zones_kc2_2_no_inter_agent(self):
        """KC2.2 (hierarchical planning) -> no 'inter_agent'."""
        result = derive_zones_from_kc(["KC1.1", "KC2.2"])
        assert "inter_agent" not in result


class TestDeriveZonesFull:
    """All zones active with appropriate KC codes."""

    def test_derive_zones_full(self):
        """All four optional zones activated by appropriate codes."""
        result = derive_zones_from_kc([
            "KC1.1",     # baseline
            "KC2.3",     # inter_agent
            "KC4.4",     # memory
            "KC5.1",     # tool_execution
        ])
        assert result == [
            "input", "inter_agent", "memory", "reasoning", "tool_execution",
        ]

    def test_derive_zones_result_is_sorted(self):
        """Output is always sorted alphabetically."""
        result = derive_zones_from_kc(["KC6.7", "KC4.6", "KC2.3", "KC1.1"])
        assert result == sorted(result)


# ---------------------------------------------------------------------------
# Consistency with taxonomy data
# ---------------------------------------------------------------------------


class TestDeriveZonesMatchesRealData:
    """Verify derive_zones_from_kc is consistent with kc-threat-mapping.yaml."""

    def test_derive_zones_matches_real_data(self):
        """Every KC sub-code in the taxonomy maps to the expected zone(s).

        The mapping rules:
        - KC1.*/KC3.* -> input + reasoning (baseline)
        - KC2.1/KC2.2 -> reasoning (baseline only)
        - KC2.3 -> inter_agent
        - KC4.1/KC4.2 -> baseline only (session memory)
        - KC4.3-KC4.6 -> memory
        - KC5.* -> tool_execution
        - KC6.* -> tool_execution
        """
        mapping_path = (
            Path(__file__).resolve().parent.parent
            / "data" / "taxonomies" / "mappings" / "kc-threat-mapping.yaml"
        )
        with open(mapping_path) as f:
            taxonomy = yaml.safe_load(f)

        # Expected zone activation per KC category
        expected_extra_zones: dict[str, set[str]] = {
            "KC1.": set(),             # baseline only
            "KC2.1": set(),            # baseline only
            "KC2.2": set(),            # baseline only
            "KC2.3": {"inter_agent"},
            "KC3.": set(),             # baseline only
            "KC4.1": set(),            # session-only, no zone
            "KC4.2": set(),            # session-only, no zone
            "KC4.3": {"memory"},
            "KC4.4": {"memory"},
            "KC4.5": {"memory"},
            "KC4.6": {"memory"},
            "KC5.": {"tool_execution"},
            "KC6.": {"tool_execution"},
        }

        all_kc_codes = [entry["kc_subcode"] for entry in taxonomy["kc_subcodes"]]

        for kc_code in all_kc_codes:
            derived = set(derive_zones_from_kc([kc_code]))
            baseline = {"input", "reasoning"}

            # Find the expected extra zones for this code
            extra = None
            # Try exact match first, then prefix match
            if kc_code in expected_extra_zones:
                extra = expected_extra_zones[kc_code]
            else:
                for prefix, zones in expected_extra_zones.items():
                    if kc_code.startswith(prefix):
                        extra = zones
                        break

            assert extra is not None, f"No mapping rule found for {kc_code}"
            expected = baseline | extra
            assert derived == expected, (
                f"{kc_code}: derived {sorted(derived)} != expected {sorted(expected)}"
            )


# ---------------------------------------------------------------------------
# Stage1Profile zone derivation
# ---------------------------------------------------------------------------


class TestStage1ProfileZoneDerivation:
    """Stage1Profile.to_capability_profile() derives zones from kc_subcodes."""

    def test_basic_kc_produces_baseline_zones(self):
        """KC1.1 only -> zones_active=['input', 'reasoning']."""
        s = Stage1Profile(
            has_persistent_memory=False,
            multi_agent=False,
            hitl=False,
            entry_points=["user input (input)"],
            confidence="medium",
            kc_subcodes=["KC1.1"],
        )
        p = s.to_capability_profile()
        assert p.zones_active == ["input", "reasoning"]

    def test_tool_kc_activates_tool_execution(self):
        """KC5.1 -> zones_active includes 'tool_execution'."""
        s = Stage1Profile(
            has_persistent_memory=False,
            multi_agent=False,
            hitl=False,
            entry_points=["user input (input)"],
            confidence="medium",
            kc_subcodes=["KC1.1", "KC5.1"],
            tool_inventory=_TEST_TOOL_INVENTORY,
        )
        p = s.to_capability_profile()
        assert p.zones_active == ["input", "reasoning", "tool_execution"]

    def test_memory_kc_activates_memory_zone(self):
        """KC4.3 -> zones_active includes 'memory'."""
        s = Stage1Profile(
            has_persistent_memory=True,
            multi_agent=False,
            hitl=False,
            entry_points=["user input (input)"],
            confidence="medium",
            kc_subcodes=["KC1.1", "KC4.3"],
        )
        p = s.to_capability_profile()
        assert "memory" in p.zones_active

    def test_inter_agent_kc_activates_inter_agent_zone(self):
        """KC2.3 -> zones_active includes 'inter_agent'."""
        s = Stage1Profile(
            has_persistent_memory=False,
            multi_agent=True,
            hitl=False,
            entry_points=["user input (input)"],
            confidence="medium",
            kc_subcodes=["KC1.1", "KC2.3"],
        )
        p = s.to_capability_profile()
        assert "inter_agent" in p.zones_active

    def test_all_zones_from_full_kc_set(self):
        """All optional zones activated by appropriate KC codes."""
        s = Stage1Profile(
            has_persistent_memory=True,
            multi_agent=True,
            hitl=True,
            entry_points=["user input (input)"],
            confidence="high",
            kc_subcodes=["KC1.1", "KC2.3", "KC4.4", "KC5.1"],
            tool_inventory=_TEST_TOOL_INVENTORY,
        )
        p = s.to_capability_profile()
        assert p.zones_active == [
            "input", "inter_agent", "memory", "reasoning", "tool_execution",
        ]

    def test_empty_kc_subcodes_on_stage1_produces_baseline(self):
        """Empty kc_subcodes on Stage1Profile -> baseline zones on promoted profile.

        Note: CapabilityProfile requires min_length=1, but Stage1Profile
        allows empty kc_subcodes (LLM may not emit them).  The promoted
        profile gets zones derived from the empty list, which is baseline.
        """
        s = Stage1Profile(
            has_persistent_memory=False,
            multi_agent=False,
            hitl=False,
            entry_points=["user input (input)"],
            confidence="medium",
            kc_subcodes=[],
        )
        # Stage1Profile.to_capability_profile() passes the empty list;
        # CapabilityProfile requires min_length=1, so this should raise.
        import pytest
        from pydantic import ValidationError
        with pytest.raises(ValidationError, match="kc_subcodes"):
            s.to_capability_profile()


# ---------------------------------------------------------------------------
# CapabilityProfile zone derivation
# ---------------------------------------------------------------------------


class TestCapabilityProfileZoneDerivation:
    """CapabilityProfile derives zones_active from kc_subcodes."""

    def test_zones_derived_from_kc_subcodes(self):
        """When kc_subcodes is populated, zones_active is derived."""
        p = CapabilityProfile(
            zones_active=["input", "reasoning"],  # will be overridden
            entry_points=["user input (input)"],
            confidence="medium",
            kc_subcodes=["KC1.1", "KC5.1"],
            tool_inventory=_TEST_TOOL_INVENTORY,
        )
        assert p.zones_active == ["input", "reasoning", "tool_execution"]

    def test_explicit_zones_overridden_by_kc_derivation(self):
        """Explicit zones_active is replaced by KC-derived zones."""
        p = CapabilityProfile(
            zones_active=["input", "memory", "reasoning"],  # wrong for these KCs
            entry_points=["user input (input)"],
            confidence="medium",
            kc_subcodes=["KC1.1", "KC5.1"],  # derives tool_execution, not memory
            tool_inventory=_TEST_TOOL_INVENTORY,
        )
        # memory should be gone, tool_execution should be present
        assert "memory" not in p.zones_active
        assert "tool_execution" in p.zones_active

    def test_all_zones_derived(self):
        """Full KC set derives all five zones."""
        p = CapabilityProfile(
            zones_active=["input", "reasoning"],  # will be overridden
            entry_points=["user input (input)"],
            confidence="high",
            kc_subcodes=["KC1.1", "KC2.3", "KC4.4", "KC5.1"],
            tool_inventory=_TEST_TOOL_INVENTORY,
        )
        assert p.zones_active == [
            "input", "inter_agent", "memory", "reasoning", "tool_execution",
        ]

    def test_kc_derived_flags_prevent_cross_field_error(self):
        """KC4.3 derives both memory zone AND has_persistent_memory=True (no error)."""
        p = CapabilityProfile(
            zones_active=["input", "reasoning"],
            entry_points=["user input (input)"],
            confidence="medium",
            kc_subcodes=["KC1.1", "KC4.3"],
        )
        assert "memory" in p.zones_active
        assert p.has_persistent_memory is True  # computed from KC4.3


# ---------------------------------------------------------------------------
# Computed boolean flag tests (replaces derive_flags_from_kc unit tests)
# ---------------------------------------------------------------------------


class TestComputedFlags:
    """Boolean flags are computed from kc_subcodes on CapabilityProfile."""

    def _make(self, kc_subcodes: list[str]) -> CapabilityProfile:
        """Build a minimal CapabilityProfile with the given KC codes."""
        return CapabilityProfile(
            zones_active=["input", "reasoning"],
            entry_points=["user input (input)"],
            confidence="medium",
            kc_subcodes=kc_subcodes,
        )

    # --- has_persistent_memory ---

    def test_kc4_3_sets_persistent_memory(self):
        """KC4.3 (in-agent cross-session) -> has_persistent_memory."""
        p = self._make(["KC1.1", "KC4.3"])
        assert p.has_persistent_memory is True

    def test_kc4_4_sets_persistent_memory(self):
        """KC4.4 (cross-agent cross-session) -> has_persistent_memory."""
        p = self._make(["KC1.1", "KC4.4"])
        assert p.has_persistent_memory is True

    def test_kc4_5_sets_persistent_memory(self):
        """KC4.5 (in-agent cross-user) -> has_persistent_memory."""
        p = self._make(["KC1.1", "KC4.5"])
        assert p.has_persistent_memory is True

    def test_kc4_6_sets_persistent_memory(self):
        """KC4.6 (cross-agent cross-user) -> has_persistent_memory."""
        p = self._make(["KC1.1", "KC4.6"])
        assert p.has_persistent_memory is True

    def test_kcx_pmem_sets_persistent_memory(self):
        """KCX-PMEM -> has_persistent_memory."""
        p = self._make(["KC1.1", "KCX-PMEM"])
        assert p.has_persistent_memory is True

    def test_kc4_1_no_persistent_memory(self):
        """KC4.1 (in-agent session-only) -> no has_persistent_memory."""
        p = self._make(["KC1.1", "KC4.1"])
        assert p.has_persistent_memory is False

    def test_kc4_2_no_persistent_memory(self):
        """KC4.2 (cross-agent session-only) -> no has_persistent_memory."""
        p = self._make(["KC1.1", "KC4.2"])
        assert p.has_persistent_memory is False

    # --- multi_agent ---

    def test_kc2_3_sets_multi_agent(self):
        """KC2.3 (multi-agent communication) -> multi_agent."""
        p = self._make(["KC1.1", "KC2.3"])
        assert p.multi_agent is True

    def test_kcx_magent_sets_multi_agent(self):
        """KCX-MAGENT -> multi_agent."""
        p = self._make(["KC1.1", "KCX-MAGENT"])
        assert p.multi_agent is True

    def test_kc2_1_no_multi_agent(self):
        """KC2.1 (predefined workflows) -> no multi_agent."""
        p = self._make(["KC1.1", "KC2.1"])
        assert p.multi_agent is False

    def test_kc2_2_no_multi_agent(self):
        """KC2.2 (hierarchical planning) -> no multi_agent."""
        p = self._make(["KC1.1", "KC2.2"])
        assert p.multi_agent is False

    # --- hitl ---

    def test_kcx_hitl_sets_hitl(self):
        """KCX-HITL -> hitl."""
        p = self._make(["KC1.1", "KCX-HITL"])
        assert p.hitl is True

    def test_no_kcx_hitl_no_hitl(self):
        """Without KCX-HITL -> hitl is False."""
        p = self._make(["KC1.1"])
        assert p.hitl is False

    # --- Multiple flags ---

    def test_both_persistent_memory_and_multi_agent(self):
        """KC4.4 + KC2.3 -> both flags True."""
        p = self._make(["KC1.1", "KC2.3", "KC4.4"])
        assert p.has_persistent_memory is True
        assert p.multi_agent is True

    def test_all_three_flags(self):
        """KC4.3 + KC2.3 + KCX-HITL -> all three flags True."""
        p = self._make(["KC1.1", "KC2.3", "KC4.3", "KCX-HITL"])
        assert p.has_persistent_memory is True
        assert p.multi_agent is True
        assert p.hitl is True

    def test_baseline_kc_only_no_flags(self):
        """KC1.1 alone -> no flags set."""
        p = self._make(["KC1.1"])
        assert p.has_persistent_memory is False
        assert p.multi_agent is False
        assert p.hitl is False


# ---------------------------------------------------------------------------
# Flag derivation on Stage1Profile
# ---------------------------------------------------------------------------


class TestStage1ProfileFlagDerivation:
    """Stage1Profile.to_capability_profile() derives flags from kc_subcodes."""

    def test_kc4_4_derives_persistent_memory_flag(self):
        """KC4.4 with LLM-inferred has_persistent_memory=False -> corrected to True."""
        s = Stage1Profile(
            has_persistent_memory=False,  # LLM got it wrong
            multi_agent=False,
            hitl=False,
            entry_points=["user input (input)"],
            confidence="medium",
            kc_subcodes=["KC1.1", "KC4.4"],
        )
        p = s.to_capability_profile()
        assert p.has_persistent_memory is True
        assert "memory" in p.zones_active

    def test_kc4_1_does_not_derive_persistent_memory(self):
        """KC4.1 only -> has_persistent_memory stays False."""
        s = Stage1Profile(
            has_persistent_memory=False,
            multi_agent=False,
            hitl=False,
            entry_points=["user input (input)"],
            confidence="medium",
            kc_subcodes=["KC1.1", "KC4.1"],
        )
        p = s.to_capability_profile()
        assert p.has_persistent_memory is False
        assert "memory" not in p.zones_active

    def test_kc2_3_derives_multi_agent_flag(self):
        """KC2.3 with LLM-inferred multi_agent=False -> corrected to True."""
        s = Stage1Profile(
            has_persistent_memory=False,
            multi_agent=False,  # LLM got it wrong
            hitl=False,
            entry_points=["user input (input)"],
            confidence="medium",
            kc_subcodes=["KC1.1", "KC2.3"],
        )
        p = s.to_capability_profile()
        assert p.multi_agent is True
        assert "inter_agent" in p.zones_active

    def test_no_kc2_3_multi_agent_stays_false(self):
        """No KC2.3 -> multi_agent stays False."""
        s = Stage1Profile(
            has_persistent_memory=False,
            multi_agent=False,
            hitl=False,
            entry_points=["user input (input)"],
            confidence="medium",
            kc_subcodes=["KC1.1", "KC2.1"],
        )
        p = s.to_capability_profile()
        assert p.multi_agent is False

    def test_full_profile_both_flags_derived(self):
        """KC4.4 + KC2.3 -> both flags True, validator passes."""
        s = Stage1Profile(
            has_persistent_memory=False,  # LLM got both wrong
            multi_agent=False,
            hitl=True,
            entry_points=["user input (input)"],
            confidence="high",
            kc_subcodes=["KC1.1", "KC2.3", "KC4.4", "KC5.1"],
            tool_inventory=_TEST_TOOL_INVENTORY,
        )
        p = s.to_capability_profile()
        assert p.has_persistent_memory is True
        assert p.multi_agent is True
        assert p.zones_active == [
            "input", "inter_agent", "memory", "reasoning", "tool_execution",
        ]


# ---------------------------------------------------------------------------
# Flag derivation on CapabilityProfile (computed properties)
# ---------------------------------------------------------------------------


class TestCapabilityProfileFlagDerivation:
    """CapabilityProfile computed boolean flags from kc_subcodes."""

    def test_kc4_4_computes_persistent_memory(self):
        """KC4.4 -> has_persistent_memory computed as True."""
        p = CapabilityProfile(
            zones_active=["input", "reasoning"],
            entry_points=["user input (input)"],
            confidence="medium",
            kc_subcodes=["KC1.1", "KC4.4"],
        )
        assert p.has_persistent_memory is True
        assert "memory" in p.zones_active

    def test_kc2_3_computes_multi_agent(self):
        """KC2.3 -> multi_agent computed as True."""
        p = CapabilityProfile(
            zones_active=["input", "reasoning"],
            entry_points=["user input (input)"],
            confidence="medium",
            kc_subcodes=["KC1.1", "KC2.3"],
        )
        assert p.multi_agent is True
        assert "inter_agent" in p.zones_active

    def test_legacy_bool_fields_stripped_from_input(self):
        """Legacy boolean fields in input data are silently stripped."""
        p = CapabilityProfile(
            zones_active=["input", "reasoning"],
            has_persistent_memory=True,  # will be stripped
            multi_agent=True,            # will be stripped
            hitl=True,                   # will be stripped
            entry_points=["user input (input)"],
            confidence="medium",
            kc_subcodes=["KC1.1"],       # no flag-triggering codes
        )
        # Computed fields reflect KC codes, not the stripped input
        assert p.has_persistent_memory is False
        assert p.multi_agent is False
        assert p.hitl is False

    def test_computed_flags_in_model_dump(self):
        """Computed fields appear in model_dump output."""
        p = CapabilityProfile(
            zones_active=["input", "reasoning"],
            entry_points=["user input (input)"],
            confidence="medium",
            kc_subcodes=["KC1.1", "KC4.3", "KC2.3", "KCX-HITL"],
        )
        d = p.model_dump()
        assert d["has_persistent_memory"] is True
        assert d["multi_agent"] is True
        assert d["hitl"] is True
