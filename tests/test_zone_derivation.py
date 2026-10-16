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
    derive_zones_from_kc,
)
import pytest
from pydantic import ValidationError

_TEST_TOOL_INVENTORY = [ToolInventoryEntry(name="test_tool", description="A test tool")]


# ---------------------------------------------------------------------------
# derive_zones_from_kc unit tests
# ---------------------------------------------------------------------------


class TestDeriveZonesBasic:
    """Minimal KC set produces baseline zones."""

    def test_derive_zones_empty_list(self):
        """Empty KC list still returns baseline zones."""
        result = derive_zones_from_kc([])
        assert result == ["input", "reasoning"]


class TestDeriveZonesFull:
    """All zones active with appropriate KC codes."""

    def test_derive_zones_full(self):
        """All four optional zones activated by appropriate codes."""
        result = derive_zones_from_kc(
            [
                "KC1.1",  # baseline
                "KC2.3",  # inter_agent
                "KC4.4",  # memory
                "KC5.1",  # tool_execution
            ]
        )
        assert result == [
            "input",
            "inter_agent",
            "memory",
            "reasoning",
            "tool_execution",
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
            / "data"
            / "taxonomies"
            / "mappings"
            / "kc-threat-mapping.yaml"
        )
        with open(mapping_path) as f:
            taxonomy = yaml.safe_load(f)

        # Expected zone activation per KC category
        expected_extra_zones: dict[str, set[str]] = {
            "KC1.": set(),  # baseline only
            "KC2.1": set(),  # baseline only
            "KC2.2": set(),  # baseline only
            "KC2.3": {"inter_agent"},
            "KC3.": set(),  # baseline only
            "KC4.1": set(),  # session-only, no zone
            "KC4.2": set(),  # session-only, no zone
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

    @pytest.mark.parametrize(
        ("kc_subcodes", "stated_flags", "expected_zones", "expected_flags"),
        [
            pytest.param(
                ["KC1.1", "KC4.4"],
                (False, False, False),
                ["input", "memory", "reasoning"],
                (True, False, False),
                id="cross_session_memory_corrects_persistent_memory",
            ),
            pytest.param(
                ["KC1.1", "KC2.3"],
                (False, False, False),
                ["input", "inter_agent", "reasoning"],
                (False, True, False),
                id="peer_agents_correct_multi_agent",
            ),
            pytest.param(
                ["KC1.1", "KC2.1", "KC4.1"],
                (True, True, True),
                ["input", "reasoning"],
                (False, False, False),
                id="session_memory_and_workflows_clear_stated_flags",
            ),
            pytest.param(
                ["KC1.1", "KC2.3", "KC4.4", "KC5.1"],
                (False, False, True),
                ["input", "inter_agent", "memory", "reasoning", "tool_execution"],
                (True, True, False),
                id="full_set_corrects_every_stated_flag",
            ),
        ],
    )
    def test_promotion_derives_zones_and_flags_from_kc_subcodes(
        self, kc_subcodes, stated_flags, expected_zones, expected_flags
    ):
        """Stated flags are replaced by the flags the KC sub-codes imply."""
        persistent_memory, multi_agent, hitl = stated_flags
        s = Stage1Profile(
            has_persistent_memory=persistent_memory,
            multi_agent=multi_agent,
            hitl=hitl,
            entry_points=["user input (input)"],
            confidence="medium",
            kc_subcodes=kc_subcodes,
            tool_inventory=_TEST_TOOL_INVENTORY,
        )
        p = s.to_capability_profile()
        assert p.zones_active == expected_zones
        assert (p.has_persistent_memory, p.multi_agent, p.hitl) == expected_flags

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

        with pytest.raises(ValidationError, match="kc_subcodes"):
            s.to_capability_profile()


# ---------------------------------------------------------------------------
# CapabilityProfile zone derivation
# ---------------------------------------------------------------------------


class TestCapabilityProfileZoneDerivation:
    """CapabilityProfile derives zones_active from kc_subcodes."""

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

    @pytest.mark.parametrize(
        ("code", "expected"),
        [
            pytest.param("KC4.3", True, id="kc4_3_sets_persistent_memory"),
            pytest.param("KC4.4", True, id="kc4_4_sets_persistent_memory"),
            pytest.param("KC4.5", True, id="kc4_5_sets_persistent_memory"),
            pytest.param("KC4.6", True, id="kc4_6_sets_persistent_memory"),
            pytest.param("KCX-PMEM", True, id="kcx_pmem_sets_persistent_memory"),
            pytest.param("KC4.1", False, id="kc4_1_no_persistent_memory"),
            pytest.param("KC4.2", False, id="kc4_2_no_persistent_memory"),
        ],
    )
    def test_persistent_memory_flag(self, code, expected):
        """Cross-session and cross-user memory codes set has_persistent_memory."""
        p = self._make(["KC1.1", code])
        assert p.has_persistent_memory is expected

    # --- multi_agent ---

    @pytest.mark.parametrize(
        ("code", "expected"),
        [
            pytest.param("KC2.3", True, id="kc2_3_sets_multi_agent"),
            pytest.param("KCX-MAGENT", True, id="kcx_magent_sets_multi_agent"),
            pytest.param("KC2.1", False, id="kc2_1_no_multi_agent"),
            pytest.param("KC2.2", False, id="kc2_2_no_multi_agent"),
        ],
    )
    def test_multi_agent_flag(self, code, expected):
        """KC2.3 and KCX-MAGENT set multi_agent; KC2.1 and KC2.2 do not."""
        p = self._make(["KC1.1", code])
        assert p.multi_agent is expected

    # --- hitl ---

    @pytest.mark.parametrize(
        ("codes", "expected"),
        [
            pytest.param(["KC1.1", "KCX-HITL"], True, id="kcx_hitl_sets_hitl"),
            pytest.param(["KC1.1"], False, id="no_kcx_hitl_no_hitl"),
        ],
    )
    def test_hitl_flag(self, codes, expected):
        """KCX-HITL sets hitl; without it hitl is False."""
        p = self._make(codes)
        assert p.hitl is expected

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
# Flag derivation on CapabilityProfile (computed properties)
# ---------------------------------------------------------------------------


class TestCapabilityProfileFlagDerivation:
    """CapabilityProfile computed boolean flags from kc_subcodes."""

    def test_legacy_bool_fields_stripped_from_input(self):
        """Legacy boolean fields in input data are silently stripped."""
        p = CapabilityProfile(
            zones_active=["input", "reasoning"],
            has_persistent_memory=True,  # will be stripped
            multi_agent=True,  # will be stripped
            hitl=True,  # will be stripped
            entry_points=["user input (input)"],
            confidence="medium",
            kc_subcodes=["KC1.1"],  # no flag-triggering codes
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
