"""Tests for KCX (asago-scenario-generator extension) sub-codes.

KCX-prefixed codes are asago-scenario-generator-specific extensions — NOT from OWASP.
They gate attack patterns that require structural privilege infrastructure
most AI systems lack.

Covers:
  - KCX codes pass the kc_subcodes validator on both models
  - KCX codes in attack pattern prerequisites cause filtering
  - KCX codes in profile allow T3 patterns through gating
  - KCX codes coexist with standard KC codes
  - Unknown non-KCX codes still rejected
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from asago_scenario_generator.data.threat_gating import (
    _evaluate_prerequisite_capabilities,
    _filter_attack_patterns,
)
from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    KC_SUBCODE_NAMES,
    KCX_PREFIX,
    KCX_SUBCODES,
    Stage1Profile,
    ToolInventoryEntry,
    VALID_KC_SUBCODES,
)
from tests.test_kc_subcodes import _base_stage1_data


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _base_profile_data(**overrides) -> dict:
    """Minimal valid CapabilityProfile payload."""
    data = {
        "zones_active": ["input", "reasoning", "tool_execution"],
        "entry_points": ["user input (input)"],
        "confidence": "high",
        "kc_subcodes": ["KC1.1", "KC6.1.1"],
        "tool_inventory": [{"name": "test_tool", "description": "A test tool"}],
    }
    data.update(overrides)
    return data


def _make_profile(
    *,
    kc_subcodes: list[str] | None = None,
) -> CapabilityProfile:
    """Build a CapabilityProfile with sensible defaults for testing."""
    if kc_subcodes is None:
        kc_subcodes = ["KC1.1", "KC6.1.1"]
    kw = {}
    if any(c.startswith("KC5.") or c.startswith("KC6.") for c in kc_subcodes):
        kw["tool_inventory"] = [
            ToolInventoryEntry(name="test_tool", description="A test tool")
        ]
    return CapabilityProfile(
        zones_active=["input", "reasoning"],
        entry_points=["user input (zone 1)"],
        confidence="medium",
        kc_subcodes=kc_subcodes,
        **kw,
    )


# Synthetic T3 attack patterns matching real YAML structure

_AP_T3_01 = {
    "id": "AP-T3-01",
    "threat_id": "T3",
    "name": "Temporary privilege retention via misconfiguration exploitation",
    "description": "...",
    "prerequisite_capabilities": {
        "min_zones": ["input", "reasoning", "tool_execution"],
        "kc_requires": {
            "all": ["KCX-PRIV"],
            "any": ["KC6.1.2", "KC6.2.2", "KC6.3.2", "KC6.5"],
        },
    },
}

_AP_T3_02 = {
    "id": "AP-T3-02",
    "threat_id": "T3",
    "name": "Cross-boundary authorization escalation",
    "description": "...",
    "prerequisite_capabilities": {
        "min_zones": ["input", "reasoning", "tool_execution"],
        "kc_requires": {
            "any": ["KC6.1.2", "KC6.2.2", "KC6.5", "KCX-XAUTH"],
        },
    },
}


# ---------------------------------------------------------------------------
# KCX validation on CapabilityProfile
# ---------------------------------------------------------------------------


class TestKCXValidation:
    """KCX-prefixed codes pass the kc_subcodes validator."""

    @pytest.mark.parametrize(
        "codes",
        [
            ["KC1.1", "KCX-PRIV"],
            ["KC1.1", "KCX-XAUTH"],
            ["KC1.1", "KCX-PRIV", "KCX-XAUTH"],
            ["KC1.1", "KC6.1.2", "KCX-PRIV", "KC6.2.2"],
            ["KC1.1", "KCX-FUTURE"],  # any KCX- prefixed code: future extensibility
        ],
        ids=["priv", "xauth", "both", "mixed_with_standard", "arbitrary_kcx_prefix"],
    )
    def test_kcx_codes_accepted(self, codes):
        p = CapabilityProfile(**_base_profile_data(kc_subcodes=codes))
        assert set(codes) == set(p.kc_subcodes)

    def test_invalid_non_kcx_code_still_rejected(self):
        """Non-KCX, non-standard codes are still rejected."""
        with pytest.raises(ValidationError, match="Invalid KC sub-code"):
            CapabilityProfile(**_base_profile_data(kc_subcodes=["KC1.1", "KC99.1"]))

    def test_kcx_codes_sorted_with_standard(self):
        """KCX codes sort correctly alongside standard KC codes."""
        codes = ["KCX-PRIV", "KC1.1", "KC6.1.1"]
        p = CapabilityProfile(**_base_profile_data(kc_subcodes=codes))
        assert p.kc_subcodes == sorted(set(codes))

    def test_kcx_codes_deduplicated(self):
        codes = ["KCX-PRIV", "KC1.1", "KCX-PRIV"]
        p = CapabilityProfile(**_base_profile_data(kc_subcodes=codes))
        assert p.kc_subcodes.count("KCX-PRIV") == 1


# ---------------------------------------------------------------------------
# KCX validation on Stage1Profile
# ---------------------------------------------------------------------------


class TestKCXStage1Validation:
    """KCX codes pass Stage1Profile validation and promotion."""

    def test_stage1_accepts_kcx_codes(self):
        s = Stage1Profile(**_base_stage1_data(kc_subcodes=["KC1.1", "KCX-PRIV"]))
        assert "KCX-PRIV" in s.kc_subcodes

    def test_stage1_to_capability_profile_preserves_kcx(self):
        s = Stage1Profile(
            **_base_stage1_data(kc_subcodes=["KC1.1", "KCX-PRIV", "KCX-XAUTH"])
        )
        p = s.to_capability_profile()
        assert "KCX-PRIV" in p.kc_subcodes
        assert "KCX-XAUTH" in p.kc_subcodes

    def test_stage1_rejects_invalid_non_kcx(self):
        with pytest.raises(ValidationError, match="Invalid KC sub-code"):
            Stage1Profile(**_base_stage1_data(kc_subcodes=["KC1.1", "INVALID"]))


# ---------------------------------------------------------------------------
# KCX gating: T3 patterns filtered when profile lacks KCX codes
# ---------------------------------------------------------------------------


class TestKCXGatingFiltering:
    """KCX codes in attack pattern prerequisites cause filtering."""

    @pytest.mark.parametrize(
        ("pattern", "codes", "survives"),
        [
            # AP-T3-01 needs KCX-PRIV (all) AND one of KC6.1.2/6.2.2/6.3.2/6.5 (any).
            (_AP_T3_01, ["KC1.1", "KC6.1.1"], False),  # limited API: neither
            # Headline fix for phantom privilege scenarios on static-capability systems.
            (_AP_T3_01, ["KC1.1", "KC6.1.2"], False),  # a KC6 code, no KCX-PRIV
            (_AP_T3_01, ["KC1.1", "KCX-PRIV"], False),  # KCX-PRIV, no KC6 code
            (_AP_T3_01, ["KC1.1", "KC6.1.2", "KCX-PRIV"], True),
            # AP-T3-02 needs KCX-XAUTH or one of KC6.1.2/6.2.2/6.5.
            (_AP_T3_02, ["KC1.1", "KC6.1.1"], False),
            (_AP_T3_02, ["KC1.1", "KC6.1.1", "KCX-XAUTH"], True),
        ],
        ids=[
            "t3_01_neither",
            "t3_01_kc6_without_priv",
            "t3_01_priv_without_kc6",
            "t3_01_both",
            "t3_02_neither",
            "t3_02_xauth",
        ],
    )
    def test_t3_pattern_gating(self, pattern, codes, survives):
        result = _filter_attack_patterns([pattern], _make_profile(kc_subcodes=codes))
        assert (pattern["id"] in result) is survives


# ---------------------------------------------------------------------------
# KCX gating: prerequisite evaluation
# ---------------------------------------------------------------------------


class TestKCXPrerequisiteEvaluation:
    """Verify kc_requires any/all logic works with KCX codes."""

    @pytest.mark.parametrize(
        ("codes", "kc_requires", "expected"),
        [
            (["KC1.1", "KCX-PRIV"], {"any": ["KCX-PRIV", "KC6.2.2"]}, True),
            (["KC1.1", "KC6.1.1"], {"any": ["KCX-PRIV"]}, False),
            (
                ["KC1.1", "KC2.3", "KCX-XAUTH"],
                {"all": ["KC2.3", "KCX-XAUTH"]},
                True,
            ),
            (["KC1.1", "KC2.3"], {"all": ["KC2.3", "KCX-XAUTH"]}, False),
        ],
        ids=["any_passes", "any_fails", "all_passes", "all_fails"],
    )
    def test_kc_requires_with_kcx_codes(self, codes, kc_requires, expected):
        profile = _make_profile(kc_subcodes=codes)
        prereqs = {"kc_requires": kc_requires}
        assert _evaluate_prerequisite_capabilities(prereqs, profile) is expected


# ---------------------------------------------------------------------------
# KCX constants
# ---------------------------------------------------------------------------


class TestKCXConstants:
    """Verify KCX constants are properly defined."""

    def test_kcx_prefix_value(self):
        assert KCX_PREFIX == "KCX-"

    def test_kcx_subcodes_are_exactly_the_nine_extensions(self):
        """Set equality catches an added or removed code; sorting catches duplicates."""
        assert sorted(KCX_SUBCODES) == sorted(
            [
                "KCX-PRIV",
                "KCX-XAUTH",
                "KCX-PMEM",
                "KCX-SHMEM",
                "KCX-MAGENT",
                "KCX-VSTORE",
                "KCX-HITL",
                "KCX-AUDIT",
                "KCX-PSTATE",
            ]
        )

    def test_kcx_subcodes_not_in_valid_kc_subcodes(self):
        """KCX codes are NOT in the OWASP VALID_KC_SUBCODES set."""
        for code in KCX_SUBCODES:
            assert code not in VALID_KC_SUBCODES

    def test_all_kcx_codes_start_with_prefix(self):
        for code in KCX_SUBCODES:
            assert code.startswith(KCX_PREFIX)


# ---------------------------------------------------------------------------
# KC_SUBCODE_NAMES constants
# ---------------------------------------------------------------------------


class TestKCSubcodeNames:
    """Verify KC_SUBCODE_NAMES covers all standard KC sub-codes."""

    def test_names_cover_exactly_the_valid_kc_subcodes(self):
        """Every standard KC sub-code has a name, and no other key exists."""
        missing = VALID_KC_SUBCODES - set(KC_SUBCODE_NAMES)
        extra = set(KC_SUBCODE_NAMES) - VALID_KC_SUBCODES
        assert (missing, extra) == (set(), set())

    def test_names_are_nonempty_strings(self):
        for code, name in KC_SUBCODE_NAMES.items():
            assert isinstance(name, str) and len(name) > 0, (
                f"{code} has empty or non-string name"
            )
