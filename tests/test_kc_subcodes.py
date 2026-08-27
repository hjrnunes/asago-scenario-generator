"""Tests for KC sub-code field on CapabilityProfile and Stage1Profile."""

from __future__ import annotations

import logging

import pytest
from pydantic import ValidationError

from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    Stage1Profile,
    ToolInventoryEntry,
    VALID_KC_SUBCODES,
)

_LOGGER = "asago_scenario_generator.models.capability_profile"


def _base_profile_data(**overrides) -> dict:
    """Minimal valid CapabilityProfile payload."""
    data = {
        "zones_active": ["input", "reasoning", "tool_execution"],
        "entry_points": ["user input (input)"],
        "confidence": "high",
        "kc_subcodes": ["KC1.1", "KC6.1.1"],
        "tool_inventory": [ToolInventoryEntry(name="test_tool", description="A test tool")],
    }
    data.update(overrides)
    return data


def _base_stage1_data(**overrides) -> dict:
    """Minimal valid Stage1Profile payload (no zones_active field)."""
    data = {
        "has_persistent_memory": False,
        "multi_agent": False,
        "hitl": False,
        "entry_points": ["user input (input)"],
        "confidence": "high",
    }
    data.update(overrides)
    return data


class TestKCSubcodesValidation:

    def test_valid_kc_subcodes_accepted(self):
        codes = ["KC1.1", "KC4.3", "KC6.1.1"]
        p = CapabilityProfile(**_base_profile_data(kc_subcodes=codes))
        assert set(p.kc_subcodes) == set(codes)

    def test_invalid_kc_subcode_rejected(self):
        with pytest.raises(ValidationError, match="Invalid KC sub-code"):
            CapabilityProfile(**_base_profile_data(kc_subcodes=["KC99.1"]))

    def test_empty_kc_subcodes_rejected(self):
        """kc_subcodes is required with min_length=1."""
        with pytest.raises(ValidationError, match="kc_subcodes"):
            CapabilityProfile(**_base_profile_data(kc_subcodes=[]))

    def test_missing_kc_subcodes_rejected(self):
        """kc_subcodes is a required field."""
        data = _base_profile_data()
        del data["kc_subcodes"]
        with pytest.raises(ValidationError, match="kc_subcodes"):
            CapabilityProfile(**data)

    def test_kc_subcodes_deduplicated_and_sorted(self):
        codes = ["KC6.1.1", "KC1.1", "KC6.1.1", "KC1.1"]
        p = CapabilityProfile(**_base_profile_data(kc_subcodes=codes))
        assert p.kc_subcodes == ["KC1.1", "KC6.1.1"]

    def test_all_valid_subcodes_accepted(self):
        p = CapabilityProfile(
            **_base_profile_data(kc_subcodes=list(VALID_KC_SUBCODES))
        )
        assert set(p.kc_subcodes) == VALID_KC_SUBCODES

    def test_mixed_valid_and_invalid_rejected(self):
        with pytest.raises(ValidationError, match="Invalid KC sub-code"):
            CapabilityProfile(
                **_base_profile_data(kc_subcodes=["KC1.1", "KC0.0"])
            )


class TestStage1ProfileKCSubcodes:

    def test_stage1_accepts_kc_subcodes(self):
        codes = ["KC1.1", "KC5.2", "KC6.1.1"]
        s = Stage1Profile(**_base_stage1_data(kc_subcodes=codes))
        assert set(s.kc_subcodes) == set(codes)

    def test_stage1_to_capability_profile_preserves_kc_subcodes(self):
        codes = ["KC1.1", "KC4.3", "KC6.2.2"]
        s = Stage1Profile(**_base_stage1_data(
            kc_subcodes=codes,
            tool_inventory=[ToolInventoryEntry(name="test_tool", description="A test tool")],
        ))
        p = s.to_capability_profile()
        assert p.kc_subcodes == sorted(codes)

    def test_stage1_default_kc_subcodes(self):
        s = Stage1Profile(**_base_stage1_data())
        assert s.kc_subcodes == []

    def test_stage1_empty_kc_to_capability_profile_rejected(self):
        """Stage1Profile with empty kc_subcodes cannot promote to CapabilityProfile."""
        s = Stage1Profile(**_base_stage1_data())
        with pytest.raises(ValidationError, match="kc_subcodes"):
            s.to_capability_profile()

    def test_stage1_invalid_kc_subcode_rejected(self):
        with pytest.raises(ValidationError, match="Invalid KC sub-code"):
            Stage1Profile(**_base_stage1_data(kc_subcodes=["INVALID"]))


class TestBackwardCompatibility:

    def test_legacy_bool_fields_stripped(self):
        """Legacy boolean fields are silently stripped from input."""
        p = CapabilityProfile(**_base_profile_data(
            has_persistent_memory=True,
            multi_agent=True,
            hitl=True,
        ))
        # Flags are computed from kc_subcodes, not from input
        # Default kc_subcodes=["KC1.1", "KC6.1.1"] has no flag-triggering codes
        assert p.has_persistent_memory is False
        assert p.multi_agent is False
        assert p.hitl is False

    def test_serialization_roundtrip(self):
        codes = ["KC1.1", "KC2.3", "KC6.4"]
        p = CapabilityProfile(**_base_profile_data(kc_subcodes=codes))
        dumped = p.model_dump(mode="json")
        p2 = CapabilityProfile(**dumped)
        assert p2.kc_subcodes == p.kc_subcodes
        assert p2.zones_active == p.zones_active
        assert p2.multi_agent == p.multi_agent

    def test_serialization_roundtrip_preserves_computed_flags(self):
        """model_dump includes computed fields; roundtrip still works."""
        codes = ["KC1.1", "KC4.3", "KC2.3", "KCX-HITL", "KC6.1.1"]
        p = CapabilityProfile(**_base_profile_data(kc_subcodes=codes))
        dumped = p.model_dump(mode="json")
        # dumped contains has_persistent_memory, multi_agent, hitl
        assert dumped["has_persistent_memory"] is True
        # Roundtrip: legacy fields are stripped, computed from kc_subcodes
        p2 = CapabilityProfile(**dumped)
        assert p2.has_persistent_memory is True
        assert p2.multi_agent is True
        assert p2.hitl is True

    def test_roundtrip_own_output_emits_no_warning(self, caplog):
        """Reloading the project's own output raises no deprecation noise.

        The serialized output contains the computed booleans; they match
        the kc-derived values, so the strip is silent (issue #10).
        """
        codes = ["KC1.1", "KC4.3", "KC2.3", "KCX-HITL", "KC6.1.1"]
        p = CapabilityProfile(**_base_profile_data(kc_subcodes=codes))
        with caplog.at_level(logging.WARNING, logger=_LOGGER):
            CapabilityProfile(**p.model_dump(mode="json"))
        assert not any(
            "Stripped deprecated fields" in record.message
            for record in caplog.records
        )

    def test_conflicting_legacy_values_still_warn(self, caplog):
        """A legacy value disagreeing with the computed flag warns and is stripped."""
        codes = ["KC1.1", "KCX-HITL"]  # KCX-HITL computes hitl=True
        with caplog.at_level(logging.WARNING, logger=_LOGGER):
            p = CapabilityProfile(
                **_base_profile_data(kc_subcodes=codes, hitl=False)
            )
        assert p.hitl is True
        assert any(
            "Stripped deprecated fields" in record.message
            for record in caplog.records
        )

    def test_legacy_values_without_kc_evidence_still_warn(self, caplog):
        """True legacy values with no supporting KC sub-codes warn (conflict)."""
        with caplog.at_level(logging.WARNING, logger=_LOGGER):
            p = CapabilityProfile(**_base_profile_data(
                kc_subcodes=["KC1.1"],
                multi_agent=True,
            ))
        assert p.multi_agent is False
        assert any(
            "Stripped deprecated fields" in record.message
            for record in caplog.records
        )
