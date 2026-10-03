"""Tests for the KC sub-code to threat mapping YAML data file."""

from __future__ import annotations

import pytest

from asago_scenario_generator.data.loaders import load_kc_threat_mapping
from asago_scenario_generator.models.capability_profile import VALID_KC_SUBCODES


VALID_THREAT_IDS = frozenset(f"T{i}" for i in range(1, 18))


@pytest.fixture(scope="module")
def mapping():
    return load_kc_threat_mapping()


class TestMappingStructure:
    def test_loads_successfully(self, mapping):
        assert mapping is not None
        assert isinstance(mapping, dict)

    def test_has_required_sections(self, mapping):
        for key in (
            "metadata",
            "kc_subcodes",
            "kc_to_threats",
            "threat_to_kc_subcodes",
            "hitl",
        ):
            assert key in mapping, f"Missing required section: {key}"

    def test_metadata_has_version(self, mapping):
        assert "version" in mapping["metadata"]
        assert "source" in mapping["metadata"]


class TestForwardIndex:
    def test_covers_all_subcodes(self, mapping):
        fwd = mapping["kc_to_threats"]
        detail_codes = {e["kc_subcode"] for e in mapping["kc_subcodes"]}
        assert set(fwd.keys()) == detail_codes

    def test_all_kc_subcodes_are_valid(self, mapping):
        fwd = mapping["kc_to_threats"]
        invalid = set(fwd.keys()) - VALID_KC_SUBCODES
        assert not invalid, f"Invalid KC sub-codes in forward index: {invalid}"

    def test_all_threat_ids_are_valid(self, mapping):
        fwd = mapping["kc_to_threats"]
        for kc, threats in fwd.items():
            invalid = set(threats) - VALID_THREAT_IDS
            assert not invalid, f"{kc} has invalid threat IDs: {invalid}"

    def test_every_subcode_has_at_least_one_threat(self, mapping):
        fwd = mapping["kc_to_threats"]
        for kc, threats in fwd.items():
            assert len(threats) > 0, f"{kc} has no threat mappings"


class TestReverseIndex:
    def test_covers_expected_threats(self, mapping):
        rev = mapping["threat_to_kc_subcodes"]
        missing = VALID_THREAT_IDS - set(rev.keys())
        assert not missing, f"Missing threats in reverse index: {missing}"

    def test_all_kc_subcodes_in_reverse_are_valid(self, mapping):
        rev = mapping["threat_to_kc_subcodes"]
        for tid, codes in rev.items():
            invalid = set(codes) - VALID_KC_SUBCODES
            assert not invalid, f"{tid} has invalid KC sub-codes: {invalid}"


class TestConsistency:
    def test_forward_reverse_consistency(self, mapping):
        """Every (KC, T) pair in the forward index must appear in the reverse."""
        fwd = mapping["kc_to_threats"]
        rev = mapping["threat_to_kc_subcodes"]

        for kc, threats in fwd.items():
            for tid in threats:
                assert kc in rev.get(tid, []), (
                    f"Forward has {kc} -> {tid} but reverse {tid} does not include {kc}"
                )

    def test_reverse_forward_consistency(self, mapping):
        """Every (T, KC) pair in the reverse index must appear in the forward."""
        fwd = mapping["kc_to_threats"]
        rev = mapping["threat_to_kc_subcodes"]

        for tid, codes in rev.items():
            for kc in codes:
                assert tid in fwd.get(kc, []), (
                    f"Reverse has {tid} -> {kc} but forward {kc} does not include {tid}"
                )

    def test_detailed_list_matches_forward_index(self, mapping):
        """The kc_subcodes detail list should match the kc_to_threats index."""
        fwd = mapping["kc_to_threats"]
        for entry in mapping["kc_subcodes"]:
            kc = entry["kc_subcode"]
            assert kc in fwd, f"{kc} in detail list but not in forward index"
            assert set(entry["threat_ids"]) == set(fwd[kc]), (
                f"{kc} detail list threats {entry['threat_ids']} "
                f"!= forward index {fwd[kc]}"
            )


class TestHITL:
    def test_hitl_has_t10(self, mapping):
        assert "T10" in mapping["hitl"]["threat_ids"]
