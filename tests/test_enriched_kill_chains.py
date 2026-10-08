"""Canonical-chain semantic tests for the five historically enriched patterns.

Originally these patterns (bead 3vw9) carried legacy ``kill_chain`` enrichments.
After the canonical-chain migration they carry ``canonical_chain`` with exact
ATLAS mappings.  These tests validate canonical semantics — chain structure,
exact mappings, step provenance, and evidence — without restoring any legacy
``kill_chain`` field.
"""

from __future__ import annotations

import pytest

from asago_scenario_generator.data.loaders import load_attack_patterns
from asago_scenario_generator.models.attack_pattern_chain import AttackPattern

# The five historically enriched pattern IDs.  AP-T17-02 was retired in the
# canonical lineage (disposition=retire) and has no resulting live record.
ENRICHED_PATTERN_IDS = [
    "AP-T1-01",
    "AP-T17-01",
    "AP-T11-01",
    "AP-T11-02",
]

# Expected case-study provenance for each pattern (None = no case study).
EXPECTED_CASE_STUDIES = {
    "AP-T1-01": "AML.CS0040",
    "AP-T17-01": "AML.CS0041",
    "AP-T11-01": "AML.CS0052",
    "AP-T11-02": "AML.CS0047",
}

# Minimum expected canonical chain step counts.
MIN_CHAIN_STEPS = {
    "AP-T1-01": 5,
    "AP-T17-01": 5,
    "AP-T11-01": 5,
    "AP-T11-02": 4,
}


@pytest.fixture(scope="module")
def all_patterns():
    """Load all attack patterns once for the module."""
    return load_attack_patterns()


class TestEnrichedPatternsLoad:
    """Verify enriched patterns load correctly with canonical chains."""

    def test_all_enriched_patterns_present(self, all_patterns):
        """All 5 enriched pattern IDs exist in loaded patterns."""
        for pid in ENRICHED_PATTERN_IDS:
            assert pid in all_patterns, f"{pid} missing from loaded patterns"

    @pytest.mark.parametrize("pid", ENRICHED_PATTERN_IDS)
    def test_enriched_pattern_has_canonical_chain(self, all_patterns, pid):
        """Each enriched pattern has a canonical_chain, not a kill_chain."""
        pattern = all_patterns[pid]
        assert "canonical_chain" in pattern, f"{pid} missing canonical_chain"
        assert "kill_chain" not in pattern, f"{pid} still has legacy kill_chain"
        cc = pattern["canonical_chain"]
        assert len(cc["steps"]) > 0, f"{pid} has empty canonical_chain steps"

    @pytest.mark.parametrize("pid", ENRICHED_PATTERN_IDS)
    def test_enriched_pattern_has_no_evidence_field(self, all_patterns, pid):
        """Canonical patterns do not carry the legacy evidence field."""
        pattern = all_patterns[pid]
        assert "evidence" not in pattern, f"{pid} still has legacy evidence field"


class TestEnrichedPatternsValidate:
    """Verify enriched patterns pass canonical model validation."""

    @pytest.mark.parametrize("pid", ENRICHED_PATTERN_IDS)
    def test_pattern_validates(self, all_patterns, pid):
        """Each enriched pattern validates as a canonical AttackPattern."""
        validated = AttackPattern.model_validate(all_patterns[pid])
        assert validated.id == pid
        assert validated.canonical_chain is not None

    @pytest.mark.parametrize("pid", ENRICHED_PATTERN_IDS)
    def test_canonical_chain_minimum_steps(self, all_patterns, pid):
        """Each enriched pattern has at least the expected number of steps."""
        validated = AttackPattern.model_validate(all_patterns[pid])
        expected_min = MIN_CHAIN_STEPS[pid]
        actual = len(validated.canonical_chain.steps)
        assert actual >= expected_min, (
            f"{pid}: expected >= {expected_min} canonical chain steps, got {actual}"
        )


class TestCanonicalChainContent:
    """Verify canonical chain content is well-formed."""

    @pytest.mark.parametrize("pid", ENRICHED_PATTERN_IDS)
    def test_all_steps_have_step_ids(self, all_patterns, pid):
        """All canonical chain steps have non-empty step_id identifiers."""
        validated = AttackPattern.model_validate(all_patterns[pid])
        for step in validated.canonical_chain.steps:
            assert step.step_id.strip(), f"{pid} has a step with empty step_id"

    @pytest.mark.parametrize("pid", ENRICHED_PATTERN_IDS)
    def test_step_ids_are_unique(self, all_patterns, pid):
        """Canonical chain step_ids are unique within each pattern."""
        validated = AttackPattern.model_validate(all_patterns[pid])
        ids = [s.step_id for s in validated.canonical_chain.steps]
        assert len(ids) == len(set(ids)), f"{pid} has duplicate step_ids: {ids}"

    @pytest.mark.parametrize("pid", ENRICHED_PATTERN_IDS)
    def test_exact_mappings_use_valid_atlas_ids(self, all_patterns, pid):
        """All exact mappings in the canonical chain use valid AML.T IDs."""
        validated = AttackPattern.model_validate(all_patterns[pid])
        for mapping in validated.canonical_chain.mappings:
            if hasattr(mapping, "ids") and mapping.ids:
                for atlas_id in mapping.ids:
                    assert atlas_id.startswith("AML.T"), (
                        f"{pid} chain mapping has invalid technique: {atlas_id}"
                    )
        for step in validated.canonical_chain.steps:
            for mapping in step.mappings:
                if hasattr(mapping, "ids") and mapping.ids:
                    for atlas_id in mapping.ids:
                        assert atlas_id.startswith("AML.T"), (
                            f"{pid} step '{step.step_id}' has invalid technique: {atlas_id}"
                        )


class TestProvenanceContent:
    """Verify provenance references in canonical chains are correct."""

    @pytest.mark.parametrize("pid", ENRICHED_PATTERN_IDS)
    def test_expected_case_study_referenced(self, all_patterns, pid):
        """Each pattern's canonical chain references the expected case study."""
        expected = EXPECTED_CASE_STUDIES[pid]
        if expected is None:
            pytest.skip(f"{pid} has no expected case study")
        pattern = all_patterns[pid]
        cc = pattern["canonical_chain"]
        # Collect all reference_ids from all steps' provenance
        ref_ids = set()
        for step in cc.get("steps", []):
            for ref in step.get("provenance", {}).get("references", []):
                ref_ids.add(ref.get("reference_id", ""))
        # Reference IDs may include step suffixes (e.g. "AML.CS0041 S03")
        assert any(expected in rid for rid in ref_ids), (
            f"{pid}: expected case study '{expected}' not referenced in "
            f"canonical chain provenance (found: {ref_ids})"
        )


class TestExistingFieldsPreserved:
    """Verify that core fields were not modified during canonical migration."""

    @pytest.mark.parametrize("pid", ENRICHED_PATTERN_IDS)
    def test_core_fields_present(self, all_patterns, pid):
        """Core fields (id, threat_id, name, description) are intact."""
        pattern = all_patterns[pid]
        assert pattern["id"] == pid
        assert "threat_id" in pattern
        assert "name" in pattern
        assert len(pattern["name"]) > 0
        assert "description" in pattern
        assert len(pattern["description"]) > 0

    @pytest.mark.parametrize("pid", ENRICHED_PATTERN_IDS)
    def test_prerequisite_capabilities_present(self, all_patterns, pid):
        """prerequisite_capabilities field is preserved."""
        pattern = all_patterns[pid]
        assert "prerequisite_capabilities" in pattern
        assert "min_zones" in pattern["prerequisite_capabilities"]

    def test_non_enriched_patterns_still_valid(self, all_patterns):
        """Patterns not in the enrichment set still pass canonical validation."""
        for pid, pattern in all_patterns.items():
            if pid not in ENRICHED_PATTERN_IDS:
                validated = AttackPattern.model_validate(pattern)
                assert validated.id == pid
