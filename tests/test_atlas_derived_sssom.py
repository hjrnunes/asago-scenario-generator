"""Tests for ATLAS-derived SSSOM provenance entries (bead r446).

Validates that:
- All 5 ATLAS-derived patterns have SSSOM entries that parse correctly
- Each pattern has at least 2 entries (distinctive techniques)
- No duplicate entries exist across the file
- All entries reference techniques from their pattern's kill chain
- Generic techniques (AML.T0065, AML.T0051) are excluded
"""

from __future__ import annotations

from collections import Counter

import pytest

from asago_scenario_generator.data.loaders import load_attack_patterns
from asago_scenario_generator.data.sssom import SSSOMMapping, load_sssom

# Path to the new SSSOM file
_SSSOM_PATH = "data/taxonomies/attack-patterns/attack-patterns-atlas-derived.sssom.tsv"

# The 5 ATLAS-derived pattern IDs
ATLAS_DERIVED_IDS = ["AP-T6-06", "AP-T11-05", "AP-T17-03", "AP-T1-06", "AP-T3-04"]

# Expected distinctive technique mappings per pattern
EXPECTED_TECHNIQUES: dict[str, list[str]] = {
    "AP-T6-06": ["AML.T0095", "AML.T0069", "AML.T0081", "AML.T0108"],
    "AP-T11-05": ["AML.T0017", "AML.T0100", "AML.T0053"],
    "AP-T17-03": ["AML.T0073", "AML.T0104", "AML.T0109", "AML.T0086"],
    "AP-T1-06": ["AML.T0093", "AML.T0070", "AML.T0085", "AML.T0077"],
    "AP-T3-04": ["AML.T0000", "AML.T0049", "AML.T0083"],
}

# Generic techniques that should NOT appear (per abstraction strategy 7.5)
GENERIC_TECHNIQUES = {"AML.T0065", "AML.T0051"}


@pytest.fixture(scope="module")
def sssom_mappings() -> list[SSSOMMapping]:
    """Load SSSOM mappings from the new ATLAS-derived file."""
    return load_sssom(_SSSOM_PATH)


@pytest.fixture(scope="module")
def all_patterns() -> dict[str, dict]:
    """Load all attack patterns."""
    return load_attack_patterns()


class TestAtlasDerivedSSSOMParsing:
    """All entries in the new SSSOM file parse correctly."""

    def test_file_loads_without_error(self, sssom_mappings: list[SSSOMMapping]):
        """The SSSOM file parses without exceptions."""
        assert len(sssom_mappings) > 0

    def test_total_entry_count(self, sssom_mappings: list[SSSOMMapping]):
        """File contains exactly 18 entries (4+3+4+4+3)."""
        assert len(sssom_mappings) == 18

    def test_all_entries_are_sssom_mappings(self, sssom_mappings: list[SSSOMMapping]):
        """Every parsed entry is a valid SSSOMMapping instance."""
        for m in sssom_mappings:
            assert isinstance(m, SSSOMMapping)

    def test_all_entries_have_correct_subject_source(
        self, sssom_mappings: list[SSSOMMapping]
    ):
        """All entries use 'asago-scenario-generator' as subject_source."""
        for m in sssom_mappings:
            assert m.subject_source == "asago-scenario-generator", (
                f"Entry {m.subject_id}->{m.object_id} has wrong subject_source: "
                f"{m.subject_source}"
            )

    def test_all_entries_have_correct_object_source(
        self, sssom_mappings: list[SSSOMMapping]
    ):
        """All entries use 'mitre-atlas' as object_source."""
        for m in sssom_mappings:
            assert m.object_source == "mitre-atlas", (
                f"Entry {m.subject_id}->{m.object_id} has wrong object_source: "
                f"{m.object_source}"
            )

    def test_all_entries_have_correct_predicate(
        self, sssom_mappings: list[SSSOMMapping]
    ):
        """All entries use 'skos:relatedMatch' predicate."""
        for m in sssom_mappings:
            assert m.predicate_id == "skos:relatedMatch"

    def test_all_entries_have_correct_justification(
        self, sssom_mappings: list[SSSOMMapping]
    ):
        """All entries use 'semapv:ManualMappingCuration' justification."""
        for m in sssom_mappings:
            assert m.mapping_justification == "semapv:ManualMappingCuration"


class TestAtlasDerivedSSSOMCoverage:
    """Each ATLAS-derived pattern has sufficient SSSOM entries."""

    @pytest.mark.parametrize("pid", ATLAS_DERIVED_IDS)
    def test_pattern_has_at_least_two_entries(
        self, sssom_mappings: list[SSSOMMapping], pid: str
    ):
        """Each pattern has at least 2 SSSOM entries."""
        entries = [m for m in sssom_mappings if m.subject_id == pid]
        assert len(entries) >= 2, (
            f"{pid} has only {len(entries)} SSSOM entries, expected >= 2"
        )

    @pytest.mark.parametrize("pid", ATLAS_DERIVED_IDS)
    def test_pattern_has_at_most_four_entries(
        self, sssom_mappings: list[SSSOMMapping], pid: str
    ):
        """Each pattern has at most 4 SSSOM entries (per strategy)."""
        entries = [m for m in sssom_mappings if m.subject_id == pid]
        assert len(entries) <= 4, (
            f"{pid} has {len(entries)} SSSOM entries, expected <= 4"
        )

    @pytest.mark.parametrize("pid", ATLAS_DERIVED_IDS)
    def test_expected_techniques_present(
        self, sssom_mappings: list[SSSOMMapping], pid: str
    ):
        """Each pattern maps to the expected distinctive techniques."""
        mapped_techniques = {m.object_id for m in sssom_mappings if m.subject_id == pid}
        expected = set(EXPECTED_TECHNIQUES[pid])
        assert mapped_techniques == expected, (
            f"{pid}: expected techniques {expected}, got {mapped_techniques}"
        )


class TestNoGenericTechniques:
    """Generic techniques should not appear in the ATLAS-derived SSSOM."""

    def test_no_prompt_crafting(self, sssom_mappings: list[SSSOMMapping]):
        """AML.T0065 (Prompt Crafting) should not appear."""
        technique_ids = {m.object_id for m in sssom_mappings}
        assert "AML.T0065" not in technique_ids, (
            "Generic technique AML.T0065 (Prompt Crafting) should not be in "
            "ATLAS-derived SSSOM entries"
        )

    def test_no_prompt_injection(self, sssom_mappings: list[SSSOMMapping]):
        """AML.T0051 (LLM Prompt Injection) should not appear."""
        technique_ids = {m.object_id for m in sssom_mappings}
        assert "AML.T0051" not in technique_ids, (
            "Generic technique AML.T0051 (LLM Prompt Injection) should not "
            "be in ATLAS-derived SSSOM entries"
        )


class TestNoDuplicateEntries:
    """No duplicate entries exist in the file."""

    def test_no_exact_duplicates(self, sssom_mappings: list[SSSOMMapping]):
        """No two entries share the same (subject_id, object_id) pair."""
        pairs = [(m.subject_id, m.object_id) for m in sssom_mappings]
        counter = Counter(pairs)
        duplicates = {pair: count for pair, count in counter.items() if count > 1}
        assert not duplicates, f"Duplicate SSSOM entries found: {duplicates}"


class TestTechniquesFromCanonicalChain:
    """Canonical chain exact mappings are valid and overlap with SSSOM provenance.

    The SSSOM file carries historical ``relatedMatch`` provenance hints; the
    canonical chain carries authoritative ``exact`` mappings.  These tests
    verify that each pattern has a canonical chain with exact ATLAS mappings,
    that every exact mapping is a valid pinned ATLAS identifier (via the
    production resolver), and that at least one exact mapping is supported
    by (or is a parent/sub-technique of) an SSSOM ``relatedMatch`` entry,
    confirming historical continuity.
    """

    @pytest.fixture(scope="module")
    def resolver(self):
        from asago_scenario_generator.data.taxonomy_pins import load_taxonomy_resolver

        return load_taxonomy_resolver()

    @pytest.mark.parametrize("pid", ATLAS_DERIVED_IDS)
    def test_canonical_chain_has_exact_mappings(
        self,
        all_patterns: dict[str, dict],
        pid: str,
    ) -> None:
        """Each pattern's canonical chain has at least one exact ATLAS mapping."""
        pattern = all_patterns[pid]
        cc = pattern.get("canonical_chain")
        assert cc is not None, f"{pid} missing canonical_chain"

        exact_techniques: set[str] = set()
        for mapping in cc.get("mappings", []):
            if mapping.get("decision") == "exact":
                exact_techniques.update(mapping.get("ids", []))
        for step in cc.get("steps", []):
            for mapping in step.get("mappings", []):
                if mapping.get("decision") == "exact":
                    exact_techniques.update(mapping.get("ids", []))

        assert exact_techniques, f"{pid}: canonical chain has no exact ATLAS mappings"

    @pytest.mark.parametrize("pid", ATLAS_DERIVED_IDS)
    def test_exact_mappings_are_valid_atlas_ids(
        self,
        all_patterns: dict[str, dict],
        resolver,
        pid: str,
    ) -> None:
        """All exact canonical chain mappings are valid pinned ATLAS identifiers."""
        pattern = all_patterns[pid]
        cc = pattern["canonical_chain"]
        all_exact: set[str] = set()
        for mapping in cc.get("mappings", []):
            if mapping.get("decision") == "exact":
                all_exact.update(mapping.get("ids", []))
        for step in cc.get("steps", []):
            for mapping in step.get("mappings", []):
                if mapping.get("decision") == "exact":
                    all_exact.update(mapping.get("ids", []))
        for tech in all_exact:
            assert resolver.contains("ATLAS", tech), (
                f"{pid}: exact mapping {tech} is not a valid pinned ATLAS identifier"
            )

    @pytest.mark.parametrize("pid", ATLAS_DERIVED_IDS)
    def test_historical_continuity_with_sssom(
        self,
        sssom_mappings: list[SSSOMMapping],
        all_patterns: dict[str, dict],
        pid: str,
    ) -> None:
        """At least one exact canonical mapping overlaps (exact or parent/sub-technique)
        with an SSSOM ``relatedMatch`` entry for the same pattern.

        This confirms historical continuity between the original SSSOM provenance
        hints and the authoritative canonical-chain exact mappings.
        """
        pattern = all_patterns[pid]
        cc = pattern["canonical_chain"]
        exact_ids: set[str] = set()
        for mapping in cc.get("mappings", []):
            if mapping.get("decision") == "exact":
                exact_ids.update(mapping.get("ids", []))
        for step in cc.get("steps", []):
            for mapping in step.get("mappings", []):
                if mapping.get("decision") == "exact":
                    exact_ids.update(mapping.get("ids", []))

        sssom_ids = {m.object_id for m in sssom_mappings if m.subject_id == pid}

        def _is_related(exact_id: str, sssom_id: str) -> bool:
            if exact_id == sssom_id:
                return True
            # exact is a sub-technique of sssom (e.g. AML.T0069.000 vs AML.T0069)
            if exact_id.startswith(sssom_id + "."):
                return True
            # sssom is a sub-technique of exact
            return bool(sssom_id.startswith(exact_id + "."))

        overlapping = [
            e for e in exact_ids if any(_is_related(e, s) for s in sssom_ids)
        ]
        assert overlapping, (
            f"{pid}: no canonical exact mapping overlaps with SSSOM provenance. "
            f"exact={sorted(exact_ids)}, sssom={sorted(sssom_ids)}"
        )
