"""Tests for ATLAS-derived SSSOM provenance entries.

The file carries exactly 18 rows, and each of the 5 ATLAS-derived patterns
maps to exactly its expected distinctive techniques.  Together these pins
rule out duplicate rows, rows for other patterns and the generic techniques
(AML.T0065, AML.T0051).  The rows name the expected sources and curation
justification, and every pattern's canonical exact mappings overlap its
SSSOM provenance.
"""

from __future__ import annotations

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


@pytest.fixture(scope="module")
def sssom_mappings() -> list[SSSOMMapping]:
    """Load SSSOM mappings from the new ATLAS-derived file."""
    return load_sssom(_SSSOM_PATH)


@pytest.fixture(scope="module")
def all_patterns() -> dict[str, dict]:
    """Load all attack patterns."""
    return load_attack_patterns()


class TestAtlasDerivedSSSOMParsing:
    """The SSSOM file's row count, sources and justification."""

    def test_total_entry_count(self, sssom_mappings: list[SSSOMMapping]):
        """File contains exactly 18 entries (4+3+4+4+3).

        With the exact per-pattern sets, this count leaves no room for a
        duplicate row or a row for another pattern."""
        assert len(sssom_mappings) == 18

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

    def test_all_entries_have_correct_justification(
        self, sssom_mappings: list[SSSOMMapping]
    ):
        """All entries use 'semapv:ManualMappingCuration' justification."""
        for m in sssom_mappings:
            assert m.mapping_justification == "semapv:ManualMappingCuration"


class TestAtlasDerivedSSSOMCoverage:
    """Each ATLAS-derived pattern maps to its expected techniques."""

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


class TestTechniquesFromCanonicalChain:
    """Canonical chain exact mappings overlap with SSSOM provenance.

    The SSSOM file carries historical ``relatedMatch`` provenance hints; the
    canonical chain carries authoritative ``exact`` mappings.  At least one
    exact mapping of each pattern's canonical chain must be supported by (or
    be a parent/sub-technique of) an SSSOM ``relatedMatch`` entry, confirming
    historical continuity.  A chain without an exact ATLAS mapping fails
    this check too.
    """

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
