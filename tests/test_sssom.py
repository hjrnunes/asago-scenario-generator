"""Tests for SSSOM parsing and predicate filtering in build_risk_to_llm_index().

Verifies that noMatch predicates are excluded from the risk-to-LLM index,
while valid match predicates (exactMatch, broadMatch, narrowMatch) are
included correctly.
"""

from __future__ import annotations


from asago_scenario_generator.data.sssom import SSSOMMapping


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mapping(
    subject_id: str = "atlas-prompt-injection",
    predicate_id: str = "skos:exactMatch",
    object_id: str = "llm012025-prompt-injection",
    object_source: str = "owasp-llm-top10-2025",
) -> SSSOMMapping:
    """Build a minimal SSSOMMapping with sensible defaults."""
    return SSSOMMapping(
        subject_id=subject_id,
        subject_source="mitre-atlas",
        predicate_id=predicate_id,
        object_id=object_id,
        object_source=object_source,
        mapping_justification="semapv:ManualMappingCuration",
    )


class TestLoadSssomAndCurieSplitting:
    def test_split_curie(self) -> None:
        from asago_scenario_generator.data.sssom import _split_curie

        assert _split_curie("ibm-risk-atlas:atlas-hallucination") == (
            "ibm-risk-atlas",
            "atlas-hallucination",
        )
        assert _split_curie("atlas-hallucination") == ("", "atlas-hallucination")
        assert _split_curie("prefix:a:b") == ("prefix", "a:b")

    def test_load_sssom_explicit_source_columns(self, tmp_path) -> None:
        from asago_scenario_generator.data.sssom import load_sssom

        path = tmp_path / "explicit.sssom.tsv"
        path.write_text(
            "# comment line\n"
            "subject_id\tsubject_source\tpredicate_id\tobject_id\t"
            "object_source\tmapping_justification\n"
            "AP-T1-01\tasago-scenario-generator\tskos:relatedMatch\t"
            "AML.T0053\tmitre-atlas\tsemapv:ManualMappingCuration\n"
            "\n"
        )
        mappings = load_sssom(path)
        assert len(mappings) == 1
        assert mappings[0].subject_id == "AP-T1-01"
        assert mappings[0].subject_source == "asago-scenario-generator"
        assert mappings[0].object_source == "mitre-atlas"

    def test_load_sssom_curie_only_format(self, tmp_path) -> None:
        from asago_scenario_generator.data.sssom import load_sssom

        path = tmp_path / "curie.sssom.tsv"
        path.write_text(
            "subject_id\tpredicate_id\tobject_id\tmapping_justification\n"
            "ibm-risk-atlas:atlas-hallucination\tskos:exactMatch\t"
            "owasp-llm-top10-2025:llm012025-excessive-agency\t"
            "semapv:ManualMappingCuration\n"
            "plain-id\tskos:exactMatch\tother:thing\tsemapv:ManualMappingCuration\n"
        )
        mappings = load_sssom(path)
        assert mappings[0].subject_source == "ibm-risk-atlas"
        assert mappings[0].subject_id == "atlas-hallucination"
        assert mappings[0].object_source == "owasp-llm-top10-2025"
        assert mappings[0].object_id == "llm012025-excessive-agency"
        assert mappings[1].subject_source == ""
        assert mappings[1].subject_id == "plain-id"


# ---------------------------------------------------------------------------
# Tests: predicate filtering in build_risk_to_llm_index
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Tests: non-owasp-llm rows are still filtered by object_source
# ---------------------------------------------------------------------------


class TestNormalizeLlmId:
    def test_exact_match_object_normalizes_to_owasp_code(self) -> None:
        from asago_scenario_generator.data.sssom import normalize_llm_id

        assert normalize_llm_id(_mapping().object_id) == "LLM01"
