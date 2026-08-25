"""Tests for SSSOM parsing and predicate filtering in build_risk_to_llm_index().

Verifies that noMatch predicates are excluded from the risk-to-LLM index,
while valid match predicates (exactMatch, broadMatch, narrowMatch) are
included correctly.
"""

from __future__ import annotations

import logging

import pytest

from asago_scenario_generator.data.sssom import SSSOMMapping, build_risk_to_llm_index


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


class TestBuildRiskToLlmIndexPredicateFiltering:
    """Predicate-based filtering: noMatch rows must be excluded."""

    def test_nomatch_excluded(self) -> None:
        """A row with predicate_id 'noMatch' must NOT appear in the index."""
        mappings = [_mapping(predicate_id="noMatch")]
        index = build_risk_to_llm_index(mappings)
        assert index == {}

    def test_skos_nomatch_excluded(self) -> None:
        """A row with predicate_id 'skos:noMatch' must NOT appear in the index."""
        mappings = [_mapping(predicate_id="skos:noMatch")]
        index = build_risk_to_llm_index(mappings)
        assert index == {}

    def test_nomatch_case_insensitive(self) -> None:
        """The noMatch filter must be case-insensitive."""
        mappings = [_mapping(predicate_id="NOMATCH")]
        index = build_risk_to_llm_index(mappings)
        assert index == {}

    def test_exact_match_included(self) -> None:
        """A row with predicate_id 'skos:exactMatch' must be included."""
        mappings = [_mapping(predicate_id="skos:exactMatch")]
        index = build_risk_to_llm_index(mappings)
        assert "atlas-prompt-injection" in index
        assert index["atlas-prompt-injection"] == ["LLM01"]

    def test_broad_match_included(self) -> None:
        """A row with predicate_id 'skos:broadMatch' must be included."""
        mappings = [_mapping(predicate_id="skos:broadMatch")]
        index = build_risk_to_llm_index(mappings)
        assert "atlas-prompt-injection" in index
        assert index["atlas-prompt-injection"] == ["LLM01"]

    def test_narrow_match_included(self) -> None:
        """A row with predicate_id 'skos:narrowMatch' must be included."""
        mappings = [_mapping(predicate_id="skos:narrowMatch")]
        index = build_risk_to_llm_index(mappings)
        assert "atlas-prompt-injection" in index
        assert index["atlas-prompt-injection"] == ["LLM01"]

    def test_mixed_predicates_filters_correctly(self) -> None:
        """Mixed predicates: only non-noMatch rows produce index entries."""
        mappings = [
            _mapping(
                subject_id="risk-a",
                predicate_id="skos:exactMatch",
                object_id="llm012025-prompt-injection",
            ),
            _mapping(
                subject_id="risk-a",
                predicate_id="noMatch",
                object_id="llm022025-insecure-output",
            ),
            _mapping(
                subject_id="risk-b",
                predicate_id="skos:broadMatch",
                object_id="llm032025-training-data-poisoning",
            ),
            _mapping(
                subject_id="risk-c",
                predicate_id="skos:noMatch",
                object_id="llm042025-model-dos",
            ),
        ]
        index = build_risk_to_llm_index(mappings)

        # risk-a: only the exactMatch row survives (LLM01), noMatch (LLM02) excluded
        assert index["risk-a"] == ["LLM01"]
        # risk-b: broadMatch included
        assert index["risk-b"] == ["LLM03"]
        # risk-c: skos:noMatch excluded entirely
        assert "risk-c" not in index

    def test_nomatch_logs_debug_message(self, caplog: pytest.LogCaptureFixture) -> None:
        """Skipped noMatch rows should emit a debug log line."""
        mappings = [_mapping(predicate_id="noMatch")]
        with caplog.at_level(
            logging.DEBUG, logger="asago_scenario_generator.data.sssom"
        ):
            build_risk_to_llm_index(mappings)
        assert any("noMatch" in record.message for record in caplog.records)


# ---------------------------------------------------------------------------
# Tests: non-owasp-llm rows are still filtered by object_source
# ---------------------------------------------------------------------------


class TestBuildRiskToLlmIndexObjectSourceFiltering:
    """Existing object_source filter must still work alongside predicate filter."""

    def test_non_owasp_llm_source_excluded(self) -> None:
        """Rows with a non-owasp-llm object_source are excluded regardless of predicate."""
        mappings = [
            _mapping(
                predicate_id="skos:exactMatch",
                object_source="some-other-source",
            )
        ]
        index = build_risk_to_llm_index(mappings)
        assert index == {}

    def test_owasp_llm_source_with_valid_predicate_included(self) -> None:
        """Rows matching both filters (owasp-llm source + valid predicate) are included."""
        mappings = [
            _mapping(
                predicate_id="skos:exactMatch",
                object_source="owasp-llm-top10-2025",
            )
        ]
        index = build_risk_to_llm_index(mappings)
        assert "atlas-prompt-injection" in index
