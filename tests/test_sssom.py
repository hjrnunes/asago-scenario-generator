"""Tests for SSSOM loading and CURIE splitting."""

from __future__ import annotations

from pathlib import Path

import pytest

from asago_scenario_generator.data.sssom import (
    _split_curie,
    check_sssom,
    load_checked_sssom,
    load_sssom,
)


class TestLoadSssomAndCurieSplitting:
    def test_split_curie(self) -> None:
        assert _split_curie("ibm-risk-atlas:atlas-hallucination") == (
            "ibm-risk-atlas",
            "atlas-hallucination",
        )
        assert _split_curie("atlas-hallucination") == ("", "atlas-hallucination")
        assert _split_curie("prefix:a:b") == ("prefix", "a:b")

    def test_load_sssom_explicit_source_columns(self, tmp_path) -> None:
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


_HEADER = (
    "subject_id\tsubject_source\tpredicate_id\tobject_id\tobject_source\t"
    "mapping_justification\n"
)


def _reviewed(tmp_path: Path, *rows: str) -> Path:
    path = tmp_path / "risk-to-llm.sssom.tsv"
    path.write_text("#curie_map:\n#  owasp: x\n" + _HEADER + "".join(rows))
    return path


def _row(subject: str, predicate: str, object_id: str, source: str) -> str:
    return f"{subject}\tcredo-ucf\t{predicate}\t{object_id}\t{source}\tj\n"


_GOOD = (
    _row("r-1", "skos:relatedMatch", "llm032026-excessive-agency", "owasp-llm-2026"),
    _row(
        "r-1", "skos:broadMatch", "asi02-tool-misuse-and-exploitation", "owasp-asi-2026"
    ),
    _row("r-2", "skos:relatedMatch", "nist-confabulation", "nist-ai-rmf"),
    _row("r-2", "skos:relatedMatch", "ail-hate", "ailuminate-v1.0"),
    _row("r-3", "skos:noMatch", "sssom:NoTermFound", "owasp-llm-2026"),
)


def test_a_checked_file_keeps_every_row(tmp_path) -> None:
    path = _reviewed(tmp_path, *_GOOD)

    checked = load_checked_sssom(path)

    assert checked == tuple(load_sssom(path))
    assert len(checked) == 5


@pytest.mark.parametrize(
    ("bad", "names"),
    [
        (
            _row(
                "other-target-risk",
                "skos:relatedMatch",
                "nist-confabulations",
                "nist-ai-rmf",
            ),
            "'nist-confabulations' is not an nist-ai-rmf entry",
        ),
        (
            _row(
                "other-target-risk",
                "skos:relatedMatch",
                "asi11-made-up",
                "owasp-asi-2026",
            ),
            "'asi11-made-up' is not an owasp-asi-2026 entry",
        ),
        (
            _row(
                "other-target-risk",
                "skos:relatedMatch",
                "llm062026-excessive-agency",
                "owasp-llm-2026",
            ),
            "'llm062026-excessive-agency' is not an owasp-llm-2026 entry",
        ),
        (
            _row(
                "other-target-risk",
                "skos:relatedMatch",
                "llm092025-misinformation",
                "OWASP-LLM-2.0",
            ),
            "'OWASP-LLM-2.0' is not a current scheme",
        ),
    ],
)
def test_a_bad_row_names_its_line_risk_and_object(tmp_path, bad, names) -> None:
    path = _reviewed(tmp_path, *_GOOD, bad)

    with pytest.raises(ValueError) as caught:
        load_checked_sssom(path)

    message = str(caught.value)
    # Two comment lines and the header precede the five good rows.
    assert f"{path}:9:" in message
    assert "'other-target-risk'" in message
    assert bad.split("\t")[3] in message
    assert names in message


def test_rows_given_in_memory_are_checked_by_position(tmp_path) -> None:
    rows = load_sssom(_reviewed(tmp_path, *_GOOD))
    bad = rows[2].model_copy(update={"object_id": "nist-confabulations"})

    with pytest.raises(ValueError, match=r"SSSOM row 3: risk 'r-2'"):
        check_sssom([*rows[:2], bad])
