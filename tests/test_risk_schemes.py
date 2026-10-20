"""The OWASP 2026 and NIST AI 600-1 vocabularies and their labels."""

from __future__ import annotations

import pytest
import yaml

from asago_scenario_generator.data import risk_schemes
from asago_scenario_generator.data.risk_schemes import (
    NIST_SCHEME,
    OWASP_ASI_SCHEME,
    OWASP_LLM_SCHEME,
    SCHEMES,
    is_edition_scheme,
    load_vocabulary,
    parse_object_id,
    scheme_label,
)


def test_each_vocabulary_has_its_ten_or_twelve_entries():
    llm = load_vocabulary(OWASP_LLM_SCHEME)
    asi = load_vocabulary(OWASP_ASI_SCHEME)
    nist = load_vocabulary(NIST_SCHEME)
    assert sorted(e.code for e in llm.values()) == [f"LLM{n:02d}" for n in range(1, 11)]
    assert sorted(e.code for e in asi.values()) == [f"ASI{n:02d}" for n in range(1, 11)]
    assert len(nist) == 12
    assert all(e.code is None for e in nist.values())
    assert SCHEMES == (NIST_SCHEME, OWASP_ASI_SCHEME, OWASP_LLM_SCHEME)


def test_owasp_llm_2026_numbers_and_titles():
    assert (
        parse_object_id(OWASP_LLM_SCHEME, "llm032026-excessive-agency").code == "LLM03"
    )
    entry = parse_object_id(OWASP_LLM_SCHEME, "llm082026-hidden-context-exposure")
    assert entry.title == "Hidden Context Exposure"
    assert entry.scheme == OWASP_LLM_SCHEME


@pytest.mark.parametrize(
    "object_id",
    [
        "llm062026-excessive-agency",
        "llm062025-excessive-agency",
        "llm01-prompt-injection",
    ],
)
def test_a_stale_title_slug_is_rejected(object_id):
    with pytest.raises(ValueError, match="not an owasp-llm-2026 entry"):
        parse_object_id(OWASP_LLM_SCHEME, object_id)


def test_an_unknown_scheme_is_rejected():
    with pytest.raises(ValueError):
        parse_object_id("owasp-llm-2025", "llm032026-excessive-agency")
    with pytest.raises(ValueError):
        load_vocabulary("owasp-llm-2025")


def test_labels():
    assert (
        scheme_label(OWASP_LLM_SCHEME, "llm032026-excessive-agency")
        == "OWASP LLM03:2026 Excessive Agency"
    )
    assert (
        scheme_label(OWASP_ASI_SCHEME, "asi02-tool-misuse-and-exploitation")
        == "OWASP ASI02:2026 Tool Misuse & Exploitation"
    )
    assert (
        scheme_label(NIST_SCHEME, "nist-human-ai-configuration")
        == "NIST AI 600-1 Human-AI Configuration"
    )


def test_asi_and_nist_ids_resolve():
    asi = load_vocabulary(OWASP_ASI_SCHEME)
    assert asi["asi10-rogue-agents"].code == "ASI10"
    nist = load_vocabulary(NIST_SCHEME)
    assert (
        nist["nist-obscene-degrading-and-or-abusive-content"].title
        == "Obscene, Degrading, and/or Abusive Content"
    )


def test_a_vocabulary_file_with_another_edition_is_refused(tmp_path):
    source = risk_schemes._vocabulary_path(OWASP_LLM_SCHEME)
    data = yaml.safe_load(source.read_text(encoding="utf-8"))
    data["edition"] = "2025"
    stale = tmp_path / "stale.yaml"
    stale.write_text(yaml.safe_dump(data), encoding="utf-8")
    with pytest.raises(ValueError, match="2025"):
        risk_schemes._load_vocabulary(OWASP_LLM_SCHEME, path=stale)


def test_is_edition_scheme():
    for source in ("owasp-llm-2.0", "owasp-llm-2026", "owasp-asi"):
        assert is_edition_scheme(source)
    for source in ("nist-ai-rmf", "ailuminate-v1.0"):
        assert not is_edition_scheme(source)
