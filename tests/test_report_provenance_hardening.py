"""Hardening tests for the provenance report helper decomposition.

These tests pin the branch behavior of the named helpers extracted from
``src/asago_scenario_generator/report/provenance.py`` so the CRAP gate
(<= 6 on every function in the module) holds under coverage measurement.
They deliberately stay separate from the rendering-behavior tests in
``test_seed_provenance.py`` / ``test_taxonomy_report_rendering.py``.
"""

from __future__ import annotations

import pytest

from asago_scenario_generator.report.provenance import (
    _ZONE_NAMES_TUPLE,
    _ATTACK_PATTERN_INFO,
    _THREAT_DESCRIPTIONS,
    _assign_tier_for_category,
    _attack_pattern_tooltip,
    _build_accepted_badges,
    _build_candidate_filter_block,
    _build_goal_grid,
    _build_rejected_combinations,
    _build_tier_lookup,
    _build_zone_crumbs,
    _field_values_or_legacy,
    _find_goal_category,
    _goal_context_span,
    _goal_item_html,
    _goal_tier_context,
    _join_escaped,
    _join_nonempty,
    _join_text,
    _meta_list_or_default,
    _meta_text_or_default,
    _meta_text_with_fallback,
    _normalize_zone,
    _provenance_suffix,
    _reject,
    _scenario_dict,
    _seed_provenance_parts,
    _threat_id_tooltip,
    _tier_context_parts,
    _truncate,
)


# ---------------------------------------------------------------------------
# Goal-tier classification helpers
# ---------------------------------------------------------------------------


def test_goal_tier_context_primary_tier() -> None:
    badge, parts = _goal_tier_context(["C1", "C2"], ["C3"], "C1")
    assert "prov-badge-green" in badge
    assert "primary" in badge
    assert parts == ["also primary: C2", "secondary: C3"]


def test_goal_tier_context_secondary_tier() -> None:
    badge, parts = _goal_tier_context(["C1"], ["C3", "C4"], "C4")
    assert "prov-badge-amber" in badge
    assert "secondary" in badge
    assert parts == ["primary: C1", "also secondary: C3"]


def test_goal_tier_context_single_category_tier_has_empty_parts() -> None:
    badge, parts = _goal_tier_context(["C1"], [], "C1")
    assert badge
    assert parts == []


def test_goal_tier_context_unknown_category_is_none() -> None:
    badge, parts = _goal_tier_context(["C1"], ["C3"], "C9")
    assert badge == ""
    assert parts is None


def test_tier_context_parts_drops_empty_entries() -> None:
    parts = _tier_context_parts([("a", ["x", "y"]), ("b", [])])
    assert parts == ["a: x, y"]


def test_reject_removes_only_the_excluded_value() -> None:
    assert _reject(["a", "b", "c"], "b") == ["a", "c"]
    assert _reject([], "x") == []


def test_goal_context_span_fallback_for_unknown_tier() -> None:
    span = _goal_context_span(["C1"], ["C3"], None)
    assert "(primary: C1 | secondary: C3)" in span


def test_goal_context_span_empty_and_populated_parts() -> None:
    assert _goal_context_span([], [], []) == ""
    span = _goal_context_span([], [], ["also primary: C2"])
    assert "(also primary: C2)" in span


# ---------------------------------------------------------------------------
# Provenance suffix / seed metadata lookups
# ---------------------------------------------------------------------------


def test_seed_provenance_parts_defaults() -> None:
    assert _seed_provenance_parts(None) == ("", [], [])
    assert _seed_provenance_parts({}) == ("", [], [])


def test_seed_provenance_parts_populated() -> None:
    meta = {
        "owasp_origin": "T7-S1",
        "laaf_technique_ids": ["S1"],
        "atlas_provenance_ids": ["AML.T0054"],
    }
    assert _seed_provenance_parts(meta) == (
        "T7-S1",
        ["S1"],
        ["AML.T0054"],
    )


def test_provenance_suffix_combinations() -> None:
    assert _provenance_suffix([], []) == ""
    assert _provenance_suffix(["S1"], []) == " | Provenance: LAAF: S1"
    assert _provenance_suffix([], ["AML.T0054"]) == (
        " | Provenance: ATLAS: AML.T0054"
    )
    assert _provenance_suffix(["S1", "M3"], ["AML.T0054"]) == (
        " | Provenance: LAAF: S1, M3; ATLAS: AML.T0054"
    )


def test_attack_pattern_tooltip_uses_seed_provenance() -> None:
    if not _ATTACK_PATTERN_INFO:
        pytest.skip("attack pattern lookup table not loaded")
    ap_id = next(iter(_ATTACK_PATTERN_INFO))
    plain = _attack_pattern_tooltip(ap_id)
    assert plain.startswith(" data-tooltip=")
    assert "Provenance:" not in plain
    enriched = _attack_pattern_tooltip(
        ap_id,
        {
            "owasp_origin": "T7-S1",
            "laaf_technique_ids": ["S1"],
            "atlas_provenance_ids": ["AML.T0054"],
        },
    )
    assert "(derived from T7-S1)" in enriched
    assert "LAAF: S1" in enriched
    assert "ATLAS: AML.T0054" in enriched


def test_meta_lookup_helpers() -> None:
    meta = {"name": "n", "items": ["a"], "empty": ""}
    assert _meta_text_or_default(meta, "empty", "d") == "d"
    assert _meta_text_or_default(meta, "name") == "n"
    assert _meta_list_or_default(meta, "items") == ["a"]
    assert _meta_list_or_default(meta, "missing") == []
    assert _meta_text_with_fallback(meta, "missing", "name") == "n"
    assert _meta_text_with_fallback(meta, "missing", "gone") == ""


def test_scenario_dict_defaults_to_empty() -> None:
    assert _scenario_dict({}, "missing") == {}
    assert _scenario_dict({"k": {"a": 1}}, "k") == {"a": 1}
    assert _scenario_dict({"k": None}, "k") == {}


def test_join_helpers() -> None:
    assert _join_text(["a", "b"], " + ") == "a + b"
    assert _join_text([], " + ") == ""
    assert _join_escaped(["<a>", "b"]) == "&lt;a&gt;, b"
    assert _join_nonempty(["", "x", "y"]) == "x y"
    assert _join_nonempty(["", ""]) == ""


# ---------------------------------------------------------------------------
# Candidate filter helpers
# ---------------------------------------------------------------------------


def test_field_values_or_legacy_fallbacks() -> None:
    assert _field_values_or_legacy({}, "ids", "id") == []
    assert _field_values_or_legacy({"ids": ["a"]}, "ids", "id") == ["a"]
    assert _field_values_or_legacy({"id": "a"}, "ids", "id") == ["a"]
    assert _field_values_or_legacy({"ids": [], "id": "a"}, "ids", "id") == ["a"]


def test_build_rejected_combinations_empty_and_populated() -> None:
    assert _build_rejected_combinations([]) == ""
    html = _build_rejected_combinations(
        [
            {
                "entry_point": "ze-query",
                "atlas_technique_ids": ["AML.T0054", "AML.T0015"],
                "rationale": "no matching tool",
            },
            {
                "entry_point": "ze-rag",
                "atlas_technique_id": "AML.T0053",
                "rationale": "unsafe",
            },
        ]
    )
    assert "Rejected combinations (2)" in html
    assert "ze-query" in html
    assert "AML.T0054 + AML.T0015" in html
    assert "no matching tool" in html
    assert "AML.T0053" in html
    assert "unsafe" in html


def test_build_accepted_badges_variants() -> None:
    html = _build_accepted_badges("ze-rag", ["AML.T0054"], ["LLM Jailbreak"])
    assert "Accepted:" in html
    assert "ze-rag" in html
    assert "AML.T0054" in html
    assert ": LLM Jailbreak" in html
    bare = _build_accepted_badges("", ["AML.T0054"], [])
    assert ": " not in bare


# ---------------------------------------------------------------------------
# Truncate / tooltip boundary helpers
# ---------------------------------------------------------------------------


def test_truncate_boundaries() -> None:
    assert _truncate("a" * 199, 200) == "a" * 199
    assert _truncate("a" * 200, 200) == "a" * 200
    assert _truncate("One. Two", 6) == "One."
    assert _truncate(". abcd", 5) == ". abc..."
    assert _truncate("x" * 201, 200) == "x" * 200 + "..."
    # Sentence end at index 1: `_truncate` must keep the sentence break
    # (sentence_end > 0), while a window that excludes the break falls back
    # to the ellipsis suffix.
    assert _truncate("x. y", 3) == "x."
    assert _truncate("x. y", 1) == "x..."


def test_legacy_int_zone_mapping_pins_names() -> None:
    """Legacy integer zone IDs map 1-based onto the canonical zone order."""
    assert _normalize_zone(1) == _ZONE_NAMES_TUPLE[0]
    assert _normalize_zone(2) == _ZONE_NAMES_TUPLE[1]
    assert _normalize_zone(len(_ZONE_NAMES_TUPLE)) == _ZONE_NAMES_TUPLE[-1]
    assert _normalize_zone(99) == "99"
    assert _normalize_zone("reasoning") == "reasoning"


def test_threat_id_tooltip_dashed_base() -> None:
    tip = _threat_id_tooltip("T7-marker")
    assert ' data-tooltip="T7' in tip
    assert " — " in tip
    assert _threat_id_tooltip("T999") == ""


# ---------------------------------------------------------------------------
# Goal category / tier lookup helpers
# ---------------------------------------------------------------------------


def test_find_goal_category_match_and_miss() -> None:
    cats = [
        {"id": "C1", "sub_goals": [{"id": "G1"}]},
        {"id": "C2", "sub_goals": [{"id": "G2", "name": "n"}]},
        {"id": "C3"},
    ]
    assert _find_goal_category(cats, "G2") == "C2"
    assert _find_goal_category(cats, "G9") == ""
    assert _find_goal_category(cats, "G1") == "C1"


def test_build_tier_lookup_tiers_and_direct_assign() -> None:
    cats = [
        {"id": "C1", "sub_goals": [{"id": "G1"}, {"id": "G2"}]},
        {"id": "C2", "sub_goals": [{"id": "G3"}]},
    ]
    affinity = {"T6": {"primary": ["C1"], "secondary": ["C2"], "excluded": []}}
    assert _build_tier_lookup(affinity, cats, "T6") == {
        "G1": "primary",
        "G2": "primary",
        "G3": "secondary",
    }
    assert _build_tier_lookup(affinity, cats, "T9") == {}
    lookup: dict[str, str] = {}
    _assign_tier_for_category(lookup, cats, "C9", "primary")
    assert lookup == {}


def test_goal_item_html_variants() -> None:
    sg = {"id": "G1", "name": "Goal one"}
    selected = _goal_item_html(sg, "primary", "G1", "C1")
    assert 'class="prov-highlight"' in selected
    assert "PRIMARY" in selected
    excluded = _goal_item_html(sg, "excluded", "G2", "C1")
    assert "prov-dim" in excluded
    plain = _goal_item_html(sg, "", "G2", "C1")
    assert "prov-badge-muted" in plain
    assert "prov-dim" not in plain
    assert "prov-badge-muted" in _goal_item_html({"name": "x"}, "", "G2", "C1")


def test_build_goal_grid_empty_and_plain() -> None:
    assert _build_goal_grid([], {}, "G1") == ""
    html = _build_goal_grid(
        [{"id": "C1", "name": "C1", "sub_goals": [{"id": "G1", "name": "g1"}]}],
        {"G1": "primary"},
        "G1",
    )
    assert 'class="prov-highlight"' in html
    assert "G1" in html


# ---------------------------------------------------------------------------
# Zone crumbs / rejected combinations / taxonomy lookups
# ---------------------------------------------------------------------------


def test_build_zone_crumbs_arrows() -> None:
    two = _build_zone_crumbs(["Z1", "Z2"])
    assert two.count("zone-crumb-arrow") == 1
    assert _build_zone_crumbs(["Z1"]).count("zone-crumb-arrow") == 0
    assert _build_zone_crumbs([]) == ""
    assert _build_zone_crumbs([1]).count("zone-crumb") == 1


def test_build_rejected_combinations_single_rejection() -> None:
    html = _build_rejected_combinations(
        [{"entry_point": "ze-query", "atlas_technique_id": "AML.T0015"}]
    )
    assert "Rejected combinations (1)" in html
    assert "AML.T0015" in html


def test_taxonomy_lookups_populated() -> None:
    assert "T7" in _THREAT_DESCRIPTIONS


def test_build_candidate_filter_block_absent_plural_and_legacy() -> None:
    assert _build_candidate_filter_block(None) == ""
    assert _build_candidate_filter_block({}) == ""
    full = {
        "pinned_entry_point": "ze-rag",
        "pinned_technique_ids": ["AML.T0054"],
        "pinned_technique_names": ["LLM Jailbreak"],
        "rejection_rationales": [
            {"entry_point": "ze-query", "atlas_technique_id": "AML.T0015"}
        ],
    }
    html = _build_candidate_filter_block(full)
    assert "Candidate Filter Results" in html
    assert "LLM Jailbreak" in html
    legacy = {
        "pinned_entry_point": "ze-rag",
        "pinned_technique_id": "AML.T0054",
        "pinned_technique_name": "LLM Jailbreak",
    }
    assert "AML.T0054: LLM Jailbreak" in _build_candidate_filter_block(legacy)
