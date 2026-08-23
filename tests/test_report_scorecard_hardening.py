"""Hardening tests for the scorecard report helper decomposition.

These tests pin the branch behavior of the named helpers extracted from
``src/asago_scenario_generator/report/scorecard.py`` so the CRAP gate
(<= 6 on every function in the module) holds under coverage measurement.
They deliberately stay separate from the rendering-behavior tests in
``test_versioned_scorecard.py`` / ``test_taxonomy_report_rendering.py``.
"""

from __future__ import annotations

from asago_scenario_generator.report.scorecard import (
    _badge_css_class,
    _build_consistency_detail,
    _build_consistency_group,
    _build_diversity_entropy_badges,
    _build_diversity_zone_badges,
    _build_gherkin_group,
    _build_grounding_group,
    _build_legacy_summary_html,
    _build_plausibility_group,
    _build_ta_per_scenario,
    _build_technique_agreement_group,
    _build_versioned_metric_row,
    _build_violations_detail,
    _collect_consistency_outliers,
    _collect_diversity_outliers,
    _collect_ep_coverage_outliers,
    _collect_plausibility_outliers,
    _collect_scorecard_outliers,
    _collect_technique_agreement_outliers,
    _display_or_dash,
    _join_strs,
    _low_value_rank,
    _mapping_row,
    _metric_badge_class,
    _missing_parts,
    _plausibility_issue_rows,
    _scalar_scorecard_badge,
    _ta_row,
    _violation_rows,
)


# ---------------------------------------------------------------------------
# Outlier collection helpers
# ---------------------------------------------------------------------------


def test_missing_parts_combinations() -> None:
    assert _missing_parts([], [], []) == []
    assert _missing_parts(["A"], [], []) == ["narrative: A"]
    assert _missing_parts([], ["B"], []) == ["tree: B"]
    assert _missing_parts([], [], ["C"]) == ["spec: C"]
    assert _missing_parts(["A"], ["B", "C"], ["D"]) == [
        "narrative: A",
        "tree: B, C",
        "spec: D",
    ]


def test_mapping_row_score_and_missing_branches() -> None:
    red = _mapping_row("s1", {"technique_agreement": 0.5})
    assert red is not None
    assert red[0] == "red"
    assert red[3] == "Mapping Agreement"
    yellow = _mapping_row("s1", {"technique_agreement": 0.8})
    assert yellow is not None
    assert yellow[0] == "yellow"
    missing = _mapping_row(
        "s1",
        {
            "technique_agreement": 0.95,
            "missing_from_narrative": ["AML.T0054"],
            "missing_from_tree": ["AML.T0015"],
        },
    )
    assert missing == (
        "yellow",
        "s1",
        "Projected-step Mapping Agreement",
        "Missing Techniques",
        "narrative: AML.T0054; tree: AML.T0015",
        "scorecard-badge-yellow",
    )
    assert _mapping_row("s1", {"technique_agreement": 0.95}) is None


def test_collect_technique_agreement_outliers() -> None:
    ev = {
        "technique_agreement": {
            "per_scenario": {
                "s-red": {"technique_agreement": 0.5},
                "s-missing": {
                    "technique_agreement": 0.95,
                    "missing_from_spec": ["AML.T0053"],
                },
                "s-clean": {"technique_agreement": 1.0},
            }
        }
    }
    rows = _collect_technique_agreement_outliers(ev)
    assert [row[1] for row in rows] == ["s-red", "s-missing"]


def test_plausibility_issue_rows_branches() -> None:
    assert _plausibility_issue_rows("s1", ["too complex"])[0][3] == (
        "Capability Violation"
    )
    assert _plausibility_issue_rows("s1", []) == []
    assert _plausibility_issue_rows("s1", "not-a-list") == []


def test_collect_plausibility_outliers_with_aggregate() -> None:
    ev = {
        "plausibility": {
            "per_scenario": {"s1": ["violation a"], "s2": []},
            "capability_complexity_violation_count": 2,
        }
    }
    rows = _collect_plausibility_outliers(ev)
    assert (rows[0][1], rows[0][3]) == ("s1", "Capability Violation")
    assert (rows[1][1], rows[1][3]) == ("(aggregate)", "Capability Violations")


def test_collect_diversity_outliers_tiers() -> None:
    red = _collect_diversity_outliers(
        {"diversity": {"title_uniqueness": 0.4, "entry_point_entropy": {}}}
    )
    assert red == [
        ("red", "(aggregate)", "Diversity", "Title Uniqueness", 0.4, "scorecard-badge-red")
    ]
    yellow = _collect_diversity_outliers(
        {
            "diversity": {
                "title_uniqueness": 0.6,
                "entry_point_entropy": {"entry_point_coverage": 0.6},
            }
        }
    )
    assert [(row[0], row[3]) for row in yellow] == [
        ("yellow", "Title Uniqueness"),
        ("yellow", "EP Coverage"),
    ]
    clean = _collect_diversity_outliers(
        {
            "diversity": {
                "title_uniqueness": 0.8,
                "entry_point_entropy": {"entry_point_coverage": 0.8},
            }
        }
    )
    assert clean == []


def test_low_value_rank_all_tiers() -> None:
    assert _low_value_rank(0.95, 0.9, 0.7) is None
    assert _low_value_rank(0.8, 0.9, 0.7) == ("yellow", "scorecard-badge-yellow")
    assert _low_value_rank(0.5, 0.9, 0.7) == ("red", "scorecard-badge-red")


# ---------------------------------------------------------------------------
# Detail-table builders
# ---------------------------------------------------------------------------


def test_violation_rows_and_detail() -> None:
    assert _violation_rows({}) == ""
    assert _violation_rows({"s1": ["issue a"], "s2": "not-a-list"}) == (
        "<tr><td>s1</td><td>issue a</td></tr>"
    )
    assert _build_violations_detail({}) == ""
    detail = _build_violations_detail({"s1": ["issue a"]})
    assert "Violation Details" in detail
    assert "<td>s1</td>" in detail
    assert "<td>issue a</td>" in detail


def test_ta_per_scenario_rows() -> None:
    assert _build_ta_per_scenario({}) == ""
    html = _build_ta_per_scenario(
        {
            "s1": {
                "technique_agreement": 0.92,
                "scenario_classifications": ["AML.T0054"],
                "missing_from_tree": ["AML.T0015"],
                "missing_from_spec": [],
            }
        }
    )
    assert "Per-Scenario Disagreements" in html
    assert "<td>s1</td>" in html
    assert "0.92" in html
    assert "AML.T0054" in html
    assert "AML.T0015" in html
    assert "<td>-</td>" in html


def test_join_strs_and_display_or_dash() -> None:
    assert _join_strs(["a", 1]) == "a, 1"
    assert _join_strs(["a"], "; ") == "a"
    assert _display_or_dash("x") == "x"
    assert _display_or_dash("") == "-"


def test_versioned_metric_row_fraction_and_value_variants() -> None:
    full = _build_versioned_metric_row(
        "m1",
        {
            "status": "pass",
            "numerator": 2,
            "denominator": 3,
            "value": 0.6667,
            "evidence": ["e1"],
            "affected_ids": ["s1", "s2"],
        },
    )
    assert ">m1</td>" in full
    assert "2 / 3" in full
    assert "0.6667" in full
    assert "e1" in full
    assert "s1, s2" in full
    bare = _build_versioned_metric_row(
        "m2",
        {"status": "error", "numerator": None, "value": None},
    )
    assert ">—</td>" in bare
    assert "error" in bare


def test_scalar_scorecard_badge_requires_numeric() -> None:
    assert _scalar_scorecard_badge({"actor_type_entropy": 0.8}, "actor_type_entropy", "Actor Type Entropy") == (
        '<span class="scorecard-badge scorecard-badge-yellow" data-tooltip="Shannon entropy of actor-type distribution. Higher values indicate more diverse attacker personas">Actor Type Entropy: 0.80</span>'
    )
    assert _scalar_scorecard_badge({"actor_type_entropy": "high"}, "actor_type_entropy", "Actor Type Entropy") == ""
    assert "Actor Type Entropy: 0</span>" in _scalar_scorecard_badge(
        {}, "actor_type_entropy", "Actor Type Entropy"
    )


# ---------------------------------------------------------------------------
# Badge classification boundaries
# ---------------------------------------------------------------------------


def test_badge_css_class_boundaries() -> None:
    assert _badge_css_class(0.0, invert=True) == "scorecard-badge-green"
    assert _badge_css_class(1.0, invert=True) == "scorecard-badge-red"
    assert _badge_css_class(0.9, invert=False) == "scorecard-badge-green"
    assert _badge_css_class(0.7, invert=False) == "scorecard-badge-yellow"
    assert _badge_css_class(0.5, invert=False) == "scorecard-badge-red"


def test_metric_badge_class_boundaries() -> None:
    assert _metric_badge_class(1.0) == "scorecard-badge-green"
    assert _metric_badge_class(0.9) == "scorecard-badge-green"
    assert _metric_badge_class(0.7) == "scorecard-badge-yellow"
    assert _metric_badge_class(0.5) == "scorecard-badge-red"


def test_low_value_rank_boundaries() -> None:
    assert _low_value_rank(0.95, 0.9, 0.7) is None
    assert _low_value_rank(0.9, 0.9, 0.7) is None
    assert _low_value_rank(0.7, 0.9, 0.7) == ("yellow", "scorecard-badge-yellow")
    assert _low_value_rank(0.6, 0.9, 0.7) == ("red", "scorecard-badge-red")


# ---------------------------------------------------------------------------
# Consistency collection and rendering defaults
# ---------------------------------------------------------------------------


def test_collect_consistency_outliers_defaults_absent() -> None:
    assert (
        _collect_consistency_outliers(
            {"consistency": {"per_scenario": {"s1": {}}}}
        )
        == []
    )


def test_collect_consistency_outliers_zero_entry_point_agreement() -> None:
    rows = _collect_consistency_outliers(
        {"consistency": {"per_scenario": {"s-z": {"entry_point_agreement": 0}}}}
    )
    assert [r[:4] for r in rows] == [
        ("red", "s-z", "Consistency", "Entry Point Agreement")
    ]
    assert rows[0][4] == 0


def test_build_consistency_detail_defaults_and_full_row() -> None:
    degenerate = _build_consistency_detail({"s1": {}})
    assert degenerate.count("scorecard-badge-red") == 3
    full = _build_consistency_detail(
        {"s2": {"zone_alignment": 0.95, "entry_point_agreement": 1, "step_node_correspondence": 0.8}}
    )
    assert "scorecard-badge-green" in full
    assert "0.95" in full


def test_build_consistency_group_missing_stat_defaults() -> None:
    html = _build_consistency_group({"consistency": {"per_scenario": {}}})
    assert "Mean: 0" in html
    assert "Stddev: 0.000: 1" in html


# ---------------------------------------------------------------------------
# Gherkin / grounding group default and empty rendering
# ---------------------------------------------------------------------------


def test_build_gherkin_group_defaults_warnings_and_empty() -> None:
    assert _build_gherkin_group({}) == ""
    degenerate = _build_gherkin_group({"gherkin": {"tag_consistency": {}}})
    assert "Parse Success Rate: 0" in degenerate
    assert "Mean Step Count: 0.0" in degenerate
    assert "Inconsistent Tag Groups: 0" in degenerate
    assert degenerate.count("scorecard-badge-green") == 2
    warned = _build_gherkin_group(
        {"gherkin": {"background_missing_warnings": ["w1", "w2"]}}
    )
    assert "Background Warnings: 2" in warned


def test_build_grounding_group_defaults_and_empty() -> None:
    assert _build_grounding_group({"grounding": {}}) == ""
    degenerate = _build_grounding_group({"grounding": {"x": 1}})
    assert "Threat ID Validity: 0" in degenerate
    assert "Dangling References: 0" in degenerate
    assert "Technique ID Grounding: 0" in degenerate
    assert "Ungrounded Technique Refs: 0" in degenerate
    assert degenerate.count("scorecard-badge-green") == 2


# ---------------------------------------------------------------------------
# Technique agreement rows and diversity defaults
# ---------------------------------------------------------------------------


def test_ta_row_default_score_is_red() -> None:
    row = _ta_row("s1", {})
    assert "s1" in row
    assert "scorecard-badge-red" in row


def test_build_technique_agreement_group_default_mean() -> None:
    html = _build_technique_agreement_group(
        {"technique_agreement": {"per_scenario": {}}}
    )
    assert "Mean Technique Agreement: 0" in html


def test_build_diversity_entropy_and_zone_defaults() -> None:
    entropy = _build_diversity_entropy_badges({"shannon": 3})
    assert "EP Entropy: 0.00" in entropy
    assert "EP Coverage: 0" in entropy
    zones = _build_diversity_zone_badges({"other": 1})
    assert "Active Zone Coverage: 0" in zones


# ---------------------------------------------------------------------------
# Plausibility group and legacy summary defaults
# ---------------------------------------------------------------------------


def test_build_plausibility_group_empty_per_scenario() -> None:
    html = _build_plausibility_group({"plausibility": {"per_scenario": {}}})
    assert "Capability Violations: 0" in html


def test_build_legacy_summary_html_zero_defaults() -> None:
    html = _build_legacy_summary_html({})
    assert html.count('scorecard-stat-value">0</div>') == 2


def test_collect_outliers_defaults_and_sort_order() -> None:
    assert (
        _collect_plausibility_outliers(
            {"plausibility": {"capability_complexity_violation_count": 0}}
        )
        == []
    )
    single = _collect_plausibility_outliers(
        {"plausibility": {"capability_complexity_violation_count": 1}}
    )
    assert [r[:4] for r in single] == [
        ("red", "(aggregate)", "Plausibility", "Capability Violations")
    ]
    assert _collect_ep_coverage_outliers({"shannon": 2}) == []
    low_cov = _collect_ep_coverage_outliers(
        {"entry_point_entropy": {"entry_point_coverage": 0.4}}
    )
    assert low_cov == [
        ("red", "(aggregate)", "Diversity", "EP Coverage", 0.4, "scorecard-badge-red")
    ]
    ev = {
        "consistency": {
            "per_scenario": {
                "z-red": {"zone_alignment": 0.5},
                "a-yel": {"zone_alignment": 0.8},
            }
        }
    }
    rows = _collect_scorecard_outliers(ev)
    assert [r[1] for r in rows] == ["z-red", "a-yel"]
