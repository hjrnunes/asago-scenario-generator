"""Tests for the STPA HTML report generator."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from asago_scenario_generator.stpa.report import generate_report
from asago_scenario_generator.stpa.report.generator import (
    _build_sp3_html,
    _compute_has_sp2,
    _extract_eval_metrics,
    _extract_hero_data,
    _load_model_artifact,
    _load_raw_yaml,
    _load_scenarios,
    _read_calls_jsonl,
    _read_dict_file,
    _read_json_dict,
    _read_yaml_dict,
    _resolve_output_path,
)
from asago_scenario_generator.stpa.report.template import (
    _advance_docstring_state,
    _apply_gherkin_keyword_highlight,
    _attr_list,
    _average_rate_fields,
    _build_attack_tree_visual,
    _build_attacker_bdi_block,
    _build_bdi_section,
    _build_call_entry_html,
    _build_constraints_table,
    _build_data_table,
    _build_defender_bdi_block,
    _build_eval_gauge,
    _build_eval_scorecard,
    _build_hazards_table,
    _build_hero_summary,
    _build_losses_table,
    _build_manifest_grid,
    _build_manifest_hashes_table,
    _build_produces_arrow,
    _build_raw_yaml_section,
    _build_raw_yaml_sections,
    _build_scenario_card,
    _build_sp1_capability_section,
    _build_sp1_control_section,
    _build_sp1_losses_section,
    _build_sp2_coverage_section,
    _build_sp2_enrichment_section,
    _build_sp2_ica_section,
    _build_sticky_nav,
    _build_tab_bar,
    _build_tab_panels,
    _build_table_rows,
    _build_tree_branch_node,
    _docstring_opening,
    _docstring_row_html,
    _envelope_gherkin_text,
    _envelope_has_gherkin,
    _esc,
    _feature_text_section,
    _gauge_color,
    _gherkin_decorative_row,
    _gherkin_keyword_class,
    _gherkin_keyword_row,
    _gherkin_row_html,
    _has_tree_content,
    _highlight_gherkin,
    _highlight_yaml,
    _highlight_yaml_value,
    _is_quoted_string,
    _is_valid_hashes,
    _kc_item_html,
    _kc_item_rows,
    _loss_analysis_losses,
    _loss_to_dict,
    _parse_tree_dict,
    _rate_field_values,
    _render_tree_child,
    _resolve_model_name,
    _safe_float,
    _safe_floats,
    _scenario_tab_contents,
    _tab_active,
    _tree_branch_rows,
    _tree_leaf_markup,
    _tree_leaf_rows,
    _tree_root_markup,
    _yaml_value_class,
    build_html,
    build_llm_call_inspector,
    build_run_manifest,
    build_sp1_card,
    build_sp2_card,
    build_sp3_card,
    extract_metric_rate,
)

FIXTURES_DIR = (
    Path(__file__).resolve().parent.parent.parent
    / "src"
    / "asago_scenario_generator"
    / "stpa"
    / "fixtures"
)


# ---------------------------------------------------------------------------
# Mock factories
# ---------------------------------------------------------------------------


def _make_loss(
    loss_id: str = "L-1",
    description: str = "Test loss",
    provenance: str = "use_case",
) -> SimpleNamespace:
    return SimpleNamespace(
        loss_id=loss_id, description=description, provenance=provenance,
    )


def _make_loss_analysis(
    risk_card_losses=None,
    use_case_losses=None,
    hazards=None,
    security_constraints=None,
) -> SimpleNamespace:
    return SimpleNamespace(
        risk_card_losses=risk_card_losses or [],
        use_case_losses=use_case_losses or [],
        hazards=hazards or [],
        security_constraints=security_constraints or [],
    )


def _make_capability_profile(
    zones_active=None, kc_subcodes=None,
) -> SimpleNamespace:
    return SimpleNamespace(
        zones_active=zones_active or [],
        kc_subcodes=kc_subcodes or [],
    )


def _make_control_structure(responsibilities=None) -> SimpleNamespace:
    return SimpleNamespace(responsibilities=responsibilities or [])


def _make_ica_slot(
    slot_id: str = "S-1",
    uca_type: str = "Provided",
    is_na: bool = False,
    icas=None,
) -> SimpleNamespace:
    return SimpleNamespace(
        slot_id=slot_id, uca_type=uca_type, is_na=is_na, icas=icas or [],
    )


def _make_ica_enumeration(slots=None) -> SimpleNamespace:
    return SimpleNamespace(slots=slots or [])


def _make_catalog_mapping(mapping_id: str = "M-1") -> SimpleNamespace:
    return SimpleNamespace(id=mapping_id)


def _make_structural_threat(
    ica_slot_id: str = "S-1", catalog_mappings=None,
) -> SimpleNamespace:
    return SimpleNamespace(
        ica_slot_id=ica_slot_id,
        catalog_mappings=catalog_mappings or [],
    )


def _make_coverage_analysis(coverage_rate=None) -> SimpleNamespace:
    sc = {"coverage_rate": coverage_rate} if coverage_rate is not None else {}
    return SimpleNamespace(structural_coverage=sc)


def _make_enriched_threat_set(
    structural_threats=None, coverage_analysis=None,
) -> SimpleNamespace:
    return SimpleNamespace(
        structural_threats=structural_threats or [],
        coverage_analysis=coverage_analysis or _make_coverage_analysis(),
    )


def _make_defender_bdi(
    beliefs=None, desires=None, intentions=None,
) -> SimpleNamespace:
    return SimpleNamespace(
        beliefs=beliefs or [],
        desires=desires or [],
        intentions=intentions or [],
    )


def _make_attacker_bdi(
    beliefs=None, desires=None, intentions=None,
) -> SimpleNamespace:
    return SimpleNamespace(
        beliefs=beliefs or [],
        desires=desires or [],
        intentions=intentions or [],
    )


def _make_scenario_spec(
    defender_bdi=None, attacker_bdi=None,
) -> SimpleNamespace:
    return SimpleNamespace(
        defender_bdi=defender_bdi,
        attacker_bdi=attacker_bdi,
    )


def _make_scenario_envelope(
    scenario_spec=None, narrative="", attack_tree=None,
) -> SimpleNamespace:
    return SimpleNamespace(
        scenario_spec=scenario_spec,
        narrative=narrative,
        attack_tree=attack_tree,
    )


# ---------------------------------------------------------------------------
# Escaping
# ---------------------------------------------------------------------------


class TestEscaping:
    def test_esc_none(self):
        assert _esc(None) == ""

    def test_esc_html(self):
        assert _esc("<script>alert('xss')</script>") == "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;"

    def test_esc_int(self):
        assert _esc(42) == "42"


# ---------------------------------------------------------------------------
# YAML highlighting
# ---------------------------------------------------------------------------


class TestYamlValueClass:
    def test_null(self):
        assert _yaml_value_class("null") == "yaml-null"

    def test_tilde(self):
        assert _yaml_value_class("~") == "yaml-null"

    def test_true(self):
        assert _yaml_value_class("true") == "yaml-bool"

    def test_false(self):
        assert _yaml_value_class("false") == "yaml-bool"

    def test_integer(self):
        assert _yaml_value_class("42") == "yaml-number"

    def test_negative_number(self):
        assert _yaml_value_class("-3.14") == "yaml-number"

    def test_single_quoted_string(self):
        assert _yaml_value_class("'hello'") == "yaml-string"

    def test_double_quoted_string(self):
        assert _yaml_value_class('"hello"') == "yaml-string"

    def test_plain_value_returns_none(self):
        assert _yaml_value_class("hello") is None


class TestHighlightYamlValue:
    def test_empty_returns_as_is(self):
        assert _highlight_yaml_value("") == ""

    def test_whitespace_returns_as_is(self):
        assert _highlight_yaml_value("   ") == "   "

    def test_null_wrapped(self):
        result = _highlight_yaml_value("null")
        assert "yaml-null" in result

    def test_bool_wrapped(self):
        result = _highlight_yaml_value("false")
        assert "yaml-bool" in result

    def test_number_wrapped(self):
        result = _highlight_yaml_value("42")
        assert "yaml-number" in result

    def test_string_wrapped(self):
        result = _highlight_yaml_value('"value"')
        assert "yaml-string" in result

    def test_plain_value_unwrapped(self):
        assert _highlight_yaml_value("some_value") == "some_value"


class TestHighlightYaml:
    def test_highlight_yaml_keys(self):
        result = _highlight_yaml("key: value")
        assert "yaml-key" in result

    def test_highlight_yaml_list(self):
        result = _highlight_yaml("- item")
        assert result

    def test_highlight_yaml_comment(self):
        result = _highlight_yaml("# comment")
        assert "yaml-comment" in result

    def test_highlight_yaml_number_value(self):
        result = _highlight_yaml("count: 42")
        assert "yaml-number" in result

    def test_highlight_yaml_bool_value(self):
        result = _highlight_yaml("enabled: true")
        assert "yaml-bool" in result

    def test_highlight_yaml_null_value(self):
        result = _highlight_yaml("value: null")
        assert "yaml-null" in result

    def test_highlight_yaml_plain_line(self):
        result = _highlight_yaml("just some text")
        assert "just some text" in result


# ---------------------------------------------------------------------------
# Gherkin highlighting
# ---------------------------------------------------------------------------


class TestGherkinKeywordClass:
    def test_given(self):
        assert _gherkin_keyword_class("Given:") == "step-given"

    def test_when(self):
        assert _gherkin_keyword_class("When:") == "step-when"

    def test_then(self):
        assert _gherkin_keyword_class("Then:") == "step-then"

    def test_unknown(self):
        assert _gherkin_keyword_class("Unknown:") == "gherkin-keyword"


class TestApplyGherkinKeywordHighlight:
    def test_given_keyword(self):
        result = _apply_gherkin_keyword_highlight("Given the system is running")
        assert "gherkin-keyword" in result

    def test_when_keyword(self):
        result = _apply_gherkin_keyword_highlight("When the user sends a request")
        assert "gherkin-keyword" in result

    def test_no_keyword(self):
        result = _apply_gherkin_keyword_highlight("just a regular line")
        assert result == "just a regular line"


class TestHighlightGherkin:
    def test_given(self):
        result = _highlight_gherkin("Given the system is running")
        assert "step-given" in result
        assert "step-keyword" in result

    def test_then(self):
        result = _highlight_gherkin("Then the response should be valid")
        assert "step-then" in result
        assert "step-keyword" in result

    def test_comment(self):
        result = _highlight_gherkin("# a comment")
        assert "gherkin-comment-line" in result

    def test_tag(self):
        result = _highlight_gherkin("@some-tag")
        assert "gherkin-tag-line" in result

    def test_docstring_delimiter(self):
        result = _highlight_gherkin('Given a step\n"""\ndocstring\n"""')
        assert "step-docstring" in result

    def test_plain_line(self):
        result = _highlight_gherkin("just text")
        assert "just text" in result


# ---------------------------------------------------------------------------
# Eval gauge
# ---------------------------------------------------------------------------


class TestSafeFloat:
    def test_valid_float(self):
        assert _safe_float(3.14) == 3.14

    def test_int(self):
        assert _safe_float(42) == 42.0

    def test_string_number(self):
        assert _safe_float("0.85") == 0.85

    def test_invalid_string(self):
        assert _safe_float("abc") is None

    def test_none(self):
        assert _safe_float(None) is None


class TestGaugeColor:
    def test_green(self):
        assert _gauge_color(0.85) == "green"

    def test_green_boundary(self):
        assert _gauge_color(0.8) == "green"

    def test_yellow(self):
        assert _gauge_color(0.65) == "yellow"

    def test_yellow_boundary(self):
        assert _gauge_color(0.6) == "yellow"

    def test_red(self):
        assert _gauge_color(0.45) == "red"


class TestEvalGauge:
    def test_green_threshold(self):
        html = _build_eval_gauge("test_metric", 0.85)
        assert "green" in html.lower()

    def test_yellow_threshold(self):
        html = _build_eval_gauge("test_metric", 0.65)
        assert "yellow" in html.lower()

    def test_red_threshold(self):
        html = _build_eval_gauge("test_metric", 0.45)
        assert "red" in html.lower()


class TestAverageRateFields:
    def test_with_rate_fields(self):
        data = {"a_rate": 0.8, "b_rate": 0.6}
        assert _average_rate_fields(data) == 0.7

    def test_no_rate_fields(self):
        assert _average_rate_fields({"name": "test"}) is None

    def test_all_invalid(self):
        assert _average_rate_fields({"a_rate": "abc"}) is None

    def test_partial_invalid(self):
        data = {"a_rate": 0.8, "b_rate": "abc"}
        assert _average_rate_fields(data) == 0.8


class TestExtractMetricRate:
    def test_none_input(self):
        assert extract_metric_rate(None) is None

    def test_non_dict_input(self):
        assert extract_metric_rate("string") is None

    def test_with_rate_key(self):
        assert extract_metric_rate({"rate": 0.9}) == 0.9

    def test_with_rate_fields(self):
        data = {"a_rate": 0.8, "b_rate": 0.6}
        assert extract_metric_rate(data) == 0.7

    def test_no_rate(self):
        assert extract_metric_rate({"name": "test"}) is None

    def test_invalid_rate_value(self):
        assert extract_metric_rate({"rate": "abc"}) is None


class TestBuildEvalScorecard:
    def test_empty_data(self):
        html = _build_eval_scorecard(None)
        assert "No eval scorecard" in html

    def test_with_metrics(self):
        data = {"metrics": {"consistency": {"rate": 0.9}}}
        html = _build_eval_scorecard(data)
        assert "consistency" in html

    def test_metrics_not_dict(self):
        html = _build_eval_scorecard({"metrics": "bad"})
        assert "No eval scorecard" in html

    def test_metrics_with_no_rate(self):
        html = _build_eval_scorecard({"metrics": {"name": {"label": "test"}}})
        assert "eval-scorecard" not in html or "subsection" in html


# ---------------------------------------------------------------------------
# Attack tree
# ---------------------------------------------------------------------------


class TestRenderTreeChild:
    def test_leaf_with_details(self):
        child = {"label": "Leaf node", "details": "Some details"}
        result = _render_tree_child(child)
        assert any("tree-node-details" in r for r in result)

    def test_leaf_without_details(self):
        child = {"label": "Leaf node"}
        result = _render_tree_child(child)
        assert any("tree-leaf" in r for r in result)

    def test_with_children(self):
        child = {"label": "Parent", "children": [{"label": "Child1"}]}
        result = _render_tree_child(child)
        assert len(result) >= 2


class TestBuildTreeBranchNode:
    def test_with_category(self):
        branch = {"category": "controller_side", "label": "Test", "children": []}
        result = _build_tree_branch_node(branch)
        assert any("controller_side" in r for r in result)

    def test_without_category(self):
        branch = {"category": "", "label": "Test", "children": []}
        result = _build_tree_branch_node(branch)
        assert any("gate-and" in r for r in result)

    def test_with_children(self):
        branch = {
            "category": "path_side",
            "label": "Branch",
            "children": [{"label": "Child", "details": "Detail"}],
        }
        result = _build_tree_branch_node(branch)
        assert any("tree-node-details" in r for r in result)


class TestAttackTreeVisual:
    def test_empty_tree(self):
        html = _build_attack_tree_visual({})
        assert isinstance(html, str)

    def test_none_tree(self):
        html = _build_attack_tree_visual(None)
        assert "tree-empty" in html

    def test_tree_with_root_only(self):
        html = _build_attack_tree_visual({"root": "Goal"})
        assert "gate-or" in html
        assert "Goal" in html

    def test_tree_with_branches(self):
        tree = {
            "root": "Test root",
            "branches": [
                {"category": "controller_side", "label": "Corrupt PM", "children": []},
                {"category": "path_side", "label": "Actuator failure", "children": []},
            ],
        }
        html = _build_attack_tree_visual(tree)
        assert "controller_side" in html
        assert "path_side" in html

    def test_tree_with_leaves(self):
        tree = {"leaves": ["leaf-1", "leaf-2"]}
        html = _build_attack_tree_visual(tree)
        assert "tree-leaf" in html
        assert "leaf-1" in html
        assert "leaf-1" in html

    def test_tree_with_nested_children(self):
        tree = {
            "root": "Goal",
            "branches": [
                {
                    "category": "controller_side",
                    "label": "Branch",
                    "children": [
                        {"label": "Sub", "details": "Info", "children": [
                            {"label": "Deep leaf"},
                        ]},
                    ],
                },
            ],
        }
        html = _build_attack_tree_visual(tree)
        assert "Deep leaf" in html

    def test_empty_tree_dict_with_all_none(self):
        html = _build_attack_tree_visual({"root": "", "branches": [], "leaves": []})
        assert "tree-empty" in html


# ---------------------------------------------------------------------------
# Produces arrow and sticky nav
# ---------------------------------------------------------------------------


class TestProducesArrow:
    def test_arrow_is_div(self):
        html = _build_produces_arrow()
        assert isinstance(html, str)
        assert "produces-arrow" in html


class TestStickyNav:
    def test_nav_has_links(self):
        html = _build_sticky_nav()
        assert "SP1" in html
        assert "SP2" in html
        assert "SP3" in html

    def test_nav_has_anchors(self):
        html = _build_sticky_nav()
        assert "#sp1" in html
        assert "#calls" in html


# ---------------------------------------------------------------------------
# Raw YAML section
# ---------------------------------------------------------------------------


class TestBuildRawYamlSection:
    def test_basic_section(self):
        html = _build_raw_yaml_section("test.yaml", "key: value")
        assert "raw-yaml" in html
        assert "test.yaml" in html
        assert "yaml-key" in html

    def test_id_sanitization(self):
        html = _build_raw_yaml_section("file.with.dots.yaml", "key: value")
        assert "raw-file-with-dots-yaml" in html


# ---------------------------------------------------------------------------
# Table helpers
# ---------------------------------------------------------------------------


class TestBuildTableRows:
    def test_single_row(self):
        result = _build_table_rows([("a", "b")])
        assert "<td>a</td>" in result
        assert "<td>b</td>" in result

    def test_multiple_rows(self):
        result = _build_table_rows([("1", "2"), ("3", "4")])
        assert "<td>1</td>" in result
        assert "<td>4</td>" in result

    def test_empty_list(self):
        assert _build_table_rows([]) == ""


class TestBuildDataTable:
    def test_basic_table(self):
        html = _build_data_table(["A", "B"], "<tr><td>1</td></tr>")
        assert "data-table" in html
        assert "<th>A</th>" in html
        assert "<th>B</th>" in html


# ---------------------------------------------------------------------------
# Loss helpers
# ---------------------------------------------------------------------------


class TestLossToDict:
    def test_string_provenance(self):
        loss = _make_loss(provenance="use_case")
        result = _loss_to_dict(loss)
        assert result["id"] == "L-1"
        assert result["provenance"] == "use_case"

    def test_enum_provenance(self):
        loss = _make_loss(provenance=SimpleNamespace(value="risk_card"))
        result = _loss_to_dict(loss)
        assert result["provenance"] == "risk_card"


class TestLossAnalysisLosses:
    def test_empty(self):
        la = _make_loss_analysis()
        assert _loss_analysis_losses(la) == []

    def test_with_risk_card_losses(self):
        la = _make_loss_analysis(risk_card_losses=[_make_loss("L-1")])
        result = _loss_analysis_losses(la)
        assert len(result) == 1
        assert result[0]["id"] == "L-1"

    def test_with_use_case_losses(self):
        la = _make_loss_analysis(use_case_losses=[_make_loss("L-2")])
        result = _loss_analysis_losses(la)
        assert len(result) == 1
        assert result[0]["id"] == "L-2"

    def test_with_both(self):
        la = _make_loss_analysis(
            risk_card_losses=[_make_loss("L-1")],
            use_case_losses=[_make_loss("L-2")],
        )
        result = _loss_analysis_losses(la)
        assert len(result) == 2


# ---------------------------------------------------------------------------
# SP1 section builders
# ---------------------------------------------------------------------------


class TestBuildSp1LossesSection:
    def test_empty(self):
        la = _make_loss_analysis()
        html = _build_sp1_losses_section(la)
        assert "subsection" in html

    def test_with_losses(self):
        la = _make_loss_analysis(use_case_losses=[_make_loss("L-1")])
        html = _build_sp1_losses_section(la)
        assert "L-1" in html

    def test_with_hazards(self):
        la = _make_loss_analysis(hazards=[
            SimpleNamespace(hazard_id="H-1", description="Test hazard"),
        ])
        html = _build_sp1_losses_section(la)
        assert "H-1" in html

    def test_with_constraints(self):
        la = _make_loss_analysis(security_constraints=[
            SimpleNamespace(constraint_id="SC-1", description="Test constraint"),
        ])
        html = _build_sp1_losses_section(la)
        assert "SC-1" in html


class TestBuildSp1CapabilitySection:
    def test_empty(self):
        cp = _make_capability_profile()
        html = _build_sp1_capability_section(cp)
        assert "subsection" in html

    def test_with_zones(self):
        cp = _make_capability_profile(zones_active=["input", "reasoning"])
        html = _build_sp1_capability_section(cp)
        assert "zone-chip" in html
        assert "input" in html

    def test_with_kcs(self):
        cp = _make_capability_profile(kc_subcodes=["KC-01", "KC-02"])
        html = _build_sp1_capability_section(cp)
        assert "KC-01" in html


class TestBuildSp1ControlSection:
    def test_empty(self):
        cs = _make_control_structure()
        html = _build_sp1_control_section(cs)
        assert "subsection" in html

    def test_with_responsibilities(self):
        cs = _make_control_structure(responsibilities=[
            SimpleNamespace(resp_id="R-1", description="Test resp"),
        ])
        html = _build_sp1_control_section(cs)
        assert "R-1" in html


class TestBuildSp1Card:
    def test_all_none(self):
        html = build_sp1_card(None, None, None, None)
        assert "flow-card" in html
        assert "SP1" in html

    def test_with_loss_analysis(self):
        la = _make_loss_analysis(use_case_losses=[_make_loss()])
        html = build_sp1_card(la, None, None, None)
        assert "L-1" in html

    def test_with_raw_yaml(self):
        html = build_sp1_card(
            None, None, None,
            {"loss-analysis.yaml": "key: value"},
        )
        assert "raw-yaml" in html

    def test_with_all_artifacts(self):
        la = _make_loss_analysis(use_case_losses=[_make_loss()])
        cp = _make_capability_profile(zones_active=["input"])
        cs = _make_control_structure(responsibilities=[
            SimpleNamespace(resp_id="R-1", description="Resp"),
        ])
        html = build_sp1_card(la, cp, cs, {"loss-analysis.yaml": "key: val"})
        assert "SP1" in html
        assert "L-1" in html
        assert "input" in html
        assert "R-1" in html


# ---------------------------------------------------------------------------
# SP2 section builders
# ---------------------------------------------------------------------------


class TestBuildSp2IcaSection:
    def test_empty_slots(self):
        ica = _make_ica_enumeration()
        html = _build_sp2_ica_section(ica)
        assert "subsection" in html

    def test_with_slots(self):
        ica = _make_ica_enumeration(slots=[_make_ica_slot("S-1", "Provided")])
        html = _build_sp2_ica_section(ica)
        assert "S-1" in html
        assert "ICAs" in html

    def test_na_slot(self):
        ica = _make_ica_enumeration(slots=[_make_ica_slot("S-2", "N/A", is_na=True)])
        html = _build_sp2_ica_section(ica)
        assert "N/A" in html


class TestBuildSp2EnrichmentSection:
    def test_empty(self):
        et = _make_enriched_threat_set()
        html = _build_sp2_enrichment_section(et)
        assert "subsection" in html

    def test_with_threats(self):
        et = _make_enriched_threat_set(structural_threats=[
            _make_structural_threat("S-1", [_make_catalog_mapping("M-1")]),
        ])
        html = _build_sp2_enrichment_section(et)
        assert "S-1" in html
        assert "M-1" in html

    def test_with_no_mappings(self):
        et = _make_enriched_threat_set(structural_threats=[
            _make_structural_threat("S-1", []),
        ])
        html = _build_sp2_enrichment_section(et)
        assert "S-1" in html


class TestBuildSp2CoverageSection:
    def test_with_rate(self):
        et = _make_enriched_threat_set(
            coverage_analysis=_make_coverage_analysis(0.75),
        )
        html = _build_sp2_coverage_section(et)
        assert "75.0%" in html

    def test_without_rate(self):
        et = _make_enriched_threat_set(
            coverage_analysis=_make_coverage_analysis(),
        )
        html = _build_sp2_coverage_section(et)
        assert "subsection" in html


class TestBuildSp2Card:
    def test_all_none(self):
        html = build_sp2_card(None, None, None)
        assert "flow-card" in html
        assert "SP2" in html

    def test_with_ica(self):
        ica = _make_ica_enumeration(slots=[_make_ica_slot()])
        html = build_sp2_card(ica, None, None)
        assert "S-1" in html

    def test_with_enriched_threats(self):
        et = _make_enriched_threat_set(
            structural_threats=[_make_structural_threat()],
            coverage_analysis=_make_coverage_analysis(0.8),
        )
        html = build_sp2_card(None, et, None)
        assert "80.0%" in html

    def test_with_raw_yaml(self):
        html = build_sp2_card(None, None, {"ica-enumeration.yaml": "key: val"})
        assert "raw-yaml" in html


# ---------------------------------------------------------------------------
# BDI section
# ---------------------------------------------------------------------------


class TestBuildDefenderBdiBlock:
    def test_with_beliefs(self):
        bdi = _make_defender_bdi(beliefs=[
            SimpleNamespace(pm_id="PM-1", content="Test belief", vulnerability="vuln"),
        ])
        html = _build_defender_bdi_block(bdi)
        assert "PM-1" in html
        assert "Vulnerability" in html

    def test_with_desires(self):
        bdi = _make_defender_bdi(desires=[
            SimpleNamespace(resp_id="R-1", content="Test desire"),
        ])
        html = _build_defender_bdi_block(bdi)
        assert "Desire" in html
        assert "R-1" in html

    def test_with_intentions(self):
        bdi = _make_defender_bdi(intentions=[
            SimpleNamespace(ca_id="CA-1", content="Test intention"),
        ])
        html = _build_defender_bdi_block(bdi)
        assert "Intention" in html
        assert "CA-1" in html

    def test_empty(self):
        bdi = _make_defender_bdi()
        html = _build_defender_bdi_block(bdi)
        assert "Defender BDI" in html

    def test_belief_without_vulnerability(self):
        bdi = _make_defender_bdi(beliefs=[
            SimpleNamespace(pm_id="PM-1", content="Test", vulnerability=None),
        ])
        html = _build_defender_bdi_block(bdi)
        assert "PM-1" in html
        assert "Vulnerability" not in html


class TestBuildAttackerBdiBlock:
    def test_with_beliefs(self):
        bdi = _make_attacker_bdi(beliefs=["belief-1"])
        html = _build_attacker_bdi_block(bdi)
        assert "belief-1" in html

    def test_with_desires(self):
        bdi = _make_attacker_bdi(desires=["desire-1"])
        html = _build_attacker_bdi_block(bdi)
        assert "desire-1" in html

    def test_with_intentions(self):
        bdi = _make_attacker_bdi(intentions=["intention-1"])
        html = _build_attacker_bdi_block(bdi)
        assert "intention-1" in html

    def test_empty(self):
        bdi = _make_attacker_bdi()
        html = _build_attacker_bdi_block(bdi)
        assert "Attacker BDI" in html


class TestBuildBdiSection:
    def test_with_both(self):
        spec = _make_scenario_spec(
            defender_bdi=_make_defender_bdi(),
            attacker_bdi=_make_attacker_bdi(),
        )
        html = _build_bdi_section(spec)
        assert "Defender BDI" in html
        assert "Attacker BDI" in html

    def test_defender_only(self):
        spec = _make_scenario_spec(
            defender_bdi=_make_defender_bdi(),
            attacker_bdi=None,
        )
        html = _build_bdi_section(spec)
        assert "Defender BDI" in html
        assert "No data" in html

    def test_attacker_only(self):
        spec = _make_scenario_spec(
            defender_bdi=None,
            attacker_bdi=_make_attacker_bdi(),
        )
        html = _build_bdi_section(spec)
        assert "Attacker BDI" in html
        assert "No data" in html

    def test_both_none(self):
        spec = _make_scenario_spec()
        html = _build_bdi_section(spec)
        assert "No data" in html


# ---------------------------------------------------------------------------
# Scenario card
# ---------------------------------------------------------------------------


class TestBuildScenarioCard:
    def test_no_envelope_no_feature(self):
        html = _build_scenario_card("scen-1", None, None)
        assert "scen-1" in html
        assert "scenario-card" in html

    def test_with_feature_text(self):
        html = _build_scenario_card("scen-1", None, "Feature: Test")
        assert "gherkin-block" in html

    def test_with_envelope_narrative(self):
        env = _make_scenario_envelope(narrative="Attack narrative text")
        html = _build_scenario_card("scen-1", env, None)
        assert "narrative-text" in html
        assert "Attack narrative" in html

    def test_with_envelope_and_spec(self):
        env = _make_scenario_envelope(
            scenario_spec=_make_scenario_spec(
                defender_bdi=_make_defender_bdi(),
                attacker_bdi=_make_attacker_bdi(),
            ),
            narrative="Narrative",
            attack_tree={"root": "Goal"},
        )
        html = _build_scenario_card("scen-1", env, "Feature: Test")
        assert "BDI Models" in html
        assert "Narrative" in html
        assert "Attack Tree" in html
        assert "Gherkin" in html


# ---------------------------------------------------------------------------
# SP3 card
# ---------------------------------------------------------------------------


class TestBuildSp3Card:
    def test_empty_scenarios_no_eval(self):
        html = build_sp3_card([], None, None)
        assert "SP3" in html
        assert "Scenarios (0)" in html

    def test_with_scenarios(self):
        scenarios = [("scen-1", None, None)]
        html = build_sp3_card(scenarios, None, None)
        assert "scen-1" in html

    def test_with_eval_data(self):
        html = build_sp3_card([], {"metrics": {"test": {"rate": 0.9}}}, None)
        assert "test" in html

    def test_with_raw_yaml(self):
        html = build_sp3_card([], None, {"eval-scorecard.yaml": "key: val"})
        assert "raw-yaml" in html


# ---------------------------------------------------------------------------
# LLM call inspector
# ---------------------------------------------------------------------------


class TestBuildCallEntryHtml:
    def test_successful_call(self):
        entry = {"stage": "sp1", "step": "step1", "model": "gpt-4", "success": True}
        html = _build_call_entry_html(entry, 0)
        assert "call-entry" in html
        assert "sp1/step1" in html
        assert "OK" in html

    def test_failed_call(self):
        entry = {"stage": "sp2", "step": "step2", "success": False}
        html = _build_call_entry_html(entry, 1)
        assert "failed" in html
        assert "FAILED" in html

    def test_with_content_sections(self):
        entry = {
            "stage": "sp1", "step": "step1",
            "system_prompt_text": "system prompt",
            "user_prompt_text": "user prompt",
            "response_content": "response",
        }
        html = _build_call_entry_html(entry, 0)
        assert "system_prompt" in html
        assert "user_prompt" in html
        assert "response_content" in html

    def test_with_tokens_and_duration(self):
        entry = {
            "stage": "sp1", "step": "step1",
            "prompt_tokens": 100, "completion_tokens": 50, "duration_ms": 200,
        }
        html = _build_call_entry_html(entry, 0)
        assert "100" in html
        assert "200" in html


class TestBuildLlmCallInspector:
    def test_empty(self):
        html = build_llm_call_inspector([])
        assert "<strong>0</strong>" in html
        assert "Total" in html

    def test_with_calls(self):
        calls = [
            {"stage": "sp1", "step": "s1", "success": True},
            {"stage": "sp2", "step": "s2", "success": False},
        ]
        html = build_llm_call_inspector(calls)
        assert "<strong>2</strong>" in html
        assert "<strong>1</strong>" in html


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------


class TestBuildManifestGrid:
    def test_basic(self):
        html = _build_manifest_grid("run-1", "2026-01-01", "gpt-4", 4)
        assert "run-1" in html
        assert "2026-01-01" in html
        assert "gpt-4" in html
        assert "4" in html


class TestBuildManifestHashesTable:
    def test_with_hashes(self):
        html = _build_manifest_hashes_table({"file.yaml": "abc123"})
        assert "file.yaml" in html
        assert "abc123" in html

    def test_empty(self):
        html = _build_manifest_hashes_table({})
        assert "data-table" in html


class TestBuildRunManifest:
    def test_none_manifest(self):
        html = build_run_manifest(None, None)
        assert "No run manifest" in html

    def test_with_manifest(self):
        manifest = {"run_id": "test", "created_at": "2026-01-01"}
        html = build_run_manifest(manifest, None)
        assert "test" in html
        assert "2026-01-01" in html

    def test_with_model_config(self):
        manifest = {"run_id": "r", "model_config": {"model": "gpt-4"}}
        html = build_run_manifest(manifest, None)
        assert "gpt-4" in html

    def test_with_model_config_not_dict(self):
        manifest = {"run_id": "r", "model_config": "bad"}
        html = build_run_manifest(manifest, None)
        assert "N/A" in html

    def test_with_input_hashes(self):
        manifest = {"run_id": "r", "input_hashes": {"file.yaml": "hash123"}}
        html = build_run_manifest(manifest, None)
        assert "file.yaml" in html
        assert "hash123" in html

    def test_with_raw_yaml(self):
        manifest = {"run_id": "r"}
        html = build_run_manifest(manifest, {"run-manifest.yaml": "key: val"})
        assert "raw-yaml" in html


# ---------------------------------------------------------------------------
# Hero summary
# ---------------------------------------------------------------------------


class TestBuildHeroSummary:
    def test_all_none(self):
        html = _build_hero_summary(None, None, None, None)
        assert "N/A" in html
        assert "STPA-Sec Report" in html

    def test_with_data(self):
        html = _build_hero_summary("run-1", "2026-01-01", 5, None)
        assert "run-1" in html
        assert "2026-01-01" in html
        assert "5" in html

    def test_with_eval_metrics(self):
        html = _build_hero_summary("r", "ts", 3, {"consistency": 0.9})
        assert "consistency" in html
        assert "90%" in html

    def test_without_eval_metrics_shows_na(self):
        html = _build_hero_summary("r", "ts", 3, None)
        assert "N/A" in html


# ---------------------------------------------------------------------------
# build_html
# ---------------------------------------------------------------------------


class TestBuildHtml:
    def test_minimal(self):
        html = build_html()
        assert "<!DOCTYPE html>" in html
        assert "</html>" in html
        assert "<style>" in html
        assert "<script>" in html

    def test_with_all_sections(self):
        html = build_html(
            run_id="test",
            sp1_html="<div>SP1</div>",
            sp2_html="<div>SP2</div>",
            sp3_html="<div>SP3</div>",
            calls_html="<div>Calls</div>",
            manifest_html="<div>Manifest</div>",
            has_sp2=True,
            has_sp3=True,
        )
        assert "SP1" in html
        assert "SP2" in html
        assert "SP3" in html
        assert "Calls" in html
        assert '<div class="produces-arrow"' in html

    def test_without_sp2(self):
        html = build_html(sp1_html="<div>SP1</div>", has_sp2=False)
        assert '<div class="produces-arrow"' not in html

    def test_without_sp3(self):
        html = build_html(
            sp1_html="<div>SP1</div>",
            sp2_html="<div>SP2</div>",
            has_sp2=True,
            has_sp3=False,
               )
        # SP2 arrow present, SP3 arrow absent
        assert html.count('<div class="produces-arrow"') == 1


# ---------------------------------------------------------------------------
# Generator helpers
# ---------------------------------------------------------------------------


class TestReadDictFile:
    def test_missing_file(self, tmp_path):
        assert _read_dict_file(tmp_path / "missing.yaml", yaml.safe_load, "YAML") is None

    def test_valid_yaml(self, tmp_path):
        path = tmp_path / "test.yaml"
        path.write_text("key: value\n")
        result = _read_dict_file(path, yaml.safe_load, "YAML")
        assert result == {"key": "value"}

    def test_non_dict_result(self, tmp_path):
        path = tmp_path / "test.yaml"
        path.write_text("- item1\n- item2\n")
        assert _read_dict_file(path, yaml.safe_load, "YAML") is None

    def test_parse_error(self, tmp_path):
        path = tmp_path / "bad.yaml"
        path.write_text("{invalid yaml: [")
        assert _read_dict_file(path, yaml.safe_load, "YAML") is None


class TestReadYamlDict:
    def test_missing(self, tmp_path):
        assert _read_yaml_dict(tmp_path / "missing.yaml") is None

    def test_valid(self, tmp_path):
        path = tmp_path / "test.yaml"
        path.write_text("key: val\n")
        assert _read_yaml_dict(path) == {"key": "val"}

    def test_invalid(self, tmp_path):
        path = tmp_path / "bad.yaml"
        path.write_text("{bad: [")
        assert _read_yaml_dict(path) is None


class TestReadJsonDict:
    def test_missing(self, tmp_path):
        assert _read_json_dict(tmp_path / "missing.json") is None

    def test_valid(self, tmp_path):
        path = tmp_path / "test.json"
        path.write_text('{"key": "val"}')
        assert _read_json_dict(path) == {"key": "val"}

    def test_invalid(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text("{bad json")
        assert _read_json_dict(path) is None

    def test_non_dict(self, tmp_path):
        path = tmp_path / "list.json"
        path.write_text("[1, 2, 3]")
        assert _read_json_dict(path) is None


class TestReadCallsJsonl:
    def test_missing_file(self, tmp_path):
        assert _read_calls_jsonl(tmp_path / "missing.jsonl") == []

    def test_empty_file(self, tmp_path):
        path = tmp_path / "calls.jsonl"
        path.write_text("")
        assert _read_calls_jsonl(path) == []

    def test_valid_entries(self, tmp_path):
        path = tmp_path / "calls.jsonl"
        path.write_text('{"a": 1}\n{"b": 2}\n')
        result = _read_calls_jsonl(path)
        assert len(result) == 2
        assert result[0] == {"a": 1}

    def test_with_blank_lines(self, tmp_path):
        path = tmp_path / "calls.jsonl"
        path.write_text('{"a": 1}\n\n  \n{"b": 2}\n')
        result = _read_calls_jsonl(path)
        assert len(result) == 2

    def test_with_malformed_line(self, tmp_path):
        path = tmp_path / "calls.jsonl"
        path.write_text('{"a": 1}\n{bad json}\n{"b": 2}\n')
        result = _read_calls_jsonl(path)
        assert len(result) == 2


class TestLoadScenarios:
    def test_missing_dir(self, tmp_path):
        assert _load_scenarios(tmp_path / "scenarios") == []

    def test_with_scenarios(self, tmp_path):
        sc_dir = tmp_path / "scenarios"
        sc_dir.mkdir()
        (sc_dir / "scen-1.yaml").write_text("narrative: test\n")
        (sc_dir / "scen-1.feature").write_text("Feature: Test\n")
        result = _load_scenarios(sc_dir)
        assert len(result) == 1
        assert result[0][0] == "scen-1"
        assert result[0][2] == "Feature: Test\n"

    def test_without_feature_file(self, tmp_path):
        sc_dir = tmp_path / "scenarios"
        sc_dir.mkdir()
        (sc_dir / "scen-1.yaml").write_text("narrative: test\n")
        result = _load_scenarios(sc_dir)
        assert len(result) == 1
        assert result[0][2] is None

    def test_sorted_by_id(self, tmp_path):
        sc_dir = tmp_path / "scenarios"
        sc_dir.mkdir()
        (sc_dir / "scen-b.yaml").write_text("narrative: b\n")
        (sc_dir / "scen-a.yaml").write_text("narrative: a\n")
        result = _load_scenarios(sc_dir)
        assert result[0][0] == "scen-a"
        assert result[1][0] == "scen-b"


class TestLoadModelArtifact:
    def test_missing_file(self, tmp_path):
        class DummyModel:
            @staticmethod
            def model_validate(data):
                return data
        raw: dict[str, str] = {}
        result = _load_model_artifact(
            tmp_path / "missing.yaml", raw, DummyModel, "missing.yaml",
        )
        assert result is None
        assert raw == {}

    def test_valid_file(self, tmp_path):
        class DummyModel:
            @staticmethod
            def model_validate(data):
                return SimpleNamespace(data=data)
        path = tmp_path / "test.yaml"
        path.write_text("key: val\n")
        raw: dict[str, str] = {}
        result = _load_model_artifact(path, raw, DummyModel, "test.yaml")
        assert result is not None
        assert "test.yaml" in raw

    def test_parse_error(self, tmp_path):
        class DummyModel:
            @staticmethod
            def model_validate(data):
                raise ValueError("bad data")
        path = tmp_path / "test.yaml"
        path.write_text("key: val\n")
        raw: dict[str, str] = {}
        result = _load_model_artifact(path, raw, DummyModel, "test.yaml")
        assert result is None
        assert "test.yaml" in raw


class TestLoadRawYaml:
    def test_missing_file(self, tmp_path):
        raw: dict[str, str] = {}
        _load_raw_yaml(tmp_path / "missing.yaml", raw, "missing.yaml")
        assert raw == {}

    def test_existing_file(self, tmp_path):
        path = tmp_path / "test.yaml"
        path.write_text("key: val\n")
        raw: dict[str, str] = {}
        _load_raw_yaml(path, raw, "test.yaml")
        assert raw["test.yaml"] == "key: val\n"


class TestExtractEvalMetrics:
    def test_none(self):
        assert _extract_eval_metrics(None) is None

    def test_empty(self):
        assert _extract_eval_metrics({}) is None

    def test_with_metrics_key(self):
        data = {"metrics": {"consistency": {"rate": 0.9}}}
        result = _extract_eval_metrics(data)
        assert result == {"consistency": 0.9}

    def test_without_metrics_key(self):
        data = {"consistency": {"rate": 0.9}}
        result = _extract_eval_metrics(data)
        assert result == {"consistency": 0.9}

    def test_metrics_not_dict(self):
        assert _extract_eval_metrics({"metrics": "bad"}) is None

    def test_no_valid_rates(self):
        assert _extract_eval_metrics({"metrics": {"name": {"label": "test"}}}) is None


class TestExtractHeroData:
    def test_no_manifest(self):
        run_id, created_at, count, metrics = _extract_hero_data(None, [], None)
        assert run_id is None
        assert created_at is None
        assert count is None
        assert metrics is None

    def test_with_manifest(self):
        manifest = {"run_id": "r1", "created_at": "2026-01-01", "scenario_count": 5}
        run_id, created_at, count, metrics = _extract_hero_data(manifest, [], None)
        assert run_id == "r1"
        assert created_at == "2026-01-01"
        assert count == 5

    def test_scenario_count_from_scenarios(self):
        manifest = {"run_id": "r1"}
        scenarios = [("s1", None, None), ("s2", None, None)]
        _, _, count, _ = _extract_hero_data(manifest, scenarios, None)
        assert count == 2

    def test_with_eval_data(self):
        eval_data = {"metrics": {"consistency": {"rate": 0.9}}}
        _, _, _, metrics = _extract_hero_data(None, [], eval_data)
        assert metrics == {"consistency": 0.9}


# ---------------------------------------------------------------------------
# New helper function tests
# ---------------------------------------------------------------------------


class TestAttrList:
    def test_existing_list(self):
        obj = SimpleNamespace(items=["a", "b"])
        assert _attr_list(obj, "items") == ["a", "b"]

    def test_missing_attr(self):
        obj = SimpleNamespace()
        assert _attr_list(obj, "items") == []

    def test_none_value(self):
        obj = SimpleNamespace(items=None)
        assert _attr_list(obj, "items") == []


class TestIsQuotedString:
    def test_single_quoted(self):
        assert _is_quoted_string("'hello'") is True

    def test_double_quoted(self):
        assert _is_quoted_string('"hello"') is True

    def test_unquoted(self):
        assert _is_quoted_string("hello") is False

    def test_mismatched_quotes(self):
        assert _is_quoted_string("'hello\"") is False

    def test_empty_string(self):
        assert _is_quoted_string("") is False


class TestRateFieldValues:
    def test_with_rate_fields(self):
        data = {"a_rate": 0.8, "b_rate": 0.6, "name": "test"}
        result = _rate_field_values(data)
        assert result == [0.8, 0.6]

    def test_no_rate_fields(self):
        assert _rate_field_values({"name": "test"}) == []


class TestSafeFloats:
    def test_all_valid(self):
        assert _safe_floats([0.8, 0.6, "0.9"]) == [0.8, 0.6, 0.9]

    def test_with_invalid(self):
        assert _safe_floats([0.8, "abc", None]) == [0.8]

    def test_empty(self):
        assert _safe_floats([]) == []


class TestParseTreeDict:
    def test_full_tree(self):
        tree = {"root": "Goal", "branches": [{"label": "B"}], "leaves": ["L"]}
        root, branches, leaves = _parse_tree_dict(tree)
        assert root == "Goal"
        assert len(branches) == 1
        assert len(leaves) == 1

    def test_empty_tree(self):
        root, branches, leaves = _parse_tree_dict({})
        assert root == ""
        assert branches == []
        assert leaves == []

    def test_none_branches_and_leaves(self):
        root, branches, leaves = _parse_tree_dict(
            {"root": "G", "branches": None, "leaves": None}
        )
        assert root == "G"
        assert branches == []
        assert leaves == []


class TestHasTreeContent:
    def test_with_root(self):
        assert _has_tree_content("Goal", [], []) is True

    def test_with_branches(self):
        assert _has_tree_content("", [{"label": "B"}], []) is True

    def test_with_leaves(self):
        assert _has_tree_content("", [], ["L"]) is True

    def test_empty(self):
        assert _has_tree_content("", [], []) is False


class TestBuildRawYamlSections:
    def test_with_matching_files(self):
        raw = {"a.yaml": "key: val", "b.yaml": "key2: val2"}
        result = _build_raw_yaml_sections(raw, ("a.yaml", "b.yaml"))
        assert len(result) == 2
        assert "a.yaml" in result[0]

    def test_with_partial_match(self):
        raw = {"a.yaml": "key: val"}
        result = _build_raw_yaml_sections(raw, ("a.yaml", "b.yaml"))
        assert len(result) == 1

    def test_with_none(self):
        assert _build_raw_yaml_sections(None, ("a.yaml",)) == []

    def test_with_empty(self):
        assert _build_raw_yaml_sections({}, ("a.yaml",)) == []


class TestBuildLossesTable:
    def test_empty(self):
        assert _build_losses_table([]) == ""

    def test_with_losses(self):
        losses = [{"id": "L-1", "description": "Test", "provenance": "uc"}]
        html = _build_losses_table(losses)
        assert "data-table" in html
        assert "L-1" in html


class TestBuildHazardsTable:
    def test_empty(self):
        assert _build_hazards_table([]) == ""

    def test_with_hazards(self):
        hazards = [SimpleNamespace(hazard_id="H-1", description="Test")]
        html = _build_hazards_table(hazards)
        assert "data-table" in html
        assert "H-1" in html


class TestBuildConstraintsTable:
    def test_empty(self):
        assert _build_constraints_table([]) == ""

    def test_with_constraints(self):
        constraints = [SimpleNamespace(constraint_id="SC-1", description="Test")]
        html = _build_constraints_table(constraints)
        assert "data-table" in html
        assert "SC-1" in html


class TestResolveModelName:
    def test_with_model_config(self):
        manifest = {"model_config": {"model": "gpt-4"}}
        assert _resolve_model_name(manifest) == "gpt-4"

    def test_without_model_config(self):
        assert _resolve_model_name({}) == "N/A"

    def test_with_non_dict_model_config(self):
        manifest = {"model_config": "bad"}
        assert _resolve_model_name(manifest) == "N/A"

    def test_with_none_model_config(self):
        manifest = {"model_config": None}
        assert _resolve_model_name(manifest) == "N/A"

    def test_without_model_key(self):
        manifest = {"model_config": {"other": "val"}}
        assert _resolve_model_name(manifest) == "N/A"


class TestIsValidHashes:
    def test_valid_dict(self):
        assert _is_valid_hashes({"file": "hash"}) is True

    def test_empty_dict(self):
        assert _is_valid_hashes({}) is False

    def test_none(self):
        assert _is_valid_hashes(None) is False

    def test_non_dict(self):
        assert _is_valid_hashes("string") is False


class TestResolveOutputPath:
    def test_default_path(self, tmp_path):
        result = _resolve_output_path(tmp_path, None)
        assert result == tmp_path / "stpa-report.html"

    def test_custom_path(self, tmp_path):
        custom = tmp_path / "custom.html"
        result = _resolve_output_path(tmp_path, custom)
        assert result == custom


class TestBuildSp3Html:
    def test_no_data(self):
        assert _build_sp3_html([], None, {}) == ""

    def test_with_scenarios(self):
        html = _build_sp3_html([("s1", None, None)], None, {})
        assert "SP3" in html

    def test_with_eval_data(self):
        html = _build_sp3_html([], {"metrics": {}}, {})
        assert "SP3" in html


class TestComputeHasSp2:
    def test_with_html_and_ica(self):
        assert _compute_has_sp2("<div>", SimpleNamespace(), None) is True

    def test_with_html_and_threats(self):
        assert _compute_has_sp2("<div>", None, SimpleNamespace()) is True

    def test_with_empty_html(self):
        assert _compute_has_sp2("", SimpleNamespace(), None) is False

    def test_without_models(self):
        assert _compute_has_sp2("<div>", None, None) is False


# ---------------------------------------------------------------------------
# Generate report integration tests
# ---------------------------------------------------------------------------


class TestGenerateReport:
    def test_generate_from_minimal_dir(self, tmp_path):
        """Report generation works with a minimal output directory."""
        (tmp_path / "loss-analysis.yaml").write_text(
            "risk_card_losses: []\n"
            "use_case_losses:\n"
            "  - loss_id: L-1\n"
            "    description: Test loss\n"
            "    provenance: use_case\n"
            "hazards:\n"
            "  - hazard_id: H-1\n"
            "    description: Test hazard\n"
            "    related_losses: [L-1]\n"
            "security_constraints:\n"
            "  - constraint_id: SC-1\n"
            "    description: Test constraint\n"
            "    related_hazards: [H-1]\n"
        )
        (tmp_path / "run-manifest.yaml").write_text(
            "run_id: test-run\n"
            "created_at: '2026-08-10T12:00:00Z'\n"
        )

        result = generate_report(tmp_path)
        assert result.exists()
        html = result.read_text(encoding="utf-8")
        assert "<html" in html
        assert "</html>" in html
        assert "test-run" in html

    def test_generate_with_custom_output_path(self, tmp_path):
        """Report generation respects custom output path."""
        (tmp_path / "run-manifest.yaml").write_text("run_id: test\n")
        output_file = tmp_path / "custom-report.html"
        result = generate_report(tmp_path, output_file)
        assert result == output_file
        assert output_file.exists()

    def test_nonexistent_dir_raises(self):
        with pytest.raises(FileNotFoundError):
            generate_report(Path("/nonexistent/path"))

    def test_self_contained_no_external_deps(self, tmp_path):
        """Report HTML has no external dependencies."""
        (tmp_path / "run-manifest.yaml").write_text("run_id: test\n")
        result = generate_report(tmp_path)
        html = result.read_text(encoding="utf-8")
        assert '<link rel="stylesheet"' not in html
        assert '<link href=' not in html
        assert '<script src=' not in html
        assert '<img src="http' not in html

    def test_generate_with_klarna_fixtures(self, tmp_path):
        """Report generation works with real Klarna fixtures."""
        import shutil

        for name in ["loss_analysis_klarna.yaml", "capability_profile_klarna.yaml",
                      "control_structure_klarna.yaml"]:
            src = FIXTURES_DIR / name
            if src.exists():
                dest_name = name.replace("_klarna", "")
                shutil.copy(src, tmp_path / dest_name)

        for name in ["ica_enumeration_klarna.yaml", "enriched_threats_klarna.yaml"]:
            src = FIXTURES_DIR / name
            if src.exists():
                dest_name = name.replace("_klarna", "")
                shutil.copy(src, tmp_path / dest_name)

        (tmp_path / "run-manifest.yaml").write_text(
            "run_id: klarna-test\n"
            "created_at: '2026-08-10T12:00:00Z'\n"
        )

        result = generate_report(tmp_path)
        assert result.exists()
        html = result.read_text(encoding="utf-8")
        assert "klarna" in html.lower() or "Klarna" in html

    def test_generate_with_calls_jsonl(self, tmp_path):
        """Report includes LLM call inspector when calls.jsonl exists."""
        (tmp_path / "run-manifest.yaml").write_text("run_id: test\n")
        (tmp_path / "calls.jsonl").write_text(
            json.dumps({"stage": "sp1", "step": "s1", "success": True}) + "\n"
        )
        result = generate_report(tmp_path)
        html = result.read_text(encoding="utf-8")
        assert "call-entry" in html

    def test_generate_with_eval_scorecard(self, tmp_path):
        """Report includes eval scorecard when eval-scorecard.yaml exists."""
        (tmp_path / "run-manifest.yaml").write_text("run_id: test\n")
        (tmp_path / "eval-scorecard.yaml").write_text(
            "metrics:\n  consistency:\n    rate: 0.9\n"
        )
        result = generate_report(tmp_path)
        html = result.read_text(encoding="utf-8")
        assert "consistency" in html
        assert "90%" in html

    def test_generate_with_scenarios_dir(self, tmp_path):
        """Report includes scenarios from scenarios/ directory."""
        (tmp_path / "run-manifest.yaml").write_text("run_id: test\n")
        sc_dir = tmp_path / "scenarios"
        sc_dir.mkdir()
        (sc_dir / "scen-1.yaml").write_text(
            "narrative: Test attack\n"
            "scenario_spec: null\n"
            "attack_tree: null\n"
        )
        (sc_dir / "scen-1.feature").write_text("Feature: Test\n")
        result = generate_report(tmp_path)
        html = result.read_text(encoding="utf-8")
        assert "scen-1" in html

    def test_generate_with_coverage_gaps(self, tmp_path):
        """Report loads coverage-gaps.json without error."""
        (tmp_path / "run-manifest.yaml").write_text("run_id: test\n")
        (tmp_path / "coverage-gaps.json").write_text(
            json.dumps({"gaps": []})
        )
        result = generate_report(tmp_path)
        assert result.exists()

    def test_generate_with_malformed_yaml_artifact(self, tmp_path):
        """Report handles malformed YAML gracefully."""
        (tmp_path / "run-manifest.yaml").write_text("run_id: test\n")
        (tmp_path / "loss-analysis.yaml").write_text("{invalid: [\n")
        result = generate_report(tmp_path)
        assert result.exists()

    def test_generate_creates_parent_dirs(self, tmp_path):
        """Report creates parent directories for output path."""
        (tmp_path / "run-manifest.yaml").write_text("run_id: test\n")
        output = tmp_path / "subdir" / "report.html"
        generate_report(tmp_path, output)
        assert output.exists()

    def test_generate_with_manifest_input_hashes(self, tmp_path):
        """Report shows input hashes from manifest."""
        (tmp_path / "run-manifest.yaml").write_text(
            "run_id: test\n"
            "input_hashes:\n"
            "  file.yaml: abc123\n"
        )
        result = generate_report(tmp_path)
        html = result.read_text(encoding="utf-8")
        assert "file.yaml" in html
        assert "abc123" in html

    def test_generate_empty_dir(self, tmp_path):
        """Report generates with an empty directory (no artifacts)."""
        result = generate_report(tmp_path)
        assert result.exists()
        html = result.read_text(encoding="utf-8")
        assert "<html" in html


class TestGherkinLineHelpers:
    """Decomposed Gherkin highlighting helpers."""

    def test_gherkin_keyword_row_step(self):
        """_gherkin_keyword_row extracts step keywords."""
        assert _gherkin_keyword_row("Given the system") == ("Given", "the system", "step-given")
        assert _gherkin_keyword_row("* a bullet") == ("*", "a bullet", "step-star")

    def test_gherkin_keyword_row_header(self):
        """_gherkin_keyword_row normalizes header keywords."""
        assert _gherkin_keyword_row("Scenario Outline: demo") == (
            "Scenario Outline",
            "demo",
            "",
        )

    def test_gherkin_keyword_row_plain(self):
        """_gherkin_keyword_row returns None for plain lines."""
        assert _gherkin_keyword_row("just prose") is None

    def test_gherkin_decorative_row_tag_and_comment(self):
        """_gherkin_decorative_row renders tags and comments."""
        assert 'gherkin-tag-line' in _gherkin_decorative_row("@tag")
        assert 'gherkin-comment-line' in _gherkin_decorative_row("# note")
        assert _gherkin_decorative_row("plain") is None

    def test_gherkin_row_html_skips_empty(self):
        """_gherkin_row_html returns None for empty lines."""
        assert _gherkin_row_html("") is None

    def test_gherkin_row_html_plain_and_step(self):
        """_gherkin_row_html renders plain, step, and header rows."""
        assert "feature-step step-when" in _gherkin_row_html("When x happens")
        assert "font-size:13px" in _gherkin_row_html("unstructured text")
        assert 'Scenario:</span>' in _gherkin_row_html("Scenario: demo")

    def test_docstring_opening(self):
        """_docstring_opening collects the opening remainder."""
        assert _docstring_opening('"""') == []
        assert _docstring_opening('"""line one') == ["line one"]
        assert _docstring_opening("not a docstring") is None

    def test_docstring_row_html_closes(self):
        """_docstring_row_html renders the closing docstring row."""
        html = _docstring_row_html('"""', ["line one", "line two"])
        assert "line one\nline two" in html
        assert 'step-docstring' in html

    def test_advance_docstring_state_lifecycle(self):
        """_advance_docstring_state tracks open and close transitions."""
        result: list[str] = []
        state, lines = _advance_docstring_state('"""', False, [], result)
        assert state is True
        assert lines == []
        state, lines = _advance_docstring_state("content", True, lines, result)
        assert state is True
        assert lines == ["content"]
        state, lines = _advance_docstring_state('"""', True, lines, result)
        assert state is False
        assert lines == []
        assert len(result) == 1
        assert "content" in result[0]

    def test_highlight_gherkin_docstring_roundtrip(self):
        """_highlight_gherkin renders a docstring block end to end."""
        html = _highlight_gherkin('Scenario: s\n"""\nbody text\n"""')
        assert 'step-docstring' in html
        assert "body text" in html


class TestTabHelpers:
    """Scenario tab bar and panel helpers."""

    def test_tab_active_only_first(self):
        """_tab_active marks only the first tab."""
        assert _tab_active(0) == " active"
        assert _tab_active(1) == ""

    def test_build_tab_bar_and_panels(self):
        """_build_tab_bar and _build_tab_panels render matching rows."""
        contents = [("narrative", "n"), ("gherkin", "g")]
        bar = _build_tab_bar(contents, {"narrative": "Narrative", "gherkin": "Gherkin"})
        panels = _build_tab_panels(contents)
        assert bar[0].startswith('          <div class="scenario-tab active"')
        assert "Narrative" in bar[0]
        assert panels[0].startswith('        <div class="scenario-tab-content active"')
        assert 'data-tab-content="gherkin"' in panels[1]
        assert "g" in panels[1]

    def test_envelope_gherkin_text_prefers_spec(self):
        """_envelope_gherkin_text uses the structured spec's feature text."""
        spec = SimpleNamespace(to_feature_text=lambda: "Feature: from spec", feature="x")
        envelope = SimpleNamespace(gherkin_spec=spec, gherkin_raw="raw")
        assert _envelope_gherkin_text(envelope) == "Feature: from spec"

    def test_envelope_gherkin_text_falls_back_to_raw(self):
        """_envelope_gherkin_text falls back to the raw response."""
        envelope = SimpleNamespace(
            gherkin_spec=SimpleNamespace(feature="", to_feature_text=lambda: ""),
            gherkin_raw="raw text",
        )
        assert _envelope_gherkin_text(envelope) == "raw text"
        envelope2 = SimpleNamespace(gherkin_spec=None, gherkin_raw=None)
        assert _envelope_gherkin_text(envelope2) == ""

    def test_scenario_tab_contents_always_has_attack_tree(self):
        """_scenario_tab_contents collects narrative, tree, and gherkin tabs."""
        envelope = SimpleNamespace(
            scenario_spec=None,
            narrative="story",
            attack_tree={"root": "r", "branches": [], "leaves": ["l"]},
            gherkin_spec=None,
            gherkin_raw="Given x",
        )
        contents = _scenario_tab_contents(envelope)
        ids = [tab_id for tab_id, _ in contents]
        assert ids == ["narrative", "attack_tree", "gherkin"]

    def test_envelope_has_gherkin(self):
        """_envelope_has_gherkin detects raw or structured Gherkin."""
        assert _envelope_has_gherkin(SimpleNamespace(gherkin_raw="x", gherkin_spec=None)) is True
        assert _envelope_has_gherkin(SimpleNamespace(gherkin_raw=None, gherkin_spec=object())) is True
        assert _envelope_has_gherkin(SimpleNamespace(gherkin_raw=None, gherkin_spec=None)) is False
        assert _envelope_has_gherkin(None) is False

    def test_feature_text_section(self):
        """_feature_text_section renders the standalone Gherkin section."""
        parts = _feature_text_section("Given x")
        assert any("Gherkin Spec" in p for p in parts)
        assert any('gherkin-block' in p for p in parts)


class TestCapabilityKcHelpers:
    """Capability key-code row helpers."""

    def test_kc_item_html_with_label(self):
        """_kc_item_html includes the display label when distinct."""
        html = _kc_item_html("KC1", "Key Code One")
        assert "KC1" in html
        assert "Key Code One" in html

    def test_kc_item_html_without_label(self):
        """_kc_item_html omits the label when absent or identical."""
        assert "dup" not in _kc_item_html("KC1", "KC1")
        assert "label" not in _kc_item_html("KC1", "")

    def test_kc_item_rows(self):
        """_kc_item_rows builds one row per key code."""
        rows = _kc_item_rows(["KC1", "KC2"], {"KC1": "One"})
        assert len(rows) == 2
        assert "One" in rows[0]
        assert "KC2" in rows[1]


class TestTreeHelpers:
    """Attack tree visual decomposition helpers."""

    def test_tree_root_markup(self):
        """_tree_root_markup returns open/close details rows."""
        opening, closing = _tree_root_markup("root goal")
        assert "gate-or" in opening
        assert "root goal" in opening
        assert closing == "  </details>"

    def test_tree_leaf_markup(self):
        """_tree_leaf_markup renders one leaf row."""
        html = _tree_leaf_markup("leaf")
        assert "gate-leaf" in html
        assert "leaf" in html

    def test_tree_branch_rows(self):
        """_tree_branch_rows renders every branch node."""
        rows = _tree_branch_rows(
            [{"category": "path_side", "label": "b1", "children": []}]
        )
        assert any("b1" in row for row in rows)
        assert "cat-badge path_side" in "".join(rows)

    def test_tree_leaf_rows(self):
        """_tree_leaf_rows renders every flat leaf."""
        rows = _tree_leaf_rows(["l1", "l2"])
        assert len(rows) == 2
        assert "l1" in rows[0]
        assert "l2" in rows[1]
