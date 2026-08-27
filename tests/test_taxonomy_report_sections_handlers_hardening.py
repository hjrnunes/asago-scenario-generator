"""Hardening tests for the taxonomy report section step handlers.

The acceptance step handlers in
``acceptance/runtime_features/taxonomy_report_sections`` return ``(ok,
detail)`` tuples and fail *softly*: a missing piece of report content must
surface as ``ok=False`` rather than being silently accepted.  These tests pin
that fail-loudly contract for the compound membership checks, the index-0
sentinel boundaries (a row whose identifier appears at the very start of the
extracted region is still found), and the exactness of the fixture-building
Given handlers.

The handlers are pure/offline: a ``World`` carrying only the attributes the
handlers read is sufficient; no LLM endpoint is contacted.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Callable

import pytest

_PROJECT_ROOT = next(
    p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file()
)
sys.path.insert(0, str(_PROJECT_ROOT / "acceptance"))

from runtime_world import World  # noqa: E402

from runtime_features.taxonomy_report_sections import (  # noqa: E402
    given_profile,
    given_scenarios,
    then_atlas,
    then_behavior_spec,
    then_cards,
    then_coverage,
    then_diversity,
    then_matrix,
    then_panels,
    then_profile,
    then_summary,
    then_threats,
)
from runtime_features.taxonomy_report_sections._helpers import _card_region  # noqa: E402

Handler = Callable[[World, str, dict[str, Any]], tuple[bool, str]]


def _world(**overrides: Any) -> World:
    """World carrying just the report/section surface a handler reads."""
    world = World()
    world.trpt_html = ""
    world.trpt_scenarios = []
    world.trpt_profile_data = {}
    world.trpt_feature_files = {}
    for name, value in overrides.items():
        setattr(world, name, value)
    return world


# ---------------------------------------------------------------------------
# Fail-loudly contract: compound membership checks must report ok=False when
# any asserted member is missing from the report content.  Each case targets
# the conjunct the mutant relaxes, so the mutant's `or` result diverges from
# the honest `and` result.
# ---------------------------------------------------------------------------

FAIL_LOUDLY: list[tuple[str, Handler, str, str]] = [
    # --- Scenario cards (then_cards) ---
    (
        "signals values second pair differs",
        then_cards._h_ts_signals_values,
        'the priority signals grid shows the value "on" for "Technique Maturity" '
        'and "off" for "Risk Impact"',
        '<div id="sec-scenarios">'
        '<div class="signal-label">Technique Maturity</div>'
        '<div class="signal-value">on</div>'
        '<div class="signal-label">Risk Impact</div>'
        '<div class="signal-value">off-site</div>'
        "</div>",
    ),
    (
        "actor access entry point missing",
        then_cards._h_ts_actor_access,
        "the actor profile block shows the access provenance with ingress "
        '"network" and entry point "ze-query"',
        "Ingress: <strong>network</strong>",
    ),
    (
        "no-actor block with access provenance present",
        then_cards._h_ts_no_actor_block,
        'the scenario card for "s1" shows no actor profile block',
        'id="scenario-s1"><div>ACCESS PROVENANCE:</div>',
    ),
    (
        "leaf meta code missing",
        then_cards._h_ts_leaf_meta,
        'the leaf node meta shows "Wait" with code "AML.T0015"',
        "Wait",
    ),
    (
        "card title missing",
        then_cards._h_ts_scenario_card_title,
        'the report contains a scenario card for "s1" with the title "T1"',
        'id="scenario-s1"',
    ),
    (
        "badge score missing",
        then_cards._h_ts_card_badge_score,
        'the card shows the priority badge "HIGH" with the score "0.85"',
        '<div id="sec-scenarios"><span class="priority-badge">HIGH</span></div>',
    ),
    (
        "no-scenarios placeholder section without message",
        then_cards._h_ts_no_scenarios_placeholder,
        'the report contains a Scenarios section showing "No scenarios generated."',
        '<div id="sec-scenarios"></div>',
    ),
    # --- Raw panels and tabs (then_panels) ---
    (
        "yaml panel without key highlight",
        then_panels._h_ts_yaml_panel,
        'the YAML panel shows a highlighted comment, key "completeness", number '
        "value 3, boolean value true, and null value",
        '<div id="sec-raw"><span class="yaml-comment">#</span>'
        '<span class="yaml-number">3</span>'
        '<span class="yaml-bool">true</span>'
        '<span class="yaml-null">null</span></div>',
    ),
    (
        "yaml panel without number highlight",
        then_panels._h_ts_yaml_panel,
        'the YAML panel shows a highlighted comment, key "completeness", number '
        "value 3, boolean value true, and null value",
        '<div id="sec-raw"><span class="yaml-comment">#</span>'
        '<span class="yaml-key">completeness</span>'
        '<span class="yaml-bool">true</span>'
        '<span class="yaml-null">null</span></div>',
    ),
    (
        "yaml panel without boolean highlight",
        then_panels._h_ts_yaml_panel,
        'the YAML panel shows a highlighted comment, key "completeness", number '
        "value 3, boolean value true, and null value",
        '<div id="sec-raw"><span class="yaml-comment">#</span>'
        '<span class="yaml-key">completeness</span>'
        '<span class="yaml-number">3</span>'
        '<span class="yaml-null">null</span></div>',
    ),
    (
        "yaml panel without null highlight",
        then_panels._h_ts_yaml_panel,
        'the YAML panel shows a highlighted comment, key "completeness", number '
        "value 3, boolean value true, and null value",
        '<div id="sec-raw"><span class="yaml-comment">#</span>'
        '<span class="yaml-key">completeness</span>'
        '<span class="yaml-number">3</span>'
        '<span class="yaml-bool">true</span></div>',
    ),
    (
        "yaml quoted string with highlight class present",
        then_panels._h_ts_yaml_quoted,
        'the YAML panel renders the quoted string "confirmed" without a highlight class',
        '<div id="sec-raw">&quot;confirmed&quot;'
        '<span class="yaml-string">x</span></div>',
    ),
    (
        "gherkin panel without tag highlight",
        then_panels._h_ts_gherkin_panel,
        'the Gherkin panel shows a highlighted comment, tag "@smoke", and the '
        'keywords "Feature:" and "Given"',
        '<div id="sec-raw"><span class="gherkin-comment">#</span>'
        '<span class="gherkin-keyword">Feature:</span>'
        '<span class="gherkin-keyword">Given </span></div>',
    ),
    (
        "gherkin panel without feature keyword",
        then_panels._h_ts_gherkin_panel,
        'the Gherkin panel shows a highlighted comment, tag "@smoke", and the '
        'keywords "Feature:" and "Given"',
        '<div id="sec-raw"><span class="gherkin-comment">#</span>'
        '<span class="gherkin-tag">@smoke</span>'
        '<span class="gherkin-keyword">Given </span></div>',
    ),
    (
        "gherkin panel without given keyword",
        then_panels._h_ts_gherkin_panel,
        'the Gherkin panel shows a highlighted comment, tag "@smoke", and the '
        'keywords "Feature:" and "Given"',
        '<div id="sec-raw"><span class="gherkin-comment">#</span>'
        '<span class="gherkin-tag">@smoke</span>'
        '<span class="gherkin-keyword">Feature:</span></div>',
    ),
    (
        "generation inputs row without value",
        then_panels._h_ts_gen_inputs_row,
        'the Generation Inputs tab shows the row "Attack pattern" with the value '
        '"Prompt injection"',
        '<div id="sec-scenarios"><td>Attack pattern</td></div>',
    ),
    (
        "generation inputs em dash row without dash",
        then_panels._h_ts_gen_inputs_em_dash,
        'the Generation Inputs tab shows the row "Narrative summary" with the em dash "—"',
        '<div id="sec-scenarios"><td>Narrative summary</td></div>',
    ),
    (
        "behavior spec missing first step text",
        then_behavior_spec._h_ts_behavior_spec_steps,
        'the Behavior Spec tab of scenario "s1" shows the step keywords "Given", '
        '"When", and "Then" with the texts "A", "B", and "C"',
        'id="scenario-s1">'
        '<span class="step-keyword">Given</span>'
        '<span class="step-keyword">When</span>'
        '<span class="step-keyword">Then</span>'
        '<span class="step-text">B</span>'
        '<span class="step-text">C</span>',
    ),
    (
        "behavior spec missing second step text",
        then_behavior_spec._h_ts_behavior_spec_steps,
        'the Behavior Spec tab of scenario "s1" shows the step keywords "Given", '
        '"When", and "Then" with the texts "A", "B", and "C"',
        'id="scenario-s1">'
        '<span class="step-keyword">Given</span>'
        '<span class="step-keyword">When</span>'
        '<span class="step-keyword">Then</span>'
        '<span class="step-text">A</span>'
        '<span class="step-text">C</span>',
    ),
    (
        "behavior spec missing third step text",
        then_behavior_spec._h_ts_behavior_spec_steps,
        'the Behavior Spec tab of scenario "s1" shows the step keywords "Given", '
        '"When", and "Then" with the texts "A", "B", and "C"',
        'id="scenario-s1">'
        '<span class="step-keyword">Given</span>'
        '<span class="step-keyword">When</span>'
        '<span class="step-keyword">Then</span>'
        '<span class="step-text">A</span>'
        '<span class="step-text">B</span>',
    ),
    (
        "atlas none placeholder badge missing",
        then_atlas._h_ts_atlas_none,
        'the ATLAS Techniques tab shows the heading "Projected-step mappings" '
        'with the placeholder "none"',
        "Projected-step mappings",
    ),
    (
        "complexity final level missing",
        then_atlas._h_ts_complexity_levels,
        'the attack complexity block shows "Candidate lower bound" as "Advanced" '
        'and "Final required level" as "Expert"',
        '<div id="sec-scenarios">Candidate lower bound: Advanced</div>',
    ),
    # --- Capability profile (then_profile) ---
    (
        "profile inactive zone chip missing",
        then_profile._h_ts_profile_zone_chips,
        'the capability profile shows an active zone chip "Input" and an '
        'inactive zone chip "Planning"',
        '<div id="sec-profile"><span class="zone-chip active">Input</span></div>',
    ),
    (
        "profile flags second flag missing",
        then_profile._h_ts_profile_flags,
        'the capability profile shows the flag "Memory" on, the flag '
        '"Multi-Agent" off, and confidence "High"',
        '<div id="sec-profile">Capability Flags'
        '<span class="flag-dot on"></span>'
        '<span class="flag-label">Memory</span>'
        "Confidence: High</div>",
    ),
    (
        "profile flags confidence missing",
        then_profile._h_ts_profile_flags,
        'the capability profile shows the flag "Memory" on, the flag '
        '"Multi-Agent" off, and confidence "High"',
        '<div id="sec-profile">Capability Flags'
        '<span class="flag-dot on"></span>'
        '<span class="flag-label">Memory</span>'
        '<span class="flag-dot off"></span>'
        '<span class="flag-label">Multi-Agent</span></div>',
    ),
    (
        "profile completeness evidence missing",
        then_profile._h_ts_profile_completeness,
        'the capability profile shows entry point completeness "Confirmed" with '
        'the evidence "use-case.md"',
        '<div id="sec-profile"><span>Confirmed</span></div>',
    ),
    (
        "profile tool completeness message missing",
        then_profile._h_ts_profile_tool_completeness,
        'the capability profile shows tool inventory completeness "Partial" and '
        'the message "No evidence sources recorded"',
        '<div id="sec-profile"><span>Partial</span></div>',
    ),
    (
        "profile kc badge value missing",
        then_profile._h_ts_profile_kc,
        'the capability profile shows the KC sub-code badge "KC6.1.1"',
        '<div id="sec-profile"><span class="kc-badge"></span></div>',
    ),
    (
        "profile no entry point row but direction marker present",
        then_profile._h_ts_no_entry_point_row,
        "the capability profile renders no entry point row",
        '<div id="sec-profile"><span class="ep-direction"></span></div>',
    ),
    # --- Run summary (then_summary) ---
    (
        "run summary rejected stat missing",
        then_summary._h_ts_run_summary_stats,
        'the run summary shows "1" Failed, "3" Rejected, and the rejection rate "30.0%"',
        '<div id="sec-run-summary">'
        '<span class="stat-number">1</span>'
        '<span class="stat-label">Failed</span>'
        "<span>30.0%</span></div>",
    ),
    (
        "run summary rejection rate missing",
        then_summary._h_ts_run_summary_stats,
        'the run summary shows "1" Failed, "3" Rejected, and the rejection rate "30.0%"',
        '<div id="sec-run-summary">'
        '<span class="stat-number">1</span>'
        '<span class="stat-label">Failed</span>'
        '<span class="stat-number">3</span>'
        '<span class="stat-label">Rejected</span></div>',
    ),
    (
        "run summary temperature missing",
        then_summary._h_ts_run_summary_config,
        'the run summary shows model "gemma-3-27b", temperature "0.7", start '
        '"2026-08-24T10:00:00", and end "2026-08-24T10:05:30"',
        '<div id="sec-run-summary">gemma-3-27b</div>'
        "2026-08-24T10:00:00 2026-08-24T10:05:30",
    ),
    (
        "run summary end timestamp missing",
        then_summary._h_ts_run_summary_config,
        'the run summary shows model "gemma-3-27b", temperature "0.7", start '
        '"2026-08-24T10:00:00", and end "2026-08-24T10:05:30"',
        '<div id="sec-run-summary">gemma-3-27b</div><div>0.7</div>2026-08-24T10:00:00',
    ),
    # --- Threat surface assertions (then_threats) ---
    (
        "threat entry row values missing last value",
        then_threats._h_ts_entry_row_values,
        'the threat surface entry for "r1" shows the status badge "ACT" and the '
        'row values "v1", "v2", "v3", "v4", and "v5"',
        'id="sec-threats">r1</td>status-badge status-actionable'
        ">v1</span>>v2</span>>v3</span>>v4</span></tr>",
    ),
    (
        "threat outcomes chip missing",
        then_threats._h_ts_outcomes,
        'the threat surface entry for "r1" shows the outcomes "2 scenarios" with '
        'the chip "high"',
        'id="sec-threats">r1</td>>2 scenarios</tr>',
    ),
    (
        "coverage universe evidence missing",
        then_coverage._h_ts_coverage_universe,
        'the coverage universe card shows inventory completeness "Confirmed '
        'Complete" with the evidence "operator-confirmation.md"',
        '<div id="sec-coverage">Confirmed Complete</div>',
    ),
    (
        "coverage card attribution missing from window",
        then_coverage._h_ts_coverage_card_attribution,
        'the coverage card "Entry Points" shows the status "Covered" and the '
        'uncovered entry point "ze-query" with the attribution '
        '"deterministic_rule_rejection"',
        '<div id="sec-coverage">'
        '<span class="coverage-card-title">Entry Points</span>'
        '<span class="coverage-status coverage-status-ok">Covered</span>'
        "<span>Entry Points</span>ze-query"
        + "x" * 2500
        + "deterministic_rule_rejection</div>",
    ),
    (
        "coverage cards pair missing second card",
        then_coverage._h_ts_coverage_cards_pair,
        'the coverage section shows the "Entry Points" and "Zones" cards',
        '<div id="sec-coverage">Entry Points</div>',
    ),
    (
        "matrix cell missing scenario link",
        then_matrix._h_ts_matrix_cell,
        'the matrix shows for threat "T6" a count of 2 for technique "AML.T0015" '
        'linking to scenario "s1"',
        '<div id="sec-threat-matrix">class="matrix-count-link">2</a>AML.T0015</div>',
    ),
    (
        "matrix cell missing count",
        then_matrix._h_ts_matrix_cell,
        'the matrix shows for threat "T6" a count of 2 for technique "AML.T0015" '
        'linking to scenario "s1"',
        '<div id="sec-threat-matrix">class="matrix-count-link"'
        'href="#scenario-s1"AML.T0015</div>',
    ),
    (
        "matrix cell missing technique",
        then_matrix._h_ts_matrix_cell,
        'the matrix shows for threat "T6" a count of 2 for technique "AML.T0015" '
        'linking to scenario "s1"',
        '<div id="sec-threat-matrix">class="matrix-count-link"'
        'href="#scenario-s1">2</a></div>',
    ),
    (
        "roster no-technique row with technique present",
        then_matrix._h_ts_roster_no_technique,
        'the roster row for "s1" shows the attack pattern "AP-T6-01" with no '
        "technique value",
        '<div id="sec-threat-matrix">Scenario Roster'
        "<tr>s1 AP-T6-01 and AML.T0040</tr></div>",
    ),
    (
        "diversity type percent mismatch",
        then_diversity._h_ts_diversity_type,
        'the distribution shows the actor type "Cybercriminal" with the count 3 '
        "and 100 percent",
        '<div id="sec-diversity">'
        '<span class="diversity-bar-label">Cybercriminal</span>'
        '<div class="diversity-bar-fill">3</div>'
        '<span class="diversity-bar-count">90%</span></div>',
    ),
    (
        "coverage attribution outside the bounded window is not detected",
        then_coverage._h_ts_coverage_card_attribution,
        'the coverage card "Entry Points" shows the status "Covered" and the '
        'uncovered entry point "ze-query" with the attribution "far-behind"',
        '<div id="sec-coverage">'
        '<span class="coverage-card-title">Entry Points</span>'
        '<span class="coverage-status coverage-status-ok">Covered</span>'
        "<span>Entry Points</span>ze-query" + "y" * 3000 + "far-behind</div>",
    ),
]


@pytest.mark.parametrize(
    ("name", "handler", "text", "html"),
    FAIL_LOUDLY,
    ids=[case[0] for case in FAIL_LOUDLY],
)
def test_handler_fails_loudly_on_missing_content(
    name: str, handler: Handler, text: str, html: str
) -> None:
    """A missing asserted member must surface as ok=False, never a silent pass."""
    ok, _detail = handler(_world(trpt_html=html), text, {})
    assert ok is False


# ---------------------------------------------------------------------------
# Boundary contracts: markers at the very start of the extracted region are
# still found (the missing-marker sentinel is `== -1`, not `== 0`), and the
# actor-type distribution filter matches the declared type exactly.
# ---------------------------------------------------------------------------

POSITIVE_BOUNDARY: list[tuple[str, Handler, str, str]] = [
    (
        "scenario card marker at document start",
        lambda w, t, e: (True, _card_region(w.trpt_html, "s1")),
        "",
        'id="scenario-s1">rest',
    ),
    (
        "threat entry row at region start",
        then_threats._h_ts_entry_row_values,
        'the threat surface entry for "i" shows the status badge "ACT" and the '
        'row values "a", "b", "c", "d", and "e"',
        'id="sec-threats">i</td>status-badge status-actionable>a>b>c>d>e</tr>',
    ),
    (
        "threat entry status row at region start",
        then_threats._h_ts_entry_status,
        'the threat surface entry for "i" shows the status badge "ACT"',
        'id="sec-threats">i</td>status-badge status-actionable status-badge</tr>',
    ),
    (
        "threat outcomes row at region start",
        then_threats._h_ts_outcomes,
        'the threat surface entry for "i" shows the outcomes "2" with the chip "high"',
        'id="sec-threats">i</td>>2 high</tr>',
    ),
    (
        "roster row at roster start",
        then_matrix._h_ts_roster_row,
        'the roster row for "Scenario Roster" shows threat "T6", attack pattern '
        '"AP-T6-01", technique "AML.T0015", actor type "Cybercriminal", and '
        'capability "Advanced"',
        '<div id="sec-threat-matrix">Scenario Roster'
        "<tr>Scenario Roster T6 AP-T6-01 AML.T0015 Cybercriminal Advanced"
        "</tr></div>",
    ),
    (
        "roster no-technique row at roster start",
        then_matrix._h_ts_roster_no_technique,
        'the roster row for "Scenario Roster" shows the attack pattern "AP-T6-01" '
        "with no technique value",
        '<div id="sec-threat-matrix">Scenario Roster'
        "<tr>Scenario Roster AP-T6-01</tr></div>",
    ),
    (
        "diversity type exact match",
        then_diversity._h_ts_diversity_type,
        'the distribution shows the actor type "Cybercriminal" with the count 3 '
        "and 100 percent",
        '<div id="sec-diversity">'
        '<span class="diversity-bar-label">Cybercriminal</span>'
        '<div class="diversity-bar-fill">3</div>'
        '<span class="diversity-bar-count">100%</span></div>',
    ),
    (
        "coverage attribution within the bounded window is detected",
        then_coverage._h_ts_coverage_card_attribution,
        'the coverage card "Entry Points" shows the status "Covered" and the '
        'uncovered entry point "ze-query" with the attribution "nearby"',
        '<div id="sec-coverage">'
        '<span class="coverage-card-title">Entry Points</span>'
        '<span class="coverage-status coverage-status-ok">Covered</span>'
        "<span>Entry Points</span>ze-query nearby</div>",
    ),
]


@pytest.mark.parametrize(
    ("name", "handler", "text", "html"),
    POSITIVE_BOUNDARY,
    ids=[case[0] for case in POSITIVE_BOUNDARY],
)
def test_handler_contract_holds_at_boundary(
    name: str, handler: Handler, text: str, html: str
) -> None:
    """Boundary content is still asserted truthfully."""
    ok, _detail = handler(_world(trpt_html=html), text, {})
    assert ok is True


# ---------------------------------------------------------------------------
# Given-handler exactness: fixture data is recorded exactly as declared, and
# fixture mutations target the last scenario.
# ---------------------------------------------------------------------------


def test_profile_kc_subcode_recorded_exactly() -> None:
    """The declared KC sub-code is stored verbatim (not the whole step text)."""
    world = _world()
    ok, _detail = given_profile._h_profile_kc(
        world,
        'the capability profile declares the KC sub-code "KC6.1.1"',
        {},
    )
    assert ok is True
    assert world.trpt_profile_data["kc_subcodes"] == ["KC6.1.1"]


def test_feature_file_contains_only_declared_steps() -> None:
    """The fixture feature file contains exactly the declared step texts."""
    world = _world()
    ok, _detail = given_scenarios._h_contains_feature_file(
        world,
        'the run fixture contains scenario "s1" with a behavior feature '
        'file containing the steps "A", "B", and "C"',
        {},
    )
    assert ok is True
    assert world.trpt_feature_files["s1"] == "Feature: s1\n  A\n  B\n  C\n"


def test_last_scenario_is_the_mutation_target() -> None:
    """Fixture mutations land on the last declared scenario, not the first."""
    world = _world(trpt_scenarios=[{"scenario_id": "first"}, {"scenario_id": "second"}])
    ok, _detail = given_scenarios._h_actor_bdi(
        world,
        'the actor profile records the beliefs "B", the desires "D", the '
        'intentions "I", and the resources "R"',
        {},
    )
    assert ok is True
    assert world.trpt_scenarios[1]["actor_profile"]["beliefs"] == ["B"]
    assert "actor_profile" not in world.trpt_scenarios[0]
