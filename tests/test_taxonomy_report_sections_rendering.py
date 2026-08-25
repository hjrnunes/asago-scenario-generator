"""Unit tests for taxonomy/risk HTML report section rendering.

Driven through the public report entry
(:func:`asago_scenario_generator.report.generator.generate_report`) so the
behavior pinned by ``features/taxonomy_report_sections_rendering.feature``
is verified on the real rendered document: capability profile, threat
surface, coverage analysis, threat-technique matrix, actor profile
distribution, scenario cards (priority signals, actor profile, attack
tree, generation inputs, behavior spec, ATLAS techniques, attack
complexity), the run summary, pipeline call logs, and raw-data syntax
highlighting.  All fixtures are offline.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

from asago_scenario_generator.report.data import ReportData
from asago_scenario_generator.report.generator import generate_report


# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------


def _corpus_claims() -> list[dict[str, str]]:
    """Typed corpus-claim records the report generator requires."""
    return [
        {
            "category": "entry_points",
            "status": "not_applicable",
            "reason": "Acceptance fixture",
        },
        {
            "category": "tool_inventory",
            "status": "not_applicable",
            "reason": "Acceptance fixture",
        },
    ]


def _scenario(
    sid: str,
    *,
    priority: dict[str, Any] | None = None,
    narrative: dict[str, Any] | None = None,
    actor_profile: dict[str, Any] | None = None,
    attack_complexity_assessment: dict[str, Any] | None = None,
    attack_tree: dict[str, Any] | None = None,
    technique_scope_evidence: dict[str, Any] | None = None,
    scenario_seed_metadata: dict[str, Any] | None = None,
    candidate_filter: dict[str, Any] | None = None,
    taxonomy_chain: dict[str, Any] | None = None,
    capability_profile: dict[str, Any] | None = None,
    feature_files: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Build a reportable scenario with honest optional-field degradation."""
    scenario: dict[str, Any] = {
        "scenario_id": sid,
        "priority": priority if priority is not None else {"composite": 0.5},
        "narrative": narrative
        or {"title": sid, "summary": "", "entry_point": "", "zone_sequence": []},
        "faceting": {
            "taxonomy_chain": taxonomy_chain or {},
            "capability_profile": capability_profile or {},
        },
        "validation": {"semantic": {"corpus_claim_applicability": _corpus_claims()}},
    }
    if actor_profile is not None:
        scenario["actor_profile"] = actor_profile
    if attack_complexity_assessment is not None:
        scenario["attack_complexity_assessment"] = attack_complexity_assessment
    if attack_tree is not None:
        scenario["attack_tree"] = attack_tree
    if technique_scope_evidence is not None:
        scenario["technique_scope_evidence"] = technique_scope_evidence
    if scenario_seed_metadata is not None:
        scenario["scenario_seed_metadata"] = scenario_seed_metadata
    if candidate_filter is not None:
        scenario["candidate_filter"] = candidate_filter
    if feature_files and sid in feature_files:
        scenario.setdefault("_feature", feature_files[sid])
    return scenario


def _profile(**overrides: Any) -> dict[str, Any]:
    profile: dict[str, Any] = {
        "zones_active": [],
        "entry_points": [],
        "tool_inventory": [],
        "external_integrations": [],
    }
    profile.update(overrides)
    return profile


def _ts_entry(
    risk_id: str,
    risk_name: str,
    *,
    confidence: float = 0.0,
    owasp_llm_ids: list[str] | None = None,
    agentic_threat_ids: list[str] | None = None,
    attack_pattern_ids: list[str] | None = None,
    governance_only: bool = False,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "risk_card": {"risk_id": risk_id, "risk_name": risk_name},
        "owasp_llm_ids": owasp_llm_ids or [],
        "agentic_threat_ids": agentic_threat_ids or [],
        "attack_pattern_ids": attack_pattern_ids or [],
    }
    if confidence:
        entry["risk_card"]["confidence"] = confidence
    if governance_only:
        entry["governance_only"] = True
    return entry


def _coverage(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "coverage_gaps": {
            "uncovered_entry_points": [],
            "uncovered_zones": [],
            "uncovered_threats": [],
            "uncovered_attack_patterns": [],
        },
        "coverage_universe": {"completeness": "not_applicable"},
    }
    data.update(overrides)
    return data


def _manifest(**overrides: Any) -> dict[str, Any]:
    manifest: dict[str, Any] = {
        "seeds_generated": 0,
        "funnel": {},
        "scenarios_generated": 0,
        "scenarios_failed": 0,
        "config": {},
    }
    manifest.update(overrides)
    return manifest


# ---------------------------------------------------------------------------
# HTML extraction helpers
# ---------------------------------------------------------------------------


def _html(data: ReportData, tmp_path: Path) -> str:
    """Generate the report through the public entry and return its HTML."""
    report_path = generate_report(data, tmp_path)
    return report_path.read_text(encoding="utf-8")


def _card_region(html: str, sid: str) -> str:
    """Slice of the report containing the scenario card for *sid*."""
    marker = f'id="scenario-{sid}"'
    idx = html.find(marker)
    assert idx != -1, f"scenario card {sid} is not rendered"
    return html[idx:]


def _section_region(html: str, sid_attr: str) -> str:
    """Slice of the report containing the section with the given id attribute."""
    marker = f'id="{sid_attr}"'
    idx = html.find(marker)
    assert idx != -1, f"section {sid_attr!r} is not rendered"
    return html[idx : idx + 40000]


def _stats(region: str) -> dict[str, int]:
    """Return label -> count for every stat-number/stat-label pair."""
    return {
        label: int(count)
        for count, label in re.findall(
            r'<span class="stat-number">(\d+)</span>\s*'
            r'<span class="stat-label">([^<]+)</span>',
            region,
        )
    }


def _visible(fragment: str) -> str:
    """Strip markup for text-content assertions."""
    text = re.sub(r"<[^>]+>", "", fragment)
    text = (
        text.replace("&rarr;", "→")
        .replace("&ndash;", "–")
        .replace("&middot;", "·")
        .replace("&mdash;", "—")
        .replace("&amp;", "&")
        .replace("&quot;", '"')
        .replace("&nbsp;", " ")
        .replace("&#10;", " ")
        .replace("&and;", "∧")
        .replace("&or;", "∨")
        .replace("&bull;", "•")
    )
    return text.strip()


# ---------------------------------------------------------------------------
# 01/02: Capability profile
# ---------------------------------------------------------------------------


def test_capability_profile_composite_renders(tmp_path: Path) -> None:
    data = ReportData(
        profile_data=_profile(
            zones_active=["input", "tool_execution"],
            has_persistent_memory=True,
            multi_agent=False,
            hitl=True,
            confidence="high",
            entry_points=[
                {"name": "ze-query", "direction": "input"},
                {"name": "ze-rag", "direction": "bidirectional"},
            ],
            tool_inventory=[{"name": "Web search", "tool_id": "tool-web"}],
            external_integrations=[{"name": "OAuth IdP", "integration_id": "int-oidc"}],
            entry_point_completeness="confirmed",
            entry_point_evidence=["use-case.md"],
            tool_inventory_completeness="partial",
            kc_subcodes=["KC6.1.1"],
        )
    )

    html = _html(data, tmp_path)
    region = _section_region(html, "sec-profile")

    assert "<h2>Capability Profile</h2>" in region
    assert ">Schneider 5-Zone</span>" in region
    assert '<span class="zone-chip active"' in region and "Input Surfaces" in region
    assert (
        '<span class="zone-chip inactive"' in region
        and "Planning &amp; Reasoning" in region
    )

    memory_idx = region.find("Memory")
    flags_region = region[
        region.find("Capability Flags") : region.find("Entry Points") + 400
    ]
    assert '<span class="flag-dot on"></span>' in flags_region
    assert '<span class="flag-dot off"></span>' in flags_region
    assert "Multi-Agent" in flags_region
    assert "Confidence:" in flags_region and "High" in flags_region

    assert 'class="ep-direction" title="input">←</span>' in region
    assert 'class="ep-direction" title="bidirectional">↔</span>' in region
    assert "ze-query" in region and "ze-rag" in region

    assert "Web search" in region and "tool-web" in region
    assert "OAuth IdP" in region and "int-oidc" in region

    assert ">Confirmed</span>" in region
    assert "use-case.md" in region
    assert ">Partial</span>" in region
    assert "No evidence sources recorded" in region

    assert '<span class="kc-badge' in region and "KC6.1.1" in region
    assert memory_idx != -1


def test_capability_profile_degrades_empty_inventories(tmp_path: Path) -> None:
    data = ReportData(profile_data=_profile(zones_active=["input"]))

    html = _html(data, tmp_path)
    region = _section_region(html, "sec-profile")

    assert "No tools inventoried" in region
    assert "No external integrations inventoried" in region
    assert "No evidence sources recorded" in region
    assert "ep-direction" not in region
    assert ">Entry Points</div>" not in region


# ---------------------------------------------------------------------------
# 03/04/05: Threat surface
# ---------------------------------------------------------------------------


def test_threat_surface_actionable_and_governance_distinct(tmp_path: Path) -> None:
    data = ReportData(
        threat_surface_data={
            "entries": [
                _ts_entry(
                    "atlas-phishing",
                    "Spear phishing",
                    confidence=0.85,
                    owasp_llm_ids=["LLM01"],
                    agentic_threat_ids=["T6"],
                    attack_pattern_ids=["AP-T6-01"],
                )
            ],
            "governance_only": [
                _ts_entry(
                    "atlas-copyright",
                    "Copyright compliance",
                    governance_only=True,
                )
            ],
        }
    )

    html = _html(data, tmp_path)
    region = _section_region(html, "sec-threats")

    assert ">1 actionable / 1 governance</span>" in region
    assert '<span class="status-badge status-actionable">ACT</span>' in region
    assert '<span class="status-badge status-governance">GOV</span>' in region
    assert "Spear phishing" in region
    assert ">0.85</td>" in region
    assert "LLM01" in region and "T6" in region and "AP-T6-01" in region
    gov_row = region[region.find("atlas-copyright") :]
    gov_row = gov_row[: gov_row.find("</tr>")]
    assert "-" in gov_row
    assert "LLM01" not in gov_row


def test_threat_surface_empty_renders_placeholders(tmp_path: Path) -> None:
    data = ReportData(threat_surface_data={"entries": [], "governance_only": []})

    html = _html(data, tmp_path)
    region = _section_region(html, "sec-threats")

    assert ">0 actionable / 0 governance</span>" in region
    assert "No actionable entries to visualize." in region


def test_threat_surface_outcomes_column_scenario_priority(tmp_path: Path) -> None:
    data = ReportData(
        threat_surface_data={
            "entries": [
                _ts_entry(
                    "atlas-phishing",
                    "Spear phishing",
                    agentic_threat_ids=["T6"],
                )
            ],
            "governance_only": [],
        },
        scenarios=[
            _scenario(
                "scn-a",
                priority={"composite": 0.85},
                taxonomy_chain={
                    "owasp_llm_ids": ["LLM01"],
                    "agentic_threat_ids": ["T6"],
                },
            )
        ],
    )

    html = _html(data, tmp_path)
    region = _section_region(html, "sec-threats")

    assert ">Outcomes</th>" in region
    assert "1 scenarios" in region
    assert "1 high" in region


# ---------------------------------------------------------------------------
# 06/07: Coverage analysis
# ---------------------------------------------------------------------------


def test_coverage_full_covers_every_card_and_sidebar_link(tmp_path: Path) -> None:
    data = ReportData(
        coverage_data=_coverage(
            coverage_universe={
                "completeness": "confirmed_complete",
                "evidence_refs": ["operator-confirmation.md"],
            }
        )
    )

    html = _html(data, tmp_path)
    region = _section_region(html, "sec-coverage")

    assert ">Full Coverage</span>" in region
    statuses = re.findall(
        r'<span class="coverage-status coverage-status-[\w-]+">Covered</span>', region
    )
    assert len(statuses) == 4
    assert "All confirmed entry points have scenario coverage." in region
    assert "All active zones are traversed by scenarios." in region
    assert "All in-scope threats have scenario coverage." in region
    assert "All in-scope attack patterns have scenario coverage." in region
    assert "Confirmed Complete" in region
    assert "operator-confirmation.md" in region
    assert '<a href="#sec-coverage">' in html


def test_coverage_gaps_counts_tiers_and_attributions(tmp_path: Path) -> None:
    data = ReportData(
        coverage_data=_coverage(
            coverage_gaps={
                "uncovered_entry_points": [
                    {"name": "ze-query", "entry_point_id": "ze-query"},
                    {"name": "ze-eph", "entry_point_id": "ze-eph"},
                    {"name": "ze-s3", "entry_point_id": "ze-s3"},
                ],
                "uncovered_zones": ["reasoning"],
                "uncovered_threats": ["T3", "T5"],
                "uncovered_attack_patterns": [],
                "gap_attributions": {
                    "entry_points": {"ze-query": "deterministic_rule_rejection"}
                },
            },
            coverage_universe={
                "completeness": "partial",
                "feasible_targets": [
                    {
                        "name": "ze-query",
                        "entry_point_id": "ze-query",
                        "direction": "input",
                        "controllability": "direct",
                    },
                    {
                        "name": "ze-rag",
                        "entry_point_id": "ze-rag",
                        "direction": "bidirectional",
                        "controllability": "direct",
                    },
                ],
                "excluded_targets": [
                    {
                        "name": "ze-legacy",
                        "entry_point_id": "ze-legacy",
                        "reason": "deprecated",
                    }
                ],
            },
        )
    )

    html = _html(data, tmp_path)
    region = _section_region(html, "sec-coverage")

    assert ">6 gaps</span>" in region
    assert ">3 gaps</span>" in region
    assert "ze-query" in region
    assert "rejected by deterministic rules" in region
    assert ">1 gap</span>" in region
    assert ">2 gaps</span>" in region
    assert "Feasible Targets (2)" in region
    assert "Excluded Targets (1)" in region


# ---------------------------------------------------------------------------
# 08/09: Threat-technique matrix and roster
# ---------------------------------------------------------------------------


def _matrix_scenario(sid: str, threat: str, seed: str, techniques: list[str]) -> dict:
    return _scenario(
        sid,
        taxonomy_chain={
            "agentic_threat_ids": [threat],
            "atlas_technique_ids": techniques,
            "scenario_seed": seed,
        },
    )


def test_threat_technique_matrix_and_roster_render(tmp_path: Path) -> None:
    scn_a = _matrix_scenario("scn-a", "T6", "AP-T6-01", ["AML.T0015"])
    scn_a["candidate_filter"] = {
        "pinned_technique_ids": ["AML.T0015"],
        "pinned_technique_names": ["Phishing"],
    }
    scn_a["actor_profile"] = {
        "actor_type": "cybercriminal",
        "capability_level": "advanced",
    }
    scn_b = _matrix_scenario("scn-b", "T11", "AP-T11-01", ["AML.T0015", "AML.T0040"])
    scn_b["candidate_filter"] = {
        "pinned_technique_ids": ["AML.T0040"],
        "pinned_technique_names": ["LLM Data Leakage"],
    }
    scn_b["actor_profile"] = {
        "actor_type": "nation-state",
        "capability_level": "expert",
    }

    data = ReportData(scenarios=[scn_a, scn_b])

    html = _html(data, tmp_path)
    region = _section_region(html, "sec-threat-matrix")

    assert "Threat&ndash;Technique Matrix" in region
    assert "2/17 threats" in region
    assert "2 techniques" in region
    assert "2 scenarios" in region
    assert 'class="matrix-count-link"' in region
    assert 'href="#scenario-scn-a"' in region
    assert 'href="#scenario-scn-b"' in region

    roster = region[region.find("Scenario Roster") :]
    assert "AP-T6-01" in roster and "AML.T0015" in roster
    assert "Cybercriminal" in roster and "Advanced" in roster
    assert "AP-T11-01" in roster and "Nation State" in roster
    assert "Expert" in roster


def test_threat_technique_matrix_degrades_without_techniques(tmp_path: Path) -> None:
    scn_a = _matrix_scenario("scn-a", "T6", "AP-T6-01", [])

    data = ReportData(scenarios=[scn_a])

    html = _html(data, tmp_path)
    region = _section_region(html, "sec-threat-matrix")

    assert "1/17 threats" in region
    assert "0 techniques" in region
    assert "1 scenarios" in region
    assert "matrix-col-header" not in region
    roster = region[region.find("Scenario Roster") :]
    row_start = roster.find("scn-a")
    assert row_start != -1
    scn_a_row = roster[row_start : roster.find("</tr>", row_start)]
    assert "AP-T6-01" in scn_a_row
    assert "AML." not in scn_a_row


# ---------------------------------------------------------------------------
# 10: Actor profile distribution
# ---------------------------------------------------------------------------


def test_actor_distribution_monotone_warning_and_goals(tmp_path: Path) -> None:
    scenarios = [
        _scenario(
            f"scn-{i}",
            actor_profile={
                "actor_type": "cybercriminal",
                "capability_level": "advanced",
                "goal_category_parent": "integrity",
            },
        )
        for i in range(3)
    ]

    data = ReportData(scenarios=scenarios)

    html = _html(data, tmp_path)
    region = _section_region(html, "sec-diversity")

    assert ">1 type</span>" in region
    assert "Cybercriminal" in region
    assert re.search(r'class="diversity-bar-fill"[^>]*>\s*3\s*</div>', region)
    assert "100%" in region
    assert (
        "Low actor diversity: 100% of scenarios use the Cybercriminal actor type."
        in _visible(region)
    )
    assert "Integrity" in region
    assert "1 category" in region


# ---------------------------------------------------------------------------
# 11/12: Priority signals grid
# ---------------------------------------------------------------------------


def test_priority_signals_grid_renders_six_values(tmp_path: Path) -> None:
    data = ReportData(
        scenarios=[
            _scenario(
                "scn-a",
                priority={
                    "composite": 0.72,
                    "signals": {
                        "technique_maturity": "realized",
                        "risk_impact": "critical",
                        "risk_likelihood": "high",
                        "attack_complexity": "medium",
                        "architecture_match": "explicit",
                        "structural_exposure": "elevated",
                    },
                },
            )
        ]
    )

    html = _html(data, tmp_path)
    region = _card_region(html, "scn-a")

    assert 'class="signals-grid"' in region
    for label in (
        "Technique Maturity",
        "Risk Impact",
        "Risk Likelihood",
        "Attack Complexity",
        "Architecture Match",
        "Structural Exposure",
    ):
        assert f">{label}</div>" in region
    assert ">Realized</div>" in region
    assert ">Critical</div>" in region


def test_priority_signals_grid_omitted_without_signals(tmp_path: Path) -> None:
    data = ReportData(scenarios=[_scenario("scn-a", priority={"composite": 0.5})])

    html = _html(data, tmp_path)

    assert "signals-grid" not in _card_region(html, "scn-a")


# ---------------------------------------------------------------------------
# 13/14: Actor profile block
# ---------------------------------------------------------------------------


def test_actor_profile_block_renders_bdi_and_access(tmp_path: Path) -> None:
    data = ReportData(
        scenarios=[
            _scenario(
                "scn-a",
                actor_profile={
                    "actor_type": "malicious-insider",
                    "capability_level": "advanced",
                    "goal_category_name": "Sell stolen data",
                    "beliefs": ["Data is not monitored"],
                    "desires": ["Exfiltrate the billing database"],
                    "intentions": ["Move laterally to the data store"],
                    "resources": ["Incident response creds"],
                    "access": {
                        "ingress_mode": "network",
                        "initial_entry_point_id": "ze-query",
                        "influence_source": "helpdesk",
                    },
                },
            )
        ]
    )

    html = _html(data, tmp_path)
    region = _card_region(html, "scn-a")

    assert ">Malicious Insider</span>" in region
    assert ">Advanced</span>" in region
    assert ">Sell Stolen Data</span>" in region
    assert "Data is not monitored" in region
    assert "Exfiltrate the billing database" in region
    assert "Move laterally to the data store" in region
    assert "Incident response creds" in region
    assert "Ingress: <strong>network</strong>" in region
    assert "Entry point ID: <code>ze-query</code>" in region
    assert "Influence source: <code>helpdesk</code>" in region


def test_actor_profile_block_omitted_when_absent(tmp_path: Path) -> None:
    data = ReportData(scenarios=[_scenario("scn-b")])

    html = _html(data, tmp_path)
    region = _card_region(html, "scn-b")

    assert "BELIEFS:" not in region
    assert "Malicious Insider" not in region
    assert "ACCESS PROVENANCE:" not in region


# ---------------------------------------------------------------------------
# 15/16: Attack tree
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tree", "rendered", "leaf_count", "details_open"),
    [
        (
            {
                "goal": "Gain access",
                "root": {
                    "gate": "OR",
                    "label": "Gain access",
                    "children": [
                        {
                            "gate": "LEAF",
                            "label": "Leaf A",
                            "technique_id": "AML.T0015",
                        },
                        {
                            "gate": "LEAF",
                            "label": "Leaf B",
                            "technique_id": "AML.T0040",
                        },
                    ],
                },
            },
            ["gate-or", "AML.T0015", "AML.T0040"],
            2,
            True,
        ),
        (
            {
                "goal": "Exfiltrate data",
                "root": {"gate": "LEAF", "label": "Exfiltrate data"},
            },
            [],
            1,
            False,
        ),
        ({"goal": "Gain access"}, [], 0, False),
    ],
)
def test_attack_tree_node_shapes(
    tmp_path: Path,
    tree: dict[str, Any],
    rendered: list[str],
    leaf_count: int,
    details_open: bool,
) -> None:
    data = ReportData(scenarios=[_scenario("scn-a", attack_tree=tree)])

    html = _html(data, tmp_path)
    region = _card_region(html, "scn-a")

    for marker in rendered:
        assert marker in region
    assert region.count('class="tree-leaf"') == leaf_count
    assert ("<details open" in region) is details_open
    if not rendered and leaf_count == 0:
        assert "gate-or" not in region and "gate-and" not in region


def test_attack_tree_unresolved_resource_ids(tmp_path: Path) -> None:
    tree = {
        "goal": "Gain access",
        "root": {
            "gate": "OR",
            "label": "Gain access",
            "children": [
                {
                    "gate": "LEAF",
                    "label": "Run the tool",
                    "action": {"kind": "tool_invocation", "tool_id": "tool-code"},
                },
                {
                    "gate": "LEAF",
                    "label": "Enter the portal",
                    "action": {
                        "kind": "initial_ingress",
                        "entry_point_id": "ze-gone",
                        "zone": "input",
                    },
                },
            ],
        },
    }

    data = ReportData(
        profile_data=_profile(),
        scenarios=[_scenario("scn-a", attack_tree=tree)],
    )

    html = _html(data, tmp_path)
    region = _card_region(html, "scn-a")

    assert "Tool: Unresolved" in region
    assert "<code>tool-code</code>" in region
    assert "Entry Point: Unresolved" in region
    assert "<code>ze-gone</code>" in region


# ---------------------------------------------------------------------------
# 17/18/19: Scenarios dashboard and cards
# ---------------------------------------------------------------------------


def test_scenarios_dashboard_stats_and_card_titles(tmp_path: Path) -> None:
    data = ReportData(
        scenarios=[
            _scenario(
                "scn-a",
                priority={"composite": 0.85},
                narrative={
                    "title": "Phishing the support desk",
                    "summary": "",
                    "entry_point": "",
                    "zone_sequence": [],
                },
                taxonomy_chain={"agentic_threat_ids": ["T6"]},
            ),
            _scenario(
                "scn-b",
                priority={"composite": 0.35},
                narrative={
                    "title": "Exfiltrate via RAG",
                    "summary": "",
                    "entry_point": "",
                    "zone_sequence": [],
                },
                taxonomy_chain={"agentic_threat_ids": ["T11"]},
            ),
        ]
    )

    html = _html(data, tmp_path)
    region = _section_region(html, "sec-scenarios")
    stats = _stats(region)

    assert stats["In Report"] == 2
    assert stats["High Priority"] == 1
    assert stats["Medium Priority"] == 0
    assert stats["Low Priority"] == 1
    assert stats["Coverage Gaps"] == 0
    assert "Phishing the support desk" in region
    assert "Exfiltrate via RAG" in region


def test_minimal_scenario_card_keeps_every_tab(tmp_path: Path) -> None:
    # A scenario with only its scenario ID carries no priority block, so the
    # composite defaults to zero (LOW, 0.00).
    scenario = _scenario("scn-min", priority=None)
    scenario.pop("priority")
    data = ReportData(scenarios=[scenario])

    html = _html(data, tmp_path)
    region = _card_region(html, "scn-min")

    assert re.search(r'class="priority-badge"[^>]*>\s*LOW\s*</span>', region)
    assert "0.00" in region
    for label in (
        "Provenance",
        "Generation Inputs",
        "Actor Profile",
        "ATLAS Techniques",
        "Narrative",
        "Attack Tree",
        "Behavior Spec",
        "Priority Signals",
        "LLM Calls",
    ):
        assert f">{label}</label>" in region
    assert "zone-crumb" not in region


def test_empty_scenarios_placeholder(tmp_path: Path) -> None:
    data = ReportData(scenarios=[])

    html = _html(data, tmp_path)

    assert "No scenarios generated." in html


# ---------------------------------------------------------------------------
# 20/21/22: Run summary
# ---------------------------------------------------------------------------


def test_run_summary_funnel_outcomes_and_config(tmp_path: Path) -> None:
    data = ReportData(
        scenarios=[_scenario("scn-a", priority={"composite": 0.85})],
        manifest_data=_manifest(
            seeds_generated=12,
            funnel={
                "expanded_instances": 10,
                "filter_submitted": 6,
                "filter_accepted": 3,
            },
            scenarios_generated=4,
            scenarios_failed=1,
            config={"model": "gemma-3-27b", "temperature": 0.7},
            timestamp_start="2026-08-24T10:00:00",
            timestamp_end="2026-08-24T10:05:30",
        ),
    )

    html = _html(data, tmp_path)
    region = _section_region(html, "sec-run-summary")
    stats = _stats(region)

    assert stats["Seeds Generated"] == 12
    assert stats["Candidates Expanded"] == 10
    assert stats["Candidates Accepted"] == 3
    assert stats["Scenarios Generated"] == 4
    assert stats["In Report"] == 1
    assert stats["Failed"] == 1
    assert stats["Rejected"] == 3
    assert ">30.0%</span>" in region
    assert "5m 30s" in region
    assert "gemma-3-27b" in region
    assert ">0.7</div>" in region
    assert "2026-08-24T10:00:00" in region
    assert "2026-08-24T10:05:30" in region


def test_run_summary_omitted_without_manifest(tmp_path: Path) -> None:
    data = ReportData(scenarios=[_scenario("scn-a")])

    html = _html(data, tmp_path)

    assert "<h2>Run Summary</h2>" not in html
    assert '<a href="#sec-run-summary">' not in html


def test_run_summary_honest_absence_values(tmp_path: Path) -> None:
    data = ReportData(
        scenarios=[_scenario("scn-a")],
        manifest_data=_manifest(),
    )

    html = _html(data, tmp_path)
    region = _section_region(html, "sec-run-summary")

    assert "<h2>Run Summary</h2>" in region
    assert ">N/A</span>" in region
    assert ">unknown</div>" in region
    assert region.count(">N/A</div>") >= 3


# ---------------------------------------------------------------------------
# 23: Raw data highlighting
# ---------------------------------------------------------------------------


def test_raw_data_yaml_and_gherkin_highlighting(tmp_path: Path) -> None:
    data = ReportData(
        raw_files={
            "capability-profile.yaml": (
                "# profile snippet\n"
                'completeness: "confirmed"\n'
                "count: 3\n"
                "enabled: true\n"
                "note: null\n"
            ),
            "scenario.feature": (
                "# smoke suite\n@smoke\nFeature: Demo\n  Given a precondition\n"
            ),
        }
    )

    html = _html(data, tmp_path)
    region = _section_region(html, "sec-raw")

    assert ">2 files</span>" in region
    assert 'class="yaml-comment"' in region
    assert 'class="yaml-key">completeness</span>' in region
    assert 'class="yaml-number">3</span>' in region
    assert 'class="yaml-bool">true</span>' in region
    assert 'class="yaml-null">null</span>' in region
    assert "&quot;confirmed&quot;" in region
    assert "yaml-string" not in region
    assert 'class="gherkin-comment"' in region
    assert 'class="gherkin-tag">@smoke</span>' in region
    assert 'class="gherkin-keyword">Feature:</span>' in region
    assert 'class="gherkin-keyword">Given </span>' in region


# ---------------------------------------------------------------------------
# 24: Generation inputs block
# ---------------------------------------------------------------------------


def test_generation_inputs_block_values_and_em_dash(tmp_path: Path) -> None:
    data = ReportData(
        scenarios=[
            _scenario(
                "scn-a",
                scenario_seed_metadata={
                    "attack_pattern_name": "Prompt injection",
                    "threat_id": "T6",
                    "threat_name": "Social engineering",
                },
                taxonomy_chain={"atlas_technique_ids": ["AML.T0015"]},
                narrative={
                    "title": "Phish the desk",
                    "summary": "",
                    "entry_point": "",
                    "zone_sequence": [],
                },
            )
        ]
    )

    html = _html(data, tmp_path)
    region = _card_region(html, "scn-a")

    assert "Call 0: Actor Profile" in region
    assert "Call 3: Behavior Spec" in region
    assert ">Attack pattern</td>" in region
    assert ">Prompt injection</td>" in region
    assert "T6 — Social engineering" in region
    assert ">ATLAS techniques</td>" in region
    assert "AML.T0015" in region
    assert ">Narrative summary</td>" in region
    assert ">—</td>" in region


# ---------------------------------------------------------------------------
# 25: Behavior spec
# ---------------------------------------------------------------------------


def test_behavior_spec_steps_and_degradation(tmp_path: Path) -> None:
    feature_content = (
        "Feature: Support desk phishing\n"
        "  Given a precondition\n"
        "  When the event occurs\n"
        "  Then the outcome holds\n"
    )
    data = ReportData(
        scenarios=[
            _scenario("scn-a"),
            _scenario("scn-b"),
        ],
        feature_files={"scn-a": feature_content},
    )

    html = _html(data, tmp_path)
    scn_a = _card_region(html, "scn-a")
    scn_b = _card_region(html, "scn-b")

    assert 'class="step-keyword">Given</span>' in scn_a
    assert 'class="step-keyword">When</span>' in scn_a
    assert 'class="step-keyword">Then</span>' in scn_a
    assert 'class="step-text">a precondition</span>' in scn_a
    assert 'class="step-text">the event occurs</span>' in scn_a
    assert 'class="step-text">the outcome holds</span>' in scn_a
    assert "No behavior specification available." in scn_b


# ---------------------------------------------------------------------------
# 26: ATLAS techniques block
# ---------------------------------------------------------------------------


def test_atlas_techniques_scope_and_none_placeholder(tmp_path: Path) -> None:
    data = ReportData(
        scenarios=[
            _scenario(
                "scn-a",
                taxonomy_chain={"atlas_technique_ids": ["AML.T0015"]},
                technique_scope_evidence={
                    "scenario_classification_ids": ["AML.T0015"],
                    "projected_step_mapping_ids": [],
                },
            )
        ]
    )

    html = _html(data, tmp_path)
    region = _card_region(html, "scn-a")

    assert "Scenario classifications" in region
    assert "AML.T0015" in region
    assert "Projected-step mappings" in region
    assert '<span class="prov-badge prov-badge-muted">none</span>' in region


# ---------------------------------------------------------------------------
# 27/28: Attack complexity assessment
# ---------------------------------------------------------------------------


def test_attack_complexity_assessment_block(tmp_path: Path) -> None:
    data = ReportData(
        scenarios=[
            _scenario(
                "scn-a",
                attack_complexity_assessment={
                    "rule_version": 3,
                    "candidate_lower_bound": {"required_level": "advanced"},
                    "final": {
                        "required_level": "expert",
                        "reasons": [
                            {
                                "rule_id": "R-7",
                                "required_level": "expert",
                                "detail": "requires chaining three tools",
                                "evidence": [{"kind": "projection", "ref_id": "R7"}],
                            }
                        ],
                    },
                },
            )
        ]
    )

    html = _html(data, tmp_path)
    region = _card_region(html, "scn-a")

    assert "ATTACK COMPLEXITY (RULE V3):" in region
    assert "Candidate lower bound: " in _visible(region)
    assert ">Advanced</span>" in region
    assert "Final required level: " in _visible(region)
    assert ">Expert</span>" in region
    reason_line = re.search(r"<code>R-7</code> &rarr; <strong>expert</strong>", region)
    assert reason_line is not None
    assert "requires chaining three tools" in region
    assert "[projection:R7]" in region


def test_attack_complexity_omitted_when_absent(tmp_path: Path) -> None:
    data = ReportData(scenarios=[_scenario("scn-b")])

    html = _html(data, tmp_path)

    assert "ATTACK COMPLEXITY" not in _card_region(html, "scn-b")


# ---------------------------------------------------------------------------
# 29: Pipeline call logs
# ---------------------------------------------------------------------------


def test_pipeline_call_logs_usage_totals_and_semantic_status(tmp_path: Path) -> None:
    data = ReportData(
        pipeline_call_logs=[
            {
                "call": "candidate_filter",
                "prompt_tokens": 100,
                "completion_tokens": 40,
                "duration_ms": 25,
                "semantic_evidence": {
                    "stage": "candidate_filter",
                    "accepted_draft_digest": "abc123",
                    "attempts": [{"result": "accepted"}],
                    "warnings": ["presentation_fallback: raw JSON payload"],
                },
            },
            {
                "call": "capability_profile",
                "prompt_tokens": 50,
                "completion_tokens": 20,
                "duration_ms": 15,
                "semantic_evidence": {
                    "stage": "capability_profile",
                    "attempts": [{"result": "invalid"}],
                },
            },
        ]
    )

    html = _html(data, tmp_path)
    region = _section_region(html, "sec-pipeline-calls")

    assert "<h2>Pipeline LLM Calls</h2>" in region
    assert "2 call(s)" in region
    assert "150 prompt tokens" in region
    assert "60 completion tokens" in region
    assert "40ms total" in region
    visible = _visible(region)
    assert "Candidate Filter semantic draft: Accepted provider semantics" in visible
    assert "Capability Profile semantic draft: Rejected: invalid" in visible
    assert "Presentation fallback used:" in visible
    assert "raw JSON payload" in visible


# ---------------------------------------------------------------------------
# 30: Threat surface count badges
# ---------------------------------------------------------------------------


def test_threat_surface_count_badges_for_many_mappings(tmp_path: Path) -> None:
    data = ReportData(
        threat_surface_data={
            "entries": [
                _ts_entry(
                    "atlas-phishing",
                    "Spear phishing",
                    confidence=0.85,
                    owasp_llm_ids=["LLM01"],
                    agentic_threat_ids=["T6", "T7", "T8"],
                    attack_pattern_ids=["AP-T6-01", "AP-T7-01", "AP-T8-01"],
                )
            ],
            "governance_only": [],
        }
    )

    html = _html(data, tmp_path)
    region = _section_region(html, "sec-threats")

    assert ">1 actionable / 0 governance</span>" in region
    assert '<span class="count-badge"' in region
    assert "3 threats" in region
    assert "3 patterns" in region


# ---------------------------------------------------------------------------
# 31: Behavior spec headers, tags, docstrings, And/But steps, zone badges
# ---------------------------------------------------------------------------


def test_behavior_spec_headers_steps_docstring_and_zone_badges(tmp_path: Path) -> None:
    feature_content = (
        "@smoke\n"
        "Feature: Phish suite\n"
        "Scenario: Phish the desk\n"
        "  And escalate privileges\n"
        "  Given access through (Zone input)\n"
        "  But hold the session\n"
        "  the platform times out\n"
        '  """\n'
        "  requires a compromised credential\n"
        '  """\n'
    )
    data = ReportData(
        scenarios=[_scenario("scn-a")],
        feature_files={"scn-a": feature_content},
    )

    html = _html(data, tmp_path)
    region = _card_region(html, "scn-a")

    assert re.search(r"Feature:</span>\s*Phish suite</div>", region)
    assert re.search(r"Scenario:</span>\s*Phish the desk</div>", region)
    assert (
        'class="step-keyword">And</span><span class="step-text">'
        "escalate privileges</span>" in region
    )
    assert (
        'class="step-keyword">But</span><span class="step-text">'
        "hold the session</span>" in region
    )
    assert (
        'class="step-keyword">Given</span><span class="step-text">'
        'access through (Zone input)<span class="zone-badge"' in region
    )
    assert ">Input Surfaces</span>" in region
    assert "the platform times out" in region
    assert (
        '<div class="step-docstring">requires a compromised credential</div>' in region
    )
    # Tag lines are skipped inside the rendered spec block (the raw-data
    # section later in the document still shows the fixture feature file).
    spec_start = region.find('<div class="feature-spec">')
    assert spec_start != -1
    spec_end = region.find('<div class="tab-panel">', spec_start)
    assert spec_end != -1
    assert "@smoke" not in region[spec_start:spec_end]


def test_behavior_spec_display_name_zone_badge(tmp_path: Path) -> None:
    feature_content = (
        "Feature: Zone display names\n"
        "Scenario: Use display names\n"
        "  Given access through (Zone Tool Execution)\n"
    )
    data = ReportData(
        scenarios=[_scenario("scn-a")],
        feature_files={"scn-a": feature_content},
    )

    html = _html(data, tmp_path)
    region = _card_region(html, "scn-a")

    assert (
        'class="step-keyword">Given</span><span class="step-text">'
        'access through (Zone Tool Execution)<span class="zone-badge"' in region
    )
    assert ">Tool Execution</span>" in region


# ---------------------------------------------------------------------------
# 32: Per-scenario LLM call entries
# ---------------------------------------------------------------------------


def test_per_scenario_llm_call_entries_usage_and_failure_markers(
    tmp_path: Path,
) -> None:
    data = ReportData(
        scenarios=[_scenario("scn-a")],
        call_logs={
            "scn-a": [
                {
                    "call": "actor_profile",
                    "prompt_tokens": 100,
                    "completion_tokens": 40,
                    "duration_ms": 250,
                    "system_prompt": "Assess the profile",
                    "user_prompt": "Profile the capability",
                    "success": True,
                },
                {
                    "call": "behavior_spec",
                    "prompt_tokens": 30,
                    "completion_tokens": 10,
                    "duration_ms": 80,
                    "system_prompt": "Generate the feature",
                    "user_prompt": "Write the behavior",
                    "success": False,
                    "error": "timeout",
                },
            ]
        },
    )

    html = _html(data, tmp_path)
    region = _card_region(html, "scn-a")

    assert "Call 0: Actor Profile (100 prompt / 40 completion tokens, 250ms)" in region
    assert (
        "Call 1: Behavior Spec (30 prompt / 10 completion tokens, 80ms)"
        " FAILED: timeout" in region
    )
    assert 'class="call-log-pre"' in region
    for prompt in ("Assess the profile", "Profile the capability"):
        assert prompt in region
    for prompt in ("Generate the feature", "Write the behavior"):
        assert prompt in region


def test_per_scenario_llm_call_anomaly_badges(tmp_path: Path) -> None:
    # 20 sampled calls (a single extreme outlier plus a consistent baseline)
    # so call stats are computed and the outlier is flagged slow / high tokens.
    baseline_duration, baseline_prompt, baseline_completion = 50, 100, 40
    calls = [
        {
            "call": "narrative",
            "prompt_tokens": baseline_prompt,
            "completion_tokens": baseline_completion,
            "duration_ms": baseline_duration,
            "success": True,
        }
        for _ in range(19)
    ]
    calls.append(
        {
            "call": "narrative",
            "prompt_tokens": 1000,
            "completion_tokens": 400,
            "duration_ms": 5000,
            "success": True,
        }
    )

    data = ReportData(
        scenarios=[_scenario("scn-a")],
        call_logs={"scn-a": calls},
    )

    html = _html(data, tmp_path)
    region = _card_region(html, "scn-a")

    assert 'class="call-anomaly-badge">⚠ slow</span>' in region
    assert 'class="call-anomaly-badge">⚠ high tokens</span>' in region
    assert 'class="expandable call-anomaly"' in region
    assert "Call 0: Narrative (100 prompt / 40 completion tokens, 50ms)" in region
    assert "Call 19: Narrative (1000 prompt / 400 completion tokens, 5000ms)" in region


# ---------------------------------------------------------------------------
# 33/38: Categorized coverage summary, plan, and category cards
# ---------------------------------------------------------------------------


def test_coverage_categorized_summary_plan_and_not_confirmed_universe(
    tmp_path: Path,
) -> None:
    data = ReportData(
        coverage_data=_coverage(
            coverage_summary={
                "covered_feasible": ["AP-T6-01"],
                "selection_limitations": [
                    {
                        "entry_point_id": "ze-query",
                        "reason": "selection_limitation",
                        "detail": "candidate queue saturated",
                        "candidate_ids": ["cand-42"],
                    }
                ],
                "policy_exclusions": [
                    {"entry_point_id": "ze-license", "reason": "out_of_scope"}
                ],
            },
            coverage_plan={
                "schema_version": 1,
                "targets": [
                    {
                        "entry_point_id": "ze-query",
                        "entry_point_name": "ze-query",
                        "primary_candidate_id": "cand-42",
                        "primary_state": "planned",
                        "ordered_choices": [
                            {"candidate_id": "cand-42"},
                            {"candidate_id": "cand-7"},
                        ],
                    }
                ],
            },
        )
    )

    html = _html(data, tmp_path)
    region = _section_region(html, "sec-coverage")

    assert ">Known Targets Covered</span>" in region
    assert (
        "All identified feasible entry points have scenario coverage; "
        "inventory completeness is not confirmed." in region
    )
    assert "All active zones are traversed by scenarios." in region
    assert "All in-scope threats have scenario coverage." in region
    assert "All in-scope attack patterns have scenario coverage." in region
    assert "Covered Feasible Targets" in region
    assert ">AP-T6-01</li>" in region
    assert "Selection Limitations" in region
    visible = _visible(region)
    assert "cap overflow (coverage preserved)" in visible
    assert "candidate queue saturated" in visible
    assert ">cand-42</code>" in region
    assert "Policy Exclusions" in region
    assert "out of scope" in visible
    assert "Coverage Plan (schema v1)" in region
    assert "ze-query" in region
    assert ">planned</td>" in region
    assert "Not Applicable (Inferred Partial)" in region
    assert "No operator-confirmed evidence" in region


def test_coverage_remaining_category_cards_render(tmp_path: Path) -> None:
    data = ReportData(
        coverage_data=_coverage(
            coverage_summary={
                "structural_gaps": [
                    {"entry_point_id": "ze-query", "reason": "projection_limitation"}
                ],
                "runtime_generation_gaps": [
                    {
                        "entry_point_id": "ze-rag",
                        "reason": "generation_exhaustion",
                    }
                ],
                "quarantine_admission_failures": [
                    {"entry_point_id": "ze-scan", "reason": "admission_failure"}
                ],
                "projection_limitations": [
                    {"entry_point_id": "ze-parse", "reason": "projection_limitation"}
                ],
            }
        )
    )

    html = _html(data, tmp_path)
    region = _section_region(html, "sec-coverage")

    assert ">Known Targets Covered</span>" in region
    assert "Structural / Projection Gaps" in region
    assert "Runtime Generation Gaps" in region
    assert "Quarantine / Admission Failures" in region
    assert "Projection Limitations" in region
    for entry in ("ze-query", "ze-rag", "ze-scan", "ze-parse"):
        assert entry in region
    assert "generation exhausted" in _visible(region)
    assert "admission failure" in _visible(region)


# ---------------------------------------------------------------------------
# 34: Run summary outcome summary and coverage gaps card
# ---------------------------------------------------------------------------


def test_run_summary_outcome_summary_and_coverage_gaps_card(tmp_path: Path) -> None:
    data = ReportData(
        scenarios=[
            _scenario("scn-a", priority={"composite": 0.85}),
            _scenario("scn-b", priority={"composite": 0.35}),
        ],
        manifest_data=_manifest(
            seeds_generated=12,
            funnel={
                "expanded_instances": 10,
                "filter_submitted": 6,
                "filter_accepted": 3,
            },
            scenarios_generated=4,
            scenarios_failed=1,
        ),
        coverage_data=_coverage(
            coverage_gaps={
                "uncovered_entry_points": [
                    {"name": "ze-query", "entry_point_id": "ze-query"}
                ],
                "uncovered_zones": ["input"],
                "uncovered_threats": ["T6", "T11"],
                "uncovered_attack_patterns": [],
            }
        ),
    )

    html = _html(data, tmp_path)
    region = _section_region(html, "sec-run-summary")
    start = region.find("Outcome Summary")
    stats = _stats(region[start : start + 3000])

    assert stats["High Priority"] == 1
    assert stats["Medium Priority"] == 0
    assert stats["Low Priority"] == 1
    assert stats["Coverage Gaps"] == 4


# ---------------------------------------------------------------------------
# 35/39: Scenarios-section sub-charts, matrix, filters, and zone crumbs
# ---------------------------------------------------------------------------


def _signals() -> dict[str, str]:
    return {
        "technique_maturity": "realized",
        "risk_impact": "critical",
        "risk_likelihood": "high",
        "attack_complexity": "medium",
        "architecture_match": "explicit",
        "structural_exposure": "elevated",
    }


def test_scenarios_section_subcharts_matrix_and_filters(tmp_path: Path) -> None:
    data = ReportData(
        scenarios=[
            _scenario(
                "scn-a",
                priority={"composite": 0.72, "signals": _signals()},
                taxonomy_chain={
                    "owasp_llm_ids": ["LLM01"],
                    "agentic_threat_ids": ["T6"],
                },
                capability_profile={"zones_traversed": ["input", "tool_execution"]},
                narrative={
                    "title": "scn-a",
                    "summary": "",
                    "entry_point": "ze-query",
                    "zone_sequence": ["input", "tool_execution"],
                },
            ),
            _scenario(
                "scn-b",
                priority={"composite": 0.35, "signals": _signals()},
                taxonomy_chain={
                    "owasp_llm_ids": ["LLM02"],
                    "agentic_threat_ids": ["T6"],
                },
                capability_profile={"zones_traversed": ["input"]},
                narrative={
                    "title": "scn-b",
                    "summary": "",
                    "entry_point": "ze-rag",
                    "zone_sequence": ["input"],
                },
            ),
        ],
        manifest_data=_manifest(scenarios_generated=4),
    )

    html = _html(data, tmp_path)
    region = _section_region(html, "sec-scenarios")

    assert "Risk Impact: critical" in region
    assert "Threat x Zone Coverage" in region
    assert 'data-tooltip="T6 x Input Surfaces: 2 scenarios"' in region
    assert ">Input Surfaces</div>" in region
    assert ">Tool Execution</div>" in region
    assert 'class="ep-dist-name" data-tooltip="ze-query"' in region
    assert 'class="ep-dist-name" data-tooltip="ze-rag"' in region
    assert 'data-filter-type="threat" data-filter-value="T6"' in region
    assert (
        'data-filter-type="zone" data-filter-value="input"' in region
        and ">Input Surfaces</span>" in region
        and 'data-filter-type="zone" data-filter-value="tool_execution"' in region
        and ">Tool Execution</span>" in region
    )
    for priority in ("high", "medium", "low"):
        assert f'data-filter-type="priority" data-filter-value="{priority}"' in region
    assert '<span class="stat-label">In Report</span>' in region
    assert "of 4 generated" in region

    crumbs = _card_region(html, "scn-a")
    assert 'class="zone-crumb"' in crumbs
    assert ">input</span>" in crumbs
    assert ">tool_execution</span>" in crumbs
    assert "&rarr;" in crumbs


def test_threat_zone_matrix_nonzero_gaps_and_empty_cells(tmp_path: Path) -> None:
    data = ReportData(
        scenarios=[
            _scenario(
                "scn-a",
                taxonomy_chain={"agentic_threat_ids": ["T6"]},
                capability_profile={"zones_traversed": ["input"]},
                narrative={
                    "title": "scn-a",
                    "summary": "",
                    "entry_point": "",
                    "zone_sequence": ["input"],
                },
            ),
            _scenario(
                "scn-b",
                taxonomy_chain={"agentic_threat_ids": ["T11"]},
                capability_profile={"zones_traversed": ["tool_execution"]},
                narrative={
                    "title": "scn-b",
                    "summary": "",
                    "entry_point": "",
                    "zone_sequence": ["tool_execution"],
                },
            ),
        ]
    )

    html = _html(data, tmp_path)
    region = _section_region(html, "sec-scenarios")

    assert _stats(region)["Coverage Gaps"] == 2
    assert 'data-tooltip="T6 x Input Surfaces: 1 scenario"' in region
    assert 'data-tooltip="T11 x Input Surfaces: no scenarios"' in region
    assert 'class="matrix-cell empty"' in region


# ---------------------------------------------------------------------------
# 36: Actor profile distribution diversity
# ---------------------------------------------------------------------------


def test_actor_distribution_plural_goals_without_monotone_warning(
    tmp_path: Path,
) -> None:
    scenarios = [
        _scenario(
            "scn-a",
            actor_profile={
                "actor_type": "cybercriminal",
                "capability_level": "advanced",
                "goal_category_parent": "integrity",
            },
        ),
        _scenario(
            "scn-b",
            actor_profile={
                "actor_type": "nation-state",
                "capability_level": "expert",
                "goal_category_parent": "privacy",
            },
        ),
        _scenario(
            "scn-c",
            actor_profile={
                "actor_type": "hacktivist",
                "capability_level": "intermediate",
                "goal_category_parent": "availability",
            },
        ),
    ]

    data = ReportData(scenarios=scenarios)

    html = _html(data, tmp_path)
    region = _section_region(html, "sec-diversity")

    assert ">3 types</span>" in region
    assert ">3 categories</span>" in region
    assert re.search(r'class="diversity-bar-fill"[^>]*>\s*1\s*</div>', region)
    assert "33%" in region
    assert "Low actor diversity" not in region
    assert "Integrity" in region
    assert "Privacy" in region
    assert "Availability" in region


# ---------------------------------------------------------------------------
# 37: Roster technique fallback without pinned techniques
# ---------------------------------------------------------------------------


def test_matrix_roster_technique_fallback_when_unpinned(tmp_path: Path) -> None:
    scn_a = _matrix_scenario("scn-a", "T6", "AP-T6-01", ["AML.T0015", "AML.T0040"])
    scn_a["actor_profile"] = {
        "actor_type": "cybercriminal",
        "capability_level": "advanced",
    }

    data = ReportData(scenarios=[scn_a])

    html = _html(data, tmp_path)
    region = _section_region(html, "sec-threat-matrix")

    assert "1/17 threats" in region
    assert "2 techniques" in region
    assert "1 scenarios" in region
    assert (
        '<th class="matrix-col-header"' in region
        and "AML.T0015" in region
        and "AML.T0040" in region
    )
    assert 'class="matrix-count-link"' in region
    assert 'href="#scenario-scn-a"' in region
    roster = region[
        region.find("Scenario Roster") : region.find(
            "</table>", region.find("Scenario Roster")
        )
    ]
    scn_a_row = roster[
        roster.find("scn-a") : roster.find("</tr>", roster.find("scn-a"))
    ]
    assert "AP-T6-01" in scn_a_row
    assert ">AML.T0015</span>" in scn_a_row
    assert ">AML.T0040</span>" in scn_a_row


# ---------------------------------------------------------------------------
# 40: Pipeline call usage warnings and unavailable metrics
# ---------------------------------------------------------------------------


def test_pipeline_calls_partial_telemetry_warning_and_unavailable_summary(
    tmp_path: Path,
) -> None:
    data = ReportData(
        pipeline_call_logs=[
            {
                "call": "candidate_filter",
                "prompt_tokens": 100,
                "completion_tokens": 40,
                "duration_ms": 25,
                "semantic_evidence": {
                    "stage": "candidate_filter",
                    "accepted_draft_digest": "accepted-draft-digest",
                    "attempts": [{"result": "accepted"}],
                },
            },
            {
                "call": "capability_profile",
                "prompt_tokens": 50,
                "completion_tokens": 20,
                "duration_ms": 15,
                "semantic_evidence": {
                    "stage": "capability_profile",
                    "attempts": [{"result": "invalid"}],
                },
            },
            {
                "call": "behavior",
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "duration_ms": None,
            },
        ]
    )

    html = _html(data, tmp_path)
    region = _section_region(html, "sec-pipeline-calls")

    assert "3 call(s)" in region
    assert "150 prompt tokens" in region
    assert "60 completion tokens" in region
    assert "40ms total" in region
    visible = _visible(region)
    assert "Warning: call behavior has unavailable usage metrics" in visible
    assert "duration_ms" in visible
    assert (
        "Call 2: behavior (prompt_tokens=0, completion_tokens=0,"
        " duration_ms=unavailable)" in region
    )


# ---------------------------------------------------------------------------
# generator.py: conflicting corpus claims refuse generation
# ---------------------------------------------------------------------------


def test_conflicting_corpus_claims_refuse_generation(tmp_path: Path) -> None:
    def _claims(evidence: str) -> list[dict[str, str]]:
        return [
            {
                "category": "entry_points",
                "status": "applicable",
                "evidence": [evidence],
            },
            {
                "category": "tool_inventory",
                "status": "not_applicable",
                "reason": "Acceptance fixture",
            },
        ]

    scenario_a = _scenario("scn-a")
    scenario_a["validation"] = {
        "semantic": {"corpus_claim_applicability": _claims("a.md")}
    }
    scenario_b = _scenario("scn-b")
    scenario_b["validation"] = {
        "semantic": {"corpus_claim_applicability": _claims("b.md")}
    }
    data = ReportData(scenarios=[scenario_a, scenario_b])

    with pytest.raises(ValueError, match="entry_points"):
        _html(data, tmp_path)
