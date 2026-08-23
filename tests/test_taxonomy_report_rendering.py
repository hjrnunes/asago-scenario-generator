"""Unit tests for taxonomy/risk HTML report provenance and scorecard rendering.

The tests are driven through the public report entry
(:func:`asago_scenario_generator.report.generator.generate_report`) so the
behavior pinned by ``features/taxonomy_report_rendering.feature`` is verified
on the real rendered document rather than on private template helpers.
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


def _seed_meta(**overrides: Any) -> dict[str, str]:
    meta: dict[str, str] = {
        "seed_id": "AP-T6-01",
        "attack_pattern_name": "Prompt injection with hidden intent",
        "attack_pattern_description": "A short attack pattern description.",
        "threat_id": "T6",
        "threat_name": "Social engineering",
        "owasp_origin": "LLM01",
    }
    meta.update(overrides)
    return meta


def _scenario(
    sid: str = "scn-01",
    *,
    risk_card: dict[str, Any] | None = None,
    owasp_llm_ids: list[str] | None = None,
    agentic_threat_ids: list[str] | None = None,
    seed_metadata: dict[str, Any] | None = None,
    entry_point: str | None = None,
    zones: list[str] | None = None,
    goal: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a reportable scenario with honest optional-field degradation."""
    taxonomy_chain: dict[str, Any] = {}
    if owasp_llm_ids is not None:
        taxonomy_chain["owasp_llm_ids"] = owasp_llm_ids
    if agentic_threat_ids is not None:
        taxonomy_chain["agentic_threat_ids"] = agentic_threat_ids

    faceting: dict[str, Any] = {"taxonomy_chain": taxonomy_chain}
    if risk_card is not None:
        faceting["risk_card"] = risk_card
    if entry_point is not None or zones is not None:
        capability_profile: dict[str, Any] = {}
        if entry_point:
            capability_profile["entry_point"] = entry_point
        if zones:
            capability_profile["zones_traversed"] = zones
        faceting["capability_profile"] = capability_profile

    scenario: dict[str, Any] = {
        "scenario_id": sid,
        "priority": {"composite": 0.5},
        "narrative": {
            "title": sid,
            "summary": "",
            "entry_point": entry_point or "",
            "zone_sequence": zones or [],
        },
        "faceting": faceting,
        "validation": {"semantic": {"corpus_claim_applicability": _corpus_claims()}},
    }
    if seed_metadata is not None:
        scenario["scenario_seed_metadata"] = seed_metadata
    if goal is not None:
        scenario["actor_profile"] = goal
    return scenario


def _risk_card(**overrides: Any) -> dict[str, Any]:
    card: dict[str, Any] = {
        "risk_id": "atlas-phishing",
        "risk_name": "Spear phishing",
        "taxonomy": "ibm-risk-atlas",
        "confidence": 0.85,
    }
    card.update(overrides)
    return card


def _threat_surface(
    risk_card: dict[str, Any] | None = None,
    *,
    attack_pattern_ids: list[str] | None = None,
    atlas_technique_ids: list[str] | None = None,
    agentic_threat_ids: list[str] | None = None,
) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    if risk_card is not None:
        entries.append(
            {
                "risk_card": risk_card,
                "owasp_llm_ids": ["LLM01", "LLM06"],
                "agentic_threat_ids": agentic_threat_ids or [],
                "attack_pattern_ids": attack_pattern_ids or [],
                "atlas_technique_ids": atlas_technique_ids or [],
            }
        )
    return {"entries": entries, "governance_only": []}


def _goal() -> dict[str, Any]:
    return {
        "goal_category": "G2",
        "goal_category_name": "Exfiltrate data",
        "goal_category_parent": "Espionage",
    }


def _legacy_scorecard(**overrides: Any) -> dict[str, Any]:
    """Legacy scorecard carrying every metric group in range."""
    data: dict[str, Any] = {
        "evaluation": {
            "scenario_count": 3,
            "feature_file_count": 2,
            "consistency": {
                "mean": 0.95,
                "stddev": 0.04,
                "per_scenario": {
                    "scn-ok": {
                        "zone_alignment": 0.98,
                        "entry_point_agreement": 1,
                        "step_node_correspondence": 0.97,
                    }
                },
            },
            "gherkin": {
                "parse_success_rate": 1.0,
                "mean_step_count": 7.5,
                "tag_consistency": {"inconsistent_groups": 0},
                "background_missing_warnings": [],
            },
            "grounding": {
                "threat_id_validity": 1.0,
                "dangling_references": 0,
                "technique_id_grounding": 0.95,
                "ungrounded_technique_references": 0,
            },
            "technique_agreement": {
                "mean_technique_agreement": 0.92,
                "per_scenario": {},
            },
            "diversity": {
                "title_uniqueness": 0.9,
                "entry_point_entropy": {
                    "entropy": 1.1,
                    "entry_point_coverage": 0.93,
                },
                "zone_coverage": {
                    "active_zone_coverage": 0.91,
                    "out_of_scope_zone_violations": [],
                },
                "actor_type_entropy": 0.8,
                "capability_level_evenness": 0.85,
            },
            "plausibility": {
                "capability_complexity_violation_count": 0,
                "per_scenario": {},
            },
        }
    }
    data["evaluation"].update(overrides)
    return data


_VERSIONED_GROUPS = {
    "Presence / Coverage": "presence_coverage",
    "Validity / Grounding": "validity_grounding",
    "Cross-artifact Agreement": "cross_artifact_agreement",
    "Semantic Quality / Diagnostics": "semantic_quality_diagnostics",
    "Release Qualification": "release_qualification",
}


def _versioned_scorecard(status: str, group: str) -> dict[str, Any]:
    """Schema v1 scorecard with a single metric under *group*."""
    key = _VERSIONED_GROUPS[group]
    scorecard: dict[str, Any] = {
        "schema_version": "1",
        "scenario_count": 1,
        "feature_file_count": 1,
        "qualification": {
            "status": "pass",
            "failed_gate_ids": [],
            "error_gate_ids": [],
            "not_applicable_gate_ids": [],
        },
    }
    for group_key in _VERSIONED_GROUPS.values():
        scorecard[group_key] = {"metrics": {}}
    scorecard[key] = {
        "metrics": {
            "single": {
                "status": status,
                "numerator": 1,
                "denominator": 1,
                "value": 1.0,
                "evidence": [],
                "affected_ids": [],
            }
        }
    }
    return scorecard


# ---------------------------------------------------------------------------
# HTML extraction helpers (report-scoped, not private-helper scraping)
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


def _prov_chain(html: str, sid: str) -> str:
    """HTML of the provenance chain inside the scenario card for *sid*."""
    region = _card_region(html, sid)
    start_marker = '<div class="prov-chain">'
    start = region.find(start_marker)
    assert start != -1, f"provenance chain missing for {sid}"
    body = region[start + len(start_marker) :]
    end = body.find('<div class="tab-panel">')
    assert end != -1, "provenance tab panel boundary not found"
    return body[:end]


_STEP_RE = re.compile(
    r'<div class="prov-step-label">(.*?)</div>(.*?)(?=<div class="prov-step-label">|$)',
    re.S,
)

_KV_RE = re.compile(
    r'<span class="prov-kv-label">(.*?)</span>'
    r'<span class="prov-kv-value"[^>]*>(.*?)</span>',
    re.S,
)


def _prov_steps(chain: str) -> dict[str, str]:
    """Return label -> body for every provenance chain step.

    Labels carry enumeration prefixes and helper hints, so callers match
    them by unambiguous prefix.
    """
    return {
        label: body
        for label, body in ((m.group(1), m.group(2)) for m in _STEP_RE.finditer(chain))
    }


def _step(steps: dict[str, str], prefix: str) -> str:
    """Return the body of the single step whose label starts with *prefix*."""
    matches = [body for label, body in steps.items() if label.startswith(prefix)]
    assert len(matches) == 1, (
        f"expected one step starting {prefix!r}, got {len(matches)}"
    )
    return matches[0]


def _step_kv(body: str) -> dict[str, str]:
    """Return label -> value for the key/value rows in a step body."""
    return {label: value for label, value in _KV_RE.findall(body)}


def _visible(fragment: str) -> str:
    """Strip markup and entities for emptiness/content checks."""
    text = re.sub(r"<[^>]+>", "", fragment)
    text = text.replace("&mdash;", "").replace("&nbsp;", " ")
    return text.strip()


def _in_order(fragment: str, values: list[str]) -> bool:
    """Return whether *values* appear in *fragment* in document order."""
    position = -1
    for value in values:
        idx = fragment.find(value)
        if idx == -1 or idx < position:
            return False
        position = idx
    return True


def _highlighted_value(body: str, value: str) -> bool:
    """Return whether *value* is inside the first prov-highlight span."""
    head = body.split("prov-highlight", 1)
    if len(head) < 2:
        return False
    return value in head[1].split("</span>", 1)[0]


# ---------------------------------------------------------------------------
# Provenance chain
# ---------------------------------------------------------------------------


_PROV_LABELS = [
    "Risk Card",
    "OWASP LLM IDs",
    "Agentic Threats",
    "Attack Pattern",
    "Attack Goal",
    "Scenario classifications",
    "Entry Point",
    "Zone Sequence",
]


def test_provenance_chain_renders_full_chain_in_order(tmp_path: Path) -> None:
    data = ReportData(
        profile_data={"entry_points": ["ze-query", "ze-rag"]},
        threat_surface_data=_threat_surface(
            _risk_card(),
            attack_pattern_ids=["AP-T11-01", "AP-T6-01"],
            atlas_technique_ids=["AML.T0015", "AML.T0053"],
            agentic_threat_ids=["T6", "T11"],
        ),
        scenarios=[
            _scenario(
                risk_card=_risk_card(),
                owasp_llm_ids=["LLM01", "LLM06"],
                agentic_threat_ids=["T6", "T11"],
                seed_metadata=_seed_meta(),
                entry_point="ze-rag",
                zones=["Z1", "Z2"],
                goal=_goal(),
            )
        ],
    )

    html = _html(data, tmp_path)
    chain = _prov_chain(html, "scn-01")
    assert _in_order(chain, _PROV_LABELS)

    steps = _prov_steps(chain)
    kv = _step_kv(_step(steps, "1. Risk Card"))
    assert kv["Risk ID"] == "atlas-phishing"
    assert kv["Risk Name"] == "Spear phishing"
    assert "ibm-risk-atlas" in kv["Taxonomy"]
    assert kv["Confidence"] == "0.85"

    assert _in_order(_step(steps, "2. OWASP LLM IDs"), ["LLM01", "LLM06"])
    assert _in_order(_step(steps, "3. Agentic Threats"), ["T6", "T11"])

    pattern_body = _step(steps, "4a. Attack Pattern")
    assert _highlighted_value(pattern_body, "AP-T6-01")
    assert "AP-T11-01" in pattern_body

    atlas_body = _step(steps, "4c. Scenario classifications")
    assert _in_order(atlas_body, ["AML.T0015", "AML.T0053"])
    assert "prov-highlight" not in atlas_body

    entry_body = _step(steps, "5. Entry Point")
    assert _highlighted_value(entry_body, "ze-rag")
    assert "prov-dim" in entry_body

    assert _in_order(_step(steps, "6. Zone Sequence"), ["Z1", "Z2"])


def test_provenance_chain_degrades_missing_risk_card(tmp_path: Path) -> None:
    data = ReportData(
        scenarios=[
            _scenario(
                owasp_llm_ids=["LLM01"],
                agentic_threat_ids=["T6"],
                goal=_goal(),
            )
        ]
    )

    html = _html(data, tmp_path)
    chain = _prov_chain(html, "scn-01")
    steps = _prov_steps(chain)
    risk_body = _step(steps, "1. Risk Card")
    kv = _step_kv(risk_body)
    assert _visible(kv["Risk ID"]) == ""
    assert _visible(kv["Risk Name"]) == ""
    assert kv["Confidence"] == "0.00"
    assert "prov-badge" not in risk_body


@pytest.mark.parametrize(
    ("empty_list", "empty_step", "other_step", "remaining_badge"),
    [
        ("owasp_llm_ids", "2. OWASP LLM IDs", "3. Agentic Threats", "T6"),
        ("agentic_threat_ids", "3. Agentic Threats", "2. OWASP LLM IDs", "LLM01"),
    ],
)
def test_provenance_chain_empty_id_list_placeholder(
    tmp_path: Path,
    empty_list: str,
    empty_step: str,
    other_step: str,
    remaining_badge: str,
) -> None:
    owasp = ["LLM01"] if empty_list != "owasp_llm_ids" else []
    threats = ["T6"] if empty_list != "agentic_threat_ids" else []
    data = ReportData(
        scenarios=[
            _scenario(owasp_llm_ids=owasp, agentic_threat_ids=threats, goal=_goal())
        ]
    )

    html = _html(data, tmp_path)
    chain = _prov_chain(html, "scn-01")
    steps = _prov_steps(chain)
    empty_body = _step(steps, empty_step)
    assert 'class="prov-badge prov-badge-muted">none</span>' in empty_body
    assert remaining_badge not in empty_body
    assert remaining_badge in _step(steps, other_step)


def test_provenance_chain_without_seed_metadata_still_renders_other_steps(
    tmp_path: Path,
) -> None:
    data = ReportData(
        scenarios=[_scenario(goal=_goal(), entry_point="ze-rag", zones=["Z1"])]
    )

    html = _html(data, tmp_path)
    chain = _prov_chain(html, "scn-01")
    steps = _prov_steps(chain)
    pattern_body = _step(steps, "4a. Attack Pattern")
    kv = _step_kv(pattern_body)
    assert _visible(kv["Seed ID"]) == ""
    assert _visible(kv["Name"]) == ""
    assert _visible(kv["Threat"]) == ""
    assert "Description" not in pattern_body
    assert _in_order(chain, ["Attack Goal", "Entry Point", "Zone Sequence"])


def test_provenance_truncates_long_description_at_300(tmp_path: Path) -> None:
    run_on = "x" * 400
    data = ReportData(
        scenarios=[
            _scenario(
                risk_card=_risk_card(),
                seed_metadata=_seed_meta(attack_pattern_description=run_on),
                goal=_goal(),
            )
        ]
    )

    html = _html(data, tmp_path)
    chain = _prov_chain(html, "scn-01")
    steps = _prov_steps(chain)
    pattern_body = _step(steps, "4a. Attack Pattern")
    assert ("x" * 300) + "..." in pattern_body
    assert "x" * 400 not in pattern_body


def test_provenance_keeps_short_description_in_full(tmp_path: Path) -> None:
    description = "A short attack pattern description."
    data = ReportData(
        scenarios=[
            _scenario(
                seed_metadata=_seed_meta(attack_pattern_description=description),
                goal=_goal(),
            )
        ]
    )

    html = _html(data, tmp_path)
    chain = _prov_chain(html, "scn-01")
    steps = _prov_steps(chain)
    pattern_body = _step(steps, "4a. Attack Pattern")
    assert _visible(_step_kv(pattern_body)["Description"]) == description


# ---------------------------------------------------------------------------
# Scorecard
# ---------------------------------------------------------------------------

_GROUP_TITLE_RE = re.compile(
    r'<div class="scorecard-group-title"[^>]*>(.*?)</div>', re.S
)


def test_scorecard_renders_summary_groups_and_badges(tmp_path: Path) -> None:
    data = ReportData(scorecard_data=_legacy_scorecard())

    html = _html(data, tmp_path)

    assert "<h2>Eval Scorecard</h2>" in html
    assert '<div class="scorecard-stat-value">3</div>' in html
    assert '<div class="scorecard-stat-value">2</div>' in html
    group_titles = _GROUP_TITLE_RE.findall(html)
    for group in (
        "Consistency",
        "Gherkin Quality",
        "Grounding",
        "Projected-step Mapping Agreement",
        "Diversity",
        "Plausibility",
    ):
        assert group in group_titles
    assert "Mean Technique Agreement: 0.92" in html


def test_scorecard_clean_outliers_panel_when_all_in_range(tmp_path: Path) -> None:
    data = ReportData(scorecard_data=_legacy_scorecard())

    html = _html(data, tmp_path)

    assert "All scenarios pass quality checks" in html
    assert "Quality Outliers" not in html


def test_scorecard_outliers_list_red_before_yellow_in_order(tmp_path: Path) -> None:
    scorecard = _legacy_scorecard(
        consistency={
            "mean": 0.8,
            "per_scenario": {
                "scn-a": {
                    "zone_alignment": 0.65,
                    "entry_point_agreement": 1,
                    "step_node_correspondence": 0.9,
                },
                "scn-b": {
                    "zone_alignment": 0.80,
                    "entry_point_agreement": 1,
                    "step_node_correspondence": 0.9,
                },
            },
        },
        plausibility={
            "capability_complexity_violation_count": 2,
            "per_scenario": {},
        },
    )
    data = ReportData(scorecard_data=scorecard)

    html = _html(data, tmp_path)

    assert "Quality Outliers" in html
    panel = html.split("Quality Outliers", 1)[1]
    assert "Capability Violations" in panel
    assert "Zone Alignment" in panel
    rows = re.findall(r"<tbody>(.*?)</tbody>", panel, re.S)
    assert rows
    first_cells = re.findall(r"<tr><td>(.*?)</td>", rows[0], re.S)
    assert first_cells == ["(aggregate)", "scn-a", "scn-b"]
    assert ">2</span>" in panel
    assert ">0.65</span>" in panel
    assert ">0.80</span>" in panel


@pytest.mark.parametrize(
    ("mean", "badge_color", "display"),
    [
        (0.95, "scorecard-badge-green", "0.95"),
        (0.75, "scorecard-badge-yellow", "0.75"),
        (0.55, "scorecard-badge-red", "0.55"),
        (1.0, "scorecard-badge-green", "1"),
    ],
)
def test_scorecard_mean_badge_threshold_colors(
    tmp_path: Path,
    mean: float,
    badge_color: str,
    display: str,
) -> None:
    data = ReportData(scorecard_data=_legacy_scorecard(consistency={"mean": mean}))

    html = _html(data, tmp_path)

    assert badge_color in html
    assert f"Mean: {display}</span>" in html


@pytest.mark.parametrize(
    ("violations", "badge_color", "display"),
    [
        (0, "scorecard-badge-green", "0"),
        (2, "scorecard-badge-red", "2"),
    ],
)
def test_scorecard_inverted_count_badge_colors(
    tmp_path: Path,
    violations: int,
    badge_color: str,
    display: str,
) -> None:
    data = ReportData(
        scorecard_data=_legacy_scorecard(
            plausibility={
                "capability_complexity_violation_count": violations,
                "per_scenario": {},
            }
        )
    )

    html = _html(data, tmp_path)

    assert badge_color in html
    assert f"Capability Violations: {display}</span>" in html


@pytest.mark.parametrize(
    ("status", "group", "badge_color"),
    [
        ("pass", "Presence / Coverage", "scorecard-badge-green"),
        ("fail", "Validity / Grounding", "scorecard-badge-red"),
        ("not_applicable", "Release Qualification", "scorecard-badge-yellow"),
    ],
)
def test_versioned_scorecard_status_badges(
    tmp_path: Path,
    status: str,
    group: str,
    badge_color: str,
) -> None:
    data = ReportData(scorecard_data=_versioned_scorecard(status, group))

    html = _html(data, tmp_path)

    assert "<h2>Versioned Eval Scorecard</h2>" in html
    assert '<span class="badge">Schema v1</span>' in html
    group_marker = f'<div class="scorecard-group-title">{group}</div>'
    assert group_marker in html
    group_region = html.split(group_marker, 1)[1]
    assert badge_color in group_region
    assert f">{status}</span>" in group_region


# ---------------------------------------------------------------------------
# Scenario Seed block
# ---------------------------------------------------------------------------

_SEED_SECTION_MARKER = "<summary>Scenario Seed</summary>"


def _seed_region(html: str) -> str:
    """HTML of the Scenario Seed section inside the report."""
    assert _SEED_SECTION_MARKER in html, "Scenario Seed section is not rendered"
    region = html.split(_SEED_SECTION_MARKER, 1)[1]
    return region.split("</details>", 1)[0]


@pytest.mark.parametrize(
    ("metadata_case", "renders"),
    [
        ("absent", False),
        ("complete", True),
        ("incomplete", False),
    ],
)
def test_scenario_seed_section_rendering_cases(
    tmp_path: Path,
    metadata_case: str,
    renders: bool,
) -> None:
    seed_metadata: dict[str, Any] | None = None
    if metadata_case == "complete":
        seed_metadata = _seed_meta()
    elif metadata_case == "incomplete":
        seed_metadata = {"threat_id": "T6"}

    data = ReportData(scenarios=[_scenario(seed_metadata=seed_metadata)])

    html = _html(data, tmp_path)
    assert (_SEED_SECTION_MARKER in html) is renders
    if renders:
        assert _SEED_SECTION_MARKER in _card_region(html, "scn-01")


def test_scenario_seed_section_shows_seed_fields(tmp_path: Path) -> None:
    data = ReportData(
        scenarios=[
            _scenario(
                risk_card=_risk_card(),
                seed_metadata=_seed_meta(),
                goal=_goal(),
            )
        ]
    )

    html = _html(data, tmp_path)
    seed_region = _seed_region(html)

    assert "Prompt injection with hidden intent" in seed_region
    assert "A short attack pattern description." in seed_region
    assert "T6 &mdash; Social engineering" in seed_region
    assert "LLM01" in seed_region
    assert "AP-T6-01" in seed_region


def test_no_scorecard_omits_section_and_sidebar_link(tmp_path: Path) -> None:
    data = ReportData(scenarios=[_scenario()])

    html = _html(data, tmp_path)

    assert "Eval Scorecard" not in html
    assert '<a href="#sec-scorecard">' not in html


# ---------------------------------------------------------------------------
# Priority bucket statistics
# ---------------------------------------------------------------------------

_STAT_NUM_RE = re.compile(
    r'stat-number">(\d+)</span>\s*<span class="stat-label">'
    r"(High|Medium|Low) Priority</span>"
)


def test_priority_bucket_counts_rendered_in_dashboard(tmp_path: Path) -> None:
    scenarios = [
        _scenario(sid=f"scn-p{i}", agentic_threat_ids=["T6"]) for i in range(6)
    ]
    for scenario, composite in zip(scenarios, [0.7, 0.4, 0.9, 0.5, 0.2]):
        scenario["priority"] = {"composite": composite}
    # The last scenario has no priority block: its composite defaults to 0.
    scenarios[-1].pop("priority")
    data = ReportData(
        scenarios=scenarios,
        manifest_data={"seeds_generated": 6, "funnel": {}},
    )

    html = _html(data, tmp_path)

    # The scenario dashboard self-counts buckets; the run summary renders the
    # counts computed by the report generator, so pin both.
    assert {label: int(c) for c, label in _STAT_NUM_RE.findall(html)} == {
        "High": 2,
        "Medium": 2,
        "Low": 2,
    }
    idx = html.find('scenario-section-title">Outcome Summary</div>')
    assert idx != -1
    summary_stats = {
        label: int(c)
        for c, label in _STAT_NUM_RE.findall(html[idx : idx + 2000])
    }
    assert summary_stats == {"High": 2, "Medium": 2, "Low": 2}
