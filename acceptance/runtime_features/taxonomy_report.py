"""Acceptance step handlers for taxonomy/risk HTML report rendering.

Fixtures are assembled step-by-step on the world (scenario fields, threat
surface entries, capability profile entry points, evaluation scorecards)
and the When step drives the public report entry ``generate_report`` so
the pinned provenance-chain and scorecard behavior is verified on the
real rendered document.
"""

from __future__ import annotations

import re
import tempfile
from pathlib import Path
from typing import Any

from asago_scenario_generator.report.data import ReportData
from asago_scenario_generator.report.generator import generate_report
from runtime_world import World

FEATURE_ID = "taxonomy_report"


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


def _new_scenario(sid: str) -> dict[str, Any]:
    """A reportable scenario with every optional input left empty."""
    return {
        "scenario_id": sid,
        "priority": {"composite": 0.5},
        "narrative": {
            "title": sid,
            "summary": "",
            "entry_point": "",
            "zone_sequence": [],
        },
        "faceting": {"taxonomy_chain": {"owasp_llm_ids": [], "agentic_threat_ids": []}},
        "validation": {"semantic": {"corpus_claim_applicability": _corpus_claims()}},
    }


def _seed_meta(
    seed_id: str,
    name: str,
    description: str,
    threat_id: str,
    threat_name: str,
    origin: str,
) -> dict[str, str]:
    return {
        "seed_id": seed_id,
        "attack_pattern_name": name,
        "attack_pattern_description": description,
        "threat_id": threat_id,
        "threat_name": threat_name,
        "owasp_origin": origin,
    }


# Complete seed metadata used when a step does not declare its own values.
_DEFAULT_SEED_META = {
    "seed_id": "AP-T6-01",
    "attack_pattern_name": "Prompt injection with hidden intent",
    "attack_pattern_description": "A short attack pattern description.",
    "threat_id": "T6",
    "threat_name": "Social engineering",
    "owasp_origin": "LLM01",
}

# HTML marker delimiting the Scenario Seed section.
_SEED_SECTION_MARKER = "<summary>Scenario Seed</summary>"


def _scn(world: World, sid: str) -> dict[str, Any]:
    """Return the fixture scenario with id *sid*."""
    for scenario in world.trpt_scenarios:
        if scenario["scenario_id"] == sid:
            return scenario
    raise AssertionError(f"scenario {sid!r} is not part of the fixture")


def _legacy_scorecard() -> dict[str, Any]:
    """Legacy scorecard carrying every metric group in range."""
    return {
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


def _split_csv(raw: str) -> list[str]:
    return [part.strip() for part in raw.split(",") if part.strip()]


# ---------------------------------------------------------------------------
# Given steps
# ---------------------------------------------------------------------------


def _h_background(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an offline completed taxonomy-and-risk run fixture."""
    world.trpt_tmpdir = Path(tempfile.mkdtemp(prefix="taxonomy-report-"))
    world.trpt_scenarios: list[dict[str, Any]] = []
    world.trpt_profile_data: dict[str, Any] = {}
    world.trpt_threat_surface: dict[str, Any] = {"entries": [], "governance_only": []}
    world.trpt_ts_entries: dict[str, dict[str, list[str]]] = {}
    world.trpt_scorecard: dict[str, Any] = {}
    world.trpt_html: str | None = None
    return True, ""


def _h_contains_scenario(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the run fixture contains scenario "X"."""
    match = re.search(r'the run fixture contains scenario "([^"]+)"$', text)
    if not match:
        return False, f"Could not parse contains-scenario step: {text}"
    world.trpt_scenarios.append(_new_scenario(match.group(1)))
    return True, ""


def _h_contains_scenario_without_risk_card(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the run fixture contains scenario "X" without a risk card."""
    match = re.search(
        r'the run fixture contains scenario "([^"]+)" without a risk card', text
    )
    if not match:
        return False, f"Could not parse no-risk-card step: {text}"
    world.trpt_scenarios.append(_new_scenario(match.group(1)))
    return True, ""


def _h_contains_scenario_no_seed_metadata(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: ... with no seed metadata but an attack goal and one traversed zone."""
    match = re.search(
        r'the run fixture contains scenario "([^"]+)" with no seed metadata '
        r"but an attack goal and one traversed zone",
        text,
    )
    if not match:
        return False, f"Could not parse no-seed-metadata step: {text}"
    sid = match.group(1)
    scenario = _new_scenario(sid)
    scenario["actor_profile"] = {
        "goal_category": "G2",
        "goal_category_name": "Exfiltrate data",
        "goal_category_parent": "Espionage",
    }
    scenario["faceting"]["capability_profile"] = {
        "entry_point": "ze-rag",
        "zones_traversed": ["Z1"],
    }
    scenario["narrative"]["entry_point"] = "ze-rag"
    scenario["narrative"]["zone_sequence"] = ["Z1"]
    world.trpt_scenarios.append(scenario)
    return True, ""


def _h_contains_scenario_seed_case(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: ... whose seed metadata is <metadata_case>."""
    match = re.search(
        r'the run fixture contains scenario "([^"]+)" whose seed metadata is', text
    )
    if not match:
        return False, f"Could not parse seed-metadata-case step: {text}"
    sid = match.group(1)
    scenario = _new_scenario(sid)
    metadata_case = examples.get("metadata_case", "")
    if metadata_case == "present with attack pattern name and seed ID":
        scenario["scenario_seed_metadata"] = dict(_DEFAULT_SEED_META)
    elif metadata_case == "present without attack pattern name or seed ID":
        scenario["scenario_seed_metadata"] = {"threat_id": "T6"}
    world.trpt_scenarios.append(scenario)
    return True, ""


def _h_contains_scenario_with_seed(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: ... with seed metadata carrying seed "S", ... and origin "O"."""
    match = re.search(
        r'the run fixture contains scenario "([^"]+)" with seed metadata carrying '
        r'seed "([^"]+)", attack pattern name "([^"]+)", description "([^"]*)", '
        r'threat "([^"]+)", threat name "([^"]+)", and origin "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse carrying-seed step: {text}"
    sid, seed_id, name, description, threat_id, threat_name, origin = match.groups()
    scenario = _new_scenario(sid)
    scenario["scenario_seed_metadata"] = _seed_meta(
        seed_id, name, description, threat_id, threat_name, origin
    )
    world.trpt_scenarios.append(scenario)
    return True, ""


def _h_carries_risk_card(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: scenario "X" carries risk card "R" with risk name "N", taxonomy "T", and confidence C."""
    match = re.search(
        r'scenario "([^"]+)" carries risk card "([^"]+)" with risk name "([^"]+)"'
        r', taxonomy "([^"]+)", and confidence ([0-9.]+)',
        text,
    )
    if not match:
        return False, f"Could not parse risk-card step: {text}"
    sid, risk_id, risk_name, taxonomy, confidence = match.groups()
    scenario = _scn(world, sid)
    scenario["faceting"]["risk_card"] = {
        "risk_id": risk_id,
        "risk_name": risk_name,
        "taxonomy": taxonomy,
        "confidence": float(confidence),
    }
    return True, ""


def _h_lists_ids_except_empty(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: scenario "X" lists OWASP LLM IDs "A" and agentic threats "B" except the <empty_list> is empty."""
    match = re.search(
        r'scenario "([^"]+)" lists OWASP LLM IDs "([^"]*)" and agentic threats "([^"]*)"',
        text,
    )
    if not match:
        return False, f"Could not parse ID-list step: {text}"
    sid, owasp_csv, threats_csv = match.groups()
    scenario = _scn(world, sid)
    if examples.get("empty_list") == "OWASP LLM IDs":
        owasp: list[str] = []
        threats = _split_csv(threats_csv)
    elif examples.get("empty_list") == "agentic threats":
        owasp = _split_csv(owasp_csv)
        threats = []
    else:
        owasp = _split_csv(owasp_csv)
        threats = _split_csv(threats_csv)
    scenario["faceting"]["taxonomy_chain"]["owasp_llm_ids"] = owasp
    scenario["faceting"]["taxonomy_chain"]["agentic_threat_ids"] = threats
    return True, ""


def _h_lists_ids(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: scenario "X" lists OWASP LLM IDs "A" and agentic threats "B"."""
    match = re.search(
        r'scenario "([^"]+)" lists OWASP LLM IDs "([^"]*)" and agentic threats "([^"]*)"$',
        text,
    )
    if not match:
        return False, f"Could not parse ID-list step: {text}"
    sid, owasp_csv, threats_csv = match.groups()
    scenario = _scn(world, sid)
    scenario["faceting"]["taxonomy_chain"]["owasp_llm_ids"] = _split_csv(owasp_csv)
    scenario["faceting"]["taxonomy_chain"]["agentic_threat_ids"] = _split_csv(
        threats_csv
    )
    return True, ""


def _h_carries_seed_metadata(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: scenario "X" carries seed metadata with seed "S", ... and origin "O"."""
    match = re.search(
        r'scenario "([^"]+)" carries seed metadata with seed "([^"]+)", '
        r'attack pattern name "([^"]+)", description "([^"]*)", threat "([^"]+)", '
        r'threat name "([^"]+)", and origin "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse seed-metadata step: {text}"
    sid, seed_id, name, description, threat_id, threat_name, origin = match.groups()
    scenario = _scn(world, sid)
    scenario["scenario_seed_metadata"] = _seed_meta(
        seed_id, name, description, threat_id, threat_name, origin
    )
    return True, ""


def _h_seed_description_case(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the seed metadata description of scenario "X" is <description_case>."""
    match = re.search(r'the seed metadata description of scenario "([^"]+)" is', text)
    if not match:
        return False, f"Could not parse description-case step: {text}"
    scenario = _scn(world, match.group(1))
    metadata = scenario.get("scenario_seed_metadata") or dict(_DEFAULT_SEED_META)
    description_case = examples.get("description_case", "")
    if "400-character" in description_case:
        metadata["attack_pattern_description"] = "x" * 400
    else:
        metadata["attack_pattern_description"] = "y" * 119 + "."
    scenario["scenario_seed_metadata"] = metadata
    return True, ""


def _h_threat_surface_entry(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the threat surface entry for risk card "R" lists attack patterns "A" and ATLAS techniques "B"."""
    match = re.search(
        r'the threat surface entry for risk card "([^"]+)" lists attack patterns '
        r'"([^"]+)" and ATLAS techniques "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse threat-surface entry step: {text}"
    risk_id, patterns_csv, atlas_csv = match.groups()
    world.trpt_ts_entries[risk_id] = {
        "attack_pattern_ids": _split_csv(patterns_csv),
        "atlas_technique_ids": _split_csv(atlas_csv),
    }
    return True, ""


def _h_capability_profile_entry_points(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the capability profile lists entry points "A" and scenario "X" selects "E"."""
    match = re.search(
        r'the capability profile lists entry points "([^"]+)" and scenario '
        r'"([^"]+)" selects "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse entry-point step: {text}"
    entry_points_csv, sid, selected = match.groups()
    world.trpt_profile_data = {"entry_points": _split_csv(entry_points_csv)}
    scenario = _scn(world, sid)
    scenario["faceting"]["capability_profile"] = {
        "entry_point": selected,
        "zones_traversed": scenario.get("faceting", {})
        .get("capability_profile", {})
        .get("zones_traversed", []),
    }
    scenario["narrative"]["entry_point"] = selected
    return True, ""


def _h_traverses_zones(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: scenario "X" traverses zones "A,B"."""
    match = re.search(r'scenario "([^"]+)" traverses zones "([^"]+)"', text)
    if not match:
        return False, f"Could not parse zone-traversal step: {text}"
    sid, zones_csv = match.groups()
    zones = _split_csv(zones_csv)
    scenario = _scn(world, sid)
    capability_profile = scenario.get("faceting", {}).get("capability_profile", {})
    capability_profile = dict(capability_profile)
    capability_profile["zones_traversed"] = zones
    scenario["faceting"]["capability_profile"] = capability_profile
    scenario["narrative"]["zone_sequence"] = zones
    return True, ""


def _h_scorecard_full(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: ... carries an evaluation scorecard with every metric group."""
    world.trpt_scorecard = _legacy_scorecard()
    return True, ""


def _h_scorecard_in_range(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: ... whose consistency, agreement, diversity, and plausibility metrics are all in range."""
    world.trpt_scorecard = _legacy_scorecard()
    return True, ""


def _h_scorecard_zone_alignment(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: ... where scenario "scn-a" has zone alignment 0.65 and scenario "scn-b" has zone alignment 0.80."""
    match = re.search(
        r'where scenario "([^"]+)" has zone alignment ([0-9.]+) and scenario '
        r'"([^"]+)" has zone alignment ([0-9.]+)',
        text,
    )
    if not match:
        return False, f"Could not parse zone-alignment step: {text}"
    first_sid, first_value, second_sid, second_value = match.groups()
    world.trpt_scorecard = {
        "evaluation": {
            "scenario_count": 2,
            "feature_file_count": 1,
            "consistency": {
                "mean": 0.7,
                "per_scenario": {
                    first_sid: {
                        "zone_alignment": float(first_value),
                        "entry_point_agreement": 1,
                        "step_node_correspondence": 1.0,
                    },
                    second_sid: {
                        "zone_alignment": float(second_value),
                        "entry_point_agreement": 1,
                        "step_node_correspondence": 1.0,
                    },
                },
            },
            "plausibility": {
                "capability_complexity_violation_count": 0,
                "per_scenario": {},
            },
        }
    }
    return True, ""


def _h_scorecard_violations(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the same scorecard records N capability-complexity violations."""
    match = re.search(r"records (\d+) capability-complexity violations", text)
    if not match:
        return False, f"Could not parse violations step: {text}"
    count = int(match.group(1))
    evaluation = world.trpt_scorecard.setdefault("evaluation", {})
    evaluation["plausibility"] = {
        "capability_complexity_violation_count": count,
        "per_scenario": {},
    }
    return True, ""


def _h_scorecard_only_mean(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: ... whose only consistency metric is the mean <mean_value>."""
    mean = examples.get("mean_value", "")
    try:
        mean_value = float(mean)
    except ValueError:
        return False, f"Could not parse mean value: {mean!r}"
    world.trpt_scorecard = {
        "evaluation": {
            "scenario_count": 1,
            "feature_file_count": 1,
            "consistency": {"mean": mean_value},
        }
    }
    return True, ""


def _h_scorecard_only_violations(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: ... whose only plausibility metric is <violation_count> capability-complexity violations."""
    try:
        count = int(examples.get("violation_count", ""))
    except ValueError:
        return False, "Could not parse violation count from examples"
    world.trpt_scorecard = {
        "evaluation": {
            "scenario_count": 1,
            "feature_file_count": 1,
            "plausibility": {
                "capability_complexity_violation_count": count,
                "per_scenario": {},
            },
        }
    }
    return True, ""


def _h_scorecard_versioned(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: ... carries a schema v1 scorecard with one metric in status <status> under the <group> group."""
    status = examples.get("status", "")
    group = examples.get("group", "")
    if status not in {"pass", "fail", "not_applicable"}:
        return False, f"Unknown schema v1 status: {status!r}"
    if group not in _VERSIONED_GROUPS:
        return False, f"Unknown schema v1 group: {group!r}"
    world.trpt_scorecard = _versioned_scorecard(status, group)
    return True, ""


def _h_scorecard_none(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the run fixture carries no eval scorecard."""
    world.trpt_scorecard = {}
    return True, ""


# ---------------------------------------------------------------------------
# When step
# ---------------------------------------------------------------------------


def _materialize_threat_surface(world: World) -> dict[str, Any]:
    """Build threat-surface entries from the declared per-risk-card overrides."""
    entries: list[dict[str, Any]] = []
    for risk_id, overrides in world.trpt_ts_entries.items():
        matching = [
            scenario
            for scenario in world.trpt_scenarios
            if scenario.get("faceting", {}).get("risk_card", {}).get("risk_id")
            == risk_id
        ]
        if matching:
            risk_card = matching[0]["faceting"]["risk_card"]
            chain = matching[0]["faceting"]["taxonomy_chain"]
        else:
            risk_card = {
                "risk_id": risk_id,
                "risk_name": risk_id,
                "taxonomy": "",
                "confidence": 0,
            }
            chain = {}
        entries.append(
            {
                "risk_card": risk_card,
                "owasp_llm_ids": chain.get("owasp_llm_ids", []),
                "agentic_threat_ids": chain.get("agentic_threat_ids", []),
                "attack_pattern_ids": overrides["attack_pattern_ids"],
                "atlas_technique_ids": overrides["atlas_technique_ids"],
            }
        )
    return {"entries": entries, "governance_only": []}


def _h_generate_report(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the HTML report is generated."""
    if world.trpt_tmpdir is None:
        return False, "Report fixture was not initialized"
    data = ReportData(
        profile_data=world.trpt_profile_data,
        threat_surface_data=_materialize_threat_surface(world),
        scenarios=world.trpt_scenarios,
        scorecard_data=world.trpt_scorecard,
    )
    try:
        report_path = generate_report(data, world.trpt_tmpdir)
        world.trpt_html = report_path.read_text(encoding="utf-8")
    except Exception as exc:  # noqa: BLE001
        return False, f"report generation failed: {exc}"
    return True, ""


# ---------------------------------------------------------------------------
# Then steps
# ---------------------------------------------------------------------------


def _html(world: World) -> str:
    if not world.trpt_html:
        raise AssertionError("the HTML report has not been generated")
    return world.trpt_html


def _card_region(html: str, sid: str) -> str:
    marker = f'id="scenario-{sid}"'
    idx = html.find(marker)
    if idx == -1:
        raise AssertionError(f"scenario card {sid} is not rendered")
    return html[idx:]


def _prov_chain(html: str, sid: str) -> str:
    region = _card_region(html, sid)
    start_marker = '<div class="prov-chain">'
    start = region.find(start_marker)
    if start == -1:
        raise AssertionError(f"provenance chain missing for {sid}")
    body = region[start + len(start_marker) :]
    end = body.find('<div class="tab-panel">')
    if end == -1:
        raise AssertionError("provenance tab panel boundary not found")
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

# Feature step labels -> provenance step label prefixes
_STEP_PREFIX: dict[str, str] = {
    "OWASP LLM IDs": "2. OWASP LLM IDs",
    "Agentic Threats": "3. Agentic Threats",
    "Attack Pattern": "4a. Attack Pattern",
    "Attack Goal": "4b. Attack Goal",
    "Scenario classifications": "4c. Scenario classifications",
    "Entry Point": "5. Entry Point",
    "Zone Sequence": "6. Zone Sequence",
}


def _prov_steps(chain: str) -> dict[str, str]:
    """Return label -> body for every provenance chain step."""
    return {
        label: body
        for label, body in ((m.group(1), m.group(2)) for m in _STEP_RE.finditer(chain))
    }


def _step(steps: dict[str, str], prefix: str) -> str:
    matches = [body for label, body in steps.items() if label.startswith(prefix)]
    if len(matches) != 1:
        raise AssertionError(
            f"expected one provenance step starting {prefix!r}, got {len(matches)}"
        )
    return matches[0]


def _step_kv(body: str) -> dict[str, str]:
    return {label: value for label, value in _KV_RE.findall(body)}


def _visible(fragment: str) -> str:
    text = re.sub(r"<[^>]+>", "", fragment)
    text = text.replace("&mdash;", "").replace("&nbsp;", " ")
    return text.strip()


def _in_order(fragment: str, values: list[str]) -> bool:
    position = -1
    for value in values:
        idx = fragment.find(value)
        if idx == -1 or idx < position:
            return False
        position = idx
    return True


def _highlighted_value(body: str, value: str) -> bool:
    head = body.split("prov-highlight", 1)
    if len(head) < 2:
        return False
    return value in head[1].split("</span>", 1)[0]


def _chain_for(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Shared: resolve the scenario ID and return its provenance chain."""
    match = re.search(r'scenario "([^"]+)"|scenario card for "([^"]+)"', text)
    sid = (match.group(1) or match.group(2)) if match else "scn-01"
    try:
        return True, _prov_chain(_html(world), sid)
    except AssertionError as exc:
        return False, str(exc)


def _h_t_provenance_tab(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the scenario card for "X" contains a Provenance tab."""
    match = re.search(r'the scenario card for "([^"]+)"', text)
    if not match:
        return False, f"Could not parse Provenance tab step: {text}"
    try:
        region = _card_region(_html(world), match.group(1))
    except AssertionError as exc:
        return False, str(exc)
    return ">Provenance</label>" in region, "Provenance tab is missing"


def _h_t_step_labels(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the provenance chain shows the step labels ... in order."""
    match = re.search(r"the step labels (.*?) in order", text)
    if not match:
        return False, f"Could not parse step-label step: {text}"
    labels = re.findall(r'"([^"]+)"', match.group(1))
    passed, chain = _chain_for(world, text, examples)
    if not passed:
        return chain, ""
    return _in_order(chain, labels), f"step labels out of order: {labels}"


def _h_t_risk_card_values(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the provenance chain shows risk card "R" with risk name "N" and confidence value "C"."""
    match = re.search(
        r'risk card "([^"]+)" with risk name "([^"]+)" and confidence value "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse risk-card assertion: {text}"
    risk_id, risk_name, confidence = match.groups()
    passed, chain = _chain_for(world, text, examples)
    if not passed:
        return chain, ""
    kv = _step_kv(_step(_prov_steps(chain), "1. Risk Card"))
    return (
        kv["Risk ID"] == risk_id
        and kv["Risk Name"] == risk_name
        and kv["Confidence"] == confidence,
        f"risk card step shows {kv}",
    )


def _h_t_id_badges(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the provenance chain shows the OWASP LLM badges "A" and the agentic threat badges "B" in order."""
    match = re.search(
        r'the OWASP LLM badges "([^"]+)" and the agentic threat badges "([^"]+)" in order',
        text,
    )
    if not match:
        return False, f"Could not parse badge assertion: {text}"
    owasp, threats = match.groups()
    passed, chain = _chain_for(world, text, examples)
    if not passed:
        return chain, ""
    steps = _prov_steps(chain)
    owasp_body = _step(steps, "2. OWASP LLM IDs")
    threat_body = _step(steps, "3. Agentic Threats")
    return (
        _in_order(owasp_body, _split_csv(owasp))
        and _in_order(threat_body, _split_csv(threats)),
        "badges are missing or out of order",
    )


def _h_t_seed_highlight(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the provenance chain highlights seed "S" as the selected attack pattern."""
    match = re.search(r'highlights seed "([^"]+)" as the selected attack pattern', text)
    if not match:
        return False, f"Could not parse seed-highlight assertion: {text}"
    seed_id = match.group(1)
    passed, chain = _chain_for(world, text, examples)
    if not passed:
        return chain, ""
    pattern_body = _step(_prov_steps(chain), "4a. Attack Pattern")
    return (
        _highlighted_value(pattern_body, seed_id),
        f"seed {seed_id} is not highlighted",
    )


def _h_t_atlas_candidates(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the provenance chain shows the ATLAS techniques "A" as unpinned classification candidates."""
    match = re.search(r'the ATLAS techniques "([^"]+)" as unpinned', text)
    if not match:
        return False, f"Could not parse ATLAS assertion: {text}"
    atlas_ids = _split_csv(match.group(1))
    passed, chain = _chain_for(world, text, examples)
    if not passed:
        return chain, ""
    atlas_body = _step(_prov_steps(chain), "4c. Scenario classifications")
    return (
        _in_order(atlas_body, atlas_ids) and "prov-highlight" not in atlas_body,
        "ATLAS techniques are not shown as unpinned candidates",
    )


def _h_t_entry_and_zones(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the provenance chain highlights entry point "E" and shows zone crumbs "Z" in order."""
    match = re.search(
        r'highlights entry point "([^"]+)" and shows zone crumbs "([^"]+)" in order',
        text,
    )
    if not match:
        return False, f"Could not parse entry/zone assertion: {text}"
    entry_point, zones_csv = match.groups()
    passed, chain = _chain_for(world, text, examples)
    if not passed:
        return chain, ""
    steps = _prov_steps(chain)
    entry_body = _step(steps, "5. Entry Point")
    zones_body = _step(steps, "6. Zone Sequence")
    return (
        _highlighted_value(entry_body, entry_point)
        and _in_order(zones_body, _split_csv(zones_csv)),
        "entry point or zone crumbs are not highlighted in order",
    )


def _h_t_empty_risk(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the provenance chain shows an empty risk ID and risk name with confidence value "0.00"."""
    match = re.search(r'with confidence value "([^"]+)"', text)
    if not match:
        return False, f"Could not parse degraded risk-card assertion: {text}"
    confidence = match.group(1)
    passed, chain = _chain_for(world, text, examples)
    if not passed:
        return chain, ""
    kv = _step_kv(_step(_prov_steps(chain), "1. Risk Card"))
    return (
        _visible(kv["Risk ID"]) == ""
        and _visible(kv["Risk Name"]) == ""
        and kv["Confidence"] == confidence,
        f"degraded risk card step shows {kv}",
    )


def _h_t_no_taxonomy_badge(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the provenance chain shows no taxonomy badge in the risk card step."""
    passed, chain = _chain_for(world, text, examples)
    if not passed:
        return chain, ""
    risk_body = _step(_prov_steps(chain), "1. Risk Card")
    return "prov-badge" not in risk_body, "taxonomy badge is present"


def _h_t_placeholder(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the provenance chain shows the placeholder "none" in the <empty_step> step."""
    match = re.search(r'the placeholder "([^"]+)"', text)
    if not match:
        return False, f"Could not parse placeholder assertion: {text}"
    placeholder = match.group(1)
    empty_step = examples.get("empty_step", "")
    prefix = _STEP_PREFIX.get(empty_step)
    if not prefix:
        return False, f"Unknown empty-step label: {empty_step!r}"
    passed, chain = _chain_for(world, text, examples)
    if not passed:
        return chain, ""
    body = _step(_prov_steps(chain), prefix)
    marker = f'class="prov-badge prov-badge-muted">{placeholder}</span>'
    return marker in body, f"placeholder {placeholder!r} is missing"


def _h_t_remaining_badge(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the provenance chain still shows the "<remaining_badge>" badge in the other step."""
    match = re.search(r'still shows the "([^"]+)" badge', text)
    if not match:
        return False, f"Could not parse remaining-badge assertion: {text}"
    remaining = match.group(1)
    empty_step = examples.get("empty_step", "")
    other = "Agentic Threats" if empty_step == "OWASP LLM IDs" else "OWASP LLM IDs"
    prefix = _STEP_PREFIX.get(other)
    if not prefix:
        return False, f"Unknown other-step label: {other!r}"
    passed, chain = _chain_for(world, text, examples)
    if not passed:
        return chain, ""
    body = _step(_prov_steps(chain), prefix)
    return (
        remaining in body and "prov-badge" in body,
        f"badge {remaining!r} is missing from the {other} step",
    )


def _h_t_empty_seed_fields(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the provenance chain shows an empty seed ID, attack pattern name, and threat in the attack pattern step."""
    passed, chain = _chain_for(world, text, examples)
    if not passed:
        return chain, ""
    pattern_body = _step(_prov_steps(chain), "4a. Attack Pattern")
    kv = _step_kv(pattern_body)
    return (
        _visible(kv["Seed ID"]) == ""
        and _visible(kv["Name"]) == ""
        and _visible(kv["Threat"]) == "",
        "attack pattern step is not empty",
    )


def _h_t_no_description(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the provenance chain shows no description in the attack pattern step."""
    passed, chain = _chain_for(world, text, examples)
    if not passed:
        return chain, ""
    pattern_body = _step(_prov_steps(chain), "4a. Attack Pattern")
    return "Description" not in pattern_body, "description row is present"


def _h_t_steps_still_rendered(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the provenance chain still shows the "Attack Goal", "Entry Point", and "Zone Sequence" steps."""
    passed, chain = _chain_for(world, text, examples)
    if not passed:
        return chain, ""
    labels = ["Attack Goal", "Entry Point", "Zone Sequence"]
    return _in_order(chain, labels), "one of the later provenance steps is missing"


def _h_t_description_rendering(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the provenance chain shows the attack pattern description <rendering>."""
    rendering = examples.get("rendering", "")
    passed, chain = _chain_for(world, text, examples)
    if not passed:
        return chain, ""
    pattern_body = _step(_prov_steps(chain), "4a. Attack Pattern")
    description = _step_kv(pattern_body)["Description"]
    visible = _visible(description)
    if "truncated" in rendering:
        return (
            len(visible) == 303 and visible.endswith("..."),
            f"description not truncated to 300 chars: {len(visible)} chars",
        )
    return (
        len(visible) < 300 and not visible.endswith("..."),
        f"description not shown in full: {len(visible)} chars",
    )


def _h_t_scorecard_section(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the report contains an "Eval Scorecard" section."""
    return "<h2>Eval Scorecard</h2>" in _html(world), "Eval Scorecard section missing"


def _h_t_summary(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the scorecard summary shows scenario count N and feature file count M."""
    match = re.search(r"scenario count (\d+) and feature file count (\d+)", text)
    if not match:
        return False, f"Could not parse scorecard summary assertion: {text}"
    scenarios, features = match.groups()
    html = _html(world)
    return (
        f'<div class="scorecard-stat-value">{scenarios}</div>' in html
        and f'<div class="scorecard-stat-value">{features}</div>' in html,
        "scorecard summary statistics are missing",
    )


def _h_t_groups(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the scorecard shows the groups "A", "B", ... ."""
    match = re.search(r"the scorecard shows the groups (.*?)$", text)
    if not match:
        return False, f"Could not parse scorecard groups assertion: {text}"
    groups = re.findall(r'"([^"]+)"', match.group(1))
    html = _html(world)
    titles = re.findall(
        r'<div class="scorecard-group-title"[^>]*>(.*?)</div>', html, re.S
    )
    missing = [group for group in groups if group not in titles]
    return not missing, f"scorecard groups missing: {missing}"


def _h_t_badge_text(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the scorecard shows the badge "TEXT"."""
    match = re.search(r'the scorecard shows the badge "([^"]+)"', text)
    if not match:
        return False, f"Could not parse scorecard badge assertion: {text}"
    return match.group(1) in _html(world), f"scorecard badge {match.group(1)!r} missing"


def _h_t_clean_panel(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the scorecard shows the text "All scenarios pass quality checks"."""
    return (
        "All scenarios pass quality checks" in _html(world),
        "clean outliers panel missing",
    )


def _h_t_no_outliers_panel(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the scorecard shows no "Quality Outliers" panel."""
    return "Quality Outliers" not in _html(world), "outliers panel is present"


def _h_t_outliers_panel(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the scorecard shows a "Quality Outliers" panel."""
    return "Quality Outliers" in _html(world), "outliers panel missing"


def _outlier_rows(html: str) -> list[tuple[str, str, str]]:
    """Return (scenario, metric, value) rows from the outliers panel."""
    panel = html.split("Quality Outliers", 1)
    if len(panel) < 2:
        return []
    table = panel[1].split("</table>", 1)[0]
    body = table.split("<tbody>", 1)
    if len(body) < 2:
        return []
    rows: list[tuple[str, str, str]] = []
    for row in re.findall(r"<tr>(.*?)</tr>", body[1], re.S):
        cells = re.findall(r"<td[^>]*>(.*?)</td>", row, re.S)
        if len(cells) != 4:
            continue
        _sid, _group, metric, value_cell = cells
        value_match = re.search(r"<span[^>]*>(.*?)</span>", value_cell, re.S)
        rows.append((_sid, metric, value_match.group(1) if value_match else ""))
    return rows


def _h_t_outlier_row(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the outlier rows list "SID" with metric "M" and value "V"."""
    match = re.search(
        r'the outlier rows list "([^"]+)" with metric "([^"]+)" and value "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse outlier-row assertion: {text}"
    sid, metric, value = match.groups()
    rows = _outlier_rows(_html(world))
    found = any(
        row_sid == sid and row_metric == metric and row_value == value
        for row_sid, row_metric, row_value in rows
    )
    return found, f"outlier row {sid}/{metric}/{value} not found in {rows}"


def _h_t_outlier_order(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the outlier rows appear in the order ..., then ... ."""
    match = re.search(r"appear in the order (.*?)$", text)
    if not match:
        return False, f"Could not parse outlier-order assertion: {text}"
    expected = re.sub(r"\bthen\b", ",", match.group(1))
    sids = re.findall(r'"([^"]+)"', expected)
    rows = _outlier_rows(_html(world))
    actual = [row[0] for row in rows]
    return actual == sids, f"outlier order expected {sids}, got {actual}"


def _h_t_badge_color(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the scorecard shows a <badge_color> badge with label "L" and value V."""
    match = re.search(r'shows a (\w+) badge with label "([^"]+)" and value (.+)$', text)
    if not match:
        return False, f"Could not parse badge-color assertion: {text}"
    color, label, value = match.groups()
    html = _html(world)
    return (
        f"scorecard-badge-{color}" in html and f"{label}: {value}</span>" in html,
        f"badge {label}: {value} ({color}) not found",
    )


def _h_t_versioned_section(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the report contains a "Versioned Eval Scorecard" section with the schema badge "Schema v1"."""
    html = _html(world)
    return (
        "<h2>Versioned Eval Scorecard</h2>" in html
        and '<span class="badge">Schema v1</span>' in html,
        "Versioned Eval Scorecard section is missing",
    )


def _h_t_versioned_group(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the scorecard shows the <group> group with the metric's status badge in <badge_color>."""
    group = examples.get("group", "")
    badge_color = examples.get("badge_color", "")
    html = _html(world)
    marker = f'<div class="scorecard-group-title">{group}</div>'
    if marker not in html:
        return False, f"scorecard group {group!r} missing"
    group_region = html.split(marker, 1)[1]
    return (
        f"scorecard-badge-{badge_color}" in group_region,
        f"status badge color {badge_color!r} missing in group {group!r}",
    )


def _h_t_seed_section(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the report <rendering> a "Scenario Seed" section."""
    match = re.search(r"the report (renders|does not render) a ", text)
    if not match:
        return False, f"Could not parse Scenario Seed section assertion: {text}"
    renders = match.group(1) == "renders"
    return (
        (_SEED_SECTION_MARKER in _html(world)) is renders,
        "Scenario Seed section mismatch",
    )


def _h_t_seed_section_present(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the report contains a "Scenario Seed" section."""
    return _SEED_SECTION_MARKER in _html(world), "Scenario Seed section is missing"


def _h_t_seed_name(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the Scenario Seed section shows the attack pattern name "N"."""
    match = re.search(r'shows the attack pattern name "([^"]+)"', text)
    if not match:
        return False, f"Could not parse seed-name assertion: {text}"
    html = _html(world)
    region = _seed_region(html)
    return match.group(1) in region, "attack pattern name missing from Scenario Seed"


def _h_t_seed_description(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the Scenario Seed section shows the description "D"."""
    match = re.search(r'shows the description "([^"]+)"', text)
    if not match:
        return False, f"Could not parse seed-description assertion: {text}"
    region = _seed_region(_html(world))
    return match.group(1) in region, "description missing from Scenario Seed"


def _h_t_seed_threat(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the Scenario Seed section shows threat "T" with threat name "N"."""
    match = re.search(r'shows threat "([^"]+)" with threat name "([^"]+)"', text)
    if not match:
        return False, f"Could not parse seed-threat assertion: {text}"
    threat_id, threat_name = match.groups()
    region = _seed_region(_html(world))
    return (
        f"{threat_id} &mdash; {threat_name}" in region,
        "threat pair missing from Scenario Seed",
    )


def _h_t_seed_origin(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the Scenario Seed section shows origin "O" and seed "S"."""
    match = re.search(r'shows origin "([^"]+)" and seed "([^"]+)"', text)
    if not match:
        return False, f"Could not parse seed-origin assertion: {text}"
    origin, seed_id = match.groups()
    region = _seed_region(_html(world))
    return (
        origin in region and seed_id in region,
        "origin or seed missing from Scenario Seed",
    )


def _seed_region(html: str) -> str:
    if _SEED_SECTION_MARKER not in html:
        raise AssertionError("Scenario Seed section is not rendered")
    region = html.split(_SEED_SECTION_MARKER, 1)[1]
    return region.split("</details>", 1)[0]


def _h_t_no_scorecard_section(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the report contains no "Eval Scorecard" section."""
    return "Eval Scorecard" not in _html(world), "Eval Scorecard section is present"


def _h_t_no_sidebar_link(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the report contains no scorecard sidebar link."""
    return (
        '<a href="#sec-scorecard">' not in _html(world),
        "scorecard sidebar link is present",
    )


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def register(api: object) -> None:
    """Register taxonomy report rendering step handlers."""
    api.set_feature(None)
    api.register(
        "an offline completed taxonomy-and-risk run fixture",
        _h_background,
        source_order=6000,
    )
    api.register(
        r'the run fixture contains scenario "([^"]+)" with seed metadata carrying seed "([^"]+)", attack pattern name "([^"]+)", description "([^"]*)", threat "([^"]+)", threat name "([^"]+)", and origin "([^"]+)"',
        _h_contains_scenario_with_seed,
        source_order=6001,
    )
    api.register(
        r'the run fixture contains scenario "([^"]+)" whose seed metadata is .*',
        _h_contains_scenario_seed_case,
        source_order=6002,
    )
    api.register(
        r'the run fixture contains scenario "([^"]+)" with no seed metadata but an attack goal and one traversed zone',
        _h_contains_scenario_no_seed_metadata,
        source_order=6003,
    )
    api.register(
        r'the run fixture contains scenario "([^"]+)" without a risk card',
        _h_contains_scenario_without_risk_card,
        source_order=6004,
    )
    api.register(
        r'the run fixture contains scenario "([^"]+)"$',
        _h_contains_scenario,
        source_order=6005,
    )
    api.register(
        r'scenario "([^"]+)" carries seed metadata with seed "([^"]+)", attack pattern name "([^"]+)", description "([^"]*)", threat "([^"]+)", threat name "([^"]+)", and origin "([^"]+)"',
        _h_carries_seed_metadata,
        source_order=6010,
    )
    api.register(
        r'scenario "([^"]+)" carries risk card "([^"]+)" with risk name "([^"]+)", taxonomy "([^"]+)", and confidence ([0-9.]+)',
        _h_carries_risk_card,
        source_order=6011,
    )
    api.register(
        r'scenario "([^"]+)" lists OWASP LLM IDs "([^"]*)" and agentic threats "([^"]*)" except the .* is empty',
        _h_lists_ids_except_empty,
        source_order=6012,
    )
    api.register(
        r'scenario "([^"]+)" lists OWASP LLM IDs "([^"]*)" and agentic threats "([^"]*)"$',
        _h_lists_ids,
        source_order=6013,
    )
    api.register(
        r'the threat surface entry for risk card "([^"]+)" lists attack patterns "([^"]+)" and ATLAS techniques "([^"]+)"',
        _h_threat_surface_entry,
        source_order=6014,
    )
    api.register(
        r'the capability profile lists entry points "([^"]+)" and scenario "([^"]+)" selects "([^"]+)"',
        _h_capability_profile_entry_points,
        source_order=6015,
    )
    api.register(
        r'scenario "([^"]+)" traverses zones "([^"]+)"',
        _h_traverses_zones,
        source_order=6016,
    )
    api.register(
        r'the seed metadata description of scenario "([^"]+)" is .*',
        _h_seed_description_case,
        source_order=6017,
    )
    api.register(
        r"an evaluation scorecard with consistency, gherkin, grounding, technique-agreement, diversity, and plausibility metrics",
        _h_scorecard_full,
        source_order=6020,
    )
    api.register(
        r"an evaluation scorecard whose consistency, agreement, diversity, and plausibility metrics are all in range",
        _h_scorecard_in_range,
        source_order=6021,
    )
    api.register(
        r'an evaluation scorecard where scenario "([^"]+)" has zone alignment ([0-9.]+) and scenario "([^"]+)" has zone alignment ([0-9.]+)',
        _h_scorecard_zone_alignment,
        source_order=6022,
    )
    api.register(
        r"the same scorecard records (\d+) capability-complexity violations",
        _h_scorecard_violations,
        source_order=6023,
    )
    api.register(
        r"an evaluation scorecard whose only consistency metric is the mean .*",
        _h_scorecard_only_mean,
        source_order=6024,
    )
    api.register(
        r"an evaluation scorecard whose only plausibility metric is .* capability-complexity violations",
        _h_scorecard_only_violations,
        source_order=6025,
    )
    api.register(
        r"a schema v1 scorecard with one metric in status .* under the .* group",
        _h_scorecard_versioned,
        source_order=6026,
    )
    api.register(
        "the run fixture carries no eval scorecard",
        _h_scorecard_none,
        source_order=6027,
    )
    # Tagged first-class registration: nullable_usage registers the same raw
    # pattern globally, so this feature-specific handler must win within this
    # feature's own scope only.
    api.set_feature("taxonomy_report")
    api.register_first(
        "the HTML report is generated",
        _h_generate_report,
        source_order=6100,
    )
    api.set_feature(None)
    api.register(
        r'the scenario card for "([^"]+)" (?:still )?contains a Provenance tab',
        _h_t_provenance_tab,
        source_order=6200,
    )
    api.register(
        r"the provenance chain shows the step labels .* in order",
        _h_t_step_labels,
        source_order=6201,
    )
    api.register(
        r'the provenance chain shows risk card "([^"]+)" with risk name "([^"]+)" and confidence value "([^"]+)"',
        _h_t_risk_card_values,
        source_order=6202,
    )
    api.register(
        r'the provenance chain shows the OWASP LLM badges "([^"]+)" and the agentic threat badges "([^"]+)" in order',
        _h_t_id_badges,
        source_order=6203,
    )
    api.register(
        r'the provenance chain highlights seed "([^"]+)" as the selected attack pattern',
        _h_t_seed_highlight,
        source_order=6204,
    )
    api.register(
        r'the provenance chain shows the ATLAS techniques "([^"]+)" as unpinned classification candidates',
        _h_t_atlas_candidates,
        source_order=6205,
    )
    api.register(
        r'the provenance chain highlights entry point "([^"]+)" and shows zone crumbs "([^"]+)" in order',
        _h_t_entry_and_zones,
        source_order=6206,
    )
    api.register(
        r"the provenance chain shows an empty risk ID and risk name with confidence value \"([^\"]+)\"",
        _h_t_empty_risk,
        source_order=6207,
    )
    api.register(
        r"the provenance chain shows no taxonomy badge in the risk card step",
        _h_t_no_taxonomy_badge,
        source_order=6208,
    )
    api.register(
        r'the provenance chain shows the placeholder "([^"]+)" in the .* step',
        _h_t_placeholder,
        source_order=6209,
    )
    api.register(
        r'the provenance chain still shows the "([^"]+)" badge in the other step',
        _h_t_remaining_badge,
        source_order=6210,
    )
    api.register(
        r"the provenance chain shows an empty seed ID, attack pattern name, and threat in the attack pattern step",
        _h_t_empty_seed_fields,
        source_order=6211,
    )
    api.register(
        r"the provenance chain shows no description in the attack pattern step",
        _h_t_no_description,
        source_order=6212,
    )
    api.register(
        r'the provenance chain still shows the "Attack Goal", "Entry Point", and "Zone Sequence" steps',
        _h_t_steps_still_rendered,
        source_order=6213,
    )
    api.register(
        r"the provenance chain shows the attack pattern description .*",
        _h_t_description_rendering,
        source_order=6214,
    )
    api.register(
        r'the report contains an "Eval Scorecard" section',
        _h_t_scorecard_section,
        source_order=6215,
    )
    api.register(
        r"the scorecard summary shows scenario count \d+ and feature file count \d+",
        _h_t_summary,
        source_order=6216,
    )
    api.register(
        r"the scorecard shows the groups .*",
        _h_t_groups,
        source_order=6217,
    )
    api.register(
        r'the scorecard shows the badge "([^"]+)"',
        _h_t_badge_text,
        source_order=6218,
    )
    api.register(
        r'the scorecard shows the text "All scenarios pass quality checks"',
        _h_t_clean_panel,
        source_order=6219,
    )
    api.register(
        r'the scorecard shows no "Quality Outliers" panel',
        _h_t_no_outliers_panel,
        source_order=6220,
    )
    api.register(
        r'the scorecard shows a "Quality Outliers" panel',
        _h_t_outliers_panel,
        source_order=6221,
    )
    api.register(
        r'the outlier rows list "([^"]+)" with metric "([^"]+)" and value "([^"]+)"',
        _h_t_outlier_row,
        source_order=6222,
    )
    api.register(
        r"the outlier rows appear in the order .*",
        _h_t_outlier_order,
        source_order=6223,
    )
    api.register(
        r"the scorecard shows a \w+ badge with label \"([^\"]+)\" and value .*",
        _h_t_badge_color,
        source_order=6224,
    )
    api.register(
        r'the report contains a "Versioned Eval Scorecard" section with the schema badge "Schema v1"',
        _h_t_versioned_section,
        source_order=6225,
    )
    api.register(
        r"the scorecard shows the .* group with the metric's status badge in .*",
        _h_t_versioned_group,
        source_order=6226,
    )
    api.register(
        r'the report (renders|does not render) a "Scenario Seed" section',
        _h_t_seed_section,
        source_order=6227,
    )
    api.register(
        r'the report contains a "Scenario Seed" section',
        _h_t_seed_section_present,
        source_order=6228,
    )
    api.register(
        r'the Scenario Seed section shows the attack pattern name "([^"]+)"',
        _h_t_seed_name,
        source_order=6229,
    )
    api.register(
        r'the Scenario Seed section shows the description "([^"]+)"',
        _h_t_seed_description,
        source_order=6230,
    )
    api.register(
        r'the Scenario Seed section shows threat "([^"]+)" with threat name "([^"]+)"',
        _h_t_seed_threat,
        source_order=6231,
    )
    api.register(
        r'the Scenario Seed section shows origin "([^"]+)" and seed "([^"]+)"',
        _h_t_seed_origin,
        source_order=6232,
    )
    api.register(
        r'the report contains no "Eval Scorecard" section',
        _h_t_no_scorecard_section,
        source_order=6233,
    )
    api.register(
        "the report contains no scorecard sidebar link",
        _h_t_no_sidebar_link,
        source_order=6234,
    )


__all__ = ["FEATURE_ID", "register"]
