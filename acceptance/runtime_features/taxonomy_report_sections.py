"""Acceptance step handlers for taxonomy/risk HTML report section rendering.

Covers the section builders that still live in ``report/template.py``: the
capability profile, threat surface, coverage analysis, threat-technique
matrix, actor profile distribution, scenario cards (priority signals,
actor profile, attack tree, generation inputs, behavior spec, ATLAS
techniques, attack complexity), the run summary, pipeline call logs, and
raw-data syntax highlighting.  Fixtures are assembled step-by-step on the
world reusing the ``taxonomy_report`` vocabulary; the When step drives the
public report entry ``generate_report`` so the pinned behavior is
verified on the real rendered document.  All fixtures are offline.
"""

from __future__ import annotations

import re
from typing import Any

from runtime_world import World
from runtime_features.taxonomy_report import (
    _h_background,
    _h_generate_report,
    _new_scenario,
    _scn,
    _split_csv,
)

FEATURE_ID = "taxonomy_report_sections"


# ---------------------------------------------------------------------------
# Extraction helpers
# ---------------------------------------------------------------------------


def _html(world: World) -> str:
    """Return the generated report HTML, failing loudly if absent."""
    if not world.trpt_html:
        raise AssertionError("the HTML report has not been generated")
    return world.trpt_html


def _card_region(html: str, sid: str) -> str:
    marker = f'id="scenario-{sid}"'
    idx = html.find(marker)
    if idx == -1:
        raise AssertionError(f"scenario card {sid} is not rendered")
    return html[idx:]


def _section_region(html: str, section_id: str) -> str:
    marker = f'id="{section_id}"'
    idx = html.find(marker)
    if idx == -1:
        raise AssertionError(f"section {section_id!r} is not rendered")
    return html[idx : idx + 60000]


def _profile_region(world: World) -> str:
    return _section_region(_html(world), "sec-profile")


def _threats_region(world: World) -> str:
    return _section_region(_html(world), "sec-threats")


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
    """Strip markup and decode entities for text-content assertions."""
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


def _last_scenario(world: World) -> dict[str, Any]:
    if not world.trpt_scenarios:
        raise AssertionError("the fixture contains no scenarios yet")
    return world.trpt_scenarios[-1]


def _coverage_card_statuses(region: str) -> dict[str, str]:
    """Return coverage-card title -> status label."""
    return {
        title: status
        for title, _cls, status in re.findall(
            r'<span class="coverage-card-title">([^<]+)</span>\s*'
            r'<span class="coverage-status [\w-]+">([^<]+)</span>',
            region,
        )
    }


# ---------------------------------------------------------------------------
# Given steps
# ---------------------------------------------------------------------------


def _h_profile_zones(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the capability profile declares active zones "A,B"."""
    match = re.search(r'the capability profile declares active zones "([^"]+)"', text)
    if not match:
        return False, f"Could not parse active-zones step: {text}"
    world.trpt_profile_data["zones_active"] = _split_csv(match.group(1))
    return True, ""


def _h_profile_degraded_zone(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: ... declares active zone "Z" with no tool inventory, no external integrations, and no evidence."""
    match = re.search(
        r'the capability profile declares active zone "([^"]+)" with no tool '
        r"inventory, no external integrations, and no evidence",
        text,
    )
    if not match:
        return False, f"Could not parse degraded-profile step: {text}"
    world.trpt_profile_data = {
        "zones_active": [match.group(1)],
        "entry_points": [],
        "tool_inventory": [],
        "external_integrations": [],
        "entry_point_evidence": [],
        "tool_inventory_evidence": [],
    }
    return True, ""


def _h_profile_flags(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: ... declares the flag "F1" <on|off> and the flag "F2" <on|off> with confidence "C"."""
    match = re.search(
        r'the capability profile declares the flag "([^"]+)" (on|off) and the '
        r'flag "([^"]+)" (on|off) with confidence "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse flag step: {text}"
    name1, state1, name2, state2, confidence = match.groups()
    flag_map = {
        "memory": "has_persistent_memory",
        "multi-agent": "multi_agent",
        "hitl": "hitl",
    }
    world.trpt_profile_data[flag_map[name1.lower()]] = state1 == "on"
    world.trpt_profile_data[flag_map[name2.lower()]] = state2 == "on"
    world.trpt_profile_data["confidence"] = confidence
    return True, ""


def _h_profile_entry_points(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: ... lists entry point "E1" with direction "D1" and entry point "E2" with direction "D2"."""
    match = re.search(
        r'the capability profile lists entry point "([^"]+)" with direction '
        r'"([^"]+)"(?: and entry point "([^"]+)" with direction "([^"]+)")?',
        text,
    )
    if not match:
        return False, f"Could not parse entry-point step: {text}"
    entries: list[dict[str, str]] = []
    if match.group(1):
        entries.append({"name": match.group(1), "direction": match.group(2)})
    if match.group(3):
        entries.append({"name": match.group(3), "direction": match.group(4)})
    world.trpt_profile_data["entry_points"] = entries
    return True, ""


def _h_profile_tool(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: ... lists the tool "T" with tool id "ID"."""
    match = re.search(
        r'the capability profile lists the tool "([^"]+)" with tool id "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse tool step: {text}"
    world.trpt_profile_data["tool_inventory"] = [
        {"name": match.group(1), "tool_id": match.group(2)}
    ]
    return True, ""


def _h_profile_integration(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: ... lists the integration "I" with integration id "ID"."""
    match = re.search(
        r'the capability profile lists the integration "([^"]+)" with '
        r'integration id "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse integration step: {text}"
    world.trpt_profile_data["external_integrations"] = [
        {"name": match.group(1), "integration_id": match.group(2)}
    ]
    return True, ""


def _h_profile_ep_completeness(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: ... records entry point completeness "C" with evidence "E"."""
    match = re.search(
        r'the capability profile records entry point completeness "([^"]+)" '
        r'with evidence "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse entry-point completeness step: {text}"
    world.trpt_profile_data["entry_point_completeness"] = match.group(1)
    world.trpt_profile_data["entry_point_evidence"] = [match.group(2)]
    return True, ""


def _h_profile_tool_completeness(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: ... records tool inventory completeness "C" with no evidence."""
    match = re.search(
        r'the capability profile records tool inventory completeness "([^"]+)" '
        r"with no evidence",
        text,
    )
    if not match:
        return False, f"Could not parse tool-inventory completeness step: {text}"
    world.trpt_profile_data["tool_inventory_completeness"] = match.group(1)
    world.trpt_profile_data["tool_inventory_evidence"] = []
    return True, ""


def _h_profile_kc(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: ... declares the KC sub-code "K"."""
    match = re.search(
        r'the capability profile declares the KC sub-code "([^"]+)"', text
    )
    if not match:
        return False, f"Could not parse KC sub-code step: {text}"
    world.trpt_profile_data.setdefault("kc_subcodes", []).append(match.group(1))
    return True, ""


# --- Threat surface Given steps ------------------------------------------


def _h_ts_actionable(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: ... lists the actionable entry for risk card "R" with risk name "N"[, confidence C][, OWASP LLM IDs "A"][, agentic threats "T"][, and attack patterns "P"]."""
    match = re.search(
        r'the threat surface lists the actionable entry for risk card "([^"]+)"'
        r'(?: with risk name "([^"]+)")?(?:, confidence ([0-9.]+))?'
        r'(?:, OWASP LLM IDs "([^"]*)")?(?:,? (?:with )?agentic threats "([^"]*)")?'
        r'(?:,? and attack patterns "([^"]*)")?',
        text,
    )
    if not match:
        return False, f"Could not parse actionable entry step: {text}"
    risk_id, risk_name, confidence, owasp, threats, patterns = match.groups()
    entry: dict[str, Any] = {
        "risk_card": {
            "risk_id": risk_id,
            "risk_name": risk_name or risk_id,
        },
        "owasp_llm_ids": _split_csv(owasp or "") if owasp is not None else [],
        "agentic_threat_ids": _split_csv(threats or "") if threats is not None else [],
        "attack_pattern_ids": _split_csv(patterns or "")
        if patterns is not None
        else [],
    }
    if confidence:
        entry["risk_card"]["confidence"] = float(confidence)
    world.trpt_threat_surface.setdefault("entries", []).append(entry)
    return True, ""


def _h_ts_governance(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: ... lists the governance-only entry for risk card "R" with risk name "N" and no mappings."""
    match = re.search(
        r"the threat surface lists the governance-only entry for risk card "
        r'"([^"]+)" with risk name "([^"]+)" and no mappings',
        text,
    )
    if not match:
        return False, f"Could not parse governance-only step: {text}"
    world.trpt_threat_surface.setdefault("governance_only", []).append(
        {
            "risk_card": {
                "risk_id": match.group(1),
                "risk_name": match.group(2),
            },
            "owasp_llm_ids": [],
            "agentic_threat_ids": [],
            "attack_pattern_ids": [],
            "governance_only": True,
        }
    )
    return True, ""


def _h_ts_empty(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the threat surface lists no actionable entries and no governance-only entries."""
    world.trpt_threat_surface = {"entries": [], "governance_only": []}
    return True, ""


# --- Scenario Given steps -------------------------------------------------


def _h_contains_many(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the run fixture contains scenario "A" and scenario "B"."""
    match = re.search(
        r'the run fixture contains scenario "([^"]+)" and scenario "([^"]+)"$', text
    )
    if not match:
        return False, f"Could not parse two-scenario step: {text}"
    world.trpt_scenarios.append(_new_scenario(match.group(1)))
    world.trpt_scenarios.append(_new_scenario(match.group(2)))
    return True, ""


def _h_contains_three(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the run fixture contains scenario "A", "B", and "C"."""
    match = re.search(
        r'the run fixture contains scenario "([^"]+)", "([^"]+)", and "([^"]+)"$',
        text,
    )
    if not match:
        return False, f"Could not parse three-scenario step: {text}"
    for sid in match.groups():
        world.trpt_scenarios.append(_new_scenario(sid))
    return True, ""


def _h_contains_minimal(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: ... contains scenario "X" with only its scenario ID."""
    match = re.search(
        r'the run fixture contains scenario "([^"]+)" with only its scenario ID',
        text,
    )
    if not match:
        return False, f"Could not parse minimal-scenario step: {text}"
    scenario = _new_scenario(match.group(1))
    scenario.pop("priority", None)
    world.trpt_scenarios.append(scenario)
    return True, ""


def _h_contains_empty_optional(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: ... contains scenario "X" with no priority signals / no actor profile / no attack complexity assessment."""
    match = re.search(
        r'the run fixture contains scenario "([^"]+)" with no (priority signals|actor profile|attack complexity assessment)',
        text,
    )
    if not match:
        return False, f"Could not parse empty-optional step: {text}"
    world.trpt_scenarios.append(_new_scenario(match.group(1)))
    return True, ""


def _h_contains_no_feature_file(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: ... contains scenario "X" with no behavior feature file."""
    match = re.search(
        r'the run fixture contains scenario "([^"]+)" with no behavior feature file',
        text,
    )
    if not match:
        return False, f"Could not parse no-feature-file step: {text}"
    world.trpt_scenarios.append(_new_scenario(match.group(1)))
    return True, ""


def _h_each_scenario_actor_goal(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: each scenario has actor type "T" with capability level "C" and goal category "G"."""
    match = re.search(
        r'each scenario has actor type "([^"]+)" with capability level '
        r'"([^"]+)" and goal category "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse each-scenario actor step: {text}"
    actor_type, capability, goal = match.groups()
    if not world.trpt_scenarios:
        return _resolve(False, "no scenarios in the fixture")
    for scenario in world.trpt_scenarios:
        scenario["actor_profile"] = {
            "actor_type": actor_type,
            "capability_level": capability,
            "goal_category_parent": goal,
        }
    return True, ""


def _h_no_run_manifest(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the run fixture contains no run manifest."""
    world.trpt_manifest_data = {}
    return True, ""


def _h_contains_feature_file(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: ... contains scenario "X" with a behavior feature file containing the steps "S1", "S2", and "S3"."""
    match = re.search(
        r'the run fixture contains scenario "([^"]+)" with a behavior feature '
        r'file containing the steps "([^"]+)", "([^"]+)", and "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse feature-file step: {text}"
    sid = match.group(1)
    world.trpt_scenarios.append(_new_scenario(sid))
    steps = match.groups()[1:]
    world.trpt_feature_files[sid] = (
        "\n".join([f"Feature: {sid}", *(f"  {step}" for step in steps)]) + "\n"
    )
    return True, ""


def _h_no_scenarios(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the run fixture contains no scenarios."""
    world.trpt_scenarios = []
    return True, ""


def _h_scn_priority(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: scenario "X" carries priority composite C."""
    match = re.search(r'scenario "([^"]+)" carries priority composite ([0-9.]+)$', text)
    if not match:
        return False, f"Could not parse priority step: {text}"
    scenario = _scn(world, match.group(1))
    scenario["priority"] = {"composite": float(match.group(2))}
    return True, ""


def _h_scn_priority_signals(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: scenario "X" carries priority composite C with the signals "A", "B", "C", "D", "E", and "F"."""
    match = re.search(
        r'scenario "([^"]+)" carries priority composite ([0-9.]+) with the '
        r'signals "([^"]+)", "([^"]+)", "([^"]+)", "([^"]+)", "([^"]+)", and "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse priority-signals step: {text}"
    sid, composite, *signal_values = match.groups()
    signals = {
        "technique_maturity": signal_values[0],
        "risk_impact": signal_values[1],
        "risk_likelihood": signal_values[2],
        "attack_complexity": signal_values[3],
        "architecture_match": signal_values[4],
        "structural_exposure": signal_values[5],
    }
    _scn(world, sid)["priority"] = {"composite": float(composite), "signals": signals}
    return True, ""


def _h_scn_priority_title(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: scenario "X" carries priority composite C with narrative title "T"."""
    match = re.search(
        r'scenario "([^"]+)" carries priority composite ([0-9.]+) with '
        r'narrative title "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse priority-title step: {text}"
    scenario = _scn(world, match.group(1))
    scenario["priority"] = {"composite": float(match.group(2))}
    scenario["narrative"]["title"] = match.group(3)
    return True, ""


def _h_scn_actor_profile(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: scenario "X" has an actor profile of type "T" with capability "C" and goal "G"."""
    match = re.search(
        r'scenario "([^"]+)" has an actor profile of type "([^"]+)" with '
        r'capability "([^"]+)" and goal "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse actor-profile step: {text}"
    _scn(world, match.group(1))["actor_profile"] = {
        "actor_type": match.group(2),
        "capability_level": match.group(3),
        "goal_category_name": match.group(4),
    }
    return True, ""


def _h_scn_actor_type(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: scenario "X" has actor type "T" with capability level "C"."""
    match = re.search(
        r'scenario "([^"]+)" has actor type "([^"]+)" with capability level "([^"]+)"$',
        text,
    )
    if not match:
        return False, f"Could not parse actor-type step: {text}"
    _scn(world, match.group(1))["actor_profile"] = {
        "actor_type": match.group(2),
        "capability_level": match.group(3),
    }
    return True, ""


def _h_scn_actor_type_goal(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: scenario "X" has actor type "T" with capability level "C" and goal category "G"."""
    match = re.search(
        r'scenario "([^"]+)" has actor type "([^"]+)" with capability level '
        r'"([^"]+)" and goal category "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse actor-type-goal step: {text}"
    _scn(world, match.group(1))["actor_profile"] = {
        "actor_type": match.group(2),
        "capability_level": match.group(3),
        "goal_category_parent": match.group(4),
    }
    return True, ""


def _h_actor_bdi(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the actor profile records the beliefs "B", the desires "D", the intentions "I", and the resources "R"."""
    match = re.search(
        r'the actor profile records the beliefs "([^"]+)", the desires "([^"]+)", '
        r'the intentions "([^"]+)", and the resources "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse BDI step: {text}"
    actor = _last_scenario(world).setdefault("actor_profile", {})
    beliefs, desires, intentions, resources = match.groups()
    actor["beliefs"] = [beliefs]
    actor["desires"] = [desires]
    actor["intentions"] = [intentions]
    actor["resources"] = [resources]
    return True, ""


def _h_actor_access(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the actor profile records access with ingress mode "I", initial entry point ID "E", and influence source "S"."""
    match = re.search(
        r'the actor profile records access with ingress mode "([^"]+)", initial '
        r'entry point ID "([^"]+)", and influence source "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse access step: {text}"
    _last_scenario(world).setdefault("actor_profile", {})["access"] = {
        "ingress_mode": match.group(1),
        "initial_entry_point_id": match.group(2),
        "influence_source": match.group(3),
    }
    return True, ""


def _h_scn_seed_and_techniques(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: scenario "X" carries the attack pattern seed "S" with ATLAS techniques "A"."""
    match = re.search(
        r'scenario "([^"]+)" carries the attack pattern seed "([^"]+)" with '
        r'ATLAS techniques "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse seed-techniques step: {text}"
    chain = (
        _scn(world, match.group(1))
        .setdefault("faceting", {})
        .setdefault("taxonomy_chain", {})
    )
    chain["scenario_seed"] = match.group(2)
    chain["atlas_technique_ids"] = _split_csv(match.group(3))
    return True, ""


def _h_scn_seed_no_techniques(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: scenario "X" carries the attack pattern seed "S" with no ATLAS techniques."""
    match = re.search(
        r'scenario "([^"]+)" carries the attack pattern seed "([^"]+)" with '
        r"no ATLAS techniques",
        text,
    )
    if not match:
        return False, f"Could not parse no-techniques step: {text}"
    chain = (
        _scn(world, match.group(1))
        .setdefault("faceting", {})
        .setdefault("taxonomy_chain", {})
    )
    chain["scenario_seed"] = match.group(2)
    chain["atlas_technique_ids"] = []
    return True, ""


def _h_scn_pin_technique(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: scenario "X" pins the technique "T" with the name "N"."""
    match = re.search(
        r'scenario "([^"]+)" pins the technique "([^"]+)" with the name "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse pinned-technique step: {text}"
    _scn(world, match.group(1))["candidate_filter"] = {
        "pinned_technique_ids": [match.group(2)],
        "pinned_technique_names": [match.group(3)],
    }
    return True, ""


def _h_scn_seed_metadata(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: scenario "X" carries seed metadata with the attack pattern name "N", threat "T" with name "TN", and the taxonomy chain ATLAS techniques "A"."""
    match = re.search(
        r'scenario "([^"]+)" carries seed metadata with the attack pattern name '
        r'"([^"]+)", threat "([^"]+)" with name "([^"]+)", and the taxonomy '
        r'chain ATLAS techniques "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse seed-metadata step: {text}"
    sid, pattern_name, threat_id, threat_name, atlas_csv = match.groups()
    _scn(world, sid)["scenario_seed_metadata"] = {
        "attack_pattern_name": pattern_name,
        "threat_id": threat_id,
        "threat_name": threat_name,
    }
    chain = _scn(world, sid).setdefault("faceting", {}).setdefault("taxonomy_chain", {})
    chain["atlas_technique_ids"] = _split_csv(atlas_csv)
    return True, ""


def _h_scn_narrative(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: scenario "X" has a narrative with title "T" and no summary."""
    match = re.search(
        r'scenario "([^"]+)" has a narrative with title "([^"]+)" and no summary',
        text,
    )
    if not match:
        return False, f"Could not parse narrative step: {text}"
    narrative = _scn(world, match.group(1))["narrative"]
    narrative["title"] = match.group(2)
    narrative["summary"] = ""
    return True, ""


def _h_scn_technique_scope(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: scenario "X" records technique scope evidence with scenario classifications "A" and no projected-step mappings."""
    match = re.search(
        r'scenario "([^"]+)" records technique scope evidence with scenario '
        r'classifications "([^"]+)" and no projected-step mappings',
        text,
    )
    if not match:
        return False, f"Could not parse technique-scope step: {text}"
    _scn(world, match.group(1))["technique_scope_evidence"] = {
        "scenario_classification_ids": _split_csv(match.group(2)),
        "projected_step_mapping_ids": [],
    }
    return True, ""


def _h_scn_taxonomy_chain_atlas(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: scenario "X" lists ATLAS techniques "A" in its taxonomy chain."""
    match = re.search(
        r'scenario "([^"]+)" lists ATLAS techniques "([^"]+)" in its taxonomy chain',
        text,
    )
    if not match:
        return False, f"Could not parse taxonomy-chain step: {text}"
    chain = (
        _scn(world, match.group(1))
        .setdefault("faceting", {})
        .setdefault("taxonomy_chain", {})
    )
    chain["atlas_technique_ids"] = _split_csv(match.group(2))
    return True, ""


def _h_scn_attack_tree(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: scenario "X" carries an attack tree with <tree_case>."""
    match = re.search(r'scenario "([^"]+)" carries an attack tree with (.*)$', text)
    if not match:
        return False, f"Could not parse attack-tree step: {text}"
    sid, tree_case = match.groups()

    or_match = re.search(
        r'an OR root labeled "([^"]+)" with two leaf children carrying the '
        r'techniques "([^"]+)" and "([^"]+)"',
        tree_case,
    )
    if or_match:
        label, tech1, tech2 = or_match.groups()
        _scn(world, sid)["attack_tree"] = {
            "goal": label,
            "root": {
                "gate": "OR",
                "label": label,
                "children": [
                    {"gate": "LEAF", "label": "Leaf 1", "technique_id": tech1},
                    {"gate": "LEAF", "label": "Leaf 2", "technique_id": tech2},
                ],
            },
        }
        return True, ""

    leaf_match = re.search(
        r'a single leaf node labeled "([^"]+)" with no children', tree_case
    )
    if leaf_match:
        _scn(world, sid)["attack_tree"] = {
            "goal": leaf_match.group(1),
            "root": {"gate": "LEAF", "label": leaf_match.group(1)},
        }
        return True, ""

    action_match = re.search(
        r'a leaf node labeled "([^"]+)" whose action invokes tool "([^"]+)" and '
        r'a leaf node labeled "([^"]+)" whose action performs initial ingress '
        r'through entry point "([^"]+)" in zone "([^"]+)"',
        tree_case,
    )
    if action_match:
        label1, tool_id, label2, ep_id, zone = action_match.groups()
        _scn(world, sid)["attack_tree"] = {
            "goal": "Gain access",
            "root": {
                "gate": "OR",
                "label": "Gain access",
                "children": [
                    {
                        "gate": "LEAF",
                        "label": label1,
                        "action": {"kind": "tool_invocation", "tool_id": tool_id},
                    },
                    {
                        "gate": "LEAF",
                        "label": label2,
                        "action": {
                            "kind": "initial_ingress",
                            "entry_point_id": ep_id,
                            "zone": zone,
                        },
                    },
                ],
            },
        }
        return True, ""

    if "no root" in tree_case:
        _scn(world, sid)["attack_tree"] = {"goal": ""}
        return True, ""

    return False, f"Could not parse attack-tree case: {tree_case}"


def _h_scn_complexity(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: scenario "X" carries an attack complexity assessment at rule version "V" with candidate lower bound "L", final required level "F", and the reason "R" of detail "D" citing evidence "E"."""
    match = re.search(
        r'scenario "([^"]+)" carries an attack complexity assessment at rule '
        r'version "([^"]+)" with candidate lower bound "([^"]+)", final '
        r'required level "([^"]+)", and the reason "([^"]+)" of detail '
        r'"([^"]+)" citing evidence "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse complexity step: {text}"
    sid, rule_version, lower, final, reason_id, detail, evidence_ref = match.groups()
    kind, ref_id = evidence_ref.split(":", 1)
    _scn(world, sid)["attack_complexity_assessment"] = {
        "rule_version": int(rule_version),
        "candidate_lower_bound": {"required_level": lower},
        "final": {
            "required_level": final,
            "reasons": [
                {
                    "rule_id": reason_id,
                    "required_level": final,
                    "detail": detail,
                    "evidence": [{"kind": kind, "ref_id": ref_id}],
                }
            ],
        },
    }
    return True, ""


# --- Coverage / manifest / raw / pipeline call Given steps ----------------


def _h_coverage_complete(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the coverage data confirms a complete inventory with no uncovered entry points, zones, threats, or attack patterns."""
    world.trpt_coverage_data = {
        "coverage_gaps": {
            "uncovered_entry_points": [],
            "uncovered_zones": [],
            "uncovered_threats": [],
            "uncovered_attack_patterns": [],
        },
        "coverage_universe": {"completeness": "confirmed_complete"},
    }
    return True, ""


def _h_coverage_evidence(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the coverage universe records the evidence reference "E"."""
    match = re.search(
        r'the coverage universe records the evidence reference "([^"]+)"', text
    )
    if not match:
        return False, f"Could not parse coverage-evidence step: {text}"
    world.trpt_coverage_data.setdefault("coverage_universe", {}).setdefault(
        "evidence_refs", []
    ).append(match.group(1))
    return True, ""


def _h_coverage_counts(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the coverage data reports N uncovered entry points, M uncovered zone, and K uncovered threats."""
    match = re.search(
        r"the coverage data reports (\d+) uncovered entry points?, (\d+) "
        r"uncovered zones?, and (\d+) uncovered threats?$",
        text,
    )
    if not match:
        return False, f"Could not parse coverage-counts step: {text}"
    ep_count, zone_count, threat_count = (int(g) for g in match.groups())
    eps = [
        {"name": "ze-query", "entry_point_id": "ze-query"},
        *(  # coalesce-expression is overkill; build directly below
            {"name": f"ze-gap-{i}", "entry_point_id": f"ze-gap-{i}"}
            for i in range(max(ep_count - 1, 0))
        ),
    ]
    world.trpt_coverage_data = {
        "coverage_gaps": {
            "uncovered_entry_points": eps,
            "uncovered_zones": [f"zone-{i}" for i in range(zone_count)],
            "uncovered_threats": [f"T{i}" for i in range(1, threat_count + 1)],
            "uncovered_attack_patterns": [],
            "gap_attributions": {"entry_points": {}},
        },
        "coverage_universe": {"completeness": "not_applicable"},
    }
    return True, ""


def _h_coverage_no_patterns(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the coverage data records no uncovered attack patterns."""
    world.trpt_coverage_data.setdefault("coverage_gaps", {})[
        "uncovered_attack_patterns"
    ] = []
    return True, ""


def _h_coverage_attribution(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the coverage data attributes the uncovered entry point "E" to "R"."""
    match = re.search(
        r'the coverage data attributes the uncovered entry point "([^"]+)" to "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse coverage-attribution step: {text}"
    ep_id, reason = match.groups()
    gaps = world.trpt_coverage_data.setdefault("coverage_gaps", {})
    gaps.setdefault("gap_attributions", {}).setdefault("entry_points", {})[ep_id] = (
        reason
    )
    return True, ""


def _h_coverage_universe(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the coverage data records a coverage universe with N feasible targets and M excluded targets."""
    match = re.search(
        r"the coverage data records a coverage universe with (\d+) feasible "
        r"targets? and (\d+) excluded targets?",
        text,
    )
    if not match:
        return False, f"Could not parse coverage-universe step: {text}"
    feasible, excluded = (int(g) for g in match.groups())
    world.trpt_coverage_data["coverage_universe"] = {
        "completeness": "not_applicable",
        "feasible_targets": [
            {
                "name": f"ze-f{i}",
                "entry_point_id": f"ze-f{i}",
                "direction": "input",
                "controllability": "direct",
            }
            for i in range(feasible)
        ],
        "excluded_targets": [
            {
                "name": f"ze-x{i}",
                "entry_point_id": f"ze-x{i}",
                "reason": "out of scope",
            }
            for i in range(excluded)
        ],
    }
    return True, ""


def _h_manifest_funnel(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the run manifest records seeds generated N, candidates expanded M with S submitted and A accepted, G scenarios generated, and F failed."""
    match = re.search(
        r"the run manifest records seeds generated (\d+), candidates expanded "
        r"(\d+) with (\d+) submitted and (\d+) accepted, (\d+) scenarios "
        r"generated, and (\d+) failed",
        text,
    )
    if not match:
        return False, f"Could not parse manifest-funnel step: {text}"
    seeds, expanded, submitted, accepted, generated, failed = (
        int(g) for g in match.groups()
    )
    world.trpt_manifest_data.update(
        {
            "seeds_generated": seeds,
            "funnel": {
                "expanded_instances": expanded,
                "filter_submitted": submitted,
                "filter_accepted": accepted,
            },
            "scenarios_generated": generated,
            "scenarios_failed": failed,
        }
    )
    return True, ""


def _h_manifest_config(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the run manifest records model "M" with temperature T and timestamps "S" to "E"."""
    match = re.search(
        r'the run manifest records model "([^"]+)" with temperature ([0-9.]+) '
        r'and timestamps "([^"]+)" to "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse manifest-config step: {text}"
    model, temperature, start, end = match.groups()
    world.trpt_manifest_data.update(
        {
            "config": {"model": model, "temperature": float(temperature)},
            "timestamp_start": start,
            "timestamp_end": end,
        }
    )
    return True, ""


def _h_manifest_absent_values(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the run manifest records zero candidates expanded and no timestamps and no model."""
    world.trpt_manifest_data = {
        "seeds_generated": 0,
        "funnel": {},
        "scenarios_generated": 0,
        "scenarios_failed": 0,
        "config": {},
    }
    return True, ""


def _h_raw_files(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the run fixture carries raw files including a YAML file and a Gherkin file."""
    world.trpt_raw_files = {
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
    return True, ""


def _h_pipeline_call_log(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the pipeline call log contains the accepted "A" call with P prompt tokens and the rejected "R" call with Q prompt tokens."""
    match = re.search(
        r'the pipeline call log contains the accepted "([^"]+)" call with (\d+) '
        r'prompt tokens and the rejected "([^"]+)" call with (\d+) prompt tokens',
        text,
    )
    if not match:
        return False, f"Could not parse pipeline-call-log step: {text}"
    accepted_call, accepted_prompt, rejected_call, rejected_prompt = match.groups()
    world.trpt_pipeline_call_logs = [
        {
            "call": accepted_call,
            "prompt_tokens": int(accepted_prompt),
            "completion_tokens": 40,
            "duration_ms": 25,
            "semantic_evidence": {
                "stage": accepted_call,
                "accepted_draft_digest": "accepted-draft-digest",
                "attempts": [{"result": "accepted"}],
            },
        },
        {
            "call": rejected_call,
            "prompt_tokens": int(rejected_prompt),
            "completion_tokens": 20,
            "duration_ms": 15,
            "semantic_evidence": {
                "stage": rejected_call,
                "attempts": [{"result": "invalid"}],
            },
        },
    ]
    return True, ""


# ---------------------------------------------------------------------------
# Then steps
# ---------------------------------------------------------------------------


def _resolve(ok: bool, detail: str) -> tuple[bool, str]:
    return ok, detail


def _h_ts_section_with_badge(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the report contains a "Section" section with the badge ... ."""
    match = re.search(
        r'the report contains an? "([^"]+)" section with the badge (.+)$', text
    )
    if not match:
        return False, f"Could not parse section-badge step: {text}"
    section_name, badges_phrase = match.groups()
    h2 = {
        "Threat–Technique Matrix": "Threat&ndash;Technique Matrix",
    }.get(section_name, section_name)
    html = _html(world)
    if f"<h2>{h2}</h2>" not in html:
        return _resolve(False, f"section {section_name!r} is not rendered")
    for badge in re.findall(r'"([^"]+)"', badges_phrase):
        if badge not in html:
            return _resolve(False, f"badge {badge!r} is not rendered")
    return _resolve(True, "")


def _h_ts_profile_zone_chips(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the capability profile shows an active zone chip "A" and an inactive zone chip "I"."""
    from asago_scenario_generator.html_utils import escape_html as _esc

    match = re.search(
        r'the capability profile shows an active zone chip "([^"]+)" and an '
        r'inactive zone chip "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse zone-chip step: {text}"
    active, inactive = match.groups()
    region = _profile_region(world)
    active_texts = re.findall(
        r'<span class="zone-chip active"[^>]*>(.*?)</span>', region, re.S
    )
    inactive_texts = re.findall(
        r'<span class="zone-chip inactive"[^>]*>(.*?)</span>', region, re.S
    )
    ok = _esc(active) in [t.strip() for t in active_texts]
    ok = ok and _esc(inactive) in [t.strip() for t in inactive_texts]
    return _resolve(ok, f"zone chips active={active_texts} inactive={inactive_texts}")


def _h_ts_profile_flags(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the capability profile shows the flag "F1" <on|off>, the flag "F2" <on|off>, and confidence "C"."""
    match = re.search(
        r'the capability profile shows the flag "([^"]+)" (on|off), the flag '
        r'"([^"]+)" (on|off), and confidence "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse flag assertion: {text}"
    name1, state1, name2, state2, confidence = match.groups()
    region = _profile_region(world)
    flags = region[region.find("Capability Flags") :]
    chips = re.findall(
        r'<span class="flag-dot (on|off)"></span>\s*'
        r'<span class="flag-label">([^<]+)</span>',
        flags,
    )
    by_name = {name: state for state, name in chips}
    ok = by_name.get(name1) == state1 and by_name.get(name2) == state2
    ok = ok and "Confidence:" in flags and confidence.capitalize() in flags
    return _resolve(ok, f"flag chips={chips} confidence={confidence!r}")


def _h_ts_profile_entry_points(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the capability profile shows entry point "E1" with input direction and entry point "E2" with bidirectional direction."""
    match = re.search(
        r"the capability profile shows entry point \"([^\"]+)\" with input "
        r'direction and entry point "([^"]+)" with bidirectional direction',
        text,
    )
    if not match:
        return False, f"Could not parse entry-point assertion: {text}"
    ep_input, ep_bidi = match.groups()
    region = _profile_region(world)
    ok = (
        'class="ep-direction" title="input">←</span>' in region
        and ep_input in region
        and 'class="ep-direction" title="bidirectional">↔</span>' in region
        and ep_bidi in region
    )
    return _resolve(ok, f"entry points input={ep_input!r} bidirectional={ep_bidi!r}")


def _h_ts_profile_tools_integrations(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the capability profile shows tool "T" with tool id "TI" and integration "I" with integration id "II"."""
    match = re.search(
        r'the capability profile shows tool "([^"]+)" with tool id "([^"]+)" '
        r'and integration "([^"]+)" with integration id "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse tool/integration assertion: {text}"
    tool, tool_id, integration, integration_id = match.groups()
    region = _profile_region(world)
    ok = all(value in region for value in (tool, tool_id, integration, integration_id))
    return _resolve(
        ok, f"tools={tool} {tool_id} integrations={integration} {integration_id}"
    )


def _h_ts_profile_completeness(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the capability profile shows entry point completeness "C" with the evidence "E"."""
    match = re.search(
        r'the capability profile shows entry point completeness "([^"]+)" with '
        r'the evidence "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse completeness assertion: {text}"
    completeness, evidence = match.groups()
    region = _profile_region(world)
    ok = f">{completeness}</span>" in region and evidence in region
    return _resolve(ok, f"completeness={completeness} evidence={evidence}")


def _h_ts_profile_tool_completeness(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the capability profile shows tool inventory completeness "C" and the message "M"."""
    match = re.search(
        r'the capability profile shows tool inventory completeness "([^"]+)" '
        r'and the message "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse tool-completeness assertion: {text}"
    completeness, message = match.groups()
    region = _profile_region(world)
    ok = f">{completeness}</span>" in region and message in region
    return _resolve(ok, f"tool completeness={completeness} message={message}")


def _h_ts_profile_kc(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the capability profile shows the KC sub-code badge "K"."""
    match = re.search(
        r'the capability profile shows the KC sub-code badge "([^"]+)"', text
    )
    if not match:
        return False, f"Could not parse KC badge assertion: {text}"
    region = _profile_region(world)
    ok = 'class="kc-badge' in region and match.group(1) in region
    return _resolve(ok, f"kc badge={match.group(1)!r}")


def _h_ts_profile_message(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the capability profile shows the message "M"."""
    match = re.search(r'the capability profile shows the message "([^"]+)"', text)
    if not match:
        return False, f"Could not parse profile-message assertion: {text}"
    return _resolve(
        match.group(1) in _profile_region(world), f"message={match.group(1)!r}"
    )


def _h_ts_no_entry_point_row(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the capability profile renders no entry point row."""
    region = _profile_region(world)
    ok = "ep-direction" not in region and ">Entry Points</div>" not in region
    return _resolve(ok, "entry point row still rendered")


def _h_ts_entry_row_values(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the threat surface entry for "R" shows the status badge "S" and the row values ... ."""
    match = re.search(
        r'the threat surface entry for "([^"]+)" shows the status badge "([^"]+)" '
        r"and the row values \"([^\"]+)\", \"([^\"]+)\", \"([^\"]+)\", \"([^\"]+)\", and \"([^\"]+)\"",
        text,
    )
    if not match:
        return False, f"Could not parse entry-row assertion: {text}"
    risk_id, status, value1, value2, value3, value4, value5 = match.groups()
    region = _threats_region(world)
    row_start = region.find(risk_id)
    if row_start == -1:
        return _resolve(False, f"risk row {risk_id!r} is not rendered")
    row = region[row_start : region.find("</tr>", row_start)]
    badge = "status-actionable" if status == "ACT" else "status-governance"
    ok = f"status-badge {badge}" in row
    for value in (value1, value2, value3, value4, value5):
        ok = ok and f">{value}" in row
    return _resolve(
        ok,
        f"row {risk_id!r} status={status} values={value1} {value2} {value3} {value4} {value5}",
    )


def _h_ts_entry_status(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the threat surface entry for "R" shows the status badge "S"."""
    match = re.search(
        r'the threat surface entry for "([^"]+)" shows the status badge "([^"]+)"$',
        text,
    )
    if not match:
        return False, f"Could not parse entry-status assertion: {text}"
    risk_id, status = match.groups()
    region = _threats_region(world)
    row_start = region.find(risk_id)
    if row_start == -1:
        return _resolve(False, f"risk row {risk_id!r} is not rendered")
    row = region[row_start : region.find("</tr>", row_start)]
    badge = "status-actionable" if status == "ACT" else "status-governance"
    return _resolve(f"status-badge {badge}" in row, f"status={status}")


def _h_ts_governance_placeholder(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the governance-only entry shows the placeholder "-" for the OWASP LLM IDs, agentic threats, and attack patterns."""
    region = _threats_region(world)
    gov_start = region.find("status-governance")
    if gov_start == -1:
        return _resolve(False, "no governance-only row rendered")
    gov_row = region[gov_start : region.find("</tr>", gov_start)]
    return _resolve(
        gov_row.count("-") >= 3, f"governance row placeholders={gov_row.count('-')}"
    )


def _h_ts_message(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the threat surface shows the message "M"."""
    match = re.search(r'the threat surface shows the message "([^"]+)"', text)
    if not match:
        return False, f"Could not parse threat-surface message: {text}"
    return _resolve(
        match.group(1) in _threats_region(world), f"message={match.group(1)!r}"
    )


def _h_ts_outcomes_column(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the threat surface table shows the "Outcomes" column."""
    return _resolve(
        ">Outcomes</th>" in _threats_region(world), "Outcomes column missing"
    )


def _h_ts_outcomes(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the threat surface entry for "R" shows the outcomes "O" with the chip "C"."""
    match = re.search(
        r'the threat surface entry for "([^"]+)" shows the outcomes "([^"]+)" '
        r'with the chip "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse outcomes assertion: {text}"
    risk_id, outcomes, chip = match.groups()
    region = _threats_region(world)
    row_start = region.find(risk_id)
    if row_start == -1:
        return _resolve(False, f"risk row {risk_id!r} is not rendered")
    row = region[row_start : region.find("</tr>", row_start)]
    ok = f">{outcomes}" in row and chip in row
    return _resolve(ok, f"outcomes={outcomes} chip={chip}")


def _h_ts_coverage_cards(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the coverage cards "A", "B", "C", and "D" each show the status "S"."""
    match = re.search(
        r'the coverage cards "([^"]+)", "([^"]+)", "([^"]+)", and "([^"]+)" '
        r'each show the status "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse coverage-cards assertion: {text}"
    cards = match.groups()[:4]
    status = match.group(5)
    region = _section_region(_html(world), "sec-coverage")
    statuses = _coverage_card_statuses(region)
    ok = all(statuses.get(card) == status for card in cards)
    return _resolve(ok, f"card statuses={statuses}")


def _h_ts_coverage_messages(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the coverage section shows the messages "A", "B", "C", and "D"."""
    match = re.search(
        r'the coverage section shows the messages "([^"]+)", "([^"]+)", "([^"]+)", and "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse coverage-messages assertion: {text}"
    region = _section_region(_html(world), "sec-coverage")
    ok = all(message in region for message in match.groups())
    return _resolve(ok, f"messages={match.groups()}")


def _h_ts_coverage_universe(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the coverage universe card shows inventory completeness "C" with the evidence "E"."""
    match = re.search(
        r'the coverage universe card shows inventory completeness "([^"]+)" '
        r'with the evidence "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse coverage-universe assertion: {text}"
    region = _section_region(_html(world), "sec-coverage")
    ok = match.group(1) in region and match.group(2) in region
    return _resolve(ok, f"universe={match.group(1)} evidence={match.group(2)}")


def _h_ts_sidebar_link(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the sidebar shows a link to the "Section" section."""
    match = re.search(r'the sidebar shows a link to the "([^"]+)" section', text)
    if not match:
        return False, f"Could not parse sidebar-link assertion: {text}"
    href = {
        "Coverage Analysis": "#sec-coverage",
        "Run Summary": "#sec-run-summary",
        "Eval Scorecard": "#sec-scorecard",
    }.get(match.group(1))
    if href is None:
        return False, f"Unknown sidebar section {match.group(1)!r}"
    return _resolve(href in _html(world), f"sidebar link {href} missing")


def _h_ts_coverage_card_status(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the coverage card "C" shows the status "S" (single card)."""
    match = re.search(r'the coverage card "([^"]+)" shows the status "([^"]+)"$', text)
    if not match:
        return False, f"Could not parse coverage-card assertion: {text}"
    region = _section_region(_html(world), "sec-coverage")
    statuses = _coverage_card_statuses(region)
    return _resolve(
        statuses.get(match.group(1)) == match.group(2), f"statuses={statuses}"
    )


def _h_ts_coverage_card_attribution(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the coverage card "C" shows the status "S" and the uncovered entry point "E" with the attribution "A"."""
    match = re.search(
        r'the coverage card "([^"]+)" shows the status "([^"]+)" and the '
        r'uncovered entry point "([^"]+)" with the attribution "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse coverage-attribution assertion: {text}"
    card, status, entry_point, attribution = match.groups()
    region = _section_region(_html(world), "sec-coverage")
    statuses = _coverage_card_statuses(region)
    if statuses.get(card) != status:
        return _resolve(False, f"card {card} status={statuses.get(card)}")
    card_start = region.find(f">{card}</span>")
    card_body = region[card_start : card_start + 2000]
    ok = entry_point in card_body and attribution in card_body
    return _resolve(ok, f"entry point {entry_point} attribution={attribution}")


def _h_ts_coverage_cards_pair(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the coverage section shows the "A" and "B" cards."""
    match = re.search(
        r'the coverage section shows the "([^"]+)" and "([^"]+)" cards', text
    )
    if not match:
        return False, f"Could not parse coverage-card-pair assertion: {text}"
    region = _section_region(_html(world), "sec-coverage")
    ok = match.group(1) in region and match.group(2) in region
    return _resolve(ok, f"cards={match.group(1)} {match.group(2)}")


def _h_ts_matrix_cell(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the matrix shows for threat "T" a count of N for technique "A" linking to scenario "S"."""
    match = re.search(
        r'the matrix shows for threat "([^"]+)" a count of (\d+) for technique '
        r'"([^"]+)" linking to scenario "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse matrix-cell assertion: {text}"
    threat, count, technique, scenario = match.groups()
    region = _section_region(_html(world), "sec-threat-matrix")
    ok = 'class="matrix-count-link"' in region
    ok = ok and f'href="#scenario-{scenario}"' in region
    ok = ok and f">{count}</a>" in region
    ok = ok and technique in region
    return _resolve(
        ok,
        f"cell threat={threat} count={count} technique={technique} scenario={scenario}",
    )


def _h_ts_no_tech_headers(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the matrix shows no technique column headers."""
    region = _section_region(_html(world), "sec-threat-matrix")
    return _resolve(
        "matrix-col-header" not in region, "technique headers still rendered"
    )


def _h_ts_roster_row(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the roster row for "S" shows threat "T", attack pattern "P", technique "A", actor type "AT", and capability "C"."""
    match = re.search(
        r'the roster row for "([^"]+)" shows threat "([^"]+)", attack pattern '
        r'"([^"]+)", technique "([^"]+)", actor type "([^"]+)", and capability "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse roster-row assertion: {text}"
    sid, threat, pattern, technique, actor_type, capability = match.groups()
    region = _section_region(_html(world), "sec-threat-matrix")
    roster = region[region.find("Scenario Roster") :]
    row_start = roster.find(sid)
    if row_start == -1:
        return _resolve(False, f"roster row {sid!r} is not rendered")
    row = roster[row_start : roster.find("</tr>", row_start)]
    visible = _visible(row)
    ok = all(
        value in visible
        for value in (threat, pattern, technique, actor_type, capability)
    )
    return _resolve(ok, f"roster {sid} row={visible}")


def _h_ts_roster_no_technique(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the roster row for "S" shows the attack pattern "P" with no technique value."""
    match = re.search(
        r'the roster row for "([^"]+)" shows the attack pattern "([^"]+)" with '
        r"no technique value",
        text,
    )
    if not match:
        return False, f"Could not parse roster-no-technique assertion: {text}"
    sid, pattern = match.groups()
    region = _section_region(_html(world), "sec-threat-matrix")
    roster = region[region.find("Scenario Roster") :]
    row_start = roster.find(sid)
    if row_start == -1:
        return _resolve(False, f"roster row {sid!r} is not rendered")
    row = roster[row_start : roster.find("</tr>", row_start)]
    ok = pattern in row and "AML." not in row
    return _resolve(ok, f"roster {sid} technique cell not empty")


def _h_ts_diversity_type(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the distribution shows the actor type "T" with the count N and P percent."""
    match = re.search(
        r'the distribution shows the actor type "([^"]+)" with the count (\d+) '
        r"and (\d+) percent",
        text,
    )
    if not match:
        return False, f"Could not parse diversity-type assertion: {text}"
    actor_type, count, percent = match.groups()
    region = _section_region(_html(world), "sec-diversity")
    bars = re.findall(
        r'<span class="diversity-bar-label">([^<]+)</span>.*?'
        r'<div class="diversity-bar-fill"[^>]*>\s*(\d+)\s*</div>.*?'
        r'<span class="diversity-bar-count">([^<]+)</span>',
        region,
        re.S,
    )
    matched = [bar for bar in bars if bar[0] == actor_type]
    ok = bool(matched) and matched[0][1] == count and percent in matched[0][2]
    return _resolve(ok, f"diversity bars={bars}")


def _h_ts_diversity_warning(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the distribution shows the warning "W"."""
    match = re.search(r'the distribution shows the warning "([^"]+)"', text)
    if not match:
        return False, f"Could not parse diversity-warning assertion: {text}"
    region = _section_region(_html(world), "sec-diversity")
    return _resolve(match.group(1) in _visible(region), f"warning={match.group(1)!r}")


def _h_ts_diversity_goal(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the distribution shows the goal category "G" with the count N."""
    match = re.search(
        r'the distribution shows the goal category "([^"]+)" with the count (\d+)',
        text,
    )
    if not match:
        return False, f"Could not parse diversity-goal assertion: {text}"
    goal, count = match.groups()
    region = _section_region(_html(world), "sec-diversity")
    goal_region = region[region.find("Goal Category Distribution") :]
    bars = re.findall(
        r'<span class="diversity-bar-label">([^<]+)</span>.*?'
        r'<div class="diversity-bar-fill"[^>]*>\s*(\d+)\s*</div>',
        goal_region,
        re.S,
    )
    ok = (goal, count) in bars
    return _resolve(ok, f"goal bars={bars}")


def _h_ts_signals_grid(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the scenario card for "S" shows a priority signals grid."""
    match = re.search(
        r'the scenario card for "([^"]+)" shows a priority signals grid', text
    )
    if not match:
        return False, f"Could not parse signals-grid assertion: {text}"
    return _resolve(
        'class="signals-grid"' in _card_region(_html(world), match.group(1)),
        "signals grid missing",
    )


def _h_ts_signals_labels(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the priority signals grid shows the labels "L1", ..., and "L6"."""
    match = re.search(
        r'the priority signals grid shows the labels "([^"]+)", "([^"]+)", '
        r'"([^"]+)", "([^"]+)", "([^"]+)", and "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse signals-labels assertion: {text}"
    region = _section_region(_html(world), "sec-scenarios")
    ok = all(f">{label}</div>" in region for label in match.groups())
    return _resolve(ok, f"signal labels={match.groups()}")


def _h_ts_signals_values(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the priority signals grid shows the value "V1" for "L1" and "V2" for "L2"."""
    match = re.search(
        r'the priority signals grid shows the value "([^"]+)" for "([^"]+)" '
        r'and "([^"]+)" for "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse signals-values assertion: {text}"
    value1, label1, value2, label2 = match.groups()
    region = _section_region(_html(world), "sec-scenarios")
    item = re.compile(
        r'<div class="signal-label">([^<]+)</div>\s*'
        r'<div class="signal-value">([^<]+)</div>'
    )
    pairs = dict(item.findall(region))
    ok = pairs.get(label1) == value1 and pairs.get(label2) == value2
    return _resolve(ok, f"signal pairs={pairs}")


def _h_ts_no_signals_grid(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the scenario card for "S" shows no priority signals grid."""
    match = re.search(
        r'the scenario card for "([^"]+)" shows no priority signals grid', text
    )
    if not match:
        return False, f"Could not parse no-signals assertion: {text}"
    return _resolve(
        'class="signals-grid"' not in _card_region(_html(world), match.group(1)),
        "signals grid rendered unexpectedly",
    )


def _h_ts_actor_chips(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the scenario card for "S" shows the actor type chip "AT", the capability chip "C", and the goal chip "G"."""
    match = re.search(
        r'the scenario card for "([^"]+)" shows the actor type chip "([^"]+)", '
        r'the capability chip "([^"]+)", and the goal chip "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse actor-chip assertion: {text}"
    sid, actor_type, capability, goal = match.groups()
    region = _card_region(_html(world), sid)
    ok = (
        f">{actor_type}</span>" in region
        and f">{capability}</span>" in region
        and f">{goal}</span>" in region
    )
    return _resolve(ok, f"chips actor={actor_type} capability={capability} goal={goal}")


def _h_ts_actor_bdi(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the actor profile block shows the belief "B", the desire "D", the intention "I", and the resource "R"."""
    match = re.search(
        r'the actor profile block shows the belief "([^"]+)", the desire '
        r'"([^"]+)", the intention "([^"]+)", and the resource "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse actor-BDI assertion: {text}"
    values = match.groups()
    html = _html(world)
    ok = all(value in html for value in values)
    return _resolve(ok, f"BDI values={values}")


def _h_ts_actor_access(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the actor profile block shows the access provenance with ingress "I" and entry point "E"."""
    match = re.search(
        r"the actor profile block shows the access provenance with ingress "
        r'"([^"]+)" and entry point "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse actor-access assertion: {text}"
    ingress, entry_point = match.groups()
    html = _html(world)
    ok = f"Ingress: <strong>{ingress}</strong>" in html
    ok = ok and f"Entry point ID: <code>{entry_point}</code>" in html
    return _resolve(ok, f"access ingress={ingress} entry_point={entry_point}")


def _h_ts_no_actor_block(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the scenario card for "S" shows no actor profile block."""
    match = re.search(
        r'the scenario card for "([^"]+)" shows no actor profile block', text
    )
    if not match:
        return False, f"Could not parse no-actor-block assertion: {text}"
    region = _card_region(_html(world), match.group(1))
    ok = "BELIEFS:" not in region and "ACCESS PROVENANCE:" not in region
    return _resolve(ok, "actor profile block rendered unexpectedly")


def _h_ts_attack_tree_tab(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the Attack Tree tab of scenario "S" <rendering>."""
    match = re.search(r'the Attack Tree tab of scenario "([^"]+)" (.*)$', text)
    if not match:
        return False, f"Could not parse attack-tree tab assertion: {text}"
    sid, rendering = match.groups()
    region = _card_region(_html(world), sid)
    if "renders an OR gate summary" in rendering:
        ok = (
            region.count('class="tree-leaf"') == 2
            and "gate-or" in region
            and "AML.T0015" in region
            and "AML.T0040" in region
        )
    elif "renders exactly one leaf node and no gate summary" in rendering:
        ok = (
            region.count('class="tree-leaf"') == 1
            and "gate-or" not in region
            and "gate-and" not in region
        )
    else:  # renders no tree node markup
        ok = (
            region.count('class="tree-leaf"') == 0
            and "<details open" not in region
            and "gate-or" not in region
        )
    return _resolve(ok, f"attack tree rendering case: {rendering}")


def _h_ts_tree_meta(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the Attack Tree tab shows the leaf node meta "M" with code "C"."""
    match = re.search(
        r'the Attack Tree tab shows the leaf node meta "([^"]+)" with code "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse tree-meta assertion: {text}"
    meta, code = match.groups()
    html = _html(world)
    ok = meta in html and f"<code>{code}</code>" in html
    return _resolve(ok, f"tree meta={meta} code={code}")


def _h_ts_leaf_meta(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the leaf node meta shows "M" with code "C"."""
    match = re.search(r'the leaf node meta shows "([^"]+)" with code "([^"]+)"', text)
    if not match:
        return False, f"Could not parse leaf-meta assertion: {text}"
    meta, code = match.groups()
    html = _html(world)
    ok = meta in html and f"<code>{code}</code>" in html
    return _resolve(ok, f"leaf meta={meta} code={code}")


def _h_ts_dashboard_stats(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the Scenarios section shows the dashboard stats "N" In Report, "H" High Priority, "M" Medium Priority, and "L" Low Priority."""
    match = re.search(
        r'the Scenarios section shows the dashboard stats "(\d+)" In Report, '
        r'"(\d+)" High Priority, "(\d+)" Medium Priority, and "(\d+)" Low Priority',
        text,
    )
    if not match:
        return False, f"Could not parse dashboard assertion: {text}"
    expected = {
        "In Report": int(match.group(1)),
        "High Priority": int(match.group(2)),
        "Medium Priority": int(match.group(3)),
        "Low Priority": int(match.group(4)),
    }
    region = _section_region(_html(world), "sec-scenarios")
    stats = _stats(region)
    ok = all(stats.get(label) == count for label, count in expected.items())
    return _resolve(ok, f"dashboard stats={stats}")


def _h_ts_coverage_gaps_stat(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the Scenarios section shows "N" Coverage Gaps."""
    match = re.search(r'the Scenarios section shows "(\d+)" Coverage Gaps', text)
    if not match:
        return False, f"Could not parse coverage-gaps stat: {text}"
    region = _section_region(_html(world), "sec-scenarios")
    stats = _stats(region)
    return _resolve(stats.get("Coverage Gaps") == int(match.group(1)), f"stats={stats}")


def _h_ts_scenario_card_title(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the report contains a scenario card for "S" with the title "T"."""
    match = re.search(
        r'the report contains a scenario card for "([^"]+)" with the title "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse card-title assertion: {text}"
    sid, title = match.groups()
    html = _html(world)
    ok = f'id="scenario-{sid}"' in html and title in html
    return _resolve(ok, f"card {sid} title={title}")


def _h_ts_scenario_card(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the report contains a scenario card for "S"."""
    match = re.search(r'the report contains a scenario card for "([^"]+)"$', text)
    if not match:
        return False, f"Could not parse card assertion: {text}"
    return _resolve(
        f'id="scenario-{match.group(1)}"' in _html(world),
        f"scenario card {match.group(1)!r} is not rendered",
    )


def _h_ts_card_badge_score(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the card shows the priority badge "B" with the score "S"."""
    match = re.search(
        r'the card shows the priority badge "([^"]+)" with the score "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse badge-score assertion: {text}"
    badge, score = match.groups()
    region = _section_region(_html(world), "sec-scenarios")
    ok = re.search(
        rf'class="priority-badge"[^>]*>\s*{re.escape(badge)}\s*</span>', region
    )
    ok = bool(ok) and f">{score}</span>" in region
    return _resolve(ok, f"badge={badge} score={score}")


def _h_ts_nine_tabs(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the card shows all nine tab labels ... ."""
    match = re.search(r"the card shows all nine tab labels (.*)$", text)
    if not match:
        return False, f"Could not parse tab-labels assertion: {text}"
    labels = re.findall(r'"([^"]+)"', match.group(1))
    region = _section_region(_html(world), "sec-scenarios")
    ok = all(f">{label}</label>" in region for label in labels)
    return _resolve(ok, f"tab labels={labels}")


def _h_ts_no_zone_crumbs(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the card shows no zone crumbs."""
    return _resolve(
        "zone-crumb" not in _section_region(_html(world), "sec-scenarios"),
        "zone crumbs rendered",
    )


def _h_ts_no_scenarios_placeholder(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the report contains a Scenarios section showing "No scenarios generated."."""
    html = _html(world)
    ok = 'id="sec-scenarios"' in html and "No scenarios generated." in html
    return _resolve(ok, "scenarios placeholder missing")


def _h_ts_run_summary_present(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the report contains a "Run Summary" section."""
    return _resolve("<h2>Run Summary</h2>" in _html(world), "Run Summary missing")


def _h_ts_run_summary_absent(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the report contains no "Run Summary" section."""
    return _resolve("<h2>Run Summary</h2>" not in _html(world), "Run Summary rendered")


def _h_ts_sidebar_no_link(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the sidebar shows no link to the "Run Summary" section."""
    return _resolve(
        '<a href="#sec-run-summary">' not in _html(world),
        "Run Summary sidebar link rendered",
    )


def _h_ts_funnel_stats(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the funnel shows "N" <Label>, ... ."""
    match = re.search(r"the funnel shows (.*)$", text)
    if not match:
        return False, f"Could not parse funnel assertion: {text}"
    pairs = re.findall(r'"(\d+)" ([^,]+?)(?:,| and |$)', match.group(1))
    expected = {label.strip(): int(count) for count, label in pairs}
    region = _section_region(_html(world), "sec-run-summary")
    stats = _stats(region)
    ok = all(stats.get(label) == count for label, count in expected.items())
    return _resolve(ok, f"funnel stats={stats}")


def _h_ts_run_summary_stats(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the run summary shows "F" Failed, "R" Rejected, and the rejection rate "P"."""
    match = re.search(
        r'the run summary shows "(\d+)" Failed, "(\d+)" Rejected, and the '
        r'rejection rate "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse run-summary stats: {text}"
    failed, rejected, rate = match.groups()
    region = _section_region(_html(world), "sec-run-summary")
    stats = _stats(region)
    ok = stats.get("Failed") == int(failed) and stats.get("Rejected") == int(rejected)
    ok = ok and f">{rate}</span>" in region
    return _resolve(ok, f"stats={stats} rate={rate}")


def _h_ts_run_summary_duration(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the run summary shows the duration "D"."""
    match = re.search(r'the run summary shows the duration "([^"]+)"', text)
    if not match:
        return False, f"Could not parse duration assertion: {text}"
    return _resolve(
        match.group(1) in _section_region(_html(world), "sec-run-summary"),
        f"duration={match.group(1)!r}",
    )


def _h_ts_run_summary_config(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the run summary shows model "M", temperature "T", start "S", and end "E"."""
    match = re.search(
        r'the run summary shows model "([^"]+)", temperature "([^"]+)", '
        r'start "([^"]+)", and end "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse run-summary config: {text}"
    model, temperature, start, end = match.groups()
    region = _section_region(_html(world), "sec-run-summary")
    ok = f">{model}</div>" in region and f">{temperature}</div>" in region
    ok = ok and start in region and end in region
    return _resolve(ok, f"config model={model} temperature={temperature}")


def _h_ts_rerun_summary_absent_values(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the run summary shows model "unknown", temperature "N/A", start "N/A", and end "N/A"."""
    region = _section_region(_html(world), "sec-run-summary")
    ok = ">unknown</div>" in region
    ok = ok and region.count(">N/A</div>") >= 3
    return _resolve(
        ok, f"absent values region has {region.count('>N/A</div>')} N/A divs"
    )


def _h_ts_rejection_rate_na(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the run summary shows the rejection rate "N/A"."""
    return _resolve(
        ">N/A</span>" in _section_region(_html(world), "sec-run-summary"),
        "rejection rate N/A missing",
    )


def _h_ts_yaml_panel(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the YAML panel shows a highlighted comment, key "K", number value N, boolean value B, and null value."""
    match = re.search(
        r'the YAML panel shows a highlighted comment, key "([^"]+)", number '
        r"value \d+, boolean value .*, and null value",
        text,
    )
    if not match:
        return False, f"Could not parse YAML panel assertion: {text}"
    key = match.group(1)
    region = _section_region(_html(world), "sec-raw")
    ok = 'class="yaml-comment"' in region
    ok = ok and f'class="yaml-key">{key}</span>' in region
    ok = ok and 'class="yaml-number">3</span>' in region
    ok = ok and 'class="yaml-bool">true</span>' in region
    ok = ok and 'class="yaml-null">null</span>' in region
    return _resolve(ok, f"YAML panel key={key}")


def _h_ts_yaml_quoted(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the YAML panel renders the quoted string "S" without a highlight class."""
    match = re.search(
        r'the YAML panel renders the quoted string "([^"]+)" without a highlight class',
        text,
    )
    if not match:
        return False, f"Could not parse YAML quoted-string assertion: {text}"
    region = _section_region(_html(world), "sec-raw")
    ok = f"&quot;{match.group(1)}&quot;" in region
    ok = ok and "yaml-string" not in region
    return _resolve(ok, f"quoted string {match.group(1)!r}")


def _h_ts_gherkin_panel(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the Gherkin panel shows a highlighted comment, tag "T", and the keywords "Feature:" and "Given"."""
    match = re.search(
        r'the Gherkin panel shows a highlighted comment, tag "([^"]+)", and '
        r'the keywords "([^"]+)" and "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse Gherkin panel assertion: {text}"
    tag, keyword1, keyword2 = match.groups()
    region = _section_region(_html(world), "sec-raw")
    ok = 'class="gherkin-comment"' in region
    ok = ok and f'class="gherkin-tag">@{tag}</span>' in region
    ok = ok and f'class="gherkin-keyword">{keyword1}</span>' in region
    ok = ok and f'class="gherkin-keyword">{keyword2} </span>' in region
    return _resolve(ok, f"gherkin tag={tag} keywords={keyword1} {keyword2}")


def _h_ts_gen_inputs_headers(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the Generation Inputs tab of scenario "S" shows the call headers "H1" and "H2"."""
    match = re.search(
        r'the Generation Inputs tab of scenario "([^"]+)" shows the call '
        r'headers "([^"]+)" and "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse gen-inputs headers: {text}"
    sid, header1, header2 = match.groups()
    region = _card_region(_html(world), sid)
    return _resolve(
        header1 in region and header2 in region, f"headers={header1} {header2}"
    )


def _h_ts_gen_inputs_row(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the Generation Inputs tab shows the row "L" with the value "V"."""
    match = re.search(
        r'the Generation Inputs tab shows the row "([^"]+)" with the value "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse gen-inputs row: {text}"
    label, value = match.groups()
    region = _section_region(_html(world), "sec-scenarios")
    ok = f">{label}</td>" in region and value in region
    return _resolve(ok, f"row label={label} value={value}")


def _h_ts_gen_inputs_em_dash(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the Generation Inputs tab shows the row "Narrative summary" with the em dash "—"."""
    match = re.search(
        r'the Generation Inputs tab shows the row "([^"]+)" with the em dash "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse gen-inputs em-dash: {text}"
    label, dash = match.groups()
    region = _section_region(_html(world), "sec-scenarios")
    ok = f">{label}</td>" in region and f">{dash}</td>" in region
    return _resolve(ok, f"em-dash row label={label}")


def _h_ts_behavior_spec_steps(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the Behavior Spec tab of scenario "S" shows the step keywords "Given", "When", and "Then" with the texts "A", "B", and "C"."""
    match = re.search(
        r'the Behavior Spec tab of scenario "([^"]+)" shows the step keywords '
        r'"Given", "When", and "Then" with the texts "([^"]+)", "([^"]+)", and "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse behavior-spec assertion: {text}"
    sid, text1, text2, text3 = match.groups()
    region = _card_region(_html(world), sid)
    ok = (
        'class="step-keyword">Given</span>' in region
        and 'class="step-keyword">When</span>' in region
        and 'class="step-keyword">Then</span>' in region
    )
    ok = ok and f'class="step-text">{text1}</span>' in region
    ok = ok and f'class="step-text">{text2}</span>' in region
    ok = ok and f'class="step-text">{text3}</span>' in region
    return _resolve(ok, f"behavior steps texts={text1} {text2} {text3}")


def _h_ts_behavior_spec_absent(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the Behavior Spec tab of scenario "S" shows the message "M"."""
    match = re.search(
        r'the Behavior Spec tab of scenario "([^"]+)" shows the message "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse behavior-absent assertion: {text}"
    sid, message = match.groups()
    return _resolve(message in _card_region(_html(world), sid), f"message={message}")


def _h_ts_atlas_classifications(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the ATLAS Techniques tab of scenario "S" shows the heading "Scenario classifications" with the badge "B"."""
    match = re.search(
        r'the ATLAS Techniques tab of scenario "([^"]+)" shows the heading '
        r'"Scenario classifications" with the badge "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse atlas-classifications assertion: {text}"
    sid, badge = match.groups()
    region = _card_region(_html(world), sid)
    block = region[
        region.find("Scenario classifications") : region.find("Projected-step mappings")
    ]
    return _resolve(
        "Scenario classifications" in region and badge in block, f"badge={badge}"
    )


def _h_ts_atlas_none(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the ATLAS Techniques tab shows the heading "Projected-step mappings" with the placeholder "none"."""
    match = re.search(
        r'the ATLAS Techniques tab shows the heading "([^"]+)" with the '
        r'placeholder "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse atlas-none assertion: {text}"
    heading, placeholder = match.groups()
    html = _html(world)
    ok = heading in html
    ok = ok and f'class="prov-badge prov-badge-muted">{placeholder}</span>' in html
    return _resolve(ok, f"heading={heading} placeholder={placeholder}")


def _h_ts_complexity_heading(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the Actor Profile tab of scenario "S" shows the heading "ATTACK COMPLEXITY (RULE V3):"."""
    match = re.search(
        r'the Actor Profile tab of scenario "([^"]+)" shows the heading "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse complexity-heading assertion: {text}"
    sid, heading = match.groups()
    return _resolve(heading in _card_region(_html(world), sid), f"heading={heading}")


def _h_ts_complexity_levels(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the attack complexity block shows "Candidate lower bound" as "L" and "Final required level" as "F"."""
    match = re.search(
        r'the attack complexity block shows "Candidate lower bound" as '
        r'"([^"]+)" and "Final required level" as "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse complexity-levels assertion: {text}"
    lower, final = match.groups()
    region = _section_region(_html(world), "sec-scenarios")
    visible = _visible(region)
    ok = f"Candidate lower bound: {lower}" in visible
    ok = ok and f"Final required level: {final}" in visible
    return _resolve(ok, f"lower={lower} final={final}")


def _h_ts_complexity_reason(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the attack complexity block shows the reason line "R"."""
    match = re.search(
        r'the attack complexity block shows the reason line "([^"]+)"', text
    )
    if not match:
        return False, f"Could not parse complexity-reason assertion: {text}"
    region = _section_region(_html(world), "sec-scenarios")
    return _resolve(match.group(1) in _visible(region), f"reason={match.group(1)!r}")


def _h_ts_no_attack_complexity(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the Actor Profile tab of scenario "S" shows no attack complexity block."""
    match = re.search(
        r'the Actor Profile tab of scenario "([^"]+)" shows no attack complexity block',
        text,
    )
    if not match:
        return False, f"Could not parse no-complexity assertion: {text}"
    return _resolve(
        "ATTACK COMPLEXITY" not in _card_region(_html(world), match.group(1)),
        "attack complexity block rendered unexpectedly",
    )


def _h_ts_pipeline_section(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the report contains a "Pipeline LLM Calls" section."""
    return _resolve(
        "<h2>Pipeline LLM Calls</h2>" in _html(world), "pipeline calls missing"
    )


def _h_ts_pipeline_summary(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the pipeline calls summary shows "A" with "B", "C", and "D"."""
    match = re.search(
        r'the pipeline calls summary shows "([^"]+)" with "([^"]+)", "([^"]+)", and "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse pipeline summary: {text}"
    values = match.groups()
    region = _section_region(_html(world), "sec-pipeline-calls")
    ok = all(value in region for value in values)
    return _resolve(ok, f"pipeline summary={values}")


def _h_ts_pipeline_semantic_status(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the pipeline calls summary shows the semantic status "S"."""
    match = re.search(
        r'the pipeline calls summary shows the semantic status "([^"]+)"', text
    )
    if not match:
        return False, f"Could not parse semantic-status assertion: {text}"
    region = _section_region(_html(world), "sec-pipeline-calls")
    return _resolve(
        match.group(1) in _visible(region), f"semantic status={match.group(1)!r}"
    )


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def register(api: Any) -> None:
    # Shared Background/When: register under this feature's scope so the
    # same public-report vocabulary drives the section-rendering scenarios.
    api.set_feature(FEATURE_ID)
    api.register_first(
        "an offline completed taxonomy-and-risk run fixture",
        _h_background,
        source_order=6000,
    )
    api.register_first(
        "the HTML report is generated",
        _h_generate_report,
        source_order=6100,
    )
    api.set_feature(None)

    # --- Capability profile Given steps ---
    api.register(
        r'the capability profile declares active zones "([^"]+)"',
        _h_profile_zones,
        source_order=7000,
    )
    api.register(
        r"the capability profile declares active zone \"([^\"]+)\" with no tool inventory, no external integrations, and no evidence",
        _h_profile_degraded_zone,
        source_order=7001,
    )
    api.register(
        r'the capability profile declares the flag "([^"]+)" (on|off) and the flag "([^"]+)" (on|off) with confidence "([^"]+)"',
        _h_profile_flags,
        source_order=7002,
    )
    api.register(
        r'the capability profile lists entry point "([^"]+)" with direction "([^"]+)"(?: and entry point "([^"]+)" with direction "([^"]+)")?',
        _h_profile_entry_points,
        source_order=7003,
    )
    api.register(
        r'the capability profile lists the tool "([^"]+)" with tool id "([^"]+)"',
        _h_profile_tool,
        source_order=7004,
    )
    api.register(
        r'the capability profile lists the integration "([^"]+)" with integration id "([^"]+)"',
        _h_profile_integration,
        source_order=7005,
    )
    api.register(
        r'the capability profile records entry point completeness "([^"]+)" with evidence "([^"]+)"',
        _h_profile_ep_completeness,
        source_order=7006,
    )
    api.register(
        r'the capability profile records tool inventory completeness "([^"]+)" with no evidence',
        _h_profile_tool_completeness,
        source_order=7007,
    )
    api.register(
        r'the capability profile declares the KC sub-code "([^"]+)"',
        _h_profile_kc,
        source_order=7008,
    )

    # --- Threat surface Given steps ---
    api.register(
        r'the threat surface lists the actionable entry for risk card "([^"]+)"(?: with risk name "([^"]+)")?(?:, confidence ([0-9.]+))?(?:, OWASP LLM IDs "([^"]*)")?(?:,? (?:with )?agentic threats "([^"]*)")?(?:,? and attack patterns "([^"]*)")?',
        _h_ts_actionable,
        source_order=7010,
    )
    api.register(
        r'the threat surface lists the governance-only entry for risk card "([^"]+)" with risk name "([^"]+)" and no mappings',
        _h_ts_governance,
        source_order=7011,
    )
    api.register(
        r"the threat surface lists no actionable entries and no governance-only entries",
        _h_ts_empty,
        source_order=7012,
    )

    # --- Scenario Given steps ---
    api.register(
        r'the run fixture contains scenario "([^"]+)" and scenario "([^"]+)"$',
        _h_contains_many,
        source_order=7020,
    )
    api.register(
        r'the run fixture contains scenario "([^"]+)", "([^"]+)", and "([^"]+)"$',
        _h_contains_three,
        source_order=7021,
    )
    api.register(
        r'the run fixture contains scenario "([^"]+)" with only its scenario ID',
        _h_contains_minimal,
        source_order=7022,
    )
    api.register(
        r'the run fixture contains scenario "([^"]+)" with no (priority signals|actor profile|attack complexity assessment)',
        _h_contains_empty_optional,
        source_order=7023,
    )
    api.register(
        r'the run fixture contains scenario "([^"]+)" with a behavior feature file containing the steps "([^"]+)", "([^"]+)", and "([^"]+)"',
        _h_contains_feature_file,
        source_order=7024,
    )
    api.register(
        r'the run fixture contains scenario "([^"]+)" with no behavior feature file',
        _h_contains_no_feature_file,
        source_order=7025,
    )
    api.register(
        r"the run fixture contains no scenarios",
        _h_no_scenarios,
        source_order=7026,
    )
    api.register(
        r'each scenario has actor type "([^"]+)" with capability level "([^"]+)" and goal category "([^"]+)"',
        _h_each_scenario_actor_goal,
        source_order=7027,
    )
    api.register(
        r"the run fixture contains no run manifest",
        _h_no_run_manifest,
        source_order=7028,
    )
    api.register(
        r'scenario "([^"]+)" carries priority composite ([0-9.]+)$',
        _h_scn_priority,
        source_order=7030,
    )
    api.register(
        r'scenario "([^"]+)" carries priority composite ([0-9.]+) with the signals "([^"]+)", "([^"]+)", "([^"]+)", "([^"]+)", "([^"]+)", and "([^"]+)"',
        _h_scn_priority_signals,
        source_order=7031,
    )
    api.register(
        r'scenario "([^"]+)" carries priority composite ([0-9.]+) with narrative title "([^"]+)"',
        _h_scn_priority_title,
        source_order=7032,
    )
    api.register(
        r'scenario "([^"]+)" has an actor profile of type "([^"]+)" with capability "([^"]+)" and goal "([^"]+)"',
        _h_scn_actor_profile,
        source_order=7033,
    )
    api.register(
        r'scenario "([^"]+)" has actor type "([^"]+)" with capability level "([^"]+)" and goal category "([^"]+)"',
        _h_scn_actor_type_goal,
        source_order=7034,
    )
    api.register(
        r'scenario "([^"]+)" has actor type "([^"]+)" with capability level "([^"]+)"$',
        _h_scn_actor_type,
        source_order=7035,
    )
    api.register(
        r'the actor profile records the beliefs "([^"]+)", the desires "([^"]+)", the intentions "([^"]+)", and the resources "([^"]+)"',
        _h_actor_bdi,
        source_order=7036,
    )
    api.register(
        r'the actor profile records access with ingress mode "([^"]+)", initial entry point ID "([^"]+)", and influence source "([^"]+)"',
        _h_actor_access,
        source_order=7037,
    )
    api.register(
        r'scenario "([^"]+)" carries the attack pattern seed "([^"]+)" with ATLAS techniques "([^"]+)"',
        _h_scn_seed_and_techniques,
        source_order=7038,
    )
    api.register(
        r'scenario "([^"]+)" carries the attack pattern seed "([^"]+)" with no ATLAS techniques',
        _h_scn_seed_no_techniques,
        source_order=7039,
    )
    api.register(
        r'scenario "([^"]+)" pins the technique "([^"]+)" with the name "([^"]+)"',
        _h_scn_pin_technique,
        source_order=7040,
    )
    api.register(
        r'scenario "([^"]+)" carries seed metadata with the attack pattern name "([^"]+)", threat "([^"]+)" with name "([^"]+)", and the taxonomy chain ATLAS techniques "([^"]+)"',
        _h_scn_seed_metadata,
        source_order=7041,
    )
    api.register(
        r'scenario "([^"]+)" has a narrative with title "([^"]+)" and no summary',
        _h_scn_narrative,
        source_order=7042,
    )
    api.register(
        r'scenario "([^"]+)" records technique scope evidence with scenario classifications "([^"]+)" and no projected-step mappings',
        _h_scn_technique_scope,
        source_order=7043,
    )
    api.register(
        r'scenario "([^"]+)" lists ATLAS techniques "([^"]+)" in its taxonomy chain',
        _h_scn_taxonomy_chain_atlas,
        source_order=7044,
    )
    api.register(
        r'scenario "([^"]+)" carries an attack tree with .+',
        _h_scn_attack_tree,
        source_order=7045,
    )
    api.register(
        r'scenario "([^"]+)" carries an attack complexity assessment at rule version "([^"]+)" with candidate lower bound "([^"]+)", final required level "([^"]+)", and the reason "([^"]+)" of detail "([^"]+)" citing evidence "([^"]+)"',
        _h_scn_complexity,
        source_order=7046,
    )

    # --- Coverage / manifest / raw / pipeline Given steps ---
    api.register(
        r"the coverage data confirms a complete inventory with no uncovered entry points, zones, threats, or attack patterns",
        _h_coverage_complete,
        source_order=7050,
    )
    api.register(
        r'the coverage universe records the evidence reference "([^"]+)"',
        _h_coverage_evidence,
        source_order=7051,
    )
    api.register(
        r"the coverage data reports \d+ uncovered entry points?, \d+ uncovered zones?, and \d+ uncovered threats?$",
        _h_coverage_counts,
        source_order=7052,
    )
    api.register(
        r"the coverage data records no uncovered attack patterns",
        _h_coverage_no_patterns,
        source_order=7053,
    )
    api.register(
        r'the coverage data attributes the uncovered entry point "([^"]+)" to "([^"]+)"',
        _h_coverage_attribution,
        source_order=7054,
    )
    api.register(
        r"the coverage data records a coverage universe with \d+ feasible targets? and \d+ excluded targets?",
        _h_coverage_universe,
        source_order=7055,
    )
    api.register(
        r"the run manifest records seeds generated \d+, candidates expanded \d+ with \d+ submitted and \d+ accepted, \d+ scenarios generated, and \d+ failed",
        _h_manifest_funnel,
        source_order=7056,
    )
    api.register(
        r'the run manifest records model "([^"]+)" with temperature ([0-9.]+) and timestamps "([^"]+)" to "([^"]+)"',
        _h_manifest_config,
        source_order=7057,
    )
    api.register(
        r"the run manifest records zero candidates expanded and no timestamps and no model",
        _h_manifest_absent_values,
        source_order=7058,
    )
    api.register(
        r"the run fixture carries raw files including a YAML file and a Gherkin file",
        _h_raw_files,
        source_order=7059,
    )
    api.register(
        r'the pipeline call log contains the accepted "([^"]+)" call with \d+ prompt tokens and the rejected "([^"]+)" call with \d+ prompt tokens',
        _h_pipeline_call_log,
        source_order=7060,
    )

    # --- Then steps ---
    api.register(
        r'the report contains an? "([^"]+)" section with the badge .+$',
        _h_ts_section_with_badge,
        source_order=8000,
    )
    api.register(
        r'the capability profile shows an active zone chip "([^"]+)" and an inactive zone chip "([^"]+)"',
        _h_ts_profile_zone_chips,
        source_order=8001,
    )
    api.register(
        r'the capability profile shows the flag "([^"]+)" (on|off), the flag "([^"]+)" (on|off), and confidence "([^"]+)"',
        _h_ts_profile_flags,
        source_order=8002,
    )
    api.register(
        r'the capability profile shows entry point "([^"]+)" with input direction and entry point "([^"]+)" with bidirectional direction',
        _h_ts_profile_entry_points,
        source_order=8003,
    )
    api.register(
        r'the capability profile shows tool "([^"]+)" with tool id "([^"]+)" and integration "([^"]+)" with integration id "([^"]+)"',
        _h_ts_profile_tools_integrations,
        source_order=8004,
    )
    api.register(
        r'the capability profile shows entry point completeness "([^"]+)" with the evidence "([^"]+)"',
        _h_ts_profile_completeness,
        source_order=8005,
    )
    api.register(
        r'the capability profile shows tool inventory completeness "([^"]+)" and the message "([^"]+)"',
        _h_ts_profile_tool_completeness,
        source_order=8006,
    )
    api.register(
        r'the capability profile shows the KC sub-code badge "([^"]+)"',
        _h_ts_profile_kc,
        source_order=8007,
    )
    api.register(
        r'the capability profile shows the message "([^"]+)"',
        _h_ts_profile_message,
        source_order=8008,
    )
    api.register(
        r"the capability profile renders no entry point row",
        _h_ts_no_entry_point_row,
        source_order=8009,
    )
    api.register(
        r'the threat surface entry for "([^"]+)" shows the status badge "([^"]+)" and the row values .+$',
        _h_ts_entry_row_values,
        source_order=8010,
    )
    api.register(
        r'the threat surface entry for "([^"]+)" shows the status badge "([^"]+)"$',
        _h_ts_entry_status,
        source_order=8011,
    )
    api.register(
        r'the governance-only entry shows the placeholder "-" for the OWASP LLM IDs, agentic threats, and attack patterns',
        _h_ts_governance_placeholder,
        source_order=8012,
    )
    api.register(
        r'the threat surface shows the message "([^"]+)"',
        _h_ts_message,
        source_order=8013,
    )
    api.register(
        r'the threat surface table shows the "Outcomes" column',
        _h_ts_outcomes_column,
        source_order=8014,
    )
    api.register(
        r'the threat surface entry for "([^"]+)" shows the outcomes "([^"]+)" with the chip "([^"]+)"',
        _h_ts_outcomes,
        source_order=8015,
    )
    api.register(
        r'the coverage cards "([^"]+)", "([^"]+)", "([^"]+)", and "([^"]+)" each show the status "([^"]+)"',
        _h_ts_coverage_cards,
        source_order=8016,
    )
    api.register(
        r'the coverage section shows the messages "([^"]+)", "([^"]+)", "([^"]+)", and "([^"]+)"',
        _h_ts_coverage_messages,
        source_order=8017,
    )
    api.register(
        r'the coverage universe card shows inventory completeness "([^"]+)" with the evidence "([^"]+)"',
        _h_ts_coverage_universe,
        source_order=8018,
    )
    api.register(
        r'the sidebar shows a link to the "([^"]+)" section',
        _h_ts_sidebar_link,
        source_order=8019,
    )
    api.register(
        r'the coverage card "([^"]+)" shows the status "([^"]+)" and the uncovered entry point "([^"]+)" with the attribution "([^"]+)"',
        _h_ts_coverage_card_attribution,
        source_order=8020,
    )
    api.register(
        r'the coverage card "([^"]+)" shows the status "([^"]+)"$',
        _h_ts_coverage_card_status,
        source_order=8021,
    )
    api.register(
        r'the coverage section shows the "([^"]+)" and "([^"]+)" cards',
        _h_ts_coverage_cards_pair,
        source_order=8022,
    )
    api.register(
        r'the matrix shows for threat "([^"]+)" a count of (\d+) for technique "([^"]+)" linking to scenario "([^"]+)"',
        _h_ts_matrix_cell,
        source_order=8023,
    )
    api.register(
        r"the matrix shows no technique column headers",
        _h_ts_no_tech_headers,
        source_order=8024,
    )
    api.register(
        r'the roster row for "([^"]+)" shows threat "([^"]+)", attack pattern "([^"]+)", technique "([^"]+)", actor type "([^"]+)", and capability "([^"]+)"',
        _h_ts_roster_row,
        source_order=8025,
    )
    api.register(
        r'the roster row for "([^"]+)" shows the attack pattern "([^"]+)" with no technique value',
        _h_ts_roster_no_technique,
        source_order=8026,
    )
    api.register(
        r'the distribution shows the actor type "([^"]+)" with the count (\d+) and (\d+) percent',
        _h_ts_diversity_type,
        source_order=8027,
    )
    api.register(
        r'the distribution shows the warning "([^"]+)"',
        _h_ts_diversity_warning,
        source_order=8028,
    )
    api.register(
        r'the distribution shows the goal category "([^"]+)" with the count (\d+)',
        _h_ts_diversity_goal,
        source_order=8029,
    )
    api.register(
        r'the scenario card for "([^"]+)" shows a priority signals grid',
        _h_ts_signals_grid,
        source_order=8030,
    )
    api.register(
        r'the priority signals grid shows the labels "([^"]+)", "([^"]+)", "([^"]+)", "([^"]+)", "([^"]+)", and "([^"]+)"',
        _h_ts_signals_labels,
        source_order=8031,
    )
    api.register(
        r'the priority signals grid shows the value "([^"]+)" for "([^"]+)" and "([^"]+)" for "([^"]+)"',
        _h_ts_signals_values,
        source_order=8032,
    )
    api.register(
        r'the scenario card for "([^"]+)" shows no priority signals grid',
        _h_ts_no_signals_grid,
        source_order=8033,
    )
    api.register(
        r'the scenario card for "([^"]+)" shows the actor type chip "([^"]+)", the capability chip "([^"]+)", and the goal chip "([^"]+)"',
        _h_ts_actor_chips,
        source_order=8034,
    )
    api.register(
        r'the actor profile block shows the belief "([^"]+)", the desire "([^"]+)", the intention "([^"]+)", and the resource "([^"]+)"',
        _h_ts_actor_bdi,
        source_order=8035,
    )
    api.register(
        r'the actor profile block shows the access provenance with ingress "([^"]+)" and entry point "([^"]+)"',
        _h_ts_actor_access,
        source_order=8036,
    )
    api.register(
        r'the scenario card for "([^"]+)" shows no actor profile block',
        _h_ts_no_actor_block,
        source_order=8037,
    )
    api.register(
        r'the Attack Tree tab of scenario "([^"]+)" .+$',
        _h_ts_attack_tree_tab,
        source_order=8038,
    )
    api.register(
        r'the Attack Tree tab shows the leaf node meta "([^"]+)" with code "([^"]+)"',
        _h_ts_tree_meta,
        source_order=8039,
    )
    api.register(
        r'the leaf node meta shows "([^"]+)" with code "([^"]+)"',
        _h_ts_leaf_meta,
        source_order=8040,
    )
    api.register(
        r'the Scenarios section shows the dashboard stats "(\d+)" In Report, "(\d+)" High Priority, "(\d+)" Medium Priority, and "(\d+)" Low Priority',
        _h_ts_dashboard_stats,
        source_order=8041,
    )
    api.register(
        r'the Scenarios section shows "(\d+)" Coverage Gaps',
        _h_ts_coverage_gaps_stat,
        source_order=8042,
    )
    api.register(
        r'the report contains a scenario card for "([^"]+)" with the title "([^"]+)"',
        _h_ts_scenario_card_title,
        source_order=8043,
    )
    api.register(
        r'the report contains a scenario card for "([^"]+)"$',
        _h_ts_scenario_card,
        source_order=8044,
    )
    api.register(
        r'the card shows the priority badge "([^"]+)" with the score "([^"]+)"',
        _h_ts_card_badge_score,
        source_order=8045,
    )
    api.register(
        r"the card shows all nine tab labels .+",
        _h_ts_nine_tabs,
        source_order=8046,
    )
    api.register(
        r"the card shows no zone crumbs",
        _h_ts_no_zone_crumbs,
        source_order=8047,
    )
    api.register(
        r'the report contains a Scenarios section showing "No scenarios generated."',
        _h_ts_no_scenarios_placeholder,
        source_order=8048,
    )
    api.register(
        r'the report contains a "Run Summary" section',
        _h_ts_run_summary_present,
        source_order=8049,
    )
    api.register(
        r'the report contains no "Run Summary" section',
        _h_ts_run_summary_absent,
        source_order=8050,
    )
    api.register(
        r'the sidebar shows no link to the "Run Summary" section',
        _h_ts_sidebar_no_link,
        source_order=8051,
    )
    api.register(
        r"the funnel shows .+",
        _h_ts_funnel_stats,
        source_order=8052,
    )
    api.register(
        r'the run summary shows "(\d+)" Failed, "(\d+)" Rejected, and the rejection rate "([^"]+)"',
        _h_ts_run_summary_stats,
        source_order=8053,
    )
    api.register(
        r'the run summary shows the duration "([^"]+)"',
        _h_ts_run_summary_duration,
        source_order=8054,
    )
    api.register(
        r'the run summary shows model "([^"]+)", temperature "([^"]+)", start "([^"]+)", and end "([^"]+)"',
        _h_ts_run_summary_config,
        source_order=8055,
    )
    api.register(
        r'the run summary shows model "unknown", temperature "N/A", start "N/A", and end "N/A"',
        _h_ts_rerun_summary_absent_values,
        source_order=8056,
    )
    api.register(
        r'the run summary shows the rejection rate "N/A"',
        _h_ts_rejection_rate_na,
        source_order=8057,
    )
    api.register(
        r'the YAML panel shows a highlighted comment, key "([^"]+)", number value \d+, boolean value .*, and null value',
        _h_ts_yaml_panel,
        source_order=8058,
    )
    api.register(
        r'the YAML panel renders the quoted string "([^"]+)" without a highlight class',
        _h_ts_yaml_quoted,
        source_order=8059,
    )
    api.register(
        r'the Gherkin panel shows a highlighted comment, tag "([^"]+)", and the keywords "([^"]+)" and "([^"]+)"',
        _h_ts_gherkin_panel,
        source_order=8060,
    )
    api.register(
        r'the Generation Inputs tab of scenario "([^"]+)" shows the call headers "([^"]+)" and "([^"]+)"',
        _h_ts_gen_inputs_headers,
        source_order=8061,
    )
    api.register(
        r'the Generation Inputs tab shows the row "([^"]+)" with the value "([^"]+)"',
        _h_ts_gen_inputs_row,
        source_order=8062,
    )
    api.register(
        r'the Generation Inputs tab shows the row "([^"]+)" with the em dash "([^"]+)"',
        _h_ts_gen_inputs_em_dash,
        source_order=8063,
    )
    api.register(
        r'the Behavior Spec tab of scenario "([^"]+)" shows the step keywords "Given", "When", and "Then" with the texts "([^"]+)", "([^"]+)", and "([^"]+)"',
        _h_ts_behavior_spec_steps,
        source_order=8064,
    )
    api.register(
        r'the Behavior Spec tab of scenario "([^"]+)" shows the message "([^"]+)"',
        _h_ts_behavior_spec_absent,
        source_order=8065,
    )
    api.register(
        r'the ATLAS Techniques tab of scenario "([^"]+)" shows the heading "Scenario classifications" with the badge "([^"]+)"',
        _h_ts_atlas_classifications,
        source_order=8066,
    )
    api.register(
        r'the ATLAS Techniques tab shows the heading "([^"]+)" with the placeholder "([^"]+)"',
        _h_ts_atlas_none,
        source_order=8067,
    )
    api.register(
        r'the Actor Profile tab of scenario "([^"]+)" shows the heading "([^"]+)"',
        _h_ts_complexity_heading,
        source_order=8068,
    )
    api.register(
        r'the attack complexity block shows "Candidate lower bound" as "([^"]+)" and "Final required level" as "([^"]+)"',
        _h_ts_complexity_levels,
        source_order=8069,
    )
    api.register(
        r'the attack complexity block shows the reason line "([^"]+)"',
        _h_ts_complexity_reason,
        source_order=8070,
    )
    api.register(
        r'the Actor Profile tab of scenario "([^"]+)" shows no attack complexity block',
        _h_ts_no_attack_complexity,
        source_order=8071,
    )
    api.register(
        r'the report contains a "Pipeline LLM Calls" section',
        _h_ts_pipeline_section,
        source_order=8072,
    )
    api.register(
        r'the pipeline calls summary shows "([^"]+)" with "([^"]+)", "([^"]+)", and "([^"]+)"',
        _h_ts_pipeline_summary,
        source_order=8073,
    )
    api.register(
        r'the pipeline calls summary shows the semantic status "([^"]+)"',
        _h_ts_pipeline_semantic_status,
        source_order=8074,
    )


__all__ = ["FEATURE_ID", "register"]
