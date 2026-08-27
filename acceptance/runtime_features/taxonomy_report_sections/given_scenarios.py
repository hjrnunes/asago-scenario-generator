"""Given step handlers that assemble scenario fixtures."""

from __future__ import annotations

import re
from typing import Any
from runtime_world import World
from ._helpers import _resolve
from runtime_features.taxonomy_report import _split_csv, _new_scenario, _scn


def _last_scenario(world: World) -> dict[str, Any]:
    if not world.trpt_scenarios:
        raise AssertionError("the fixture contains no scenarios yet")
    return world.trpt_scenarios[-1]


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


def _h_contains_rich_feature_file(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: ... contains scenario "X" with a behavior feature file containing the tag "T", the section "Feature" titled "F", the section "Scenario" titled "S", the "And" step "A", the "Given" step "G", the "But" step "B", a continuation line "C", and the docstring "D"."""
    match = re.search(
        r'the run fixture contains scenario "([^"]+)" with a behavior feature '
        r'file containing the tag "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse rich feature-file step: {text}"
    sid, tag = match.groups()
    spec = text[match.end(2) :]  # remainder after the tag value
    world.trpt_scenarios.append(_new_scenario(sid))
    lines = [f"@{tag}"]
    for section, title in re.findall(r'the section "([^"]+)" titled "([^"]+)"', spec):
        lines.append(f"{section}: {title}")
    for keyword, step_text in re.findall(r'the "([^"]+)" step "([^"]+)"', spec):
        lines.append(f"  {keyword} {step_text}")
    continuation = re.search(r'a continuation line "([^"]+)"', spec)
    if continuation:
        lines.append(f"  {continuation.group(1)}")
    docstring = re.search(r'the docstring "([^"]+)"', spec)
    if docstring:
        lines.extend(['  """', f"  {docstring.group(1)}", '  """'])
    world.trpt_feature_files[sid] = "\n".join(lines) + "\n"
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


def _h_scn_narrative_entry_point(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: scenario "X" carries a narrative entry point "E"."""
    match = re.search(
        r'scenario "([^"]+)" carries a narrative entry point "([^"]+)"', text
    )
    if not match:
        return False, f"Could not parse narrative entry-point step: {text}"
    _scn(world, match.group(1))["narrative"]["entry_point"] = match.group(2)
    return True, ""


def _h_scn_records_call(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: scenario "X" records the call "C" with P prompt tokens, M completion tokens, duration Dms, the system prompt "S", the user prompt "U", and (success|failing with the error "E")."""
    match = re.search(
        r'scenario "([^"]+)" records the call "([^"]+)" with (\d+) prompt tokens, '
        r"(\d+) completion tokens, duration (\d+)ms, the system prompt "
        r'"([^"]+)", the user prompt "([^"]+)", (?:and )?'
        r'(success|failing with the error "([^"]+)")',
        text,
    )
    if not match:
        return False, f"Could not parse per-scenario call step: {text}"
    groups = match.groups()
    sid, call, prompt, completion, duration, system_prompt, user_prompt = groups[:7]
    outcome = groups[7]
    error = groups[8] if outcome.startswith("failing") else None
    entry: dict[str, Any] = {
        "scenario_id": sid,
        "call": call,
        "prompt_tokens": int(prompt),
        "completion_tokens": int(completion),
        "duration_ms": int(duration),
        "system_prompt": system_prompt,
        "user_prompt": user_prompt,
        "success": not outcome.startswith("failing"),
    }
    if error is not None:
        entry["error"] = error
    world.trpt_call_logs.setdefault(sid, []).append(entry)
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

    gate_match = re.search(
        r'an (AND|OR) root labeled "([^"]+)" with two leaf children carrying '
        r'the techniques "([^"]+)" and "([^"]+)"',
        tree_case,
    )
    if gate_match:
        gate, label, tech1, tech2 = gate_match.groups()
        _scn(world, sid)["attack_tree"] = {
            "goal": label,
            "root": {
                "gate": gate,
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
        r'a leaf node labeled "([^"]+)" whose action invokes tool "([^"]+)"'
        r'(?: with integration "([^"]+)")? and a leaf node labeled "([^"]+)" '
        r'whose action performs initial ingress through entry point "([^"]+)" '
        r'in zone "([^"]+)"',
        tree_case,
    )
    if action_match:
        label1, tool_id, integration_id, label2, ep_id, zone = action_match.groups()
        tool_action: dict[str, str] = {
            "kind": "tool_invocation",
            "tool_id": tool_id,
        }
        if integration_id:
            tool_action["integration_id"] = integration_id
        _scn(world, sid)["attack_tree"] = {
            "goal": "Gain access",
            "root": {
                "gate": "OR",
                "label": "Gain access",
                "children": [
                    {"gate": "LEAF", "label": label1, "action": tool_action},
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


def register(api: Any) -> None:
    # --- Scenario Given steps ---
    api.register(
        'the run fixture contains scenario "([^"]+)" and scenario "([^"]+)"$',
        _h_contains_many,
        source_order=7020,
    )
    api.register(
        'the run fixture contains scenario "([^"]+)", "([^"]+)", and "([^"]+)"$',
        _h_contains_three,
        source_order=7021,
    )
    api.register(
        'the run fixture contains scenario "([^"]+)" with only its scenario ID',
        _h_contains_minimal,
        source_order=7022,
    )
    api.register(
        'the run fixture contains scenario "([^"]+)" with no (priority signals|actor profile|attack complexity assessment)',
        _h_contains_empty_optional,
        source_order=7023,
    )
    api.register(
        'the run fixture contains scenario "([^"]+)" with a behavior feature file containing the steps "([^"]+)", "([^"]+)", and "([^"]+)"',
        _h_contains_feature_file,
        source_order=7024,
    )
    api.register(
        'the run fixture contains scenario "([^"]+)" with no behavior feature file',
        _h_contains_no_feature_file,
        source_order=7025,
    )
    api.register(
        "the run fixture contains no scenarios",
        _h_no_scenarios,
        source_order=7026,
    )
    api.register(
        'each scenario has actor type "([^"]+)" with capability level "([^"]+)" and goal category "([^"]+)"',
        _h_each_scenario_actor_goal,
        source_order=7027,
    )
    api.register(
        "the run fixture contains no run manifest",
        _h_no_run_manifest,
        source_order=7028,
    )
    api.register(
        'scenario "([^"]+)" carries priority composite ([0-9.]+)$',
        _h_scn_priority,
        source_order=7030,
    )
    api.register(
        'scenario "([^"]+)" carries priority composite ([0-9.]+) with the signals "([^"]+)", "([^"]+)", "([^"]+)", "([^"]+)", "([^"]+)", and "([^"]+)"',
        _h_scn_priority_signals,
        source_order=7031,
    )
    api.register(
        'scenario "([^"]+)" carries priority composite ([0-9.]+) with narrative title "([^"]+)"',
        _h_scn_priority_title,
        source_order=7032,
    )
    api.register(
        'scenario "([^"]+)" has an actor profile of type "([^"]+)" with capability "([^"]+)" and goal "([^"]+)"',
        _h_scn_actor_profile,
        source_order=7033,
    )
    api.register(
        'scenario "([^"]+)" has actor type "([^"]+)" with capability level "([^"]+)" and goal category "([^"]+)"',
        _h_scn_actor_type_goal,
        source_order=7034,
    )
    api.register(
        'scenario "([^"]+)" has actor type "([^"]+)" with capability level "([^"]+)"$',
        _h_scn_actor_type,
        source_order=7035,
    )
    api.register(
        'the actor profile records the beliefs "([^"]+)", the desires "([^"]+)", the intentions "([^"]+)", and the resources "([^"]+)"',
        _h_actor_bdi,
        source_order=7036,
    )
    api.register(
        'the actor profile records access with ingress mode "([^"]+)", initial entry point ID "([^"]+)", and influence source "([^"]+)"',
        _h_actor_access,
        source_order=7037,
    )
    api.register(
        'scenario "([^"]+)" carries the attack pattern seed "([^"]+)" with ATLAS techniques "([^"]+)"',
        _h_scn_seed_and_techniques,
        source_order=7038,
    )
    api.register(
        'scenario "([^"]+)" carries the attack pattern seed "([^"]+)" with no ATLAS techniques',
        _h_scn_seed_no_techniques,
        source_order=7039,
    )
    api.register(
        'scenario "([^"]+)" pins the technique "([^"]+)" with the name "([^"]+)"',
        _h_scn_pin_technique,
        source_order=7040,
    )
    api.register(
        'scenario "([^"]+)" carries seed metadata with the attack pattern name "([^"]+)", threat "([^"]+)" with name "([^"]+)", and the taxonomy chain ATLAS techniques "([^"]+)"',
        _h_scn_seed_metadata,
        source_order=7041,
    )
    api.register(
        'scenario "([^"]+)" has a narrative with title "([^"]+)" and no summary',
        _h_scn_narrative,
        source_order=7042,
    )
    api.register(
        'scenario "([^"]+)" records technique scope evidence with scenario classifications "([^"]+)" and no projected-step mappings',
        _h_scn_technique_scope,
        source_order=7043,
    )
    api.register(
        'scenario "([^"]+)" lists ATLAS techniques "([^"]+)" in its taxonomy chain',
        _h_scn_taxonomy_chain_atlas,
        source_order=7044,
    )
    api.register(
        'scenario "([^"]+)" carries an attack tree with .+',
        _h_scn_attack_tree,
        source_order=7045,
    )
    api.register(
        'scenario "([^"]+)" carries an attack complexity assessment at rule version "([^"]+)" with candidate lower bound "([^"]+)", final required level "([^"]+)", and the reason "([^"]+)" of detail "([^"]+)" citing evidence "([^"]+)"',
        _h_scn_complexity,
        source_order=7046,
    )
    api.register(
        'the run fixture contains scenario "([^"]+)" with a behavior feature file containing the tag "([^"]+)".*',
        _h_contains_rich_feature_file,
        source_order=7047,
    )
    api.register(
        'scenario "([^"]+)" records the call "([^"]+)" with \\d+ prompt tokens, \\d+ completion tokens, duration \\d+ms, the system prompt "([^"]+)", the user prompt "([^"]+)", (?:and )?(?:success|failing with the error "([^"]+)")',
        _h_scn_records_call,
        source_order=7048,
    )
    api.register(
        'scenario "([^"]+)" carries a narrative entry point "([^"]+)"',
        _h_scn_narrative_entry_point,
        source_order=7049,
    )
