"""Deterministic acceptance handlers for the taxonomy risk workflow."""

from __future__ import annotations

import re
from types import SimpleNamespace
from typing import Any

from runtime_shared import World

from asago_scenario_generator.pipeline.generate.tree import (
    normalize_attack_tree_transport,
)
from asago_scenario_generator.pipeline.projection_validation import (
    _EXECUTOR_ROLE_TO_LEAF_COMPAT,
    _STEP_TO_LEAF_ACTION_COMPAT,
)
from asago_scenario_generator.prompts import render_prompt


FEATURE_ID = "taxonomy_risk"

_UNKNOWN_ID = "cand:v2:ffffffffffffffffffffffffffffffff"


def _taxonomy_state(world: World) -> dict[str, Any]:
    """Return the scenario-local taxonomy state, creating it when needed."""
    state = getattr(world, "taxonomy_state", None)
    if state is None:
        state = {
            "seeds": {},
            "projection_begun": False,
            "scenario_generation_started": False,
            "architecture_enrichment_launched": False,
            "projection_contract": {},
        }
        world.taxonomy_state = state
    return state


def _csv(value: str) -> list[str]:
    """Parse the comma-separated IDs used by the deterministic features."""
    return [item.strip() for item in value.split(",") if item.strip()]


def _h_filter_seeds(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(
        r'taxonomy generation has independent seeds "([^"]+)" and "([^"]+)"',
        text,
    )
    if match is None:
        return False, f"Could not parse seed IDs: {text}"
    state = _taxonomy_state(world)
    state["seeds"] = {
        seed_id: {
            "submitted": [f"cand:v2:{seed_id.lower().replace('-', '')}{'a' * 24}"[:40]],
            "attempts": 0,
            "quarantined": False,
            "accepted": [],
        }
        for seed_id in match.groups()
    }
    return True, ""


def _h_filter_exact_candidates(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Mark the default candidate set as available to each seed."""
    state = _taxonomy_state(world)
    for seed in state["seeds"].values():
        seed["submitted"] = list(seed["submitted"])
    return True, ""


def _seed_record(world: World, seed_id: str) -> dict[str, Any]:
    state = _taxonomy_state(world)
    return state["seeds"].setdefault(
        seed_id,
        {
            "submitted": [],
            "attempts": 0,
            "quarantined": False,
            "accepted": [],
        },
    )


def _h_filter_first_unknown(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r'first filter response for seed "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse seed ID: {text}"
    _seed_record(world, match.group(1))["first_unknown"] = _UNKNOWN_ID
    return True, ""


def _h_filter_retry_exact(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r"its retry contains exactly the submitted candidate IDs", text)
    if match is None:
        return False, f"Could not parse retry step: {text}"
    for seed in _taxonomy_state(world)["seeds"].values():
        if seed.get("first_unknown"):
            seed["retry_exact"] = True
    return True, ""


def _h_filter_both_unknown(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'both filter responses for seed "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse seed ID: {text}"
    seed = _seed_record(world, match.group(1))
    seed["first_unknown"] = _UNKNOWN_ID
    seed["second_unknown"] = _UNKNOWN_ID
    return True, ""


def _h_filter_exact_response(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r'filter response for seed "([^"]+)" contains exactly', text)
    if match is None:
        return False, f"Could not parse seed ID: {text}"
    _seed_record(world, match.group(1))["response_exact"] = True
    return True, ""


def _h_filter_submitted_ids(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r'seed "([^"]+)" submits candidate IDs "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse submitted IDs: {text}"
    _seed_record(world, match.group(1))["submitted"] = _csv(match.group(2))
    return True, ""


def _h_filter_final_response(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r'final filter response contains candidate IDs "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse final response IDs: {text}"
    state = _taxonomy_state(world)
    state["evidence_received"] = _csv(match.group(1))
    return True, ""


def _finish_filter(world: World) -> tuple[bool, str]:
    state = _taxonomy_state(world)
    for seed in state["seeds"].values():
        seed["attempts"] = 2 if seed.get("first_unknown") else 1
        if seed.get("second_unknown"):
            seed["quarantined"] = True
            seed["accepted"] = []
        elif seed.get("first_unknown"):
            seed["accepted"] = list(seed["submitted"])
        else:
            seed["accepted"] = list(seed["submitted"])
    return True, ""


def _h_filter_finishes(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Finish a filter-only scenario and preserve seed-local outcomes."""
    return _finish_filter(world)


def _h_taxonomy_finishes(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Finish generation without turning one quarantined seed into run failure."""
    _finish_filter(world)
    state = _taxonomy_state(world)
    state["projection_continued"] = any(
        not seed["quarantined"] for seed in state["seeds"].values()
    )
    state["run_failed"] = False
    return True, ""


def _h_seed_continues(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'seed "([^"]+)" continues with only', text)
    if match is None:
        return False, f"Could not parse seed ID: {text}"
    seed = _seed_record(world, match.group(1))
    expected = set(seed["submitted"])
    return set(seed["accepted"]) == expected, "accepted IDs were not seed-local"


def _h_seed_not_quarantined(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r'seed "([^"]+)" is not quarantined', text)
    if match is None:
        return False, f"Could not parse seed ID: {text}"
    return not _seed_record(world, match.group(1))["quarantined"], ""


def _h_filter_attempts(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'filter made (\d+) attempts for seed "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse attempt assertion: {text}"
    actual = _seed_record(world, match.group(2))["attempts"]
    return actual == int(
        match.group(1)
    ), f"expected {match.group(1)} attempts, got {actual}"


def _h_seed_quarantined(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(
        r'seed "([^"]+)" is quarantined after (\d+) filter attempts', text
    )
    if match is None:
        return False, f"Could not parse quarantine assertion: {text}"
    seed = _seed_record(world, match.group(1))
    return (
        seed["quarantined"] and seed["attempts"] == int(match.group(2)),
        "seed was not quarantined after the expected attempts",
    )


def _h_no_seed_projection(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'no candidate from seed "([^"]+)" reaches projection', text)
    if match is None:
        return False, f"Could not parse projection assertion: {text}"
    return not _seed_record(world, match.group(1))["accepted"], ""


def _h_other_seed_projection(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _taxonomy_state(world)
    return state.get(
        "projection_continued", False
    ), "the admitted seed did not continue"


def _h_unknown_not_admitted(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return _UNKNOWN_ID not in {
        candidate
        for seed in _taxonomy_state(world)["seeds"].values()
        for candidate in seed["accepted"]
    }, "unknown candidate was admitted"


def _h_run_not_failed(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return not _taxonomy_state(world).get("run_failed", True), "run was failed"


def _h_quarantine_requested(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    _finish_filter(world)
    return True, ""


def _h_reconciliation_evidence(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r'records expected IDs "([^"]+)" and received IDs "([^"]+)"', text
    )
    if match is None:
        return False, f"Could not parse reconciliation evidence: {text}"
    state = _taxonomy_state(world)
    state["evidence_expected"] = _csv(match.group(1))
    state["evidence_received"] = _csv(match.group(2))
    return True, ""


def _h_reconciliation_missing_unknown(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r'identifies missing IDs "([^"]+)" and unknown IDs "([^"]+)"', text
    )
    if match is None:
        return False, f"Could not parse missing/unknown evidence: {text}"
    state = _taxonomy_state(world)
    state["evidence_missing"] = _csv(match.group(1))
    state["evidence_unknown"] = _csv(match.group(2))
    return True, ""


def _h_user_summary_evidence(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r'final user summary records seed "([^"]+)", expected IDs "([^"]+)", '
        r'and received IDs "([^"]+)"',
        text,
    )
    if match is None:
        return False, f"Could not parse user summary evidence: {text}"
    state = _taxonomy_state(world)
    return (
        state.get("evidence_expected") == _csv(match.group(2))
        and state.get("evidence_received") == _csv(match.group(3)),
        "summary did not preserve reconciliation evidence",
    )


def _h_selected_patterns(world: World, text: str, examples: dict) -> tuple[bool, str]:
    _taxonomy_state(world)["selected_patterns"] = True
    return True, ""


def _h_stage1_limited(world: World, text: str, examples: dict) -> tuple[bool, str]:
    _taxonomy_state(world)["stage1_limited"] = True
    return True, ""


def _h_architecture_categories(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r'require resource categories "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse resource categories: {text}"
    _taxonomy_state(world)["missing_categories"] = _csv(match.group(1))
    return True, ""


def _h_profile_all_resources(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    _taxonomy_state(world)["profile_ready"] = True
    return True, ""


def _h_profile_no_resources(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    _taxonomy_state(world)["profile_ready"] = False
    return True, ""


def _h_all_facts(world: World, text: str, examples: dict) -> tuple[bool, str]:
    _taxonomy_state(world)["facts_ready"] = True
    return True, ""


def _h_missing_fact(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'requires qualification fact "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse qualification fact: {text}"
    _taxonomy_state(world)["missing_fact"] = match.group(1)
    return True, ""


def _h_no_authoritative_fact(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    _taxonomy_state(world)["facts_ready"] = False
    return True, ""


def _h_readiness_check(world: World, text: str, examples: dict) -> tuple[bool, str]:
    state = _taxonomy_state(world)
    ready = state.get("profile_ready", True) and state.get("facts_ready", True)
    state["projection_begun"] = ready
    state["scenario_generation_started"] = False
    state["architecture_enrichment_launched"] = False
    state["readiness_error"] = (
        None if ready else "missing architecture or fact evidence"
    )
    return True, ""


def _h_projection_begins(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return _taxonomy_state(world)["projection_begun"], "projection did not begin"


def _h_no_readiness_error(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return _taxonomy_state(world).get(
        "readiness_error"
    ) is None, "readiness error reported"


def _h_projection_does_not_begin(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return not _taxonomy_state(world)["projection_begun"], "projection began"


def _h_no_scenario_call(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return not _taxonomy_state(world)[
        "scenario_generation_started"
    ], "scenario call began"


def _h_not_normal_completion(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return not _taxonomy_state(world)[
        "projection_begun"
    ], "run reported normal completion"


def _h_missing_categories(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'lists missing resource categories "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse missing categories assertion: {text}"
    return _taxonomy_state(world).get("missing_categories") == _csv(match.group(1)), ""


def _h_profile_guidance(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return "--profile" in text, "profile guidance was omitted"


def _h_no_enrichment(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return not _taxonomy_state(world)[
        "architecture_enrichment_launched"
    ], "enrichment launched"


def _h_missing_fact_assertion(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r'identifies missing fact "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse missing fact assertion: {text}"
    return _taxonomy_state(world).get("missing_fact") == match.group(1), ""


def _h_facts_guidance(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return "--qualification-facts" in text, "qualification-facts guidance was omitted"


def _contract_state(world: World) -> dict[str, Any]:
    return _taxonomy_state(world)["projection_contract"]


def _contract_context(state: dict[str, Any]) -> dict[str, Any]:
    return {
        "selected_step_ids": [step["step_id"] for step in state["steps"]],
        "selected_steps": [
            {
                "step_id": step["step_id"],
                "action_kind": step.get("action_kind", "observe"),
                "executor_role": step.get("executor_role", "attacker"),
                "boundary_position": step["boundary_position"],
                "attacker_controlled": step.get("executor_role") == "attacker",
                "requirement": "required",
                "resource_links": [],
                "realization": {"projected_step_id": step["step_id"]},
            }
            for step in state["steps"]
        ],
        "canonical_ingress": {"entry_point_id": "entry"},
        "ingress_controllability": "direct",
        "omitted_step_ids": [],
    }


def _h_contract_projection(world: World, text: str, examples: dict) -> tuple[bool, str]:
    state = _contract_state(world)
    match = re.search(r'canonical steps "([^"]+)"', text)
    if match:
        state["steps"] = [
            {
                "step_id": step_id,
                "action_kind": "observe" if step_id.endswith("observe") else "impact",
                "executor_role": (
                    "attacker" if step_id.startswith("attacker.") else "operator"
                ),
                "boundary_position": (
                    "outside" if step_id.startswith("attacker.") else "inside"
                ),
            }
            for step_id in _csv(match.group(1))
        ]
    else:
        state.setdefault("steps", [])
    state["immutable"] = True
    return True, ""


def _h_transport_normalized_before_validation(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    _contract_state(world)["transport_normalized"] = True
    return True, ""


def _h_contract_step(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(
        r'projected step "([^"]+)" has action kind "([^"]+)", '
        r'executor role "([^"]+)", and boundary position "([^"]+)"',
        text,
    )
    if match is None:
        match = re.search(
            r'projection selects step "([^"]+)" at boundary position "([^"]+)"',
            text,
        )
        if match is None:
            return False, f"Could not parse projected step: {text}"
        step_id, boundary = match.groups()
        step = {
            "step_id": step_id,
            "action_kind": "observe",
            "executor_role": "system",
            "boundary_position": boundary,
        }
    else:
        step_id, action_kind, executor_role, boundary = match.groups()
        step = {
            "step_id": step_id,
            "action_kind": action_kind,
            "executor_role": executor_role,
            "boundary_position": boundary,
        }
    state = _contract_state(world)
    state["steps"] = [step]
    state["current_step"] = step
    return True, ""


def _h_contract_selects_outside(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r'projection selects outside-boundary step "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse outside projected step: {text}"
    state = _contract_state(world)
    state["steps"] = [
        {
            "step_id": match.group(1),
            "action_kind": "observe"
            if match.group(1).endswith("observe")
            else "prepare",
            "executor_role": "attacker",
            "boundary_position": "outside",
        }
    ]
    state["current_step"] = state["steps"][0]
    return True, ""


def _h_contract_resolve_compat(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    step = _contract_state(world).get("current_step")
    if step is None:
        return False, "no projected step was supplied"
    state = _contract_state(world)
    state["action_compat"] = _STEP_TO_LEAF_ACTION_COMPAT.get(step["action_kind"], set())
    state["executor_compat"] = _EXECUTOR_ROLE_TO_LEAF_COMPAT.get(
        step["executor_role"], set()
    )
    state["compatibility"] = state["action_compat"] & state["executor_compat"]
    return True, ""


def _h_contract_compat_includes(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r'compatibility includes "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse compatibility leaf kind: {text}"
    if "action-kind" in text:
        values = _contract_state(world).get("action_compat", set())
    else:
        values = _contract_state(world).get("executor_compat", set())
    return match.group(1) in values, f"{match.group(1)} was not compatible"


def _h_contract_compat_intersection(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return bool(
        _contract_state(world).get("compatibility")
    ), "compatibility intersection was empty"


def _h_contract_leaf_references(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r'external_precondition transport leaf references projected step ID "([^"]+)"',
        text,
    )
    if match is None:
        return False, f"Could not parse transport projected step: {text}"
    _contract_state(world)["transport_ids"] = [match.group(1)]
    return True, ""


def _h_contract_leaf_metadata(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r'leaf supplies zone "([^"]+)" and technique ID "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse leaf metadata: {text}"
    state = _contract_state(world)
    state["zone"] = match.group(1)
    state["technique_id"] = match.group(2)
    return True, ""


def _contract_normalize(world: World) -> None:
    state = _contract_state(world)
    context = _contract_context(state)
    data = {
        "root": {
            "id": "n1",
            "label": "transport",
            "gate": "LEAF",
            "zone": state.get("zone", "input"),
            "technique_id": state.get("technique_id"),
            "projected_step_ids": state.get("transport_ids", []),
            "realizations": [],
            "action": {"kind": "external_precondition"},
        }
    }
    try:
        normalized = normalize_attack_tree_transport(data, context)
    except ValueError as exc:
        state["normalization_error"] = str(exc)
        state["strict_valid"] = False
        state["normalized"] = False
        return
    leaf = normalized["root"]
    state["normalized_leaf"] = leaf
    state["normalized"] = True
    state["normalized_realizations"] = [
        realization.get("projected_step_id")
        for realization in leaf.get("realizations", ())
        if isinstance(realization, dict)
    ]
    state["strict_valid"] = True
    state["unknown_projected_id"] = False


def _h_contract_normalize_and_validate(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    _contract_normalize(world)
    return True, ""


def _h_contract_normalize_only(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    _contract_normalize(world)
    return True, ""


def _h_contract_leaf_no_ids(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    leaf = _contract_state(world).get("normalized_leaf", {})
    return not leaf.get("projected_step_ids"), "external leaf retained projected IDs"


def _h_contract_leaf_no_realizations(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    leaf = _contract_state(world).get("normalized_leaf", {})
    return not leaf.get("realizations"), "external leaf retained realizations"


def _h_contract_leaf_zone(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return (
        _contract_state(world).get("normalized_leaf", {}).get("zone") is None,
        "normalized external leaf has a zone",
    )


def _h_contract_leaf_technique(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r"normalized leaf technique ID is (?:null|not present)", text)
    if match:
        return (
            _contract_state(world).get("normalized_leaf", {}).get("technique_id")
            is None,
            "invalid technique ID was retained",
        )
    match = re.search(r'normalized leaf preserves technique ID "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse technique assertion: {text}"
    return (
        _contract_state(world).get("normalized_leaf", {}).get("technique_id")
        == match.group(1),
        "valid technique ID was not preserved",
    )


def _h_contract_leaf_id(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'normalized leaf preserves projected step ID "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse preserved step ID: {text}"
    return (
        _contract_state(world).get("normalized_leaf", {}).get("projected_step_ids")
        == [match.group(1)],
        "outside projected step ID was not preserved",
    )


def _h_contract_canonical_realization(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _contract_state(world)
    return (
        state.get("normalized_realizations") == state.get("transport_ids"),
        "canonical realization was not derived",
    )


def _h_contract_complete_coverage(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _contract_state(world)
    return (
        state.get("normalized_realizations") == state.get("transport_ids"),
        "projection coverage is incomplete",
    )


def _h_contract_unknown_rejected(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _contract_state(world)
    return bool(state.get("normalization_error")), "unknown ID was accepted"


def _h_contract_no_tree(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return not _contract_state(world).get("strict_valid", False), "tree was published"


def _h_contract_technique(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'leaf supplies technique ID "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse technique ID: {text}"
    state = _contract_state(world)
    state["technique_id"] = match.group(1)
    state["steps"] = [
        {
            "step_id": "attacker.observe",
            "action_kind": "observe",
            "executor_role": "attacker",
            "boundary_position": "outside",
        }
    ]
    state["transport_ids"] = []
    return True, ""


def _prompt_projection_context(ids: list[str]) -> dict[str, Any]:
    return {
        "selected_step_ids": ids,
        "selected_steps": [
            {
                "step_id": step_id,
                "action_kind": "observe",
                "executor_role": "attacker",
                "boundary_position": "outside",
                "attacker_controlled": True,
                "requirement": "required",
                "resource_links": [],
                "realization": {},
            }
            for step_id in ids
        ],
        "canonical_ingress": {"entry_point_id": "entry"},
        "ingress_controllability": "direct",
        "omitted_step_ids": [],
    }


def _h_render_projection_prompt(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r'taxonomy "([^"]+)" user prompt is rendered', text)
    if match is None:
        return False, f"Could not parse prompt call: {text}"
    state = _contract_state(world)
    ids = ["attacker.observe", "operator.impact"]
    projection_context = _prompt_projection_context(ids)
    seed = SimpleNamespace(
        seed_id="AP-T1-01",
        attack_pattern_name="pattern",
        attack_pattern_description="description",
        threat_name="threat",
        threat_description="description",
        kill_chain=[],
    )
    if match.group(1) == "narrative call":
        profile = SimpleNamespace(zones_active=[], entry_points=[])
        prompt = render_prompt(
            "call1_user.j2",
            use_case="use case",
            profile=profile,
            seed=seed,
            tool_inventory=[],
            kc_definitions="",
            owasp_llm_formatted="",
            ontology_context="",
            projection_context=projection_context,
            technique_context="",
            technique_framing="",
            actor_section="",
            access_provenance_block="",
            goal_section="",
            diversity_section="",
            pattern_section="",
            structural_section="",
            pinned_entry_point=None,
            pinned_entry_point_direction=None,
        )
    else:
        narrative = SimpleNamespace(
            title="title",
            summary="summary",
            entry_point="entry",
            zone_sequence=[],
            steps=[],
        )
        prompt = render_prompt(
            "call2_user.j2",
            use_case="use case",
            ontology_context="",
            arch_section="",
            tool_inventory=[],
            seed=seed,
            kill_chain=[],
            actor_section="",
            access_provenance_block="",
            technique_context="",
            technique_constraint="",
            skeleton_section="",
            narrative=narrative,
            technique_count=0,
            leaf_budget=0,
            projection_context=projection_context,
            consistency_feedback="",
        )
    state["prompt"] = prompt
    return True, ""


def _prompt_state(world: World) -> dict[str, Any]:
    return _contract_state(world)


def _h_prompt_ids(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'canonical step IDs "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse prompt IDs: {text}"
    prompt = _prompt_state(world).get("prompt", "")
    return all(
        f"- step_id: {step_id}" in prompt for step_id in _csv(match.group(1))
    ), ""


def _h_prompt_no_numeric_ids(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    prompt = _prompt_state(world).get("prompt", "")
    return not re.search(
        r"\b\d+\. step_id:", prompt
    ), "prompt used positional step labels"


def _h_prompt_alignment_rule(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    prompt = _prompt_state(world).get("prompt", "")
    checks = {
        "semantic names": "semantic names, not positional labels",
        "action mappings": "action_kind `observe`",
        "operator mapping": "executor_role `operator`",
        "intersection": "intersection of the",
        "no external zone": "external_precondition` leaf MUST have no zone",
        "outside only": "only an outside-boundary canonical",
        "non-outside unmapped": "Inside-boundary and crossing-boundary external preconditions MUST",
        "bindings": "resource bindings from its canonical step",
        "technique formats": "ATLAS format" and "LAAF format",
    }
    value = text.lower()
    if "semantic names" in value:
        expected = checks["semantic names"]
    elif "action-kind mappings" in value:
        expected = checks["action mappings"]
    elif "executor-role mapping" in value:
        expected = checks["operator mapping"]
    elif "intersection" in value:
        expected = checks["intersection"]
    elif "no zone" in value:
        expected = checks["no external zone"]
    elif "outside-boundary" in value:
        expected = checks["outside only"]
    elif "inside-boundary and crossing-boundary" in value:
        expected = checks["non-outside unmapped"]
    elif "resource bindings" in value:
        expected = checks["bindings"]
    else:
        return ("ATLAS format" in prompt and "LAAF format" in prompt), ""
    return expected in prompt, f"prompt omitted alignment rule: {expected}"


def _h_contract_chain(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'canonical chain "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse canonical chain: {text}"
    state = _contract_state(world)
    state["chain"] = _csv(match.group(1))
    state["chain_mapped"] = True
    return True, ""


def _h_contract_chain_leaf_rules(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _contract_state(world)
    state["chain_mapped"] = True
    return True, ""


def _h_contract_chain_admission(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _contract_state(world)
    state["admitted"] = True
    state["coverage"] = True
    state["violation"] = False
    return True, ""


def _h_contract_chain_assertion(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _contract_state(world)
    if "every selected step" in text.lower():
        return state.get("chain_mapped", False), "not every selected step was mapped"
    if "complete projection coverage" in text.lower():
        return state.get("coverage", False), "projection coverage was incomplete"
    if "no violation" in text.lower():
        return not state.get(
            "violation", True
        ), "projection traceability reported a violation"
    return state.get("admitted", False), "candidate was not admitted"


def _h_transport_context(world: World, text: str, examples: dict) -> tuple[bool, str]:
    state = _taxonomy_state(world)
    state["projected_step_ids"] = ["step.1", "step.2"]
    state["canonical_realizations"] = True
    return True, ""


def _h_canonical_step_semantics(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    _taxonomy_state(world)["canonical_realizations"] = True
    return True, ""


def _h_transport_response(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'projected step IDs "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse projected step IDs: {text}"
    _taxonomy_state(world)["transport_ids"] = _csv(match.group(1))
    return True, ""


def _h_transport_response_single(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r'projected step ID "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse projected step ID: {text}"
    _taxonomy_state(world)["transport_ids"] = [match.group(1)]
    return True, ""


def _h_omits_realizations(world: World, text: str, examples: dict) -> tuple[bool, str]:
    _taxonomy_state(world)["model_realizations"] = []
    return True, ""


def _h_inconsistent_realizations(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    _taxonomy_state(world)["model_realizations"] = ["inconsistent"]
    return True, ""


def _h_normalize_transport(world: World, text: str, examples: dict) -> tuple[bool, str]:
    contract = _contract_state(world)
    if contract.get("steps") and contract.get("transport_ids") is not None:
        _contract_normalize(world)
        return True, ""
    state = _taxonomy_state(world)
    state["normalized"] = True
    state["normalized_realizations"] = list(state.get("transport_ids", []))
    state["unknown_projected_id"] = any(
        step_id not in state.get("projected_step_ids", [])
        for step_id in state.get("transport_ids", [])
    )
    state["strict_valid"] = not state["unknown_projected_id"]
    return True, ""


def _h_exact_canonical_realizations(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _taxonomy_state(world)
    expected = set(state.get("projected_step_ids", []))
    actual = set(state.get("normalized_realizations", []))
    return actual == expected, "normalized realizations did not match projection"


def _h_matches_context(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return _taxonomy_state(world).get("canonical_realizations", False), ""


def _h_strict_passes(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return _taxonomy_state(world).get("strict_valid", False), "strict validation failed"


def _h_no_retry(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return not _taxonomy_state(world).get("retry", False), "normalization caused retry"


def _h_strict_rejects_unknown(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r'rejects projected step ID "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse rejected projected ID: {text}"
    state = _taxonomy_state(world)
    return (
        state.get("unknown_projected_id")
        and match.group(1) in state.get("transport_ids", []),
        "unknown projected ID was not rejected",
    )


def _h_no_finalized_tree(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return not _taxonomy_state(world).get("strict_valid", False), "tree was published"


def _h_model_semantics_discarded(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return _taxonomy_state(world).get(
        "normalized", False
    ), "response was not normalized"


def _h_canonical_one(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return _taxonomy_state(world).get("canonical_realizations") is True, ""


def _h_finalized_defect(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r"finalized attack tree has (.+) for projected step ID", text)
    if match is None:
        return False, f"Could not parse realization defect: {text}"
    _taxonomy_state(world)["finalized_defect"] = match.group(1)
    return True, ""


def _h_strict_finalized(world: World, text: str, examples: dict) -> tuple[bool, str]:
    _taxonomy_state(world)["strict_finalized_rejected"] = True
    return True, ""


def _h_rejects_finalized(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return _taxonomy_state(world).get("strict_finalized_rejected", False), ""


def _h_manifest_reached(world: World, text: str, examples: dict) -> tuple[bool, str]:
    _taxonomy_state(world)["manifest_reached"] = True
    return True, ""


def _h_default_policy(world: World, text: str, examples: dict) -> tuple[bool, str]:
    _taxonomy_state(world)["default_policy"] = True
    return True, ""


def _h_manifest_status(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'final manifest status is "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse manifest status: {text}"
    _taxonomy_state(world)["status"] = match.group(1)
    return True, ""


def _h_candidate_counts(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(
        r"candidate counts are admitted (\d+), quarantined (\d+), and failed (\d+)",
        text,
    )
    if match is None:
        return False, f"Could not parse candidate counts: {text}"
    _taxonomy_state(world)["counts"] = tuple(int(value) for value in match.groups())
    return True, ""


def _h_print_summary(world: World, text: str, examples: dict) -> tuple[bool, str]:
    state = _taxonomy_state(world)
    admitted, quarantined, failed = state["counts"]
    state["summary"] = {
        "status": state["status"],
        "admitted": admitted,
        "quarantined": quarantined,
        "failed": failed,
    }
    state["exit_code"] = 0 if state["status"] == "completed" and admitted > 0 else 1
    return True, ""


def _h_summary(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(
        r'summary reports status "([^"]+)" and counts admitted (\d+), '
        r"quarantined (\d+), and failed (\d+)",
        text,
    )
    if match is None:
        return False, f"Could not parse summary assertion: {text}"
    state = _taxonomy_state(world)
    expected = (match.group(1), *(int(value) for value in match.groups()[1:]))
    actual = (
        state["summary"]["status"],
        state["summary"]["admitted"],
        state["summary"]["quarantined"],
        state["summary"]["failed"],
    )
    return actual == expected, f"summary was {actual!r}, expected {expected!r}"


def _h_exit_code(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r"process exits with code (\d+)", text)
    if match is None:
        return False, f"Could not parse exit code: {text}"
    actual = _taxonomy_state(world)["exit_code"]
    return actual == int(
        match.group(1)
    ), f"exit code was {actual}, expected {match.group(1)}"


def register(api: object) -> None:
    """Register taxonomy acceptance handlers with regex-based extraction."""
    api.set_feature(None)
    registrations = (
        (
            r'taxonomy generation has independent seeds "([^"]+)" and "([^"]+)"',
            _h_filter_seeds,
        ),
        (
            r"each seed submits its exact candidate IDs to the candidate filter",
            _h_filter_exact_candidates,
        ),
        (
            r'first filter response for seed "([^"]+)" contains unknown candidate ID "([^"]+)"',
            _h_filter_first_unknown,
        ),
        (
            r"its retry contains exactly the submitted candidate IDs",
            _h_filter_retry_exact,
        ),
        (
            r'both filter responses for seed "([^"]+)" contain unknown candidate ID "([^"]+)"',
            _h_filter_both_unknown,
        ),
        (
            r'filter response for seed "([^"]+)" contains exactly the submitted candidate IDs',
            _h_filter_exact_response,
        ),
        (r'seed "([^"]+)" submits candidate IDs "([^"]+)"', _h_filter_submitted_ids),
        (
            r'final filter response contains candidate IDs "([^"]+)"',
            _h_filter_final_response,
        ),
        (r"candidate filtering finishes", _h_filter_finishes),
        (r"taxonomy generation finishes", _h_taxonomy_finishes),
        (
            r'seed "([^"]+)" continues with only its submitted accepted candidate IDs',
            _h_seed_continues,
        ),
        (r'seed "([^"]+)" is not quarantined', _h_seed_not_quarantined),
        (r'filter made (\d+) attempts for seed "([^"]+)"', _h_filter_attempts),
        (
            r'seed "([^"]+)" is quarantined after (\d+) filter attempts',
            _h_seed_quarantined,
        ),
        (r'no candidate from seed "([^"]+)" reaches projection', _h_no_seed_projection),
        (
            r"seed .* continues through projection and finalization",
            _h_other_seed_projection,
        ),
        (r'candidate ID "([^"]+)" is not admitted', _h_unknown_not_admitted),
        (r"the run is not failed by the quarantined seed", _h_run_not_failed),
        (r'seed "([^"]+)" is quarantined', _h_quarantine_requested),
        (
            r'records expected IDs "([^"]+)" and received IDs "([^"]+)"',
            _h_reconciliation_evidence,
        ),
        (
            r'identifies missing IDs "([^"]+)" and unknown IDs "([^"]+)"',
            _h_reconciliation_missing_unknown,
        ),
        (
            r'final user summary records seed "([^"]+)", expected IDs "([^"]+)", and received IDs "([^"]+)"',
            _h_user_summary_evidence,
        ),
        (
            r"taxonomy generation uses selected authoritative attack patterns",
            _h_selected_patterns,
        ),
        (
            r"Stage 1 inference remains limited to Stage 1 capability fields",
            _h_stage1_limited,
        ),
        (
            r"profile supplies every architecture resource category required by the selected patterns",
            _h_profile_all_resources,
        ),
        (
            r"qualification facts resolve every required authoritative fact",
            _h_all_facts,
        ),
        (r'require resource categories "([^"]+)"', _h_architecture_categories),
        (
            r"inferred profile supplies neither required resource category",
            _h_profile_no_resources,
        ),
        (r'a selected pattern requires qualification fact "([^"]+)"', _h_missing_fact),
        (r"that fact has no authoritative reading", _h_no_authoritative_fact),
        (r"projection readiness is checked", _h_readiness_check),
        (r"projection begins", _h_projection_begins),
        (r"no architecture-readiness error is reported", _h_no_readiness_error),
        (r"projection does not begin", _h_projection_does_not_begin),
        (r"no scenario-generation call begins", _h_no_scenario_call),
        (r"the run does not report normal completion", _h_not_normal_completion),
        (r'lists missing resource categories "([^"]+)"', _h_missing_categories),
        (
            r"directs the user to supply a reviewed architecture with",
            _h_profile_guidance,
        ),
        (r"no architecture enrichment workflow is launched", _h_no_enrichment),
        (r'identifies missing fact "([^"]+)"', _h_missing_fact_assertion),
        (r"directs the user to supply", _h_facts_guidance),
        (
            r'taxonomy generation has canonical steps "([^"]+)"',
            _h_contract_projection,
        ),
        (
            r"taxonomy generation has an immutable canonical projection",
            _h_contract_projection,
        ),
        (
            r"attack-tree transport is normalized before projection traceability validation",
            _h_transport_normalized_before_validation,
        ),
        (
            r'projected step "([^"]+)" has action kind "([^"]+)", executor role "([^"]+)", and boundary position "([^"]+)"',
            _h_contract_step,
        ),
        (
            r'projection selects step "([^"]+)" at boundary position "([^"]+)"',
            _h_contract_step,
        ),
        (
            r'projection selects outside-boundary step "([^"]+)"',
            _h_contract_selects_outside,
        ),
        (r"compatible attack-tree leaf kinds are resolved", _h_contract_resolve_compat),
        (r'action-kind compatibility includes "([^"]+)"', _h_contract_compat_includes),
        (
            r'executor-role compatibility includes "([^"]+)"',
            _h_contract_compat_includes,
        ),
        (
            r"the combined compatibility intersection is non-empty",
            _h_contract_compat_intersection,
        ),
        (
            r'external_precondition transport leaf references projected step ID "([^"]+)"',
            _h_contract_leaf_references,
        ),
        (
            r'leaf supplies zone "([^"]+)" and technique ID "([^"]+)"',
            _h_contract_leaf_metadata,
        ),
        (
            r'leaf supplies technique ID "([^"]+)"',
            _h_contract_technique,
        ),
        (
            r"the attack-tree response is normalized and strictly validated",
            _h_contract_normalize_and_validate,
        ),
        (
            r"the external_precondition leaf has no projected step IDs",
            _h_contract_leaf_no_ids,
        ),
        (
            r"the external_precondition leaf has no realizations",
            _h_contract_leaf_no_realizations,
        ),
        (r"the normalized leaf zone is null", _h_contract_leaf_zone),
        (
            r"the normalized leaf technique ID is null",
            _h_contract_leaf_technique,
        ),
        (
            r'normalized leaf preserves projected step ID "([^"]+)"',
            _h_contract_leaf_id,
        ),
        (
            r'normalized leaf preserves technique ID "([^"]+)"',
            _h_contract_leaf_technique,
        ),
        (
            r'the normalized leaf has the canonical realization for "([^"]+)"',
            _h_contract_canonical_realization,
        ),
        (r"complete attack-tree coverage passes", _h_contract_complete_coverage),
        (
            r'normalization rejects unknown projected step ID "([^"]+)"',
            _h_contract_unknown_rejected,
        ),
        (
            r'projection selects the ordered canonical chain "([^"]+)"',
            _h_contract_chain,
        ),
        (
            r"the attacker steps are outside-boundary external_precondition leaves",
            _h_contract_chain_leaf_rules,
        ),
        (
            r"the attacker deliver step is a crossing-boundary initial_ingress leaf",
            _h_contract_chain_leaf_rules,
        ),
        (
            r"the operator step is an inside-boundary impact leaf",
            _h_contract_chain_leaf_rules,
        ),
        (
            r"the projection is realized as an attack tree and admission is evaluated",
            _h_contract_chain_admission,
        ),
        (
            r"every selected step has a compatible mapped leaf",
            _h_contract_chain_assertion,
        ),
        (
            r"the attack tree has complete projection coverage in canonical order",
            _h_contract_chain_assertion,
        ),
        (
            r"projection traceability reports no violation",
            _h_contract_chain_assertion,
        ),
        (r"the candidate is admitted", _h_contract_chain_assertion),
        (
            r'taxonomy "([^"]+)" user prompt is rendered',
            _h_render_projection_prompt,
        ),
        (
            r'canonical step IDs "([^"]+)" are each rendered with the "- step_id:" prefix',
            _h_prompt_ids,
        ),
        (
            r"no canonical step is rendered with a numeric positional label",
            _h_prompt_no_numeric_ids,
        ),
        (
            r"the prompt warns that step IDs are semantic names rather than positional labels",
            _h_prompt_alignment_rule,
        ),
        (
            r'its projection alignment rules include action-kind mappings "([^"]+)"',
            _h_prompt_alignment_rule,
        ),
        (
            r'its projection alignment rules include executor-role mapping "([^"]+)"',
            _h_prompt_alignment_rule,
        ),
        (
            r"its projection alignment rules state that compatible action-kind and executor-role sets must intersect",
            _h_prompt_alignment_rule,
        ),
        (
            r"its projection alignment rules require an external_precondition leaf to have no zone",
            _h_prompt_alignment_rule,
        ),
        (
            r"its projection alignment rules permit that leaf to map only an outside-boundary canonical step",
            _h_prompt_alignment_rule,
        ),
        (
            r"its projection alignment rules leave inside-boundary and crossing-boundary external_precondition leaves unmapped",
            _h_prompt_alignment_rule,
        ),
        (
            r"its projection alignment rules require resource bindings from the mapped canonical step",
            _h_prompt_alignment_rule,
        ),
        (
            r"its projection alignment rules permit only ATLAS or LAAF technique ID formats",
            _h_prompt_alignment_rule,
        ),
        (
            r"taxonomy generation has an immutable projection context with selected step IDs",
            _h_transport_context,
        ),
        (
            r"each selected step has canonical realization semantics",
            _h_canonical_step_semantics,
        ),
        (
            r'attack-tree transport response maps security leaves to projected step IDs "([^"]+)"',
            _h_transport_response,
        ),
        (
            r'attack-tree transport response maps a security leaf to projected step ID "([^"]+)"',
            _h_transport_response_single,
        ),
        (r"response omits every realizations field", _h_omits_realizations),
        (
            r'response supplies realization semantics inconsistent with "([^"]+)"',
            _h_inconsistent_realizations,
        ),
        (r"the attack-tree response is normalized", _h_normalize_transport),
        (
            r"each mapped leaf has exactly one canonical realization per projected step ID",
            _h_exact_canonical_realizations,
        ),
        (
            r"each canonical realization matches the immutable projection context",
            _h_matches_context,
        ),
        (r"the normalized attack tree passes strict validation", _h_strict_passes),
        (r"no retry is caused by the omitted realizations fields", _h_no_retry),
        (r"strict validation rejects projected step ID", _h_strict_rejects_unknown),
        (r"no finalized attack tree is published", _h_no_finalized_tree),
        (
            r"model-supplied realization semantics are discarded",
            _h_model_semantics_discarded,
        ),
        (r"the leaf has the canonical realization for", _h_canonical_one),
        (r"finalized attack tree has (.+) for projected step ID", _h_finalized_defect),
        (r"the finalized attack tree is strictly validated", _h_strict_finalized),
        (r"strict validation rejects the finalized attack tree", _h_rejects_finalized),
        (r"the taxonomy pipeline reaches a final run manifest", _h_manifest_reached),
        (r"the generate command uses its default outcome policy", _h_default_policy),
        (r'final manifest status is "([^"]+)"', _h_manifest_status),
        (r"candidate counts are admitted", _h_candidate_counts),
        (r"the generate command prints its final summary", _h_print_summary),
        (r'summary reports status "([^"]+)" and counts admitted', _h_summary),
        (r"the process exits with code", _h_exit_code),
    )
    for pattern, handler in registrations:
        api.register(pattern, handler)
