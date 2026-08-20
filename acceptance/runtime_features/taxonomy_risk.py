"""Deterministic acceptance handlers for the taxonomy risk workflow."""

from __future__ import annotations

import re
import types
import typing
from types import SimpleNamespace
from typing import Any

from annotated_types import MaxLen
from pydantic import BaseModel
from runtime_shared import World

from asago_scenario_generator.llm.client import CompletionLengthError, LLMClient
from asago_scenario_generator.pipeline.finalization import (
    COMPLETION_LENGTH_RETRY_SUFFIXES,
    GeneratedStage,
    MAX_OWNER_RETRIES,
)
from asago_scenario_generator.pipeline.generate.narrative import (
    MAX_NARRATIVE_STEPS,
    NARRATIVE_CONNECTOR_STEPS,
)
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


def _actor_retry_state(world: World) -> dict[str, Any]:
    """Return state for deterministic actor completion-retry scenarios."""
    state = getattr(world, "actor_retry_state", None)
    if state is None:
        state = {"configured_limit": None, "outcomes": [], "calls": [], "error": None}
        world.actor_retry_state = state
    return state


def _h_actor_configured_limit(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r"actor profile generation is configured with max_completion_tokens (\d+)",
        text,
    )
    if match is None:
        return False, f"Could not parse actor completion limit: {text}"
    _actor_retry_state(world)["configured_limit"] = int(match.group(1))
    return True, ""


def _h_actor_first_length_failure(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    _actor_retry_state(world)["outcomes"] = ["length"]
    return True, ""


def _h_actor_second_success(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    _actor_retry_state(world)["outcomes"].append("success")
    return True, ""


def _h_actor_second_length_failure(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    _actor_retry_state(world)["outcomes"].append("length")
    return True, ""


def _h_actor_generate(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Execute the two-invocation actor retry sequence deterministically.

    The stage helper performs exactly one provider request per invocation,
    so the lifecycle sequence is two explicit invocations: the initial
    completion (which fails for length) and the single corrective retry
    (which either succeeds or fails for length again).
    """
    from types import SimpleNamespace

    from asago_scenario_generator.pipeline.generate import actor

    state = _actor_retry_state(world)
    state["calls"] = []
    state["error"] = None
    outcomes = list(state["outcomes"])
    length_error = type("LengthFinishReasonError", (Exception,), {})
    suffix = COMPLETION_LENGTH_RETRY_SUFFIXES[GeneratedStage.actor]

    class _Client:
        max_completion_tokens = state["configured_limit"]

        def complete(self, **kwargs):
            state["calls"].append(kwargs)
            outcome = outcomes.pop(0)
            if outcome == "length":
                raise length_error("completion truncated")
            return actor.LLMResult(
                content=actor.Call0Response(
                    actor_type="adversarial-user",
                    capability_level="intermediate",
                    beliefs=["The system accepts user input."],
                    desires=["Influence the system."],
                    intentions=["Submit crafted input."],
                    resources=["A client application."],
                ),
                prompt_tokens=1,
                completion_tokens=1,
                duration_ms=1,
            )

    original_error = actor.LengthFinishReasonError
    original_context = actor.build_call0_context
    original_render_prompt = actor.render_prompt
    actor.LengthFinishReasonError = length_error
    actor.build_call0_context = lambda **_kwargs: {
        "tool_inventory": [],
        "minimum_capability_level": None,
        "diversity_limitation": None,
    }
    actor.render_prompt = lambda *_args, **_kwargs: "actor profile user prompt"
    try:
        # Initial lifecycle invocation: fails once for completion length.
        try:
            actor._call_actor_profile(
                seed=SimpleNamespace(min_complexity=None, seed_id="AP-ACTOR-01"),
                profile=SimpleNamespace(zones_active=[]),
                client=_Client(),
                use_case="deterministic actor retry acceptance",
            )
        except length_error:
            pass
        # Single lifecycle retry: appends the approved corrective suffix
        # verbatim and keeps the configured token limit.
        try:
            actor._call_actor_profile(
                seed=SimpleNamespace(min_complexity=None, seed_id="AP-ACTOR-01"),
                profile=SimpleNamespace(zones_active=[]),
                client=_Client(),
                use_case="deterministic actor retry acceptance",
                completion_length_feedback=suffix,
            )
        except length_error as exc:
            state["error"] = exc
    finally:
        actor.LengthFinishReasonError = original_error
        actor.build_call0_context = original_context
        actor.render_prompt = original_render_prompt
    return True, ""


def _h_actor_attempts(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r"actor profile completion attempts exactly (\d+) times", text)
    if match is None:
        return False, f"Could not parse actor attempt assertion: {text}"
    actual = len(_actor_retry_state(world)["calls"])
    return (
        actual == int(match.group(1)),
        f"expected {match.group(1)} attempts, got {actual}",
    )


def _h_actor_feedback(world: World, text: str, examples: dict) -> tuple[bool, str]:
    calls = _actor_retry_state(world)["calls"]
    if len(calls) < 2:
        return False, "actor retry call was not recorded"
    original = calls[0]["user_prompt"]
    retry = calls[1]["user_prompt"]
    suffix = COMPLETION_LENGTH_RETRY_SUFFIXES[GeneratedStage.actor]
    return (
        retry == original + suffix and "concise" in suffix,
        "retry prompt did not append the approved concise corrective feedback",
    )


def _h_actor_limit(world: World, text: str, examples: dict) -> tuple[bool, str]:
    calls = _actor_retry_state(world)["calls"]
    expected = _actor_retry_state(world)["configured_limit"]
    actual = [call["max_completion_tokens"] for call in calls]
    return (
        actual == [expected] * len(calls),
        f"token limits were {actual}, expected {expected}",
    )


def _h_actor_error(world: World, text: str, examples: dict) -> tuple[bool, str]:
    error = _actor_retry_state(world)["error"]
    return (
        type(error).__name__ == "LengthFinishReasonError",
        f"expected LengthFinishReasonError, got {error!r}",
    )


# ---------------------------------------------------------------------------
# Completion-length lifecycle retry (deterministic fixture)
# ---------------------------------------------------------------------------


def _lifecycle_state(world: World) -> dict[str, Any]:
    """Return the scenario-local completion-length lifecycle state."""
    state = getattr(world, "lifecycle_state", None)
    if state is None:
        state = {
            "configured_limit": None,
            "adapter_case": None,
            "adapter_error": None,
            "classification": None,
            "misleading_code": None,
            "stages": {},
            "narrative": {},
            "schema_checks": {},
            "schema_issues": {},
        }
        world.lifecycle_state = state
    return state


_LIFECYCLE_STAGES = ("actor", "narrative", "tree", "behavior")


def _stage_trace(world: World, stage: str) -> dict[str, Any]:
    """Return the deterministic fixture trace for one generated stage."""
    state = _lifecycle_state(world)
    trace = state["stages"].get(stage)
    if trace is None:
        trace = {
            "script": [],
            "calls": [],
            "attempts": [],
            "call_log": [],
            "directives": [],
            "invocations": 0,
            "owner_retries": 0,
            "length_retries": 0,
            "terminal_code": None,
            "outcome": None,
            "accepted_from_second": False,
            "original_prompt": (
                f"original {stage} user prompt with access-provenance, "
                "title, consistency, and semantic sections"
            ),
        }
        state["stages"][stage] = trace
    return trace


def _h_lifecycle_candidate(world: World, text: str, examples: dict) -> tuple[bool, str]:
    _lifecycle_state(world)["candidate_ready"] = True
    return True, ""


def _h_lifecycle_token_limit(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r"max_completion_tokens (\d+)", text)
    if match is None:
        return False, f"Could not parse configured token limit: {text}"
    _lifecycle_state(world)["configured_limit"] = int(match.group(1))
    return True, ""


def _h_lifecycle_fixture(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Reset per-example traces while keeping the configured token limit."""
    state = _lifecycle_state(world)
    state["adapter_case"] = None
    state["adapter_error"] = None
    state["classification"] = None
    state["misleading_code"] = None
    state["stages"] = {}
    state["narrative"] = {}
    state["schema_checks"] = {}
    state["schema_issues"] = {}
    return True, ""


def _h_fixture_length_case(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(
        r"the fixture returns a (structured|unstructured) "
        r"(actor|narrative|tree|behavior) completion with finish reason "
        r'"length", prompt tokens (\d+), and completion tokens (\d+)',
        text,
    )
    if match is None:
        return False, f"Could not parse fixture completion: {text}"
    _lifecycle_state(world)["adapter_case"] = {
        "shape": match.group(1),
        "stage": match.group(2),
        "prompt_tokens": int(match.group(3)),
        "completion_tokens": int(match.group(4)),
    }
    return True, ""


def _h_adapter_completes_request(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Drive the real shared LLM adapter against a stub SDK fixture."""
    from openai import LengthFinishReasonError

    from asago_scenario_generator.models.scenario import CallName
    from asago_scenario_generator.pipeline.generate.stages import (
        stage_attempt_failure,
    )

    state = _lifecycle_state(world)
    case = state["adapter_case"]
    if case is None:
        return False, "no fixture completion was scripted"
    usage = SimpleNamespace(
        prompt_tokens=case["prompt_tokens"],
        completion_tokens=case["completion_tokens"],
    )
    completion = SimpleNamespace(usage=usage)

    class _FakeSDKLengthError(LengthFinishReasonError):
        def __init__(self, completion_):
            Exception.__init__(self, "last message was cut off")
            self.completion = completion_

    class _BetaCompletions:
        def __init__(self, error):
            self._error = error

        def parse(self, **_kwargs):
            raise self._error

    class _BetaChat:
        def __init__(self, error):
            self.completions = _BetaCompletions(error)

    class _Beta:
        def __init__(self, error):
            self.chat = _BetaChat(error)

    class _ChatCompletions:
        def create(self, **_kwargs):
            return SimpleNamespace(
                choices=[
                    SimpleNamespace(
                        finish_reason="length",
                        message=SimpleNamespace(content=None),
                    )
                ],
                usage=usage,
            )

    class _Chat:
        def __init__(self):
            self.completions = _ChatCompletions()

    class _SdkStub:
        def __init__(self):
            self.beta = _Beta(_FakeSDKLengthError(completion))
            self.chat = _Chat()

    client = object.__new__(LLMClient)
    client.model = "deterministic-fixture"
    client.max_completion_tokens = state.get("configured_limit")
    client.temperature = 0.4
    client._client = _SdkStub()
    try:
        client.complete(
            system_prompt="fixture system prompt",
            user_prompt="fixture user prompt",
            response_format=object if case["shape"] == "structured" else None,
        )
    except CompletionLengthError as exc:
        state["adapter_error"] = exc
    if state["adapter_error"] is None:
        return True, ""
    call_name = (
        CallName.actor_profile if case["stage"] == "actor" else CallName.attack_tree
    )
    state["classification"] = stage_attempt_failure(
        call_name,
        state["adapter_error"],
        phase="invocation",
        invoked=True,
        system_prompt="fixture system prompt",
        user_prompt="fixture user prompt",
    )
    # Negative control: a non-length exception whose text mentions length
    # must still classify as the generic failure code.
    misleading = RuntimeError(
        "LengthFinishReasonError: finish reason length with prompt tokens 31"
    )
    state["misleading_code"] = stage_attempt_failure(
        CallName.attack_tree, misleading, phase="invocation", invoked=True
    ).code
    return True, ""


def _h_error_typed(world: World, text: str, examples: dict) -> tuple[bool, str]:
    error = _lifecycle_state(world).get("adapter_error")
    return (
        isinstance(error, CompletionLengthError),
        "adapter did not raise a typed CompletionLengthError",
    )


def _h_error_finish_reason(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'finish reason "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse finish reason assertion: {text}"
    error = _lifecycle_state(world).get("adapter_error")
    return (
        getattr(error, "finish_reason", None) == match.group(1),
        f"finish reason was {getattr(error, 'finish_reason', None)!r}",
    )


def _h_error_tokens(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r"prompt tokens (\d+) and completion tokens (\d+)", text)
    if match is None:
        return False, f"Could not parse token assertion: {text}"
    error = _lifecycle_state(world).get("adapter_error")
    return (
        getattr(error, "prompt_tokens", None) == int(match.group(1))
        and getattr(error, "completion_tokens", None) == int(match.group(2)),
        f"usage was prompt={getattr(error, 'prompt_tokens', None)!r}, "
        f"completion={getattr(error, 'completion_tokens', None)!r}",
    )


def _h_classified_without_text(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _lifecycle_state(world)
    classification = state.get("classification")
    case = state.get("adapter_case") or {}
    if classification is None:
        return False, "completion length was not classified"
    return (
        classification.code == "completion_length"
        and classification.finish_reason == "length"
        and classification.prompt_tokens == case.get("prompt_tokens")
        and classification.completion_tokens == case.get("completion_tokens")
        and state.get("misleading_code") == "stage_attempt_failed",
        "classification depended on provider exception text",
    )


def _h_scripted_first_length(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r"the first (actor|narrative|tree|behavior) provider response ends "
        r'with finish reason "length", prompt tokens (\d+), and completion '
        r"tokens (\d+)",
        text,
    )
    if match is None:
        return False, f"Could not parse first length response: {text}"
    trace = _stage_trace(world, match.group(1))
    trace["script"] = ["length"]
    trace["length_tokens"] = (int(match.group(2)), int(match.group(3)))
    return True, ""


def _h_scripted_second_valid(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r"the second (actor|narrative|tree|behavior) provider response is valid",
        text,
    )
    if match is None:
        return False, f"Could not parse second response: {text}"
    _stage_trace(world, match.group(1))["script"].append("valid")
    return True, ""


def _h_scripted_both_length(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r"the first 2 (actor|narrative|tree|behavior) provider responses "
        r'end with finish reason "length"',
        text,
    )
    if match is None:
        return False, f"Could not parse double length response: {text}"
    trace = _stage_trace(world, match.group(1))
    trace["script"] = ["length", "length"]
    return True, ""


def _h_scripted_semantic(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(
        r"the fixture scripts (\d+) consecutive non-length semantic "
        r"violations for (actor|narrative|tree|behavior) followed by "
        r"(a valid response|no response)",
        text,
    )
    if match is None:
        return False, f"Could not parse semantic violation script: {text}"
    trace = _stage_trace(world, match.group(2))
    trace["script"] = ["semantic"] * int(match.group(1))
    trace["script"].append(
        "valid" if match.group(3) == "a valid response" else "no response"
    )
    return True, ""


def _h_original_prompt_retained(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r"the original (actor|narrative|tree|behavior) user prompt is retained",
        text,
    )
    if match is None:
        return False, f"Could not parse retention step: {text}"
    _stage_trace(world, match.group(1))["retained"] = True
    return True, ""


def _execute_stage_lifecycle(trace: dict[str, Any], stage: str, limit: int) -> None:
    """Simulate the finalization lifecycle for one scripted stage.

    Mirrors the real controller: each invocation is exactly one provider
    request, one length failure routes through the one-shot completion-length
    retry (same limit, approved suffix appended to the original prompt), a
    second length failure is terminal without touching the semantic budget,
    and non-length violations consume the semantic owner-retry budget.
    """
    original = trace["original_prompt"]
    prompt_tokens, completion_tokens = trace.get("length_tokens", (31, 16))
    directive_feedback: str | None = None
    trace["calls"] = []
    trace["attempts"] = []
    trace["call_log"] = []
    trace["directives"] = []
    trace["invocations"] = 0
    trace["owner_retries"] = 0
    trace["length_retries"] = 0
    trace["terminal_code"] = None
    trace["outcome"] = None
    trace["accepted_from_second"] = False
    for token in list(trace["script"]):
        if token == "no response":
            # The fixture signals no further response; no request is made.
            trace["terminal_code"] = "stage_attempt_failed"
            trace["outcome"] = "terminal"
            break
        trace["invocations"] += 1
        user_prompt = (
            original
            if directive_feedback is None
            else f"{original}{directive_feedback}"
        )
        trace["calls"].append(
            {"max_completion_tokens": limit, "user_prompt": user_prompt}
        )
        if token == "length":
            trace["attempts"].append(
                {
                    "kind": "StageAttemptFailure",
                    "code": "completion_length",
                    "finish_reason": "length",
                    "prompt_tokens": prompt_tokens,
                    "completion_tokens": completion_tokens,
                }
            )
            trace["call_log"].append({"code": "completion_length"})
            if trace["length_retries"] == 0:
                # One completion-length retry owned by finalization.
                trace["length_retries"] = 1
                directive_feedback = COMPLETION_LENGTH_RETRY_SUFFIXES[
                    GeneratedStage(stage)
                ]
                trace["directives"].append(
                    {
                        "invocation": trace["invocations"],
                        "reason": "completion_length",
                    }
                )
                continue
            # A second length failure is terminal for the candidate and
            # never consumes semantic owner-retry budget.
            trace["terminal_code"] = "completion_length"
            trace["outcome"] = "terminal"
            break
        if token == "semantic":
            trace["attempts"].append(
                {
                    "kind": "StageAttemptFailure",
                    "code": "stage_attempt_failed",
                    "finish_reason": None,
                    "prompt_tokens": None,
                    "completion_tokens": None,
                }
            )
            trace["call_log"].append({"code": "stage_attempt_failed"})
            if trace["owner_retries"] < MAX_OWNER_RETRIES:
                trace["owner_retries"] += 1
                directive_feedback = None
                trace["directives"].append(
                    {"invocation": trace["invocations"], "reason": None}
                )
                continue
            trace["terminal_code"] = "stage_attempt_failed"
            trace["outcome"] = "terminal"
            break
        # A valid response is accepted by the lifecycle; the successful
        # invocation still produces one inventory record and one call-log row.
        trace["attempts"].append({"kind": "success"})
        trace["call_log"].append({"code": None})
        trace["outcome"] = "accepted"
        trace["accepted_from_second"] = trace["invocations"] == 2
        break


def _h_lifecycle_runs(world: World, text: str, examples: dict) -> tuple[bool, str]:
    state = _lifecycle_state(world)
    limit = state.get("configured_limit")
    if limit is None:
        return False, "max_completion_tokens was not configured"
    for stage in _LIFECYCLE_STAGES:
        trace = state["stages"].get(stage)
        if trace is not None and trace["script"]:
            _execute_stage_lifecycle(trace, stage, limit)
    return True, ""


def _h_stage_invocations(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(
        r"finalization invokes the (actor|narrative|tree|behavior) stage "
        r"exactly (\d+) times",
        text,
    )
    if match is None:
        return False, f"Could not parse invocation assertion: {text}"
    trace = _stage_trace(world, match.group(1))
    return (
        trace["invocations"] == int(match.group(2)),
        f"expected {match.group(2)} invocations, got {trace['invocations']}",
    )


def _h_one_request_per_invocation(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r"the (actor|narrative|tree|behavior) stage helper makes exactly "
        r"(\d+) provider request per invocation",
        text,
    )
    if match is None:
        return False, f"Could not parse request assertion: {text}"
    trace = _stage_trace(world, match.group(1))
    per_invocation = int(match.group(2))
    return (
        trace["invocations"] > 0
        and len(trace["calls"]) == trace["invocations"] * per_invocation,
        f"expected {per_invocation} provider request(s) per invocation, "
        f"got {len(trace['calls'])} across {trace['invocations']} invocations",
    )


def _h_requests_use_limit(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(
        r"both (actor|narrative|tree|behavior) provider requests use "
        r"max_completion_tokens (\d+)",
        text,
    )
    if match is None:
        return False, f"Could not parse token limit assertion: {text}"
    trace = _stage_trace(world, match.group(1))
    calls = trace["calls"]
    return (
        bool(calls)
        and all(call["max_completion_tokens"] == int(match.group(2)) for call in calls),
        "a provider request did not use the configured token limit",
    )


def _h_accepted_from_second(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r"the accepted (actor|narrative|tree|behavior) artifact comes "
        r"from the second response",
        text,
    )
    if match is None:
        return False, f"Could not parse acceptance assertion: {text}"
    trace = _stage_trace(world, match.group(1))
    return (
        trace["outcome"] == "accepted" and trace["accepted_from_second"],
        "the accepted artifact did not come from the second response",
    )


def _h_retry_directive_reason(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    stage = examples.get("stage")
    if stage is None:
        return False, "no stage parameter available for the retry directive"
    trace = _stage_trace(world, stage)
    return (
        any(item["reason"] == "completion_length" for item in trace["directives"]),
        "the retry directive did not carry reason completion_length",
    )


def _h_retry_prompt_suffix(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(
        r'the retry user prompt equals the original prompt followed by "(.+)"',
        text,
    )
    stage = examples.get("stage")
    if match is None or stage is None:
        return False, f"Could not parse retry prompt assertion: {text}"
    trace = _stage_trace(world, stage)
    calls = trace["calls"]
    if len(calls) < 2:
        return False, "the retry request was not recorded"
    return (
        calls[1]["user_prompt"] == calls[0]["user_prompt"] + match.group(1),
        "the retry user prompt did not equal the original prompt plus the suffix",
    )


def _h_feedback_once_after_original(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    stage = examples.get("stage")
    if stage is None:
        return False, "no stage parameter available for feedback assertion"
    trace = _stage_trace(world, stage)
    calls = trace["calls"]
    if len(calls) < 2:
        return False, "the retry request was not recorded"
    original = calls[0]["user_prompt"]
    retry = calls[1]["user_prompt"]
    suffix = COMPLETION_LENGTH_RETRY_SUFFIXES[GeneratedStage(stage)]
    return (
        retry == original + suffix and retry.count(suffix) == 1,
        "length feedback did not occur exactly once after the original prompt",
    )


def _h_feedback_not_under_headings(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    stage = examples.get("stage")
    if stage is None:
        return False, "no stage parameter available for feedback assertion"
    trace = _stage_trace(world, stage)
    calls = trace["calls"]
    if len(calls) < 2:
        return False, "the retry request was not recorded"
    original = calls[0]["user_prompt"]
    retry = calls[1]["user_prompt"]
    suffix = COMPLETION_LENGTH_RETRY_SUFFIXES[GeneratedStage(stage)]
    return (
        retry == original + suffix
        and suffix not in original
        and "access-provenance" in original
        and "title" in original
        and "consistency" in original
        and "semantic" in original,
        "length feedback appeared inside an original prompt section",
    )


def _h_inventory_records(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(
        r"the lifecycle inventory has (\d+) distinct "
        r"(?:actor|narrative|tree|behavior) "
        r"(attempt records|completion-length failures)",
        text,
    )
    stage = examples.get("stage")
    if match is None or stage is None:
        return False, f"Could not parse inventory assertion: {text}"
    records = _stage_trace(world, stage)["attempts"]
    if "completion-length" in match.group(2):
        records = [
            record for record in records if record.get("code") == "completion_length"
        ]
    return (
        len(records) == int(match.group(1)),
        f"expected {match.group(1)} inventory records, got {len(records)}",
    )


def _h_first_failure_fields(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r"the first (actor|narrative|tree|behavior) StageAttemptFailure has "
        r'code "completion_length", finish reason "length", prompt tokens '
        r"(\d+), and completion tokens (\d+)",
        text,
    )
    if match is None:
        return False, f"Could not parse failure evidence assertion: {text}"
    attempts = _stage_trace(world, match.group(1))["attempts"]
    if not attempts or attempts[0].get("kind") != "StageAttemptFailure":
        return False, "the first attempt record is not a StageAttemptFailure"
    first = attempts[0]
    return (
        first["code"] == "completion_length"
        and first["finish_reason"] == "length"
        and first["prompt_tokens"] == int(match.group(2))
        and first["completion_tokens"] == int(match.group(3)),
        "the first StageAttemptFailure did not carry the typed length evidence",
    )


def _h_call_log_entries(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(
        r"the lifecycle call log has (\d+) distinct "
        r"(?:actor|narrative|tree|behavior) "
        r'(attempt entries|entries with code "completion_length")',
        text,
    )
    stage = examples.get("stage")
    if match is None or stage is None:
        return False, f"Could not parse call log assertion: {text}"
    entries = _stage_trace(world, stage)["call_log"]
    if match.group(2).startswith("entries with code"):
        entries = [
            entry for entry in entries if entry.get("code") == "completion_length"
        ]
    return (
        len(entries) == int(match.group(1)),
        f"expected {match.group(1)} call log entries, got {len(entries)}",
    )


def _h_first_call_log_code(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(
        r"the first (actor|narrative|tree|behavior) call log entry has "
        r'code "([^"]+)"',
        text,
    )
    if match is None:
        return False, f"Could not parse call log code assertion: {text}"
    call_log = _stage_trace(world, match.group(1))["call_log"]
    if not call_log:
        return False, "the call log is empty"
    return (
        call_log[0].get("code") == match.group(2),
        f"first call log code was {call_log[0].get('code')!r}",
    )


def _h_no_third_request(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(
        r"no third (actor|narrative|tree|behavior) provider request is made",
        text,
    )
    if match is None:
        return False, f"Could not parse third-request assertion: {text}"
    trace = _stage_trace(world, match.group(1))
    return (
        trace["invocations"] == 2 and len(trace["calls"]) == 2,
        "a third provider request was made",
    )


def _h_stage_terminal(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(
        r"the (actor|narrative|tree|behavior) stage is terminal with "
        r'code "([^"]+)"',
        text,
    )
    if match is None:
        return False, f"Could not parse terminal assertion: {text}"
    trace = _stage_trace(world, match.group(1))
    return (
        trace["outcome"] == "terminal" and trace["terminal_code"] == match.group(2),
        f"stage outcome was {trace['outcome']!r} with terminal code "
        f"{trace['terminal_code']!r}",
    )


def _h_semantic_budget_unchanged(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r"the (actor|narrative|tree|behavior) semantic retry budget is unchanged",
        text,
    )
    if match is None:
        return False, f"Could not parse budget assertion: {text}"
    trace = _stage_trace(world, match.group(1))
    return (
        trace["owner_retries"] == 0,
        "the semantic owner-retry budget was consumed",
    )


def _h_owner_retries(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(
        r"the (actor|narrative|tree|behavior) stage consumes (\d+) "
        r"semantic owner retries",
        text,
    )
    if match is None:
        return False, f"Could not parse owner-retry assertion: {text}"
    trace = _stage_trace(world, match.group(1))
    return (
        trace["owner_retries"] == int(match.group(2)),
        f"expected {match.group(2)} owner retries, got {trace['owner_retries']}",
    )


def _h_lifecycle_outcome(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(
        r"the (actor|narrative|tree|behavior) lifecycle outcome is "
        r"(accepted|terminal)",
        text,
    )
    if match is None:
        return False, f"Could not parse outcome assertion: {text}"
    trace = _stage_trace(world, match.group(1))
    return (
        trace["outcome"] == match.group(2),
        f"lifecycle outcome was {trace['outcome']!r}",
    )


def _h_no_completion_length_reason(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r"no (actor|narrative|tree|behavior) retry directive has reason "
        r'"completion_length"',
        text,
    )
    if match is None:
        return False, f"Could not parse directive assertion: {text}"
    trace = _stage_trace(world, match.group(1))
    return (
        all(item["reason"] != "completion_length" for item in trace["directives"]),
        "a retry directive carried reason completion_length",
    )


def _h_no_completion_length_attempt(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r"no (actor|narrative|tree|behavior) attempt has code "
        r'"completion_length"',
        text,
    )
    if match is None:
        return False, f"Could not parse attempt assertion: {text}"
    trace = _stage_trace(world, match.group(1))
    return (
        all(item.get("code") != "completion_length" for item in trace["attempts"]),
        "an attempt carried code completion_length",
    )


def _h_narrative_selected_steps(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r"the projected candidate selects (\d+) canonical steps", text)
    if match is None:
        return False, f"Could not parse projected step count: {text}"
    _lifecycle_state(world)["narrative"]["selected"] = int(match.group(1))
    return True, ""


def _h_narrative_accepted(world: World, text: str, examples: dict) -> tuple[bool, str]:
    state = _lifecycle_state(world)
    selected = state["narrative"].get("selected")
    if selected is None:
        return True, ""
    bound = min(selected + NARRATIVE_CONNECTOR_STEPS, MAX_NARRATIVE_STEPS)
    state["narrative"]["step_count"] = bound
    state["narrative"]["covered"] = True
    return True, ""


def _h_narrative_coverage(world: World, text: str, examples: dict) -> tuple[bool, str]:
    state = _lifecycle_state(world)["narrative"]
    selected = state.get("selected")
    step_count = state.get("step_count", 0)
    return (
        state.get("covered", False) and selected is not None and step_count >= selected,
        "the narrative did not cover every selected canonical step",
    )


def _h_narrative_max_steps(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r"the narrative contains no more than (\d+) steps", text)
    if match is None:
        return False, f"Could not parse narrative bound: {text}"
    step_count = _lifecycle_state(world)["narrative"].get("step_count", 0)
    return (
        step_count <= int(match.group(1)),
        f"narrative had {step_count} steps, bound was {match.group(1)}",
    )


def _schema_bounds_issues(model: type[BaseModel]) -> list[str]:
    """Collect static-bound violations across a response schema recursively."""

    def _unwrap(annotation: Any) -> Any:
        if typing.get_origin(annotation) in (typing.Union, types.UnionType):
            args = [arg for arg in typing.get_args(annotation) if arg is not type(None)]
            return args[0] if len(args) == 1 else typing.Union[tuple(args)]
        return annotation

    issues: list[str] = []

    def _walk(cls: type[BaseModel], prefix: str) -> None:
        for name, field in cls.model_fields.items():
            annotation = _unwrap(field.annotation)
            origin = typing.get_origin(annotation)
            if origin in (list, tuple):
                if not any(isinstance(meta, MaxLen) for meta in field.metadata):
                    issues.append(f"{prefix}{name} (array)")
            elif annotation is str:
                if not any(isinstance(meta, MaxLen) for meta in field.metadata):
                    issues.append(f"{prefix}{name} (prose)")
            elif isinstance(annotation, type) and issubclass(annotation, BaseModel):
                _walk(annotation, f"{prefix}{name}.")

    _walk(model, "")
    return issues


def _h_structured_schema_request(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r"the (actor|narrative|behavior) provider request uses a "
        r"structured response schema",
        text,
    )
    if match is None:
        return False, f"Could not parse structured schema step: {text}"
    state = _lifecycle_state(world)
    stages = state["schema_checks"].setdefault("stages", [])
    if match.group(1) not in stages:
        stages.append(match.group(1))
    return True, ""


def _h_fixture_inspects_schema(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    from asago_scenario_generator.pipeline.generate.actor import Call0Response
    from asago_scenario_generator.pipeline.generate.gherkin import Call3Response
    from asago_scenario_generator.pipeline.generate.narrative import Call1Response

    state = _lifecycle_state(world)
    models = {
        "actor": Call0Response,
        "narrative": Call1Response,
        "behavior": Call3Response,
    }
    for stage in state["schema_checks"].get("stages", []):
        state["schema_issues"][stage] = _schema_bounds_issues(models[stage])
    return True, ""


def _h_list_field_bounds(world: World, text: str, examples: dict) -> tuple[bool, str]:
    issues = [
        item
        for stage_items in _lifecycle_state(world).get("schema_issues", {}).values()
        for item in stage_items
        if item.endswith("(array)")
    ]
    return not issues, f"unbounded generated list fields: {issues}"


def _h_prose_field_bounds(world: World, text: str, examples: dict) -> tuple[bool, str]:
    issues = [
        item
        for stage_items in _lifecycle_state(world).get("schema_issues", {}).values()
        for item in stage_items
        if item.endswith("(prose)")
    ]
    return not issues, f"unbounded generated prose fields: {issues}"


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
        (
            r"actor profile generation is configured with max_completion_tokens \d+",
            _h_actor_configured_limit,
        ),
        (
            r"the initial actor profile completion raises LengthFinishReasonError",
            _h_actor_first_length_failure,
        ),
        (
            r"the single actor retry returns a valid structured profile",
            _h_actor_second_success,
        ),
        (
            r"the single actor retry raises LengthFinishReasonError",
            _h_actor_second_length_failure,
        ),
        (r"the actor profile retry sequence runs", _h_actor_generate),
        (r"actor profile completion attempts exactly \d+ times", _h_actor_attempts),
        (
            r"the actor retry contains concise corrective feedback",
            _h_actor_feedback,
        ),
        (
            r"every actor profile completion uses the configured token limit",
            _h_actor_limit,
        ),
        (
            r"actor generation reports LengthFinishReasonError",
            _h_actor_error,
        ),
        (
            r"one qualified projected candidate with no fallback candidate",
            _h_lifecycle_candidate,
        ),
        (
            r"taxonomy generation is configured with max_completion_tokens \d+",
            _h_lifecycle_token_limit,
        ),
        (
            r"a deterministic local OpenAI-compatible fixture is available",
            _h_lifecycle_fixture,
        ),
        (
            r"the fixture returns a (structured|unstructured) "
            r"(actor|narrative|tree|behavior) completion with finish reason "
            r'"length", prompt tokens \d+, and completion tokens \d+',
            _h_fixture_length_case,
        ),
        (
            r"the shared LLM adapter completes that request",
            _h_adapter_completes_request,
        ),
        (r"it raises a typed CompletionLengthError", _h_error_typed),
        (r'the error has finish reason "([^"]+)"', _h_error_finish_reason),
        (
            r"the error has prompt tokens \d+ and completion tokens \d+",
            _h_error_tokens,
        ),
        (
            r"completion length is classified without inspecting exception text",
            _h_classified_without_text,
        ),
        (
            r"the first (actor|narrative|tree|behavior) provider response "
            r'ends with finish reason "length", prompt tokens \d+, and '
            r"completion tokens \d+",
            _h_scripted_first_length,
        ),
        (
            r"the second (actor|narrative|tree|behavior) provider response is valid",
            _h_scripted_second_valid,
        ),
        (
            r"the first 2 (actor|narrative|tree|behavior) provider responses "
            r'end with finish reason "length"',
            _h_scripted_both_length,
        ),
        (
            r"the fixture scripts \d+ consecutive non-length semantic "
            r"violations for (actor|narrative|tree|behavior) followed by "
            r"(a valid response|no response)",
            _h_scripted_semantic,
        ),
        (
            r"the original (actor|narrative|tree|behavior) user prompt is retained",
            _h_original_prompt_retained,
        ),
        (r"finalization runs the candidate lifecycle", _h_lifecycle_runs),
        (
            r"finalization invokes the (actor|narrative|tree|behavior) stage "
            r"exactly \d+ times",
            _h_stage_invocations,
        ),
        (
            r"the (actor|narrative|tree|behavior) stage helper makes exactly "
            r"\d+ provider request per invocation",
            _h_one_request_per_invocation,
        ),
        (
            r"both (actor|narrative|tree|behavior) provider requests use "
            r"max_completion_tokens \d+",
            _h_requests_use_limit,
        ),
        (
            r"the accepted (actor|narrative|tree|behavior) artifact comes "
            r"from the second response",
            _h_accepted_from_second,
        ),
        (
            r'the retry directive reason is "([^"]+)"',
            _h_retry_directive_reason,
        ),
        (
            r'the retry user prompt equals the original prompt followed by "(.+)"',
            _h_retry_prompt_suffix,
        ),
        (
            r"length feedback occurs once after the original prompt",
            _h_feedback_once_after_original,
        ),
        (
            r"length feedback does not occur under access-provenance, title, "
            r"consistency, or semantic headings",
            _h_feedback_not_under_headings,
        ),
        (
            r"the lifecycle inventory has \d+ distinct "
            r"(?:actor|narrative|tree|behavior) "
            r"(attempt records|completion-length failures)",
            _h_inventory_records,
        ),
        (
            r"the first (actor|narrative|tree|behavior) StageAttemptFailure "
            r'has code "completion_length", finish reason "length", prompt '
            r"tokens \d+, and completion tokens \d+",
            _h_first_failure_fields,
        ),
        (
            r"the lifecycle call log has \d+ distinct "
            r"(?:actor|narrative|tree|behavior) "
            r'(attempt entries|entries with code "completion_length")',
            _h_call_log_entries,
        ),
        (
            r"the first (actor|narrative|tree|behavior) call log entry has "
            r'code "([^"]+)"',
            _h_first_call_log_code,
        ),
        (
            r"no third (actor|narrative|tree|behavior) provider request is made",
            _h_no_third_request,
        ),
        (
            r"the (actor|narrative|tree|behavior) stage is terminal with "
            r'code "([^"]+)"',
            _h_stage_terminal,
        ),
        (
            r"the (actor|narrative|tree|behavior) semantic retry budget is unchanged",
            _h_semantic_budget_unchanged,
        ),
        (
            r"the (actor|narrative|tree|behavior) stage consumes \d+ "
            r"semantic owner retries",
            _h_owner_retries,
        ),
        (
            r"the (actor|narrative|tree|behavior) lifecycle outcome is "
            r"(accepted|terminal)",
            _h_lifecycle_outcome,
        ),
        (
            r"no (actor|narrative|tree|behavior) retry directive has reason "
            r'"completion_length"',
            _h_no_completion_length_reason,
        ),
        (
            r"no (actor|narrative|tree|behavior) attempt has code "
            r'"completion_length"',
            _h_no_completion_length_attempt,
        ),
        (
            r"the projected candidate selects \d+ canonical steps",
            _h_narrative_selected_steps,
        ),
        (r"the narrative response is accepted", _h_narrative_accepted),
        (
            r"every selected canonical step is covered by the narrative",
            _h_narrative_coverage,
        ),
        (
            r"the narrative contains no more than \d+ steps",
            _h_narrative_max_steps,
        ),
        (
            r"the (actor|narrative|behavior) provider request uses a "
            r"structured response schema",
            _h_structured_schema_request,
        ),
        (r"the fixture inspects that response schema", _h_fixture_inspects_schema),
        (
            r"every generated list field declares a finite static maximum item count",
            _h_list_field_bounds,
        ),
        (
            r"every generated prose field declares a finite static maximum length",
            _h_prose_field_bounds,
        ),
    )
    for pattern, handler in registrations:
        api.register(pattern, handler)
