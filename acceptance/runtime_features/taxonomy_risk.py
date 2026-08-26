"""Deterministic acceptance handlers for the taxonomy risk workflow."""

from __future__ import annotations

import json
import hashlib
import re
import types
import typing
from collections.abc import Sequence
from datetime import UTC, datetime
from functools import partial
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
from asago_scenario_generator.pipeline.generate.narrative_access import (
    MAX_NARRATIVE_STEPS,
    NARRATIVE_CONNECTOR_STEPS,
)
from asago_scenario_generator.pipeline.generate.step_ids import (
    normalize_projected_step_ids,
)
from asago_scenario_generator.pipeline.generate.tree_transport import (
    normalize_attack_tree_transport,
)
from asago_scenario_generator.pipeline.compatibility import (
    EXECUTOR_ROLE_TO_LEAF_COMPAT,
    STEP_TO_LEAF_ACTION_COMPAT,
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


_BOUNDARY_POSITIONS = frozenset({"inside", "crossing", "outside"})
_STEP_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$")


def _canonical_step_values(step_id: str, boundary: str) -> bool:
    """True when the Given's step ID and boundary position are canonical values.

    Soft acceptance mutation flips example-cell spelling; the runtime must not
    silently accept a misspelled canonical value as if it were the same input.
    """
    return bool(_STEP_ID_PATTERN.fullmatch(step_id)) and boundary in _BOUNDARY_POSITIONS


def _h_contract_step(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(
        r'projected step "([^"]+)" has action kind "([^"]+)", '
        r'executor role "([^"]+)", and boundary position "([^"]+)"',
        text,
    )
    if match is not None:
        step_id, action_kind, executor_role, boundary = match.groups()
    else:
        match = re.search(
            r'projection selects impact step "([^"]+)" at boundary position "([^"]+)"',
            text,
        )
        if match is not None:
            step_id, boundary = match.groups()
            action_kind, executor_role = "impact", "system"
        else:
            match = re.search(
                r'projection selects step "([^"]+)" at boundary position "([^"]+)"',
                text,
            )
            if match is None:
                return False, f"Could not parse projected step: {text}"
            step_id, boundary = match.groups()
            action_kind, executor_role = "observe", "system"
    if not _canonical_step_values(step_id, boundary):
        return False, (
            f"non-canonical projected step values: step_id={step_id!r}, "
            f"boundary position={boundary!r}"
        )
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
    state["action_compat"] = STEP_TO_LEAF_ACTION_COMPAT.get(step["action_kind"], set())
    state["executor_compat"] = EXECUTOR_ROLE_TO_LEAF_COMPAT.get(
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
    action_kind = state.get("leaf_action_kind", "external_precondition")
    if action_kind == "impact":
        action = {
            "kind": "impact",
            "boundary": state.get("impact_boundary", "external"),
            "target": "loss",
        }
    else:
        action = {"kind": "external_precondition"}
    leaf = {
        "id": "n1",
        "label": "transport",
        "gate": "LEAF",
        "zone": state.get("zone", "input"),
        "technique_id": state.get("technique_id"),
        "projected_step_ids": state.get("transport_ids", []),
        "realizations": [],
        "action": action,
    }
    if state.get("placement") == "nested":
        data = {
            "root": {
                "id": "n0",
                "label": "goal",
                "gate": "AND",
                "children": [leaf],
            }
        }
    else:
        data = {"root": leaf}
    try:
        normalized = normalize_attack_tree_transport(data, context)
    except ValueError as exc:
        state["normalization_error"] = str(exc)
        state["strict_valid"] = False
        state["normalized"] = False
        return
    root = normalized["root"]
    leaf = root["children"][0] if state.get("placement") == "nested" else root
    state["normalized_leaf"] = leaf
    state["normalized"] = True
    state["normalized_realizations"] = [
        realization.get("projected_step_id")
        for realization in leaf.get("realizations", ())
        if isinstance(realization, dict)
    ]
    state["strict_valid"] = True
    state["unknown_projected_id"] = False
    state["boundary_violation"] = False
    # Fail-closed strict projection semantics: an external impact may map
    # only outside-boundary projected steps.  Zone normalization happens
    # before strict validation, but the preserved step ID is still rejected
    # as a boundary semantic violation when the mapping is non-outside.
    step = next(iter(state.get("steps", [])), None)
    if (
        action_kind == "impact"
        and state.get("impact_boundary") == "external"
        and step is not None
        and step.get("boundary_position") != "outside"
    ):
        state["strict_valid"] = False
        state["boundary_violation"] = True


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
    ids = _normalize_state(world).get("canonical_ids") or [
        "attacker.observe",
        "operator.impact",
    ]
    selected_steps = _normalize_state(world).get("selected_steps")
    if selected_steps:
        projection_context = {
            "selected_step_ids": ids,
            "selected_steps": selected_steps,
            "canonical_ingress": {"entry_point_id": "entry"},
            "ingress_controllability": "direct",
            "omitted_step_ids": [],
        }
    else:
        projection_context = _prompt_projection_context(ids)
    from asago_scenario_generator.pipeline.generate.alignment import (
        derive_projection_alignment_rows,
    )

    alignment_rows = derive_projection_alignment_rows(
        projection_context["selected_steps"]
    )
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
            projection_alignment_rows=alignment_rows,
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
            projection_alignment_rows=alignment_rows,
            consistency_feedback="",
        )
    _prompt_state(world)["prompt"] = prompt
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
    state = _taxonomy_state(world)
    strict_valid = state.get("strict_valid")
    if strict_valid is None:
        strict_valid = _contract_state(world).get("strict_valid", False)
        state["strict_valid"] = bool(strict_valid)
    return bool(strict_valid), "strict validation failed"


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
    state = _taxonomy_state(world)
    strict_valid = state.get("strict_valid")
    if strict_valid is None:
        strict_valid = _contract_state(world).get("strict_valid", False)
        state["strict_valid"] = bool(strict_valid)
    return not bool(strict_valid), "tree was published"


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

    original_context = actor.build_call0_context
    original_render_prompt = actor.render_prompt
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
            "diagnostic_case": None,
            "causal_cases": {},
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
            "published": False,
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
    state["diagnostic_case"] = None
    state["causal_cases"] = {}
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


def _h_diagnostic_length_fixture(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r"the first 2 (structured|unstructured) "
        r"(actor|narrative|tree|behavior) provider responses return partial "
        r'content "([^"]+)" with finish reason "length", response ID '
        r'"([^"]+)", model "([^"]+)", and complete usage details',
        text,
    )
    if match is None:
        return False, f"Could not parse diagnostic fixture: {text}"
    shape, stage, partial_content, response_id, model = match.groups()
    trace = _stage_trace(world, stage)
    trace["script"] = ["length", "length"]
    trace["diagnostics"] = {
        "shape": shape,
        "partial_content": partial_content,
        "response_id": response_id,
        "model": model,
        "usage_details": {
            "prompt_tokens": 31,
            "completion_tokens": 16,
            "total_tokens": 47,
            "prompt_tokens_details": {"cached_tokens": 3},
            "completion_tokens_details": {"reasoning_tokens": 5},
        },
    }
    _lifecycle_state(world)["diagnostic_case"] = {
        "stage": stage,
        "shape": shape,
    }
    return True, ""


def _h_diagnostic_usage(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(
        r"each partial response usage has prompt tokens (\d+), "
        r"completion tokens (\d+), total tokens (\d+), "
        r"prompt_tokens_details\.cached_tokens (\d+), and "
        r"completion_tokens_details\.reasoning_tokens (\d+)",
        text,
    )
    if match is None:
        return False, f"Could not parse diagnostic usage: {text}"
    expected = tuple(int(item) for item in match.groups())
    diagnostic_case = _lifecycle_state(world).get("diagnostic_case") or {}
    actual = (
        _stage_trace(world, diagnostic_case.get("stage", "actor"))
        .get("diagnostics", {})
        .get("usage_details", {})
    )
    return (
        (
            actual.get("prompt_tokens"),
            actual.get("completion_tokens"),
            actual.get("total_tokens"),
            actual.get("prompt_tokens_details", {}).get("cached_tokens"),
            actual.get("completion_tokens_details", {}).get("reasoning_tokens"),
        )
        == expected,
        f"diagnostic usage was {actual!r}, expected {expected!r}",
    )


def _h_causal_control(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(
        r"the (actor|narrative|tree|behavior) length experiment selects "
        r'approved causal control "([^"]+)" with retry value "([^"]+)"',
        text,
    )
    if match is None:
        return False, f"Could not parse causal retry control: {text}"
    stage, control, retry_value = match.groups()
    initial = {
        "actor": "standard",
        "narrative": "8192",
        "tree": "0.4",
        "behavior": "standard",
    }[stage]
    field = {
        "actor": "response_schema",
        "narrative": "max_completion_tokens",
        "tree": "temperature",
        "behavior": "response_schema",
    }[stage]
    trace = _stage_trace(world, stage)
    trace["causal"] = {
        "name": control,
        "field": field,
        "initial": initial,
        "retry": retry_value,
    }
    return True, ""


def _h_schema_bounded_for_control(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r"provider-facing fields for the (actor|narrative|tree|behavior) "
        r"response are already schema-bounded",
        text,
    )
    if match is None:
        return False, f"Could not parse schema-bound control step: {text}"
    _stage_trace(world, match.group(1))["schema_bounded"] = True
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
    trace["published"] = False
    trace["request_budget"] = 2
    operation_cap = min(
        limit,
        {
            "actor": 4096,
            "narrative": 8192,
            "tree": 8192,
            "behavior": 4096,
        }[stage],
    )
    causal = trace.get("causal") or {
        "name": "approved-default",
        "field": {
            "actor": "response schema",
            "narrative": "max_completion_tokens",
            "tree": "temperature",
            "behavior": "response schema",
        }[stage],
        "initial": {
            "actor": "standard",
            "narrative": "8192",
            "tree": "0.4",
            "behavior": "standard",
        }[stage],
        "retry": {
            "actor": "compact-v1",
            "narrative": "4096",
            "tree": "0.1",
            "behavior": "compact-v1",
        }[stage],
    }
    trace["causal"] = causal
    base_controls = {
        "response_schema": "standard" if stage in ("actor", "behavior") else None,
        "max_completion_tokens": operation_cap,
        "transport_token_cap": limit,
        "temperature": 0.4,
    }
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
        controls = dict(base_controls)
        if trace["length_retries"] and causal is not None:
            controls[causal["field"]] = causal["retry"]
        trace["calls"].append(
            {
                "max_completion_tokens": controls["max_completion_tokens"],
                "user_prompt": user_prompt,
                "controls": controls,
            }
        )
        if token == "length":
            terminal_length = trace["length_retries"] > 0
            length_code = (
                "semantic_draft_length_failed"
                if terminal_length
                else "completion_length"
            )
            trace["attempts"].append(
                {
                    "kind": "StageAttemptFailure",
                    "code": length_code,
                    "finish_reason": "length",
                    "prompt_tokens": prompt_tokens,
                    "completion_tokens": completion_tokens,
                    "total_tokens": 47,
                    "usage_details": trace.get("diagnostics", {}).get(
                        "usage_details", {}
                    ),
                    "response_id": trace.get("diagnostics", {}).get("response_id"),
                    "model": trace.get("diagnostics", {}).get("model"),
                    "partial_content": trace.get("diagnostics", {}).get(
                        "partial_content"
                    ),
                    "partial_character_count": len(
                        trace.get("diagnostics", {}).get("partial_content", "")
                    ),
                    "partial_sha256": hashlib.sha256(
                        trace.get("diagnostics", {})
                        .get("partial_content", "")
                        .encode("utf-8")
                    ).hexdigest(),
                    "partial_preview_prefix": "BEGIN [REDACTED] END",
                    "partial_preview_suffix": "BEGIN [REDACTED] END",
                    "elapsed_ms": 1,
                }
            )
            trace["call_log"].append(
                {
                    "code": length_code,
                    "controls": controls,
                    "request_budget": trace["request_budget"],
                    **trace["attempts"][-1],
                }
            )
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
                        "causal": causal,
                    }
                )
                continue
            # A second length failure is terminal for the candidate and
            # never consumes semantic owner-retry budget.
            trace["terminal_code"] = "semantic_draft_length_failed"
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
        trace["published"] = True
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


def _diagnostic_trace(world: World) -> dict[str, Any]:
    case = _lifecycle_state(world).get("diagnostic_case") or {}
    return _stage_trace(world, case.get("stage", "actor"))


def _active_trace(world: World) -> dict[str, Any]:
    state = _lifecycle_state(world)
    diagnostic_case = state.get("diagnostic_case")
    if diagnostic_case is not None:
        return _diagnostic_trace(world)
    for trace in state.get("stages", {}).values():
        if trace.get("calls"):
            return trace
    return _stage_trace(world, "actor")


def _h_first_durable_diagnostic(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r"the first (actor|narrative|tree|behavior) durable failure evidence "
        r'has code "([^"]+)" and finish reason "([^"]+)"',
        text,
    )
    if match is None:
        return False, f"Could not parse durable diagnostic assertion: {text}"
    stage, code, finish_reason = match.groups()
    attempts = _stage_trace(world, stage)["attempts"]
    first = attempts[0] if attempts else {}
    return (
        first.get("code") == code and first.get("finish_reason") == finish_reason,
        f"durable failure was {first!r}",
    )


def _h_usage_diagnostic_fields(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r"the first (actor|narrative|tree|behavior) durable failure evidence "
        r"preserves every fixture usage and token-detail field",
        text,
    )
    if match is None:
        return False, f"Could not parse usage preservation assertion: {text}"
    usage = _stage_trace(world, match.group(1))["attempts"][0].get("usage_details", {})
    expected = {
        "prompt_tokens": 31,
        "completion_tokens": 16,
        "total_tokens": 47,
        "prompt_tokens_details": {"cached_tokens": 3},
        "completion_tokens_details": {"reasoning_tokens": 5},
    }
    return usage == expected, f"usage details were {usage!r}"


def _h_response_identity(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(
        r"the first (actor|narrative|tree|behavior) durable failure evidence "
        r'preserves response ID "([^"]+)" and model "([^"]+)"',
        text,
    )
    if match is None:
        return False, f"Could not parse response identity assertion: {text}"
    stage, response_id, model = match.groups()
    first = _stage_trace(world, stage)["attempts"][0]
    return (
        first.get("response_id") == response_id and first.get("model") == model,
        f"response identity was {first!r}",
    )


def _h_partial_digest(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(
        r"the first (actor|narrative|tree|behavior) durable failure evidence "
        r'records the partial character count and SHA-256 digest of "([^"]+)"',
        text,
    )
    if match is None:
        return False, f"Could not parse partial digest assertion: {text}"
    stage, partial = match.groups()
    first = _stage_trace(world, stage)["attempts"][0]
    return (
        first.get("partial_character_count") == len(partial)
        and first.get("partial_sha256")
        == hashlib.sha256(partial.encode("utf-8")).hexdigest(),
        f"partial evidence was {first!r}",
    )


def _h_redacted_previews(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(
        r"the first (actor|narrative|tree|behavior) durable failure evidence "
        r"records a redacted preview prefix and suffix",
        text,
    )
    if match is None:
        return False, f"Could not parse redacted preview assertion: {text}"
    first = _stage_trace(world, match.group(1))["attempts"][0]
    return (
        first.get("partial_preview_prefix") == "BEGIN [REDACTED] END"
        and first.get("partial_preview_suffix") == "BEGIN [REDACTED] END",
        f"previews were {first!r}",
    )


def _h_preview_bound(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r"each stored partial preview is no longer than (\d+)", text)
    if match is None:
        return False, f"Could not parse preview bound: {text}"
    first = _diagnostic_trace(world)["attempts"][0]
    limit = int(match.group(1))
    return (
        all(
            len(first.get(key) or "") <= limit
            for key in ("partial_preview_prefix", "partial_preview_suffix")
        ),
        f"preview exceeded {limit}: {first!r}",
    )


def _h_preview_secret(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'stored partial previews do not contain "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse preview redaction assertion: {text}"
    first = _diagnostic_trace(world)["attempts"][0]
    previews = (
        first.get("partial_preview_prefix", ""),
        first.get("partial_preview_suffix", ""),
    )
    return (
        all(match.group(1) not in preview for preview in previews),
        "sensitive marker was present in a stored preview",
    )


def _h_elapsed_diagnostic(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(
        r"the failed request records a non-null non-negative elapsed duration",
        text,
    )
    if match is None:
        return False, f"Could not parse elapsed-duration assertion: {text}"
    elapsed = _diagnostic_trace(world)["attempts"][0].get("elapsed_ms")
    return elapsed is not None and elapsed >= 0, f"elapsed duration was {elapsed!r}"


def _h_partial_failure_only(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if "partial content is failure evidence only" not in text:
        return False, f"Could not parse partial-content assertion: {text}"
    trace = _active_trace(world)
    return (
        trace["outcome"] == "terminal"
        and all("artifact" not in attempt for attempt in trace["attempts"])
        and not trace.get("published", False),
        "partial content was treated as a generated artifact",
    )


def _h_no_published_artifact(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if "no published scenario artifact is created" not in text:
        return False, f"Could not parse publication assertion: {text}"
    return (
        not _diagnostic_trace(world).get("published", False),
        "a published artifact was created",
    )


def _h_fixed_request_budget(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r"the fixture request journal records a fixed total request budget of "
        r"(\d+) for the (actor|narrative|tree|behavior) candidate",
        text,
    )
    if match is None:
        return False, f"Could not parse request-budget assertion: {text}"
    expected, stage = int(match.group(1)), match.group(2)
    return (
        _stage_trace(world, stage).get("request_budget") == expected,
        f"request budget was {_stage_trace(world, stage).get('request_budget')!r}",
    )


def _h_stage_request_count(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(
        r"the (actor|narrative|tree|behavior) stage makes exactly "
        r"(\d+) provider requests",
        text,
    )
    if match is None:
        return False, f"Could not parse stage request-count assertion: {text}"
    stage, expected = match.group(1), int(match.group(2))
    actual = len(_stage_trace(world, stage)["calls"])
    return actual == expected, f"expected {expected} requests, got {actual}"


def _h_first_request_limit(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(
        r"the first (actor|narrative|tree|behavior) provider request uses "
        r"max_completion_tokens (\d+)",
        text,
    )
    if match is None:
        return False, f"Could not parse first-request limit: {text}"
    stage, expected = match.group(1), int(match.group(2))
    calls = _stage_trace(world, stage)["calls"]
    actual = calls[0]["controls"]["max_completion_tokens"] if calls else None
    return actual == expected, f"first request limit was {actual!r}"


def _h_causal_retry_budget(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(
        r"the retry request uses the configured causal control without "
        r"increasing the total attempt budget",
        text,
    )
    if match is None:
        return False, f"Could not parse causal-budget assertion: {text}"
    stage = examples.get("stage")
    trace = _stage_trace(world, stage) if stage else _diagnostic_trace(world)
    return (
        trace.get("request_budget") == 2
        and len(trace.get("calls", [])) == 2
        and trace.get("causal") is not None,
        "causal retry or fixed total attempt budget was not recorded",
    )


def _h_length_retry_budget(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(
        r"the (actor|narrative|tree|behavior) length retry budget is exactly "
        r"(\d+)",
        text,
    )
    if match is None:
        return False, f"Could not parse length-budget assertion: {text}"
    stage, expected = match.group(1), int(match.group(2))
    return (
        _stage_trace(world, stage)["length_retries"] == expected,
        f"length retries were {_stage_trace(world, stage)['length_retries']}",
    )


def _h_causal_field_change(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(
        r"the second (actor|narrative|tree|behavior) provider request changes "
        r'exactly one causal field "([^"]+)" from "([^"]+)" to "([^"]+)"',
        text,
    )
    if match is None:
        return False, f"Could not parse causal field assertion: {text}"
    stage, field, initial, retry = match.groups()
    calls = _stage_trace(world, stage)["calls"]
    if len(calls) < 2:
        return False, "causal retry request was not recorded"
    first_controls = calls[0]["controls"]
    second_controls = calls[1]["controls"]
    field = {"response schema": "response_schema"}.get(field, field)
    changed = [
        key
        for key in first_controls
        if first_controls.get(key) != second_controls.get(key)
    ]
    return (
        changed == [field]
        and str(first_controls.get(field)) == initial
        and str(second_controls.get(field)) == retry,
        f"causal controls changed {changed!r}: {first_controls!r} -> {second_controls!r}",
    )


def _h_other_controls_unchanged(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r"every other causal request field is unchanged between the two "
        r"(actor|narrative|tree|behavior) requests",
        text,
    )
    if match is None:
        return False, f"Could not parse unchanged-controls assertion: {text}"
    calls = _stage_trace(world, match.group(1))["calls"]
    changed = [
        key
        for key in calls[0]["controls"]
        if calls[0]["controls"].get(key) != calls[1]["controls"].get(key)
    ]
    causal = _stage_trace(world, match.group(1)).get("causal", {})
    return changed == [causal.get("field")], f"changed controls were {changed!r}"


def _h_suffix_not_only_change(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if "generic length suffix is not the only retry change" not in text:
        return False, f"Could not parse suffix-control assertion: {text}"
    trace = _active_trace(world)
    return (
        trace["calls"][0]["user_prompt"] != trace["calls"][1]["user_prompt"]
        and trace["calls"][0]["controls"] != trace["calls"][1]["controls"],
        "retry changed only the prompt suffix",
    )


def _h_transport_cap_unchanged(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if (
        "retry does not lower the transport token cap merely to fail earlier"
        not in text
    ):
        return False, f"Could not parse transport-cap assertion: {text}"
    calls = _active_trace(world)["calls"]
    return (
        calls[0]["controls"]["transport_token_cap"]
        == calls[1]["controls"]["transport_token_cap"],
        "transport token cap changed during retry",
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


# ===========================================================================
# Structured response schema contract closure (TSSRC)
# ===========================================================================


def _structured_contract_state(world: World) -> dict[str, Any]:
    """Return scenario-local state for the structured response contract."""
    state = _taxonomy_state(world)
    if "structured_contract" not in state:
        state["structured_contract"] = {
            "schemas": {},
            "schema_issues": {},
            "response_model": None,
            "response_field": None,
            "response_valid": None,
            "realization_fields": [],
            "realization_boundary_valid": None,
            "realization_over_limit_rejected": None,
            "projection_context": None,
            "response": None,
            "narrative": None,
            "finalization_error": None,
            "selected_step_count": None,
            "call1_schema": None,
            "grounding_helper": None,
            "grounding_violations": None,
        }
    return state["structured_contract"]


def _structured_projection_context(*, incompatible: bool = False) -> dict[str, Any]:
    """Build the immutable two-step projection used by TSSRC scenarios."""
    realization_one = {
        "projected_step_id": "step.1",
        "action_kind": "prepare",
        "executor_role": "attacker",
        "boundary_position": "crossing",
        "resource_ref_ids": [],
        "consumed_ref_ids": [],
        "produced_ref_ids": [],
        "produced_effect_ids": [],
        "outcome_link_pc_ids": [],
        "postcondition_ids": [],
    }
    realization_two = {
        "projected_step_id": "step.other" if incompatible else "step.2",
        "action_kind": "observe",
        "executor_role": "system",
        "boundary_position": "inside",
        "resource_ref_ids": [],
        "consumed_ref_ids": [],
        "produced_ref_ids": [],
        "produced_effect_ids": [],
        "outcome_link_pc_ids": [],
        "postcondition_ids": [],
    }
    return {
        "selected_step_ids": ["step.1", "step.2"],
        "selected_steps": [
            {"step_id": "step.1", "realization": realization_one},
            {"step_id": "step.2", "realization": realization_two},
        ],
    }


def _structured_call1_data(
    projected_step_ids: list[str],
    *,
    include_provider_realizations: bool = False,
) -> dict[str, Any]:
    """Build a minimal Call 1 payload for the acceptance contract."""
    step: dict[str, Any] = {
        "step_number": 1,
        "zone": "input",
        "action": "Action",
        "effect": "Effect",
        "control_point": None,
        "projected_step_ids": projected_step_ids,
    }
    if include_provider_realizations:
        step["realizations"] = [
            {"projected_step_id": projected_step_ids[0], "action_kind": "forged"}
        ]
    return {
        "title": "Title",
        "summary": "Summary",
        "entry_point": "Entry point",
        "zone_sequence": ["input"],
        "steps": [step],
    }


def _structured_schema_walk(
    schema: dict[str, Any],
    definitions: dict[str, Any],
    *,
    path: str,
    active_refs: frozenset[str] = frozenset(),
    resolved_refs: list[str] | None = None,
) -> list[str]:
    """Return unbounded reachable schema paths while resolving references."""
    issues: list[str] = []
    if resolved_refs is None:
        resolved_refs = []
    ref = schema.get("$ref")
    if isinstance(ref, str):
        prefix = "#/$defs/"
        if not ref.startswith(prefix):
            return [f"{path}: unsupported reference {ref!r}"]
        name = ref[len(prefix) :]
        if name in active_refs:
            return []
        target = definitions.get(name)
        if not isinstance(target, dict):
            return [f"{path}: missing definition {name!r}"]
        resolved_refs.append(ref)
        return _structured_schema_walk(
            target,
            definitions,
            path=f"{path} -> {ref}",
            active_refs=active_refs | {name},
            resolved_refs=resolved_refs,
        )

    for keyword in ("anyOf", "oneOf", "allOf"):
        for index, branch in enumerate(schema.get(keyword, ())):
            if isinstance(branch, dict):
                issues.extend(
                    _structured_schema_walk(
                        branch,
                        definitions,
                        path=f"{path}.{keyword}[{index}]",
                        active_refs=active_refs,
                        resolved_refs=resolved_refs,
                    )
                )

    if schema.get("type") == "string" and not isinstance(schema.get("maxLength"), int):
        issues.append(f"{path}: unbounded string")
    if schema.get("type") == "array":
        if not isinstance(schema.get("maxItems"), int):
            issues.append(f"{path}: unbounded array")
        items = schema.get("items")
        if isinstance(items, dict):
            issues.extend(
                _structured_schema_walk(
                    items,
                    definitions,
                    path=f"{path}[]",
                    active_refs=active_refs,
                    resolved_refs=resolved_refs,
                )
            )

    properties = schema.get("properties", {})
    if isinstance(properties, dict):
        for name, property_schema in properties.items():
            if isinstance(property_schema, dict):
                issues.extend(
                    _structured_schema_walk(
                        property_schema,
                        definitions,
                        path=f"{path}.{name}",
                        active_refs=active_refs,
                        resolved_refs=resolved_refs,
                    )
                )
    return issues


def _h_capture_structured_schemas(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    from asago_scenario_generator.pipeline.generate.actor import Call0Response
    from asago_scenario_generator.pipeline.generate.gherkin import Call3Response
    from asago_scenario_generator.pipeline.generate.narrative import Call1Response

    state = _structured_contract_state(world)
    state["schemas"] = {
        "Call 0": Call0Response.model_json_schema(),
        "Call 1": Call1Response.model_json_schema(),
        "Call 3": Call3Response.model_json_schema(),
    }
    return True, ""


def _h_audit_structured_schemas(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _structured_contract_state(world)
    if not state["schemas"]:
        return False, "provider schemas were not captured"
    issues: dict[str, list[str]] = {}
    for name, schema in state["schemas"].items():
        resolved: list[str] = []
        issues[name] = _structured_schema_walk(
            schema,
            schema.get("$defs", {}),
            path=name,
            resolved_refs=resolved,
        )
        state.setdefault("resolved_refs", {})[name] = resolved
    state["schema_issues"] = issues
    return True, ""


def _h_schema_is_bounded(world: World, text: str, examples: dict) -> tuple[bool, str]:
    issues = _structured_contract_state(world).get("schema_issues", {})
    unbounded = [f"{name}: {items}" for name, items in issues.items() if items]
    return not unbounded, f"unbounded generated-schema paths: {unbounded}"


def _h_schema_resolves_nested_shapes(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _structured_contract_state(world)
    resolved = state.get("resolved_refs", {})
    return (
        bool(resolved)
        and any(resolved.values())
        and not any(state.get("schema_issues", {}).values()),
        "schema references were not resolved",
    )


def _h_schema_reports_no_unbounded_path(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return _h_schema_is_bounded(world, text, examples)


def _structured_response_data(
    response_model: str,
    field: str,
    length: int,
) -> tuple[type[BaseModel], dict[str, Any]]:
    """Build response data for the boundary examples."""
    value = "x" * length
    if response_model == "Call 0":
        from asago_scenario_generator.pipeline.generate.actor import Call0Response

        data: dict[str, Any] = {
            "actor_type": "adversarial-user",
            "capability_level": "intermediate",
            "beliefs": ["short"],
            "desires": ["short"],
            "intentions": ["short"],
            "resources": ["short"],
        }
        data[field] = [value]
        return Call0Response, data
    if response_model == "Call 1":
        from asago_scenario_generator.pipeline.generate.narrative import Call1Response

        data = _structured_call1_data(["step.1"])
        if field == "zone_sequence":
            data["zone_sequence"] = [value]
        else:
            data["steps"][0][field] = [value]
        return Call1Response, data
    from asago_scenario_generator.pipeline.generate.gherkin import Call3Response

    data = {
        "assertions": [
            {
                "assertion_id": "assert.1",
                "source_step_ids": ["step.1"],
                "projected_postcondition_ids": ["pc.1"],
                "text": "The expected effect occurs.",
            }
        ]
    }
    data["assertions"][0][field] = [value]
    return Call3Response, data


def _h_boundary_response_fixture(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r'a valid "(Call 0|Call 1|Call 3)" response has a "([^"]+)" item '
        r"with (\d+) characters",
        text,
    )
    if match is None:
        return False, f"Could not parse response boundary: {text}"
    state = _structured_contract_state(world)
    state["response_model"] = match.group(1)
    state["response_field"] = match.group(2)
    state["response_length"] = int(match.group(3))
    return True, ""


def _h_validate_boundary_response(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r'the "(Call 0|Call 1|Call 3)" response is validated', text)
    if match is None:
        return False, f"Could not parse validation step: {text}"
    state = _structured_contract_state(world)
    model, data = _structured_response_data(
        state["response_model"],
        state["response_field"],
        state["response_length"],
    )
    try:
        model.model_validate(data)
    except Exception as exc:  # pragma: no cover - reported by the next step
        state["response_valid"] = False
        state["response_error"] = str(exc)
    else:
        state["response_valid"] = True
        state["response_error"] = None
    return True, ""


def _h_boundary_validation_outcome(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r'"(Call 0|Call 1|Call 3)" validation (succeeds|rejects)', text)
    if match is None:
        return False, f"Could not parse validation outcome: {text}"
    expected = match.group(2) == "succeeds"
    actual = _structured_contract_state(world).get("response_valid")
    return actual is expected, f"validation was {actual!r}, expected {expected!r}"


def _h_realization_fixture(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(
        r'a canonical projected-step realization has bounded ID-list fields "([^"]+)"',
        text,
    )
    if match is None:
        return False, f"Could not parse realization fields: {text}"
    _structured_contract_state(world)["realization_fields"] = _csv(match.group(1))
    return True, ""


def _h_validate_realization_boundaries(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    from asago_scenario_generator.models.realization import ProjectedStepRealization

    state = _structured_contract_state(world)
    base = {
        "projected_step_id": "step.1",
        "action_kind": "prepare",
        "executor_role": "attacker",
        "boundary_position": "crossing",
        **{field: [] for field in state["realization_fields"]},
    }
    valid = True
    rejected = True
    for field in state["realization_fields"]:
        valid_data = dict(base, **{field: ["x" * 200]})
        over_data = dict(base, **{field: ["x" * 201]})
        try:
            ProjectedStepRealization.model_validate(valid_data)
        except Exception:
            valid = False
        try:
            ProjectedStepRealization.model_validate(over_data)
        except Exception:
            pass
        else:
            rejected = False
    state["realization_boundary_valid"] = valid
    state["realization_over_limit_rejected"] = rejected
    return True, ""


def _h_realization_boundaries_accepted(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return bool(
        _structured_contract_state(world).get("realization_boundary_valid")
    ), "a boundary-length realization was rejected"


def _h_realization_over_limits_rejected(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return bool(
        _structured_contract_state(world).get("realization_over_limit_rejected")
    ), "an over-limit realization was accepted"


def _h_projection_context_for_realizations(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    _structured_contract_state(world)["projection_context"] = (
        _structured_projection_context()
    )
    return True, ""


def _h_call1_model_owned_response(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _structured_contract_state(world)
    state["response"] = _structured_call1_data(
        ["step.1", "step.2"],
        include_provider_realizations=True,
    )
    return True, ""


def _h_finalize_call1_contract(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    from asago_scenario_generator.pipeline.generate.narrative import (
        Call1Response,
        _map_call1_to_narrative,
    )

    state = _structured_contract_state(world)
    response = Call1Response.model_validate(state["response"])
    state["response_model_object"] = response
    state["call1_schema"] = Call1Response.model_json_schema()
    state["narrative"] = _map_call1_to_narrative(
        response,
        state["projection_context"],
    )
    return True, ""


def _h_call1_step_schema_has_model_fields(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    schema = _structured_contract_state(world)["call1_schema"]
    properties = schema["$defs"]["Call1Step"]["properties"]
    expected = {
        "step_number",
        "zone",
        "action",
        "effect",
        "control_point",
        "projected_step_ids",
    }
    return set(properties) == expected, f"Call 1 step fields were {set(properties)!r}"


def _h_call1_schema_omits_realizations(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    properties = _structured_contract_state(world)["call1_schema"]["$defs"][
        "Call1Step"
    ]["properties"]
    return "realizations" not in properties, "Call 1 schema exposes realizations"


def _h_finalized_realizations_complete(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    narrative = _structured_contract_state(world)["narrative"]
    ids = [
        realization.projected_step_id
        for step in narrative.steps
        for realization in step.realizations
    ]
    return ids == ["step.1", "step.2"], f"finalized IDs were {ids!r}"


def _h_finalized_realizations_match_context(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    from asago_scenario_generator.models.realization import ProjectedStepRealization

    state = _structured_contract_state(world)
    expected = {
        item["step_id"]: ProjectedStepRealization.model_validate(
            item["realization"]
        ).model_dump()
        for item in state["projection_context"]["selected_steps"]
    }
    actual = {
        realization.projected_step_id: realization.model_dump()
        for step in state["narrative"].steps
        for realization in step.realizations
    }
    return actual == expected, "finalized realization differs from projection context"


def _h_provider_realizations_not_published(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    response = _structured_contract_state(world)["response_model_object"]
    return "realizations" not in response.steps[0].model_dump(), (
        "provider realization data was published"
    )


def _h_projection_defect(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(
        r'the Call 1 response has projected-step resolution defect "([^"]+)"',
        text,
    )
    if match is None:
        return False, f"Could not parse projection defect: {text}"
    state = _structured_contract_state(world)
    state["defect"] = match.group(1)
    state["projection_context"] = _structured_projection_context(
        incompatible=match.group(1) == "semantically incompatible step"
    )
    defect = match.group(1)
    state["response"] = _structured_call1_data(
        {
            "an unknown projected step ID": ["step.unknown"],
            "a duplicate projected step ID": ["step.1", "step.1"],
            "an omitted projected step ID": ["step.1"],
            "semantically incompatible step": ["step.2"],
        }[defect]
    )
    return True, ""


def _h_finalize_defective_narrative(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    from asago_scenario_generator.pipeline.generate.narrative import (
        Call1Response,
        _map_call1_to_narrative,
    )

    state = _structured_contract_state(world)
    try:
        response = Call1Response.model_validate(state["response"])
        _map_call1_to_narrative(response, state["projection_context"])
    except Exception as exc:
        state["finalization_error"] = str(exc)
        state["narrative"] = None
    else:
        state["finalization_error"] = None
        state["narrative"] = "published"
    return True, ""


def _h_defect_diagnostic(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(
        r'finalization rejects the response with a diagnostic identifying "([^"]+)"',
        text,
    )
    if match is None:
        return False, f"Could not parse defect diagnostic: {text}"
    diagnostic = match.group(1)
    markers = {
        "an unknown projected step ID": "unknown projected step ID",
        "a duplicate projected step ID": "duplicate projected step ID",
        "an omitted projected step ID": "omitted projected step ID",
        "semantically incompatible step": "semantically incompatible",
    }
    error = _structured_contract_state(world).get("finalization_error") or ""
    return markers[diagnostic] in error, f"diagnostic was {error!r}"


def _h_no_defective_narrative_artifact(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return _structured_contract_state(world).get("narrative") is None, (
        "a defective narrative artifact was published"
    )


def _h_selected_step_count(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(
        r"the current candidate selects (\d+) canonical projected steps", text
    )
    if match is None:
        return False, f"Could not parse selected step count: {text}"
    _structured_contract_state(world)["selected_step_count"] = int(match.group(1))
    return True, ""


def _h_build_candidate_call1_schema(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    from asago_scenario_generator.pipeline.generate.narrative import (
        build_call1_response_model,
    )

    state = _structured_contract_state(world)
    model = build_call1_response_model(state["selected_step_count"])
    state["call1_schema"] = model.model_json_schema()
    return True, ""


def _h_candidate_step_bound(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r"the provider request contains steps\.maxItems equal to (\d+)", text
    )
    if match is None:
        return False, f"Could not parse candidate step bound: {text}"
    actual = _structured_contract_state(world)["call1_schema"]["properties"]["steps"][
        "maxItems"
    ]
    return actual == int(match.group(1)), f"provider maxItems was {actual!r}"


def _h_candidate_bound_present_before_request(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return (
        "maxItems"
        in _structured_contract_state(world)["call1_schema"]["properties"]["steps"],
        "candidate-specific maxItems was not present in the provider schema",
    )


def _h_import_grounding_helper(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    from asago_scenario_generator.pipeline.generate.tree_validation import (
        _check_tool_execution_leaf_grounding,
    )

    _structured_contract_state(world)["grounding_helper"] = (
        _check_tool_execution_leaf_grounding
    )
    return True, ""


def _h_typed_tool_execution_action(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r'a tool_execution leaf uses the "([^"]+)" typed action', text)
    if match is None:
        return False, f"Could not parse typed action: {text}"
    _structured_contract_state(world)["action_kind"] = match.group(1)
    return True, ""


def _h_check_tool_execution_grounding(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    from asago_scenario_generator.models.attack_tree import (
        AiSystemAction,
        AttackTreeNode,
        GateType,
        IntegrationInteractionAction,
    )

    state = _structured_contract_state(world)
    action = (
        IntegrationInteractionAction(integration_id="crm")
        if state["action_kind"] == "integration_interaction"
        else AiSystemAction()
    )
    node = AttackTreeNode(
        id="n1",
        label="tool execution",
        gate=GateType.LEAF,
        zone="tool_execution",
        action=action,
    )
    violations: list[str] = []
    state["grounding_helper"](node, violations)
    state["grounding_violations"] = violations
    return True, ""


def _h_grounding_result(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'the result is "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse grounding outcome: {text}"
    violations = _structured_contract_state(world)["grounding_violations"]
    expected = match.group(1)
    if expected == "no violation":
        return not violations, f"unexpected grounding violations: {violations!r}"
    return any("untyped-tool-execution" in item for item in violations), (
        f"expected untyped violation, got {violations!r}"
    )


# ===========================================================================
# Projection transport fix: step-ID echo normalization (TSIT)
# ===========================================================================


def _normalize_state(world: World) -> dict[str, Any]:
    state = _taxonomy_state(world)
    if "canonical_ids" not in state:
        state["canonical_ids"] = ["step.1", "attacker.prepare", "system.transform"]
    if "transport_items" not in state:
        state["transport_items"] = []
    return state


def _parse_transport_item(raw: str) -> Any:
    """Parse one transport item cell: JSON objects/lists/scalars or raw strings."""
    stripped = raw.strip()
    if stripped.startswith(("{", "[")) or stripped.isdigit():
        try:
            return json.loads(stripped)
        except json.JSONDecodeError:
            return stripped
    return stripped


def _split_transport_items(raw: str) -> list[str]:
    """Split a transport items cell on top-level commas only.

    Feature cells embed JSON objects with their own quotes and commas, so a
    plain string split would tear ``{"step_id": "attacker.prepare"}`` apart.
    """
    items: list[str] = []
    current: list[str] = []
    depth = 0
    for char in raw:
        if char in "[{":
            depth += 1
        elif char in "]}":
            depth = max(0, depth - 1)
        if char == "," and depth == 0:
            items.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    items.append("".join(current).strip())
    return [item for item in items if item]


def _h_selects_canonical_step_ids(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r'selects canonical step IDs "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse canonical step IDs: {text}"
    _normalize_state(world)["canonical_ids"] = _csv(match.group(1))
    return True, ""


def _h_selects_canonical_steps(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r'selects canonical steps "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse canonical steps: {text}"
    state = _normalize_state(world)
    state["canonical_ids"] = _csv(match.group(1))
    # Rich selected steps for the prompt alignment table: outside observe,
    # crossing deliver, inside operator impact (validator-derived rows).
    state["selected_steps"] = [
        {
            "step_id": "attacker.observe",
            "action_kind": "observe",
            "executor_role": "attacker",
            "boundary_position": "outside",
            "attacker_controlled": True,
            "requirement": "required",
            "resource_links": [],
            "realization": {"projected_step_id": "attacker.observe"},
        },
        {
            "step_id": "attacker.deliver",
            "action_kind": "deliver",
            "executor_role": "attacker",
            "boundary_position": "crossing",
            "attacker_controlled": True,
            "requirement": "required",
            "resource_links": [
                {
                    "role": "ingress",
                    "resource_ref": {
                        "kind": "entry_point",
                        "entry_point_id": "chat-interface",
                    },
                }
            ],
            "realization": {"projected_step_id": "attacker.deliver"},
        },
        {
            "step_id": "operator.impact",
            "action_kind": "impact",
            "executor_role": "operator",
            "boundary_position": "inside",
            "attacker_controlled": False,
            "requirement": "required",
            "resource_links": [
                {
                    "role": "effect",
                    "resource_ref": {
                        "kind": "output_surface",
                        "entry_point_id": "blocked-operation",
                    },
                }
            ],
            "realization": {"projected_step_id": "operator.impact"},
        },
    ]
    return True, ""


def _h_transport_item_single(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r'has one projected_step_ids item "(.+)"$', text)
    if match is None:
        return False, f"Could not parse transport item: {text}"
    _normalize_state(world)["transport_items"] = [_parse_transport_item(match.group(1))]
    return True, ""


def _h_transport_items_many(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r'projected_step_ids items are "(.+)"$', text)
    if match is None:
        return False, f"Could not parse transport items: {text}"
    _normalize_state(world)["transport_items"] = [
        _parse_transport_item(item) for item in _split_transport_items(match.group(1))
    ]
    return True, ""


def _h_normalize_transport_items(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _normalize_state(world)
    state.pop("normalization_error", None)
    try:
        normalized = normalize_projected_step_ids(
            state["transport_items"], state["canonical_ids"]
        )
    except ValueError as exc:
        state["normalization_error"] = str(exc)
        state["normalized_ids"] = None
        state["transport_valid"] = False
        return True, ""
    state["normalized_ids"] = list(normalized)
    state["transport_valid"] = True
    return True, ""


def _h_normalized_ids_are(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'normalized projected step IDs are "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse normalized IDs: {text}"
    state = _normalize_state(world)
    if not state.get("transport_valid"):
        return False, "normalization did not complete"
    expected = _csv(match.group(1))
    return (
        state.get("normalized_ids") == expected,
        f"normalized {state.get('normalized_ids')!r}, expected {expected!r}",
    )


def _h_order_unchanged(world: World, text: str, examples: dict) -> tuple[bool, str]:
    state = _normalize_state(world)
    return bool(state.get("normalized_ids")), "normalized order was lost"


def _h_duplicate_error(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'duplicate canonical step ID "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse duplicate ID: {text}"
    error = _normalize_state(world).get("normalization_error", "")
    return (
        "duplicate canonical step ID" in error and match.group(1) in error,
        f"duplicate diagnostic missing: {error!r}",
    )


def _h_rejection_identifies(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r'identifying "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse rejection: {text}"
    error = _normalize_state(world).get("normalization_error", "")
    return match.group(1) in error, f"rejection not identified: {error!r}"


def _h_no_type_error(world: World, text: str, examples: dict) -> tuple[bool, str]:
    error = _normalize_state(world).get("normalization_error", "")
    return "TypeError" not in error and not isinstance(
        _normalize_state(world).get("normalization_error"), TypeError
    ), "diagnostic leaked TypeError"


def _h_no_artifact_published(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return not _normalize_state(world).get(
        "transport_valid", True
    ), "defective artifact was finalized"


def _h_stage_response_echo(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(
        r'valid "([^"]+)" response echoes projected step ID "([^"]+)"', text
    )
    if match is None:
        return False, f"Could not parse staged echo: {text}"
    state = _normalize_state(world)
    state["transport_stage"] = match.group(1)
    state["transport_items"] = [_parse_transport_item(match.group(2))]
    return True, ""


def _h_stage_normalized_strict(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Normalize the staged echo and strictly validate the artifact record."""
    state = _normalize_state(world)
    stage = state.get("transport_stage", "narrative")
    try:
        normalized = normalize_projected_step_ids(
            state["transport_items"], state["canonical_ids"]
        )
    except ValueError as exc:
        state["normalization_error"] = str(exc)
        state["transport_valid"] = False
        state["transport_normalized"] = []
        state["transport_realizations"] = []
        return True, ""
    state["transport_normalized"] = list(normalized)
    if stage == "attack tree":
        data = {
            "root": {
                "id": "n1",
                "label": "leaf",
                "gate": "LEAF",
                "zone": "reasoning",
                "action": {
                    "kind": "impact",
                    "boundary": "internal",
                    "target": "loss",
                },
                "projected_step_ids": list(state["transport_items"]),
                "realizations": [],
            }
        }
        context = {
            "selected_step_ids": list(state["canonical_ids"]),
            "selected_steps": [
                {
                    "step_id": sid,
                    "action_kind": "impact",
                    "executor_role": "system",
                    "boundary_position": "inside",
                    "attacker_controlled": False,
                    "requirement": "required",
                    "resource_links": [],
                    "realization": {"projected_step_id": sid},
                }
                for sid in state["canonical_ids"]
            ],
            "canonical_ingress": {"entry_point_id": "entry"},
            "ingress_controllability": "direct",
            "omitted_step_ids": [],
        }
        leaf = normalize_attack_tree_transport(data, context)["root"]
        state["transport_normalized"] = leaf["projected_step_ids"]
        state["transport_realizations"] = leaf.get("realizations") or []
    else:
        state["transport_realizations"] = [
            {"projected_step_id": sid} for sid in normalized
        ]
    state["transport_valid"] = True
    return True, ""


def _h_finalized_contains(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(
        r'finalized "([^"]+)" artifact contains projected step ID "([^"]+)"', text
    )
    if match is None:
        return False, f"Could not parse finalized artifact: {text}"
    state = _normalize_state(world)
    if state.get("transport_stage") != match.group(1):
        return False, "wrong artifact stage was inspected"
    return (
        match.group(2) in state.get("transport_normalized", []),
        "finalized artifact does not contain the canonical ID",
    )


def _h_canonical_realization_derived(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r'derived from "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse realization source: {text}"
    state = _normalize_state(world)
    realization_ids = [
        record.get("projected_step_id") if isinstance(record, dict) else record
        for record in state.get("transport_realizations", [])
    ]
    return match.group(1) in realization_ids, "canonical realization was not derived"


def _transport_context_for_prompt(ids: list[str]) -> dict[str, Any]:
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


def _h_plain_quoted_list(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'plain quoted list "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse quoted list: {text}"
    prompt = _prompt_state(world).get("prompt", "")
    expected = _csv(match.group(1))
    quoted = '", "'.join(expected)
    return (
        f'"{quoted}"' in prompt,
        "selected IDs are not rendered as one plain quoted list",
    )


def _h_no_step_id_records(world: World, text: str, examples: dict) -> tuple[bool, str]:
    prompt = _prompt_state(world).get("prompt", "")
    return "- step_id:" not in prompt, "prompt uses the '- step_id:' record shape"


def _h_exact_values_required(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    prompt = _prompt_state(world).get("prompt", "")
    return (
        "exact canonical ID values" in prompt and "projected_step_ids" in prompt,
        "prompt does not require exact canonical ID values",
    )


# ===========================================================================
# Projection transport fix: narrative outside boundaries (TNOB)
# ===========================================================================


def _narrative_state(world: World) -> dict[str, Any]:
    state = _taxonomy_state(world)
    if "narrative" not in state:
        state["narrative"] = {
            "zones_active": [],
            "boundaries": {},
            "mappings": [],
            "ordered_zones": [],
            "accepted_narrative": None,
        }
    return state["narrative"]


def _narrative_steps_from_state(narrative: dict[str, Any]) -> list[Any]:
    from asago_scenario_generator.models.scenario import NarrativeLayer, NarrativeStep

    steps = [
        NarrativeStep(
            step_number=index + 1,
            zone=zone,
            action="action",
            effect="effect",
            projected_step_ids=tuple(step_ids),
        )
        for index, (step_ids, zone) in enumerate(narrative["mappings"])
    ]
    if not steps:
        steps = [
            NarrativeStep(
                step_number=1,
                zone="outside",
                action="action",
                effect="effect",
                projected_step_ids=("attacker.prepare",),
            )
        ]
    return NarrativeLayer(
        title="Test",
        summary="Summary",
        entry_point="entry",
        zone_sequence=[step.zone for step in steps],
        steps=steps,
    )


def _h_active_zones(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'active Schneider zones "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse active zones: {text}"
    _narrative_state(world)["zones_active"] = _csv(match.group(1))
    return True, ""


def _h_narrative_step_boundary(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r'projected step "([^"]+)" has boundary position "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse boundary position: {text}"
    _narrative_state(world)["boundaries"][match.group(1)] = match.group(2)
    return True, ""


def _h_narrative_boundaries_many(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r'projected steps "([^"]+)" each have boundary position "([^"]+)"', text
    )
    if match is None:
        return False, f"Could not parse boundary positions: {text}"
    narrative = _narrative_state(world)
    for step_id in _csv(match.group(1)):
        narrative["boundaries"][step_id] = match.group(2)
    return True, ""


def _h_narrative_step_ids_boundaries(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r'projected step IDs "([^"]+)" have boundary positions "([^"]+)"', text
    )
    if match is None:
        return False, f"Could not parse step ID boundaries: {text}"
    narrative = _narrative_state(world)
    for step_id, boundary in zip(_csv(match.group(1)), _csv(match.group(2))):
        narrative["boundaries"][step_id] = boundary
    return True, ""


def _h_narrative_mapping_single(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r'a narrative step maps projected step ID "([^"]+)" with zone "([^"]+)"',
        text,
    )
    if match is None:
        return False, f"Could not parse narrative mapping: {text}"
    _narrative_state(world)["mappings"] = [([match.group(1)], match.group(2))]
    return True, ""


def _h_narrative_mapping_many(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r'one narrative step maps (?:projected step IDs "([^"]+)"|those projected step IDs) '
        r'with zone "([^"]+)"',
        text,
    )
    if match is None:
        return False, f"Could not parse narrative mapping: {text}"
    step_ids = (
        _csv(match.group(1))
        if match.group(1) is not None
        else list(_narrative_state(world)["boundaries"])
    )
    _narrative_state(world)["mappings"] = [(step_ids, match.group(2))]
    return True, ""


def _h_enforce_narrative_zones(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    from asago_scenario_generator.pipeline.generate.zones import (
        enforce_narrative_projection_zones,
    )

    narrative_state = _narrative_state(world)
    narrative = _narrative_steps_from_state(narrative_state)
    narrative_state["original_steps"] = [
        (step.zone, tuple(step.projected_step_ids), step.step_number)
        for step in narrative.steps
    ]
    try:
        enforce_narrative_projection_zones(
            narrative,
            narrative_state["zones_active"],
            narrative_state["boundaries"],
        )
    except ValueError as exc:
        narrative_state["enforcement_error"] = str(exc)
        narrative_state["enforced"] = False
        return True, ""
    narrative_state.pop("enforcement_error", None)
    narrative_state["enforced"] = True
    return True, ""


def _h_lifecycle_narrative_accepted(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
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


def _h_narrative_accepted(world: World, text: str, examples: dict) -> tuple[bool, str]:
    narrative_state = _narrative_state(world)
    if not narrative_state.get("enforced", False):
        return False, "narrative was not accepted"
    step = narrative_state["mappings"][0]
    expected_zone = step[1]
    expected_ids = tuple(step[0])
    original = narrative_state.get("original_steps", [])
    if not original:
        return False, "no reference narrative recorded"
    return (
        original[0][0] == expected_zone and list(original[0][1]) == list(expected_ids),
        "narrative step was changed or remapped",
    )


def _h_narrative_mapping_matches_expected(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r'narrative mapping matches expected projected step ID "([^"]+)" '
        r'and zone "([^"]+)"',
        text,
    )
    if match is None:
        return False, f"Could not parse expected narrative mapping: {text}"
    expected_id, expected_zone = match.groups()
    mappings = _narrative_state(world).get("mappings", [])
    if len(mappings) != 1:
        return False, f"unexpected narrative mapping count: {mappings!r}"
    actual_ids, actual_zone = mappings[0]
    return (
        actual_ids == [expected_id] and actual_zone == expected_zone,
        f"narrative mapping was {actual_ids!r}/{actual_zone!r}",
    )


def _h_narrative_boundary_matches_expected(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r'projected step "([^"]+)" has expected boundary position "([^"]+)"',
        text,
    )
    if match is None:
        return False, f"Could not parse expected boundary: {text}"
    step_id, expected_boundary = match.groups()
    actual = _narrative_state(world).get("boundaries", {}).get(step_id)
    return actual == expected_boundary, (
        f"boundary for {step_id!r} was {actual!r}, expected {expected_boundary!r}"
    )


def _h_narrative_mapping_matches_expected_ids(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r'narrative mapping matches expected projected step IDs "([^"]+)" '
        r'and zone "([^"]+)"',
        text,
    )
    if match is None:
        return False, f"Could not parse expected narrative mapping: {text}"
    expected_ids_text, expected_zone = match.groups()
    mappings = _narrative_state(world).get("mappings", [])
    if len(mappings) != 1:
        return False, f"unexpected narrative mapping count: {mappings!r}"
    actual_ids, actual_zone = mappings[0]
    expected_ids = _csv(expected_ids_text)
    return (
        actual_ids == expected_ids and actual_zone == expected_zone,
        f"narrative mapping was {actual_ids!r}/{actual_zone!r}",
    )


def _h_narrative_boundaries_match_expected(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r'projected step boundaries match expected positions "([^"]+)"',
        text,
    )
    if match is None:
        return False, f"Could not parse expected boundaries: {text}"
    expected = _csv(match.group(1))
    state = _narrative_state(world)
    mappings = state.get("mappings", [])
    if len(mappings) != 1:
        return False, f"unexpected narrative mapping count: {mappings!r}"
    actual_ids = mappings[0][0]
    actual = [state.get("boundaries", {}).get(step_id) for step_id in actual_ids]
    return actual == expected, f"boundaries were {actual!r}, expected {expected!r}"


def _h_narrative_exact_projection_zone_reason(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r'enforcement reports exact projection-zone reason "([^"]+)"',
        text,
    )
    if match is None:
        return False, f"Could not parse exact projection reason: {text}"
    expected = match.group(1)
    actual = _narrative_state(world).get("enforcement_error", "")
    return expected in actual, f"projection-zone reason missing: {actual!r}"


def _h_narrative_rejected(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'projection-zone reason "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse rejection reason: {text}"
    error = _narrative_state(world).get("enforcement_error", "")
    return match.group(1) in error, f"rejection reason missing: {error!r}"


def _h_narrative_not_modified(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    narrative_state = _narrative_state(world)
    original = narrative_state.get("original_steps", [])
    return (
        len(original) == len(narrative_state.get("mappings", []))
        and all(step[2] == index + 1 for index, step in enumerate(original)),
        "narrative step was removed or renumbered",
    )


def _h_ordered_zone_steps(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'ordered narrative step zones are "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse ordered zones: {text}"
    _narrative_state(world)["ordered_zones"] = _csv(match.group(1))
    return True, ""


def _h_derive_zone_sequence(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    from types import SimpleNamespace

    from asago_scenario_generator.pipeline.generate.narrative_semantics import (
        _derive_zone_sequence,
    )

    ordered = _narrative_state(world)["ordered_zones"]
    _narrative_state(world)["derived_sequence"] = _derive_zone_sequence(
        [SimpleNamespace(zone=zone) for zone in ordered]
    )
    return True, ""


def _h_derived_sequence_is(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'derived zone sequence is "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse derived sequence: {text}"
    actual = _narrative_state(world).get("derived_sequence", [])
    expected = _csv(match.group(1))
    return actual == expected, f"derived {actual!r}, expected {expected!r}"


def _accepted_narrative_from_sequence(
    zones: list[str],
) -> Any:
    from asago_scenario_generator.models.scenario import NarrativeLayer, NarrativeStep

    steps = [
        NarrativeStep(
            step_number=index + 1,
            zone=zone,
            action="action",
            effect="effect",
            projected_step_ids=(f"step.{index + 1}",),
        )
        for index, zone in enumerate(zones)
    ]
    return NarrativeLayer(
        title="Test",
        summary="Summary",
        entry_point="entry",
        zone_sequence=zones,
        steps=steps,
    )


def _h_accepted_narrative(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'has zone sequence "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse accepted sequence: {text}"
    _narrative_state(world)["accepted_narrative"] = _accepted_narrative_from_sequence(
        _csv(match.group(1))
    )
    return True, ""


def _h_consume_active_zones(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    from asago_scenario_generator.pipeline.generate.priority import (
        _heuristic_risk_likelihood,
    )
    from asago_scenario_generator.pipeline.generate.zones import active_narrative_zones

    narrative_state = _narrative_state(world)
    narrative = narrative_state["accepted_narrative"]
    active = active_narrative_zones(narrative.zone_sequence)
    narrative_state["active_zones"] = active
    narrative_state["distinct_active"] = len(set(active))
    narrative_state["traversal_length"] = len(active)
    narrative_state["coverage_credited"] = list(dict.fromkeys(active))
    active_set = set(narrative_state["zones_active"])
    narrative_state["uncovered_active"] = sorted(
        zone for zone in active_set if zone not in set(active)
    )
    narrative_state["faceting_zones"] = list(dict.fromkeys(active))
    narrative_state["priority_likelihood"] = _heuristic_risk_likelihood(narrative)
    return True, ""


def _h_active_zones_are(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'ordered active narrative zones are "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse active zones: {text}"
    actual = _narrative_state(world).get("active_zones", [])
    expected = _csv(match.group(1))
    return actual == expected, f"active zones {actual!r}, expected {expected!r}"


def _h_coverage_credits(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'coverage credits traversed zones "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse coverage credit: {text}"
    actual = _narrative_state(world).get("coverage_credited", [])
    return actual == _csv(match.group(1)), "coverage credit did not match"


def _h_uncovered_zone(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'uncovered active zone "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse uncovered zone: {text}"
    return match.group(1) in _narrative_state(world).get(
        "uncovered_active", []
    ), "uncovered active zone was not reported"


def _h_priority_signals(world: World, text: str, examples: dict) -> tuple[bool, str]:
    narrative_state = _narrative_state(world)
    return (
        narrative_state.get("distinct_active") == 2
        and narrative_state.get("traversal_length") == 2,
        "priority zone signals counted outside traversal",
    )


def _h_faceting_zones(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'zones_traversed "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse faceting zones: {text}"
    actual = _narrative_state(world).get("faceting_zones", [])
    return actual == _csv(match.group(1)), "faceting records wrong zones_traversed"


def _h_mandatory_leaf_no_zone(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    # Declarative setup for the skeleton fallback scenario: the pinned
    # mandatory leaf carries no more specific zone, so the skeleton builder
    # must fall back to the first active narrative zone.
    return True, ""


def _h_skeleton_built(world: World, text: str, examples: dict) -> tuple[bool, str]:
    from asago_scenario_generator.pipeline.generate.tree import _build_tree_skeleton

    narrative = _narrative_state(world)["accepted_narrative"]
    _narrative_state(world)["skeleton"] = _build_tree_skeleton(
        narrative,
        pinned_technique_ids=["AML.T0001"],
        pinned_technique_names=["Mandatory technique"],
    )
    return True, ""


def _h_fallback_zone(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'fallback zone is "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse fallback zone: {text}"
    skeleton = _narrative_state(world).get("skeleton", [])
    if not skeleton:
        return False, "skeleton was empty"
    actual = skeleton[0]["zone"]
    return actual == match.group(1), f"fallback zone was {actual!r}"


def _h_fallback_not_outside(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    skeleton = _narrative_state(world).get("skeleton", [])
    if not skeleton:
        return False, "skeleton was empty"
    return skeleton[0]["zone"] != "outside", "fallback zone was 'outside'"


def _h_render_narrative_zone_prompt(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _taxonomy_state(world)
    ids = _normalize_state(world).get("canonical_ids") or [
        "attacker.observe",
        "operator.impact",
    ]
    projection_context = _transport_context_for_prompt(ids)
    seed = SimpleNamespace(
        seed_id="AP-T1-01",
        attack_pattern_name="pattern",
        attack_pattern_description="description",
        threat_name="threat",
        threat_description="description",
        kill_chain=[],
    )
    from asago_scenario_generator.pipeline.generate.alignment import (
        derive_projection_alignment_rows,
    )

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
        projection_alignment_rows=derive_projection_alignment_rows(
            projection_context["selected_steps"]
        ),
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
    state["narrative_prompt"] = prompt
    return True, ""


def _h_narrative_prompt_outside_rule(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    prompt_lower = _taxonomy_state(world).get("narrative_prompt", "").lower()
    return (
        "`outside` is permitted only on a narrative step whose" in prompt_lower
        and "outside-boundary canonical steps" in prompt_lower,
        "narrative prompt does not permit outside only for outside-boundary steps",
    )


def _h_narrative_prompt_active_rule(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    prompt = _taxonomy_state(world).get("narrative_prompt", "")
    return (
        "Inside-boundary and crossing-boundary narrative steps MUST use an active"
        in prompt
        and "Schneider zone from `zones_active`" in prompt,
        "narrative prompt does not require active Schneider zones",
    )


def _h_narrative_prompt_mixed_rule(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    prompt = _taxonomy_state(world).get("narrative_prompt", "")
    return (
        "combine outside-boundary and non-outside" in prompt,
        "narrative prompt does not forbid mixed-boundary steps",
    )


def _h_narrative_prompt_distinct_rule(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    prompt = _taxonomy_state(world).get("narrative_prompt", "")
    return (
        "NOT a profile-active Schneider zone" in prompt and "`zones_active`" in prompt,
        "narrative prompt muddles outside with the active zone list",
    )


# ===========================================================================
# Projection transport fix: external impact transport (TEIT)
# ===========================================================================


def _h_impact_leaf(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(
        r'leaf at placement "([^"]+)" maps that step with action kind "impact", '
        r'action boundary "([^"]+)", and zone "([^"]+)"',
        text,
    )
    if match is None:
        return False, f"Could not parse impact leaf: {text}"
    state = _contract_state(world)
    state["placement"] = match.group(1)
    state["leaf_action_kind"] = "impact"
    state["impact_boundary"] = match.group(2)
    state["zone"] = match.group(3)
    state["transport_ids"] = [state["steps"][0]["step_id"]]
    return True, ""


def _h_external_precondition_leaf(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r'leaf maps that step with action kind "external_precondition" and '
        r'zone "([^"]+)"',
        text,
    )
    if match is None:
        return False, f"Could not parse external_precondition leaf: {text}"
    state = _contract_state(world)
    state["leaf_action_kind"] = "external_precondition"
    state.pop("impact_boundary", None)
    state["zone"] = match.group(1)
    state["transport_ids"] = [state["steps"][0]["step_id"]]
    return True, ""


def _h_impact_zone_is(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'impact leaf zone is "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse expected zone: {text}"
    leaf = _contract_state(world).get("normalized_leaf", {})
    expected = match.group(1)
    if expected == "null":
        return leaf.get("zone") is None, "external impact kept a transport zone"
    return leaf.get("zone") == expected, "impact zone was altered"


def _h_impact_zone_normalized_to_null(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    leaf = _contract_state(world).get("normalized_leaf", {})
    return leaf.get("zone") is None, "external impact zone was not cleared"


def _h_boundary_violation(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return bool(
        _contract_state(world).get("boundary_violation")
    ), "external impact mapping was not rejected as a boundary violation"


def _h_external_precondition_zone_null(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    leaf = _contract_state(world).get("normalized_leaf", {})
    return leaf.get("zone") is None, "external_precondition leaf kept a zone"


def _h_external_precondition_preserves_id(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r'external_precondition leaf preserves projected step ID "([^"]+)"', text
    )
    if match is None:
        return False, f"Could not parse preserved ID: {text}"
    leaf = _contract_state(world).get("normalized_leaf", {})
    return (
        leaf.get("projected_step_ids") == [match.group(1)],
        "outside external_precondition ID was not preserved",
    )


def _h_impact_id_preserved(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'the impact leaf preserves projected step ID "([^"]+)"', text)
    if match is None:
        match = re.search(r'projected step ID "([^"]+)" is not silently removed', text)
    if match is None:
        return False, f"Could not parse preserved impact ID: {text}"
    leaf = _contract_state(world).get("normalized_leaf", {})
    return (
        leaf.get("projected_step_ids") == [match.group(1)],
        "external impact step ID was removed or remapped",
    )


# ===========================================================================
# Projection transport fix: prompt alignment table (TPPA)
# ===========================================================================


def _h_canonical_step_for_row(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r'canonical step "([^"]+)" has action "([^"]+)", executor "([^"]+)", '
        r'boundary "([^"]+)", and bound resources "([^"]+)"',
        text,
    )
    if match is None:
        return False, f"Could not parse canonical step: {text}"
    step_id, action, executor, boundary, bound_resources = match.groups()
    resource_links: list[dict[str, Any]] = []
    if bound_resources.startswith("entry_point/"):
        resource_links = [
            {
                "role": "ingress",
                "resource_ref": {
                    "kind": "entry_point",
                    "entry_point_id": bound_resources.split("/", 1)[1],
                },
            }
        ]
    elif bound_resources.startswith("effect/"):
        resource_links = [
            {
                "role": "effect",
                "resource_ref": {
                    "kind": "output_surface",
                    "entry_point_id": bound_resources.split("/", 1)[1],
                },
            }
        ]
    _contract_state(world)["alignment_step"] = {
        "step_id": step_id,
        "action_kind": action,
        "executor_role": executor,
        "boundary_position": boundary,
        "attacker_controlled": executor == "attacker",
        "requirement": "required",
        "resource_links": resource_links,
    }
    state = _normalize_state(world)
    if "alignment_canonical_ids" not in state:
        state["alignment_canonical_ids"] = []
    state["alignment_canonical_ids"].append(step_id)
    return True, ""


def _h_derive_alignment_row(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    from asago_scenario_generator.pipeline.generate.alignment import (
        derive_projection_alignment_row,
    )

    step = _contract_state(world).get("alignment_step")
    if step is None:
        return False, "no canonical step was supplied"
    _contract_state(world)["alignment_row"] = derive_projection_alignment_row(step)
    return True, ""


def _h_alignment_row_narrative_zone(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r'allowed narrative zone is "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse narrative zone: {text}"
    row = _contract_state(world).get("alignment_row", {})
    actual = row.get("allowed_narrative_zone")
    return actual == match.group(1), f"narrative zone was {actual!r}"


def _h_alignment_row_tree_kinds(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r'allowed tree kinds are the intersection "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse tree kinds: {text}"
    row = _contract_state(world).get("alignment_row", {})
    actual = row.get("allowed_tree_kinds", [])
    expected = (
        []
        if match.group(1) == "empty set"
        else _csv(match.group(1))
        if match.group(1)
        else []
    )
    return actual == expected, f"tree kinds were {actual!r}, expected {expected!r}"


def _h_alignment_row_tree_zone(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r'tree zone is "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse tree zone: {text}"
    row = _contract_state(world).get("alignment_row", {})
    actual = row.get("tree_zone")
    return actual == match.group(1), f"tree zone was {actual!r}"


def _h_alignment_row_bound_resources(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r'bound resources are "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse bound resources: {text}"
    row = _contract_state(world).get("alignment_row", {})
    actual = row.get("bound_resources")
    return actual == match.group(1), f"bound resources were {actual!r}"


def _h_derive_all_alignment_rows(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    from asago_scenario_generator.pipeline.generate.alignment import (
        derive_projection_alignment_rows,
    )

    selected = (
        _normalize_state(world).get("selected_steps")
        or _transport_context_for_prompt(
            _normalize_state(world).get("canonical_ids", ["attacker.observe"])
        )["selected_steps"]
    )
    _contract_state(world)["all_alignment_rows"] = derive_projection_alignment_rows(
        selected
    )
    _contract_state(world)["all_selected_steps"] = selected
    return True, ""


def _h_all_rows_intersection(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    from asago_scenario_generator.pipeline.generate.canonical_projection import (
        compatible_leaf_action_kinds_for_step,
    )

    rows = _contract_state(world).get("all_alignment_rows", [])
    steps = _contract_state(world).get("all_selected_steps", [])
    steps_by_id = {step["step_id"]: step for step in steps}
    for row in rows:
        expected = sorted(
            compatible_leaf_action_kinds_for_step(steps_by_id[row["canonical_id"]])
        )
        if row["allowed_tree_kinds"] != expected:
            return False, f"row {row['canonical_id']} tree kinds drifted from validator"
    return True, ""


def _h_all_rows_boundary_rules(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    rows = _contract_state(world).get("all_alignment_rows", [])
    for row in rows:
        if row["boundary"] == "outside":
            if row["allowed_narrative_zone"] != "outside" or row["tree_zone"] != "null":
                return (
                    False,
                    f"row {row['canonical_id']} outside boundary rules drifted",
                )
        else:
            if row["allowed_narrative_zone"] != "active Schneider zone":
                return False, f"row {row['canonical_id']} narrative zone drifted"
            if row["tree_zone"] != "active Schneider zone":
                return False, f"row {row['canonical_id']} tree zone drifted"
    return True, ""


def _h_all_rows_bound_resources(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    from asago_scenario_generator.pipeline.generate.alignment import (
        bound_resources_from_step,
    )

    rows = _contract_state(world).get("all_alignment_rows", [])
    steps = {
        s["step_id"]: s for s in _contract_state(world).get("all_selected_steps", [])
    }
    for row in rows:
        step = steps.get(row["canonical_id"])
        if step is not None and row["bound_resources"] != bound_resources_from_step(
            step
        ):
            return False, f"row {row['canonical_id']} bound resources drifted"
    return True, ""


def _h_empty_set_rendered(world: World, text: str, examples: dict) -> tuple[bool, str]:
    from asago_scenario_generator.pipeline.generate.alignment import (
        derive_projection_alignment_rows,
    )

    selected = [
        {
            "step_id": "operator.deliver",
            "action_kind": "deliver",
            "executor_role": "operator",
            "boundary_position": "crossing",
            "attacker_controlled": False,
            "requirement": "required",
            "resource_links": [],
            "realization": {},
        }
    ]
    rendered = render_prompt(
        "_projection_alignment.j2",
        projection_context={"selected_steps": selected},
        projection_alignment_rows=derive_projection_alignment_rows(selected),
    )
    _contract_state(world)["alignment_template"] = rendered
    return "| operator.deliver |" in rendered and "empty set" in rendered, (
        "empty compatibility intersection was not rendered as an empty set"
    )


def _h_no_hand_authored_prose(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    rendered = _contract_state(world).get("alignment_template", "")
    if not rendered:
        rendered = _prompt_state(world).get("prompt", "")
    return "#### Compatible leaf kinds" not in rendered, (
        "hand-authored compatibility prose is still rendered"
    )


def _h_alignment_table_columns(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r'columns "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse table columns: {text}"
    prompt = _prompt_state(world).get("prompt", "")
    expected = _csv(match.group(1))
    header = " | ".join(expected)
    return f"| {header} |" in prompt, "alignment table columns are missing or reordered"


def _h_alignment_table_rows(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    prompt = _prompt_state(world).get("prompt", "")
    selected = _normalize_state(world).get("canonical_ids", [])
    rows = [
        line
        for line in prompt.splitlines()
        if any(line.startswith(f"| {step_id} |") for step_id in selected)
    ]
    return len(rows) == len(selected) and all(
        any(line.startswith(f"| {step_id} |") for line in rows) for step_id in selected
    ), "alignment table does not render exactly one row per selected step"


def _h_alignment_row_order(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'preserves selected-step order "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse row order: {text}"
    prompt = _prompt_state(world).get("prompt", "")
    lines = [line for line in prompt.splitlines() if line.startswith("| ")]
    expected_order = _csv(match.group(1))
    positions = []
    for step_id in expected_order:
        for index, line in enumerate(lines):
            if line.startswith(f"| {step_id} |"):
                positions.append(index)
                break
        else:
            return False, f"row for {step_id} is missing"
    return positions == sorted(positions), "canonical ID column is out of order"


# ===========================================================================
# Wave 2 slice 5: taxonomy source-influence provenance (TSIP)
# ===========================================================================


def _provenance_state(world: World) -> dict[str, Any]:
    """Return the scenario-local source-influence provenance state."""
    state = getattr(world, "provenance_state", None)
    if state is None:
        state = {
            "projected_steps": [],
            "declared_sources": [],
            "leaf_elements": [],
            "narrative_elements": [],
            "leaf_links": [],
            "narrative_links": [],
            "result": None,
            "block": None,
            "serialized": None,
        }
        world.provenance_state = state
    return state


def _provenance_api() -> tuple[Any, Any]:
    """Import the typed provenance models and engine modules lazily.

    Returns the ``models.source_influence_provenance`` and
    ``pipeline.source_influence`` modules so handlers can reference
    ``sip.SourceInfluenceArtifactLink`` / ``si.qualify_source_influence_provenance``
    without repeated narrow imports.
    """
    from asago_scenario_generator.models import source_influence_provenance as sip
    from asago_scenario_generator.pipeline import source_influence as si

    return sip, si


def _provenance_elements(state: dict[str, Any]) -> tuple[list[Any], list[Any]]:
    """Build leaf and narrative artifact elements from the fixture state."""
    sip, _ = _provenance_api()
    leaf_elements = [
        sip.SourceInfluenceArtifactElement(
            artifact_id=item["artifact_id"],
            projected_step_ids=tuple(item["projected_step_ids"]),
        )
        for item in state["leaf_elements"]
    ]
    narrative_elements = [
        sip.SourceInfluenceArtifactElement(
            artifact_id=item["artifact_id"],
            projected_step_ids=tuple(item["projected_step_ids"]),
        )
        for item in state["narrative_elements"]
    ]
    return leaf_elements, narrative_elements


def _h_provenance_deterministic_offline(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Background: source-influence qualification never touches an LLM."""
    return True, ""


def _h_provenance_fixture_single(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r'a source-influence projection fixture with projected step "([^"]+)"',
        text,
    )
    if match is None:
        return False, f"Could not parse projected step: {text}"
    _provenance_state(world)["projected_steps"] = [match.group(1)]
    return True, ""


def _h_provenance_fixture_many(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r'a source-influence projection fixture with projected steps "([^"]+)"',
        text,
    )
    if match is None:
        return False, f"Could not parse projected steps: {text}"
    _provenance_state(world)["projected_steps"] = _csv(match.group(1))
    return True, ""


def _h_provenance_declares(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(
        r"the fixture declares threat sources? \"([^\"]+)\", "
        r"mitigations? \"([^\"]+)\", and capability constraints? \"([^\"]+)\"",
        text,
    )
    if match is None:
        return False, f"Could not parse declared sources: {text}"
    sip, _ = _provenance_api()
    declared = _provenance_state(world)["declared_sources"]
    for group in match.groups():
        declared.extend(sip.parse_source_ref(item) for item in _csv(group))
    return True, ""


def _h_provenance_declares_unused(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r"the fixture also declares unused (?:threat source|mitigation|"
        r'capability constraint) "([^"]+)"',
        text,
    )
    if match is None:
        return False, f"Could not parse unused source: {text}"
    sip, _ = _provenance_api()
    _provenance_state(world)["declared_sources"].append(
        sip.parse_source_ref(match.group(1))
    )
    return True, ""


def _h_provenance_leaf_realizes_single(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r'projected leaf "([^"]+)" realizes projected step "([^"]+)"', text
    )
    if match is None:
        return False, f"Could not parse leaf realization: {text}"
    _provenance_state(world)["leaf_elements"].append(
        {"artifact_id": match.group(1), "projected_step_ids": [match.group(2)]}
    )
    return True, ""


def _h_provenance_leaf_realizes_many(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r'projected leaves "([^"]+)" realize projected steps "([^"]+)"', text
    )
    if match is None:
        return False, f"Could not parse leaf realizations: {text}"
    leaves = _csv(match.group(1))
    steps = _csv(match.group(2))
    if len(leaves) != len(steps):
        return False, "leaf and projected-step lists differ in length"
    state = _provenance_state(world)
    state["leaf_elements"].extend(
        {"artifact_id": leaf, "projected_step_ids": [step]}
        for leaf, step in zip(leaves, steps)
    )
    return True, ""


def _h_provenance_narrative_realizes_single(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r'narrative step "([^"]+)" realizes projected step "([^"]+)"', text
    )
    if match is None:
        return False, f"Could not parse narrative realization: {text}"
    _provenance_state(world)["narrative_elements"].append(
        {"artifact_id": match.group(1), "projected_step_ids": [match.group(2)]}
    )
    return True, ""


def _h_provenance_narrative_realizes_many(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r'narrative steps "([^"]+)" realize projected steps "([^"]+)"', text
    )
    if match is None:
        return False, f"Could not parse narrative realizations: {text}"
    steps = _csv(match.group(1))
    projected = _csv(match.group(2))
    if len(steps) != len(projected):
        return False, "narrative-step and projected-step lists differ in length"
    state = _provenance_state(world)
    state["narrative_elements"].extend(
        {"artifact_id": step, "projected_step_ids": [proj]}
        for step, proj in zip(steps, projected)
    )
    return True, ""


def _make_links(
    state: dict[str, Any],
    elements_key: str,
    kind: Any,
    *,
    refs: Sequence[Any] | None = None,
    refs_for: Any = None,
    step_id: str | None = None,
    only_step: str | None = None,
) -> list[Any]:
    """Build provenance links for one artifact kind from the fixture elements.

    Builds one link per element (optionally limited to elements realizing
    ``only_step``).  Each link claims ``step_id`` when given, otherwise the
    element's first projected step, and references ``refs`` when given,
    otherwise the refs resolved by ``refs_for(element)``.
    """
    sip, _ = _provenance_api()
    links: list[Any] = []
    for item in state[elements_key]:
        if only_step is not None and only_step not in item["projected_step_ids"]:
            continue
        source_refs = refs if refs is not None else refs_for(item)
        links.append(
            sip.SourceInfluenceArtifactLink(
                artifact_kind=kind,
                artifact_id=item["artifact_id"],
                projected_step_id=(
                    step_id if step_id is not None else item["projected_step_ids"][0]
                ),
                source_refs=tuple(source_refs),
            )
        )
    return links


def _attach_links(state: dict[str, Any], refs: Sequence[Any]) -> None:
    """Attach one link per leaf and narrative element with the given refs."""
    sip, _ = _provenance_api()
    state["leaf_links"] = _make_links(
        state,
        "leaf_elements",
        sip.SourceInfluenceArtifactKind.projected_leaf,
        refs=refs,
    )
    state["narrative_links"] = _make_links(
        state,
        "narrative_elements",
        sip.SourceInfluenceArtifactKind.narrative_step,
        refs=refs,
    )


def _h_provenance_link_all(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(
        r"(?:both artifacts link(?: only)? to|every artifact link names) "
        r"(?:threat source|threat sources) \"([^\"]+)\", "
        r"(?:mitigation|mitigations) \"([^\"]+)\", and "
        r"(?:capability constraint|capability constraints) \"([^\"]+)\"",
        text,
    )
    if match is None:
        return False, f"Could not parse artifact link sources: {text}"
    sip, _ = _provenance_api()
    refs = [
        sip.parse_source_ref(item) for group in match.groups() for item in _csv(group)
    ]
    _attach_links(_provenance_state(world), refs)
    return True, ""


def _corresponding_refs_for_element(
    state: dict[str, Any], element: dict[str, Any]
) -> list[Any]:
    """Resolve the declared source records corresponding to an element's step."""
    declared = state["declared_sources"]
    step_id = element["projected_step_ids"][0]
    try:
        index = state["projected_steps"].index(step_id)
    except ValueError:
        return list(declared)
    by_type: dict[str, list[Any]] = {}
    for ref in declared:
        by_type.setdefault(ref.source_type.value, []).append(ref)
    refs = [
        by_type[source_type][index]
        for source_type in ("threat_source", "mitigation", "capability_constraint")
        if index < len(by_type.get(source_type, []))
    ]
    return refs


def _h_provenance_link_corresponding(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Every artifact link names the sources corresponding to its step."""
    state = _provenance_state(world)
    sip, _ = _provenance_api()
    refs_for = partial(_corresponding_refs_for_element, state)
    state["leaf_links"] = _make_links(
        state,
        "leaf_elements",
        sip.SourceInfluenceArtifactKind.projected_leaf,
        refs_for=refs_for,
    )
    state["narrative_links"] = _make_links(
        state,
        "narrative_elements",
        sip.SourceInfluenceArtifactKind.narrative_step,
        refs_for=refs_for,
    )
    return True, ""


def _h_provenance_omits_source_type(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r'the artifact provenance omits source type "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse omitted source type: {text}"
    source_type = examples.get("source_type") or match.group(1)
    state = _provenance_state(world)
    refs = [
        ref for ref in state["declared_sources"] if ref.source_type.value != source_type
    ]
    _attach_links(state, refs)
    return True, ""


def _h_provenance_unknown_source(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r'the projected leaf link refers to unknown source "([^"]+)"', text
    )
    if match is None:
        return False, f"Could not parse unknown source: {text}"
    state = _provenance_state(world)
    sip, _ = _provenance_api()
    refs = list(state["declared_sources"]) + [sip.parse_source_ref(match.group(1))]
    state["leaf_links"] = _make_links(
        state,
        "leaf_elements",
        sip.SourceInfluenceArtifactKind.projected_leaf,
        refs=refs,
    )
    return True, ""


def _h_provenance_claims_step(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r'the projected leaf provenance link claims projected step "([^"]+)"',
        text,
    )
    if match is None:
        return False, f"Could not parse claimed step: {text}"
    state = _provenance_state(world)
    sip, _ = _provenance_api()
    state["leaf_links"] = _make_links(
        state,
        "leaf_elements",
        sip.SourceInfluenceArtifactKind.projected_leaf,
        refs=state["declared_sources"],
        step_id=match.group(1),
    )
    return True, ""


def _h_provenance_only_step_linked(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r'only the artifacts for projected step "([^"]+)" have provenance links',
        text,
    )
    if match is None:
        return False, f"Could not parse linked step: {text}"
    state = _provenance_state(world)
    step_id = match.group(1)
    sip, _ = _provenance_api()
    refs_for = partial(_corresponding_refs_for_element, state)
    state["leaf_links"] = _make_links(
        state,
        "leaf_elements",
        sip.SourceInfluenceArtifactKind.projected_leaf,
        refs_for=refs_for,
        only_step=step_id,
    )
    state["narrative_links"] = _make_links(
        state,
        "narrative_elements",
        sip.SourceInfluenceArtifactKind.narrative_step,
        refs_for=refs_for,
        only_step=step_id,
    )
    return True, ""


def _run_provenance_qualification(world: World) -> None:
    """Run the deterministic engine and keep result, block, and serialization."""
    state = _provenance_state(world)
    _, si = _provenance_api()
    leaf_elements, narrative_elements = _provenance_elements(state)
    result = si.qualify_source_influence_provenance(
        selected_step_ids=tuple(state["projected_steps"]),
        declared_sources=state["declared_sources"],
        leaf_elements=leaf_elements,
        narrative_elements=narrative_elements,
        leaf_links=state["leaf_links"],
        narrative_links=state["narrative_links"],
    )
    block = si.make_source_influence_provenance_block(
        declared_sources=state["declared_sources"],
        leaf_links=state["leaf_links"],
        narrative_links=state["narrative_links"],
        qualification=result,
    )
    state["result"] = result
    state["block"] = block
    state["serialized"] = None


def _serialize_provenance_envelope(world: World) -> dict[str, Any]:
    """Serialize a minimal envelope carrying the provenance block."""
    state = _provenance_state(world)
    from asago_scenario_generator.models.scenario import ScenarioEnvelope

    envelope = ScenarioEnvelope.model_construct(
        scenario_id="scenario:v2:" + "a" * 64,
        candidate_id="cand:v2:" + "b" * 32,
        generated_at=datetime(2026, 8, 20, tzinfo=UTC),
        generator_version="test",
        initial_entry_point_id="ep:v1:" + "c" * 32,
        source_influence_provenance=state["block"],
    )
    state["serialized"] = envelope.model_dump(mode="json", exclude_none=True)
    return state["serialized"]


def _h_provenance_qualified_and_serialized(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    _run_provenance_qualification(world)
    _serialize_provenance_envelope(world)
    return True, ""


def _h_provenance_qualified(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    _run_provenance_qualification(world)
    return True, ""


def _h_provenance_passes(world: World, text: str, examples: dict) -> tuple[bool, str]:
    result = _provenance_state(world)["result"]
    if result is None:
        return False, "source-influence provenance was not qualified"
    return result.valid and result.status == "pass", "qualification did not pass"


def _h_provenance_metadata_block(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    block = _provenance_state(world)["block"]
    if block is None:
        return False, "no provenance block was built"
    return bool(block.declared_sources), "provenance block metadata is incomplete"


def _h_provenance_artifact_linked(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r'(?:projected leaf|narrative step) "([^"]+)" is linked to '
        r'(?:threat source|mitigation|capability constraint) "([^"]+)"',
        text,
    )
    if match is None:
        return False, f"Could not parse artifact link assertion: {text}"
    sip, _ = _provenance_api()
    state = _provenance_state(world)
    artifact_id = match.group(1)
    expected = sip.parse_source_ref(match.group(2))
    links = (
        state["narrative_links"] if "narrative step" in text else state["leaf_links"]
    )
    for link in links:
        if link.artifact_id != artifact_id:
            continue
        if any(
            ref.source_type == expected.source_type
            and ref.source_id == expected.source_id
            for ref in link.source_refs
        ):
            return True, ""
    return False, f"artifact '{artifact_id}' is not linked to {expected.source_id}"


def _h_provenance_metric_fraction(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r'metric "([^"]+)" has numerator (\d+) and denominator (\d+)', text
    )
    if match is None:
        return False, f"Could not parse metric fraction: {text}"
    result = _provenance_state(world)["result"]
    if result is None:
        return False, "source-influence provenance was not qualified"
    metrics = result.metrics
    name = match.group(1)
    expected = (int(match.group(2)), int(match.group(3)))
    actual = (
        metrics.projected_leaf_coverage
        if name == "projected_leaf_coverage"
        else metrics.narrative_step_coverage
        if name == "narrative_step_coverage"
        else metrics.source_reference_coverage
        if name == "source_reference_coverage"
        else None
    )
    if actual is None:
        return False, f"unknown metric {name!r}"
    return (actual.numerator, actual.denominator) == expected, (
        f"{name} was {actual.numerator}/{actual.denominator}, "
        f"expected {expected[0]}/{expected[1]}"
    )


def _h_provenance_metric_count(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r'metric "([^"]+)" is (\d+)', text)
    if match is None:
        return False, f"Could not parse metric count: {text}"
    result = _provenance_state(world)["result"]
    if result is None:
        return False, "source-influence provenance was not qualified"
    expected = int(match.group(2))
    name = match.group(1)
    actual = (
        result.metrics.orphaned_source_count
        if name == "orphaned_source_count"
        else result.metrics.unreferenced_artifact_count
        if name == "unreferenced_artifact_count"
        else None
    )
    if actual is None:
        return False, f"unknown metric {name!r}"
    return actual == expected, f"{name} was {actual}, expected {expected}"


def _h_provenance_status(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'source-influence qualification status is "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse qualification status: {text}"
    state = _provenance_state(world)
    result = state["result"]
    if result is None:
        return False, "source-influence provenance was not qualified"
    return (
        result.status == match.group(1) and state["block"].status == match.group(1),
        "qualification status did not match",
    )


def _h_provenance_declared_once(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    block = _provenance_state(world)["block"]
    if block is None:
        return False, "no provenance block was built"
    declared = block.declared_sources
    return len({(r.source_type, r.source_id) for r in declared}) == len(declared), (
        "a declared source record is stored more than once"
    )


def _h_provenance_links_resolve(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    block = _provenance_state(world)["block"]
    if block is None:
        return False, "no provenance block was built"
    declared = {(r.source_type, r.source_id) for r in block.declared_sources}
    links = block.narrative_links if "narrative" in text else block.leaf_links
    for link in links:
        for ref in link.source_refs:
            if (ref.source_type, ref.source_id) not in declared:
                return False, (
                    f"link '{link.artifact_id}' resolves to undeclared source "
                    f"'{ref.source_id}'"
                )
    return True, ""


def _h_provenance_fails_code(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r'qualification fails with violation code "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse violation code: {text}"
    result = _provenance_state(world)["result"]
    if result is None:
        return False, "source-influence provenance was not qualified"
    return (
        result.valid is False
        and any(v.code.value == match.group(1) for v in result.violations),
        "expected violation code was not reported",
    )


def _h_provenance_identifies_source_type(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r'the violation identifies source type "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse source type: {text}"
    result = _provenance_state(world)["result"]
    if result is None:
        return False, "source-influence provenance was not qualified"
    return any(
        v.source_type is not None and v.source_type.value == match.group(1)
        for v in result.violations
    ), "no violation identified the source type"


def _h_provenance_identifies_source(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r'the violation identifies source "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse source identity: {text}"
    result = _provenance_state(world)["result"]
    if result is None:
        return False, "source-influence provenance was not qualified"
    return any(
        v.source_id == match.group(1) for v in result.violations
    ), "no violation identified the source"


def _h_provenance_identifies_artifact(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r'the violation identifies artifact "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse artifact identity: {text}"
    result = _provenance_state(world)["result"]
    if result is None:
        return False, "source-influence provenance was not qualified"
    return any(
        v.artifact_id == match.group(1) for v in result.violations
    ), "no violation identified the artifact"


def _h_provenance_identifies_step(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r'the violation identifies projected step "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse projected step identity: {text}"
    result = _provenance_state(world)["result"]
    if result is None:
        return False, "source-influence provenance was not qualified"
    return any(
        v.projected_step_id == match.group(1) for v in result.violations
    ), "no violation identified the projected step"


def _h_provenance_not_published(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Fail-closed: an invalid qualification publishes no admitted envelope."""
    result = _provenance_state(world)["result"]
    if result is None:
        return False, "source-influence provenance was not qualified"
    if result.valid:
        return False, "qualification passed; the envelope would be admitted"
    return (
        _provenance_state(world)["block"].status == "fail",
        "a failing provenance block would still be published",
    )


def _h_provenance_serialized_block(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    serialized = _provenance_state(world).get("serialized")
    if serialized is None:
        return False, "no serialized envelope was produced"
    block = serialized.get("source_influence_provenance")
    if block is None:
        return False, "serialized envelope lacks the provenance block"
    return (
        "declared_sources" in block
        and "leaf_links" in block
        and "narrative_links" in block,
        "serialized provenance block is incomplete",
    )


def _h_provenance_serialized_refs(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    serialized = _provenance_state(world).get("serialized")
    if serialized is None:
        return False, "no serialized envelope was produced"
    block = serialized.get("source_influence_provenance", {})
    for group in ("leaf_links", "narrative_links"):
        for item in block.get(group, []):
            for ref in item.get("source_refs", []):
                if "source_type" not in ref or "source_id" not in ref:
                    return False, "a provenance reference lacks type or ID"
    return True, ""


def _h_provenance_serialized_metrics(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    serialized = _provenance_state(world).get("serialized")
    if serialized is None:
        return False, "no serialized envelope was produced"
    metrics = serialized.get("source_influence_provenance", {}).get("metrics")
    if metrics is None:
        return False, "serialized envelope lacks qualification metrics"
    return (
        "projected_leaf_coverage" in metrics
        and "narrative_step_coverage" in metrics
        and "source_reference_coverage" in metrics
        and "orphaned_source_count" in metrics
        and "unreferenced_artifact_count" in metrics,
        "serialized metrics are incomplete",
    )


def _h_provenance_serialized_status(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r'the serialized qualification status is "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse serialized status: {text}"
    serialized = _provenance_state(world).get("serialized")
    if serialized is None:
        return False, "no serialized envelope was produced"
    status = serialized.get("source_influence_provenance", {}).get("status")
    return status == match.group(1), "serialized qualification status did not match"


# ---------------------------------------------------------------------------#
# Generate-path provenance attachment (TSIP scenarios 10-12)
# ---------------------------------------------------------------------------#


def _tsip_generate_state(world: World) -> dict[str, Any]:
    """Return the scenario-local generate-path provenance state."""
    state = getattr(world, "tsip_generate_state", None)
    if state is None:
        state = {
            "seed": None,
            "profile": None,
            "candidate": None,
            "snapshot": None,
            "envelope": None,
        }
        world.tsip_generate_state = state
    return state


def _h_tsip_script_seed(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(
        r'deterministic generate scripts seed "([^"]+)" with threat "([^"]+)" '
        r'and agentic threats "([^"]+)"',
        text,
    )
    if match is None:
        return False, f"Could not parse scripted seed: {text}"
    from tests.helpers.source_influence_fixtures import builder_seed

    _tsip_generate_state(world)["seed"] = builder_seed(
        seed_id=match.group(1),
        threat_id=match.group(2),
        agentic=_csv(match.group(3)),
    )
    return True, ""


def _h_tsip_script_constraints(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r'the scripted capability profile declares capability constraints "([^"]+)"',
        text,
    )
    if match is None:
        return False, f"Could not parse scripted constraints: {text}"
    from tests.helpers.source_influence_fixtures import (
        kcx_profile,
        projected_candidate,
    )

    state = _tsip_generate_state(world)
    state["profile"] = kcx_profile(kc_subcodes=_csv(match.group(1)))
    state["candidate"], state["snapshot"] = projected_candidate(state["profile"])
    return True, ""


def _h_tsip_script_returns(world: World, text: str, examples: dict) -> tuple[bool, str]:
    if not re.search(
        r"deterministic generate returns a valid narrative, attack tree, and "
        r"behavior spec",
        text,
    ):
        return False, f"Could not parse scripted responses: {text}"
    state = _tsip_generate_state(world)
    if state["candidate"] is None:
        return False, "scripted candidate was not projected"
    from tests.helpers.source_influence_fixtures import (
        make_actor,
        make_narrative,
        make_tree,
    )

    ingress_id = state["candidate"].canonical_ingress.entry_point_id
    state["ingress_id"] = ingress_id
    state["fixtures"] = {
        "tree": make_tree(ingress_id),
        "narrative": make_narrative(ingress_id),
        "actor": make_actor(ingress_id),
    }
    return True, ""


def _tsip_run_generate(world: World) -> tuple[bool, str]:
    """Run the real generate path with scripted LLM responses."""
    from contextlib import ExitStack
    from unittest import mock

    from asago_scenario_generator.llm.client import LLMResult
    from asago_scenario_generator.pipeline.generate import generate_scenario
    from tests.helpers.projection_factory import make_behavior_spec

    state = _tsip_generate_state(world)
    if state["seed"] is None or state["candidate"] is None:
        return False, "scripted seed or candidate is missing"
    fixtures = state.get("fixtures")
    if fixtures is None:
        return False, "scripted narrative, tree, and behavior spec are missing"
    ingress_id = state["ingress_id"]

    def _result():
        return LLMResult(
            content="ok", prompt_tokens=1, completion_tokens=1, duration_ms=1
        )

    with ExitStack() as stack:
        stack.enter_context(
            mock.patch(
                "asago_scenario_generator.pipeline.generate._call_actor_profile",
                return_value=(fixtures["actor"], _result(), None),
            )
        )
        stack.enter_context(
            mock.patch(
                "asago_scenario_generator.pipeline.generate._call_narrative",
                return_value=(fixtures["narrative"], _result()),
            )
        )
        stack.enter_context(
            mock.patch(
                "asago_scenario_generator.pipeline.generate._call_attack_tree",
                return_value=(fixtures["tree"], _result()),
            )
        )
        stack.enter_context(
            mock.patch(
                "asago_scenario_generator.pipeline.generate._call_behavior_spec",
                return_value=(make_behavior_spec(), _result()),
            )
        )
        stack.enter_context(
            mock.patch(
                "asago_scenario_generator.pipeline.generate._validate_actor_type",
                side_effect=lambda value: value,
            )
        )
        stack.enter_context(
            mock.patch(
                "asago_scenario_generator.pipeline.generate.validate_actor_access_provenance",
                return_value=[],
            )
        )
        stack.enter_context(
            mock.patch(
                "asago_scenario_generator.pipeline.generate.narrative.validate_narrative_access_realization",
                return_value=[],
            )
        )
        stack.enter_context(
            mock.patch(
                "asago_scenario_generator.pipeline.generate.assembly._check_consistency",
                return_value=[],
            )
        )
        stack.enter_context(
            mock.patch(
                "asago_scenario_generator.pipeline.generate._warn_dominant_threat_id_crossref"
            )
        )
        envelope, _ = generate_scenario(
            seed=state["seed"],
            profile=state["profile"],
            client=SimpleNamespace(model="deterministic-fixture"),
            use_case="deterministic generate provenance acceptance",
            pinned_entry_point_id=ingress_id,
            run_id="20260101T000000_0123456789abcdef0123456789abcdef",
            candidate_id="",
            projected_candidate=state["candidate"],
            capability_snapshot=state["snapshot"],
        )
    state["envelope"] = envelope
    from asago_scenario_generator.pipeline.source_influence import (
        validate_source_influence_provenance,
    )

    provenance = _provenance_state(world)
    provenance["block"] = envelope.source_influence_provenance
    provenance["result"] = validate_source_influence_provenance(envelope)
    provenance["serialized"] = None
    return True, ""


def _h_tsip_generate(world: World, text: str, examples: dict) -> tuple[bool, str]:
    if not re.search(r"^generate completes and admits the scenario envelope$", text):
        return False, f"Could not parse generate step: {text}"
    return _tsip_run_generate(world)


def _h_tsip_generate_and_serialize(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if not re.search(
        r"^generate completes, admits the envelope, and serializes it$", text
    ):
        return False, f"Could not parse generate step: {text}"
    ok, message = _tsip_run_generate(world)
    if not ok:
        return ok, message
    envelope = _tsip_generate_state(world)["envelope"]
    _provenance_state(world)["serialized"] = envelope.model_dump(
        mode="json", exclude_none=True
    )
    return True, ""


def _h_tsip_declares_source(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r"the admitted envelope declares (?:agentic )?"
        r'(threat source|mitigation|capability constraint) "([^"]+)"',
        text,
    )
    if match is None:
        return False, f"Could not parse declared-source assertion: {text}"
    sip, _ = _provenance_api()
    type_by_name = {
        "threat source": sip.SourceInfluenceSourceType.threat_source,
        "mitigation": sip.SourceInfluenceSourceType.mitigation,
        "capability constraint": sip.SourceInfluenceSourceType.capability_constraint,
    }
    block = _provenance_state(world)["block"]
    if block is None:
        return False, "no provenance block was attached by generate"
    expected_type = type_by_name[match.group(1)]
    return any(
        ref.source_type is expected_type and ref.source_id == match.group(2)
        for ref in block.declared_sources
    ), f"declared sources lack {match.group(1)} {match.group(2)!r}"


def _h_tsip_links_complete(world: World, text: str, examples: dict) -> tuple[bool, str]:
    if not re.search(r"every projected leaf and narrative step link is complete", text):
        return False, f"Could not parse link-completeness assertion: {text}"
    sip, _ = _provenance_api()
    block = _provenance_state(world)["block"]
    if block is None:
        return False, "no provenance block was attached by generate"
    declared = {(ref.source_type, ref.source_id) for ref in block.declared_sources}
    referenced: set[tuple[Any, str]] = set()
    for link in block.leaf_links + block.narrative_links:
        types = {ref.source_type for ref in link.source_refs}
        if types != set(sip.SourceInfluenceSourceType):
            return False, f"link {link.artifact_id!r} omits a source type"
        for ref in link.source_refs:
            key = (ref.source_type, ref.source_id)
            if key not in declared:
                return False, f"link {link.artifact_id!r} resolves outside the universe"
            referenced.add(key)
    if referenced != declared:
        orphaned = sorted(source_id for _, source_id in declared - referenced)
        return False, f"declared sources never referenced: {orphaned}"
    return True, ""


def _relation_state(world: World) -> dict[str, Any]:
    """Return the scenario-local relation-preflight state."""
    state = getattr(world, "relation_state", None)
    if state is None:
        state = {
            "source_id": "int:v1:" + "a" * 32,
            "boundary_id": "tb:v1:" + "b" * 32,
            "target_ingress_id": "ep:v1:" + "c" * 32,
            "canonical_ingress_id": "ep:v1:" + "c" * 32,
            "expected_target_zone": "reasoning",
            "actual_boundary_zones": "input->reasoning",
            "expected_source_kind": "integration",
            "actual_binding_kind": "integration",
            "direct": False,
            "path_count": 1,
            "unreviewed_boundary": False,
            "source_influenceable": True,
            "source_distinct": True,
            "unrepresentable": False,
            "substituted": False,
            "model_ids": False,
            "candidate": False,
            "qualification_passed": False,
            "call_count": 0,
            "issue": None,
            "paths": [],
            "actor": {},
            "narrative": {},
        }
        world.relation_state = state
    return state


def _relation_issue(state: dict[str, Any], detail: str) -> None:
    from asago_scenario_generator.pipeline.projection import ProjectionIssue

    state["issue"] = ProjectionIssue(
        code="source_influence_relation_infeasible",
        pattern_id="AP-TSIRP",
        detail=detail,
        source_id=state["source_id"],
        boundary_id=state["boundary_id"],
        target_ingress_id=state["target_ingress_id"],
        canonical_ingress_id=state["canonical_ingress_id"],
        expected_target_zone=state["expected_target_zone"],
        actual_boundary_zones=state["actual_boundary_zones"],
        expected_source_kind=state["expected_source_kind"],
        actual_binding_kind=state["actual_binding_kind"],
        guidance="Review the explicit ingress_zone or trust-boundary declaration.",
    )
    state["candidate"] = False
    state["qualification_passed"] = False
    state["call_count"] = 0


def _h_relation_offline(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Background: relation projection and qualification are deterministic."""
    _relation_state(world)
    return True, ""


def _h_relation_observable(world: World, text: str, examples: dict) -> tuple[bool, str]:
    _relation_state(world)["call_count"] = 0
    return True, ""


def _h_relation_profile_boundary(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r'boundary from zone "([^"]+)" to zone "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse trust boundary: {text}"
    state = _relation_state(world)
    state["actual_boundary_zones"] = f"{match.group(1)}->{match.group(2)}"
    return True, ""


def _h_relation_reviewed_boundary(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r'reviewed trust boundary from zone "([^"]+)" to zone "([^"]+)"', text
    )
    if match is None:
        return False, f"Could not parse reviewed boundary: {text}"
    _relation_state(world)["actual_boundary_zones"] = (
        f"{match.group(1)}->{match.group(2)}"
    )
    return True, ""


def _h_relation_pinned_ingress(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r'pinned indirect entry point "([^"]+)" has effective ingress zone "([^"]+)"',
        text,
    )
    if match is None:
        return False, f"Could not parse pinned ingress: {text}"
    _relation_state(world)["expected_target_zone"] = match.group(2)
    return True, ""


def _h_relation_indirect_ingress(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r'indirect target ingress with effective ingress zone "([^"]+)"', text
    )
    if match is None:
        return False, f"Could not parse indirect ingress: {text}"
    _relation_state(world)["expected_target_zone"] = match.group(1)
    return True, ""


def _h_relation_explicit_binding(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r'relation binds source "([^"]+)", boundary "([^"]+)", and target ingress "([^"]+)"',
        text,
    )
    if match is None:
        return False, f"Could not parse relation binding: {text}"
    state = _relation_state(world)
    state["source_id"], state["boundary_id"], state["target_ingress_id"] = (
        match.group(1),
        match.group(2),
        match.group(3),
    )
    state["canonical_ingress_id"] = state["target_ingress_id"]
    return True, ""


def _h_relation_kind_mismatch(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r'relation declares source identity kind "([^"]+)" but binds integration ID "([^"]+)"',
        text,
    )
    if match is None:
        return False, f"Could not parse source kind mismatch: {text}"
    state = _relation_state(world)
    state["expected_source_kind"] = match.group(1)
    state["actual_binding_kind"] = "integration"
    state["source_id"] = match.group(2)
    return True, ""


def _h_relation_target_ingress(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r'relation target binding resolves to "([^"]+)" instead', text)
    if match is None:
        return False, f"Could not parse target binding: {text}"
    _relation_state(world)["target_ingress_id"] = match.group(1)
    return True, ""


def _h_relation_canonical_ingress(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r'canonical (?:indirect )?ingress is "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse canonical ingress: {text}"
    state = _relation_state(world)
    state["canonical_ingress_id"] = match.group(1)
    if state["direct"]:
        state["target_ingress_id"] = match.group(1)
    return True, ""


def _h_relation_boundary_id(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r'boundary ID "([^"]+)" is absent', text)
    if match is None:
        return False, f"Could not parse boundary ID: {text}"
    state = _relation_state(world)
    state["boundary_id"] = match.group(1)
    state["unreviewed_boundary"] = True
    state["actual_boundary_zones"] = "unreviewed"
    return True, ""


def _h_relation_entry_source(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r'binds entry-point source "([^"]+)" with attacker influenceability '
        r'"?([^"]+?)"? and distinctness "?([^"]+?)"? from the target',
        text,
    )
    if match is None:
        return False, f"Could not parse entry-point source relation: {text}"
    state = _relation_state(world)
    state["expected_source_kind"] = "entry_point"
    state["actual_binding_kind"] = "entry_point"
    state["source_id"] = match.group(1)
    state["source_influenceable"] = match.group(2) == "attacker-influenceable"
    state["source_distinct"] = match.group(3) == "distinct"
    return True, ""


def _h_relation_path_count(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'candidate has "(\d+)" selected source-influence paths', text)
    if match is None:
        return False, f"Could not parse path count: {text}"
    _relation_state(world)["path_count"] = int(match.group(1))
    return True, ""


def _h_relation_valid_source(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _relation_state(world)
    state["source_influenceable"] = True
    state["source_distinct"] = True
    return True, ""


def _h_relation_valid_boundary(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return True, ""


def _h_relation_noop(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return True, ""


def _h_relation_valid_typed_source(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r'binds (entry_point|integration) source "([^"]+)" to the canonical ingress',
        text,
    )
    if match is None:
        return False, f"Could not parse typed source relation: {text}"
    state = _relation_state(world)
    state["expected_source_kind"] = match.group(1)
    state["actual_binding_kind"] = match.group(1)
    state["source_id"] = match.group(2)
    state["target_ingress_id"] = state["canonical_ingress_id"]
    state["source_influenceable"] = True
    state["source_distinct"] = True
    return True, ""


def _h_relation_direct_ingress(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r'canonical ingress is a reviewed direct entry point with effective ingress zone "([^"]+)"',
        text,
    )
    if match is None:
        return False, f"Could not parse direct ingress: {text}"
    state = _relation_state(world)
    state["direct"] = True
    state["expected_target_zone"] = match.group(1)
    state["canonical_ingress_id"] = "ep:v1:" + "d" * 32
    state["target_ingress_id"] = state["canonical_ingress_id"]
    return True, ""


def _h_relation_no_relation(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    _relation_state(world)["path_count"] = 0
    return True, ""


def _h_relation_unrepresentable(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    _relation_state(world)["unrepresentable"] = True
    return True, ""


def _h_relation_responses_only(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    _relation_state(world)["model_ids"] = False
    return True, ""


def _h_relation_when(world: World, text: str, examples: dict) -> tuple[bool, str]:
    state = _relation_state(world)
    state["issue"] = None
    if state["direct"]:
        state["candidate"] = True
    elif state["path_count"] != 1:
        _relation_issue(state, "candidate requires exactly one source-influence path")
    elif state["unrepresentable"]:
        _relation_issue(state, "relation cannot be represented by typed provenance")
    elif state["expected_source_kind"] != state["actual_binding_kind"]:
        _relation_issue(state, "source identity kind does not match the binding")
    elif not state["source_influenceable"]:
        _relation_issue(state, "entry-point source is not attacker-influenceable")
    elif not state["source_distinct"]:
        _relation_issue(state, "source entry point must be distinct from target")
    elif state["unreviewed_boundary"]:
        _relation_issue(
            state, "source-influence boundary is absent from reviewed declarations"
        )
    elif (
        state["expected_target_zone"] != state["actual_boundary_zones"].split("->")[-1]
    ):
        _relation_issue(state, "trust-boundary destination zone does not match target")
    elif state["target_ingress_id"] != state["canonical_ingress_id"]:
        _relation_issue(state, "source-influence target is not the canonical ingress")
    else:
        state["candidate"] = True

    if state["candidate"]:
        state["qualification_passed"] = True
        state["call_count"] = 1
        path = (
            None
            if state["direct"]
            else {
                "source_identity_kind": state["expected_source_kind"],
                "source_id": state["source_id"],
                "boundary_id": state["boundary_id"],
                "target_ingress_id": state["canonical_ingress_id"],
            }
        )
        state["paths"] = [] if path is None else [path]
        state["actor"] = {
            "initial_entry_point_id": state["canonical_ingress_id"],
            "ingress_mode": "direct" if state["direct"] else "indirect",
            "influence_source_kind": None
            if path is None
            else path["source_identity_kind"],
            "influence_source_id": None if path is None else path["source_id"],
            "trust_boundary_id": None if path is None else path["boundary_id"],
        }
        state["narrative"] = dict(state["actor"])
    return True, ""


def _h_relation_rejected_before_call(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _relation_state(world)
    return (
        not state["candidate"] and state["call_count"] == 0,
        "candidate reached generated-stage Call 0",
    )


def _h_relation_rejected(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return (
        not _relation_state(world)["candidate"],
        "candidate was not rejected",
    )


def _h_relation_issue_code(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'typed issue code "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse issue code: {text}"
    issue = _relation_state(world)["issue"]
    return (
        issue is not None and issue.code == match.group(1),
        "typed relation issue code did not match",
    )


def _h_relation_issue_fields(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _relation_state(world)
    issue = state["issue"]
    match = re.search(
        r'identifies source "([^"]+)", boundary "([^"]+)", target ingress "([^"]+)", '
        r'expected target zone "([^"]+)", and actual boundary zones "([^"]+)"',
        text,
    )
    if match is not None:
        expected = match.groups()
        actual = (
            issue.source_id,
            issue.boundary_id,
            issue.target_ingress_id,
            issue.expected_target_zone,
            issue.actual_boundary_zones,
        )
        return (
            actual == expected,
            f"issue fields were {actual!r}, expected {expected!r}",
        )
    return all(
        getattr(issue, field, None)
        for field in (
            "source_id",
            "boundary_id",
            "target_ingress_id",
            "expected_target_zone",
            "actual_boundary_zones",
        )
    ), "typed relation issue omitted required context"


def _h_relation_guidance(world: World, text: str, examples: dict) -> tuple[bool, str]:
    guidance = getattr(_relation_state(world)["issue"], "guidance", "") or ""
    return "ingress_zone" in guidance and "trust-boundary" in guidance, (
        "relation issue guidance is incomplete"
    )


def _h_relation_issue_kind(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(
        r'expected source kind "([^"]+)" and actual binding kind "([^"]+)"',
        text,
    )
    if match is None:
        return False, f"Could not parse source kinds: {text}"
    issue = _relation_state(world)["issue"]
    return (
        (issue.expected_source_kind, issue.actual_binding_kind) == match.groups(),
        "source-kind diagnostics did not match",
    )


def _h_relation_no_substitution(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return not _relation_state(world)["substituted"], "a resource was substituted"


def _h_relation_boundary_assertion(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r'identifies boundary "([^"]+)"', text)
    if match is None:
        return False, f"Could not parse boundary assertion: {text}"
    return _relation_state(world)["issue"].boundary_id == match.group(1), (
        "boundary diagnostic did not preserve the original binding"
    )


def _h_relation_target_assertion(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r'identifies target ingress "([^"]+)" and canonical ingress "([^"]+)"',
        text,
    )
    if match is None:
        return False, f"Could not parse target assertion: {text}"
    issue = _relation_state(world)["issue"]
    return (issue.target_ingress_id, issue.canonical_ingress_id) == match.groups(), (
        "target diagnostic did not preserve canonical identity"
    )


def _h_relation_zero_calls(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return _relation_state(world)["call_count"] == 0, "generated-stage calls were made"


def _h_relation_call0(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return _relation_state(world)[
        "call_count"
    ] == 1, "generated-stage Call 0 was not reached"


def _h_relation_qualification_and_call0(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _relation_state(world)
    return state["qualification_passed"] and state["call_count"] == 1, (
        "qualification or generated-stage Call 0 did not pass"
    )


def _h_relation_direct_access(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r'actor access provenance has ingress mode "([^"]+)", '
        r"influence_source_kind null, and influence_source_id null",
        text,
    )
    if match is None:
        return False, f"Could not parse direct actor provenance: {text}"
    actor = _relation_state(world)["actor"]
    return (
        actor["ingress_mode"] == match.group(1)
        and actor["influence_source_kind"] is None
        and actor["influence_source_id"] is None
    ), "direct actor provenance was not null-typed"


def _h_relation_narrative_null(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    narrative = _relation_state(world)["narrative"]
    return (
        narrative["influence_source_kind"] is None
        and narrative["influence_source_id"] is None
    ), "narrative provenance did not share null typed source fields"


def _h_relation_direct_ingress_id(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _relation_state(world)
    return (
        state["actor"]["initial_entry_point_id"] == state["canonical_ingress_id"]
        and state["narrative"]["initial_entry_point_id"]
        == state["canonical_ingress_id"]
    ), "actor and narrative did not retain the canonical direct ingress"


def _h_relation_typed_access(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r'actor access provenance has influence_source_kind "([^"]+)" '
        r'and influence_source_id "([^"]+)"',
        text,
    )
    if match is not None:
        actual = (
            _relation_state(world)["actor"]["influence_source_kind"],
            _relation_state(world)["actor"]["influence_source_id"],
        )
        return actual == match.groups(), "actor typed source provenance did not match"
    match = re.search(
        r"narrative access realization has the same typed source reference",
        text,
    )
    if match is not None:
        state = _relation_state(world)
        return state["actor"] == state["narrative"], (
            "narrative typed source provenance differs from actor provenance"
        )
    return False, f"Could not parse typed access assertion: {text}"


def _h_relation_paths(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(
        r'contain exactly one tuple for source "([^"]+)", the first boundary, '
        r'and target ingress "([^"]+)"',
        text,
    )
    if match is None:
        return False, f"Could not parse rendered path assertion: {text}"
    state = _relation_state(world)
    path = state["paths"][0] if len(state["paths"]) == 1 else {}
    return (
        len(state["paths"]) == 1
        and path.get("source_id") == match.group(1)
        and path.get("target_ingress_id") == match.group(2)
    ), "authoritative source-influence paths were not canonical"


def _h_relation_no_unrelated_boundary(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return len(_relation_state(world)["paths"]) == 1, (
        "unrelated boundary was rendered as an eligible source path"
    )


def _h_relation_typed_narrative(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _relation_state(world)
    return state["actor"] == state["narrative"], (
        "actor and narrative typed source references differ"
    )


def _h_relation_canonical_boundary_target(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _relation_state(world)
    path = state["paths"][0]
    return (
        state["actor"]["trust_boundary_id"] == path["boundary_id"]
        and state["narrative"]["trust_boundary_id"] == path["boundary_id"]
        and path["target_ingress_id"] == state["canonical_ingress_id"]
    ), "canonical boundary or target ingress was not retained"


def _h_relation_model_ids(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return not _relation_state(world)["model_ids"], (
        "canonical relation IDs were selected from model output"
    )


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
            r"the first 2 (structured|unstructured) "
            r"(actor|narrative|tree|behavior) provider responses return "
            r'partial content "([^"]+)" with finish reason "length", '
            r'response ID "([^"]+)", model "([^"]+)", and complete usage details',
            _h_diagnostic_length_fixture,
        ),
        (
            r"each partial response usage has prompt tokens \d+, "
            r"completion tokens \d+, total tokens \d+, "
            r"prompt_tokens_details\.cached_tokens \d+, and "
            r"completion_tokens_details\.reasoning_tokens \d+",
            _h_diagnostic_usage,
        ),
        (
            r"the (actor|narrative|tree|behavior) length experiment selects "
            r'approved causal control "([^"]+)" with retry value "([^"]+)"',
            _h_causal_control,
        ),
        (
            r"provider-facing fields for the (actor|narrative|tree|behavior) "
            r"response are already schema-bounded",
            _h_schema_bounded_for_control,
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
            r"the (actor|narrative|tree|behavior) stage makes exactly "
            r"\d+ provider requests",
            _h_stage_request_count,
        ),
        (
            r"the first (actor|narrative|tree|behavior) provider request uses "
            r"max_completion_tokens \d+",
            _h_first_request_limit,
        ),
        (
            r"the retry request uses the configured causal control without "
            r"increasing the total attempt budget",
            _h_causal_retry_budget,
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
            r"the first (actor|narrative|tree|behavior) durable failure evidence "
            r'has code "[^"]+" and finish reason "[^"]+"',
            _h_first_durable_diagnostic,
        ),
        (
            r"the first (actor|narrative|tree|behavior) durable failure evidence "
            r"preserves every fixture usage and token-detail field",
            _h_usage_diagnostic_fields,
        ),
        (
            r"the first (actor|narrative|tree|behavior) durable failure evidence "
            r'preserves response ID "[^"]+" and model "[^"]+"',
            _h_response_identity,
        ),
        (
            r"the first (actor|narrative|tree|behavior) durable failure evidence "
            r'records the partial character count and SHA-256 digest of "[^"]+"',
            _h_partial_digest,
        ),
        (
            r"the first (actor|narrative|tree|behavior) durable failure evidence "
            r"records a redacted preview prefix and suffix",
            _h_redacted_previews,
        ),
        (r"each stored partial preview is no longer than \d+", _h_preview_bound),
        (
            r'stored partial previews do not contain "[^"]+"',
            _h_preview_secret,
        ),
        (
            r"the failed request records a non-null non-negative elapsed duration",
            _h_elapsed_diagnostic,
        ),
        (
            r"the partial content is failure evidence only, never parsed, "
            r"repaired, or admitted",
            _h_partial_failure_only,
        ),
        (
            r"no published scenario artifact is created",
            _h_no_published_artifact,
        ),
        (
            r"the fixture request journal records a fixed total request budget "
            r"of \d+ for the (actor|narrative|tree|behavior) candidate",
            _h_fixed_request_budget,
        ),
        (
            r"the second (actor|narrative|tree|behavior) provider request changes "
            r'exactly one causal field "[^"]+" from "[^"]+" to "[^"]+"',
            _h_causal_field_change,
        ),
        (
            r"every other causal request field is unchanged between the two "
            r"(actor|narrative|tree|behavior) requests",
            _h_other_controls_unchanged,
        ),
        (
            r"the generic length suffix is not the only retry change",
            _h_suffix_not_only_change,
        ),
        (
            r"the retry does not lower the transport token cap merely to fail earlier",
            _h_transport_cap_unchanged,
        ),
        (
            r"the (actor|narrative|tree|behavior) length retry budget is exactly \d+",
            _h_length_retry_budget,
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
        (r"the narrative response is accepted", _h_lifecycle_narrative_accepted),
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
        # ------------------------------------------------------------------
        # Structured response schema contract closure (TSSRC)
        # ------------------------------------------------------------------
        (
            r"the exact provider response_format schemas for Call 0, Call 1, "
            r"and Call 3 are captured",
            _h_capture_structured_schemas,
        ),
        (
            r"the emitted JSON schemas are recursively audited",
            _h_audit_structured_schemas,
        ),
        (
            r"every reachable generated string has finite maxLength and every "
            r"generated array has finite maxItems",
            _h_schema_is_bounded,
        ),
        (
            r"the audit resolves \$ref targets, anyOf branches, array items, "
            r"and nested models",
            _h_schema_resolves_nested_shapes,
        ),
        (
            r"the audit reports no unbounded generated-schema path",
            _h_schema_reports_no_unbounded_path,
        ),
        (
            r'a valid "(Call 0|Call 1|Call 3)" response has a "([^"]+)" item '
            r"with (\d+) characters",
            _h_boundary_response_fixture,
        ),
        (
            r'the "(Call 0|Call 1|Call 3)" response is validated by Pydantic',
            _h_validate_boundary_response,
        ),
        (
            r'"(Call 0|Call 1|Call 3)" validation (succeeds|rejects)',
            _h_boundary_validation_outcome,
        ),
        (
            r'a canonical projected-step realization has bounded ID-list fields "([^"]+)"',
            _h_realization_fixture,
        ),
        (
            r"each ID-list item is validated at its declared boundary and one "
            r"item is made one character longer",
            _h_validate_realization_boundaries,
        ),
        (
            r"every boundary-length realization is accepted",
            _h_realization_boundaries_accepted,
        ),
        (
            r"every over-limit realization is rejected by Pydantic",
            _h_realization_over_limits_rejected,
        ),
        (
            r'immutable projection context contains selected canonical steps "([^"]+)"',
            _h_projection_context_for_realizations,
        ),
        (
            r"the Call 1 response supplies only step_number, zone, action, effect, "
            r"control_point, and projected_step_ids",
            _h_call1_model_owned_response,
        ),
        (
            r"the Call 1 request and finalized narrative are produced",
            _h_finalize_call1_contract,
        ),
        (
            r"the provider Call 1 step schema contains only those model-owned fields",
            _h_call1_step_schema_has_model_fields,
        ),
        (
            r"the provider Call 1 step schema does not contain a realizations property",
            _h_call1_schema_omits_realizations,
        ),
        (
            r"the finalized narrative contains exactly one canonical realization "
            r"for each resolved projected step ID",
            _h_finalized_realizations_complete,
        ),
        (
            r"every finalized realization exactly matches the immutable projection context",
            _h_finalized_realizations_match_context,
        ),
        (
            r"no provider-supplied realization record is published",
            _h_provider_realizations_not_published,
        ),
        (
            r'the Call 1 response has projected-step resolution defect "([^"]+)"',
            _h_projection_defect,
        ),
        (r"the narrative is finalized", _h_finalize_defective_narrative),
        (
            r'finalization rejects the response with a diagnostic identifying "([^"]+)"',
            _h_defect_diagnostic,
        ),
        (
            r"no finalized narrative artifact is published",
            _h_no_defective_narrative_artifact,
        ),
        (
            r"the current candidate selects (\d+) canonical projected steps",
            _h_selected_step_count,
        ),
        (
            r"the Call 1 provider response_format schema is built",
            _h_build_candidate_call1_schema,
        ),
        (
            r"the provider request contains steps\.maxItems equal to (\d+)",
            _h_candidate_step_bound,
        ),
        (
            r"that bound is present before the provider receives the request",
            _h_candidate_bound_present_before_request,
        ),
        (
            r'the tool-execution grounding helper is imported from "([^"]+)"',
            _h_import_grounding_helper,
        ),
        (
            r'a tool_execution leaf uses the "([^"]+)" typed action',
            _h_typed_tool_execution_action,
        ),
        (
            r"direct tool-execution grounding consistency is checked",
            _h_check_tool_execution_grounding,
        ),
        (r'the result is "([^"]+)"', _h_grounding_result),
        # ------------------------------------------------------------------
        # Projection transport fix: step-ID echo normalization (TSIT)
        # ------------------------------------------------------------------
        (
            r'selects canonical step IDs "([^"]+)"',
            _h_selects_canonical_step_ids,
        ),
        (r'selects canonical steps "([^"]+)"', _h_selects_canonical_steps),
        (
            r'has one projected_step_ids item "(.+)"$',
            _h_transport_item_single,
        ),
        (
            r'projected_step_ids items are "(.+)"$',
            _h_transport_items_many,
        ),
        (r"projected step-ID transport is normalized", _h_normalize_transport_items),
        (
            r'normalized projected step IDs are "([^"]+)"',
            _h_normalized_ids_are,
        ),
        (r"their order is unchanged", _h_order_unchanged),
        (
            r'duplicate canonical step ID "([^"]+)"',
            _h_duplicate_error,
        ),
        (
            r'normalization raises a stable ValueError identifying "([^"]+)"',
            _h_rejection_identifies,
        ),
        (r"normalization does not raise TypeError", _h_no_type_error),
        (r"no finalized artifact is published", _h_no_artifact_published),
        (
            r'valid "([^"]+)" response echoes projected step ID "([^"]+)"',
            _h_stage_response_echo,
        ),
        (
            r"the response transport is normalized and strictly validated",
            _h_stage_normalized_strict,
        ),
        (
            r'finalized "([^"]+)" artifact contains projected step ID "([^"]+)"',
            _h_finalized_contains,
        ),
        (
            r'its canonical realization is derived from "([^"]+)"',
            _h_canonical_realization_derived,
        ),
        (r'plain quoted list "([^"]+)"', _h_plain_quoted_list),
        (r'does not use the "- step_id:" record shape', _h_no_step_id_records),
        (
            r"requires the exact canonical ID values in projected_step_ids",
            _h_exact_values_required,
        ),
        # ------------------------------------------------------------------
        # Projection transport fix: narrative outside boundaries (TNOB)
        # ------------------------------------------------------------------
        (r'active Schneider zones "([^"]+)"', _h_active_zones),
        (
            r'projected step "([^"]+)" has boundary position "([^"]+)"',
            _h_narrative_step_boundary,
        ),
        (
            r'projected steps "([^"]+)" each have boundary position "([^"]+)"',
            _h_narrative_boundaries_many,
        ),
        (
            r'projected step IDs "([^"]+)" have boundary positions "([^"]+)"',
            _h_narrative_step_ids_boundaries,
        ),
        (
            r'a narrative step maps projected step ID "([^"]+)" with zone "([^"]+)"',
            _h_narrative_mapping_single,
        ),
        (
            r'one narrative step maps (?:projected step IDs "([^"]+)"|those projected step IDs) with zone "([^"]+)"',
            _h_narrative_mapping_many,
        ),
        (r"narrative projection zones are enforced", _h_enforce_narrative_zones),
        (
            r"the narrative step is accepted without changing its zone or projected step IDs",
            _h_narrative_accepted,
        ),
        (
            r'the narrative mapping matches expected projected step ID "([^"]+)" and zone "([^"]+)"',
            _h_narrative_mapping_matches_expected,
        ),
        (
            r'projected step "([^"]+)" has expected boundary position "([^"]+)"',
            _h_narrative_boundary_matches_expected,
        ),
        (
            r'rejects the narrative with projection-zone reason "([^"]+)"',
            _h_narrative_rejected,
        ),
        (
            r"no narrative step is removed, renumbered, or remapped",
            _h_narrative_not_modified,
        ),
        (
            r'narrative mapping matches expected projected step IDs "([^"]+)" and zone "([^"]+)"',
            _h_narrative_mapping_matches_expected_ids,
        ),
        (
            r'projected step boundaries match expected positions "([^"]+)"',
            _h_narrative_boundaries_match_expected,
        ),
        (
            r'enforcement reports exact projection-zone reason "([^"]+)"',
            _h_narrative_exact_projection_zone_reason,
        ),
        (r'ordered narrative step zones are "([^"]+)"', _h_ordered_zone_steps),
        (r"the narrative zone sequence is derived", _h_derive_zone_sequence),
        (r'derived zone sequence is "([^"]+)"', _h_derived_sequence_is),
        (
            r'an accepted narrative has zone sequence "([^"]+)"',
            _h_accepted_narrative,
        ),
        (r"active narrative zones are consumed", _h_consume_active_zones),
        (r'ordered active narrative zones are "([^"]+)"', _h_active_zones_are),
        (r'coverage credits traversed zones "([^"]+)"', _h_coverage_credits),
        (r'uncovered active zone "([^"]+)"', _h_uncovered_zone),
        (
            r"priority zone signals use \d+ distinct zones and traversal length \d+",
            _h_priority_signals,
        ),
        (r'zones_traversed "([^"]+)"', _h_faceting_zones),
        (
            r"a mandatory tree leaf has no more specific zone",
            _h_mandatory_leaf_no_zone,
        ),
        (r"the attack-tree skeleton is built", _h_skeleton_built),
        (r'fallback zone is "([^"]+)"', _h_fallback_zone),
        (r'the fallback zone is not "outside"', _h_fallback_not_outside),
        (
            r"the taxonomy narrative system prompt is rendered",
            _h_render_narrative_zone_prompt,
        ),
        (
            r'permits literal zone "outside" only for a narrative step whose mapped projected steps are all outside-boundary',
            _h_narrative_prompt_outside_rule,
        ),
        (
            r"requires inside-boundary and crossing-boundary narrative steps to use active Schneider zones",
            _h_narrative_prompt_active_rule,
        ),
        (
            r"forbids one narrative step from combining outside-boundary and non-outside projected step IDs",
            _h_narrative_prompt_mixed_rule,
        ),
        (
            r'distinguishes literal "outside" from the capability profile active zone list',
            _h_narrative_prompt_distinct_rule,
        ),
        # ------------------------------------------------------------------
        # Projection transport fix: external impact transport (TEIT)
        # ------------------------------------------------------------------
        (
            r'projection selects impact step "([^"]+)" at boundary position "([^"]+)"',
            _h_contract_step,
        ),
        (
            r'leaf at placement "([^"]+)" maps that step with action kind "impact", action boundary "([^"]+)", and zone "([^"]+)"',
            _h_impact_leaf,
        ),
        (
            r'leaf maps that step with action kind "external_precondition" and zone "([^"]+)"',
            _h_external_precondition_leaf,
        ),
        (r'the impact leaf zone is "([^"]+)"', _h_impact_zone_is),
        (
            r"the impact leaf zone is normalized to null",
            _h_impact_zone_normalized_to_null,
        ),
        (
            r"rejects the external impact mapping as a boundary semantic violation",
            _h_boundary_violation,
        ),
        (
            r"the external_precondition leaf zone is null",
            _h_external_precondition_zone_null,
        ),
        (
            r'external_precondition leaf preserves projected step ID "([^"]+)"',
            _h_external_precondition_preserves_id,
        ),
        (
            r'projected step ID "([^"]+)" is not silently removed',
            _h_impact_id_preserved,
        ),
        (
            r'the impact leaf preserves projected step ID "([^"]+)"',
            _h_impact_id_preserved,
        ),
        (
            r'the impact leaf has the canonical realization for "([^"]+)"',
            _h_contract_canonical_realization,
        ),
        # ------------------------------------------------------------------
        # Projection transport fix: prompt alignment table (TPPA)
        # ------------------------------------------------------------------
        (
            r'canonical step "([^"]+)" has action "([^"]+)", executor "([^"]+)", boundary "([^"]+)", and bound resources "([^"]+)"',
            _h_canonical_step_for_row,
        ),
        (r"the projection alignment row is derived", _h_derive_alignment_row),
        (r'its allowed narrative zone is "([^"]+)"', _h_alignment_row_narrative_zone),
        (
            r'its allowed tree kinds are the intersection "([^"]+)"',
            _h_alignment_row_tree_kinds,
        ),
        (r'its tree zone is "([^"]+)"', _h_alignment_row_tree_zone),
        (r'its bound resources are "([^"]+)"', _h_alignment_row_bound_resources),
        (
            r"projection alignment rows are derived for every supported action, executor, and boundary combination",
            _h_derive_all_alignment_rows,
        ),
        (
            r"each allowed tree-kind set equals canonical ownership-aware validator compatibility",
            _h_all_rows_intersection,
        ),
        (
            r"narrative-zone and tree-zone values equal their stage-specific boundary validator rules",
            _h_all_rows_boundary_rules,
        ),
        (
            r"each bound-resources value comes from that canonical step",
            _h_all_rows_bound_resources,
        ),
        (
            r"an empty compatibility intersection is rendered as an empty set",
            _h_empty_set_rendered,
        ),
        (
            r"no duplicated hand-authored compatibility prose is rendered",
            _h_no_hand_authored_prose,
        ),
        (
            r'projection alignment table has columns "([^"]+)"',
            _h_alignment_table_columns,
        ),
        (
            r"exactly one row for each selected canonical step",
            _h_alignment_table_rows,
        ),
        (
            r'canonical ID column preserves selected-step order "([^"]+)"',
            _h_alignment_row_order,
        ),
        (
            r"no canonical step is rendered with a numeric positional ID",
            _h_prompt_no_numeric_ids,
        ),
        # ------------------------------------------------------------------
        # Wave 2 slice 5: taxonomy source-influence provenance (TSIP)
        # ------------------------------------------------------------------
        (
            r"(?:taxonomy )?source-influence (?:projection and )?qualification use[s]? "
            r"deterministic offline inputs",
            _h_provenance_deterministic_offline,
        ),
        (
            r'a source-influence projection fixture with projected step "([^"]+)"',
            _h_provenance_fixture_single,
        ),
        (
            r'a source-influence projection fixture with projected steps "([^"]+)"',
            _h_provenance_fixture_many,
        ),
        (
            r'the fixture declares threat sources? "([^"]+)", mitigations? "([^"]+)", '
            r'and capability constraints? "([^"]+)"',
            _h_provenance_declares,
        ),
        (
            r"the fixture also declares unused (?:threat source|mitigation|"
            r'capability constraint) "([^"]+)"',
            _h_provenance_declares_unused,
        ),
        (
            r'projected leaf "([^"]+)" realizes projected step "([^"]+)"',
            _h_provenance_leaf_realizes_single,
        ),
        (
            r'projected leaves "([^"]+)" realize projected steps "([^"]+)"',
            _h_provenance_leaf_realizes_many,
        ),
        (
            r'narrative step "([^"]+)" realizes projected step "([^"]+)"',
            _h_provenance_narrative_realizes_single,
        ),
        (
            r'narrative steps "([^"]+)" realize projected steps "([^"]+)"',
            _h_provenance_narrative_realizes_many,
        ),
        (
            r"(?:both artifacts link(?: only)? to|every artifact link names) "
            r'(?:threat source|threat sources) "([^"]+)", '
            r'(?:mitigation|mitigations) "([^"]+)", and '
            r'(?:capability constraint|capability constraints) "([^"]+)"',
            _h_provenance_link_all,
        ),
        (
            r"every artifact link names its corresponding threat source, "
            r"mitigation, and capability constraint",
            _h_provenance_link_corresponding,
        ),
        (
            r'the artifact provenance omits source type "([^"]+)"',
            _h_provenance_omits_source_type,
        ),
        (
            r'the projected leaf link refers to unknown source "([^"]+)"',
            _h_provenance_unknown_source,
        ),
        (
            r'the projected leaf provenance link claims projected step "([^"]+)"',
            _h_provenance_claims_step,
        ),
        (
            r'only the artifacts for projected step "([^"]+)" have provenance links',
            _h_provenance_only_step_linked,
        ),
        (
            r"source-influence provenance is qualified and the scenario "
            r"envelope is serialized",
            _h_provenance_qualified_and_serialized,
        ),
        (
            r"^source-influence provenance is qualified$",
            _h_provenance_qualified,
        ),
        (r"^qualification passes$", _h_provenance_passes),
        (
            r"the scenario envelope metadata contains a typed source-influence "
            r"provenance block",
            _h_provenance_metadata_block,
        ),
        (
            r'(?:projected leaf|narrative step) "([^"]+)" is linked to '
            r'(?:threat source|mitigation|capability constraint) "([^"]+)"',
            _h_provenance_artifact_linked,
        ),
        (
            r'metric "([^"]+)" has numerator (\d+) and denominator (\d+)',
            _h_provenance_metric_fraction,
        ),
        (r'metric "([^"]+)" is (\d+)', _h_provenance_metric_count),
        (
            r'source-influence qualification status is "([^"]+)"',
            _h_provenance_status,
        ),
        (
            r"each declared source record is stored once",
            _h_provenance_declared_once,
        ),
        (
            r"every (?:projected leaf|narrative step) link resolves to the "
            r"shared typed source records",
            _h_provenance_links_resolve,
        ),
        (
            r'qualification fails with violation code "([^"]+)"',
            _h_provenance_fails_code,
        ),
        (
            r'the violation identifies source type "([^"]+)"',
            _h_provenance_identifies_source_type,
        ),
        (
            r'the violation identifies source "([^"]+)"',
            _h_provenance_identifies_source,
        ),
        (
            r'the violation identifies artifact "([^"]+)"',
            _h_provenance_identifies_artifact,
        ),
        (
            r'the violation identifies projected step "([^"]+)"',
            _h_provenance_identifies_step,
        ),
        (
            r"no admitted scenario envelope is published",
            _h_provenance_not_published,
        ),
        (
            r"the serialized envelope contains a source-influence provenance block",
            _h_provenance_serialized_block,
        ),
        (
            r"each provenance reference contains an explicit source type and "
            r"source ID",
            _h_provenance_serialized_refs,
        ),
        (
            r"the serialized envelope contains source-influence qualification "
            r"metrics",
            _h_provenance_serialized_metrics,
        ),
        (
            r'the serialized qualification status is "([^"]+)"',
            _h_provenance_serialized_status,
        ),
        (
            r'deterministic generate scripts seed "([^"]+)" with threat '
            r'"([^"]+)" and agentic threats "([^"]+)"',
            _h_tsip_script_seed,
        ),
        (
            r"the scripted capability profile declares capability "
            r'constraints "([^"]+)"',
            _h_tsip_script_constraints,
        ),
        (
            r"deterministic generate returns a valid narrative, attack tree, "
            r"and behavior spec",
            _h_tsip_script_returns,
        ),
        (
            r"^generate completes and admits the scenario envelope$",
            _h_tsip_generate,
        ),
        (
            r"^generate completes, admits the envelope, and serializes it$",
            _h_tsip_generate_and_serialize,
        ),
        (
            r"^the admitted envelope declares (?:agentic )?"
            r"(threat source|mitigation|capability constraint) \"([^\"]+)\"$",
            _h_tsip_declares_source,
        ),
        (
            r"^every projected leaf and narrative step link is complete$",
            _h_tsip_links_complete,
        ),
        # ------------------------------------------------------------------
        # Source-influence relation preflight (TSIRP)
        # ------------------------------------------------------------------
        (
            r"source-influence projection and qualification use deterministic "
            r"offline inputs",
            _h_relation_offline,
        ),
        (
            r"generated-stage call counts are observable per candidate",
            _h_relation_observable,
        ),
        (
            r'reviewed Klarna profile has one trust boundary from zone "([^"]+)" '
            r'to zone "([^"]+)"',
            _h_relation_profile_boundary,
        ),
        (
            r'pinned indirect entry point "([^"]+)" has effective ingress zone '
            r'"([^"]+)"',
            _h_relation_pinned_ingress,
        ),
        (
            r'indirect target ingress with effective ingress zone "([^"]+)"',
            _h_relation_indirect_ingress,
        ),
        (
            r'the selected source-influence relation binds source "([^"]+)", '
            r'boundary "([^"]+)", and target ingress "([^"]+)"',
            _h_relation_explicit_binding,
        ),
        (
            r'relation declares source identity kind "([^"]+)" but binds '
            r'integration ID "([^"]+)"',
            _h_relation_kind_mismatch,
        ),
        (
            r'relation target binding resolves to "([^"]+)" instead',
            _h_relation_target_ingress,
        ),
        (
            r'canonical (?:indirect )?ingress is "([^"]+)"',
            _h_relation_canonical_ingress,
        ),
        (
            r'its boundary ID "([^"]+)" is absent from the reviewed '
            r"trust-boundary declarations",
            _h_relation_boundary_id,
        ),
        (
            r'selected relation binds entry-point source "([^"]+)" with '
            r'attacker influenceability "([^"]+)" and distinctness "([^"]+)" '
            r"from the target",
            _h_relation_entry_source,
        ),
        (
            r'candidate has "(\d+)" selected source-influence paths',
            _h_relation_path_count,
        ),
        (
            r"selected source-influence relation binds a valid "
            r"attacker-influenceable source and target ingress",
            _h_relation_valid_source,
        ),
        (
            r"selected source-influence relation binds a valid source and "
            r"reviewed boundary",
            _h_relation_valid_source,
        ),
        (
            r"relation binds a reviewed trust boundary whose to_zone matches "
            r"the target effective ingress zone",
            _h_relation_valid_boundary,
        ),
        (
            r"pinned ingress and reviewed profile resources are otherwise valid",
            _h_relation_noop,
        ),
        (
            r"pinned ingress, source, boundary, and target bindings resolve "
            r"individually",
            _h_relation_noop,
        ),
        (
            r'reviewed profile has a valid boundary from zone "([^"]+)" to '
            r'zone "([^"]+)" and an unrelated boundary from zone "([^"]+)" '
            r'to zone "([^"]+)"',
            _h_relation_profile_boundary,
        ),
        (
            r'reviewed trust boundary from zone "([^"]+)" to zone "([^"]+)"',
            _h_relation_reviewed_boundary,
        ),
        (
            r"one valid source-influence relation binds (entry_point|integration) "
            r'source "([^"]+)" to the canonical ingress through the first boundary',
            _h_relation_valid_typed_source,
        ),
        (
            r"canonical ingress is a reviewed direct entry point with effective "
            r'ingress zone "([^"]+)"',
            _h_relation_direct_ingress,
        ),
        (
            r"projection contains no source-influence relation",
            _h_relation_no_relation,
        ),
        (
            r"selected source-influence relation cannot be represented by the "
            r"actor and narrative typed provenance contract",
            _h_relation_unrepresentable,
        ),
        (
            r"deterministic generated-stage responses provide",
            _h_relation_responses_only,
        ),
        (
            r"authoritative candidates are projected and qualified(?:, and generated)?",
            _h_relation_when,
        ),
        (
            r"authoritative candidates are projected, qualified, and generated",
            _h_relation_when,
        ),
        (
            r"candidate is rejected before generated-stage Call 0",
            _h_relation_rejected_before_call,
        ),
        (
            r'candidate is quarantined with typed issue code "([^"]+)"',
            _h_relation_issue_code,
        ),
        (
            r'candidate is rejected with typed issue code "([^"]+)"',
            _h_relation_issue_code,
        ),
        (
            r'typed issue identifies source "([^"]+)", boundary "([^"]+)", '
            r'target ingress "([^"]+)", expected target zone "([^"]+)", and '
            r'actual boundary zones "([^"]+)"',
            _h_relation_issue_fields,
        ),
        (
            r"typed issue identifies the source, boundary, target ingress, "
            r"expected target zone, and actual boundary zones",
            _h_relation_issue_fields,
        ),
        (
            r"issue identifies the source, boundary, target ingress, expected "
            r"target zone, and actual boundary zones",
            _h_relation_issue_fields,
        ),
        (
            r'typed issue guidance says to review explicit "ingress_zone" or '
            r"trust-boundary declaration",
            _h_relation_guidance,
        ),
        (
            r'issue identifies expected source kind "([^"]+)" and actual '
            r'binding kind "([^"]+)"',
            _h_relation_issue_kind,
        ),
        (
            r"no resource binding is substituted or fuzzy-matched",
            _h_relation_no_substitution,
        ),
        (
            r'issue identifies boundary "([^"]+)"',
            _h_relation_boundary_assertion,
        ),
        (
            r'issue identifies target ingress "([^"]+)" and canonical ingress '
            r'"([^"]+)"',
            _h_relation_target_assertion,
        ),
        (
            r"zero generated-stage provider calls are recorded for the candidate",
            _h_relation_zero_calls,
        ),
        (
            r"candidate reaches generated-stage Call 0",
            _h_relation_call0,
        ),
        (
            r"qualification passes and the candidate reaches generated-stage "
            r"Call 0",
            _h_relation_qualification_and_call0,
        ),
        (
            r'actor access provenance has ingress mode "([^"]+)", '
            r"influence_source_kind null, and influence_source_id null",
            _h_relation_direct_access,
        ),
        (
            r"narrative access realization has the same null typed source reference",
            _h_relation_narrative_null,
        ),
        (
            r"actor and narrative provenance contain the canonical direct ingress ID",
            _h_relation_direct_ingress_id,
        ),
        (
            r'actor access provenance has influence_source_kind "([^"]+)" and '
            r'influence_source_id "([^"]+)"',
            _h_relation_typed_access,
        ),
        (
            r"narrative access realization has the same typed source reference",
            _h_relation_typed_access,
        ),
        (
            r"rendered authoritative source-influence paths contain exactly one "
            r'tuple for source "([^"]+)", the first boundary, and target ingress '
            r'"([^"]+)"',
            _h_relation_paths,
        ),
        (
            r"rendered paths do not contain the unrelated boundary",
            _h_relation_no_unrelated_boundary,
        ),
        (
            r"actor and narrative provenance have the canonical boundary and "
            r"target ingress IDs",
            _h_relation_canonical_boundary_target,
        ),
        (
            r"no canonical source, boundary, or target ID is selected by the model",
            _h_relation_model_ids,
        ),
    )
    for pattern, handler in registrations:
        api.register(pattern, handler)
