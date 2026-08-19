"""Deterministic acceptance handlers for the taxonomy risk workflow."""

from __future__ import annotations

import re
from typing import Any

from runtime_shared import World


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
    """Execute actor generation against a deterministic two-outcome client."""
    from types import SimpleNamespace

    from asago_scenario_generator.pipeline.generate import actor

    state = _actor_retry_state(world)
    state["calls"] = []
    outcomes = list(state["outcomes"])
    length_error = type("LengthFinishReasonError", (Exception,), {})

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
    actor.render_prompt = lambda *_args, **_kwargs: "actor prompt"
    try:
        actor._call_actor_profile(
            seed=SimpleNamespace(min_complexity=None, seed_id="AP-ACTOR-01"),
            profile=SimpleNamespace(zones_active=[]),
            client=_Client(),
            use_case="deterministic actor retry acceptance",
        )
    except Exception as exc:
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
    retry_prompt = calls[1]["user_prompt"].lower()
    return (
        "prior response was truncated" in retry_prompt
        and "concise schema-matching response" in retry_prompt,
        "retry prompt did not contain corrective concise feedback",
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
    )
    for pattern, handler in registrations:
        api.register(pattern, handler)
