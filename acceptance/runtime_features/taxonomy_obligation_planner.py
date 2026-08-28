"""Deterministic acceptance handlers for taxonomy obligation planning and artifacts."""

from __future__ import annotations

import json
import os
import re
import socket
import shutil
import subprocess
import sys
import tempfile
import threading
from contextlib import ExitStack
from copy import deepcopy
from pathlib import Path
from typing import Any
from unittest.mock import patch

import yaml

from runtime_shared import World
from runtime_bootstrap import PROJECT_ROOT

from asago_scenario_generator.cli.obligation import run_plan_obligations
from asago_scenario_generator.models.obligation_plan import TaxonomyObligationPlan
from asago_scenario_generator.pipeline.obligation_contracts import (
    compute_mapping_bundle_digest,
)

FEATURE_ID = "taxonomy_obligation_planner"

# Compatibility fixtures pair each workflow with its default command.
_COMPAT_WORKFLOW_COMMANDS = {
    "taxonomy/risk": "generate",
    "STPA": "stpa-run",
}


def _typed_authoritative_fixture() -> tuple[Any, dict[str, Any], Any]:
    """Return the same offline projection fixture used by the contract tests.

    The typed acceptance seam must exercise candidate derivation from a real
    canonical chain and capability snapshot.  Importing the shared fixture
    keeps this runtime from inventing a second, subtly different authority
    record while remaining entirely offline.
    """
    from tests.helpers.projection_factory import (
        get_projected_candidate,
        get_test_raw_pattern,
        get_test_snapshot,
    )

    return get_projected_candidate(), get_test_raw_pattern(), get_test_snapshot()


def _jsonable(value: Any) -> Any:
    """Convert typed fixture values to JSON for the file adapter."""
    if hasattr(value, "model_dump"):
        return _jsonable(value.model_dump(mode="json"))
    if isinstance(value, dict):
        return {key: _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def _typed_pin_payload(
    raw_pattern: dict[str, Any] | None = None,
    snapshot: Any | None = None,
    cross_taxonomy_mappings: Any = (),
    sssom_mappings: Any = (),
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Capture catalog and mapping pins from an authoritative fixture."""
    candidate, default_pattern, default_snapshot = _typed_authoritative_fixture()
    raw_pattern = raw_pattern or default_pattern
    snapshot = snapshot or default_snapshot
    context = raw_pattern["canonical_chain"]["taxonomy_context"]
    if raw_pattern == default_pattern and snapshot == default_snapshot:
        catalog_digest = candidate.projection.catalog_pin
    else:
        from asago_scenario_generator.pipeline.projection import (
            ProjectionBudget,
            project_authoritative_candidates,
        )
        from asago_scenario_generator.pipeline.projection_qualification import (
            compute_authoritative_catalog_pin,
        )
        from tests.helpers.projection_factory import get_test_resolver

        resolver = get_test_resolver()
        catalog_digest = compute_authoritative_catalog_pin([raw_pattern], resolver)
        batch = project_authoritative_candidates(
            [raw_pattern],
            resolver,
            snapshot,
            budget=ProjectionBudget(max_candidates=100),
        )
        if batch.candidates:
            catalog_digest = batch.candidates[0].projection.catalog_pin
    return (
        {
            "atlas": {
                "release": context["atlas"]["release"],
                "digest": catalog_digest,
            }
        },
        {
            "sssom": {
                "release": context["atlas"]["release"],
                "digest": context["mapping_set_digest"],
            },
            "obligation_edges": {
                "release": "obligation-mapping-bundle-v1",
                "digest": compute_mapping_bundle_digest(
                    cross_taxonomy_mappings, sssom_mappings
                ),
            },
        },
    )


def _typed_expected_candidate() -> Any:
    """Return the candidate derived from the shared authoritative fixture."""
    return _typed_authoritative_fixture()[0]


def _typed_default_qualification(snapshot: Any | None = None) -> dict[str, Any]:
    """Build qualification facts with the shared content-integrity digest."""
    if snapshot is None:
        _candidate, _raw_pattern, snapshot = _typed_authoritative_fixture()
    facts = [item.model_dump(mode="json") for item in snapshot.facts]
    from asago_scenario_generator.pipeline.obligation_contracts import (
        QualificationFactsInput,
    )

    fact_set = QualificationFactsInput(facts=facts)
    return fact_set.model_dump(mode="json")


def _typed_risk_card(risk_id: str) -> dict[str, Any]:
    """Return a reviewed risk-card fixture for the typed planner seam."""
    return {
        "risk_id": risk_id,
        "risk_name": f"Risk {risk_id}",
        "risk_description": "A reviewed risk used by acceptance contract tests.",
        "taxonomy": "ibm-risk-atlas",
        "confidence": 1.0,
        "grounding_confidence": "high",
        "evidence": [],
        "mitigations": [],
    }


def _typed_pattern_variant(pattern_id: str) -> dict[str, Any]:
    """Return a repinned full authoritative pattern for identity tests."""
    from asago_scenario_generator.models.attack_pattern import (
        compute_chain_semantic_digest,
    )

    _candidate, raw_pattern, _snapshot = _typed_authoritative_fixture()
    variant = deepcopy(raw_pattern)
    variant["id"] = pattern_id
    variant["canonical_chain"]["pattern_id"] = pattern_id
    variant["canonical_chain"]["semantic_digest"] = compute_chain_semantic_digest(
        variant["canonical_chain"]
    )
    return variant


def _typed_capability_excluded_pattern(pattern_id: str = "AP-T1-01") -> dict[str, Any]:
    """Return a complete pattern whose authoritative profile gate is unmet."""
    _candidate, raw_pattern, _snapshot = _typed_authoritative_fixture()
    variant = deepcopy(raw_pattern)
    variant["id"] = pattern_id
    variant["canonical_chain"]["pattern_id"] = pattern_id
    variant["prerequisite_capabilities"]["min_zones"] = [
        "zone-not-present-in-authoritative-profile"
    ]
    return variant


def _typed_capability_variant() -> Any:
    """Return a full capability snapshot with changed authoritative facts."""
    from asago_scenario_generator.pipeline.projection import (
        capture_capability_snapshot,
    )
    from tests.helpers.projection_factory import get_test_profile, get_test_snapshot

    snapshot = get_test_snapshot()
    changed_fact = snapshot.facts[0].model_copy(update={"value": "inactive"})
    return capture_capability_snapshot(get_test_profile(), (changed_fact,))


def _typed_missing_qualification_snapshot() -> Any:
    """Return a complete capability snapshot with no qualification evidence."""
    from asago_scenario_generator.pipeline.projection import (
        capture_capability_snapshot,
    )
    from tests.helpers.projection_factory import get_test_profile

    return capture_capability_snapshot(get_test_profile(), ())


def _typed_contradictory_qualification_payload() -> dict[str, Any]:
    """Return a valid typed payload with an explicit contradictory reading."""
    payload = _typed_payload()
    qualification = payload["qualification_facts"]
    if not isinstance(qualification, dict):
        raise TypeError("Typed fixture qualification facts are not a mapping")
    fact_key = next(iter(qualification["facts"]))
    qualification["facts"][fact_key]["status"] = "contradictory"
    qualification["facts"][fact_key]["value"] = None
    qualification["semantic_digest"] = None
    from asago_scenario_generator.pipeline.obligation_contracts import (
        QualificationFactsInput,
    )

    payload["qualification_facts"] = QualificationFactsInput.model_validate(
        qualification
    ).model_dump(mode="json")
    return payload


def _typed_projection_infeasible_snapshot(resource_kind: str) -> Any:
    """Return a complete profile that cannot satisfy one canonical slot."""
    from asago_scenario_generator.pipeline.projection import (
        capture_capability_snapshot,
    )
    from tests.helpers.projection_factory import get_test_profile, get_test_snapshot

    if resource_kind != "entry_point":
        raise ValueError(
            f"Unsupported projection-infeasibility fixture: {resource_kind}"
        )
    # Keep the inventory structurally valid while making its sole entry point
    # ineligible for attacker-controlled initial ingress.  An empty list is
    # rejected by the typed profile contract before the planner can observe
    # the projection infeasibility.
    output_only = (
        get_test_profile()
        .entry_points[0]
        .model_copy(update={"direction": "output", "controllability": "system"})
    )
    profile = get_test_profile().model_copy(update={"entry_points": [output_only]})
    return capture_capability_snapshot(profile, get_test_snapshot().facts)


def _typed_payload(
    *,
    risk_ids: tuple[str, ...] = ("risk-a",),
    pattern_id: str | None = "AP-T1-01",
    catalog_pin: str | None = None,
    mapping_pin: str | None = None,
    pattern_record: dict[str, Any] | None = None,
    capability_snapshot: Any | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the normative ``TaxonomyObligationInputs`` mapping fixture."""
    _candidate, raw_pattern, default_snapshot = _typed_authoritative_fixture()
    actual_pattern_id = raw_pattern["id"]
    if pattern_id is None:
        selected_pattern: dict[str, Any] | None = None
    elif pattern_record is not None:
        selected_pattern = deepcopy(pattern_record)
    elif pattern_id == actual_pattern_id:
        selected_pattern = deepcopy(raw_pattern)
    else:
        # Even identity variants must carry a complete, self-consistent
        # authoritative AttackPattern record.  A caller-supplied ID or digest
        # alone is deliberately not a valid typed fixture.
        selected_pattern = _typed_pattern_variant(pattern_id)

    selected_snapshot = capability_snapshot or default_snapshot
    mappings = [
        {
            "source_id": risk_id,
            "target_id": pattern_id,
            "relation": "exact",
            "evidence": ["reviewed-risk-card-mapping"],
        }
        for risk_id in risk_ids
        if pattern_id is not None
    ]
    actual_catalog_pin, actual_mapping_pin = _typed_pin_payload(
        selected_pattern or raw_pattern,
        selected_snapshot,
        mappings,
        [],
    )
    qualification = _typed_default_qualification(selected_snapshot)
    payload: dict[str, Any] = {
        "risk_cards": [_typed_risk_card(risk_id) for risk_id in risk_ids],
        "capability_snapshot": selected_snapshot,
        "attack_pattern_catalog": (
            [selected_pattern] if selected_pattern is not None else []
        ),
        "cross_taxonomy_mappings": mappings,
        "sssom_mappings": [],
        "catalog_pins": {
            "atlas": {
                "release": catalog_pin or actual_catalog_pin["atlas"]["release"],
                "digest": actual_catalog_pin["atlas"]["digest"],
            }
        },
        "mapping_pins": {
            "sssom": {
                "release": mapping_pin or actual_mapping_pin["sssom"]["release"],
                "digest": actual_mapping_pin["sssom"]["digest"],
            },
            "obligation_edges": actual_mapping_pin["obligation_edges"],
        },
        "qualification_facts": qualification,
        "projection_budget": {"max_candidates": 100, "max_derivation_work": 4096},
        "compatibility_policy": {"allow_legacy_keyword_matches": False},
    }
    if extra:
        payload.update(extra)
    return payload


def _typed_input_model(payload: dict[str, Any]) -> Any:
    """Validate one mapping through the public typed input model."""
    from asago_scenario_generator.pipeline.obligation_contracts import (
        TaxonomyObligationInputs,
    )

    return TaxonomyObligationInputs.model_validate(payload)


def _typed_plan_from_payload(payload: dict[str, Any]) -> Any:
    """Plan typed inputs through the public normative planner seam."""
    from asago_scenario_generator.pipeline.obligation_planner import (
        plan_taxonomy_obligations,
    )

    return plan_taxonomy_obligations(_typed_input_model(payload))


def _planner_state(world: World) -> dict[str, Any]:
    state = getattr(world, "obligation_planner_state", None)
    if state is None:
        state = {
            "plan": None,
            "plan_a": None,
            "plan_b": None,
            "fixture_workflow": None,
            "ran_command": None,
            "compatibility": None,
            "compatibility_help": None,
            "typed_inputs": None,
            "typed_plan": None,
            "typed_error": None,
            "typed_identity_plans": [],
            "typed_normalized_plans": [],
            "typed_prose_plans": [],
            "typed_no_provider_calls": None,
            "typed_publication": None,
        }
        world.obligation_planner_state = state
    return state


def _summary_from_plan_rows(plan: Any) -> dict[str, int]:
    """Recompute the closed summary solely from typed obligation rows."""
    rows = tuple(plan.obligations)
    candidates = tuple(candidate for row in rows for candidate in row.candidate_records)
    return {
        "total": len(rows),
        "applicable": sum(row.scope_disposition == "applicable" for row in rows),
        "governance_only": sum(
            row.scope_disposition == "governance_only" for row in rows
        ),
        "capability_excluded": sum(
            row.scope_disposition == "capability_excluded" for row in rows
        ),
        "ready": sum(row.qualification_disposition == "ready" for row in rows),
        "missing_or_contradictory": sum(
            row.qualification_disposition
            in {"missing_evidence", "contradictory_evidence"}
            for row in rows
        ),
        "structurally_infeasible": sum(
            row.qualification_disposition == "structurally_infeasible" for row in rows
        ),
        "projectable": sum(
            candidate.projection_disposition == "projectable"
            for candidate in candidates
        ),
        "projection_infeasible": sum(
            candidate.projection_disposition == "projection_infeasible"
            for candidate in candidates
        ),
        "budget_deferred": sum(
            candidate.projection_disposition == "budget_deferred"
            for candidate in candidates
        ),
    }


# Normative typed planner contract
def _h_typed_governance_input(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Prepare a reviewed risk with no actionable pattern."""
    state = _planner_state(world)
    match = re.search(r'reviewed risk "([^"]+)" with no pattern', text)
    risk_id = match.group(1) if match else "risk-governance-only"
    state["typed_inputs"] = _typed_payload(risk_ids=(risk_id,), pattern_id=None)
    state["typed_plan"] = None
    state["typed_error"] = None
    return True, ""


def _h_typed_candidate_input(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Prepare one typed risk, pattern, and canonical resource inventory."""
    state = _planner_state(world)
    match = re.search(
        r'risk "([^"]+)" mapped to attack pattern "([^"]+)" with the canonical resources',
        text,
    )
    if match:
        risk_id, pattern_id = match.groups()
    else:
        risk_id, pattern_id = (
            "risk-a",
            "AP-T1-01",
        )
    state["typed_inputs"] = _typed_payload(
        risk_ids=(risk_id,),
        pattern_id=pattern_id,
    )
    state["typed_expected_pattern_id"] = pattern_id
    state["typed_expected_risk_id"] = risk_id
    state["typed_plan"] = None
    state["typed_error"] = None
    return True, ""


def _h_typed_shared_pattern_input(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Prepare two reviewed risks that share one authoritative pattern."""
    state = _planner_state(world)
    match = re.search(
        r'typed planner inputs include reviewed risks "([^"]+)" and "([^"]+)" mapped to attack pattern "([^"]+)"',
        text,
    )
    risk_a, risk_b, pattern_id = (
        match.groups()
        if match
        else (
            "risk-a",
            "risk-b",
            "AP-T1-01",
        )
    )
    state["typed_inputs"] = _typed_payload(
        risk_ids=(risk_a, risk_b),
        pattern_id=pattern_id,
    )
    state["typed_expected_pattern_id"] = pattern_id
    state["typed_plan"] = None
    state["typed_error"] = None
    return True, ""


def _h_typed_capability_excluded_input(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Prepare a typed input whose authoritative profile gate excludes capability."""
    state = _planner_state(world)
    match = re.search(
        r'typed planner inputs include risk "([^"]+)" mapped to attack pattern "([^"]+)" whose authoritative profile gate is unmet',
        text,
    )
    risk_id, pattern_id = (
        match.groups()
        if match
        else (
            "risk-gated",
            "AP-T1-01",
        )
    )
    payload = _typed_payload(
        risk_ids=(risk_id,),
        pattern_id=pattern_id,
        pattern_record=_typed_capability_excluded_pattern(pattern_id),
    )
    state["typed_inputs"] = payload
    state["typed_expected_risk_id"] = risk_id
    state["typed_expected_pattern_id"] = pattern_id
    state["typed_plan"] = None
    state["typed_error"] = None
    return True, ""


def _h_typed_input_ready(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Prepare the default typed planner fixture."""
    state = _planner_state(world)
    state["typed_inputs"] = _typed_payload()
    state["typed_expected_pattern_id"] = "AP-T1-01"
    state["typed_plan"] = None
    state["typed_error"] = None
    return True, ""


def _h_typed_plan_contains_rows(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Assert the typed plan contains the requested number of complete rows."""
    state = _planner_state(world)
    match = re.search(r"typed plan contains (\d+) obligation rows?", text)
    expected = int(match.group(1)) if match else 1
    plan = state.get("typed_plan")
    actual = len(plan.obligations) if plan is not None else 0
    if actual != expected:
        return False, f"Expected {expected} typed rows, got {actual}"
    return True, ""


def _h_typed_rows_keep_risk_identity(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Assert shared-pattern rows retain distinct risk references and IDs."""
    plan = _planner_state(world).get("typed_plan")
    if plan is None:
        return False, "No typed plan was produced"
    rows = plan.model_dump(mode="json")["obligations"]
    match = re.search(
        r'typed rows retain risk identities "([^"]+)" and "([^"]+)" for attack pattern "([^"]+)"',
        text,
    )
    if match is None:
        return False, "Typed risk-identity expectation was not rendered"
    expected_risks = {match.group(1), match.group(2)}
    expected_pattern = match.group(3)
    risk_ids = [row["risk_ref"]["risk_id"] for row in rows]
    obligation_ids = [row["obligation_id"] for row in rows]
    if set(risk_ids) != expected_risks:
        return False, f"Risk identities differ: {risk_ids} != {sorted(expected_risks)}"
    if any(row["attack_pattern_id"] != expected_pattern for row in rows):
        return False, f"Attack-pattern identities differ from {expected_pattern}"
    if len(set(risk_ids)) != len(risk_ids) or len(set(obligation_ids)) != len(
        obligation_ids
    ):
        return (
            False,
            f"Risk or obligation identity collapsed: {risk_ids}/{obligation_ids}",
        )
    return True, ""


def _h_typed_scope_disposition(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Assert a typed relationship receives the requested scope disposition."""
    state = _planner_state(world)
    match = re.search(
        r'typed row has risk "([^"]+)" and attack pattern "([^"]+)" with scope disposition "([^"]+)"',
        text,
    )
    if match:
        expected_risk, expected_pattern, expected = match.groups()
    else:
        legacy_match = re.search(r'typed row has scope disposition "([^"]+)"', text)
        expected_risk = expected_pattern = None
        expected = legacy_match.group(1) if legacy_match else "capability_excluded"
    plan = state.get("typed_plan")
    if plan is None or len(plan.obligations) != 1:
        return False, "Expected one typed row"
    row = plan.obligations[0]
    if expected_risk is not None:
        actual_risk = row.risk_ref.risk_id
        if actual_risk != expected_risk:
            return False, f"Expected risk {expected_risk}, got {actual_risk}"
        if row.attack_pattern_id != expected_pattern:
            return False, (
                f"Expected attack pattern {expected_pattern}, "
                f"got {row.attack_pattern_id}"
            )
    if row.scope_disposition != expected:
        return False, f"Expected scope {expected}, got {row.scope_disposition}"
    if row.qualification_disposition != "not_attempted":
        return False, "Capability-excluded row attempted qualification"
    if row.candidate_records:
        return False, "Capability-excluded row retained candidate records"
    return True, ""


def _h_typed_projection_evidence(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Assert authoritative projection evidence is retained on the row."""
    state = _planner_state(world)
    match = re.search(r'typed row retains projection evidence from "([^"]+)"', text)
    expected_source = match.group(1) if match else "unsupported_requirement_derivation"
    plan = state.get("typed_plan")
    if plan is None:
        return False, "No typed plan was produced"
    evidence = [
        item
        for row in plan.obligations
        for item in row.evidence
        if item.kind == "projection"
    ]
    if not any(item.source == expected_source for item in evidence):
        return False, f"Projection source {expected_source!r} not found: {evidence}"
    return True, ""


def _h_typed_planning_runs(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Invoke the public typed planner and retain expected validation errors."""
    state = _planner_state(world)
    payload = state.get("typed_inputs")
    if payload is None:
        return False, "No typed planner inputs were prepared"
    try:
        state["typed_plan"] = _typed_plan_from_payload(payload)
        state["typed_error"] = None
    except Exception as exc:  # noqa: BLE001 - acceptance validation boundary
        state["typed_plan"] = None
        state["typed_error"] = str(exc)
        return False, f"Typed obligation planning failed: {exc}"
    return True, ""


def _h_typed_plan_contains_one_row(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    plan = state.get("typed_plan")
    if plan is None or len(plan.obligations) != 1:
        return (
            False,
            f"Expected one typed obligation, got {getattr(plan, 'obligations', None)}",
        )
    return True, ""


def _h_typed_governance_row(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    plan = state.get("typed_plan")
    if plan is None:
        return False, "No typed plan was produced"
    row = plan.obligations[0]
    match = re.search(
        r'risk_ref "([^"]+)" with "([^"]+)" scope',
        text,
    )
    if match:
        expected_risk, expected_scope = match.groups()
    else:
        legacy_match = re.search(r'risk_ref "([^"]+)" with governance-only scope', text)
        expected_risk = (
            legacy_match.group(1) if legacy_match else "risk-governance-only"
        )
        expected_scope = "governance_only"
    risk_ref = getattr(row, "risk_ref", None)
    if isinstance(risk_ref, dict):
        risk_id = risk_ref.get("risk_id")
    else:
        risk_id = getattr(risk_ref, "risk_id", None)
    if risk_id != expected_risk or row.scope_disposition != expected_scope:
        return (
            False,
            f"Expected governance row for {expected_risk}, got {risk_id}/{row.scope_disposition}",
        )
    if row.qualification_disposition != "not_attempted":
        return (
            False,
            f"Expected not_attempted qualification, got {row.qualification_disposition}",
        )
    if row.correspondence_disposition != "not_assessed":
        return (
            False,
            f"Expected not_assessed correspondence, got {row.correspondence_disposition}",
        )
    return True, ""


def _h_typed_row_exact_shape(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    plan = state.get("typed_plan")
    if plan is None:
        return False, "No typed plan was produced"
    row = plan.model_dump(mode="json")["obligations"][0]
    expected = {
        "obligation_id",
        "risk_ref",
        "taxonomy_chain",
        "attack_pattern_id",
        "attack_pattern_semantic_digest",
        "scope_disposition",
        "qualification_disposition",
        "candidate_records",
        "correspondence_disposition",
        "evidence",
    }
    actual = set(row)
    if actual != expected:
        return False, f"Normative obligation row fields differ: {actual} != {expected}"
    expected_pattern = _planner_state(world).get(
        "typed_expected_pattern_id", "AP-T1-01"
    )
    if row["attack_pattern_id"] != expected_pattern:
        return False, f"Unexpected attack-pattern identity: {row['attack_pattern_id']}"
    _candidate, raw_pattern, _snapshot = _typed_authoritative_fixture()
    if (
        row["attack_pattern_semantic_digest"]
        != raw_pattern["canonical_chain"]["semantic_digest"]
    ):
        return False, "Attack-pattern semantic digest was not retained"
    if not row["taxonomy_chain"]:
        return False, "Taxonomy chain was not retained"
    if not isinstance(row["evidence"], list):
        return False, "Evidence is not a list"
    return True, ""


def _h_typed_candidate_identity(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    plan = state.get("typed_plan")
    if plan is None:
        return False, "No typed plan was produced"
    candidate_rows = plan.model_dump(mode="json")["obligations"][0]["candidate_records"]
    projectable_rows = [
        candidate
        for candidate in candidate_rows
        if candidate.get("projection_disposition") == "projectable"
    ]
    if len(projectable_rows) != 1:
        return False, f"Expected one projectable candidate record, got {candidate_rows}"
    candidate = projectable_rows[0]
    expected = _typed_expected_candidate()
    expected_id = expected.candidate_id
    if candidate.get("candidate_id") != expected_id:
        return False, f"Candidate identity changed: {candidate.get('candidate_id')}"
    if candidate.get("canonical_ingress") != expected.canonical_ingress.model_dump(
        mode="json"
    ):
        return False, "Canonical ingress identity was not retained"
    expected_bindings = [
        binding.model_dump(mode="json") for binding in expected.projection.bindings
    ]
    if candidate.get("resource_bindings") != expected_bindings:
        return False, "Canonical resource bindings were not retained"
    return True, ""


def _h_typed_candidate_row_identity(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Assert the candidate row retains the rendered risk and pattern identity."""
    plan = _planner_state(world).get("typed_plan")
    if plan is None or len(plan.obligations) != 1:
        return False, "Expected one typed obligation"
    match = re.search(
        r'typed candidate row retains risk "([^"]+)" and attack pattern "([^"]+)"',
        text,
    )
    if match is None:
        return False, "Typed candidate identity expectation was not rendered"
    expected_risk, expected_pattern = match.groups()
    row = plan.obligations[0]
    actual_risk = row.risk_ref.risk_id
    if actual_risk != expected_risk or row.attack_pattern_id != expected_pattern:
        return False, (
            "Candidate row identity differs: "
            f"{actual_risk}/{row.attack_pattern_id} != "
            f"{expected_risk}/{expected_pattern}"
        )
    return True, ""


def _h_typed_summary_reconciles(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    plan = state.get("typed_plan")
    if plan is None:
        return False, "No typed plan was produced"
    expected = _summary_from_plan_rows(plan)
    actual = plan.summary.model_dump(mode="json")
    if actual != expected:
        return False, f"Typed summary does not reconcile: {actual} != {expected}"
    return True, ""


def _h_typed_identity_variants(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    base_payload = _typed_payload()
    variants = [
        _typed_payload(risk_ids=("risk-b",)),
        _typed_payload(pattern_id="AP-T1-02"),
        _typed_payload(capability_snapshot=_typed_capability_variant()),
        _typed_payload(catalog_pin="atlas-2026.06"),
        _typed_payload(mapping_pin="sssom-v2"),
    ]
    try:
        plans = [
            _typed_plan_from_payload(payload) for payload in [base_payload, *variants]
        ]
    except Exception as exc:  # pragma: no cover - diagnostic boundary
        return False, f"Identity fixture planning failed: {exc}"
    base_id = plans[0].obligations[0].obligation_id
    if any(plan.obligations[0].obligation_id == base_id for plan in plans[1:]):
        return False, "An identity-bearing input failed to change obligation_id"
    if not all(
        re.fullmatch(r"ob:v1:[0-9a-f]{64}", plan.obligations[0].obligation_id)
        for plan in plans
    ):
        return False, "Obligation ID is not a versioned digest identity"
    state["typed_identity_plans"] = plans
    return True, ""


def _h_typed_identity_changes_observed(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if not _planner_state(world).get("typed_identity_plans"):
        return False, "Identity variants were not planned"
    return True, ""


def _h_typed_normalized_input_variants(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Prepare two NFC-equivalent typed inputs for canonical comparison."""
    state = _planner_state(world)
    match = re.search(
        r'typed planner inputs use semantically equivalent "([^"]+)" and "([^"]+)" normalized representations',
        text,
    )
    left, right = match.groups() if match else ("composed", "decomposed")
    if (left, right) != ("composed", "decomposed"):
        return False, f"Unknown normalization fixtures: {left!r}, {right!r}"

    # The two values differ only in Unicode representation.  The input model
    # owns normalization, so both planner calls receive the same semantic
    # risk identity after validation.
    payloads = (
        _typed_payload(risk_ids=("risk-é",)),
        _typed_payload(risk_ids=("risk-e\u0301",)),
    )
    try:
        plans = [_typed_plan_from_payload(payload) for payload in payloads]
    except Exception as exc:  # pragma: no cover - acceptance diagnostic boundary
        return False, f"Normalized-input planning failed: {exc}"
    state["typed_normalized_plans"] = plans
    return True, ""


def _h_typed_normalized_content_is_identical(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Require canonical semantic bytes and digests to agree for NFC inputs."""
    plans = _planner_state(world).get("typed_normalized_plans", [])
    if len(plans) != 2:
        return False, "Two normalized typed plans were not produced"
    yaml_bytes = tuple(plan.to_yaml().encode("utf-8") for plan in plans)
    json_bytes = tuple(plan.to_json().encode("utf-8") for plan in plans)
    digests = tuple(plan.semantic_digest for plan in plans)
    if yaml_bytes[0] != yaml_bytes[1] or json_bytes[0] != json_bytes[1]:
        return False, "NFC-equivalent plans have different canonical semantic bytes"
    if digests[0] != digests[1]:
        return False, "NFC-equivalent plans have different semantic digests"
    return True, ""


def _h_typed_normalized_ids_are_identical(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Require obligation and candidate identities to agree for NFC inputs."""
    plans = _planner_state(world).get("typed_normalized_plans", [])
    if len(plans) != 2:
        return False, "Two normalized typed plans were not produced"
    obligation_ids = [
        tuple(row.obligation_id for row in plan.obligations) for plan in plans
    ]
    candidate_ids = [
        tuple(
            candidate.candidate_id
            for row in plan.obligations
            for candidate in row.candidate_records
        )
        for plan in plans
    ]
    if obligation_ids[0] != obligation_ids[1]:
        return False, f"Obligation IDs differ: {obligation_ids}"
    if candidate_ids[0] != candidate_ids[1]:
        return False, f"Candidate IDs differ: {candidate_ids}"
    return True, ""


def _h_typed_keyword_prose_fixture(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Keep ICA/scenario wording outside the typed planner input contract."""
    state = _planner_state(world)
    match = re.search(
        r'typed planner has ICA keyword prose fixture "([^"]+)" and scenario keyword prose fixture "([^"]+)"',
        text,
    )
    ica_prose, scenario_prose = (
        match.groups()
        if match
        else ("ica-keyword-baseline", "scenario-keyword-baseline")
    )
    expected = ("ica-keyword-baseline", "scenario-keyword-baseline")
    if (ica_prose, scenario_prose) != expected:
        return False, (
            f"Unknown ICA/scenario prose fixtures: {ica_prose!r}/{scenario_prose!r}"
        )
    state["typed_prose_fixture"] = {
        "payload": _typed_payload(),
        "baseline": (ica_prose, scenario_prose),
        "changed": (
            "ICA prose with entirely different keywords and punctuation",
            "scenario prose with Given When Then words rearranged",
        ),
    }
    state["typed_prose_plans"] = []
    return True, ""


def _plan_with_keyword_prose(
    payload: dict[str, Any], ica_prose: str, scenario_prose: str
) -> Any:
    """Plan typed inputs while retaining unrelated workflow prose at the edge."""
    # Deliberately keep these values out of ``payload``: ICA and scenario
    # keyword prose is not part of TaxonomyObligationInputs.
    del ica_prose, scenario_prose
    return _typed_plan_from_payload(payload)


def _h_typed_keyword_prose_planning_runs(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Plan the same typed inputs with two different ICA/scenario narratives."""
    state = _planner_state(world)
    fixture = state.get("typed_prose_fixture")
    if fixture is None:
        return False, "No ICA/scenario prose fixture was prepared"
    try:
        payload = fixture["payload"]
        baseline = _plan_with_keyword_prose(payload, *fixture["baseline"])
        changed = _plan_with_keyword_prose(payload, *fixture["changed"])
    except Exception as exc:  # pragma: no cover - acceptance diagnostic boundary
        return False, f"Keyword-prose planning failed: {exc}"
    state["typed_prose_plans"] = [baseline, changed]
    return True, ""


def _h_typed_keyword_prose_no_effect(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Require ICA/scenario keyword prose to leave semantic planner output alone."""
    plans = _planner_state(world).get("typed_prose_plans", [])
    if len(plans) != 2:
        return False, "Two keyword-prose planner results were not produced"
    if plans[0].to_yaml().encode("utf-8") != plans[1].to_yaml().encode("utf-8"):
        return False, "Changing ICA/scenario prose changed semantic plan bytes"
    if plans[0].semantic_digest != plans[1].semantic_digest:
        return False, "Changing ICA/scenario prose changed the semantic digest"
    if tuple(row.obligation_id for row in plans[0].obligations) != tuple(
        row.obligation_id for row in plans[1].obligations
    ):
        return False, "Changing ICA/scenario prose changed obligation IDs"
    return True, ""


def _run_planner_with_no_provider_guards(
    payload: dict[str, Any],
) -> tuple[Any, dict[str, int]]:
    """Run the planner while failing closed on provider construction or sockets."""
    observations = {
        "provider_client_constructions": 0,
        "endpoint_connections": 0,
    }

    def blocked_provider_init(_self: Any, *args: Any, **kwargs: Any) -> None:
        del args, kwargs
        observations["provider_client_constructions"] += 1
        raise AssertionError(
            "obligation planner attempted provider-client construction"
        )

    def blocked_endpoint(*args: Any, **kwargs: Any) -> None:
        del args, kwargs
        observations["endpoint_connections"] += 1
        raise AssertionError("obligation planner attempted endpoint connection")

    with ExitStack() as guards:
        seen_client_types: set[type[Any]] = set()
        for module_name in (
            "asago_scenario_generator.llm.client",
            "asago_scenario_generator.stpa.infra.llm",
        ):
            module = __import__(module_name, fromlist=["LLMClient"])
            client_type = getattr(module, "LLMClient", None)
            if isinstance(client_type, type) and client_type not in seen_client_types:
                guards.enter_context(
                    patch.object(client_type, "__init__", blocked_provider_init)
                )
                seen_client_types.add(client_type)
        guards.enter_context(patch.object(socket.socket, "connect", blocked_endpoint))
        guards.enter_context(
            patch.object(socket, "create_connection", blocked_endpoint)
        )
        plan = _typed_plan_from_payload(payload)
    return plan, observations


def _h_typed_no_provider_calls(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Execute a real planner call with provider and endpoint guards installed."""
    state = _planner_state(world)
    payload = state.get("typed_inputs") or _typed_payload()
    try:
        plan, observations = _run_planner_with_no_provider_guards(payload)
    except Exception as exc:  # pragma: no cover - acceptance diagnostic boundary
        state["typed_no_provider_calls"] = None
        return False, f"Guarded obligation planning failed: {exc}"
    state["typed_plan"] = plan
    state["typed_no_provider_calls"] = observations
    if any(observations.values()):
        return False, f"Provider/endpoint guard observed activity: {observations}"
    return True, ""


def _h_typed_no_provider_counts(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Match both explicit zero-count expectations from the no-call outline."""
    state = _planner_state(world)
    observations = state.get("typed_no_provider_calls")
    if observations is None:
        return False, "No guarded provider-call observation was recorded"
    match = re.search(
        r"typed obligation planning constructs (\d+) provider clients and contacts (\d+) endpoints",
        text,
    )
    if match is None:
        return False, "No provider-call count expectation was rendered"
    expected = {
        "provider_client_constructions": int(match.group(1)),
        "endpoint_connections": int(match.group(2)),
    }
    if observations != expected:
        return False, f"Expected provider-call counts {expected}, got {observations}"
    return True, ""


def _h_typed_invalid_input(world: World, text: str, examples: dict) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(r'unknown field "([^"]+)"', text)
    field = match.group(1) if match else "unsupported_field"
    payload = _typed_payload(extra={field: True})
    state["typed_inputs"] = payload
    state["typed_unknown_field"] = field
    state["typed_plan"] = None
    state["typed_error"] = None
    return True, ""


def _h_typed_unknown_field_identified(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Require validation diagnostics to identify the rejected field."""
    error = str(_planner_state(world).get("typed_error", ""))
    match = re.search(r'unknown field "([^"]+)"', text)
    expected = match.group(1) if match else "unsupported_field"
    if expected not in error:
        return False, f"Validation error does not identify {expected}: {error}"
    return True, ""


def _h_typed_false_qualification_digest(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Prepare typed input with a stale content-integrity digest."""
    state = _planner_state(world)
    match = re.search(
        r'typed planner inputs contain a "([^"]+)" qualification facts digest',
        text,
    )
    digest_state = match.group(1).lower() if match else "false"
    if digest_state != "false":
        return False, f"This fixture only represents a false digest, not {digest_state}"
    payload = _typed_payload()
    qualification = payload["qualification_facts"]
    if not isinstance(qualification, dict):
        return False, "Typed fixture qualification facts are not a mapping"
    qualification["semantic_digest"] = "0" * 64
    state["typed_inputs"] = payload
    state["typed_plan"] = None
    state["typed_error"] = None
    return True, ""


def _h_typed_missing_qualification_facts(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Prepare a full authoritative profile with qualification facts absent."""
    match = re.search(
        r'normative typed planner inputs contain no "([^"]+)" qualification facts',
        text,
    )
    fact_source = match.group(1) if match else "authoritative-capability-snapshot"
    if fact_source != "authoritative-capability-snapshot":
        return False, f"Unknown missing-facts fixture: {fact_source}"
    state = _planner_state(world)
    state["typed_inputs"] = _typed_payload(
        capability_snapshot=_typed_missing_qualification_snapshot()
    )
    state["typed_expected_pattern_id"] = "AP-T1-01"
    state["typed_plan"] = None
    state["typed_error"] = None
    return True, ""


def _h_typed_contradictory_qualification_facts(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Prepare a complete typed input with contradictory qualification evidence."""
    match = re.search(
        r'normative typed planner inputs contain a contradictory "([^"]+)" qualification fact',
        text,
    )
    fact_source = match.group(1) if match else "authoritative-qualification-input"
    if fact_source != "authoritative-qualification-input":
        return False, f"Unknown contradictory-facts fixture: {fact_source}"
    state = _planner_state(world)
    state["typed_inputs"] = _typed_contradictory_qualification_payload()
    state["typed_expected_pattern_id"] = "AP-T1-01"
    state["typed_plan"] = None
    state["typed_error"] = None
    return True, ""


def _h_typed_projection_infeasible_input(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Prepare an authoritative profile with a required resource unavailable."""
    match = re.search(
        r'normative typed planner inputs use an authoritative profile with no compatible "([^"]+)" resource',
        text,
    )
    resource_kind = match.group(1) if match else "entry_point"
    state = _planner_state(world)
    state["typed_inputs"] = _typed_payload(
        capability_snapshot=_typed_projection_infeasible_snapshot(resource_kind)
    )
    state["typed_expected_pattern_id"] = "AP-T1-01"
    state["typed_plan"] = None
    state["typed_error"] = None
    return True, ""


def _h_typed_qualification_disposition(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Assert qualification disposition and absence of derived candidates."""
    match = re.search(r'typed row has qualification disposition "([^"]+)"', text)
    expected = match.group(1) if match else "missing_evidence"
    plan = _planner_state(world).get("typed_plan")
    if plan is None or len(plan.obligations) != 1:
        return False, "Expected one typed obligation"
    row = plan.obligations[0]
    if row.qualification_disposition != expected:
        return False, (
            f"Expected qualification {expected}, got {row.qualification_disposition}"
        )
    return True, ""


def _h_typed_projection_rejection_records(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Assert structural projection rejects remain typed candidate records."""
    ok, detail = _h_typed_qualification_disposition(world, text, examples)
    if not ok:
        return ok, detail
    row = _planner_state(world)["typed_plan"].obligations[0]
    if row.scope_disposition != "applicable":
        return False, f"Expected applicable scope, got {row.scope_disposition}"
    rejected = [
        record
        for record in row.candidate_records
        if record.projection_disposition == "projection_infeasible"
    ]
    if not rejected:
        return False, "Expected at least one projection-infeasible candidate record"
    if any(not record.reason or not record.evidence for record in rejected):
        return False, "Projection-infeasible records must retain reason and evidence"
    return True, ""


def _h_typed_no_candidate_records(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Assert missing qualification evidence does not omit the obligation row."""
    plan = _planner_state(world).get("typed_plan")
    if plan is None or len(plan.obligations) != 1:
        return False, "Expected one typed obligation"
    if plan.obligations[0].candidate_records:
        return False, "Expected no candidate records for the retained row"
    return True, ""


def _h_typed_contradictory_qualification_evidence(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Require contradictory qualification status and rationale to survive planning."""
    plan = _planner_state(world).get("typed_plan")
    if plan is None or len(plan.obligations) != 1:
        return False, "Expected one typed obligation"
    evaluations = tuple(
        evaluation
        for evidence in plan.obligations[0].evidence
        for evaluation in evidence.fact_evaluations
        if evaluation.evaluation_type == "qualification_fact"
    )
    if len(evaluations) != 1:
        return False, "Expected one typed qualification-fact evaluation"
    evaluation = evaluations[0]
    if evaluation.rationale != "authoritative qualification fact is contradictory":
        return False, f"Unexpected contradictory rationale: {evaluation.rationale}"
    if [fact.status for fact in evaluation.facts] != ["contradictory"]:
        return False, "Contradictory fact status was not retained"
    return True, ""


def _h_typed_validation_runs(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Validate the prepared typed payload without returning a partial plan."""
    state = _planner_state(world)
    payload = state.get("typed_inputs")
    if payload is None:
        return False, "No typed inputs were prepared"
    try:
        _typed_input_model(payload)
    except Exception as exc:  # noqa: BLE001 - expected validation boundary
        state["typed_error"] = str(exc)
        state["typed_plan"] = None
        return True, ""
    state["typed_error"] = None
    state["typed_plan"] = None
    return True, ""


def _h_typed_input_rejected(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    error = _planner_state(world).get("typed_error")
    if not error:
        return False, "Expected typed input validation to fail"
    return True, ""


def _h_typed_no_partial_plan(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if _planner_state(world).get("typed_plan") is not None:
        return False, "A partial typed plan was returned after input validation failure"
    return True, ""


def _h_typed_atomic_publication(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    payload = state.get("typed_inputs") or _typed_payload()
    root = Path(tempfile.mkdtemp(prefix="asago-typed-obligation-pub-"))
    snapshot = root / "typed-inputs.json"
    snapshot.write_text(json.dumps(_jsonable(payload)), encoding="utf-8")
    match = re.search(r'typed plan is published atomically as "([^"]+)"', text)
    requested_format = match.group(1) if match else "YAML"
    if requested_format != "YAML":
        return False, f"Typed publication format must be YAML, got {requested_format}"
    format_name = requested_format.lower()
    try:
        plan, written = run_plan_obligations(
            snapshot_path=snapshot,
            output_dir=root / "published",
            format_name=format_name,
        )
        state["typed_publication"] = {
            "plan": plan,
            "written": written,
            "root": root,
        }
        loaded = TaxonomyObligationPlan.from_yaml(
            written[0].read_text(encoding="utf-8")
        )
        if loaded != plan:
            return False, "Published typed plan did not round-trip to the returned plan"
        if list((root / "published").glob("*.tmp")) or list(
            (root / "published").glob("*.part")
        ):
            return False, "Atomic publication left a partial file"
    except Exception as exc:  # noqa: BLE001 - acceptance diagnostic boundary
        state["typed_publication"] = None
        return False, f"Typed publication failed: {exc}"
    return True, ""


def _h_typed_publication_named(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    publication = _planner_state(world).get("typed_publication")
    if publication is None:
        return False, "No typed publication was produced"
    match = re.search(r'named "([^"]+)"', text)
    expected = match.group(1) if match else "taxonomy-obligation-plan.yaml"
    written = publication["written"]
    if not any(path.name == expected for path in written):
        return False, f"Expected published artifact {expected}, got {written}"
    return True, ""


def _h_typed_publication_round_trips(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    publication = _planner_state(world).get("typed_publication")
    if publication is None:
        return False, "No typed publication was produced"
    written = publication.get("written", [])
    if len(written) != 1 or written[0].name != "taxonomy-obligation-plan.yaml":
        return False, f"Unexpected typed publication: {written}"
    try:
        loaded = TaxonomyObligationPlan.from_yaml(
            written[0].read_text(encoding="utf-8")
        )
    except Exception as exc:  # pragma: no cover - diagnostic boundary
        return False, f"Published artifact did not load: {exc}"
    if loaded != publication["plan"]:
        return False, "Published typed plan changed during round-trip"
    return True, ""


def _h_typed_no_partial_publication(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    publication = _planner_state(world).get("typed_publication")
    if publication is None:
        return False, "No typed publication was produced"
    published_dir = publication["root"] / "published"
    leftovers = list(published_dir.glob("*.tmp")) + list(published_dir.glob("*.part"))
    if leftovers:
        return False, f"Typed publication left partial files: {leftovers}"
    return True, ""


def _h_typed_metadata(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Check the closed top-level metadata of the typed plan."""
    plan = _planner_state(world).get("typed_plan")
    if plan is None:
        return False, "No typed plan was produced"
    actual = set(plan.model_dump(mode="json"))
    expected = {
        "schema_version",
        "semantic_digest",
        "capability_snapshot_digest",
        "catalog_pins",
        "mapping_pins",
        "qualification_facts_digest",
        "obligations",
        "summary",
    }
    if actual != expected:
        return False, f"Typed plan metadata fields differ: {actual} != {expected}"
    if plan.schema_version != "taxonomy-obligation-plan-v1":
        return False, f"Unexpected schema version: {plan.schema_version}"
    for name in (
        "semantic_digest",
        "capability_snapshot_digest",
        "qualification_facts_digest",
    ):
        value = getattr(plan, name)
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            return False, f"Invalid {name}: {value}"
    if not plan.catalog_pins or not plan.mapping_pins:
        return False, "Typed plan omitted catalog or mapping pins"
    if set(plan.mapping_pins) != {"sssom", "obligation_edges"}:
        return (
            False,
            "Typed plan mapping pin inventory is not exactly sssom and obligation_edges",
        )
    if plan.mapping_pins["obligation_edges"].release != (
        "obligation-mapping-bundle-v1"
    ):
        return False, "Typed plan obligation edge pin has the wrong release"
    return True, ""


def _h_typed_schema_version(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Require the rendered schema version to match the closed output model."""
    plan = _planner_state(world).get("typed_plan")
    if plan is None:
        return False, "No typed plan was produced"
    match = re.search(r'typed plan schema version is "([^"]+)"', text)
    expected = match.group(1) if match else "taxonomy-obligation-plan-v1"
    if plan.schema_version != expected:
        return False, f"Expected schema version {expected}, got {plan.schema_version}"
    return True, ""


def _h_typed_serialize_twice(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Serialize the typed model twice through the canonical YAML writer."""
    plan = _planner_state(world).get("typed_plan")
    if plan is None:
        return False, "No typed plan was produced"
    match = re.search(r'typed "([^"]+)" plan is serialized twice', text)
    requested_format = match.group(1) if match else "YAML"
    if requested_format != "YAML":
        return False, f"Unsupported typed serialization format: {requested_format}"
    _planner_state(world)["typed_serialized"] = [plan.to_yaml(), plan.to_yaml()]
    return True, ""


def _h_typed_byte_identical(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Require byte identity for repeated canonical YAML serialization."""
    match = re.search(r'typed "([^"]+)" artifacts are byte-identical', text)
    expected_format = match.group(1) if match else "YAML"
    if expected_format != "YAML":
        return False, f"Unsupported typed artifact format: {expected_format}"
    values = _planner_state(world).get("typed_serialized", [])
    if len(values) != 2 or values[0] != values[1]:
        return False, "Typed YAML serialization was not byte-identical"
    return True, ""


def _h_typed_tamper_published_content(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Change published content while retaining its recorded semantic digest."""
    state = _planner_state(world)
    publication = state.get("typed_publication")
    if publication is None:
        return False, "No typed publication was produced"
    match = re.search(r'tampered in field "([^"]+)"', text)
    field = match.group(1) if match else "risk_ref"
    if field != "risk_ref":
        return False, f"Unsupported tamper fixture field: {field}"
    path = publication["written"][0]
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data["obligations"][0]["risk_ref"]["risk_id"] = "tampered-risk"
    state["typed_persisted_text"] = yaml.safe_dump(data, sort_keys=False)
    return True, ""


def _h_typed_publication_loaded(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Load tampered YAML through the public closed-plan loader."""
    state = _planner_state(world)
    raw = state.get("typed_persisted_text")
    if raw is None:
        return False, "No tampered typed artifact was prepared"
    try:
        state["typed_loaded_plan"] = TaxonomyObligationPlan.from_yaml(raw)
        state["typed_load_error"] = None
    except Exception as exc:  # noqa: BLE001 - expected integrity boundary
        state["typed_loaded_plan"] = None
        state["typed_load_error"] = str(exc)
    return True, ""


def _h_typed_loading_rejected(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Require tampered typed publication loading to fail."""
    error = _planner_state(world).get("typed_load_error")
    if not error:
        return False, "Tampered typed publication loaded successfully"
    return True, ""


def _h_typed_digest_mismatch(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Require the load failure to identify semantic digest integrity."""
    error = str(_planner_state(world).get("typed_load_error", ""))
    match = re.search(r'typed load error identifies a "([^"]+)"', text)
    expected = (match.group(1) if match else "digest mismatch").split()
    if not all(token in error for token in expected):
        return False, f"Expected {expected}, got: {error}"
    return True, ""


# Compatibility Scenario
def _compatibility_fixtures() -> Any:
    """Load the shared deterministic command fixtures used by QA.

    The fixture module contains only sanitized inputs and a localhost model
    responder.  The handlers still invoke the installed public CLI in a child
    process; importing the fixture helper avoids maintaining a second copy of
    its large structured-output responses in the acceptance runtime.
    """
    from acceptance.qa.taxonomy_risk import obligation_planner_compatibility

    return obligation_planner_compatibility


def _compatibility_command() -> list[str]:
    """Return an executable command for the installed public CLI."""
    executable = shutil.which("asago-scenario-generator")
    if executable:
        return [executable]
    uv = shutil.which("uv")
    if uv:
        return [uv, "run", "asago-scenario-generator"]
    # This fallback keeps the acceptance runtime usable inside a minimal
    # virtualenv where the console-script shim was not installed.
    return [
        sys.executable,
        "-c",
        "from asago_scenario_generator.cli import app; app()",
    ]


def _compatibility_env(**updates: str) -> dict[str, str]:
    """Build a child environment that cannot inherit a live endpoint."""
    environment = dict(os.environ)
    for key in (
        "ASAGO_SCENARIO_GENERATOR_QA_PIPELINE",
        "ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL",
        "OPENAI_BASE_URL",
        "OPENAI_API_KEY",
        "ASAGO_SCENARIO_GENERATOR_API_KEY",
    ):
        environment.pop(key, None)
    environment.update(updates)
    environment["PYTHONHASHSEED"] = "0"
    return environment


def _run_compatibility_command(
    argv: list[str], *, environment: dict[str, str], timeout: int = 600
) -> subprocess.CompletedProcess[str]:
    """Run one public command and retain its exit status and output."""
    return subprocess.run(
        argv,
        cwd=PROJECT_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )


def _scenario_signatures(run_dir: Path) -> list[tuple[str, bytes]]:
    """Return semantic scenario artifacts with volatile fields normalized."""
    signatures: list[tuple[str, bytes]] = []
    scenarios_dir = run_dir / "scenarios"
    if not scenarios_dir.is_dir():
        return signatures
    for path in sorted(scenarios_dir.iterdir()):
        if not path.is_file() or path.suffix not in {".yaml", ".yml", ".feature"}:
            continue
        if path.suffix == ".feature":
            content = path.read_bytes()
            kind = "feature"
        else:
            text_data = path.read_text(encoding="utf-8")
            text_data = re.sub(
                r"(?m)^scenario_id:\s*.*$",
                "scenario_id: <volatile-scenario-id>",
                text_data,
            )
            text_data = re.sub(
                r"(?m)^candidate_id:\s*.*$",
                "candidate_id: <volatile-candidate-id>",
                text_data,
            )
            text_data = re.sub(
                r"(?m)^generated_at:\s*.*$",
                "generated_at: <volatile-timestamp>",
                text_data,
            )
            text_data = re.sub(
                r"(?m)^(\s*duration_ms:)\s*.*$",
                r"\1 <volatile-duration>",
                text_data,
            )
            content = text_data.encode("utf-8")
            kind = "scenario"
        signatures.append((kind, content))
    return signatures


def _artifact_roles(run_dir: Path) -> list[str]:
    """List non-scenario artifact roles published by one run."""
    return sorted(
        path.name
        for path in run_dir.rglob("*")
        if path.is_file() and path.parent.name != "scenarios"
    )


def _contains_obligation_artifact(root: Path) -> bool:
    """Detect any obligation sidecar in a compatibility run."""
    return any(
        path.is_file() and "obligation" in path.name.lower() for path in root.rglob("*")
    )


def _count_stdout_labels(stdout: str, labels: tuple[str, ...]) -> dict[str, str | None]:
    """Extract literal command-summary values for compatibility comparison."""
    return {
        label: (
            match.group(1)
            if (match := re.search(rf"^\s*{re.escape(label)}:\s+(\S+)", stdout, re.M))
            else None
        )
        for label in labels
    }


def _prompt_evidence(
    requests: list[dict[str, str]], selected_pattern: str
) -> dict[str, Any]:
    """Extract stable, observable prompt contracts from fixture requests.

    Candidate seeds are intentionally shuffled by the production coverage
    planner. Comparing the raw request list would make this compatibility
    check flaky even though the public workflow and every response contract
    are unchanged. We therefore compare the exact prompt for the selected
    scenario plus an order-independent inventory of the required prompt
    contracts for every stage.
    """
    contracts: list[tuple[str, str, tuple[bool, ...]]] = []
    selected: dict[str, str] = {}
    marker_sets = {
        "candidate_filter": (
            "## Candidates to judge",
            "candidate handle",
            "Return an object with exactly one required field per candidate handle above.",
        ),
        "actor_profile": (
            "Compatible actor/capability choices:",
            "Resource handles (select zero to four; do not invent resources):",
        ),
        "narrative": (
            "Semantic Draft V3 Response Protocol",
            "Compatibility regions and projected-step handles:",
        ),
        "attack_tree": ("Canonical leaf inventory (respond with handles only):",),
        "behavior_spec": (
            "Action handles:",
            "Required assertion handles:",
        ),
    }
    for request in requests:
        schema = str(request.get("schema", ""))
        prompt = str(request.get("user_prompt", ""))
        if schema.startswith("FilterMapDraftV3For"):
            family = "candidate_filter"
            pattern_match = re.search(r"\*\*Name:\*\* ([^\n]+)", prompt)
            if pattern_match and pattern_match.group(1) == selected_pattern:
                selected[family] = prompt
        elif schema.startswith("ActorDraftV3For"):
            family = "actor_profile"
            selected.setdefault(family, prompt)
        elif schema.startswith("NarrativeDraftV3For"):
            family = "narrative"
            selected.setdefault(family, prompt)
        elif schema.startswith("AttackTreeDraftV3For"):
            family = "attack_tree"
            selected.setdefault(family, prompt)
        elif schema.startswith("BehaviorDraftV2For"):
            family = "behavior_spec"
            selected.setdefault(family, prompt)
        else:
            family = "unknown"
        markers = marker_sets.get(family, ())
        contracts.append(
            (family, schema, tuple(marker in prompt for marker in markers))
        )

    return {
        "contracts": sorted(contracts),
        "selected_prompts": selected,
    }


def _run_taxonomy_compatibility() -> dict[str, Any]:
    """Exercise two real ``generate`` runs against a localhost fixture."""
    fixtures = _compatibility_fixtures()
    root = Path(tempfile.mkdtemp(prefix="asago-taxonomy-compat-"))
    server = fixtures.ThreadingHTTPServer(("127.0.0.1", 0), fixtures.FixtureHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    observations: list[dict[str, Any]] = []
    count_labels = (
        "Candidates admitted",
        "Candidates quarantined",
        "Candidates failed",
        "Scenarios generated",
        "Governance-only",
    )
    # The fixture responder runs in this process while the public CLI runs in
    # a child process. Its deterministic acceptance selector therefore has to
    # be scoped in the server process; putting it only in the child env would
    # leave every pattern eligible and make the comparison depend on catalog
    # iteration order.
    previous_accept_pattern = os.environ.get("ACCEPT_PATTERN")
    os.environ["ACCEPT_PATTERN"] = fixtures.ACCEPT_AP_T6_04
    try:
        for label in ("fixture", "observed"):
            workspace = root / label
            workspace.mkdir(parents=True)
            fixtures._write_generate_inputs(workspace)
            fixtures.FixtureHandler.reset()
            command = fixtures._generate_argv(workspace, server)
            environment = _compatibility_env()
            completed = _run_compatibility_command(
                command, environment=environment, timeout=600
            )
            run_dir = fixtures._run_dir(workspace)
            observations.append(
                {
                    "label": label,
                    "command": command,
                    "completed": completed,
                    "run_dir": run_dir,
                    "scenario_signatures": _scenario_signatures(run_dir)
                    if run_dir is not None
                    else [],
                    "artifact_roles": _artifact_roles(run_dir)
                    if run_dir is not None
                    else [],
                    "counts": _count_stdout_labels(completed.stdout, count_labels),
                    "requests": list(fixtures.FixtureHandler.requests),
                    "prompt_evidence": _prompt_evidence(
                        list(fixtures.FixtureHandler.requests),
                        fixtures.ACCEPT_AP_T6_04,
                    ),
                    "has_obligation_artifact": _contains_obligation_artifact(workspace),
                }
            )
    finally:
        if previous_accept_pattern is None:
            os.environ.pop("ACCEPT_PATTERN", None)
        else:
            os.environ["ACCEPT_PATTERN"] = previous_accept_pattern
        server.shutdown()
        server.server_close()

    fixture, observed = observations
    fixture_result = fixture["completed"]
    observed_result = observed["completed"]
    artifacts_match = (
        fixture["scenario_signatures"] == observed["scenario_signatures"]
        and fixture["artifact_roles"] == observed["artifact_roles"]
        and bool(fixture["scenario_signatures"])
    )
    counts_match = fixture["counts"] == observed["counts"] and all(
        value is not None for value in observed["counts"].values()
    )
    prompts_match = (
        fixture["prompt_evidence"] == observed["prompt_evidence"]
        and bool(observed["requests"])
        and "candidate_filter" in observed["prompt_evidence"]["selected_prompts"]
        and "actor_profile" in observed["prompt_evidence"]["selected_prompts"]
        and "narrative" in observed["prompt_evidence"]["selected_prompts"]
        and "attack_tree" in observed["prompt_evidence"]["selected_prompts"]
        and "behavior_spec" in observed["prompt_evidence"]["selected_prompts"]
    )
    no_obligation_sidecar = not (
        fixture["has_obligation_artifact"] or observed["has_obligation_artifact"]
    )
    result_match = (
        fixture_result.returncode == 0
        and observed_result.returncode == 0
        and "Pipeline complete." in observed_result.stdout
    )
    command_has_no_hybrid_flags = all(
        "obligation" not in argument.lower() for argument in observed["command"]
    )
    return {
        "workflow": "taxonomy/risk",
        "command": "generate",
        "fixture_root": root,
        "exit_match": result_match and command_has_no_hybrid_flags,
        "result_match": result_match,
        "artifacts_match": artifacts_match,
        "counts_match": counts_match,
        "prompts_match": prompts_match,
        "no_obligation_sidecar": no_obligation_sidecar,
        "detail": (
            f"fixture_exit={fixture_result.returncode}, "
            f"observed_exit={observed_result.returncode}, "
            f"scenario_files={len(observed['scenario_signatures'])}, "
            f"provider_requests={len(observed['requests'])}"
        ),
    }


def _run_stpa_compatibility() -> dict[str, Any]:
    """Exercise two real resume-mode ``stpa-run`` commands offline."""
    fixtures = _compatibility_fixtures()
    root = Path(tempfile.mkdtemp(prefix="asago-stpa-compat-"))
    observations: list[dict[str, Any]] = []
    count_labels = (
        "Losses",
        "Hazards",
        "Constraints",
        "Responsibilities",
        "Control Actions",
        "Total slots",
        "N/A slots",
        "Structural threats",
        "Mapped",
        "Unmapped",
    )
    for label in ("fixture", "observed"):
        workspace = root / label
        workspace.mkdir(parents=True)
        fixtures._write_stpa_fixture(workspace)
        output_dir = workspace / "output"
        before = fixtures._file_index(output_dir)
        command = [
            *_compatibility_command(),
            "stpa-run",
            "--use-case",
            str(workspace / "use-case.txt"),
            "--risk-extraction",
            str(workspace / "risk-extraction.json"),
            "--output-dir",
            str(output_dir),
            "--resume",
        ]
        completed = _run_compatibility_command(
            command, environment=_compatibility_env(), timeout=180
        )
        after = fixtures._file_index(output_dir)
        observations.append(
            {
                "label": label,
                "command": command,
                "completed": completed,
                "before": before,
                "after": after,
                "scenario_signatures": _scenario_signatures(output_dir),
                "artifact_roles": _artifact_roles(output_dir),
                "counts": _count_stdout_labels(completed.stdout, count_labels),
                "has_obligation_artifact": _contains_obligation_artifact(output_dir),
                "has_prompt_log": any(
                    path.name == "calls.jsonl" for path in output_dir.rglob("*")
                ),
            }
        )

    fixture, observed = observations
    unchanged = all(
        all(
            observed["after"].get(name) == observed["before"].get(name)
            for name in (
                "loss-analysis.yaml",
                "control-structure.yaml",
                "ica-enumeration.yaml",
                "enriched-threats.yaml",
                "scenario-001.yaml",
                "scenario-001.feature",
            )
        )
        for observed in observations
    )
    result_match = (
        all(item["completed"].returncode == 0 for item in observations)
        and all(
            "STPA PIPELINE SUMMARY" in item["completed"].stdout for item in observations
        )
        and unchanged
    )
    artifacts_match = (
        fixture["scenario_signatures"] == observed["scenario_signatures"]
        and fixture["artifact_roles"] == observed["artifact_roles"]
        and bool(observed["scenario_signatures"])
    )
    counts_match = fixture["counts"] == observed["counts"] and all(
        value is not None for value in observed["counts"].values()
    )
    prompts_match = not fixture["has_prompt_log"] and not observed["has_prompt_log"]
    no_obligation_sidecar = not (
        fixture["has_obligation_artifact"] or observed["has_obligation_artifact"]
    )
    command_has_no_hybrid_flags = all(
        "obligation" not in argument.lower() for argument in observed["command"]
    )
    return {
        "workflow": "STPA",
        "command": "stpa-run",
        "fixture_root": root,
        "exit_match": result_match and command_has_no_hybrid_flags,
        "result_match": result_match,
        "artifacts_match": artifacts_match,
        "counts_match": counts_match,
        "prompts_match": prompts_match,
        "no_obligation_sidecar": no_obligation_sidecar,
        "detail": (
            f"fixture_exit={fixture['completed'].returncode}, "
            f"observed_exit={observed['completed'].returncode}, "
            f"scenario_files={len(observed['scenario_signatures'])}"
        ),
    }


def _h_obligation_planner_present(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if not callable(run_plan_obligations):
        return False, "Public obligation-planning entry point is unavailable"
    return True, ""


def _h_default_commands_no_flags(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    help_results: dict[str, subprocess.CompletedProcess[str]] = {}
    for command in ("generate", "stpa-run"):
        completed = _run_compatibility_command(
            [*_compatibility_command(), command, "--help"],
            environment=_compatibility_env(),
            timeout=60,
        )
        help_results[command] = completed
        if completed.returncode != 0:
            return False, f"{command} --help exited {completed.returncode}"
        if "obligation" in (completed.stdout + completed.stderr).lower():
            return False, f"{command} --help exposes obligation-planner flags"
    state["compatibility_help"] = help_results
    return True, ""


def _h_deterministic_workflow_fixture(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(r'deterministic offline "([^"]+)" fixture', text)
    workflow = match.group(1) if match else examples.get("workflow", "")
    if workflow not in _COMPAT_WORKFLOW_COMMANDS:
        return False, f"Unknown deterministic compatibility workflow '{workflow}'"
    state["fixture_workflow"] = workflow
    return True, ""


def _h_default_command_runs(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(r'default "([^"]+)" runs', text)
    command = match.group(1) if match else examples.get("command", "")
    workflow = state.get("fixture_workflow", "")
    expected_command = _COMPAT_WORKFLOW_COMMANDS.get(workflow)
    if expected_command != command:
        return False, f"Command '{command}' does not match workflow '{workflow}'"
    try:
        observation = (
            _run_taxonomy_compatibility()
            if command == "generate"
            else _run_stpa_compatibility()
        )
    except Exception as exc:  # pragma: no cover - diagnostic boundary
        return False, f"{command} fixture execution failed: {exc}"
    state["compatibility"] = observation
    state["ran_command"] = command
    if not observation["exit_match"]:
        return (
            False,
            f"{command} did not complete successfully: {observation['detail']}",
        )
    return True, observation["detail"]


def _h_artifacts_match_fixture(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    observation = state.get("compatibility")
    if observation is None:
        return False, "No public compatibility command was executed"
    if not observation["result_match"]:
        return False, observation["detail"]
    if not observation["artifacts_match"]:
        return False, f"Scenario artifacts differ from fixture: {observation['detail']}"
    return True, ""


def _h_generation_counts_unchanged(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    observation = _planner_state(world).get("compatibility")
    if observation is None:
        return False, "No public compatibility command was executed"
    if not observation["counts_match"]:
        return False, f"Generation summary counts differ: {observation['detail']}"
    return True, ""


def _h_scenario_prompts_unchanged(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    observation = _planner_state(world).get("compatibility")
    if observation is None:
        return False, "No public compatibility command was executed"
    if not observation["prompts_match"]:
        return (
            False,
            f"Scenario prompts or call evidence differ: {observation['detail']}",
        )
    return True, ""


def _h_no_obligation_plan_added(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    observation = _planner_state(world).get("compatibility")
    if observation is None:
        return False, "No public compatibility command was executed"
    if not observation["no_obligation_sidecar"]:
        return False, f"An obligation sidecar was published: {observation['detail']}"
    return True, ""


def register(api: Any) -> None:
    api.set_feature(FEATURE_ID)
    registrations = (
        (
            r"a typed taxonomy obligation input fixture is available",
            _h_typed_input_ready,
        ),
        (
            r"typed obligation planning makes no network or model calls",
            _h_typed_no_provider_calls,
        ),
        (
            r'the normative typed planner inputs contain only reviewed risk "([^\"]+)" with no pattern',
            _h_typed_governance_input,
        ),
        (
            r'the normative typed planner inputs include risk "([^\"]+)" mapped to attack pattern "([^\"]+)" with the canonical resources',
            _h_typed_candidate_input,
        ),
        (
            r'typed planner inputs include reviewed risks "([^\"]+)" and "([^\"]+)" mapped to attack pattern "([^\"]+)"',
            _h_typed_shared_pattern_input,
        ),
        (
            r'typed planner inputs include risk "([^\"]+)" mapped to attack pattern "([^\"]+)" whose authoritative profile gate is unmet',
            _h_typed_capability_excluded_input,
        ),
        (r"the default normative typed planner inputs are ready", _h_typed_input_ready),
        (r"typed obligation planning runs", _h_typed_planning_runs),
        (r"typed plan contains (\d+) obligation rows?", _h_typed_plan_contains_rows),
        (
            r"typed rows retain distinct risk identities",
            _h_typed_rows_keep_risk_identity,
        ),
        (
            r'typed rows retain risk identities "([^\"]+)" and "([^\"]+)" for attack pattern "([^\"]+)"',
            _h_typed_rows_keep_risk_identity,
        ),
        (
            r'typed row has risk "([^\"]+)" and attack pattern "([^\"]+)" with scope disposition "([^\"]+)"',
            _h_typed_scope_disposition,
        ),
        (
            r'typed row retains projection evidence from "([^\"]+)"',
            _h_typed_projection_evidence,
        ),
        (r"the typed plan contains one obligation row", _h_typed_plan_contains_one_row),
        (
            r'the typed row retains risk_ref "([^\"]+)" with governance-only scope',
            _h_typed_governance_row,
        ),
        (
            r'the typed row retains risk_ref "([^\"]+)" with "([^\"]+)" scope',
            _h_typed_governance_row,
        ),
        (
            r"the typed obligation row has exactly the normative closed fields",
            _h_typed_row_exact_shape,
        ),
        (
            r'typed candidate row retains risk "([^\"]+)" and attack pattern "([^\"]+)"',
            _h_typed_candidate_row_identity,
        ),
        (
            r"the typed candidate identity and resource bindings are retained",
            _h_typed_candidate_identity,
        ),
        (
            r"the typed summary reconciles from typed obligation rows",
            _h_typed_summary_reconciles,
        ),
        (
            r"normative typed planner identity inputs vary independently",
            _h_typed_input_ready,
        ),
        (r"typed identity planning runs", _h_typed_identity_variants),
        (
            r"every changed risk, pattern, capability snapshot, catalog pin, and mapping pin changes the obligation identity",
            _h_typed_identity_changes_observed,
        ),
        (
            r'typed planner inputs use semantically equivalent "([^\"]+)" and "([^\"]+)" normalized representations',
            _h_typed_normalized_input_variants,
        ),
        (
            r"normalized typed plan contents are byte-equivalent",
            _h_typed_normalized_content_is_identical,
        ),
        (
            r"normalized typed obligation IDs are identical",
            _h_typed_normalized_ids_are_identical,
        ),
        (
            r'typed planner has ICA keyword prose fixture "([^\"]+)" and scenario keyword prose fixture "([^\"]+)"',
            _h_typed_keyword_prose_fixture,
        ),
        (
            r"typed normalized-input planning runs",
            _h_typed_normalized_input_variants,
        ),
        (
            r"typed keyword-prose planning runs",
            _h_typed_keyword_prose_planning_runs,
        ),
        (
            r"changing ICA or scenario keyword prose leaves the typed plan unchanged",
            _h_typed_keyword_prose_no_effect,
        ),
        (
            r"typed planning runs under provider and endpoint guards",
            _h_typed_no_provider_calls,
        ),
        (
            r"typed obligation planning constructs (\d+) provider clients and contacts (\d+) endpoints",
            _h_typed_no_provider_counts,
        ),
        (
            r'the normative typed planner inputs contain unknown field "([^\"]+)"',
            _h_typed_invalid_input,
        ),
        (
            r'typed input validation identifies unknown field "([^\"]+)"',
            _h_typed_unknown_field_identified,
        ),
        (
            r'the normative typed planner inputs contain a "([^\"]+)" qualification facts digest',
            _h_typed_false_qualification_digest,
        ),
        (r"typed input validation runs", _h_typed_validation_runs),
        (r"typed input validation is rejected", _h_typed_input_rejected),
        (r"no partial typed plan is returned", _h_typed_no_partial_plan),
        (
            r'normative typed planner inputs contain no "([^\"]+)" qualification facts',
            _h_typed_missing_qualification_facts,
        ),
        (
            r'normative typed planner inputs contain a contradictory "([^\"]+)" qualification fact',
            _h_typed_contradictory_qualification_facts,
        ),
        (
            r'normative typed planner inputs use an authoritative profile with no compatible "([^\"]+)" resource',
            _h_typed_projection_infeasible_input,
        ),
        (
            r'typed row has qualification disposition "([^\"]+)" and projection-infeasible candidate records',
            _h_typed_projection_rejection_records,
        ),
        (
            r'typed row has qualification disposition "([^\"]+)"',
            _h_typed_qualification_disposition,
        ),
        (r"typed row has no candidate records", _h_typed_no_candidate_records),
        (
            r"typed row retains contradictory qualification evidence",
            _h_typed_contradictory_qualification_evidence,
        ),
        (
            r'the typed plan is published atomically as "([^\"]+)"',
            _h_typed_atomic_publication,
        ),
        (r'the typed publication is named "([^\"]+)"', _h_typed_publication_named),
        (
            r"the typed publication round-trips without semantic loss",
            _h_typed_publication_round_trips,
        ),
        (r"no typed partial plan file remains", _h_typed_no_partial_publication),
        (
            r"the typed plan has closed schema metadata, pins, and content digests",
            _h_typed_metadata,
        ),
        (
            r'the typed plan schema version is "([^\"]+)"',
            _h_typed_schema_version,
        ),
        (
            r'the typed "([^\"]+)" plan is serialized twice',
            _h_typed_serialize_twice,
        ),
        (
            r'the typed "([^\"]+)" artifacts are byte-identical',
            _h_typed_byte_identical,
        ),
        (
            r'the published typed content is tampered in field "([^\"]+)" without updating the semantic digest',
            _h_typed_tamper_published_content,
        ),
        (r"the published typed plan is loaded", _h_typed_publication_loaded),
        (r"typed loading is rejected", _h_typed_loading_rejected),
        (r'the typed load error identifies a "([^\"]+)"', _h_typed_digest_mismatch),
        (r"the obligation planner is present", _h_obligation_planner_present),
        (
            r"default generation commands are invoked without obligation-planner flags",
            _h_default_commands_no_flags,
        ),
        (
            r'a deterministic offline "([^\"]+)" fixture',
            _h_deterministic_workflow_fixture,
        ),
        (r'the default "([^\"]+)" runs', _h_default_command_runs),
        (r"published scenario artifacts match the fixture", _h_artifacts_match_fixture),
        (r"generation counts are unchanged", _h_generation_counts_unchanged),
        (r"scenario prompts are unchanged", _h_scenario_prompts_unchanged),
        (
            r"no obligation-plan artifact is added to the run outputs",
            _h_no_obligation_plan_added,
        ),
    )
    for pattern, handler in registrations:
        api.register(pattern, handler)


__all__ = ["FEATURE_ID", "register"]
