"""Deterministic acceptance handlers for taxonomy obligation planning and artifacts."""

from __future__ import annotations

import json
import re
import socket
import tempfile
from contextlib import ExitStack
from copy import deepcopy
from pathlib import Path
from typing import Any
from unittest.mock import patch

import yaml

from runtime_shared import World
from runtime_obligation_fixture import (
    jsonable as _jsonable,
    typed_authoritative_fixture as _typed_authoritative_fixture,
    typed_expected_candidate as _typed_expected_candidate,
    typed_input_model as _typed_input_model,
    typed_payload as _typed_payload,
)

from asago_scenario_generator.models.obligation_plan import TaxonomyObligationPlan
from asago_scenario_generator.pipeline.obligation_persistence import (
    write_taxonomy_obligation_plan,
)

FEATURE_ID = "taxonomy_obligation_planner"


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


def _typed_resource_operation_input(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Prepare a typed operation-support fixture for the planner boundary."""
    del examples
    match = re.search(
        r'normative typed planner inputs require "([^"]+)" with "([^"]+)" resource support',
        text,
    )
    operation, support_state = match.groups() if match else ("retrieve_data", "unknown")
    if operation not in {"retrieve_data", "transmit_data", "execute_code"}:
        return False, f"Unsupported operation fixture: {operation}"
    if support_state not in {"unknown", "unsupported"}:
        return False, f"Unsupported operation-support fixture: {support_state}"

    from asago_scenario_generator.models.attack_pattern import (
        compute_chain_semantic_digest,
    )
    from asago_scenario_generator.pipeline.projection import (
        capture_capability_snapshot,
    )
    from tests.helpers.projection_factory import get_test_profile, get_test_snapshot

    _candidate, raw_pattern, _snapshot = _typed_authoritative_fixture()
    raw_pattern = deepcopy(raw_pattern)
    tool_slot = next(
        slot
        for slot in raw_pattern["canonical_chain"]["resource_slots"]
        if slot["kind"] == "tool"
    )
    tool_slot["required_operations"] = [operation]
    raw_pattern["canonical_chain"]["semantic_digest"] = compute_chain_semantic_digest(
        raw_pattern["canonical_chain"]
    )

    if support_state == "unknown":
        snapshot = get_test_snapshot()
    else:
        profile_payload = get_test_profile().model_dump(mode="json")
        unsupported_operation = next(
            candidate
            for candidate in ("retrieve_data", "transmit_data", "execute_code")
            if candidate != operation
        )
        profile_payload["tool_inventory"][0]["supported_operations"] = [
            unsupported_operation
        ]
        snapshot = capture_capability_snapshot(
            get_test_profile().model_validate(profile_payload),
            get_test_snapshot().facts,
        )

    state = _planner_state(world)
    state["typed_inputs"] = _typed_payload(
        pattern_record=raw_pattern,
        capability_snapshot=snapshot,
    )
    state["typed_expected_pattern_id"] = raw_pattern["id"]
    state["typed_operation_support_state"] = support_state
    state["typed_plan"] = None
    state["typed_error"] = None
    return True, ""


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


def _h_typed_resource_operation_evidence(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Assert the planner retains the exact operation-support diagnostic."""
    del examples
    match = re.search(
        r'typed row retains resource-operation evidence from "([^"]+)"', text
    )
    expected_source = match.group(1) if match else "unknown_resource_operation"
    plan = _planner_state(world).get("typed_plan")
    if plan is None or len(plan.obligations) != 1:
        return False, "Expected one typed obligation"
    sources = {
        evidence.source
        for evidence in plan.obligations[0].evidence
        if evidence.source is not None
    }
    if expected_source not in sources:
        return (
            False,
            f"Operation source {expected_source!r} not found: {sorted(sources)}",
        )
    return True, ""


def _h_typed_resource_operation_outcome(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Assert unknown support emits no candidate while unsupported support does."""
    del examples
    match = re.search(r'typed row has candidate outcome "([^"]+)"', text)
    expected = match.group(1) if match else "no_candidates"
    plan = _planner_state(world).get("typed_plan")
    if plan is None or len(plan.obligations) != 1:
        return False, "Expected one typed obligation"
    candidates = plan.obligations[0].candidate_records
    if expected == "no_candidates" and not candidates:
        return True, ""
    if expected == "projection_infeasible" and len(candidates) == 1:
        if candidates[0].projection_disposition == "projection_infeasible":
            return True, ""
    return False, f"Unexpected candidate outcome {expected}: {candidates}"


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
    match = re.search(r'typed plan is published atomically as "([^"]+)"', text)
    requested_format = match.group(1) if match else "YAML"
    if requested_format != "YAML":
        return False, f"Typed publication format must be YAML, got {requested_format}"
    try:
        plan = _typed_plan_from_payload(json.loads(json.dumps(_jsonable(payload))))
        written = [write_taxonomy_obligation_plan(root / "published", plan)]
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
        (
            r'normative typed planner inputs require "([^\"]+)" with "([^\"]+)" resource support',
            _typed_resource_operation_input,
        ),
        (
            r'typed row retains resource-operation evidence from "([^\"]+)"',
            _h_typed_resource_operation_evidence,
        ),
        (
            r'typed row has candidate outcome "([^\"]+)"',
            _h_typed_resource_operation_outcome,
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
    )
    for pattern, handler in registrations:
        api.register(pattern, handler)


__all__ = ["FEATURE_ID", "register"]
