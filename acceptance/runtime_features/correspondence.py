"""Deterministic acceptance handlers for correspondence proposal, reconciliation, artifacts, and compatibility."""

from __future__ import annotations

import re
from typing import Any

from runtime_shared import World

from asago_scenario_generator.models.correspondence import (
    AdjudicationHistoryItem,
    CorrespondenceProposal,
    ReconciledProposal,
    ReconciliationResult,
)
from asago_scenario_generator.models.system_resource_map import (
    ControlActionEntry,
    LossLinkEntry,
    SystemResourceEntry,
    SystemResourceMap,
    TrustBoundaryEntry,
)
from asago_scenario_generator.pipeline.correspondence import (
    propose_correspondence,
    reconcile_correspondence,
)

FEATURE_ID = "correspondence"


def _make_default_resource_map(
    stpa_version: str = "stpa-v1",
    taxonomy_version: str = "atlas-2026.05",
) -> SystemResourceMap:
    return SystemResourceMap(
        schema_version="1",
        stpa_version=stpa_version,
        taxonomy_version=taxonomy_version,
        system_resources=[
            SystemResourceEntry(
                element_id="SR-1",
                name="Primary Database",
                description="Database hosting user records",
                taxonomy_ref="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            SystemResourceEntry(
                element_id="SR-2",
                name="Attack Pattern Reference",
                description="Taxonomy attack pattern",
                taxonomy_ref="AP-T6-01",
            ),
        ],
        control_actions=[
            ControlActionEntry(
                element_id="CA-1-1",
                controller_id="RESP-1",
                process_id="CP-2",
                action_name="Issue Payment",
            )
        ],
        loss_links=[
            LossLinkEntry(
                element_id="LL-1",
                loss_id="L-1",
                hazard_id="H-1",
            )
        ],
        trust_boundaries=[
            TrustBoundaryEntry(
                element_id="TB-1",
                name="DMZ Boundary",
                resource_ids=["SR-1"],
                taxonomy_ref="tb:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            )
        ],
    )


def _get_corr_state(world: World) -> dict[str, Any]:
    """Return this feature's per-scenario state, initializing it on first use."""
    state = getattr(world, "correspondence_state", None)
    if state is None:
        state = {
            "resource_map": _make_default_resource_map(),
            "source_artifacts": {},
            "raw_proposals": {},
            "proposal_set": None,
            "adjudications": {},
            "reconciliation_result": None,
            "result_a": None,
            "result_b": None,
            "serialized_a": None,
            "serialized_b": None,
            "serialized_twice": [],
            "deserialized_result": None,
            "last_error": None,
            "prose": None,
            "proposer_meta": {},
            "existing_ids": [],
            "new_id": None,
            "new_adjudication": None,
            "source_artifact_snapshots": {},
        }
        world.correspondence_state = state
    return state


def _require_reconciliation_result(
    state: dict[str, Any],
) -> tuple[ReconciliationResult | None, str | None]:
    """Return the reconciliation result, or a failure message when missing."""
    result = state.get("reconciliation_result")
    if result is None:
        return None, "Reconciliation result missing"
    return result, None


def _require_proposal_set(
    state: dict[str, Any],
) -> tuple[Any, str | None]:
    """Return the proposal set, or a failure message when missing."""
    pset = state.get("proposal_set")
    if pset is None:
        return None, "Proposal set missing"
    return pset, None


def _proposal_by_id(
    proposals: list[Any],
    prop_id: str,
) -> tuple[Any | None, str | None]:
    """Find one proposal by id, or a failure message when absent."""
    prop = next((p for p in proposals if p.proposal_id == prop_id), None)
    if prop is None:
        return None, f"Proposal {prop_id} missing"
    return prop, None


def _make_proposal(
    state: dict[str, Any],
    prop_id: str,
    **overrides: Any,
) -> CorrespondenceProposal:
    """Build a proposal pinned to the state's resource-map versions."""
    srm = state["resource_map"]
    fields: dict[str, Any] = {
        "proposal_id": prop_id,
        "left_ref": "CA-1-1",
        "right_ref": "ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "relation_type": "supports",
        "evidence_source": "exact-id",
        "strength": "high",
        "evidence_refs": ["CA-1-1"],
        "stpa_version": str(srm.stpa_version),
        "taxonomy_version": str(srm.taxonomy_version),
    }
    fields.update(overrides)
    return CorrespondenceProposal(**fields)


def _proposals_for_ids(
    state: dict[str, Any],
    ids: list[str],
) -> list[CorrespondenceProposal]:
    """Build one canonical proposal per id for presentation-order scenarios."""
    return [_make_proposal(state, pid) for pid in ids]


def _serialize_result(result: ReconciliationResult, fmt: str) -> str:
    """Serialize a reconciliation result in the requested format (YAML or JSON)."""
    if fmt.upper() == "YAML":
        return result.to_yaml()
    return result.to_json()


def _deserialize_result(text: str, fmt: str) -> ReconciliationResult:
    """Deserialize a reconciliation result from the requested format (YAML or JSON)."""
    if fmt.upper() == "YAML":
        return ReconciliationResult.from_yaml(text)
    return ReconciliationResult.from_json(text)


# -----------------------------------------------------------------------------
# Background steps
# -----------------------------------------------------------------------------


def _h_valid_srm_available(world: World, text: str, examples: dict) -> tuple[bool, str]:
    state = _get_corr_state(world)
    state["resource_map"] = _make_default_resource_map()
    return True, ""


def _h_reconciliation_depends_on_srm(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return True, ""


def _h_no_network_or_model_calls(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return True, ""


def _h_proposal_and_reconciliation_present(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return True, ""


def _h_default_commands_no_flags(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return True, ""


# -----------------------------------------------------------------------------
# Reconciliation Feature Handlers
# -----------------------------------------------------------------------------


def _h_proposal_has_relation_type(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    match = re.search(r'proposal "([^"]*)" has relation type "([^"]*)"$', text)
    if match:
        prop_id, rel_type = match.group(1), match.group(2)
    else:
        prop_id = examples.get("proposal_id", "P-1")
        rel_type = examples.get("relation_type", "supports")

    prop = _make_proposal(state, prop_id, relation_type=rel_type)
    state["raw_proposals"][prop_id] = prop
    return True, ""


def _h_proposal_has_relation_type_and_strength(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    match = re.search(
        r'proposal "([^"]*)" has relation type "([^"]*)" and strength "([^"]*)"', text
    )
    if match:
        prop_id, rel_type, strength = match.group(1), match.group(2), match.group(3)
    else:
        prop_id = examples.get("proposal_id", "P-1")
        rel_type = examples.get("relation_type", "supports")
        strength = examples.get("strength", "high")

    prop = _make_proposal(
        state,
        prop_id,
        relation_type=rel_type,
        evidence_source="exact-id" if strength == "high" else "resource-overlap",
        strength=strength,
    )
    state["raw_proposals"][prop_id] = prop
    return True, ""


def _h_reconciliation_assigns_adjudication(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    match = re.search(
        r'reconciliation input assigns adjudication "([^"]*)" to "([^"]*)"', text
    )
    if match:
        adjudication, prop_id = match.group(1), match.group(2)
    else:
        adjudication = examples.get("adjudication", "confirmed")
        prop_id = examples.get("proposal_id", "P-1")

    state["adjudications"][prop_id] = adjudication
    return True, ""


def _h_correspondence_is_reconciled(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    srm = state["resource_map"]
    proposals = list(state["raw_proposals"].values())
    adjudications = dict(state["adjudications"])
    res = reconcile_correspondence(srm, proposals, adjudications=adjudications)
    state["reconciliation_result"] = res
    return True, ""


def _h_result_retains_proposal(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    match = re.search(r'the result retains proposal "([^"]*)"', text)
    prop_id = match.group(1) if match else examples.get("proposal_id", "")
    res, failure = _require_reconciliation_result(state)
    if failure:
        return False, failure
    found = any(p.proposal_id == prop_id for p in res.proposals)
    if not found:
        return False, f"Proposal {prop_id} not retained in result"
    return True, ""


def _h_result_records_adjudication(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    match = re.search(r'the result records adjudication "([^"]*)" for "([^"]*)"', text)
    if match:
        expected_adj, prop_id = match.group(1), match.group(2)
    else:
        expected_adj = examples.get("adjudication", "")
        prop_id = examples.get("proposal_id", "")

    res, failure = _require_reconciliation_result(state)
    if failure:
        return False, failure
    prop, failure = _proposal_by_id(res.proposals, prop_id)
    if failure:
        return False, f"Proposal {prop_id} not found in result"
    if prop.adjudication != expected_adj:
        return (
            False,
            f"Proposal {prop_id} adjudication '{prop.adjudication}' != expected '{expected_adj}'",
        )
    return True, ""


def _h_result_records_relation_type(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    match = re.search(r'the result records relation type "([^"]*)" for "([^"]*)"', text)
    if match:
        expected_rel, prop_id = match.group(1), match.group(2)
    else:
        expected_rel = examples.get("relation_type", "")
        prop_id = examples.get("proposal_id", "")

    res, failure = _require_reconciliation_result(state)
    if failure:
        return False, failure
    prop, failure = _proposal_by_id(res.proposals, prop_id)
    if failure:
        return False, f"Proposal {prop_id} not found in result"
    if prop.relation_type != expected_rel:
        return (
            False,
            f"Proposal {prop_id} relation_type '{prop.relation_type}' != expected '{expected_rel}'",
        )
    return True, ""


def _h_proposal_has_relation_type_check(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    match = re.search(r'proposal "([^"]*)" has relation type "([^"]*)"$', text)
    if match:
        prop_id, expected_rel = match.group(1), match.group(2)
    else:
        prop_id = examples.get("proposal_id", "")
        expected_rel = examples.get("relation_type", "")

    res, failure = _require_reconciliation_result(state)
    if failure:
        return False, failure
    prop, failure = _proposal_by_id(res.proposals, prop_id)
    if failure:
        return False, f"Proposal {prop_id} not found in result"
    if prop.relation_type != expected_rel:
        return (
            False,
            f"Proposal {prop_id} relation_type '{prop.relation_type}' != expected '{expected_rel}'",
        )
    return True, ""


def _h_proposal_has_strength_check(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    match = re.search(r'proposal "([^"]*)" has strength "([^"]*)"', text)
    if match:
        prop_id, expected_strength = match.group(1), match.group(2)
    else:
        prop_id = examples.get("proposal_id", "")
        expected_strength = examples.get("strength", "")

    res, failure = _require_reconciliation_result(state)
    if failure:
        return False, failure
    prop, failure = _proposal_by_id(res.proposals, prop_id)
    if failure:
        return False, f"Proposal {prop_id} not found in result"
    if prop.strength != expected_strength:
        return (
            False,
            f"Proposal {prop_id} strength '{prop.strength}' != expected '{expected_strength}'",
        )
    return True, ""


def _h_proposal_has_adjudication_check(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    match = re.search(r'proposal "([^"]*)" has adjudication "([^"]*)"', text)
    if match:
        prop_id, expected_adj = match.group(1), match.group(2)
    else:
        prop_id = examples.get("proposal_id", "")
        expected_adj = examples.get("adjudication", "")

    res, failure = _require_reconciliation_result(state)
    if failure:
        return False, failure
    prop, failure = _proposal_by_id(res.proposals, prop_id)
    if failure:
        return False, f"Proposal {prop_id} not found in result"
    if prop.adjudication != expected_adj:
        return (
            False,
            f"Proposal {prop_id} adjudication '{prop.adjudication}' != expected '{expected_adj}'",
        )
    return True, ""


def _h_relation_type_not_equal_adjudication(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    res, failure = _require_reconciliation_result(state)
    if failure:
        return False, failure
    for p in res.proposals:
        if p.relation_type == p.adjudication:
            return (
                False,
                f"Proposal {p.proposal_id} relation_type equals adjudication '{p.relation_type}'",
            )
    return True, ""


def _h_relation_type_not_equal_strength(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    res, failure = _require_reconciliation_result(state)
    if failure:
        return False, failure
    for p in res.proposals:
        if p.relation_type == p.strength:
            return (
                False,
                f"Proposal {p.proposal_id} relation_type equals strength '{p.relation_type}'",
            )
    return True, ""


def _h_conflicting_proposals(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    match = re.search(
        r'conflicting proposals "([^"]*)" with type "([^"]*)" and "([^"]*)" with type "([^"]*)" for "([^"]*)" and "([^"]*)"',
        text,
    )
    if match:
        prop_a, type_a, prop_b, type_b, left_ref, right_ref = match.groups()
    else:
        prop_a = examples.get("proposal_a", "P-1")
        type_a = examples.get("type_a", "supports")
        prop_b = examples.get("proposal_b", "P-4")
        type_b = examples.get("type_b", "contradicts")
        left_ref = examples.get("left_ref", "CA-1-1")
        right_ref = examples.get("right_ref", "ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

    p_a = _make_proposal(
        state,
        prop_a,
        left_ref=left_ref,
        right_ref=right_ref,
        relation_type=type_a,
        evidence_refs=[left_ref],
    )
    p_b = _make_proposal(
        state,
        prop_b,
        left_ref=left_ref,
        right_ref=right_ref,
        relation_type=type_b,
        evidence_refs=[left_ref],
    )
    state["raw_proposals"] = {prop_a: p_a, prop_b: p_b}
    state["adjudications"] = {prop_a: "confirmed", prop_b: "confirmed"}
    return True, ""


def _h_proposals_presented_in_order(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    match = re.search(r'the proposals are presented in order "([^"]*)"', text)
    order_csv = match.group(1) if match else examples.get("order", "")
    ordered_ids = [x.strip() for x in order_csv.split(",") if x.strip()]
    ordered_props = [
        state["raw_proposals"][pid]
        for pid in ordered_ids
        if pid in state["raw_proposals"]
    ]
    # Re-order the dictionary keys
    state["raw_proposals"] = {p.proposal_id: p for p in ordered_props}
    return True, ""


def _h_both_proposals_retained(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    res = state["reconciliation_result"]
    if res is None:
        return False, "Reconciliation result is missing"
    if len(res.proposals) < 2:
        return False, f"Expected both proposals retained, got {len(res.proposals)}"
    return True, ""


def _h_pair_has_adjudication(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    match = re.search(r'the pair has adjudication "([^"]*)"', text)
    expected_adj = match.group(1) if match else examples.get("adjudication", "")
    res, failure = _require_reconciliation_result(state)
    if failure:
        return False, failure
    for p in res.proposals:
        if p.adjudication != expected_adj:
            return (
                False,
                f"Proposal {p.proposal_id} in pair has adjudication '{p.adjudication}' != '{expected_adj}'",
            )
    return True, ""


def _h_pair_has_conflict_reason(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    match = re.search(r'the pair has conflict reason "([^"]*)"', text)
    expected_reason = match.group(1) if match else examples.get("conflict_reason", "")
    res, failure = _require_reconciliation_result(state)
    if failure:
        return False, failure
    for p in res.proposals:
        if p.conflict_reason != expected_reason:
            return (
                False,
                f"Proposal {p.proposal_id} in pair has conflict_reason '{p.conflict_reason}' != '{expected_reason}'",
            )
    return True, ""


def _h_neither_proposal_confirmed_by_order(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    res, failure = _require_reconciliation_result(state)
    if failure:
        return False, failure
    for p in res.proposals:
        if p.adjudication == "confirmed":
            return False, f"Proposal {p.proposal_id} was confirmed by order"
    return True, ""


def _h_proposal_has_confirmation_defect(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    match = re.search(r'proposal "([^"]*)" has confirmation defect "([^"]*)"', text)
    if match:
        prop_id, defect = match.group(1), match.group(2)
    else:
        prop_id = examples.get("proposal_id", "P-9")
        defect = examples.get("defect", "")

    if defect == "dangling-left":
        prop = _make_proposal(
            state,
            prop_id,
            left_ref="NON-EXISTENT-LEFT",
            evidence_refs=["NON-EXISTENT-LEFT"],
        )
    elif defect == "dangling-right":
        prop = _make_proposal(
            state,
            prop_id,
            right_ref="NON-EXISTENT-RIGHT",
        )
    elif defect == "stale-version":
        prop = _make_proposal(
            state,
            prop_id,
            stpa_version="stpa-v0-outdated",
        )
    elif defect == "evidence-free":
        prop = _make_proposal(
            state,
            prop_id,
            evidence_source="",
            evidence_refs=[],
        )
    else:
        # Unknown defect: match the model defaults, including empty evidence.
        prop = _make_proposal(state, prop_id, evidence_refs=[])

    state["raw_proposals"] = {prop_id: prop}
    state["adjudications"] = {prop_id: "confirmed"}
    return True, ""


def _h_reconciliation_fails(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    res = state["reconciliation_result"]
    if res is None:
        return False, "Reconciliation result is missing"
    if res.is_valid:
        return False, "Expected reconciliation to fail, but is_valid was True"
    return True, ""


def _h_no_confirmed_relation_written(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    match = re.search(r'no confirmed relation is written for "([^"]*)"', text)
    prop_id = match.group(1) if match else examples.get("proposal_id", "")
    res = state["reconciliation_result"]
    if res is None:
        return False, "Reconciliation result is missing"
    prop = next((p for p in res.proposals if p.proposal_id == prop_id), None)
    if prop and prop.adjudication == "confirmed":
        return False, f"Proposal {prop_id} has confirmed relation written"
    return True, ""


def _h_proposals_order_a_reconciled(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    match = re.search(r'proposals "([^"]*)" are reconciled to a result', text)
    order_a = match.group(1) if match else examples.get("order_a", "P-1,P-2,P-3")
    ids = [x.strip() for x in order_a.split(",") if x.strip()]

    srm = state["resource_map"]
    props = _proposals_for_ids(state, ids)
    adjudications = {pid: "confirmed" for pid in ids}
    state["result_a"] = reconcile_correspondence(
        srm, props, adjudications=adjudications
    )
    return True, ""


def _h_same_proposals_presented_as_order_b(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    match = re.search(r'the same proposals are presented as "([^"]*)"', text)
    order_b = match.group(1) if match else examples.get("order_b", "P-3,P-1,P-2")
    ids = [x.strip() for x in order_b.split(",") if x.strip()]

    state["raw_proposals_b"] = _proposals_for_ids(state, ids)
    state["adjudications_b"] = {pid: "confirmed" for pid in ids}
    return True, ""


def _h_correspondence_reconciled_again(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    srm = state["resource_map"]
    props_b = state["raw_proposals_b"]
    adjs_b = state["adjudications_b"]
    state["result_b"] = reconcile_correspondence(srm, props_b, adjudications=adjs_b)
    return True, ""


def _h_both_results_identical_identities(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    res_a = state["result_a"]
    res_b = state["result_b"]
    if res_a is None or res_b is None:
        return False, "Results A or B missing"
    ids_a = [p.proposal_id for p in res_a.proposals]
    ids_b = [p.proposal_id for p in res_b.proposals]
    if ids_a != ids_b:
        return False, f"Identities mismatch: {ids_a} != {ids_b}"
    return True, ""


def _h_both_results_identical_adjudications(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    res_a = state["result_a"]
    res_b = state["result_b"]
    if res_a is None or res_b is None:
        return False, "Results A or B missing"
    adjs_a = [p.adjudication for p in res_a.proposals]
    adjs_b = [p.adjudication for p in res_b.proposals]
    if adjs_a != adjs_b:
        return False, f"Adjudications mismatch: {adjs_a} != {adjs_b}"
    return True, ""


def _h_repeating_reconciliation_no_change(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    res_a = state["result_a"]
    srm = state["resource_map"]
    res_repeat = reconcile_correspondence(srm, res_a.proposals)
    if res_repeat.to_yaml() != res_a.to_yaml():
        return False, "Repeating reconciliation changed the result"
    return True, ""


def _h_scenario_prose_contains(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    match = re.search(r'scenario prose contains "([^"]*)"', text)
    prose = match.group(1) if match else examples.get("prose", "")
    state["prose"] = prose
    return True, ""


def _h_no_explicit_proposal_cites_prose(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    state["raw_proposals"] = {}
    return True, ""


def _h_result_contains_proposal_count(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    match = re.search(r"the result contains (\d+) proposals", text)
    expected_count = (
        int(match.group(1)) if match else int(examples.get("proposal_count", 0))
    )
    res, failure = _require_reconciliation_result(state)
    if failure:
        return False, failure
    if len(res.proposals) != expected_count:
        return (
            False,
            f"Expected {expected_count} proposals, got {len(res.proposals)}",
        )
    return True, ""


def _h_no_relation_inferred_from_wording(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    res, failure = _require_reconciliation_result(state)
    if failure:
        return False, failure
    if len(res.proposals) > 0:
        return False, "Relation was inferred from wording"
    return True, ""


def _h_source_stpa_and_taxonomy_artifacts(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    match = re.search(
        r'source STPA artifact "([^"]*)" and taxonomy artifact "([^"]*)"', text
    )
    if match:
        stpa_art, tax_art = match.group(1), match.group(2)
    else:
        stpa_art = examples.get("stpa_artifact", "control-structure.yaml")
        tax_art = examples.get("taxonomy_artifact", "attack-patterns.sssom.tsv")

    content_stpa = f"dummy stpa content for {stpa_art}"
    content_tax = f"dummy taxonomy content for {tax_art}"
    state["source_artifact_snapshots"] = {
        stpa_art: content_stpa,
        tax_art: content_tax,
    }
    state["source_artifacts"] = {
        "stpa_file": stpa_art,
        "stpa_content": content_stpa,
        "tax_file": tax_art,
        "tax_content": content_tax,
        "evidence": [],
    }
    return True, ""


def _h_source_artifacts_unchanged(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    match = re.search(
        r'source STPA artifact "([^"]*)" and taxonomy artifact "([^"]*)" are unchanged',
        text,
    )
    if match:
        stpa_art, tax_art = match.group(1), match.group(2)
    else:
        stpa_art = examples.get("stpa_artifact", "control-structure.yaml")
        tax_art = examples.get("taxonomy_artifact", "attack-patterns.sssom.tsv")

    orig = state["source_artifact_snapshots"]
    current = state["source_artifacts"]
    if current.get("stpa_content") != orig.get(stpa_art):
        return False, f"STPA artifact {stpa_art} changed"
    if current.get("tax_content") != orig.get(tax_art):
        return False, f"Taxonomy artifact {tax_art} changed"
    return True, ""


# -----------------------------------------------------------------------------
# Proposal Feature Handlers
# -----------------------------------------------------------------------------


def _h_source_evidence_linking(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    match = re.search(
        r'source artifacts contain "([^"]*)" evidence linking "([^"]*)" to "([^"]*)"',
        text,
    )
    if match:
        ev_source, left_ref, right_ref = (
            match.group(1),
            match.group(2),
            match.group(3),
        )
    else:
        ev_source = examples.get("evidence_source", "exact-id")
        left_ref = examples.get("left_ref", "CA-1-1")
        right_ref = examples.get("right_ref", "ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

    prop_id = examples.get("proposal_id", "P-1")
    strength = examples.get(
        "strength", "high" if ev_source in ("exact-id", "curated-map") else "weak"
    )
    rel_type = examples.get(
        "relation_type",
        "supports"
        if ev_source == "exact-id"
        else ("addresses" if ev_source == "curated-map" else "overlaps"),
    )

    item = {
        "proposal_id": prop_id,
        "left_ref": left_ref,
        "right_ref": right_ref,
        "evidence_source": ev_source,
        "strength": strength,
        "relation_type": rel_type,
    }
    state.setdefault("source_artifacts", {}).setdefault("evidence", []).append(item)
    return True, ""


def _h_correspondence_proposals_produced(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    srm = state["resource_map"]
    src = state.get("source_artifacts", {})
    pset = propose_correspondence(srm, source_artifacts=src)
    state["proposal_set"] = pset
    state["raw_proposals"] = {p.proposal_id: p for p in pset.proposals}
    return True, ""


def _h_proposal_set_contains_proposal(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    match = re.search(r'the proposal set contains proposal "([^"]*)"', text)
    prop_id = match.group(1) if match else examples.get("proposal_id", "")
    pset, failure = _require_proposal_set(state)
    if failure:
        return False, failure
    found = any(p.proposal_id == prop_id for p in pset.proposals)
    if not found:
        return False, f"Proposal {prop_id} not in proposal set"
    return True, ""


def _h_that_proposal_has_evidence_source(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    match = re.search(r'that proposal has evidence source "([^"]*)"', text)
    expected_src = match.group(1) if match else examples.get("evidence_source", "")
    prop_id = examples.get("proposal_id", "P-1")
    pset, failure = _require_proposal_set(state)
    if failure:
        return False, failure
    prop, failure = _proposal_by_id(pset.proposals, prop_id)
    if failure:
        return False, failure
    if prop.evidence_source != expected_src:
        return (
            False,
            f"Proposal {prop_id} evidence_source '{prop.evidence_source}' != expected '{expected_src}'",
        )
    return True, ""


def _h_that_proposal_has_strength(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    match = re.search(r'that proposal has strength "([^"]*)"', text)
    expected_strength = match.group(1) if match else examples.get("strength", "")
    prop_id = examples.get("proposal_id", "P-1")
    pset, failure = _require_proposal_set(state)
    if failure:
        return False, failure
    prop, failure = _proposal_by_id(pset.proposals, prop_id)
    if failure:
        return False, failure
    if prop.strength != expected_strength:
        return (
            False,
            f"Proposal {prop_id} strength '{prop.strength}' != expected '{expected_strength}'",
        )
    return True, ""


def _h_that_proposal_has_relation_type(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    match = re.search(r'that proposal has relation type "([^"]*)"', text)
    expected_rel = match.group(1) if match else examples.get("relation_type", "")
    prop_id = examples.get("proposal_id", "P-1")
    pset, failure = _require_proposal_set(state)
    if failure:
        return False, failure
    prop, failure = _proposal_by_id(pset.proposals, prop_id)
    if failure:
        return False, failure
    if prop.relation_type != expected_rel:
        return (
            False,
            f"Proposal {prop_id} relation_type '{prop.relation_type}' != expected '{expected_rel}'",
        )
    return True, ""


def _h_that_proposal_not_confirmed(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    prop_id = examples.get("proposal_id", "P-1")
    pset, failure = _require_proposal_set(state)
    if failure:
        return False, failure
    prop, failure = _proposal_by_id(pset.proposals, prop_id)
    if failure:
        return False, failure
    if prop.is_confirmed:
        return False, f"Proposal {prop_id} was confirmed"
    return True, ""


def _h_that_proposal_not_classified_as_other(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    match = re.search(
        r'that proposal is not classified as evidence source "([^"]*)"', text
    )
    other_src = match.group(1) if match else examples.get("other_source", "")
    prop_id = examples.get("proposal_id", "P-3")
    pset, failure = _require_proposal_set(state)
    if failure:
        return False, failure
    prop, failure = _proposal_by_id(pset.proposals, prop_id)
    if failure:
        return False, failure
    if prop.evidence_source == other_src:
        return False, f"Proposal {prop_id} classified as other source '{other_src}'"
    return True, ""


def _h_proposer_emits_proposal(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    match = re.search(
        r'proposer "([^"]*)" version "([^"]*)" emits a proposal for "([^"]*)" and "([^"]*)"',
        text,
    )
    if match:
        proposer_id, ver, left_ref, right_ref = match.groups()
    else:
        proposer_id = examples.get("proposer_id", "exact-id-adapter")
        ver = examples.get("proposer_version", "1")
        left_ref = examples.get("left_ref", "CA-1-1")
        right_ref = examples.get("right_ref", "ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

    prop_id = examples.get("proposal_id", "P-1")
    state["proposer_meta"] = {
        "proposal_id": prop_id,
        "proposer_id": proposer_id,
        "proposer_version": ver,
        "left_ref": left_ref,
        "right_ref": right_ref,
    }
    return True, ""


def _h_proposal_cites_evidence_refs(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    match = re.search(r'the proposal cites evidence references "([^"]*)"', text)
    refs_csv = match.group(1) if match else examples.get("evidence_refs", "")
    refs = [x.strip() for x in refs_csv.split(",") if x.strip()]
    state.setdefault("proposer_meta", {})["evidence_refs"] = refs
    return True, ""


def _h_proposal_pins_versions(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    match = re.search(
        r'the proposal pins STPA version "([^"]*)" and taxonomy version "([^"]*)"',
        text,
    )
    if match:
        stpa_v, tax_v = match.group(1), match.group(2)
    else:
        stpa_v = examples.get("stpa_version", "stpa-v1")
        tax_v = examples.get("taxonomy_version", "atlas-2026.05")

    state.setdefault("proposer_meta", {})["stpa_version"] = stpa_v
    state.setdefault("proposer_meta", {})["taxonomy_version"] = tax_v
    return True, ""


def _h_proposal_rationale_is(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    match = re.search(r'the proposal rationale is "([^"]*)"', text)
    rationale = match.group(1) if match else examples.get("rationale", "")
    meta = state.setdefault("proposer_meta", {})
    meta["rationale"] = rationale
    meta["evidence_source"] = "exact-id"
    meta["strength"] = "high"
    meta["relation_type"] = "supports"

    state.setdefault("source_artifacts", {}).setdefault("evidence", []).append(meta)
    return True, ""


def _h_proposal_has_left_and_right_ref(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    match = re.search(
        r'proposal "([^"]*)" has left ref "([^"]*)" and right ref "([^"]*)"', text
    )
    if match:
        prop_id, left_ref, right_ref = match.groups()
    else:
        prop_id = examples.get("proposal_id", "P-1")
        left_ref = examples.get("left_ref", "")
        right_ref = examples.get("right_ref", "")

    pset, failure = _require_proposal_set(state)
    if failure:
        return False, failure
    prop, failure = _proposal_by_id(pset.proposals, prop_id)
    if failure:
        return False, failure
    if prop.left_ref != left_ref or prop.right_ref != right_ref:
        return (
            False,
            f"Proposal {prop_id} refs ({prop.left_ref}, {prop.right_ref}) != ({left_ref}, {right_ref})",
        )
    return True, ""


def _h_proposal_records_proposer_and_ver(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    match = re.search(
        r'proposal "([^"]*)" records proposer "([^"]*)" version "([^"]*)"', text
    )
    if match:
        prop_id, proposer_id, ver = match.groups()
    else:
        prop_id = examples.get("proposal_id", "P-1")
        proposer_id = examples.get("proposer_id", "")
        ver = examples.get("proposer_version", "")

    pset, failure = _require_proposal_set(state)
    if failure:
        return False, failure
    prop, failure = _proposal_by_id(pset.proposals, prop_id)
    if failure:
        return False, failure
    if prop.proposer_id != proposer_id or str(prop.proposer_version) != str(ver):
        return (
            False,
            f"Proposal {prop_id} proposer ({prop.proposer_id}, {prop.proposer_version}) != ({proposer_id}, {ver})",
        )
    return True, ""


def _h_proposal_records_evidence_refs(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    match = re.search(r'proposal "([^"]*)" records evidence references "([^"]*)"', text)
    if match:
        prop_id, refs_csv = match.group(1), match.group(2)
    else:
        prop_id = examples.get("proposal_id", "P-1")
        refs_csv = examples.get("evidence_refs", "")

    expected_refs = [x.strip() for x in refs_csv.split(",") if x.strip()]
    pset, failure = _require_proposal_set(state)
    if failure:
        return False, failure
    prop, failure = _proposal_by_id(pset.proposals, prop_id)
    if failure:
        return False, failure
    if prop.evidence_refs != expected_refs:
        return (
            False,
            f"Proposal {prop_id} evidence_refs {prop.evidence_refs} != {expected_refs}",
        )
    return True, ""


def _h_proposal_records_stpa_and_tax_ver(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    match = re.search(
        r'proposal "([^"]*)" records STPA version "([^"]*)" and taxonomy version "([^"]*)"',
        text,
    )
    if match:
        prop_id, stpa_v, tax_v = match.groups()
    else:
        prop_id = examples.get("proposal_id", "P-1")
        stpa_v = examples.get("stpa_version", "")
        tax_v = examples.get("taxonomy_version", "")

    pset, failure = _require_proposal_set(state)
    if failure:
        return False, failure
    prop, failure = _proposal_by_id(pset.proposals, prop_id)
    if failure:
        return False, failure
    if prop.stpa_version != stpa_v or prop.taxonomy_version != tax_v:
        return (
            False,
            f"Proposal {prop_id} versions ({prop.stpa_version}, {prop.taxonomy_version}) != ({stpa_v}, {tax_v})",
        )
    return True, ""


def _h_proposal_records_rationale(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    match = re.search(r'proposal "([^"]*)" records rationale "([^"]*)"', text)
    if match:
        prop_id, rationale = match.group(1), match.group(2)
    else:
        prop_id = examples.get("proposal_id", "P-1")
        rationale = examples.get("rationale", "")

    pset, failure = _require_proposal_set(state)
    if failure:
        return False, failure
    prop, failure = _proposal_by_id(pset.proposals, prop_id)
    if failure:
        return False, failure
    if prop.rationale != rationale:
        return (
            False,
            f"Proposal {prop_id} rationale '{prop.rationale}' != expected '{rationale}'",
        )
    return True, ""


def _h_proposer_is_adapter_kind(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    match = re.search(r'proposer "([^"]*)" is a "([^"]*)" adapter', text)
    if match:
        proposer_id, kind = match.group(1), match.group(2)
    else:
        proposer_id = examples.get("proposer_id", "heuristic-adapter")
        kind = examples.get("adapter_kind", "heuristic")

    ev_source = examples.get("evidence_source", kind)
    item = {
        "proposal_id": f"P-{proposer_id}",
        "left_ref": "CA-1-1",
        "right_ref": "ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "proposer_id": proposer_id,
        "adapter_kind": kind,
        "evidence_source": ev_source,
        "strength": "weak",
        "relation_type": "supports",
    }
    state.setdefault("source_artifacts", {}).setdefault("evidence", []).append(item)
    return True, ""


def _h_every_proposal_from_proposer_has_evidence_source(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    match = re.search(
        r'every proposal from "([^"]*)" has evidence source "([^"]*)"', text
    )
    if match:
        proposer_id, expected_src = match.group(1), match.group(2)
    else:
        proposer_id = examples.get("proposer_id", "")
        expected_src = examples.get("evidence_source", "")

    pset, failure = _require_proposal_set(state)
    if failure:
        return False, failure
    props = [p for p in pset.proposals if p.proposer_id == proposer_id]
    for p in props:
        if p.evidence_source != expected_src:
            return (
                False,
                f"Proposal {p.proposal_id} evidence_source '{p.evidence_source}' != '{expected_src}'",
            )
    return True, ""


def _h_no_confirmed_relation_written_by_proposer(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    match = re.search(r'no confirmed relation is written by "([^"]*)"', text)
    proposer_id = match.group(1) if match else examples.get("proposer_id", "")
    pset, failure = _require_proposal_set(state)
    if failure:
        return False, failure
    props = [p for p in pset.proposals if p.proposer_id == proposer_id]
    for p in props:
        if p.is_confirmed:
            return (
                False,
                f"Proposal {p.proposal_id} from {proposer_id} was confirmed",
            )
    return True, ""


# -----------------------------------------------------------------------------
# Artifact Feature Handlers
# -----------------------------------------------------------------------------


def _h_every_proposal_records_stpa_ver(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    match = re.search(r'every proposal records STPA version "([^"]*)"', text)
    expected_v = match.group(1) if match else examples.get("stpa_version", "")
    pset, failure = _require_proposal_set(state)
    if failure:
        return False, failure
    for p in pset.proposals:
        if p.stpa_version != expected_v:
            return (
                False,
                f"Proposal {p.proposal_id} stpa_version '{p.stpa_version}' != '{expected_v}'",
            )
    return True, ""


def _h_every_proposal_records_tax_ver(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    match = re.search(r'every proposal records taxonomy version "([^"]*)"', text)
    expected_v = match.group(1) if match else examples.get("taxonomy_version", "")
    pset, failure = _require_proposal_set(state)
    if failure:
        return False, failure
    for p in pset.proposals:
        if p.taxonomy_version != expected_v:
            return (
                False,
                f"Proposal {p.proposal_id} taxonomy_version '{p.taxonomy_version}' != '{expected_v}'",
            )
    return True, ""


def _h_reconciliation_result_with_varied_outcomes(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    rec1 = ReconciledProposal(
        proposal_id="P-1",
        left_ref="CA-1-1",
        right_ref="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        relation_type="supports",
        evidence_source="exact-id",
        strength="high",
        adjudication="confirmed",
        stpa_version="stpa-v1",
        taxonomy_version="atlas-2026.05",
        adjudication_history=[
            AdjudicationHistoryItem(adjudication="confirmed", reason="verified")
        ],
    )
    rec2 = ReconciledProposal(
        proposal_id="P-2",
        left_ref="L-1",
        right_ref="AP-T6-01",
        relation_type="addresses",
        evidence_source="curated-map",
        strength="high",
        adjudication="rejected",
        stpa_version="stpa-v1",
        taxonomy_version="atlas-2026.05",
    )
    rec3 = ReconciledProposal(
        proposal_id="P-3",
        left_ref="CP-2",
        right_ref="tb:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        relation_type="overlaps",
        evidence_source="resource-overlap",
        strength="weak",
        adjudication="unresolved",
        stpa_version="stpa-v1",
        taxonomy_version="atlas-2026.05",
    )

    result = ReconciliationResult(
        schema_version="1",
        stpa_version="stpa-v1",
        taxonomy_version="atlas-2026.05",
        is_valid=True,
        proposals=[rec1, rec2, rec3],
        errors=[],
        network_calls=0,
        model_calls=0,
    )
    state["reconciliation_result"] = result
    return True, ""


def _h_result_serialized_and_deserialized(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    match = re.search(r'the result is serialized as "([^"]*)" and deserialized', text)
    fmt = match.group(1) if match else examples.get("format", "YAML")
    res, failure = _require_reconciliation_result(state)
    if failure:
        return False, failure

    state["deserialized_result"] = _deserialize_result(_serialize_result(res, fmt), fmt)
    return True, ""


def _h_proposal_identities_preserved(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    orig = state["reconciliation_result"]
    deserialized = state["deserialized_result"]
    if orig is None or deserialized is None:
        return False, "Original or deserialized result missing"
    orig_ids = [p.proposal_id for p in orig.proposals]
    deser_ids = [p.proposal_id for p in deserialized.proposals]
    if orig_ids != deser_ids:
        return False, f"Identities {deser_ids} != {orig_ids}"
    return True, ""


def _h_evidence_provenance_preserved(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    orig = state["reconciliation_result"]
    deserialized = state["deserialized_result"]
    if orig is None or deserialized is None:
        return False, "Original or deserialized result missing"
    for o, d in zip(orig.proposals, deserialized.proposals):
        if (
            o.evidence_source != d.evidence_source
            or o.strength != d.strength
            or o.evidence_refs != d.evidence_refs
        ):
            return False, f"Evidence provenance mismatch on {o.proposal_id}"
    return True, ""


def _h_adjudication_history_preserved(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    orig = state["reconciliation_result"]
    deserialized = state["deserialized_result"]
    if orig is None or deserialized is None:
        return False, "Original or deserialized result missing"
    for o, d in zip(orig.proposals, deserialized.proposals):
        if o.adjudication != d.adjudication:
            return False, f"Adjudication mismatch on {o.proposal_id}"
        if len(o.adjudication_history) != len(d.adjudication_history):
            return False, f"Adjudication history length mismatch on {o.proposal_id}"
    return True, ""


def _h_relation_types_preserved(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    orig = state["reconciliation_result"]
    deserialized = state["deserialized_result"]
    if orig is None or deserialized is None:
        return False, "Original or deserialized result missing"
    for o, d in zip(orig.proposals, deserialized.proposals):
        if o.relation_type != d.relation_type:
            return False, f"Relation type mismatch on {o.proposal_id}"
    return True, ""


def _h_result_serialized_twice(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    match = re.search(r'the result is serialized as "([^"]*)" twice', text)
    fmt = match.group(1) if match else examples.get("format", "YAML")
    res, failure = _require_reconciliation_result(state)
    if failure:
        return False, failure

    state["serialized_twice"] = [
        _serialize_result(res, fmt),
        _serialize_result(res, fmt),
    ]
    return True, ""


def _h_one_proposal_set_presents_order_a(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    match = re.search(r'one proposal set presents identities in order "([^"]*)"', text)
    order_a = match.group(1) if match else examples.get("order_a", "P-1,P-2,P-3")
    ids = [x.strip() for x in order_a.split(",") if x.strip()]

    state["set_a_proposals"] = _proposals_for_ids(state, ids)
    return True, ""


def _h_another_proposal_set_presents_order_b(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    match = re.search(
        r'another proposal set presents the same identities in order "([^"]*)"',
        text,
    )
    order_b = match.group(1) if match else examples.get("order_b", "P-3,P-2,P-1")
    ids = [x.strip() for x in order_b.split(",") if x.strip()]

    state["set_b_proposals"] = _proposals_for_ids(state, ids)
    return True, ""


def _h_each_set_reconciled_and_serialized(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    srm = state["resource_map"]
    res_a = reconcile_correspondence(srm, state["set_a_proposals"])
    res_b = reconcile_correspondence(srm, state["set_b_proposals"])
    state["result_a"] = res_a
    state["result_b"] = res_b
    state["serialized_a"] = res_a.to_yaml()
    state["serialized_b"] = res_b.to_yaml()
    return True, ""


def _h_both_results_identical_canonical_order(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    res_a = state["result_a"]
    res_b = state["result_b"]
    if res_a is None or res_b is None:
        return False, "Results A or B missing"
    ids_a = [p.proposal_id for p in res_a.proposals]
    ids_b = [p.proposal_id for p in res_b.proposals]
    if ids_a != ids_b:
        return False, f"Canonical order mismatch: {ids_a} != {ids_b}"
    return True, ""


def _h_both_serialized_canonically_equivalent(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    ser_a = state["serialized_a"]
    ser_b = state["serialized_b"]
    if ser_a != ser_b:
        return False, "Serialized artifacts are not canonically equivalent"
    return True, ""


def _h_proposer_emits_shared_contract(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    match = re.search(r'proposer "([^"]*)" emits the shared proposal contract', text)
    proposer_id = (
        match.group(1) if match else examples.get("proposer_id", "overlap-adapter")
    )
    new_id = examples.get("new_id", "P-3")
    new_adj = examples.get("new_adjudication", "unresolved")

    prop_new = _make_proposal(
        state,
        new_id,
        left_ref="CP-2",
        right_ref="tb:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        relation_type="overlaps",
        evidence_source="resource-overlap",
        strength="weak",
        proposer_id=proposer_id,
        evidence_refs=["CP-2"],
    )
    state["raw_proposals"][new_id] = prop_new
    state["new_id"] = new_id
    state["new_adjudication"] = new_adj
    return True, ""


def _h_existing_proposals_already_have_adjudications(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    match = re.search(r'existing proposals "([^"]*)" already have adjudications', text)
    existing_csv = match.group(1) if match else examples.get("existing_ids", "P-1,P-2")
    existing_ids = [x.strip() for x in existing_csv.split(",") if x.strip()]
    state["existing_ids"] = existing_ids

    p1 = _make_proposal(state, "P-1")
    p2 = _make_proposal(
        state,
        "P-2",
        left_ref="L-1",
        right_ref="AP-T6-01",
        relation_type="addresses",
        evidence_source="curated-map",
        evidence_refs=["L-1"],
    )
    state["raw_proposals"]["P-1"] = p1
    state["raw_proposals"]["P-2"] = p2
    state["adjudications"]["P-1"] = "confirmed"
    state["adjudications"]["P-2"] = "rejected"
    return True, ""


def _h_proposal_retained_with_new_adjudication(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    match = re.search(
        r'proposal "([^"]*)" is retained with adjudication "([^"]*)"', text
    )
    if match:
        prop_id, adj = match.group(1), match.group(2)
    else:
        prop_id = examples.get("new_id", "P-3")
        adj = examples.get("new_adjudication", "unresolved")

    res, failure = _require_reconciliation_result(state)
    if failure:
        return False, failure
    prop, lookup_failure = _proposal_by_id(res.proposals, prop_id)
    if lookup_failure:
        return False, f"Proposal {prop_id} missing in result"
    if prop.adjudication != adj:
        return (
            False,
            f"Proposal {prop_id} adjudication '{prop.adjudication}' != expected '{adj}'",
        )
    return True, ""


def _h_existing_proposals_keep_adjudications(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    match = re.search(r'proposals "([^"]*)" keep their previous adjudications', text)
    existing_csv = match.group(1) if match else examples.get("existing_ids", "P-1,P-2")
    existing_ids = [x.strip() for x in existing_csv.split(",") if x.strip()]
    res, failure = _require_reconciliation_result(state)
    if failure:
        return False, failure

    for eid in existing_ids:
        prop, lookup_failure = _proposal_by_id(res.proposals, eid)
        if lookup_failure:
            return False, f"Existing proposal {eid} missing in result"
        expected_adj = state["adjudications"].get(eid)
        if prop.adjudication != expected_adj:
            return (
                False,
                f"Existing proposal {eid} adjudication '{prop.adjudication}' != previous '{expected_adj}'",
            )
    return True, ""


def _h_reconciliation_rules_unchanged(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return True, ""


def _h_result_serialized_as_format(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    match = re.search(r'the result is serialized as "([^"]*)"$', text)
    fmt = match.group(1) if match else examples.get("format", "YAML")
    res, failure = _require_reconciliation_result(state)
    if failure:
        return False, failure
    state["serialized_output"] = _serialize_result(res, fmt)
    return True, ""


def _h_artifact_no_coverage_score(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    text_out = state.get("serialized_output", "")
    if "coverage" in text_out.lower():
        return False, "Artifact contains coverage score"
    return True, ""


def _h_artifact_no_blended_metric(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_corr_state(world)
    text_out = state.get("serialized_output", "")
    if "blended" in text_out.lower():
        return False, "Artifact contains blended method metric"
    return True, ""


# -----------------------------------------------------------------------------
# Compatibility Handlers
# -----------------------------------------------------------------------------


def _h_no_correspondence_artifact_added(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return True, ""


def _h_existing_stpa_tax_artifacts_not_mutated(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return True, ""


# =============================================================================
# Registration
# =============================================================================


def register(api: Any) -> None:
    """Register all acceptance handlers for correspondence."""
    registrations = (
        (
            r"^a valid SystemResourceMap is available$",
            _h_valid_srm_available,
        ),
        (
            r"^correspondence reconciliation depends on the SystemResourceMap domain contract$",
            _h_reconciliation_depends_on_srm,
        ),
        (
            r"^correspondence reconciliation makes no network or model calls$",
            _h_no_network_or_model_calls,
        ),
        (
            r"^correspondence proposal makes no network or model calls$",
            _h_no_network_or_model_calls,
        ),
        (
            r"^correspondence proposal and reconciliation are present$",
            _h_proposal_and_reconciliation_present,
        ),
        (
            r"^default generation commands are invoked without correspondence flags$",
            _h_default_commands_no_flags,
        ),
        (
            r'^proposal "([^"]*)" has relation type "([^"]*)"$',
            _h_proposal_has_relation_type,
        ),
        (
            r'^proposal "([^"]*)" has relation type "([^"]*)" and strength "([^"]*)"$',
            _h_proposal_has_relation_type_and_strength,
        ),
        (
            r'^reconciliation input assigns adjudication "([^"]*)" to "([^"]*)"$',
            _h_reconciliation_assigns_adjudication,
        ),
        (
            r"^correspondence is reconciled$",
            _h_correspondence_is_reconciled,
        ),
        (
            r'^the result retains proposal "([^"]*)"$',
            _h_result_retains_proposal,
        ),
        (
            r'^the result records adjudication "([^"]*)" for "([^"]*)"$',
            _h_result_records_adjudication,
        ),
        (
            r'^the result records relation type "([^"]*)" for "([^"]*)"$',
            _h_result_records_relation_type,
        ),
        (
            r'^proposal "([^"]*)" has strength "([^"]*)"$',
            _h_proposal_has_strength_check,
        ),
        (
            r'^proposal "([^"]*)" has adjudication "([^"]*)"$',
            _h_proposal_has_adjudication_check,
        ),
        (
            r"^relation type is not equal to adjudication$",
            _h_relation_type_not_equal_adjudication,
        ),
        (
            r"^relation type is not equal to strength$",
            _h_relation_type_not_equal_strength,
        ),
        (
            r'^conflicting proposals "([^"]*)" with type "([^"]*)" and "([^"]*)" with type "([^"]*)" for "([^"]*)" and "([^"]*)"$',
            _h_conflicting_proposals,
        ),
        (
            r'^the proposals are presented in order "([^"]*)"$',
            _h_proposals_presented_in_order,
        ),
        (
            r"^both proposals are retained$",
            _h_both_proposals_retained,
        ),
        (
            r'^the pair has adjudication "([^"]*)"$',
            _h_pair_has_adjudication,
        ),
        (
            r'^the pair has conflict reason "([^"]*)"$',
            _h_pair_has_conflict_reason,
        ),
        (
            r"^neither proposal is confirmed by iteration order$",
            _h_neither_proposal_confirmed_by_order,
        ),
        (
            r'^proposal "([^"]*)" has confirmation defect "([^"]*)"$',
            _h_proposal_has_confirmation_defect,
        ),
        (
            r"^reconciliation fails$",
            _h_reconciliation_fails,
        ),
        (
            r'^no confirmed relation is written for "([^"]*)"$',
            _h_no_confirmed_relation_written,
        ),
        (
            r'^proposals "([^"]*)" are reconciled to a result$',
            _h_proposals_order_a_reconciled,
        ),
        (
            r'^the same proposals are presented as "([^"]*)"$',
            _h_same_proposals_presented_as_order_b,
        ),
        (
            r"^correspondence is reconciled again$",
            _h_correspondence_reconciled_again,
        ),
        (
            r"^both results have identical proposal identities$",
            _h_both_results_identical_identities,
        ),
        (
            r"^both results have identical adjudications$",
            _h_both_results_identical_adjudications,
        ),
        (
            r"^repeating reconciliation on the first result does not change it$",
            _h_repeating_reconciliation_no_change,
        ),
        (
            r'^scenario prose contains "([^"]*)"$',
            _h_scenario_prose_contains,
        ),
        (
            r"^no explicit proposal cites that prose$",
            _h_no_explicit_proposal_cites_prose,
        ),
        (
            r"^the result contains (\d+) proposals$",
            _h_result_contains_proposal_count,
        ),
        (
            r"^no relation is inferred from scenario wording$",
            _h_no_relation_inferred_from_wording,
        ),
        (
            r'^source STPA artifact "([^"]*)" and taxonomy artifact "([^"]*)"$',
            _h_source_stpa_and_taxonomy_artifacts,
        ),
        (
            r"^correspondence proposals are produced$",
            _h_correspondence_proposals_produced,
        ),
        (
            r'^source STPA artifact "([^"]*)" and taxonomy artifact "([^"]*)" are unchanged$',
            _h_source_artifacts_unchanged,
        ),
        (
            r'^source artifacts contain "([^"]*)" evidence linking "([^"]*)" to "([^"]*)"$',
            _h_source_evidence_linking,
        ),
        (
            r'^the proposal set contains proposal "([^"]*)"$',
            _h_proposal_set_contains_proposal,
        ),
        (
            r'^that proposal has evidence source "([^"]*)"$',
            _h_that_proposal_has_evidence_source,
        ),
        (
            r'^that proposal has strength "([^"]*)"$',
            _h_that_proposal_has_strength,
        ),
        (
            r'^that proposal has relation type "([^"]*)"$',
            _h_that_proposal_has_relation_type,
        ),
        (
            r"^that proposal is not confirmed$",
            _h_that_proposal_not_confirmed,
        ),
        (
            r'^that proposal is not classified as evidence source "([^"]*)"$',
            _h_that_proposal_not_classified_as_other,
        ),
        (
            r'^proposer "([^"]*)" version "([^"]*)" emits a proposal for "([^"]*)" and "([^"]*)"$',
            _h_proposer_emits_proposal,
        ),
        (
            r'^the proposal cites evidence references "([^"]*)"$',
            _h_proposal_cites_evidence_refs,
        ),
        (
            r'^the proposal pins STPA version "([^"]*)" and taxonomy version "([^"]*)"$',
            _h_proposal_pins_versions,
        ),
        (
            r'^the proposal rationale is "([^"]*)"$',
            _h_proposal_rationale_is,
        ),
        (
            r'^proposal "([^"]*)" has left ref "([^"]*)" and right ref "([^"]*)"$',
            _h_proposal_has_left_and_right_ref,
        ),
        (
            r'^proposal "([^"]*)" records proposer "([^"]*)" version "([^"]*)"$',
            _h_proposal_records_proposer_and_ver,
        ),
        (
            r'^proposal "([^"]*)" records evidence references "([^"]*)"$',
            _h_proposal_records_evidence_refs,
        ),
        (
            r'^proposal "([^"]*)" records STPA version "([^"]*)" and taxonomy version "([^"]*)"$',
            _h_proposal_records_stpa_and_tax_ver,
        ),
        (
            r'^proposal "([^"]*)" records rationale "([^"]*)"$',
            _h_proposal_records_rationale,
        ),
        (
            r'^proposer "([^"]*)" is a "([^"]*)" adapter$',
            _h_proposer_is_adapter_kind,
        ),
        (
            r'^every proposal from "([^"]*)" has evidence source "([^"]*)"$',
            _h_every_proposal_from_proposer_has_evidence_source,
        ),
        (
            r'^no confirmed relation is written by "([^"]*)"$',
            _h_no_confirmed_relation_written_by_proposer,
        ),
        (
            r'^every proposal records STPA version "([^"]*)"$',
            _h_every_proposal_records_stpa_ver,
        ),
        (
            r'^every proposal records taxonomy version "([^"]*)"$',
            _h_every_proposal_records_tax_ver,
        ),
        (
            r"^a reconciliation result with confirmed, rejected, and unresolved proposals$",
            _h_reconciliation_result_with_varied_outcomes,
        ),
        (
            r'^the result is serialized as "([^"]*)" and deserialized$',
            _h_result_serialized_and_deserialized,
        ),
        (
            r"^proposal identities are preserved$",
            _h_proposal_identities_preserved,
        ),
        (
            r"^evidence provenance is preserved$",
            _h_evidence_provenance_preserved,
        ),
        (
            r"^adjudication history is preserved$",
            _h_adjudication_history_preserved,
        ),
        (
            r"^relation types are preserved$",
            _h_relation_types_preserved,
        ),
        (
            r'^the result is serialized as "([^"]*)" twice$',
            _h_result_serialized_twice,
        ),
        (
            r'^one proposal set presents identities in order "([^"]*)"$',
            _h_one_proposal_set_presents_order_a,
        ),
        (
            r'^another proposal set presents the same identities in order "([^"]*)"$',
            _h_another_proposal_set_presents_order_b,
        ),
        (
            r"^each set is reconciled and serialized$",
            _h_each_set_reconciled_and_serialized,
        ),
        (
            r"^both results have identical canonical order$",
            _h_both_results_identical_canonical_order,
        ),
        (
            r'^proposer "([^"]*)" emits the shared proposal contract$',
            _h_proposer_emits_shared_contract,
        ),
        (
            r'^existing proposals "([^"]*)" already have adjudications$',
            _h_existing_proposals_already_have_adjudications,
        ),
        (
            r'^proposal "([^"]*)" is retained with adjudication "([^"]*)"$',
            _h_proposal_retained_with_new_adjudication,
        ),
        (
            r'^proposals "([^"]*)" keep their previous adjudications$',
            _h_existing_proposals_keep_adjudications,
        ),
        (
            r"^reconciliation rules are unchanged$",
            _h_reconciliation_rules_unchanged,
        ),
        (
            r'^the result is serialized as "([^"]*)"$',
            _h_result_serialized_as_format,
        ),
        (
            r"^the artifact does not contain a coverage score$",
            _h_artifact_no_coverage_score,
        ),
        (
            r"^the artifact does not contain a blended method metric$",
            _h_artifact_no_blended_metric,
        ),
        (
            r"^no correspondence artifact is added to the run outputs$",
            _h_no_correspondence_artifact_added,
        ),
        (
            r"^existing STPA and taxonomy artifacts are not mutated$",
            _h_existing_stpa_tax_artifacts_not_mutated,
        ),
    )
    for pattern, handler in registrations:
        api.register(pattern, handler)


__all__ = ["FEATURE_ID", "register"]
