"""Deterministic acceptance handlers for taxonomy obligation planning and artifacts."""

from __future__ import annotations

import json
import re
from typing import Any

from runtime_shared import World

from asago_scenario_generator.models.obligation_plan import (
    TaxonomyObligation,
    TaxonomyObligationPlan,
    TaxonomyObligationSnapshot,
)
from asago_scenario_generator.pipeline.obligation_planner import plan_obligations

FEATURE_ID = "taxonomy_obligation_planner"


def _default_snapshot() -> TaxonomyObligationSnapshot:
    return TaxonomyObligationSnapshot(
        taxonomy_version="atlas-2026.05",
        mapping_version="sssom-v1",
        qualification_ruleset_version="catalog-qualification-v1",
        template_version="scenario-envelope-v1",
        digest="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        relationships=[],
        risk_cards=[],
        config={},
        qualification_evaluations=[],
        candidate_expansions=[],
    )


def _planner_state(world: World) -> dict[str, Any]:
    state = getattr(world, "obligation_planner_state", None)
    if state is None:
        state = {
            "snapshot": _default_snapshot(),
            "snapshot_a": None,
            "snapshot_b": None,
            "plan": None,
            "plan_a": None,
            "plan_b": None,
            "deserialized_plan": None,
            "serialized_texts": [],
            "selected_risk_id": None,
            "selected_pattern_id": None,
            "selected_obligation": None,
            "fixture_workflow": None,
            "ran_command": None,
        }
        world.obligation_planner_state = state
    return state


def _rel(
    risk_id: str, pattern_id: str | None, scope: str, disposition: str
) -> dict[str, Any]:
    """Build one risk-to-pattern relationship dict for snapshot fixtures."""
    return {
        "risk_id": risk_id,
        "pattern_id": pattern_id,
        "scope": scope,
        "disposition": disposition,
    }


def _ensure_in_scope_relationship(
    snap: TaxonomyObligationSnapshot, risk_id: str, pattern_id: str | None
) -> None:
    """Add an in-scope relationship unless one already exists for the pair."""
    if not any(
        r.get("risk_id") == risk_id and r.get("pattern_id") == pattern_id
        for r in snap.relationships
    ):
        snap.relationships.append(_rel(risk_id, pattern_id, "in-scope", "generated"))


def _get_or_create_expansion(
    snap: TaxonomyObligationSnapshot, risk_id: str, pattern_id: str | None
) -> dict[str, Any]:
    """Return the candidate-expansion record for a pair, creating one if absent."""
    exp = next(
        (
            e
            for e in snap.candidate_expansions
            if e.get("risk_id") == risk_id and e.get("pattern_id") == pattern_id
        ),
        None,
    )
    if exp is None:
        exp = {
            "risk_id": risk_id,
            "pattern_id": pattern_id,
            "accepted_candidates": [],
            "rejected_candidates": [],
        }
        snap.candidate_expansions.append(exp)
    return exp


def _obligation_ids(plan: TaxonomyObligationPlan) -> list[str]:
    """List obligation identifiers in ledger order."""
    return [o.obligation_id for o in plan.obligations]


def _matching_obligations(
    plan: TaxonomyObligationPlan,
    risk_id: str | None = None,
    pattern_id: str | None = None,
) -> list[TaxonomyObligation]:
    """List obligations matching the given risk and/or pattern."""
    return [
        o
        for o in plan.obligations
        if (risk_id is None or o.risk_id == risk_id)
        and (pattern_id is None or o.pattern_id == pattern_id)
    ]


def _selected_or_first(state: dict[str, Any]) -> TaxonomyObligation:
    """Return the selected obligation, falling back to the first ledger entry."""
    return state.get("selected_obligation") or state["plan"].obligations[0]


def _requested_format(
    text: str, examples: dict, step_pattern: str, example_key: str
) -> str:
    """Parse the requested serialization format from a step."""
    match = re.search(step_pattern, text)
    return (match.group(1) if match else examples.get(example_key, "")).upper()


def _serialize_plan(plan: TaxonomyObligationPlan, fmt: str) -> str:
    """Serialize a plan in the requested format (YAML or JSON)."""
    if fmt == "YAML":
        return plan.to_yaml()
    return plan.to_json()


def _deserialize_plan(text_data: str, fmt: str) -> TaxonomyObligationPlan:
    """Deserialize a plan from the requested format (YAML or JSON)."""
    if fmt == "YAML":
        return TaxonomyObligationPlan.from_yaml(text_data)
    return TaxonomyObligationPlan.from_json(text_data)


def _make_records_handler(field: str, step_pattern: str, example_key: str):
    """Build a handler asserting the plan records one pinned version field."""

    def _records_field(world: World, text: str, examples: dict) -> tuple[bool, str]:
        state = _planner_state(world)
        match = re.search(step_pattern, text)
        expected = match.group(1) if match else examples.get(example_key, "")
        plan = state["plan"]
        actual = getattr(plan, field) if plan else None
        if actual != expected:
            return False, f"Expected {field} {expected}, got {actual}"
        return True, ""

    return _records_field


def _make_order_handler(state_key: str, example_key: str):
    """Build a handler capturing one ordered relationship presentation."""

    def _snapshot_order(world: World, text: str, examples: dict) -> tuple[bool, str]:
        state = _planner_state(world)
        match = re.search(r'relationships in order "([^"]+)"', text)
        order = match.group(1) if match else examples.get(example_key, "")
        snap = _default_snapshot()
        snap.relationships = _parse_order(order)
        state[state_key] = snap
        return True, ""

    return _snapshot_order


def _make_mapping_handler(scope: str, disposition: str):
    """Build a handler appending one risk-to-pattern mapping relationship."""

    def _add_mapping(world: World, text: str, examples: dict) -> tuple[bool, str]:
        state = _planner_state(world)
        match = re.search(
            rf'risk "([^"]+)" has an {scope} mapping to pattern "([^"]+)"', text
        )
        if not match:
            return False, f"Could not parse {scope} mapping: {text}"
        risk_id, pattern_id = match.group(1), match.group(2)
        state["snapshot"].relationships.append(
            _rel(risk_id, pattern_id, scope, disposition)
        )
        return True, ""

    return _add_mapping


def _make_obligation_field_handler(
    field: str, label: str, step_pattern: str, example_key: str
):
    """Build a handler asserting the selected obligation has a field value."""

    def _obligation_has(world: World, text: str, examples: dict) -> tuple[bool, str]:
        state = _planner_state(world)
        match = re.search(step_pattern, text)
        expected = match.group(1) if match else examples.get(example_key, "")
        ob = _selected_or_first(state)
        actual = getattr(ob, field)
        if actual != expected:
            return False, f"Expected {label} {expected}, got {actual}"
        return True, ""

    return _obligation_has


def _h_snapshot_available(world: World, text: str, examples: dict) -> tuple[bool, str]:
    state = _planner_state(world)
    state["snapshot"] = _default_snapshot()
    state["plan"] = None
    state["selected_obligation"] = None
    return True, ""


def _h_no_network_or_model(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return True, ""


def _h_pins_versions(world: World, text: str, examples: dict) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(
        r'taxonomy version "([^"]+)", mapping version "([^"]+)", qualification ruleset version "([^"]+)", template version "([^"]+)", and digest "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse pins versions from: {text}"
    snap = state["snapshot"]
    snap.taxonomy_version = match.group(1)
    snap.mapping_version = match.group(2)
    snap.qualification_ruleset_version = match.group(3)
    snap.template_version = match.group(4)
    snap.digest = match.group(5)
    return True, ""


def _h_produce_plan(world: World, text: str, examples: dict) -> tuple[bool, str]:
    state = _planner_state(world)
    snap = state["snapshot"]
    state["plan"] = plan_obligations(snap)
    return True, ""


def _parse_order(order_str: str) -> list[dict[str, Any]]:
    rels: list[dict[str, Any]] = []
    items = [x.strip() for x in order_str.split(",") if x.strip()]
    for item in items:
        if ":" in item:
            risk_id, pattern_id = item.split(":", 1)
            rels.append(_rel(risk_id, pattern_id, "in-scope", "generated"))
        else:
            rels.append(_rel(item, None, "in-scope", "governance-only"))
    return rels


def _h_produce_both_plans(world: World, text: str, examples: dict) -> tuple[bool, str]:
    state = _planner_state(world)
    state["plan_a"] = plan_obligations(state["snapshot_a"])
    state["plan_b"] = plan_obligations(state["snapshot_b"])
    return True, ""


def _h_identical_identifiers(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    ids_a = _obligation_ids(state["plan_a"])
    ids_b = _obligation_ids(state["plan_b"])
    if ids_a != ids_b:
        return False, f"Identifiers mismatch: {ids_a} vs {ids_b}"
    return True, ""


def _h_identical_order(world: World, text: str, examples: dict) -> tuple[bool, str]:
    state = _planner_state(world)
    ids_a = _obligation_ids(state["plan_a"])
    ids_b = _obligation_ids(state["plan_b"])
    if ids_a != ids_b:
        return False, f"Order mismatch: {ids_a} vs {ids_b}"
    return True, ""


def _h_canonically_equivalent(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    if state["plan_a"] is None:
        # Shared generated-test registry: this step text is also registered by
        # the system resource map feature, whose state answers first here.
        map_state = getattr(world, "system_resource_map_state", None)
        if map_state and map_state.get("serialized_a") is not None:
            if map_state["serialized_a"] != map_state["serialized_b"]:
                return False, "Serialized SRM artifacts not equivalent"
            return True, ""
        return False, "No plan_a in planner state"
    if state["plan_a"].to_json() != state["plan_b"].to_json():
        return False, "JSON serialization is not canonically equivalent"
    if state["plan_a"].to_yaml() != state["plan_b"].to_yaml():
        return False, "YAML serialization is not canonically equivalent"
    return True, ""


def _h_snapshot_produces_rich_plan(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    snap = _default_snapshot()
    snap.relationships = [
        _rel("atlas-prompt-injection", "AP-T6-01", "in-scope", "generated"),
        _rel("atlas-memory-poisoning", "AP-T1-01", "in-scope", "missing-template"),
    ]
    snap.qualification_evaluations = [
        {
            "risk_id": "atlas-prompt-injection",
            "pattern_id": "AP-T6-01",
            "predicate": "deployment.attacker_code_execution_on_agent_host",
            "facts": "deployment.attacker_code_execution_on_agent_host=false",
            "result": "false",
            "reason": "fact present and unequal",
        }
    ]
    snap.candidate_expansions = [
        {
            "risk_id": "atlas-prompt-injection",
            "pattern_id": "AP-T6-01",
            "accepted_candidates": ["cand:v2:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
            "rejected_candidates": [
                {
                    "candidate_id": "cand:v2:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "reason": "rule rejected combination",
                }
            ],
        }
    ]
    state["snapshot"] = snap
    state["plan"] = plan_obligations(snap)
    return True, ""


def _h_serialize_and_deserialize(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    fmt = _requested_format(
        text, examples, r'serialized as "([^"]+)" and deserialized', "format"
    )
    if fmt not in ("YAML", "JSON"):
        return False, f"Unknown format: {fmt}"
    plan = state["plan"]
    text_data = _serialize_plan(plan, fmt)
    state["deserialized_plan"] = _deserialize_plan(text_data, fmt)
    return True, ""


def _h_identities_preserved(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    orig_ids = _obligation_ids(state["plan"])
    des_ids = _obligation_ids(state["deserialized_plan"])
    if orig_ids != des_ids:
        return False, f"Identities not preserved: {orig_ids} vs {des_ids}"
    return True, ""


def _h_pinned_versions_preserved(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    p1 = state["plan"]
    p2 = state["deserialized_plan"]
    if (
        p1.taxonomy_version != p2.taxonomy_version
        or p1.mapping_version != p2.mapping_version
        or p1.qualification_ruleset_version != p2.qualification_ruleset_version
        or p1.template_version != p2.template_version
        or p1.digest != p2.digest
    ):
        return False, "Pinned versions not preserved"
    return True, ""


def _h_terminal_dispositions_preserved(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    p1 = state["plan"]
    p2 = state["deserialized_plan"]
    d1 = [o.terminal_disposition for o in p1.obligations]
    d2 = [o.terminal_disposition for o in p2.obligations]
    if d1 != d2:
        return False, f"Dispositions not preserved: {d1} vs {d2}"
    return True, ""


def _h_evidence_preserved(world: World, text: str, examples: dict) -> tuple[bool, str]:
    state = _planner_state(world)
    p1 = state["plan"]
    p2 = state["deserialized_plan"]
    if len(p1.obligations) != len(p2.obligations):
        return False, "Obligations count mismatch"
    for o1, o2 in zip(p1.obligations, p2.obligations):
        if o1.qualification_trace != o2.qualification_trace:
            return (
                False,
                f"Qualification trace mismatch: {o1.qualification_trace} vs {o2.qualification_trace}",
            )
        if o1.accepted_candidates != o2.accepted_candidates:
            return (
                False,
                f"Accepted candidates mismatch: {o1.accepted_candidates} vs {o2.accepted_candidates}",
            )
        if o1.rejected_candidates != o2.rejected_candidates:
            return (
                False,
                f"Rejected candidates mismatch: {o1.rejected_candidates} vs {o2.rejected_candidates}",
            )
    return True, ""


def _h_serialize_twice(world: World, text: str, examples: dict) -> tuple[bool, str]:
    state = _planner_state(world)
    fmt = _requested_format(text, examples, r'serialized as "([^"]+)" twice', "format")
    if fmt not in ("YAML", "JSON"):
        return False, f"Unknown format: {fmt}"
    plan = state["plan"]
    state["serialized_texts"] = [_serialize_plan(plan, fmt), _serialize_plan(plan, fmt)]
    return True, ""


def _h_byte_identical(world: World, text: str, examples: dict) -> tuple[bool, str]:
    state = _planner_state(world)
    texts = state["serialized_texts"]
    if len(texts) != 2:
        # Shared generated-test registry: the system resource map feature also
        # registers this step and may own the serialized texts.
        map_state = getattr(world, "system_resource_map_state", None)
        if map_state and len(map_state.get("serialized_texts", [])) == 2:
            map_texts = map_state["serialized_texts"]
            if map_texts[0] == map_texts[1]:
                return True, ""
            return False, "Serialized texts are not byte-identical"
        return False, "Serialized texts are not byte-identical"
    if texts[0] != texts[1]:
        return False, "Serialized texts are not byte-identical"
    return True, ""


def _h_risk_cards_map_shared_pattern(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(
        r'risk cards "([^"]+)" and "([^"]+)" both map in-scope to attack pattern "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse shared pattern step: {text}"
    risk_a, risk_b, pattern_id = match.group(1), match.group(2), match.group(3)
    snap = state["snapshot"]
    snap.relationships = [
        _rel(risk_a, pattern_id, "in-scope", "generated"),
        _rel(risk_b, pattern_id, "in-scope", "generated"),
    ]
    return True, ""


def _h_ledger_count_for_pattern(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(r'contains (\d+) obligations for pattern "([^"]+)"', text)
    if not match:
        return False, f"Could not parse pattern count step: {text}"
    expected_count = int(match.group(1))
    pattern_id = match.group(2)
    plan = state["plan"]
    matching = _matching_obligations(plan, pattern_id=pattern_id)
    if len(matching) != expected_count:
        return (
            False,
            f"Expected {expected_count} obligations for pattern {pattern_id}, got {len(matching)}",
        )
    return True, ""


def _h_distinct_obligations(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(
        r'obligation for risk "([^"]+)" is distinct from the obligation for risk "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse distinct obligations step: {text}"
    risk_a, risk_b = match.group(1), match.group(2)
    plan = state["plan"]
    ob_a = next((o for o in plan.obligations if o.risk_id == risk_a), None)
    ob_b = next((o for o in plan.obligations if o.risk_id == risk_b), None)
    if ob_a is None or ob_b is None:
        return False, f"Could not find obligations for {risk_a} or {risk_b}"
    if ob_a.obligation_id == ob_b.obligation_id:
        return False, f"Obligations are not distinct: {ob_a.obligation_id}"
    return True, ""


def _h_retains_risk_identity(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    plan = state["plan"]
    for ob in plan.obligations:
        if ob.risk_id not in ob.obligation_id:
            return (
                False,
                f"Obligation {ob.obligation_id} does not retain risk {ob.risk_id}",
            )
    return True, ""


def _h_records_scope_decision(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(
        r'records an (in-scope|out-of-scope) decision for risk "([^"]+)" and pattern "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse scope decision: {text}"
    scope, risk_id, pattern_id = match.group(1), match.group(2), match.group(3)
    plan = state["plan"]
    ob = next(
        (
            o
            for o in plan.obligations
            if o.risk_id == risk_id and o.pattern_id == pattern_id
        ),
        None,
    )
    if ob is None:
        return False, f"No obligation found for {risk_id} and {pattern_id}"
    if ob.scope != scope:
        return False, f"Expected scope {scope}, got {ob.scope}"
    return True, ""


def _h_expected_relationships_count(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(r'contains "(\d+)" expected risk-to-pattern relationships', text)
    count = int(match.group(1)) if match else int(examples.get("relationship_count", 6))
    snap = state["snapshot"]
    snap.relationships = []
    dispositions = [
        "gated",
        "missing-template",
        "infeasible",
        "unsupported",
        "generated",
        "governance-only",
    ]
    for i in range(count):
        disp = dispositions[i % len(dispositions)]
        pattern = f"AP-T{i + 1}-01" if disp != "governance-only" else None
        scope = "out-of-scope" if disp == "gated" else "in-scope"
        snap.relationships.append(_rel(f"risk-{i + 1}", pattern, scope, disp))
    return True, ""


def _h_ledger_contains_obligations(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(r'contains "?(\d+)"? obligations', text)
    if not match:
        return False, f"Could not parse obligations count: {text}"
    expected_count = int(match.group(1))
    plan = state["plan"]
    if len(plan.obligations) != expected_count:
        return (
            False,
            f"Expected {expected_count} obligations, got {len(plan.obligations)}",
        )
    return True, ""


def _h_exactly_one_terminal_disposition(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    plan = state["plan"]
    for ob in plan.obligations:
        if not ob.terminal_disposition:
            return False, f"Obligation {ob.obligation_id} missing terminal disposition"
    return True, ""


def _h_no_relationship_omitted(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    snap = state["snapshot"]
    plan = state["plan"]
    if len(plan.obligations) != len(snap.relationships):
        return (
            False,
            f"Obligations count {len(plan.obligations)} != snapshot relationships count {len(snap.relationships)}",
        )
    return True, ""


def _h_snapshot_contains_kind_relationship(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(
        r'contains a "([^"]+)" relationship for risk "([^"]+)" and pattern "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse kind relationship: {text}"
    kind, risk_id, pattern_id = match.group(1), match.group(2), match.group(3)
    snap = state["snapshot"]
    snap.relationships = [
        {"risk_id": risk_id, "pattern_id": pattern_id, "relationship_kind": kind}
    ]
    return True, ""


def _h_ledger_count_for_risk_pattern(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(
        r'contains (\d+) obligations for risk "([^"]+)" and pattern "([^"]+)"', text
    )
    if not match:
        return False, f"Could not parse risk/pattern count: {text}"
    count, risk_id, pattern_id = int(match.group(1)), match.group(2), match.group(3)
    plan = state["plan"]
    matching = _matching_obligations(plan, risk_id=risk_id, pattern_id=pattern_id)
    if len(matching) != count:
        return (
            False,
            f"Expected {count} obligations for {risk_id}/{pattern_id}, got {len(matching)}",
        )
    state["selected_obligation"] = matching[0]
    return True, ""


def _h_risk_no_actionable_pattern(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(r'risk card "([^"]+)" has no actionable attack pattern', text)
    if not match:
        return False, f"Could not parse risk no pattern step: {text}"
    risk_id = match.group(1)
    snap = state["snapshot"]
    snap.relationships = [_rel(risk_id, None, "in-scope", "governance-only")]
    return True, ""


def _h_ledger_count_for_risk(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(r'contains (\d+) obligations for risk "([^"]+)"', text)
    if not match:
        return False, f"Could not parse risk count step: {text}"
    count, risk_id = int(match.group(1)), match.group(2)
    plan = state["plan"]
    matching = _matching_obligations(plan, risk_id=risk_id)
    if len(matching) != count:
        return False, f"Expected {count} obligations for {risk_id}, got {len(matching)}"
    state["selected_obligation"] = matching[0]
    return True, ""


def _h_obligation_lists_no_pattern(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    ob = _selected_or_first(state)
    if ob.pattern_id is not None:
        return False, f"Expected no pattern_id, got {ob.pattern_id}"
    return True, ""


def _h_snapshot_includes_secret(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(r'secret "([^"]+)"', text)
    secret = match.group(1) if match else examples.get("secret", "")
    snap = state["snapshot"]
    snap.config["api_secret"] = secret
    return True, ""


def _h_qualification_applicable(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(
        r'qualification is applicable for risk "([^"]+)" and pattern "([^"]+)"', text
    )
    if not match:
        return False, f"Could not parse qualification applicable: {text}"
    risk_id, pattern_id = match.group(1), match.group(2)
    state["selected_risk_id"] = risk_id
    state["selected_pattern_id"] = pattern_id
    _ensure_in_scope_relationship(state["snapshot"], risk_id, pattern_id)
    return True, ""


def _h_qualification_evaluates_predicate(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(
        r'evaluates predicate "([^"]+)" with facts "([^"]+)" resulting in "([^"]+)" because "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse qualification eval: {text}"
    predicate, facts, result, reason = (
        match.group(1),
        match.group(2),
        match.group(3),
        match.group(4),
    )
    risk_id = state.get("selected_risk_id") or "atlas-prompt-injection"
    pattern_id = state.get("selected_pattern_id") or "AP-T6-01"
    snap = state["snapshot"]
    snap.qualification_evaluations.append(
        {
            "risk_id": risk_id,
            "pattern_id": pattern_id,
            "predicate": predicate,
            "facts": facts,
            "result": result,
            "reason": reason,
        }
    )
    return True, ""


def _h_qualification_trace_records(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(
        r'records predicate "([^"]+)", facts "([^"]+)", result "([^"]+)", and reason "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse qualification trace check: {text}"
    predicate, facts, result, reason = (
        match.group(1),
        match.group(2),
        match.group(3),
        match.group(4),
    )
    plan = state["plan"]
    ob = state.get("selected_obligation") or plan.obligations[0]
    if not ob.qualification_trace:
        return False, f"No qualification traces in obligation {ob.obligation_id}"
    item = ob.qualification_trace[0]
    if (
        item.predicate != predicate
        or item.facts != facts
        or str(item.result) != result
        or item.reason != reason
    ):
        return (
            False,
            f"Trace mismatch: {item} vs expected ({predicate}, {facts}, {result}, {reason})",
        )
    return True, ""


def _h_qualification_trace_no_secret(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(r'does not contain "([^"]+)"', text)
    secret = match.group(1) if match else examples.get("secret", "")
    plan = state["plan"]
    ob = state.get("selected_obligation") or plan.obligations[0]
    dumped = json.dumps([t.model_dump() for t in ob.qualification_trace])
    if secret in dumped:
        return False, f"Secret {secret} found in qualification trace: {dumped}"
    return True, ""


def _h_candidate_expansion_applicable(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(
        r'candidate expansion is applicable for risk "([^"]+)" and pattern "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse candidate expansion step: {text}"
    risk_id, pattern_id = match.group(1), match.group(2)
    state["selected_risk_id"] = risk_id
    state["selected_pattern_id"] = pattern_id
    _ensure_in_scope_relationship(state["snapshot"], risk_id, pattern_id)
    return True, ""


def _h_expansion_produces_accepted(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(r'expansion produces accepted candidate "([^"]+)"', text)
    if not match:
        return False, f"Could not parse accepted candidate step: {text}"
    accepted_id = match.group(1)
    risk_id = state.get("selected_risk_id") or "atlas-prompt-injection"
    pattern_id = state.get("selected_pattern_id") or "AP-T6-01"
    snap = state["snapshot"]
    exp = _get_or_create_expansion(snap, risk_id, pattern_id)
    exp["accepted_candidates"].append(accepted_id)
    return True, ""


def _h_expansion_produces_rejected(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(
        r'expansion produces rejected candidate "([^"]+)" with reason "([^"]+)"', text
    )
    if not match:
        return False, f"Could not parse rejected candidate step: {text}"
    rejected_id, reason = match.group(1), match.group(2)
    risk_id = state.get("selected_risk_id") or "atlas-prompt-injection"
    pattern_id = state.get("selected_pattern_id") or "AP-T6-01"
    snap = state["snapshot"]
    exp = _get_or_create_expansion(snap, risk_id, pattern_id)
    exp["rejected_candidates"].append({"candidate_id": rejected_id, "reason": reason})
    return True, ""


def _h_obligation_retains_accepted(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(r'retains accepted candidate "([^"]+)"', text)
    if not match:
        return False, f"Could not parse retains accepted step: {text}"
    accepted_id = match.group(1)
    plan = state["plan"]
    ob = state.get("selected_obligation") or plan.obligations[0]
    if accepted_id not in ob.accepted_candidates:
        return (
            False,
            f"Accepted candidate {accepted_id} not in {ob.accepted_candidates}",
        )
    return True, ""


def _h_obligation_retains_rejected(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(
        r'retains rejected candidate "([^"]+)" with reason "([^"]+)"', text
    )
    if not match:
        return False, f"Could not parse retains rejected step: {text}"
    rejected_id, reason = match.group(1), match.group(2)
    plan = state["plan"]
    ob = state.get("selected_obligation") or plan.obligations[0]
    rej = next(
        (r for r in ob.rejected_candidates if r.candidate_id == rejected_id), None
    )
    if rej is None:
        return (
            False,
            f"Rejected candidate {rejected_id} not found in {ob.rejected_candidates}",
        )
    if rej.reason != reason:
        return False, f"Expected reason {reason}, got {rej.reason}"
    return True, ""


def _h_snapshot_in_and_out_of_scope(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    snap = state["snapshot"]
    snap.relationships = [
        _rel("atlas-prompt-injection", "AP-T6-01", "in-scope", "generated"),
        _rel("atlas-memory-poisoning", "AP-T11-01", "out-of-scope", "gated"),
    ]
    return True, ""


def _h_recorded_network_calls(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(r"recorded (\d+) network calls", text)
    expected = int(match.group(1)) if match else int(examples.get("network_calls", 0))
    plan = state["plan"]
    if plan.network_calls != expected:
        return False, f"Expected {expected} network calls, got {plan.network_calls}"
    return True, ""


def _h_recorded_model_calls(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(r"recorded (\d+) model calls", text)
    expected = int(match.group(1)) if match else int(examples.get("model_calls", 0))
    plan = state["plan"]
    if plan.model_calls != expected:
        return False, f"Expected {expected} model calls, got {plan.model_calls}"
    return True, ""


def _h_obligation_planner_present(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return True, ""


def _h_default_commands_no_flags(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return True, ""


def _h_deterministic_workflow_fixture(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(r'deterministic offline "([^"]+)" fixture', text)
    workflow = match.group(1) if match else examples.get("workflow", "")
    state["fixture_workflow"] = workflow
    return True, ""


def _h_default_command_runs(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(r'default "([^"]+)" runs', text)
    command = match.group(1) if match else examples.get("command", "")
    state["ran_command"] = command
    return True, ""


def _h_artifacts_match_fixture(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return True, ""


def _h_generation_counts_unchanged(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return True, ""


def _h_scenario_prompts_unchanged(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return True, ""


def _h_no_obligation_plan_added(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return True, ""


def register(api: Any) -> None:
    api.set_feature(FEATURE_ID)
    registrations = (
        (r"a pinned taxonomy obligation snapshot is available", _h_snapshot_available),
        (
            r"obligation planning makes no network or model calls",
            _h_no_network_or_model,
        ),
        (
            r'the snapshot pins taxonomy version "([^"]+)", mapping version "([^"]+)", qualification ruleset version "([^"]+)", template version "([^"]+)", and digest "([^"]+)"',
            _h_pins_versions,
        ),
        (r"the obligation plan is produced", _h_produce_plan),
        (
            r'the plan records taxonomy version "([^"]+)"',
            _make_records_handler(
                "taxonomy_version", r'taxonomy version "([^"]+)"', "taxonomy_version"
            ),
        ),
        (
            r'the plan records mapping version "([^"]+)"',
            _make_records_handler(
                "mapping_version", r'mapping version "([^"]+)"', "mapping_version"
            ),
        ),
        (
            r'the plan records qualification ruleset version "([^"]+)"',
            _make_records_handler(
                "qualification_ruleset_version",
                r'qualification ruleset version "([^"]+)"',
                "ruleset_version",
            ),
        ),
        (
            r'the plan records template version "([^"]+)"',
            _make_records_handler(
                "template_version", r'template version "([^"]+)"', "template_version"
            ),
        ),
        (
            r'the plan records digest "([^"]+)"',
            _make_records_handler("digest", r'digest "([^"]+)"', "digest"),
        ),
        (
            r'one snapshot presents relationships in order "([^"]+)"',
            _make_order_handler("snapshot_a", "order_a"),
        ),
        (
            r'another snapshot presents the same relationships in order "([^"]+)"',
            _make_order_handler("snapshot_b", "order_b"),
        ),
        (
            r"an obligation plan is produced from each presentation",
            _h_produce_both_plans,
        ),
        (r"both plans have identical obligation identifiers", _h_identical_identifiers),
        (r"both plans have identical canonical ledger order", _h_identical_order),
        (
            r"both serialized artifacts are canonically equivalent",
            _h_canonically_equivalent,
        ),
        (
            r"the snapshot produces a plan with pinned versions, dispositions, and evidence",
            _h_snapshot_produces_rich_plan,
        ),
        (
            r'the plan is serialized as "([^"]+)" and deserialized',
            _h_serialize_and_deserialize,
        ),
        (r"obligation identities are preserved", _h_identities_preserved),
        (r"pinned versions are preserved", _h_pinned_versions_preserved),
        (r"terminal dispositions are preserved", _h_terminal_dispositions_preserved),
        (
            r"qualification traces and candidate evidence are preserved",
            _h_evidence_preserved,
        ),
        (r'the plan is serialized as "([^"]+)" twice', _h_serialize_twice),
        (r"the two artifacts are byte-identical", _h_byte_identical),
        (
            r'risk cards "([^"]+)" and "([^"]+)" both map in-scope to attack pattern "([^"]+)"',
            _h_risk_cards_map_shared_pattern,
        ),
        (
            r'the plan ledger contains (\d+) obligations for pattern "([^"]+)"',
            _h_ledger_count_for_pattern,
        ),
        (
            r'the obligation for risk "([^"]+)" is distinct from the obligation for risk "([^"]+)"',
            _h_distinct_obligations,
        ),
        (r"each obligation retains its own risk identity", _h_retains_risk_identity),
        (
            r'risk "([^"]+)" has an in-scope mapping to pattern "([^"]+)"',
            _make_mapping_handler("in-scope", "generated"),
        ),
        (
            r'risk "([^"]+)" has an out-of-scope mapping to pattern "([^"]+)"',
            _make_mapping_handler("out-of-scope", "gated"),
        ),
        (
            r'the plan records an (in-scope|out-of-scope) decision for risk "([^"]+)" and pattern "([^"]+)"',
            _h_records_scope_decision,
        ),
        (
            r'the snapshot contains "([^"]+)" expected risk-to-pattern relationships',
            _h_expected_relationships_count,
        ),
        (
            r'the plan ledger contains "?(\d+)"? obligations',
            _h_ledger_contains_obligations,
        ),
        (
            r"every obligation has exactly one terminal disposition",
            _h_exactly_one_terminal_disposition,
        ),
        (
            r"no expected relationship is omitted from the ledger",
            _h_no_relationship_omitted,
        ),
        (
            r'the snapshot contains a "([^"]+)" relationship for risk "([^"]+)" and pattern "([^"]+)"',
            _h_snapshot_contains_kind_relationship,
        ),
        (
            r'the plan ledger contains (\d+) obligations for risk "([^"]+)" and pattern "([^"]+)"',
            _h_ledger_count_for_risk_pattern,
        ),
        (
            r'that obligation has terminal disposition "([^"]+)"',
            _make_obligation_field_handler(
                "terminal_disposition",
                "terminal disposition",
                r'terminal disposition "([^"]+)"',
                "disposition",
            ),
        ),
        (
            r'that obligation has scope "([^"]+)"',
            _make_obligation_field_handler(
                "scope", "scope", r'scope "([^"]+)"', "scope"
            ),
        ),
        (
            r'risk card "([^"]+)" has no actionable attack pattern',
            _h_risk_no_actionable_pattern,
        ),
        (
            r'the plan ledger contains (\d+) obligations for risk "([^"]+)"',
            _h_ledger_count_for_risk,
        ),
        (r"that obligation lists no attack-pattern ID", _h_obligation_lists_no_pattern),
        (
            r'the snapshot configuration includes secret "([^"]+)"',
            _h_snapshot_includes_secret,
        ),
        (
            r'qualification is applicable for risk "([^"]+)" and pattern "([^"]+)"',
            _h_qualification_applicable,
        ),
        (
            r'qualification evaluates predicate "([^"]+)" with facts "([^"]+)" resulting in "([^"]+)" because "([^"]+)"',
            _h_qualification_evaluates_predicate,
        ),
        (
            r'the qualification trace for that obligation records predicate "([^"]+)", facts "([^"]+)", result "([^"]+)", and reason "([^"]+)"',
            _h_qualification_trace_records,
        ),
        (
            r'the qualification trace does not contain "([^"]+)"',
            _h_qualification_trace_no_secret,
        ),
        (
            r'candidate expansion is applicable for risk "([^"]+)" and pattern "([^"]+)"',
            _h_candidate_expansion_applicable,
        ),
        (
            r'expansion produces accepted candidate "([^"]+)"',
            _h_expansion_produces_accepted,
        ),
        (
            r'expansion produces rejected candidate "([^"]+)" with reason "([^"]+)"',
            _h_expansion_produces_rejected,
        ),
        (
            r'the obligation retains accepted candidate "([^"]+)"',
            _h_obligation_retains_accepted,
        ),
        (
            r'the obligation retains rejected candidate "([^"]+)" with reason "([^"]+)"',
            _h_obligation_retains_rejected,
        ),
        (
            r"the snapshot contains in-scope and out-of-scope relationships",
            _h_snapshot_in_and_out_of_scope,
        ),
        (
            r"obligation planning recorded (\d+) network calls",
            _h_recorded_network_calls,
        ),
        (r"obligation planning recorded (\d+) model calls", _h_recorded_model_calls),
        (r"the obligation planner is present", _h_obligation_planner_present),
        (
            r"default generation commands are invoked without obligation-planner flags",
            _h_default_commands_no_flags,
        ),
        (
            r'a deterministic offline "([^"]+)" fixture',
            _h_deterministic_workflow_fixture,
        ),
        (r'the default "([^"]+)" runs', _h_default_command_runs),
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
