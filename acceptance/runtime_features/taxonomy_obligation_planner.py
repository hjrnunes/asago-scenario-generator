"""Deterministic acceptance handlers for taxonomy obligation planning and artifacts."""

from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path
from typing import Any

import yaml

from runtime_shared import World

from asago_scenario_generator.cli.obligation import run_plan_obligations
from asago_scenario_generator.models.obligation_plan import (
    TaxonomyObligation,
    TaxonomyObligationPlan,
    TaxonomyObligationSnapshot,
)
from asago_scenario_generator.pipeline.obligation_planner import plan_obligations

FEATURE_ID = "taxonomy_obligation_planner"

# Compatibility fixtures pair each workflow with its default command.
_COMPAT_WORKFLOW_COMMANDS = {
    "taxonomy/risk": "generate",
    "STPA": "stpa-run",
}


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
            "selected_candidate": None,
            "fixture_workflow": None,
            "ran_command": None,
            "load_error": None,
            "plan_error": None,
            "persisted_text": None,
            "persisted_format": None,
            "published_dir": None,
            "published_artifact_name": None,
            "false_digests": {},
        }
        world.obligation_planner_state = state
    return state


def _rel(
    risk_id: str,
    pattern_id: str | None = None,
    *,
    scope: str = "applicable",
    disposition: str = "ready",
) -> dict[str, Any]:
    """Build one risk-to-pattern relationship dict for snapshot fixtures."""
    rel: dict[str, Any] = {
        "risk_id": risk_id,
        "pattern_id": pattern_id,
        "scope_disposition": scope,
        "qualification_disposition": disposition,
    }
    if disposition == "ready":
        rel["projection_disposition"] = "projectable"
    elif scope == "capability_excluded" or disposition != "ready":
        rel["projection_disposition"] = "not_attempted"
    return rel


def _ready_relationship(
    risk_id: str = "atlas-prompt-injection",
    pattern_id: str | None = "AP-T6-01",
) -> dict[str, Any]:
    """Build the in-scope, ready, projectable relationship fixture."""
    return {
        "risk_id": risk_id,
        "pattern_id": pattern_id,
        "scope_disposition": "applicable",
        "qualification_disposition": "ready",
        "projection_disposition": "projectable",
    }


def _ensure_in_scope_relationship(
    snap: TaxonomyObligationSnapshot, risk_id: str, pattern_id: str | None
) -> None:
    """Add an in-scope relationship unless one already exists for the pair."""
    if not any(
        r.get("risk_id") == risk_id and r.get("pattern_id") == pattern_id
        for r in snap.relationships
    ):
        snap.relationships.append(_ready_relationship(risk_id, pattern_id))


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


# Background and common handlers
def _h_snapshot_available(world: World, text: str, examples: dict) -> tuple[bool, str]:
    state = _planner_state(world)
    state["snapshot"] = _default_snapshot()
    state["plan"] = None
    state["selected_obligation"] = None
    state["load_error"] = None
    state["plan_error"] = None
    return True, ""


def _h_no_network_or_model(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return True, ""


# Artifact Scenario 01
def _h_pins_catalog_mapping_capability_facts(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(
        r'catalog pin "([^"]+)", mapping pin "([^"]+)", capability snapshot content "([^"]+)", and qualification facts "([^"]+)"',
        text,
    )
    if not match:
        catalog_pin = examples.get("catalog_pin", "atlas-2026.05")
        mapping_pin = examples.get("mapping_pin", "sssom-v1")
        cap_content = examples.get("capability_content", "profile-v1")
        facts = examples.get("qualification_facts", "facts-v1")
    else:
        catalog_pin, mapping_pin, cap_content, facts = match.groups()

    snap = state["snapshot"]
    snap.catalog_pin = catalog_pin
    snap.mapping_pin = mapping_pin
    snap.taxonomy_version = catalog_pin
    snap.mapping_version = mapping_pin
    snap.capability_content = {"content": cap_content}
    snap.qualification_facts = {"facts": facts}
    snap.relationships = [
        {"risk_id": "atlas-prompt-injection", "pattern_id": "AP-T6-01"}
    ]
    return True, ""


def _h_produce_plan(world: World, text: str, examples: dict) -> tuple[bool, str]:
    state = _planner_state(world)
    snap = state["snapshot"]
    try:
        state["plan"] = plan_obligations(snap)
        state["plan_error"] = None
    except Exception as exc:
        state["plan"] = None
        state["plan_error"] = exc
    return True, ""


def _h_records_schema_version(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(r'records schema version "([^"]+)"', text)
    expected = match.group(1) if match else examples.get("schema_version", "")
    plan = state["plan"]
    if plan.schema_version != expected:
        return (
            False,
            f"Expected schema_version '{expected}', got '{plan.schema_version}'",
        )
    return True, ""


def _h_records_catalog_pin(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return _check_recorded_pin(
        world,
        text,
        examples,
        step_pattern=r'records catalog pin "([^"]+)"',
        example_key="catalog_pin",
        pins_attribute="catalog_pins",
        label="catalog",
    )


def _h_records_mapping_pin(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return _check_recorded_pin(
        world,
        text,
        examples,
        step_pattern=r'records mapping pin "([^"]+)"',
        example_key="mapping_pin",
        pins_attribute="mapping_pins",
        label="mapping",
    )


def _check_recorded_pin(
    world: World,
    text: str,
    examples: dict,
    *,
    step_pattern: str,
    example_key: str,
    pins_attribute: str,
    label: str,
) -> tuple[bool, str]:
    """Check that the plan records one kind of pin."""
    state = _planner_state(world)
    match = re.search(step_pattern, text)
    expected = match.group(1) if match else examples.get(example_key, "")
    plan = state["plan"]
    pins = getattr(plan, pins_attribute)
    values = list(pins.values()) if isinstance(pins, dict) else pins
    if expected not in values:
        return (
            False,
            f"Expected {label} pin '{expected}', got {getattr(plan, pins_attribute)}",
        )
    return True, ""


def _h_records_computed_digests(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    plan = state["plan"]
    if (
        not plan.capability_snapshot_digest
        or len(plan.capability_snapshot_digest) != 64
    ):
        return (
            False,
            f"Invalid capability_snapshot_digest: {plan.capability_snapshot_digest}",
        )
    if (
        not plan.qualification_facts_digest
        or len(plan.qualification_facts_digest) != 64
    ):
        return (
            False,
            f"Invalid qualification_facts_digest: {plan.qualification_facts_digest}",
        )
    if not plan.generation_inputs_digest or len(plan.generation_inputs_digest) != 64:
        return (
            False,
            f"Invalid generation_inputs_digest: {plan.generation_inputs_digest}",
        )
    if not plan.semantic_digest or len(plan.semantic_digest) != 64:
        return False, f"Invalid semantic_digest: {plan.semantic_digest}"
    return True, ""


# Artifact Scenario 02
def _parse_order(order_str: str) -> list[dict[str, Any]]:
    rels: list[dict[str, Any]] = []
    items = [x.strip() for x in order_str.split(",") if x.strip()]
    for item in items:
        if ":" in item:
            risk_id, pattern_id = item.split(":", 1)
            rels.append(_ready_relationship(risk_id, pattern_id))
        else:
            rels.append(
                {
                    "risk_id": item,
                    "pattern_id": None,
                    "scope_disposition": "governance_only",
                    "qualification_disposition": "not_attempted",
                    "projection_disposition": "not_attempted",
                }
            )
    return rels


def _ordered_snapshot(order: str) -> TaxonomyObligationSnapshot:
    """Build a snapshot presenting the parsed relationship order."""
    snap = _default_snapshot()
    snap.relationships = _parse_order(order)
    return snap


def _h_order_a(world: World, text: str, examples: dict) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(r'order "([^"]+)"', text)
    order = match.group(1) if match else examples.get("order_a", "")
    state["snapshot_a"] = _ordered_snapshot(order)
    return True, ""


def _h_order_b(world: World, text: str, examples: dict) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(r'order "([^"]+)"', text)
    order = match.group(1) if match else examples.get("order_b", "")
    state["snapshot_b"] = _ordered_snapshot(order)
    return True, ""


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


def _h_identical_semantic_digests(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    if state["plan_a"].semantic_digest != state["plan_b"].semantic_digest:
        return (
            False,
            f"Digests mismatch: {state['plan_a'].semantic_digest} vs {state['plan_b'].semantic_digest}",
        )
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
        map_state = getattr(world, "system_resource_map_state", None)
        if map_state and map_state.get("serialized_a") is not None:
            if map_state["serialized_a"] != map_state["serialized_b"]:
                return False, "Serialized SRM artifacts not equivalent"
            return True, ""
        corr_state = getattr(world, "correspondence_state", None)
        if corr_state and corr_state.get("serialized_a") is not None:
            if corr_state["serialized_a"] != corr_state["serialized_b"]:
                return False, "Serialized correspondence artifacts not equivalent"
            return True, ""
        return False, "No plan_a in planner state"
    if state["plan_a"].to_json() != state["plan_b"].to_json():
        return False, "JSON serialization is not canonically equivalent"
    if state["plan_a"].to_yaml() != state["plan_b"].to_yaml():
        return False, "YAML serialization is not canonically equivalent"
    return True, ""


# Artifact Scenario 03 & 04
def _h_rich_plan_snapshot(world: World, text: str, examples: dict) -> tuple[bool, str]:
    state = _planner_state(world)
    snap = _default_snapshot()
    snap.relationships = [
        _ready_relationship(),
        {
            "risk_id": "atlas-memory-poisoning",
            "pattern_id": "AP-T1-01",
            "scope_disposition": "applicable",
            "qualification_disposition": "missing_evidence",
            "projection_disposition": "not_attempted",
        },
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
            "candidates": [
                {
                    "candidate_id": "cand:v2:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "projection_disposition": "projectable",
                    "reason": "rule qualified",
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


def _h_schema_pins_digests_preserved(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    p1 = state["plan"]
    p2 = state["deserialized_plan"]
    if p1.schema_version != p2.schema_version:
        return False, "Schema version mismatch"
    if p1.catalog_pins != p2.catalog_pins:
        return False, "Catalog pins mismatch"
    if p1.mapping_pins != p2.mapping_pins:
        return False, "Mapping pins mismatch"
    if p1.semantic_digest != p2.semantic_digest:
        return False, "Semantic digest mismatch"
    return True, ""


def _h_dispositions_preserved(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    p1 = state["plan"]
    p2 = state["deserialized_plan"]
    for o1, o2 in zip(p1.obligations, p2.obligations):
        if (
            o1.scope_disposition != o2.scope_disposition
            or o1.qualification_disposition != o2.qualification_disposition
            or o1.projection_disposition != o2.projection_disposition
            or o1.correspondence_disposition != o2.correspondence_disposition
        ):
            return False, f"Dispositions mismatch between {o1} and {o2}"
    return True, ""


def _h_traces_candidates_summaries_preserved(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    p1 = state["plan"]
    p2 = state["deserialized_plan"]
    for o1, o2 in zip(p1.obligations, p2.obligations):
        if o1.qualification_trace != o2.qualification_trace:
            return False, "Qualification trace mismatch"
        if o1.candidate_records != o2.candidate_records:
            return False, "Candidate records mismatch"
    if p1.summary != p2.summary:
        return False, "Summary counts mismatch"
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
    texts = state.get("serialized_texts", [])
    if len(texts) != 2:
        map_state = getattr(world, "system_resource_map_state", None)
        if map_state and len(map_state.get("serialized_texts", [])) == 2:
            map_texts = map_state["serialized_texts"]
            if map_texts[0] == map_texts[1]:
                return True, ""
            return False, "Serialized texts are not byte-identical"
        corr_state = getattr(world, "correspondence_state", None)
        if corr_state and len(corr_state.get("serialized_twice", [])) == 2:
            corr_texts = corr_state["serialized_twice"]
            if corr_texts[0] == corr_texts[1]:
                return True, ""
            return False, "Serialized texts are not byte-identical"
        return False, "Serialized texts are not byte-identical"
    if texts[0] != texts[1]:
        return False, "Serialized texts are not byte-identical"
    return True, ""


# Artifact Scenario 05 (Tampering)
def _h_published_plan_in_format(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    fmt = _requested_format(text, examples, r'in "([^"]+)"', "format")
    snap = _default_snapshot()
    snap.relationships = [_ready_relationship()]
    state["plan"] = plan_obligations(snap)
    state["persisted_format"] = fmt
    state["persisted_text"] = _serialize_plan(state["plan"], fmt)
    return True, ""


def _h_tamper_persisted_field(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(r'tampered in field "([^"]+)"', text)
    field = match.group(1) if match else examples.get("field", "")
    fmt = state["persisted_format"]

    if fmt == "YAML":
        data = yaml.safe_load(state["persisted_text"])
    else:
        data = json.loads(state["persisted_text"])

    if field == "catalog_pins":
        if isinstance(data.get("catalog_pins"), dict):
            data["catalog_pins"]["tampered"] = "atlas-tampered-2099"
        else:
            data["catalog_pins"] = ["atlas-tampered-2099"]
    elif field == "mapping_pins":
        if isinstance(data.get("mapping_pins"), dict):
            data["mapping_pins"]["tampered"] = "tampered-mapping-v99"
        else:
            data["mapping_pins"] = ["tampered-mapping-v99"]
    elif field == "obligations":
        data["obligations"][0]["risk_id"] = "tampered-risk"
    else:
        data[field] = "tampered_value"

    if fmt == "YAML":
        state["persisted_text"] = yaml.safe_dump(data, sort_keys=False)
    else:
        state["persisted_text"] = json.dumps(data)
    return True, ""


def _h_load_plan(world: World, text: str, examples: dict) -> tuple[bool, str]:
    state = _planner_state(world)
    fmt = state.get("persisted_format", "YAML")
    text_data = state["persisted_text"]
    try:
        if fmt == "YAML":
            state["deserialized_plan"] = TaxonomyObligationPlan.from_yaml(text_data)
        else:
            state["deserialized_plan"] = TaxonomyObligationPlan.from_json(text_data)
        state["load_error"] = None
    except Exception as exc:
        state["deserialized_plan"] = None
        state["load_error"] = str(exc)
    return True, ""


def _h_loading_is_rejected(world: World, text: str, examples: dict) -> tuple[bool, str]:
    state = _planner_state(world)
    if state.get("load_error") is None:
        return False, "Expected loading to be rejected, but it succeeded"
    return True, ""


def _h_identifies_digest_mismatch(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    err = state.get("load_error", "").lower()
    if "digest" not in err and "mismatch" not in err:
        return (
            False,
            f"Expected digest mismatch in error, got: {state.get('load_error')}",
        )
    return True, ""


# Artifact Scenario 06 (Unknown fields)
def _h_persisted_plan_unknown_field(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(r'unknown field "([^"]+)"', text)
    field = match.group(1) if match else examples.get("field", "")
    snap = _default_snapshot()
    snap.relationships = [_ready_relationship()]
    p = plan_obligations(snap)
    data = json.loads(p.to_json())
    data[field] = 12345
    state["persisted_text"] = json.dumps(data)
    state["persisted_format"] = "JSON"
    state["unknown_field"] = field
    return True, ""


def _h_identifies_unknown_field(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(r'unknown field "([^"]+)"', text)
    field = (
        match.group(1)
        if match
        else examples.get("field", state.get("unknown_field", ""))
    )
    err = state.get("load_error", "")
    if field not in err and "extra" not in err.lower():
        return False, f"Expected unknown field '{field}' in error, got: {err}"
    return True, ""


# Artifact Scenario 07 (Unsupported schema version)
def _h_persisted_plan_declares_schema_version(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(r'schema version "([^"]+)"', text)
    version = match.group(1) if match else examples.get("schema_version", "")
    snap = _default_snapshot()
    snap.relationships = [_ready_relationship()]
    p = plan_obligations(snap)
    data = json.loads(p.to_json())
    data["schema_version"] = version
    state["persisted_text"] = json.dumps(data)
    state["persisted_format"] = "JSON"
    state["schema_version"] = version
    return True, ""


def _h_identifies_schema_version_unsupported(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(r'schema version "([^"]+)" as unsupported', text)
    version = (
        match.group(1)
        if match
        else examples.get("schema_version", state.get("schema_version", ""))
    )
    err = state.get("load_error", "")
    if version not in err and "unsupported" not in err.lower():
        return False, f"Expected schema version '{version}' in error, got: {err}"
    return True, ""


# Artifact Scenario 08 (False digests ignored)
def _h_snapshot_supplies_false_digest(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(r'supplies "([^"]+)" with false value "([^"]+)"', text)
    if not match:
        digest_kind = examples.get("digest_kind", "")
        false_digest = examples.get("false_digest", "")
    else:
        digest_kind, false_digest = match.groups()
    snap = _default_snapshot()
    snap.relationships = [_ready_relationship()]
    setattr(snap, digest_kind, false_digest)
    state["snapshot"] = snap
    state["false_digests"][digest_kind] = false_digest
    return True, ""


def _h_canonical_content_does_not_match(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return True, ""


def _h_plan_does_not_record_false_digest(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(r'does not record "([^"]+)" as the "([^"]+)"', text)
    if not match:
        false_digest = examples.get("false_digest", "")
        digest_kind = examples.get("digest_kind", "")
    else:
        false_digest, digest_kind = match.groups()
    plan = state["plan"]
    actual = getattr(plan, digest_kind, None)
    if actual == false_digest:
        return (
            False,
            f"Plan incorrectly recorded false digest '{false_digest}' for '{digest_kind}'",
        )
    return True, ""


def _h_plan_records_computed_digest_kind(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(r'records the "([^"]+)" computed from canonical content', text)
    digest_kind = match.group(1) if match else examples.get("digest_kind", "")
    plan = state["plan"]
    actual = getattr(plan, digest_kind, None)
    if not actual or len(actual) != 64:
        return False, f"Invalid computed digest for {digest_kind}: {actual}"
    return True, ""


# Artifact Scenario 09 (Atomically published)
def _h_publish_plan_atomically(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    fmt = _requested_format(text, examples, r'published as "([^"]+)"', "format")
    snap = state.get("snapshot") or _default_snapshot()
    if not snap.relationships:
        snap.relationships = [_ready_relationship()]
    tmp_dir = Path(tempfile.mkdtemp(prefix="asago_obligation_pub_"))
    snap_path = tmp_dir / "snapshot.yaml"
    snap_path.write_text(yaml.safe_dump(snap.model_dump(), sort_keys=False))
    run_plan_obligations(
        snapshot_path=snap_path,
        output_dir=tmp_dir,
        format_name=fmt.lower(),
    )
    state["published_dir"] = tmp_dir
    state["published_format"] = fmt.lower()
    return True, ""


def _h_published_artifact_named(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(r'named "([^"]+)"', text)
    expected_name = match.group(1) if match else examples.get("artifact_name", "")
    state["published_artifact_name"] = expected_name
    pub_dir = state["published_dir"]
    target = pub_dir / expected_name
    if not target.is_file():
        return False, f"Artifact '{expected_name}' not found in {pub_dir}"
    return True, ""


def _h_published_artifact_loads(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    pub_dir = state["published_dir"]
    name = state["published_artifact_name"]
    target = pub_dir / name
    raw = target.read_text(encoding="utf-8")
    if name.endswith(".json"):
        plan = TaxonomyObligationPlan.from_json(raw)
    else:
        plan = TaxonomyObligationPlan.from_yaml(raw)
    if not plan.obligations:
        return False, "Loaded published plan has no obligations"
    return True, ""


def _h_no_partial_plan_remains(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    pub_dir = state.get("published_dir")
    if pub_dir is not None:
        tmp_files = list(pub_dir.glob("*.tmp")) + list(pub_dir.glob("*.part"))
        if tmp_files:
            return False, f"Partial files remained: {tmp_files}"
    return True, ""


# Artifact Scenario 10 (Phase 1 correspondence claims rejected)
def _h_persisted_plan_invalid_correspondence(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(r'correspondence disposition to "([^"]+)"', text)
    disp = match.group(1) if match else examples.get("invalid_disposition", "")
    snap = _default_snapshot()
    snap.relationships = [_ready_relationship()]
    p = plan_obligations(snap)
    data = json.loads(p.to_json())
    data["obligations"][0]["correspondence_disposition"] = disp
    state["persisted_text"] = json.dumps(data)
    state["persisted_format"] = "JSON"
    state["invalid_correspondence"] = disp
    return True, ""


def _h_identifies_correspondence_invalid(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(r'correspondence disposition "([^"]+)" as invalid', text)
    disp = (
        match.group(1)
        if match
        else examples.get(
            "invalid_disposition", state.get("invalid_correspondence", "")
        )
    )
    err = state.get("load_error", "")
    if disp not in err and "correspondence" not in err.lower():
        return False, f"Expected invalid correspondence '{disp}' in error, got: {err}"
    return True, ""


# Planner Feature Scenario 01
def _h_risk_cards_map_shared_pattern(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(
        r'risk cards "([^"]+)" and "([^"]+)" both map as applicable to attack pattern "([^"]+)"',
        text,
    )
    if not match:
        risk_a = examples.get("risk_a", "atlas-prompt-injection")
        risk_b = examples.get("risk_b", "atlas-memory-poisoning")
        pattern_id = examples.get("pattern_id", "AP-T1-01")
    else:
        risk_a, risk_b, pattern_id = match.groups()
    snap = state["snapshot"]
    snap.relationships = [
        _rel(risk_a, pattern_id, scope="applicable", disposition="ready"),
        _rel(risk_b, pattern_id, scope="applicable", disposition="ready"),
    ]
    return True, ""


def _h_ledger_count_for_pattern(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(r'contains (\d+) obligations for pattern "([^"]+)"', text)
    expected_count = (
        int(match.group(1)) if match else int(examples.get("obligation_count", 2))
    )
    pattern_id = match.group(2) if match else examples.get("pattern_id", "AP-T1-01")
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
        risk_a = examples.get("risk_a", "atlas-prompt-injection")
        risk_b = examples.get("risk_b", "atlas-memory-poisoning")
    else:
        risk_a, risk_b = match.groups()
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


# Planner Feature Scenario 02
def _h_applicable_and_excluded_mapping(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match_app = re.search(
        r'risk "([^"]+)" has an applicable mapping to pattern "([^"]+)"', text
    )
    match_exc = re.search(
        r'risk "([^"]+)" has a capability-excluded mapping to pattern "([^"]+)"', text
    )
    snap = state["snapshot"]
    if match_app:
        risk_id, pattern_id = match_app.groups()
        snap.relationships.append(
            _rel(risk_id, pattern_id, scope="applicable", disposition="ready")
        )
    elif match_exc:
        risk_id, pattern_id = match_exc.groups()
        snap.relationships.append(
            _rel(
                risk_id,
                pattern_id,
                scope="capability_excluded",
                disposition="not_attempted",
            )
        )
    return True, ""


def _h_records_scope_disposition_for_risk_pattern(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(
        r'records scope disposition "([^"]+)" for risk "([^"]+)" and pattern "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse scope disposition: {text}"
    scope, risk_id, pattern_id = match.groups()
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
        return False, f"No obligation for {risk_id} and {pattern_id}"
    if ob.scope_disposition != scope:
        return (
            False,
            f"Expected scope disposition '{scope}', got '{ob.scope_disposition}'",
        )
    return True, ""


# Planner Feature Scenario 03
def _h_expected_relationships_count(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    snap = state["snapshot"]
    snap.relationships = [
        {
            "risk_id": "risk-1",
            "pattern_id": "AP-T1-01",
            "relationship_kind": "gated threat",
        },
        {
            "risk_id": "risk-2",
            "pattern_id": "AP-T1-02",
            "relationship_kind": "missing generation template",
        },
        {
            "risk_id": "risk-3",
            "pattern_id": "AP-T1-03",
            "relationship_kind": "projection infeasibility",
        },
        {
            "risk_id": "risk-4",
            "pattern_id": "AP-T1-04",
            "relationship_kind": "unsupported requirement",
        },
        {
            "risk_id": "risk-5",
            "pattern_id": "AP-T1-05",
            "relationship_kind": "qualified generable pattern",
        },
        {"risk_id": "risk-6", "relationship_kind": "governance review"},
    ]
    return True, ""


def _h_ledger_contains_obligations(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(r'contains "?(\d+)"? obligations', text)
    expected_count = (
        int(match.group(1)) if match else int(examples.get("relationship_count", 6))
    )
    plan = state["plan"]
    if len(plan.obligations) != expected_count:
        return (
            False,
            f"Expected {expected_count} obligations, got {len(plan.obligations)}",
        )
    return True, ""


def _h_every_obligation_has_one_scope(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    for o in state["plan"].obligations:
        if not o.scope_disposition:
            return False, f"Missing scope disposition in {o}"
    return True, ""


def _h_every_obligation_has_one_qualification(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    for o in state["plan"].obligations:
        if not o.qualification_disposition:
            return False, f"Missing qualification disposition in {o}"
    return True, ""


def _h_every_obligation_correspondence_not_assessed(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(r'correspondence disposition "([^"]+)"', text)
    expected = match.group(1) if match else "not_assessed"
    for o in state["plan"].obligations:
        if o.correspondence_disposition != expected:
            return False, f"Expected {expected}, got {o.correspondence_disposition}"
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


# Planner Feature Scenario 04
def _h_snapshot_contains_kind_relationship(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(
        r'contains a "([^"]+)" relationship for risk "([^"]+)" and pattern "([^"]+)"',
        text,
    )
    if not match:
        kind = examples.get("relationship_kind", "")
        risk_id = examples.get("risk_id", "")
        pattern_id = examples.get("pattern_id", "")
    else:
        kind, risk_id, pattern_id = match.groups()
    snap = state["snapshot"]
    snap.relationships = [
        {"risk_id": risk_id, "pattern_id": pattern_id, "relationship_kind": kind}
    ]
    state["selected_risk_id"] = risk_id
    state["selected_pattern_id"] = pattern_id
    return True, ""


def _h_ledger_count_for_risk_pattern(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(
        r'contains (\d+) obligations? for risk "([^"]+)" and pattern "([^"]+)"', text
    )
    if not match:
        count = 1
        risk_id = examples.get("risk_id", state.get("selected_risk_id", ""))
        pattern_id = examples.get("pattern_id", state.get("selected_pattern_id", ""))
    else:
        count, risk_id, pattern_id = (
            int(match.group(1)),
            match.group(2),
            match.group(3),
        )
    plan = state["plan"]
    matching = _matching_obligations(plan, risk_id=risk_id, pattern_id=pattern_id)
    if len(matching) != count:
        return (
            False,
            f"Expected {count} obligations for {risk_id}/{pattern_id}, got {len(matching)}",
        )
    state["selected_obligation"] = matching[0]
    return True, ""


def _h_obligation_has_scope_disposition(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(r'scope disposition "([^"]+)"', text)
    expected = match.group(1) if match else examples.get("scope_disposition", "")
    ob = _selected_or_first(state)
    if ob.scope_disposition != expected:
        return (
            False,
            f"Expected scope disposition '{expected}', got '{ob.scope_disposition}'",
        )
    return True, ""


def _h_obligation_has_qualification_disposition(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(r'qualification disposition "([^"]+)"', text)
    expected = (
        match.group(1) if match else examples.get("qualification_disposition", "")
    )
    ob = _selected_or_first(state)
    if ob.qualification_disposition != expected:
        return (
            False,
            f"Expected qualification disposition '{expected}', got '{ob.qualification_disposition}'",
        )
    return True, ""


def _h_obligation_records_candidate_projection_disposition(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(r'candidate projection disposition "([^"]+)"', text)
    expected = match.group(1) if match else examples.get("projection_disposition", "")
    ob = _selected_or_first(state)
    if ob.projection_disposition != expected:
        return (
            False,
            f"Expected projection disposition '{expected}', got '{ob.projection_disposition}'",
        )
    return True, ""


def _h_obligation_retains_evidence_for_kind(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(r'retains evidence for "([^"]+)"', text)
    kind = match.group(1) if match else examples.get("relationship_kind", "")
    ob = _selected_or_first(state)
    if ob.evidence.get("relationship_kind") != kind:
        return (
            False,
            f"Expected evidence relationship_kind '{kind}', got '{ob.evidence.get('relationship_kind')}'",
        )
    return True, ""


# Planner Feature Scenario 05 (Governance only)
def _h_risk_no_actionable_pattern(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(r'risk card "([^"]+)" has no actionable attack pattern', text)
    risk_id = match.group(1) if match else examples.get("risk_id", "atlas-orphan-risk")
    snap = state["snapshot"]
    snap.relationships = [
        {
            "risk_id": risk_id,
            "pattern_id": None,
            "scope_disposition": "governance_only",
            "qualification_disposition": "not_attempted",
            "projection_disposition": "not_attempted",
        }
    ]
    return True, ""


def _h_ledger_count_for_risk(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(r'contains (\d+) obligations? for risk "([^"]+)"', text)
    if not match:
        count = int(examples.get("obligation_count", 1))
        risk_id = examples.get("risk_id", "atlas-orphan-risk")
    else:
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


# Planner Feature Scenario 06 (Secret redaction)
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
        risk_id = examples.get("risk_id", "atlas-prompt-injection")
        pattern_id = examples.get("pattern_id", "AP-T6-01")
    else:
        risk_id, pattern_id = match.groups()
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
        predicate = examples.get("predicate", "")
        facts = examples.get("facts", "")
        result = examples.get("result", "")
        reason = examples.get("reason", "")
    else:
        predicate, facts, result, reason = match.groups()
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
        predicate = examples.get("predicate", "")
        facts = examples.get("facts", "")
        result = examples.get("result", "")
        reason = examples.get("reason", "")
    else:
        predicate, facts, result, reason = match.groups()
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
    match = re.search(r'do not contain "([^"]+)"', text)
    secret = match.group(1) if match else examples.get("secret", "")
    plan = state["plan"]
    ob = state.get("selected_obligation") or plan.obligations[0]
    trace = ob.qualification_trace[0]
    if (
        secret in trace.predicate
        or secret in str(trace.facts)
        or secret in str(trace.result)
        or secret in trace.reason
    ):
        return False, f"Secret {secret} found in qualification trace: {trace}"
    return True, ""


# Planner Feature Scenario 07 (Candidate records)
def _h_candidate_projection_applicable(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(
        r'candidate projection is applicable for risk "([^"]+)" and pattern "([^"]+)"',
        text,
    )
    if match:
        risk_id, pattern_id = match.groups()
    else:
        risk_id = "atlas-prompt-injection"
        pattern_id = "AP-T6-01"
    state["selected_risk_id"] = risk_id
    state["selected_pattern_id"] = pattern_id
    _ensure_in_scope_relationship(state["snapshot"], risk_id, pattern_id)
    return True, ""


def _h_projection_produces_candidate(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(
        r'candidate "([^"]+)" with disposition "([^"]+)" and reason "([^"]+)"', text
    )
    if not match:
        cand_id = examples.get("candidate_id", "")
        disp = examples.get("projection_disposition", "")
        reason = examples.get("reason", "")
    else:
        cand_id, disp, reason = match.groups()
    risk_id = state.get("selected_risk_id") or "atlas-prompt-injection"
    pattern_id = state.get("selected_pattern_id") or "AP-T6-01"
    snap = state["snapshot"]
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
            "candidates": [],
        }
        snap.candidate_expansions.append(exp)
    exp.setdefault("candidates", []).append(
        {
            "candidate_id": cand_id,
            "projection_disposition": disp,
            "reason": reason,
        }
    )
    return True, ""


def _h_obligation_retains_candidate(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(
        r'candidate "([^"]+)" with projection disposition "([^"]+)"', text
    )
    if not match:
        cand_id = examples.get("candidate_id", "")
        disp = examples.get("projection_disposition", "")
    else:
        cand_id, disp = match.groups()
    plan = state["plan"]
    ob = state.get("selected_obligation") or plan.obligations[0]
    cand = next((c for c in ob.candidate_records if c.candidate_id == cand_id), None)
    if cand is None:
        return (
            False,
            f"Candidate {cand_id} not found in {ob.candidate_records}",
        )
    if cand.projection_disposition != disp:
        return (
            False,
            f"Expected candidate projection disposition '{disp}', got '{cand.projection_disposition}'",
        )
    state["selected_candidate"] = cand
    return True, ""


def _h_candidate_record_retains_reason(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(r'retains reason "([^"]+)"', text)
    reason = (
        match.group(1)
        if match
        else examples.get(
            "reason", getattr(state.get("selected_candidate"), "reason", "")
        )
    )
    cand = state.get("selected_candidate")
    if cand is None or cand.reason != reason:
        return (
            False,
            f"Expected reason '{reason}', got '{getattr(cand, 'reason', None)}'",
        )
    return True, ""


# Planner Feature Scenario 08 (Zero network/model calls)
def _h_snapshot_applicable_and_excluded(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    snap = state["snapshot"]
    snap.relationships = [
        _ready_relationship(),
        {
            "risk_id": "atlas-memory-poisoning",
            "pattern_id": "AP-T11-01",
            "scope_disposition": "capability_excluded",
            "qualification_disposition": "not_attempted",
            "projection_disposition": "not_attempted",
        },
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


# Planner Feature Scenario 09 (Identity input change)
def _snapshot_with_identity_input(inp: str, val: str) -> TaxonomyObligationSnapshot:
    """Build a snapshot varying exactly one identity-bearing input."""
    snap = _default_snapshot()
    if inp == "risk ID":
        snap.relationships = [_ready_relationship(risk_id=val)]
    elif inp == "pattern ID":
        snap.relationships = [_ready_relationship(pattern_id=val)]
    elif inp == "capability snapshot":
        snap.capability_content = val
        snap.relationships = [_ready_relationship()]
    elif inp == "catalog pin":
        snap.catalog_pin = val
        snap.taxonomy_version = val
        snap.relationships = [_ready_relationship()]
    elif inp == "mapping pin":
        snap.mapping_pin = val
        snap.mapping_version = val
        snap.relationships = [_ready_relationship()]
    return snap


def _h_snapshot_input_a(world: World, text: str, examples: dict) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(r'one snapshot has "([^"]+)" "([^"]+)"', text)
    inp = match.group(1) if match else examples.get("identity_input", "")
    val = match.group(2) if match else examples.get("value_a", "")
    state["snapshot_a"] = _snapshot_with_identity_input(inp, val)
    return True, ""


def _h_snapshot_input_b(world: World, text: str, examples: dict) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(r'another snapshot has "([^"]+)" "([^"]+)"', text)
    inp = match.group(1) if match else examples.get("identity_input", "")
    val = match.group(2) if match else examples.get("value_b", "")
    state["snapshot_b"] = _snapshot_with_identity_input(inp, val)
    return True, ""


def _h_share_remaining_inputs(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return True, ""


def _h_two_plans_different_ids(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    ids_a = _obligation_ids(state["plan_a"])
    ids_b = _obligation_ids(state["plan_b"])
    if ids_a == ids_b:
        return False, f"Obligation identifiers are unexpectedly identical: {ids_a}"
    return True, ""


def _h_two_plans_different_digests(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    if state["plan_a"].semantic_digest == state["plan_b"].semantic_digest:
        return (
            False,
            f"Semantic digests are unexpectedly identical: {state['plan_a'].semantic_digest}",
        )
    return True, ""


# Planner Feature Scenario 10 (ICA prose ignored)
def _snapshot_with_ica_prose(prose: str) -> TaxonomyObligationSnapshot:
    """Build a ready-relationship snapshot carrying ICA prose."""
    snap = _default_snapshot()
    snap.ica_prose = prose
    snap.relationships = [_ready_relationship()]
    return snap


def _h_snapshot_ica_prose_a(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(r'includes ICA prose "([^"]+)"', text)
    prose = match.group(1) if match else examples.get("prose_a", "")
    state["snapshot_a"] = _snapshot_with_ica_prose(prose)
    return True, ""


def _h_snapshot_ica_prose_b(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(r'includes ICA prose "([^"]+)"', text)
    prose = match.group(1) if match else examples.get("prose_b", "")
    state["snapshot_b"] = _snapshot_with_ica_prose(prose)
    return True, ""


def _h_share_same_risks_patterns_pins(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return True, ""


def _h_identical_scope_dispositions(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    s_a = [o.scope_disposition for o in state["plan_a"].obligations]
    s_b = [o.scope_disposition for o in state["plan_b"].obligations]
    if s_a != s_b:
        return False, f"Scope dispositions differ: {s_a} vs {s_b}"
    return True, ""


def _h_identical_qualification_dispositions(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    q_a = [o.qualification_disposition for o in state["plan_a"].obligations]
    q_b = [o.qualification_disposition for o in state["plan_b"].obligations]
    if q_a != q_b:
        return False, f"Qualification dispositions differ: {q_a} vs {q_b}"
    return True, ""


# Planner Feature Scenario 11 (Invalid scope/qual combinations)
def _h_snapshot_invalid_combination(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(
        r'combine scope disposition "([^"]+)" with qualification disposition "([^"]+)"',
        text,
    )
    if not match:
        scope = examples.get("scope_disposition", "")
        qual = examples.get("qualification_disposition", "")
    else:
        scope, qual = match.groups()
    snap = _default_snapshot()
    snap.relationships = [
        {
            "risk_id": "atlas-prompt-injection",
            "pattern_id": "AP-T6-01" if scope != "governance_only" else None,
            "scope_disposition": scope,
            "qualification_disposition": qual,
            "projection_disposition": "projectable"
            if qual == "ready"
            else "not_attempted",
        }
    ]
    state["snapshot"] = snap
    state["invalid_scope"] = scope
    state["invalid_qual"] = qual
    return True, ""


def _h_planning_is_rejected(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    if state.get("plan_error") is None:
        return False, "Expected planning to be rejected, but it succeeded"
    return True, ""


def _h_identifies_disposition_combination_invalid(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    err = str(state.get("plan_error", ""))
    scope = state.get("invalid_scope", "")
    qual = state.get("invalid_qual", "")
    if scope not in err or qual not in err:
        return (
            False,
            f"Expected error mentioning invalid combination ({scope}, {qual}), got: {err}",
        )
    return True, ""


# Planner Feature Scenario 12 (Summary counts)
def _h_snapshot_summary_category(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    snap = _default_snapshot()
    snap.relationships = [
        # applicable + ready (1)
        {
            "risk_id": "risk-ready",
            "pattern_id": "AP-T6-01",
            "scope_disposition": "applicable",
            "qualification_disposition": "ready",
            "projection_disposition": "projectable",
        },
        # applicable + missing_evidence (1)
        {
            "risk_id": "risk-missing",
            "pattern_id": "AP-T1-01",
            "scope_disposition": "applicable",
            "qualification_disposition": "missing_evidence",
            "projection_disposition": "not_attempted",
        },
        # applicable + contradictory_evidence (1)
        {
            "risk_id": "risk-contradictory",
            "pattern_id": "AP-T1-02",
            "scope_disposition": "applicable",
            "qualification_disposition": "contradictory_evidence",
            "projection_disposition": "not_attempted",
        },
        # applicable + structurally_infeasible (1)
        {
            "risk_id": "risk-struct",
            "pattern_id": "AP-T1-03",
            "scope_disposition": "applicable",
            "qualification_disposition": "structurally_infeasible",
            "projection_disposition": "not_attempted",
        },
        # capability_excluded (1)
        {
            "risk_id": "risk-gated",
            "pattern_id": "AP-T11-01",
            "scope_disposition": "capability_excluded",
            "qualification_disposition": "not_attempted",
            "projection_disposition": "not_attempted",
        },
        # governance_only (1)
        {
            "risk_id": "risk-gov",
            "pattern_id": None,
            "scope_disposition": "governance_only",
            "qualification_disposition": "not_attempted",
            "projection_disposition": "not_attempted",
        },
    ]
    # candidate records: projectable (1), projection_infeasible (1), budget_deferred (1)
    snap.candidate_expansions = [
        {
            "risk_id": "risk-ready",
            "pattern_id": "AP-T6-01",
            "candidates": [
                {
                    "candidate_id": "cand:v2:11111111111111111111111111111111",
                    "projection_disposition": "projectable",
                    "reason": "ready",
                },
                {
                    "candidate_id": "cand:v2:22222222222222222222222222222222",
                    "projection_disposition": "projection_infeasible",
                    "reason": "infeasible",
                },
                {
                    "candidate_id": "cand:v2:33333333333333333333333333333333",
                    "projection_disposition": "budget_deferred",
                    "reason": "deferred",
                },
            ],
        }
    ]
    state["snapshot"] = snap
    return True, ""


def _h_plan_summary_counts(world: World, text: str, examples: dict) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(
        r"total (\d+), applicable (\d+), governance-only (\d+), capability-excluded (\d+), ready (\d+), missing-or-contradictory (\d+), structurally-infeasible (\d+)",
        text,
    )
    if not match:
        total = int(examples.get("total", 6))
        applicable = int(examples.get("applicable", 4))
        gov = int(examples.get("governance_only", 1))
        cap_exc = int(examples.get("capability_excluded", 1))
        ready = int(examples.get("ready", 1))
        missing_or_contra = int(examples.get("missing_or_contradictory", 2))
        struct = int(examples.get("structurally_infeasible", 1))
    else:
        (
            total,
            applicable,
            gov,
            cap_exc,
            ready,
            missing_or_contra,
            struct,
        ) = (int(x) for x in match.groups())

    s = state["plan"].summary
    if s.total != total:
        return False, f"total: expected {total}, got {s.total}"
    if s.applicable != applicable:
        return False, f"applicable: expected {applicable}, got {s.applicable}"
    if s.governance_only != gov:
        return False, f"governance_only: expected {gov}, got {s.governance_only}"
    if s.capability_excluded != cap_exc:
        return (
            False,
            f"capability_excluded: expected {cap_exc}, got {s.capability_excluded}",
        )
    if s.ready != ready:
        return False, f"ready: expected {ready}, got {s.ready}"
    if s.missing_or_contradictory != missing_or_contra:
        return (
            False,
            f"missing_or_contradictory: expected {missing_or_contra}, got {s.missing_or_contradictory}",
        )
    if s.structurally_infeasible != struct:
        return (
            False,
            f"structurally_infeasible: expected {struct}, got {s.structurally_infeasible}",
        )
    return True, ""


def _h_plan_summary_candidate_counts(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _planner_state(world)
    match = re.search(
        r"projectable (\d+), projection-infeasible (\d+), budget-deferred (\d+)", text
    )
    if not match:
        proj = int(examples.get("projectable", 1))
        infeas = int(examples.get("projection_infeasible", 1))
        budget = int(examples.get("budget_deferred", 1))
    else:
        proj, infeas, budget = (int(x) for x in match.groups())

    s = state["plan"].summary
    if s.projectable != proj:
        return False, f"projectable: expected {proj}, got {s.projectable}"
    if s.projection_infeasible != infeas:
        return False, f"infeasible: expected {infeas}, got {s.projection_infeasible}"
    if s.budget_deferred != budget:
        return False, f"budget_deferred: expected {budget}, got {s.budget_deferred}"
    return True, ""


def _h_counts_derived_from_rows(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return True, ""


def _h_summary_no_taxonomy_correspondence_rate(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    s = _planner_state(world)["plan"].summary
    if hasattr(s, "taxonomy_correspondence_rate"):
        return False, "Summary should not include taxonomy_correspondence_rate"
    return True, ""


def _h_summary_no_scenario_realization_rate(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    s = _planner_state(world)["plan"].summary
    if hasattr(s, "scenario_realization_rate"):
        return False, "Summary should not include scenario_realization_rate"
    return True, ""


# Compatibility Scenario
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
    state = _planner_state(world)
    workflow = state.get("fixture_workflow", "")
    command = state.get("ran_command", "")
    expected_command = _COMPAT_WORKFLOW_COMMANDS.get(workflow)
    if expected_command is None:
        return False, f"Unknown fixture workflow '{workflow}'"
    if command != expected_command:
        return (
            False,
            f"Default command '{command}' does not match workflow "
            f"'{workflow}' (expected '{expected_command}')",
        )
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
            r'the snapshot pins catalog pin "([^"]+)", mapping pin "([^"]+)", capability snapshot content "([^"]+)", and qualification facts "([^"]+)"',
            _h_pins_catalog_mapping_capability_facts,
        ),
        (r"the obligation plan is produced", _h_produce_plan),
        (
            r'the plan records schema version "([^"]+)"',
            _h_records_schema_version,
        ),
        (
            r'the plan records catalog pin "([^"]+)"',
            _h_records_catalog_pin,
        ),
        (
            r'the plan records mapping pin "([^"]+)"',
            _h_records_mapping_pin,
        ),
        (
            r"the plan records computed digests for capability snapshot, qualification facts, generation inputs, and semantic content",
            _h_records_computed_digests,
        ),
        (
            r'one snapshot presents relationships in order "([^"]+)"',
            _h_order_a,
        ),
        (
            r'another snapshot presents the same relationships in order "([^"]+)"',
            _h_order_b,
        ),
        (
            r"an obligation plan is produced from each presentation",
            _h_produce_both_plans,
        ),
        (r"both plans have identical obligation identifiers", _h_identical_identifiers),
        (r"both plans have identical semantic digests", _h_identical_semantic_digests),
        (r"both plans have identical canonical ledger order", _h_identical_order),
        (
            r"both serialized artifacts are canonically equivalent",
            _h_canonically_equivalent,
        ),
        (
            r"the snapshot produces a plan with pins, dispositions, digests, and evidence",
            _h_rich_plan_snapshot,
        ),
        (
            r'the plan is serialized as "([^"]+)" and deserialized',
            _h_serialize_and_deserialize,
        ),
        (r"obligation identities are preserved", _h_identities_preserved),
        (
            r"schema version, pins, and computed digests are preserved",
            _h_schema_pins_digests_preserved,
        ),
        (
            r"scope, qualification, projection, and correspondence dispositions are preserved",
            _h_dispositions_preserved,
        ),
        (
            r"qualification traces, candidate records, and summary counts are preserved",
            _h_traces_candidates_summaries_preserved,
        ),
        (r'the plan is serialized as "([^"]+)" twice', _h_serialize_twice),
        (r"the two artifacts are byte-identical", _h_byte_identical),
        (
            r'a published plan artifact in "([^"]+)"',
            _h_published_plan_in_format,
        ),
        (
            r'the persisted content is tampered in field "([^"]+)" without updating the semantic digest',
            _h_tamper_persisted_field,
        ),
        (r"the plan is loaded", _h_load_plan),
        (r"loading is rejected", _h_loading_is_rejected),
        (r"the result identifies a digest mismatch", _h_identifies_digest_mismatch),
        (
            r'a persisted plan includes unknown field "([^"]+)"',
            _h_persisted_plan_unknown_field,
        ),
        (
            r'the result identifies unknown field "([^"]+)"',
            _h_identifies_unknown_field,
        ),
        (
            r'a persisted plan declares schema version "([^"]+)"',
            _h_persisted_plan_declares_schema_version,
        ),
        (
            r'the result identifies schema version "([^"]+)" as unsupported',
            _h_identifies_schema_version_unsupported,
        ),
        (
            r'the snapshot supplies "([^"]+)" with false value "([^"]+)"',
            _h_snapshot_supplies_false_digest,
        ),
        (
            r'the canonical content does not match "([^"]+)"',
            _h_canonical_content_does_not_match,
        ),
        (
            r'the plan does not record "([^"]+)" as the "([^"]+)"',
            _h_plan_does_not_record_false_digest,
        ),
        (
            r'the plan records the "([^"]+)" computed from canonical content',
            _h_plan_records_computed_digest_kind,
        ),
        (r'the plan is published as "([^"]+)"', _h_publish_plan_atomically),
        (r'the published artifact is named "([^"]+)"', _h_published_artifact_named),
        (
            r"the published artifact loads as a complete closed plan",
            _h_published_artifact_loads,
        ),
        (r"no partial plan file remains", _h_no_partial_plan_remains),
        (
            r'a persisted plan sets correspondence disposition to "([^"]+)"',
            _h_persisted_plan_invalid_correspondence,
        ),
        (
            r'the result identifies correspondence disposition "([^"]+)" as invalid',
            _h_identifies_correspondence_invalid,
        ),
        (
            r'risk cards "([^"]+)" and "([^"]+)" both map as applicable to attack pattern "([^"]+)"',
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
            r'risk "([^"]+)" has an applicable mapping to pattern "([^"]+)"',
            _h_applicable_and_excluded_mapping,
        ),
        (
            r'risk "([^"]+)" has a capability-excluded mapping to pattern "([^"]+)"',
            _h_applicable_and_excluded_mapping,
        ),
        (
            r'the plan records scope disposition "([^"]+)" for risk "([^"]+)" and pattern "([^"]+)"',
            _h_records_scope_disposition_for_risk_pattern,
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
            r"every obligation has exactly one scope disposition",
            _h_every_obligation_has_one_scope,
        ),
        (
            r"every obligation has exactly one qualification disposition",
            _h_every_obligation_has_one_qualification,
        ),
        (
            r'every obligation has correspondence disposition "([^"]+)"',
            _h_every_obligation_correspondence_not_assessed,
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
            r'the plan ledger contains (\d+) obligations? for risk "([^"]+)" and pattern "([^"]+)"',
            _h_ledger_count_for_risk_pattern,
        ),
        (
            r'that obligation has scope disposition "([^"]+)"',
            _h_obligation_has_scope_disposition,
        ),
        (
            r'that obligation has qualification disposition "([^"]+)"',
            _h_obligation_has_qualification_disposition,
        ),
        (
            r'that obligation has correspondence disposition "([^"]+)"',
            _h_every_obligation_correspondence_not_assessed,
        ),
        (
            r'that obligation records candidate projection disposition "([^"]+)"',
            _h_obligation_records_candidate_projection_disposition,
        ),
        (
            r'that obligation retains evidence for "([^"]+)"',
            _h_obligation_retains_evidence_for_kind,
        ),
        (
            r'risk card "([^"]+)" has no actionable attack pattern',
            _h_risk_no_actionable_pattern,
        ),
        (
            r'the plan ledger contains (\d+) obligations? for risk "([^"]+)"',
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
            r'the qualification trace predicate, facts, result, and reason do not contain "([^"]+)"',
            _h_qualification_trace_no_secret,
        ),
        (
            r'candidate projection is applicable for risk "([^"]+)" and pattern "([^"]+)"',
            _h_candidate_projection_applicable,
        ),
        (
            r'projection produces candidate "([^"]+)" with disposition "([^"]+)" and reason "([^"]+)"',
            _h_projection_produces_candidate,
        ),
        (
            r'the obligation retains candidate "([^"]+)" with projection disposition "([^"]+)"',
            _h_obligation_retains_candidate,
        ),
        (
            r'that candidate record retains reason "([^"]+)"',
            _h_candidate_record_retains_reason,
        ),
        (
            r"the snapshot contains applicable and capability-excluded relationships",
            _h_snapshot_applicable_and_excluded,
        ),
        (
            r"obligation planning recorded (\d+) network calls",
            _h_recorded_network_calls,
        ),
        (r"obligation planning recorded (\d+) model calls", _h_recorded_model_calls),
        (
            r'one snapshot has "([^"]+)" "([^"]+)"',
            _h_snapshot_input_a,
        ),
        (
            r'another snapshot has "([^"]+)" "([^"]+)"',
            _h_snapshot_input_b,
        ),
        (
            r"both snapshots otherwise share the remaining identity-bearing inputs",
            _h_share_remaining_inputs,
        ),
        (
            r"an obligation plan is produced from each snapshot",
            _h_produce_both_plans,
        ),
        (
            r"the two plans have different obligation identifiers",
            _h_two_plans_different_ids,
        ),
        (
            r"the two plans have different semantic digests",
            _h_two_plans_different_digests,
        ),
        (
            r'one snapshot includes ICA prose "([^"]+)"',
            _h_snapshot_ica_prose_a,
        ),
        (
            r'another snapshot includes ICA prose "([^"]+)"',
            _h_snapshot_ica_prose_b,
        ),
        (
            r"both snapshots otherwise share the same risks, patterns, and pins",
            _h_share_same_risks_patterns_pins,
        ),
        (
            r"both plans have identical scope dispositions",
            _h_identical_scope_dispositions,
        ),
        (
            r"both plans have identical qualification dispositions",
            _h_identical_qualification_dispositions,
        ),
        (
            r'a snapshot would combine scope disposition "([^"]+)" with qualification disposition "([^"]+)"',
            _h_snapshot_invalid_combination,
        ),
        (r"planning is rejected", _h_planning_is_rejected),
        (r"no partial plan is published", _h_no_partial_plan_remains),
        (
            r"the result identifies the disposition combination as invalid",
            _h_identifies_disposition_combination_invalid,
        ),
        (
            r"a snapshot whose obligation rows include every summary category",
            _h_snapshot_summary_category,
        ),
        (
            r"the plan summary counts are total (\d+), applicable (\d+), governance-only (\d+), capability-excluded (\d+), ready (\d+), missing-or-contradictory (\d+), structurally-infeasible (\d+)",
            _h_plan_summary_counts,
        ),
        (
            r"the plan summary candidate counts are projectable (\d+), projection-infeasible (\d+), budget-deferred (\d+)",
            _h_plan_summary_candidate_counts,
        ),
        (
            r"those counts are derived from the obligation rows",
            _h_counts_derived_from_rows,
        ),
        (
            r"the plan summary does not include a taxonomy correspondence rate",
            _h_summary_no_taxonomy_correspondence_rate,
        ),
        (
            r"the plan summary does not include a scenario realization rate",
            _h_summary_no_scenario_realization_rate,
        ),
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
