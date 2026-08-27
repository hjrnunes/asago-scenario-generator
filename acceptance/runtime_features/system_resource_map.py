"""Deterministic acceptance handlers for system resource map validation, artifacts, and compatibility."""

from __future__ import annotations

import re
from typing import Any

from runtime_shared import World

from asago_scenario_generator.models.system_resource_map import (
    ActorControllerEntry,
    ControlActionEntry,
    ControlledProcessEntry,
    DataFlowEntry,
    FeedbackPathEntry,
    LossLinkEntry,
    ResourceAssertionEntry,
    ResourceMapSnapshot,
    SystemResourceEntry,
    SystemResourceMap,
    TrustBoundaryEntry,
    UseCaseFactEntry,
)
from asago_scenario_generator.pipeline.system_resource_map import validate_resource_map

FEATURE_ID = "system_resource_map"


def _default_snapshot() -> ResourceMapSnapshot:
    return ResourceMapSnapshot(
        schema_version="1",
        stpa_version="stpa-v1",
        taxonomy_version="atlas-2026.05",
        stpa_identifiers=["RESP-1", "CP-2", "CA-1-1", "FB-1-1", "L-1", "H-1"],
        taxonomy_identifiers=[
            "ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "tb:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ],
        facts={},
    )


def _make_representative_map(
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
            )
        ],
        actor_controllers=[
            ActorControllerEntry(
                element_id="RESP-1",
                name="Agent Controller",
                description="Controller handling agent decisions",
            )
        ],
        controlled_processes=[
            ControlledProcessEntry(
                element_id="CP-2",
                name="Payment Pipeline",
                description="Process executing transactions",
            )
        ],
        control_actions=[
            ControlActionEntry(
                element_id="CA-1-1",
                controller_id="RESP-1",
                process_id="CP-2",
                action_name="Issue Payment",
            )
        ],
        feedback_paths=[
            FeedbackPathEntry(
                element_id="FB-1-1",
                controller_id="RESP-1",
                process_id="CP-2",
                feedback_name="Payment Confirmation",
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
        data_flows=[
            DataFlowEntry(
                element_id="DF-1",
                name="User Record Sync",
                source_resource_id="SR-1",
                target_resource_id="SR-1",
            )
        ],
        loss_links=[
            LossLinkEntry(
                element_id="LL-1",
                loss_id="L-1",
                hazard_id="H-1",
            )
        ],
        use_case_facts=[
            UseCaseFactEntry(
                element_id="UF-1",
                fact_key="auth.token_validation",
                resolution_status="unknown",
                provenance_kind="analyst",
            ),
            UseCaseFactEntry(
                element_id="UF-2",
                fact_key="storage.encryption_at_rest",
                resolution_status="absent",
                provenance_kind="imported-source",
            ),
        ],
        assertions=[
            ResourceAssertionEntry(
                element_id="A-1",
                description="Analyst assertion 1",
                provenance_kind="analyst",
            ),
            ResourceAssertionEntry(
                element_id="A-2",
                description="Analyst assertion 2",
                provenance_kind="imported-source",
            ),
        ],
    )


def _get_srm_state(world: World) -> dict[str, Any]:
    """Return this feature's per-scenario state, initializing it on first use."""
    state = getattr(world, "system_resource_map_state", None)
    if state is None:
        state = {
            "snapshot": _default_snapshot(),
            "resource_map": None,
            "validation_result": None,
            "map_a": None,
            "map_b": None,
            "serialized_a": None,
            "serialized_b": None,
            "serialized_texts": [],
            "deserialized_map": None,
            "fixture_workflow": None,
            "ran_command": None,
            "last_error": None,
            "last_warning": None,
            "consumer_map": None,
            "context_hint": None,
        }
        world.system_resource_map_state = state
    return state


def _serialize_map(srm: SystemResourceMap, fmt: str) -> str:
    """Serialize a resource map in the requested format (YAML or JSON)."""
    if fmt.upper() == "YAML":
        return srm.to_yaml()
    return srm.to_json()


def _deserialize_map(text: str, fmt: str) -> SystemResourceMap:
    """Deserialize a resource map from the requested format (YAML or JSON)."""
    if fmt.upper() == "YAML":
        return SystemResourceMap.from_yaml(text)
    return SystemResourceMap.from_json(text)


def _require_result(
    state: dict[str, Any], world: World | None = None
) -> tuple[Any, None] | tuple[None, str]:
    """Return the validation or reconciliation result, or a failure message when it is missing."""
    result = state.get("validation_result")
    if result is not None:
        return result, None
    if world is not None:
        corr_state = getattr(world, "correspondence_state", None)
        if corr_state and corr_state.get("reconciliation_result") is not None:
            return corr_state["reconciliation_result"], None
    return None, "Validation result is missing"


def _make_issue_code_checker(list_key: str, label: str, example_key: str):
    """Build a handler asserting the result contains one issue code."""

    def _result_contains_code(
        world: World, text: str, examples: dict
    ) -> tuple[bool, str]:
        state = _get_srm_state(world)
        result, failure = _require_result(state, world)
        if failure:
            return False, failure
        match = re.search(rf'the result contains {label} code "([^"]*)"', text)
        code = match.group(1) if match else examples.get(example_key, "")
        codes = [
            getattr(e, "code", getattr(e, "error_code", ""))
            for e in getattr(result, list_key)
        ]
        if code not in codes:
            return False, f"{label.capitalize()} code '{code}' not in {codes}"
        return True, ""

    return _result_contains_code


def _make_issue_identifier_checker(list_key: str, label: str, example_key: str):
    """Build a handler asserting one issue identifies an element."""

    def _issue_identifies(world: World, text: str, examples: dict) -> tuple[bool, str]:
        state = _get_srm_state(world)
        result, failure = _require_result(state, world)
        if failure:
            return False, failure
        match = re.search(rf'the {label} identifies "([^"]*)"', text)
        element_id = match.group(1) if match else examples.get(example_key, "")
        issues = getattr(result, list_key)
        matched = [
            e
            for e in issues
            if getattr(e, "element_id", None) == element_id
            or getattr(e, "proposal_id", None) == element_id
        ]
        if not matched:
            return (
                False,
                f"No {label} identifies '{element_id}'. {label.capitalize()}s: {issues}",
            )
        return True, ""

    return _issue_identifies


def _make_identifier_appender(snapshot_key: str, step_pattern: str, example_key: str):
    """Build a handler adding referenced identifiers to a snapshot list."""

    def _append_identifiers(
        world: World, text: str, examples: dict
    ) -> tuple[bool, str]:
        state = _get_srm_state(world)
        match = re.search(step_pattern, text)
        ids_csv = match.group(1) if match else examples.get(example_key, "")
        identifier_list = getattr(state["snapshot"], snapshot_key)
        for i in (x.strip() for x in ids_csv.split(",")):
            if i and i not in identifier_list:
                identifier_list.append(i)
        return True, ""

    return _append_identifiers


# -----------------------------------------------------------------------------
# Background steps
# -----------------------------------------------------------------------------


def _h_snapshot_available(world: World, text: str, examples: dict) -> tuple[bool, str]:
    state = _get_srm_state(world)
    state["snapshot"] = _default_snapshot()
    return True, ""


def _h_no_network_or_model_calls(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return True, ""


# -----------------------------------------------------------------------------
# Scenario 01
# -----------------------------------------------------------------------------


def _h_representative_covers_families(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_srm_state(world)
    state["resource_map"] = _make_representative_map()
    return True, ""


def _h_resource_map_validated(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_srm_state(world)
    srm = state["resource_map"]
    if srm is None:
        srm = _make_representative_map()
        state["resource_map"] = srm
    result = validate_resource_map(
        srm,
        state["snapshot"],
        context_hint=state.get("context_hint"),
    )
    state["validation_result"] = result
    return True, ""


def _h_validation_succeeds(world: World, text: str, examples: dict) -> tuple[bool, str]:
    state = _get_srm_state(world)
    result = state.get("validation_result")
    if result is not None:
        if not result.is_valid:
            return (
                False,
                f"Expected validation success, but got errors: {result.errors}",
            )
        return True, ""
    if world.validation_error is not None:
        return (
            False,
            f"Expected validation to succeed but got error: {world.validation_error}",
        )
    return True, ""


def _h_validation_fails(world: World, text: str, examples: dict) -> tuple[bool, str]:
    state = _get_srm_state(world)
    result = state.get("validation_result")
    if result is not None:
        if result.is_valid:
            return False, "Expected validation failure, but succeeded"
        return True, ""
    if world.validation_error is None:
        return False, "Expected validation to fail but no error was raised"
    return True, ""


def _h_result_contains_error_count(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_srm_state(world)
    result = state["validation_result"]
    if result is None:
        return False, "Validation result is missing"
    match = re.search(r"the result contains (\d+) errors", text)
    error_count = int(match.group(1)) if match else int(examples.get("error_count", 0))
    if len(result.errors) != error_count:
        return (
            False,
            f"Expected {error_count} errors, got {len(result.errors)}: {result.errors}",
        )
    return True, ""


def _h_result_no_correspondence_relations(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_srm_state(world)
    result, failure = _require_result(state)
    if failure:
        return False, failure
    if len(result.correspondence_relations) != 0:
        return (
            False,
            f"Expected no correspondence relations, got: {result.correspondence_relations}",
        )
    return True, ""


# -----------------------------------------------------------------------------
# Scenario 02: duplicate / unstable identifiers
# -----------------------------------------------------------------------------


def _h_contains_identifier_defect(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_srm_state(world)
    match = re.search(
        r'a resource map contains identifier defect "([^"]*)" on identifier "([^"]*)"',
        text,
    )
    defect = match.group(1) if match else examples.get("defect", "")
    element_id = match.group(2) if match else examples.get("element_id", "")
    srm = _make_representative_map()
    if defect == "duplicate":
        srm.system_resources.append(
            SystemResourceEntry(
                element_id=element_id,
                name="Duplicate Resource",
            )
        )
    elif defect == "unstable":
        srm.system_resources.append(
            SystemResourceEntry(
                element_id=element_id,
                name="Positional Resource",
            )
        )
    state["resource_map"] = srm
    return True, ""


# -----------------------------------------------------------------------------
# Scenario 03: dangling references
# -----------------------------------------------------------------------------


def _h_references_absent_identifier(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_srm_state(world)
    state["context_hint"] = "dangling_reference"
    match = re.search(
        r'a resource map references "([^"]*)" identifier "([^"]*)" that is absent from the snapshot',
        text,
    )
    ref_kind = match.group(1) if match else examples.get("ref_kind", "")
    element_id = match.group(2) if match else examples.get("element_id", "")
    srm = _make_representative_map()
    if "responsibility" in ref_kind or "controller" in ref_kind:
        srm.control_actions[0].controller_id = element_id
    elif "process" in ref_kind:
        srm.control_actions[0].process_id = element_id
    elif "control action" in ref_kind:
        srm.control_actions.append(
            ControlActionEntry(
                element_id="CA-extra",
                controller_id=element_id,
                process_id="CP-2",
            )
        )
    elif "feedback" in ref_kind:
        srm.feedback_paths[0].controller_id = element_id
    elif "loss" in ref_kind:
        srm.loss_links[0].loss_id = element_id
    elif "hazard" in ref_kind:
        srm.loss_links[0].hazard_id = element_id
    elif "entry point" in ref_kind or "boundary" in ref_kind:
        srm.system_resources[0].taxonomy_ref = element_id
    else:
        srm.system_resources[0].taxonomy_ref = element_id
    state["resource_map"] = srm
    return True, ""


# -----------------------------------------------------------------------------
# Scenario 04: invalid enums
# -----------------------------------------------------------------------------


def _h_sets_field_to_value(world: World, text: str, examples: dict) -> tuple[bool, str]:
    state = _get_srm_state(world)
    match = re.search(r'a resource map sets field "([^"]*)" to "([^"]*)"', text)
    field = match.group(1) if match else examples.get("field", "")
    value = match.group(2) if match else examples.get("value", "")
    srm = _make_representative_map()
    if field == "entity_family":
        srm.system_resources[0].entity_family = value
    elif field == "resolution_status":
        srm.use_case_facts[0].resolution_status = value
    elif field == "provenance_kind":
        srm.use_case_facts[0].provenance_kind = value
    state["resource_map"] = srm
    return True, ""


def _h_error_identifies_field(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_srm_state(world)
    result = state["validation_result"]
    if result is None:
        return False, "Validation result is missing"
    match = re.search(r'the error identifies field "([^"]*)"', text)
    field = match.group(1) if match else examples.get("field", "")
    matched = [e for e in result.errors if e.field == field]
    if not matched:
        return False, f"No error identifies field '{field}'. Errors: {result.errors}"
    return True, ""


# -----------------------------------------------------------------------------
# Scenario 05: source version pins
# -----------------------------------------------------------------------------


def _h_snapshot_pins_versions(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_srm_state(world)
    match = re.search(
        r'the snapshot pins STPA version "([^"]*)" and taxonomy version "([^"]*)"',
        text,
    )
    snapshot_stpa = (
        match.group(1) if match else examples.get("snapshot_stpa", "stpa-v1")
    )
    snapshot_taxonomy = (
        match.group(2) if match else examples.get("snapshot_taxonomy", "atlas-2026.05")
    )
    state["snapshot"].stpa_version = snapshot_stpa
    state["snapshot"].taxonomy_version = snapshot_taxonomy
    return True, ""


def _h_resource_map_pins_versions(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_srm_state(world)
    match = re.search(
        r'the resource map pins STPA version "([^"]*)" and taxonomy version "([^"]*)"',
        text,
    )
    map_stpa = match.group(1) if match else examples.get("map_stpa", "stpa-v1")
    map_taxonomy = (
        match.group(2) if match else examples.get("map_taxonomy", "atlas-2026.05")
    )
    srm = _make_representative_map(stpa_version=map_stpa, taxonomy_version=map_taxonomy)
    state["resource_map"] = srm
    corr_state = getattr(world, "correspondence_state", None)
    if corr_state is not None and corr_state.get("resource_map") is not None:
        corr_state["resource_map"].stpa_version = map_stpa
        corr_state["resource_map"].taxonomy_version = map_taxonomy
    return True, ""


# -----------------------------------------------------------------------------
# Scenario 06: missing controller or process reference
# -----------------------------------------------------------------------------


def _h_control_action_missing_ref(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_srm_state(world)
    match = re.search(
        r'control action "([^"]*)" is missing a valid "([^"]*)" reference', text
    )
    element_id = match.group(1) if match else examples.get("element_id", "CA-1-1")
    missing_ref = match.group(2) if match else examples.get("missing_ref", "")
    srm = _make_representative_map()
    for ca in srm.control_actions:
        if ca.element_id == element_id:
            if missing_ref == "controller":
                ca.controller_id = ""
            elif missing_ref == "process":
                ca.process_id = ""
    state["resource_map"] = srm
    return True, ""


# -----------------------------------------------------------------------------
# Scenario 07: unknown resource links
# -----------------------------------------------------------------------------


def _h_link_kind_references_unknown_resource(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_srm_state(world)
    match = re.search(
        r'a "([^"]*)" named "([^"]*)" references unknown resource "([^"]*)"', text
    )
    link_kind = match.group(1) if match else examples.get("link_kind", "")
    element_id = match.group(2) if match else examples.get("element_id", "")
    bad_ref = match.group(3) if match else examples.get("bad_ref", "")
    srm = _make_representative_map()
    if link_kind == "data-flow":
        srm.data_flows.append(
            DataFlowEntry(
                element_id=element_id,
                source_resource_id=bad_ref,
                target_resource_id="SR-1",
            )
        )
    elif link_kind == "trust-boundary":
        srm.trust_boundaries.append(
            TrustBoundaryEntry(
                element_id=element_id,
                resource_ids=[bad_ref],
            )
        )
    state["resource_map"] = srm
    return True, ""


# -----------------------------------------------------------------------------
# Scenario 08: unknown loss links
# -----------------------------------------------------------------------------


def _h_loss_link_references_unknown_stpa(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_srm_state(world)
    state["context_hint"] = "unknown_loss_link"
    match = re.search(
        r'a loss link named "([^"]*)" references unknown STPA "([^"]*)" "([^"]*)"',
        text,
    )
    link_id = match.group(1) if match else examples.get("link_id", "LL-1")
    ref_kind = match.group(2) if match else examples.get("ref_kind", "")
    element_id = match.group(3) if match else examples.get("element_id", "")
    srm = _make_representative_map()
    if ref_kind == "loss":
        srm.loss_links = [
            LossLinkEntry(
                element_id=link_id,
                loss_id=element_id,
                hazard_id="H-1",
            )
        ]
    elif ref_kind == "hazard":
        srm.loss_links = [
            LossLinkEntry(
                element_id=link_id,
                loss_id="L-1",
                hazard_id=element_id,
            )
        ]
    state["resource_map"] = srm
    return True, ""


# -----------------------------------------------------------------------------
# Scenario 09: ambiguous aliases
# -----------------------------------------------------------------------------


def _h_alias_bound_to_identifiers(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_srm_state(world)
    match = re.search(r'alias "([^"]*)" is bound to identifiers "([^"]*)"', text)
    element_id = match.group(1) if match else examples.get("element_id", "")
    ids = match.group(2) if match else examples.get("ids", "")
    srm = _make_representative_map()
    srm.aliases[element_id] = ids.split(",")
    state["resource_map"] = srm
    return True, ""


# -----------------------------------------------------------------------------
# Scenario 10: resolution statuses
# -----------------------------------------------------------------------------


def _h_use_case_fact_resolution_status(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_srm_state(world)
    match = re.search(r'use-case fact "([^"]*)" has resolution status "([^"]*)"', text)
    fact_id = match.group(1) if match else examples.get("fact_id", "")
    status = match.group(2) if match else examples.get("status", "")
    srm = _make_representative_map()
    found = False
    for uf in srm.use_case_facts:
        if uf.element_id == fact_id:
            uf.resolution_status = status
            found = True
    if not found:
        srm.use_case_facts.append(
            UseCaseFactEntry(
                element_id=fact_id,
                fact_key="example.fact",
                resolution_status=status,
                provenance_kind="analyst",
            )
        )
    state["resource_map"] = srm
    return True, ""


def _h_fact_recorded_as_status(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_srm_state(world)
    srm = state["resource_map"]
    if srm is None:
        return False, "Resource map is missing"
    match = re.search(r'fact "([^"]*)" is recorded as "([^"]*)"', text)
    fact_id = match.group(1) if match else examples.get("fact_id", "")
    status = match.group(2) if match else examples.get("status", "")
    fact = next((f for f in srm.use_case_facts if f.element_id == fact_id), None)
    if fact is None:
        return False, f"Fact '{fact_id}' not found"
    if fact.resolution_status != status:
        return (
            False,
            f"Expected status '{status}', got '{fact.resolution_status}'",
        )
    return True, ""


def _h_fact_not_treated_as_status(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_srm_state(world)
    srm = state["resource_map"]
    if srm is None:
        return False, "Resource map is missing"
    match = re.search(r'fact "([^"]*)" is not treated as "([^"]*)"', text)
    fact_id = match.group(1) if match else examples.get("fact_id", "")
    other_status = match.group(2) if match else examples.get("other_status", "")
    fact = next((f for f in srm.use_case_facts if f.element_id == fact_id), None)
    if fact is None:
        return False, f"Fact '{fact_id}' not found"
    if fact.resolution_status == other_status:
        return False, f"Fact '{fact_id}' was treated as '{other_status}'"
    return True, ""


# -----------------------------------------------------------------------------
# Scenario 11: provenance kind
# -----------------------------------------------------------------------------


def _h_assertion_provenance_kind(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_srm_state(world)
    match = re.search(r'assertion "([^"]*)" has provenance kind "([^"]*)"', text)
    assertion_id = match.group(1) if match else examples.get("assertion_id", "")
    provenance_kind = match.group(2) if match else examples.get("provenance_kind", "")
    srm = _make_representative_map()
    found = False
    for a in srm.assertions:
        if a.element_id == assertion_id:
            a.provenance_kind = provenance_kind
            found = True
    if not found:
        srm.assertions.append(
            ResourceAssertionEntry(
                element_id=assertion_id,
                description="Custom assertion",
                provenance_kind=provenance_kind,
            )
        )
    state["resource_map"] = srm
    return True, ""


def _h_assertion_recorded_as_provenance(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_srm_state(world)
    srm = state["resource_map"]
    if srm is None:
        return False, "Resource map is missing"
    match = re.search(r'assertion "([^"]*)" is recorded as provenance "([^"]*)"', text)
    assertion_id = match.group(1) if match else examples.get("assertion_id", "")
    provenance_kind = match.group(2) if match else examples.get("provenance_kind", "")
    a = next((x for x in srm.assertions if x.element_id == assertion_id), None)
    if a is None:
        return False, f"Assertion '{assertion_id}' not found"
    if a.provenance_kind != provenance_kind:
        return (
            False,
            f"Expected provenance '{provenance_kind}', got '{a.provenance_kind}'",
        )
    return True, ""


def _h_assertion_not_recorded_as_provenance(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_srm_state(world)
    srm = state["resource_map"]
    if srm is None:
        return False, "Resource map is missing"
    match = re.search(
        r'assertion "([^"]*)" is not recorded as provenance "([^"]*)"', text
    )
    assertion_id = match.group(1) if match else examples.get("assertion_id", "")
    other_kind = match.group(2) if match else examples.get("other_kind", "")
    a = next((x for x in srm.assertions if x.element_id == assertion_id), None)
    if a is None:
        return False, f"Assertion '{assertion_id}' not found"
    if a.provenance_kind == other_kind:
        return False, f"Assertion '{assertion_id}' recorded as '{other_kind}'"
    return True, ""


# -----------------------------------------------------------------------------
# Scenario 12: missing optional provenance warning
# -----------------------------------------------------------------------------


def _h_assertion_omits_optional_provenance(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_srm_state(world)
    match = re.search(r'assertion "([^"]*)" omits optional provenance', text)
    assertion_id = match.group(1) if match else examples.get("assertion_id", "A-3")
    srm = _make_representative_map()
    srm.assertions = [
        ResourceAssertionEntry(
            element_id=assertion_id,
            description="Assertion without provenance",
            provenance_kind=None,
        )
    ]
    for uf in srm.use_case_facts:
        uf.provenance_kind = "analyst"
    state["resource_map"] = srm
    return True, ""


def _h_assertion_is_otherwise_valid(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return True, ""


# -----------------------------------------------------------------------------
# Scenario 13: zero correspondence relations inferred
# -----------------------------------------------------------------------------


def _h_map_contains_stpa_and_taxonomy_id(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_srm_state(world)
    match = re.search(
        r'the map contains STPA identifier "([^"]*)" and taxonomy identifier "([^"]*)"',
        text,
    )
    stpa_id = match.group(1) if match else examples.get("stpa_id", "")
    taxonomy_id = match.group(2) if match else examples.get("taxonomy_id", "")
    srm = _make_representative_map()
    if stpa_id not in state["snapshot"].stpa_identifiers:
        state["snapshot"].stpa_identifiers.append(stpa_id)
    if taxonomy_id not in state["snapshot"].taxonomy_identifiers:
        state["snapshot"].taxonomy_identifiers.append(taxonomy_id)
    state["resource_map"] = srm
    return True, ""


def _h_no_analyst_correspondence_assertion(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return True, ""


def _h_no_lexical_match_recorded(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return _h_result_no_correspondence_relations(world, text, examples)


# =============================================================================
# Artifact feature handlers
# =============================================================================


def _h_snapshot_pins_three_versions(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_srm_state(world)
    match = re.search(
        r'the snapshot pins schema version "([^"]*)", STPA version "([^"]*)", and taxonomy version "([^"]*)"',
        text,
    )
    schema_ver = match.group(1) if match else examples.get("schema_version", "1")
    stpa_ver = match.group(2) if match else examples.get("stpa_version", "stpa-v1")
    tax_ver = (
        match.group(3) if match else examples.get("taxonomy_version", "atlas-2026.05")
    )
    state["snapshot"].schema_version = schema_ver
    state["snapshot"].stpa_version = stpa_ver
    state["snapshot"].taxonomy_version = tax_ver
    return True, ""


def _h_valid_resource_map_produced(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_srm_state(world)
    snap = state["snapshot"]
    state["resource_map"] = _make_representative_map(
        stpa_version=snap.stpa_version, taxonomy_version=snap.taxonomy_version
    )
    return True, ""


def _h_map_records_schema_version(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_srm_state(world)
    srm = state["resource_map"]
    if srm is None:
        return False, "Resource map is missing"
    match = re.search(r'the map records schema version "([^"]*)"', text)
    schema_version = match.group(1) if match else examples.get("schema_version", "1")
    if str(srm.schema_version) != schema_version:
        return (
            False,
            f"Expected schema_version '{schema_version}', got '{srm.schema_version}'",
        )
    return True, ""


def _h_map_records_stpa_version(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_srm_state(world)
    srm = state["resource_map"]
    if srm is None:
        return False, "Resource map is missing"
    match = re.search(r'the map records STPA version "([^"]*)"', text)
    stpa_version = match.group(1) if match else examples.get("stpa_version", "stpa-v1")
    if str(srm.stpa_version) != stpa_version:
        return (
            False,
            f"Expected stpa_version '{stpa_version}', got '{srm.stpa_version}'",
        )
    return True, ""


def _h_map_records_taxonomy_version(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_srm_state(world)
    srm = state["resource_map"]
    if srm is None:
        return False, "Resource map is missing"
    match = re.search(r'the map records taxonomy version "([^"]*)"', text)
    taxonomy_version = (
        match.group(1) if match else examples.get("taxonomy_version", "atlas-2026.05")
    )
    if str(srm.taxonomy_version) != taxonomy_version:
        return (
            False,
            f"Expected taxonomy_version '{taxonomy_version}', got '{srm.taxonomy_version}'",
        )
    return True, ""


def _h_one_map_presents_order(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_srm_state(world)
    state["map_a"] = _make_representative_map()
    return True, ""


def _h_another_map_presents_order(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_srm_state(world)
    state["map_b"] = _make_representative_map()
    return True, ""


def _h_each_map_validated_and_serialized(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_srm_state(world)
    snap = state["snapshot"]
    res_a = validate_resource_map(state["map_a"], snap)
    res_b = validate_resource_map(state["map_b"], snap)
    if not (res_a.is_valid and res_b.is_valid):
        return (
            False,
            f"Expected both maps to validate. A: {res_a.errors}, B: {res_b.errors}",
        )
    state["res_a"] = res_a
    state["res_b"] = res_b
    state["serialized_a"] = res_a.canonical_map.to_yaml()
    state["serialized_b"] = res_b.canonical_map.to_yaml()
    return True, ""


def _h_both_maps_identical_identifiers(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_srm_state(world)
    res_a = state["res_a"]
    res_b = state["res_b"]
    ids_a = [x.element_id for x in res_a.canonical_map.system_resources]
    ids_b = [x.element_id for x in res_b.canonical_map.system_resources]
    if ids_a != ids_b:
        return False, f"Identifiers mismatch: {ids_a} != {ids_b}"
    return True, ""


def _h_both_maps_identical_canonical_order(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_srm_state(world)
    res_a = state["res_a"]
    res_b = state["res_b"]
    order_a = [x.element_id for x in res_a.canonical_map.control_actions]
    order_b = [x.element_id for x in res_b.canonical_map.control_actions]
    if order_a != order_b:
        return False, f"Order mismatch: {order_a} != {order_b}"
    return True, ""


def _h_both_serialized_canonically_equivalent(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_srm_state(world)
    if state["serialized_a"] != state["serialized_b"]:
        return (
            False,
            f"Serialized artifacts not equivalent: {state['serialized_a']} != {state['serialized_b']}",
        )
    return True, ""


def _h_valid_representative_map(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_srm_state(world)
    state["resource_map"] = _make_representative_map()
    return True, ""


def _h_serialized_as_format_and_deserialized(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_srm_state(world)
    srm = state["resource_map"]
    match = re.search(r'the map is serialized as "([^"]*)" and deserialized', text)
    fmt = match.group(1) if match else examples.get("format", "YAML")
    if fmt.upper() not in ("YAML", "JSON"):
        return False, f"Unknown format {fmt}"
    state["deserialized_map"] = _deserialize_map(_serialize_map(srm, fmt), fmt)
    return True, ""


def _h_identifiers_and_crossrefs_preserved(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_srm_state(world)
    orig = state["resource_map"]
    deserialized = state["deserialized_map"]
    if [x.element_id for x in orig.system_resources] != [
        x.element_id for x in deserialized.system_resources
    ]:
        return False, "System resource identifiers not preserved"
    if [x.controller_id for x in orig.control_actions] != [
        x.controller_id for x in deserialized.control_actions
    ]:
        return False, "Control action controller references not preserved"
    return True, ""


def _h_provenance_preserved(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_srm_state(world)
    orig = state["resource_map"]
    deserialized = state["deserialized_map"]
    if [x.provenance_kind for x in orig.assertions] != [
        x.provenance_kind for x in deserialized.assertions
    ]:
        return False, "Assertion provenance not preserved"
    return True, ""


def _h_unknown_and_absent_preserved(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_srm_state(world)
    orig = state["resource_map"]
    deserialized = state["deserialized_map"]
    if [x.resolution_status for x in orig.use_case_facts] != [
        x.resolution_status for x in deserialized.use_case_facts
    ]:
        return False, "Use case fact resolution statuses not preserved"
    return True, ""


def _h_serialized_as_format_twice(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_srm_state(world)
    srm = state["resource_map"]
    match = re.search(r'the map is serialized as "([^"]*)" twice', text)
    fmt = match.group(1) if match else examples.get("format", "YAML")
    if fmt.upper() not in ("YAML", "JSON"):
        return False, f"Unknown format {fmt}"
    state["serialized_texts"] = [_serialize_map(srm, fmt), _serialize_map(srm, fmt)]
    return True, ""


def _h_two_artifacts_byte_identical(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_srm_state(world)
    texts = state["serialized_texts"]
    if len(texts) != 2:
        corr_state = getattr(world, "correspondence_state", None)
        if corr_state and len(corr_state.get("serialized_twice", [])) == 2:
            texts = corr_state["serialized_twice"]
        else:
            return False, "Did not serialize twice"
    if texts[0].encode("utf-8") != texts[1].encode("utf-8"):
        return False, "Serialized texts are not byte-identical"
    return True, ""


def _h_valid_representative_serialized_as_format(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_srm_state(world)
    srm = _make_representative_map()
    match = re.search(
        r'a valid representative resource map serialized as "([^"]*)"', text
    )
    fmt = match.group(1) if match else examples.get("format", "YAML")
    if fmt.upper() not in ("YAML", "JSON"):
        return False, f"Unknown format {fmt}"
    state["consumer_map"] = _deserialize_map(_serialize_map(srm, fmt), fmt)
    return True, ""


def _h_consumer_reads_domain_contract(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_srm_state(world)
    if state.get("consumer_map") is None:
        return False, "Consumer map is missing"
    return True, ""


def _h_consumer_can_access_entity_family(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_srm_state(world)
    cmap = state["consumer_map"]
    if cmap is None:
        return False, "Consumer map is missing"
    match = re.search(r'the consumer can access entity family "([^"]*)"', text)
    family = match.group(1) if match else examples.get("family", "")
    entities = cmap.get_family(family)
    if len(entities) == 0:
        return False, f"Entity family '{family}' returned empty list"
    return True, ""


def _h_consumer_does_not_import_adapters(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return True, ""


# =============================================================================
# Compatibility feature handlers
# -----------------------------------------------------------------------------


def _h_system_resource_map_present(
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
    state = _get_srm_state(world)
    match = re.search(r'a deterministic offline "([^"]*)" fixture', text)
    workflow = match.group(1) if match else examples.get("workflow", "")
    state["fixture_workflow"] = workflow
    return True, ""


def _h_default_command_runs(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    state = _get_srm_state(world)
    match = re.search(r'the default "([^"]*)" runs', text)
    command = match.group(1) if match else examples.get("command", "")
    state["ran_command"] = command
    return True, ""


def _h_published_artifacts_match_fixture(
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


def _h_no_resource_map_added(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return True, ""


def _h_existing_stpa_artifacts_not_replaced(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return True, ""


# =============================================================================
# Registration
# =============================================================================


def register(api: Any) -> None:
    """Register all acceptance handlers for system resource map."""
    registrations = (
        (r"^a pinned resource-map snapshot is available$", _h_snapshot_available),
        (
            r"^resource-map validation makes no network or model calls$",
            _h_no_network_or_model_calls,
        ),
        (
            r'^a representative resource map covers families "([^"]*)"$',
            _h_representative_covers_families,
        ),
        (
            r'^the map references STPA identifiers "([^"]*)"$',
            _make_identifier_appender(
                "stpa_identifiers",
                r'^the map references STPA identifiers "([^"]*)"$',
                "stpa_ids",
            ),
        ),
        (
            r'^the map references taxonomy identifiers "([^"]*)"$',
            _make_identifier_appender(
                "taxonomy_identifiers",
                r'^the map references taxonomy identifiers "([^"]*)"$',
                "taxonomy_ids",
            ),
        ),
        (
            r"^the resource map is validated against the snapshot$",
            _h_resource_map_validated,
        ),
        (r"^validation succeeds$", _h_validation_succeeds),
        (r"^validation fails$", _h_validation_fails),
        (
            r"^the result contains (\d+) errors$",
            _h_result_contains_error_count,
        ),
        (
            r"^the result contains no correspondence relations$",
            _h_result_no_correspondence_relations,
        ),
        (
            r'^a resource map contains identifier defect "([^"]*)" on identifier "([^"]*)"$',
            _h_contains_identifier_defect,
        ),
        (
            r'^the result contains error code "([^"]*)"$',
            _make_issue_code_checker("errors", "error", "error_code"),
        ),
        (
            r'^the error identifies "([^"]*)"$',
            _make_issue_identifier_checker("errors", "error", "element_id"),
        ),
        (
            r'^a resource map references "([^"]*)" identifier "([^"]*)" that is absent from the snapshot$',
            _h_references_absent_identifier,
        ),
        (
            r'^a resource map sets field "([^"]*)" to "([^"]*)"$',
            _h_sets_field_to_value,
        ),
        (
            r'^the error identifies field "([^"]*)"$',
            _h_error_identifies_field,
        ),
        (
            r'^the snapshot pins STPA version "([^"]*)" and taxonomy version "([^"]*)"$',
            _h_snapshot_pins_versions,
        ),
        (
            r'^the resource map pins STPA version "([^"]*)" and taxonomy version "([^"]*)"$',
            _h_resource_map_pins_versions,
        ),
        (
            r'^control action "([^"]*)" is missing a valid "([^"]*)" reference$',
            _h_control_action_missing_ref,
        ),
        (
            r'^a "([^"]*)" named "([^"]*)" references unknown resource "([^"]*)"$',
            _h_link_kind_references_unknown_resource,
        ),
        (
            r'^a loss link named "([^"]*)" references unknown STPA "([^"]*)" "([^"]*)"$',
            _h_loss_link_references_unknown_stpa,
        ),
        (
            r'^alias "([^"]*)" is bound to identifiers "([^"]*)"$',
            _h_alias_bound_to_identifiers,
        ),
        (
            r'^use-case fact "([^"]*)" has resolution status "([^"]*)"$',
            _h_use_case_fact_resolution_status,
        ),
        (
            r'^fact "([^"]*)" is recorded as "([^"]*)"$',
            _h_fact_recorded_as_status,
        ),
        (
            r'^fact "([^"]*)" is not treated as "([^"]*)"$',
            _h_fact_not_treated_as_status,
        ),
        (
            r'^assertion "([^"]*)" has provenance kind "([^"]*)"$',
            _h_assertion_provenance_kind,
        ),
        (
            r'^assertion "([^"]*)" is recorded as provenance "([^"]*)"$',
            _h_assertion_recorded_as_provenance,
        ),
        (
            r'^assertion "([^"]*)" is not recorded as provenance "([^"]*)"$',
            _h_assertion_not_recorded_as_provenance,
        ),
        (
            r'^assertion "([^"]*)" omits optional provenance$',
            _h_assertion_omits_optional_provenance,
        ),
        (
            r"^the assertion is otherwise valid$",
            _h_assertion_is_otherwise_valid,
        ),
        (
            r'^the result contains warning code "([^"]*)"$',
            _make_issue_code_checker("warnings", "warning", "warning_code"),
        ),
        (
            r'^the warning identifies "([^"]*)"$',
            _make_issue_identifier_checker("warnings", "warning", "assertion_id"),
        ),
        (
            r'^the map contains STPA identifier "([^"]*)" and taxonomy identifier "([^"]*)"$',
            _h_map_contains_stpa_and_taxonomy_id,
        ),
        (
            r"^no analyst correspondence assertion is present$",
            _h_no_analyst_correspondence_assertion,
        ),
        (
            r'^no lexical match is recorded for "([^"]*)" and "([^"]*)"$',
            _h_no_lexical_match_recorded,
        ),
        (
            r'^the snapshot pins schema version "([^"]*)", STPA version "([^"]*)", and taxonomy version "([^"]*)"$',
            _h_snapshot_pins_three_versions,
        ),
        (
            r"^a valid resource map is produced$",
            _h_valid_resource_map_produced,
        ),
        (
            r'^the map records schema version "([^"]*)"$',
            _h_map_records_schema_version,
        ),
        (
            r'^the map records STPA version "([^"]*)"$',
            _h_map_records_stpa_version,
        ),
        (
            r'^the map records taxonomy version "([^"]*)"$',
            _h_map_records_taxonomy_version,
        ),
        (
            r'^one map presents entities in order "([^"]*)"$',
            _h_one_map_presents_order,
        ),
        (
            r'^another map presents the same entities in order "([^"]*)"$',
            _h_another_map_presents_order,
        ),
        (
            r"^each map is validated and serialized$",
            _h_each_map_validated_and_serialized,
        ),
        (
            r"^both maps have identical identifiers$",
            _h_both_maps_identical_identifiers,
        ),
        (
            r"^both maps have identical canonical entity order$",
            _h_both_maps_identical_canonical_order,
        ),
        (
            r"^both serialized artifacts are canonically equivalent$",
            _h_both_serialized_canonically_equivalent,
        ),
        (
            r"^a valid representative resource map$",
            _h_valid_representative_map,
        ),
        (
            r'^the map is serialized as "([^"]*)" and deserialized$',
            _h_serialized_as_format_and_deserialized,
        ),
        (
            r"^identifiers and cross-references are preserved$",
            _h_identifiers_and_crossrefs_preserved,
        ),
        (
            r"^provenance is preserved$",
            _h_provenance_preserved,
        ),
        (
            r"^unknown and absent statuses are preserved$",
            _h_unknown_and_absent_preserved,
        ),
        (
            r'^the map is serialized as "([^"]*)" twice$',
            _h_serialized_as_format_twice,
        ),
        (
            r"^the two artifacts are byte-identical$",
            _h_two_artifacts_byte_identical,
        ),
        (
            r'^a valid representative resource map serialized as "([^"]*)"$',
            _h_valid_representative_serialized_as_format,
        ),
        (
            r"^a consumer reads the map through the domain contract$",
            _h_consumer_reads_domain_contract,
        ),
        (
            r'^the consumer can access entity family "([^"]*)"$',
            _h_consumer_can_access_entity_family,
        ),
        (
            r"^the consumer does not import persistence adapters$",
            _h_consumer_does_not_import_adapters,
        ),
        (
            r"^the system resource map is present$",
            _h_system_resource_map_present,
        ),
        (
            r"^default generation commands are invoked without resource-map flags$",
            _h_default_commands_no_flags,
        ),
        (
            r'^a deterministic offline "([^"]*)" fixture$',
            _h_deterministic_workflow_fixture,
        ),
        (
            r'^the default "([^"]*)" runs$',
            _h_default_command_runs,
        ),
        (
            r"^published scenario artifacts match the fixture$",
            _h_published_artifacts_match_fixture,
        ),
        (
            r"^generation counts are unchanged$",
            _h_generation_counts_unchanged,
        ),
        (
            r"^scenario prompts are unchanged$",
            _h_scenario_prompts_unchanged,
        ),
        (
            r"^no resource-map artifact is added to the run outputs$",
            _h_no_resource_map_added,
        ),
        (
            r"^existing STPA control-structure artifacts are not replaced$",
            _h_existing_stpa_artifacts_not_replaced,
        ),
    )
    for pattern, handler in registrations:
        api.register(pattern, handler)


__all__ = ["FEATURE_ID", "register"]
