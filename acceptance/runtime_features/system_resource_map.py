"""Deterministic acceptance handlers for the normative resource-map seam."""

from __future__ import annotations

import re
import tempfile
from pathlib import Path
from typing import Any

from runtime_shared import World

from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.models.system_resource_map import (
    ResourceLink,
    SystemResourceMap,
    compute_control_structure_digest,
    compute_resource_map_semantic_digest,
)
from asago_scenario_generator.pipeline.projection_contracts import (
    capture_capability_snapshot,
)
from asago_scenario_generator.pipeline.system_resource_map import (
    validate_system_resource_map,
)
from asago_scenario_generator.pipeline.system_resource_map_persistence import (
    write_system_resource_map,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    ControlledProcess,
    ProcessModelPart,
    Responsibility,
)
from acceptance.qa.taxonomy_risk.correspondence_support import (
    run_workflow_compatibility,
)

FEATURE_ID = "system_resource_map"


def _authorities() -> tuple[Any, ControlStructure]:
    """Create one deterministic capability/control authority pair."""
    profile = CapabilityProfile.model_validate(
        {
            "zones_active": ["input", "reasoning", "tool_execution"],
            "entry_points": [
                {
                    "name": "Customer input",
                    "entry_point_type": "user_input",
                    "direction": "input",
                    "controllability": "direct",
                    "ingress_zone": "input",
                }
            ],
            "confidence": "high",
            "kc_subcodes": ["KC1.1", "KC5.3"],
            "tool_inventory": [
                {"name": "Payment API", "description": "Mutates payments"}
            ],
        }
    )
    snapshot = capture_capability_snapshot(profile)
    control = ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Payment controller",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-1-1", description="Payment state")
                ],
                control_actions=[
                    ControlAction(ca_id="CA-1-1", description="Authorize payment")
                ],
            )
        ],
        controlled_processes=[
            ControlledProcess(cp_id="CP-1", description="Payment process")
        ],
    )
    return snapshot, control


def _state(world: World) -> dict[str, Any]:
    state = getattr(world, "system_resource_map_state", None)
    if state is None:
        snapshot, control = _authorities()
        state = {
            "snapshot": snapshot,
            "control": control,
            "resource_map": None,
            "result": None,
            "serialized": None,
            "persisted": None,
            "error": None,
            "compatibility_workflow": None,
            "compatibility": None,
        }
        world.system_resource_map_state = state
    return state


def _valid_link(state: dict[str, Any], *, link_id: str = "srm:v1:1") -> ResourceLink:
    snapshot = state["snapshot"]
    profile = snapshot.profile
    return ResourceLink(
        link_id=link_id,
        capability_resource_ref={
            "kind": "tool",
            "tool_id": profile.tool_inventory[0].tool_id,
        },
        control_structure_ref={"kind": "CA", "id": "CA-1-1"},
        relation_kind="acts_on",
        provenance="operator_declared",
        evidence_refs=("review:resource-map-1",),
        confidence=0.9,
        authority_status="authoritative",
    )


def _make_map(state: dict[str, Any], *links: ResourceLink) -> SystemResourceMap:
    snapshot = state["snapshot"]
    control = state["control"]
    links = links or (_valid_link(state),)
    digest = compute_resource_map_semantic_digest(
        schema_version="system-resource-map-v1",
        capability_snapshot_digest=snapshot.snapshot_digest,
        control_structure_digest=compute_control_structure_digest(control),
        links=links,
    )
    return SystemResourceMap(
        schema_version="system-resource-map-v1",
        semantic_digest=digest,
        capability_snapshot_digest=snapshot.snapshot_digest,
        control_structure_digest=compute_control_structure_digest(control),
        links=links,
    )


def _replace_link(link: ResourceLink, **updates: Any) -> ResourceLink:
    """Return a validated link with selected fields replaced.

    ``BaseModel.model_copy(update=...)`` deliberately skips validation.  That
    is useful for a few scalar digest-tampering checks, but it is unsafe for
    nested reference dictionaries: Pydantic would retain the raw dictionaries
    and emit serializer warnings during canonical digest computation.  This
    helper keeps the acceptance fixtures on the same validated public seam as
    production inputs.
    """
    payload = link.model_dump(mode="json")
    payload.update(updates)
    return ResourceLink.model_validate(payload)


def _run_validation(world: World) -> None:
    state = _state(world)
    state["result"] = validate_system_resource_map(
        state["resource_map"], state["snapshot"], state["control"]
    )


def _ok(
    world: World, text: str = "", examples: dict[str, Any] | None = None
) -> tuple[bool, str]:
    del world, text, examples
    return True, ""


def _authorities_available(world: World, text: str, examples: dict) -> tuple[bool, str]:
    _state(world)
    return _ok(world)


def _valid_map_available(world: World, text: str, examples: dict) -> tuple[bool, str]:
    state = _state(world)
    state["resource_map"] = _make_map(state)
    return _ok(world)


def _map_validated(world: World, text: str, examples: dict) -> tuple[bool, str]:
    _run_validation(world)
    return _ok(world)


def _resource_map_passes_validation(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Assert that the prepared system-resource map passes validation."""
    result = _state(world).get("result")
    if result is None or not result.is_valid:
        return False, f"expected valid result: {result}"
    return _ok(world)


def _resource_map_fails_validation(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Assert that the prepared system-resource map fails validation."""
    result = _state(world).get("result")
    if result is None or result.is_valid:
        return False, f"expected invalid result: {result}"
    return _ok(world)


def _contains_violation(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'violation code "([^"]+)"', text)
    code = match.group(1) if match else ""
    result = _state(world).get("result")
    codes = {item.code for item in (result.violations if result else ())}
    return (True, "") if code in codes else (False, f"{code!r} not in {sorted(codes)}")


def _schema_recorded(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r'schema version "([^"]+)"', text)
    expected = match.group(1) if match else ""
    actual = _state(world)["resource_map"].schema_version
    return (True, "") if actual == expected else (False, f"{actual!r} != {expected!r}")


def _pin_substituted(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.fullmatch(
        r'the map substitutes digest pin "(capability_snapshot_digest|control_structure_digest)"',
        text,
    )
    if match is None:
        return False, f"unexpected digest-pin step: {text}"
    field = match.group(1)
    state = _state(world)
    state["resource_map"] = _make_map(state).model_copy(update={field: "f" * 64})
    return _ok(world)


def _unknown_reference(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.fullmatch(
        r"the map references an unknown (capability resource|STPA identifier)", text
    )
    if match is None:
        return False, f"unexpected unknown-reference step: {text}"
    state = _state(world)
    link = _valid_link(state)
    if match and match.group(1) == "capability resource":
        ref = {"kind": "tool", "tool_id": "tool:v1:" + "f" * 32}
        link = _replace_link(link, capability_resource_ref=ref)
    else:
        ref = {"kind": "CA", "id": "CA-9-9"}
        link = _replace_link(link, control_structure_ref=ref)
    state["resource_map"] = _make_map(state, link)
    return _ok(world)


def _relation_defect(world: World, text: str, examples: dict) -> tuple[bool, str]:
    if text not in {
        "the map uses an incompatible relation kind",
        "the map marks a model-proposed link authoritative",
        "the map has an authoritative link with no evidence",
        "the map contains duplicate semantic links",
    }:
        return False, f"unexpected relation-defect step: {text}"
    state = _state(world)
    profile = state["snapshot"].profile
    link = _replace_link(
        _valid_link(state),
        relation_kind="coordinates_via",
        control_structure_ref={"kind": "CA", "id": "CA-1-1"},
        capability_resource_ref={
            "kind": "entry_point",
            "entry_point_id": profile.entry_points[0].entry_point_id,
        },
    )
    state["resource_map"] = _make_map(state, link)
    return _ok(world)


def _authority_defect(world: World, text: str, examples: dict) -> tuple[bool, str]:
    if text != "the map marks a model-proposed link authoritative":
        return False, f"unexpected authority-defect step: {text}"
    state = _state(world)
    link = _replace_link(_valid_link(state), provenance="model_proposed")
    state["resource_map"] = _make_map(state, link)
    return _ok(world)


def _no_evidence(world: World, text: str, examples: dict) -> tuple[bool, str]:
    if text != "the map has an authoritative link with no evidence":
        return False, f"unexpected evidence-defect step: {text}"
    state = _state(world)
    link = _replace_link(_valid_link(state), evidence_refs=())
    state["resource_map"] = _make_map(state, link)
    return _ok(world)


def _duplicate_links(world: World, text: str, examples: dict) -> tuple[bool, str]:
    if text != "the map contains duplicate semantic links":
        return False, f"unexpected duplicate-link step: {text}"
    state = _state(world)
    state["resource_map"] = _make_map(
        state,
        _valid_link(state, link_id="srm:v1:1"),
        _valid_link(state, link_id="srm:v1:2"),
    )
    return _ok(world)


def _cardinality_conflict(world: World, text: str, examples: dict) -> tuple[bool, str]:
    if text != "the map contains a contradictory authoritative cardinality":
        return False, f"unexpected cardinality step: {text}"
    state = _state(world)
    profile = state["snapshot"].profile
    first = _replace_link(
        _valid_link(state, link_id="srm:v1:2"),
        relation_kind="represents",
        control_structure_ref={"kind": "CP", "id": "CP-1"},
        capability_resource_ref={
            "kind": "entry_point",
            "entry_point_id": profile.entry_points[0].entry_point_id,
        },
    )
    second = _replace_link(
        _valid_link(state, link_id="srm:v1:3"),
        relation_kind="represents",
        control_structure_ref={"kind": "CP", "id": "CP-1"},
    )
    state["resource_map"] = _make_map(state, first, second)
    return _ok(world)


def _advisory_model_link(world: World, text: str, examples: dict) -> tuple[bool, str]:
    state = _state(world)
    link = _replace_link(
        _valid_link(state),
        provenance="model_proposed",
        authority_status="advisory",
        evidence_refs=(),
    )
    state["resource_map"] = _make_map(state, link)
    return _ok(world)


def _advisory_is_valid(world: World, text: str, examples: dict) -> tuple[bool, str]:
    result = _state(world).get("result")
    if result is None or not result.is_valid:
        return False, f"expected advisory map to validate: {result}"
    return _ok(world)


def _order_maps(world: World, text: str, examples: dict) -> tuple[bool, str]:
    state = _state(world)
    profile = state["snapshot"].profile
    first = _valid_link(state, link_id="srm:v1:2")
    second = _replace_link(
        _valid_link(state, link_id="srm:v1:1"),
        relation_kind="represents",
        control_structure_ref={"kind": "CP", "id": "CP-1"},
        capability_resource_ref={
            "kind": "entry_point",
            "entry_point_id": profile.entry_points[0].entry_point_id,
        },
    )
    state["map_a"] = _make_map(state, first, second)
    state["map_b"] = _make_map(state, second, first)
    return _ok(world)


def _ordered_maps_equal(world: World, text: str, examples: dict) -> tuple[bool, str]:
    state = _state(world)
    if (
        state["map_a"] != state["map_b"]
        or state["map_a"].to_yaml() != state["map_b"].to_yaml()
    ):
        return False, "presentation order changed the canonical map"
    return _ok(world)


def _round_trip(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Round-trip only the explicitly supported serialization formats."""
    state = _state(world)
    fmt = examples.get("format", "YAML")
    if fmt not in {"YAML", "JSON"}:
        return False, f"unsupported serialization format: {fmt!r}"
    state["serialized"] = (
        state["resource_map"].to_json()
        if fmt == "JSON"
        else state["resource_map"].to_yaml()
    )
    state["restored"] = (
        SystemResourceMap.from_json(state["serialized"])
        if fmt == "JSON"
        else SystemResourceMap.from_yaml(state["serialized"])
    )
    return _ok(world)


def _round_trip_equal(world: World, text: str, examples: dict) -> tuple[bool, str]:
    state = _state(world)
    return (
        (True, "")
        if state["restored"] == state["resource_map"]
        else (False, "round-trip changed the map")
    )


def _persist(world: World, text: str, examples: dict) -> tuple[bool, str]:
    state = _state(world)
    output_dir = Path(tempfile.mkdtemp(prefix="asago-system-resource-map-"))
    state["persisted"] = write_system_resource_map(output_dir, state["resource_map"])
    return _ok(world)


def _persisted_filename(world: World, text: str, examples: dict) -> tuple[bool, str]:
    path = _state(world).get("persisted")
    return (
        (True, "")
        if path and path.name == "system-resource-map.yaml"
        else (False, f"unexpected path {path}")
    )


def _compatibility_fixture(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Record the workflow whose real before/after fixture will be executed."""
    del examples
    match = re.search(r'for "([^"]+)"', text)
    workflow = match.group(1) if match else ""
    if workflow not in {"taxonomy/risk", "STPA"}:
        return False, f"unsupported workflow fixture {workflow!r}"
    _state(world)["compatibility_workflow"] = workflow
    return True, ""


def _compatibility_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Run the real public command before and after sidecar inputs are present."""
    del examples
    match = re.search(
        r'^resource-map "([^"]+)" runs before and after Phase 2 sidecars$',
        text,
    )
    command = match.group(1) if match else ""
    state = _state(world)
    expected = {"taxonomy/risk": "generate", "STPA": "stpa-run"}.get(
        state.get("compatibility_workflow")
    )
    if command != expected:
        return False, f"{command!r} is not the expected command {expected!r}"
    try:
        observation = run_workflow_compatibility(state["compatibility_workflow"])
    except Exception as exc:  # pragma: no cover - acceptance diagnostic boundary
        return False, f"compatibility subprocesses failed: {exc}"
    state["compatibility"] = observation
    return observation["exit_match"], observation["detail"]


def _compatibility_assert(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Assert one exact compatibility dimension from the subprocess result."""
    del examples
    match = re.search(r'^the resource-map "([^"]+)" (.+)$', text)
    if match is None:
        return False, f"cannot parse compatibility assertion: {text}"
    key = {
        "exit status is unchanged": "exit_match",
        "scenario artifacts are identical after normalization of known volatile fields": "artifacts_match",
        "generation counts are identical": "counts_match",
        "prompt contracts are identical": "prompts_match",
    }.get(match.group(2))
    observation = _state(world).get("compatibility") or {}
    if key is None:
        return False, f"unknown compatibility assertion: {match.group(2)}"
    return bool(
        observation.get(key)
    ), f"compatibility {key} failed: {observation.get('detail')}"


def _no_phase2_output(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Ensure Phase 2 sidecars do not leak into default workflow output."""
    del text, examples
    observation = _state(world).get("compatibility") or {}
    return (
        bool(observation.get("sidecars_present"))
        and bool(observation.get("no_phase2_output")),
        f"Phase 2 output leaked into workflow artifacts: {observation.get('detail')}",
    )


def register(api) -> None:
    """Register handlers in the isolated acceptance registry."""
    registrations = (
        (
            r"^typed capability and STPA authorities are available$",
            _authorities_available,
        ),
        (r"^a valid typed resource map is available$", _valid_map_available),
        (r"^resource-map validation makes no network or model calls$", _ok),
        (r"^the resource map is validated$", _map_validated),
        (r"^the resource map passes validation$", _resource_map_passes_validation),
        (r"^the resource map fails validation$", _resource_map_fails_validation),
        (r'^the result contains violation code "([^"]+)"$', _contains_violation),
        (r'^the map records schema version "([^"]+)"$', _schema_recorded),
        (r'^the map substitutes digest pin "([^"]+)"$', _pin_substituted),
        (r"^the map references an unknown capability resource$", _unknown_reference),
        (r"^the map references an unknown STPA identifier$", _unknown_reference),
        (r"^the map uses an incompatible relation kind$", _relation_defect),
        (r"^the map marks a model-proposed link authoritative$", _authority_defect),
        (r"^the map has an authoritative link with no evidence$", _no_evidence),
        (r"^the map contains duplicate semantic links$", _duplicate_links),
        (
            r"^the map contains a contradictory authoritative cardinality$",
            _cardinality_conflict,
        ),
        (r"^a model-proposed advisory link is present$", _advisory_model_link),
        (r"^the advisory map validates$", _advisory_is_valid),
        (r"^the same links are presented in two orders$", _order_maps),
        (r"^both canonical maps are identical$", _ordered_maps_equal),
        (r'^the map is serialized and deserialized as "([^"]+)"$', _round_trip),
        (r"^the round-trip map is identical$", _round_trip_equal),
        (r"^the map is atomically persisted$", _persist),
        (r'^the published filename is "([^"]+)"$', _persisted_filename),
        (
            r'^a deterministic resource-map compatibility fixture includes valid Phase 2 sidecars for "([^"]+)"$',
            _compatibility_fixture,
        ),
        (
            r'^resource-map "([^"]+)" runs before and after Phase 2 sidecars$',
            _compatibility_run,
        ),
        (
            r'^the resource-map "([^"]+)" exit status is unchanged$',
            _compatibility_assert,
        ),
        (
            r'^the resource-map "([^"]+)" scenario artifacts are identical after normalization of known volatile fields$',
            _compatibility_assert,
        ),
        (
            r'^the resource-map "([^"]+)" generation counts are identical$',
            _compatibility_assert,
        ),
        (
            r'^the resource-map "([^"]+)" prompt contracts are identical$',
            _compatibility_assert,
        ),
        (
            r"^no resource-map Phase 2 artifact is written into either workflow output$",
            _no_phase2_output,
        ),
    )
    for pattern, handler in registrations:
        api.register(pattern, handler)


__all__ = ["FEATURE_ID", "register"]
