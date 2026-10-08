"""Tests for STPA execution contracts, target profiles, and environment bases."""

from __future__ import annotations

import pytest

from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionTargetProfile,
    McpToolObservation,
    ProfileBasis,
    SimulationBehavior,
    TargetProfileResource,
)
from tests.helpers.execution_classification import (
    _simulation_profile,
    _simulation_resource,
    _target_profile,
)


def _profile_update(
    profile: ExecutionTargetProfile, **updates
) -> ExecutionTargetProfile:
    payload = profile.model_dump(mode="json", exclude={"semantic_digest"})
    if updates.get("basis") in {"simulation", ProfileBasis.simulation}:
        target_id = updates.pop("target_id", profile.target_id)
        updates.pop("environment_id", None)
        payload.update(
            {
                "target_id": target_id,
                "basis": "simulation",
                "source_protocol": "simulation",
                "inventory_authority": None,
                "inventory_completeness": "unknown",
                "source_inventory_digest": None,
                "discovery_provenance": None,
                "inventory": None,
                "interpretations": (),
            }
        )
    payload.update(updates)
    return ExecutionTargetProfile.model_validate(payload)


def test_target_profile_digest_is_content_addressed() -> None:
    profile = _target_profile()
    assert profile.semantic_digest == profile.compute_semantic_digest()
    with pytest.raises(ValueError, match="semantic_digest"):
        ExecutionTargetProfile.model_validate(
            profile.model_dump(mode="json") | {"semantic_digest": "0" * 64}
        )


def test_profile_resource_requires_unique_semantic_operations() -> None:
    base = _target_profile().resources[0]
    duplicate = base.operations[0].model_copy(update={"operation_id": "retrieve-2"})
    payload = base.model_dump(mode="python")
    payload["operations"] = (base.operations[0], duplicate)
    with pytest.raises(ValueError, match="exactly one operation"):
        TargetProfileResource(**payload)


def test_simulation_profile_requires_behavior_for_every_resource() -> None:
    resource = _simulation_resource().model_copy(update={"simulation_behavior": None})
    with pytest.raises(ValueError, match="simulation_behavior"):
        _simulation_profile((resource,))


def test_target_profile_rejects_simulation_behavior() -> None:
    resource = (
        _target_profile()
        .resources[0]
        .model_copy(
            update={
                "simulation_behavior": SimulationBehavior(
                    inputs={"content": "fixture"},
                    outputs={"content_reaches_model_context": True},
                    observation_points=("model_context",),
                )
            }
        )
    )
    with pytest.raises(ValueError, match="MCP resources"):
        _profile_update(_target_profile(resources=(resource,)))


@pytest.mark.parametrize("properties", (None, [], "query"))
def test_input_schema_rejects_non_mapping_properties_before_names_derive(
    properties: object,
) -> None:
    schema = {"type": "object", "properties": properties}
    with pytest.raises(ValueError, match="not a valid JSON Schema"):
        McpToolObservation(
            name="lookup",
            source_observation_sha256="1" * 64,
            input_schema=schema,
        )
    payload = _target_profile().resources[0].model_dump(mode="json")
    payload["input_schema"] = schema
    with pytest.raises(ValueError, match="not a valid JSON Schema"):
        TargetProfileResource.model_validate(payload)


def test_reviewed_resource_requires_evidence() -> None:
    resource = _target_profile().resources[0]
    payload = resource.model_dump(mode="python")
    payload["evidence_refs"] = ()
    with pytest.raises(ValueError, match="evidence_refs"):
        TargetProfileResource(**payload)


@pytest.mark.parametrize(
    ("updates", "message"),
    (
        ({"basis": "target"}, "require basis=simulation"),
        ({"inventory_authority": "observed"}, "cannot claim observed inventory"),
        ({"source_inventory_digest": "0" * 64}, "source_inventory_digest"),
        (
            {
                "discovery_provenance": {
                    "scanner_id": "s",
                    "interpreter_id": "i",
                    "verifier_id": "v",
                }
            },
            "discovery_provenance",
        ),
        (
            {
                "inventory": {
                    "target_id": "sim-1",
                    "authorization_scope_id": "fixture-scope",
                    "tools": (),
                }
            },
            "cannot carry an MCP inventory",
        ),
        ({"inventory_completeness": "observed_complete"}, "unknown inventory"),
        (
            {
                "interpretations": (
                    {
                        "resource_id": "sim:retrieve-1",
                        "tool_name": "retrieve-1",
                        "disposition": "supported",
                        "evidence_refs": ("simulation:sim:retrieve-1",),
                        "rationale": "fixture interpretation",
                    },
                )
            },
            "cannot carry MCP interpretations",
        ),
    ),
)
def test_simulation_profile_rejects_observed_mcp_claims(
    updates: dict, message: str
) -> None:
    payload = _simulation_profile().model_dump(mode="json", exclude={"semantic_digest"})
    payload.update(updates)
    with pytest.raises(ValueError, match=message):
        ExecutionTargetProfile.model_validate(payload)


@pytest.mark.parametrize(
    ("updates", "message"),
    (
        ({"resource_kind": "integration"}, "only valid for tool resources"),
        ({"target_id": None}, "require target_id"),
        ({"surfaces": ("tool_call",)}, "tool_call and tool_result surfaces"),
        ({"tool_name": "retrieve-2"}, "operation_id must equal tool_name"),
        (
            {
                "operations": (
                    {"operation_id": "retrieve-1", "semantic_operation": "x"},
                )
            },
            "semantic_operation must equal",
        ),
        (
            {
                "operations": (
                    {
                        "operation_id": "retrieve-1",
                        "semantic_operation": "retrieve-1",
                        "argument_names": ("query",),
                    },
                )
            },
            "argument_names must match input schema",
        ),
        (
            {
                "input_schema": {
                    "type": "object",
                    "properties": {"query": {"type": "string"}},
                },
                "argument_names": ("other",),
            },
            "argument_names must match input_schema properties",
        ),
    ),
)
def test_mcp_profile_resource_rejects_inexact_tool_identity(
    updates: dict, message: str
) -> None:
    payload = _target_profile().resources[0].model_dump(mode="json")
    payload.update(updates)
    with pytest.raises(ValueError, match=message):
        TargetProfileResource.model_validate(payload)


def test_profile_resource_derives_argument_names_from_schema() -> None:
    payload = _simulation_resource().model_dump(mode="json")
    payload["input_schema"] = {
        "type": "object",
        "properties": {"b": {"type": "string"}, "a": {"type": "string"}},
    }
    resource = TargetProfileResource.model_validate(payload)
    assert resource.argument_names == ("a", "b")
    payload["input_schema"] = {"type": "object"}
    payload["argument_names"] = ("z", "y")
    assert TargetProfileResource.model_validate(payload).argument_names == ("y", "z")
