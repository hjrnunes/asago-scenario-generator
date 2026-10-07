"""Target-profile fixtures for the shape step tests."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping

from asago_scenario_generator.models.canonical import canonical_json_bytes
from asago_scenario_generator.stpa.models.execution_classification import (
    DiscoveryProvenance,
    ExecutionResourceKind,
    ExecutionTargetProfile,
    InventoryAuthority,
    InventoryCompleteness,
    McpInventoryObservation,
    McpToolObservation,
    ProfileBasis,
    SemanticAuthority,
    SourceProtocol,
    TargetProfileOperation,
    TargetProfileResource,
)

_TARGET = "shape-target"
_SCHEMA = {"type": "object", "properties": {}, "additionalProperties": False}


def _tool(name: str) -> McpToolObservation:
    payload = {
        "name": name,
        "description": f"Operation {name}.",
        "input_schema": _SCHEMA,
        "output_schema": "opaque",
    }
    digest = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    return McpToolObservation(source_observation_sha256=digest, **payload)


def _resource(name: str, influence: str) -> TargetProfileResource:
    return TargetProfileResource(
        resource_id=f"mcp:{_TARGET}:{name}",
        resource_kind=ExecutionResourceKind.tool,
        target_id=_TARGET,
        tool_name=name,
        description=f"Operation {name}.",
        input_schema=_SCHEMA,
        output_schema="opaque",
        attacker_influence=influence,
        surfaces=("tool_call", "tool_result"),
        operations=(
            TargetProfileOperation(
                operation_id=name,
                semantic_operation=name,
                observable_properties=("content_reaches_model_context",),
            ),
        ),
        evidence_refs=(f"inventory:tool:{name}",),
    )


def profile_with_influence(
    influence_by_tool: Mapping[str, str],
) -> ExecutionTargetProfile:
    """Build an observed MCP profile whose tools carry the given influence."""
    inventory = McpInventoryObservation(
        target_id=_TARGET,
        authorization_scope_id="shape-scope",
        tools=tuple(_tool(name) for name in influence_by_tool),
    )
    return ExecutionTargetProfile(
        target_id=_TARGET,
        authorization_scope_id="shape-scope",
        basis=ProfileBasis.target,
        inventory_authority=InventoryAuthority.observed,
        semantic_authority=SemanticAuthority.reviewed,
        inventory_completeness=InventoryCompleteness.observed_complete,
        source_protocol=SourceProtocol.mcp,
        source_inventory_digest=inventory.semantic_digest,
        discovery_provenance=DiscoveryProvenance(
            scanner_id="fixture-scanner",
            interpreter_id="fixture-interpreter",
            verifier_id="fixture-verifier",
        ),
        inventory=inventory,
        resources=tuple(
            _resource(name, influence) for name, influence in influence_by_tool.items()
        ),
        interpretations=tuple(
            {
                "resource_id": f"mcp:{_TARGET}:{name}",
                "tool_name": name,
                "disposition": "supported",
                "evidence_refs": (f"inventory:tool:{name}:description",),
                "rationale": "fixture interpretation",
            }
            for name in influence_by_tool
        ),
    )
