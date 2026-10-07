"""Shared test builders moved out of test modules."""

from __future__ import annotations

import json
from asago_scenario_generator.stpa.models.execution_classification import (
    DiscoveryProvenance,
    ExecutionTargetProfile,
    ExecutionSurface,
    InventoryAuthority,
    InventoryCompleteness,
    McpInventoryObservation,
    McpToolObservation,
    ProfileBasis,
    SemanticAuthority,
    SourceProtocol,
    TargetProfileOperation,
    TargetProfileResource,
    TargetSemanticInterpretation,
    mcp_resource_id,
)
from asago_scenario_generator.stpa.scenario_prod.target_observations import (
    TargetObservation,
    TargetObservationSnapshot,
)


def _tool(name: str, description: str | None) -> McpToolObservation:
    return McpToolObservation(
        name=name,
        description=description,
        source_observation_sha256="1" * 64,
        input_schema={
            "type": "object",
            "properties": {"customer_id": {"type": "string"}},
        },
    )


def _profile(
    *,
    tools=("lookup_order", "process_refund", "escalate_to_human", "retrieve_policy"),
    interpretations=True,
) -> ExecutionTargetProfile:
    observations = tuple(_tool(name, f"Observed {name} tool") for name in tools)
    inventory = McpInventoryObservation(
        target_id="target:mini",
        authorization_scope_id="scope:test",
        tools=observations,
    )
    resources = tuple(
        TargetProfileResource(
            resource_id=mcp_resource_id("target:mini", tool.name),
            target_id="target:mini",
            tool_name=tool.name,
            description=tool.description,
            input_schema=tool.input_schema,
            surfaces=(ExecutionSurface.tool_call, ExecutionSurface.tool_result),
            operations=(
                TargetProfileOperation(
                    operation_id=tool.name,
                    semantic_operation=tool.name,
                    argument_names=("customer_id",),
                ),
            ),
            evidence_refs=(f"inventory:tool:{tool.name}",),
        )
        for tool in observations
    )
    interpretation_rows = ()
    if interpretations:
        interpretation_rows = tuple(
            TargetSemanticInterpretation(
                resource_id=resource.resource_id,
                tool_name=resource.tool_name,
                disposition="supported",
                likely_effect=(
                    "escalate" if resource.tool_name == "escalate_to_human" else "read"
                ),
                likely_state_effect="none",
                semantic_roles=(
                    ("text_search",) if resource.tool_name == "retrieve_policy" else ()
                ),
                evidence_refs=(f"inventory:tool:{resource.tool_name}",),
                rationale="typed test interpretation",
            )
            for resource in resources
        )
    return ExecutionTargetProfile(
        target_id="target:mini",
        authorization_scope_id="scope:test",
        basis=ProfileBasis.target,
        inventory_authority=InventoryAuthority.observed,
        semantic_authority=SemanticAuthority.inferred,
        inventory_completeness=InventoryCompleteness.observed_complete,
        source_protocol=SourceProtocol.mcp,
        source_inventory_digest=inventory.semantic_digest,
        discovery_provenance=DiscoveryProvenance(
            scanner_id="scanner:test",
            interpreter_id="interpreter:test",
            verifier_id="verifier:test",
        ),
        inventory=inventory,
        resources=resources,
        interpretations=interpretation_rows,
    )


def _observations() -> TargetObservationSnapshot:
    state = {"authenticated_customer_id": "CUST001", "orders": {}}
    return TargetObservationSnapshot.create(
        target_profile_digest=_profile().semantic_digest,
        observations=[
            TargetObservation(
                observation_ref="TARGET-STATE",
                kind="state",
                content_format="json",
                content=json.dumps(state),
            )
        ],
    )
