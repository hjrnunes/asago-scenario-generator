"""Shared test builders moved out of test modules."""

from __future__ import annotations

from asago_scenario_generator.stpa.models.execution_classification import (
    SimulationBehavior,
)

from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionResourceKind,
    ExecutionTargetProfile,
    DiscoveryProvenance,
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


def _target_profile(
    *,
    inventory_completeness: InventoryCompleteness = InventoryCompleteness.observed_complete,
    resources: tuple[TargetProfileResource, ...] | None = None,
    basis: ProfileBasis = ProfileBasis.target,
) -> ExecutionTargetProfile:
    resources = resources or (
        TargetProfileResource(
            resource_id="mcp:target-1:retrieve-1",
            resource_kind=ExecutionResourceKind.tool,
            target_id="target-1",
            tool_name="retrieve-1",
            description="Retrieve content for the model context.",
            input_schema={
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
            output_schema="opaque",
            role_ids=("attacker_influenced_content_source",),
            structural_refs=("PM-1-1",),
            attacker_influence="indirect",
            surfaces=("tool_call", "tool_result"),
            operations=(
                TargetProfileOperation(
                    operation_id="retrieve-1",
                    semantic_operation="retrieve-1",
                    observable_properties=("content_reaches_model_context",),
                ),
            ),
            evidence_refs=("inventory:tool:retrieve-1",),
        ),
    )
    tool = McpToolObservation(
        name="retrieve-1",
        source_observation_sha256=(
            "3458984c2818544369783de6780da78f10f3c60be6e2c07dcd2dc6c585108a3a"
        ),
        description="Retrieve content for the model context.",
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        output_schema="opaque",
    )
    inventory = McpInventoryObservation(
        target_id="target-1",
        authorization_scope_id="scope-1",
        tools=(tool,),
    )
    return ExecutionTargetProfile(
        target_id="target-1",
        authorization_scope_id="scope-1",
        basis=basis,
        inventory_authority=InventoryAuthority.observed,
        semantic_authority=SemanticAuthority.reviewed,
        inventory_completeness=inventory_completeness,
        source_protocol=SourceProtocol.mcp,
        source_inventory_digest=inventory.semantic_digest,
        discovery_provenance=DiscoveryProvenance(
            scanner_id="fixture-scanner",
            interpreter_id="fixture-interpreter",
            verifier_id="fixture-verifier",
        ),
        inventory=inventory,
        resources=resources,
        interpretations=(
            {
                "resource_id": "mcp:target-1:retrieve-1",
                "tool_name": "retrieve-1",
                "disposition": "supported",
                "evidence_refs": ("inventory:tool:retrieve-1:description",),
                "rationale": "fixture interpretation",
            },
        ),
    )


def _simulation_resource(
    resource_id: str = "sim:retrieve-1",
) -> TargetProfileResource:
    return TargetProfileResource(
        resource_id=resource_id,
        resource_kind=ExecutionResourceKind.tool,
        description="Simulate content retrieval.",
        input_schema={"type": "object", "properties": {}},
        role_ids=("attacker_influenced_content_source",),
        structural_refs=("PM-1-1",),
        attacker_influence="indirect",
        surfaces=("tool_result",),
        operations=(
            TargetProfileOperation(
                operation_id="retrieve-1",
                semantic_operation="retrieve-1",
                observable_properties=("content_reaches_model_context",),
            ),
        ),
        evidence_refs=(f"simulation:{resource_id}",),
        simulation_behavior=SimulationBehavior(
            inputs={"content": "fixture"},
            outputs={"content_reaches_model_context": True},
            emitted_events=("content_retrieved",),
            observation_points=("model_context",),
        ),
    )


def _simulation_profile(
    resources: tuple[TargetProfileResource, ...] | None = None,
    *,
    semantic_authority: SemanticAuthority = SemanticAuthority.reviewed,
) -> ExecutionTargetProfile:
    return ExecutionTargetProfile(
        target_id="sim-1",
        authorization_scope_id="fixture-scope",
        basis=ProfileBasis.simulation,
        inventory_authority=None,
        semantic_authority=semantic_authority,
        inventory_completeness=InventoryCompleteness.unknown,
        source_protocol=SourceProtocol.simulation,
        resources=resources or (_simulation_resource(),),
    )
