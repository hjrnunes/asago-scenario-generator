"""Synthetic Stage 5 target facts shaped like a live target-observations file.

The names are synthetic. The shape matches a real capture: one JSON state
observation with keyed record collections, a session identity and an empty
list, plus several read observations that carry ``source_arguments``.
"""

from __future__ import annotations

import json

from asago_scenario_generator.stpa.models.execution_classification import (
    DiscoveryProvenance,
    ExecutionSurface,
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
    TargetSemanticInterpretation,
    mcp_resource_id,
)
from asago_scenario_generator.stpa.scenario_prod.target_observations import (
    TargetObservation,
    TargetObservationSnapshot,
)

TOOLS: dict[str, tuple[str, ...]] = {
    "get_member": ("member_id",),
    "get_gadget": ("gadget_id",),
    "update_gadget": ("gadget_id", "note", "quantity"),
    "search_manual": ("query",),
    "schedule_service": ("plan_id", "service_date"),
    "open_ticket": ("summary", "gadget_id"),
}


def _schema(arguments: tuple[str, ...]) -> dict:
    return {
        "type": "object",
        "properties": {
            name: {"type": "number" if name == "quantity" else "string"}
            for name in arguments
        },
        "required": list(arguments),
    }


def realistic_profile() -> ExecutionTargetProfile:
    """Return a six-operation synthetic profile."""

    tools = tuple(
        McpToolObservation(
            name=name,
            description=f"Synthetic {name.replace('_', ' ')} operation.",
            source_observation_sha256="1" * 64,
            input_schema=_schema(arguments),
        )
        for name, arguments in TOOLS.items()
    )
    inventory = McpInventoryObservation(
        target_id="target:synthetic",
        authorization_scope_id="scope:synthetic",
        tools=tools,
    )
    resources = tuple(
        TargetProfileResource(
            resource_id=mcp_resource_id("target:synthetic", tool.name),
            target_id="target:synthetic",
            tool_name=tool.name,
            description=tool.description,
            input_schema=tool.input_schema,
            surfaces=(ExecutionSurface.tool_call, ExecutionSurface.tool_result),
            operations=(
                TargetProfileOperation(
                    operation_id=tool.name,
                    semantic_operation=tool.name,
                    argument_names=tuple(tool.input_schema["properties"]),
                ),
            ),
            evidence_refs=(f"inventory:tool:{tool.name}",),
        )
        for tool in tools
    )
    return ExecutionTargetProfile(
        target_id="target:synthetic",
        authorization_scope_id="scope:synthetic",
        basis=ProfileBasis.target,
        inventory_authority=InventoryAuthority.observed,
        semantic_authority=SemanticAuthority.inferred,
        inventory_completeness=InventoryCompleteness.observed_complete,
        source_protocol=SourceProtocol.mcp,
        source_inventory_digest=inventory.semantic_digest,
        discovery_provenance=DiscoveryProvenance(
            scanner_id="scanner:synthetic",
            interpreter_id="interpreter:synthetic",
            verifier_id="verifier:synthetic",
        ),
        inventory=inventory,
        resources=resources,
        interpretations=tuple(
            TargetSemanticInterpretation(
                resource_id=resource.resource_id,
                tool_name=resource.tool_name,
                disposition="supported",
                likely_effect="read",
                likely_state_effect="none",
                semantic_roles=(),
                evidence_refs=(f"inventory:tool:{resource.tool_name}",),
                rationale="synthetic interpretation",
            )
            for resource in resources
        ),
    )


def realistic_state() -> dict:
    """Return a state object with the size of a live capture."""

    gadgets = {
        f"G-{index}": {
            "owner_id": owner,
            "label": f"Gadget {index}",
            "vendor": f"Vendor {index % 3}",
            "list_price": price,
            "serviceable": index != 4,
            "balance_due": balance,
            "status": status,
        }
        for index, owner, price, balance, status in (
            (1, "M-1", 40.0, 40.0, "open"),
            (2, "M-9", 220.0, 220.0, "open"),
            (3, "M-1", 75.0, 75.0, "disputed"),
            (4, "M-1", 129.0, 80.0, "open"),
            (5, "M-2", 22.0, 22.0, "open"),
            (6, "M-1", 310.0, 0.0, "closed"),
        )
    }
    plans = {
        f"P-{index}": {
            "installment": amount,
            "next_service": date,
            "gadget_id": gadget,
            "status": "active",
        }
        for index, amount, date, gadget in (
            (1, 40.0, "2026-09-15", "G-1"),
            (2, 55.0, "2026-10-01", "G-2"),
            (3, 20.0, "2026-10-12", "G-4"),
        )
    }
    return {
        "session_member_id": "M-1",
        "tickets": [],
        "gadgets": gadgets,
        "plans": plans,
    }


def realistic_observations(
    profile: ExecutionTargetProfile,
) -> TargetObservationSnapshot:
    """Return one state observation and four reads with source arguments."""

    reads = [
        TargetObservation(
            observation_ref=f"TARGET-READ-00{index}",
            kind="read",
            source_name="search_manual",
            source_description="Search approved manual sections for a query.",
            source_arguments={"query": query},
            content_format="json",
            content=json.dumps(content, separators=(",", ":")),
        )
        for index, query, content in (
            (
                1,
                "service",
                {
                    "documents": [
                        {
                            "body": "Service is available within 14 days of "
                            "purchase when the gadget is unused.",
                            "doc_id": "MAN-SERVICE",
                            "title": "Service window",
                        }
                    ],
                    "status": "OK",
                },
            ),
            (2, "fees", {"documents": [], "status": "NO_MATCH"}),
            (3, "plans", {"documents": [], "status": "NO_MATCH"}),
            (4, "eligibility", {"documents": [], "status": "NO_MATCH"}),
        )
    ]
    return TargetObservationSnapshot.create(
        target_profile_digest=profile.semantic_digest,
        observations=(
            TargetObservation(
                observation_ref="TARGET-STATE",
                kind="state",
                content_format="json",
                content=json.dumps(realistic_state(), separators=(",", ":")),
            ),
            *reads,
        ),
    )
