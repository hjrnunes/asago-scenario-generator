"""The published evidence-model status of the supplied inventories.

A missing tool/operation inventory is recorded as unknown — never as empty —
and an explicitly supplied empty inventory is recorded distinctly. These
tests pin the deterministic classification the synthesis manifest publishes.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.pipeline.evidence_inventory import (
    classify_evidence_inventory,
)


def _profile(tool_inventory: Any) -> CapabilityProfile:
    payload: dict[str, Any] = {
        "zones_active": ["input", "reasoning"],
        "entry_points": [
            {"name": "User chat", "direction": "input", "controllability": "direct"},
        ],
        "confidence": "medium",
        "kc_subcodes": ["KC1.1"],
    }
    if tool_inventory is not None:
        payload["tool_inventory"] = tool_inventory
    return CapabilityProfile.model_validate(payload)


def test_no_supplied_profile_records_the_inventory_as_unknown() -> None:
    """A narrative-only run supplies no inventory; unknown is never empty."""
    status = classify_evidence_inventory(
        profile_supplied=False,
        capability_profile=_profile([]),
        execution_target_profile=None,
    )

    assert status.tool_inventory_status == "unknown"
    assert status.tool_inventory_count is None


def test_derived_profile_never_establishes_an_empty_inventory() -> None:
    """Stage 1 inference establishes presence, never absence.

    A derived (inferred) profile with no observed tools is still unknown:
    inference cannot have established that the target has no tools.
    """
    status = classify_evidence_inventory(
        profile_supplied=False,
        capability_profile=_profile([]),
        execution_target_profile=None,
    )

    assert status.tool_inventory_status == "unknown"
    assert "inference" in status.note


def test_supplied_profile_without_an_inventory_is_unknown() -> None:
    """A supplied profile may declare its tool inventory unknown (null)."""
    status = classify_evidence_inventory(
        profile_supplied=True,
        capability_profile=_profile(None),
        execution_target_profile=None,
    )

    assert status.tool_inventory_status == "unknown"


def test_supplied_empty_inventory_is_recorded_distinctly() -> None:
    """An explicitly supplied empty inventory is not unknown."""
    status = classify_evidence_inventory(
        profile_supplied=True,
        capability_profile=_profile([]),
        execution_target_profile=None,
    )

    assert status.tool_inventory_status == "explicitly_empty"
    assert status.tool_inventory_count == 0


def test_supplied_nonempty_inventory_is_recorded_with_its_count() -> None:
    """A supplied inventory records its exact size."""
    inventory = [
        {"name": "lookup_order", "description": "Look up an order"},
        {"name": "process_refund", "description": "Process a refund"},
    ]
    status = classify_evidence_inventory(
        profile_supplied=True,
        capability_profile=_profile(inventory),
        execution_target_profile=None,
    )

    assert status.tool_inventory_status == "supplied"
    assert status.tool_inventory_count == 2


def test_operation_inventory_follows_the_target_profile() -> None:
    """Operations are unknown without a target profile and counted with one."""
    from asago_scenario_generator.stpa.models.execution_classification import (
        ExecutionSurface,
        McpToolObservation,
        TargetProfileOperation,
        TargetProfileResource,
        mcp_resource_id,
    )

    tool = McpToolObservation(
        name="commit_to_ehr",
        description="Commit a draft to the EHR",
        source_observation_sha256="1" * 64,
        input_schema={"type": "object", "properties": {"draft_id": {"type": "string"}}},
    )
    resource = TargetProfileResource(
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
                argument_names=("draft_id",),
            ),
        ),
        evidence_refs=("inventory:tool:commit_to_ehr",),
    )

    without_target = classify_evidence_inventory(
        profile_supplied=True,
        capability_profile=_profile([]),
        execution_target_profile=None,
    )
    with_target = classify_evidence_inventory(
        profile_supplied=True,
        capability_profile=_profile([]),
        execution_target_profile=SimpleNamespace(resources=(resource,)),
    )

    assert without_target.operation_inventory_status == "unknown"
    assert with_target.operation_inventory_status == "supplied"
    assert with_target.operation_inventory_count == 1
