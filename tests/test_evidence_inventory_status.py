"""The published evidence-model status of the run's inventories.

The operation inventory follows the execution target profile; contradictory
qualification facts publish every reading. These tests pin the deterministic
evidence the synthesis manifest publishes.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from asago_scenario_generator.pipeline.evidence_inventory import (
    CONFLICT_MARKING,
    classify_evidence_inventory,
    conflicting_fact_readings,
)
from asago_scenario_generator.pipeline.obligation_contracts import (
    QualificationFactsInput,
)


def test_published_inventory_status_covers_operations_only() -> None:
    """The derived profile's tool inventory is constant, so it is not published."""
    status = classify_evidence_inventory(execution_target_profile=None)

    assert status.model_dump(mode="json") == {
        "operation_inventory_status": "unknown",
        "operation_inventory_count": None,
    }


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

    without_target = classify_evidence_inventory(execution_target_profile=None)
    with_target = classify_evidence_inventory(
        execution_target_profile=SimpleNamespace(resources=(resource,)),
    )

    assert without_target.operation_inventory_status == "unknown"
    assert with_target.operation_inventory_status == "supplied"
    assert with_target.operation_inventory_count == 1


def _reference(fact_id: str, value_type: str) -> dict[str, Any]:
    return {
        "namespace": "profile",
        "fact_id": fact_id,
        "value_type": value_type,
        "property_path": [],
    }


def test_contradictory_facts_publish_every_reading_under_the_conflict_marking() -> None:
    """Each contradictory fact keeps all readings and sources; none is adopted.

    A fact marked contradictory without retained readings still appears with
    the marking and no invented value; unambiguous facts never appear.
    """
    facts = QualificationFactsInput.model_validate(
        [
            {
                "fact": _reference("payments_enabled", "boolean"),
                "status": "contradictory",
                "readings": [
                    {"value": True, "source": "profile-a"},
                    {"value": False, "source": "profile-b"},
                ],
            },
            {
                "fact": _reference("mode", "string"),
                "status": "present",
                "value": "active",
            },
            {"fact": _reference("tier", "string"), "status": "contradictory"},
        ]
    )

    assert conflicting_fact_readings(facts) == [
        {
            "fact": _reference("payments_enabled", "boolean"),
            "status": "contradictory",
            "readings": [
                {"value": True, "source": "profile-a"},
                {"value": False, "source": "profile-b"},
            ],
            "marking": CONFLICT_MARKING,
        },
        {
            "fact": _reference("tier", "string"),
            "status": "contradictory",
            "readings": [],
            "marking": CONFLICT_MARKING,
        },
    ]


def test_runs_without_qualification_facts_publish_no_conflicts() -> None:
    assert conflicting_fact_readings(None) == []
