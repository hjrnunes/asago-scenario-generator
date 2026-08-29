"""Shared typed fixtures for the normative system-resource-map tests."""

from __future__ import annotations

from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.models.system_resource_map import (
    ResourceLink,
    SystemResourceMap,
    compute_control_structure_digest,
    compute_resource_map_semantic_digest,
)
from asago_scenario_generator.pipeline.projection_contracts import (
    CapabilityFactSnapshot,
    capture_capability_snapshot,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    ControlledProcess,
    ProcessModelPart,
    Responsibility,
)

ENTRY_POINT = "ep:v1:" + "a" * 32
TOOL = "tool:v1:21063c1075f97711533173103b1b40da"


def make_snapshot() -> CapabilityFactSnapshot:
    """Return one complete typed capability snapshot for tests."""
    profile = CapabilityProfile.model_validate(
        {
            "zones_active": ["input", "reasoning", "tool_execution"],
            "entry_points": [
                {
                    "name": "User input",
                    "entry_point_type": "user_input",
                    "direction": "input",
                    "controllability": "direct",
                    "ingress_zone": "input",
                    "entry_point_id": ENTRY_POINT,
                }
            ],
            "confidence": "high",
            "kc_subcodes": ["KC1.1", "KC5.3"],
            "tool_inventory": [
                {
                    "name": "Payment API",
                    "description": "Mutates payments",
                    "tool_id": TOOL,
                }
            ],
        }
    )
    return capture_capability_snapshot(profile)


def make_control_structure() -> ControlStructure:
    """Return one minimal typed STPA control structure for tests."""
    return ControlStructure(
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


def make_link(
    *,
    link_id: str = "srm:v1:1",
    capability_resource_ref: dict[str, str] | None = None,
    control_structure_ref: dict[str, str] | None = None,
    relation_kind: str = "acts_on",
    provenance: str = "operator_declared",
    evidence_refs: tuple[str, ...] = ("review:1",),
    confidence: float | None = 0.9,
    authority_status: str = "authoritative",
) -> ResourceLink:
    """Build one typed link while allowing tests to target one rule."""
    return ResourceLink(
        link_id=link_id,
        capability_resource_ref=capability_resource_ref
        or {"kind": "tool", "tool_id": TOOL},
        control_structure_ref=control_structure_ref or {"kind": "CA", "id": "CA-1-1"},
        relation_kind=relation_kind,
        provenance=provenance,
        evidence_refs=evidence_refs,
        confidence=confidence,
        authority_status=authority_status,
    )


def make_map(
    *links: ResourceLink,
    snapshot: CapabilityFactSnapshot | None = None,
    control: ControlStructure | None = None,
    capability_digest: str | None = None,
    control_digest: str | None = None,
) -> SystemResourceMap:
    """Build a content-addressed map for the supplied typed authorities."""
    snapshot = snapshot or make_snapshot()
    control = control or make_control_structure()
    selected_links = tuple(links or (make_link(),))
    capability_digest = capability_digest or snapshot.snapshot_digest
    control_digest = control_digest or compute_control_structure_digest(control)
    semantic_digest = compute_resource_map_semantic_digest(
        schema_version="system-resource-map-v1",
        capability_snapshot_digest=capability_digest,
        control_structure_digest=control_digest,
        links=selected_links,
    )
    return SystemResourceMap(
        schema_version="system-resource-map-v1",
        semantic_digest=semantic_digest,
        capability_snapshot_digest=capability_digest,
        control_structure_digest=control_digest,
        links=selected_links,
    )
