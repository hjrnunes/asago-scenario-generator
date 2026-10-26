"""Shared builders for the mechanism suggestion tests."""

from __future__ import annotations

from typing import Any

from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlledProcess,
    ControlStructure,
    CoordinationLink,
    CoordinationMechanism,
    FeedbackChannel,
    ProcessModelPart,
    Responsibility,
)

CP_REF = {"type": "controlled_process", "id": "CP-1"}
SELF_REF = {"type": "responsibility", "id": "RESP-1"}
ACTION_PATH = ("FB-1-1", "PM-1-1", "CA-1-1")
LINK_PATH = ("FB-1-1", "PM-1-1", "CL-1")


def suggestion_structure(
    *,
    source_kind: str = "user_message",
    source: dict[str, str] = CP_REF,
    authority: str | None = None,
    temporality: str | None = None,
) -> ControlStructure:
    """One controller whose untrusted channel feeds an action and a link."""
    channel: dict[str, Any] = {
        "fb_id": "FB-1-1",
        "description": "Requested refund amount",
        "updates": "PM-1-1",
        "source": source,
        "source_kind": source_kind,
    }
    if authority is not None:
        channel["authority_for_update"] = {
            "status": authority,
            "basis": f"The use case says the source is {authority}.",
        }
    return ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Handle refunds",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-1-1", description="Refund amount")
                ],
                control_actions=[
                    ControlAction(
                        ca_id="CA-1-1",
                        description="Refund",
                        target=CP_REF,
                        effect_kind="tool_call",
                        process_model_refs=["PM-1-1"],
                        temporality=temporality,
                    )
                ],
                feedback_channels=[FeedbackChannel.model_validate(channel)],
            ),
            Responsibility(
                resp_id="RESP-2",
                description="Approve refunds",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-2-1", description="Approval state")
                ],
            ),
        ],
        controlled_processes=[ControlledProcess(cp_id="CP-1", description="Chat")],
        coordination_links=[
            CoordinationLink(
                link_id="CL-1",
                source="RESP-1",
                target="RESP-2",
                shared_pm="PM-1-1",
                coordination_mechanism=CoordinationMechanism(
                    cm_id="CM-1", description="Pass amount", payload="amount"
                ),
                description="Controller 1 passes the refund amount on.",
            )
        ],
    )
