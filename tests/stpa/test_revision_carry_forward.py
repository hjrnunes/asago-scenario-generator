"""A restated responsibility borrows context only for elements it already had."""

from __future__ import annotations

from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ElementRef,
    FeedbackChannel,
    FeedbackSourceKind,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
)
from asago_scenario_generator.stpa.system_model.critic import _revised_responsibility

_TARGET = ElementRef(type=ReferenceType.controlled_process, id="CP-1")


def _original() -> Responsibility:
    return Responsibility(
        resp_id="RESP-1",
        description="Move pallets",
        process_model_parts=[
            ProcessModelPart(
                pm_id="PM-1-1",
                description="Bay state",
                values=["clear", "occupied"],
                evidence_refs=["state:bays.status"],
            )
        ],
        control_actions=[
            ControlAction(
                ca_id="CA-1-1",
                description="Lift a pallet",
                target=_TARGET,
                operation="lift_pallet",
                process_model_refs=["PM-1-1"],
            )
        ],
        feedback_channels=[
            FeedbackChannel(
                fb_id="FB-1-1",
                description="Operator request",
                updates="PM-1-1",
                source=_TARGET,
                source_kind=FeedbackSourceKind.user_message,
            )
        ],
    )


def test_new_elements_keep_their_own_context_beside_restated_ones() -> None:
    replacement = Responsibility(
        resp_id="RESP-1",
        description="Move pallets",
        process_model_parts=[
            ProcessModelPart(pm_id="PM-1-1", description="Bay state"),
            ProcessModelPart(pm_id="PM-1-2", description="Load weight"),
        ],
        control_actions=[
            ControlAction(ca_id="CA-1-1", description="Lift a pallet", target=_TARGET),
            ControlAction(ca_id="CA-1-2", description="Weigh a pallet", target=_TARGET),
        ],
        feedback_channels=[
            FeedbackChannel(
                fb_id="FB-1-1",
                description="Operator request",
                updates="PM-1-1",
                source=_TARGET,
                source_kind=FeedbackSourceKind.operation_result,
            ),
            FeedbackChannel(
                fb_id="FB-1-2",
                description="Scale reading",
                updates="PM-1-2",
                source=_TARGET,
            ),
        ],
    )

    revised = _revised_responsibility(_original(), replacement)

    pms = {pm.pm_id: pm for pm in revised.process_model_parts}
    assert pms["PM-1-1"].values == ["clear", "occupied"]
    assert (pms["PM-1-2"].values, pms["PM-1-2"].evidence_refs) == ([], [])
    cas = {ca.ca_id: ca for ca in revised.control_actions}
    assert (cas["CA-1-1"].operation, cas["CA-1-1"].process_model_refs) == (
        "lift_pallet",
        ["PM-1-1"],
    )
    assert (cas["CA-1-2"].operation, cas["CA-1-2"].process_model_refs) == (None, [])
    kinds = {fb.fb_id: fb.source_kind for fb in revised.feedback_channels}
    assert kinds == {
        "FB-1-1": FeedbackSourceKind.operation_result,
        "FB-1-2": None,
    }
