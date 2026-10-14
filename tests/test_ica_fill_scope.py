"""An ICA fill request shows and accepts only references its slot may cite."""

from __future__ import annotations

from typing import Any

from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    ControlledProcess,
    CoordinationLink,
    CoordinationMechanism,
    ElementRef,
    FeedbackChannel,
    FeedbackSourceKind,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
    control_action_context_rows,
)
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    SynthesisSlotRequest,
)
from asago_scenario_generator.stpa.obligation_aware.provider import (
    ObligationAwareLLMAdapter,
)
from asago_scenario_generator.stpa.threat_enum.slot_creation import (
    SlotPlaceholder,
    create_slots,
)
from tests.helpers.obligation_aware import _controls, _loss_analysis
from tests.helpers.scripted_client import ScriptedClient

_PROCESS = ElementRef(type=ReferenceType.controlled_process, id="CP-1")


def _part(pm_id: str, description: str) -> ProcessModelPart:
    return ProcessModelPart(
        pm_id=pm_id, description=description, values=["valid", "stale"]
    )


def _structure() -> ControlStructure:
    """Two actions with their own context tables, and one coordination link."""
    return ControlStructure(
        controlled_processes=[
            ControlledProcess(cp_id="CP-1", description="Reservation store.")
        ],
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Retrieve reservation details.",
                process_model_parts=[
                    _part("PM-1-1", "The reservation status."),
                    _part("PM-1-2", "The guest ID of the reservation."),
                    _part("PM-1-3", "The host ID of the reservation."),
                ],
                control_actions=[
                    ControlAction(
                        ca_id="CA-1-1",
                        description="Read a reservation.",
                        target=_PROCESS,
                        process_model_refs=["PM-1-1"],
                    ),
                    ControlAction(
                        ca_id="CA-1-2",
                        description="Read a listing.",
                        target=_PROCESS,
                        process_model_refs=["PM-1-2"],
                    ),
                ],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1",
                        description="The reservation record.",
                        updates="PM-1-1",
                        source=_PROCESS,
                        source_kind=FeedbackSourceKind.operation_result,
                    )
                ],
            ),
            Responsibility(
                resp_id="RESP-2",
                description="Modify a booking.",
                process_model_parts=[_part("PM-2-1", "The requested change.")],
                control_actions=[
                    ControlAction(
                        ca_id="CA-2-1",
                        description="Modify a booking.",
                        target=_PROCESS,
                        process_model_refs=["PM-2-1"],
                    )
                ],
            ),
        ],
        coordination_links=[
            CoordinationLink(
                link_id="CL-1",
                source="RESP-1",
                target="RESP-2",
                shared_pm="PM-1-2",
                coordination_mechanism=CoordinationMechanism(
                    cm_id="CM-1",
                    description="Validate the reservation parties.",
                    payload="guest and host IDs",
                ),
                description=(
                    "RESP-1 provides the guest and host IDs (PM-1-2, PM-1-3) "
                    "that RESP-2 needs."
                ),
            )
        ],
    )


def _slot(action: str) -> SlotPlaceholder:
    return next(
        slot
        for slot in create_slots(_structure())
        if slot.control_action == action and slot.uca_type.value == "NOT_PROVIDED"
    )


def _request(slot: SlotPlaceholder) -> SynthesisSlotRequest:
    return SynthesisSlotRequest(
        target_id=slot.responsibility or slot.coordination_link or "",
        target_kind="responsibility" if slot.responsibility else "coordination_link",
        slots=(slot,),
        loss_analysis=_loss_analysis(),
        control_structure=_structure(),
        controls=_controls(),
    )


def _na_reply(slot_id: str) -> dict[str, Any]:
    return {
        "filled_slots": [
            {
                "slot_id": slot_id,
                "is_na": True,
                "na_rationale": "No complete structural property applies.",
                "findings": [],
                "consideration_results": [],
            }
        ]
    }


def _fill(slot: SlotPlaceholder, tmp_path) -> ScriptedClient:
    client = ScriptedClient([_na_reply(slot.slot_id)], model="fill-scope")
    ObligationAwareLLMAdapter(client, run_dir=tmp_path, controls=_controls()).fill(
        _request(slot)
    )
    return client


def _definition(schema: dict[str, Any], name: str) -> dict[str, Any]:
    """Return the one schema definition whose properties include *name*."""
    found = [
        item
        for item in schema.get("$defs", {}).values()
        if name in item.get("properties", {})
    ]
    assert len(found) == 1, name
    return found[0]["properties"][name]


def _string_choices(field: dict[str, Any]) -> list[str] | None:
    options = field.get("anyOf", [field])
    return next((option["enum"] for option in options if "enum" in option), None)


def _schema(client: ScriptedClient) -> dict[str, Any]:
    return client.calls[0]["response_format"].model_json_schema()


def _rows(action: str) -> list[str]:
    return [row.row_id for row in control_action_context_rows(_structure(), action)]


def test_the_fill_index_shows_only_the_rows_of_the_slots_action(tmp_path) -> None:
    client = _fill(_slot("CA-1-1"), tmp_path)

    prompt = client.prompts[0]
    assert all(row in prompt for row in _rows("CA-1-1"))
    assert not any(row in prompt for row in _rows("CA-1-2"))


def test_the_fill_schema_enumerates_the_slot_rows_and_its_owners_ids(
    tmp_path,
) -> None:
    slot = _slot("CA-1-1")
    schema = _schema(_fill(slot, tmp_path))

    assert _string_choices(_definition(schema, "slot_id")) == [slot.slot_id]
    assert _string_choices(_definition(schema, "context_row")) == _rows("CA-1-1")
    assert _definition(schema, "process_model_refs")["items"]["enum"] == [
        "PM-1-1",
        "PM-1-2",
        "PM-1-3",
    ]
    assert _definition(schema, "feedback_refs")["items"]["enum"] == ["FB-1-1"]


def test_a_coordination_slot_may_cite_only_the_shared_part(tmp_path) -> None:
    client = _fill(_slot("CM-1"), tmp_path)
    schema = _schema(client)

    assert _definition(schema, "process_model_refs")["items"]["enum"] == ["PM-1-2"]
    assert _definition(schema, "feedback_refs")["maxItems"] == 0
    assert _string_choices(_definition(schema, "context_row")) is None
    system = client.calls[0]["system_prompt"]
    assert "only its path's `shared_process_model`" in " ".join(system.split())
