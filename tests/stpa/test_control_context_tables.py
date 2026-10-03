"""Process-model variables, context tables, and feedback trust."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from asago_scenario_generator.stpa.models.control_structure import (
    MAX_CONTEXT_ROWS_PER_ACTION,
    ControlAction,
    ControlStructure,
    ControlledProcess,
    ElementRef,
    FeedbackChannel,
    FeedbackSourceKind,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
    control_action_context_rows,
)
from asago_scenario_generator.stpa.obligation_aware.slot_filling import (
    _finding_context,
)
from asago_scenario_generator.stpa.system_model.critic import (
    _carry_forward_context,
)

_TARGET = ElementRef(type=ReferenceType.controlled_process, id="CP-1")


def _responsibility(
    resp_id: str,
    *,
    pm_values: dict[str, list[str]],
    refs: list[str],
    source_kind: FeedbackSourceKind | None = None,
) -> Responsibility:
    number = resp_id.removeprefix("RESP-")
    return Responsibility(
        resp_id=resp_id,
        description="Move pallets",
        process_model_parts=[
            ProcessModelPart(pm_id=pm_id, description=pm_id, values=values)
            for pm_id, values in pm_values.items()
        ],
        control_actions=[
            ControlAction(
                ca_id=f"CA-{number}-1",
                description="Lift a pallet",
                target=_TARGET,
                operation="lift_pallet",
                process_model_refs=refs,
            )
        ],
        feedback_channels=[
            FeedbackChannel(
                fb_id=f"FB-{number}-1",
                description="Operator request",
                updates=next(iter(pm_values)),
                source=_TARGET,
                source_kind=source_kind,
            )
        ],
    )


def _structure(*responsibilities: Responsibility) -> ControlStructure:
    return ControlStructure(
        controlled_processes=[ControlledProcess(cp_id="CP-1", description="Forklift")],
        responsibilities=list(responsibilities),
    )


def test_context_rows_are_the_ordered_product_of_referenced_values() -> None:
    structure = _structure(
        _responsibility(
            "RESP-1",
            pm_values={
                "PM-1-1": ["clear", "occupied"],
                "PM-1-2": ["rated", "overweight"],
                "PM-1-3": [],
            },
            refs=["PM-1-1", "PM-1-2", "PM-1-3"],
        )
    )

    rows = control_action_context_rows(structure, "CA-1-1")

    assert [row.row_id for row in rows] == [f"CA-1-1:ctx-{n}" for n in range(1, 5)]
    assert rows[0].assignments == (("PM-1-1", "clear"), ("PM-1-2", "rated"))
    assert rows[3].assignments == (("PM-1-1", "occupied"), ("PM-1-2", "overweight"))


def test_context_rows_are_capped_and_absent_without_values() -> None:
    wide = _structure(
        _responsibility(
            "RESP-1",
            pm_values={"PM-1-1": list("abcd"), "PM-1-2": list("wxyz")},
            refs=["PM-1-1", "PM-1-2"],
        )
    )
    bare = _structure(
        _responsibility("RESP-1", pm_values={"PM-1-1": []}, refs=["PM-1-1"])
    )

    assert (
        len(control_action_context_rows(wide, "CA-1-1")) == MAX_CONTEXT_ROWS_PER_ACTION
    )
    assert control_action_context_rows(bare, "CA-1-1") == ()
    assert control_action_context_rows(wide, "CA-9-9") == ()


def test_action_may_reference_only_its_own_controllers_variables() -> None:
    with pytest.raises(ValidationError, match="PM-2-1"):
        _structure(
            _responsibility("RESP-1", pm_values={"PM-1-1": ["a"]}, refs=["PM-2-1"]),
            _responsibility("RESP-2", pm_values={"PM-2-1": ["b"]}, refs=[]),
        )


def test_empty_context_fields_are_omitted_from_serialized_structure() -> None:
    structure = _structure(
        Responsibility(
            resp_id="RESP-1",
            description="Move pallets",
            process_model_parts=[ProcessModelPart(pm_id="PM-1-1", description="Bay")],
            control_actions=[
                ControlAction(ca_id="CA-1-1", description="Lift", target=_TARGET)
            ],
        )
    )

    dumped = structure.model_dump(mode="json")

    resp = dumped["responsibilities"][0]
    assert "values" not in resp["process_model_parts"][0]
    assert "evidence_refs" not in resp["process_model_parts"][0]
    assert "operation" not in resp["control_actions"][0]
    assert "process_model_refs" not in resp["control_actions"][0]


@pytest.mark.parametrize(
    ("kind", "untrusted"),
    [
        (FeedbackSourceKind.user_message, True),
        (FeedbackSourceKind.conversation_history, True),
        (FeedbackSourceKind.retrieved_content, True),
        (FeedbackSourceKind.operation_result, False),
        (FeedbackSourceKind.session_context, False),
        (None, False),
    ],
)
def test_feedback_trust_follows_its_source_kind(
    kind: FeedbackSourceKind | None, untrusted: bool
) -> None:
    resp = _responsibility(
        "RESP-1", pm_values={"PM-1-1": []}, refs=[], source_kind=kind
    )

    assert resp.feedback_channels[0].untrusted is untrusted


def test_revision_keeps_context_fields_a_restatement_omits() -> None:
    original = _responsibility(
        "RESP-1",
        pm_values={"PM-1-1": ["clear", "occupied"]},
        refs=["PM-1-1"],
        source_kind=FeedbackSourceKind.user_message,
    )
    original.process_model_parts[0].evidence_refs = ["state:bays.status"]
    revised = Responsibility(
        resp_id="RESP-1",
        description="Move pallets safely",
        process_model_parts=[ProcessModelPart(pm_id="PM-1-1", description="Bay")],
        control_actions=[
            ControlAction(ca_id="CA-1-1", description="Lift", target=_TARGET)
        ],
        feedback_channels=[
            FeedbackChannel(
                fb_id="FB-1-1", description="Request", updates="PM-1-1", source=_TARGET
            )
        ],
    )

    _carry_forward_context(original, revised)

    assert revised.process_model_parts[0].values == ["clear", "occupied"]
    assert revised.process_model_parts[0].evidence_refs == ["state:bays.status"]
    assert revised.control_actions[0].operation == "lift_pallet"
    assert revised.control_actions[0].process_model_refs == ["PM-1-1"]
    assert revised.feedback_channels[0].source_kind is FeedbackSourceKind.user_message


def test_finding_must_cite_a_row_of_its_own_action() -> None:
    structure = _structure(
        _responsibility(
            "RESP-1", pm_values={"PM-1-1": ["clear", "occupied"]}, refs=["PM-1-1"]
        ),
        _responsibility("RESP-2", pm_values={"PM-2-1": ["a"]}, refs=["PM-2-1"]),
    )
    slot = SimpleNamespace(control_action="CA-1-1")

    context = _finding_context(
        SimpleNamespace(context_row="CA-1-1:ctx-2"),
        slot=slot,
        control_structure=structure,
    )

    assert context == {"PM-1-1": "occupied"}
    assert (
        _finding_context(
            SimpleNamespace(context_row=None), slot=slot, control_structure=structure
        )
        is None
    )
    with pytest.raises(ValueError, match="CA-2-1:ctx-1"):
        _finding_context(
            SimpleNamespace(context_row="CA-2-1:ctx-1"),
            slot=slot,
            control_structure=structure,
        )
