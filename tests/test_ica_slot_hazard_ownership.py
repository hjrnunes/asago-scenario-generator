"""An ICA's hazard must depend on an operation its own slot's action invokes.

ICA synthesis offers every hazard to every slot, so a slot whose control
action invokes no operation can tie itself to a hazard about another action's
operation.  The final-ICA verification flags such an ICA, on the ICA and in
the verification batch, and names the slot that owns the operation.
"""

from __future__ import annotations

from types import SimpleNamespace

from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    ControlledProcess,
    Responsibility,
)
from asago_scenario_generator.stpa.models.ica_enumeration import (
    ICA,
    ICAEnumeration,
    ICASlot,
)
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)
from asago_scenario_generator.pipeline.synthesis_scenarios import (
    _run_ica_verification,
)
from asago_scenario_generator.pipeline.synthesis_types import SynthesisAdapters
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    SynthesisSlotFillResult,
)
from asago_scenario_generator.stpa.obligation_aware.ica_verification import (
    verify_final_ica_batch,
)
from asago_scenario_generator.stpa.obligation_aware.slot_filling import (
    SlotFillRunResult,
)
from asago_scenario_generator.stpa.obligation_aware.slot_hazard_ownership import (
    SLOT_HAZARD_MISMATCH_CODE,
    SlotHazardMismatch,
    declared_operation_names,
    find_slot_hazard_mismatches,
    flag_slot_hazard_mismatches,
)

CODE = SLOT_HAZARD_MISMATCH_CODE


class _Supporting:
    """A verifier that supports every ICA it is shown, with absence evidence."""

    def verify_ica_hazards(self, requests, **_):
        return [
            {
                "ica_id": request.ica_id,
                "verdict": "supported",
                "rationale": "The supplied STPA path is coherent.",
                "absence_loss_ids": [loss.loss_id for loss in request.losses],
                "absence_consequence": "Nobody reviews the reported concern.",
            }
            for request in requests
        ]


def _losses() -> LossAnalysis:
    return LossAnalysis(
        risk_card_losses=[],
        use_case_losses=[
            Loss(
                loss_id="L-1",
                description="Unsafe conduct goes unreviewed by staff.",
                provenance=LossProvenance.use_case,
            ),
            Loss(
                loss_id="L-2",
                description="A reply shows unequal treatment.",
                provenance=LossProvenance.use_case,
            ),
        ],
        hazards=[
            Hazard(
                hazard_id="H-1",
                description="A reply treats one group of guests worse than another.",
                related_losses=["L-2"],
            ),
            Hazard(
                hazard_id="H-3",
                description=(
                    "A reported safety concern never reaches "
                    "`escalate_trust_safety`, so no person reviews it."
                ),
                related_losses=["L-1"],
            ),
        ],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1",
                rule="Hand every reported safety concern to staff review.",
                related_hazards=["H-3"],
            ),
            SecurityConstraint(
                constraint_id="SC-2",
                rule="Replies treat every guest alike.",
                related_hazards=["H-1"],
            ),
        ],
    )


def _structure(*, second_owner: bool = False) -> ControlStructure:
    escalations = [
        ControlAction(
            ca_id="CA-7-2",
            description="Open a safety case",
            target={"type": "controlled_process", "id": "CP-1"},
            effect_kind="tool_call",
            operation="escalate_trust_safety",
        )
    ]
    if second_owner:
        escalations.insert(
            0,
            ControlAction(
                ca_id="CA-7-1",
                description="Escalate a safety concern",
                target={"type": "controlled_process", "id": "CP-1"},
                effect_kind="tool_call",
                operation="escalate_trust_safety",
            ),
        )
    return ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-7",
                description="Routes safety concerns to staff.",
                control_actions=escalations,
            ),
            Responsibility(
                resp_id="RESP-8",
                description="Writes the chat replies.",
                control_actions=[
                    ControlAction(
                        ca_id="CA-8-1",
                        description="Send a chat reply",
                        target={"type": "controlled_process", "id": "CP-2"},
                        effect_kind="model_output",
                    )
                ],
            ),
        ],
        controlled_processes=[
            ControlledProcess(cp_id="CP-1", description="Safety case queue"),
            ControlledProcess(cp_id="CP-2", description="Chat channel"),
        ],
    )


def _ica(slot_id: str, hazard_id: str, constraint_id: str) -> ICA:
    return ICA(
        ica_id=f"{slot_id}:1",
        ica_text="The action is not taken when a concern is reported.",
        hazardous_context="A guest reports a safety concern.",
        loss_scenario="The concern stays with no person to review it.",
        related_hazards=[hazard_id],
        related_constraints=[constraint_id],
    )


def _slot(resp: str, ca: str, hazard_id: str, constraint_id: str) -> ICASlot:
    slot_id = f"{resp}:{ca}:NOT_PROVIDED"
    return ICASlot(
        slot_id=slot_id,
        responsibility=resp,
        control_action=ca,
        uca_type="NOT_PROVIDED",
        is_na=False,
        icas=[_ica(slot_id, hazard_id, constraint_id)],
    )


def _verify(slots: list[ICASlot], structure: ControlStructure):
    return verify_final_ica_batch(
        _Supporting(),
        ICAEnumeration(slots=slots),
        loss_analysis=_losses(),
        control_structure=structure,
    )


def _flags(batch) -> list:
    return [item for item in batch.diagnostics if item.code == CODE]


def _icas(enumeration: ICAEnumeration) -> dict[str, ICA]:
    return {ica.ica_id: ica for slot in enumeration.slots for ica in slot.icas}


def test_a_hazard_about_another_actions_operation_is_flagged_on_the_ica() -> None:
    filtered, batch = _verify([_slot("RESP-8", "CA-8-1", "H-3", "SC-1")], _structure())

    [flag] = _flags(batch)
    assert flag.refs == ("RESP-8:CA-8-1:NOT_PROVIDED:1",)
    assert "H-3" in flag.detail
    assert "escalate_trust_safety" in flag.detail
    assert "RESP-7:CA-7-2:NOT_PROVIDED" in flag.detail
    ica = _icas(filtered)["RESP-8:CA-8-1:NOT_PROVIDED:1"]
    assert any(
        CODE in warning and "RESP-7:CA-7-2:NOT_PROVIDED" in warning
        for warning in ica.quality_warnings
    )


def test_the_flag_keeps_the_ica_in_its_own_slot() -> None:
    filtered, batch = _verify([_slot("RESP-8", "CA-8-1", "H-3", "SC-1")], _structure())

    assert [slot.slot_id for slot in filtered.slots] == ["RESP-8:CA-8-1:NOT_PROVIDED"]
    assert batch.records[0].disposition == "supported"


def test_an_operation_owned_by_two_actions_names_both_and_moves_nothing() -> None:
    _, batch = _verify(
        [_slot("RESP-8", "CA-8-1", "H-3", "SC-1")], _structure(second_owner=True)
    )

    [flag] = _flags(batch)
    assert "RESP-7:CA-7-1:NOT_PROVIDED" in flag.detail
    assert "RESP-7:CA-7-2:NOT_PROVIDED" in flag.detail


def test_a_slot_whose_action_owns_the_operation_is_not_flagged() -> None:
    filtered, batch = _verify([_slot("RESP-7", "CA-7-2", "H-3", "SC-1")], _structure())

    assert _flags(batch) == []
    assert all(not ica.quality_warnings for ica in _icas(filtered).values())


def test_a_hazard_naming_no_operation_is_not_flagged() -> None:
    filtered, batch = _verify([_slot("RESP-8", "CA-8-1", "H-1", "SC-2")], _structure())

    assert _flags(batch) == []
    assert all(not ica.quality_warnings for ica in _icas(filtered).values())


def _hazard_text(text: str) -> LossAnalysis:
    losses = _losses()
    hazards = [
        hazard.model_copy(update={"description": text})
        if hazard.hazard_id == "H-3"
        else hazard
        for hazard in losses.hazards
    ]
    return losses.model_copy(update={"hazards": hazards})


def _mismatches(slot: ICASlot, losses: LossAnalysis, structure: ControlStructure):
    return find_slot_hazard_mismatches(ICAEnumeration(slots=[slot]), losses, structure)


def test_an_operation_matches_only_as_a_whole_identifier() -> None:
    losses = _hazard_text("A concern reaches `escalate_trust_safety_v2` too late.")

    assert (
        _mismatches(_slot("RESP-8", "CA-8-1", "H-3", "SC-1"), losses, _structure())
        == ()
    )


def test_a_hazard_naming_the_slots_operation_among_others_is_not_flagged() -> None:
    structure = _structure()
    structure.responsibilities[1].control_actions[0].operation = "send_reply"
    losses = _hazard_text(
        "A concern reaches neither `send_reply` nor `escalate_trust_safety`."
    )

    assert (
        _mismatches(_slot("RESP-8", "CA-8-1", "H-3", "SC-1"), losses, structure) == ()
    )


def test_the_mismatch_records_the_slot_operation_and_the_owner() -> None:
    structure = _structure()
    structure.responsibilities[1].control_actions[0].operation = "send_reply"

    [mismatch] = _mismatches(
        _slot("RESP-8", "CA-8-1", "H-3", "SC-1"), _losses(), structure
    )

    assert mismatch == SlotHazardMismatch(
        ica_id="RESP-8:CA-8-1:NOT_PROVIDED:1",
        slot_id="RESP-8:CA-8-1:NOT_PROVIDED",
        control_action_id="CA-8-1",
        slot_operation="send_reply",
        hazard_id="H-3",
        hazard_operations=("escalate_trust_safety",),
        owning_slot_ids=("RESP-7:CA-7-2:NOT_PROVIDED",),
    )
    assert "invokes `send_reply`" in mismatch.reason
    assert "the owning slot is RESP-7:CA-7-2:NOT_PROVIDED" in mismatch.reason


def _unowned_structure() -> ControlStructure:
    """The structure with no control action invoking `escalate_trust_safety`."""
    structure = _structure()
    structure.responsibilities[0].control_actions[0].operation = None
    return structure


def test_a_declared_operation_no_action_invokes_is_flagged_as_unowned() -> None:
    [mismatch] = find_slot_hazard_mismatches(
        ICAEnumeration(slots=[_slot("RESP-8", "CA-8-1", "H-3", "SC-1")]),
        _losses(),
        _unowned_structure(),
        operation_inventory=("escalate_trust_safety",),
    )

    assert mismatch.owning_slot_ids == ()
    assert mismatch.unowned_operations == ("escalate_trust_safety",)
    assert mismatch.reason.endswith(
        "no slot owns `escalate_trust_safety`: no control action invokes it"
    )


def test_an_unowned_operation_is_flagged_by_the_verification() -> None:
    filtered, batch = verify_final_ica_batch(
        _Supporting(),
        ICAEnumeration(slots=[_slot("RESP-8", "CA-8-1", "H-3", "SC-1")]),
        loss_analysis=_losses(),
        control_structure=_unowned_structure(),
        operation_inventory=("escalate_trust_safety",),
    )

    [flag] = _flags(batch)
    assert "no slot owns `escalate_trust_safety`" in flag.detail
    [warning] = _icas(filtered)["RESP-8:CA-8-1:NOT_PROVIDED:1"].quality_warnings
    assert "no slot owns `escalate_trust_safety`" in warning


def test_a_hazard_naming_an_owned_and_an_unowned_operation_names_both() -> None:
    losses = _hazard_text(
        "A concern reaches neither `escalate_trust_safety` nor `notify_staff`."
    )

    [mismatch] = find_slot_hazard_mismatches(
        ICAEnumeration(slots=[_slot("RESP-8", "CA-8-1", "H-3", "SC-1")]),
        losses,
        _structure(),
        operation_inventory=("escalate_trust_safety", "notify_staff"),
    )

    assert mismatch.hazard_operations == ("escalate_trust_safety", "notify_staff")
    assert mismatch.owning_slot_ids == ("RESP-7:CA-7-2:NOT_PROVIDED",)
    assert mismatch.unowned_operations == ("notify_staff",)
    assert "the owning slot is RESP-7:CA-7-2:NOT_PROVIDED" in mismatch.reason
    assert "no slot owns `notify_staff`" in mismatch.reason


def test_a_name_in_neither_the_inventory_nor_an_action_is_not_an_operation() -> None:
    assert (
        _mismatches(
            _slot("RESP-8", "CA-8-1", "H-3", "SC-1"), _losses(), _unowned_structure()
        )
        == ()
    )


def test_synthesis_checks_against_the_target_profiles_operations() -> None:
    enumeration = ICAEnumeration(slots=[_slot("RESP-8", "CA-8-1", "H-3", "SC-1")])
    profile = SimpleNamespace(
        resources=[
            SimpleNamespace(
                operations=[SimpleNamespace(operation_id="escalate_trust_safety")]
            )
        ]
    )

    verified = _run_ica_verification(
        SlotFillRunResult(result=SynthesisSlotFillResult(ica_enumeration=enumeration)),
        adapters=SynthesisAdapters(obligation_adapter=_Supporting()),
        loss_analysis=_losses(),
        control_structure=_unowned_structure(),
        inputs=SimpleNamespace(execution_target_profile=profile),
    )

    [flag] = _flags(verified.ica_hazard_verification)
    assert "no slot owns `escalate_trust_safety`" in flag.detail


def test_declared_operation_names_reads_every_resource_operation() -> None:
    profile = SimpleNamespace(
        resources=[
            SimpleNamespace(operations=[SimpleNamespace(operation_id="a")]),
            SimpleNamespace(
                operations=[
                    SimpleNamespace(operation_id="b"),
                    SimpleNamespace(operation_id="c"),
                ]
            ),
        ]
    )

    assert declared_operation_names(profile) == ("a", "b", "c")
    assert declared_operation_names(None) == ()


def test_flagging_twice_adds_each_warning_once() -> None:
    enumeration = ICAEnumeration(slots=[_slot("RESP-8", "CA-8-1", "H-3", "SC-1")])
    mismatches = find_slot_hazard_mismatches(enumeration, _losses(), _structure())

    once = flag_slot_hazard_mismatches(enumeration, mismatches)
    twice = flag_slot_hazard_mismatches(once, mismatches)

    assert once == twice
    assert len(once.slots[0].icas[0].quality_warnings) == 1
