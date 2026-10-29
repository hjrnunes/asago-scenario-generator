"""Which NOT_PROVIDED findings the inverted-omission check quarantines, and how.

The fill-level tests in ``test_ica_inverted_omission_fill.py`` drive the
check through ``fill_synthesis_slots``; these call it on assembled slots.
"""

from __future__ import annotations

from asago_scenario_generator.models.mechanism_suggestion import (
    MechanismIcaConsideration,
)
from asago_scenario_generator.models.obligation_consideration import (
    ConsiderationDiagnostic,
)
from asago_scenario_generator.stpa.mechanism_library import MechanismId
from asago_scenario_generator.stpa.models.ica_enumeration import (
    ICA,
    ICASlot,
    UCAType,
)
from asago_scenario_generator.stpa.obligation_aware.inverted_omission import (
    INVERTED_OMISSION_CODE,
    inverted_omissions,
    quarantine_inverted_omissions,
)

ROW = "CA-1-1:ctx-2"
INCORRECT = "RESP-1:CA-1-1:INCORRECT"
NOT_PROVIDED = "RESP-1:CA-1-1:NOT_PROVIDED"


def _ica(
    slot_id: str,
    index: int,
    *,
    row: str | None = ROW,
    hazards: tuple[str, ...] = ("H-1",),
    constraints: tuple[str, ...] = ("SC-1",),
) -> ICA:
    return ICA(
        ica_id=f"{slot_id}:{index}",
        ica_text=f"finding {index} of {slot_id}",
        hazardous_context="the request reaches the process",
        loss_scenario="the protected operation is harmed",
        related_hazards=list(hazards),
        related_constraints=list(constraints),
        context_row=row,
    )


def _slot(uca_type: UCAType, *icas: ICA) -> ICASlot:
    return ICASlot(
        slot_id=f"RESP-1:CA-1-1:{uca_type.value}",
        responsibility="RESP-1",
        control_action="CA-1-1",
        uca_type=uca_type,
        is_na=False,
        icas=list(icas),
    )


def _slots(*omitted: ICA, sibling: ICA | None = None) -> dict[str, ICASlot]:
    incorrect = _slot(UCAType.incorrect, sibling or _ica(INCORRECT, 1))
    not_provided = _slot(UCAType.not_provided, *omitted)
    return {INCORRECT: incorrect, NOT_PROVIDED: not_provided}


def _mechanism(
    ica_ids: tuple[str, ...], suggestion_id: str = "msug-1"
) -> MechanismIcaConsideration:
    return MechanismIcaConsideration(
        suggestion_id=suggestion_id,
        mechanism_id=MechanismId.user_claim,
        slot_id=NOT_PROVIDED,
        disposition="finding",
        ica_ids=ica_ids,
        exec_candidate_ids=("EXEC:1",),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        evidence=("provider-structured-consideration",),
    )


def _run(slots, pairs=(), mechanism_pairs=()):
    pairs, mechanism_pairs = list(pairs), list(mechanism_pairs)
    diagnostics: list[ConsiderationDiagnostic] = []
    quarantined = quarantine_inverted_omissions(
        slots, pairs, mechanism_pairs, diagnostics
    )
    return quarantined, pairs, mechanism_pairs, diagnostics


def test_a_flagged_omission_is_recorded_whole_as_quarantined() -> None:
    omitted = _ica(NOT_PROVIDED, 1)
    slots = _slots(omitted)

    quarantined, _pairs, _mechanisms, diagnostics = _run(slots)

    [record] = quarantined
    assert record.status == "quarantined"
    assert record.slot_id == NOT_PROVIDED
    assert record.sibling_ica_id == f"{INCORRECT}:1"
    # The whole finding is kept, so a later check can release it.
    assert record.ica == omitted
    assert (
        record.ica.ica_id,
        record.ica.context_row,
        record.ica.related_hazards,
        record.ica.related_constraints,
    ) == (f"{NOT_PROVIDED}:1", ROW, ["H-1"], ["SC-1"])
    assert (
        record.diagnostic.code
        == INVERTED_OMISSION_CODE
        == ("ica_inverted_omission_quarantined")
    )
    assert record.diagnostic.detail == (
        f"{NOT_PROVIDED}:1 quarantined: the NOT_PROVIDED finding repeats the "
        f"context row ({ROW}), hazards (H-1) and constraints (SC-1) of the "
        f"INCORRECT finding {INCORRECT}:1, so it may be the INCORRECT finding "
        "inverted. It is kept out of scenario generation pending a semantic "
        "check."
    )
    assert diagnostics == [record.diagnostic]
    # The finding leaves the slot that scenario generation reads.
    assert slots[NOT_PROVIDED].icas == []
    assert slots[NOT_PROVIDED].unresolved_reason == (
        "Every finding of this slot repeats an INCORRECT finding of the same "
        "control action and is quarantined pending a semantic check."
    )
    assert slots[INCORRECT].icas == [_ica(INCORRECT, 1)]


def test_the_quarantine_record_round_trips_through_its_serialized_form() -> None:
    [record] = _run(_slots(_ica(NOT_PROVIDED, 1)))[0]

    dumped = record.model_dump(mode="json")

    assert dumped["status"] == "quarantined"
    assert dumped["ica"]["context_row"] == ROW
    assert type(record).model_validate(dumped) == record


def test_mechanism_results_lose_credit_for_a_quarantined_omission() -> None:
    flagged, other = _ica(NOT_PROVIDED, 1), _ica(NOT_PROVIDED, 2, row=None)
    only = _mechanism((flagged.ica_id,))
    both = _mechanism((flagged.ica_id, other.ica_id), "msug-2")

    _quarantined, _pairs, mechanisms, _diagnostics = _run(
        _slots(flagged, other), mechanism_pairs=(only, both)
    )

    by_id = {item.suggestion_id: item for item in mechanisms}
    lone = by_id["msug-1"]
    assert (lone.disposition, lone.ica_ids, lone.exec_candidate_ids) == (
        "unresolved",
        (),
        (),
    )
    assert INVERTED_OMISSION_CODE in {item.code for item in lone.diagnostics}
    kept = by_id["msug-2"]
    assert (kept.disposition, kept.ica_ids) == ("finding", (other.ica_id,))
    assert INVERTED_OMISSION_CODE in {item.code for item in kept.diagnostics}


def test_a_mechanism_result_without_the_omission_is_unchanged() -> None:
    flagged, other = _ica(NOT_PROVIDED, 1), _ica(NOT_PROVIDED, 2, row=None)
    untouched = _mechanism((other.ica_id,))

    _quarantined, _pairs, mechanisms, _diagnostics = _run(
        _slots(flagged, other), mechanism_pairs=(untouched,)
    )

    assert mechanisms == [untouched]


def test_absent_context_rows_are_never_equal() -> None:
    # Both sides without a row: equal keys, but neither cites a context.
    both_absent = _slots(
        _ica(NOT_PROVIDED, 1, row=None), sibling=_ica(INCORRECT, 1, row=None)
    )
    # Only one side without a row.
    omission_absent = _slots(_ica(NOT_PROVIDED, 1, row=None))
    sibling_absent = _slots(_ica(NOT_PROVIDED, 1), sibling=_ica(INCORRECT, 1, row=None))

    for slots in (both_absent, omission_absent, sibling_absent):
        assert inverted_omissions(list(slots.values())) == []
        before = {key: slot.model_copy(deep=True) for key, slot in slots.items()}
        assert _run(slots)[0] == ()
        assert slots == before


def test_differing_hazard_sets_prevent_the_flag() -> None:
    slots = _slots(_ica(NOT_PROVIDED, 1, hazards=("H-1", "H-2")))

    assert inverted_omissions(list(slots.values())) == []
    assert _run(slots)[0] == ()
    assert len(slots[NOT_PROVIDED].icas) == 1


def test_differing_constraint_sets_prevent_the_flag() -> None:
    slots = _slots(_ica(NOT_PROVIDED, 1, constraints=("SC-2",)))

    assert inverted_omissions(list(slots.values())) == []
    assert _run(slots)[0] == ()
    assert len(slots[NOT_PROVIDED].icas) == 1


def test_set_order_and_repeats_do_not_prevent_the_flag() -> None:
    slots = _slots(
        _ica(NOT_PROVIDED, 1, hazards=("H-2", "H-1", "H-1")),
        sibling=_ica(INCORRECT, 1, hazards=("H-1", "H-2")),
    )

    [record] = _run(slots)[0]
    assert record.ica.ica_id == f"{NOT_PROVIDED}:1"
