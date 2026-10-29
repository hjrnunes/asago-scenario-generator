"""A NOT_PROVIDED finding that repeats an INCORRECT one is quarantined by the fill.

The fill sends every slot in its own request, so the two findings meet only
once the per-slot replies are assembled.
"""

from __future__ import annotations

from types import SimpleNamespace

from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
from asago_scenario_generator.pipeline.synthesis_manifest import (
    _manifest_provider_evidence,
)
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    IcaDeviationDraft,
    IcaFindingDraft,
    ObligationIcaDraft,
    ObligationRoute,
    SlotIcaDraft,
    SynthesisSlotResponse,
)
from asago_scenario_generator.stpa.obligation_aware.inverted_omission import (
    INVERTED_OMISSION_CODE,
)
from asago_scenario_generator.stpa.obligation_aware.routing import build_neutral_briefs
from asago_scenario_generator.stpa.obligation_aware.slot_filling import (
    fill_synthesis_slots,
)
from asago_scenario_generator.stpa.threat_enum.slot_creation import create_slots
from tests.helpers.obligation_aware import (
    _DEVIATION_FIELDS,
    _control_structure,
    _controls,
    _loss_analysis,
)
from tests.helpers.obligation_factory import make_plan
from tests.helpers.projection_factory import get_test_raw_pattern

ROW_VALID = "CA-1-1:ctx-1"
ROW_INVALID = "CA-1-1:ctx-2"
INCORRECT = "RESP-1:CA-1-1:INCORRECT"
NOT_PROVIDED = "RESP-1:CA-1-1:NOT_PROVIDED"


def _valued_structure():
    """CA-1-1 reads PM-1-1, so its context table has one row per value."""
    structure = _control_structure()
    [resp] = structure.responsibilities
    [part] = resp.process_model_parts
    [action] = resp.control_actions
    return structure.model_copy(
        update={
            "responsibilities": (
                resp.model_copy(
                    update={
                        "process_model_parts": (
                            part.model_copy(update={"values": ["valid", "invalid"]}),
                        ),
                        "control_actions": (
                            action.model_copy(
                                update={"process_model_refs": ["PM-1-1"]}
                            ),
                        ),
                    }
                ),
            )
        }
    )


def _finding(uca_type: UCAType, text: str, row: str) -> IcaFindingDraft:
    return IcaFindingDraft(
        deviation=IcaDeviationDraft(**{_DEVIATION_FIELDS[uca_type]: text}),
        hazardous_context=f"{text} reaches the process",
        loss_consequence="the protected operation is harmed",
        related_hazard_ids=("H-1",),
        related_constraint_ids=("SC-1",),
        process_model_refs=("PM-1-1",),
        context_row=row,
    )


class _OneSlotAdapter:
    """Answer each single-slot request; record the slots of every request."""

    def __init__(self, omitted_rows: tuple[str, ...]) -> None:
        self.omitted_rows = omitted_rows
        self.requested: list[tuple[str, ...]] = []

    def fill(self, request):
        self.requested.append(tuple(slot.slot_id for slot in request.slots))
        drafts = []
        for slot in request.slots:
            routes = [r for r in request.routed_routes if slot.slot_id in r.slot_ids]
            if slot.slot_id == INCORRECT:
                findings = (
                    _finding(
                        slot.uca_type, "the request is checked wrongly", ROW_INVALID
                    ),
                )
            elif slot.slot_id == NOT_PROVIDED:
                findings = tuple(
                    _finding(slot.uca_type, f"the request is not checked ({row})", row)
                    for row in self.omitted_rows
                )
            else:
                drafts.append(
                    SlotIcaDraft(
                        slot_id=slot.slot_id, is_na=True, na_rationale="Not applicable."
                    )
                )
                continue
            drafts.append(
                SlotIcaDraft(
                    slot_id=slot.slot_id,
                    is_na=False,
                    findings=findings,
                    consideration_results=tuple(
                        ObligationIcaDraft(
                            obligation_handle=route.obligation_id,
                            disposition="finding",
                            finding_indexes=tuple(range(len(findings))),
                            rationale="The routed concern is these findings.",
                        )
                        for route in routes
                    ),
                )
            )
        return SynthesisSlotResponse(
            adapter_kind="fake",
            request_digest=request.semantic_digest,
            filled_slots=tuple(drafts),
        )


def _fill(omitted_rows: tuple[str, ...]):
    structure = _valued_structure()
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    [brief] = build_neutral_briefs(make_plan(risk_ids=("risk-a",)), (pattern,))
    slot_ids = {slot.slot_id for slot in create_slots(structure)}
    assert {INCORRECT, NOT_PROVIDED} <= slot_ids
    route = ObligationRoute(
        obligation_id=brief.obligation_id,
        disposition="targeted",
        slot_ids=(INCORRECT, NOT_PROVIDED),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        evidence=("route-0",),
    )
    adapter = _OneSlotAdapter(omitted_rows)
    result = fill_synthesis_slots(
        adapter,
        briefs=(brief,),
        routes=(route,),
        loss_analysis=_loss_analysis(),
        control_structure=structure,
        controls=_controls(),
    )
    slots = {slot.slot_id: slot for slot in result.ica_enumeration.slots}
    pairs = {item.slot_id: item for item in result.considerations}
    return adapter, result, slots, pairs


def test_the_omission_is_quarantined_after_the_per_slot_replies_are_assembled() -> None:
    adapter, result, slots, pairs = _fill((ROW_INVALID,))

    # Production sends each slot in a request of its own.
    assert all(len(slot_ids) == 1 for slot_ids in adapter.requested)
    omitted = slots[NOT_PROVIDED]
    assert omitted.icas == []
    assert omitted.unresolved_reason == (
        "Every finding of this slot repeats an INCORRECT finding of the same "
        "control action and is quarantined pending a semantic check."
    )
    assert [ica.ica_id for ica in slots[INCORRECT].icas] == [f"{INCORRECT}:1"]
    [diagnostic] = [
        item for item in result.diagnostics if item.code == INVERTED_OMISSION_CODE
    ]
    # Diagnostic refs are kept in sorted order.
    assert diagnostic.refs == (f"{INCORRECT}:1", f"{NOT_PROVIDED}:1")
    assert diagnostic.detail == (
        f"{NOT_PROVIDED}:1 quarantined: the NOT_PROVIDED finding repeats the "
        f"context row ({ROW_INVALID}), hazards (H-1) and constraints (SC-1) of "
        f"the INCORRECT finding {INCORRECT}:1, so it may be the INCORRECT "
        "finding inverted. It is kept out of scenario generation pending a "
        "semantic check."
    )
    # The pair no longer credits the quarantined ICA.
    pair = pairs[NOT_PROVIDED]
    assert (pair.disposition, pair.ica_ids) == ("unresolved", ())
    assert INVERTED_OMISSION_CODE in {item.code for item in pair.diagnostics}
    assert pairs[INCORRECT].ica_ids == (f"{INCORRECT}:1",)


def test_the_quarantined_omission_is_absent_from_scenario_generation_input() -> None:
    _adapter, result, _slots, _pairs = _fill((ROW_INVALID,))

    # Stage 5 builds scenarios from the ICA enumeration and its considerations.
    ica_ids = {ica.ica_id for slot in result.ica_enumeration.slots for ica in slot.icas}
    credited = {ica_id for item in result.considerations for ica_id in item.ica_ids}
    assert f"{NOT_PROVIDED}:1" not in ica_ids | credited
    assert ica_ids == {f"{INCORRECT}:1"}


def test_the_quarantined_omission_is_recorded_with_its_finding_and_diagnostic() -> None:
    _adapter, result, _slots, _pairs = _fill((ROW_INVALID,))

    [record] = result.quarantined_icas
    assert result.result.quarantined_icas == result.quarantined_icas
    assert record.status == "quarantined"
    assert (record.slot_id, record.sibling_ica_id) == (NOT_PROVIDED, f"{INCORRECT}:1")
    assert (
        record.ica.ica_id,
        record.ica.context_row,
        record.ica.related_hazards,
        record.ica.related_constraints,
    ) == (f"{NOT_PROVIDED}:1", ROW_INVALID, ["H-1"], ["SC-1"])
    assert record.ica.ica_text
    [diagnostic] = [
        item for item in result.diagnostics if item.code == INVERTED_OMISSION_CODE
    ]
    assert record.diagnostic == diagnostic


def test_the_manifest_lists_the_quarantined_omission() -> None:
    _adapter, result, _slots, _pairs = _fill((ROW_INVALID,))

    evidence = _manifest_provider_evidence(
        {"ica": result}, SimpleNamespace(profile="synthesis")
    )

    [entry] = evidence["ica"]["quarantined_icas"]
    assert entry == result.quarantined_icas[0].model_dump(mode="json")
    assert entry["status"] == "quarantined"
    assert entry["ica"]["ica_id"] == f"{NOT_PROVIDED}:1"
    assert entry["ica"]["context_row"] == ROW_INVALID
    assert entry["ica"]["related_hazards"] == ["H-1"]
    assert entry["ica"]["related_constraints"] == ["SC-1"]
    assert entry["sibling_ica_id"] == f"{INCORRECT}:1"
    assert entry["diagnostic"]["code"] == INVERTED_OMISSION_CODE


def test_a_sibling_omission_on_another_row_stays() -> None:
    _adapter, result, slots, pairs = _fill((ROW_INVALID, ROW_VALID))

    # The quarantined ICA keeps its identity gap; the other keeps its ID.
    assert [ica.ica_id for ica in slots[NOT_PROVIDED].icas] == [f"{NOT_PROVIDED}:2"]
    assert pairs[NOT_PROVIDED].disposition == "finding"
    assert pairs[NOT_PROVIDED].ica_ids == (f"{NOT_PROVIDED}:2",)


def test_an_omission_on_its_own_row_is_kept() -> None:
    _adapter, result, slots, pairs = _fill((ROW_VALID,))

    assert [ica.context_row for ica in slots[NOT_PROVIDED].icas] == [ROW_VALID]
    assert pairs[NOT_PROVIDED].ica_ids == (f"{NOT_PROVIDED}:1",)
    assert INVERTED_OMISSION_CODE not in {item.code for item in result.diagnostics}
    assert result.quarantined_icas == ()
    evidence = _manifest_provider_evidence(
        {"ica": result}, SimpleNamespace(profile="synthesis")
    )
    assert "quarantined_icas" not in evidence["ica"]
