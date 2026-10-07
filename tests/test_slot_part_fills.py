"""A slot is filled once; a budget split never discards a part's pair answers."""

from __future__ import annotations

from asago_scenario_generator.stpa.infra.prompt_preflight import PromptBudget
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    IcaDeviationDraft,
    IcaFindingDraft,
    ObligationIcaDraft,
    SlotIcaDraft,
    SynthesisSlotResponse,
)
from asago_scenario_generator.stpa.obligation_aware.slot_filling import (
    fill_synthesis_slots,
)
from tests.helpers.obligation_aware import (
    _DEVIATION_FIELDS,
    _control_structure,
    _controls,
    _loss_analysis,
    _routed_slot_draft,
)
from tests.test_slot_fill_budget_split import (
    _COMPLETION,
    _prompt_tokens,
    _routes_to_first_slot,
)


def _finding(slot, text: str) -> IcaFindingDraft:
    return IcaFindingDraft(
        deviation=IcaDeviationDraft(**{_DEVIATION_FIELDS[slot.uca_type]: text}),
        hazardous_context=f"{text} reaches the process",
        loss_consequence="the protected operation is harmed",
        related_hazard_ids=("H-1",),
        related_constraint_ids=("SC-1",),
    )


def _answer(slot, texts, results) -> SlotIcaDraft:
    """Build a slot fill with one finding per text and the given pair results.

    Each result is ``(route, disposition, finding_indexes)``.
    """
    return SlotIcaDraft(
        slot_id=slot.slot_id,
        is_na=False,
        findings=tuple(_finding(slot, text) for text in texts),
        consideration_results=tuple(
            ObligationIcaDraft(
                obligation_handle=route.obligation_id,
                disposition=disposition,
                finding_indexes=indexes,
                rationale=f"{disposition} by the part answering {route.obligation_id[-4:]}",
            )
            for route, disposition, indexes in results
        ),
    )


def _not_applicable(
    slot, routes, rationale="No routed concern applies."
) -> SlotIcaDraft:
    return SlotIcaDraft(
        slot_id=slot.slot_id,
        is_na=True,
        na_rationale=rationale,
        consideration_results=tuple(
            ObligationIcaDraft(
                obligation_handle=route.obligation_id,
                disposition="proposed_not_applicable",
                rationale="The structure excludes it.",
            )
            for route in routes
        ),
    )


class _PartAdapter:
    """Answer the target slot's parts from a script, every other slot as N/A."""

    def __init__(self, target, script, usable_input_tokens: int) -> None:
        self.prompt_budget = PromptBudget(
            context_window=_COMPLETION + usable_input_tokens,
            maximum_completion_tokens=_COMPLETION,
            safety_margin=0,
        )
        self.target = target
        self.script = script
        self.parts: list[tuple[str, ...]] = []

    def fill(self, request):
        drafts = []
        for slot in request.slots:
            if slot.slot_id != self.target.slot_id:
                drafts.append(_routed_slot_draft(slot, ()))
                continue
            routes = tuple(
                route
                for route in request.routed_routes
                if slot.slot_id in route.slot_ids
            )
            self.parts.append(tuple(route.obligation_id for route in routes))
            drafts.append(self.script[len(self.parts) - 1](slot, routes))
        return SynthesisSlotResponse(
            adapter_kind="fake",
            request_digest=request.semantic_digest,
            filled_slots=tuple(drafts),
        )


def _run(script, *, split: bool):
    briefs, routes, slot = _routes_to_first_slot()
    budget = _prompt_tokens(briefs, routes[:2], slot) if split else 10**9
    adapter = _PartAdapter(slot, script, budget)
    result = fill_synthesis_slots(
        adapter,
        briefs=briefs,
        routes=routes,
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
        controls=_controls(),
    )
    pairs = {item.obligation_id: item for item in result.considerations}
    return result, adapter, [pairs[route.obligation_id] for route in routes], slot


def test_slot_with_more_routes_than_the_batch_size_is_filled_once() -> None:
    """The batch size no longer splits a slot whose prompt fits the budget."""
    briefs, routes, slot = _routes_to_first_slot()
    controls = _controls().model_copy(update={"max_batch_size": 1})

    def script(target, request_routes):
        return _routed_slot_draft(target, request_routes)

    adapter = _PartAdapter(slot, [script], 10**9)
    result = fill_synthesis_slots(
        adapter,
        briefs=briefs,
        routes=routes,
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
        controls=controls,
    )

    assert adapter.parts == [tuple(route.obligation_id for route in routes)]
    assert [item.disposition for item in result.considerations] == ["finding"] * 3
    assert not result.result.diagnostics


def test_later_part_pairs_map_to_the_authoritative_fill_by_ica_content() -> None:
    """A later part's finding keeps its pair when the first fill holds that ICA."""
    result, adapter, pairs, slot = _run(
        [
            lambda s, r: _answer(
                s,
                ["first deviation", "second deviation"],
                [(r[0], "finding", (0,)), (r[1], "finding", (1,))],
            ),
            # The second part lists the same ICA at another position.
            lambda s, r: _answer(
                s,
                ["extra deviation", "second deviation"],
                [(r[0], "finding", (1,))],
            ),
        ],
        split=True,
    )

    assert len(adapter.parts) == 2
    filled = next(
        item for item in result.ica_enumeration.slots if item.slot_id == slot.slot_id
    )
    assert [ica.ica_id for ica in filled.icas] == [
        f"{slot.slot_id}:1",
        f"{slot.slot_id}:2",
    ]
    assert [item.disposition for item in pairs] == ["finding"] * 3
    assert pairs[2].ica_ids == (f"{slot.slot_id}:2",)
    assert not any(
        item.code == "slot_response_unresolved" for item in result.result.diagnostics
    )
    assert {item.outcome for item in result.result.call_evidence} == {"accepted"}


def test_later_part_pair_without_a_matching_ica_is_unresolved_alone() -> None:
    """Only the pair whose ICA the authoritative fill lacks is unresolved."""
    result, _adapter, pairs, slot = _run(
        [
            lambda s, r: _answer(
                s,
                ["first deviation"],
                [(r[0], "finding", (0,)), (r[1], "finding", (0,))],
            ),
            lambda s, r: _answer(s, ["unseen deviation"], [(r[0], "finding", (0,))]),
        ],
        split=True,
    )

    assert [item.disposition for item in pairs] == ["finding", "finding", "unresolved"]
    assert "authoritative" in pairs[2].rationale
    assert pairs[2].diagnostics[0].code == "slot_pair_unresolved"
    filled = next(
        item for item in result.ica_enumeration.slots if item.slot_id == slot.slot_id
    )
    assert len(filled.icas) == 1
    assert not any(
        item.code == "slot_response_unresolved" for item in result.result.diagnostics
    )


def test_later_part_not_applicable_pair_needs_a_not_applicable_authoritative_fill() -> (
    None
):
    """A later part cannot declare N/A on a slot the first fill answered with ICAs."""
    _result, _adapter, pairs, _slot = _run(
        [
            lambda s, r: _answer(
                s,
                ["first deviation"],
                [(r[0], "finding", (0,)), (r[1], "finding", (0,))],
            ),
            lambda s, r: _not_applicable(s, r),
        ],
        split=True,
    )

    assert [item.disposition for item in pairs] == ["finding", "finding", "unresolved"]


def test_later_part_not_applicable_pair_is_kept_beside_a_not_applicable_fill() -> None:
    """Both parts answering N/A keep every pair although the rationales differ."""
    result, _adapter, pairs, slot = _run(
        [
            lambda s, r: _not_applicable(s, r, "The action is a communication."),
            lambda s, r: _not_applicable(s, r, "Nothing applies to this action."),
        ],
        split=True,
    )

    assert [item.disposition for item in pairs] == ["proposed_not_applicable"] * 3
    filled = next(
        item for item in result.ica_enumeration.slots if item.slot_id == slot.slot_id
    )
    assert filled.na_justification == "The action is a communication."


def test_later_part_model_unresolved_pair_is_kept_as_the_model_answered() -> None:
    """An unresolved answer needs no ICA, so a differing fill does not discard it."""
    _result, _adapter, pairs, _slot = _run(
        [
            lambda s, r: _answer(
                s,
                ["first deviation"],
                [(r[0], "finding", (0,)), (r[1], "finding", (0,))],
            ),
            lambda s, r: _answer(s, ["unseen deviation"], [(r[0], "unresolved", ())]),
        ],
        split=True,
    )

    assert pairs[2].disposition == "unresolved"
    assert pairs[2].rationale.startswith("unresolved by the part")
