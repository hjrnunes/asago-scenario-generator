"""Prompt-budget splitting of slot-filling requests."""

from __future__ import annotations

from asago_scenario_generator.stpa.infra.prompt_preflight import (
    PromptBudget,
)
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    SynthesisSlotResponse,
)
from asago_scenario_generator.stpa.obligation_aware.slot_filling import (
    fill_synthesis_slots,
)
from tests.helpers.obligation_aware import (
    _control_structure,
    _controls,
    _loss_analysis,
    _routed_slot_draft,
)
from tests.helpers.slot_fill_budget_split import (
    _COMPLETION,
    _prompt_tokens,
    _routes_to_first_slot,
)


class _Adapter:
    """Answer each part deterministically and record its routed obligations."""

    def __init__(self, usable_input_tokens: int) -> None:
        self.prompt_budget = PromptBudget(
            context_window=_COMPLETION + usable_input_tokens,
            maximum_completion_tokens=_COMPLETION,
            safety_margin=0,
        )
        self.parts: list[tuple[str, tuple[str, ...]]] = []

    def fill(self, request):
        self.parts.append(
            (
                request.slots[0].slot_id,
                tuple(route.obligation_id for route in request.routed_routes),
            )
        )
        return SynthesisSlotResponse(
            adapter_kind="fake",
            request_digest=request.semantic_digest,
            filled_slots=tuple(
                _routed_slot_draft(
                    slot,
                    [r for r in request.routed_routes if slot.slot_id in r.slot_ids],
                )
                for slot in request.slots
            ),
        )


def _fill(adapter, briefs, routes):
    return fill_synthesis_slots(
        adapter,
        briefs=briefs,
        routes=routes,
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
        controls=_controls(),
    )


def test_oversized_routed_slot_is_split_greedily_by_route() -> None:
    """Routes fill each part in order until the next one would not fit."""
    briefs, routes, slot = _routes_to_first_slot()
    adapter = _Adapter(_prompt_tokens(briefs, routes[:2], slot))

    result = _fill(adapter, briefs, routes)

    ids = [route.obligation_id for route in routes]
    assert [part for part in adapter.parts if part[0] == slot.slot_id] == [
        (slot.slot_id, (ids[0], ids[1])),
        (slot.slot_id, (ids[2],)),
    ]
    assert sorted(item.obligation_id for item in result.considerations) == sorted(ids)
    assert all(item.unresolved_reason is None for item in result.ica_enumeration.slots)
    # Unrouted slots fit the same budget and stay one request each.
    unrouted = [part for part in adapter.parts if part[0] != slot.slot_id]
    assert unrouted and all(obligations == () for _, obligations in unrouted)
    assert len({slot_id for slot_id, _ in unrouted}) == len(unrouted)


def test_indivisible_requests_are_left_whole_for_provider_preflight() -> None:
    """A budget below one route or one slot leaves every request unchanged."""
    briefs, routes, slot = _routes_to_first_slot()
    adapter = _Adapter(1)

    _fill(adapter, briefs, routes)

    ids = tuple(route.obligation_id for route in routes)
    assert [part for part in adapter.parts if part[0] == slot.slot_id] == [
        (slot.slot_id, ids)
    ]
    # Every slot, routed or not, is still sent exactly once.
    assert len(adapter.parts) == len({slot_id for slot_id, _ in adapter.parts})
