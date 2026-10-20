"""The identities an ICA fill reply may cite, taken from its request.

The fill schema turns each list into an enum, so a reply cannot name a slot,
governing constraint-and-hazard pair, context row, process-model part, or
feedback channel that its slot's validation would reject.
"""

from __future__ import annotations

from dataclasses import dataclass

from asago_scenario_generator.stpa.models.control_structure import (
    control_action_context_rows,
)
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    SynthesisSlotRequest,
)
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    local_obligation_handles,
)
from asago_scenario_generator.stpa.obligation_aware.slot_filling import (
    _slot_authority,
)
from asago_scenario_generator.stpa.obligation_aware.stpa_index import (
    build_stpa_index,
)


@dataclass(frozen=True)
class FillScope:
    """The identities one fill request lets its reply cite, in schema order."""

    slot_ids: tuple[str, ...]
    pair_ids: tuple[str, ...]
    context_row_ids: tuple[str, ...]
    process_model_ids: tuple[str, ...]
    feedback_ids: tuple[str, ...]
    # The local handles (R1..Rn) of the obligations routed to these slots,
    # which key ``consideration_results``. With one slot every handle is
    # required; with several, each slot answers its own subset, so none is.
    handles: tuple[str, ...] = ()
    every_handle_required: bool = True


def fill_scope(request: SynthesisSlotRequest) -> FillScope:
    """Collect the citable identities of every slot in *request*.

    A responsibility slot cites its owner's process-model parts and feedback
    channels; a coordination slot cites only its link's shared part. A
    context row must belong to the slot's own action.
    """
    index = build_stpa_index(request.control_structure)
    process_models: set[str] = set()
    feedback: set[str] = set()
    rows: list[str] = []
    for slot in request.slots:
        _owner, _action, _process, slot_models, slot_feedback = _slot_authority(
            slot, index
        )
        process_models.update(slot_models)
        feedback.update(slot_feedback)
        rows.extend(
            row.row_id
            for row in control_action_context_rows(
                request.control_structure, slot.control_action
            )
        )
    return FillScope(
        slot_ids=tuple(slot.slot_id for slot in request.slots),
        pair_ids=governing_pairs(request.loss_analysis),
        context_row_ids=tuple(dict.fromkeys(rows)),
        process_model_ids=tuple(sorted(process_models)),
        feedback_ids=tuple(sorted(feedback)),
        handles=routed_handles(request),
        every_handle_required=len(request.slots) == 1,
    )


def routed_handles(request: SynthesisSlotRequest) -> tuple[str, ...]:
    """Return the handles of the obligations routed to the request's slots."""
    slot_ids = {slot.slot_id for slot in request.slots}
    routed = {
        route.obligation_id
        for route in request.routed_routes
        if slot_ids.intersection(route.slot_ids)
    }
    return tuple(
        handle
        for obligation_id, handle in local_obligation_handles(
            request.routed_routes,
            {brief.obligation_id: brief for brief in request.routed_briefs},
        ).items()
        if obligation_id in routed
    )


def governing_pairs(loss_analysis: LossAnalysis) -> tuple[str, ...]:
    """Name every constraint with each hazard it governs, as ``"SC-x/H-y"``."""
    return tuple(
        dict.fromkeys(
            f"{constraint.constraint_id}/{hazard_id}"
            for constraint in loss_analysis.security_constraints
            for hazard_id in constraint.related_hazards
        )
    )


def split_pair(pair: str) -> tuple[str, str]:
    """Return the constraint ID and the hazard ID a governing pair names."""
    constraint_id, hazard_id = pair.split("/")
    return constraint_id, hazard_id


__all__ = [
    "FillScope",
    "fill_scope",
    "governing_pairs",
    "routed_handles",
    "split_pair",
]
