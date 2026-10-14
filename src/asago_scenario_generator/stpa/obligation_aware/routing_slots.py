"""The slots structural routing offers the model and accepts in a route."""

from __future__ import annotations

from collections.abc import Sequence

from asago_scenario_generator.stpa.models.control_structure import (
    ControlStructure,
    ReferenceType,
)
from asago_scenario_generator.stpa.obligation_aware.stpa_index import (
    StpaIndex,
    build_stpa_index,
)
from asago_scenario_generator.stpa.threat_enum.slot_creation import (
    SlotPlaceholder,
    requires_provider_slot_analysis,
)


def routing_slots(
    slots: Sequence[SlotPlaceholder], control_structure: ControlStructure
) -> tuple[SlotPlaceholder, ...]:
    """Return the slots a structural route may name.

    Slot filling never asks the model about a slot it does not analyse, and
    route validation rejects every route through an owned action without a
    known controlled-process target, so a route through either kind of slot
    could not yield a finding.
    """
    index = build_stpa_index(control_structure)
    return tuple(
        slot
        for slot in slots
        if requires_provider_slot_analysis(slot) and _reaches_a_process(slot, index)
    )


def _reaches_a_process(slot: SlotPlaceholder, index: StpaIndex) -> bool:
    """Return whether a slot's owned action targets a known controlled process.

    A coordination slot has no owned action and always passes.
    """
    if slot.responsibility is None:
        return True
    action = index.slot_path(slot).action
    return (
        action is not None
        and action.target is not None
        and action.target.type is ReferenceType.controlled_process
        and action.target.id in index.controlled_processes
    )
