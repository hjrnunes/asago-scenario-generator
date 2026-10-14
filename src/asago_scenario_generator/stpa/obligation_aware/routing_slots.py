"""The slots structural routing offers the model and accepts in a route."""

from __future__ import annotations

from collections.abc import Sequence

from asago_scenario_generator.stpa.threat_enum.slot_creation import (
    SlotPlaceholder,
    requires_provider_slot_analysis,
)


def routing_slots(slots: Sequence[SlotPlaceholder]) -> tuple[SlotPlaceholder, ...]:
    """Return the slots a structural route may name.

    Slot filling never asks the model about any other slot, so a route through
    one could not yield a finding.
    """
    return tuple(slot for slot in slots if requires_provider_slot_analysis(slot))
