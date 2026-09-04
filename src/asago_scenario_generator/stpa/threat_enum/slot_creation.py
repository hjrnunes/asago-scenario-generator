"""Stage 3 Phase 1 — Deterministic slot creation.

Creates one slot per ``(responsibility × control_action × UCA_type)``
triple plus one slot per ``(coordination_link × UCA_type)``.

Four UCA types: NOT_PROVIDED, INCORRECT, WRONG_TIMING, WRONG_DURATION.

Slot count formula::

    (sum of control_actions per responsibility × 4)
    + (N_coordination_links × 4)

Purely deterministic — no LLM calls.

Phase 1 creates :class:`SlotPlaceholder` objects (not :class:`ICASlot`)
because the ``ICASlot`` model's ``validate_na_exclusivity`` validator
rejects the unfilled state (``is_na=False, icas=[]``).  Placeholders are
converted to ``ICASlot`` by the LLM slot-filling phase after the LLM
provides either concrete ICAs or an N/A justification.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from asago_scenario_generator.stpa.models.control_structure import (
    ControlActionTemporality,
    ControlStructure,
)
from asago_scenario_generator.stpa.models.ica_enumeration import ICA, UCAType

__all__ = [
    "SlotPlaceholder",
    "create_slots",
    "is_wrong_duration_eligible",
]


class SlotPlaceholder(BaseModel):
    """An unfilled ICA slot created by Phase 1.

    Has the same fields as :class:`ICASlot` but without the
    ``validate_na_exclusivity`` validator, allowing the unfilled state
    (``is_na=False, icas=[], na_justification=None``).

    Converted to :class:`ICASlot` after LLM slot-filling.
    """

    slot_id: str
    responsibility: str | None = None
    coordination_link: str | None = None
    control_action: str
    action_temporality: ControlActionTemporality | None = None
    uca_type: UCAType
    is_na: bool = False
    icas: list[ICA] = Field(default_factory=list)
    na_justification: str | None = None


def create_slots(control_structure: ControlStructure) -> list[SlotPlaceholder]:
    """Create ICA slot placeholders for every responsibility and coordination link.

    Each responsibility produces ``len(control_actions) × 4`` slots
    (one per UCA type). Each coordination link produces ``4`` slots.

    Slot IDs follow the format:
    - ``RESP-X:CA-Y:UCA_TYPE`` for responsibility slots
    - ``CL-X:CM-Y:UCA_TYPE`` for coordination link slots

    All slots start with ``is_na=False``, ``icas=[]``, and
    ``na_justification=None`` — they are filled by the LLM in Phase 2.

    Args:
        control_structure: The control structure to derive slots from.

    Returns:
        A list of :class:`SlotPlaceholder` objects in deterministic order:
        responsibility slots first (in responsibility → control_action →
        UCA type order), then coordination link slots.
    """
    slots: list[SlotPlaceholder] = []

    for resp in control_structure.responsibilities:
        for ca in resp.control_actions:
            for uca_type in UCAType:
                slots.append(
                    SlotPlaceholder(
                        slot_id=f"{resp.resp_id}:{ca.ca_id}:{uca_type.value}",
                        responsibility=resp.resp_id,
                        coordination_link=None,
                        control_action=ca.ca_id,
                        action_temporality=ca.temporality,
                        uca_type=uca_type,
                        is_na=False,
                        icas=[],
                    )
                )

    for link in control_structure.coordination_links:
        for uca_type in UCAType:
            slots.append(
                SlotPlaceholder(
                    slot_id=f"{link.link_id}:{link.coordination_mechanism.cm_id}:{uca_type.value}",
                    responsibility=None,
                    coordination_link=link.link_id,
                    control_action=link.coordination_mechanism.cm_id,
                    action_temporality=None,
                    uca_type=uca_type,
                    is_na=False,
                    icas=[],
                )
            )

    return slots


def is_wrong_duration_eligible(
    action_or_temporality: SlotPlaceholder | ControlActionTemporality | str | None,
) -> bool:
    """Return whether typed action temporality permits WRONG_DURATION.

    The decision deliberately has no prose fallback.  A missing or explicit
    ``unknown`` temporal value remains analytical and is not eligible for a
    duration finding.  Coordination mechanisms have no action temporality and
    therefore follow the same conservative rule.
    """
    if isinstance(action_or_temporality, SlotPlaceholder):
        temporality = action_or_temporality.action_temporality
    else:
        temporality = action_or_temporality
    if temporality is None:
        return False
    try:
        temporality = ControlActionTemporality(temporality)
    except (TypeError, ValueError):
        return False
    return temporality in {
        ControlActionTemporality.continuous,
        ControlActionTemporality.bounded_duration,
    }
