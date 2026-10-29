"""Check that an ICA's hazard depends on its own slot's operation.

ICA synthesis offers every hazard to every slot, so a slot can tie an ICA to
a hazard about an operation that another control action invokes.  A slot
whose action sends a chat reply, for example, can cite a hazard about the
escalation operation that a different action calls.  Everything built from
the slot then follows the slot's action, while the hazard points at the
other one.

The check is deterministic.  A hazard depends on an operation when its
description names, as a whole identifier, the ``operation`` of some control
action in the final structure.  A hazard that names no such operation is
not checked.  For each hazard an ICA cites, at least one named operation
must be the operation of the slot's own control action; otherwise the ICA
is flagged with the slots that own the named operations.

A mismatch is flagged, never moved.  The ICA's deviation, context, and loss
were written for the slot's own action, so moving it to the owning slot
would describe one action under another's identity.  An operation can also
belong to several actions, and a hazard can name several operations, so the
owning slot is often not unique.  A lexical match cannot tell a wrong tie
from a real causal path through another action either (a wrong lookup that
leads to a harmful update), so the flag removes nothing and leaves the
judgement to the reader.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from asago_scenario_generator.models.obligation_consideration import (
    ConsiderationDiagnostic,
)
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.ica_enumeration import (
    ICAEnumeration,
    ICASlot,
)
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis

SLOT_HAZARD_MISMATCH_CODE = "ica_hazard_operation_outside_slot"


@dataclass(frozen=True)
class SlotHazardMismatch:
    """One cited hazard whose operations the ICA's slot action does not invoke.

    ``owning_slot_ids`` are the same-category slots of every control action
    that invokes one of ``hazard_operations``, in structure order.
    """

    ica_id: str
    slot_id: str
    control_action_id: str
    slot_operation: str | None
    hazard_id: str
    hazard_operations: tuple[str, ...]
    owning_slot_ids: tuple[str, ...]

    @property
    def reason(self) -> str:
        """Describe the mismatch and the slots that own the operation."""
        invoked = (
            f"invokes `{self.slot_operation}`"
            if self.slot_operation
            else "invokes no operation"
        )
        operations = ", ".join(f"`{name}`" for name in self.hazard_operations)
        if len(self.owning_slot_ids) == 1:
            owner = f"the owning slot is {self.owning_slot_ids[0]}"
        else:
            owner = "the owning slots are " + ", ".join(self.owning_slot_ids)
        return (
            f"hazard {self.hazard_id} depends on {operations}, but control "
            f"action {self.control_action_id} of slot {self.slot_id} {invoked}; "
            f"{owner}"
        )


def find_slot_hazard_mismatches(
    enumeration: ICAEnumeration,
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
) -> tuple[SlotHazardMismatch, ...]:
    """Return every cited hazard whose operations lie outside the ICA's slot."""
    owners = _operation_owners(control_structure)
    if not owners:
        return ()
    hazard_operations = {
        hazard.hazard_id: _named_operations(hazard.description, owners)
        for hazard in loss_analysis.hazards
    }
    slot_operations = _slot_operations(control_structure)
    return tuple(
        mismatch
        for slot in enumeration.slots
        if not slot.is_na
        for mismatch in _slot_mismatches(
            slot, hazard_operations, owners, slot_operations
        )
    )


def _operation_owners(
    control_structure: ControlStructure,
) -> dict[str, tuple[tuple[str, str], ...]]:
    """Map each operation to the (responsibility, action) pairs invoking it."""
    owners: dict[str, list[tuple[str, str]]] = {}
    for resp in control_structure.responsibilities:
        for action in resp.control_actions:
            if action.operation:
                owners.setdefault(action.operation, []).append(
                    (resp.resp_id, action.ca_id)
                )
    return {name: tuple(pairs) for name, pairs in owners.items()}


def _slot_operations(control_structure: ControlStructure) -> dict[tuple[str, str], str]:
    return {
        (resp.resp_id, action.ca_id): action.operation
        for resp in control_structure.responsibilities
        for action in resp.control_actions
        if action.operation
    }


def _named_operations(text: str, operations: Mapping[str, object]) -> tuple[str, ...]:
    """Return the operations *text* names as whole identifiers, sorted."""
    return tuple(
        sorted(
            name
            for name in operations
            if re.search(rf"(?<![\w]){re.escape(name)}(?![\w])", text)
        )
    )


def _slot_mismatches(
    slot: ICASlot,
    hazard_operations: Mapping[str, tuple[str, ...]],
    owners: Mapping[str, tuple[tuple[str, str], ...]],
    slot_operations: Mapping[tuple[str, str], str],
) -> list[SlotHazardMismatch]:
    # A coordination-link slot has no responsibility and invokes no operation.
    own = slot_operations.get((str(slot.responsibility), slot.control_action))
    mismatches: list[SlotHazardMismatch] = []
    for ica in slot.icas:
        for hazard_id in ica.related_hazards:
            named = hazard_operations.get(hazard_id, ())
            if not named or own in named:
                continue
            mismatches.append(
                SlotHazardMismatch(
                    ica_id=ica.ica_id,
                    slot_id=slot.slot_id,
                    control_action_id=slot.control_action,
                    slot_operation=own,
                    hazard_id=hazard_id,
                    hazard_operations=named,
                    owning_slot_ids=_owning_slot_ids(slot, named, owners),
                )
            )
    return mismatches


def _owning_slot_ids(
    slot: ICASlot,
    operations: Sequence[str],
    owners: Mapping[str, tuple[tuple[str, str], ...]],
) -> tuple[str, ...]:
    slot_ids: list[str] = []
    for name in operations:
        for resp_id, ca_id in owners[name]:
            slot_id = f"{resp_id}:{ca_id}:{slot.uca_type.value}"
            if slot_id not in slot_ids:
                slot_ids.append(slot_id)
    return tuple(slot_ids)


def slot_hazard_diagnostics(
    mismatches: Sequence[SlotHazardMismatch],
) -> tuple[ConsiderationDiagnostic, ...]:
    """Record each mismatch as a warning that names its ICA."""
    return tuple(
        ConsiderationDiagnostic(
            code=SLOT_HAZARD_MISMATCH_CODE,
            detail=mismatch.reason,
            refs=(mismatch.ica_id,),
        )
        for mismatch in mismatches
    )


def flag_slot_hazard_mismatches(
    enumeration: ICAEnumeration,
    mismatches: Sequence[SlotHazardMismatch],
) -> ICAEnumeration:
    """Add each mismatch to its ICA's quality warnings; change nothing else."""
    if not mismatches:
        return enumeration
    by_ica: dict[str, list[str]] = {}
    for mismatch in mismatches:
        by_ica.setdefault(mismatch.ica_id, []).append(
            f"{SLOT_HAZARD_MISMATCH_CODE}: {mismatch.reason}"
        )
    slots = []
    for slot in enumeration.slots:
        if not any(ica.ica_id in by_ica for ica in slot.icas):
            slots.append(slot)
            continue
        icas = [
            ica.model_copy(
                update={
                    "quality_warnings": [
                        *ica.quality_warnings,
                        *(
                            warning
                            for warning in by_ica.get(ica.ica_id, ())
                            if warning not in ica.quality_warnings
                        ),
                    ]
                }
            )
            for ica in slot.icas
        ]
        slots.append(slot.model_copy(update={"icas": icas}))
    return enumeration.model_copy(update={"slots": slots})


__all__ = [
    "SLOT_HAZARD_MISMATCH_CODE",
    "SlotHazardMismatch",
    "find_slot_hazard_mismatches",
    "flag_slot_hazard_mismatches",
    "slot_hazard_diagnostics",
]
