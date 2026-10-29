"""Withhold a NOT_PROVIDED ICA that repeats an INCORRECT ICA of its action.

Both ICAs are on the same controller and control action and cite the same
context row, hazards and constraints. The NOT_PROVIDED ICA then states that
omitting the action in that context causes the hazard that the INCORRECT ICA
says providing it causes; for one hazard in one context both cannot hold. In
the case this guards against the omission is the inverted one: providing the
action is the hazard, so the scenario built from the omission fails an agent
for the behavior its INCORRECT sibling states as safe.

The slot fill sends every slot in a request of its own, so the two ICAs meet
only once the per-slot replies are assembled, and no correction can be sent
then. The check is deterministic and runs on the assembled slots: each
flagged NOT_PROVIDED ICA is removed from its slot, with a diagnostic that
names both ICAs and what they share. The slot keeps the identifiers of its
other ICAs, and a slot left with no ICA is unresolved. Every obligation or
mechanism result that credited a withheld ICA no longer does: it keeps its
other ICAs, or becomes unresolved when it had no other, and carries the
diagnostic. An ICA that cites no context row is never compared.
"""

from __future__ import annotations

from collections.abc import MutableMapping, MutableSequence, Sequence
from typing import Any

from asago_scenario_generator.models.obligation_consideration import (
    ConsiderationDiagnostic,
)
from asago_scenario_generator.stpa.models.ica_enumeration import (
    ICA,
    ICASlot,
    UCAType,
)

INVERTED_OMISSION_CODE = "ica_inverted_omission_withheld"
_WITHHELD_SLOT_REASON = (
    "Every finding of this slot repeats an INCORRECT finding of the same "
    "control action and was withheld."
)


def inverted_omissions(slots: Sequence[ICASlot]) -> list[tuple[ICA, ICA]]:
    """Return each (NOT_PROVIDED ICA, INCORRECT ICA) pair the check flags."""

    def action(slot: ICASlot) -> tuple[str | None, str]:
        return (slot.responsibility or slot.coordination_link, slot.control_action)

    def key(ica: ICA) -> tuple[str | None, frozenset[str], frozenset[str]]:
        return (
            ica.context_row,
            frozenset(ica.related_hazards),
            frozenset(ica.related_constraints),
        )

    provided: dict[tuple[Any, ...], ICA] = {}
    for slot in slots:
        if slot.uca_type is UCAType.incorrect:
            for ica in slot.icas:
                if ica.context_row is not None:
                    provided.setdefault((action(slot), key(ica)), ica)
    return [
        (ica, provided[(action(slot), key(ica))])
        for slot in slots
        if slot.uca_type is UCAType.not_provided
        for ica in slot.icas
        if (action(slot), key(ica)) in provided
    ]


def withhold_inverted_omissions(
    slots: MutableMapping[str, ICASlot],
    pairs: MutableSequence[Any],
    mechanism_pairs: MutableSequence[Any],
    diagnostics: MutableSequence[ConsiderationDiagnostic],
) -> None:
    """Remove each flagged NOT_PROVIDED ICA in place; see the module docstring.

    ``slots`` maps slot IDs to the assembled slots; ``pairs`` and
    ``mechanism_pairs`` hold the obligation and mechanism results.
    """
    flagged = inverted_omissions(list(slots.values()))
    if not flagged:
        return
    reasons = {
        omitted.ica_id: _diagnostic(omitted, sibling) for omitted, sibling in flagged
    }
    diagnostics.extend(reasons.values())
    for slot_id, slot in list(slots.items()):
        kept = [ica for ica in slot.icas if ica.ica_id not in reasons]
        if len(kept) == len(slot.icas):
            continue
        slots[slot_id] = ICASlot.model_validate(
            {
                **slot.model_dump(mode="python"),
                "icas": kept,
                "unresolved_reason": None if kept else _WITHHELD_SLOT_REASON,
            }
        )
    icas = {ica.ica_id: ica for slot in slots.values() for ica in slot.icas}
    for results in (pairs, mechanism_pairs):
        results[:] = [_uncredited(item, reasons, icas) for item in results]


def _diagnostic(omitted: ICA, sibling: ICA) -> ConsiderationDiagnostic:
    return ConsiderationDiagnostic(
        code=INVERTED_OMISSION_CODE,
        detail=(
            f"{omitted.ica_id} withheld: it cites the same context row "
            f"({omitted.context_row}), hazards "
            f"({', '.join(sorted(omitted.related_hazards))}) and constraints "
            f"({', '.join(sorted(omitted.related_constraints))}) as "
            f"{sibling.ica_id}. The NOT_PROVIDED finding states that omitting "
            "the action in that context causes the hazard, and the INCORRECT "
            "finding that providing it does; both cannot hold for the same "
            "hazard."
        ),
        refs=(omitted.ica_id, sibling.ica_id),
    )


def _uncredited(
    item: Any,
    reasons: dict[str, ConsiderationDiagnostic],
    icas: dict[str, ICA],
) -> Any:
    """Return ``item`` without credit for any withheld ICA."""
    withheld = [ica_id for ica_id in item.ica_ids if ica_id in reasons]
    if item.disposition != "finding" or not withheld:
        return item
    retained = tuple(ica_id for ica_id in item.ica_ids if ica_id not in reasons)
    payload = item.model_dump(mode="python", exclude={"pair_id"})
    payload["diagnostics"] = (
        *item.diagnostics,
        *(reasons[ica_id] for ica_id in withheld),
    )
    if retained:
        payload["ica_ids"] = retained
        payload["hazard_ids"] = _refs(retained, icas, "related_hazards")
        payload["constraint_ids"] = _refs(retained, icas, "related_constraints")
    else:
        payload.update(
            disposition="unresolved",
            ica_ids=(),
            exec_candidate_ids=(),
            hazard_ids=(),
            constraint_ids=(),
        )
    return type(item).model_validate(payload)


def _refs(ica_ids: Sequence[str], icas: dict[str, ICA], field: str) -> tuple[str, ...]:
    return tuple(
        sorted({ref for ica_id in ica_ids for ref in getattr(icas[ica_id], field)})
    )


__all__ = [
    "INVERTED_OMISSION_CODE",
    "inverted_omissions",
    "withhold_inverted_omissions",
]
