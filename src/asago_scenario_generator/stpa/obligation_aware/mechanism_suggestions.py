"""Mechanism suggestions: library mechanisms the graph join proposes for slots.

A suggestion works bottom up.  The authority-filtered join
(:func:`~asago_scenario_generator.stpa.obligation_aware.stpa_index.mechanism_candidates`)
finds typed paths from untrusted feedback to the control actions and
coordination links that read its variable, and each path proposes its
mechanisms for the ICA slots of that action or link.  A suggestion carries no
risk and makes no coverage claim: no routing call is made for it, it never
enters a routing prompt, and obligation accounting never counts it.

The join's fit is not evidence that a path carries a mechanism, so a proposal
reaches slot filling only after the mechanism verifier judges its path
against the mechanism's library entry.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType

from asago_scenario_generator.stpa.mechanism_library import (
    MechanismId,
    bundled_mechanism_library,
)
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.obligation_aware.stpa_index import (
    DropReason,
    MechanismCandidate,
    mechanism_join,
)
from asago_scenario_generator.stpa.threat_enum.slot_creation import (
    SlotPlaceholder,
    create_slots,
    requires_provider_slot_analysis,
)

MechanismPath = tuple[str, str, str]
"""``(FB, PM, CA)`` or ``(FB, PM, CL)``, as :class:`MechanismCandidate` names it."""


def library_order() -> Mapping[MechanismId, int]:
    """The position of each mechanism in the bundled library."""
    return MappingProxyType(
        {
            entry.id: index
            for index, entry in enumerate(bundled_mechanism_library().mechanisms)
        }
    )


@dataclass(frozen=True)
class ProposedSuggestion:
    """One mechanism the join proposes for one slot, with every path it took.

    ``paths`` follow the join's structure order; a slot reached by several
    channels has one path per channel.
    """

    mechanism: MechanismId
    slot_id: str
    paths: tuple[MechanismPath, ...]


@dataclass(frozen=True)
class MechanismProposal:
    """What the join proposes for a slot universe, and what it holds back.

    - ``proposed``: suggestions for slots the provider analyzes;
    - ``structural``: suggestions for slots decided by structure alone (an
      ineligible ``WRONG_DURATION``), which no request carries;
    - ``filtered``: the ``(mechanism, slot)`` pairs only the unfiltered join
      reaches, with the authority filter's reasons for dropping each path.

    ``proposed`` and ``structural`` are ordered by slot ID, then library order.
    """

    proposed: tuple[ProposedSuggestion, ...] = ()
    structural: tuple[ProposedSuggestion, ...] = ()
    filtered: Mapping[tuple[MechanismId, str], tuple[DropReason, ...]] = (
        MappingProxyType({})
    )

    def candidates(self) -> tuple[MechanismCandidate, ...]:
        """The distinct ``(mechanism, path)`` pairs the proposed slots need judged.

        They are ordered by first appearance in ``proposed``.
        """
        found: dict[MechanismCandidate, None] = {}
        for item in self.proposed:
            for path in item.paths:
                found.setdefault(MechanismCandidate(item.mechanism, path), None)
        return tuple(found)


def _slots_by_path_end(
    slots: Iterable[SlotPlaceholder],
) -> dict[str, list[SlotPlaceholder]]:
    """Index slots by the action or link a join path ends at."""
    result: dict[str, list[SlotPlaceholder]] = {}
    for slot in slots:
        end = slot.coordination_link or slot.control_action
        result.setdefault(end, []).append(slot)
    return result


def _pair_paths(
    candidates: Iterable[MechanismCandidate],
    slots_by_end: Mapping[str, Sequence[SlotPlaceholder]],
) -> dict[tuple[MechanismId, str], list[MechanismPath]]:
    result: dict[tuple[MechanismId, str], list[MechanismPath]] = {}
    for candidate in candidates:
        for slot in slots_by_end.get(candidate.path[2], ()):
            paths = result.setdefault((candidate.mechanism, slot.slot_id), [])
            if candidate.path not in paths:
                paths.append(candidate.path)
    return result


def propose_mechanism_suggestions(
    control_structure: ControlStructure,
    slots: Sequence[SlotPlaceholder] | None = None,
) -> MechanismProposal:
    """Propose each filtered join candidate for every slot of its action or link.

    A path ``(FB, PM, CA)`` reaches the four slots of ``CA``; a path ``(FB,
    PM, CL)`` the four slots of ``CL``.  *slots* defaults to every slot of
    the structure.  The join runs with its authority filter on; the
    unfiltered candidates it drops are reported in ``filtered`` and propose
    nothing.
    """
    universe = (
        tuple(slots) if slots is not None else tuple(create_slots(control_structure))
    )
    by_end = _slots_by_path_end(universe)
    slot_by_id = {slot.slot_id: slot for slot in universe}
    join = mechanism_join(control_structure)
    kept = _pair_paths((item.candidate for item in join.kept), by_end)
    dropped: dict[tuple[MechanismId, str], list[DropReason]] = {}
    for item in join.dropped:
        for slot in by_end.get(item.candidate.path[2], ()):
            key = (item.candidate.mechanism, slot.slot_id)
            if key in kept:
                continue
            reasons = dropped.setdefault(key, [])
            if item.reason not in reasons:
                reasons.append(item.reason)
    rank = library_order()
    proposed: list[ProposedSuggestion] = []
    structural: list[ProposedSuggestion] = []
    for (mechanism, slot_id), paths in sorted(
        kept.items(), key=lambda item: (item[0][1], rank[item[0][0]])
    ):
        suggestion = ProposedSuggestion(mechanism, slot_id, tuple(paths))
        if requires_provider_slot_analysis(slot_by_id[slot_id]):
            proposed.append(suggestion)
        else:
            structural.append(suggestion)
    return MechanismProposal(
        proposed=tuple(proposed),
        structural=tuple(structural),
        filtered=MappingProxyType(
            {key: tuple(value) for key, value in sorted(dropped.items())}
        ),
    )


__all__ = [
    "MechanismPath",
    "MechanismProposal",
    "ProposedSuggestion",
    "library_order",
    "propose_mechanism_suggestions",
]
