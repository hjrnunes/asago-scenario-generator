"""One id index over a control structure and its loss analysis, and one join.

:func:`mechanism_candidates` walks the typed control structure from untrusted
feedback to the actions and coordination links it reaches.
:func:`mechanism_join` runs the same walk under the authority filter and
records why each channel's candidates were kept or dropped.

The index is rebuilt per call rather than cached: the STPA models are mutable,
so a cache keyed on them could serve records that were changed in place.
Validated models carry unique IDs; for an unvalidated model that repeats an
ID, the first record wins.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any, TypeVar

from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlActionEffectKind,
    ControlledProcess,
    ControlStructure,
    CoordinationLink,
    CoordinationMechanism,
    FeedbackAuthorityStatus,
    FeedbackChannel,
    FeedbackSourceKind,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
    ResponsibilityConstraint,
    coordination_process_model_owner,
)
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    SecurityConstraint,
)

_Record = TypeVar("_Record")


def _first_by_id(records: Iterable[_Record], id_field: str) -> dict[str, _Record]:
    result: dict[str, _Record] = {}
    for record in records:
        result.setdefault(getattr(record, id_field), record)
    return result


@dataclass(frozen=True)
class SlotPath:
    """The records one slot names; a missing record is ``None``, never an error.

    ``owner`` is the owning responsibility, or the source of the slot's
    coordination link.  ``action`` is the control action that responsibility
    owns, and ``link`` is the coordination link; each is ``None`` for the
    other kind of slot.
    """

    owner: Responsibility | None
    action: ControlAction | None
    link: CoordinationLink | None


@dataclass(frozen=True)
class StpaIndex:
    """Records of one control structure and loss analysis, by ID."""

    responsibilities: Mapping[str, Responsibility]
    responsibility_constraints: Mapping[str, ResponsibilityConstraint]
    process_model_parts: Mapping[str, ProcessModelPart]
    control_actions: Mapping[str, ControlAction]
    feedback_channels: Mapping[str, FeedbackChannel]
    controlled_processes: Mapping[str, ControlledProcess]
    coordination_links: Mapping[str, CoordinationLink]
    coordination_mechanisms: Mapping[str, CoordinationMechanism]
    hazards: Mapping[str, Hazard]
    security_constraints: Mapping[str, SecurityConstraint]
    losses: Mapping[str, Loss]
    _owned_actions: Mapping[tuple[str, str], ControlAction]
    _structural_descriptions: Mapping[str, str]

    def owned_action(
        self, resp_id: str | None, ca_id: str | None
    ) -> ControlAction | None:
        """Return the action only when *resp_id* owns it."""
        return self._owned_actions.get((str(resp_id), str(ca_id)))

    def slot_path(self, slot: Any) -> SlotPath:
        """Resolve a slot's owner, owned action, and coordination link.

        Each caller decides how to fail on a missing record, so this raises
        nothing.
        """
        if slot.responsibility is not None:
            owner = self.responsibilities.get(slot.responsibility)
            action = (
                None
                if owner is None
                else self.owned_action(owner.resp_id, slot.control_action)
            )
            return SlotPath(owner, action, None)
        if slot.coordination_link is not None:
            link = self.coordination_links.get(slot.coordination_link)
            owner = None if link is None else self.responsibilities.get(link.source)
            return SlotPath(owner, None, link)
        return SlotPath(None, None, None)

    def structural_descriptions(self) -> dict[str, str]:
        """Describe every structural ID, each responsibility with its children."""
        return dict(self._structural_descriptions)

    def loss_descriptions(self) -> dict[str, str]:
        """Describe every security constraint, hazard, and loss ID."""
        return {
            identity: record.description
            for records in (self.security_constraints, self.hazards, self.losses)
            for identity, record in records.items()
        }


def build_stpa_index(
    control_structure: ControlStructure,
    loss_analysis: LossAnalysis | None = None,
) -> StpaIndex:
    """Index *control_structure* and, when given, *loss_analysis* by ID."""
    responsibilities = control_structure.responsibilities
    links = control_structure.coordination_links
    hazards, constraints, losses = _loss_records(loss_analysis)
    return StpaIndex(
        responsibilities=_first_by_id(responsibilities, "resp_id"),
        responsibility_constraints=_first_by_id(
            _children(responsibilities, "responsibility_constraints"), "rc_id"
        ),
        process_model_parts=_first_by_id(
            _children(responsibilities, "process_model_parts"), "pm_id"
        ),
        control_actions=_first_by_id(
            _children(responsibilities, "control_actions"), "ca_id"
        ),
        feedback_channels=_first_by_id(
            _children(responsibilities, "feedback_channels"), "fb_id"
        ),
        controlled_processes=_first_by_id(
            control_structure.controlled_processes, "cp_id"
        ),
        coordination_links=_first_by_id(links, "link_id"),
        coordination_mechanisms=_first_by_id(
            [link.coordination_mechanism for link in links], "cm_id"
        ),
        hazards=_first_by_id(hazards, "hazard_id"),
        security_constraints=_first_by_id(constraints, "constraint_id"),
        losses=_first_by_id(losses, "loss_id"),
        _owned_actions=_owned_actions(responsibilities),
        _structural_descriptions=_describe_structure(control_structure),
    )


def _children(responsibilities: Iterable[Responsibility], field: str) -> list[Any]:
    return [child for item in responsibilities for child in getattr(item, field)]


def _loss_records(
    loss_analysis: LossAnalysis | None,
) -> tuple[Sequence[Hazard], Sequence[SecurityConstraint], Sequence[Loss]]:
    if loss_analysis is None:
        return (), (), ()
    return (
        loss_analysis.hazards,
        loss_analysis.security_constraints,
        (*loss_analysis.risk_card_losses, *loss_analysis.use_case_losses),
    )


def _owned_actions(
    responsibilities: Iterable[Responsibility],
) -> dict[tuple[str, str], ControlAction]:
    result: dict[tuple[str, str], ControlAction] = {}
    for responsibility in responsibilities:
        for action in responsibility.control_actions:
            result.setdefault((responsibility.resp_id, action.ca_id), action)
    return result


def _describe_structure(control_structure: ControlStructure) -> dict[str, str]:
    result: dict[str, str] = {}
    for responsibility in control_structure.responsibilities:
        result.setdefault(responsibility.resp_id, responsibility.description)
        for children, identity in (
            (responsibility.responsibility_constraints, "rc_id"),
            (responsibility.process_model_parts, "pm_id"),
            (responsibility.control_actions, "ca_id"),
            (responsibility.feedback_channels, "fb_id"),
        ):
            for child in children:
                result.setdefault(getattr(child, identity), child.description)
    for process in control_structure.controlled_processes:
        result.setdefault(process.cp_id, process.description)
    for link in control_structure.coordination_links:
        result.setdefault(link.link_id, link.description)
        mechanism = link.coordination_mechanism
        result.setdefault(mechanism.cm_id, mechanism.description)
    return result


SOURCE_MECHANISMS: Mapping[FeedbackSourceKind, str] = MappingProxyType(
    {
        FeedbackSourceKind.retrieved_content: "retrieved_instructions",
        FeedbackSourceKind.conversation_history: "stale_history",
        FeedbackSourceKind.user_message: "user_claim",
    }
)
"""The mechanism an untrusted channel's source kind suggests on every path.

- ``retrieved_instructions``: retrieved free text can change what the
  controller believes about its instructions or authority;
- ``stale_history``: an earlier turn can justify an action after the state it
  described has changed;
- ``user_claim``: the current message's claim can stand in for the value the
  variable should record.
"""

CROSS_CONTROLLER_MECHANISM = "delegated_authority"
"""The mechanism of a path whose untrusted belief reaches another controller.

One controller's adversary-influenced belief or message can count as
permission for the other.
"""


@dataclass(frozen=True)
class MechanismCandidate:
    """One mechanism worth considering on one typed path.

    ``path`` is ``(FB, PM, CA)``: the untrusted feedback channel, the variable
    it updates, and a control action that lists the variable in
    ``process_model_refs``.  Or it is ``(FB, PM, CL)``: a coordination link
    whose ``source`` owns that variable as its ``shared_pm``.
    """

    mechanism: str
    path: tuple[str, str, str]


def mechanism_candidates(
    control_structure: ControlStructure,
    *,
    authority_filter: bool = False,
) -> tuple[MechanismCandidate, ...]:
    """Join untrusted feedback to the actions and links its variable reaches.

    A channel is untrusted when its ``source_kind`` is, which says only that an
    adversary could author the information, not that one can.  For each such
    channel the join follows ``updates`` to its variable, then:

    - to every control action that lists the variable in
      ``process_model_refs``;
    - to every coordination link whose ``shared_pm`` is the variable and is
      owned by the link's ``source``, as
      :func:`coordination_process_model_owner` resolves it.  A link is
      directed: its ``source`` issues the coordination and its ``target``
      receives it, so such a link carries the adversary-influenced belief to
      the ``target``.  A link whose variable belongs to its ``target``, to a
      third controller, or to both endpoints, and a link from a controller to
      itself, join no path.  The path stops at the link: the target's actions
      cannot list the variable, and the link names none of them, so extending
      the path to its actions would cross the link with every action.

    Each path gets the mechanism of its channel's source kind, from
    :data:`SOURCE_MECHANISMS`.  A path that reaches another controller, through
    a coordination link or an action whose effect is ``agent_message``, also
    gets :data:`CROSS_CONTROLLER_MECHANISM`.  Candidates follow the structure's
    order: responsibilities, their channels, the actions of every
    responsibility, then the links; a repeated candidate is kept once.

    With *authority_filter*, the candidates are those :func:`mechanism_join`
    keeps, in the same order; without it the join is unchanged.
    """
    if authority_filter:
        return tuple(item.candidate for item in mechanism_join(control_structure).kept)
    actions = _children(control_structure.responsibilities, "control_actions")
    result: dict[MechanismCandidate, None] = {}
    for channel in _children(control_structure.responsibilities, "feedback_channels"):
        if not channel.untrusted:
            continue
        for path, crosses in _channel_paths(control_structure, actions, channel):
            _add_candidates(
                result, path, SOURCE_MECHANISMS.get(channel.source_kind), crosses
            )
    return tuple(result)


class ReachBasis(str, Enum):
    """The structure field that decided whether an adversary reaches a channel.

    - ``argument_evidence``: the updated variable cites an ``argument:``
      evidence reference.  Its value is a tool argument the controller fills
      from the conversation, so the user can shape it: reachable, whatever
      ``source_kind`` says.
    - ``own_controller``: the channel's ``source`` is the responsibility that
      owns the channel.  The controller produces the information itself (its
      own check, classification, or draft), so no adversary authors it:
      not reachable, whatever ``source_kind`` says.  Adversary influence on
      such a value enters through the controller's other channels, which the
      join follows on their own.
    - ``source_kind``: neither applies, so ``source_kind`` decides, as in the
      unfiltered join.  A source that is a controlled process or another
      controller names where the information enters, not who authors it.
    """

    argument_evidence = "argument_evidence"
    own_controller = "own_controller"
    source_kind = "source_kind"


class DropReason(str, Enum):
    """Why the authority filter drops a channel's candidates.

    - ``authoritative``: an adversary reaches the channel, but its
      ``authority_for_update`` says it is entitled to set the variable;
    - ``own_controller``: ``source_kind`` is untrusted, but the channel's
      source is its own controller (:attr:`ReachBasis.own_controller`).
    """

    authoritative = "authoritative"
    own_controller = "own_controller"


ASSESSED_AUTHORITY = frozenset(
    {FeedbackAuthorityStatus.non_authoritative, FeedbackAuthorityStatus.conditional}
)
"""The statuses that settle a kept channel's lack of authority.

A kept channel with any other status is kept only because its authority is
``unknown``: recorded so, or absent.
"""


@dataclass(frozen=True)
class KeptCandidate:
    """A candidate the authority filter keeps, with what kept it.

    ``authority`` is the channel's status, ``unknown`` when
    ``authority_for_update`` is absent; ``authority_recorded`` says whether it
    was present.  ``reach`` is the field that made the channel reachable.
    """

    candidate: MechanismCandidate
    authority: FeedbackAuthorityStatus
    authority_recorded: bool
    reach: ReachBasis

    @property
    def authority_assessed(self) -> bool:
        """Whether the record settles that the channel lacks authority."""
        return self.authority in ASSESSED_AUTHORITY


@dataclass(frozen=True)
class DroppedCandidate:
    """A candidate the authority filter drops, and why."""

    candidate: MechanismCandidate
    reason: DropReason


@dataclass(frozen=True)
class MechanismJoin:
    """The filtered join: what it keeps and what it drops, in structure order.

    ``kept`` holds the filtered candidates.  ``dropped`` holds the candidates
    of channels the filter refuses, with the mechanisms they would carry; for
    an ``own_controller`` drop these are exactly the unfiltered join's
    candidates on that channel.
    """

    kept: tuple[KeptCandidate, ...]
    dropped: tuple[DroppedCandidate, ...]


def mechanism_join(control_structure: ControlStructure) -> MechanismJoin:
    """Join adversary-reachable feedback that lacks authority over its variable.

    The paths and mechanisms are those of :func:`mechanism_candidates`; the
    filter changes only which channels start a path:

    1. Reach.  A channel is adversary-reachable as :class:`ReachBasis`
       decides, in its order: the updated variable's ``evidence_refs``, then
       the channel's ``source`` against the responsibility that owns the
       channel, then ``source_kind``.  A channel the ``argument:`` rule makes
       reachable takes its source kind's mechanism, or ``user_claim`` when the
       kind names none.  Other evidence prefixes (``state:``, ``session:``,
       ``policy:``, ``operation:``) decide nothing: a variable can cite them
       and still hold what the user wrote.
    2. Authority.  A reachable channel is kept unless its
       ``update_authority`` status is ``authoritative``; ``non_authoritative``,
       ``conditional`` and ``unknown`` (recorded or absent) keep it.

    A channel that fails both is dropped for the first.  A channel neither
    join would follow is not reported.
    """
    actions = _children(control_structure.responsibilities, "control_actions")
    kept: dict[MechanismCandidate, KeptCandidate] = {}
    dropped: dict[MechanismCandidate, DroppedCandidate] = {}
    for owner in control_structure.responsibilities:
        variables = _first_by_id(owner.process_model_parts, "pm_id")
        for channel in owner.feedback_channels:
            reach, reachable = _channel_reach(owner, channel, variables)
            mechanism = SOURCE_MECHANISMS.get(channel.source_kind)
            if mechanism is None and reach is ReachBasis.argument_evidence:
                mechanism = SOURCE_MECHANISMS[FeedbackSourceKind.user_message]
            status = channel.update_authority.status
            reason: DropReason | None = None
            if not reachable:
                if reach is not ReachBasis.own_controller or not channel.untrusted:
                    continue
                reason = DropReason.own_controller
            elif status is FeedbackAuthorityStatus.authoritative:
                reason = DropReason.authoritative
            found: dict[MechanismCandidate, None] = {}
            for path, crosses in _channel_paths(control_structure, actions, channel):
                _add_candidates(found, path, mechanism, crosses)
            for candidate in found:
                if reason is None:
                    kept.setdefault(
                        candidate,
                        KeptCandidate(
                            candidate,
                            status,
                            channel.authority_for_update is not None,
                            reach,
                        ),
                    )
                else:
                    dropped.setdefault(candidate, DroppedCandidate(candidate, reason))
    return MechanismJoin(tuple(kept.values()), tuple(dropped.values()))


def _channel_reach(
    owner: Responsibility,
    channel: FeedbackChannel,
    variables: Mapping[str, ProcessModelPart],
) -> tuple[ReachBasis, bool]:
    variable = variables.get(channel.updates)
    if variable is not None and any(
        ref.startswith("argument:") for ref in variable.evidence_refs
    ):
        return ReachBasis.argument_evidence, True
    source = channel.source
    if (
        source is not None
        and source.type is ReferenceType.responsibility
        and source.id == owner.resp_id
    ):
        return ReachBasis.own_controller, False
    return ReachBasis.source_kind, channel.untrusted


def _channel_paths(
    control_structure: ControlStructure,
    actions: Sequence[ControlAction],
    channel: FeedbackChannel,
) -> list[tuple[tuple[str, str, str], bool]]:
    """Every path from *channel*, and whether it reaches another controller."""
    variable = channel.updates
    paths = [
        (
            (channel.fb_id, variable, action.ca_id),
            action.effect_kind is ControlActionEffectKind.agent_message,
        )
        for action in actions
        if variable in action.process_model_refs
    ]
    paths += [
        ((channel.fb_id, variable, link.link_id), True)
        for link in control_structure.coordination_links
        if link.shared_pm == variable and _issued_by_owner(control_structure, link)
    ]
    return paths


def _issued_by_owner(
    control_structure: ControlStructure, link: CoordinationLink
) -> bool:
    if link.source == link.target:
        return False
    try:
        owner = coordination_process_model_owner(control_structure, link)
    except ValueError:
        return False
    return owner.resp_id == link.source


def _add_candidates(
    result: dict[MechanismCandidate, None],
    path: tuple[str, str, str],
    source_mechanism: str | None,
    crosses: bool,
) -> None:
    for mechanism in (
        source_mechanism,
        CROSS_CONTROLLER_MECHANISM if crosses else None,
    ):
        if mechanism is not None:
            result.setdefault(MechanismCandidate(mechanism, path), None)


__all__ = [
    "ASSESSED_AUTHORITY",
    "CROSS_CONTROLLER_MECHANISM",
    "SOURCE_MECHANISMS",
    "DropReason",
    "DroppedCandidate",
    "KeptCandidate",
    "MechanismCandidate",
    "MechanismJoin",
    "ReachBasis",
    "SlotPath",
    "StpaIndex",
    "build_stpa_index",
    "mechanism_candidates",
    "mechanism_join",
]
