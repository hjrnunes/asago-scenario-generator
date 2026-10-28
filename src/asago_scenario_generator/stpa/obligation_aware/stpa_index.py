"""One id index over a control structure and its loss analysis, and one join.

:func:`mechanism_candidates` walks the typed control structure from untrusted
feedback to the actions and coordination links it reaches.
:func:`mechanism_join` runs the same walk under the authority filter and
records why each channel's candidates were kept or dropped.  Both take
``signature_retrieval``, off by default, which matches every channel against
each mechanism library entry's signature instead of the fixed source-kind
labels; no pipeline stage turns it on.

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

from asago_scenario_generator.stpa.mechanism_library import (
    ControllerCrossing,
    MechanismId,
    MechanismSignature,
    bundled_mechanism_library,
)
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


SOURCE_MECHANISMS: Mapping[FeedbackSourceKind, MechanismId] = MappingProxyType(
    {
        FeedbackSourceKind.retrieved_content: MechanismId.retrieved_instructions,
        FeedbackSourceKind.conversation_history: MechanismId.stale_history,
        FeedbackSourceKind.user_message: MechanismId.user_claim,
    }
)
"""The mechanism an untrusted channel's source kind suggests on every path.

Each label is a mechanism library ID, and its entry's signature lists that
source kind.

- ``retrieved_instructions``: retrieved free text can change what the
  controller believes about its instructions or authority;
- ``stale_history``: an earlier turn can justify an action after the state it
  described has changed;
- ``user_claim``: the current message's claim can stand in for the value the
  variable should record.
"""

CROSS_CONTROLLER_MECHANISM = MechanismId.delegated_authority
"""The mechanism of a path whose untrusted belief reaches another controller.

Its library entry's signature must cross controllers.

One controller's adversary-influenced belief or message can count as
permission for the other.
"""


@dataclass(frozen=True)
class MechanismCandidate:
    """One mechanism worth considering on one typed path.

    ``path`` is ``(FB, PM, CA)``: the feedback channel (untrusted, unless
    signature retrieval matched it), the variable it updates, and a control
    action that lists the variable in
    ``process_model_refs``.  Or it is ``(FB, PM, CL)``: a coordination link
    whose ``source`` owns that variable as its ``shared_pm``.
    """

    mechanism: MechanismId
    path: tuple[str, str, str]


def mechanism_candidates(
    control_structure: ControlStructure,
    *,
    authority_filter: bool = False,
    signature_retrieval: bool = False,
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

    With *signature_retrieval*, every channel starts a path, and each path
    gets every library entry whose signature it fits, in library order
    (:func:`signature_fits`).  The signature decides alone: the channel need
    not be untrusted, and its authority is the filter's concern.  Each fixed
    label is an entry that fits wherever the label applies, so the candidates
    without the flag are a subsequence of those with it.

    With *authority_filter*, the candidates are those :func:`mechanism_join`
    keeps, in the same order; without it the join is unchanged.
    """
    if authority_filter:
        join = mechanism_join(
            control_structure, signature_retrieval=signature_retrieval
        )
        return tuple(item.candidate for item in join.kept)
    actions = _children(control_structure.responsibilities, "control_actions")
    result: dict[MechanismCandidate, None] = {}
    for channel in _children(control_structure.responsibilities, "feedback_channels"):
        if not (signature_retrieval or channel.untrusted):
            continue
        for path, crosses in _channel_paths(control_structure, actions, channel):
            for mechanism in _path_mechanisms(channel, crosses, signature_retrieval):
                result.setdefault(MechanismCandidate(mechanism, path), None)
    return tuple(result)


def signature_fits(
    signature: MechanismSignature,
    source_kind: FeedbackSourceKind | None,
    crosses: bool,
) -> bool:
    """Whether a path from a *source_kind* channel fits *signature*'s structure.

    The channel's kind must be one of ``source_kinds``, and the path's crossing
    must meet ``crossing``: ``within_controller`` forbids a path that reaches
    another controller, ``must_cross`` requires one.  Every join path reads its
    variable, so ``process_model_refs`` (``read_by_path``) always holds.  The
    signature's ``authority`` is left to the authority filter.
    """
    if source_kind not in signature.source_kinds:
        return False
    if signature.crossing is ControllerCrossing.within_controller:
        return not crosses
    if signature.crossing is ControllerCrossing.must_cross:
        return crosses
    return True


def _path_mechanisms(
    channel: FeedbackChannel, crosses: bool, signature_retrieval: bool
) -> tuple[MechanismId, ...]:
    """The mechanisms one path from *channel* gets, in library order."""
    if signature_retrieval:
        return tuple(
            entry.id
            for entry in bundled_mechanism_library().mechanisms
            if signature_fits(entry.signature, channel.source_kind, crosses)
        )
    found = (
        SOURCE_MECHANISMS.get(channel.source_kind),
        CROSS_CONTROLLER_MECHANISM if crosses else None,
    )
    return tuple(mechanism for mechanism in found if mechanism is not None)


def admitted_authority(mechanism: MechanismId) -> frozenset[FeedbackAuthorityStatus]:
    """The channel authority statuses under which *mechanism* applies.

    They are its library entry's signature ``authority``.  Most entries admit
    every status but ``authoritative``: a channel entitled to set the value
    cannot plant a false one.  ``stale_feedback`` also admits
    ``authoritative``, because an entitled source's value can still be out of
    date when the action runs.
    """
    return frozenset(bundled_mechanism_library().entry(mechanism).signature.authority)


class ReachBasis(str, Enum):
    """The structure field that decided whether an adversary reaches a channel.

    Only the channel's own fields decide.  The updated variable's
    ``evidence_refs`` describe the variable, not this channel, so they decide
    no channel's reach.

    - ``own_controller``: the channel's ``source`` is the responsibility that
      owns the channel and its ``source_kind`` is ``retrieved_content`` or
      ``conversation_history``: not reachable.  ``source`` says who holds the
      information, and here the controller holds it itself, so the external
      kind labels the controller's own check or state rather than content an
      adversary authored.  A ``user_message`` channel sourced from its own
      controller stays with ``source_kind``: the user authored the text even
      when the controller relays or classifies it.
    - ``source_kind``: otherwise ``source_kind`` decides, as in the unfiltered
      join.  A source that is a controlled process or another controller names
      where the information enters, not who authors it.
    """

    own_controller = "own_controller"
    source_kind = "source_kind"


OWN_CONTROLLER_KINDS = frozenset(
    {FeedbackSourceKind.retrieved_content, FeedbackSourceKind.conversation_history}
)
"""The untrusted kinds that a source on the channel's own controller overrides."""


class DropReason(str, Enum):
    """Why the authority filter drops a channel's candidates.

    - ``authoritative``: an adversary reaches the channel, but its
      ``authority_for_update`` says it is entitled to set the variable, and
      the candidate's mechanism does not apply under that status
      (:func:`admitted_authority`);
    - ``own_controller``: ``source_kind`` is ``retrieved_content`` or
      ``conversation_history``, but the channel's source is its own
      controller (:attr:`ReachBasis.own_controller`).
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


def mechanism_join(
    control_structure: ControlStructure, *, signature_retrieval: bool = False
) -> MechanismJoin:
    """Join adversary-reachable feedback that lacks authority over its variable.

    The paths and mechanisms are those of :func:`mechanism_candidates`, with
    the same *signature_retrieval*; the filter changes only which candidates
    are kept:

    1. Reach.  A channel is adversary-reachable as :class:`ReachBasis`
       decides: its ``source`` against the responsibility that owns it, for
       the kinds in :data:`OWN_CONTROLLER_KINDS`, then its ``source_kind``.
       The filter never makes reachable a channel the unfiltered join skips.
    2. Authority.  A reachable channel's candidate is kept when its
       ``update_authority`` status is one its mechanism admits
       (:func:`admitted_authority`).  Without *signature_retrieval* every
       mechanism admits ``non_authoritative``, ``conditional`` and ``unknown``
       (recorded or absent) but not ``authoritative``.

    A candidate that fails both is dropped for the first.  A channel neither
    join would follow is not reported.
    """
    actions = _children(control_structure.responsibilities, "control_actions")
    kept: dict[MechanismCandidate, KeptCandidate] = {}
    dropped: dict[MechanismCandidate, DroppedCandidate] = {}
    for owner in control_structure.responsibilities:
        for channel in owner.feedback_channels:
            if not (signature_retrieval or channel.untrusted):
                continue
            reach = _channel_reach(owner, channel)
            status = channel.update_authority.status
            found: dict[MechanismCandidate, None] = {}
            for path, crosses in _channel_paths(control_structure, actions, channel):
                for mechanism in _path_mechanisms(
                    channel, crosses, signature_retrieval
                ):
                    found.setdefault(MechanismCandidate(mechanism, path), None)
            for candidate in found:
                reason: DropReason | None = None
                if reach is ReachBasis.own_controller:
                    reason = DropReason.own_controller
                elif status not in admitted_authority(candidate.mechanism):
                    reason = DropReason.authoritative
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


def _channel_reach(owner: Responsibility, channel: FeedbackChannel) -> ReachBasis:
    source = channel.source
    if (
        channel.source_kind in OWN_CONTROLLER_KINDS
        and source is not None
        and source.type is ReferenceType.responsibility
        and source.id == owner.resp_id
    ):
        return ReachBasis.own_controller
    return ReachBasis.source_kind


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


__all__ = [
    "ASSESSED_AUTHORITY",
    "CROSS_CONTROLLER_MECHANISM",
    "OWN_CONTROLLER_KINDS",
    "SOURCE_MECHANISMS",
    "DropReason",
    "DroppedCandidate",
    "KeptCandidate",
    "MechanismCandidate",
    "MechanismJoin",
    "ReachBasis",
    "SlotPath",
    "StpaIndex",
    "admitted_authority",
    "build_stpa_index",
    "mechanism_candidates",
    "mechanism_join",
    "signature_fits",
]
