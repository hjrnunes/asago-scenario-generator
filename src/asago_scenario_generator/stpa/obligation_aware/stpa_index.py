"""One id index over a control structure and its loss analysis, and one join.

:func:`mechanism_candidates` walks the typed control structure from untrusted
feedback to the actions and coordination links it reaches.

The index is rebuilt per call rather than cached: the STPA models are mutable,
so a cache keyed on them could serve records that were changed in place.
Validated models carry unique IDs; for an unvalidated model that repeats an
ID, the first record wins.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, TypeVar

from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlActionEffectKind,
    ControlledProcess,
    ControlStructure,
    CoordinationLink,
    CoordinationMechanism,
    FeedbackChannel,
    FeedbackSourceKind,
    ProcessModelPart,
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
    ``process_model_refs``.  Or it is ``(FB, PM, CL)``: the coordination link
    whose ``shared_pm`` is that variable.
    """

    mechanism: str
    path: tuple[str, str, str]


def mechanism_candidates(
    control_structure: ControlStructure,
) -> tuple[MechanismCandidate, ...]:
    """Join untrusted feedback to the actions and links its variable reaches.

    A channel is untrusted when its ``source_kind`` is, which says only that an
    adversary could author the information, not that one can.  For each such
    channel the join follows ``updates`` to its variable, then:

    - to every control action that lists the variable in
      ``process_model_refs``;
    - to every coordination link whose ``shared_pm`` is the variable and is
      owned by exactly one of the link's endpoints
      (:func:`coordination_process_model_owner`).  The link carries the
      adversary-influenced belief from that owner to the other endpoint.  A
      link whose shared variable belongs to a third controller, or to both
      endpoints, joins no path.  The path stops at the link: the other
      endpoint's actions cannot list the variable, and the link names none of
      them, so extending the path to its actions would cross the link with
      every action.

    Each path gets the mechanism of its channel's source kind, from
    :data:`SOURCE_MECHANISMS`.  A path that reaches another controller, through
    a coordination link or an action whose effect is ``agent_message``, also
    gets :data:`CROSS_CONTROLLER_MECHANISM`.  Candidates follow the structure's
    order: responsibilities, their channels, the actions of every
    responsibility, then the links; a repeated candidate is kept once.
    """
    actions = _children(control_structure.responsibilities, "control_actions")
    result: dict[MechanismCandidate, None] = {}
    for channel in _children(control_structure.responsibilities, "feedback_channels"):
        if not channel.untrusted:
            continue
        variable = channel.updates
        source_mechanism = SOURCE_MECHANISMS.get(channel.source_kind)
        for action in actions:
            if variable in action.process_model_refs:
                crosses = action.effect_kind is ControlActionEffectKind.agent_message
                _add_candidates(
                    result,
                    (channel.fb_id, variable, action.ca_id),
                    source_mechanism,
                    crosses,
                )
        for link in control_structure.coordination_links:
            if link.shared_pm == variable and _endpoint_owned(control_structure, link):
                _add_candidates(
                    result,
                    (channel.fb_id, variable, link.link_id),
                    source_mechanism,
                    True,
                )
    return tuple(result)


def _endpoint_owned(
    control_structure: ControlStructure, link: CoordinationLink
) -> bool:
    try:
        coordination_process_model_owner(control_structure, link)
    except ValueError:
        return False
    return True


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
    "CROSS_CONTROLLER_MECHANISM",
    "SOURCE_MECHANISMS",
    "MechanismCandidate",
    "SlotPath",
    "StpaIndex",
    "build_stpa_index",
    "mechanism_candidates",
]
