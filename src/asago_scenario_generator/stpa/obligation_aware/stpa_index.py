"""One id index over a control structure and its loss analysis.

The index is rebuilt per call rather than cached: the STPA models are mutable,
so a cache keyed on them could serve records that were changed in place.
Validated models carry unique IDs; for an unvalidated model that repeats an
ID, the first record wins.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, TypeVar

from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlledProcess,
    ControlStructure,
    CoordinationLink,
    CoordinationMechanism,
    FeedbackChannel,
    ProcessModelPart,
    Responsibility,
    ResponsibilityConstraint,
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


__all__ = ["SlotPath", "StpaIndex", "build_stpa_index"]
