"""Deterministic defender BDI from the control structure."""

from __future__ import annotations

from collections.abc import Sequence
from asago_scenario_generator.stpa.models.control_structure import (
    ControlStructure,
    CoordinationLink,
    Responsibility,
)
from asago_scenario_generator.stpa.models.scenario_spec import (
    DefenderBDI,
    DefenderBelief,
    DefenderDesire,
    DefenderIntention,
)
from asago_scenario_generator.stpa.models.scenario_context import ScenarioConstraint


def populate_defender_bdi(
    control_structure: ControlStructure,
    target_resp_id: str,
    constraints: Sequence[ScenarioConstraint] = (),
) -> DefenderBDI:
    """Deterministically derive defender BDI from the control structure.

    Extracts beliefs from process model parts, desires from the selected
    security constraints, and intentions from control actions.  The optional
    constraint projection keeps direct historical callers compatible; when it
    is absent, local responsibility constraints are used where available.

    Args:
        control_structure: The control structure.
        target_resp_id: The responsibility ID to extract from.
        constraints: Exact selected scenario constraints, when available.

    Returns:
        A :class:`DefenderBDI` with empty vulnerability fields.

    Raises:
        ValueError: If ``target_resp_id`` is not found in the control structure.
    """
    if target_resp_id.startswith("CL-"):
        return _populate_coordination_bdi(
            control_structure,
            target_resp_id,
            constraints,
        )

    resp = _find_responsibility(control_structure, target_resp_id)

    beliefs = [
        DefenderBelief(
            pm_id=pm.pm_id,
            content=pm.description,
            vulnerability="",
        )
        for pm in resp.process_model_parts
    ]

    desires = [
        _defender_desire(resp.resp_id, constraint)
        for constraint in _responsibility_desire_constraints(constraints)
    ]
    if not desires:
        desires = [
            DefenderDesire(
                resp_id=resp.resp_id,
                content=resp.description,
            )
        ]

    intentions = [
        DefenderIntention(
            ca_id=ca.ca_id,
            content=ca.description,
        )
        for ca in resp.control_actions
    ]

    return DefenderBDI(beliefs=beliefs, desires=desires, intentions=intentions)


def _populate_coordination_bdi(
    control_structure: ControlStructure,
    link_id: str,
    constraints: Sequence[ScenarioConstraint] = (),
) -> DefenderBDI:
    """Derive one defender BDI from both exact endpoints of a CL path."""
    responsibilities = _coordination_responsibilities(control_structure, link_id)
    selected = tuple(constraints)
    if selected:
        desires = [
            _defender_desire(
                responsibility.resp_id,
                constraint,
            )
            for responsibility in responsibilities
            for constraint in selected
        ]
    else:
        desires = _coordination_desires(responsibilities)
    return DefenderBDI(
        beliefs=_coordination_beliefs(responsibilities),
        desires=desires,
        intentions=_coordination_intentions(responsibilities),
    )


def _responsibility_desire_constraints(
    selected: Sequence[ScenarioConstraint],
) -> tuple[ScenarioConstraint, ...]:
    """Return exact selected constraints for a contextual scenario."""
    if selected:
        return tuple(selected)
    return ()


def _defender_desire(
    resp_id: str,
    constraint: ScenarioConstraint,
) -> DefenderDesire:
    """Create one desire whose content and identity come from a constraint."""
    return DefenderDesire(
        resp_id=resp_id,
        constraint_id=constraint.constraint_id,
        content=constraint.description,
    )


def _coordination_responsibilities(
    control_structure: ControlStructure,
    link_id: str,
) -> tuple[Responsibility, Responsibility]:
    """Resolve the two exact responsibility endpoints of one CL link."""
    links = [
        item for item in control_structure.coordination_links if item.link_id == link_id
    ]
    if len(links) != 1:
        raise ValueError(
            f"Coordination link '{link_id}' not found in control structure."
        )
    link: CoordinationLink = links[0]
    return (
        _find_responsibility(control_structure, link.source),
        _find_responsibility(control_structure, link.target),
    )


def _coordination_beliefs(
    responsibilities: tuple[Responsibility, Responsibility],
) -> list[DefenderBelief]:
    """Build belief records for both coordination endpoints."""
    return [
        DefenderBelief(pm_id=part.pm_id, content=part.description, vulnerability="")
        for responsibility in responsibilities
        for part in responsibility.process_model_parts
    ]


def _coordination_desires(
    responsibilities: tuple[Responsibility, Responsibility],
) -> list[DefenderDesire]:
    """Build desire records for both coordination endpoints."""
    return [
        DefenderDesire(
            resp_id=responsibility.resp_id, content=responsibility.description
        )
        for responsibility in responsibilities
    ]


def _coordination_intentions(
    responsibilities: tuple[Responsibility, Responsibility],
) -> list[DefenderIntention]:
    """Build intention records for every action on both endpoints."""
    return [
        DefenderIntention(ca_id=action.ca_id, content=action.description)
        for responsibility in responsibilities
        for action in responsibility.control_actions
    ]


def _find_responsibility(
    control_structure: ControlStructure,
    resp_id: str,
) -> Responsibility:
    """Find a responsibility by ID in the control structure."""
    for resp in control_structure.responsibilities:
        if resp.resp_id == resp_id:
            return resp
    raise ValueError(f"Responsibility '{resp_id}' not found in control structure.")
