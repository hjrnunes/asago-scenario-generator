"""Stage 2 post-checks on the assembled ControlStructure.

``uncited_security_constraints`` is advisory: it runs after Stage 2 Call 3
assembles the structure.  ``untyped_control_actions`` gates the final
structure: an action without a typed target and effect cannot be routed;
``system_model.publication`` applies it to every canonical publication.
The structural checks live in
``stpa.models.control_structure.check_structural_heuristics``.
"""

from __future__ import annotations

from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis


def uncited_security_constraints(
    cs: ControlStructure, loss_analysis: LossAnalysis
) -> list[str]:
    """Return Stage 1a constraint IDs that no Stage 2 responsibility cites.

    A constraint no responsibility implements yields no control action to
    analyze, so its rule reaches no scenario.  The result is advisory.
    """
    cited = {
        ref
        for responsibility in cs.responsibilities
        for ref in responsibility.security_constraint_refs
    }
    return [
        constraint.constraint_id
        for constraint in loss_analysis.security_constraints
        if constraint.constraint_id not in cited
    ]


def untyped_control_actions(cs: ControlStructure) -> list[str]:
    """Describe each control action that lacks a typed target or effect.

    Routing reads an action's controlled process from ``target`` and its
    observable effect from ``effect_kind``; neither is recovered from the
    description.  ``temporality`` is not required: a missing value only makes
    the action ineligible for a duration finding.  An empty result means
    every action is typed.
    """
    return [
        f"control action {action.ca_id} of {responsibility.resp_id} lacks "
        + ", ".join(missing)
        for responsibility in cs.responsibilities
        for action in responsibility.control_actions
        if (
            missing := [
                name
                for name, value in (
                    ("target", action.target),
                    ("effect_kind", action.effect_kind),
                )
                if value is None
            ]
        )
    ]
