"""Stage 2 advisory post-check: security constraints no responsibility cites.

This deterministic check runs after Stage 2 Call 3 assembles the
ControlStructure; the structural checks live in
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
