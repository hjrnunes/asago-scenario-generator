"""Exact structural sources grounded by defender BDI and a control path."""

from __future__ import annotations

from typing import Any

from asago_scenario_generator.stpa.models.scenario_spec import DefenderBDI

# The ``format`` value of an AND/OR attack tree; a flat tree has no ``format``.
AND_OR_TREE_FORMAT = "and-or-tree-v1"


def defender_tree_sources(defender: DefenderBDI) -> set[str]:
    """Collect exact source IDs grounded by defender BDI."""
    return {
        *[belief.pm_id for belief in defender.beliefs],
        *[desire.resp_id for desire in defender.desires],
        *[
            desire.constraint_id
            for desire in defender.desires
            if desire.constraint_id is not None
        ],
        *[intention.ca_id for intention in defender.intentions],
    }


def context_tree_sources(context: Any) -> set[str]:
    """Collect exact source IDs from the selected control path.

    The path's controller and control action are left out; each caller
    decides whether they count as tree evidence.
    """
    path = context.target_control_path
    allowed = {
        *(item.element_id for item in path.process_model_parts),
        *(item.element_id for item in path.feedback),
        *(item.action_id for item in path.related_control_actions),
    }
    if path.responsibility is not None:
        allowed.add(path.responsibility.element_id)
    if path.coordination_path is not None:
        coordination = path.coordination_path
        allowed.update(
            {
                coordination.link_id,
                coordination.source.element_id,
                coordination.target.element_id,
                coordination.shared_process_model.element_id,
                coordination.coordination_mechanism.element_id,
            }
        )
    return allowed
