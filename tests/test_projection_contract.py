from __future__ import annotations

import pytest

from asago_scenario_generator.models.attack_tree import (
    AttackTree,
    AttackTreeNode,
    ExternalPreconditionAction,
)
from asago_scenario_generator.models.realization import ProjectedStepRealization
from asago_scenario_generator.pipeline.generate.tree import (
    _validate_tree_against_projection,
    normalize_attack_tree_transport,
)
from asago_scenario_generator.pipeline.projection_validation import (
    _EXECUTOR_ROLE_TO_LEAF_COMPAT,
    _STEP_TO_LEAF_ACTION_COMPAT,
)


def _projection_context(*steps: tuple[str, str]) -> dict:
    return {
        "selected_step_ids": [step_id for step_id, _ in steps],
        "selected_steps": [
            {
                "step_id": step_id,
                "boundary_position": boundary,
                "realization": {"projected_step_id": step_id},
            }
            for step_id, boundary in steps
        ],
    }


def _external_leaf(
    *,
    step_id: str,
    realization: ProjectedStepRealization | None = None,
) -> AttackTree:
    node = AttackTreeNode(
        id="n1",
        label="external setup",
        gate="LEAF",
        action=ExternalPreconditionAction(),
        projected_step_ids=(step_id,),
        realizations=(realization,) if realization else (),
    )
    return AttackTree(
        id="tree-AP-T1-01",
        seed_id="AP-T1-01",
        goal="goal",
        root=node,
    )


def test_observe_and_operator_impact_have_non_empty_compatibility_intersections():
    assert (
        _STEP_TO_LEAF_ACTION_COMPAT["observe"]
        & _EXECUTOR_ROLE_TO_LEAF_COMPAT["attacker"]
    ) >= {"external_precondition"}
    assert (
        _STEP_TO_LEAF_ACTION_COMPAT["prepare"]
        & _EXECUTOR_ROLE_TO_LEAF_COMPAT["attacker"]
    ) >= {"external_precondition"}
    assert (
        _STEP_TO_LEAF_ACTION_COMPAT["impact"]
        & _EXECUTOR_ROLE_TO_LEAF_COMPAT["operator"]
    ) >= {"impact"}


def test_normalization_preserves_outside_mapping_and_canonical_realization():
    data = {
        "root": {
            "id": "n1",
            "label": "prepare outside",
            "gate": "LEAF",
            "zone": "input",
            "technique_id": "not-a-technique",
            "projected_step_ids": ["attacker.observe"],
            "realizations": [],
            "action": {"kind": "external_precondition"},
        }
    }

    normalized = normalize_attack_tree_transport(
        data, _projection_context(("attacker.observe", "outside"))
    )
    leaf = normalized["root"]

    assert leaf["zone"] is None
    assert leaf["technique_id"] is None
    assert leaf["projected_step_ids"] == ["attacker.observe"]
    assert leaf["realizations"] == [{"projected_step_id": "attacker.observe"}]


@pytest.mark.parametrize(
    "technique_id", ["AML.T0051", "AML.T0051.001", "S1", "M2", "L3"]
)
def test_normalization_preserves_valid_technique_id(technique_id: str):
    data = {
        "root": {
            "id": "n1",
            "label": "external setup",
            "gate": "LEAF",
            "technique_id": technique_id,
            "action": {"kind": "external_precondition"},
        }
    }

    normalized = normalize_attack_tree_transport(
        data, _projection_context(("attacker.observe", "outside"))
    )

    assert normalized["root"]["technique_id"] == technique_id


def test_normalization_unmaps_inside_external_leaf():
    data = {
        "root": {
            "id": "n1",
            "label": "internal claim",
            "gate": "LEAF",
            "zone": "input",
            "projected_step_ids": ["system.observe"],
            "realizations": [{"projected_step_id": "system.observe"}],
            "action": {"kind": "external_precondition"},
        }
    }

    normalized = normalize_attack_tree_transport(
        data, _projection_context(("system.observe", "inside"))
    )
    leaf = normalized["root"]

    assert leaf["zone"] is None
    assert leaf["projected_step_ids"] == ()
    assert leaf["realizations"] == ()


def test_normalization_recurses_through_nested_nodes():
    data = {
        "root": {
            "id": "n1",
            "label": "combined setup",
            "gate": "AND",
            "children": [
                {
                    "id": "n1.1",
                    "label": "external setup",
                    "gate": "LEAF",
                    "zone": "input",
                    "action": {"kind": "external_precondition"},
                },
                "not-a-node",
            ],
        }
    }

    normalized = normalize_attack_tree_transport(
        data, _projection_context(("attacker.observe", "outside"))
    )

    assert normalized["root"]["children"][0]["zone"] is None
    assert normalized["root"]["children"][1] == "not-a-node"


def test_normalization_handles_wrapped_attack_tree():
    data = {
        "attack_tree": {
            "root": {
                "id": "n1",
                "label": "external setup",
                "gate": "LEAF",
                "zone": "input",
                "action": {"kind": "external_precondition"},
            }
        }
    }

    normalized = normalize_attack_tree_transport(
        data, _projection_context(("attacker.observe", "outside"))
    )

    assert normalized["attack_tree"]["root"]["zone"] is None


def test_normalization_rejects_unknown_ids_before_external_unmapping():
    data = {
        "root": {
            "id": "n1",
            "label": "unknown claim",
            "gate": "LEAF",
            "projected_step_ids": ["step.unknown"],
            "action": {"kind": "external_precondition"},
        }
    }

    with pytest.raises(ValueError, match="step.unknown"):
        normalize_attack_tree_transport(
            data, _projection_context(("attacker.observe", "outside"))
        )


def test_strict_tree_validation_allows_outside_external_mapping():
    realization = ProjectedStepRealization(
        projected_step_id="attacker.observe",
        action_kind="observe",
        executor_role="attacker",
        boundary_position="outside",
        resource_ref_ids=(),
        consumed_ref_ids=(),
        produced_ref_ids=(),
        produced_effect_ids=(),
        outcome_link_pc_ids=(),
        postcondition_ids=(),
    )
    tree = _external_leaf(step_id="attacker.observe", realization=realization)

    _validate_tree_against_projection(
        tree,
        _projection_context(("attacker.observe", "outside")),
    )


def test_strict_tree_validation_rejects_inside_external_mapping():
    realization = ProjectedStepRealization(
        projected_step_id="system.observe",
        action_kind="observe",
        executor_role="system",
        boundary_position="inside",
        resource_ref_ids=(),
        consumed_ref_ids=(),
        produced_ref_ids=(),
        produced_effect_ids=(),
        outcome_link_pc_ids=(),
        postcondition_ids=(),
    )
    tree = _external_leaf(step_id="system.observe", realization=realization)

    with pytest.raises(ValueError, match="External precondition"):
        _validate_tree_against_projection(
            tree,
            _projection_context(("system.observe", "inside")),
        )
