"""Mutation hardening tests for tree_validation.py.

Targets surviving mutants identified by mutate4py on the post-generation
structure-validation helpers.  Tests use ``SimpleNamespace`` stand-ins so
private functions can be exercised without the full pydantic construction
cost and validator friction, while still driving the exact branch
conditions (None vs non-None, boundary comparisons, and/or logic) that
the surviving mutants flip.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from asago_scenario_generator.models.attack_tree import GateType
from asago_scenario_generator.pipeline.generate.tree_validation import (
    _check_consistency,
    _check_non_actionable_leaves,
    _check_parsimony,
    _check_scenario_threat_id,
    _check_step_node_correspondence,
    _check_zone_sequence,
    _collect_all_leaves,
    _collect_threat_ids_from_tree_set,
    _count_leaves,
    _enumerate_root_to_leaf_paths,
    _initial_ingress_leaves,
    _ingress_action_of,
    _ingress_zone_violations,
    _is_external_impact_leaf,
    _leaf_ingress_zone_violation,
    _missing_ingress_path_violations,
    _path_has_initial_ingress,
    _strip_non_skeleton_leaf,
    _strip_zone_invalid_technique,
    _untyped_tool_execution_violation,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mk_node(
    *,
    gate: GateType = GateType.LEAF,
    id: str = "n1",
    label: str = "label",
    zone: str | None = None,
    action: object | None = None,
    technique_id: str | None = None,
    threat_id: str | None = None,
    children: list | None = None,
    projected_step_ids: tuple = (),
    realizations: tuple = (),
) -> SimpleNamespace:
    return SimpleNamespace(
        id=id,
        label=label,
        gate=gate,
        zone=zone,
        action=action,
        technique_id=technique_id,
        threat_id=threat_id,
        children=children,
        projected_step_ids=projected_step_ids,
        realizations=realizations,
    )


def _mk_tree(root: SimpleNamespace) -> SimpleNamespace:
    return SimpleNamespace(root=root)


def _mk_action(kind: str, **kw) -> SimpleNamespace:
    return SimpleNamespace(kind=kind, **kw)


def _mk_narrative(
    zone_sequence: list[str] | None = None,
    steps: list | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        zone_sequence=zone_sequence or ["input"],
        steps=steps if steps is not None else [SimpleNamespace()],
    )


def _mk_profile(
    zones_active: list[str] | None = None,
    resolve_return: object | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        zones_active=zones_active or ["input"],
        resolve_entry_point=lambda _eid: resolve_return,
    )


def _accessible_ep(zone: str = "input", name: str = "EP1") -> SimpleNamespace:
    """An entry point that passes ``is_attacker_accessible_ingress``."""
    return SimpleNamespace(
        name=name,
        direction="bidirectional",
        effective_controllability="user",
        effective_ingress_zone=zone,
    )


LEAF = GateType.LEAF
AND = GateType.AND
OR = GateType.OR


# ---------------------------------------------------------------------------
# _enumerate_root_to_leaf_paths
# ---------------------------------------------------------------------------


class TestEnumerateRootToLeafPaths:
    def test_leaf_returns_single_path(self) -> None:
        node = _mk_node(gate=LEAF, id="n1")
        assert _enumerate_root_to_leaf_paths(node) == [[node]]

    def test_and_gate_merges_children_into_one_path(self) -> None:
        child_a = _mk_node(gate=LEAF, id="n1.1")
        child_b = _mk_node(gate=LEAF, id="n1.2")
        root = _mk_node(gate=AND, id="n1", children=[child_a, child_b])
        paths = _enumerate_root_to_leaf_paths(root)
        assert paths == [[child_a, child_b]]

    def test_or_gate_creates_branch_per_child(self) -> None:
        child_a = _mk_node(gate=LEAF, id="n1.1")
        child_b = _mk_node(gate=LEAF, id="n1.2")
        root = _mk_node(gate=OR, id="n1", children=[child_a, child_b])
        paths = _enumerate_root_to_leaf_paths(root)
        assert paths == [[child_a], [child_b]]


# ---------------------------------------------------------------------------
# _collect_all_leaves
# ---------------------------------------------------------------------------


class TestCollectAllLeaves:
    def test_leaf_returns_self(self) -> None:
        node = _mk_node(gate=LEAF, id="n1")
        assert _collect_all_leaves(node) == [node]

    def test_and_collects_all_descendant_leaves(self) -> None:
        leaf_a = _mk_node(gate=LEAF, id="n1.1")
        leaf_b = _mk_node(gate=LEAF, id="n1.2")
        root = _mk_node(gate=AND, id="n1", children=[leaf_a, leaf_b])
        assert _collect_all_leaves(root) == [leaf_a, leaf_b]


# ---------------------------------------------------------------------------
# _is_external_impact_leaf
# ---------------------------------------------------------------------------


class TestIsExternalImpactLeaf:
    def test_external_impact_leaf_returns_true(self) -> None:
        node = _mk_node(
            gate=LEAF,
            action=_mk_action("impact", boundary="external"),
        )
        assert _is_external_impact_leaf(node) is True

    def test_internal_impact_leaf_returns_false(self) -> None:
        node = _mk_node(
            gate=LEAF,
            action=_mk_action("impact", boundary="internal"),
        )
        assert _is_external_impact_leaf(node) is False

    def test_non_impact_action_with_external_boundary_returns_false(self) -> None:
        node = _mk_node(
            gate=LEAF,
            action=_mk_action("ai_system_action", boundary="external"),
        )
        assert _is_external_impact_leaf(node) is False

    def test_action_none_returns_false_without_raising(self) -> None:
        node = _mk_node(gate=LEAF, action=None)
        assert _is_external_impact_leaf(node) is False

    def test_non_leaf_node_returns_false(self) -> None:
        node = _mk_node(
            gate=AND,
            children=[_mk_node(gate=LEAF, id="n1.1")],
            action=_mk_action("impact", boundary="external"),
        )
        assert _is_external_impact_leaf(node) is False


# ---------------------------------------------------------------------------
# _initial_ingress_leaves
# ---------------------------------------------------------------------------


class TestInitialIngressLeaves:
    def test_collects_initial_ingress_leaves(self) -> None:
        ingress = _mk_node(
            gate=LEAF,
            id="n1.1",
            action=_mk_action("initial_ingress", entry_point_id="ep1"),
        )
        other = _mk_node(gate=LEAF, id="n1.2", action=_mk_action("ai_system_action"))
        none_action = _mk_node(gate=LEAF, id="n1.3", action=None)
        root = _mk_node(gate=AND, id="n1", children=[ingress, other, none_action])
        tree = _mk_tree(root)
        assert _initial_ingress_leaves(tree) == [ingress]

    def test_no_ingress_leaves_returns_empty(self) -> None:
        leaf = _mk_node(gate=LEAF, id="n1", action=_mk_action("ai_system_action"))
        tree = _mk_tree(leaf)
        assert _initial_ingress_leaves(tree) == []


# ---------------------------------------------------------------------------
# _path_has_initial_ingress
# ---------------------------------------------------------------------------


class TestPathHasInitialIngress:
    def test_path_with_initial_ingress_returns_true(self) -> None:
        ingress = _mk_node(
            gate=LEAF,
            action=_mk_action("initial_ingress", entry_point_id="ep1"),
        )
        assert _path_has_initial_ingress([ingress]) is True

    def test_path_without_ingress_returns_false(self) -> None:
        leaf = _mk_node(gate=LEAF, action=_mk_action("ai_system_action"))
        assert _path_has_initial_ingress([leaf]) is False

    def test_path_with_none_action_does_not_raise(self) -> None:
        leaf = _mk_node(gate=LEAF, action=None)
        assert _path_has_initial_ingress([leaf]) is False

    def test_empty_path_returns_false(self) -> None:
        assert _path_has_initial_ingress([]) is False


# ---------------------------------------------------------------------------
# _ingress_action_of
# ---------------------------------------------------------------------------


class TestIngressActionOf:
    def test_initial_ingress_action_returned(self) -> None:
        action = _mk_action("initial_ingress", entry_point_id="ep1")
        leaf = _mk_node(gate=LEAF, action=action)
        assert _ingress_action_of(leaf) is action

    def test_none_action_returns_none_without_raising(self) -> None:
        leaf = _mk_node(gate=LEAF, action=None)
        assert _ingress_action_of(leaf) is None

    def test_non_initial_ingress_action_returns_none(self) -> None:
        leaf = _mk_node(gate=LEAF, action=_mk_action("ai_system_action"))
        assert _ingress_action_of(leaf) is None


# ---------------------------------------------------------------------------
# _missing_ingress_path_violations
# ---------------------------------------------------------------------------


class TestMissingIngressPathViolations:
    def test_missing_ingress_produces_violation_with_one_based_index(self) -> None:
        leaf = _mk_node(gate=LEAF, action=_mk_action("ai_system_action"))
        violations = _missing_ingress_path_violations([[leaf]])
        assert len(violations) == 1
        assert "attack path 1" in violations[0]

    def test_path_with_ingress_no_violation(self) -> None:
        ingress = _mk_node(
            gate=LEAF,
            action=_mk_action("initial_ingress", entry_point_id="ep1"),
        )
        assert _missing_ingress_path_violations([[ingress]]) == []

    def test_second_path_missing_uses_index_2(self) -> None:
        ingress = _mk_node(
            gate=LEAF,
            action=_mk_action("initial_ingress", entry_point_id="ep1"),
        )
        other = _mk_node(gate=LEAF, action=_mk_action("ai_system_action"))
        violations = _missing_ingress_path_violations([[ingress], [other]])
        assert len(violations) == 1
        assert "attack path 2" in violations[0]


# ---------------------------------------------------------------------------
# _ingress_zone_violations
# ---------------------------------------------------------------------------


class TestIngressZoneViolations:
    def test_profile_none_returns_empty_without_raising(self) -> None:
        ingress = _mk_node(
            gate=LEAF,
            id="n1",
            action=_mk_action("initial_ingress", entry_point_id="ep1"),
        )
        tree = _mk_tree(ingress)
        assert _ingress_zone_violations(tree, None) == []

    def test_zone_mismatch_produces_violation(self) -> None:
        ingress = _mk_node(
            gate=LEAF,
            id="n1",
            zone="reasoning",
            action=_mk_action("initial_ingress", entry_point_id="ep1"),
        )
        tree = _mk_tree(ingress)
        profile = _mk_profile(
            zones_active=["input"],
            resolve_return=_accessible_ep(zone="input"),
        )
        violations = _ingress_zone_violations(tree, profile)
        assert len(violations) == 1
        assert "ingress-zone-mismatch" in violations[0]


# ---------------------------------------------------------------------------
# _leaf_ingress_zone_violation
# ---------------------------------------------------------------------------


class TestLeafIngressZoneViolation:
    def test_non_ingress_leaf_returns_none_without_raising(self) -> None:
        leaf = _mk_node(gate=LEAF, action=_mk_action("ai_system_action"))
        profile = _mk_profile()
        assert _leaf_ingress_zone_violation(leaf, profile, {"input"}) is None

    def test_none_action_returns_none_without_raising(self) -> None:
        leaf = _mk_node(gate=LEAF, action=None)
        profile = _mk_profile()
        assert _leaf_ingress_zone_violation(leaf, profile, {"input"}) is None

    def test_matching_zone_returns_none(self) -> None:
        leaf = _mk_node(
            gate=LEAF,
            id="n1",
            zone="input",
            action=_mk_action("initial_ingress", entry_point_id="ep1"),
        )
        profile = _mk_profile(
            zones_active=["input"],
            resolve_return=_accessible_ep(zone="input"),
        )
        assert _leaf_ingress_zone_violation(leaf, profile, {"input"}) is None

    def test_mismatched_zone_returns_violation(self) -> None:
        leaf = _mk_node(
            gate=LEAF,
            id="n1",
            zone="reasoning",
            action=_mk_action("initial_ingress", entry_point_id="ep1"),
        )
        profile = _mk_profile(
            zones_active=["input"],
            resolve_return=_accessible_ep(zone="input"),
        )
        result = _leaf_ingress_zone_violation(leaf, profile, {"input"})
        assert result is not None
        assert "ingress-zone-mismatch" in result


# ---------------------------------------------------------------------------
# _strip_non_skeleton_leaf
# ---------------------------------------------------------------------------


class TestStripNonSkeletonLeaf:
    def test_non_leaf_node_returns_zero_no_strip(self) -> None:
        node = _mk_node(
            gate=AND,
            technique_id="AML.T0051.000",
            children=[_mk_node(gate=LEAF, id="n1.1")],
        )
        skeleton = {"S1"}
        assert _strip_non_skeleton_leaf(node, skeleton) == 0
        assert node.technique_id == "AML.T0051.000"

    def test_technique_id_none_returns_zero_without_raising(self) -> None:
        node = _mk_node(gate=LEAF, technique_id=None)
        assert _strip_non_skeleton_leaf(node, {"S1"}) == 0

    def test_technique_in_skeleton_returns_zero_no_strip(self) -> None:
        node = _mk_node(gate=LEAF, technique_id="S1")
        assert _strip_non_skeleton_leaf(node, {"S1"}) == 0
        assert node.technique_id == "S1"

    def test_technique_not_in_skeleton_strips_and_returns_one(self) -> None:
        node = _mk_node(gate=LEAF, technique_id="AML.T0051.000")
        assert _strip_non_skeleton_leaf(node, {"S1"}) == 1
        assert node.technique_id is None


# ---------------------------------------------------------------------------
# _strip_zone_invalid_technique
# ---------------------------------------------------------------------------


class TestStripZoneInvalidTechnique:
    def test_technique_id_none_returns_zero_without_raising(self) -> None:
        node = _mk_node(gate=LEAF, technique_id=None, zone="input")
        assert _strip_zone_invalid_technique(node) == 0

    def test_zone_none_returns_zero_no_strip(self) -> None:
        node = _mk_node(gate=LEAF, technique_id="AML.T0051.000", zone=None)
        assert _strip_zone_invalid_technique(node) == 0
        assert node.technique_id == "AML.T0051.000"

    def test_technique_not_in_constraints_returns_zero_without_raising(self) -> None:
        node = _mk_node(gate=LEAF, technique_id="UNKNOWN.T9999", zone="input")
        assert _strip_zone_invalid_technique(node) == 0
        assert node.technique_id == "UNKNOWN.T9999"

    def test_valid_zone_returns_zero_no_strip(self) -> None:
        node = _mk_node(gate=LEAF, technique_id="AML.T0051.000", zone="input")
        assert _strip_zone_invalid_technique(node) == 0
        assert node.technique_id == "AML.T0051.000"

    def test_invalid_zone_strips_and_returns_one(self) -> None:
        node = _mk_node(gate=LEAF, technique_id="AML.T0051.000", zone="reasoning")
        assert _strip_zone_invalid_technique(node) == 1
        assert node.technique_id is None

    def test_non_leaf_node_returns_zero(self) -> None:
        node = _mk_node(
            gate=AND,
            technique_id="AML.T0051.000",
            zone="reasoning",
            children=[_mk_node(gate=LEAF, id="n1.1")],
        )
        assert _strip_zone_invalid_technique(node) == 0
        assert node.technique_id == "AML.T0051.000"


# ---------------------------------------------------------------------------
# _count_leaves
# ---------------------------------------------------------------------------


class TestCountLeaves:
    def test_single_leaf_returns_one(self) -> None:
        node = _mk_node(gate=LEAF)
        assert _count_leaves(node) == 1

    def test_and_with_two_leaf_children_returns_two(self) -> None:
        root = _mk_node(
            gate=AND,
            children=[
                _mk_node(gate=LEAF, id="n1.1"),
                _mk_node(gate=LEAF, id="n1.2"),
            ],
        )
        assert _count_leaves(root) == 2

    def test_nested_tree_counts_all_leaves(self) -> None:
        root = _mk_node(
            gate=AND,
            children=[
                _mk_node(gate=LEAF, id="n1.1"),
                _mk_node(
                    gate=AND,
                    id="n1.2",
                    children=[
                        _mk_node(gate=LEAF, id="n1.2.1"),
                        _mk_node(gate=LEAF, id="n1.2.2"),
                    ],
                ),
            ],
        )
        assert _count_leaves(root) == 3


# ---------------------------------------------------------------------------
# _check_non_actionable_leaves
# ---------------------------------------------------------------------------


class TestCheckNonActionableLeaves:
    def test_two_observation_leaves_produce_violation(self) -> None:
        leaf_a = _mk_node(gate=LEAF, id="n1.1", label="Confirm access", technique_id=None)
        leaf_b = _mk_node(gate=LEAF, id="n1.2", label="Observe traffic", technique_id=None)
        root = _mk_node(gate=AND, id="n1", label="root", children=[leaf_a, leaf_b])
        violations: list[str] = []
        _check_non_actionable_leaves(root, violations)
        assert len(violations) == 1
        assert "non-actionable-leaves" in violations[0]

    def test_single_observation_leaf_no_violation(self) -> None:
        leaf = _mk_node(gate=LEAF, id="n1", label="Confirm access", technique_id=None)
        violations: list[str] = []
        _check_non_actionable_leaves(leaf, violations)
        assert violations == []

    def test_leaf_with_technique_id_not_flagged(self) -> None:
        leaf_a = _mk_node(gate=LEAF, id="n1.1", label="Confirm access", technique_id="S1")
        leaf_b = _mk_node(gate=LEAF, id="n1.2", label="Observe traffic", technique_id="S2")
        root = _mk_node(gate=AND, id="n1", children=[leaf_a, leaf_b])
        violations: list[str] = []
        _check_non_actionable_leaves(root, violations)
        assert violations == []

    def test_keyword_match_uses_positive_membership(self) -> None:
        # Include every observation keyword so ``any(kw in label_lower)``
        # is true while the inverted predicate is false for every keyword.
        label = (
            "confirm observe verify monitor validate note detect assess "
            "the evidence"
        )
        root = _mk_node(
            gate=AND,
            id="n1",
            children=[
                _mk_node(gate=LEAF, id="n1.1", label=label),
                _mk_node(gate=LEAF, id="n1.2", label=label),
            ],
        )
        violations: list[str] = []
        _check_non_actionable_leaves(root, violations)
        assert len(violations) == 1


# ---------------------------------------------------------------------------
# _check_parsimony
# ---------------------------------------------------------------------------


class TestCheckParsimony:
    def test_leaf_count_equal_budget_no_violation(self) -> None:
        violations: list[str] = []
        _check_parsimony(5, 5, violations)
        assert violations == []

    def test_leaf_count_above_budget_violation(self) -> None:
        violations: list[str] = []
        _check_parsimony(6, 5, violations)
        assert len(violations) == 1
        assert "parsimony" in violations[0]

    def test_leaf_count_below_budget_no_violation(self) -> None:
        violations: list[str] = []
        _check_parsimony(3, 5, violations)
        assert violations == []


# ---------------------------------------------------------------------------
# _check_zone_sequence
# ---------------------------------------------------------------------------


class TestCheckZoneSequence:
    def test_missing_narrative_zone_produces_violation(self) -> None:
        root = _mk_node(gate=LEAF, zone="input")
        tree = _mk_tree(root)
        narrative = _mk_narrative(zone_sequence=["input", "reasoning"])
        violations: list[str] = []
        _check_zone_sequence(narrative, tree, violations)
        assert len(violations) == 1
        assert "zone-sequence" in violations[0]
        assert "reasoning" in violations[0]

    def test_all_zones_present_no_violation(self) -> None:
        root = _mk_node(gate=LEAF, zone="input")
        tree = _mk_tree(root)
        narrative = _mk_narrative(zone_sequence=["input"])
        violations: list[str] = []
        _check_zone_sequence(narrative, tree, violations)
        assert violations == []


# ---------------------------------------------------------------------------
# _check_step_node_correspondence
# ---------------------------------------------------------------------------


class TestCheckStepNodeCorrespondence:
    def test_zero_steps_no_violation(self) -> None:
        violations: list[str] = []
        _check_step_node_correspondence(0, 5, 0.7, violations)
        assert violations == []

    def test_zero_leaves_with_steps_produces_violation(self) -> None:
        violations: list[str] = []
        _check_step_node_correspondence(3, 0, 0.7, violations)
        assert len(violations) == 1
        assert "step-node" in violations[0]
        assert "0 leaves" in violations[0]

    def test_correspondence_equal_floor_no_violation(self) -> None:
        violations: list[str] = []
        # min(1,2)/max(1,2) = 1/2 = 0.5 == floor
        _check_step_node_correspondence(1, 2, 0.5, violations)
        assert violations == []

    def test_correspondence_below_floor_violation(self) -> None:
        violations: list[str] = []
        # min(1,3)/max(1,3) = 1/3 ~ 0.33 < 0.5
        _check_step_node_correspondence(1, 3, 0.5, violations)
        assert len(violations) == 1
        assert "step-node" in violations[0]

    def test_correspondence_above_floor_no_violation(self) -> None:
        violations: list[str] = []
        _check_step_node_correspondence(5, 5, 0.7, violations)
        assert violations == []


# ---------------------------------------------------------------------------
# _check_scenario_threat_id
# ---------------------------------------------------------------------------


class TestCheckScenarioThreatId:
    def test_threat_id_present_no_violation(self) -> None:
        root = _mk_node(gate=LEAF, threat_id="T2")
        tree = _mk_tree(root)
        violations: list[str] = []
        _check_scenario_threat_id(tree, "T2", violations)
        assert violations == []

    def test_threat_id_absent_produces_violation(self) -> None:
        root = _mk_node(gate=LEAF, threat_id="T3")
        tree = _mk_tree(root)
        violations: list[str] = []
        _check_scenario_threat_id(tree, "T2", violations)
        assert len(violations) == 1
        assert "missing-scenario-threat-id" in violations[0]

    def test_none_threat_id_no_violation(self) -> None:
        root = _mk_node(gate=LEAF, threat_id="T2")
        tree = _mk_tree(root)
        violations: list[str] = []
        _check_scenario_threat_id(tree, None, violations)
        assert violations == []


# ---------------------------------------------------------------------------
# _collect_threat_ids_from_tree_set
# ---------------------------------------------------------------------------


class TestCollectThreatIdsFromTreeSet:
    def test_node_with_threat_id_returns_set(self) -> None:
        node = _mk_node(gate=LEAF, threat_id="T1")
        assert _collect_threat_ids_from_tree_set(node) == {"T1"}

    def test_node_with_none_threat_id_returns_empty(self) -> None:
        node = _mk_node(gate=LEAF, threat_id=None)
        assert _collect_threat_ids_from_tree_set(node) == set()

    def test_collects_from_children(self) -> None:
        root = _mk_node(
            gate=AND,
            threat_id="T1",
            children=[
                _mk_node(gate=LEAF, id="n1.1", threat_id="T2"),
                _mk_node(gate=LEAF, id="n1.2", threat_id="T1"),
            ],
        )
        assert _collect_threat_ids_from_tree_set(root) == {"T1", "T2"}


# ---------------------------------------------------------------------------
# _untyped_tool_execution_violation
# ---------------------------------------------------------------------------


class TestUntypedToolExecutionViolation:
    def test_tool_execution_leaf_none_action_violation(self) -> None:
        node = _mk_node(
            gate=LEAF,
            id="n1",
            zone="tool_execution",
            action=None,
        )
        violations: list[str] = []
        _untyped_tool_execution_violation(node, violations)
        assert len(violations) == 1
        assert "untyped-tool-execution" in violations[0]

    def test_tool_execution_leaf_wrong_action_kind_violation(self) -> None:
        node = _mk_node(
            gate=LEAF,
            id="n1",
            zone="tool_execution",
            action=_mk_action("ai_system_action"),
        )
        violations: list[str] = []
        _untyped_tool_execution_violation(node, violations)
        assert len(violations) == 1

    def test_tool_execution_leaf_tool_invocation_no_violation(self) -> None:
        node = _mk_node(
            gate=LEAF,
            id="n1",
            zone="tool_execution",
            action=_mk_action("tool_invocation", tool_id="t1"),
        )
        violations: list[str] = []
        _untyped_tool_execution_violation(node, violations)
        assert violations == []

    def test_tool_execution_leaf_integration_interaction_no_violation(self) -> None:
        node = _mk_node(
            gate=LEAF,
            id="n1",
            zone="tool_execution",
            action=_mk_action("integration_interaction", integration_id="i1"),
        )
        violations: list[str] = []
        _untyped_tool_execution_violation(node, violations)
        assert violations == []

    def test_non_tool_execution_zone_no_violation(self) -> None:
        node = _mk_node(
            gate=LEAF,
            id="n1",
            zone="input",
            action=None,
        )
        violations: list[str] = []
        _untyped_tool_execution_violation(node, violations)
        assert violations == []

    def test_non_leaf_tool_execution_node_no_violation(self) -> None:
        node = _mk_node(
            gate=AND,
            id="n1",
            zone="tool_execution",
            action=None,
            children=[_mk_node(gate=LEAF, id="n1.1")],
        )
        violations: list[str] = []
        _untyped_tool_execution_violation(node, violations)
        assert violations == []


# ---------------------------------------------------------------------------
# _check_consistency (tool_names guard)
# ---------------------------------------------------------------------------


class TestCheckConsistencyToolNamesGuard:
    def test_tool_names_provided_runs_grounding_check(self) -> None:
        root = _mk_node(
            gate=LEAF,
            id="n1",
            label="act",
            zone="tool_execution",
            action=None,
            technique_id="S1",
        )
        tree = _mk_tree(root)
        narrative = _mk_narrative(
            zone_sequence=["tool_execution"],
            steps=[SimpleNamespace()],
        )
        violations = _check_consistency(
            tree,
            narrative,
            parsimony_budget=5,
            step_node_floor=0.7,
            threat_id=None,
            tool_names=["t1"],
        )
        tool_violations = [v for v in violations if "untyped-tool-execution" in v]
        assert len(tool_violations) == 1

    def test_tool_names_none_skips_grounding_check(self) -> None:
        root = _mk_node(
            gate=LEAF,
            id="n1",
            label="act",
            zone="tool_execution",
            action=None,
            technique_id="S1",
        )
        tree = _mk_tree(root)
        narrative = _mk_narrative(
            zone_sequence=["tool_execution"],
            steps=[SimpleNamespace()],
        )
        violations = _check_consistency(
            tree,
            narrative,
            parsimony_budget=5,
            step_node_floor=0.7,
            threat_id=None,
            tool_names=None,
        )
        tool_violations = [v for v in violations if "untyped-tool-execution" in v]
        assert tool_violations == []
