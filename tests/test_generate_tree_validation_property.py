"""Property tests for attack-tree path enumeration.

These properties pin ``_enumerate_root_to_leaf_paths`` in
``pipeline.generate.tree_validation``: AND concatenates child paths, OR
branches them. They are offline and never contact an LLM endpoint.
"""

from __future__ import annotations

from hypothesis import given, settings, strategies as st

from asago_scenario_generator.models.attack_tree import AttackTreeNode, GateType
from asago_scenario_generator.pipeline.generate.tree_validation import (
    _enumerate_root_to_leaf_paths,
)
from tests.helpers.typed_actions import make_leaf

_MAX_EXAMPLES = 60


def _internal(
    node_id: str, gate: GateType, children: list[AttackTreeNode]
) -> AttackTreeNode:
    """Build an AND/OR node with the required child-id prefix."""
    return AttackTreeNode(
        id=node_id,
        label=node_id,
        gate=gate,
        children=children,
    )


def _leaf_ids(path: list[AttackTreeNode]) -> list[str]:
    return [node.id for node in path]


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(leaf_count=st.integers(min_value=2, max_value=4))
def test_and_concatenates_direct_leaf_paths(leaf_count: int) -> None:
    """AND of N leaves yields one path with those leaves in child order."""
    leaves = [
        make_leaf(f"n1.{index}", f"n1.{index}", zone="reasoning")
        for index in range(1, leaf_count + 1)
    ]
    paths = _enumerate_root_to_leaf_paths(_internal("n1", GateType.AND, leaves))
    assert [_leaf_ids(path) for path in paths] == [[leaf.id for leaf in leaves]]
    assert all(node.gate == GateType.LEAF for path in paths for node in path)


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(leaf_count=st.integers(min_value=2, max_value=4))
def test_or_branches_direct_leaf_paths(leaf_count: int) -> None:
    """OR of N leaves yields one singleton path per child, in order."""
    leaves = [
        make_leaf(f"n1.{index}", f"n1.{index}", zone="reasoning")
        for index in range(1, leaf_count + 1)
    ]
    paths = _enumerate_root_to_leaf_paths(_internal("n1", GateType.OR, leaves))
    assert [_leaf_ids(path) for path in paths] == [[leaf.id] for leaf in leaves]
    assert all(node.gate == GateType.LEAF for path in paths for node in path)


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(
    left_count=st.integers(min_value=2, max_value=3),
    right_count=st.integers(min_value=2, max_value=3),
)
def test_and_of_or_children_is_cartesian_product(
    left_count: int, right_count: int
) -> None:
    """AND concatenates every left OR path with every right OR path."""
    left_leaves = [
        make_leaf(f"n1.1.{index}", f"L{index}", zone="reasoning")
        for index in range(1, left_count + 1)
    ]
    right_leaves = [
        make_leaf(f"n1.2.{index}", f"R{index}", zone="reasoning")
        for index in range(1, right_count + 1)
    ]
    root = _internal(
        "n1",
        GateType.AND,
        [
            _internal("n1.1", GateType.OR, left_leaves),
            _internal("n1.2", GateType.OR, right_leaves),
        ],
    )
    paths = [_leaf_ids(path) for path in _enumerate_root_to_leaf_paths(root)]
    expected = [[left.id, right.id] for left in left_leaves for right in right_leaves]
    assert paths == expected
