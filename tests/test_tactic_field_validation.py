"""Tests for tactic field validation on AttackTreeNode.

Ensures the optional MITRE ATLAS tactic field (format AML.TAnnnn)
is accepted when present, allows None for backward compatibility,
and rejects invalid formats.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from asago_scenario_generator.models.attack_tree import (
    AiSystemAction,
    AttackTreeNode,
    GateType,
)


def _make_leaf(**overrides) -> dict:
    """Build a minimal LEAF node dict with optional overrides."""
    node = {
        "id": "n1",
        "label": "Test node",
        "gate": "LEAF",
        "zone": "input",
        "action": AiSystemAction(),
    }
    node.update(overrides)
    return node


# ---------------------------------------------------------------------------
# Valid tactic values
# ---------------------------------------------------------------------------


class TestValidTacticValues:
    """Valid ATLAS tactic IDs should be accepted."""

    @pytest.mark.parametrize(
        "tactic_id",
        [
            "AML.TA0000",
            "AML.TA0001",
            "AML.TA0002",
            "AML.TA0003",
            "AML.TA0004",
            "AML.TA0005",
            "AML.TA0006",
            "AML.TA0007",
            "AML.TA0008",
            "AML.TA0009",
            "AML.TA0010",
            "AML.TA0011",
            "AML.TA0012",
            "AML.TA0013",
            "AML.TA0014",
            "AML.TA0015",
        ],
    )
    def test_all_atlas_tactics_accepted(self, tactic_id: str) -> None:
        node = AttackTreeNode.model_validate(_make_leaf(tactic=tactic_id))
        assert node.tactic == tactic_id

    def test_tactic_with_technique_id(self) -> None:
        """Node with both tactic and technique_id validates correctly."""
        node = AttackTreeNode.model_validate(
            _make_leaf(tactic="AML.TA0005", technique_id="AML.T0054")
        )
        assert node.tactic == "AML.TA0005"
        assert node.technique_id == "AML.T0054"


# ---------------------------------------------------------------------------
# Missing tactic (backward compatibility)
# ---------------------------------------------------------------------------


class TestMissingTactic:
    """Nodes without tactic field should still validate."""

    def test_none_is_valid(self) -> None:
        node = AttackTreeNode.model_validate(_make_leaf())
        assert node.tactic is None

    def test_explicit_none_is_valid(self) -> None:
        node = AttackTreeNode.model_validate(_make_leaf(tactic=None))
        assert node.tactic is None

    def test_existing_tree_without_tactic(self) -> None:
        """A full tree structure without any tactic fields validates."""
        from asago_scenario_generator.models.attack_tree import AttackTree

        tree = AttackTree(
            id="tree-AP-T1-01",
            seed_id="AP-T1-01",
            goal="Test goal",
            root=AttackTreeNode(
                id="n1",
                label="Root",
                gate=GateType.OR,
                zone="input",
                children=[
                    AttackTreeNode(
                        id="n1.1",
                        label="Path A",
                        gate=GateType.LEAF,
                        zone="input",
                        technique_id="AML.T0054",
                        action=AiSystemAction(),
                    ),
                    AttackTreeNode(
                        id="n1.2",
                        label="Path B",
                        gate=GateType.LEAF,
                        zone="reasoning",
                        action=AiSystemAction(),
                    ),
                ],
            ),
        )
        assert tree.root.tactic is None
        assert tree.root.children[0].tactic is None
        assert tree.root.children[1].tactic is None


# ---------------------------------------------------------------------------
# Invalid tactic formats
# ---------------------------------------------------------------------------


class TestInvalidTacticFormats:
    """Invalid tactic formats should be rejected by the pattern constraint."""

    @pytest.mark.parametrize(
        "bad_tactic,reason",
        [
            ("TA0005", "missing AML. prefix"),
            ("AML.T0005", "technique format, not tactic (T vs TA)"),
            ("AML.TA005", "only 3 digits instead of 4"),
            ("AML.TA00050", "5 digits instead of 4"),
            ("ATLAS.TA0005", "wrong prefix"),
            ("aml.ta0005", "lowercase not accepted"),
            ("AML.TA0005.001", "sub-ID not allowed for tactics"),
            ("AML.TAxxxx", "non-digit characters"),
            ("", "empty string"),
        ],
    )
    def test_invalid_format_rejected(self, bad_tactic: str, reason: str) -> None:
        with pytest.raises(ValidationError):
            AttackTreeNode.model_validate(_make_leaf(tactic=bad_tactic))
