"""Focused unit tests for the decomposed attack-tree helpers."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from asago_scenario_generator.models.attack_tree import (
    AttackTreeNode,
    GateType,
    ImpactAction,
    _child_id_prefix_error,
    _forbidden_zone_error,
    _impact_zone_error,
    _is_single_child_gate,
    _repair_children,
    _required_zone_error,
    _validate_gate_arity,
    _validate_internal_arity,
    _validate_leaf_arity,
    _zone_rule_error,
)

_ZONES = frozenset({"input", "reasoning"})
_ACTION = SimpleNamespace(kind="ai_system_action")


def _node(**overrides: Any) -> SimpleNamespace:
    """Minimal duck-typed attack-tree node for the module helpers."""
    base: dict[str, Any] = {
        "id": "n1",
        "gate": GateType.LEAF,
        "children": (),
        "action": None,
        "zone": None,
        "projected_step_ids": (),
        "realizations": (),
    }
    base.update(overrides)
    return SimpleNamespace(**base)


class TestGateArity:
    """LEAF vs internal gate/children/action arity rules."""

    def test_leaf_valid(self) -> None:
        _validate_leaf_arity(_node(action=_ACTION))

    def test_leaf_with_children_raises(self) -> None:
        with pytest.raises(ValueError, match="must not have children"):
            _validate_leaf_arity(_node(children=(object(),), action=_ACTION))

    def test_leaf_without_action_raises(self) -> None:
        with pytest.raises(ValueError, match="must carry exactly one typed action"):
            _validate_leaf_arity(_node())

    def test_internal_valid(self) -> None:
        _validate_internal_arity(
            _node(gate=GateType.OR, children=(object(), object()))
        )

    def test_internal_single_child_raises(self) -> None:
        with pytest.raises(ValueError, match="at least 2 children"):
            _validate_internal_arity(_node(gate=GateType.AND, children=(object(),)))

    def test_internal_with_action_raises(self) -> None:
        with pytest.raises(ValueError, match="must not carry a leaf action"):
            _validate_internal_arity(
                _node(gate=GateType.OR, children=(object(), object()), action=_ACTION)
            )

    def test_validate_gate_arity_dispatches_leaf(self) -> None:
        _validate_gate_arity(_node(action=_ACTION))

    def test_validate_gate_arity_dispatches_internal(self) -> None:
        _validate_gate_arity(_node(gate=GateType.OR, children=(object(), object())))


class TestChildIdPrefix:
    """Child ID prefix validation."""

    def test_prefix_error_none_when_all_prefixed(self) -> None:
        node = _node(
            gate=GateType.OR,
            children=(
                SimpleNamespace(id="n1.1"),
                SimpleNamespace(id="n1.2"),
            ),
        )
        assert _child_id_prefix_error(node) is None

    def test_prefix_error_none_without_children(self) -> None:
        assert _child_id_prefix_error(_node()) is None

    def test_prefix_error_returns_first_bad_child(self) -> None:
        node = _node(
            gate=GateType.OR,
            children=(
                SimpleNamespace(id="n1.1"),
                SimpleNamespace(id="n2.1"),
            ),
        )
        error = _child_id_prefix_error(node)
        assert error is not None
        assert "n2.1" in error


class TestZoneHelpers:
    """Action-kind zone requirement errors."""

    def test_impact_zone_error_internal_valid(self) -> None:
        node = _node(
            action=ImpactAction(boundary="internal", target="data"),
            zone="reasoning",
        )
        assert _impact_zone_error(node, _ZONES) is None

    def test_impact_zone_error_internal_missing_zone(self) -> None:
        node = _node(action=ImpactAction(boundary="internal", target="data"))
        error = _impact_zone_error(node, _ZONES)
        assert error is not None
        assert "internal impact must have" in error

    def test_impact_zone_error_internal_invalid_zone(self) -> None:
        node = _node(
            action=ImpactAction(boundary="internal", target="data"),
            zone="output",
        )
        error = _impact_zone_error(node, _ZONES)
        assert error is not None
        assert "invalid zone" in error

    def test_impact_zone_error_external_valid(self) -> None:
        node = _node(action=ImpactAction(boundary="external", target="reputation"))
        assert _impact_zone_error(node, _ZONES) is None

    def test_impact_zone_error_external_with_zone(self) -> None:
        node = _node(
            action=ImpactAction(boundary="external", target="reputation"),
            zone="input",
        )
        error = _impact_zone_error(node, _ZONES)
        assert error is not None
        assert "external impact must not have" in error

    def test_forbidden_zone_error_none_when_zone_absent(self) -> None:
        assert _forbidden_zone_error(_node(), "external_precondition") is None

    def test_forbidden_zone_error_when_zone_present(self) -> None:
        error = _forbidden_zone_error(_node(zone="input"), "external_precondition")
        assert error is not None
        assert "must not have a Schneider zone" in error

    def test_required_zone_error_none_when_valid(self) -> None:
        assert _required_zone_error(_node(zone="input"), "ai_system_action", _ZONES) is None

    def test_required_zone_error_missing_zone(self) -> None:
        error = _required_zone_error(_node(), "ai_system_action", _ZONES)
        assert error is not None
        assert "must have a valid zone" in error

    def test_required_zone_error_invalid_zone(self) -> None:
        error = _required_zone_error(_node(zone="output"), "ai_system_action", _ZONES)
        assert error is not None
        assert "invalid zone" in error

    def test_zone_rule_error_dispatches_impact(self) -> None:
        node = _node(action=ImpactAction(boundary="internal", target="data"))
        error = _zone_rule_error(
            node, "impact", {"zone_required": "conditional", "valid_zones": _ZONES}
        )
        assert error is not None
        assert "internal impact must have" in error

    def test_zone_rule_error_dispatches_forbidden(self) -> None:
        node = _node(zone="input")
        error = _zone_rule_error(
            node, "external_precondition", {"zone_required": False}
        )
        assert error is not None
        assert "must not have a Schneider zone" in error

    def test_zone_rule_error_dispatches_required(self) -> None:
        node = _node()
        error = _zone_rule_error(
            node, "ai_system_action", {"zone_required": True, "valid_zones": _ZONES}
        )
        assert error is not None
        assert "must have a valid zone" in error

    def test_zone_rule_error_defaults_to_forbidden_for_unknown_kind(self) -> None:
        node = _node(zone="input")
        error = _zone_rule_error(node, "mystery_kind", {})
        assert error is not None
        assert "must not have a Schneider zone" in error


class TestRepairHelpers:
    """Single-child AND/OR collapse helpers."""

    def test_repair_children_none_without_children(self) -> None:
        assert _repair_children({"id": "n1"}) is None

    def test_repair_children_none_for_empty_list(self) -> None:
        assert _repair_children({"id": "n1", "children": []}) is None

    def test_repair_children_none_for_non_list(self) -> None:
        assert _repair_children({"id": "n1", "children": "not-a-list"}) is None

    def test_repair_children_collapses_nested_single_child_gate(self) -> None:
        node = {
            "id": "n1",
            "children": [
                {
                    "id": "n1.1",
                    "gate": "and",
                    "children": [
                        {"id": "n1.1.1", "gate": "leaf", "label": "leaf"}
                    ],
                }
            ],
        }
        repaired = _repair_children(node)
        assert repaired is not None
        assert repaired[0]["id"] == "n1.1"
        assert repaired[0]["gate"] == "leaf"
        assert "children" not in repaired[0]

    def test_is_single_child_gate_true_for_and_or(self) -> None:
        assert _is_single_child_gate("AND", [object()]) is True
        assert _is_single_child_gate("OR", [object()]) is True

    def test_is_single_child_gate_false_for_multi_child(self) -> None:
        assert _is_single_child_gate("AND", [object(), object()]) is False

    def test_is_single_child_gate_false_for_leaf(self) -> None:
        assert _is_single_child_gate("LEAF", [object()]) is False

    def test_is_single_child_gate_false_without_children(self) -> None:
        assert _is_single_child_gate("AND", None) is False
        assert _is_single_child_gate("AND", []) is False


class TestGateChildrenValidator:
    """AttackTreeNode.validate_gate_children_action raise paths."""

    @staticmethod
    def _validator_node(**overrides: Any) -> SimpleNamespace:
        node = _node(action=_ACTION)
        node._validate_action_zone = lambda: None
        for key, value in overrides.items():
            setattr(node, key, value)
        return node

    def test_valid_leaf_passes(self) -> None:
        node = self._validator_node()
        assert AttackTreeNode.validate_gate_children_action(node) is node

    def test_valid_internal_node_passes(self) -> None:
        node = self._validator_node(
            gate=GateType.OR,
            action=None,
            children=(
                SimpleNamespace(id="n1.1"),
                SimpleNamespace(id="n1.2"),
            ),
        )
        assert AttackTreeNode.validate_gate_children_action(node) is node

    def test_rejects_child_with_wrong_prefix(self) -> None:
        node = self._validator_node(
            gate=GateType.OR,
            action=None,
            children=(
                SimpleNamespace(id="n1.1"),
                SimpleNamespace(id="n2.1"),
            ),
        )
        with pytest.raises(ValueError, match="must have id starting with"):
            AttackTreeNode.validate_gate_children_action(node)

    def test_rejects_leaf_with_uncovered_realizations(self) -> None:
        node = self._validator_node(
            projected_step_ids=("s1",),
            realizations=(SimpleNamespace(projected_step_id="s9"),),
        )
        with pytest.raises(ValueError, match="do not match projected_step_ids"):
            AttackTreeNode.validate_gate_children_action(node)

    def test_rejects_leaf_with_duplicate_realizations(self) -> None:
        node = self._validator_node(
            projected_step_ids=("s1",),
            realizations=(SimpleNamespace(projected_step_id="s1"),) * 2,
        )
        with pytest.raises(ValueError, match="duplicate realization records"):
            AttackTreeNode.validate_gate_children_action(node)
