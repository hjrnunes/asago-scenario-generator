"""Focused adversarial coverage for zone-enforcement helpers."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from asago_scenario_generator.pipeline.generate.zones import (
    _enforce_zones_attack_tree,
    _validate_tree_zones_node,
    enforce_narrative_projection_zones,
    validate_attack_tree_zones,
)


def _tree(node: SimpleNamespace) -> SimpleNamespace:
    return SimpleNamespace(root=node)


def test_projection_zone_enforcement_skips_when_either_context_is_missing() -> None:
    narrative = SimpleNamespace(
        steps=[
            SimpleNamespace(
                projected_step_ids=("step.1",),
                zone="outside",
                step_number=1,
            )
        ]
    )

    assert enforce_narrative_projection_zones(narrative, None, {}) is narrative
    assert enforce_narrative_projection_zones(narrative, [], None) is narrative


@pytest.mark.parametrize(
    ("zone", "expected_count"),
    (
        (None, 0),
        ("input", 0),
        ("inactive", 1),
    ),
)
def test_tree_zone_node_checks_none_allowed_and_disallowed(
    zone: str | None,
    expected_count: int,
) -> None:
    node = SimpleNamespace(id="n1", zone=zone, children=None)
    violations: list[str] = []

    _validate_tree_zones_node(node, {"input"}, violations)

    assert len(violations) == expected_count


def test_validate_tree_zones_skips_validation_without_active_zones() -> None:
    tree = _tree(SimpleNamespace(id="n1", zone="inactive", children=None))

    assert validate_attack_tree_zones(tree, None) == []


def test_enforce_tree_zones_returns_tree_without_active_zones() -> None:
    tree = _tree(SimpleNamespace(id="n1", zone="inactive", children=None))

    assert _enforce_zones_attack_tree(tree, None) is tree


def test_enforce_tree_zones_includes_disallowed_zone_details() -> None:
    tree = _tree(SimpleNamespace(id="n1", zone="inactive", children=None))

    with pytest.raises(ValueError, match="disallowed-zone"):
        _enforce_zones_attack_tree(tree, ["input"])
