"""Shared tree traversal helpers."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from asago_scenario_generator.models.attack_tree import AttackTreeNode


def collect_tree_values(
    node: AttackTreeNode,
    attribute: str,
    *,
    transform: Callable[[Any], Any] = lambda value: value,
    include_empty: bool = True,
) -> set[object]:
    """Collect one attribute from every node, applying a value transform."""
    values: set[object] = set()
    value = getattr(node, attribute, None)
    if value is not None and (include_empty or value):
        values.add(transform(value))
    if node.children:
        for child in node.children:
            values.update(
                collect_tree_values(
                    child,
                    attribute,
                    transform=transform,
                    include_empty=include_empty,
                )
            )
    return values


def collect_tree_zones(
    node: AttackTreeNode,
    *,
    include_empty: bool = True,
) -> set[str]:
    """Collect zone values from a tree, preserving the caller's null policy."""
    return {
        value
        for value in collect_tree_values(node, "zone", include_empty=include_empty)
        if isinstance(value, str)
    }
