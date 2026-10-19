"""The ``attack-path-v1`` attack path: one scenario's own route to its hazard.

An ``and-or-tree-v1`` tree joins this scenario to the others that reach the
same hazard. The path keeps only this scenario's part of it: the attacker, the
conditions that must hold, the attack steps in order, the unsafe action, the
observable failure, and the hazard with its losses. The OR, the other
scenarios' ids, the grouping nodes, and the tree's top-level keys (which the
handoff repeats elsewhere) drop out. Code derives the path from the tree; no
model request depends on it.

Node ids keep their meaning and change their prefix: ``AT-`` becomes ``AP-`` and
the root ``AT-ROOT`` becomes ``AP-HAZ``. A node's ``source_id`` joins its
``source_ids``, so a path node carries one list.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from typing import Any

from .tree_sources import AND_OR_TREE_FORMAT

ATTACK_PATH_FORMAT = "attack-path-v1"
PATH_ID_PREFIX = "AP-"
HAZARD_NODE_ID = "AP-HAZ"
TREE_ID_PREFIX = "AT-"
TREE_ROOT_ID = "AT-ROOT"
_CONDITION_KEYS = ("evidence_status", "belief")
_STEP_KEYS = ("technique_id", "technique", "asset")


def path_node_id(tree_node_id: str) -> str:
    """Return the path id of a tree node id: ``AT-WP-1`` becomes ``AP-WP-1``."""
    if tree_node_id == TREE_ROOT_ID:
        return HAZARD_NODE_ID
    if not tree_node_id.startswith(TREE_ID_PREFIX):
        raise ValueError(f"tree node id {tree_node_id!r} does not start with AT-")
    return PATH_ID_PREFIX + tree_node_id[len(TREE_ID_PREFIX) :]


def reduce_to_attack_path(tree: Mapping[str, Any]) -> dict[str, Any]:
    """Reduce an ``and-or-tree-v1`` tree to the ``attack-path-v1`` of its scenario.

    The scenario is the one node the tree marks ``this_scenario``. A functional
    scenario has no attacker and no steps, so its path has no ``attacker`` key
    and an empty ``steps`` list. Optional node fields stay absent when the
    tree omits them.
    """
    if tree.get("format") != AND_OR_TREE_FORMAT:
        raise ValueError("an attack path reduces from an and-or-tree-v1 tree")
    root = tree.get("root")
    if not isinstance(root, Mapping):
        raise ValueError("the and-or tree has no root node")
    scenario = next(
        (node for node in _walk(root) if node.get("this_scenario") is True), None
    )
    if scenario is None:
        raise ValueError("the and-or tree marks no node as this scenario")
    parts = {
        str(child.get("node_id")): child
        for child in _children(scenario)
        if child.get("node_id") is not None
    }
    for needed in ("AT-UCA", "AT-FAIL"):
        if needed not in parts:
            raise ValueError(f"the scenario node has no {needed} child")
    path: dict[str, Any] = {"format": ATTACK_PATH_FORMAT}
    if isinstance(scenario.get("attacker"), Mapping):
        path["attacker"] = _attacker(scenario["attacker"])
    path["conditions"] = [
        _condition(node) for node in _children(parts.get("AT-COND", {}))
    ]
    path["steps"] = [_step(node) for node in _children(parts.get("AT-STEPS", {}))]
    path["unsafe_action"] = _unsafe_action(parts["AT-UCA"])
    path["observable_failure"] = _failure(parts["AT-FAIL"])
    path["hazard"] = _hazard(root)
    if "source_uncertainty" in tree:
        path["source_uncertainty"] = tree["source_uncertainty"]
    return path


def other_scenario_ids(tree: Mapping[str, Any]) -> list[str]:
    """Return the ids of the other scenarios an and-or tree names, in tree order."""
    root = tree.get("root")
    if not isinstance(root, Mapping):
        return []
    return [
        str(node["scenario_id"])
        for node in _walk(root)
        if node.get("type") == "reference" and node.get("scenario_id")
    ]


def path_node_ids(path: Mapping[str, Any]) -> list[str]:
    """Return every node id of a path, in publication order."""
    nodes: list[Mapping[str, Any]] = [
        *path.get("conditions", ()),
        *path.get("steps", ()),
        path["unsafe_action"],
        path["observable_failure"],
        path["hazard"],
    ]
    return [str(node["node_id"]) for node in nodes]


def attack_path_errors(
    path: Mapping[str, Any], causal_factor_ids: Sequence[str]
) -> list[str]:
    """Return what is wrong with a path: duplicate ids, or weak points off the factors.

    A scenario has one weak point per causal factor, in the factors' order.
    """
    errors: list[str] = []
    seen: set[str] = set()
    for node_id in path_node_ids(path):
        if not node_id.startswith(PATH_ID_PREFIX):
            errors.append(f"Attack path node {node_id} needs an AP- node_id.")
        elif node_id in seen:
            errors.append(f"Attack path node id {node_id} is not unique.")
        seen.add(node_id)
    weak = [
        node.get("source_ids", [])
        for node in path.get("conditions", ())
        if node.get("category") == "weak_point"
    ]
    expected = [[source_id] for source_id in causal_factor_ids]
    if weak != expected:
        errors.append(
            "Attack path needs one weak point per causal factor "
            f"({list(causal_factor_ids)}); found {[ids[0] if ids else '' for ids in weak]}."
        )
    return errors


def _walk(node: Mapping[str, Any]) -> Iterator[Mapping[str, Any]]:
    yield node
    for child in _children(node):
        yield from _walk(child)


def _children(node: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    children = node.get("children")
    if not isinstance(children, list):
        return []
    return [child for child in children if isinstance(child, Mapping)]


def _source_ids(node: Mapping[str, Any]) -> list[str]:
    ids = [node.get("source_id"), *(node.get("source_ids") or ())]
    return list(dict.fromkeys(str(item) for item in ids if item))


def _attacker(attacker: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {"profile": attacker.get("profile")}
    if attacker.get("goal"):
        result["goal"] = attacker["goal"]
    result["plan"] = list(attacker.get("plan") or ())
    return result


def _condition(node: Mapping[str, Any]) -> dict[str, Any]:
    result = {
        "node_id": path_node_id(str(node.get("node_id"))),
        "category": node.get("category"),
        "label": node.get("label"),
        "source_ids": _source_ids(node),
    }
    result.update({key: node[key] for key in _CONDITION_KEYS if key in node})
    return result


def _step(node: Mapping[str, Any]) -> dict[str, Any]:
    result = {
        "node_id": path_node_id(str(node.get("node_id"))),
        "label": node.get("label"),
    }
    result.update({key: node[key] for key in _STEP_KEYS if key in node})
    return result


def _unsafe_action(node: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "node_id": path_node_id(str(node.get("node_id"))),
        "label": node.get("label"),
        "source_ids": _source_ids(node),
        "violates": [dict(item) for item in node.get("violates") or ()],
    }


def _failure(node: Mapping[str, Any]) -> dict[str, Any]:
    result = {
        "node_id": path_node_id(str(node.get("node_id"))),
        "label": node.get("label"),
    }
    if "safe_outcome" in node:
        result["safe_outcome"] = node["safe_outcome"]
    return result


def _hazard(root: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "node_id": path_node_id(str(root.get("node_id"))),
        "label": root.get("label"),
        "source_ids": _source_ids(root),
        "hazards": [dict(item) for item in root.get("hazards") or ()],
        "losses": [dict(item) for item in root.get("losses") or ()],
    }


__all__ = [
    "ATTACK_PATH_FORMAT",
    "HAZARD_NODE_ID",
    "attack_path_errors",
    "other_scenario_ids",
    "path_node_id",
    "path_node_ids",
    "reduce_to_attack_path",
]
