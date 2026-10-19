"""A scenario's attack path as the report shows it.

A v5 handoff carries ``attack_path``; a v4 handoff with an and-or tree carries
the same route inside the tree, and the reduction the producer uses for v5
recovers it. The panel reads the path in the order it happens and hides node
ids. The hazard view and the Attack Flow files read the same path as the
scenario's own subtree of an and-or tree, so their text stays what the tree
gave them.
"""

from __future__ import annotations

from typing import Any

from asago_scenario_generator.report.common import plural
from asago_scenario_generator.report_kit import Markup, chip, esc, fields, join
from asago_scenario_generator.stpa.scenario_prod.attack_path import (
    other_scenario_ids,
    reduce_to_attack_path,
)

CONDITION_WORD = {
    "situation": "Situation",
    "attacker_assumption": "Attacker assumption",
    "weak_point": "Weak point",
}
CONDITIONS_LABEL = "Conditions that must hold"
STEPS_LABEL = "Attack steps, in order"
SCENARIO_NODE = "AP-SCN"
CONDITIONS_NODE = "AP-COND"
STEPS_NODE = "AP-STEPS"


def scenario_path(scenario: Any) -> dict[str, Any] | None:
    """Return a scenario's attack path, or None when its tree is not an and-or tree.

    A tree the reduction cannot read also returns None, so a report that finds
    one falls back to the plain outline.
    """
    path = getattr(scenario, "attack_path", None)
    if path is not None:
        return path.model_dump(mode="json")
    tree = scenario.attack_tree
    if not isinstance(tree.get("root"), dict):
        return None
    try:
        return reduce_to_attack_path(tree)
    except ValueError:
        return None


def other_scenarios(scenario: Any) -> list[str] | None:
    """Return the other scenarios a v4 and-or tree names; None for a v5 handoff."""
    if getattr(scenario, "attack_path", None) is not None:
        return None
    return other_scenario_ids(scenario.attack_tree)


def _chips(source_ids: list[str]) -> Markup:
    return join((Markup(f" {chip(i)}") for i in source_ids))


def _sourced(items: list[dict[str, Any]], word: str) -> Markup:
    return join(
        Markup(
            f'<div class="nm">{esc(word)} {chip(i["source_id"])} {esc(i["label"])}</div>'
        )
        for i in items
    )


def _ol(items: list[str]) -> Markup:
    return Markup(f"<ol>{''.join(f'<li>{esc(item)}</li>' for item in items)}</ol>")


def _attacker(attacker: dict[str, Any]) -> Markup:
    goal = attacker.get("goal")
    return join(
        [
            Markup(f"<b>{esc(attacker['profile'])}</b>"),
            Markup(f'<div class="nm">Goal: {esc(goal)}</div>') if goal else Markup(""),
            Markup('<div class="nm">Plan:</div>') if attacker["plan"] else Markup(""),
            _ol(attacker["plan"]) if attacker["plan"] else Markup(""),
        ]
    )


def _condition(node: dict[str, Any]) -> Any:
    word = CONDITION_WORD.get(node["category"], node["category"].replace("_", " "))
    head = Markup(
        f"<b>{esc(word)}</b>{_chips(node['source_ids'])} {esc(' '.join(node['label'].split()))}"
    )
    notes = []
    if node.get("belief"):
        notes.append(Markup(f"<b>Belief</b> {esc(node['belief'])}"))
    if node.get("evidence_status"):
        status = node["evidence_status"].replace("_", " ")
        notes.append(Markup(f'<span class="nm">Evidence status:</span> {chip(status)}'))
    return (head, notes) if notes else head


def _step(node: dict[str, Any]) -> Markup:
    technique = " ".join(
        part for part in (node.get("technique_id"), node.get("technique")) if part
    )
    extras = join(
        [
            Markup(f" {chip(technique)}") if technique else Markup(""),
            Markup(f" {chip('asset ' + node['asset'])}") if node.get("asset") else "",
        ]
    )
    return Markup(f"{esc(' '.join(node['label'].split()))}{extras}")


def _unsafe_action(node: dict[str, Any]) -> Markup:
    return join(
        [
            Markup(
                f"{esc(' '.join(node['label'].split()))}{_chips(node['source_ids'])}"
            ),
            _sourced(node["violates"], "Violates"),
        ]
    )


def _failure(node: dict[str, Any]) -> Markup:
    safe = node.get("safe_outcome")
    return join(
        [
            esc(" ".join(node["label"].split())),
            Markup(f'<div class="nm">Safe outcome: {esc(safe)}</div>') if safe else "",
        ]
    )


def _hazard(node: dict[str, Any]) -> Markup:
    label = " ".join(node["label"].split())
    others = [h for h in node["hazards"] if " ".join(h["label"].split()) != label]
    return join(
        [
            Markup(f"{esc(label)}{_chips(node['source_ids'])}"),
            _sourced(others, "Also hazard"),
            _sourced(node["losses"], "Loss"),
        ]
    )


def path_rows(path: dict[str, Any]) -> list[tuple[str, Any]]:
    """Return the labelled rows of a path: the attacker, then the five parts."""
    rows: list[tuple[str, Any]] = []
    if path.get("attacker"):
        rows.append(("Attacker", _attacker(path["attacker"])))
    rows.append(("1 Conditions", [_condition(n) for n in path["conditions"]]))
    # The numbering stays 1 to 5 for a scenario without steps (a functional one).
    rows.append(
        (
            "2 Attack steps",
            [_step(n) for n in path["steps"]] if path["steps"] else "None",
        )
    )
    rows.append(("3 Unsafe action", _unsafe_action(path["unsafe_action"])))
    rows.append(("4 Observable failure", _failure(path["observable_failure"])))
    rows.append(("5 Hazard", _hazard(path["hazard"])))
    return rows


def path_preview(path: dict[str, Any]) -> str:
    """Summarize a path in one line: its parts and its weak points."""
    weak = sorted(
        {
            source_id
            for node in path["conditions"]
            if node["category"] == "weak_point"
            for source_id in node["source_ids"]
        }
    )
    return (
        f"{plural(len(path['conditions']), 'condition')} · "
        f"{plural(len(path['steps']), 'attack step')} · "
        f"weak point {', '.join(weak) or 'none'}"
    )


def path_body(path: dict[str, Any], others: list[str] | None = None) -> Markup:
    """Render a path as its rows, with the other scenarios of a v4 tree above them."""
    notes = []
    if others is not None:
        named = ", ".join(others) if others else "none"
        notes.append(f"Other scenarios that reach the same hazard: {named}.")
    if path.get("source_uncertainty"):
        notes.append(str(path["source_uncertainty"]))
    intro = join(Markup(f'<p class="nm">{esc(line)}</p>') for line in notes)
    return join([intro, fields(path_rows(path))])


def weak_point_count(path: dict[str, Any]) -> int:
    """Count the weak points of a path: one per causal factor."""
    return sum(node["category"] == "weak_point" for node in path["conditions"])


def path_subtree(path: dict[str, Any]) -> dict[str, Any]:
    """Return a path as the ``AT-SCN``-shaped subtree the hazard view and Attack Flow read.

    The grouping nodes carry the labels the producer's tree gave them, and the
    scenario node carries the failure's label; only the node ids differ.
    """
    conditions = [
        {
            "node_id": node["node_id"],
            "type": "condition",
            "label": node["label"],
            "source_ids": node["source_ids"],
            **{
                key: node[key]
                for key in ("category", "evidence_status", "belief")
                if key in node
            },
        }
        for node in path["conditions"]
    ]
    children: list[dict[str, Any]] = [
        {
            "node_id": CONDITIONS_NODE,
            "type": "operator",
            "operator": "AND",
            "category": "conditions",
            "label": CONDITIONS_LABEL,
            "children": conditions,
        }
    ]
    if path["steps"]:
        steps = [
            {"type": "action", "category": "attack_step", **node}
            for node in path["steps"]
        ]
        children.append(
            {
                "node_id": STEPS_NODE,
                "type": "operator",
                "operator": "AND",
                "ordered": True,
                "category": "attack_steps",
                "label": STEPS_LABEL,
                "children": steps,
            }
        )
    children.append(
        {"type": "action", "category": "unsafe_action", **path["unsafe_action"]}
    )
    children.append(
        {
            "type": "condition",
            "category": "observable_failure",
            **path["observable_failure"],
        }
    )
    return {
        "node_id": SCENARIO_NODE,
        "type": "operator",
        "operator": "AND",
        "ordered": True,
        "category": "scenario",
        "label": path["observable_failure"]["label"],
        "this_scenario": True,
        "children": children,
    }
