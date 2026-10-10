"""A scenario as authoring receives it: narrative, attack tree, and Gherkin.

The producer writes the narrative and the Gherkin in fixed formats, so the
renderers parse them. A line they do not recognize renders as plain text.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from asago_scenario_generator.report.common import code_id, plural
from asago_scenario_generator.report.run_data import RunData
from asago_scenario_generator.report_kit import (
    Markup,
    TreeNode,
    code,
    esc,
    fields,
    join,
    tree,
)

DEFAULT_AUTHORITY = "proposed_hypothesis"
LINE = re.compile(r"^(?P<label>[^():]+?)(?: \((?P<meta>[^)]*)\))?:(?: (?P<text>.*))?$")
NOTES = ("Causal relations", "The account remains semantics-only")
ID_TOKEN = re.compile(r"\b[A-Z]{1,6}-\d+(?:-\d+)*\b")
VULNERABILITY = " Vulnerability: "
PREVIEW_LIMIT = 110
CATEGORY_WORD = {
    "defender_belief": "Belief",
    "defender_desire": "Desire",
    "defender_intention": "Intention",
    "unsafe_action": "Unsafe action",
    "constraint": "Constraint",
    "hazard": "Hazard",
    "loss": "Loss",
    "causal_factor": "Causal factor",
    "actor_belief": "Actor belief",
    "actor_desire": "Actor desire",
    "actor_intention": "Actor intention",
}


@dataclass(frozen=True)
class Panel:
    """One closed panel of a scenario row: its anchor key, title, preview, and body."""

    key: str
    title: str
    preview: str
    body: Markup
    differs: bool = False


@dataclass
class Entry:
    """One labelled line of a narrative with the lines nested under it."""

    label: str
    meta: str | None
    text: str
    line: str
    items: list[tuple[int, str]] = field(default_factory=list)
    turns: list[str] = field(default_factory=list)


def _clip(text: str, limit: int = PREVIEW_LIMIT) -> str:
    return text if len(text) <= limit else text[:limit].rsplit(" ", 1)[0] + "…"


def _entry(line: str) -> Entry:
    match = LINE.match(line)
    if match is None:
        return Entry("", None, line, line)
    return Entry(match["label"], match["meta"], match["text"] or "", line)


def parse_narrative(text: str) -> tuple[str, list[Entry]]:
    """Split a narrative into its framing line and labelled entries."""
    lines = [line for line in text.split("\n") if line.strip()]
    framing = lines.pop(0) if lines and lines[0].startswith("Test hypothesis") else ""
    entries: list[Entry] = []
    for line in lines:
        item = re.match(r"^( *)- (.*)$", line)
        turn = re.match(r"^\d+\. (.*)$", line)
        if entries and item:
            entries[-1].items.append((len(item.group(1)) // 2, item.group(2)))
        elif entries and turn:
            entries[-1].turns.append(turn.group(1))
        else:
            entries.append(_entry(line))
    return framing, entries


def meta_html(meta: str | None) -> Markup:
    """Render a claim's ``(source: ...; authority: ...)`` note; the default authority stays unmarked."""
    parts = []
    for part in (meta or "").split("; "):
        key, sep, value = part.partition(": ")
        if not sep:
            parts.append(esc(part))
        elif key == "source":
            parts.append(join((code_id(s) for s in value.split(", ")), " "))
        elif not (key == "authority" and value == DEFAULT_AUTHORITY):
            parts.append(esc(f"{key} {value}"))
    shown = join([p for p in parts if p], " · ")
    return Markup(f'<span class="nm">{shown}</span>') if shown else Markup("")


def _vulnerability(text: str) -> tuple[str, Markup]:
    if VULNERABILITY not in text:
        return text, Markup("")
    text, vulnerability = text.split(VULNERABILITY, 1)
    if vulnerability.startswith("Not selected"):
        return text, Markup(' <span class="nm">not a causal factor here</span>')
    return text, Markup(f'<div class="vul">Vulnerability: {esc(vulnerability)}</div>')


def _claim(text: str) -> Markup:
    match = LINE.match(text)
    if match is None:
        return Markup(f'<span class="nm">{esc(text)}</span>')
    body, vulnerability = _vulnerability(match["text"] or "")
    return Markup(
        f"<b>{esc(match['label'])}</b> {esc(body)} {meta_html(match['meta'])}{vulnerability}"
    )


def nest(items: list[tuple[int, str]]) -> list[Any]:
    """Turn indented claim lines into kit list items: text, or ``(text, children)``."""
    roots: list[dict] = []
    stack: list[tuple[int, list]] = [(-1, roots)]
    for level, text in items:
        node = {"text": text, "children": []}
        while stack[-1][0] >= level:
            stack.pop()
        stack[-1][1].append(node)
        stack.append((level, node["children"]))
    return [_item(n) for n in roots]


def _item(node: dict) -> Any:
    claim = _claim(node["text"])
    if not node["children"]:
        return claim
    return (claim, [_item(child) for child in node["children"]])


def _row(entry: Entry) -> tuple[Markup, Any]:
    label = esc(entry.label)
    if entry.meta and entry.items:
        label = Markup(f'{label}<div class="nm">{esc(entry.meta)}</div>')
    if entry.turns:
        return label, list(entry.turns)
    if entry.items:
        return label, nest(entry.items)
    note = meta_html(entry.meta) if entry.meta else Markup("")
    return label, Markup(f"{esc(entry.text)}{note}")


def narrative_preview(entries: list[Entry]) -> str:
    """Summarize a narrative in one line: the actor for an attack, the claims for an everyday check."""
    by_label = {e.label: e for e in entries}
    if "Actor" in by_label:
        turns = len(by_label.get("Turns, in order", Entry("", None, "", "")).turns)
        channel = by_label.get("Channel", Entry("", None, "", "")).text.split(";")[0]
        actor = by_label["Actor"].text.rstrip(".")
        return f"{actor} · {channel} channel · {plural(turns, 'turn')}"
    items = [t for e in entries for _, t in e.items]
    factor = next(
        (LINE.match(t)["text"] for t in items if t.startswith("Factor (")), ""
    )
    sourced = sum(" (source: " in t for t in items)
    return f"{plural(sourced, 'sourced claim')} · factor: {_clip(factor or '')}"


def narrative_panel(text: str) -> Panel:
    """Build the narrative panel from the producer's narrative text."""
    framing, entries = parse_narrative(text)
    notes = [e.line for e in entries if e.label.startswith(NOTES)]
    rows = [_row(e) for e in entries if not e.label.startswith(NOTES)]
    hypotheses = (
        " Claims without an authority note are proposed hypotheses."
        if any(e.items for e in entries)
        else ""
    )
    intro = Markup(f'<p class="nm">{esc(framing)}{hypotheses}</p>')
    foot = join(Markup(f'<p class="nm">{esc(n)}</p>') for n in notes)
    return Panel(
        "narrative",
        "Narrative",
        narrative_preview(entries),
        join([intro, fields(rows), foot]),
    )


def _node_tags(node: dict, leaves: set[str], leaf_sources: set[str]) -> list[str]:
    tags = []
    if f"{node.get('source_id')}: {node['label']}" in leaves:
        tags.append("leaf")
    elif node.get("source_id") in leaf_sources:
        tags.append("named by the causal factor")
    if node.get("evidence_status"):
        tags.append(node["evidence_status"].replace("_", " "))
    if node.get("authority", DEFAULT_AUTHORITY) != DEFAULT_AUTHORITY:
        tags.append(f"authority {node['authority']}")
    if node.get("source_uncertainty"):
        tags.append(f"source uncertainty: {node['source_uncertainty']}")
    return tags


def _tree_node(
    node: dict, leaves: set[str], leaf_sources: set[str], seen: dict[str, str]
) -> TreeNode:
    ids = list(
        dict.fromkeys(
            i for i in [node.get("source_id"), *(node.get("source_ids") or [])] if i
        )
    )
    label = " ".join(node["label"].split())
    first = seen.setdefault(label, node["node_id"])
    tags = _node_tags(node, leaves, leaf_sources)
    prefix = join([code_id(i) for i in ids], " ")
    if first != node["node_id"]:
        text = Markup(f'{prefix} <span class="dup">{esc(label)}</span>')
        tags.append(f"same text as {first}")
    else:
        text = Markup(f"{prefix} {esc(label)}")
    return TreeNode(text, node["node_id"], tags)


def _category_word(category: str, count: int) -> str:
    word = CATEGORY_WORD.get(category, category.replace("_", " ").capitalize())
    if count == 1:
        return word
    return "Losses" if word == "Loss" else word + "s"


def _branch(
    branch: dict, leaves: set[str], leaf_sources: set[str], seen: dict[str, str]
) -> TreeNode:
    groups: dict[str, list[dict]] = defaultdict(list)
    for node in branch["children"]:
        groups[node["category"]].append(node)
    children = [
        TreeNode(
            _category_word(category, len(nodes)),
            None,
            (),
            [_tree_node(n, leaves, leaf_sources, seen) for n in nodes],
        )
        for category, nodes in groups.items()
    ]
    count = len(branch["children"])
    tags = [f"{branch['category'].replace('_', ' ')} · {plural(count, 'node')}"]
    if branch.get("authority", DEFAULT_AUTHORITY) != DEFAULT_AUTHORITY:
        tags.append(f"authority {branch['authority']}")
    return TreeNode(
        Markup(f"<b>{esc(branch['label'])}</b>"), branch["node_id"], tags, children
    )


def tree_panel(attack_tree: dict) -> Panel:
    """Build the attack-tree panel: nodes grouped by category, as authoring projects them."""
    leaves = set(attack_tree.get("leaves") or [])
    leaf_sources = {leaf.split(": ", 1)[0] for leaf in leaves}
    seen: dict[str, str] = {}
    branches = [_branch(b, leaves, leaf_sources, seen) for b in attack_tree["branches"]]
    total = sum(len(b["children"]) for b in attack_tree["branches"])
    preview = (
        f"{plural(total, 'node')} in {plural(len(branches), 'branch', 'branches')} · leaf "
        + ", ".join(sorted(leaf_sources))
    )
    root = TreeNode(attack_tree["root"])
    note = (
        f"Relations are {attack_tree.get('relation')} ({attack_tree.get('relation_evidence')}): "
        "the tree names no AND or OR, so nodes are grouped by category, the projection "
        "authoring receives."
    )
    uncertainty = attack_tree.get("source_uncertainty")
    lines = [
        f"Loss scenario: {attack_tree.get('loss_scenario')}",
        f"{attack_tree.get('framing')} {note}",
        *([str(uncertainty)] if uncertainty else []),
    ]
    intro = join(Markup(f'<p class="nm">{esc(line)}</p>') for line in lines)
    return Panel("tree", "Attack tree", preview, join([intro, tree(root, branches)]))


def feature_matches(gherkin: Any, text: str) -> bool:
    """Tell whether a feature file holds the YAML block's feature, scenario, steps, and comments."""
    lines = [s.strip() for s in text.splitlines() if s.strip()]
    skipped = ("Feature:", "Background:", "Scenario:", "#")
    steps = [s for s in lines if not s.startswith(skipped)]
    expected = gherkin.given + gherkin.when + gherkin.then_expected
    return (
        lines[:1] == [f"Feature: {gherkin.feature}"]
        and f"Scenario: {gherkin.scenario}" in lines
        and steps == expected
        and sum(s.startswith("#") for s in lines)
        == len(gherkin.then_unsafe_alternative)
    )


def _feature_text(gherkin: Any) -> str:
    return gherkin.to_feature_text()


def gherkin_panel(scenario_id: str, gherkin: Any, feature: str | None) -> Panel:
    """Build the Gherkin panel from the feature file, or from the YAML block without one."""
    if feature is None:
        text, differs = _feature_text(gherkin), False
        source = "No feature file; rendered from the YAML gherkin block."
    else:
        text, differs = feature, not feature_matches(gherkin, feature)
        verdict = "It differs from the YAML block." if differs else "The two agree."
        source = (
            f"From {scenario_id}.feature, which authoring reads in place of the YAML "
            f"gherkin block. {verdict}"
        )
    unsafe = (
        " · unsafe alternative as a comment" if gherkin.then_unsafe_alternative else ""
    )
    preview = (
        f"{len(gherkin.given)} Given · {len(gherkin.when)} When · "
        f"{len(gherkin.then_expected)} Then{unsafe}"
        + (" · differs from YAML" if differs else "")
    )
    body = join([Markup(f'<p class="nm">{esc(source)}</p>'), code(text, "gherkin")])
    return Panel("gherkin", "Gherkin", preview, body, differs)


def scenario_panels(run: RunData, scenario_id: str) -> list[Panel]:
    """Build the narrative, tree, and Gherkin panels of one scenario."""
    scenario = run.scenarios[scenario_id]
    return [
        narrative_panel(scenario.narrative),
        tree_panel(scenario.attack_tree),
        gherkin_panel(scenario_id, scenario.gherkin, run.features.get(scenario_id)),
    ]


@dataclass(frozen=True)
class PanelStats:
    """Counts across the run that show a change in the trees or feature files at a glance."""

    trees: int
    flat: int
    single_leaf: int
    features: int
    matching: int


def panel_stats(run: RunData) -> PanelStats:
    """Count flat trees, one-leaf trees, and feature files that match their YAML."""
    trees = [s.attack_tree for s in run.scenarios.values()]
    matching = sum(
        feature_matches(run.scenarios[s].gherkin, text)
        for s, text in run.features.items()
        if s in run.scenarios
    )
    return PanelStats(
        len(trees),
        sum(t.get("relation") == "flat" for t in trees),
        sum(len(t.get("leaves") or []) == 1 for t in trees),
        len(run.features),
        matching,
    )
