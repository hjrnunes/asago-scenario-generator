"""Hazards: every published scenario that reaches each hazard.

The view reads the published scenarios and ``loss-analysis.yaml`` only.
Membership is each scenario's ``lineage.hazard_ids``, so a scenario that names
two hazards appears under both; the ``AT-ALT`` references inside a tree come
from an index built before publication and do not decide membership. Each
hazard is an OR of its scenarios, and each scenario is the ``AT-SCN`` subtree
of its and-or attack tree, or of its v5 attack path read in that shape: an
ordered AND of its conditions and steps.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from asago_scenario_generator.report.attack_path_view import path_subtree
from asago_scenario_generator.report.common import (
    code_id,
    code_ids,
    kind_chip,
    missing,
    natural_key,
    plural,
)
from asago_scenario_generator.report.run_data import RunData
from asago_scenario_generator.report.scenario_panels import and_or_node
from asago_scenario_generator.report_kit import (
    Column,
    Markup,
    Row,
    TreeNode,
    artifact,
    badge,
    callout,
    disclosure,
    esc,
    expand_controls,
    join,
    section,
    table,
    tree,
)

HAZARD_VIEWS = ("off", "report")
QUESTION = (
    "Which scenarios reach each hazard, and how? A hazard is reached when any one "
    "of its scenarios holds; open a hazard for each scenario's conditions and steps."
)
OR_LABEL = "Any one of these scenarios reaches the hazard"
SCENARIO_NODE = "AT-SCN"
ATTACK_FLOW_DIR = "attack-flow"


@dataclass(frozen=True)
class HazardGroup:
    """One hazard, its losses, and the published scenarios that name it."""

    hazard_id: str
    description: str | None
    losses: tuple[tuple[str, str | None], ...]
    scenario_ids: tuple[str, ...]


@dataclass(frozen=True)
class Disposition:
    """A scenario's deduplication status, and the scenario it duplicates."""

    status: str | None
    duplicate_of: str | None = None

    @property
    def label(self) -> str:
        if self.status == "duplicate":
            return f"duplicate of {self.duplicate_of}"
        if self.status is None:
            return "deduplication unknown"
        return self.status.replace("_", " ")


def hazard_groups(run: RunData) -> list[HazardGroup]:
    """Group the published scenarios by the hazards their lineage names.

    Every hazard of the loss analysis appears, with or without a scenario, and
    so does a hazard a scenario names that the loss analysis lacks.
    """
    losses: dict[str, str] = {}
    hazards: dict[str, Any] = {}
    if run.loss is not None:
        every_loss = run.loss.risk_card_losses + run.loss.use_case_losses
        losses = {loss.loss_id: loss.description for loss in every_loss}
        hazards = {hazard.hazard_id: hazard for hazard in run.loss.hazards}
    members: dict[str, list[str]] = {hazard_id: [] for hazard_id in hazards}
    for scenario_id in sorted(run.scenarios, key=natural_key):
        lineage = run.scenarios[scenario_id].lineage
        for hazard_id in dict.fromkeys(lineage.hazard_ids):
            members.setdefault(hazard_id, []).append(scenario_id)
    groups = []
    for hazard_id in sorted(members, key=natural_key):
        hazard = hazards.get(hazard_id)
        loss_ids = list(hazard.related_losses) if hazard is not None else []
        groups.append(
            HazardGroup(
                hazard_id,
                hazard.description
                if hazard is not None
                else _tree_description(run, hazard_id, members[hazard_id]),
                tuple((loss_id, losses.get(loss_id)) for loss_id in loss_ids),
                tuple(members[hazard_id]),
            )
        )
    return groups


def _tree_description(
    run: RunData, hazard_id: str, scenario_ids: list[str]
) -> str | None:
    """Describe a hazard the loss analysis lacks from its scenarios' tree roots."""
    for scenario_id in scenario_ids:
        scenario = run.scenarios[scenario_id]
        path = getattr(scenario, "attack_path", None)
        root = (
            path.hazard.model_dump(mode="json")
            if path is not None
            else scenario.attack_tree.get("root") or {}
        )
        for item in root.get("hazards") or []:
            if isinstance(item, dict) and item.get("source_id") == hazard_id:
                return item.get("label")
    return None


def scenario_subtree(scenario: Any) -> dict:
    """Return a scenario's own AND: its ``AT-SCN`` node, or its v5 path in that shape."""
    path = getattr(scenario, "attack_path", None)
    if path is not None:
        return path_subtree(path.model_dump(mode="json"))
    return _tree_subtree(scenario.attack_tree)


def _tree_subtree(attack_tree: dict) -> dict:
    """Return the ``AT-SCN`` node of an and-or attack tree: this scenario's AND."""
    stack = [attack_tree.get("root")]
    while stack:
        node = stack.pop()
        if not isinstance(node, dict):
            continue
        if node.get("node_id") == SCENARIO_NODE:
            return node
        stack.extend(reversed(node.get("children") or []))
    raise ValueError(
        f"the attack tree has no {SCENARIO_NODE} node; the hazard view needs "
        "and-or attack trees"
    )


def disposition(run: RunData, scenario_id: str) -> Disposition:
    """Read a scenario's deduplication status from its handoff, else testability."""
    dedup = run.scenarios[scenario_id].deduplication
    if dedup is not None:
        return Disposition(dedup.status, dedup.duplicate_of)
    row = None if run.testability is None else run.testability.get(scenario_id)
    if row is not None:
        return Disposition(row.status, row.duplicate_of)
    return Disposition(None)


def uca_parts(run: RunData, scenario_id: str) -> tuple[str, str, str]:
    """Return the unsafe control action's source controller, type, and action."""
    scenario = run.scenarios[scenario_id]
    uca = getattr(scenario, "uca", None)
    if uca is not None:
        return uca.source, uca.type, uca.control_action
    lineage = scenario.lineage
    return (
        lineage.controller_id,
        lineage.ica_slot_id.rsplit(":", 1)[-1],
        lineage.control_action_id,
    )


def flow_file_name(hazard_id: str) -> str:
    """Return the file name of a hazard's Attack Flow file."""
    return re.sub(r"[^A-Za-z0-9_.-]", "-", hazard_id) + ".json"


def anchor(hazard_id: str) -> str:
    """Return the HTML id of a hazard's disclosure."""
    return "hazard-" + "".join(
        c if c.isalnum() or c in "_.:-" else "-" for c in hazard_id
    )


def _dedup_badge(item: Disposition) -> Markup:
    return badge("pass" if item.status == "canonical" else "skip", item.label)


def _branch(run: RunData, scenario_id: str) -> TreeNode:
    scenario = run.scenarios[scenario_id]
    node = and_or_node(scenario_subtree(scenario))
    source, kind, action = uca_parts(run, scenario_id)
    header = Markup(
        f'<a href="#{esc(scenario_id)}">{esc(scenario_id)}</a> '
        f"{kind_chip(scenario.kind)} <b>{esc(scenario.gherkin.scenario)}</b> "
        f"{_dedup_badge(disposition(run, scenario_id))}"
        f'<div class="nm">Unsafe control action: {code_id(source)} {esc(kind)}: '
        f"{esc(action)}</div><div>{node.text}</div>"
    )
    return TreeNode(header, node.id, node.tags, node.children)


def _losses(group: HazardGroup) -> Markup:
    if not group.losses:
        return Markup("")
    items = join(
        (
            Markup(f"{code_id(loss_id)} {esc(text or 'not in loss-analysis.yaml')}")
            for loss_id, text in group.losses
        ),
        Markup("; "),
    )
    return Markup(f'<div class="nm">Losses: {items}</div>')


def _hazard_tree(run: RunData, group: HazardGroup) -> Markup:
    root = TreeNode(
        Markup(
            f"{code_id(group.hazard_id)} <b>{esc(_described(group))}</b>"
            f"{_losses(group)}"
        ),
        None,
        ["hazard"],
    )
    branches = [_branch(run, scenario_id) for scenario_id in group.scenario_ids]
    choice = TreeNode(
        Markup(f"<b>{esc(OR_LABEL)}</b>"),
        None,
        ["OR", plural(len(branches), "scenario")],
        branches,
    )
    flow = artifact(
        f"{ATTACK_FLOW_DIR}/{flow_file_name(group.hazard_id)}",
        run.output_dir / "report",
        "Attack Flow file",
    )
    return Markup(f'<p class="nm">{flow}</p>{tree(root, [choice])}')


def _described(group: HazardGroup) -> str:
    return group.description or "not in loss-analysis.yaml"


def _hazard_detail(run: RunData, group: HazardGroup) -> Markup:
    try:
        body = _hazard_tree(run, group)
    except Exception as error:  # noqa: BLE001 - one hazard must not drop the report
        return callout(
            "warning",
            f"{group.hazard_id} could not be rendered",
            Markup(f'<p class="nm">{esc(" ".join(str(error).split())[:300])}</p>'),
        )
    summary = Markup(
        f"{code_id(group.hazard_id)} <b>{esc(_described(group))}</b> "
        f'<span class="nm">{plural(len(group.scenario_ids), "scenario")}</span>'
    )
    return disclosure(summary, body, anchor(group.hazard_id), level="hazard")


def _counts(run: RunData, group: HazardGroup) -> list[int]:
    kinds = [run.scenarios[s].kind for s in group.scenario_ids]
    statuses = [disposition(run, s).status for s in group.scenario_ids]
    return [
        len(group.scenario_ids),
        kinds.count("adversarial"),
        len(kinds) - kinds.count("adversarial"),
        statuses.count("duplicate"),
        statuses.count("analytical_only"),
    ]


def _summary_table(run: RunData, groups: list[HazardGroup]) -> Markup:
    columns = [
        Column("Hazard"),
        Column("Description", sortable=False),
        Column("Losses", sortable=False),
        Column("Scenarios", numeric=True),
        Column("Attack", numeric=True),
        Column("Everyday", numeric=True),
        Column("Duplicates", numeric=True),
        Column("Analytical only", numeric=True),
    ]
    rows = [
        Row(
            [
                Markup(f'<a href="#{anchor(g.hazard_id)}">{esc(g.hazard_id)}</a>')
                if g.scenario_ids
                else code_id(g.hazard_id),
                _described(g),
                code_ids(loss_id for loss_id, _ in g.losses),
                *_counts(run, g),
            ],
            id=f"row-{anchor(g.hazard_id)}",
        )
        for g in groups
    ]
    return table(columns, rows, "hazards-table")


def _intro(run: RunData, groups: list[HazardGroup]) -> Markup:
    reached = sum(bool(g.scenario_ids) for g in groups)
    several = sum(
        len(dict.fromkeys(s.lineage.hazard_ids)) > 1 for s in run.scenarios.values()
    )
    verbs = (
        "names more than one and appears"
        if several == 1
        else "name more than one and appear"
    )
    return Markup(
        f"<p>{reached} of {plural(len(groups), 'hazard')} have a published scenario. "
        "A scenario belongs to every hazard its lineage names; "
        f"{plural(several, 'scenario')} {verbs} under each. "
        "Every published scenario appears, including everyday checks, duplicates, "
        "and analytical-only scenarios, each labeled. Each hazard links an Attack "
        "Flow file (STIX 2.1, attack-tree scope) with the same tree.</p>"
    )


def hazard_section(run: RunData) -> Markup:
    """Render the hazard table and one closed attack tree per reached hazard."""
    if run.loss is None and not run.scenarios:
        return section(
            "hazards", "Hazards", QUESTION, missing(run, "loss-analysis.yaml")
        )
    groups = hazard_groups(run)
    details = join(_hazard_detail(run, g) for g in groups if g.scenario_ids)
    body = join(
        [
            _intro(run, groups),
            _summary_table(run, groups),
            expand_controls("hazard-details", "hazard"),
            Markup(f'<div id="hazard-details">{details}</div>'),
        ]
    )
    return section("hazards", "Hazards", QUESTION, body)
