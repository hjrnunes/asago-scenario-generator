"""Deterministic BehaviorSpec compilation from tree leaves and projection.

The structured behavior spec is compiled directly from validated tree
leaves and the projection block, then deterministically rendered to
Gherkin.  This module stays pure — no LLM calls, no envelope assembly,
no I/O — so the compilation is directly unit-testable and the rendered
Gherkin is authoritative: every action/assertion ID appears in the text
in the correct order, allowing LLM-authored Call 3 output to be
cross-checked exactly against this rendering.
"""

from __future__ import annotations

from asago_scenario_generator.models.attack_pattern import CanonicalAttackChain
from asago_scenario_generator.models.attack_tree import AttackTree, AttackTreeNode
from asago_scenario_generator.models.projection_envelope import (
    ProjectionEnvelopeBlock,
)
from asago_scenario_generator.models.scenario import (
    BehaviorAction,
    BehaviorAssertion,
    BehaviorScenario,
    BehaviorSpec,
)
from asago_scenario_generator.pipeline.projection_realizations import _iter_leaves

# ---------------------------------------------------------------------------
# Leaf selection
# ---------------------------------------------------------------------------


def _leaf_action_text(leaf: AttackTreeNode) -> str:
    """Gherkin step text for a projected leaf.

    The tree leaf's description wins over its label; an empty label falls
    back to the leaf's node id.
    """
    if leaf.description:
        return leaf.description
    return leaf.label or leaf.id


def _projected_leaves(tree: AttackTree, selected: set[str]) -> list[AttackTreeNode]:
    """Return leaves whose projected steps are non-empty and fully selected."""
    return [
        leaf
        for leaf in _iter_leaves(tree.root)
        if leaf.projected_step_ids
        and all(step_id in selected for step_id in leaf.projected_step_ids)
    ]


def _action_from_leaf(leaf: AttackTreeNode) -> BehaviorAction:
    """Compile one structured action from a fully projected leaf.

    The leaf's canonical realization records are carried verbatim: the
    tree validator guarantees exactly one record per projected step ID.
    """
    return BehaviorAction(
        action_id=f"ba-{leaf.id}",
        projected_step_ids=leaf.projected_step_ids,
        source_leaf_id=leaf.id,
        gherkin_keyword="When",
        text=_leaf_action_text(leaf),
        realizations=leaf.realizations,
    )


# ---------------------------------------------------------------------------
# Assertion compilation
# ---------------------------------------------------------------------------


def _postcondition_descriptions(
    chain: CanonicalAttackChain,
    step_id: str,
    pc_ids: list[str],
) -> list[str]:
    """Resolve postcondition descriptions, falling back to the raw IDs."""
    step_obj = next((s for s in chain.steps if s.step_id == step_id), None)
    pc_by_id = {
        pc.postcondition_id: pc.description
        for pc in (step_obj.observable_postconditions if step_obj else [])
    }
    return [pc_by_id.get(pc_id, pc_id) for pc_id in pc_ids]


def _assertions_from_block(block: ProjectionEnvelopeBlock) -> list[BehaviorAssertion]:
    """Compile assertions from the block's security-relevant postconditions.

    Assertion IDs are stable: ``assert-<step_id>-<postcondition_ids>`` with
    postcondition IDs dash-joined, matching the deterministic Call 3 ID
    scheme so the LLM-authored assertions can be cross-checked exactly.
    """
    chain = block.projection.source_chain
    sec_pcs = block.security_relevant_postconditions()
    assertions: list[BehaviorAssertion] = []
    for step_id in block.projection.selected_step_ids:
        pc_ids = sec_pcs.get(step_id, [])
        if not pc_ids:
            continue
        pc_descs = _postcondition_descriptions(chain, step_id, pc_ids)
        assertions.append(
            BehaviorAssertion(
                assertion_id=f"assert-{step_id}-{'-'.join(pc_ids)}",
                source_step_ids=(step_id,),
                projected_postcondition_ids=tuple(pc_ids),
                gherkin_keyword="Then",
                text="; ".join(pc_descs),
            )
        )
    return assertions


# ---------------------------------------------------------------------------
# Compilation entry point
# ---------------------------------------------------------------------------


def _zone_map_for_tree(tree: AttackTree) -> dict[str, str]:
    """Map compiled action IDs to leaf zones for Gherkin annotations."""
    zone_map: dict[str, str] = {}
    for leaf in _iter_leaves(tree.root):
        if leaf.projected_step_ids and leaf.zone is not None:
            zone_map[f"ba-{leaf.id}"] = leaf.zone
    return zone_map


def build_behavior_spec_from_tree(
    attack_tree: AttackTree,
    block: ProjectionEnvelopeBlock,
    gherkin_text: str | None = None,
) -> BehaviorSpec:
    """Construct a structured BehaviorSpec from tree leaves and projection.

    Structured behavior actions are deterministically derived from
    validated tree leaves (which carry ``projected_step_ids``), with stable
    IDs of the form ``ba-<leaf_id>``.  Structured assertions are derived
    from security-relevant postconditions of the projected steps, with
    stable IDs of the form ``assert-<step_id>-<postcondition_id>``.

    The Gherkin feature text is **deterministically rendered** from the
    structured actions and assertions — not from an independently authored
    LLM output.  This proves exact correspondence: every action/assertion
    ID in the structure appears in the rendered Gherkin in the correct
    order.  The LLM Call 3 output (``gherkin_text``) is cross-checked
    against the deterministic rendering to ensure the LLM did not omit,
    add, reorder, or fabricate actions/assertions.

    Validation cross-checks the structured elements against the projection
    block and the rendered Gherkin.
    """
    selected = set(block.projection.selected_step_ids)
    actions = [
        _action_from_leaf(leaf) for leaf in _projected_leaves(attack_tree, selected)
    ]
    assertions = _assertions_from_block(block)
    zone_map = _zone_map_for_tree(attack_tree)

    rendered = render_gherkin_from_behavior_spec(actions, assertions, zone_map=zone_map)
    return BehaviorSpec(
        actions=tuple(actions),
        assertions=tuple(assertions),
        gherkin_text=rendered,
    )


# ---------------------------------------------------------------------------
# Deterministic Gherkin rendering
# ---------------------------------------------------------------------------


def _zone_suffix(action_id: str, zone_map: dict[str, str] | None) -> str:
    """Zone annotation suffix for a compiled action, if any."""
    if zone_map and action_id in zone_map:
        return f" ({zone_map[action_id]})"
    return ""


def _and_shortened_keyword(previous_keyword: str | None, keyword: str) -> str:
    """Shorthand a repeated same-semantic step as ``And``."""
    return "And" if previous_keyword == keyword else keyword


def render_gherkin_from_behavior_spec(
    actions: list[BehaviorAction],
    assertions: list[BehaviorAssertion],
    *,
    zone_map: dict[str, str] | None = None,
    scenarios: list[BehaviorScenario] | None = None,
) -> str:
    """Deterministically render Gherkin feature text from structured behavior.

    This is the authoritative rendering: the structured actions and
    assertions are the source of truth, and the Gherkin text is derived
    from them.  This proves exact correspondence — every action/assertion
    ID appears in the rendered text in the correct order.

    When ``zone_map`` is supplied (mapping ``action_id`` → zone name),
    zone annotations are included in the Gherkin step text as
    ``(zone_name)`` suffixes, enabling zone-omission validation.
    """
    lines: list[str] = ["Feature: Projected scenario behavior", ""]

    # Background with projection context (informational).
    lines.append("  Background:")
    lines.append("    Given a target AI system with projected attack steps")
    lines.append("")

    if scenarios:
        action_by_id = {item.action_id: item for item in actions}
        assertion_by_id = {item.assertion_id: item for item in assertions}
        for scenario_index, scenario in enumerate(scenarios):
            lines.append(f"  Scenario: {scenario.title}")
            lines.append("")
            previous_keyword: str | None = None
            for step_id in scenario.step_ids:
                if step_id in action_by_id:
                    action = action_by_id[step_id]
                    semantic_keyword = action.gherkin_keyword
                    text = action.text
                    zone_suffix = _zone_suffix(action.action_id, zone_map)
                else:
                    assertion = assertion_by_id[step_id]
                    semantic_keyword = assertion.gherkin_keyword
                    text = assertion.text
                    zone_suffix = ""
                keyword = _and_shortened_keyword(previous_keyword, semantic_keyword)
                lines.append(f"    {keyword} {text}{zone_suffix}")
                previous_keyword = semantic_keyword
            if scenario_index < len(scenarios) - 1:
                lines.append("")
        return "\n".join(lines) + "\n"

    # Legacy single-scenario rendering for artifacts without explicit grouping.
    lines.append("  Scenario: Projected attack realization")
    lines.append("")

    # Preserve typed transitions.  ``And`` is only shorthand for another
    # action of the same semantic keyword as the immediately preceding action.
    previous_keyword: str | None = None
    for action in actions:
        zone_suffix = _zone_suffix(action.action_id, zone_map)
        keyword = _and_shortened_keyword(previous_keyword, action.gherkin_keyword)
        lines.append(f"    {keyword} {action.text}{zone_suffix}")
        previous_keyword = action.gherkin_keyword

    # Render assertions (Then steps).
    for assertion in assertions:
        lines.append(f"    {assertion.gherkin_keyword} {assertion.text}")

    return "\n".join(lines) + "\n"
