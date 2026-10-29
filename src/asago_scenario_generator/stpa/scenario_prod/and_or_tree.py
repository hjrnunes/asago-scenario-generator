"""The ``and-or-tree-v1`` attack tree: the hazard, OR the scenarios that reach it.

The tree follows the attack-tree scope of Attack Flow and the STPA Handbook's
loss-scenario form (Leveson and Thomas 2018, p. 51). Its root is the
scenario's hazard. An OR joins this scenario to every other published
scenario that shares a hazard with it. This scenario is an ordered AND of its
conditions, its attack steps, the unsafe action, and the observable failure.

The operators come from the scenario's own structure: every condition must
hold, and the attack shape fixes the step order. They are not typed causal
evidence, so ``relation_basis`` says ``scenario_structure``. Code renders
the whole tree from the scenario spec; no model request depends on it.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from asago_scenario_generator.stpa.models.attack_shape import default_attack_shape
from asago_scenario_generator.stpa.models.causal_factor import is_belief_flaw
from asago_scenario_generator.stpa.models.scenario_spec import ScenarioSpec

from .narration import (
    attack_steps,
    belief_text,
    plain,
    rule_text,
    weak_point_belief_text,
)
from .presentation import (
    ADVERSARY_WORDS,
    HYPOTHESIS_AUTHORITY,
    sanitize_tree_sources,
    selected_criterion,
)
from .tree_sources import AND_OR_TREE_FORMAT

AND_OR_RELATION = "and-or"
RELATION_BASIS = "scenario_structure"
KEPT_KEYS = (
    "framing",
    "kind",
    "criterion",
    "criterion_authority",
    "lineage",
    "loss_scenario",
    "leaves",
    "leaf_authority",
    "root_authority",
)
SCENARIOS_LABEL = "Scenarios that reach this hazard"
CONDITIONS_LABEL = "Conditions that must hold"
STEPS_LABEL = "Attack steps, in order"
SOURCE_UNCERTAINTY = (
    "Free-form text named a structural source outside the selected "
    "causal path; that source was not treated as tree evidence."
)

# hazard id -> ids of every scenario that names it
SiblingIndex = Mapping[str, Sequence[str]]


def scenario_hazard_ids(spec: ScenarioSpec) -> list[str]:
    """Return the hazard ids the scenario's lineage names."""
    context = spec.scenario_context
    if context is None:
        return list(spec.unsafe_outcome_hazard_refs)
    return [item.hazard_id for item in context.hazards]


def build_sibling_index(specs: Iterable[ScenarioSpec]) -> dict[str, list[str]]:
    """Index every scenario id by each hazard it names, in scenario-id order."""
    index: dict[str, list[str]] = {}
    for spec in sorted(specs, key=lambda item: item.scenario_id):
        for hazard_id in dict.fromkeys(scenario_hazard_ids(spec)):
            index.setdefault(hazard_id, []).append(spec.scenario_id)
    return index


def render_and_or_tree(
    spec: ScenarioSpec, flat_tree: Mapping[str, Any], siblings: SiblingIndex
) -> dict[str, Any]:
    """Render ``and-or-tree-v1`` for one scenario.

    ``flat_tree`` is the scenario's flat tree; the kept top-level keys copy
    its values. ``siblings`` names the run's other scenarios by hazard.
    """
    tree: dict[str, Any] = {
        key: flat_tree[key] for key in KEPT_KEYS if key in flat_tree
    }
    tree["format"] = AND_OR_TREE_FORMAT
    tree["relation"] = AND_OR_RELATION
    tree["relation_basis"] = RELATION_BASIS
    own = _scenario_node(spec)
    changed = sanitize_tree_sources(own, spec)
    root = _root_node(spec, tree.get("lineage", {}))
    changed |= sanitize_tree_sources(root, spec)
    root["children"] = [
        _node(
            "AT-OR",
            "operator",
            "scenarios",
            SCENARIOS_LABEL,
            operator="OR",
            children=[own, *_reference_nodes(spec, siblings)],
        )
    ]
    tree["root"] = root
    if changed or "source_uncertainty" in flat_tree:
        tree["source_uncertainty"] = flat_tree.get(
            "source_uncertainty", SOURCE_UNCERTAINTY
        )
    return tree


def _root_node(spec: ScenarioSpec, lineage: Mapping[str, Any]) -> dict[str, Any]:
    context = spec.scenario_context
    hazards = [] if context is None else list(context.hazards)
    losses = [] if context is None else list(context.losses)
    label = plain(hazards[0].description) if hazards else plain(spec.loss_scenario)
    return _node(
        "AT-ROOT",
        "goal",
        "hazard",
        label,
        source_ids=list(lineage.get("hazard_ids") or scenario_hazard_ids(spec)),
        hazards=[
            {"source_id": item.hazard_id, "label": plain(item.description)}
            for item in hazards
        ],
        losses=[
            {"source_id": item.loss_id, "label": plain(item.description)}
            for item in losses
        ],
    )


def _scenario_node(spec: ScenarioSpec) -> dict[str, Any]:
    criterion = plain(selected_criterion(spec))
    adversarial = not spec.is_functional_test
    extras: dict[str, Any] = {"scenario_id": spec.scenario_id, "this_scenario": True}
    if adversarial:
        extras["attacker"] = _attacker(spec)
    conditions = _conditions_node(spec, adversarial)
    children = [conditions] if conditions["children"] else []
    steps = _steps_node(spec) if adversarial else None
    if steps is not None and steps["children"]:
        children.append(steps)
    children.extend([_unsafe_action_node(spec), _failure_node(spec, criterion)])
    return _node(
        "AT-SCN",
        "operator",
        "scenario",
        criterion,
        operator="AND",
        ordered=True,
        children=children,
        **extras,
    )


def _attacker(spec: ScenarioSpec) -> dict[str, Any]:
    adversary = spec.adversary
    attacker: dict[str, Any] = {
        "profile": (
            ADVERSARY_WORDS.get(adversary.kind.value, "an attacker")
            if adversary is not None
            else "an attacker"
        )
    }
    if adversary is not None and plain(adversary.gain):
        attacker["goal"] = plain(adversary.gain)
    attacker["plan"] = [
        plain(item) for item in spec.attacker_bdi.intentions if plain(item)
    ]
    return attacker


def _conditions_node(spec: ScenarioSpec, adversarial: bool) -> dict[str, Any]:
    children: list[dict[str, Any]] = []
    context = spec.scenario_context
    if context is not None and plain(context.ica.hazardous_context):
        children.append(
            _node(
                "AT-SIT",
                "condition",
                "situation",
                plain(context.ica.hazardous_context),
                source_id=context.ica.ica_id,
            )
        )
    if adversarial:
        assumptions = [plain(item) for item in spec.attacker_bdi.beliefs if plain(item)]
        children.extend(
            _node(f"AT-ASM-{index}", "condition", "attacker_assumption", text)
            for index, text in enumerate(assumptions, 1)
        )
    beliefs = {belief.pm_id: belief for belief in spec.defender_bdi.beliefs}
    for index, factor in enumerate(spec.causal_factors, 1):
        extras: dict[str, Any] = {"evidence_status": factor.evidence_status.value}
        belief = beliefs.get(factor.source_id)
        if factor.flawed_belief:
            extras["belief"] = weak_point_belief_text(factor)
        elif (
            is_belief_flaw(factor.kind) and belief is not None and plain(belief.content)
        ):
            # A faulty decision rule states no belief to repeat. The belief's
            # pm_id is the weak point's source_id, so the text alone keeps
            # everything.
            extras["belief"] = belief_text(
                belief.content, belief.vulnerability, {plain(factor.description)}
            )
        children.append(
            _node(
                f"AT-WP-{index}",
                "condition",
                "weak_point",
                plain(factor.description) or factor.source_id,
                source_id=factor.source_id,
                **extras,
            )
        )
    return _node(
        "AT-COND",
        "operator",
        "conditions",
        CONDITIONS_LABEL,
        operator="AND",
        children=children,
    )


def _steps_node(spec: ScenarioSpec) -> dict[str, Any]:
    shape = spec.attack_shape or default_attack_shape(None)
    steps = attack_steps(shape)
    children = []
    for index, step in enumerate(steps, 1):
        extras: dict[str, Any] = {}
        if step.technique is not None:
            extras["technique_id"], extras["technique"] = step.technique
        # attack_steps puts the plant step first for an indirect shape.
        if index == 1 and shape.indirect is not None:
            extras["asset"] = shape.indirect.carrier_operation
        children.append(
            _node(f"AT-STEP-{index}", "action", "attack_step", step.text, **extras)
        )
    return _node(
        "AT-STEPS",
        "operator",
        "attack_steps",
        STEPS_LABEL,
        operator="AND",
        ordered=True,
        children=children,
    )


def _unsafe_action_node(spec: ScenarioSpec) -> dict[str, Any]:
    context = spec.scenario_context
    if context is None:
        return _node(
            "AT-UCA",
            "action",
            "unsafe_action",
            plain(spec.loss_scenario),
            source_ids=[spec.target_controller, spec.target_control_action],
        )
    path = context.target_control_path
    return _node(
        "AT-UCA",
        "action",
        "unsafe_action",
        plain(context.ica.exact_ica_text),
        source_ids=[path.controller.element_id, path.control_action.action_id],
        violates=[
            {"source_id": item.constraint_id, "label": rule_text(item.description)}
            for item in context.constraints
        ],
    )


def _failure_node(spec: ScenarioSpec, criterion: str) -> dict[str, Any]:
    extras: dict[str, Any] = {}
    outcome = spec.safe_observable_outcome
    if outcome is not None and plain(outcome.statement):
        extras["safe_outcome"] = plain(outcome.statement)
    return _node("AT-FAIL", "condition", "observable_failure", criterion, **extras)


def _reference_nodes(
    spec: ScenarioSpec, siblings: SiblingIndex
) -> list[dict[str, Any]]:
    # A reference names the other scenario by id only, so no other
    # scenario's text appears in this scenario's handoff.
    others = {
        scenario_id
        for hazard_id in scenario_hazard_ids(spec)
        for scenario_id in siblings.get(hazard_id, ())
        if scenario_id != spec.scenario_id
    }
    return [
        _node(
            f"AT-ALT-{index}",
            "reference",
            "other_scenario",
            scenario_id,
            scenario_id=scenario_id,
        )
        for index, scenario_id in enumerate(sorted(others), 1)
    ]


def _node(
    node_id: str,
    node_type: str,
    category: str,
    label: str,
    *,
    operator: str | None = None,
    ordered: bool = False,
    source_id: str | None = None,
    source_ids: list[str] | None = None,
    children: list[dict[str, Any]] | None = None,
    **extras: Any,
) -> dict[str, Any]:
    node: dict[str, Any] = {"node_id": node_id, "type": node_type}
    if operator is not None:
        node["operator"] = operator
        if ordered:
            node["ordered"] = True
    node.update(
        {"category": category, "label": label, "authority": HYPOTHESIS_AUTHORITY}
    )
    if source_id:
        node["source_id"] = source_id
    if source_ids:
        node["source_ids"] = list(dict.fromkeys(source_ids))
    node.update(extras)
    if children is not None:
        node["children"] = children
    return node
