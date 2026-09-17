"""Deterministic publication of one semantic scenario account.

Normal publication consumes only the selected scenario meaning and the exact
evidence carried by :class:`ScenarioSpec`.  The producer describes a proposed
causal hypothesis; the consumer still owns messages, delivery, setup,
detectors, and execution.  Narrative, tree, and Gherkin are projections of
the same local account rather than independent summaries.
"""

from __future__ import annotations

from collections.abc import Iterable
import re
from typing import Any

from asago_scenario_generator.stpa.models.causal_factor import CausalFactor
from asago_scenario_generator.stpa.models.scenario_envelope import (
    GherkinSpec,
    ScenarioEnvelope,
)
from asago_scenario_generator.stpa.models.scenario_spec import (
    AttackerBDI,
    DefenderBDI,
    ScenarioSpec,
)

TREE_FRAMING = (
    "Proposed causal hypothesis. No node below is an observed execution result, "
    "and no node restates an executable check as its own cause."
)
HYPOTHESIS_AUTHORITY = "proposed_hypothesis"
CRITERION_AUTHORITY = "selected_semantic_proposition"
FLAT_RELATION = "flat"
_STRUCTURAL_ID_PATTERN = re.compile(r"\b(?:PM|FB|CA)-\d+-\d+\b|\b(?:RESP|CL|CM)-\d+\b")


def render_scenario_summary(spec: ScenarioSpec) -> tuple[str, dict, GherkinSpec]:
    """Render one connected semantic account without artifact design.

    The returned representations share the selected proposition, exact
    structural source references, and hypothesis authority.  Missing typed
    conjunction or alternative evidence remains flat; a list of factors does
    not establish an AND or OR relation.
    """
    account = _semantic_account(spec)
    narrative = _render_narrative(account)
    tree = _render_tree(account)
    gherkin = _render_gherkin(account)
    return narrative, tree, gherkin


def validate_scenario_summary(envelope: ScenarioEnvelope) -> list[str]:
    """Verify deterministic presentation against its exact scenario authority."""
    narrative, tree, gherkin = render_scenario_summary(envelope.scenario_spec)
    expected = {
        "narrative": narrative,
        "attack_tree": tree,
        "gherkin_spec": gherkin,
        "gherkin_raw": gherkin.to_feature_text(),
    }
    return [
        f"{envelope.scenario_id} deterministic {name} differs from its source summary."
        for name, value in expected.items()
        if getattr(envelope, name) != value
    ]


def _semantic_account(spec: ScenarioSpec) -> dict[str, Any]:
    """Resolve the small canonical account shared by all renderings."""
    context = spec.scenario_context
    criterion = _selected_criterion(spec)
    kind = "functional" if spec.is_functional_test else "adversarial"
    action = (
        context.target_control_path.control_action
        if context is not None
        else {
            "action_id": spec.target_control_action,
            "description": "Selected control action",
        }
    )
    return {
        "scenario_id": spec.scenario_id,
        "kind": kind,
        "criterion": criterion,
        "context": context,
        "attacker": None if kind == "functional" else spec.attacker_bdi,
        "adversary": None if kind == "functional" else spec.adversary,
        "defender": spec.defender_bdi,
        "factors": tuple(spec.causal_factors),
        "action": action,
        "trigger": _domain_trigger(spec, context, action, criterion),
        "loss_scenario": spec.loss_scenario,
        "lineage": _lineage(spec),
        "relation": FLAT_RELATION,
    }


def _selected_criterion(spec: ScenarioSpec) -> str:
    """Prefer the authored proposition over the broad ICA fallback."""
    proposition = spec.unsafe_outcome_semantic_proposition
    if proposition is not None and proposition.strip():
        return proposition.strip()
    if spec.scenario_context is not None:
        return spec.scenario_context.ica.exact_ica_text
    return spec.loss_scenario


def _domain_trigger(
    spec: ScenarioSpec,
    context: Any,
    action: Any,
    criterion: str,
) -> str:
    """Render one domain trigger from the selected semantic account.

    The trigger stays semantics-only: it names the domain action that the
    selected proposition examines, without supplying a user message,
    payload, delivery route, or detector.  Contextual Stage 5 propositions
    carry the domain vocabulary needed here; legacy scenarios fall back to
    their selected action description.
    """
    source_text = " ".join(
        value
        for value in (
            criterion,
            getattr(getattr(context, "ica", None), "unsafe_action", ""),
            getattr(getattr(context, "ica", None), "exact_ica_text", ""),
            getattr(getattr(context, "ica", None), "hazardous_context", ""),
            _action_description(action),
        )
        if isinstance(value, str)
    ).lower()
    for terms, trigger in (
        (
            ("refund", "refund command", "process_refund"),
            "When the customer requests a refund for the selected order",
        ),
        (
            ("clinical", "ehr", "electronic health record", "commit_to_ehr"),
            "When the clinician requests that the clinical record be committed to the EHR",
        ),
        (
            ("booking", "reservation", "modify_booking"),
            "When the actor requests authorization to modify the selected booking",
        ),
    ):
        if _contains_any(source_text, terms):
            return trigger
    return f"When the actor requests {_action_description(action).rstrip('.')}"


def _contains_any(value: str, terms: tuple[str, ...]) -> bool:
    """Return whether semantic source text contains one domain term."""
    return any(term in value for term in terms)


def _action_description(action: Any) -> str:
    """Return the selected action description from either supported shape."""
    if isinstance(action, dict):
        return action.get("description", "the selected control action")
    return action.description


def _lineage(spec: ScenarioSpec) -> dict[str, Any]:
    """Return exact selected identities without adding a handoff field."""
    context = spec.scenario_context
    if context is None:
        return {
            "scenario_id": spec.scenario_id,
            "ica_slot_id": spec.threat_source.ica_slot_id,
            "ica_id": spec.threat_source.ica_id,
            "controller_id": spec.target_controller,
            "control_action_id": spec.target_control_action,
            "hazard_ids": list(spec.unsafe_outcome_hazard_refs),
            "constraint_ids": list(spec.unsafe_outcome_constraint_refs),
            "loss_ids": [],
        }
    return {
        "scenario_id": context.scenario_identity.scenario_id,
        "ica_slot_id": context.scenario_identity.ica_slot_id,
        "ica_id": context.scenario_identity.ica_id,
        "controller_id": context.target_control_path.controller.element_id,
        "control_action_id": context.target_control_path.control_action.action_id,
        "hazard_ids": [item.hazard_id for item in context.hazards],
        "constraint_ids": [item.constraint_id for item in context.constraints],
        "loss_ids": [item.loss_id for item in context.losses],
    }


def _render_narrative(account: dict[str, Any]) -> str:
    """Render the connected account in source-labelled prose."""
    context = account["context"]
    lines = [
        "Test hypothesis — not an observed execution result.",
        f"Scenario kind: {account['kind']}.",
        (
            "Selected semantic failure criterion "
            f"(source: ScenarioSpec.unsafe_outcome_semantic_proposition; "
            f"authority: {CRITERION_AUTHORITY}): {account['criterion']}"
        ),
        "Connected causal account (every claim is a proposed hypothesis):",
    ]
    lines.extend(_context_lines(context))
    lines.extend(_actor_lines(account["attacker"], account["adversary"]))
    lines.extend(_defender_lines(account["defender"]))
    lines.extend(_factor_lines(account["factors"]))
    lines.extend(_lineage_lines(context, account["action"]))
    lines.extend(
        [
            (
                "- Loss scenario statement (source: ScenarioSpec.loss_scenario; "
                f"authority: {HYPOTHESIS_AUTHORITY}): {account['loss_scenario']}"
            ),
            "Causal relations: flat. No typed conjunction or alternative evidence "
            "was supplied, so the renderer does not infer AND or OR.",
            "The account remains semantics-only: it prescribes no message, "
            "delivery, detector, setup, or executable check.",
        ]
    )
    return "\n".join(lines)


def _context_lines(context: Any) -> list[str]:
    """Render the selected hazardous context with its exact source."""
    if context is None:
        return ["- Established context: not supplied."]
    return [
        (
            "- Established context "
            f"(source: {context.ica.ica_id}; authority: selected ICA): "
            f"{context.ica.hazardous_context}"
        )
    ]


def _actor_lines(attacker: AttackerBDI | None, adversary: Any) -> list[str]:
    """Render supported actor evidence only for adversarial scenarios."""
    if attacker is None:
        return [
            "- No actor objective, knowledge, or strategy is asserted for this "
            "functional scenario."
        ]
    lines = ["- Supported actor evidence (hypothesized, not an authored message):"]
    if adversary is not None:
        lines.append(
            f"  - Objective (source: scenario_spec.adversary.gain; "
            f"kind: {adversary.kind.value}): {adversary.gain}"
        )
    lines.extend(
        _text_evidence_lines(
            "Knowledge",
            attacker.beliefs,
            "scenario_spec.attacker_bdi.beliefs",
        )
    )
    lines.extend(
        _text_evidence_lines(
            "Semantic approach",
            attacker.desires,
            "scenario_spec.attacker_bdi.desires",
        )
    )
    lines.extend(
        _text_evidence_lines(
            "Strategy",
            attacker.intentions,
            "scenario_spec.attacker_bdi.intentions",
        )
    )
    return lines


def _text_evidence_lines(
    label: str, values: Iterable[str], source_path: str
) -> list[str]:
    """Render free-form BDI evidence with an exact field path."""
    return [
        f"  - {label} (source: {source_path}[{index}]; authority: "
        f"{HYPOTHESIS_AUTHORITY}): {value}"
        for index, value in enumerate(values)
        if value.strip()
    ]


def _defender_lines(defender: DefenderBDI) -> list[str]:
    """Render grounded defender BDI and preserve hypothesis status."""
    lines = ["- Defender control-loop hypothesis:"]
    for belief in defender.beliefs:
        detail = f"{belief.content}"
        if belief.vulnerability.strip():
            detail += f" Vulnerability: {belief.vulnerability}"
        lines.append(
            f"  - Belief (source: {belief.pm_id}; authority: "
            f"{HYPOTHESIS_AUTHORITY}): {detail}"
        )
    for desire in defender.desires:
        source = desire.resp_id
        if desire.constraint_id is not None:
            source += f", {desire.constraint_id}"
        lines.append(
            f"  - Desire (source: {source}; authority: "
            f"{HYPOTHESIS_AUTHORITY}): {desire.content}"
        )
    for intention in defender.intentions:
        lines.append(
            f"  - Intention (source: {intention.ca_id}; authority: "
            f"{HYPOTHESIS_AUTHORITY}): {intention.content}"
        )
    return lines


def _factor_lines(factors: Iterable[CausalFactor]) -> list[str]:
    """Render declared causal evidence without upgrading its authority."""
    factors = tuple(factors)
    lines = ["- Semantic causal approach:"]
    for factor in factors:
        lines.append(
            f"  - Factor (source: {factor.source_id}; kind: {factor.kind.value}; "
            f"evidence: {factor.evidence_status.value}; authority: "
            f"{HYPOTHESIS_AUTHORITY}): {factor.description}"
        )
    if not tuple(factors):
        lines.append("  - No declared causal factor evidence.")
    return lines


def _lineage_lines(context: Any, action: Any) -> list[str]:
    """Render action, hazard, constraint, and loss in causal order."""
    if context is None:
        return [
            (
                f"- Unsafe action (source: {action['action_id']}; authority: "
                f"{HYPOTHESIS_AUTHORITY}): {action['description']}"
            )
        ]
    lines = [
        (
            f"- Unsafe action (source: {action.action_id}; authority: "
            f"{HYPOTHESIS_AUTHORITY}): {action.description}"
        )
    ]
    for constraint in context.constraints:
        lines.append(
            f"- Governing constraint (source: {constraint.constraint_id}; "
            f"authority: supplied structural evidence): {constraint.description}"
        )
    for hazard in context.hazards:
        lines.append(
            f"- Hazard (source: {hazard.hazard_id}; authority: supplied "
            f"structural evidence; reaches losses {', '.join(hazard.related_loss_ids)}): "
            f"{hazard.description}"
        )
    for loss in context.losses:
        lines.append(
            f"- Potential loss (source: {loss.loss_id}; authority: supplied "
            f"structural evidence): {loss.description}"
        )
    return lines


def _render_tree(account: dict[str, Any]) -> dict[str, Any]:
    """Render exact evidence nodes while keeping unsupported relations flat."""
    context = account["context"]
    defender = account["defender"]
    path_children = [
        _factor_node(index, factor)
        for index, factor in enumerate(account["factors"], 1)
    ]
    path_children.extend(
        _actor_nodes(account["attacker"], _allowed_tree_sources(account))
    )
    controller_children = _defender_nodes(defender)
    controller_children.extend(_lineage_nodes(context, account["action"]))
    tree = {
        "framing": TREE_FRAMING,
        "kind": account["kind"],
        "criterion": account["criterion"],
        "criterion_authority": CRITERION_AUTHORITY,
        "relation": account["relation"],
        "relation_evidence": "typed_relation_not_supplied",
        "lineage": account["lineage"],
        "loss_scenario": account["loss_scenario"],
        "root": account["criterion"],
        "root_authority": HYPOTHESIS_AUTHORITY,
        "branches": [
            {
                "node_id": "AT-CONTROLLER",
                "category": "controller_side",
                "label": "Defender and structural causality",
                "source_path": "scenario_spec.defender_bdi",
                "authority": HYPOTHESIS_AUTHORITY,
                "relation": account["relation"],
                "children": controller_children,
            },
            {
                "node_id": "AT-PATH",
                "category": "path_side",
                "label": "Supported semantic approach",
                "source_path": "scenario_spec.causal_factors",
                "authority": HYPOTHESIS_AUTHORITY,
                "relation": account["relation"],
                "children": path_children,
            },
        ],
        "leaves": [
            f"{factor.source_id}: {factor.description}" for factor in account["factors"]
        ],
        "leaf_authority": HYPOTHESIS_AUTHORITY,
    }
    if _sanitize_tree_text(tree, _allowed_tree_sources(account)):
        tree["source_uncertainty"] = (
            "Free-form text named a structural source outside the selected "
            "causal path; that source was not treated as tree evidence."
        )
    return tree


def _defender_nodes(defender: DefenderBDI) -> list[dict[str, Any]]:
    """Build source-grounded defender nodes."""
    nodes: list[dict[str, Any]] = []
    for index, belief in enumerate(defender.beliefs, 1):
        nodes.append(
            _node(
                f"AT-DB-{index}",
                "defender_belief",
                belief.content,
                source_id=belief.pm_id,
                source_path=f"scenario_spec.defender_bdi.beliefs[{index - 1}]",
            )
        )
    for index, desire in enumerate(defender.desires, 1):
        source_ids = [desire.resp_id]
        if desire.constraint_id is not None:
            source_ids.append(desire.constraint_id)
        nodes.append(
            _node(
                f"AT-DD-{index}",
                "defender_desire",
                desire.content,
                source_id=desire.resp_id,
                source_path=f"scenario_spec.defender_bdi.desires[{index - 1}]",
                source_ids=source_ids,
            )
        )
    for index, intention in enumerate(defender.intentions, 1):
        nodes.append(
            _node(
                f"AT-DI-{index}",
                "defender_intention",
                intention.content,
                source_id=intention.ca_id,
                source_path=(f"scenario_spec.defender_bdi.intentions[{index - 1}]"),
            )
        )
    return nodes


def _allowed_tree_sources(account: dict[str, Any]) -> set[str]:
    """Return exact structural sources that the tree is allowed to explain."""
    allowed = _lineage_tree_sources(account["lineage"])
    allowed.update(factor.source_id for factor in account["factors"])
    allowed.update(_defender_tree_sources(account["defender"]))
    context = account["context"]
    if context is not None:
        allowed.update(_context_tree_sources(context))
    return allowed


def _lineage_tree_sources(lineage: dict[str, Any]) -> set[str]:
    """Collect exact IDs from the selected lineage."""
    return {
        lineage["controller_id"],
        lineage["control_action_id"],
        *lineage["hazard_ids"],
        *lineage["constraint_ids"],
        *lineage["loss_ids"],
    }


def _defender_tree_sources(defender: DefenderBDI) -> set[str]:
    """Collect exact IDs grounded by defender BDI."""
    return {
        *[belief.pm_id for belief in defender.beliefs],
        *[desire.resp_id for desire in defender.desires],
        *[
            desire.constraint_id
            for desire in defender.desires
            if desire.constraint_id is not None
        ],
        *[intention.ca_id for intention in defender.intentions],
    }


def _context_tree_sources(context: Any) -> set[str]:
    """Collect exact IDs from the selected control path."""
    path = context.target_control_path
    allowed = {
        *(item.element_id for item in path.process_model_parts),
        *(item.element_id for item in path.feedback),
        *(item.action_id for item in path.related_control_actions),
    }
    if path.responsibility is not None:
        allowed.add(path.responsibility.element_id)
    if path.coordination_path is not None:
        coordination = path.coordination_path
        allowed.update(
            {
                coordination.link_id,
                coordination.source.element_id,
                coordination.target.element_id,
                coordination.shared_process_model.element_id,
                coordination.coordination_mechanism.element_id,
            }
        )
    return allowed


def _actor_nodes(
    attacker: AttackerBDI | None, allowed_sources: set[str]
) -> list[dict[str, Any]]:
    """Build actor nodes only when the scenario has actor evidence."""
    if attacker is None:
        return []
    nodes: list[dict[str, Any]] = []
    for category, values, path_prefix in (
        ("actor_belief", attacker.beliefs, "beliefs"),
        ("actor_desire", attacker.desires, "desires"),
        ("actor_intention", attacker.intentions, "intentions"),
    ):
        for index, value in enumerate(values):
            if value.strip():
                rendered_label, unknown_sources = _tree_actor_label(
                    value, allowed_sources
                )
                node = _node(
                    f"AT-A-{category}-{index + 1}",
                    category,
                    value,
                    source_path=f"scenario_spec.attacker_bdi.{path_prefix}[{index}]",
                )
                if unknown_sources:
                    node["label"] = rendered_label
                    node["source_uncertainty"] = (
                        "unsupported structural source omitted from tree label"
                    )
                nodes.append(node)
    return nodes


def _tree_actor_label(value: str, allowed_sources: set[str]) -> tuple[str, list[str]]:
    """Keep unsupported actor references explicit without poisoning tree joins."""
    unsupported = _unsupported_tree_sources(value, allowed_sources)
    return _replace_tree_sources(value, unsupported), unsupported


def _sanitize_tree_text(value: Any, allowed_sources: set[str]) -> bool:
    """Keep unsupported free-text IDs from becoming tree evidence."""
    if isinstance(value, dict):
        return _sanitize_tree_mapping(value, allowed_sources)
    if isinstance(value, list):
        return _sanitize_tree_sequence(value, allowed_sources)
    return False


def _sanitize_tree_mapping(value: dict[str, Any], allowed_sources: set[str]) -> bool:
    """Sanitize map values while preserving structural source fields."""
    items = (
        (key, item)
        for key, item in value.items()
        if key not in {"source_id", "source_ids", "source_path", "node_id"}
    )
    return _sanitize_tree_items(value, items, allowed_sources)


def _sanitize_tree_sequence(value: list[Any], allowed_sources: set[str]) -> bool:
    """Sanitize sequence values while preserving their ordering."""
    return _sanitize_tree_items(value, enumerate(value), allowed_sources)


def _sanitize_tree_items(
    container: dict[str, Any] | list[Any],
    items: Iterable[tuple[str | int, Any]],
    allowed_sources: set[str],
) -> bool:
    """Sanitize each selected child of a tree container."""
    changed = False
    for key, item in items:
        changed |= _sanitize_tree_value(container, key, item, allowed_sources)
    return changed


def _sanitize_tree_value(
    container: dict[str, Any] | list[Any],
    key: str | int,
    value: Any,
    allowed_sources: set[str],
) -> bool:
    """Sanitize one nested tree value."""
    if isinstance(value, str):
        sanitized, replacements = _tree_text(value, allowed_sources)
        if replacements:
            container[key] = sanitized
            return True
        return False
    return _sanitize_tree_text(value, allowed_sources)


def _tree_text(value: str, allowed_sources: set[str]) -> tuple[str, list[str]]:
    """Replace unsupported structural IDs in free-form tree text."""
    unsupported = _unsupported_tree_sources(value, allowed_sources)
    return _replace_tree_sources(value, unsupported), unsupported


def _unsupported_tree_sources(value: str, allowed_sources: set[str]) -> list[str]:
    """Find structural IDs that are not exact supported evidence."""
    return sorted(
        {
            match.group(0)
            for match in _STRUCTURAL_ID_PATTERN.finditer(value)
            if match.group(0) not in allowed_sources
        }
    )


def _replace_tree_sources(value: str, source_ids: Iterable[str]) -> str:
    """Replace unsupported structural IDs without changing other prose."""
    for source_id in source_ids:
        value = value.replace(source_id, "[unsupported source omitted]")
    return value


def _factor_node(index: int, factor: CausalFactor) -> dict[str, Any]:
    """Build one exact causal-factor node."""
    return _node(
        f"AT-CF-{index}",
        "causal_factor",
        factor.description,
        source_id=factor.source_id,
        source_path=f"scenario_spec.causal_factors[{index - 1}]",
        evidence_status=factor.evidence_status.value,
    )


def _lineage_nodes(context: Any, action: Any) -> list[dict[str, Any]]:
    """Build exact action-to-loss lineage nodes."""
    if context is None:
        return [
            _node(
                "AT-ACTION",
                "unsafe_action",
                action["description"],
                source_id=action["action_id"],
                source_path="scenario_spec.target_control_action",
            )
        ]
    nodes = [
        _node(
            "AT-ACTION",
            "unsafe_action",
            action.description,
            source_id=action.action_id,
            source_path="scenario_context.target_control_path.control_action",
        )
    ]
    nodes.extend(
        _node(
            f"AT-CONSTRAINT-{index}",
            "constraint",
            item.description,
            source_id=item.constraint_id,
            source_path=f"scenario_context.constraints[{index - 1}]",
            source_ids=[item.constraint_id, *item.related_hazard_ids],
        )
        for index, item in enumerate(context.constraints, 1)
    )
    nodes.extend(
        _node(
            f"AT-HAZARD-{index}",
            "hazard",
            item.description,
            source_id=item.hazard_id,
            source_path=f"scenario_context.hazards[{index - 1}]",
            source_ids=[item.hazard_id, *item.related_loss_ids],
        )
        for index, item in enumerate(context.hazards, 1)
    )
    nodes.extend(
        _node(
            f"AT-LOSS-{index}",
            "loss",
            item.description,
            source_id=item.loss_id,
            source_path=f"scenario_context.losses[{index - 1}]",
        )
        for index, item in enumerate(context.losses, 1)
    )
    return nodes


def _node(
    node_id: str,
    category: str,
    label: str,
    *,
    source_path: str,
    source_id: str | None = None,
    source_ids: list[str] | None = None,
    evidence_status: str | None = None,
) -> dict[str, Any]:
    """Return one uniformly marked hypothesis node."""
    node: dict[str, Any] = {
        "node_id": node_id,
        "category": category,
        "label": label,
        "source_path": source_path,
        "authority": HYPOTHESIS_AUTHORITY,
        "relation": FLAT_RELATION,
        "children": [],
    }
    if source_id:
        node["source_id"] = source_id
    if source_ids:
        node["source_ids"] = source_ids
    if evidence_status is not None:
        node["evidence_status"] = evidence_status
    return node


def _render_gherkin(account: dict[str, Any]) -> GherkinSpec:
    """Render declarative steps from the same account used by narrative/tree."""
    context = account["context"]
    given = _gherkin_given(context, account["defender"])
    if context is None:
        when = [account["trigger"]]
        expected = ["Then the system should preserve the selected safe behavior"]
    else:
        when = [account["trigger"]]
        expected = [
            (
                f"Then the system should preserve {item.constraint_id}: "
                f"{_concise_constraint(item.description)}"
            )
            for item in context.constraints
        ] or ["Then the system should preserve the selected safe behavior"]
    return GherkinSpec(
        feature=f"Selected semantic behavior for {account['scenario_id']}",
        scenario=account["criterion"],
        given=given,
        when=when,
        then_expected=expected,
        then_actual=[
            f"But the hypothesized unsafe alternative is: {account['criterion']}"
        ],
    )


def _concise_constraint(description: str) -> str:
    """Keep expected steps readable without dropping rule identity.

    Applicability prose remains in the governing-rule metadata.  The
    executable-looking declarative step states only the safe behavior that
    the selected constraint requires.
    """
    statement = description.strip()
    statement = re.split(r"\bapplies when\s*:", statement, flags=re.I)[0].strip(" .")
    if len(statement) <= 200:
        return statement
    first_sentence = re.split(r"(?<=[.!?])\s+", statement)[0]
    return first_sentence[:200].rstrip()


def _gherkin_given(context: Any, defender: DefenderBDI) -> list[str]:
    """Render relevant structural preconditions without inventing observations."""
    if context is None:
        return [
            f"Given the proposed process-model hypothesis references {belief.pm_id}"
            for belief in defender.beliefs
        ] or ["Given the proposed control context is supplied"]
    if context.target_control_path.process_model_parts:
        return [
            (
                f"Given the proposed process-model precondition {item.element_id} "
                f"({item.description}) is a hypothesis"
            )
            for item in context.target_control_path.process_model_parts
        ]
    return ["Given the proposed control context is supplied"]
