"""Leaf technique provenance and blank-leaf validation."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from asago_scenario_generator.models.attack_tree import AttackTreeNode
from asago_scenario_generator.pipeline.validation_common import _collect_leaves

if TYPE_CHECKING:
    from asago_scenario_generator.models.scenario import ScenarioEnvelope

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Leaf technique provenance — data structures
# ---------------------------------------------------------------------------


@dataclass
class LeafTechniqueViolation:
    """Scenario-level provenance mismatch for leaf technique validation."""

    node_id: str
    label: str
    zone: str
    reason: str


@dataclass
class LeafTechniqueResult:
    """Result of leaf technique provenance validation across a batch."""

    clean_scenarios: list[ScenarioEnvelope] = field(default_factory=list)
    flagged_scenarios: list[tuple[ScenarioEnvelope, list[LeafTechniqueViolation]]] = (
        field(default_factory=list)
    )

    @property
    def flagged_count(self) -> int:
        return len(self.flagged_scenarios)

    @property
    def clean_count(self) -> int:
        return len(self.clean_scenarios)


# ---------------------------------------------------------------------------
# Leaf technique provenance — consequence heuristic
# ---------------------------------------------------------------------------

# Consequence / terminal-outcome patterns.  A leaf whose label (or
# description) matches one of these is a *consequence node* — it
# describes what happens as a result of the attack, not an active
# attack step.  Consequence nodes are exempt from the technique_id
# requirement.

_CONSEQUENCE_LEAF_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        # Victim / target performing an action as a result of manipulation
        r"\bvictim\s+\w+",
        (
            r"\btarget\s+(?:user|employee|operator|person|individual)\s+"
            r"(?:transfer|send|comply|reveal|disclose|provide|submit)\w*"
        ),
        # Data / asset terminal-outcome language
        (
            r"\b(?:data|credentials?|information|secrets?|funds?|assets?|money)"
            r"\s+(?:exfiltrated|stolen|harvested|captured|diverted|"
            r"compromised|lost|leaked|extracted|obtained)\b"
        ),
        # Exfiltration as terminal step
        r"\b(?:exfiltrate|siphon)\s",
        # Attack / breach completion
        (
            r"\b(?:attack|breach|compromise|infiltration|campaign|objective)"
            r"\s+(?:succeed|complet|achiev|accomplish|finalize)\w*"
        ),
        # Impact / damage realization
        (
            r"\b(?:impact|damage|loss|harm)"
            r"\s+(?:realiz|materializ|inflict|occur)\w*"
        ),
        # Goal achievement (allow intervening words)
        (
            r"\b(?:achieve|accomplish)\w*\b"
            r"[^.]{0,30}\b(?:goal|objective|purpose|aim)\b"
        ),
        # System state as terminal outcome
        (
            r"\b(?:system|account|network|infrastructure)"
            r"\s+(?:fully\s+)?(?:compromised|breached|corrupted|infected)\b"
        ),
        # Access gained as terminal outcome
        (
            r"\b(?:gain|obtain|establish|secure)\w*"
            r"\s+(?:persistent|unauthorized|full|complete|admin|root)\s+access\b"
        ),
    ]
]


def _is_consequence_leaf(node: AttackTreeNode) -> bool:
    """Heuristic: is this leaf a terminal consequence / effect node?

    Consequence nodes describe outcomes or effects (e.g. "victim
    transfers funds", "data exfiltrated") rather than active attack
    steps.  They are exempt from the ``technique_id`` requirement
    because they are not technique-driven actions.
    """
    if node.action is not None:
        return node.action.kind == "impact"

    text = node.label
    if node.description:
        text = f"{text} {node.description}"

    for pattern in _CONSEQUENCE_LEAF_PATTERNS:
        if pattern.search(text):
            return True
    return False


# ---------------------------------------------------------------------------
# Leaf technique provenance — main validation
# ---------------------------------------------------------------------------


def _leaf_mapping_reason(
    leaf: AttackTreeNode, exact_ids_by_step: dict[str, frozenset[str]]
) -> str | None:
    """Reason a leaf technique mismatches its represented projected steps."""
    if leaf.technique_id is None:
        return None
    if not leaf.projected_step_ids:
        return (
            f"Leaf '{leaf.id}' carries '{leaf.technique_id}' without "
            "projected-step IDs."
        )
    incompatible = [
        step_id
        for step_id in leaf.projected_step_ids
        if leaf.technique_id not in exact_ids_by_step.get(step_id, frozenset())
    ]
    if incompatible:
        return (
            f"Leaf '{leaf.id}' technique '{leaf.technique_id}' is not an "
            f"exact mapping of projected steps {incompatible}."
        )
    return None


def _leaf_provenance_reasons(
    leaves: list[AttackTreeNode], exact_ids_by_step: dict[str, frozenset[str]]
) -> list[str]:
    """Per-leaf provenance mismatch reasons for one scenario."""
    reasons: list[str] = []
    for leaf in leaves:
        reason = _leaf_mapping_reason(leaf, exact_ids_by_step)
        if reason is not None:
            reasons.append(reason)
    return reasons


def _provenance_violation(
    scenario: ScenarioEnvelope, reasons: list[str]
) -> LeafTechniqueViolation:
    """Scenario-level violation record for provenance mismatches."""
    root = scenario.attack_tree.root
    return LeafTechniqueViolation(
        node_id=root.id,
        label=root.label,
        zone=root.zone,
        reason=" ".join(reasons),
    )


def check_leaf_technique_provenance(
    scenarios: list[ScenarioEnvelope],
) -> LeafTechniqueResult:
    """Check non-null leaf techniques against exact projected-step mappings.

    Scenario classifications are intentionally irrelevant to this gate. A
    legacy envelope without explicit technique-scope evidence remains readable
    and is not subjected to a per-leaf association it never published.
    """
    from asago_scenario_generator.pipeline.technique_scopes import (
        projected_step_mapping_ids_by_step,
    )

    result = LeafTechniqueResult()

    for scenario in scenarios:
        if scenario.technique_scope_evidence is None:
            result.clean_scenarios.append(scenario)
            continue

        leaves = _collect_leaves(scenario.attack_tree.root)
        exact_ids_by_step = projected_step_mapping_ids_by_step(scenario.projection)
        reasons = _leaf_provenance_reasons(leaves, exact_ids_by_step)

        if not reasons:
            result.clean_scenarios.append(scenario)
        else:
            result.flagged_scenarios.append(
                (scenario, [_provenance_violation(scenario, reasons)])
            )

    return result


# Blank-leaf validation — structural safety net
# ---------------------------------------------------------------------------


@dataclass
class BlankLeafViolation:
    """A leaf node missing a ``technique_id`` annotation."""

    node_id: str
    label: str
    zone: str


@dataclass
class BlankLeafResult:
    """Result of blank-leaf validation across a batch of scenarios."""

    clean_scenarios: list[ScenarioEnvelope] = field(default_factory=list)
    flagged_scenarios: list[tuple[ScenarioEnvelope, list[BlankLeafViolation]]] = field(
        default_factory=list
    )

    @property
    def flagged_count(self) -> int:
        return len(self.flagged_scenarios)

    @property
    def clean_count(self) -> int:
        return len(self.clean_scenarios)


def validate_blank_leaves(
    scenarios: list[ScenarioEnvelope],
) -> BlankLeafResult:
    """Flag leaf nodes that lack a ``technique_id`` annotation.

    This is a structural safety net behind the prompt-level technique
    annotation floor.  It walks each scenario's attack tree and checks
    that every LEAF node (``gate == LEAF`` or no children) has a
    non-empty ``technique_id``.  AND/OR gate (structural connector)
    nodes are not checked.

    Returns a :class:`BlankLeafResult` with clean and flagged scenarios.
    """
    result = BlankLeafResult()

    for scenario in scenarios:
        violations: list[BlankLeafViolation] = []
        leaves = _collect_leaves(scenario.attack_tree.root)

        for leaf in leaves:
            if not leaf.technique_id:
                violations.append(
                    BlankLeafViolation(
                        node_id=leaf.id,
                        label=leaf.label,
                        zone=leaf.zone,
                    )
                )

        if violations:
            node_ids = [v.node_id for v in violations]
            logger.warning(
                "Scenario %s has %d leaf node(s) without technique_id: %s",
                scenario.scenario_id,
                len(violations),
                ", ".join(node_ids),
            )
            result.flagged_scenarios.append((scenario, violations))
        else:
            result.clean_scenarios.append(scenario)

    return result
