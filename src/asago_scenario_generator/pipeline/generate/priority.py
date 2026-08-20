"""Heuristic scoring and priority computation for scenario envelopes."""

from __future__ import annotations

from asago_scenario_generator.models.attack_tree import AttackTree, AttackTreeNode
from asago_scenario_generator.models.scenario import (
    ArchitectureMatch,
    AttackComplexity,
    NarrativeLayer,
    Priority,
    PrioritySignals,
    SeverityLevel,
    StructuralExposureSignal,
    TechniqueMaturity,
)
from asago_scenario_generator.pipeline.generate.zones import active_narrative_zones
from asago_scenario_generator.pipeline.seeds import ScenarioSeed


def _extract_maestro_layers_from_tree(node: AttackTreeNode) -> set[int]:
    layers: set[int] = set()
    if node.maestro_layer is not None:
        layers.add(node.maestro_layer)
    if node.children:
        for child in node.children:
            layers.update(_extract_maestro_layers_from_tree(child))
    return layers


def _extract_structural_exposures_from_tree(
    node: AttackTreeNode,
) -> set[str]:
    exposures: set[str] = set()
    if node.structural_exposure is not None:
        exposures.add(node.structural_exposure.value)
    if node.children:
        for child in node.children:
            exposures.update(_extract_structural_exposures_from_tree(child))
    return exposures


def _tree_depth(node: AttackTreeNode, current: int = 1) -> int:
    """Return the maximum depth of an attack tree from a given node."""
    if not node.children:
        return current
    return max(_tree_depth(child, current + 1) for child in node.children)


def _tree_node_count(node: AttackTreeNode) -> int:
    """Return the total number of nodes in an attack tree."""
    count = 1
    if node.children:
        for child in node.children:
            count += _tree_node_count(child)
    return count


def _heuristic_technique_maturity(attack_tree: AttackTree | None) -> TechniqueMaturity:
    """Derive technique maturity from attack tree depth."""
    if attack_tree is None:
        return TechniqueMaturity.feasible
    depth = _tree_depth(attack_tree.root)
    if depth >= 4:
        return TechniqueMaturity.demonstrated
    if depth == 3:
        return TechniqueMaturity.feasible
    # depth 1-2: use "feasible" as lowest available enum value
    # (TechniqueMaturity.theoretical will be available once the models worker
    # adds it; until then, feasible is the conservative fallback)
    try:
        return TechniqueMaturity("theoretical")
    except ValueError:
        return TechniqueMaturity.feasible


def _heuristic_risk_impact(
    seed: ScenarioSeed,
    narrative: NarrativeLayer | None = None,
    attack_tree: AttackTree | None = None,
) -> SeverityLevel:
    """Derive risk impact from multiple signals for calibrated spread.

    Uses a multi-signal approach to avoid flat "medium" for everything:
    1. Causal chain impact text (keyword matching)
    2. Zone breadth from narrative (more zones = wider blast radius)
    3. Attack tree structural exposure signals (single-point-of-failure = critical)
    4. Consequence text analysis (financial, regulatory, systemic keywords)

    Concrete anchor criteria:
    - LOW: minor inconvenience, single user affected, no data loss,
      easily reversible (e.g., chatbot gives wrong answer once)
    - MEDIUM: data exposure affecting multiple users, temporary service
      disruption, correctable with effort (e.g., PII leaked to one user)
    - HIGH: financial loss, regulatory breach, persistent data corruption,
      multi-user impact (e.g., tainted RAG data causes wrong financial advice)
    - CRITICAL: systemic compromise, organizational-level damage, cascading
      failures across systems (e.g., supply chain attack corrupts all agent
      outputs enterprise-wide)
    """
    score = 0.0  # Accumulate evidence; map to level at end

    # Signal 1: Impact text from risk card
    impact_text = (
        getattr(seed.risk_card_ref, "impact", None) if seed.risk_card_ref else None
    )
    if impact_text:
        lower = impact_text.lower()
        if any(
            kw in lower
            for kw in (
                "severe",
                "critical",
                "catastrophic",
                "systemic",
                "enterprise",
                "cascading",
            )
        ):
            score += 1.0
        elif any(
            kw in lower
            for kw in (
                "significant",
                "major",
                "serious",
                "financial",
                "regulatory",
                "breach",
            )
        ):
            score += 0.7
        elif any(
            kw in lower
            for kw in ("minor", "minimal", "negligible", "inconvenience", "temporary")
        ):
            score += 0.1
        else:
            score += 0.4  # Generic impact text -> lean toward medium

    # Signal 2: Consequence text (richer vocabulary than impact)
    consequence_text = (
        getattr(seed.risk_card_ref, "consequence", None) if seed.risk_card_ref else None
    )
    if consequence_text:
        lower = consequence_text.lower()
        if any(
            kw in lower
            for kw in (
                "all users",
                "organization",
                "enterprise",
                "supply chain",
                "cascading",
                "systemic",
            )
        ):
            score += 0.4
        elif any(
            kw in lower
            for kw in (
                "multiple users",
                "financial",
                "legal",
                "regulatory",
                "compliance",
                "persistent",
            )
        ):
            score += 0.25
        elif any(
            kw in lower
            for kw in ("single user", "one session", "temporary", "reversible")
        ):
            score += 0.05

    # Signal 3: Zone breadth from narrative (blast radius proxy).
    # Literal 'outside' traversal is not internal traversal.
    if narrative:
        distinct_zones = len(set(active_narrative_zones(narrative.zone_sequence)))
        if distinct_zones >= 4:
            score += 0.3  # Wide blast radius
        elif distinct_zones >= 3:
            score += 0.15
        elif distinct_zones == 1:
            score -= 0.1  # Contained to single zone

    # Signal 4: Structural exposure from attack tree
    if attack_tree:
        exposures = _extract_structural_exposures_from_tree(attack_tree.root)
        if "single_point_of_failure" in exposures:
            score += 0.3
        elif "convergence_point" in exposures:
            score += 0.2

    # Map accumulated score to severity level
    if score >= 0.9:
        return SeverityLevel.critical
    if score >= 0.6:
        return SeverityLevel.high
    if score >= 0.3:
        return SeverityLevel.medium
    return SeverityLevel.low


def _heuristic_attack_complexity(
    attack_tree: AttackTree | None,
    narrative: NarrativeLayer | None = None,
) -> AttackComplexity:
    """Derive attack complexity from attack tree structure and narrative.

    Three-tier heuristic producing low/medium/high spread:
    1. Attack tree node count and depth (primary signals)
    2. Zone sequence length from narrative (fallback when no tree)

    Concrete anchor criteria:
    - LOW: Simple single-step or direct attack; tree depth <= 2 AND
      node count <= 4; 1-2 zones; no special access required
      (e.g., simple prompt injection via chat input, direct jailbreak)
    - MEDIUM: Multi-step attack crossing 2-3 zones; moderate tree
      depth and node count (default for anything between low and high)
      (e.g., crafted prompt tricks reasoning into calling a tool with
      attacker-controlled parameters)
    - HIGH: Multi-stage campaign with deep trees OR wide attack surfaces;
      either node count >= 8 OR tree depth >= 4; privileged access,
      persistence, or lateral movement (e.g., supply chain attack that
      poisons a plugin, persists in memory, and corrupts inter-agent
      communication; OR a wide attack surface with many alternative
      exploitation paths)
    """
    if attack_tree is None:
        # No tree: fall back to narrative zone count if available.
        # Literal 'outside' traversal is not internal traversal.
        if narrative:
            zones = len(set(active_narrative_zones(narrative.zone_sequence)))
            if zones >= 4:
                return AttackComplexity.high
            if zones >= 2:
                return AttackComplexity.medium
            return AttackComplexity.low
        return AttackComplexity.medium

    count = _tree_node_count(attack_tree.root)
    depth = _tree_depth(attack_tree.root)

    # Typed leaf semantics distinguish resource-backed execution from pure
    # AI reasoning.  External preconditions and external impacts legitimately
    # have no zone, so only collect zones that are present rather than deriving
    # semantics from labels (or assuming every leaf is internal).
    internal_zones: set[str] = set()
    has_resource_action = False
    pending = [attack_tree.root]
    while pending:
        node = pending.pop()
        if node.children:
            pending.extend(node.children)
            continue

        action = node.action
        if action is None:
            continue
        if action.kind in {"tool_invocation", "integration_interaction"}:
            has_resource_action = True
        if node.zone is not None:
            internal_zones.add(node.zone)

    # Low: shallow, small, and confined to pure reasoning/ingress actions.
    # Invoking a concrete tool or integration requires at least medium
    # complexity even when represented by a very small tree.
    if (
        depth <= 2
        and count <= 4
        and not has_resource_action
        and len(internal_zones) <= 1
    ):
        return AttackComplexity.low

    # High: deep trees, wide attack surfaces, or broad internal traversal.
    if count >= 8 or depth >= 4 or len(internal_zones) >= 4:
        return AttackComplexity.high

    # Medium: everything in between
    return AttackComplexity.medium


def _heuristic_risk_likelihood(narrative: NarrativeLayer) -> str:
    """Derive risk likelihood from active zone coverage.

    Literal 'outside' traversal never counts toward zone coverage.
    """
    zones_traversed = len(set(active_narrative_zones(narrative.zone_sequence)))
    if zones_traversed >= 4:
        return "high"
    if zones_traversed >= 2:
        return "medium"
    return "low"


def _continuous_zone_score(narrative: NarrativeLayer) -> float:
    """Continuous zone traversal score in [0, 1].

    Uses both the number of distinct zones and the length of the zone
    sequence to produce a fine-grained value instead of coarse buckets.
    Literal 'outside' traversal is excluded: it is not internal traversal.
    """
    active_sequence = active_narrative_zones(narrative.zone_sequence)
    distinct = len(set(active_sequence))
    length = len(active_sequence)
    # distinct zones: 1-5 mapped to 0.2-1.0
    zone_breadth = min(distinct / 5.0, 1.0)
    # sequence length: longer paths get a small bonus (capped at 10 steps)
    path_depth = min(length / 10.0, 1.0)
    # Blend: breadth is primary (70%), path depth adds differentiation (30%)
    return 0.7 * zone_breadth + 0.3 * path_depth


def _continuous_tree_complexity_score(attack_tree: AttackTree | None) -> float:
    """Continuous attack tree complexity score in [0, 1].

    Blends tree depth and node count for fine-grained differentiation.
    """
    if attack_tree is None:
        return 0.3  # default for missing tree
    depth = _tree_depth(attack_tree.root)
    nodes = _tree_node_count(attack_tree.root)
    # depth: 1-5 mapped to 0.2-1.0
    depth_score = min(depth / 5.0, 1.0)
    # nodes: 1-12 mapped to ~0.08-1.0 (diminishing returns past 12)
    node_score = min(nodes / 12.0, 1.0)
    # Blend depth (40%) and node count (60%)
    return 0.4 * depth_score + 0.6 * node_score


def _continuous_technique_maturity_score(attack_tree: AttackTree | None) -> float:
    """Continuous technique maturity score in [0, 1].

    Uses tree depth as a continuous proxy for maturity, with the
    categorical mapping as anchor points.
    """
    if attack_tree is None:
        return 0.5  # feasible default
    depth = _tree_depth(attack_tree.root)
    # Map depth 1-5 to a continuous range: 0.3 (theoretical) to 0.9
    return min(0.3 + (depth - 1) * 0.15, 1.0)


def _compute_priority(
    narrative: NarrativeLayer,
    attack_tree: AttackTree | None,
    seed: ScenarioSeed,
) -> Priority:
    # Structural exposure from attack tree
    exposure = StructuralExposureSignal.none
    if attack_tree is not None:
        exposures = _extract_structural_exposures_from_tree(attack_tree.root)
        for candidate in [
            "single_point_of_failure",
            "convergence_point",
            "probabilistic_control",
            "defense_in_depth_claim",
        ]:
            if candidate in exposures:
                exposure = StructuralExposureSignal(candidate)
                break

    signals = PrioritySignals(
        technique_maturity=_heuristic_technique_maturity(attack_tree),
        risk_impact=_heuristic_risk_impact(seed, narrative, attack_tree),
        risk_likelihood=_heuristic_risk_likelihood(narrative),
        attack_complexity=_heuristic_attack_complexity(attack_tree, narrative),
        architecture_match=ArchitectureMatch.explicit,
        structural_exposure=exposure,
    )

    # Categorical score map for signals that lack continuous proxies
    score_map = {
        "critical": 1.0,
        "high": 0.8,
        "medium": 0.5,
        "low": 0.3,
        "moderate": 0.5,
        "explicit": 1.0,
        "inferred": 0.5,
        "single_point_of_failure": 1.0,
        "convergence_point": 0.8,
        "probabilistic_control": 0.6,
        "defense_in_depth_claim": 0.4,
        "none": 0.2,
    }

    weights = {
        "technique_maturity": 0.15,
        "risk_impact": 0.25,
        "risk_likelihood": 0.20,
        "attack_complexity": 0.15,
        "architecture_match": 0.10,
        "structural_exposure": 0.15,
    }

    # Use continuous scores for signals with numeric proxies;
    # fall back to categorical map for the rest.
    composite = (
        weights["technique_maturity"]
        * _continuous_technique_maturity_score(attack_tree)
        + weights["risk_impact"] * score_map.get(signals.risk_impact.value, 0.5)
        + weights["risk_likelihood"] * _continuous_zone_score(narrative)
        + weights["attack_complexity"] * _continuous_tree_complexity_score(attack_tree)
        + weights["architecture_match"]
        * score_map.get(signals.architecture_match.value, 0.5)
        + weights["structural_exposure"]
        * score_map.get(signals.structural_exposure.value, 0.2)
    )
    composite = round(min(1.0, max(0.0, composite)), 2)

    return Priority(composite=composite, signals=signals)
