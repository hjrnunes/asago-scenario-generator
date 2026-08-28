"""Stage 7 — Six diagnostic eval metrics.

All metrics are deterministic (zero LLM calls). They measure structural
properties of the scenario set:

1. Structural consideration (imported from SP2)
2. N/A quality (imported from SP2)
3. BDI grounding
4. Tree branch coverage
5. Traceability depth
6. Diversity (Shannon entropy)
"""

from __future__ import annotations

import math
from pathlib import Path

import yaml

from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.enriched_threat_set import EnrichedThreatSet
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.models.scenario_envelope import ScenarioEnvelope

from .validators import (
    BRANCH_CATEGORIES,
    TraceabilityError,
    collect_valid_tree_ids,
    count_branch_categories,
    get_branch_categories,
    validate_traceability,
)

__all__ = [
    "metric_structural_consideration",
    "metric_na_quality",
    "metric_bdi_grounding",
    "metric_tree_branch_coverage",
    "metric_traceability_depth",
    "metric_diversity",
    "compute_eval_scorecard",
    "write_eval_scorecard",
]


def metric_structural_consideration(
    enriched_threat_set: EnrichedThreatSet,
) -> dict:
    """Import structural consideration from SP2 coverage analysis.

    Args:
        enriched_threat_set: The enriched threat set with coverage analysis.

    Returns:
        A dict with ``total_slots``, ``considered``, ``rate``, etc.
    """
    return enriched_threat_set.coverage_analysis.structural_consideration or {}


def metric_na_quality(
    enriched_threat_set: EnrichedThreatSet,
) -> dict:
    """Import N/A quality from SP2 coverage analysis.

    Args:
        enriched_threat_set: The enriched threat set with coverage analysis.

    Returns:
        A dict with ``na_count``, ``quality_count``, ``quality_rate``.
    """
    return enriched_threat_set.coverage_analysis.na_quality or {}


def metric_bdi_grounding(
    scenarios: list[ScenarioEnvelope],
    cs: ControlStructure,
) -> dict:
    """Compute fraction of BDI elements citing valid control structure IDs.

    Args:
        scenarios: List of scenario envelopes.
        cs: The control structure.

    Returns:
        A dict with ``belief_grounding_rate``, ``desire_grounding_rate``,
        and ``intention_grounding_rate``.
    """
    valid_ids = collect_valid_tree_ids(cs)

    total_beliefs = grounded_beliefs = 0
    total_desires = grounded_desires = 0
    total_intentions = grounded_intentions = 0

    for scenario in scenarios:
        bdi = scenario.scenario_spec.defender_bdi
        tb, gb = _count_grounded(bdi.beliefs, valid_ids["PM"], "pm_id")
        total_beliefs += tb
        grounded_beliefs += gb
        td, gd = _count_grounded(bdi.desires, valid_ids["RESP"], "resp_id")
        total_desires += td
        grounded_desires += gd
        ti, gi = _count_grounded(bdi.intentions, valid_ids["CA"], "ca_id")
        total_intentions += ti
        grounded_intentions += gi

    return {
        "belief_grounding_rate": _safe_rate(grounded_beliefs, total_beliefs),
        "desire_grounding_rate": _safe_rate(grounded_desires, total_desires),
        "intention_grounding_rate": _safe_rate(grounded_intentions, total_intentions),
    }


def _count_grounded(items: list, valid_ids: set[str], id_attr: str) -> tuple[int, int]:
    """Count total items and how many have a valid ID attribute.

    Args:
        items: List of objects with an ID attribute.
        valid_ids: Set of valid IDs to check against.
        id_attr: Name of the attribute holding the ID.

    Returns:
        A tuple of (total_count, grounded_count).
    """
    total = len(items)
    grounded = sum(1 for item in items if getattr(item, id_attr) in valid_ids)
    return total, grounded


def _safe_rate(numerator: int, denominator: int) -> float:
    """Compute a rate, returning 0 when the denominator is zero."""
    return numerator / denominator if denominator else 0


def metric_tree_branch_coverage(
    scenarios: list[ScenarioEnvelope],
) -> dict:
    """Compute fraction of scenarios using ≥2 of 3 branch categories.

    Args:
        scenarios: List of scenario envelopes.

    Returns:
        A dict with ``total_scenarios``, ``scenarios_with_2plus_categories``,
        and ``coverage_rate``.
    """
    total = len(scenarios)
    covered = sum(1 for s in scenarios if count_branch_categories(s.attack_tree) >= 2)
    return {
        "total_scenarios": total,
        "scenarios_with_2plus_categories": covered,
        "coverage_rate": _safe_rate(covered, total),
    }


def metric_traceability_depth(
    scenarios: list[ScenarioEnvelope],
    enriched_threat_set: EnrichedThreatSet,
    control_structure: ControlStructure,
    loss_analysis: LossAnalysis,
    *,
    precomputed_errors: list[TraceabilityError] | None = None,
) -> dict:
    """Compute fraction of scenarios with complete unbroken provenance chains.

    Args:
        scenarios: List of scenario envelopes.
        enriched_threat_set: The enriched threat set.
        control_structure: The control structure.
        loss_analysis: The loss analysis.
        precomputed_errors: If provided, use these traceability errors
            instead of re-running :func:`validate_traceability`.

    Returns:
        A dict with ``total_scenarios``, ``complete_chains``, and
        ``traceability_rate``.
    """
    total = len(scenarios)
    if total == 0:
        return {"total_scenarios": 0, "complete_chains": 0, "traceability_rate": 0}

    errors = (
        precomputed_errors
        if precomputed_errors is not None
        else validate_traceability(
            scenarios, enriched_threat_set, control_structure, loss_analysis
        )
    )
    error_scenario_ids = {e.scenario_id for e in errors}
    complete = sum(1 for s in scenarios if s.scenario_id not in error_scenario_ids)

    return {
        "total_scenarios": total,
        "complete_chains": complete,
        "traceability_rate": _safe_rate(complete, total),
    }


def _shannon_entropy(counts: dict[str, int]) -> float:
    """Compute Shannon entropy from a count distribution.

    Args:
        counts: A dict mapping category to count.

    Returns:
        The Shannon entropy value (non-negative float).
    """
    total = sum(counts.values())
    if total == 0:
        return 0.0
    entropy = 0.0
    for count in counts.values():
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    return round(entropy, 6)


def _count_by(
    scenarios: list[ScenarioEnvelope],
    key_func,
) -> dict[str, int]:
    """Count scenarios by a key function."""
    counts: dict[str, int] = {}
    for s in scenarios:
        key = key_func(s)
        counts[key] = counts.get(key, 0) + 1
    return counts


def _count_branch_usage(scenarios: list[ScenarioEnvelope]) -> dict[str, int]:
    """Count how many scenarios use each branch category."""
    counts: dict[str, int] = {cat: 0 for cat in BRANCH_CATEGORIES}
    for s in scenarios:
        cats = get_branch_categories(s.attack_tree)
        for cat in cats:
            counts[cat] = counts.get(cat, 0) + 1
    return counts


def _extract_leaf_label(leaf) -> str:
    """Extract a string label from a leaf entry (str or dict)."""
    if isinstance(leaf, str):
        return leaf
    if isinstance(leaf, dict):
        return leaf.get("label", str(leaf))
    return str(leaf)


def _count_unique_mechanisms(scenarios: list[ScenarioEnvelope]) -> int:
    """Count unique attack mechanisms across all scenario attack trees."""
    mechanisms: set[str] = set()
    for s in scenarios:
        for leaf in s.attack_tree.get("leaves", []):
            mechanisms.add(_extract_leaf_label(leaf))
    return len(mechanisms)


def metric_diversity(
    scenarios: list[ScenarioEnvelope],
) -> dict:
    """Compute distribution across responsibilities, ICA types, branch categories.

    Args:
        scenarios: List of scenario envelopes.

    Returns:
        A dict with ``by_responsibility``, ``by_ica_type``,
        ``by_branch_category``, ``unique_attack_mechanisms``,
        ``responsibility_diversity``, and ``ica_type_diversity``.
    """
    by_resp = _count_by(scenarios, lambda s: s.target_responsibility)
    by_ica = _count_by(
        scenarios,
        lambda s: s.ica_type.value if hasattr(s.ica_type, "value") else str(s.ica_type),
    )
    by_branch = _count_branch_usage(scenarios)
    unique_mechanisms = _count_unique_mechanisms(scenarios)

    return {
        "by_responsibility": by_resp,
        "by_ica_type": by_ica,
        "by_branch_category": by_branch,
        "unique_attack_mechanisms": unique_mechanisms,
        "responsibility_diversity": _shannon_entropy(by_resp),
        "ica_type_diversity": _shannon_entropy(by_ica),
    }


def compute_eval_scorecard(
    scenarios: list[ScenarioEnvelope],
    enriched_threat_set: EnrichedThreatSet,
    control_structure: ControlStructure,
    loss_analysis: LossAnalysis,
    stage_local_errors: list[str] | None = None,
    traceability_errors: list[str] | None = None,
    coverage_gaps: dict | None = None,
    *,
    precomputed_trace_errors: list[TraceabilityError] | None = None,
) -> dict:
    """Compute the full eval scorecard with all 6 metrics.

    Args:
        scenarios: List of scenario envelopes.
        enriched_threat_set: The enriched threat set.
        control_structure: The control structure.
        loss_analysis: The loss analysis.
        stage_local_errors: List of stage-local validation error messages.
        traceability_errors: List of traceability error messages.
        coverage_gaps: Coverage gap analysis dict.
        precomputed_trace_errors: If provided, pass these to
            :func:`metric_traceability_depth` to avoid re-running
            :func:`validate_traceability`.

    Returns:
        A dict with ``metrics``, ``coverage_gaps``, and ``validation`` sections.
    """
    return {
        "metrics": {
            "structural_consideration": metric_structural_consideration(
                enriched_threat_set
            ),
            "na_quality": metric_na_quality(enriched_threat_set),
            "bdi_grounding": metric_bdi_grounding(scenarios, control_structure),
            "tree_branch_coverage": metric_tree_branch_coverage(scenarios),
            "traceability_depth": metric_traceability_depth(
                scenarios,
                enriched_threat_set,
                control_structure,
                loss_analysis,
                precomputed_errors=precomputed_trace_errors,
            ),
            "diversity": metric_diversity(scenarios),
        },
        "coverage_gaps": coverage_gaps or {},
        "validation": {
            "stage_local_errors": stage_local_errors or [],
            "traceability_errors": traceability_errors or [],
        },
    }


def write_eval_scorecard(scorecard: dict, run_dir: Path) -> Path:
    """Write the eval scorecard to ``eval-scorecard.yaml``.

    Args:
        scorecard: The scorecard dict.
        run_dir: Directory to write to.

    Returns:
        The path to the written file.
    """
    path = run_dir / "eval-scorecard.yaml"
    path.write_text(
        yaml.dump(
            scorecard, default_flow_style=False, sort_keys=False, allow_unicode=True
        ),
        encoding="utf-8",
    )
    return path
