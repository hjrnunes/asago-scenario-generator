"""Conservative risk-to-pattern mapping-path classification.

The taxonomy graph discovers candidate risk/pattern pairs.  This module owns
the small deterministic policy that describes how strong that discovery is;
it does not decide whether a mechanism exists in a system or whether it
realizes the reviewed risk.
"""

from __future__ import annotations

from collections.abc import Iterable

from asago_scenario_generator.models.obligation_consideration import MappingStrength

_WEAKNESS: dict[MappingStrength, int] = {
    "direct_curated_pair": 0,
    "exact_then_category_expansion": 1,
    "broad_category_expansion": 2,
    "related_category_expansion": 3,
}


def resolve_risk_pattern_mapping_strength(
    paths: Iterable[Iterable[str]],
) -> MappingStrength:
    """Classify complete paths, retaining the weakest supplied provenance.

    Every edge in every path contributes.  Multiple weak paths never combine
    into direct support, and an exact first edge cannot hide a later broad or
    related edge.  Unknown relationship names remain discovery hypotheses.
    """
    labels = tuple(
        _classify_path(tuple(_normalize(item) for item in path)) for path in paths
    )
    if not labels:
        raise ValueError("at least one risk-to-pattern mapping path is required")
    return max(labels, key=_WEAKNESS.__getitem__)


def _classify_path(relations: tuple[str, ...]) -> MappingStrength:
    """Classify one complete path using conservative relation semantics."""
    if not relations:
        return "direct_curated_pair"
    if any(_is_related(item) for item in relations):
        return "related_category_expansion"
    if any(_is_broad(item) for item in relations):
        return "broad_category_expansion"
    if len(relations) == 1:
        return (
            "direct_curated_pair"
            if _is_direct(relations[0])
            else "related_category_expansion"
        )
    if _is_exact(relations[0]):
        return "exact_then_category_expansion"
    return "broad_category_expansion"


def _normalize(relation: str) -> str:
    """Normalize one reviewed relationship label for semantic comparison."""
    if not isinstance(relation, str) or not relation.strip():
        raise ValueError("mapping relations must be non-empty strings")
    return relation.strip().lower()


def _is_exact(relation: str) -> bool:
    # SKOS closeMatch states interchangeability for retrieval, the strongest
    # claim short of exactMatch, so it carries the same weight here.
    return "exact" in relation or "close" in relation


def _is_direct(relation: str) -> bool:
    return _is_exact(relation) or "direct" in relation


def _is_related(relation: str) -> bool:
    return "related" in relation


def _is_broad(relation: str) -> bool:
    return any(
        marker in relation
        for marker in ("broad", "narrow", "extend", "parent", "child", "category")
    )


__all__ = ["resolve_risk_pattern_mapping_strength"]
