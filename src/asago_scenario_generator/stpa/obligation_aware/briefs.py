"""Neutral-brief construction and brief batching.

This module imports only models so that both ``routing`` and the pipeline can
use it without an import cycle.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any, TypeVar

from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
from asago_scenario_generator.models.obligation_consideration import (
    NeutralObligationBrief,
)
from asago_scenario_generator.models.obligation_plan import (
    TaxonomyObligation,
    TaxonomyObligationPlan,
)

_Item = TypeVar("_Item")


def _catalog_map(
    attack_pattern_catalog: Sequence[AttackPattern] | Mapping[str, AttackPattern],
) -> dict[str, AttackPattern]:
    """Index a typed attack-pattern catalog by exact pattern identity."""
    values = (
        attack_pattern_catalog.values()
        if isinstance(attack_pattern_catalog, Mapping)
        else attack_pattern_catalog
    )
    result: dict[str, AttackPattern] = {}
    for pattern in values:
        if not isinstance(pattern, AttackPattern):
            raise TypeError("attack_pattern_catalog must contain AttackPattern values")
        if pattern.id in result:
            raise ValueError(
                f"attack pattern catalog contains duplicate id {pattern.id}"
            )
        result[pattern.id] = pattern
    return result


def _resource_references(row: TaxonomyObligation) -> tuple[Any, ...]:
    """Copy exact typed resource identities without copying candidate records."""
    references: dict[str, Any] = {}
    for candidate in row.candidate_records:
        for binding in candidate.resource_bindings:
            reference = binding.resource_ref
            references[reference.model_dump_json()] = reference
    return tuple(references[key] for key in sorted(references))


def build_neutral_brief(
    plan: TaxonomyObligationPlan,
    row: TaxonomyObligation,
    pattern: AttackPattern,
) -> NeutralObligationBrief:
    """Build one neutral STPA question from one applicable Phase 1 row.

    The brief intentionally contains no canonical chain steps and no
    candidate projection.  Qualification is copied, not used as a filter.
    """
    if not isinstance(plan, TaxonomyObligationPlan):
        raise TypeError("plan must be a TaxonomyObligationPlan")
    if not isinstance(row, TaxonomyObligation):
        raise TypeError("row must be a TaxonomyObligation")
    if row.scope_disposition != "applicable":
        raise ValueError("neutral briefs may only be built for applicable rows")
    if row.attack_pattern_id != pattern.id:
        raise ValueError("brief pattern does not match the obligation row")
    if row.attack_pattern_semantic_digest != pattern.canonical_chain.semantic_digest:
        raise ValueError("brief pattern digest does not match the obligation row")
    return NeutralObligationBrief(
        obligation_id=row.obligation_id,
        risk_ref=row.risk_ref,
        attack_pattern_id=pattern.id,
        attack_pattern_name=pattern.name,
        attack_pattern_description=pattern.description,
        attack_pattern_semantic_digest=pattern.canonical_chain.semantic_digest,
        taxonomy_chain=row.taxonomy_chain,
        prerequisite_capabilities=pattern.prerequisite_capabilities,
        qualification_disposition=row.qualification_disposition,
        applicability_evidence=row.evidence,
        resource_references=_resource_references(row),
        candidate_ids=tuple(item.candidate_id for item in row.candidate_records),
        plan_digest=plan.semantic_digest,
        catalog_pins=plan.catalog_pins,
        mapping_pins=plan.mapping_pins,
    )


def _row_pattern(
    row: TaxonomyObligation, catalog: Mapping[str, AttackPattern]
) -> AttackPattern:
    """Resolve the exact catalog pattern an applicable row names.

    ``TaxonomyObligation`` validation guarantees that an applicable row carries
    its pattern id and semantic digest.
    """
    pattern = catalog.get(row.attack_pattern_id)
    if pattern is None:
        raise ValueError(
            f"obligation {row.obligation_id} references an unknown attack pattern"
        )
    if pattern.canonical_chain.semantic_digest != row.attack_pattern_semantic_digest:
        raise ValueError(
            f"obligation {row.obligation_id} substituted its attack-pattern digest"
        )
    return pattern


def build_neutral_briefs(
    plan: TaxonomyObligationPlan,
    attack_pattern_catalog: Sequence[AttackPattern] | Mapping[str, AttackPattern],
) -> tuple[NeutralObligationBrief, ...]:
    """Build one brief for every applicable obligation in canonical order.

    Qualification and projection dispositions intentionally do not filter the
    result.  Capability-excluded and governance-only rows remain in Phase 1
    accounting but are not attack-pattern questions and therefore produce no
    brief.
    """
    if not isinstance(plan, TaxonomyObligationPlan):
        raise TypeError("plan must be a TaxonomyObligationPlan")
    plan.assert_integrity()
    catalog = _catalog_map(attack_pattern_catalog)
    briefs = [
        build_neutral_brief(plan, row, _row_pattern(row, catalog))
        for row in plan.obligations
        if row.scope_disposition == "applicable"
    ]
    return tuple(sorted(briefs, key=lambda item: item.obligation_id))


def require_batch_size(max_batch_size: int) -> None:
    """Require a positive integer batch size."""
    if type(max_batch_size) is not int:
        raise TypeError("max_batch_size must be an integer")
    if max_batch_size <= 0:
        raise ValueError("max_batch_size must be positive")


def create_obligation_batches(
    briefs: Sequence[NeutralObligationBrief],
    max_batch_size: int,
) -> tuple[tuple[NeutralObligationBrief, ...], ...]:
    """Partition briefs into stable, canonical batches."""
    require_batch_size(max_batch_size)
    ordered = tuple(sorted(briefs, key=lambda item: item.obligation_id))
    if any(not isinstance(item, NeutralObligationBrief) for item in ordered):
        raise TypeError("briefs must contain NeutralObligationBrief values")
    ids = tuple(item.obligation_id for item in ordered)
    if len(ids) != len(set(ids)):
        raise ValueError("briefs must contain unique obligation IDs")
    return tuple(
        tuple(ordered[index : index + max_batch_size])
        for index in range(0, len(ordered), max_batch_size)
    )


def split_by_budget(
    ordered: Sequence[_Item],
    max_batch_size: int,
    fits: Callable[[Sequence[_Item]], bool],
) -> tuple[tuple[_Item, ...], ...]:
    """Fill each batch in order until it is full or *fits* rejects the next item.

    A lone item always starts a batch, even when it does not fit by itself, and
    *fits* is asked only about a non-empty batch plus the candidate.
    """
    batches: list[tuple[_Item, ...]] = []
    current: list[_Item] = []
    for item in ordered:
        if current and (len(current) >= max_batch_size or not fits((*current, item))):
            batches.append(tuple(current))
            current = []
        current.append(item)
    if current:
        batches.append(tuple(current))
    return tuple(batches)
