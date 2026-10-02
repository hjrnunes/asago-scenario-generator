"""Qualification helpers for attack-pattern and projection contracts."""

from __future__ import annotations

from typing import Any

from .attack_pattern_chain import AttackPattern
from .attack_pattern_contracts import (
    CapabilitySnapshotResolver,
    ChainMappingDecision,
    ExactMapping,
    MappingDecision,
    TaxonomyResolver,
)
from .attack_pattern_projection import ProjectionSnapshot


def _check_resolver_pins(pattern: AttackPattern, resolver: TaxonomyResolver) -> None:
    """The resolver must pin the identical taxonomy context."""
    if resolver.taxonomy_context != pattern.canonical_chain.taxonomy_context:
        raise ValueError("taxonomy resolver pins do not match canonical chain pins")


def _check_mapping_membership(
    resolver: TaxonomyResolver,
    mappings: tuple[MappingDecision, ...] | tuple[ChainMappingDecision, ...],
) -> None:
    """Every exact mapping id must be resolvable in its taxonomy."""
    for mapping in mappings:
        if isinstance(mapping, ExactMapping):
            for identifier in mapping.ids:
                if not resolver.contains(mapping.taxonomy, identifier):
                    raise ValueError(f"unknown {mapping.taxonomy} id: {identifier}")


def validate_attack_pattern(
    pattern_dict: dict[str, Any], resolver: TaxonomyResolver
) -> AttackPattern:
    """Parse and qualify a pattern; ``AttackPattern.model_validate`` only parses."""
    pattern = AttackPattern.model_validate(pattern_dict)
    _check_resolver_pins(pattern, resolver)
    mapping_scopes = [
        pattern.canonical_chain.mappings,
        *(s.mappings for s in pattern.canonical_chain.steps),
    ]
    for mappings in mapping_scopes:
        _check_mapping_membership(resolver, mappings)
    return pattern


def _check_snapshot_digest_pin(
    resolver: CapabilitySnapshotResolver, snapshot: ProjectionSnapshot
) -> None:
    """The resolver must pin the identical capability snapshot digest."""
    if (
        resolver.capability_fact_snapshot_digest
        != snapshot.capability_fact_snapshot_digest
    ):
        raise ValueError("capability snapshot resolver digest pin does not match")


def _check_fact_evidence(
    resolver: CapabilitySnapshotResolver, snapshot: ProjectionSnapshot
) -> None:
    """Every supplied fact evidence must match the resolver reading."""
    for result in snapshot.condition_results:
        for supplied in result.evidence:
            authoritative = resolver.fact(supplied.fact)
            if authoritative is None:
                raise ValueError("authoritative condition fact is missing")
            if authoritative != supplied:
                raise ValueError(
                    "condition fact evidence does not match resolver reading"
                )


def _check_resource_bindings(
    resolver: CapabilitySnapshotResolver, snapshot: ProjectionSnapshot
) -> None:
    """Every binding resolves and matches its slot constraints."""
    for binding in snapshot.bindings:
        if not resolver.contains_resource(binding.resource_ref):
            raise ValueError(f"missing {binding.resource_ref.kind} resource")
        slot = next(
            item
            for item in snapshot.source_chain.resource_slots
            if item.slot_id == binding.slot_id
        )
        if not resolver.resource_matches_slot(binding.resource_ref, slot):
            raise ValueError(
                f"{binding.resource_ref.kind} resource is incompatible with slot "
                f"{binding.slot_id}"
            )


def validate_projection_snapshot(
    snapshot_dict: dict[str, Any], resolver: CapabilitySnapshotResolver
) -> ProjectionSnapshot:
    """Parse and externally qualify a projection against a mandatory pinned resolver."""
    snapshot = ProjectionSnapshot.model_validate(snapshot_dict)
    _check_snapshot_digest_pin(resolver, snapshot)
    _check_fact_evidence(resolver, snapshot)
    _check_resource_bindings(resolver, snapshot)
    return snapshot
