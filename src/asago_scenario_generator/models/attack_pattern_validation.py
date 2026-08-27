"""Qualification helpers for attack-pattern and projection contracts."""

from __future__ import annotations

from typing import Any

from .attack_pattern_chain import AttackPattern
from .attack_pattern_contracts import (
    CapabilitySnapshotResolver,
    ChainMappingDecision,
    ExactMapping,
    LegacyAttackPatternRecord,
    MappingDecision,
    TaxonomyResolver,
)
from .attack_pattern_projection import ProjectionSnapshot


def validate_legacy_attack_pattern(
    pattern_dict: dict[str, Any],
) -> LegacyAttackPatternRecord:
    return LegacyAttackPatternRecord.model_validate(pattern_dict)


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


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-26T22:10:53Z","module_hash":"d9897647129f7c2a5f490c5a5e38b9f1f6bc0a0f4b965a9ca425814eb0aab7b7","source_sha256":"179aa0c347bf9427c2f15cc9dbb5eaa3178d01e031c79e5e95ce76caf2b3b5e9","functions":[{"id":"func/validate_legacy_attack_pattern","name":"validate_legacy_attack_pattern","line":19,"end_line":22,"hash":"a8665e159d6072176797adf30d09601b320b6121805378029003be9bf50b6c99"},{"id":"func/_check_resolver_pins","name":"_check_resolver_pins","line":25,"end_line":28,"hash":"69b5b3794028989399d51a7d194e0a15a6c8558909160912d066f95ae195552c"},{"id":"func/_check_mapping_membership","name":"_check_mapping_membership","line":31,"end_line":40,"hash":"e319b94f2457e2717091bb7932a03b3ac0f356d4f8e2b7e2409cad8847797754"},{"id":"func/validate_attack_pattern","name":"validate_attack_pattern","line":43,"end_line":55,"hash":"6fe10e2a80a58576d38ac9f66cbc803860aea282826a986fad8a4debd615681c"},{"id":"func/_check_snapshot_digest_pin","name":"_check_snapshot_digest_pin","line":58,"end_line":66,"hash":"4452f3333541be1bde71b21656d539ee67ecae951a2781248ebbd5d67dcd7d81"},{"id":"func/_check_fact_evidence","name":"_check_fact_evidence","line":69,"end_line":81,"hash":"63e58119ef508cabbf8bcfc8e1672a028a58d7c0acd70c67da2d362db6cf42ed"},{"id":"func/_check_resource_bindings","name":"_check_resource_bindings","line":84,"end_line":100,"hash":"91f024b26d440587c3ee5d06e7c37d6dd540ea77f275c0d4bf34bf5e5a62fe0e"},{"id":"func/validate_projection_snapshot","name":"validate_projection_snapshot","line":103,"end_line":111,"hash":"0e4a46584d6079332c1073771bb01168deefcaf43c0872d8b63c3bf7b32eee80"}]}
# mutate4py-manifest-end
