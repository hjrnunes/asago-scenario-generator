"""Resource matching and lazy binding-combination mechanics for projection."""

from __future__ import annotations

from collections.abc import Iterable
from itertools import product
from typing import Any

from asago_scenario_generator.models.attack_pattern_chain import ResourceSlot
from asago_scenario_generator.models.attack_pattern_projection import (
    AgentInternalResourceReference,
    CanonicalResourceReference,
    EntryPointResourceReference,
    IntegrationResourceReference,
    OutputSurfaceResourceReference,
    ToolResourceReference,
    TrustBoundaryResourceReference,
)
from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    is_attacker_accessible_ingress,
)
from asago_scenario_generator.pipeline.projection_contracts import (
    _resource_id_allowed,
    _resource_key,
    _slot_reference_compatible,
)
from asago_scenario_generator.pipeline.projection_snapshot import (
    CapabilityFactSnapshot,
)


def _entry_point_reference_allowed(
    item: Any,
    active_zones: set[str],
    *,
    initial_ingress: bool,
    attacker_influence_required: bool,
) -> bool:
    """Filter entry points by the slot's attacker-accessibility requirement."""
    if initial_ingress or attacker_influence_required:
        return is_attacker_accessible_ingress(item, active_zones)
    return True


def _entry_point_references(
    profile: CapabilityProfile,
    *,
    initial_ingress: bool,
    attacker_influence_required: bool,
) -> list[CanonicalResourceReference]:
    """Build entry-point references, applying accessibility filtering."""
    active_zones = set(profile.zones_active)
    return [
        EntryPointResourceReference(
            kind="entry_point", entry_point_id=item.entry_point_id
        )
        for item in profile.entry_points
        if _entry_point_reference_allowed(
            item,
            active_zones,
            initial_ingress=initial_ingress,
            attacker_influence_required=attacker_influence_required,
        )
    ]


def _tool_references(
    profile: CapabilityProfile,
) -> list[CanonicalResourceReference]:
    """Build tool references from the inventory."""
    return [
        ToolResourceReference(kind="tool", tool_id=item.tool_id)
        for item in profile.tool_inventory or ()
    ]


def _integration_references(
    profile: CapabilityProfile,
) -> list[CanonicalResourceReference]:
    """Build integration references from the inventory."""
    return [
        IntegrationResourceReference(
            kind="integration", integration_id=item.integration_id
        )
        for item in profile.external_integrations or ()
    ]


def _output_surface_references(
    profile: CapabilityProfile,
) -> list[CanonicalResourceReference]:
    """Build output-surface references from the entry points."""
    return [
        OutputSurfaceResourceReference(
            kind="output_surface", entry_point_id=item.entry_point_id
        )
        for item in profile.entry_points
        if item.direction in ("output", "bidirectional")
    ]


def _agent_internal_references(
    profile: CapabilityProfile,
) -> list[CanonicalResourceReference]:
    """Build the intrinsic agent working-state reference, if present."""
    # Agent working state is an intrinsic singleton of every validated
    # profile (which must include the reasoning zone), not an adapter
    # inventory item.  Keep its reference typed and identity-free.
    if "reasoning" in profile.zones_active:
        return [AgentInternalResourceReference(kind="agent_internal")]
    return []


def _trust_boundary_references(
    profile: CapabilityProfile,
) -> list[CanonicalResourceReference]:
    """Build trust-boundary references from the inventory."""
    return [
        TrustBoundaryResourceReference(
            kind="trust_boundary", trust_boundary_id=item.trust_boundary_id
        )
        for item in profile.trust_boundaries or ()
    ]


_REFERENCE_BUILDERS: dict[str, Any] = {
    "entry_point": _entry_point_references,
    "tool": _tool_references,
    "integration": _integration_references,
    "output_surface": _output_surface_references,
    "agent_internal": _agent_internal_references,
}


def _references_for_kind(
    kind: str,
    snapshot: CapabilityFactSnapshot,
    *,
    initial_ingress: bool,
    attacker_influence_required: bool,
) -> tuple[CanonicalResourceReference, ...]:
    """Resolve profile resources of one kind in canonical order."""
    profile = snapshot.profile
    builder = _REFERENCE_BUILDERS.get(kind, _trust_boundary_references)
    if kind == "entry_point":
        refs = builder(
            profile,
            initial_ingress=initial_ingress,
            attacker_influence_required=attacker_influence_required,
        )
    else:
        refs = builder(profile)
    return tuple(sorted(refs, key=_resource_key))


def _references_for_slot(
    slot: ResourceSlot,
    snapshot: CapabilityFactSnapshot,
    *,
    initial_ingress: bool,
) -> tuple[CanonicalResourceReference, ...]:
    """Resolve one slot using only its typed, adapter-neutral constraints."""
    allowed_resource_ids = set(slot.allowed_resource_ids)
    references = _references_for_kind(
        slot.kind,
        snapshot,
        initial_ingress=initial_ingress,
        attacker_influence_required=(
            slot.kind == "entry_point" and slot.purpose == "supporting"
        ),
    )
    return tuple(
        reference
        for reference in references
        if _resource_id_allowed(reference, allowed_resource_ids)
        and _slot_reference_compatible(reference, slot, snapshot)
    )


def _combination_satisfies_distinctness(
    slots: tuple[ResourceSlot, ...],
    resources: tuple[CanonicalResourceReference, ...],
) -> bool:
    """True when a binding combination honors all distinctness declarations."""
    resources_by_slot = {
        slot.slot_id: resource for slot, resource in zip(slots, resources, strict=True)
    }
    return all(
        resources_by_slot[slot.slot_id] != resources_by_slot[other_slot_id]
        for slot in slots
        for other_slot_id in slot.distinct_from_slot_ids
    )


def _iter_compatible_combinations(
    slots: tuple[ResourceSlot, ...],
    options: tuple[tuple[CanonicalResourceReference, ...], ...],
) -> Iterable[tuple[CanonicalResourceReference, ...]]:
    """Yield resource combinations that honor distinctness declarations."""
    for resources in _iter_coverage_first_combinations(options):
        if _combination_satisfies_distinctness(slots, resources):
            yield resources


def _count_compatible_combinations(
    slots: tuple[ResourceSlot, ...],
    options: tuple[tuple[CanonicalResourceReference, ...], ...],
) -> int:
    """Count valid bindings without expanding unrelated Cartesian dimensions."""
    edges = _distinctness_edges(slots)
    constrained = _constrained_indexes(edges)
    total = _unconstrained_product(options, constrained)
    for component in _constrained_components(constrained, edges):
        total *= _count_component_assignments(component, edges, options)
    return total


def _distinctness_edges(
    slots: tuple[ResourceSlot, ...],
) -> set[frozenset[int]]:
    """Index slot pairs that must receive pairwise-distinct resources."""
    index_by_slot = {slot.slot_id: index for index, slot in enumerate(slots)}
    edges: set[frozenset[int]] = set()
    for index, slot in enumerate(slots):
        edges.update(_distinctness_edges_for_slot(index, slot, index_by_slot))
    return edges


def _distinctness_edges_for_slot(
    index: int,
    slot: ResourceSlot,
    index_by_slot: dict[str, int],
) -> set[frozenset[int]]:
    """Return distinctness edges declared by one slot."""
    return {
        frozenset((index, index_by_slot[other_slot_id]))
        for other_slot_id in slot.distinct_from_slot_ids
    }


def _constrained_indexes(edges: set[frozenset[int]]) -> set[int]:
    """Return the slot indexes participating in any distinctness constraint."""
    return set().union(*edges) if edges else set()


def _unconstrained_product(
    options: tuple[tuple[CanonicalResourceReference, ...], ...],
    constrained: set[int],
) -> int:
    """Multiply option counts for slots untouched by distinctness edges."""
    total = 1
    for index, slot_options in enumerate(options):
        if index not in constrained:
            total *= len(slot_options)
    return total


def _constrained_components(
    constrained: set[int], edges: set[frozenset[int]]
) -> list[set[int]]:
    """Partition constrained indexes into connected edge components."""
    remaining = set(constrained)
    components: list[set[int]] = []
    while remaining:
        components.append(_connected_component(remaining.pop(), remaining, edges))
    return components


def _connected_component(
    seed: int, remaining: set[int], edges: set[frozenset[int]]
) -> set[int]:
    """Consume one connected component from the remaining indexes."""
    component = {seed}
    frontier = [seed]
    while frontier:
        current = frontier.pop()
        new = _component_neighbors(current, edges) & remaining
        remaining -= new
        component |= new
        frontier.extend(new)
    return component


def _component_neighbors(current: int, edges: set[frozenset[int]]) -> set[int]:
    """Return indexes directly connected to the current index."""
    return {
        next(iter(edge - {current}))
        for edge in edges
        if current in edge and len(edge) == 2
    }


def _assignment_conflicts(
    index: int,
    resource: CanonicalResourceReference,
    assigned: dict[int, CanonicalResourceReference],
    edges: set[frozenset[int]],
) -> bool:
    """True when assigning ``resource`` violates a distinctness edge."""
    return any(
        frozenset((index, other_index)) in edges and resource == other_resource
        for other_index, other_resource in assigned.items()
    )


def _count_component_assignments(
    component: set[int],
    edges: set[frozenset[int]],
    options: tuple[tuple[CanonicalResourceReference, ...], ...],
) -> int:
    """Count valid assignments within one connected constrained component."""
    ordered = sorted(component)

    def count_at(offset: int, assigned: dict[int, CanonicalResourceReference]) -> int:
        if offset == len(ordered):
            return 1
        index = ordered[offset]
        count = 0
        for resource in options[index]:
            if _assignment_conflicts(index, resource, assigned, edges):
                continue
            assigned[index] = resource
            count += count_at(offset + 1, assigned)
            del assigned[index]
        return count

    return count_at(0, {})


def _iter_coverage_first_combinations(
    options: tuple[tuple[CanonicalResourceReference, ...], ...],
) -> Iterable[tuple[CanonicalResourceReference, ...]]:
    """Lazily yield coverage-first combinations without materializing the product.

    Callers stop early when the budget is reached; the full Cartesian
    product is never materialized.

    Ordering:
    1. The baseline (slot[0] for every slot).
    2. Per-slot variant offsets (cover each slot's alternatives).
    3. Remaining Cartesian fill in ``product`` order.
    """
    seen: set[tuple[str, ...]] = set()
    baseline = _combination_baseline(options)
    seen.add(_combination_key(baseline))
    yield baseline
    yield from _variant_combinations(baseline, options, seen)
    yield from _cartesian_fill(options, seen)


def _combination_key(
    items: tuple[CanonicalResourceReference, ...],
) -> tuple[str, ...]:
    """Map a resource combination to its canonical deduplication key."""
    return tuple(_resource_key(item) for item in items)


def _combination_baseline(
    options: tuple[tuple[CanonicalResourceReference, ...], ...],
) -> tuple[CanonicalResourceReference, ...]:
    """The first candidate combination: slot[0] for every slot."""
    return tuple(slot[0] for slot in options)


def _max_option_length(
    options: tuple[tuple[CanonicalResourceReference, ...], ...],
) -> int:
    """The longest per-slot option list (one when options is empty)."""
    return max(len(slot) for slot in options) if options else 1


def _variant_combinations(
    baseline: tuple[CanonicalResourceReference, ...],
    options: tuple[tuple[CanonicalResourceReference, ...], ...],
    seen: set[tuple[str, ...]],
) -> Iterable[tuple[CanonicalResourceReference, ...]]:
    """Yield per-slot variant offsets before any Cartesian fill."""
    max_len = _max_option_length(options)
    for offset in range(1, max_len):
        yield from _offset_variants(baseline, options, offset, seen)


def _offset_variants(
    baseline: tuple[CanonicalResourceReference, ...],
    options: tuple[tuple[CanonicalResourceReference, ...], ...],
    offset: int,
    seen: set[tuple[str, ...]],
) -> Iterable[tuple[CanonicalResourceReference, ...]]:
    """Yield variants replacing one slot at a fixed alternative offset."""
    for slot_index, slot in enumerate(options):
        if offset >= len(slot):
            continue
        variant = list(baseline)
        variant[slot_index] = slot[offset]
        variant_t = tuple(variant)
        key = _combination_key(variant_t)
        if key in seen:
            continue
        seen.add(key)
        yield variant_t


def _cartesian_fill(
    options: tuple[tuple[CanonicalResourceReference, ...], ...],
    seen: set[tuple[str, ...]],
) -> Iterable[tuple[CanonicalResourceReference, ...]]:
    """Yield remaining product combinations, skipping duplicates lazily."""
    for combination in product(*options):
        key = _combination_key(combination)
        if key in seen:
            continue
        seen.add(key)
        yield combination
