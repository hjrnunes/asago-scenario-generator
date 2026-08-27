"""Source-influence relation validation for authoritative projections."""

from __future__ import annotations

from typing import Any

from asago_scenario_generator.models.attack_pattern_chain import CanonicalAttackChain
from asago_scenario_generator.models.attack_pattern_contracts import SourceInfluencePath
from asago_scenario_generator.models.attack_pattern_projection import (
    EntryPointResourceReference,
    IntegrationResourceReference,
    TrustBoundaryResourceReference,
)
from asago_scenario_generator.models.capability_profile import (
    is_attacker_accessible_ingress,
)
from asago_scenario_generator.pipeline.projection_contracts import (
    CapabilityFactSnapshot,
    ProjectedCandidate,
    ProjectionIssue,
    _resource_id,
)


_SOURCE_RELATION_GUIDANCE = (
    "Review the explicit ingress_zone or trust-boundary declaration."
)


def _source_relation_issue(
    pattern_id: str,
    detail: str,
    *,
    source_id: str | None = None,
    boundary_id: str | None = None,
    target_ingress_id: str | None = None,
    canonical_ingress_id: str | None = None,
    expected_target_zone: str | None = None,
    actual_boundary_zones: str | None = None,
    expected_source_kind: str | None = None,
    actual_binding_kind: str | None = None,
) -> ProjectionIssue:
    """Build the consistent typed failure for an invalid source relation."""
    return ProjectionIssue(
        code="source_influence_relation_infeasible",
        pattern_id=pattern_id,
        detail=detail,
        source_id=source_id,
        boundary_id=boundary_id,
        target_ingress_id=target_ingress_id,
        canonical_ingress_id=canonical_ingress_id,
        expected_target_zone=expected_target_zone,
        actual_boundary_zones=actual_boundary_zones,
        expected_source_kind=expected_source_kind,
        actual_binding_kind=actual_binding_kind,
        guidance=_SOURCE_RELATION_GUIDANCE,
    )


def _source_influence_links(
    chain: CanonicalAttackChain, selected_ids: set[str]
) -> tuple[Any, ...]:
    """Collect the selected steps' source-influence links in chain order."""
    return tuple(
        link
        for step in chain.steps
        if step.step_id in selected_ids
        for link in step.resource_links
        if link.role == "source_influence"
    )


def _source_ingress_relation_guard(
    pattern_id: str,
    ingress: Any,
    ingress_ref: EntryPointResourceReference,
    links: tuple[Any, ...],
) -> tuple[tuple[SourceInfluencePath, ...], ProjectionIssue | None] | None:
    """Early-return guards for direct ingress and missing/ambiguous paths.

    Returns ``None`` when preflight continues to relation resolution.
    """
    # Preserve the legacy structural use of source-influence links on a
    # directly controlled ingress.  Relation preflight applies to indirect
    # ingress, where source provenance is the activation contract.
    if ingress.effective_controllability == "direct":
        return (), None
    if not links:
        return (), _source_relation_issue(
            pattern_id,
            "indirect canonical ingress has no selected source-influence path",
            target_ingress_id=ingress_ref.entry_point_id,
            canonical_ingress_id=ingress_ref.entry_point_id,
            expected_target_zone=ingress.effective_ingress_zone,
        )
    if len(links) != 1:
        return (), _source_relation_issue(
            pattern_id,
            (
                "candidate requires exactly one selected source-to-boundary-"
                f"to-ingress path, found {len(links)}"
            ),
            target_ingress_id=ingress_ref.entry_point_id,
            canonical_ingress_id=ingress_ref.entry_point_id,
            expected_target_zone=ingress.effective_ingress_zone,
        )
    return None


def _source_relation_refs(
    bindings_by_slot: dict[str, Any], link: Any
) -> tuple[Any, Any, Any]:
    """Resolve the source, boundary, and target bindings for one link."""
    return (
        bindings_by_slot.get(link.slot_id),
        bindings_by_slot.get(str(link.trust_boundary_slot_id)),
        bindings_by_slot.get(str(link.target_ingress_slot_id)),
    )


def _resource_id_or_none(reference: Any) -> str | None:
    """Resolve the stable resource id, mapping absence to None."""
    if reference is None:
        return None
    return _resource_id(reference)


def _source_influence_expected_kind(chain: CanonicalAttackChain, link: Any) -> str:
    """Resolve the declared source identity kind, falling back to the slot."""
    expected_kind = link.source_identity_kind
    if expected_kind is None:
        source_slot = next(
            slot for slot in chain.resource_slots if slot.slot_id == link.slot_id
        )
        expected_kind = source_slot.kind
    return expected_kind


def _source_relation_boundary(
    snapshot: CapabilityFactSnapshot, boundary_ref: Any
) -> Any | None:
    """Resolve the trust boundary only when the binding is typed."""
    if isinstance(boundary_ref, TrustBoundaryResourceReference):
        return snapshot.profile.resolve_trust_boundary(boundary_ref.trust_boundary_id)
    return None


def _boundary_zones_or_none(boundary: Any) -> str | None:
    """Format the boundary zone span, mapping absence to None."""
    if boundary is None:
        return None
    return f"{boundary.from_zone}->{boundary.to_zone}"


def _source_identity_kind_detail(
    actual_kind: str | None, expected_kind: str
) -> str | None:
    """Detail when the concrete binding kind does not match the link."""
    if actual_kind != expected_kind:
        return "source identity kind does not match the concrete binding"
    return None


def _source_binding_kind_detail(source_ref: Any) -> str | None:
    """Detail when the source binding is neither entry point nor integration."""
    if not isinstance(
        source_ref, (EntryPointResourceReference, IntegrationResourceReference)
    ):
        return "source binding is not an entry point or integration"
    return None


def _source_entry_point_detail(
    source_ref: Any,
    ingress_ref: EntryPointResourceReference,
    snapshot: CapabilityFactSnapshot,
) -> str | None:
    """Detail when the entry-point source is not influenceable or not distinct."""
    if not isinstance(source_ref, EntryPointResourceReference):
        return None
    source = snapshot.profile.resolve_entry_point(source_ref.entry_point_id)
    if source is None or not is_attacker_accessible_ingress(
        source, snapshot.profile.zones_active
    ):
        return "entry-point source is not attacker-influenceable"
    if source_ref.entry_point_id == ingress_ref.entry_point_id:
        return "source entry point must be distinct from target ingress"
    return None


def _source_boundary_detail(
    boundary: Any,
    expected_zone: str,
    target_id: str | None,
    ingress_id: str,
) -> str | None:
    """Detail when the boundary or target does not support the relation."""
    if boundary is None:
        return "source-influence boundary is absent from reviewed declarations"
    if boundary.confidence.value == "hypothesized":
        return "source-influence boundary is not a reviewed declaration"
    if boundary.to_zone != expected_zone:
        return "trust-boundary destination zone does not match target ingress"
    if target_id != ingress_id:
        return "source-influence target is not the canonical ingress binding"
    return None


def _source_relation_issue_detail(
    source_ref: Any,
    actual_kind: str | None,
    expected_kind: str,
    ingress_ref: EntryPointResourceReference,
    snapshot: CapabilityFactSnapshot,
    boundary: Any,
    target_id: str | None,
    ingress_id: str,
) -> str | None:
    """Combine the identity and boundary cascades, boundary cascade last."""
    detail = _source_identity_kind_detail(actual_kind, expected_kind)
    if detail is None:
        detail = _source_binding_kind_detail(source_ref)
    if detail is None:
        detail = _source_entry_point_detail(source_ref, ingress_ref, snapshot)
    boundary_detail = _source_boundary_detail(
        boundary,
        snapshot.profile.resolve_entry_point(
            ingress_ref.entry_point_id
        ).effective_ingress_zone,
        target_id,
        ingress_id,
    )
    if boundary_detail is not None:
        return boundary_detail
    return detail


def _source_relation_resolution(
    pattern_id: str,
    ingress: Any,
    ingress_ref: EntryPointResourceReference,
    link: Any,
    chain: CanonicalAttackChain,
    bindings_by_slot: dict[str, Any],
    snapshot: CapabilityFactSnapshot,
) -> tuple[tuple[SourceInfluencePath, ...], ProjectionIssue | None]:
    """Resolve the single source-influence path or return the typed issue."""
    source_ref, boundary_ref, target_ref = _source_relation_refs(bindings_by_slot, link)
    source_id = _resource_id_or_none(source_ref)
    boundary_id = _resource_id_or_none(boundary_ref)
    target_id = _resource_id_or_none(target_ref)
    expected_kind = _source_influence_expected_kind(chain, link)
    actual_kind = source_ref.kind if source_ref is not None else None
    boundary = _source_relation_boundary(snapshot, boundary_ref)
    actual_boundary_zones = _boundary_zones_or_none(boundary)
    issue_detail = _source_relation_issue_detail(
        source_ref,
        actual_kind,
        expected_kind,
        ingress_ref,
        snapshot,
        boundary,
        target_id,
        ingress_ref.entry_point_id,
    )
    if issue_detail is not None:
        return (), _source_relation_issue(
            pattern_id,
            detail=issue_detail,
            source_id=source_id,
            boundary_id=boundary_id,
            target_ingress_id=target_id,
            canonical_ingress_id=ingress_ref.entry_point_id,
            expected_target_zone=ingress.effective_ingress_zone,
            actual_boundary_zones=actual_boundary_zones,
            expected_source_kind=expected_kind,
            actual_binding_kind=actual_kind,
        )
    assert boundary is not None
    assert target_id is not None
    path = SourceInfluencePath(
        source_identity_kind=expected_kind,
        source_id=source_id,
        boundary_id=boundary_id,
        target_ingress_id=target_id,
        expected_target_zone=ingress.effective_ingress_zone,
        boundary_zones=actual_boundary_zones,
    )
    return (path,), None


def _source_influence_relation(
    pattern_id: str,
    chain: CanonicalAttackChain,
    selected: tuple[str, ...],
    bindings: tuple[Any, ...],
    snapshot: CapabilityFactSnapshot,
) -> tuple[tuple[SourceInfluencePath, ...], ProjectionIssue | None]:
    """Resolve exactly one source relation from immutable projection bindings."""
    bindings_by_slot = {item.slot_id: item.resource_ref for item in bindings}
    links = _source_influence_links(chain, set(selected))
    ingress_ref = bindings_by_slot[chain.initial_ingress_slot_id]
    if not isinstance(ingress_ref, EntryPointResourceReference):
        return (), _source_relation_issue(
            pattern_id,
            "canonical ingress is not an entry-point binding",
            canonical_ingress_id=_resource_id(ingress_ref),
        )
    ingress = snapshot.profile.resolve_entry_point(ingress_ref.entry_point_id)
    assert ingress is not None

    guard = _source_ingress_relation_guard(pattern_id, ingress, ingress_ref, links)
    if guard is not None:
        return guard
    return _source_relation_resolution(
        pattern_id,
        ingress,
        ingress_ref,
        links[0],
        chain,
        bindings_by_slot,
        snapshot,
    )


def _validate_source_influence_paths(
    candidate: ProjectedCandidate,
    snapshot: CapabilityFactSnapshot,
) -> None:
    """Re-derive the authoritative relation at the persistence boundary.

    Projection generation and serialized-candidate validation must share the
    same relation rule.  Digest and candidate-identity checks prove that a
    payload is self-consistent, but they do not prove that its derived path
    matches the immutable bindings and profile.
    """
    expected_paths, issue = _source_influence_relation(
        candidate.pattern_id,
        candidate.projection.source_chain,
        candidate.projection.selected_step_ids,
        candidate.projection.bindings,
        snapshot,
    )
    if issue is not None:
        raise ValueError(
            f"candidate source-influence relation is infeasible: {issue.detail}"
        )
    if candidate.projection.source_influence_paths != expected_paths:
        raise ValueError(
            "candidate source-influence paths do not match authoritative "
            "bindings and profile"
        )
