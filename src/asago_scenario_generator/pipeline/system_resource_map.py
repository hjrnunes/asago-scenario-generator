"""Pure validation of the Phase 2 system-resource-map domain contract."""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Iterable
from typing import Any

from asago_scenario_generator.models.attack_pattern_projection import (
    AgentInternalResourceReference,
    EntryPointResourceReference,
    IntegrationResourceReference,
    OutputSurfaceResourceReference,
    ToolResourceReference,
    TrustBoundaryResourceReference,
)
from asago_scenario_generator.models.system_resource_map import (
    ControlStructureReference,
    ResourceLink,
    ResourceMapViolation,
    SystemResourceMap,
    SystemResourceMapValidation,
)
from asago_scenario_generator.pipeline.projection_contracts import (
    CapabilityFactSnapshot,
)
from asago_scenario_generator.stpa.models.control_structure import ControlStructure

# A relation's source/target namespaces are intentionally closed. Adding a
# new relation or namespace is a schema change, not a permissive fallback.
_RELATION_COMPATIBILITY: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    "receives_from": (
        frozenset({"FB", "PM"}),
        frozenset(
            {
                "entry_point",
                "tool",
                "integration",
                "output_surface",
                "trust_boundary",
                "agent_internal",
            }
        ),
    ),
    "acts_on": (
        frozenset({"CA"}),
        frozenset(
            {
                "entry_point",
                "tool",
                "integration",
                "output_surface",
                "trust_boundary",
                "agent_internal",
            }
        ),
    ),
    "represents": (
        frozenset({"CP", "PM"}),
        frozenset(
            {
                "entry_point",
                "tool",
                "integration",
                "output_surface",
                "trust_boundary",
                "agent_internal",
            }
        ),
    ),
    "emits_to": (
        frozenset({"CA", "CP"}),
        frozenset({"output_surface", "integration"}),
    ),
    "crosses": (
        frozenset({"CA", "FB"}),
        frozenset({"trust_boundary"}),
    ),
    "coordinates_via": (
        frozenset({"CL", "CM"}),
        frozenset({"tool", "integration", "agent_internal"}),
    ),
}

# ``represents`` is the only one-to-one assertion in v1. The other relations
# are intentionally many-to-many: a controller can act on several resources,
# and one resource can participate in several control paths.
_CARDINALITY_RULES: dict[str, str] = {"represents": "one_capability_per_control"}


def _issue(
    code: str,
    message: str,
    *,
    link_id: str | None = None,
    field: str | None = None,
) -> ResourceMapViolation:
    """Create one typed deterministic violation."""
    return ResourceMapViolation(
        code=code,
        message=message,
        link_id=link_id,
        field=field,
    )


def _attribute_ids(items: Iterable[Any], field_name: str) -> set[str]:
    """Collect one namespace's identifiers from typed STPA records."""
    return {getattr(item, field_name) for item in items}


def _nested_attribute_ids(
    responsibilities: Iterable[Any], collection_name: str, field_name: str
) -> set[str]:
    """Collect identifiers from one nested responsibility collection."""
    return _attribute_ids(
        (
            item
            for responsibility in responsibilities
            for item in getattr(responsibility, collection_name)
        ),
        field_name,
    )


def _control_structure_ids(control_structure: ControlStructure) -> dict[str, set[str]]:
    """Collect every supported STPA namespace from one control structure."""
    responsibilities = control_structure.responsibilities
    coordination_links = control_structure.coordination_links
    return {
        "RESP": _attribute_ids(responsibilities, "resp_id"),
        "CP": _attribute_ids(control_structure.controlled_processes, "cp_id"),
        "PM": _nested_attribute_ids(responsibilities, "process_model_parts", "pm_id"),
        "CA": _nested_attribute_ids(responsibilities, "control_actions", "ca_id"),
        "FB": _nested_attribute_ids(responsibilities, "feedback_channels", "fb_id"),
        "CL": _attribute_ids(coordination_links, "link_id"),
        "CM": _attribute_ids(
            (link.coordination_mechanism for link in coordination_links), "cm_id"
        ),
    }


def _control_ref_key(reference: ControlStructureReference) -> tuple[str, str]:
    """Return a stable namespace/identifier pair for a control reference."""
    return reference.kind, reference.id


def _resource_ref_key(reference: Any) -> tuple[str, str | None]:
    """Return a stable kind/identifier pair for a capability reference."""
    kind = reference.kind
    identifier = next(
        (
            getattr(reference, field, None)
            for field in (
                "entry_point_id",
                "tool_id",
                "integration_id",
                "trust_boundary_id",
            )
            if hasattr(reference, field)
        ),
        None,
    )
    return kind, identifier


_RESOURCE_RESOLVERS: tuple[tuple[type, str, str], ...] = (
    (EntryPointResourceReference, "resolve_entry_point", "entry_point_id"),
    (OutputSurfaceResourceReference, "resolve_output_surface", "entry_point_id"),
    (ToolResourceReference, "resolve_tool", "tool_id"),
    (IntegrationResourceReference, "resolve_integration", "integration_id"),
    (TrustBoundaryResourceReference, "resolve_trust_boundary", "trust_boundary_id"),
)


def _resource_exists(snapshot: CapabilityFactSnapshot, reference: Any) -> bool:
    """Resolve a canonical capability reference against the pinned profile."""
    profile = snapshot.profile
    for reference_type, resolver_name, identifier_name in _RESOURCE_RESOLVERS:
        if isinstance(reference, reference_type):
            resolver = getattr(profile, resolver_name)
            return resolver(getattr(reference, identifier_name)) is not None
    if not isinstance(reference, AgentInternalResourceReference):
        return False
    return "reasoning" in profile.zones_active


def _unstable_link_id(link_id: str) -> bool:
    """Reject positional IDs that cannot survive authoring reorderings."""
    lowered = link_id.lower()
    return lowered.startswith(("idx-", "index-", "pos-", "item-"))


def _validate_pins(
    resource_map: SystemResourceMap,
    capability_snapshot: CapabilityFactSnapshot,
    control_structure: ControlStructure,
) -> list[ResourceMapViolation]:
    """Validate all content-addressed source pins without repairing them."""
    violations: list[ResourceMapViolation] = []
    try:
        capability_snapshot.assert_integrity()
    except ValueError as exc:
        violations.append(
            _issue(
                "invalid_capability_snapshot",
                str(exc),
                field="capability_snapshot_digest",
            )
        )
    if resource_map.capability_snapshot_digest != capability_snapshot.snapshot_digest:
        violations.append(
            _issue(
                "capability_snapshot_digest_mismatch",
                "resource map capability_snapshot_digest does not match the supplied snapshot",
                field="capability_snapshot_digest",
            )
        )

    from asago_scenario_generator.models.system_resource_map import (
        compute_control_structure_digest,
    )

    expected_control_digest = compute_control_structure_digest(control_structure)
    if resource_map.control_structure_digest != expected_control_digest:
        violations.append(
            _issue(
                "control_structure_digest_mismatch",
                "resource map control_structure_digest does not match the supplied control structure",
                field="control_structure_digest",
            )
        )
    try:
        resource_map.assert_integrity()
    except ValueError as exc:
        violations.append(
            _issue("semantic_digest_mismatch", str(exc), field="semantic_digest")
        )
    return violations


def _validate_link_identity(
    links: Iterable[ResourceLink],
) -> tuple[
    list[ResourceMapViolation],
    dict[str, list[ResourceLink]],
    dict[str, list[ResourceLink]],
]:
    """Detect unstable IDs, duplicate IDs, and semantic duplicates."""
    by_id, by_semantics, violations = _index_link_identity(links)
    for link_id, matches in sorted(by_id.items()):
        issue = _duplicate_link_id_issue(link_id, matches)
        if issue is not None:
            violations.append(issue)
    for matches in by_semantics.values():
        issue = _duplicate_semantic_issue(matches)
        if issue is not None:
            violations.append(issue)
    return violations, by_id, by_semantics


def _index_link_identity(
    links: Iterable[ResourceLink],
) -> tuple[
    dict[str, list[ResourceLink]],
    dict[str, list[ResourceLink]],
    list[ResourceMapViolation],
]:
    """Index links by ID and semantic identity while flagging unstable IDs."""
    violations: list[ResourceMapViolation] = []
    by_id: dict[str, list[ResourceLink]] = defaultdict(list)
    by_semantics: dict[str, list[ResourceLink]] = defaultdict(list)
    for link in links:
        by_id[link.link_id].append(link)
        semantic_key = _semantic_link_key(link)
        by_semantics[semantic_key].append(link)
        if _unstable_link_id(link.link_id):
            violations.append(
                _issue(
                    "unstable_identifier",
                    f"link identifier {link.link_id} is positional and unstable",
                    link_id=link.link_id,
                    field="link_id",
                )
            )
    return by_id, by_semantics, violations


def _semantic_link_key(link: ResourceLink) -> str:
    """Return a stable key for duplicate semantic-link detection."""
    return json.dumps(
        {
            "capability_resource_ref": link.capability_resource_ref.model_dump(
                mode="json"
            ),
            "control_structure_ref": link.control_structure_ref.model_dump(mode="json"),
            "relation_kind": link.relation_kind,
        },
        sort_keys=True,
    )


def _duplicate_link_id_issue(
    link_id: str, matches: list[ResourceLink]
) -> ResourceMapViolation | None:
    """Build a duplicate-ID issue when one ID appears more than once."""
    if len(matches) <= 1:
        return None
    return _issue(
        "duplicate_link_id",
        f"link_id {link_id} occurs {len(matches)} times",
        link_id=link_id,
        field="link_id",
    )


def _duplicate_semantic_issue(
    matches: list[ResourceLink],
) -> ResourceMapViolation | None:
    """Build an issue when equivalent links use different identifiers."""
    if len(matches) <= 1:
        return None
    ids = ", ".join(sorted(link.link_id for link in matches))
    return _issue(
        "duplicate_semantic_link",
        f"links {ids} assert the same capability/control relation",
        link_id=sorted(link.link_id for link in matches)[0],
    )


def _validate_link_reference(
    link: ResourceLink,
    known_ids: dict[str, set[str]],
    snapshot: CapabilityFactSnapshot,
) -> list[ResourceMapViolation]:
    """Validate both endpoint identities, namespaces, and relation legality."""
    violations: list[ResourceMapViolation] = []
    control_kind, control_id = _control_ref_key(link.control_structure_ref)
    if control_id not in known_ids.get(control_kind, set()):
        violations.append(
            _issue(
                "unknown_control_structure_reference",
                f"{control_kind} identifier {control_id} is not present in the control structure",
                link_id=link.link_id,
                field="control_structure_ref",
            )
        )
    if not _resource_exists(snapshot, link.capability_resource_ref):
        kind, identifier = _resource_ref_key(link.capability_resource_ref)
        violations.append(
            _issue(
                "unknown_capability_resource",
                f"{kind} resource {identifier or '<agent-internal>'} is not present in the capability snapshot",
                link_id=link.link_id,
                field="capability_resource_ref",
            )
        )
    allowed_control, allowed_capability = _RELATION_COMPATIBILITY[link.relation_kind]
    capability_kind = link.capability_resource_ref.kind
    if control_kind not in allowed_control or capability_kind not in allowed_capability:
        violations.append(
            _issue(
                "incompatible_relation_kind",
                f"relation {link.relation_kind} cannot connect {control_kind} to {capability_kind}",
                link_id=link.link_id,
                field="relation_kind",
            )
        )
    return violations


def _validate_authority(link: ResourceLink) -> list[ResourceMapViolation]:
    """Enforce the provenance/authority matrix for one link."""
    if link.authority_status == "authoritative" and link.provenance == "model_proposed":
        return [
            _issue(
                "model_proposed_authoritative",
                "model_proposed links may only be advisory or rejected",
                link_id=link.link_id,
                field="authority_status",
            )
        ]
    if link.authority_status == "authoritative" and not link.evidence_refs:
        return [
            _issue(
                "authoritative_link_without_evidence",
                "authoritative links require at least one evidence reference",
                link_id=link.link_id,
                field="evidence_refs",
            )
        ]
    return []


def _validate_cardinality(links: Iterable[ResourceLink]) -> list[ResourceMapViolation]:
    """Detect conflicting authoritative targets under the v1 rule table."""
    groups = _cardinality_groups(links)
    violations: list[ResourceMapViolation] = []
    for group_key, matches in sorted(groups.items()):
        issue = _cardinality_issue(group_key, matches)
        if issue is not None:
            violations.append(issue)
    return violations


def _cardinality_groups(
    links: Iterable[ResourceLink],
) -> dict[tuple[str, str, str], list[ResourceLink]]:
    """Group authoritative links governed by a v1 cardinality rule."""
    groups: dict[tuple[str, str, str], list[ResourceLink]] = defaultdict(list)
    for link in links:
        if (
            link.authority_status != "authoritative"
            or link.relation_kind not in _CARDINALITY_RULES
        ):
            continue
        control_kind, control_id = _control_ref_key(link.control_structure_ref)
        groups[(link.relation_kind, control_kind, control_id)].append(link)
    return groups


def _cardinality_issue(
    group_key: tuple[str, str, str], matches: list[ResourceLink]
) -> ResourceMapViolation | None:
    """Build a conflict issue when a cardinality group has many targets."""
    targets = {
        json.dumps(link.capability_resource_ref.model_dump(mode="json"), sort_keys=True)
        for link in matches
    }
    if len(targets) <= 1:
        return None
    relation, control_kind, control_id = group_key
    ids = ", ".join(sorted(link.link_id for link in matches))
    return _issue(
        "contradictory_authoritative_link",
        f"{relation} cardinality permits one capability target for {control_kind} {control_id}; links {ids} conflict",
        link_id=sorted(link.link_id for link in matches)[0],
        field="authority_status",
    )


def _validate_typed_inputs(
    resource_map: Any,
    capability_snapshot: Any,
    control_structure: Any,
) -> None:
    """Reject calls that bypass the typed public validation seam."""
    expected = (
        (resource_map, SystemResourceMap, "resource_map"),
        (capability_snapshot, CapabilityFactSnapshot, "capability_snapshot"),
        (control_structure, ControlStructure, "control_structure"),
    )
    for value, expected_type, name in expected:
        if not isinstance(value, expected_type):
            raise TypeError(f"{name} must be a {expected_type.__name__}")


def _validate_links(
    links: Iterable[ResourceLink],
    known_ids: dict[str, set[str]],
    snapshot: CapabilityFactSnapshot,
) -> list[ResourceMapViolation]:
    """Validate every link endpoint and authority declaration."""
    violations: list[ResourceMapViolation] = []
    for link in links:
        violations.extend(_validate_link_reference(link, known_ids, snapshot))
        violations.extend(_validate_authority(link))
    return violations


def _violation_sort_key(
    violation: ResourceMapViolation,
) -> tuple[str, str, str]:
    """Sort diagnostics by optional link/field values without mixed types."""
    link_id = violation.link_id if violation.link_id is not None else ""
    field = violation.field if violation.field is not None else ""
    return link_id, violation.code, field


def validate_system_resource_map(
    resource_map: SystemResourceMap,
    capability_snapshot: CapabilityFactSnapshot,
    control_structure: ControlStructure,
) -> SystemResourceMapValidation:
    """Validate one map against its exact capability and STPA authorities.

    The function is pure and observational: it performs no repair, proposal
    generation, correspondence inference, network calls, or model calls.
    """
    _validate_typed_inputs(resource_map, capability_snapshot, control_structure)

    violations = _validate_pins(resource_map, capability_snapshot, control_structure)
    identity_violations, _, _ = _validate_link_identity(resource_map.links)
    violations.extend(identity_violations)
    known_ids = _control_structure_ids(control_structure)
    violations.extend(
        _validate_links(resource_map.links, known_ids, capability_snapshot)
    )
    violations.extend(_validate_cardinality(resource_map.links))

    # Keep deterministic ordering so diagnostics and artifacts are stable.
    violations.sort(key=_violation_sort_key)
    valid = not violations
    return SystemResourceMapValidation(
        is_valid=valid,
        violations=tuple(violations),
        warnings=(),
        canonical_map=resource_map if valid else None,
        entry_point_completeness=(capability_snapshot.profile.entry_point_completeness),
        tool_inventory_completeness=(
            capability_snapshot.profile.tool_inventory_completeness
        ),
    )


__all__ = [
    "validate_system_resource_map",
]
