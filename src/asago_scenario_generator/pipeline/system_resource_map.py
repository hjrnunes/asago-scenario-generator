"""Deterministic offline validation for SystemResourceMap."""

from __future__ import annotations

import re
from typing import Any

from asago_scenario_generator.models.system_resource_map import (
    ResourceMapSnapshot,
    ResourceMapValidationIssue,
    ResourceMapValidationResult,
    SystemResourceMap,
    VALID_ENTITY_FAMILIES,
    VALID_PROVENANCE_KINDS,
    VALID_RESOLUTION_STATUSES,
)

_UNSTABLE_ID_PATTERNS = (
    re.compile(r"^idx-\d+", re.IGNORECASE),
    re.compile(r"^index-\d+", re.IGNORECASE),
    re.compile(r"^pos-\d+", re.IGNORECASE),
    re.compile(r"^item-\d+", re.IGNORECASE),
)

# SystemResourceMap collections sorted by element_id in the canonical map.
_CANONICAL_COLLECTIONS = (
    "system_resources",
    "actor_controllers",
    "controlled_processes",
    "control_actions",
    "feedback_paths",
    "trust_boundaries",
    "data_flows",
    "loss_links",
    "use_case_facts",
    "assertions",
)


def _is_unstable_id(element_id: str) -> bool:
    """Return True if element_id appears to be a positional or unstable index."""
    return any(p.match(element_id) for p in _UNSTABLE_ID_PATTERNS)


def _endpoint_reference_errors(
    entry: Any,
    endpoint_field: str,
    label: str,
    known_stpa: set[str],
    seen_ids: set[str],
) -> list[ResourceMapValidationIssue]:
    """Collect dangling-reference issues for one endpoint of a linked entry."""
    endpoint_id = getattr(entry, endpoint_field)
    if endpoint_id in known_stpa or endpoint_id in seen_ids:
        return []
    return [
        ResourceMapValidationIssue(
            code="dangling_reference",
            message=f"{label} reference {endpoint_id} not in snapshot",
            element_id=endpoint_id,
        )
    ]


def _missing_endpoint_error(
    entry: Any,
    label: str,
) -> ResourceMapValidationIssue:
    """Build the issue for a linked entry missing a controller or process ref."""
    return ResourceMapValidationIssue(
        code="invalid_control_action_link",
        message=f"{label} {entry.element_id} missing controller or process reference",
        element_id=entry.element_id,
    )


def _version_pin_errors(
    srm: SystemResourceMap, snap: ResourceMapSnapshot
) -> list[ResourceMapValidationIssue]:
    """Collect source-version pin mismatches against the snapshot."""
    errors: list[ResourceMapValidationIssue] = []
    if str(srm.stpa_version) != str(snap.stpa_version):
        errors.append(
            ResourceMapValidationIssue(
                code="source_version_mismatch",
                message=f"STPA version mismatch: {srm.stpa_version} != {snap.stpa_version}",
                field="stpa_version",
            )
        )
    if str(srm.taxonomy_version) != str(snap.taxonomy_version):
        errors.append(
            ResourceMapValidationIssue(
                code="source_version_mismatch",
                message=f"Taxonomy version mismatch: {srm.taxonomy_version} != {snap.taxonomy_version}",
                field="taxonomy_version",
            )
        )
    return errors


def _identifier_errors(
    all_entries: list[Any],
) -> tuple[list[ResourceMapValidationIssue], set[str]]:
    """Validate identifier uniqueness, stability, and entity families.

    Returns the issues found and the set of non-empty ids seen (for
    endpoint-reference resolution). Entries with empty element ids are
    exempt from duplicate detection.
    """
    errors: list[ResourceMapValidationIssue] = []
    seen_ids: set[str] = set()

    for entry in all_entries:
        eid = entry.element_id
        if not eid:
            continue
        if eid in seen_ids:
            errors.append(
                ResourceMapValidationIssue(
                    code="duplicate_identifier",
                    message=f"Duplicate identifier {eid}",
                    element_id=eid,
                )
            )
        else:
            seen_ids.add(eid)

        if _is_unstable_id(eid):
            errors.append(
                ResourceMapValidationIssue(
                    code="unstable_identifier",
                    message=f"Unstable identifier {eid}",
                    element_id=eid,
                )
            )

        # Entity family validation
        fam = getattr(entry, "entity_family", None)
        if fam and fam not in VALID_ENTITY_FAMILIES and fam != "assertion":
            errors.append(
                ResourceMapValidationIssue(
                    code="invalid_enum",
                    message=f"Invalid entity_family: {fam}",
                    element_id=eid,
                    field="entity_family",
                )
            )

    return errors, seen_ids


def _provenance_issues(
    element_id: str,
    provenance_kind: str | None,
    label: str,
) -> tuple[list[ResourceMapValidationIssue], list[ResourceMapValidationIssue]]:
    """Validate one optional provenance kind; return (errors, warnings)."""
    if provenance_kind and provenance_kind not in VALID_PROVENANCE_KINDS:
        return (
            [
                ResourceMapValidationIssue(
                    code="invalid_enum",
                    message=f"Invalid provenance_kind: {provenance_kind}",
                    element_id=element_id,
                    field="provenance_kind",
                )
            ],
            [],
        )
    if not provenance_kind:
        return (
            [],
            [
                ResourceMapValidationIssue(
                    code="missing_optional_provenance",
                    message=f"{label} {element_id} omits optional provenance",
                    element_id=element_id,
                    field="provenance_kind",
                )
            ],
        )
    return [], []


def _taxonomy_reference_errors(
    taxonomy_ref: str | None,
    known_taxonomy: set[str],
    label: str,
) -> list[ResourceMapValidationIssue]:
    """Collect dangling-taxonomy-reference issues for one entry field."""
    if taxonomy_ref and taxonomy_ref not in known_taxonomy:
        return [
            ResourceMapValidationIssue(
                code="dangling_reference",
                message=f"Taxonomy reference {taxonomy_ref} not in snapshot",
                element_id=taxonomy_ref,
            )
        ]
    return []


def _endpoint_errors(
    entry: Any,
    entry_label: str,
    known_stpa: set[str],
    seen_ids: set[str],
) -> list[ResourceMapValidationIssue]:
    """Validate controller/process endpoints for one linked entry."""
    if not entry.controller_id or not entry.process_id:
        return [_missing_endpoint_error(entry, entry_label)]
    return [
        *_endpoint_reference_errors(
            entry, "controller_id", "Controller", known_stpa, seen_ids
        ),
        *_endpoint_reference_errors(
            entry, "process_id", "Process", known_stpa, seen_ids
        ),
    ]


def _resource_link_error(
    entry_label: str,
    element_id: str,
    field_label: str,
    ref_id: str,
) -> ResourceMapValidationIssue:
    """Build the issue for a link to an unknown system resource."""
    return ResourceMapValidationIssue(
        code="unknown_resource_link",
        message=f"{entry_label} {element_id} references unknown {field_label} {ref_id}",
        element_id=element_id,
    )


def _resource_link_errors(
    entry: Any,
    entry_label: str,
    field_name: str,
    known_system_resources: set[str],
) -> list[ResourceMapValidationIssue]:
    """Collect unknown-resource-link issues for one entry's resource field."""
    ref_id = getattr(entry, field_name)
    if ref_id in known_system_resources:
        return []
    return [_resource_link_error(entry_label, entry.element_id, field_name, ref_id)]


def _loss_link_reference_errors(
    ll: Any,
    ref_field: str,
    ref_label: str,
    known_stpa: set[str],
    context_hint: str | None,
) -> list[ResourceMapValidationIssue]:
    """Collect loss/hazard reference issues for one loss link."""
    ref_id = getattr(ll, ref_field)
    if ref_id in known_stpa:
        return []
    return [
        ResourceMapValidationIssue(
            code=_unknown_stpa_reference_code(context_hint),
            message=f"Loss link {ll.element_id} references unknown {ref_label} {ref_id}",
            element_id=ref_id,
        )
    ]


def _unknown_stpa_reference_code(context_hint: str | None) -> str:
    """Resolve the issue code for loss/hazard references outside the snapshot."""
    is_dangling = context_hint == "dangling_reference"
    return "dangling_reference" if is_dangling else "unknown_loss_link"


def _coerce_resource_map_inputs(
    resource_map: SystemResourceMap | dict[str, Any],
    snapshot: ResourceMapSnapshot | dict[str, Any],
) -> tuple[SystemResourceMap, ResourceMapSnapshot]:
    """Normalize dict payloads into typed models."""
    srm = (
        SystemResourceMap.model_validate(resource_map)
        if isinstance(resource_map, dict)
        else resource_map
    )
    snap = (
        ResourceMapSnapshot.model_validate(snapshot)
        if isinstance(snapshot, dict)
        else snapshot
    )
    return srm, snap


def _provenance_section_errors(
    srm: SystemResourceMap,
) -> tuple[list[ResourceMapValidationIssue], list[ResourceMapValidationIssue]]:
    """Validate resolution status and provenance for facts and assertions."""
    errors: list[ResourceMapValidationIssue] = []
    warnings: list[ResourceMapValidationIssue] = []
    for uf in srm.use_case_facts:
        if uf.resolution_status not in VALID_RESOLUTION_STATUSES:
            errors.append(
                ResourceMapValidationIssue(
                    code="invalid_enum",
                    message=f"Invalid resolution_status: {uf.resolution_status}",
                    element_id=uf.element_id,
                    field="resolution_status",
                )
            )
        prov_errors, prov_warnings = _provenance_issues(
            uf.element_id, uf.provenance_kind, "Use case fact"
        )
        errors.extend(prov_errors)
        warnings.extend(prov_warnings)

    for a in srm.assertions:
        prov_errors, prov_warnings = _provenance_issues(
            a.element_id, a.provenance_kind, "Assertion"
        )
        errors.extend(prov_errors)
        warnings.extend(prov_warnings)
    return errors, warnings


def _system_resource_section_errors(
    srm: SystemResourceMap,
    known_taxonomy: set[str],
) -> list[ResourceMapValidationIssue]:
    """Collect dangling taxonomy references for system resources."""
    errors: list[ResourceMapValidationIssue] = []
    for sr in srm.system_resources:
        errors.extend(
            _taxonomy_reference_errors(
                sr.taxonomy_ref, known_taxonomy, "System resource"
            )
        )
    return errors


def _endpoint_section_errors(
    srm: SystemResourceMap,
    known_stpa: set[str],
    seen_ids: set[str],
) -> list[ResourceMapValidationIssue]:
    """Validate control-action and feedback-path endpoints."""
    errors: list[ResourceMapValidationIssue] = []
    for ca in srm.control_actions:
        errors.extend(_endpoint_errors(ca, "Control action", known_stpa, seen_ids))
    for fb in srm.feedback_paths:
        errors.extend(_endpoint_errors(fb, "Feedback path", known_stpa, seen_ids))
    return errors


def _trust_boundary_section_errors(
    srm: SystemResourceMap,
    known_taxonomy: set[str],
    known_system_resources: set[str],
) -> list[ResourceMapValidationIssue]:
    """Validate trust-boundary taxonomy and resource memberships."""
    errors: list[ResourceMapValidationIssue] = []
    for tb in srm.trust_boundaries:
        errors.extend(
            _taxonomy_reference_errors(
                tb.taxonomy_ref, known_taxonomy, "Trust boundary"
            )
        )
        for rid in tb.resource_ids:
            if rid not in known_system_resources:
                errors.append(
                    ResourceMapValidationIssue(
                        code="unknown_resource_link",
                        message=f"Trust boundary {tb.element_id} references unknown resource {rid}",
                        element_id=tb.element_id,
                    )
                )
    return errors


def _data_flow_section_errors(
    srm: SystemResourceMap,
    known_system_resources: set[str],
) -> list[ResourceMapValidationIssue]:
    """Validate data-flow source and target resource links."""
    errors: list[ResourceMapValidationIssue] = []
    for df in srm.data_flows:
        errors.extend(
            _resource_link_errors(
                df, "Data flow", "source_resource_id", known_system_resources
            )
        )
        errors.extend(
            _resource_link_errors(
                df, "Data flow", "target_resource_id", known_system_resources
            )
        )
    return errors


def _loss_link_section_errors(
    srm: SystemResourceMap,
    known_stpa: set[str],
    context_hint: str | None,
) -> list[ResourceMapValidationIssue]:
    """Validate loss and hazard references for all loss links."""
    errors: list[ResourceMapValidationIssue] = []
    for ll in srm.loss_links:
        errors.extend(
            _loss_link_reference_errors(ll, "loss_id", "loss", known_stpa, context_hint)
        )
        errors.extend(
            _loss_link_reference_errors(
                ll, "hazard_id", "hazard", known_stpa, context_hint
            )
        )
    return errors


def _alias_errors(srm: SystemResourceMap) -> list[ResourceMapValidationIssue]:
    """Collect ambiguous-alias issues for the map's alias bindings."""
    errors: list[ResourceMapValidationIssue] = []
    for alias_name, targets in srm.aliases.items():
        if isinstance(targets, list) and len(set(targets)) > 1:
            errors.append(
                ResourceMapValidationIssue(
                    code="ambiguous_alias",
                    message=f"Alias {alias_name} is bound to multiple targets: {targets}",
                    element_id=alias_name,
                )
            )
        elif isinstance(targets, str) and "," in targets:
            errors.append(
                ResourceMapValidationIssue(
                    code="ambiguous_alias",
                    message=f"Alias {alias_name} is bound to multiple targets: {targets}",
                    element_id=alias_name,
                )
            )
    return errors


def validate_resource_map(
    resource_map: SystemResourceMap | dict[str, Any],
    snapshot: ResourceMapSnapshot | dict[str, Any],
    *,
    context_hint: str | None = None,
) -> ResourceMapValidationResult:
    """Validate a SystemResourceMap against a pinned ResourceMapSnapshot.

    Performs deterministic offline validation with zero network and model calls.
    """
    srm, snap = _coerce_resource_map_inputs(resource_map, snapshot)

    # Collect known valid identifiers
    known_stpa = set(snap.stpa_identifiers)
    known_taxonomy = set(snap.taxonomy_identifiers)
    known_system_resources = {r.element_id for r in srm.system_resources}

    all_entries: list[Any] = []
    for collection in _CANONICAL_COLLECTIONS:
        all_entries.extend(getattr(srm, collection))

    errors: list[ResourceMapValidationIssue] = []
    warnings: list[ResourceMapValidationIssue] = []

    # 1. Source version pin validation
    errors.extend(_version_pin_errors(srm, snap))

    # 2. Identifier uniqueness and stability
    id_errors, seen_ids = _identifier_errors(all_entries)
    errors.extend(id_errors)

    # 3. Use-case facts and assertions (resolution status, provenance)
    prov_errors, prov_warnings = _provenance_section_errors(srm)
    errors.extend(prov_errors)
    warnings.extend(prov_warnings)

    # 4. System resource references
    errors.extend(_system_resource_section_errors(srm, known_taxonomy))

    # 5-6. Control action and feedback path endpoints
    errors.extend(_endpoint_section_errors(srm, known_stpa, seen_ids))

    # 7. Trust boundaries
    errors.extend(
        _trust_boundary_section_errors(srm, known_taxonomy, known_system_resources)
    )

    # 8. Data flows
    errors.extend(_data_flow_section_errors(srm, known_system_resources))

    # 9. Loss links
    errors.extend(_loss_link_section_errors(srm, known_stpa, context_hint))

    # 10. Ambiguous aliases
    errors.extend(_alias_errors(srm))

    # Build canonical map if valid
    canonical = None
    if len(errors) == 0:
        canonical = SystemResourceMap.model_validate(srm.model_dump(mode="json"))
        # Entries with empty element ids are exempt from duplicate detection,
        # so the sort key alone is not total; the serialized entry is the
        # final tiebreaker and canonical order never depends on presentation.
        for collection in _CANONICAL_COLLECTIONS:
            getattr(canonical, collection).sort(
                key=lambda x: (x.element_id, x.model_dump_json())
            )

    zero_network_calls = 0
    zero_model_calls = 0
    no_errors = len(errors) == 0
    return ResourceMapValidationResult(
        is_valid=no_errors,
        errors=errors,
        warnings=warnings,
        correspondence_relations=[],
        canonical_map=canonical,
        network_calls=zero_network_calls,
        model_calls=zero_model_calls,
    )
