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


def _is_unstable_id(element_id: str) -> bool:
    """Return True if element_id appears to be a positional or unstable index."""
    return any(p.match(element_id) for p in _UNSTABLE_ID_PATTERNS)


def validate_resource_map(
    resource_map: SystemResourceMap | dict[str, Any],
    snapshot: ResourceMapSnapshot | dict[str, Any],
    *,
    context_hint: str | None = None,
) -> ResourceMapValidationResult:
    """Validate a SystemResourceMap against a pinned ResourceMapSnapshot.

    Performs deterministic offline validation with zero network and model calls.
    """
    if isinstance(resource_map, dict):
        srm = SystemResourceMap.model_validate(resource_map)
    else:
        srm = resource_map

    if isinstance(snapshot, dict):
        snap = ResourceMapSnapshot.model_validate(snapshot)
    else:
        snap = snapshot

    errors: list[ResourceMapValidationIssue] = []
    warnings: list[ResourceMapValidationIssue] = []

    # 1. Source version pin validation
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

    # Collect known valid identifiers
    known_stpa = set(snap.stpa_identifiers)
    known_taxonomy = set(snap.taxonomy_identifiers)
    known_system_resources = {r.element_id for r in srm.system_resources}

    # 2. Identifier uniqueness and stability
    seen_ids: set[str] = set()
    all_entries = (
        list(srm.system_resources)
        + list(srm.actor_controllers)
        + list(srm.controlled_processes)
        + list(srm.control_actions)
        + list(srm.feedback_paths)
        + list(srm.trust_boundaries)
        + list(srm.data_flows)
        + list(srm.loss_links)
        + list(srm.use_case_facts)
        + list(srm.assertions)
    )

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

    # 3. Use-case facts and assertions validation (resolution status, provenance)
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
        if uf.provenance_kind and uf.provenance_kind not in VALID_PROVENANCE_KINDS:
            errors.append(
                ResourceMapValidationIssue(
                    code="invalid_enum",
                    message=f"Invalid provenance_kind: {uf.provenance_kind}",
                    element_id=uf.element_id,
                    field="provenance_kind",
                )
            )
        elif not uf.provenance_kind:
            warnings.append(
                ResourceMapValidationIssue(
                    code="missing_optional_provenance",
                    message=f"Use case fact {uf.element_id} omits optional provenance",
                    element_id=uf.element_id,
                    field="provenance_kind",
                )
            )

    for a in srm.assertions:
        if a.provenance_kind and a.provenance_kind not in VALID_PROVENANCE_KINDS:
            errors.append(
                ResourceMapValidationIssue(
                    code="invalid_enum",
                    message=f"Invalid provenance_kind: {a.provenance_kind}",
                    element_id=a.element_id,
                    field="provenance_kind",
                )
            )
        elif not a.provenance_kind:
            warnings.append(
                ResourceMapValidationIssue(
                    code="missing_optional_provenance",
                    message=f"Assertion {a.element_id} omits optional provenance",
                    element_id=a.element_id,
                    field="provenance_kind",
                )
            )

    # 4. System resource references
    for sr in srm.system_resources:
        if sr.taxonomy_ref and sr.taxonomy_ref not in known_taxonomy:
            errors.append(
                ResourceMapValidationIssue(
                    code="dangling_reference",
                    message=f"Taxonomy reference {sr.taxonomy_ref} not in snapshot",
                    element_id=sr.taxonomy_ref,
                )
            )

    # 5. Control actions
    for ca in srm.control_actions:
        if not ca.controller_id or not ca.process_id:
            errors.append(
                ResourceMapValidationIssue(
                    code="invalid_control_action_link",
                    message=f"Control action {ca.element_id} missing controller or process reference",
                    element_id=ca.element_id,
                )
            )
        else:
            if ca.controller_id not in known_stpa and ca.controller_id not in seen_ids:
                errors.append(
                    ResourceMapValidationIssue(
                        code="dangling_reference",
                        message=f"Controller reference {ca.controller_id} not in snapshot",
                        element_id=ca.controller_id,
                    )
                )
            if ca.process_id not in known_stpa and ca.process_id not in seen_ids:
                errors.append(
                    ResourceMapValidationIssue(
                        code="dangling_reference",
                        message=f"Process reference {ca.process_id} not in snapshot",
                        element_id=ca.process_id,
                    )
                )

    # 6. Feedback paths
    for fb in srm.feedback_paths:
        if not fb.controller_id or not fb.process_id:
            errors.append(
                ResourceMapValidationIssue(
                    code="invalid_control_action_link",
                    message=f"Feedback path {fb.element_id} missing controller or process reference",
                    element_id=fb.element_id,
                )
            )
        else:
            if fb.controller_id not in known_stpa and fb.controller_id not in seen_ids:
                errors.append(
                    ResourceMapValidationIssue(
                        code="dangling_reference",
                        message=f"Controller reference {fb.controller_id} not in snapshot",
                        element_id=fb.controller_id,
                    )
                )
            if fb.process_id not in known_stpa and fb.process_id not in seen_ids:
                errors.append(
                    ResourceMapValidationIssue(
                        code="dangling_reference",
                        message=f"Process reference {fb.process_id} not in snapshot",
                        element_id=fb.process_id,
                    )
                )

    # 7. Trust boundaries
    for tb in srm.trust_boundaries:
        if tb.taxonomy_ref and tb.taxonomy_ref not in known_taxonomy:
            errors.append(
                ResourceMapValidationIssue(
                    code="dangling_reference",
                    message=f"Taxonomy reference {tb.taxonomy_ref} not in snapshot",
                    element_id=tb.taxonomy_ref,
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

    # 8. Data flows
    for df in srm.data_flows:
        if df.source_resource_id not in known_system_resources:
            errors.append(
                ResourceMapValidationIssue(
                    code="unknown_resource_link",
                    message=f"Data flow {df.element_id} references unknown source resource {df.source_resource_id}",
                    element_id=df.element_id,
                )
            )
        if df.target_resource_id not in known_system_resources:
            errors.append(
                ResourceMapValidationIssue(
                    code="unknown_resource_link",
                    message=f"Data flow {df.element_id} references unknown target resource {df.target_resource_id}",
                    element_id=df.element_id,
                )
            )

    # 9. Loss links
    for ll in srm.loss_links:
        if ll.loss_id not in known_stpa:
            code = (
                "unknown_loss_link"
                if context_hint != "dangling_reference"
                else "dangling_reference"
            )
            errors.append(
                ResourceMapValidationIssue(
                    code=code,
                    message=f"Loss link {ll.element_id} references unknown loss {ll.loss_id}",
                    element_id=ll.loss_id,
                )
            )
        if ll.hazard_id not in known_stpa:
            code = (
                "unknown_loss_link"
                if context_hint != "dangling_reference"
                else "dangling_reference"
            )
            errors.append(
                ResourceMapValidationIssue(
                    code=code,
                    message=f"Loss link {ll.element_id} references unknown hazard {ll.hazard_id}",
                    element_id=ll.hazard_id,
                )
            )

    # 10. Ambiguous aliases
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

    # Build canonical map if valid
    canonical = None
    if len(errors) == 0:
        canonical = SystemResourceMap.model_validate(srm.model_dump(mode="json"))
        canonical.system_resources.sort(key=lambda x: x.element_id)
        canonical.actor_controllers.sort(key=lambda x: x.element_id)
        canonical.controlled_processes.sort(key=lambda x: x.element_id)
        canonical.control_actions.sort(key=lambda x: x.element_id)
        canonical.feedback_paths.sort(key=lambda x: x.element_id)
        canonical.trust_boundaries.sort(key=lambda x: x.element_id)
        canonical.data_flows.sort(key=lambda x: x.element_id)
        canonical.loss_links.sort(key=lambda x: x.element_id)
        canonical.use_case_facts.sort(key=lambda x: x.element_id)
        canonical.assertions.sort(key=lambda x: x.element_id)

    return ResourceMapValidationResult(
        is_valid=(len(errors) == 0),
        errors=errors,
        warnings=warnings,
        correspondence_relations=[],
        canonical_map=canonical,
        network_calls=0,
        model_calls=0,
    )
