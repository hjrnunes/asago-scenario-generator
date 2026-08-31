"""Deterministic exact-resource evidence for correspondence review.

This adapter identifies shared resource-map witnesses.  It deliberately emits
only ``related_but_not_coverage`` suggestions: a shared boundary or resource
does not establish that a taxonomy mechanism and an ICA mean the same thing.
"""

from __future__ import annotations

from typing import Any

from asago_scenario_generator.models.canonical import canonical_json_bytes
from asago_scenario_generator.models.correspondence import (
    CandidateAuthorityRecord,
    CorrespondenceAuthority,
    CorrespondenceEvidence,
)
from asago_scenario_generator.models.system_resource_map import (
    SystemResourceMap,
    SystemResourceMapValidation,
)


def _validated_map(validation: Any) -> SystemResourceMap:
    """Require one successful, intact public map-validation attestation."""
    if not isinstance(validation, SystemResourceMapValidation):
        raise TypeError("resource_map must be a SystemResourceMapValidation")
    validation = SystemResourceMapValidation.model_validate(
        validation.model_dump(mode="python")
    )
    if not validation.is_valid or validation.violations:
        raise ValueError("resource map validation contains blocking violations")
    if validation.canonical_map is None:
        raise ValueError("resource map validation has no canonical map")
    validation.canonical_map.assert_integrity()
    return validation.canonical_map


def _validated_authority(value: Any) -> CorrespondenceAuthority:
    """Require a complete typed authority inventory."""
    if not isinstance(value, CorrespondenceAuthority):
        raise TypeError("authority must be a CorrespondenceAuthority")
    authority = CorrespondenceAuthority.model_validate(value.model_dump(mode="python"))
    if not authority.inventory_complete:
        raise ValueError(
            "resource-link evidence requires a complete authority inventory"
        )
    return authority


def _require_matching_pins(
    resource_map: SystemResourceMap, authority: CorrespondenceAuthority
) -> None:
    """Bind evidence derivation to the exact validated map."""
    pins = authority.source_pins
    if pins.resource_map_semantic_digest != resource_map.semantic_digest:
        raise ValueError("authority is pinned to a different resource map")
    if pins.capability_snapshot_digest != resource_map.capability_snapshot_digest:
        raise ValueError("authority is pinned to a different capability snapshot")


def _resource_key(value: Any) -> bytes:
    """Return the canonical identity of one capability resource reference."""
    return canonical_json_bytes(value.model_dump(mode="json"))


def _projectable_candidates(obligation: Any) -> tuple[CandidateAuthorityRecord, ...]:
    """Return only candidates with an authoritative usable projection."""
    return tuple(
        item
        for item in obligation.candidates
        if item.projection_disposition == "projectable" and item.resource_bindings
    )


def _authoritative_links(resource_map: SystemResourceMap) -> tuple[Any, ...]:
    """Return accepted deterministic/operator links in canonical order."""
    return tuple(
        sorted(
            (
                item
                for item in resource_map.links
                if item.authority_status == "authoritative"
                and item.provenance != "model_proposed"
            ),
            key=lambda item: item.link_id,
        )
    )


def _candidate_touches_link(candidate: CandidateAuthorityRecord, link: Any) -> bool:
    """Return whether a link touches this candidate's own exact binding."""
    link_key = _resource_key(link.capability_resource_ref)
    return any(
        _resource_key(item.resource_ref) == link_key
        for item in candidate.resource_bindings
    )


def _evidence_for_witness(
    obligation: Any,
    candidate: CandidateAuthorityRecord,
    finding: Any,
    link: Any,
    authority: CorrespondenceAuthority,
    *,
    proposer_id: str,
    proposer_version: str,
) -> CorrespondenceEvidence:
    """Build one review-only association from one exact candidate/link witness."""
    confidence = link.confidence if link.confidence is not None else 0.5
    strength = "high" if link.provenance == "operator_declared" else "medium"
    return CorrespondenceEvidence(
        obligation_id=obligation.obligation_id,
        risk_id=obligation.risk_id,
        attack_pattern_id=obligation.attack_pattern_id,
        taxonomy_candidate_ids=obligation.taxonomy_candidate_ids,
        selected_candidate_id=candidate.candidate_id,
        ica_slot_id=finding.ica_slot_id,
        ica_id=finding.ica_id,
        exec_candidate_id=finding.exec_candidate_id,
        relation_kind="related_but_not_coverage",
        resource_link_ids=(link.link_id,),
        hazard_ids=finding.hazard_ids,
        constraint_ids=finding.constraint_ids,
        evidence_source="accepted_resource_link",
        evidence_refs=(
            f"candidate:{candidate.candidate_id}",
            f"resource-link:{link.link_id}",
        ),
        confidence=confidence,
        evidence_strength=strength,
        proposer_id=proposer_id,
        proposer_version=proposer_version,
        source_pins=authority.source_pins,
        rationale=(
            "The selected taxonomy candidate and STPA path share one accepted "
            "resource-map link; semantic correspondence remains unassessed."
        ),
    )


def _candidate_links(
    candidate: CandidateAuthorityRecord, links: tuple[Any, ...]
) -> tuple[Any, ...]:
    """Return accepted links touching one candidate's exact bindings."""
    return tuple(item for item in links if _candidate_touches_link(candidate, item))


def _link_findings(link: Any, findings: tuple[Any, ...]) -> tuple[Any, ...]:
    """Return exact ICA records whose authoritative path contains one link."""
    return tuple(item for item in findings if link.link_id in item.resource_link_ids)


def _candidate_evidence(
    obligation: Any,
    candidate: CandidateAuthorityRecord,
    links: tuple[Any, ...],
    findings: tuple[Any, ...],
    authority: CorrespondenceAuthority,
    *,
    proposer_id: str,
    proposer_version: str,
) -> tuple[CorrespondenceEvidence, ...]:
    """Derive all exact link/path witnesses for one projectable candidate."""
    evidence = []
    for link in _candidate_links(candidate, links):
        evidence.extend(
            _evidence_for_witness(
                obligation,
                candidate,
                finding,
                link,
                authority,
                proposer_id=proposer_id,
                proposer_version=proposer_version,
            )
            for finding in _link_findings(link, findings)
        )
    return tuple(evidence)


def _obligation_evidence(
    obligation: Any,
    links: tuple[Any, ...],
    findings: tuple[Any, ...],
    authority: CorrespondenceAuthority,
    *,
    proposer_id: str,
    proposer_version: str,
) -> tuple[CorrespondenceEvidence, ...]:
    """Derive exact witnesses for one applicable taxonomy obligation."""
    if obligation.scope_disposition != "applicable" or not obligation.attack_pattern_id:
        return ()
    evidence = []
    for candidate in _projectable_candidates(obligation):
        evidence.extend(
            _candidate_evidence(
                obligation,
                candidate,
                links,
                findings,
                authority,
                proposer_id=proposer_id,
                proposer_version=proposer_version,
            )
        )
    return tuple(evidence)


def derive_resource_link_correspondence_evidence(
    resource_map: SystemResourceMapValidation,
    authority: CorrespondenceAuthority,
    *,
    proposer_id: str = "deterministic-resource-link-v1",
    proposer_version: str = "1",
) -> tuple[CorrespondenceEvidence, ...]:
    """Derive order-independent, noncoverage evidence from exact witnesses."""
    canonical_map = _validated_map(resource_map)
    authority = _validated_authority(authority)
    _require_matching_pins(canonical_map, authority)
    links = _authoritative_links(canonical_map)
    findings = tuple(
        sorted(
            authority.structural_findings,
            key=lambda item: (item.ica_slot_id, item.ica_id),
        )
    )
    evidence: dict[bytes, CorrespondenceEvidence] = {}
    for obligation in authority.obligations:
        for item in _obligation_evidence(
            obligation,
            links,
            findings,
            authority,
            proposer_id=proposer_id,
            proposer_version=proposer_version,
        ):
            evidence[canonical_json_bytes(item.model_dump(mode="json"))] = item
    return tuple(evidence[key] for key in sorted(evidence))
