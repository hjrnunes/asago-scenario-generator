"""Pure deterministic proposal and reconciliation for hybrid correspondence.

The proposer consumes typed deterministic evidence and only emits suggestions.
The reconciler consumes a validated resource map, a proposal set, and explicit
typed adjudications. Neither function performs prose matching, repair,
inference, or provider calls.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from typing import Any

from asago_scenario_generator.models.correspondence import (
    AcceptedCorrespondenceRelation,
    AdjudicationHistoryItem,
    AdjudicationSet,
    CorrespondenceAuthority,
    CorrespondenceProposal,
    CorrespondenceSourceArtifacts,
    ProposalSet,
    ReconciledProposal,
    ReconciliationError,
    ReconciliationResult,
    SourceArtifactPins,
    compute_relation_id,
)
from asago_scenario_generator.models.system_resource_map import (
    SystemResourceMap,
    SystemResourceMapValidation,
)
from asago_scenario_generator.models.canonical import canonical_json_bytes


def _require_resource_map(validation: Any) -> SystemResourceMap:
    """Require a coherent validated-map attestation at the public seam."""
    if not isinstance(validation, SystemResourceMapValidation):
        raise TypeError("resource_map must be a SystemResourceMapValidation")
    validation = SystemResourceMapValidation.model_validate(
        validation.model_dump(mode="python")
    )
    if not validation.is_valid or validation.violations:
        raise ValueError("resource map validation contains blocking violations")
    if validation.canonical_map is None:
        raise ValueError("resource map validation has no canonical map")
    resource_map = validation.canonical_map
    resource_map.assert_integrity()
    return resource_map


def _coerce_source_artifacts(value: Any) -> CorrespondenceSourceArtifacts:
    """Parse only the typed source-artifact contract."""
    if isinstance(value, CorrespondenceSourceArtifacts):
        return value
    if isinstance(value, Mapping):
        try:
            return CorrespondenceSourceArtifacts.model_validate(value)
        except Exception as exc:  # noqa: BLE001 - typed boundary diagnostic
            raise TypeError(
                "source_artifacts must contain typed authority and deterministic evidence"
            ) from exc
    raise TypeError(
        "source_artifacts must be CorrespondenceSourceArtifacts or its typed mapping"
    )


def propose_correspondence(
    resource_map: SystemResourceMapValidation,
    source_artifacts: CorrespondenceSourceArtifacts | Mapping[str, Any],
) -> ProposalSet:
    """Emit deterministic, unconfirmed correspondence proposals.

    Every seed carries all cross-method identities and explicit evidence. The
    authority projection is retained in the proposal set so a later
    reconciliation call can validate the references without importing source
    artifact persistence modules.
    """
    resource_map = _require_resource_map(resource_map)
    source = _coerce_source_artifacts(source_artifacts)
    _require_matching_map_pin(source.authority.source_pins, resource_map)
    proposals = tuple(
        CorrespondenceProposal.from_evidence(item) for item in source.evidence
    )
    return ProposalSet(
        resource_map_semantic_digest=resource_map.semantic_digest,
        capability_snapshot_digest=resource_map.capability_snapshot_digest,
        authority=source.authority,
        proposals=proposals,
    )


def _require_matching_map_pin(
    pins: SourceArtifactPins, resource_map: SystemResourceMap
) -> None:
    """Reject source claims pinned to another resource map."""
    if pins.resource_map_semantic_digest != resource_map.semantic_digest:
        raise ValueError(
            "source artifact resource_map_semantic_digest does not match resource map"
        )
    if pins.capability_snapshot_digest != resource_map.capability_snapshot_digest:
        raise ValueError(
            "source artifact capability snapshot digest does not match resource map"
        )


def _coerce_adjudication_sequence(value: Sequence[Any]) -> AdjudicationSet:
    """Convert a sequence only after the typed boundary has been selected."""
    try:
        return AdjudicationSet(decisions=tuple(value))
    except Exception as exc:  # noqa: BLE001 - typed boundary diagnostic
        raise TypeError("adjudications must contain typed decisions") from exc


def _coerce_adjudications(value: Any) -> AdjudicationSet:
    """Require explicit typed decisions rather than a free-form mapping."""
    if value is None:
        return AdjudicationSet()
    if isinstance(value, AdjudicationSet):
        return value
    if isinstance(value, Mapping):
        raise TypeError("adjudications must be an AdjudicationSet, not a mapping")
    if _is_adjudication_sequence(value):
        return _coerce_adjudication_sequence(value)
    raise TypeError("adjudications must be an AdjudicationSet")


def _is_adjudication_sequence(value: Any) -> bool:
    """Return whether a value can be interpreted as typed decisions."""
    return type(value) in (list, tuple)


def _proposal_key(proposal: CorrespondenceProposal) -> tuple[str, ...]:
    """Return the identity used to detect contradictory relation claims."""
    return (
        proposal.obligation_id,
        proposal.ica_slot_id,
        proposal.ica_id,
        proposal.exec_candidate_id,
        *proposal.resource_link_ids,
    )


def _conflict_keys(
    proposals: Sequence[CorrespondenceProposal],
) -> set[tuple[str, ...]]:
    """Find claims with more than one proposed relation kind."""
    relation_kinds: dict[tuple[str, ...], set[str]] = defaultdict(set)
    for proposal in proposals:
        relation_kinds[_proposal_key(proposal)].add(proposal.relation_kind)
    return {key for key, values in relation_kinds.items() if len(values) > 1}


def _authority_indexes(
    authority: CorrespondenceAuthority | None,
) -> tuple[
    dict[str, Any],
    dict[tuple[str, str], Any],
    set[str],
    set[str],
]:
    """Index the explicitly supplied inventories without fallback inference."""
    if authority is None:
        return {}, {}, set(), set()
    obligations = {item.obligation_id: item for item in authority.obligations}
    findings = {
        (item.ica_slot_id, item.ica_id): item for item in authority.structural_findings
    }
    return (
        obligations,
        findings,
        set(authority.hazard_ids),
        set(authority.constraint_ids),
    )


def _error(
    proposal: CorrespondenceProposal,
    code: str,
    message: str,
    field: str | None = None,
) -> ReconciliationError:
    """Create one stable typed reconciliation diagnostic."""
    return ReconciliationError(
        proposal_id=proposal.proposal_id,
        code=code,
        message=message,
        field=field,
    )


def _pins_match(
    proposal: CorrespondenceProposal,
    authority: CorrespondenceAuthority | None,
    resource_map: SystemResourceMap,
) -> list[ReconciliationError]:
    """Validate exact source pins and map authority."""
    errors = _missing_source_pin_errors(proposal)
    errors.extend(_resource_map_pin_errors(proposal, resource_map))
    errors.extend(_authority_pin_errors(proposal, authority))
    return errors


def _missing_source_pin_errors(
    proposal: CorrespondenceProposal,
) -> list[ReconciliationError]:
    """Return one typed defect for every absent confirmation pin."""
    pins = proposal.provenance.source_pins
    required = (
        "resource_map_semantic_digest",
        "capability_snapshot_digest",
        "obligation_plan_semantic_digest",
        "control_structure_digest",
        "ica_enumeration_digest",
        "loss_analysis_digest",
        "taxonomy_version",
        "stpa_version",
    )
    return [
        _error(
            proposal,
            f"missing_{field}",
            f"confirmation requires source pin {field}",
            f"source_pins.{field}",
        )
        for field in required
        if not getattr(pins, field)
    ]


def _resource_map_pin_errors(
    proposal: CorrespondenceProposal,
    resource_map: SystemResourceMap,
) -> list[ReconciliationError]:
    """Bind one proposal to the exact validated resource map."""
    pins = proposal.provenance.source_pins
    errors = []
    if pins.resource_map_semantic_digest != resource_map.semantic_digest:
        errors.append(
            _error(
                proposal,
                "resource_map_digest_mismatch",
                "proposal source pin does not match supplied SystemResourceMap",
                "resource_map_semantic_digest",
            )
        )
    if pins.capability_snapshot_digest != resource_map.capability_snapshot_digest:
        errors.append(
            _error(
                proposal,
                "capability_snapshot_digest_mismatch",
                "proposal capability snapshot pin does not match resource map",
                "capability_snapshot_digest",
            )
        )
    return errors


def _authority_pin_errors(
    proposal: CorrespondenceProposal,
    authority: CorrespondenceAuthority | None,
) -> list[ReconciliationError]:
    """Bind one proposal to the exact typed authority inventory."""
    if authority is None or proposal.provenance.source_pins == authority.source_pins:
        return []
    return [
        _error(
            proposal,
            "source_pin_mismatch",
            "proposal source pins do not match the typed authority inventory",
            "source_pins",
        )
    ]


def _required_resource_link_errors(
    proposal: CorrespondenceProposal,
) -> list[ReconciliationError]:
    """Return the required-link diagnostic for an empty claim."""
    if proposal.resource_link_ids:
        return []
    return [
        _error(
            proposal,
            "resource_link_required",
            "correspondence requires at least one resource link",
            "resource_link_ids",
        )
    ]


def _missing_resource_link_errors(
    proposal: CorrespondenceProposal, by_id: dict[str, Any]
) -> list[ReconciliationError]:
    """Return diagnostics for links absent from the authoritative map."""
    return [
        _error(
            proposal,
            "dangling_resource_link",
            f"resource link {link_id} is not present in SystemResourceMap",
            "resource_link_ids",
        )
        for link_id in sorted(set(proposal.resource_link_ids) - set(by_id))
    ]


def _link_authority_errors(
    proposal: CorrespondenceProposal, link_id: str, link: Any
) -> list[ReconciliationError]:
    """Return diagnostics for one referenced link's authority status."""
    errors: list[ReconciliationError] = []
    if link.authority_status != "authoritative":
        errors.append(
            _error(
                proposal,
                "non_authoritative_resource_link",
                f"resource link {link_id} is not authoritative",
                "resource_link_ids",
            )
        )
    if link.provenance == "model_proposed":
        errors.append(
            _error(
                proposal,
                "model_proposed_resource_link",
                f"resource link {link_id} was model-proposed and cannot confirm correspondence",
                "resource_link_ids",
            )
        )
    return errors


def _referenced_link_authority_errors(
    proposal: CorrespondenceProposal, by_id: dict[str, Any]
) -> list[ReconciliationError]:
    """Return authority diagnostics for links that exist."""
    errors: list[ReconciliationError] = []
    for link_id in sorted(set(proposal.resource_link_ids) & set(by_id)):
        errors.extend(_link_authority_errors(proposal, link_id, by_id[link_id]))
    return errors


def _ica_path_link_errors(
    proposal: CorrespondenceProposal, finding: Any
) -> list[ReconciliationError]:
    """Reject links outside the authoritative ICA path."""
    if finding is None:
        return []
    if not finding.resource_link_ids:
        return [
            _error(
                proposal,
                "missing_ica_path_resource_authority",
                "the authoritative ICA path has no resource-link bridge",
                "resource_link_ids",
            )
        ]
    if not set(proposal.resource_link_ids) - set(finding.resource_link_ids):
        return []
    return [
        _error(
            proposal,
            "resource_link_not_on_ica_path",
            "proposal cites links absent from the authoritative ICA path",
            "resource_link_ids",
        )
    ]


def _obligation_link_errors(
    proposal: CorrespondenceProposal,
    by_id: dict[str, Any],
    obligation: Any,
) -> list[ReconciliationError]:
    """Require a cited link to connect an obligation resource when pinned."""
    if obligation is None:
        return []
    if not obligation.candidate_resource_refs:
        return [
            _error(
                proposal,
                "missing_candidate_resource_authority",
                "the obligation has no authoritative candidate resource identity",
                "resource_link_ids",
            )
        ]
    matching_refs = _matching_link_refs(proposal, by_id)
    required_refs = _required_obligation_refs(obligation)
    if matching_refs & required_refs:
        return []
    return [
        _error(
            proposal,
            "resource_link_not_required_by_obligation",
            "resource links do not connect a resource required by the obligation",
            "resource_link_ids",
        )
    ]


def _matching_link_refs(
    proposal: CorrespondenceProposal, by_id: dict[str, Any]
) -> set[bytes]:
    """Return canonical capability references for cited map links."""
    return {
        canonical_json_bytes(link.capability_resource_ref.model_dump(mode="json"))
        for link in by_id.values()
        if link.link_id in proposal.resource_link_ids
    }


def _required_obligation_refs(obligation: Any) -> set[bytes]:
    """Return canonical capability references required by an obligation."""
    return {
        canonical_json_bytes(reference.model_dump(mode="json"))
        for reference in obligation.candidate_resource_refs
    }


def _validate_resource_links(
    proposal: CorrespondenceProposal,
    resource_map: SystemResourceMap,
    finding: Any,
    obligation: Any,
) -> list[ReconciliationError]:
    """Validate link existence, authority, and structural bridge evidence."""
    required = _required_resource_link_errors(proposal)
    if required:
        return required
    by_id = {item.link_id: item for item in resource_map.links}
    errors = _missing_resource_link_errors(proposal, by_id)
    errors.extend(_referenced_link_authority_errors(proposal, by_id))
    errors.extend(_ica_path_link_errors(proposal, finding))
    errors.extend(_obligation_link_errors(proposal, by_id, obligation))
    return errors


def _missing_authority_error(
    proposal: CorrespondenceProposal,
) -> ReconciliationError:
    """Describe the absence of authoritative inventories."""
    return _error(
        proposal,
        "missing_authority_inventory",
        "confirmation requires typed Phase 1 and STPA authority inventories",
    )


def _obligation_identity_errors(
    proposal: CorrespondenceProposal, obligation: Any
) -> list[ReconciliationError]:
    """Validate the Phase 1 obligation identity and disposition."""
    if obligation is None:
        return [
            _error(
                proposal,
                "dangling_obligation",
                f"obligation {proposal.obligation_id} is not in the Phase 1 inventory",
                "obligation_id",
            )
        ]
    if obligation.scope_disposition != "applicable":
        return [
            _error(
                proposal,
                "obligation_not_applicable",
                "only applicable Phase 1 obligations can be confirmed",
                "obligation_id",
            )
        ]
    errors: list[ReconciliationError] = []
    expected = (
        (proposal.risk_id, obligation.risk_id, "risk_id"),
        (
            proposal.attack_pattern_id,
            obligation.attack_pattern_id,
            "attack_pattern_id",
        ),
        (
            proposal.taxonomy_candidate_ids,
            obligation.taxonomy_candidate_ids,
            "taxonomy_candidate_ids",
        ),
    )
    for supplied, authoritative, field in expected:
        if supplied != authoritative:
            errors.append(
                _error(
                    proposal,
                    f"{field}_mismatch",
                    f"{field} does not match the authoritative obligation",
                    field,
                )
            )
    return errors


def _exec_identity_errors(
    proposal: CorrespondenceProposal, finding: Any
) -> list[ReconciliationError]:
    """Validate canonical and authoritative EXEC identities."""
    errors: list[ReconciliationError] = []
    expected_exec = _expected_exec_id(proposal.ica_slot_id)
    if expected_exec != proposal.exec_candidate_id:
        errors.append(
            _error(
                proposal,
                "exec_identity_mismatch",
                f"exec_candidate_id must be {expected_exec} for this slot",
                "exec_candidate_id",
            )
        )
    if finding.exec_candidate_id != proposal.exec_candidate_id:
        errors.append(
            _error(
                proposal,
                "exec_inventory_mismatch",
                "exec_candidate_id does not match the authoritative ICA record",
                "exec_candidate_id",
            )
        )
    return errors


def _ica_reference_errors(
    proposal: CorrespondenceProposal, finding: Any
) -> list[ReconciliationError]:
    """Validate hazard and constraint references against the ICA record."""
    errors: list[ReconciliationError] = []
    for value, allowed, field in (
        (proposal.hazard_ids, set(finding.hazard_ids), "hazard_ids"),
        (proposal.constraint_ids, set(finding.constraint_ids), "constraint_ids"),
    ):
        for identifier in sorted(set(value) - allowed):
            errors.append(
                _error(
                    proposal,
                    "reference_not_on_ica",
                    f"{field[:-4]} {identifier} is not referenced by the ICA",
                    field,
                )
            )
    return errors


def _structural_identity_errors(
    proposal: CorrespondenceProposal, finding: Any
) -> list[ReconciliationError]:
    """Validate existence and exact EXEC/ICA identity."""
    if finding is None:
        return [
            _error(
                proposal,
                "dangling_structural_finding",
                "ICA slot and ICA identity are absent from the STPA inventory",
                "ica_id",
            )
        ]
    return _exec_identity_errors(proposal, finding) + _ica_reference_errors(
        proposal, finding
    )


def _global_reference_errors(
    proposal: CorrespondenceProposal,
    hazard_ids: set[str],
    constraint_ids: set[str],
) -> list[ReconciliationError]:
    """Validate references against global loss and constraint inventories."""
    errors: list[ReconciliationError] = []
    for identifier in sorted(set(proposal.hazard_ids) - hazard_ids):
        errors.append(
            _error(
                proposal,
                "dangling_hazard",
                f"hazard {identifier} is not in the authoritative loss inventory",
                "hazard_ids",
            )
        )
    for identifier in sorted(set(proposal.constraint_ids) - constraint_ids):
        errors.append(
            _error(
                proposal,
                "dangling_constraint",
                f"constraint {identifier} is not in the authoritative loss inventory",
                "constraint_ids",
            )
        )
    return errors


def _validate_identity(
    proposal: CorrespondenceProposal,
    authority: CorrespondenceAuthority | None,
    obligations: dict[str, Any],
    findings: dict[tuple[str, str], Any],
    hazard_ids: set[str],
    constraint_ids: set[str],
) -> tuple[list[ReconciliationError], Any, Any]:
    """Validate all typed obligation, ICA, EXEC, hazard, and constraint IDs."""
    obligation = obligations.get(proposal.obligation_id)
    finding = findings.get((proposal.ica_slot_id, proposal.ica_id))
    if authority is None:
        return [_missing_authority_error(proposal)], obligation, finding
    errors = _obligation_identity_errors(proposal, obligation)
    errors.extend(_structural_identity_errors(proposal, finding))
    errors.extend(_global_reference_errors(proposal, hazard_ids, constraint_ids))
    if not authority.inventory_complete:
        errors.append(
            _error(
                proposal,
                "incomplete_authority_inventory",
                "incomplete inventories cannot establish confirmed correspondence",
            )
        )
    return errors, obligation, finding


def _expected_exec_id(ica_slot_id: str) -> str:
    """Derive the canonical structural EXEC identity from a slot."""
    parts = ica_slot_id.split(":")
    if len(parts) < 3:
        return "EXEC::"
    return f"EXEC:{parts[0]}:{parts[1]}:{parts[2]}"


def _validate_proposal(
    proposal: CorrespondenceProposal,
    resource_map: SystemResourceMap,
    authority: CorrespondenceAuthority | None,
) -> tuple[list[ReconciliationError], Any, Any]:
    """Run the fail-closed validation matrix for one proposal."""
    obligations, findings, hazard_ids, constraint_ids = _authority_indexes(authority)
    errors, obligation, finding = _validate_identity(
        proposal,
        authority,
        obligations,
        findings,
        hazard_ids,
        constraint_ids,
    )
    errors.extend(_pins_match(proposal, authority, resource_map))
    errors.extend(_validate_resource_links(proposal, resource_map, finding, obligation))
    if not proposal.provenance.evidence_refs:
        errors.append(
            _error(
                proposal,
                "evidence_required",
                "confirmation requires non-empty deterministic evidence_refs",
                "provenance.evidence_refs",
            )
        )
    return errors, obligation, finding


def _decision_for(
    adjudications: dict[str, Any], proposal: CorrespondenceProposal
) -> tuple[str, AdjudicationHistoryItem]:
    """Select one explicit decision, defaulting to an auditable unresolved state."""
    decision = adjudications.get(proposal.proposal_id)
    if decision is None:
        return (
            "unresolved",
            AdjudicationHistoryItem(
                status="unresolved",
                reason="no explicit adjudication supplied",
                adjudicated_by="system",
            ),
        )
    return (
        decision.status,
        AdjudicationHistoryItem(
            status=decision.status,
            reason=decision.reason,
            adjudicated_by=decision.adjudicated_by,
            evidence_refs=decision.evidence_refs,
        ),
    )


def _reconciled_proposal(
    proposal: CorrespondenceProposal,
    requested_status: str,
    history: AdjudicationHistoryItem,
    defects: Sequence[ReconciliationError],
    conflict: bool,
) -> ReconciledProposal:
    """Build one immutable audit record from validation and adjudication."""
    status, validation_result = _reconciliation_outcome(
        requested_status, defects, conflict
    )
    return ReconciledProposal(
        proposal_id=proposal.proposal_id,
        obligation_id=proposal.obligation_id,
        risk_id=proposal.risk_id,
        attack_pattern_id=proposal.attack_pattern_id,
        taxonomy_candidate_ids=proposal.taxonomy_candidate_ids,
        ica_slot_id=proposal.ica_slot_id,
        ica_id=proposal.ica_id,
        exec_candidate_id=proposal.exec_candidate_id,
        relation_kind=proposal.relation_kind,
        resource_link_ids=proposal.resource_link_ids,
        hazard_ids=proposal.hazard_ids,
        constraint_ids=proposal.constraint_ids,
        provenance=proposal.provenance,
        confidence=proposal.confidence,
        evidence_strength=proposal.evidence_strength,
        status=status,
        validation_result=validation_result,
        validation_codes=tuple(item.code for item in defects)
        + (("conflict",) if conflict else ()),
        adjudication_history=(history,),
    )


def _reconciliation_outcome(
    requested_status: str,
    defects: Sequence[ReconciliationError],
    conflict: bool,
) -> tuple[str, str]:
    """Separate adjudication state from deterministic validation outcome."""
    if conflict:
        return "unresolved", "unresolved"
    if defects:
        return "rejected", "rejected"
    return requested_status, "accepted"


def _accepted_relation(
    proposal: CorrespondenceProposal,
) -> AcceptedCorrespondenceRelation:
    """Materialize one accepted relation after all checks have passed."""
    from asago_scenario_generator.models.correspondence import compute_relation_id

    relation_id = compute_relation_id(
        obligation_id=proposal.obligation_id,
        ica_slot_id=proposal.ica_slot_id,
        ica_id=proposal.ica_id,
        exec_candidate_id=proposal.exec_candidate_id,
        relation_kind=proposal.relation_kind,
        resource_link_ids=proposal.resource_link_ids,
    )
    return AcceptedCorrespondenceRelation(
        relation_id=relation_id,
        proposal_id=proposal.proposal_id,
        obligation_id=proposal.obligation_id,
        risk_id=proposal.risk_id,
        attack_pattern_id=proposal.attack_pattern_id,
        taxonomy_candidate_ids=proposal.taxonomy_candidate_ids,
        ica_slot_id=proposal.ica_slot_id,
        ica_id=proposal.ica_id,
        exec_candidate_id=proposal.exec_candidate_id,
        relation_kind=proposal.relation_kind,
        resource_link_ids=proposal.resource_link_ids,
        hazard_ids=proposal.hazard_ids,
        constraint_ids=proposal.constraint_ids,
        evidence_refs=proposal.provenance.evidence_refs,
        source_pins=proposal.provenance.source_pins,
    )


def _validate_proposal_set(
    resource_map: SystemResourceMap, proposals: ProposalSet
) -> None:
    """Require an intact proposal set pinned to the supplied map."""
    if not isinstance(proposals, ProposalSet):
        raise TypeError("proposals must be a ProposalSet")
    proposals.assert_integrity()
    if proposals.resource_map_semantic_digest != resource_map.semantic_digest:
        raise ValueError("proposal set is pinned to a different resource map")
    if proposals.capability_snapshot_digest != resource_map.capability_snapshot_digest:
        raise ValueError("proposal set is pinned to a different capability snapshot")


def _decision_index(
    proposals: ProposalSet, adjudications: AdjudicationSet | Sequence[Any] | None
) -> dict[str, Any]:
    """Index typed decisions and reject decisions for unknown proposals."""
    decisions = _coerce_adjudications(adjudications)
    decision_by_id = {item.proposal_id: item for item in decisions.decisions}
    unknown_decisions = {item.proposal_id for item in decisions.decisions} - {
        item.proposal_id for item in proposals.proposals
    }
    if unknown_decisions:
        raise ValueError(
            "adjudication references unknown proposal IDs: "
            + ", ".join(sorted(unknown_decisions))
        )
    return decision_by_id


def _conflict_errors(
    proposal: CorrespondenceProposal, is_conflict: bool
) -> list[ReconciliationError]:
    """Keep contradictory relation proposals unresolved."""
    if not is_conflict:
        return []
    return [
        _error(
            proposal,
            "conflicting_relation_proposals",
            "conflicting relation kinds remain unresolved",
            "relation_kind",
        )
    ]


def _relation_id(proposal: CorrespondenceProposal) -> str:
    """Return the accepted-relation identity implied by one proposal."""
    return compute_relation_id(
        obligation_id=proposal.obligation_id,
        ica_slot_id=proposal.ica_slot_id,
        ica_id=proposal.ica_id,
        exec_candidate_id=proposal.exec_candidate_id,
        relation_kind=proposal.relation_kind,
        resource_link_ids=proposal.resource_link_ids,
    )


def _duplicate_confirmed_relation_ids(
    proposals: Sequence[CorrespondenceProposal],
    decisions: Mapping[str, Any],
) -> set[str]:
    """Return semantic relations claimed by multiple explicit confirmations."""
    confirmed = (
        _relation_id(proposal)
        for proposal in proposals
        if getattr(decisions.get(proposal.proposal_id), "status", None) == "confirmed"
    )
    counts: dict[str, int] = defaultdict(int)
    for relation_id in confirmed:
        counts[relation_id] += 1
    return {relation_id for relation_id, count in counts.items() if count > 1}


def _duplicate_relation_errors(
    proposal: CorrespondenceProposal,
    duplicate_relation_ids: set[str],
) -> list[ReconciliationError]:
    """Reject each confirmation participating in a duplicate semantic relation."""
    if _relation_id(proposal) not in duplicate_relation_ids:
        return []
    return [
        _error(
            proposal,
            "duplicate_confirmed_relation",
            "multiple confirmed proposals claim the same semantic relation",
            "relation_id",
        )
    ]


def _proposal_defects(
    proposal: CorrespondenceProposal,
    resource_map: SystemResourceMap,
    authority: CorrespondenceAuthority | None,
    requested_status: str,
    is_conflict: bool,
    duplicate_relation_ids: set[str],
) -> list[ReconciliationError]:
    """Collect deterministic and adjudication-specific defects."""
    defects, _, _ = _validate_proposal(proposal, resource_map, authority)
    defects.extend(_conflict_errors(proposal, is_conflict))
    if requested_status == "confirmed":
        defects.extend(_duplicate_relation_errors(proposal, duplicate_relation_ids))
    return defects


def _reconcile_one(
    proposal: CorrespondenceProposal,
    resource_map: SystemResourceMap,
    authority: CorrespondenceAuthority | None,
    decision_by_id: dict[str, Any],
    conflict_keys: set[tuple[str, ...]],
    duplicate_relation_ids: set[str],
) -> tuple[
    ReconciledProposal, list[ReconciliationError], AcceptedCorrespondenceRelation | None
]:
    """Validate, audit, and optionally materialize one proposal."""
    requested, history = _decision_for(decision_by_id, proposal)
    conflict = _proposal_key(proposal) in conflict_keys
    defects = _proposal_defects(
        proposal,
        resource_map,
        authority,
        requested,
        conflict,
        duplicate_relation_ids,
    )
    accepted = (
        _accepted_relation(proposal)
        if requested == "confirmed" and not defects
        else None
    )
    reconciled = _reconciled_proposal(proposal, requested, history, defects, conflict)
    return reconciled, defects, accepted


def reconcile_correspondence(
    resource_map: SystemResourceMapValidation,
    proposals: ProposalSet,
    adjudications: AdjudicationSet | Sequence[Any] | None = None,
) -> ReconciliationResult:
    """Reconcile typed proposals under explicit human adjudications.

    The returned result retains every proposal, including rejected and
    unresolved records. A proposal can become a confirmed relation only when
    its explicit adjudication is ``confirmed`` and every deterministic
    authority/evidence check succeeds.
    """
    resource_map = _require_resource_map(resource_map)
    _validate_proposal_set(resource_map, proposals)
    decision_by_id = _decision_index(proposals, adjudications)
    conflict_keys = _conflict_keys(proposals.proposals)
    duplicate_relation_ids = _duplicate_confirmed_relation_ids(
        proposals.proposals, decision_by_id
    )
    errors: list[ReconciliationError] = []
    reconciled: list[ReconciledProposal] = []
    accepted: dict[str, AcceptedCorrespondenceRelation] = {}
    for proposal in proposals.proposals:
        item, defects, accepted_relation = _reconcile_one(
            proposal,
            resource_map,
            proposals.authority,
            decision_by_id,
            conflict_keys,
            duplicate_relation_ids,
        )
        if defects:
            errors.extend(defects)
        if accepted_relation is not None:
            accepted.setdefault(accepted_relation.relation_id, accepted_relation)
        reconciled.append(item)
    return ReconciliationResult(
        resource_map_semantic_digest=resource_map.semantic_digest,
        capability_snapshot_digest=resource_map.capability_snapshot_digest,
        is_valid=not errors,
        proposals=tuple(reconciled),
        accepted_relations=tuple(accepted.values()),
        errors=tuple(errors),
    )


__all__ = ["propose_correspondence", "reconcile_correspondence"]
