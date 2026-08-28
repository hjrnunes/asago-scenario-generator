"""Deterministic correspondence proposal and reconciliation pipeline."""

from __future__ import annotations

from typing import Any, Sequence

from asago_scenario_generator.models.correspondence import (
    AdjudicationHistoryItem,
    CorrespondenceProposal,
    ProposalSet,
    ReconciliationError,
    ReconciliationResult,
    ReconciledProposal,
)
from asago_scenario_generator.models.system_resource_map import (
    ResourceMapSnapshot,
    SystemResourceMap,
)

# SystemResourceMap collections contributing element ids, with the attribute
# holding each entry's taxonomy reference (if any).
_SRM_ELEMENT_COLLECTIONS = (
    ("system_resources", "taxonomy_ref"),
    ("actor_controllers", None),
    ("controlled_processes", None),
    ("control_actions", None),
    ("feedback_paths", None),
    ("trust_boundaries", "taxonomy_ref"),
    ("data_flows", None),
    ("use_case_facts", None),
    ("assertions", None),
)

# Evidence source -> (default strength, default relation type).
_EVIDENCE_SOURCE_DEFAULTS = {
    "exact-id": ("high", "supports"),
    "curated-map": ("high", "addresses"),
    "resource-overlap": ("weak", "overlaps"),
    "heuristic": ("weak", "supports"),
    "model-assisted": ("weak", "supports"),
}


def _extract_versions_and_identifiers(
    resource_map: SystemResourceMap | ResourceMapSnapshot | dict[str, Any],
) -> tuple[str, str, set[str], set[str]]:
    """Extract pinned versions and valid STPA / taxonomy identifiers from resource map."""
    stpa_version = ""
    taxonomy_version = ""
    stpa_ids: set[str] = set()
    tax_ids: set[str] = set()

    if isinstance(resource_map, SystemResourceMap):
        stpa_version = str(resource_map.stpa_version)
        taxonomy_version = str(resource_map.taxonomy_version)

        for collection, taxonomy_field in _SRM_ELEMENT_COLLECTIONS:
            for entry in getattr(resource_map, collection):
                stpa_ids.add(entry.element_id)
                if taxonomy_field:
                    taxonomy_ref = getattr(entry, taxonomy_field)
                    if taxonomy_ref:
                        tax_ids.add(taxonomy_ref)
        for ll in resource_map.loss_links:
            stpa_ids.add(ll.element_id)
            if ll.loss_id:
                stpa_ids.add(ll.loss_id)
            if ll.hazard_id:
                stpa_ids.add(ll.hazard_id)

    elif isinstance(resource_map, ResourceMapSnapshot):
        stpa_version = str(resource_map.stpa_version)
        taxonomy_version = str(resource_map.taxonomy_version)
        stpa_ids.update(resource_map.stpa_identifiers)
        tax_ids.update(resource_map.taxonomy_identifiers)

    elif isinstance(resource_map, dict):
        stpa_version = str(resource_map.get("stpa_version", ""))
        taxonomy_version = str(resource_map.get("taxonomy_version", ""))
        stpa_ids.update(resource_map.get("stpa_identifiers", []))
        tax_ids.update(resource_map.get("taxonomy_identifiers", []))

    return stpa_version, taxonomy_version, stpa_ids, tax_ids


def _proposal_from_evidence(
    item: dict[str, Any],
    index: int,
    stpa_version: str,
    taxonomy_version: str,
) -> CorrespondenceProposal:
    """Build one proposal from a raw evidence item, applying source defaults."""
    prop_id = item.get("proposal_id", f"P-{index}")
    left_ref = item.get("left_ref", "")
    right_ref = item.get("right_ref", "")
    evidence_source = item.get("evidence_source", "exact-id")
    adapter_kind = item.get("adapter_kind", None)

    defaults = _EVIDENCE_SOURCE_DEFAULTS.get(evidence_source)
    if defaults is None:
        # Unknown sources default to high/supports unless an adapter vouches.
        defaults = ("weak", "supports") if adapter_kind else ("high", "supports")
    default_strength, default_rel = defaults

    return CorrespondenceProposal(
        proposal_id=prop_id,
        left_ref=left_ref,
        right_ref=right_ref,
        relation_type=item.get("relation_type", default_rel),
        evidence_source=evidence_source,
        strength=item.get("strength", default_strength),
        proposer_id=item.get("proposer_id", ""),
        proposer_version=item.get("proposer_version", "1"),
        evidence_refs=item.get(
            "evidence_refs",
            [left_ref, right_ref] if left_ref and right_ref else [],
        ),
        stpa_version=item.get("stpa_version", stpa_version),
        taxonomy_version=item.get("taxonomy_version", taxonomy_version),
        rationale=item.get("rationale", ""),
        is_confirmed=False,
    )


def propose_correspondence(
    resource_map: SystemResourceMap | ResourceMapSnapshot | dict[str, Any],
    source_artifacts: Any = None,
) -> ProposalSet:
    """Generate deterministic correspondence proposals from resource map and source artifacts.

    Proposers and adapters participate only through the evidence items in
    ``source_artifacts``; no proposal is ever confirmed at proposal time.
    """
    stpa_version, taxonomy_version, _, _ = _extract_versions_and_identifiers(
        resource_map
    )

    proposals: list[CorrespondenceProposal] = []

    if isinstance(source_artifacts, dict) and "evidence" in source_artifacts:
        for idx, item in enumerate(source_artifacts["evidence"], 1):
            proposals.append(
                _proposal_from_evidence(item, idx, stpa_version, taxonomy_version)
            )

    # Sort proposals canonically by proposal_id
    proposals.sort(key=lambda p: p.proposal_id)

    return ProposalSet(
        schema_version="1",
        stpa_version=stpa_version,
        taxonomy_version=taxonomy_version,
        proposals=proposals,
    )


def _conflict_pairs(
    sorted_proposals: Sequence[CorrespondenceProposal | ReconciledProposal],
) -> set[tuple[str, str]]:
    """Detect (left_ref, right_ref) pairs whose proposals disagree."""
    pairs: dict[tuple[str, str], list[CorrespondenceProposal | ReconciledProposal]] = {}
    for p in sorted_proposals:
        key = (p.left_ref, p.right_ref)
        pairs.setdefault(key, []).append(p)

    conflict_pairs: set[tuple[str, str]] = set()
    for key, group in pairs.items():
        if len(group) > 1:
            rel_types = {p.relation_type for p in group}
            if len(rel_types) > 1 or "contradicts" in rel_types:
                conflict_pairs.add(key)
    return conflict_pairs


def _confirmation_errors(
    prop_id: str,
    left_ref: str,
    right_ref: str,
    prop_stpa_v: str,
    prop_tax_v: str,
    evidence_source: str,
    evidence_refs: list[str],
    stpa_version: str,
    taxonomy_version: str,
    valid_stpa_ids: set[str],
    valid_tax_ids: set[str],
) -> list[ReconciliationError]:
    """Collect the defects that block confirming one proposal."""
    errors: list[ReconciliationError] = []

    if valid_stpa_ids and left_ref not in valid_stpa_ids:
        errors.append(
            ReconciliationError(
                proposal_id=prop_id,
                error_code="dangling_reference",
                message=f"Proposal {prop_id} has dangling left reference {left_ref}",
            )
        )

    if valid_tax_ids and right_ref not in valid_tax_ids:
        errors.append(
            ReconciliationError(
                proposal_id=prop_id,
                error_code="dangling_reference",
                message=f"Proposal {prop_id} has dangling right reference {right_ref}",
            )
        )

    if stpa_version and prop_stpa_v and prop_stpa_v != stpa_version:
        errors.append(
            ReconciliationError(
                proposal_id=prop_id,
                error_code="source_version_mismatch",
                message=f"Proposal {prop_id} STPA version {prop_stpa_v} does not match {stpa_version}",
            )
        )
    elif taxonomy_version and prop_tax_v and prop_tax_v != taxonomy_version:
        errors.append(
            ReconciliationError(
                proposal_id=prop_id,
                error_code="source_version_mismatch",
                message=f"Proposal {prop_id} taxonomy version {prop_tax_v} does not match {taxonomy_version}",
            )
        )

    if (
        not evidence_source
        or evidence_source in ("none", "evidence-free")
        or not evidence_refs
    ):
        errors.append(
            ReconciliationError(
                proposal_id=prop_id,
                error_code="evidence_required",
                message=f"Proposal {prop_id} lacks explicit evidence required for confirmation",
            )
        )

    return errors


def _adjudication_history(
    p: CorrespondenceProposal | ReconciledProposal,
    target_adj: str,
    conflict_reason: str | None,
) -> list[AdjudicationHistoryItem]:
    """Carry forward the proposal's history and append the new adjudication."""
    history_items: list[AdjudicationHistoryItem] = []
    if hasattr(p, "adjudication_history") and p.adjudication_history:
        history_items.extend(p.adjudication_history)
    new_reason = conflict_reason or ("confirmed" if target_adj == "confirmed" else None)
    if not history_items or history_items[-1].adjudication != target_adj:
        history_items.append(
            AdjudicationHistoryItem(
                adjudication=target_adj,
                reason=new_reason,
            )
        )
    return history_items


def reconcile_correspondence(
    resource_map: SystemResourceMap | ResourceMapSnapshot | dict[str, Any],
    proposals: ProposalSet | Sequence[CorrespondenceProposal | ReconciledProposal],
    adjudications: dict[str, str] | None = None,
) -> ReconciliationResult:
    """Deterministically reconcile proposals into confirmed, rejected, or unresolved states."""
    stpa_version, taxonomy_version, valid_stpa_ids, valid_tax_ids = (
        _extract_versions_and_identifiers(resource_map)
    )

    if adjudications is None:
        adjudications = {}

    raw_list = (
        proposals.proposals if isinstance(proposals, ProposalSet) else list(proposals)
    )

    # Sort proposals canonically by proposal_id to ensure presentation order independence
    sorted_proposals = sorted(raw_list, key=lambda p: p.proposal_id)

    conflict_pairs = _conflict_pairs(sorted_proposals)

    errors: list[ReconciliationError] = []
    reconciled_proposals: list[ReconciledProposal] = []
    is_valid = True

    for p in sorted_proposals:
        prop_id = p.proposal_id
        left_ref = p.left_ref
        right_ref = p.right_ref
        evidence_source = getattr(p, "evidence_source", "exact-id")
        evidence_refs = getattr(p, "evidence_refs", [])
        prop_stpa_v = getattr(p, "stpa_version", stpa_version)
        prop_tax_v = getattr(p, "taxonomy_version", taxonomy_version)

        # Determine target adjudication
        key = (left_ref, right_ref)
        conflict_reason = None
        if key in conflict_pairs:
            target_adj = "unresolved"
            conflict_reason = "conflict"
        elif prop_id in adjudications:
            target_adj = adjudications[prop_id]
        elif hasattr(p, "adjudication") and p.adjudication:
            target_adj = p.adjudication
        else:
            target_adj = "unresolved"

        # Check for defects if attempting to confirm
        if target_adj == "confirmed":
            confirmation_defects = _confirmation_errors(
                prop_id,
                left_ref,
                right_ref,
                prop_stpa_v,
                prop_tax_v,
                evidence_source,
                evidence_refs,
                stpa_version,
                taxonomy_version,
                valid_stpa_ids,
                valid_tax_ids,
            )
            if confirmation_defects:
                is_valid = False
                errors.extend(confirmation_defects)
                target_adj = "unresolved"

        reconciled_proposals.append(
            ReconciledProposal(
                proposal_id=prop_id,
                left_ref=left_ref,
                right_ref=right_ref,
                relation_type=p.relation_type,
                evidence_source=evidence_source,
                strength=getattr(p, "strength", "high"),
                adjudication=target_adj,
                conflict_reason=conflict_reason,
                proposer_id=getattr(p, "proposer_id", ""),
                proposer_version=getattr(p, "proposer_version", "1"),
                evidence_refs=list(evidence_refs),
                stpa_version=prop_stpa_v,
                taxonomy_version=prop_tax_v,
                rationale=getattr(p, "rationale", ""),
                provenance=getattr(p, "provenance", None),
                adjudication_history=_adjudication_history(
                    p, target_adj, conflict_reason
                ),
            )
        )

    # Sort reconciled proposals canonically
    reconciled_proposals.sort(key=lambda p: p.proposal_id)

    return ReconciliationResult(
        schema_version="1",
        stpa_version=stpa_version,
        taxonomy_version=taxonomy_version,
        is_valid=is_valid,
        proposals=reconciled_proposals,
        errors=errors,
        network_calls=0,
        model_calls=0,
    )
