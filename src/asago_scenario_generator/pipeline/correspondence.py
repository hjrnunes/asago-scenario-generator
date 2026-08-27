"""Deterministic correspondence proposal and reconciliation pipeline."""

from __future__ import annotations

from typing import Any

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

        for sr in resource_map.system_resources:
            stpa_ids.add(sr.element_id)
            if sr.taxonomy_ref:
                tax_ids.add(sr.taxonomy_ref)
        for ac in resource_map.actor_controllers:
            stpa_ids.add(ac.element_id)
        for cp in resource_map.controlled_processes:
            stpa_ids.add(cp.element_id)
        for ca in resource_map.control_actions:
            stpa_ids.add(ca.element_id)
        for fb in resource_map.feedback_paths:
            stpa_ids.add(fb.element_id)
        for tb in resource_map.trust_boundaries:
            stpa_ids.add(tb.element_id)
            if tb.taxonomy_ref:
                tax_ids.add(tb.taxonomy_ref)
        for df in resource_map.data_flows:
            stpa_ids.add(df.element_id)
        for ll in resource_map.loss_links:
            stpa_ids.add(ll.element_id)
            if ll.loss_id:
                stpa_ids.add(ll.loss_id)
            if ll.hazard_id:
                stpa_ids.add(ll.hazard_id)
        for uf in resource_map.use_case_facts:
            stpa_ids.add(uf.element_id)
        for a in resource_map.assertions:
            stpa_ids.add(a.element_id)

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


def propose_correspondence(
    resource_map: SystemResourceMap | ResourceMapSnapshot | dict[str, Any],
    source_artifacts: Any = None,
    adapters: list[Any] | None = None,
) -> ProposalSet:
    """Generate deterministic correspondence proposals from resource map and source artifacts."""
    stpa_version, taxonomy_version, _, _ = _extract_versions_and_identifiers(
        resource_map
    )

    proposals: list[CorrespondenceProposal] = []

    if isinstance(source_artifacts, dict) and "evidence" in source_artifacts:
        for idx, item in enumerate(source_artifacts["evidence"], 1):
            prop_id = item.get("proposal_id", f"P-{idx}")
            left_ref = item.get("left_ref", "")
            right_ref = item.get("right_ref", "")
            evidence_source = item.get("evidence_source", "exact-id")
            adapter_kind = item.get("adapter_kind", None)

            if evidence_source == "exact-id":
                default_strength = "high"
                default_rel = "supports"
            elif evidence_source == "curated-map":
                default_strength = "high"
                default_rel = "addresses"
            elif evidence_source == "resource-overlap":
                default_strength = "weak"
                default_rel = "overlaps"
            elif evidence_source in ("heuristic", "model-assisted") or adapter_kind:
                default_strength = "weak"
                default_rel = "supports"
            else:
                default_strength = "high"
                default_rel = "supports"

            strength = item.get("strength", default_strength)
            relation_type = item.get("relation_type", default_rel)
            proposer_id = item.get("proposer_id", "")
            proposer_version = item.get("proposer_version", "1")
            evidence_refs = item.get(
                "evidence_refs", [left_ref, right_ref] if left_ref and right_ref else []
            )
            prop_stpa_v = item.get("stpa_version", stpa_version)
            prop_tax_v = item.get("taxonomy_version", taxonomy_version)
            rationale = item.get("rationale", "")

            proposal = CorrespondenceProposal(
                proposal_id=prop_id,
                left_ref=left_ref,
                right_ref=right_ref,
                relation_type=relation_type,
                evidence_source=evidence_source,
                strength=strength,
                proposer_id=proposer_id,
                proposer_version=proposer_version,
                evidence_refs=evidence_refs,
                stpa_version=prop_stpa_v,
                taxonomy_version=prop_tax_v,
                rationale=rationale,
                is_confirmed=False,
            )
            proposals.append(proposal)

    # Sort proposals canonically by proposal_id
    proposals.sort(key=lambda p: p.proposal_id)

    return ProposalSet(
        schema_version="1",
        stpa_version=stpa_version,
        taxonomy_version=taxonomy_version,
        proposals=proposals,
    )


def reconcile_correspondence(
    resource_map: SystemResourceMap | ResourceMapSnapshot | dict[str, Any],
    proposals: ProposalSet | list[Any],
    adjudications: dict[str, str] | None = None,
) -> ReconciliationResult:
    """Deterministically reconcile proposals into confirmed, rejected, or unresolved states."""
    stpa_version, taxonomy_version, valid_stpa_ids, valid_tax_ids = (
        _extract_versions_and_identifiers(resource_map)
    )

    if adjudications is None:
        adjudications = {}

    # Extract raw proposal list
    if isinstance(proposals, ProposalSet):
        raw_list = proposals.proposals
    elif isinstance(proposals, list):
        raw_list = proposals
    else:
        raw_list = []

    # Sort proposals canonically by proposal_id to ensure presentation order independence
    sorted_proposals = sorted(raw_list, key=lambda p: p.proposal_id)

    # Detect conflicts by grouping proposals on (left_ref, right_ref)
    pairs: dict[tuple[str, str], list[Any]] = {}
    for p in sorted_proposals:
        key = (p.left_ref, p.right_ref)
        pairs.setdefault(key, []).append(p)

    conflict_pairs: set[tuple[str, str]] = set()
    for key, group in pairs.items():
        if len(group) > 1:
            rel_types = {p.relation_type for p in group}
            if len(rel_types) > 1 or "contradicts" in rel_types:
                conflict_pairs.add(key)

    errors: list[ReconciliationError] = []
    reconciled_proposals: list[ReconciledProposal] = []
    is_valid = True

    for p in sorted_proposals:
        prop_id = p.proposal_id
        left_ref = p.left_ref
        right_ref = p.right_ref
        relation_type = p.relation_type
        evidence_source = getattr(p, "evidence_source", "exact-id")
        strength = getattr(p, "strength", "high")
        proposer_id = getattr(p, "proposer_id", "")
        proposer_version = getattr(p, "proposer_version", "1")
        evidence_refs = getattr(p, "evidence_refs", [])
        prop_stpa_v = getattr(p, "stpa_version", stpa_version)
        prop_tax_v = getattr(p, "taxonomy_version", taxonomy_version)
        rationale = getattr(p, "rationale", "")
        provenance = getattr(p, "provenance", None)

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
            # 1. Dangling left reference
            if valid_stpa_ids and left_ref not in valid_stpa_ids:
                is_valid = False
                errors.append(
                    ReconciliationError(
                        proposal_id=prop_id,
                        error_code="dangling_reference",
                        message=f"Proposal {prop_id} has dangling left reference {left_ref}",
                    )
                )
                target_adj = "unresolved"

            # 2. Dangling right reference
            if valid_tax_ids and right_ref not in valid_tax_ids:
                is_valid = False
                errors.append(
                    ReconciliationError(
                        proposal_id=prop_id,
                        error_code="dangling_reference",
                        message=f"Proposal {prop_id} has dangling right reference {right_ref}",
                    )
                )
                target_adj = "unresolved"

            # 3. Source version mismatch
            if stpa_version and prop_stpa_v and prop_stpa_v != stpa_version:
                is_valid = False
                errors.append(
                    ReconciliationError(
                        proposal_id=prop_id,
                        error_code="source_version_mismatch",
                        message=f"Proposal {prop_id} STPA version {prop_stpa_v} does not match {stpa_version}",
                    )
                )
                target_adj = "unresolved"
            elif taxonomy_version and prop_tax_v and prop_tax_v != taxonomy_version:
                is_valid = False
                errors.append(
                    ReconciliationError(
                        proposal_id=prop_id,
                        error_code="source_version_mismatch",
                        message=f"Proposal {prop_id} taxonomy version {prop_tax_v} does not match {taxonomy_version}",
                    )
                )
                target_adj = "unresolved"

            # 4. Evidence-free confirmation
            if (
                not evidence_source
                or evidence_source in ("none", "evidence-free")
                or not evidence_refs
            ):
                is_valid = False
                errors.append(
                    ReconciliationError(
                        proposal_id=prop_id,
                        error_code="evidence_required",
                        message=f"Proposal {prop_id} lacks explicit evidence required for confirmation",
                    )
                )
                target_adj = "unresolved"

        history_items: list[AdjudicationHistoryItem] = []
        if hasattr(p, "adjudication_history") and p.adjudication_history:
            history_items.extend(p.adjudication_history)
        new_reason = conflict_reason or (
            "confirmed" if target_adj == "confirmed" else None
        )
        if not history_items or history_items[-1].adjudication != target_adj:
            history_items.append(
                AdjudicationHistoryItem(
                    adjudication=target_adj,
                    reason=new_reason,
                )
            )

        reconciled = ReconciledProposal(
            proposal_id=prop_id,
            left_ref=left_ref,
            right_ref=right_ref,
            relation_type=relation_type,
            evidence_source=evidence_source,
            strength=strength,
            adjudication=target_adj,
            conflict_reason=conflict_reason,
            proposer_id=proposer_id,
            proposer_version=proposer_version,
            evidence_refs=list(evidence_refs),
            stpa_version=prop_stpa_v,
            taxonomy_version=prop_tax_v,
            rationale=rationale,
            provenance=provenance,
            adjudication_history=history_items,
        )
        reconciled_proposals.append(reconciled)

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
