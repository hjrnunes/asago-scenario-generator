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


def _entry_taxonomy_ref(entry: Any, taxonomy_field: str | None) -> str:
    """Return the entry's taxonomy reference, or "" when the field is absent."""
    if not taxonomy_field:
        return ""
    return getattr(entry, taxonomy_field, None) or ""


def _collect_element_ids(
    resource_map: SystemResourceMap,
    stpa_ids: set[str],
    tax_ids: set[str],
) -> None:
    """Add every element id (and taxonomy ref) from the map's collections."""
    for collection, taxonomy_field in _SRM_ELEMENT_COLLECTIONS:
        for entry in getattr(resource_map, collection):
            stpa_ids.add(entry.element_id)
            taxonomy_ref = _entry_taxonomy_ref(entry, taxonomy_field)
            if taxonomy_ref:
                tax_ids.add(taxonomy_ref)


def _collect_loss_link_ids(resource_map: SystemResourceMap, stpa_ids: set[str]) -> None:
    """Add loss-link element, loss, and hazard ids to the STPA id set."""
    for ll in resource_map.loss_links:
        stpa_ids.add(ll.element_id)
        if ll.loss_id:
            stpa_ids.add(ll.loss_id)
        if ll.hazard_id:
            stpa_ids.add(ll.hazard_id)


def _srm_versions_and_identifiers(
    resource_map: SystemResourceMap,
) -> tuple[str, str, set[str], set[str]]:
    """Extract pinned versions and identifiers from a SystemResourceMap."""
    stpa_ids: set[str] = set()
    tax_ids: set[str] = set()
    _collect_element_ids(resource_map, stpa_ids, tax_ids)
    _collect_loss_link_ids(resource_map, stpa_ids)
    return (
        str(resource_map.stpa_version),
        str(resource_map.taxonomy_version),
        stpa_ids,
        tax_ids,
    )


def _snapshot_versions_and_identifiers(
    resource_map: ResourceMapSnapshot,
) -> tuple[str, str, set[str], set[str]]:
    """Extract pinned versions and identifiers from a snapshot fixture."""
    return (
        str(resource_map.stpa_version),
        str(resource_map.taxonomy_version),
        set(resource_map.stpa_identifiers),
        set(resource_map.taxonomy_identifiers),
    )


def _dict_versions_and_identifiers(
    resource_map: dict[str, Any],
) -> tuple[str, str, set[str], set[str]]:
    """Extract pinned versions and identifiers from a plain mapping."""
    return (
        str(resource_map.get("stpa_version", "")),
        str(resource_map.get("taxonomy_version", "")),
        set(resource_map.get("stpa_identifiers", [])),
        set(resource_map.get("taxonomy_identifiers", [])),
    )


def _extract_versions_and_identifiers(
    resource_map: SystemResourceMap | ResourceMapSnapshot | dict[str, Any],
) -> tuple[str, str, set[str], set[str]]:
    """Extract pinned versions and valid STPA / taxonomy identifiers from resource map."""
    if isinstance(resource_map, SystemResourceMap):
        return _srm_versions_and_identifiers(resource_map)
    if isinstance(resource_map, ResourceMapSnapshot):
        return _snapshot_versions_and_identifiers(resource_map)
    if isinstance(resource_map, dict):
        return _dict_versions_and_identifiers(resource_map)
    return "", "", set(), set()


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

    # Conditionals and constants bound to locals so they sit on executed
    # lines: coverage attributes a call expression to its first line only,
    # leaving sites on continuation lines invisible to mutation selection.
    default_evidence_refs = [left_ref, right_ref] if left_ref and right_ref else []
    never_confirmed = False

    return CorrespondenceProposal(
        proposal_id=prop_id,
        left_ref=left_ref,
        right_ref=right_ref,
        relation_type=item.get("relation_type", default_rel),
        evidence_source=evidence_source,
        strength=item.get("strength", default_strength),
        proposer_id=item.get("proposer_id", ""),
        proposer_version=item.get("proposer_version", "1"),
        evidence_refs=item.get("evidence_refs", default_evidence_refs),
        stpa_version=item.get("stpa_version", stpa_version),
        taxonomy_version=item.get("taxonomy_version", taxonomy_version),
        rationale=item.get("rationale", ""),
        is_confirmed=never_confirmed,
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


def _pair_disagrees(
    group: Sequence[CorrespondenceProposal | ReconciledProposal],
) -> bool:
    """Return True when one pair's proposals disagree on the relation."""
    if len(group) <= 1:
        return False
    rel_types = {p.relation_type for p in group}
    return len(rel_types) > 1 or "contradicts" in rel_types


def _conflict_pairs(
    sorted_proposals: Sequence[CorrespondenceProposal | ReconciledProposal],
) -> set[tuple[str, str]]:
    """Detect (left_ref, right_ref) pairs whose proposals disagree."""
    grouped: dict[
        tuple[str, str], list[CorrespondenceProposal | ReconciledProposal]
    ] = {}
    for p in sorted_proposals:
        key = (p.left_ref, p.right_ref)
        grouped.setdefault(key, []).append(p)

    return {key for key, group in grouped.items() if _pair_disagrees(group)}


def _dangling_reference_errors(
    prop_id: str,
    left_ref: str,
    right_ref: str,
    valid_stpa_ids: set[str],
    valid_tax_ids: set[str],
) -> list[ReconciliationError]:
    """Collect dangling-reference defects for one proposal."""
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

    return errors


def _stpa_version_mismatch_error(
    prop_id: str,
    prop_stpa_v: str,
    stpa_version: str,
) -> ReconciliationError | None:
    """Return the STPA version-mismatch error, or None when versions agree."""
    if stpa_version and prop_stpa_v and prop_stpa_v != stpa_version:
        return ReconciliationError(
            proposal_id=prop_id,
            error_code="source_version_mismatch",
            message=f"Proposal {prop_id} STPA version {prop_stpa_v} does not match {stpa_version}",
        )
    return None


def _taxonomy_version_mismatch_error(
    prop_id: str,
    prop_tax_v: str,
    taxonomy_version: str,
) -> ReconciliationError | None:
    """Return the taxonomy version-mismatch error, or None when versions agree."""
    if taxonomy_version and prop_tax_v and prop_tax_v != taxonomy_version:
        return ReconciliationError(
            proposal_id=prop_id,
            error_code="source_version_mismatch",
            message=f"Proposal {prop_id} taxonomy version {prop_tax_v} does not match {taxonomy_version}",
        )
    return None


def _source_version_mismatch_error(
    prop_id: str,
    prop_stpa_v: str,
    prop_tax_v: str,
    stpa_version: str,
    taxonomy_version: str,
) -> ReconciliationError | None:
    """Return the first source-version mismatch, STPA checked before taxonomy."""
    return _stpa_version_mismatch_error(
        prop_id, prop_stpa_v, stpa_version
    ) or _taxonomy_version_mismatch_error(prop_id, prop_tax_v, taxonomy_version)


def _evidence_required_error(
    prop_id: str,
    evidence_source: str,
    evidence_refs: list[str],
) -> ReconciliationError | None:
    """Return the evidence-required error, or None when evidence is explicit."""
    # Each disjunct bound to a named local and combined in single-line
    # statements so every operator sits on an executed line: coverage
    # attributes a multi-line expression to its first line only, leaving
    # operators on continuation lines invisible to mutation selection.
    missing_evidence_source = not evidence_source
    evidence_source_neutral = evidence_source in ("none", "evidence-free")
    missing_evidence_refs = not evidence_refs
    evidence_block = missing_evidence_source or evidence_source_neutral
    evidence_block = evidence_block or missing_evidence_refs
    if evidence_block:
        return ReconciliationError(
            proposal_id=prop_id,
            error_code="evidence_required",
            message=f"Proposal {prop_id} lacks explicit evidence required for confirmation",
        )
    return None


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
    errors = _dangling_reference_errors(
        prop_id, left_ref, right_ref, valid_stpa_ids, valid_tax_ids
    )
    version_error = _source_version_mismatch_error(
        prop_id, prop_stpa_v, prop_tax_v, stpa_version, taxonomy_version
    )
    if version_error is not None:
        errors.append(version_error)
    evidence_error = _evidence_required_error(prop_id, evidence_source, evidence_refs)
    if evidence_error is not None:
        errors.append(evidence_error)
    return errors


def _carried_history(
    p: CorrespondenceProposal | ReconciledProposal,
) -> list[AdjudicationHistoryItem]:
    """Return the adjudication history carried by the input proposal."""
    if hasattr(p, "adjudication_history") and p.adjudication_history:
        return list(p.adjudication_history)
    return []


def _history_reason(
    target_adj: str,
    conflict_reason: str | None,
) -> str | None:
    """Return the history reason for one adjudication decision."""
    if conflict_reason:
        return conflict_reason
    return "confirmed" if target_adj == "confirmed" else None


def _adjudication_history(
    p: CorrespondenceProposal | ReconciledProposal,
    target_adj: str,
    conflict_reason: str | None,
) -> list[AdjudicationHistoryItem]:
    """Carry forward the proposal's history and append the new adjudication."""
    history_items = _carried_history(p)
    new_reason = _history_reason(target_adj, conflict_reason)
    if not history_items or history_items[-1].adjudication != target_adj:
        history_items.append(
            AdjudicationHistoryItem(
                adjudication=target_adj,
                reason=new_reason,
            )
        )
    return history_items


def _input_adjudication(
    p: CorrespondenceProposal | ReconciledProposal,
    prop_id: str,
    adjudications: dict[str, str],
) -> str:
    """Return the adjudication from explicit input, then any carried value."""
    if prop_id in adjudications:
        return adjudications[prop_id]
    if hasattr(p, "adjudication") and p.adjudication:
        return p.adjudication
    return "unresolved"


def _target_adjudication(
    p: CorrespondenceProposal | ReconciledProposal,
    prop_id: str,
    adjudications: dict[str, str],
    conflict_pairs: set[tuple[str, str]],
    stpa_version: str,
    taxonomy_version: str,
    valid_stpa_ids: set[str],
    valid_tax_ids: set[str],
) -> tuple[str, str | None, list[ReconciliationError]]:
    """Resolve one proposal's target adjudication, conflict reason, and defects."""
    if (p.left_ref, p.right_ref) in conflict_pairs:
        return "unresolved", "conflict", []
    target_adj = _input_adjudication(p, prop_id, adjudications)
    if target_adj != "confirmed":
        return target_adj, None, []
    confirmation_defects = _confirmation_errors(
        prop_id,
        p.left_ref,
        p.right_ref,
        getattr(p, "stpa_version", stpa_version),
        getattr(p, "taxonomy_version", taxonomy_version),
        getattr(p, "evidence_source", "exact-id"),
        list(getattr(p, "evidence_refs", [])),
        stpa_version,
        taxonomy_version,
        valid_stpa_ids,
        valid_tax_ids,
    )
    if confirmation_defects:
        return "unresolved", None, confirmation_defects
    return target_adj, None, []


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
        target_adj, conflict_reason, confirmation_defects = _target_adjudication(
            p,
            p.proposal_id,
            adjudications,
            conflict_pairs,
            stpa_version,
            taxonomy_version,
            valid_stpa_ids,
            valid_tax_ids,
        )
        if confirmation_defects:
            is_valid = False
            errors.extend(confirmation_defects)

        reconciled_proposals.append(
            ReconciledProposal(
                proposal_id=p.proposal_id,
                left_ref=p.left_ref,
                right_ref=p.right_ref,
                relation_type=p.relation_type,
                evidence_source=getattr(p, "evidence_source", "exact-id"),
                strength=getattr(p, "strength", "high"),
                adjudication=target_adj,
                conflict_reason=conflict_reason,
                proposer_id=getattr(p, "proposer_id", ""),
                proposer_version=getattr(p, "proposer_version", "1"),
                evidence_refs=list(getattr(p, "evidence_refs", [])),
                stpa_version=getattr(p, "stpa_version", stpa_version),
                taxonomy_version=getattr(p, "taxonomy_version", taxonomy_version),
                rationale=getattr(p, "rationale", ""),
                provenance=getattr(p, "provenance", None),
                adjudication_history=_adjudication_history(
                    p, target_adj, conflict_reason
                ),
            )
        )

    # Sort reconciled proposals canonically
    reconciled_proposals.sort(key=lambda p: p.proposal_id)

    zero_network_calls = 0
    zero_model_calls = 0
    return ReconciliationResult(
        schema_version="1",
        stpa_version=stpa_version,
        taxonomy_version=taxonomy_version,
        is_valid=is_valid,
        proposals=reconciled_proposals,
        errors=errors,
        network_calls=zero_network_calls,
        model_calls=zero_model_calls,
    )


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-28T07:30:47Z","module_hash":"575de75fa85dad2a363f1cfbc263a5cc7bb5038b36d590140b22584ade2f1e69","source_sha256":"660691db64a9898f0b529508b177dade0109d20e07341a3987225f9f9bd8b582","functions":[{"id":"func/_entry_taxonomy_ref","name":"_entry_taxonomy_ref","line":44,"end_line":48,"hash":"a672ec607fcdad3272780f384a79a7259182f5a2ccdc046cdd5b05fba558e846"},{"id":"func/_collect_element_ids","name":"_collect_element_ids","line":51,"end_line":62,"hash":"858aa2a5e438533c311680edd7ce5c8e3a56905f012c07309a0b16fde9678fea"},{"id":"func/_collect_loss_link_ids","name":"_collect_loss_link_ids","line":65,"end_line":72,"hash":"f48f74106f0375a1a0475d60c45649abbfb547398e96aee348b5f5236c3ad353"},{"id":"func/_srm_versions_and_identifiers","name":"_srm_versions_and_identifiers","line":75,"end_line":88,"hash":"1129a2e1551cf06867229fef4682a84f39e79e791b51f2f16ed0103e521e9f99"},{"id":"func/_snapshot_versions_and_identifiers","name":"_snapshot_versions_and_identifiers","line":91,"end_line":100,"hash":"fffefd173c2ce07de7ee82365011c6a2291d60b88fbca33ba654df6624746878"},{"id":"func/_dict_versions_and_identifiers","name":"_dict_versions_and_identifiers","line":103,"end_line":112,"hash":"aa270c60707a2719bb53e1e044d2db5987a7867c323d6e0c08513cd0e50325b2"},{"id":"func/_extract_versions_and_identifiers","name":"_extract_versions_and_identifiers","line":115,"end_line":125,"hash":"a0de1becb32d60cbc7de997ddc0db973191bf78c015bd0a8bc331403216ec8ae"},{"id":"func/_proposal_from_evidence","name":"_proposal_from_evidence","line":128,"end_line":167,"hash":"7bd1fdddb4f4473b15936e467cca70560a1ec4efd17f51bd89a72958112d0d50"},{"id":"func/propose_correspondence","name":"propose_correspondence","line":170,"end_line":199,"hash":"c61026c52ed314f4f239fe4708316fca88b72b7cca3e310738a316fde4c05e6c"},{"id":"func/_pair_disagrees","name":"_pair_disagrees","line":202,"end_line":209,"hash":"074d6e59cf443a86c7e0ba4c8b21cbef01332c79bcfd058c7d231a256792d2dd"},{"id":"func/_conflict_pairs","name":"_conflict_pairs","line":212,"end_line":223,"hash":"c0316c8ba2ca5da5988919c658ecb2795d9dab37c3e5b706dea46c99f846700d"},{"id":"func/_dangling_reference_errors","name":"_dangling_reference_errors","line":226,"end_line":254,"hash":"d7c13c5219e1c7aefaff145975d4c366743e6df24d92611377423fa2e38d345e"},{"id":"func/_stpa_version_mismatch_error","name":"_stpa_version_mismatch_error","line":257,"end_line":269,"hash":"1e4620f66d40b475c812bf8001ba833f86b921c34c56bf088850cfe8fda93359"},{"id":"func/_taxonomy_version_mismatch_error","name":"_taxonomy_version_mismatch_error","line":272,"end_line":284,"hash":"c785dc9b26df0dd2c214fe691ff0687645bb5c1d9d36836c84f935370ffc875f"},{"id":"func/_source_version_mismatch_error","name":"_source_version_mismatch_error","line":287,"end_line":297,"hash":"450d49088c98423a28b07dccf3dbe9cd32055763ac3c8fc543b0d7c2536b615f"},{"id":"func/_evidence_required_error","name":"_evidence_required_error","line":300,"end_line":321,"hash":"c72679f48bcd120c1caa66dd62981ffdfed2faa7ea3d2d0ac7dcfb8710853ba6"},{"id":"func/_confirmation_errors","name":"_confirmation_errors","line":324,"end_line":349,"hash":"78b485fc83ca3b43ad63d78ee194ae2609363fc61e5db6775f592d821aee4abf"},{"id":"func/_carried_history","name":"_carried_history","line":352,"end_line":358,"hash":"ba4e343b8bed1cccead04ed7665e2e6fe48676b0aca63662bfa589af5688a4ea"},{"id":"func/_history_reason","name":"_history_reason","line":361,"end_line":368,"hash":"5d6a1ad3da2d3bff06acd48ef920a6b55970a6499b909b69c32f999c3cdaaced"},{"id":"func/_adjudication_history","name":"_adjudication_history","line":371,"end_line":386,"hash":"b22b87f666b452b69ea64b5ec36eea88b0a817530be9557576d807b0a44b8006"},{"id":"func/_input_adjudication","name":"_input_adjudication","line":389,"end_line":399,"hash":"74212b7b7303c4a5e08ae5d991c34aeb16d7d90009f635569757f4829a7d6b2b"},{"id":"func/_target_adjudication","name":"_target_adjudication","line":402,"end_line":433,"hash":"7cd3cadcd1db7e35f73a16a8145d27e1c78c08488b5b281a60bc5eb651613d14"},{"id":"func/reconcile_correspondence","name":"reconcile_correspondence","line":436,"end_line":514,"hash":"7a2ee12b6deffef35ada334fba7e72ffc09fc60fc98dcb0b55e22aaa1592f686"}]}
# mutate4py-manifest-end
