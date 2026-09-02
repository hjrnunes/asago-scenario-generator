"""Automatic, non-blocking Phase 2 verification for synthesis runs.

The synthesis workflow already owns exact Phase 1 and STPA identities.  This
adapter projects those finished artifacts into the existing offline Phase 2
contracts.  It deliberately starts with an empty, correctly pinned resource
map and unreviewed correspondence proposals: running verification must never
turn an STPA finding into an accepted taxonomy-coverage claim by itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Sequence

from asago_scenario_generator.models.canonical import canonical_json_bytes
from asago_scenario_generator.models.correspondence import (
    AdjudicationSet,
    CorrespondenceAuthority,
    CorrespondenceEvidence,
    CorrespondenceSourceArtifacts,
    ProposalSet,
    ReconciliationResult,
)
from asago_scenario_generator.models.hybrid_coverage import (
    HybridCoverageAssessment,
    StpaCoverageInput,
    TaxonomyCoverageInput,
)
from asago_scenario_generator.models.obligation_accounting import (
    ObligationAccountingRow,
)
from asago_scenario_generator.models.obligation_consideration import (
    ObligationIcaConsideration,
)
from asago_scenario_generator.models.obligation_plan import TaxonomyObligationPlan
from asago_scenario_generator.models.system_resource_map import (
    SYSTEM_RESOURCE_MAP_SCHEMA_VERSION,
    SystemResourceMap,
    SystemResourceMapValidation,
    compute_control_structure_digest,
    compute_resource_map_semantic_digest,
)
from asago_scenario_generator.pipeline.correspondence import (
    propose_correspondence,
    reconcile_correspondence,
)
from asago_scenario_generator.pipeline.correspondence_persistence import (
    write_correspondence_proposals,
    write_correspondence_reconciliation,
)
from asago_scenario_generator.pipeline.hybrid_coverage import assess_hybrid_coverage
from asago_scenario_generator.pipeline.hybrid_coverage_persistence import (
    write_hybrid_coverage_assessment,
)
from asago_scenario_generator.pipeline.projection_contracts import (
    CapabilityFactSnapshot,
)
from asago_scenario_generator.pipeline.system_resource_map import (
    validate_system_resource_map,
)
from asago_scenario_generator.pipeline.system_resource_map_persistence import (
    write_system_resource_map,
)
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.ica_enumeration import ICAEnumeration
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.models.scenario_envelope import ScenarioEnvelope

Phase2VerificationStatus = Literal["verified", "awaiting_review", "awaiting_evidence"]


@dataclass(frozen=True)
class SynthesisPhase2Verification:
    """Finished Phase 2 projection and the normative artifacts it published."""

    status: Phase2VerificationStatus
    resource_map_validation: SystemResourceMapValidation
    proposals: ProposalSet
    reconciliation: ReconciliationResult
    assessment: HybridCoverageAssessment
    artifact_paths: dict[str, Path]
    resource_map_mode: Literal["empty_pinned_baseline"] = "empty_pinned_baseline"


def _empty_pinned_resource_map(
    snapshot: CapabilityFactSnapshot,
    control_structure: ControlStructure,
) -> SystemResourceMap:
    """Build an honest zero-link map pinned to the completed synthesis run."""
    snapshot.assert_integrity()
    snapshot_digest = snapshot.snapshot_digest
    control_digest = compute_control_structure_digest(control_structure)
    digest = compute_resource_map_semantic_digest(
        schema_version=SYSTEM_RESOURCE_MAP_SCHEMA_VERSION,
        capability_snapshot_digest=snapshot_digest,
        control_structure_digest=control_digest,
        links=(),
    )
    return SystemResourceMap(
        schema_version=SYSTEM_RESOURCE_MAP_SCHEMA_VERSION,
        semantic_digest=digest,
        capability_snapshot_digest=snapshot_digest,
        control_structure_digest=control_digest,
        links=(),
    )


def _candidate_route_evidence(
    authority: CorrespondenceAuthority,
    considerations: Sequence[ObligationIcaConsideration],
    accounting_rows: Sequence[ObligationAccountingRow],
) -> tuple[CorrespondenceEvidence, ...]:
    """Project exact synthesis routes into explicit review candidates."""
    obligations = {item.obligation_id: item for item in authority.obligations}
    accounting = {item.obligation_id: item for item in accounting_rows}
    findings = {
        (item.ica_slot_id, item.ica_id): item for item in authority.structural_findings
    }
    evidence: list[CorrespondenceEvidence] = []
    for item in considerations:
        if item.disposition != "finding":
            continue
        obligation = obligations.get(item.obligation_id)
        accounting_row = accounting.get(item.obligation_id)
        if obligation is None or accounting_row is None:
            continue
        candidates = tuple(
            candidate
            for candidate in obligation.candidates
            if candidate.projection_disposition == "projectable"
        )
        for ica_id in item.ica_ids:
            finding = findings.get((item.slot_id, ica_id))
            if finding is None:
                continue
            evidence.extend(
                _one_route_evidence(
                    obligation,
                    candidate,
                    finding,
                    item,
                    accounting_row,
                    authority,
                )
                for candidate in candidates
            )
    return _unique_evidence(evidence)


def _one_route_evidence(
    obligation: object,
    candidate: object,
    finding: object,
    consideration: ObligationIcaConsideration,
    accounting: ObligationAccountingRow,
    authority: CorrespondenceAuthority,
) -> CorrespondenceEvidence:
    """Build one explicit proposal without asserting mechanism equivalence."""
    coverage_candidate = accounting.disposition == "addressed"
    relation_kind = (
        "mechanism_enables_ica" if coverage_candidate else "related_but_not_coverage"
    )
    rationale = (
        "The synthesis mechanism/path check credited this exact obligation and "
        "ICA pair. Independent review is still required before correspondence "
        "can count as taxonomy coverage."
        if coverage_candidate
        else "The synthesis run routed this exact obligation to this exact ICA, "
        "but its accounting did not establish the taxonomy mechanism."
    )
    return CorrespondenceEvidence(
        obligation_id=obligation.obligation_id,
        risk_id=obligation.risk_id,
        attack_pattern_id=obligation.attack_pattern_id,
        taxonomy_candidate_ids=obligation.taxonomy_candidate_ids,
        selected_candidate_id=candidate.candidate_id,
        ica_slot_id=finding.ica_slot_id,
        ica_id=finding.ica_id,
        exec_candidate_id=finding.exec_candidate_id,
        relation_kind=relation_kind,
        resource_link_ids=finding.resource_link_ids,
        hazard_ids=finding.hazard_ids,
        constraint_ids=finding.constraint_ids,
        evidence_source="exact_id",
        evidence_refs=(
            f"candidate:{candidate.candidate_id}",
            f"synthesis-pair:{consideration.pair_id}",
            f"accounting:{accounting.obligation_id}:{accounting.disposition}",
            f"ica:{finding.ica_id}",
        ),
        confidence=1.0,
        evidence_strength="high",
        proposer_id="synthesis-obligation-route-v1",
        proposer_version="1",
        source_pins=authority.source_pins,
        rationale=rationale,
    )


def _unique_evidence(
    values: Sequence[CorrespondenceEvidence],
) -> tuple[CorrespondenceEvidence, ...]:
    """Remove duplicate route witnesses while retaining canonical ordering."""
    by_content = {
        canonical_json_bytes(item.model_dump(mode="json")): item for item in values
    }
    return tuple(by_content[key] for key in sorted(by_content))


def _stpa_coverage(
    enumeration: ICAEnumeration,
    scenarios: Sequence[ScenarioEnvelope],
) -> StpaCoverageInput:
    """Adapt admitted scenarios when present and retain all ICA slots regardless."""
    if scenarios:
        return StpaCoverageInput.from_scenario_envelopes(enumeration, scenarios)
    return StpaCoverageInput.from_ica_enumeration(enumeration)


def _verification_status(
    proposals: ProposalSet,
    reconciliation: ReconciliationResult,
) -> Phase2VerificationStatus:
    """Describe whether evidence is absent, awaiting review, or confirmed."""
    if reconciliation.accepted_relations:
        return "verified"
    if any(
        item.relation_kind != "related_but_not_coverage" and item.resource_link_ids
        for item in proposals.proposals
    ):
        return "awaiting_review"
    return "awaiting_evidence"


def run_synthesis_phase2_verification(
    *,
    obligation_plan: TaxonomyObligationPlan,
    capability_snapshot: CapabilityFactSnapshot,
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
    ica_enumeration: ICAEnumeration,
    ica_considerations: Sequence[ObligationIcaConsideration] = (),
    accounting_rows: Sequence[ObligationAccountingRow] = (),
    scenario_envelopes: Sequence[ScenarioEnvelope] = (),
    adjudications: AdjudicationSet | None = None,
    output_dir: Path,
) -> SynthesisPhase2Verification:
    """Run and publish Phase 2 after synthesis without changing its scenarios."""
    resource_map = _empty_pinned_resource_map(capability_snapshot, control_structure)
    validation = validate_system_resource_map(
        resource_map, capability_snapshot, control_structure
    )
    authority = CorrespondenceAuthority.from_artifacts(
        resource_map,
        obligation_plan,
        control_structure,
        ica_enumeration,
        loss_analysis,
    )
    evidence = _candidate_route_evidence(
        authority, tuple(ica_considerations), tuple(accounting_rows)
    )
    proposals = propose_correspondence(
        validation,
        CorrespondenceSourceArtifacts(authority=authority, evidence=evidence),
    )
    reconciliation = reconcile_correspondence(
        validation, proposals, adjudications or AdjudicationSet()
    )
    assessment = assess_hybrid_coverage(
        obligation_plan,
        validation,
        reconciliation,
        TaxonomyCoverageInput(),
        _stpa_coverage(ica_enumeration, tuple(scenario_envelopes)),
    )
    output_dir = Path(output_dir)
    paths = {
        "system-resource-map.yaml": write_system_resource_map(output_dir, resource_map),
        "correspondence-proposals.yaml": write_correspondence_proposals(
            output_dir, proposals
        ),
        "correspondence-reconciliation.yaml": write_correspondence_reconciliation(
            output_dir, reconciliation
        ),
        "hybrid-coverage-assessment.yaml": write_hybrid_coverage_assessment(
            output_dir, assessment
        ),
    }
    return SynthesisPhase2Verification(
        status=_verification_status(proposals, reconciliation),
        resource_map_validation=validation,
        proposals=proposals,
        reconciliation=reconciliation,
        assessment=assessment,
        artifact_paths=paths,
    )


__all__ = [
    "Phase2VerificationStatus",
    "SynthesisPhase2Verification",
    "run_synthesis_phase2_verification",
]
