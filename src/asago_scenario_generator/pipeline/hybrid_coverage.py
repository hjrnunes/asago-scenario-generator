"""Pure projection into the three normative hybrid coverage matrices."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Sequence
from typing import Any

from asago_scenario_generator.models.canonical import compute_framed_digest
from asago_scenario_generator.models.correspondence import (
    AcceptedCorrespondenceRelation,
    ReconciledProposal,
    ReconciliationResult,
)
from asago_scenario_generator.models.hybrid_coverage import (
    ArtifactPin,
    CoverageFinding,
    HybridCoverageAssessment,
    ProposalOutcome,
    ScenarioRealizationRow,
    StpaCoverageInput,
    StpaScenarioObservation,
    StructuralConsiderationRow,
    StructuralInapplicabilityDecision,
    StructuralSlotObservation,
    TaxonomyCorrespondenceRow,
    TaxonomyCoverageInput,
    TaxonomyScenarioObservation,
    TraceReference,
    compute_matrix_row_id,
    derive_hybrid_coverage_diagnostics,
)
from asago_scenario_generator.models.obligation_plan import (
    TaxonomyObligation,
    TaxonomyObligationPlan,
)
from asago_scenario_generator.models.system_resource_map import (
    SystemResourceMap,
    SystemResourceMapValidation,
)

_COVERAGE_RELATION_KINDS = {
    "same_mechanism",
    "mechanism_enables_ica",
    "ica_specializes_mechanism",
    "mechanism_specializes_ica",
}


def _pin(artifact_id: str, schema_version: str, digest: str) -> ArtifactPin:
    """Build one exact source-artifact pin."""
    return ArtifactPin(
        artifact_id=artifact_id,
        schema_version=schema_version,
        semantic_digest=digest,
    )


def _trace(pin: ArtifactPin, record_id: str) -> TraceReference:
    """Build one trace anchored to an exact artifact pin."""
    return TraceReference(**pin.model_dump(mode="json"), record_id=record_id)


def _unique_traces(values: Iterable[TraceReference]) -> tuple[TraceReference, ...]:
    """Deduplicate identical trace references before model validation."""
    by_key = {
        (
            item.artifact_id,
            item.schema_version,
            item.semantic_digest,
            item.record_id,
        ): item
        for item in values
    }
    return tuple(by_key.values())


def _observation_traces(
    source: ArtifactPin,
    record_id: str,
    trace_refs: Sequence[str],
    extra_record_ids: Sequence[str] = (),
) -> tuple[TraceReference, ...]:
    """Project one observed record and every exact adapter trace."""
    return _unique_traces(
        _trace(source, item) for item in (record_id, *extra_record_ids, *trace_refs)
    )


def _base_pins(
    plan: TaxonomyObligationPlan,
    resource_map: SystemResourceMap,
    reconciliation: ReconciliationResult,
) -> tuple[ArtifactPin, ArtifactPin, ArtifactPin, ArtifactPin]:
    """Return the mandatory Phase 1/Task 2/Task 3 artifact pins."""
    return (
        _pin(
            "capability-fact-snapshot",
            "capability-fact-snapshot-v1",
            plan.capability_snapshot_digest,
        ),
        _pin("taxonomy-obligation-plan", plan.schema_version, plan.semantic_digest),
        _pin(
            "system-resource-map",
            resource_map.schema_version,
            resource_map.semantic_digest,
        ),
        _pin(
            "correspondence-reconciliation",
            reconciliation.schema_version,
            reconciliation.semantic_digest,
        ),
    )


def _source_pins(
    base_pins: Sequence[ArtifactPin],
    taxonomy: TaxonomyCoverageInput,
    stpa: StpaCoverageInput,
) -> tuple[ArtifactPin, ...]:
    """Merge all exact upstream pins and reject identity substitution."""
    observations: tuple[Any, ...] = (
        *taxonomy.scenarios,
        *taxonomy.structural_inapplicability_decisions,
        *stpa.slots,
        *stpa.scenarios,
    )
    by_id = {item.artifact_id: item for item in base_pins}
    for observation in observations:
        candidate = observation.source_artifact
        previous = by_id.get(candidate.artifact_id)
        if previous is not None and previous != candidate:
            raise ValueError(
                f"conflicting source artifact pin: {candidate.artifact_id}"
            )
        by_id[candidate.artifact_id] = candidate
    return tuple(by_id.values())


def _finding_id(kind: str, *record_ids: str) -> str:
    """Compute a stable identity for a non-satisfying finding."""
    digest = compute_framed_digest(
        "asago-scenario-generator:hybrid-coverage-finding:v1",
        {"kind": kind, "record_ids": sorted(record_ids)},
    )
    return f"hcaf:v1:{digest}"


def _finding(
    kind: str,
    detail: str,
    pins: tuple[ArtifactPin, ...],
    reconciliation_pin: ArtifactPin,
    *,
    relation_ids: Sequence[str] = (),
    proposal_ids: Sequence[str] = (),
) -> CoverageFinding:
    """Build one reconciliation finding with exact record traces."""
    record_ids = (*relation_ids, *proposal_ids)
    return CoverageFinding(
        finding_id=_finding_id(kind, *record_ids),
        kind=kind,
        detail=detail,
        relation_ids=tuple(relation_ids),
        proposal_ids=tuple(proposal_ids),
        source_pins=pins,
        trace_refs=tuple(_trace(reconciliation_pin, item) for item in record_ids),
    )


def _supported_relations_and_findings(
    reconciliation: ReconciliationResult,
    pins: tuple[ArtifactPin, ...],
    reconciliation_pin: ArtifactPin,
) -> tuple[tuple[AcceptedCorrespondenceRelation, ...], tuple[CoverageFinding, ...]]:
    """Retain closed accepted relations and separate explicit noncoverage findings."""
    findings: list[CoverageFinding] = []
    for relation in reconciliation.accepted_relations:
        if relation.relation_kind == "related_but_not_coverage":
            findings.append(
                _finding(
                    "related_but_not_coverage",
                    "accepted noncoverage relation never satisfies an obligation",
                    pins,
                    reconciliation_pin,
                    relation_ids=(relation.relation_id,),
                )
            )
    return reconciliation.accepted_relations, tuple(findings)


def _proposal_outcomes(
    reconciliation: ReconciliationResult,
    plan: TaxonomyObligationPlan,
    resource_map: SystemResourceMap,
    pins: tuple[ArtifactPin, ...],
    plan_pin: ArtifactPin,
    map_pin: ArtifactPin,
    reconciliation_pin: ArtifactPin,
) -> tuple[ProposalOutcome, ...]:
    """Retain every proposal that did not become confirmed+accepted."""
    return tuple(
        _proposal_outcome(
            item,
            plan,
            resource_map,
            pins,
            plan_pin,
            map_pin,
            reconciliation_pin,
        )
        for item in reconciliation.proposals
        if not _is_confirmed_accepted(item)
    )


def _is_confirmed_accepted(proposal: ReconciledProposal) -> bool:
    """Return whether one proposal crossed both confirmation gates."""
    return proposal.status == "confirmed"


def _proposal_status(proposal: ReconciledProposal) -> str:
    """Collapse a nonconfirmed result into the closed diagnostic status."""
    if proposal.status == "rejected" or proposal.validation_result == "rejected":
        return "rejected"
    return "unresolved"


def _proposal_outcome(
    proposal: ReconciledProposal,
    plan: TaxonomyObligationPlan,
    resource_map: SystemResourceMap,
    pins: tuple[ArtifactPin, ...],
    plan_pin: ArtifactPin,
    map_pin: ArtifactPin,
    reconciliation_pin: ArtifactPin,
) -> ProposalOutcome:
    """Project one rejected or unresolved proposal diagnostic."""
    traces = [_trace(reconciliation_pin, proposal.proposal_id)]
    if proposal.obligation_id in {item.obligation_id for item in plan.obligations}:
        traces.append(_trace(plan_pin, proposal.obligation_id))
    link_ids = {item.link_id for item in resource_map.links}
    traces.extend(
        _trace(map_pin, item) for item in proposal.resource_link_ids if item in link_ids
    )
    return ProposalOutcome(
        proposal_id=proposal.proposal_id,
        obligation_id=proposal.obligation_id,
        risk_id=proposal.risk_id,
        attack_pattern_id=proposal.attack_pattern_id,
        taxonomy_candidate_ids=proposal.taxonomy_candidate_ids,
        ica_slot_id=proposal.ica_slot_id,
        ica_id=proposal.ica_id,
        relation_kind=proposal.relation_kind,
        status=_proposal_status(proposal),
        validation_result=proposal.validation_result,
        validation_codes=proposal.validation_codes,
        source_pins=pins,
        trace_refs=_unique_traces(traces),
    )


def _contradiction_finding(
    reconciliation: ReconciliationResult,
    pins: tuple[ArtifactPin, ...],
    reconciliation_pin: ArtifactPin,
) -> CoverageFinding | None:
    """Retain all proposal-conflict diagnostics as one explicit finding."""
    proposal_ids = tuple(
        item.proposal_id
        for item in reconciliation.proposals
        if {"conflict", "conflicting_relation_proposals"} & set(item.validation_codes)
    )
    if not proposal_ids:
        return None
    return _finding(
        "contradictory_proposals",
        "contradictory correspondence proposals remain unresolved",
        pins,
        reconciliation_pin,
        proposal_ids=proposal_ids,
    )


def _related_proposal_finding(
    reconciliation: ReconciliationResult,
    pins: tuple[ArtifactPin, ...],
    reconciliation_pin: ArtifactPin,
) -> CoverageFinding | None:
    """Retain related-but-not-coverage proposals as explicit findings."""
    proposal_ids = _unaccepted_related_proposal_ids(reconciliation.proposals)
    if not proposal_ids:
        return None
    return _finding(
        "related_but_not_coverage",
        "related proposals are findings and never accepted coverage",
        pins,
        reconciliation_pin,
        proposal_ids=proposal_ids,
    )


def _unaccepted_related_proposal_ids(
    proposals: Sequence[ReconciledProposal],
) -> tuple[str, ...]:
    """Return explicit noncoverage proposals that were not accepted."""
    return tuple(
        item.proposal_id
        for item in proposals
        if item.relation_kind == "related_but_not_coverage"
        and not _is_confirmed_accepted(item)
    )


def _structural_rows(
    stpa: StpaCoverageInput,
    pins: tuple[ArtifactPin, ...],
) -> tuple[StructuralConsiderationRow, ...]:
    """Project one structural-consideration row per deterministic UCA slot."""
    return tuple(
        StructuralConsiderationRow(
            row_id=compute_matrix_row_id("struct", slot.slot_id),
            slot_id=slot.slot_id,
            controller_id=slot.controller_id,
            control_action_id=slot.control_action_id,
            uca_type=slot.uca_type,
            ica_ids=slot.ica_ids,
            disposition=slot.disposition,
            evidence=slot.evidence,
            source_pins=pins,
            trace_refs=_observation_traces(
                slot.source_artifact,
                slot.slot_id,
                slot.trace_refs,
                slot.ica_ids,
            ),
        )
        for slot in stpa.slots
    )


def _scenario_realization_rows(
    relations: Sequence[AcceptedCorrespondenceRelation],
    stpa: StpaCoverageInput,
    pins: tuple[ArtifactPin, ...],
    plan_pin: ArtifactPin,
    map_pin: ArtifactPin,
    reconciliation_pin: ArtifactPin,
) -> tuple[ScenarioRealizationRow, ...]:
    """Project one not-attempted realization row per accepted relation."""
    return tuple(
        _scenario_realization_row(
            relation,
            stpa.scenarios,
            pins,
            plan_pin,
            map_pin,
            reconciliation_pin,
        )
        for relation in relations
    )


def _scenario_realization_row(
    relation: AcceptedCorrespondenceRelation,
    observations: Sequence[StpaScenarioObservation],
    pins: tuple[ArtifactPin, ...],
    plan_pin: ArtifactPin,
    map_pin: ArtifactPin,
    reconciliation_pin: ArtifactPin,
) -> ScenarioRealizationRow:
    """Project one accepted relation and its exact legacy observations."""
    scenarios = tuple(
        item for item in observations if _scenario_matches_relation(item, relation)
    )
    traces = _relation_traces(
        relation, scenarios, plan_pin, map_pin, reconciliation_pin
    )
    return ScenarioRealizationRow(
        row_id=compute_matrix_row_id("real", relation.relation_id),
        relation_id=relation.relation_id,
        proposal_id=relation.proposal_id,
        obligation_id=relation.obligation_id,
        risk_id=relation.risk_id,
        attack_pattern_id=relation.attack_pattern_id,
        taxonomy_candidate_ids=relation.taxonomy_candidate_ids,
        correspondence_relation_kind=relation.relation_kind,
        coverage_bearing=relation.relation_kind in _COVERAGE_RELATION_KINDS,
        legacy_scenario_ids=_field_values(scenarios, "scenario_id"),
        source_pins=pins,
        trace_refs=traces,
    )


def _relation_traces(
    relation: AcceptedCorrespondenceRelation,
    scenarios: Sequence[StpaScenarioObservation],
    plan_pin: ArtifactPin,
    map_pin: ArtifactPin,
    reconciliation_pin: ArtifactPin,
) -> tuple[TraceReference, ...]:
    """Collect exact relation, map, plan, and legacy-scenario traces."""
    traces = [
        _trace(reconciliation_pin, relation.relation_id),
        _trace(plan_pin, relation.obligation_id),
    ]
    traces.extend(_trace(map_pin, item) for item in relation.resource_link_ids)
    traces.extend(_stpa_scenario_traces(scenarios))
    return _unique_traces(traces)


def _stpa_scenario_traces(
    scenarios: Sequence[StpaScenarioObservation],
) -> tuple[TraceReference, ...]:
    """Collect traces for an exact legacy STPA scenario collection."""
    traces = []
    for scenario in scenarios:
        traces.extend(
            _observation_traces(
                scenario.source_artifact,
                scenario.scenario_id,
                scenario.trace_refs,
            )
        )
    return tuple(traces)


def _scenario_matches_relation(
    scenario: StpaScenarioObservation,
    relation: AcceptedCorrespondenceRelation,
) -> bool:
    """Match only the complete exact ICA/slot/EXEC identity."""
    return (
        scenario.ica_slot_id,
        scenario.ica_id,
        scenario.exec_candidate_id,
    ) == (
        relation.ica_slot_id,
        relation.ica_id,
        relation.exec_candidate_id,
    )


def _taxonomy_rows(
    plan: TaxonomyObligationPlan,
    resource_map: SystemResourceMap,
    taxonomy: TaxonomyCoverageInput,
    relations: Sequence[AcceptedCorrespondenceRelation],
    outcomes: Sequence[ProposalOutcome],
    findings: Sequence[CoverageFinding],
    reconciliation: ReconciliationResult,
    pins: tuple[ArtifactPin, ...],
    plan_pin: ArtifactPin,
    reconciliation_pin: ArtifactPin,
) -> tuple[TaxonomyCorrespondenceRow, ...]:
    """Project exactly one taxonomy-correspondence row per obligation."""
    relations_by_obligation = _index_by(relations, "obligation_id")
    outcomes_by_obligation = _index_by(outcomes, "obligation_id")
    scenarios_by_obligation = _index_by(taxonomy.scenarios, "obligation_id")
    decisions_by_obligation = _index_by(
        taxonomy.structural_inapplicability_decisions, "obligation_id"
    )
    findings_by_obligation = _findings_by_obligation(findings, reconciliation)
    return tuple(
        _taxonomy_row(
            obligation,
            resource_map,
            tuple(relations_by_obligation[obligation.obligation_id]),
            tuple(outcomes_by_obligation[obligation.obligation_id]),
            tuple(findings_by_obligation[obligation.obligation_id]),
            tuple(scenarios_by_obligation[obligation.obligation_id]),
            tuple(decisions_by_obligation[obligation.obligation_id]),
            pins,
            plan_pin,
            reconciliation_pin,
        )
        for obligation in plan.obligations
    )


def _index_by(values: Iterable[Any], field_name: str) -> defaultdict[str, list[Any]]:
    """Index records by one exact identity without inferring relationships."""
    result: defaultdict[str, list[Any]] = defaultdict(list)
    for item in values:
        result[getattr(item, field_name)].append(item)
    return result


def _findings_by_obligation(
    findings: Sequence[CoverageFinding],
    reconciliation: ReconciliationResult,
) -> defaultdict[str, list[CoverageFinding]]:
    """Resolve finding record references to their exact obligations."""
    proposal_index = {item.proposal_id: item for item in reconciliation.proposals}
    relation_index = {
        item.relation_id: item for item in reconciliation.accepted_relations
    }
    result: defaultdict[str, list[CoverageFinding]] = defaultdict(list)
    for finding in findings:
        for obligation_id in _finding_obligation_ids(
            finding, proposal_index, relation_index
        ):
            result[obligation_id].append(finding)
    return result


def _finding_obligation_ids(
    finding: CoverageFinding,
    proposals: dict[str, ReconciledProposal],
    relations: dict[str, AcceptedCorrespondenceRelation],
) -> set[str]:
    """Resolve one finding's exact proposal/relation obligation identities."""
    proposal_ids = {proposals[item].obligation_id for item in finding.proposal_ids}
    relation_ids = {relations[item].obligation_id for item in finding.relation_ids}
    return proposal_ids | relation_ids


def _field_values(values: Sequence[Any], field_name: str) -> tuple[Any, ...]:
    """Project one exact field from a typed record collection."""
    return tuple(getattr(item, field_name) for item in values)


def _taxonomy_row(
    obligation: TaxonomyObligation,
    resource_map: SystemResourceMap,
    relations: tuple[AcceptedCorrespondenceRelation, ...],
    outcomes: tuple[ProposalOutcome, ...],
    findings: tuple[CoverageFinding, ...],
    scenarios: tuple[TaxonomyScenarioObservation, ...],
    decisions: tuple[StructuralInapplicabilityDecision, ...],
    pins: tuple[ArtifactPin, ...],
    plan_pin: ArtifactPin,
    reconciliation_pin: ArtifactPin,
) -> TaxonomyCorrespondenceRow:
    """Build one traceable obligation roll-up from exact source records."""
    coverage_relations = _coverage_relations(relations)
    if coverage_relations and decisions:
        raise ValueError(
            "obligation cannot be both satisfied and structurally inapplicable"
        )
    rejected = _outcomes_with_status(outcomes, "rejected")
    unresolved = _outcomes_with_status(outcomes, "unresolved")
    disposition, gap = _correspondence_rollup(
        obligation,
        resource_map,
        coverage_relations,
        rejected,
        unresolved,
        findings,
        decisions,
    )
    traces = _taxonomy_traces(
        obligation,
        relations,
        outcomes,
        findings,
        scenarios,
        decisions,
        plan_pin,
        reconciliation_pin,
    )
    return TaxonomyCorrespondenceRow(
        row_id=compute_matrix_row_id("tax", obligation.obligation_id),
        obligation_id=obligation.obligation_id,
        risk_id=obligation.risk_ref.risk_id,
        attack_pattern_id=obligation.attack_pattern_id,
        attack_pattern_semantic_digest=obligation.attack_pattern_semantic_digest,
        scope_disposition=obligation.scope_disposition,
        qualification_disposition=obligation.qualification_disposition,
        taxonomy_candidate_ids=_field_values(
            obligation.candidate_records, "candidate_id"
        ),
        taxonomy_scenario_ids=_field_values(scenarios, "scenario_id"),
        accepted_relation_ids=_field_values(coverage_relations, "relation_id"),
        rejected_proposal_ids=_field_values(rejected, "proposal_id"),
        unresolved_proposal_ids=_field_values(unresolved, "proposal_id"),
        finding_ids=_field_values(findings, "finding_id"),
        structural_inapplicability_decision_ids=_field_values(decisions, "decision_id"),
        correspondence_disposition=disposition,
        gap_reason=gap,
        source_pins=pins,
        trace_refs=traces,
    )


def _coverage_relations(
    relations: Sequence[AcceptedCorrespondenceRelation],
) -> tuple[AcceptedCorrespondenceRelation, ...]:
    """Keep only accepted relation kinds that satisfy taxonomy correspondence."""
    return tuple(
        item for item in relations if item.relation_kind in _COVERAGE_RELATION_KINDS
    )


def _outcomes_with_status(
    outcomes: Sequence[ProposalOutcome], status: str
) -> tuple[ProposalOutcome, ...]:
    """Select one closed proposal-outcome bucket."""
    return tuple(item for item in outcomes if item.status == status)


def _taxonomy_traces(
    obligation: TaxonomyObligation,
    relations: Sequence[AcceptedCorrespondenceRelation],
    outcomes: Sequence[ProposalOutcome],
    findings: Sequence[CoverageFinding],
    scenarios: Sequence[TaxonomyScenarioObservation],
    decisions: Sequence[StructuralInapplicabilityDecision],
    plan_pin: ArtifactPin,
    reconciliation_pin: ArtifactPin,
) -> tuple[TraceReference, ...]:
    """Collect exact Phase 1, reconciliation, observation, and decision traces."""
    traces = list(_plan_record_traces(obligation, plan_pin))
    traces.extend(
        _reconciliation_record_traces(relations, outcomes, findings, reconciliation_pin)
    )
    traces.extend(_taxonomy_scenario_traces(scenarios))
    traces.extend(_inapplicability_decision_traces(decisions))
    return _unique_traces(traces)


def _plan_record_traces(
    obligation: TaxonomyObligation, plan_pin: ArtifactPin
) -> tuple[TraceReference, ...]:
    """Trace one obligation and each exact candidate child."""
    record_ids = (
        obligation.obligation_id,
        *_field_values(obligation.candidate_records, "candidate_id"),
    )
    return tuple(_trace(plan_pin, item) for item in record_ids)


def _reconciliation_record_traces(
    relations: Sequence[AcceptedCorrespondenceRelation],
    outcomes: Sequence[ProposalOutcome],
    findings: Sequence[CoverageFinding],
    reconciliation_pin: ArtifactPin,
) -> tuple[TraceReference, ...]:
    """Trace exact accepted, rejected, unresolved, and finding source records."""
    record_ids = (
        *_field_values(relations, "relation_id"),
        *_field_values(outcomes, "proposal_id"),
        *_finding_record_ids(findings),
    )
    return tuple(_trace(reconciliation_pin, item) for item in record_ids)


def _finding_record_ids(findings: Sequence[CoverageFinding]) -> tuple[str, ...]:
    """Return the exact reconciliation records cited by findings."""
    return tuple(
        item
        for finding in findings
        for item in (*finding.relation_ids, *finding.proposal_ids)
    )


def _taxonomy_scenario_traces(
    scenarios: Sequence[TaxonomyScenarioObservation],
) -> tuple[TraceReference, ...]:
    """Collect traces for legacy taxonomy scenario observations."""
    traces = []
    for scenario in scenarios:
        traces.extend(
            _observation_traces(
                scenario.source_artifact,
                scenario.scenario_id,
                scenario.trace_refs,
            )
        )
    return tuple(traces)


def _inapplicability_decision_traces(
    decisions: Sequence[StructuralInapplicabilityDecision],
) -> tuple[TraceReference, ...]:
    """Collect reviewed structural-inapplicability decision traces."""
    traces = []
    for decision in decisions:
        traces.extend(
            _observation_traces(
                decision.source_artifact,
                decision.decision_id,
                decision.trace_refs,
                decision.evidence_refs,
            )
        )
    return tuple(traces)


def _correspondence_rollup(
    obligation: TaxonomyObligation,
    resource_map: SystemResourceMap,
    relations: Sequence[AcceptedCorrespondenceRelation],
    rejected: Sequence[ProposalOutcome],
    unresolved: Sequence[ProposalOutcome],
    findings: Sequence[CoverageFinding],
    decisions: Sequence[StructuralInapplicabilityDecision],
) -> tuple[str, str | None]:
    """Return the normative §8.10 disposition and one typed gap reason."""
    candidates = (
        _nonapplicable_rollup(obligation),
        _accepted_rollup(relations),
        _inapplicability_rollup(decisions),
        _finding_rollup(findings),
        _proposal_rollup(rejected, unresolved),
        _resource_map_rollup(obligation, resource_map),
    )
    return next(item for item in candidates if item is not None)


def _nonapplicable_rollup(
    obligation: TaxonomyObligation,
) -> tuple[str, str] | None:
    """Preserve a non-applicable Phase 1 disposition."""
    if obligation.scope_disposition == "applicable":
        return None
    return obligation.scope_disposition, "phase1_not_applicable"


def _accepted_rollup(
    relations: Sequence[AcceptedCorrespondenceRelation],
) -> tuple[str, None] | None:
    """Return satisfaction only when coverage-bearing relations exist."""
    return ("satisfied", None) if relations else None


def _inapplicability_rollup(
    decisions: Sequence[StructuralInapplicabilityDecision],
) -> tuple[str, str] | None:
    """Return reviewed structural inapplicability only from a decision."""
    if not decisions:
        return None
    return "structurally_inapplicable", "reviewed_structural_inapplicability"


def _finding_rollup(
    findings: Sequence[CoverageFinding],
) -> tuple[str, str] | None:
    """Apply the stable priority among non-satisfying finding kinds."""
    finding_kinds = {item.kind for item in findings}
    ordered = (
        "contradictory_proposals",
        "related_but_not_coverage",
    )
    gap = next((item for item in ordered if item in finding_kinds), None)
    return ("unresolved_ambiguous", gap) if gap is not None else None


def _proposal_rollup(
    rejected: Sequence[ProposalOutcome], unresolved: Sequence[ProposalOutcome]
) -> tuple[str, str] | None:
    """Classify unresolved before rejected proposal evidence."""
    if unresolved:
        return "unresolved_ambiguous", "ambiguous_proposals"
    if rejected:
        return "unresolved_rejected_proposals", "rejected_proposals"
    return None


def _resource_map_rollup(
    obligation: TaxonomyObligation, resource_map: SystemResourceMap
) -> tuple[str, str]:
    """Distinguish obligation-specific map evidence from a proposal gap."""
    required_refs = {
        binding.resource_ref
        for candidate in obligation.candidate_records
        for binding in candidate.resource_bindings
    }
    has_authority = any(
        item.authority_status == "authoritative"
        and item.capability_resource_ref in required_refs
        for item in resource_map.links
    )
    if has_authority:
        return "unresolved_no_proposal", "no_accepted_proposal"
    return "unresolved_missing_resource_map", "missing_resource_map"


def _validate_inputs(
    obligation_plan: Any,
    resource_map_validation: Any,
    reconciliation: Any,
    taxonomy_scenarios: Any,
    stpa_scenarios: Any,
) -> tuple[
    TaxonomyObligationPlan,
    SystemResourceMap,
    ReconciliationResult,
    TaxonomyCoverageInput,
    StpaCoverageInput,
]:
    """Require intact, typed, mutually pinned public-seam inputs."""
    _require_type(obligation_plan, TaxonomyObligationPlan, "obligation_plan")
    _require_type(
        resource_map_validation,
        SystemResourceMapValidation,
        "resource_map_validation",
    )
    _require_type(reconciliation, ReconciliationResult, "reconciliation")
    _require_type(taxonomy_scenarios, TaxonomyCoverageInput, "taxonomy_scenarios")
    _require_type(stpa_scenarios, StpaCoverageInput, "stpa_scenarios")
    obligation_plan.assert_integrity()
    resource_map_validation = SystemResourceMapValidation.model_validate(
        resource_map_validation.model_dump(mode="python")
    )
    resource_map = _validated_resource_map(resource_map_validation)
    reconciliation.assert_integrity()
    if (
        obligation_plan.capability_snapshot_digest
        != resource_map.capability_snapshot_digest
    ):
        raise ValueError("resource map is pinned to another capability snapshot")
    if reconciliation.resource_map_semantic_digest != resource_map.semantic_digest:
        raise ValueError("reconciliation is pinned to another resource map")
    if (
        reconciliation.capability_snapshot_digest
        != obligation_plan.capability_snapshot_digest
    ):
        raise ValueError("reconciliation is pinned to another capability snapshot")
    _validate_source_identities(
        obligation_plan,
        resource_map_validation,
        resource_map,
        reconciliation,
        taxonomy_scenarios,
        stpa_scenarios,
    )
    return (
        obligation_plan,
        resource_map,
        reconciliation,
        taxonomy_scenarios,
        stpa_scenarios,
    )


def _validated_resource_map(
    validation: SystemResourceMapValidation,
) -> SystemResourceMap:
    """Require a successful validation attestation and return its canonical map."""
    if (
        not validation.is_valid
        or validation.violations
        or validation.canonical_map is None
    ):
        raise ValueError(
            "resource_map_validation must be a valid resource-map attestation"
        )
    validation.canonical_map.assert_integrity()
    return validation.canonical_map


def _require_type(value: Any, expected: type, label: str) -> None:
    """Require one exact public-seam model type."""
    if not isinstance(value, expected):
        raise TypeError(f"{label} must be a {expected.__name__}")


def _validate_source_identities(
    plan: TaxonomyObligationPlan,
    resource_map_validation: SystemResourceMapValidation,
    resource_map: SystemResourceMap,
    reconciliation: ReconciliationResult,
    taxonomy: TaxonomyCoverageInput,
    stpa: StpaCoverageInput,
) -> None:
    """Reject dangling obligations, candidates, structural IDs, and pins."""
    obligations = {item.obligation_id: item for item in plan.obligations}
    slots = {item.slot_id: item for item in stpa.slots}
    links = {item.link_id for item in resource_map.links}
    _validate_taxonomy_scenario_identities(taxonomy.scenarios, obligations)
    _validate_inapplicability_decisions(
        taxonomy.structural_inapplicability_decisions,
        obligations,
        stpa.inventory_status,
        resource_map_validation,
    )
    _validate_reconciliation_records(
        reconciliation, plan, resource_map, obligations, slots, links
    )


def _validate_taxonomy_scenario_identities(
    scenarios: Sequence[TaxonomyScenarioObservation],
    obligations: dict[str, TaxonomyObligation],
) -> None:
    """Require every taxonomy scenario to resolve to a projectable child."""
    for scenario in scenarios:
        _validate_taxonomy_scenario_identity(scenario, obligations)


def _validate_taxonomy_scenario_identity(
    scenario: TaxonomyScenarioObservation,
    obligations: dict[str, TaxonomyObligation],
) -> None:
    """Validate one exact legacy taxonomy scenario identity."""
    obligation = obligations.get(scenario.obligation_id)
    if obligation is None:
        raise ValueError("taxonomy scenario references an unknown obligation")
    candidates = {item.candidate_id: item for item in obligation.candidate_records}
    candidate = candidates.get(scenario.candidate_id)
    if candidate is None:
        raise ValueError("taxonomy scenario references an unknown candidate")
    if candidate.projection_disposition != "projectable":
        raise ValueError("taxonomy scenario must reference a projectable candidate")


def _validate_inapplicability_decisions(
    decisions: Sequence[StructuralInapplicabilityDecision],
    obligations: dict[str, TaxonomyObligation],
    structural_inventory_status: str,
    resource_map_validation: SystemResourceMapValidation,
) -> None:
    """Require decisions to resolve and retain the actual inventory status."""
    for decision in decisions:
        obligation = obligations.get(decision.obligation_id)
        if obligation is None:
            raise ValueError(
                "structural-inapplicability decision references an unknown obligation"
            )
        if obligation.scope_disposition != "applicable":
            raise ValueError(
                "structural-inapplicability decision requires an applicable obligation"
            )
        if decision.inventory_status != structural_inventory_status:
            raise ValueError(
                "structural-inapplicability decision inventory status does not "
                "match the structural inventory"
            )
        _require_capability_inventory_authority(
            decision, obligation, resource_map_validation
        )


def _require_capability_inventory_authority(
    decision: StructuralInapplicabilityDecision,
    obligation: TaxonomyObligation,
    validation: SystemResourceMapValidation,
) -> None:
    """Reject absence claims over resource-relevant inferred inventories."""
    relevant_kinds = _candidate_resource_kinds(obligation)
    if (
        _has_inferred_relevant_inventory(relevant_kinds, validation)
        and not decision.other_authoritative_evidence_refs
    ):
        raise ValueError(
            "structural inapplicability over inferred-partial capability inventory "
            "requires other authoritative evidence"
        )


def _candidate_resource_kinds(obligation: TaxonomyObligation) -> set[str]:
    """Return exact resource kinds present on this obligation's candidates."""
    return {
        binding.resource_ref.kind
        for candidate in obligation.candidate_records
        for binding in candidate.resource_bindings
    }


def _has_inferred_relevant_inventory(
    relevant_kinds: set[str], validation: SystemResourceMapValidation
) -> bool:
    """Match candidate resource kinds to the attested inventory categories."""
    inferred_entry_points_are_relevant = bool(
        relevant_kinds & {"entry_point", "output_surface"}
    ) and (validation.entry_point_completeness == "inferred_partial")
    inferred_tools_are_relevant = (
        "tool" in relevant_kinds
        and validation.tool_inventory_completeness == "inferred_partial"
    )
    return inferred_entry_points_are_relevant or inferred_tools_are_relevant


def _validate_reconciliation_records(
    reconciliation: ReconciliationResult,
    plan: TaxonomyObligationPlan,
    resource_map: SystemResourceMap,
    obligations: dict[str, TaxonomyObligation],
    slots: dict[str, StructuralSlotObservation],
    links: set[str],
) -> None:
    """Validate only records authorized to contribute accepted coverage."""
    for record in reconciliation.accepted_relations:
        _validate_reconciliation_record(
            record, plan, resource_map, obligations, slots, links
        )


def _validate_reconciliation_record(
    record: AcceptedCorrespondenceRelation,
    plan: TaxonomyObligationPlan,
    resource_map: SystemResourceMap,
    obligations: dict[str, TaxonomyObligation],
    slots: dict[str, StructuralSlotObservation],
    links: set[str],
) -> None:
    """Validate one reconciliation record against exact assessment authorities."""
    if record.obligation_id not in obligations:
        raise ValueError("reconciliation record references an unknown obligation")
    _validate_record_taxonomy_identity(record, obligations[record.obligation_id])
    slot = _validated_record_slot(record, slots)
    _validate_record_links(record, links)
    _validate_record_pins(record, plan, resource_map, slot)


def _validate_record_taxonomy_identity(
    record: AcceptedCorrespondenceRelation,
    obligation: TaxonomyObligation,
) -> None:
    """Require an accepted relation to retain the exact Phase 1 identity."""
    expected_candidates = tuple(
        item.candidate_id for item in obligation.candidate_records
    )
    if record.risk_id != obligation.risk_ref.risk_id:
        raise ValueError("accepted relation substituted the obligation risk")
    if record.attack_pattern_id != obligation.attack_pattern_id:
        raise ValueError("accepted relation substituted the attack pattern")
    if record.taxonomy_candidate_ids != expected_candidates:
        raise ValueError("accepted relation substituted taxonomy candidates")


def _validated_record_slot(
    record: ReconciledProposal | AcceptedCorrespondenceRelation,
    slots: dict[str, StructuralSlotObservation],
) -> StructuralSlotObservation:
    """Resolve and validate one exact slot/ICA/EXEC identity."""
    slot = slots.get(record.ica_slot_id)
    if slot is None:
        raise ValueError("reconciliation record references an unknown ICA slot")
    if record.ica_id not in slot.ica_ids:
        raise ValueError("reconciliation record references an unknown ICA")
    expected_exec = (
        f"EXEC:{slot.controller_id}:{slot.control_action_id}:{slot.uca_type}"
    )
    if record.exec_candidate_id != expected_exec:
        raise ValueError(
            "reconciliation record substituted the canonical EXEC identity"
        )
    return slot


def _validate_record_links(
    record: ReconciledProposal | AcceptedCorrespondenceRelation,
    links: set[str],
) -> None:
    """Require every cited map link to exist exactly."""
    if not set(record.resource_link_ids).issubset(links):
        raise ValueError("reconciliation record references an unknown resource link")


def _validate_record_pins(
    record: ReconciledProposal | AcceptedCorrespondenceRelation,
    plan: TaxonomyObligationPlan,
    resource_map: SystemResourceMap,
    slot: StructuralSlotObservation,
) -> None:
    """Require exact plan, map, structure, and ICA-enumeration pins."""
    source = (
        record.provenance.source_pins
        if isinstance(record, ReconciledProposal)
        else record.source_pins
    )
    _require_digest(
        source.resource_map_semantic_digest,
        resource_map.semantic_digest,
        "reconciliation record is pinned to another resource map",
    )
    _require_digest(
        source.obligation_plan_semantic_digest,
        plan.semantic_digest,
        "reconciliation record is pinned to another obligation plan",
    )
    _require_digest(
        source.control_structure_digest,
        resource_map.control_structure_digest,
        "reconciliation record substituted the control structure",
    )
    _require_digest(
        source.ica_enumeration_digest,
        slot.source_artifact.semantic_digest,
        "reconciliation record substituted the ICA enumeration",
    )


def _require_digest(actual: str | None, expected: str, message: str) -> None:
    """Reject an absent or substituted exact source digest."""
    if actual != expected:
        raise ValueError(message)


def assess_hybrid_coverage(
    obligation_plan: TaxonomyObligationPlan,
    resource_map_validation: SystemResourceMapValidation,
    reconciliation: ReconciliationResult,
    taxonomy_scenarios: TaxonomyCoverageInput,
    stpa_scenarios: StpaCoverageInput,
) -> HybridCoverageAssessment:
    """Build the three source-spec matrices without inference, IO, or providers."""
    plan, resource_map, reconciliation, taxonomy, stpa = _validate_inputs(
        obligation_plan,
        resource_map_validation,
        reconciliation,
        taxonomy_scenarios,
        stpa_scenarios,
    )
    capability_pin, plan_pin, map_pin, reconciliation_pin = _base_pins(
        plan, resource_map, reconciliation
    )
    pins = _source_pins(
        (capability_pin, plan_pin, map_pin, reconciliation_pin), taxonomy, stpa
    )
    relations, relation_findings = _supported_relations_and_findings(
        reconciliation, pins, reconciliation_pin
    )
    outcomes = _proposal_outcomes(
        reconciliation,
        plan,
        resource_map,
        pins,
        plan_pin,
        map_pin,
        reconciliation_pin,
    )
    diagnostic_findings = tuple(
        item
        for item in (
            _related_proposal_finding(reconciliation, pins, reconciliation_pin),
            _contradiction_finding(reconciliation, pins, reconciliation_pin),
        )
        if item is not None
    )
    findings = (*relation_findings, *diagnostic_findings)
    structural = _structural_rows(stpa, pins)
    taxonomy_rows = _taxonomy_rows(
        plan,
        resource_map,
        taxonomy,
        relations,
        outcomes,
        findings,
        reconciliation,
        pins,
        plan_pin,
        reconciliation_pin,
    )
    realization = _scenario_realization_rows(
        relations,
        stpa,
        pins,
        plan_pin,
        map_pin,
        reconciliation_pin,
    )
    diagnostics = derive_hybrid_coverage_diagnostics(
        structural, taxonomy_rows, realization, outcomes, findings
    )
    return HybridCoverageAssessment(
        capability_snapshot_digest=plan.capability_snapshot_digest,
        source_pins=pins,
        structural_inventory_status=stpa.inventory_status,
        structural_consideration=structural,
        taxonomy_correspondence=taxonomy_rows,
        scenario_realization=realization,
        proposal_outcomes=outcomes,
        findings=findings,
        diagnostics=diagnostics,
    )


__all__ = ["assess_hybrid_coverage"]
