"""Explicitly opted-in boundary for one Phase 3 STPA reconsideration."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any, Literal, Protocol

from asago_scenario_generator.models.challenge_analysis import (
    ChallengeAdapterFailureResponse,
    ChallengeAdapterResponse,
    ChallengeAnalysisContext,
    ChallengeAnalysisControls,
    ChallengeAnalysisRequest,
    ChallengeAnalysisResult,
    ChallengeCallEvidence,
    ChallengeConstraintContext,
    ChallengeControllerContext,
    ChallengeHazardContext,
    ChallengeLossContext,
    ChallengeTaxonomyContext,
    ChallengeTechnicalFailure,
    IcaChallengeDraft,
    JustifiedNaChallengeDraft,
    UnresolvedChallengeDraft,
)
from asago_scenario_generator.models.challenge_ledger import (
    ChallengeOutcome,
    ChallengeRecord,
    StpaChallengeLedger,
    compute_challenge_id,
)
from asago_scenario_generator.models.correspondence import compute_loss_analysis_digest
from asago_scenario_generator.models.hybrid_coverage import (
    ArtifactPin,
    HybridCoverageAssessment,
    TaxonomyCorrespondenceRow,
)
from asago_scenario_generator.models.system_resource_map import (
    compute_control_structure_digest,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlStructure,
    CoordinationLink,
    Responsibility,
)
from asago_scenario_generator.stpa.models.execution_envelope import candidate_id_for
from asago_scenario_generator.stpa.models.ica_enumeration import (
    ICA,
    ICAEnumeration,
    ICASlot,
    UCAType,
    ica_id_for,
)
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis


class ChallengeAnalysisAdapter(Protocol):
    """One-call adapter interface; a concrete implementation may own a provider."""

    def analyze(
        self, request: ChallengeAnalysisRequest
    ) -> ChallengeAdapterResponse | ChallengeAdapterFailureResponse:
        """Return one typed response for the exact request."""


def _validate_opt_in(opted_in: bool) -> bool:
    if type(opted_in) is not bool:
        raise TypeError("opted_in must be a boolean")
    return opted_in


def _validate_inputs(
    ledger: StpaChallengeLedger,
    assessment: HybridCoverageAssessment,
    controls: ChallengeAnalysisControls,
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
) -> None:
    _require_instance(ledger, StpaChallengeLedger, "ledger")
    _require_instance(assessment, HybridCoverageAssessment, "assessment")
    _require_instance(controls, ChallengeAnalysisControls, "controls")
    _require_instance(loss_analysis, LossAnalysis, "loss_analysis")
    _require_instance(control_structure, ControlStructure, "control_structure")
    ledger.assert_integrity()
    assessment.assert_integrity()
    _validate_assessment_lineage(ledger, assessment)


def _require_instance(value: Any, expected: type[Any], label: str) -> None:
    if not isinstance(value, expected):
        raise TypeError(f"{label} must be {expected.__name__}")


def _validate_assessment_lineage(
    ledger: StpaChallengeLedger, assessment: HybridCoverageAssessment
) -> None:
    if ledger.assessment_pin.semantic_digest != assessment.semantic_digest:
        raise ValueError("challenge ledger does not pin the supplied assessment")
    if ledger.source_pins != assessment.source_pins:
        raise ValueError("challenge ledger source pins do not match the assessment")


def _selected_record(ledger: StpaChallengeLedger, challenge_id: str) -> ChallengeRecord:
    records = tuple(
        item for item in ledger.records if item.challenge_id == challenge_id
    )
    if len(records) != 1:
        raise ValueError("challenge_id does not resolve to one ledger record")
    record = records[0]
    _validate_selected_state(record)
    _validate_selected_identity(record, ledger.assessment_pin.semantic_digest)
    return record


def _validate_selected_state(record: ChallengeRecord) -> None:
    if record.selection_status != "selected":
        raise ValueError("only a selected challenge target may be reconsidered")
    if record.outcome is not None:
        raise ValueError("selected challenge target already has an outcome")


def _validate_selected_identity(
    record: ChallengeRecord, assessment_digest: str
) -> None:
    expected = compute_challenge_id(
        assessment_digest,
        record.obligation_id,
        record.slot_id,
    )
    if record.challenge_id != expected:
        raise ValueError("selected challenge identity is not assessment-bound")


def _taxonomy_row(
    assessment: HybridCoverageAssessment, obligation_id: str
) -> TaxonomyCorrespondenceRow:
    rows = tuple(
        row
        for row in assessment.taxonomy_correspondence
        if row.obligation_id == obligation_id
    )
    if len(rows) != 1:
        raise ValueError("challenge obligation does not resolve in the assessment")
    return rows[0]


def _responsibility_context(
    responsibility: Responsibility, record: ChallengeRecord
) -> ChallengeControllerContext:
    action = _control_action(responsibility, record.original_decision.control_action_id)
    if action is None:
        raise ValueError("challenge control action does not resolve under controller")
    return ChallengeControllerContext(
        controller_id=responsibility.resp_id,
        controller_description=responsibility.description,
        control_action_id=action.ca_id,
        control_action_description=action.description,
        responsibility_constraint_ids=tuple(
            item.rc_id for item in responsibility.responsibility_constraints
        ),
    )


def _control_action(responsibility: Responsibility, action_id: str) -> Any | None:
    actions = tuple(
        item for item in responsibility.control_actions if item.ca_id == action_id
    )
    return actions[0] if len(actions) == 1 else None


def _coordination_context(
    link: CoordinationLink,
    responsibilities: tuple[Responsibility, ...],
    record: ChallengeRecord,
) -> ChallengeControllerContext:
    mechanism = link.coordination_mechanism
    if mechanism.cm_id != record.original_decision.control_action_id:
        raise ValueError("challenge coordination mechanism does not resolve under link")
    return ChallengeControllerContext(
        controller_id=link.link_id,
        controller_description=link.description,
        control_action_id=mechanism.cm_id,
        control_action_description=mechanism.description,
        responsibility_constraint_ids=tuple(
            constraint.rc_id
            for responsibility in responsibilities
            for constraint in responsibility.responsibility_constraints
        ),
    )


def _controller_authority(
    control_structure: ControlStructure, record: ChallengeRecord
) -> tuple[ChallengeControllerContext, tuple[Responsibility, ...]]:
    controller_id = record.original_decision.controller_id
    responsibilities = _responsibilities_by_id(control_structure, {controller_id})
    if len(responsibilities) == 1:
        return _responsibility_context(responsibilities[0], record), responsibilities
    return _coordination_authority(control_structure, record, controller_id)


def _responsibilities_by_id(
    control_structure: ControlStructure, identifiers: set[str]
) -> tuple[Responsibility, ...]:
    return tuple(
        item
        for item in control_structure.responsibilities
        if item.resp_id in identifiers
    )


def _coordination_authority(
    control_structure: ControlStructure,
    record: ChallengeRecord,
    controller_id: str,
) -> tuple[ChallengeControllerContext, tuple[Responsibility, ...]]:
    link = _coordination_link(control_structure, controller_id)
    linked = _linked_responsibilities(control_structure, link)
    return _coordination_context(link, linked, record), linked


def _coordination_link(
    control_structure: ControlStructure, controller_id: str
) -> CoordinationLink:
    links = tuple(
        item
        for item in control_structure.coordination_links
        if item.link_id == controller_id
    )
    if len(links) != 1:
        raise ValueError("challenge controller does not resolve in control structure")
    return links[0]


def _linked_responsibilities(
    control_structure: ControlStructure, link: CoordinationLink
) -> tuple[Responsibility, ...]:
    linked = _responsibilities_by_id(control_structure, {link.source, link.target})
    if len(linked) != 2:
        raise ValueError("coordination link controllers do not resolve")
    return linked


def _taxonomy_context(row: TaxonomyCorrespondenceRow) -> ChallengeTaxonomyContext:
    return ChallengeTaxonomyContext(
        obligation_id=row.obligation_id,
        risk_id=row.risk_id,
        attack_pattern_id=row.attack_pattern_id,
        attack_pattern_semantic_digest=row.attack_pattern_semantic_digest,
        scope_disposition=row.scope_disposition,
        qualification_disposition=row.qualification_disposition,
        correspondence_disposition=row.correspondence_disposition,
        gap_reason=row.gap_reason,
        accepted_relation_ids=row.accepted_relation_ids,
        trace_refs=row.trace_refs,
    )


def _loss_contexts(loss_analysis: LossAnalysis) -> tuple[ChallengeLossContext, ...]:
    return tuple(
        ChallengeLossContext(loss_id=item.loss_id, description=item.description)
        for item in (*loss_analysis.risk_card_losses, *loss_analysis.use_case_losses)
    )


def _hazard_contexts(
    loss_analysis: LossAnalysis,
) -> tuple[ChallengeHazardContext, ...]:
    return tuple(
        ChallengeHazardContext(
            hazard_id=item.hazard_id,
            description=item.description,
            related_losses=tuple(item.related_losses),
        )
        for item in loss_analysis.hazards
    )


def _constraint_contexts(
    loss_analysis: LossAnalysis, responsibilities: Sequence[Responsibility]
) -> tuple[ChallengeConstraintContext, ...]:
    system = tuple(
        ChallengeConstraintContext(
            constraint_id=item.constraint_id,
            description=item.description,
            related_hazards=tuple(item.related_hazards),
        )
        for item in loss_analysis.security_constraints
    )
    responsibility_constraints = tuple(
        ChallengeConstraintContext(
            constraint_id=item.rc_id,
            description=item.description,
        )
        for responsibility in responsibilities
        for item in responsibility.responsibility_constraints
    )
    return (*system, *responsibility_constraints)


def _analysis_context(
    record: ChallengeRecord,
    taxonomy: TaxonomyCorrespondenceRow,
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
) -> ChallengeAnalysisContext:
    controller, responsibilities = _controller_authority(control_structure, record)
    original = record.original_decision
    return ChallengeAnalysisContext(
        taxonomy=_taxonomy_context(taxonomy),
        controller=controller,
        losses=_loss_contexts(loss_analysis),
        hazards=_hazard_contexts(loss_analysis),
        constraints=_constraint_contexts(loss_analysis, responsibilities),
        loss_analysis_pin=ArtifactPin(
            artifact_id="phase3-loss-analysis",
            schema_version="loss-analysis-v1",
            semantic_digest=compute_loss_analysis_digest(loss_analysis),
        ),
        control_structure_pin=ArtifactPin(
            artifact_id="phase3-control-structure",
            schema_version="control-structure-v1",
            semantic_digest=compute_control_structure_digest(control_structure),
        ),
        exec_candidate_id=candidate_id_for(
            original.controller_id,
            original.control_action_id,
            UCAType(original.uca_type),
        ),
    )


def _request(
    ledger: StpaChallengeLedger,
    record: ChallengeRecord,
    taxonomy: TaxonomyCorrespondenceRow,
    controls: ChallengeAnalysisControls,
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
) -> ChallengeAnalysisRequest:
    return ChallengeAnalysisRequest(
        challenge_id=record.challenge_id,
        assessment_pin=ledger.assessment_pin,
        source_pins=ledger.source_pins,
        original_decision=record.original_decision,
        context=_analysis_context(record, taxonomy, loss_analysis, control_structure),
        controls=controls,
    )


def _validate_response(
    value: Any, request: ChallengeAnalysisRequest
) -> ChallengeAdapterResponse | ChallengeAdapterFailureResponse:
    response = _response_model(value)
    _validate_response_binding(response, request)
    return response


def _response_model(
    value: Any,
) -> ChallengeAdapterResponse | ChallengeAdapterFailureResponse:
    if isinstance(value, ChallengeAdapterFailureResponse) or (
        isinstance(value, dict) and value.get("status") == "technical_failure"
    ):
        return ChallengeAdapterFailureResponse.model_validate(value)
    return ChallengeAdapterResponse.model_validate(value)


def _validate_response_binding(
    response: ChallengeAdapterResponse | ChallengeAdapterFailureResponse,
    request: ChallengeAnalysisRequest,
) -> None:
    if response.request_digest != request.semantic_digest:
        raise ValueError("challenge adapter response is bound to another request")
    if response.effective_controls != request.controls:
        raise ValueError("challenge adapter substituted effective controls")


def _validate_additive_ica(
    draft: IcaChallengeDraft,
    request: ChallengeAnalysisRequest,
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
) -> None:
    proposed = draft.proposed_ica
    _validate_ica_identity(proposed.ica_id, proposed.exec_candidate_id, request)
    _validate_ica_evidence(draft)
    _validate_ica_structure(draft, request, loss_analysis, control_structure)


def _validate_ica_identity(
    ica_id: str, exec_candidate_id: str, request: ChallengeAnalysisRequest
) -> None:
    original = request.original_decision
    expected_id = ica_id_for(original.slot_id, len(original.ica_ids) + 1)
    if ica_id != expected_id:
        raise ValueError("proposed ICA identity is not the next additive slot identity")
    if exec_candidate_id != request.context.exec_candidate_id:
        raise ValueError("proposed ICA substituted the canonical EXEC identity")


def _validate_ica_evidence(draft: IcaChallengeDraft) -> None:
    proposed = draft.proposed_ica
    if not set(proposed.related_hazards).issubset(set(draft.evidence_refs)):
        raise ValueError("ICA evidence does not retain every related hazard")
    if not set(proposed.related_constraints).issubset(set(draft.evidence_refs)):
        raise ValueError("ICA evidence does not retain every related constraint")


def _validate_ica_structure(
    draft: IcaChallengeDraft,
    request: ChallengeAnalysisRequest,
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
) -> None:
    proposed = draft.proposed_ica
    original = request.original_decision
    ica = ICA(
        ica_id=proposed.ica_id,
        ica_text=proposed.ica_text,
        hazardous_context=proposed.hazardous_context,
        loss_scenario=proposed.loss_scenario,
        related_hazards=list(proposed.related_hazards),
        related_constraints=list(proposed.related_constraints),
    )
    enumeration = ICAEnumeration(
        slots=[
            ICASlot(
                slot_id=original.slot_id,
                responsibility=original.controller_id,
                control_action=original.control_action_id,
                uca_type=UCAType(original.uca_type),
                is_na=False,
                icas=[ica],
            )
        ]
    )
    enumeration.validate_against(loss_analysis, control_structure)


def _outcome(
    response: ChallengeAdapterResponse,
    request: ChallengeAnalysisRequest,
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
) -> ChallengeOutcome:
    draft = response.draft
    if isinstance(draft, IcaChallengeDraft):
        _validate_additive_ica(draft, request, loss_analysis, control_structure)
        ica_ids = (draft.proposed_ica.ica_id,)
    else:
        _validate_structural_evidence(draft, request)
        ica_ids = ()
    return ChallengeOutcome(
        disposition=draft.disposition,
        ica_ids=ica_ids,
        rationale=draft.rationale,
        evidence_refs=draft.evidence_refs,
    )


def _validate_structural_evidence(
    draft: JustifiedNaChallengeDraft | UnresolvedChallengeDraft,
    request: ChallengeAnalysisRequest,
) -> None:
    context = request.context
    hazard_ids = {item.hazard_id for item in context.hazards}
    constraint_ids = {item.constraint_id for item in context.constraints}
    allowed = _structural_evidence_ids(request)
    if not set(draft.evidence_refs).issubset(allowed):
        raise ValueError("challenge outcome references unknown structural evidence")
    if isinstance(draft, JustifiedNaChallengeDraft):
        _validate_na_evidence(draft, hazard_ids, constraint_ids)


def _structural_evidence_ids(request: ChallengeAnalysisRequest) -> set[str]:
    context = request.context
    return {
        *(item.loss_id for item in context.losses),
        *(item.hazard_id for item in context.hazards),
        *(item.constraint_id for item in context.constraints),
        context.controller.controller_id,
        context.controller.control_action_id,
    }


def _validate_na_evidence(
    draft: JustifiedNaChallengeDraft,
    hazard_ids: set[str],
    constraint_ids: set[str],
) -> None:
    refs = set(draft.evidence_refs)
    if not refs.intersection(hazard_ids):
        raise ValueError("justified N/A requires authoritative hazard evidence")
    if not refs.intersection(constraint_ids):
        raise ValueError("justified N/A requires authoritative constraint evidence")


def _call_evidence(
    response: ChallengeAdapterResponse | ChallengeAdapterFailureResponse,
    *,
    validation_status: Literal["accepted", "technical_failure"] | None = None,
) -> ChallengeCallEvidence:
    return ChallengeCallEvidence(
        adapter_kind=response.adapter_kind,
        provider_calls=response.provider_calls,
        network_calls=response.network_calls,
        request_digest=response.request_digest,
        response_digest=response.response_digest,
        request_ref=response.request_ref,
        response_ref=response.response_ref,
        effective_controls=response.effective_controls,
        validation_status=validation_status
        or (
            "accepted"
            if isinstance(response, ChallengeAdapterResponse)
            else "technical_failure"
        ),
    )


def _invalid_response_result(
    value: ChallengeAdapterResponse | ChallengeAdapterFailureResponse,
    request: ChallengeAnalysisRequest,
    record: ChallengeRecord,
    error: ValueError,
) -> ChallengeAnalysisResult:
    evidence = ChallengeCallEvidence(
        adapter_kind=value.adapter_kind,
        provider_calls=value.provider_calls,
        network_calls=value.network_calls,
        request_digest=request.semantic_digest,
        response_digest=value.response_digest,
        request_ref=value.request_ref,
        response_ref=value.response_ref,
        effective_controls=request.controls,
        validation_status="technical_failure",
    )
    return ChallengeAnalysisResult(
        status="technical_failure",
        request=request,
        original_decision=record.original_decision,
        technical_failure=ChallengeTechnicalFailure(
            kind="invalid_response",
            message=str(error),
            evidence_refs=(value.response_ref or value.request_ref,),
        ),
        call_evidence=evidence,
    )


def _reject_prior_attempt(
    record: ChallengeRecord, prior_results: Sequence[ChallengeAnalysisResult]
) -> None:
    if any(
        result.request.challenge_id == record.challenge_id for result in prior_results
    ):
        raise ValueError("selected challenge target was already attempted")


def _adapter_response(
    adapter: ChallengeAnalysisAdapter,
    request: ChallengeAnalysisRequest,
    record: ChallengeRecord,
) -> (
    ChallengeAdapterResponse | ChallengeAdapterFailureResponse | ChallengeAnalysisResult
):
    raw = adapter.analyze(request)
    try:
        return _validate_response(raw, request)
    except ValueError as error:
        if isinstance(raw, (ChallengeAdapterResponse, ChallengeAdapterFailureResponse)):
            return _invalid_response_result(raw, request, record, error)
        raise


def _adapter_failure_result(
    response: ChallengeAdapterFailureResponse,
    request: ChallengeAnalysisRequest,
    record: ChallengeRecord,
) -> ChallengeAnalysisResult:
    return ChallengeAnalysisResult(
        status="technical_failure",
        request=request,
        original_decision=record.original_decision,
        technical_failure=response.failure,
        call_evidence=_call_evidence(response),
    )


def _identity_failure_result(
    response: ChallengeAdapterResponse,
    request: ChallengeAnalysisRequest,
    record: ChallengeRecord,
    error: ValueError,
) -> ChallengeAnalysisResult:
    return ChallengeAnalysisResult(
        status="technical_failure",
        request=request,
        original_decision=record.original_decision,
        technical_failure=ChallengeTechnicalFailure(
            kind="identity_validation_failed",
            message=str(error),
            evidence_refs=(response.response_ref,),
        ),
        call_evidence=_call_evidence(response, validation_status="technical_failure"),
    )


def _completed_result(
    response: ChallengeAdapterResponse,
    request: ChallengeAnalysisRequest,
    record: ChallengeRecord,
    outcome: ChallengeOutcome,
) -> ChallengeAnalysisResult:
    draft = response.draft
    return ChallengeAnalysisResult(
        request=request,
        original_decision=record.original_decision,
        outcome=outcome,
        proposed_ica=(
            draft.proposed_ica if isinstance(draft, IcaChallengeDraft) else None
        ),
        unresolved_reason=(
            draft.reason if isinstance(draft, UnresolvedChallengeDraft) else None
        ),
        call_evidence=_call_evidence(response),
    )


def _finalize_response(
    response: ChallengeAdapterResponse | ChallengeAdapterFailureResponse,
    request: ChallengeAnalysisRequest,
    record: ChallengeRecord,
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
) -> ChallengeAnalysisResult:
    if isinstance(response, ChallengeAdapterFailureResponse):
        return _adapter_failure_result(response, request, record)
    try:
        outcome = _outcome(response, request, loss_analysis, control_structure)
    except ValueError as error:
        return _identity_failure_result(response, request, record, error)
    return _completed_result(response, request, record, outcome)


def reconsider_stpa_challenge(
    ledger: StpaChallengeLedger,
    assessment: HybridCoverageAssessment,
    challenge_id: str,
    *,
    opted_in: bool,
    controls: ChallengeAnalysisControls,
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
    adapter_factory: Callable[[], ChallengeAnalysisAdapter],
    prior_results: Sequence[ChallengeAnalysisResult] = (),
) -> ChallengeAnalysisResult | None:
    """Run one exact challenge only after explicit opt-in and offline preflight."""
    if not _validate_opt_in(opted_in):
        return None
    _validate_inputs(ledger, assessment, controls, loss_analysis, control_structure)
    record = _selected_record(ledger, challenge_id)
    _reject_prior_attempt(record, prior_results)
    taxonomy = _taxonomy_row(assessment, record.obligation_id)
    request = _request(
        ledger,
        record,
        taxonomy,
        controls,
        loss_analysis,
        control_structure,
    )
    response = _adapter_response(adapter_factory(), request, record)
    if isinstance(response, ChallengeAnalysisResult):
        return response
    return _finalize_response(
        response,
        request,
        record,
        loss_analysis,
        control_structure,
    )


__all__ = ["ChallengeAnalysisAdapter", "reconsider_stpa_challenge"]
