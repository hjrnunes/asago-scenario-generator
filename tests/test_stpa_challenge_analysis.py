"""Public-seam tests for the opted-in Phase 3 STPA challenge analysis."""

from __future__ import annotations

import pytest
import yaml
from pathlib import Path

from asago_scenario_generator.models.challenge_analysis import (
    ChallengeAdapterFailureResponse,
    ChallengeAdapterResponse,
    ChallengeAnalysisControls,
    ChallengeAnalysisResult,
    ChallengeTechnicalFailure,
    IcaChallengeDraft,
    JustifiedNaChallengeDraft,
    ProposedIca,
    UnresolvedChallengeDraft,
)
from asago_scenario_generator.models.challenge_ledger import (
    EXPLICIT_PRIORITY_POLICY_VERSION,
    ChallengeEligibility,
)
from asago_scenario_generator.models.hybrid_coverage import (
    ArtifactPin,
    HybridCoverageAssessment,
    StructuralConsiderationRow,
    TaxonomyCorrespondenceRow,
    TraceReference,
    compute_matrix_row_id,
    derive_hybrid_coverage_diagnostics,
)
from asago_scenario_generator.pipeline.challenge_analysis import (
    reconsider_stpa_challenge,
)
from asago_scenario_generator.pipeline.challenge_ledger import (
    build_stpa_challenge_ledger,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    CoordinationLink,
    CoordinationMechanism,
    ProcessModelPart,
    Responsibility,
    ResponsibilityConstraint,
)
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)


OBLIGATION_ID = "ob:v1:" + "a" * 64
SLOT_ID = "RESP-1:CA-1-1:WRONG_TIMING"
REPRESENTATIVE_ANALYSIS = (
    Path(__file__).parent / "fixtures/stpa-obligation-challenge-analysis.yaml"
)


def _pin(artifact_id: str, schema_version: str, value: str) -> ArtifactPin:
    return ArtifactPin(
        artifact_id=artifact_id,
        schema_version=schema_version,
        semantic_digest=value * 64,
    )


def _assessment() -> HybridCoverageAssessment:
    capability = _pin("capability-fact-snapshot", "capability-fact-snapshot-v1", "1")
    plan = _pin("taxonomy-obligation-plan", "taxonomy-obligation-plan-v1", "2")
    enumeration = _pin("ica-enumeration", "ica-enumeration-v1", "3")
    pins = (capability, plan, enumeration)
    structural = (
        StructuralConsiderationRow(
            row_id=compute_matrix_row_id("struct", SLOT_ID),
            slot_id=SLOT_ID,
            controller_id="RESP-1",
            control_action_id="CA-1-1",
            uca_type="WRONG_TIMING",
            disposition="justified_na",
            evidence=("baseline:timing-reviewed",),
            source_pins=pins,
            trace_refs=(
                TraceReference(
                    **enumeration.model_dump(mode="json"),
                    record_id=SLOT_ID,
                ),
            ),
        ),
    )
    taxonomy = (
        TaxonomyCorrespondenceRow(
            row_id=compute_matrix_row_id("tax", OBLIGATION_ID),
            obligation_id=OBLIGATION_ID,
            risk_id="R-1",
            attack_pattern_id="AP-1",
            attack_pattern_semantic_digest="4" * 64,
            scope_disposition="applicable",
            qualification_disposition="ready",
            correspondence_disposition="unresolved_no_proposal",
            gap_reason="no_accepted_proposal",
            source_pins=pins,
            trace_refs=(
                TraceReference(
                    **plan.model_dump(mode="json"),
                    record_id=OBLIGATION_ID,
                ),
            ),
        ),
    )
    return HybridCoverageAssessment(
        capability_snapshot_digest=capability.semantic_digest,
        source_pins=pins,
        structural_inventory_status="complete",
        structural_consideration=structural,
        taxonomy_correspondence=taxonomy,
        scenario_realization=(),
        diagnostics=derive_hybrid_coverage_diagnostics(
            structural, taxonomy, (), (), ()
        ),
    )


def _ledger(assessment: HybridCoverageAssessment):
    return build_stpa_challenge_ledger(
        assessment,
        (
            ChallengeEligibility(
                obligation_id=OBLIGATION_ID,
                slot_id=SLOT_ID,
                priority=1,
                rationale="Analyst-approved reconsideration.",
                evidence_refs=("review:case-1",),
            ),
        ),
        challenge_budget=1,
        assessment_artifact_id="assessment",
        selection_policy_version=EXPLICIT_PRIORITY_POLICY_VERSION,
    )


def _loss_analysis() -> LossAnalysis:
    return LossAnalysis(
        risk_card_losses=(
            Loss(
                loss_id="L-1",
                description="Customer funds are lost.",
                provenance=LossProvenance.risk_card,
                source_risk_cards=("R-1",),
            ),
        ),
        use_case_losses=(),
        hazards=(
            Hazard(
                hazard_id="H-1",
                description="A payment is executed at an unsafe time.",
                related_losses=("L-1",),
            ),
        ),
        security_constraints=(
            SecurityConstraint(
                constraint_id="SC-1",
                rule="Payment timing must be checked.",
                related_hazards=("H-1",),
            ),
        ),
    )


def _control_structure() -> ControlStructure:
    return ControlStructure(
        responsibilities=(
            Responsibility(
                resp_id="RESP-1",
                description="Select safe payment actions.",
                responsibility_constraints=(
                    ResponsibilityConstraint(
                        rc_id="RC-1-1",
                        description="Check timing before payment.",
                    ),
                ),
                security_constraint_refs=("SC-1",),
                control_actions=(
                    ControlAction(
                        ca_id="CA-1-1",
                        description="Execute payment.",
                    ),
                ),
            ),
        ),
    )


def _controls() -> ChallengeAnalysisControls:
    return ChallengeAnalysisControls(
        model_profile="phase3-review",
        model_name="fake-stpa-analyst",
        deadline_seconds=30.0,
        temperature=0.0,
    )


def test_opted_out_analysis_does_not_construct_an_adapter() -> None:
    """Absence of explicit opt-in stops before the provider boundary."""
    assessment = _assessment()
    ledger = _ledger(assessment)
    factory_calls = 0

    def adapter_factory():
        nonlocal factory_calls
        factory_calls += 1
        raise AssertionError("adapter must not be constructed")

    result = reconsider_stpa_challenge(
        ledger,
        assessment,
        ledger.records[0].challenge_id,
        opted_in=False,
        controls=_controls(),
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
        adapter_factory=adapter_factory,
    )

    assert result is None
    assert factory_calls == 0


def test_opted_in_fake_adapter_returns_one_additive_ica() -> None:
    """A typed ICA is structurally validated without replacing the baseline."""
    assessment = _assessment()
    ledger = _ledger(assessment)
    assessment_before = assessment.to_yaml()
    observed_requests = []

    class FakeAdapter:
        def analyze(self, request):
            observed_requests.append(request)
            return ChallengeAdapterResponse(
                request_digest=request.semantic_digest,
                draft=IcaChallengeDraft(
                    proposed_ica=ProposedIca(
                        ica_id=f"{SLOT_ID}:1",
                        exec_candidate_id="EXEC:RESP-1:CA-1-1:WRONG_TIMING",
                        ica_text="Executing payment outside the approved window is unsafe.",
                        hazardous_context="The payment window has expired.",
                        loss_scenario="An out-of-window payment causes H-1 and L-1.",
                        related_hazards=("H-1",),
                        related_constraints=("SC-1",),
                    ),
                    rationale="The obligation exposes a timing path in the existing control loop.",
                    evidence_refs=("H-1", "SC-1", "RC-1-1"),
                ),
                effective_controls=request.controls,
                adapter_kind="fake",
                request_ref="memory://challenge/request-1",
                response_ref="memory://challenge/response-1",
                provider_calls=0,
                network_calls=0,
            )

    result = reconsider_stpa_challenge(
        ledger,
        assessment,
        ledger.records[0].challenge_id,
        opted_in=True,
        controls=_controls(),
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
        adapter_factory=FakeAdapter,
    )

    assert result is not None
    assert result.status == "completed"
    assert result.outcome is not None
    assert result.outcome.disposition == "ica"
    assert result.outcome.ica_ids == (f"{SLOT_ID}:1",)
    assert result.proposed_ica is not None
    assert result.proposed_ica.exec_candidate_id == ("EXEC:RESP-1:CA-1-1:WRONG_TIMING")
    assert result.original_decision == ledger.records[0].original_decision
    assert result.call_evidence.adapter_attempts == 1
    assert result.call_evidence.provider_calls == 0
    assert result.correspondence_changes == result.coverage_changes == 0
    assert result.hybrid_generation_status == "not_attempted"
    assert result.hybrid_admission_status == "not_assessed"
    assert assessment.to_yaml() == assessment_before
    assert len(observed_requests) == 1
    request = observed_requests[0]
    assert request.context.taxonomy.risk_id == "R-1"
    assert request.context.hazards[0].hazard_id == "H-1"
    assert request.context.controller.controller_id == "RESP-1"


def test_fake_adapter_can_return_evidence_backed_justified_na() -> None:
    """A justified N/A is explicit structural evidence, never an empty answer."""
    assessment = _assessment()
    ledger = _ledger(assessment)

    class FakeAdapter:
        def analyze(self, request):
            return ChallengeAdapterResponse(
                request_digest=request.semantic_digest,
                draft=JustifiedNaChallengeDraft(
                    rationale="The timing constraint prevents this path for H-1.",
                    evidence_refs=("H-1", "SC-1"),
                ),
                effective_controls=request.controls,
                adapter_kind="fake",
                request_ref="memory://challenge/request-na",
                response_ref="memory://challenge/response-na",
                provider_calls=0,
                network_calls=0,
            )

    result = reconsider_stpa_challenge(
        ledger,
        assessment,
        ledger.records[0].challenge_id,
        opted_in=True,
        controls=_controls(),
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
        adapter_factory=FakeAdapter,
    )

    assert result is not None
    assert result.outcome is not None
    assert result.outcome.disposition == "justified_na"
    assert result.outcome.evidence_refs == ("H-1", "SC-1")
    assert result.proposed_ica is None
    assert result.original_decision.disposition == "justified_na"


def test_fake_adapter_can_return_typed_unresolved_evidence() -> None:
    """Unresolved remains a terminal STPA result distinct from absence."""
    assessment = _assessment()
    ledger = _ledger(assessment)

    class FakeAdapter:
        def analyze(self, request):
            return ChallengeAdapterResponse(
                request_digest=request.semantic_digest,
                draft=UnresolvedChallengeDraft(
                    reason="missing_evidence",
                    rationale="The available timing evidence does not resolve H-1.",
                    evidence_refs=("H-1",),
                ),
                effective_controls=request.controls,
                adapter_kind="fake",
                request_ref="memory://challenge/request-unresolved",
                response_ref="memory://challenge/response-unresolved",
                provider_calls=0,
                network_calls=0,
            )

    result = reconsider_stpa_challenge(
        ledger,
        assessment,
        ledger.records[0].challenge_id,
        opted_in=True,
        controls=_controls(),
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
        adapter_factory=FakeAdapter,
    )

    assert result is not None
    assert result.outcome is not None
    assert result.outcome.disposition == "unresolved"
    assert result.unresolved_reason == "missing_evidence"
    assert result.coverage_changes == 0


def test_provider_timeout_is_a_separate_technical_failure() -> None:
    """A failed adapter attempt is not mislabeled as an STPA conclusion."""
    assessment = _assessment()
    ledger = _ledger(assessment)

    class TimedOutAdapter:
        def analyze(self, request):
            return ChallengeAdapterFailureResponse(
                request_digest=request.semantic_digest,
                failure=ChallengeTechnicalFailure(
                    kind="provider_timeout",
                    message="The explicit 30 second deadline expired.",
                    evidence_refs=("call-log://challenge/timeout-1",),
                ),
                effective_controls=request.controls,
                adapter_kind="provider",
                request_ref="call-log://challenge/request-timeout",
                provider_calls=1,
                network_calls=1,
            )

    result = reconsider_stpa_challenge(
        ledger,
        assessment,
        ledger.records[0].challenge_id,
        opted_in=True,
        controls=_controls(),
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
        adapter_factory=TimedOutAdapter,
    )

    assert result is not None
    assert result.status == "technical_failure"
    assert result.outcome is None
    assert result.technical_failure is not None
    assert result.technical_failure.kind == "provider_timeout"
    assert result.original_decision == ledger.records[0].original_decision
    assert result.call_evidence.adapter_attempts == 1
    assert result.call_evidence.provider_calls == 1
    assert result.coverage_changes == 0


@pytest.mark.parametrize(
    ("provider_calls", "network_calls"),
    ((1, 0), (0, 1)),
)
def test_fake_adapter_cannot_claim_either_external_call(
    provider_calls: int, network_calls: int
) -> None:
    """Fake evidence stays distinguishable from any external adapter activity."""
    with pytest.raises(
        ValueError, match="fake challenge adapter cannot report provider/network calls"
    ):
        ChallengeAdapterResponse(
            request_digest="a" * 64,
            draft=UnresolvedChallengeDraft(
                reason="adapter_indeterminate",
                rationale="A deterministic fake response.",
                evidence_refs=("fake:evidence",),
            ),
            effective_controls=_controls(),
            adapter_kind="fake",
            request_ref="memory://challenge/request",
            response_ref="memory://challenge/response",
            provider_calls=provider_calls,
            network_calls=network_calls,
        )


def test_dangling_ica_identity_becomes_a_technical_failure() -> None:
    """A provider draft cannot smuggle an invalid ICA into STPA history."""
    assessment = _assessment()
    ledger = _ledger(assessment)

    class BadIdentityAdapter:
        def analyze(self, request):
            return ChallengeAdapterResponse(
                request_digest=request.semantic_digest,
                draft=IcaChallengeDraft(
                    proposed_ica=ProposedIca(
                        ica_id=f"{SLOT_ID}:99",
                        exec_candidate_id="EXEC:RESP-1:CA-1-1:WRONG_TIMING",
                        ica_text="Invalid additive identity.",
                        hazardous_context="H-1 context.",
                        loss_scenario="H-1 could lead to L-1.",
                        related_hazards=("H-1",),
                        related_constraints=("SC-1",),
                    ),
                    rationale="Draft must be rejected by structural validation.",
                    evidence_refs=("H-1", "SC-1"),
                ),
                effective_controls=request.controls,
                adapter_kind="fake",
                request_ref="memory://challenge/request-bad-identity",
                response_ref="memory://challenge/response-bad-identity",
                provider_calls=0,
                network_calls=0,
            )

    result = reconsider_stpa_challenge(
        ledger,
        assessment,
        ledger.records[0].challenge_id,
        opted_in=True,
        controls=_controls(),
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
        adapter_factory=BadIdentityAdapter,
    )

    assert result is not None
    assert result.status == "technical_failure"
    assert result.outcome is None
    assert result.technical_failure is not None
    assert result.technical_failure.kind == "identity_validation_failed"
    assert result.call_evidence.validation_status == "technical_failure"


def test_stale_unknown_and_budget_excluded_targets_stop_before_adapter() -> None:
    """Every exact identity preflight completes before provider construction."""
    assessment = _assessment()
    ledger = _ledger(assessment)
    factory_calls = 0

    def adapter_factory():
        nonlocal factory_calls
        factory_calls += 1
        raise AssertionError("preflight must stop before adapter construction")

    kwargs = {
        "opted_in": True,
        "controls": _controls(),
        "loss_analysis": _loss_analysis(),
        "control_structure": _control_structure(),
        "adapter_factory": adapter_factory,
    }
    stale = assessment.model_copy(update={"semantic_digest": "f" * 64})
    with pytest.raises(ValueError, match="digest mismatch"):
        reconsider_stpa_challenge(
            ledger, stale, ledger.records[0].challenge_id, **kwargs
        )
    with pytest.raises(ValueError, match="does not resolve"):
        reconsider_stpa_challenge(
            ledger, assessment, "challenge:v1:" + "f" * 64, **kwargs
        )
    excluded = build_stpa_challenge_ledger(
        assessment,
        (
            ChallengeEligibility(
                obligation_id=OBLIGATION_ID,
                slot_id=SLOT_ID,
                priority=1,
                rationale="Approved but outside the zero budget.",
                evidence_refs=("review:excluded",),
            ),
        ),
        challenge_budget=0,
        assessment_artifact_id="assessment",
        selection_policy_version=EXPLICIT_PRIORITY_POLICY_VERSION,
    )
    with pytest.raises(ValueError, match="only a selected"):
        reconsider_stpa_challenge(
            excluded, assessment, excluded.records[0].challenge_id, **kwargs
        )
    assert factory_calls == 0


def test_prior_result_enforces_once_only_before_second_adapter_call() -> None:
    """One exact target cannot receive a second analysis attempt."""
    assessment = _assessment()
    ledger = _ledger(assessment)
    factory_calls = 0

    class UnresolvedAdapter:
        def analyze(self, request):
            return ChallengeAdapterResponse(
                request_digest=request.semantic_digest,
                draft=UnresolvedChallengeDraft(
                    reason="insufficient_causal_support",
                    rationale="One bounded attempt found insufficient support.",
                    evidence_refs=("H-1",),
                ),
                effective_controls=request.controls,
                adapter_kind="fake",
                request_ref="memory://challenge/request-once",
                response_ref="memory://challenge/response-once",
                provider_calls=0,
                network_calls=0,
            )

    def adapter_factory():
        nonlocal factory_calls
        factory_calls += 1
        return UnresolvedAdapter()

    kwargs = {
        "opted_in": True,
        "controls": _controls(),
        "loss_analysis": _loss_analysis(),
        "control_structure": _control_structure(),
        "adapter_factory": adapter_factory,
    }
    first = reconsider_stpa_challenge(
        ledger, assessment, ledger.records[0].challenge_id, **kwargs
    )
    assert first is not None
    with pytest.raises(ValueError, match="already attempted"):
        reconsider_stpa_challenge(
            ledger,
            assessment,
            ledger.records[0].challenge_id,
            prior_results=(first,),
            **kwargs,
        )
    assert factory_calls == 1


def test_completed_analysis_round_trips_and_rejects_history_tampering() -> None:
    """The separate result is canonical and content-addressed."""
    assessment = _assessment()
    ledger = _ledger(assessment)

    class Adapter:
        def analyze(self, request):
            return ChallengeAdapterResponse(
                request_digest=request.semantic_digest,
                draft=UnresolvedChallengeDraft(
                    reason="contradictory_evidence",
                    rationale="The bounded evidence remains contradictory.",
                    evidence_refs=("H-1", "SC-1"),
                ),
                effective_controls=request.controls,
                adapter_kind="fake",
                request_ref="memory://challenge/request-roundtrip",
                response_ref="memory://challenge/response-roundtrip",
                provider_calls=0,
                network_calls=0,
            )

    result = reconsider_stpa_challenge(
        ledger,
        assessment,
        ledger.records[0].challenge_id,
        opted_in=True,
        controls=_controls(),
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
        adapter_factory=Adapter,
    )
    assert result is not None

    assert ChallengeAnalysisResult.from_yaml(result.to_yaml()) == result
    assert ChallengeAnalysisResult.from_json(result.to_json()) == result
    tampered = yaml.safe_load(result.to_yaml())
    tampered["original_decision"]["evidence"] = ["forged:baseline"]
    with pytest.raises(ValueError, match="original STPA decision|semantic_digest"):
        ChallengeAnalysisResult.from_yaml(yaml.safe_dump(tampered))
    tampered.pop("semantic_digest")
    with pytest.raises(ValueError, match="semantic_digest is required"):
        ChallengeAnalysisResult.from_yaml(yaml.safe_dump(tampered))
    forged = result.model_dump(mode="json")
    forged["semantic_digest"] = None
    forged["request"]["semantic_digest"] = None
    forged["request"]["challenge_id"] = "challenge:v1:" + "f" * 64
    with pytest.raises(ValueError, match="exact target"):
        ChallengeAnalysisResult.model_validate(forged)


def test_response_substitution_is_recorded_as_invalid_response() -> None:
    """A response for another request cannot become an STPA outcome."""
    assessment = _assessment()
    ledger = _ledger(assessment)

    class SubstitutedAdapter:
        def analyze(self, request):
            return ChallengeAdapterResponse(
                request_digest="f" * 64,
                draft=UnresolvedChallengeDraft(
                    reason="adapter_indeterminate",
                    rationale="This otherwise typed response belongs elsewhere.",
                    evidence_refs=("H-1",),
                ),
                effective_controls=request.controls,
                adapter_kind="fake",
                request_ref="memory://challenge/request-substituted",
                response_ref="memory://challenge/response-substituted",
                provider_calls=0,
                network_calls=0,
            )

    result = reconsider_stpa_challenge(
        ledger,
        assessment,
        ledger.records[0].challenge_id,
        opted_in=True,
        controls=_controls(),
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
        adapter_factory=SubstitutedAdapter,
    )

    assert result is not None
    assert result.status == "technical_failure"
    assert result.technical_failure is not None
    assert result.technical_failure.kind == "invalid_response"
    assert result.outcome is None


def test_representative_analysis_fixture_is_closed_and_integrity_checked() -> None:
    """The handoff fixture is one loadable exact reconsideration record."""
    result = ChallengeAnalysisResult.from_yaml(REPRESENTATIVE_ANALYSIS.read_bytes())

    assert result.status == "completed"
    assert result.outcome is not None
    assert result.outcome.disposition == "unresolved"
    assert result.unresolved_reason == "missing_evidence"
    assert result.original_decision.disposition == "justified_na"
    assert result.correspondence_changes == result.coverage_changes == 0


def test_coordination_slot_uses_exact_link_and_mechanism_context() -> None:
    """Coordination-link UCA slots are first-class exact STPA targets."""
    base = _assessment()
    slot_id = "CL-1:CM-1:INCORRECT"
    structural = (
        StructuralConsiderationRow(
            row_id=compute_matrix_row_id("struct", slot_id),
            slot_id=slot_id,
            controller_id="CL-1",
            control_action_id="CM-1",
            uca_type="INCORRECT",
            disposition="justified_na",
            evidence=("baseline:coordination-reviewed",),
            source_pins=base.source_pins,
            trace_refs=(
                TraceReference(
                    artifact_id="ica-enumeration",
                    schema_version="ica-enumeration-v1",
                    semantic_digest="3" * 64,
                    record_id=slot_id,
                ),
            ),
        ),
    )
    assessment = HybridCoverageAssessment(
        capability_snapshot_digest=base.capability_snapshot_digest,
        source_pins=base.source_pins,
        structural_inventory_status="complete",
        structural_consideration=structural,
        taxonomy_correspondence=base.taxonomy_correspondence,
        scenario_realization=(),
        diagnostics=derive_hybrid_coverage_diagnostics(
            structural, base.taxonomy_correspondence, (), (), ()
        ),
    )
    ledger = build_stpa_challenge_ledger(
        assessment,
        (
            ChallengeEligibility(
                obligation_id=OBLIGATION_ID,
                slot_id=slot_id,
                priority=1,
                rationale="Review the coordination mechanism.",
                evidence_refs=("review:coordination",),
            ),
        ),
        challenge_budget=1,
        assessment_artifact_id="coordination-assessment",
        selection_policy_version=EXPLICIT_PRIORITY_POLICY_VERSION,
    )
    control_structure = ControlStructure(
        responsibilities=(
            Responsibility(
                resp_id="RESP-1",
                description="Source controller.",
                process_model_parts=(
                    ProcessModelPart(
                        pm_id="PM-1-1",
                        description="Shared coordination state.",
                    ),
                ),
            ),
            Responsibility(
                resp_id="RESP-2",
                description="Target controller.",
            ),
        ),
        coordination_links=(
            CoordinationLink(
                link_id="CL-1",
                source="RESP-1",
                target="RESP-2",
                shared_pm="PM-1-1",
                coordination_mechanism=CoordinationMechanism(
                    cm_id="CM-1",
                    description="Synchronize payment state.",
                    payload="payment state",
                ),
                description="Coordinate payment state between controllers.",
            ),
        ),
    )

    class Adapter:
        def analyze(self, request):
            assert request.context.controller.controller_id == "CL-1"
            assert request.context.controller.control_action_id == "CM-1"
            return ChallengeAdapterResponse(
                request_digest=request.semantic_digest,
                draft=JustifiedNaChallengeDraft(
                    rationale="SC-1 and H-1 show the coordination path is inapplicable.",
                    evidence_refs=("H-1", "SC-1"),
                ),
                effective_controls=request.controls,
                adapter_kind="fake",
                request_ref="memory://challenge/request-coordination",
                response_ref="memory://challenge/response-coordination",
                provider_calls=0,
                network_calls=0,
            )

    result = reconsider_stpa_challenge(
        ledger,
        assessment,
        ledger.records[0].challenge_id,
        opted_in=True,
        controls=_controls(),
        loss_analysis=_loss_analysis(),
        control_structure=control_structure,
        adapter_factory=Adapter,
    )

    assert result is not None
    assert result.status == "completed"
    assert result.outcome is not None
    assert result.outcome.disposition == "justified_na"
