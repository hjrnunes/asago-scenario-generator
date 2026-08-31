"""Public-seam tests for bounded Phase 3 closed-loop composition."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from asago_scenario_generator.models.challenge_analysis import (
    ChallengeAdapterFailureResponse,
    ChallengeAdapterResponse,
    ChallengeAnalysisControls,
    ChallengeTechnicalFailure,
    IcaChallengeDraft,
    JustifiedNaChallengeDraft,
    ProposedIca,
    UnresolvedChallengeDraft,
)
from asago_scenario_generator.models.challenge_ledger import ChallengeEligibility
from asago_scenario_generator.models.closed_loop_stpa import (
    ClosedLoopRunDiagnostics,
    ClosedLoopStpaRun,
)
from asago_scenario_generator.models.hybrid_coverage import (
    HybridCoverageAssessment,
    StructuralConsiderationRow,
    compute_matrix_row_id,
    derive_hybrid_coverage_diagnostics,
)
from asago_scenario_generator.pipeline.closed_loop_stpa import run_closed_loop_stpa
from asago_scenario_generator.pipeline.closed_loop_stpa_persistence import (
    STPA_CLOSED_LOOP_RUN_FILENAME,
    read_closed_loop_stpa_run,
    write_closed_loop_stpa_run,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
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


ASSESSMENT_PATH = Path(__file__).parent / "fixtures/hybrid-coverage-assessment.yaml"
LINEAGE_AUDIT_PATH = Path(__file__).parent / "fixtures/phase3-lineage-audit.yaml"


def _assessment() -> HybridCoverageAssessment:
    return HybridCoverageAssessment.from_yaml(ASSESSMENT_PATH.read_bytes())


def _multi_assessment() -> HybridCoverageAssessment:
    base = _assessment()
    template = base.structural_consideration[0]
    specifications = (
        ("NOT_PROVIDED", "unresolved", ()),
        ("INCORRECT", "justified_na", ()),
        ("WRONG_TIMING", "ica", ("RESP-1:CA-1-1:WRONG_TIMING:1",)),
        ("WRONG_DURATION", "justified_na", ()),
    )
    structural = tuple(
        StructuralConsiderationRow(
            row_id=compute_matrix_row_id("struct", slot_id),
            slot_id=slot_id,
            controller_id="RESP-1",
            control_action_id="CA-1-1",
            uca_type=uca_type,
            disposition=disposition,
            ica_ids=ica_ids,
            evidence=(f"stpa:{slot_id}",),
            source_pins=template.source_pins,
            trace_refs=(
                template.trace_refs[0].model_copy(update={"record_id": slot_id}),
            ),
        )
        for uca_type, disposition, ica_ids in specifications
        for slot_id in (f"RESP-1:CA-1-1:{uca_type}",)
    )
    payload = base.model_dump(mode="json")
    payload.update(
        structural_consideration=[item.model_dump(mode="json") for item in structural],
        diagnostics=derive_hybrid_coverage_diagnostics(
            structural,
            base.taxonomy_correspondence,
            base.scenario_realization,
            base.findings,
            base.proposal_outcomes,
        ).model_dump(mode="json"),
        semantic_digest=None,
    )
    return HybridCoverageAssessment.model_validate(payload)


def _eligibility(
    assessment: HybridCoverageAssessment,
) -> tuple[ChallengeEligibility, ...]:
    return (
        ChallengeEligibility(
            obligation_id=assessment.taxonomy_correspondence[0].obligation_id,
            slot_id=assessment.structural_consideration[0].slot_id,
            priority=1,
            rationale="An analyst explicitly approved this bounded challenge.",
            evidence_refs=("review:phase3:composition",),
        ),
    )


def _controls() -> ChallengeAnalysisControls:
    return ChallengeAnalysisControls(
        model_profile="phase3-review",
        model_name="fake-stpa-analyst",
        deadline_seconds=30.0,
        temperature=0.0,
    )


def _loss_analysis() -> LossAnalysis:
    return LossAnalysis(
        risk_card_losses=(
            Loss(
                loss_id="L-1",
                description="Funds are lost.",
                provenance=LossProvenance.risk_card,
                source_risk_cards=("risk-a",),
            ),
        ),
        use_case_losses=(),
        hazards=(
            Hazard(
                hazard_id="H-1",
                description="An action occurs in an unsafe state.",
                related_losses=("L-1",),
            ),
        ),
        security_constraints=(
            SecurityConstraint(
                constraint_id="SC-1",
                description="The action must occur only in a safe state.",
                related_hazards=("H-1",),
            ),
        ),
    )


def _control_structure() -> ControlStructure:
    return ControlStructure(
        responsibilities=(
            Responsibility(
                resp_id="RESP-1",
                description="Control the action safely.",
                responsibility_constraints=(
                    ResponsibilityConstraint(
                        rc_id="RC-1-1",
                        description="Check state before acting.",
                    ),
                ),
                security_constraint_refs=("SC-1",),
                control_actions=(
                    ControlAction(
                        ca_id="CA-1-1",
                        description="Perform the controlled action.",
                    ),
                ),
            ),
        ),
    )


class _UnresolvedAdapter:
    def analyze(self, request):
        return ChallengeAdapterResponse(
            request_digest=request.semantic_digest,
            draft=UnresolvedChallengeDraft(
                reason="missing_evidence",
                rationale="The bounded evidence cannot resolve the causal path.",
                evidence_refs=("H-1",),
            ),
            effective_controls=request.controls,
            adapter_kind="fake",
            request_ref="memory://closed-loop/request",
            response_ref="memory://closed-loop/response",
            provider_calls=0,
            network_calls=0,
        )


class _OutcomeAdapter:
    def __init__(self, uca_type: str) -> None:
        self.uca_type = uca_type

    def analyze(self, request):
        slot_id = request.original_decision.slot_id
        if self.uca_type == "INCORRECT":
            draft = IcaChallengeDraft(
                proposed_ica=ProposedIca(
                    ica_id=f"{slot_id}:1",
                    exec_candidate_id=request.context.exec_candidate_id,
                    ica_text="The controller performs the action incorrectly.",
                    hazardous_context="The state makes the action hazardous.",
                    loss_scenario="The incorrect action contributes to L-1.",
                    related_hazards=("H-1",),
                    related_constraints=("SC-1",),
                ),
                rationale="The evidence supports one additive ICA.",
                evidence_refs=("H-1", "SC-1"),
            )
        elif self.uca_type == "WRONG_DURATION":
            draft = JustifiedNaChallengeDraft(
                rationale="H-1 and SC-1 show duration is structurally inapplicable.",
                evidence_refs=("H-1", "SC-1"),
            )
        else:
            draft = UnresolvedChallengeDraft(
                reason="contradictory_evidence",
                rationale="The bounded evidence remains contradictory.",
                evidence_refs=("H-1", "SC-1"),
            )
        return ChallengeAdapterResponse(
            request_digest=request.semantic_digest,
            draft=draft,
            effective_controls=request.controls,
            adapter_kind="fake",
            request_ref=f"memory://closed-loop/{self.uca_type}/request",
            response_ref=f"memory://closed-loop/{self.uca_type}/response",
            provider_calls=0,
            network_calls=0,
        )


class _TechnicalFailureAdapter:
    def analyze(self, request):
        return ChallengeAdapterFailureResponse(
            request_digest=request.semantic_digest,
            failure=ChallengeTechnicalFailure(
                kind="provider_timeout",
                message="The explicit deadline expired.",
                evidence_refs=("call-log://closed-loop/timeout",),
            ),
            effective_controls=request.controls,
            adapter_kind="provider",
            request_ref="call-log://closed-loop/request",
            provider_calls=1,
            network_calls=1,
        )


def test_opted_in_composition_delegates_one_selected_target_without_rewriting_phase2() -> (
    None
):
    """The composed seam adds adjacent challenge history and nothing else."""
    assessment = _assessment()
    before = assessment.to_yaml()
    adapter_targets: list[str] = []

    def adapter_factory(record):
        adapter_targets.append(record.challenge_id)
        return _UnresolvedAdapter()

    run = run_closed_loop_stpa(
        assessment,
        _eligibility(assessment),
        challenge_budget=1,
        assessment_artifact_id="representative-hybrid-coverage-assessment",
        opted_in=True,
        controls=_controls(),
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
        adapter_factory=adapter_factory,
    )

    assert len(run.ledger.records) == 1
    assert run.ledger.records[0].selection_status == "selected"
    assert adapter_targets == [run.ledger.records[0].challenge_id]
    assert len(run.analyses) == 1
    assert run.analyses[0].outcome is not None
    assert run.analyses[0].outcome.disposition == "unresolved"
    assert run.analyses[0].original_decision == run.ledger.records[0].original_decision
    assert run.correspondence_changes == run.coverage_changes == 0
    assert run.hybrid_generation_status == "not_attempted"
    assert run.hybrid_admission_status == "not_assessed"
    assert assessment.to_yaml() == before


def test_composition_rejects_non_boolean_opt_in_before_adapter_construction() -> None:
    """Truthy integers cannot cross the explicit opt-in boundary."""
    assessment = _assessment()

    with pytest.raises(TypeError, match="strict boolean"):
        run_closed_loop_stpa(
            assessment,
            _eligibility(assessment),
            challenge_budget=1,
            assessment_artifact_id="representative-hybrid-coverage-assessment",
            opted_in=1,  # type: ignore[arg-type]
            controls=_controls(),
            loss_analysis=_loss_analysis(),
            control_structure=_control_structure(),
            adapter_factory=lambda record: (_ for _ in ()).throw(
                AssertionError("adapter must not be constructed")
            ),
        )


@pytest.mark.parametrize("field_name", ClosedLoopRunDiagnostics.model_fields)
def test_closed_loop_diagnostic_counts_are_strict_non_negative_integers(
    field_name: str,
) -> None:
    """Every independent count accepts zero and rejects boolean coercion."""
    zero_counts = {name: 0 for name in ClosedLoopRunDiagnostics.model_fields}
    assert (
        ClosedLoopRunDiagnostics.model_validate(zero_counts).model_dump() == zero_counts
    )

    invalid = {**zero_counts, field_name: False}
    with pytest.raises(ValidationError):
        ClosedLoopRunDiagnostics.model_validate(invalid)


def test_repeated_run_reuses_the_exact_attempt_without_constructing_an_adapter() -> (
    None
):
    """Resume is idempotent: an exact prior attempt is history, not a retry."""
    assessment = _assessment()
    arguments = {
        "challenge_budget": 1,
        "assessment_artifact_id": "representative-hybrid-coverage-assessment",
        "opted_in": True,
        "controls": _controls(),
        "loss_analysis": _loss_analysis(),
        "control_structure": _control_structure(),
    }
    first = run_closed_loop_stpa(
        assessment,
        _eligibility(assessment),
        adapter_factory=lambda record: _UnresolvedAdapter(),
        **arguments,
    )

    def forbidden_factory(record):
        raise AssertionError(f"adapter reconstructed for {record.challenge_id}")

    repeated = run_closed_loop_stpa(
        assessment,
        _eligibility(assessment),
        adapter_factory=forbidden_factory,
        prior_run=first,
        **arguments,
    )

    assert repeated == first


def test_closed_loop_run_publishes_atomically_and_round_trips_without_repair(
    tmp_path: Path,
) -> None:
    """One canonical record contains selection and adjacent attempt history."""
    assessment = _assessment()
    run = run_closed_loop_stpa(
        assessment,
        _eligibility(assessment),
        challenge_budget=1,
        assessment_artifact_id="representative-hybrid-coverage-assessment",
        opted_in=True,
        controls=_controls(),
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
        adapter_factory=lambda record: _UnresolvedAdapter(),
    )

    path = write_closed_loop_stpa_run(tmp_path, run)
    first_bytes = path.read_bytes()
    repeated_path = write_closed_loop_stpa_run(tmp_path, run)

    assert path.name == STPA_CLOSED_LOOP_RUN_FILENAME
    assert repeated_path.read_bytes() == first_bytes
    assert read_closed_loop_stpa_run(path) == run
    assert ClosedLoopStpaRun.from_yaml(first_bytes) == run

    tampered = first_bytes.replace(b"coverage_changes: 0", b"coverage_changes: 1")
    path.write_bytes(tampered)
    with pytest.raises(ValueError):
        read_closed_loop_stpa_run(path)


def test_resume_rejects_forged_prior_result_before_adapter_construction() -> None:
    """An outer run digest cannot legitimize a tampered inner attempt."""
    assessment = _assessment()
    arguments = {
        "challenge_budget": 1,
        "assessment_artifact_id": "representative-hybrid-coverage-assessment",
        "opted_in": True,
        "controls": _controls(),
        "loss_analysis": _loss_analysis(),
        "control_structure": _control_structure(),
    }
    prior = run_closed_loop_stpa(
        assessment,
        _eligibility(assessment),
        adapter_factory=lambda record: _UnresolvedAdapter(),
        **arguments,
    )
    forged_analysis = prior.analyses[0].model_copy(update={"coverage_changes": 1})
    forged_prior = prior.model_copy(update={"analyses": (forged_analysis,)})

    with pytest.raises(ValueError, match="coverage_changes|digest mismatch"):
        run_closed_loop_stpa(
            assessment,
            _eligibility(assessment),
            adapter_factory=lambda record: (_ for _ in ()).throw(
                AssertionError("adapter must not be constructed")
            ),
            prior_run=forged_prior,
            **arguments,
        )


def test_budgeted_composition_retains_three_outcomes_and_one_unattempted_target() -> (
    None
):
    """Composition delegates selected pairs only and keeps every state distinct."""
    assessment = _multi_assessment()
    obligation_id = assessment.taxonomy_correspondence[0].obligation_id
    priorities = {
        "NOT_PROVIDED": 40,
        "INCORRECT": 10,
        "WRONG_TIMING": 30,
        "WRONG_DURATION": 20,
    }
    eligibility = tuple(
        ChallengeEligibility(
            obligation_id=obligation_id,
            slot_id=row.slot_id,
            priority=priorities[row.uca_type],
            rationale=f"Explicit review of {row.uca_type}.",
            evidence_refs=(f"review:{row.uca_type}",),
        )
        for row in reversed(assessment.structural_consideration)
    )
    invoked: list[str] = []

    def adapter_factory(record):
        uca_type = record.original_decision.uca_type
        invoked.append(uca_type)
        return _OutcomeAdapter(uca_type)

    run = run_closed_loop_stpa(
        assessment,
        eligibility,
        challenge_budget=3,
        assessment_artifact_id="multi-assessment",
        opted_in=True,
        controls=_controls(),
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
        adapter_factory=adapter_factory,
    )

    assert invoked == ["INCORRECT", "WRONG_DURATION", "WRONG_TIMING"]
    assert run.diagnostics is not None
    assert run.diagnostics.model_dump() == {
        "eligible_targets": 4,
        "selected_targets": 3,
        "not_selected_budget": 1,
        "attempted_targets": 3,
        "pending_selected_targets": 0,
        "completed_outcomes": 3,
        "technical_failures": 0,
        "ica_outcomes": 1,
        "justified_na_outcomes": 1,
        "unresolved_outcomes": 1,
        "adapter_attempts": 3,
        "provider_calls": 0,
        "network_calls": 0,
    }
    assert run.ledger.records[-1].selection_status == "not_selected_budget"


def test_audited_lineage_excludes_old_taxonomy_scenarios_and_retains_exact_stpa_ids() -> (
    None
):
    """The real-run handoff is exact evidence, never an inferred trigger."""
    fixture = yaml.safe_load(LINEAGE_AUDIT_PATH.read_bytes())
    expected = {
        "klarna": (94, 77, 17, 16, 20, 4, 2),
        "nhs": (27, 13, 14, 18, 24, 0, 0),
    }

    assert fixture["schema_version"] == "phase3-lineage-audit-v1"
    for use_case, counts in expected.items():
        evidence = fixture["use_cases"][use_case]
        taxonomy = evidence["taxonomy"]
        stpa = evidence["stpa"]
        warnings = evidence["structural_warning_context"]
        envelope_count, inconsistent, extra, exact_stpa, slots, hazards, processes = (
            counts
        )
        assert taxonomy == {
            "envelope_count": envelope_count,
            "identity_recomputed_count": envelope_count,
            "corrected_plan_join_count": 0,
            "corrected_observation_count": 0,
            "identity_lineage_bug_count": 0,
            "classifications": {
                "inconsistent_planning_input": inconsistent,
                "expected_extra_candidate": extra,
            },
        }
        assert stpa["scenario_count"] == stpa["exact_join_count"] == exact_stpa
        assert stpa["slot_count"] == slots
        assert len(stpa["records"]) == exact_stpa
        for scenario_id, slot_id, ica_id, exec_id in stpa["records"]:
            controller, action, uca_type = slot_id.split(":")
            assert scenario_id.startswith("SCN-")
            assert ica_id == f"{slot_id}:1"
            assert exec_id == f"EXEC:{controller}:{action}:{uca_type}"
        assert warnings == {
            "untraced_hazard_count": hazards,
            "unreferenced_controlled_process_count": processes,
        }
        assert evidence["explicit_eligibility_targets"] == []


def test_resume_rejects_changed_analysis_controls_before_adapter_construction() -> None:
    """A rerun cannot silently reuse evidence produced under other controls."""
    assessment = _assessment()
    arguments = {
        "challenge_budget": 1,
        "assessment_artifact_id": "representative-hybrid-coverage-assessment",
        "opted_in": True,
        "loss_analysis": _loss_analysis(),
        "control_structure": _control_structure(),
    }
    prior = run_closed_loop_stpa(
        assessment,
        _eligibility(assessment),
        controls=_controls(),
        adapter_factory=lambda record: _UnresolvedAdapter(),
        **arguments,
    )
    changed_controls = _controls().model_copy(update={"temperature": 0.7})

    with pytest.raises(ValueError, match="controls"):
        run_closed_loop_stpa(
            assessment,
            _eligibility(assessment),
            controls=changed_controls,
            adapter_factory=lambda record: (_ for _ in ()).throw(
                AssertionError("adapter must not be constructed")
            ),
            prior_run=prior,
            **arguments,
        )


def test_resume_rejects_changed_control_structure_before_adapter_construction() -> None:
    """A prior result is not reusable under different causal authority."""
    assessment = _assessment()
    original_structure = _control_structure()
    prior = run_closed_loop_stpa(
        assessment,
        _eligibility(assessment),
        challenge_budget=1,
        assessment_artifact_id="representative-hybrid-coverage-assessment",
        opted_in=True,
        controls=_controls(),
        loss_analysis=_loss_analysis(),
        control_structure=original_structure,
        adapter_factory=lambda record: _UnresolvedAdapter(),
    )
    changed_responsibility = original_structure.responsibilities[0].model_copy(
        update={"description": "A different causal responsibility."}
    )
    changed_structure = original_structure.model_copy(
        update={"responsibilities": [changed_responsibility]}
    )

    with pytest.raises(ValueError, match="control structure"):
        run_closed_loop_stpa(
            assessment,
            _eligibility(assessment),
            challenge_budget=1,
            assessment_artifact_id="representative-hybrid-coverage-assessment",
            opted_in=True,
            controls=_controls(),
            loss_analysis=_loss_analysis(),
            control_structure=changed_structure,
            adapter_factory=lambda record: (_ for _ in ()).throw(
                AssertionError("adapter must not be constructed")
            ),
            prior_run=prior,
        )


def test_opted_out_composition_records_pending_selection_without_adapter_activity() -> (
    None
):
    """Selection remains offline and an absent opt-in creates no attempt."""
    assessment = _assessment()

    def forbidden_factory(record):
        raise AssertionError(f"adapter constructed for {record.challenge_id}")

    run = run_closed_loop_stpa(
        assessment,
        _eligibility(assessment),
        challenge_budget=1,
        assessment_artifact_id="representative-hybrid-coverage-assessment",
        opted_in=False,
        controls=_controls(),
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
        adapter_factory=forbidden_factory,
    )

    assert run.analysis_opt_in is False
    assert run.analyses == ()
    assert run.diagnostics is not None
    assert run.diagnostics.selected_targets == 1
    assert run.diagnostics.pending_selected_targets == 1
    assert run.diagnostics.adapter_attempts == 0
    assert run.diagnostics.provider_calls == run.diagnostics.network_calls == 0


def test_stale_assessment_stops_composition_before_adapter_construction() -> None:
    """The composed boundary does not make stale Phase 2 history authoritative."""
    assessment = _assessment()
    stale = assessment.model_copy(update={"semantic_digest": "f" * 64})

    with pytest.raises(ValueError, match="digest mismatch"):
        run_closed_loop_stpa(
            stale,
            _eligibility(assessment),
            challenge_budget=1,
            assessment_artifact_id="representative-hybrid-coverage-assessment",
            opted_in=True,
            controls=_controls(),
            loss_analysis=_loss_analysis(),
            control_structure=_control_structure(),
            adapter_factory=lambda record: (_ for _ in ()).throw(
                AssertionError("adapter must not be constructed")
            ),
        )


def test_technical_failure_remains_an_attempt_without_a_structural_outcome() -> None:
    """Composition reports provider failure without relabeling it unresolved."""
    assessment = _assessment()
    run = run_closed_loop_stpa(
        assessment,
        _eligibility(assessment),
        challenge_budget=1,
        assessment_artifact_id="representative-hybrid-coverage-assessment",
        opted_in=True,
        controls=_controls(),
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
        adapter_factory=lambda record: _TechnicalFailureAdapter(),
    )

    assert run.analyses[0].status == "technical_failure"
    assert run.analyses[0].outcome is None
    assert run.diagnostics is not None
    assert run.diagnostics.attempted_targets == 1
    assert run.diagnostics.completed_outcomes == 0
    assert run.diagnostics.technical_failures == 1
    assert run.diagnostics.provider_calls == run.diagnostics.network_calls == 1
