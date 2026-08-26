"""Focused unit tests for the decomposed capability-admission helpers."""

from __future__ import annotations

import pytest

from asago_scenario_generator.models.complexity import (
    AttackComplexityAssessment,
    Call0RegenerationRouting,
    ComplexityEvidenceReference,
    ComplexityPhaseAssessment,
    ComplexityReason,
    QuarantineRouting,
    RealizationRetryRouting,
)
from asago_scenario_generator.pipeline.complexity import (
    _assemble_phase,
    _below_capability_violation,
    _call0_feedback,
    _phase_assessment,
    _quarantine_violation,
    _realization_retry_feedback,
    _reason_rule_ids,
    _triggering_reasons,
    _violation_routing,
)

_CALL0_REASON = ComplexityReason(
    rule_id="access.supply_chain_targeting",  # type: ignore[arg-type]
    required_level="advanced",
    detail="adversarial fixture",
    evidence=(
        ComplexityEvidenceReference(
            kind="actor_access_provenance",  # type: ignore[arg-type]
            ref_id="ep:v1:" + "ab" * 16,
        ),
    ),
)
_REALIZATION_REASON = ComplexityReason(
    rule_id="action.external_precondition",  # type: ignore[arg-type]
    required_level="intermediate",
    detail="adversarial fixture",
    evidence=(
        ComplexityEvidenceReference(
            kind="leaf_action",  # type: ignore[arg-type]
            ref_id="n1.1",
        ),
    ),
)


def _phase(
    required_level: str, reasons: tuple[ComplexityReason, ...]
) -> ComplexityPhaseAssessment:
    return ComplexityPhaseAssessment(
        phase="final", required_level=required_level, reasons=reasons  # type: ignore[arg-type]
    )


def _assessment(final: ComplexityPhaseAssessment | None = None) -> AttackComplexityAssessment:
    candidate = ComplexityPhaseAssessment(
        phase="candidate_lower_bound",
        required_level="novice",
        reasons=(),
    )
    return AttackComplexityAssessment(
        rule_version="1", candidate_lower_bound=candidate, final=final
    )


class TestPhaseAssessment:
    """Requested-phase lookup on an attack-complexity assessment."""

    def test_returns_candidate_lower_bound(self) -> None:
        assessment = _assessment()
        assert (
            _phase_assessment(assessment, "candidate_lower_bound")
            is assessment.candidate_lower_bound
        )

    def test_returns_final_when_computed(self) -> None:
        final = _phase("advanced", (_CALL0_REASON,))
        assessment = _assessment(final=final)
        assert _phase_assessment(assessment, "final") is final

    def test_returns_none_when_final_uncomputed(self) -> None:
        assert _phase_assessment(_assessment(), "final") is None


def test_assemble_phase_rejects_conflicting_reasons_for_one_rule() -> None:
    conflicting = _CALL0_REASON.model_copy(update={"detail": "different evidence"})

    with pytest.raises(ValueError, match="conflicting complexity reasons"):
        _assemble_phase("final", [_CALL0_REASON, conflicting])


class TestQuarantineViolation:
    """Fail-closed violation for an unavailable assessment phase."""

    def test_fields_and_feedback(self) -> None:
        violation = _quarantine_violation(_assessment(), "final", "novice")
        assert violation.rule_id == "complexity_assessment_phase_unavailable"
        assert violation.phase == "final"
        assert violation.required_level is None
        assert violation.triggering_reasons == ()
        assert isinstance(violation.routing, QuarantineRouting)
        assert "No 'final' attack-complexity assessment exists" in (
            violation.routing.feedback
        )


class TestTriggeringReasons:
    """Reason filtering by required level."""

    def test_filters_to_required_level(self) -> None:
        phase = _phase("advanced", (_CALL0_REASON, _REALIZATION_REASON))
        assert _triggering_reasons(phase, "intermediate") == (_REALIZATION_REASON,)

    def test_empty_when_none_match(self) -> None:
        phase = _phase("novice", ())
        assert _triggering_reasons(phase, "intermediate") == ()


class TestReasonRuleIds:
    """Comma-joined rule IDs for feedback messages."""

    def test_joins_rule_ids_in_order(self) -> None:
        assert (
            _reason_rule_ids((_REALIZATION_REASON, _CALL0_REASON))
            == "action.external_precondition, access.supply_chain_targeting"
        )

    def test_empty_for_no_reasons(self) -> None:
        assert _reason_rule_ids(()) == ""


class TestFeedbackMessages:
    """Bounded-retry feedback copy."""

    def test_call0_feedback_candidate_phase(self) -> None:
        feedback = _call0_feedback(
            "novice", "advanced", "r1", "candidate_lower_bound", "1"
        )
        assert "candidate lower bound" in feedback
        assert "Regenerate the actor" in feedback
        assert "never relabel" in feedback

    def test_call0_feedback_final_phase(self) -> None:
        feedback = _call0_feedback("novice", "advanced", "r1", "final", "1")
        assert "final required level" in feedback
        assert "rerun the bounded Call 0 retry loop" in feedback

    def test_realization_retry_feedback(self) -> None:
        feedback = _realization_retry_feedback("novice", "intermediate", "r1", "1")
        assert "retry attack-tree realization" in feedback
        assert "never relabel" in feedback


class TestViolationRouting:
    """Bounded retry routing selection by earliest responsible stage."""

    def test_call0_stage_returns_call0_routing(self) -> None:
        routing = _violation_routing(
            "novice", "advanced", "r1", "final", "1", "call0_actor_generation"
        )
        assert isinstance(routing, Call0RegenerationRouting)

    def test_realization_stage_returns_realization_routing(self) -> None:
        routing = _violation_routing(
            "novice", "intermediate", "r1", "final", "1", "attack_tree_realization"
        )
        assert isinstance(routing, RealizationRetryRouting)

    def test_unknown_stage_raises(self) -> None:
        with pytest.raises(ValueError, match="no bounded retry stage owns"):
            _violation_routing("novice", "advanced", "r1", "final", "1", "quarantine")


class TestBelowCapabilityViolation:
    """End-to-end below-capability violation assembly."""

    def test_routes_to_call0_for_call0_evidence(self) -> None:
        phase = _phase("advanced", (_CALL0_REASON,))
        violation = _below_capability_violation("novice", phase, "final", "1")
        assert violation.rule_id == "actor_capability_below_attack_complexity"
        assert violation.phase == "final"
        assert violation.required_level == "advanced"
        assert violation.triggering_reasons == (_CALL0_REASON,)
        assert isinstance(violation.routing, Call0RegenerationRouting)

    def test_routes_to_realization_retry_for_realized_action_evidence(self) -> None:
        phase = _phase("intermediate", (_REALIZATION_REASON,))
        violation = _below_capability_violation("novice", phase, "final", "1")
        assert isinstance(violation.routing, RealizationRetryRouting)
        assert violation.required_level == "intermediate"
