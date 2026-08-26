"""Focused unit tests for the decomposed complexity model helpers."""

from __future__ import annotations

import pytest

from asago_scenario_generator.models.complexity import (
    Call0RegenerationRouting,
    ComplexityEvidenceReference,
    ComplexityReason,
    QuarantineRouting,
    RealizationRetryRouting,
    _below_complexity_level_error,
    _final_phase_reason_error,
    _ordered_reasons_error,
    _phase_level_error,
    _phase_unavailable_error,
    _reason_order_error,
    _routing_stage_error,
    _top_reason_level,
    _unique_rule_ids_error,
    capability_level_rank,
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
_INTERMEDIATE_REASON = ComplexityReason(
    rule_id="chain.multi_step_attacker_control",  # type: ignore[arg-type]
    required_level="intermediate",
    detail="adversarial fixture",
    evidence=(
        ComplexityEvidenceReference(
            kind="chain_step",  # type: ignore[arg-type]
            ref_id="chain.1",
        ),
    ),
)


class TestTopReasonLevel:
    """Highest required level among triggering reasons."""

    def test_returns_max_rank(self) -> None:
        assert _top_reason_level((_INTERMEDIATE_REASON, _CALL0_REASON)) == (
            capability_level_rank("advanced")
        )

    def test_single_reason_rank(self) -> None:
        assert _top_reason_level((_INTERMEDIATE_REASON,)) == (
            capability_level_rank("intermediate")
        )


class TestRoutingStageError:
    """Routing-stage coherence against the deterministic earliest stage."""

    def test_none_when_stage_matches(self) -> None:
        assert _routing_stage_error("attack_tree_realization", (_REALIZATION_REASON,)) is None

    def test_error_when_stage_mismatches(self) -> None:
        error = _routing_stage_error("call0_actor_generation", (_REALIZATION_REASON,))
        assert error is not None
        assert "does not match" in error


class TestBelowComplexityLevelError:
    """Below-complexity violation coherence checks."""

    def test_none_when_coherent(self) -> None:
        error = _below_complexity_level_error(
            "novice", "advanced", (_CALL0_REASON,), "call0_actor_generation"
        )
        assert error is None

    def test_error_when_required_level_missing(self) -> None:
        error = _below_complexity_level_error("novice", None, (_CALL0_REASON,), "s")
        assert error is not None
        assert "require a required_level" in error

    def test_error_when_reasons_missing(self) -> None:
        error = _below_complexity_level_error("novice", "advanced", (), "s")
        assert error is not None
        assert "require reasons" in error

    def test_error_when_actor_not_strictly_below(self) -> None:
        error = _below_complexity_level_error(
            "advanced", "advanced", (_CALL0_REASON,), "call0_actor_generation"
        )
        assert error is not None
        assert "strictly below" in error

    def test_error_when_required_not_top_level(self) -> None:
        error = _below_complexity_level_error(
            "novice",
            "intermediate",
            (_CALL0_REASON,),
            "call0_actor_generation",
        )
        assert error is not None
        assert "must equal the top level" in error

    def test_error_when_routing_stage_mismatches(self) -> None:
        error = _below_complexity_level_error(
            "novice", "advanced", (_CALL0_REASON,), "attack_tree_realization"
        )
        assert error is not None
        assert "does not match" in error


class TestPhaseUnavailableError:
    """Fail-closed phase-unavailable violation coherence checks."""

    def test_none_when_coherent(self) -> None:
        error = _phase_unavailable_error(
            None, (), QuarantineRouting(feedback="fixture")
        )
        assert error is None

    def test_error_when_required_level_present(self) -> None:
        error = _phase_unavailable_error(
            "intermediate", (), QuarantineRouting(feedback="fixture")
        )
        assert error is not None
        assert "must not carry a required_level" in error

    def test_error_when_reasons_present(self) -> None:
        error = _phase_unavailable_error(
            None, (_INTERMEDIATE_REASON,), QuarantineRouting(feedback="fixture")
        )
        assert error is not None
        assert "must not carry triggering reasons" in error

    def test_error_when_routing_not_quarantine(self) -> None:
        error = _phase_unavailable_error(
            None, (), RealizationRetryRouting(feedback="fixture")
        )
        assert error is not None
        assert "quarantine routing" in error


class TestReasonOrderErrors:
    """Deterministic reason ordering checks."""

    def test_unique_rule_ids_error_none_when_unique(self) -> None:
        assert _unique_rule_ids_error((_INTERMEDIATE_REASON, _CALL0_REASON)) is None

    def test_unique_rule_ids_error_when_duplicated(self) -> None:
        error = _unique_rule_ids_error((_INTERMEDIATE_REASON, _INTERMEDIATE_REASON))
        assert error is not None
        assert "unique by rule_id" in error

    def test_final_phase_reason_error_none_in_final_phase(self) -> None:
        assert _final_phase_reason_error("final", (_REALIZATION_REASON,)) is None

    def test_final_phase_reason_error_in_candidate_phase(self) -> None:
        error = _final_phase_reason_error(
            "candidate_lower_bound", (_REALIZATION_REASON,)
        )
        assert error is not None
        assert "originates in the final phase" in error

    def test_ordered_reasons_error_none_when_sorted(self) -> None:
        assert _ordered_reasons_error((_CALL0_REASON, _INTERMEDIATE_REASON)) is None

    def test_ordered_reasons_error_when_unsorted(self) -> None:
        error = _ordered_reasons_error((_INTERMEDIATE_REASON, _CALL0_REASON))
        assert error is not None
        assert "descending required level" in error

    def test_reason_order_error_returns_first_violation(self) -> None:
        error = _reason_order_error(
            "final", (_INTERMEDIATE_REASON, _INTERMEDIATE_REASON)
        )
        assert error is not None
        assert "unique by rule_id" in error

    def test_reason_order_error_none_when_valid(self) -> None:
        assert _reason_order_error("final", (_CALL0_REASON, _INTERMEDIATE_REASON)) is None


class TestPhaseLevelError:
    """Phase required-level coherence checks."""

    def test_none_when_level_matches_top_reason(self) -> None:
        assert _phase_level_error("advanced", (_CALL0_REASON,)) is None

    def test_error_when_level_below_top_reason(self) -> None:
        error = _phase_level_error("intermediate", (_CALL0_REASON,))
        assert error is not None
        assert "must equal the highest reason level" in error

    def test_none_when_reasonless_novice(self) -> None:
        assert _phase_level_error("novice", ()) is None

    def test_error_when_reasonless_non_novice(self) -> None:
        error = _phase_level_error("advanced", ())
        assert error is not None
        assert "must be novice" in error
