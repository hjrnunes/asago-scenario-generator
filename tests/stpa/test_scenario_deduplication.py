"""Tests for deterministic producer scenario deduplication."""

from __future__ import annotations

from asago_scenario_generator.stpa.observation_contract import (
    ObservationAssessment,
    ObservationCriterion,
    SafeObservableOutcome,
)
from asago_scenario_generator.stpa.scenario_prod.deduplication import (
    deduplicate_scenario_specs,
)

from .test_sp3_context_property import _scenario_spec


def _scenario(
    scenario_id: str,
    *,
    claim_level: str | None = "command_attempt",
    operation_name: str | None = "refund_payment",
    analytical: bool = False,
):
    spec = _scenario_spec().model_copy(update={"scenario_id": scenario_id})
    criterion = ObservationCriterion(
        criterion_id="attempt",
        outcome="The selected operation is attempted.",
        observable=not analytical,
        claim_level=None if analytical else claim_level,
        evidence=(
            None
            if analytical
            else "assistant_message"
            if claim_level == "reply"
            else "tool_call"
        ),
        reason="The contract defines the observation boundary.",
    )
    assessment = ObservationAssessment(
        disposition="analytical_only" if analytical else "executable",
        reason="test",
        supported_criteria=() if analytical else ("attempt",),
        unsupported_criteria=("attempt",) if analytical else (),
    )
    safe = SafeObservableOutcome(
        observable=not analytical,
        statement=(
            "The selected operation remains within the required policy."
            if not analytical
            else "The state effect is not captured by the observation contract."
        ),
        claim_level=None if analytical else claim_level,
        evidence=(
            None
            if analytical
            else "assistant_message"
            if claim_level == "reply"
            else "tool_call"
        ),
        operation_name=None if analytical else operation_name,
    )
    return spec.model_copy(
        update={
            "observation_criteria": [criterion],
            "observation_assessment": assessment,
            "safe_observable_outcome": safe,
        }
    )


def test_deduplication_uses_the_full_key_and_excludes_analytical_scenarios() -> None:
    records = deduplicate_scenario_specs(
        [
            _scenario("SCN-003", claim_level="reply"),
            _scenario("SCN-002"),
            _scenario("SCN-001"),
            _scenario("SCN-004", analytical=True),
        ]
    )

    assert records["SCN-001"].status == "canonical"
    assert records["SCN-002"].status == "duplicate"
    assert records["SCN-002"].duplicate_of == "SCN-001"
    assert records["SCN-003"].status == "canonical"
    assert records["SCN-004"].status == "analytical_only"
    assert records["SCN-004"].duplicate_of is None
    assert records["SCN-001"].key.operation_name == "refund_payment"
    assert records["SCN-001"].key.claim_level == "command_attempt"


def test_legacy_scenario_without_safe_outcome_uses_unknown_claim_level() -> None:
    legacy = _scenario_spec().model_copy(update={"scenario_id": "SCN-legacy"})

    records = deduplicate_scenario_specs([legacy])

    assert records["SCN-legacy"].status == "canonical"
    assert records["SCN-legacy"].key.operation_name is None
    assert records["SCN-legacy"].key.claim_level == "unknown"


def test_command_attempt_without_operation_is_never_collapsed() -> None:
    records = deduplicate_scenario_specs(
        [
            _scenario("SCN-002", operation_name=None),
            _scenario("SCN-001", operation_name=None),
        ]
    )

    assert records["SCN-001"].status == "canonical"
    assert records["SCN-002"].status == "canonical"
    assert records["SCN-001"].duplicate_of is None
    assert records["SCN-002"].duplicate_of is None
