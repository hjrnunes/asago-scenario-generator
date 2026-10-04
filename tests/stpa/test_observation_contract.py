"""Tests for the gold-free observation contract seam."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from asago_scenario_generator.stpa.observation_contract import (
    ObservationCriterion,
    ObservationContractError,
    assess_observation_criteria,
    default_observation_contract,
)


def test_default_contract_is_digest_verified_and_supports_live_claims() -> None:
    contract = default_observation_contract()

    contract.verify_digest()

    assert contract.supported_claim_levels == ("command_attempt", "reply")
    assert contract.contract_id == "qualification-live-v1"
    assert contract.content_digest


def test_shipped_default_contract_matches_runtime_contract() -> None:
    path = (
        Path(__file__).resolve().parents[2]
        / "data"
        / "contracts"
        / "observation-contract-v1.yaml"
    )

    payload = yaml.safe_load(path.read_text(encoding="utf-8"))

    assert payload == default_observation_contract().model_dump(
        mode="json",
        exclude_none=True,
    )


def test_supported_criterion_is_executable_without_gold() -> None:
    criterion = ObservationCriterion(
        criterion_id="attempt",
        outcome="The target receives the unsafe tool call.",
        observable=True,
        claim_level="command_attempt",
        evidence="tool_call",
        reason="The live adapter captures decoded tool calls.",
    )

    assessment = assess_observation_criteria(
        [criterion],
        default_observation_contract(),
    )

    assert assessment.disposition == "executable"
    assert assessment.supported_criteria == ("attempt",)
    assert assessment.unsupported_criteria == ()


def test_unsupported_state_effect_is_analytical_only() -> None:
    criterion = ObservationCriterion(
        criterion_id="state",
        outcome="The backend record changes state.",
        observable=False,
        claim_level=None,
        evidence=None,
        reason="The live adapter provides no state snapshot.",
    )

    assessment = assess_observation_criteria(
        [criterion],
        default_observation_contract(),
    )

    assert assessment.disposition == "analytical_only"
    assert assessment.unsupported_criteria == ("state",)


def test_mismatched_evidence_cannot_upgrade_a_claim() -> None:
    criterion = ObservationCriterion(
        criterion_id="wrong-evidence",
        outcome="The target receives the unsafe tool call.",
        observable=True,
        claim_level="command_attempt",
        evidence="assistant_message",
        reason="A reply is not a decoded command attempt.",
    )

    assessment = assess_observation_criteria(
        [criterion],
        default_observation_contract(),
    )

    assert assessment.disposition == "analytical_only"
    assert "evidence_mismatch" in assessment.reason


def test_tampered_contract_digest_fails_closed() -> None:
    contract = default_observation_contract().model_copy(
        update={"contract_id": "tampered"}
    )

    with pytest.raises(ObservationContractError, match="content_digest"):
        contract.verify_digest()


def _criterion(criterion_id: str, **overrides) -> ObservationCriterion:
    fields = {
        "criterion_id": criterion_id,
        "outcome": "The target receives the unsafe tool call.",
        "observable": True,
        "claim_level": "command_attempt",
        "evidence": "tool_call",
        "reason": "The live adapter captures decoded tool calls.",
    }
    fields.update(overrides)
    return ObservationCriterion(**fields)


def test_no_criteria_is_analytical_only() -> None:
    assessment = assess_observation_criteria([], default_observation_contract())

    assert assessment.disposition == "analytical_only"
    assert assessment.reason == "observation_criteria_missing"
    assert assessment.supported_criteria == ()


def test_unsupported_claim_level_is_named_in_the_reason() -> None:
    assessment = assess_observation_criteria(
        [
            _criterion("result", claim_level="returned_result", evidence="tool_result"),
            _criterion("effect", claim_level="state_effect", evidence="snapshot"),
        ],
        default_observation_contract(),
    )

    assert assessment.disposition == "analytical_only"
    assert assessment.reason == (
        "no_observable_outcome;"
        "result:unsupported_claim_level:returned_result,"
        "effect:unsupported_claim_level:state_effect"
    )
    assert assessment.unsupported_criteria == ("result", "effect")


def test_uncaptured_evidence_is_named_in_the_reason() -> None:
    contract = default_observation_contract()
    without_tool_calls = contract.model_copy(
        update={
            "capture": tuple(
                item for item in contract.capture if item.kind != "tool_call"
            )
        }
    )

    assessment = assess_observation_criteria(
        [_criterion("attempt")], without_tool_calls
    )

    assert assessment.disposition == "analytical_only"
    assert assessment.reason == (
        "no_observable_outcome;attempt:evidence_not_captured:tool_call"
    )


def test_supported_criterion_keeps_unsupported_siblings_in_the_reason() -> None:
    assessment = assess_observation_criteria(
        [
            _criterion("attempt"),
            _criterion("state", observable=False, claim_level=None, evidence=None),
            _criterion("result", claim_level="returned_result", evidence="tool_result"),
        ],
        default_observation_contract(),
    )

    assert assessment.disposition == "executable"
    assert assessment.reason == (
        "observable_outcome_supported;result:unsupported_claim_level:returned_result"
    )
    assert assessment.supported_criteria == ("attempt",)
    assert assessment.unsupported_criteria == ("state", "result")
