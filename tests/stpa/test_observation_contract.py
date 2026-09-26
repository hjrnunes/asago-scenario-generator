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
