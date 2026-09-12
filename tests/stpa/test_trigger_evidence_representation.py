"""Representation boundary tests for authored omission evidence."""

from __future__ import annotations

import yaml

from asago_scenario_generator.stpa.models.loss_analysis import Obligation
from asago_scenario_generator.stpa.scenario_prod.authoring import (
    AcceptedScenario,
    AuthoredConditionEntry,
    AuthoredTriggerEvidence,
    AuthoredUnsafeObservation,
    CandidateAuthoringOutcome,
    ScenarioHold,
    write_authored_scenarios_record,
)
from tests.stpa.test_authoring_validation import (
    _candidate,
    _draft,
    _validate,
)


_REVIEWED_BINDING = frozenset({("SC-1", "O1", "process_refund")})


def _reviewed_candidate():
    return _candidate(
        obligations=(
            Obligation(
                obligation_id="O1",
                kind="required",
                behavior="process an eligible refund",
                rule_span="process a refund only for an eligible order",
                realized_by="tool_call",
            ),
        ),
        direction_authority="reviewed",
    )


def _omission_draft(quote: str):
    return _draft(
        state_facts=(),
        stimulus=f"Please review this source before processing the refund: {quote}",
        obligation_ref="O1",
        oracle=AuthoredUnsafeObservation(
            kind="tool_absent",
            tool="process_refund",
            trigger="The reviewed requirement applies to this request.",
            trigger_evidence=(
                AuthoredTriggerEvidence(
                    source="stimulus",
                    turn=1,
                    quote=quote,
                ),
            ),
        ),
        conditions=(
            AuthoredConditionEntry(
                condition=1,
                by="stimulus",
                note="The user requests the refund action.",
            ),
        ),
    )


def _validate_reviewed(draft):
    return _validate(
        draft,
        candidate=_reviewed_candidate(),
        reviewed_bindings=_REVIEWED_BINDING,
    )


def test_short_omission_evidence_remains_accepted_when_reviewed():
    result = _validate_reviewed(_omission_draft("refund ORD-201"))

    assert isinstance(result, AcceptedScenario)
    assert '"quote":"refund ORD-201"' in result.oracle.template_text


def test_long_omission_quote_is_held_before_acceptance():
    quote = "A" * 700
    draft = _omission_draft(quote)
    result = _validate_reviewed(draft)

    assert isinstance(result, ScenarioHold)
    assert not isinstance(result, AcceptedScenario)
    assert result.reason == "trigger_evidence_unrepresentable"
    assert "semantic_proposition must be at most" in result.detail


def test_url_omission_quote_is_held_without_relaxing_proposition_validation():
    result = _validate_reviewed(_omission_draft("https://example.test/policy"))

    assert isinstance(result, ScenarioHold)
    assert result.reason == "trigger_evidence_unrepresentable"
    assert "runtime URL" in result.detail


def test_structural_id_omission_quote_is_held_without_relaxing_proposition_validation():
    result = _validate_reviewed(_omission_draft("CA-123"))

    assert isinstance(result, ScenarioHold)
    assert result.reason == "trigger_evidence_unrepresentable"
    assert "structural identifiers" in result.detail


def test_unrepresentable_omission_hold_persists_trigger_and_exact_quote(tmp_path):
    quote = "A" * 700
    draft = _omission_draft(quote)
    hold = _validate_reviewed(draft)
    assert isinstance(hold, ScenarioHold)

    outcome = CandidateAuthoringOutcome(
        candidate=_reviewed_candidate(),
        held=((draft, hold),),
    )
    path = write_authored_scenarios_record(tmp_path, (outcome,))
    record = yaml.safe_load(path.read_text(encoding="utf-8"))
    row = record["candidates"][0]

    assert row["accepted"] == []
    held_row = row["held"][0]
    assert held_row["reason"] == "trigger_evidence_unrepresentable"
    assert held_row["trigger"] == draft.unsafe_observation.trigger
    assert held_row["trigger_evidence"] == [
        {"quote": quote, "source": "stimulus", "turn": 1}
    ]
