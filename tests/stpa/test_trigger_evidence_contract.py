"""Independent boundary checks for omission evidence and prompt examples."""

import json
import re

import pytest
from pydantic import ValidationError

from asago_scenario_generator.stpa.models.loss_analysis import Obligation
from asago_scenario_generator.stpa.scenario_prod.authoring import (
    AuthoredConditionEntry,
    AuthoredTriggerEvidence,
    AuthoredUnsafeObservation,
    build_authoring_user_prompt,
)
from tests.stpa.test_authoring_validation import (
    STATE,
    _candidate,
    _draft,
    _observations,
    _profile,
    _session,
    _validate,
)


@pytest.mark.parametrize(
    "fields",
    [
        {"source": "stimulus", "quote": "text", "turn": 0},
        {"source": "stimulus", "quote": "text", "turn": True},
        {"source": "stimulus", "quote": " ", "turn": 1},
        {"source": "state_fact", "quote": "true", "state_path": []},
        {"source": "observation", "quote": "text", "observation_ref": " "},
        {"source": "stimulus", "quote": "text", "turn": 1, "reviewed": True},
    ],
)
def test_evidence_wire_rejects_invalid_locators_and_self_authority(fields):
    with pytest.raises(ValidationError):
        AuthoredTriggerEvidence.model_validate(fields)


@pytest.mark.parametrize(
    ("value", "quote", "reason"),
    [
        (10, "1", "trigger_evidence_quote_mismatch"),
        (True, "true", "direction_unreviewed"),
        ({"z": 2, "a": 1}, '{"a":1,"z":2}', "direction_unreviewed"),
    ],
)
def test_nonstring_state_evidence_compares_complete_canonical_value(
    value, quote, reason
):
    draft = _draft(
        state_facts=(("requirement",),),
        oracle=AuthoredUnsafeObservation(
            kind="tool_absent",
            tool="process_refund",
            trigger="The rule applies.",
            trigger_evidence=(
                AuthoredTriggerEvidence(
                    source="state_fact",
                    state_path=("requirement",),
                    quote=quote,
                ),
            ),
        ),
        conditions=(
            AuthoredConditionEntry(
                condition=1,
                by="state_fact",
                ref=("requirement",),
                note="Supplied value.",
            ),
        ),
    )
    result = _validate(draft, state={"requirement": value}, subject_model=None)
    assert result.reason == reason


@pytest.mark.parametrize("action", ["process_refund", "retrieve_policy", "respond"])
def test_complete_prompt_oracle_examples_parse_through_the_actual_wire(action):
    candidate = _candidate(
        action=action,
        direction_authority="reviewed",
        obligations=(
            Obligation(
                obligation_id="O1",
                kind="required",
                behavior="perform the action",
                rule_span="must process a refund",
                realized_by="tool_call",
            ),
            Obligation(
                obligation_id="O2",
                kind="forbidden",
                behavior="unsafe behavior",
                rule_span="must process a refund",
                violated_via="unknown",
            ),
        ),
    )
    prompt = build_authoring_user_prompt(
        candidate,
        state=STATE,
        observation_records=_observations().prompt_records(),
        session=_session(),
        profile=_profile(),
        reviewed_bindings=frozenset({("SC-1", "O1", action)}),
    )
    examples = []
    for block in re.findall(r"```json\n(.*?)\n```", prompt, re.DOTALL):
        # The envelope has explained placeholders; the per-kind examples are JSON.
        if not re.match(r'\s*\{\s*"kind"', block):
            continue
        example = json.loads(block)
        if example.get("kind") in {
            "tool_argument",
            "tool_absent",
            "tool_order",
            "response_claim",
        }:
            examples.append(AuthoredUnsafeObservation.model_validate(example))
    assert examples
    for example in examples:
        assert bool(example.trigger_evidence) == (example.kind == "tool_absent")
