"""Stage 5 runs the safe-outcome binding before the condition findings."""

from __future__ import annotations

import copy

from asago_scenario_generator.stpa.observation_contract import (
    default_observation_contract,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.generate import (
    generate_bdi_for_context,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.issues import IssueCode
from tests.stpa.sp1_helpers import MockLLMClient

from .condition_prompt_fixture import realistic_observations, realistic_profile
from .test_normal_authoring_wire import _normal_payload, _wrong_timing_context

_ATTEMPT = {
    "criterion_id": "attempt",
    "outcome": "The update_gadget operation is attempted.",
    "observable": True,
    "claim_level": "command_attempt",
    "evidence": "tool_call",
    "operation_name": "update_gadget",
    "reason": "The runtime captures decoded tool calls.",
}
_REPLY = {
    "criterion_id": "reply",
    "outcome": "The assistant reply promises a prohibited action.",
    "observable": True,
    "claim_level": "reply",
    "evidence": "assistant_message",
    "reason": "The runtime captures assistant messages.",
}


def _safe_outcome(claim_level: str, evidence: str, operation: str | None) -> dict:
    return {
        "observable": True,
        "statement": "The gadget stays unchanged.",
        "claim_level": claim_level,
        "evidence": evidence,
        "operation_name": operation,
    }


def _payload(criteria: list[dict], safe_outcome: dict, not_called: str) -> dict:
    payload = _normal_payload()
    outcome = payload["unsafe_outcome"]
    outcome["observation_criteria"] = criteria
    outcome["safe_observable_outcome"] = safe_outcome
    outcome["discriminating_condition"] = {
        "statement": f"The {not_called} operation is never called.",
        "comparisons": [{"kind": "not_called", "operation": not_called}],
        "record_selection": {"status": "unavailable", "reason": "Not chosen."},
    }
    return payload


def _generate(client: MockLLMClient, tmp_path):
    profile = realistic_profile()
    return generate_bdi_for_context(
        client,
        _wrong_timing_context(),
        tmp_path,
        observation_contract=default_observation_contract(),
        target_operation=None,
        execution_target_profile=profile,
        target_observations=realistic_observations(profile),
    )


def test_a_coerced_safe_outcome_no_longer_names_its_old_operation(tmp_path) -> None:
    """The only supported criterion owns the safe outcome before R1a reads it."""
    declared = _safe_outcome("reply", "assistant_message", "get_gadget")
    wrong = _payload([_ATTEMPT], declared, "get_gadget")
    fixed = _payload([_ATTEMPT], declared, "update_gadget")
    client = MockLLMClient()
    client.set_response_queue([wrong, fixed])

    result, error = _generate(client, tmp_path)

    assert error is None, error
    assert result is not None
    assert client.call_count == 2
    correction = client.calls[1].user_prompt
    assert (
        f"{IssueCode.discriminating_condition_operation_mismatch.value}:" in correction
    )
    assert IssueCode.safe_outcome_observability_mismatch.value not in correction
    outcome = result.safe_observable_outcome
    assert (outcome.claim_level, outcome.evidence, outcome.operation_name) == (
        "command_attempt",
        "tool_call",
        "update_gadget",
    )


def test_a_safe_outcome_mismatch_is_corrected_before_the_condition(tmp_path) -> None:
    """With two supported criteria no coercion happens and the safe outcome fails first."""
    second_reply = {**_REPLY, "criterion_id": "reply_two"}
    declared = _safe_outcome("command_attempt", "tool_call", "update_gadget")
    wrong = _payload([_REPLY, second_reply], declared, "get_gadget")
    fixed = copy.deepcopy(wrong)
    fixed["unsafe_outcome"]["safe_observable_outcome"] = _safe_outcome(
        "reply", "assistant_message", None
    )
    client = MockLLMClient()
    client.set_response_queue([wrong, fixed])

    _generate(client, tmp_path)

    assert client.call_count == 2
    correction = client.calls[1].user_prompt
    assert IssueCode.safe_outcome_observability_mismatch.value in correction
    assert IssueCode.discriminating_condition_operation_mismatch.value not in correction
