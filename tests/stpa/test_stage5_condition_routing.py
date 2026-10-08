"""A command-attempt scenario that lost its condition is routed, never lost."""

from __future__ import annotations

import copy

import yaml

from asago_scenario_generator.stpa.scenario_prod.stage5 import generate
from asago_scenario_generator.stpa.observation_contract import (
    default_observation_contract,
)
from tests.stpa.sp1_helpers import MockLLMClient

from tests.helpers.discriminating_condition import (
    _generate,
    _ownership_condition,
    _payload_with,
)

CHECK_FAILED = "discriminating_condition_check_failed"

REPLY_CRITERION = {
    "criterion_id": "said",
    "outcome": "The assistant tells the customer the refund went through.",
    "observable": True,
    "claim_level": "reply",
    "evidence": "assistant_message",
    "reason": "The runtime captures assistant messages.",
}


REPLY_CRITERION = {
    "criterion_id": "said",
    "outcome": "The assistant tells the customer the refund went through.",
    "observable": True,
    "claim_level": "reply",
    "evidence": "assistant_message",
    "reason": "The runtime captures assistant messages.",
}


def _with_reply_criterion(payload: dict) -> dict:
    payload["unsafe_outcome"]["observation_criteria"].append(dict(REPLY_CRITERION))
    return payload


def _failed_twice(payload: dict) -> MockLLMClient:
    client = MockLLMClient()
    client.set_response_queue([payload, copy.deepcopy(payload)])
    return client


def _claim_changes(tmp_path) -> list[dict]:
    [path] = (tmp_path / "stage5-normalizations").glob("*.yaml")
    record = yaml.safe_load(path.read_text(encoding="utf-8"))
    return [
        item
        for item in record["normalizations"]
        if item["field"] == "safe_observable_outcome.claim_level"
    ]


def test_command_attempt_without_a_reply_criterion_is_published_analytical_only(
    tmp_path,
) -> None:
    client = _failed_twice(_payload_with(_ownership_condition("ORD-1")))

    result, error = _generate(client, tmp_path)

    assert error is None
    assert result is not None
    assert client.call_count == 2
    assert result.discriminating_condition is None
    assert result.observation_assessment.disposition == "analytical_only"
    safe = result.safe_observable_outcome
    assert (safe.observable, safe.claim_level, safe.evidence, safe.operation_name) == (
        False,
        None,
        None,
        None,
    )
    assert (safe.record_refs, safe.fact_refs) == ((), ())
    assert [item.observable for item in result.observation_criteria] == [False]
    assert result.tool_call_condition_status.status == "not_executable"
    assert result.condition_omitted_reason == (
        f"The discriminating condition failed validation after one correction "
        f"({CHECK_FAILED}); the response declares no reply criterion the "
        "contract supports, so the command_attempt claim cannot run without "
        "its condition and the scenario is published as analytical_only."
    )


def test_a_rerouted_scenario_records_its_levels_and_failure_code(tmp_path) -> None:
    payload = _payload_with(_ownership_condition("ORD-1"))

    result, error = _generate(_failed_twice(payload), tmp_path)

    assert error is None
    assert result is not None
    assert _claim_changes(tmp_path) == [
        {
            "field": "safe_observable_outcome.claim_level",
            "original": "command_attempt",
            "normalized": None,
            "reason": f"condition_dropped_analytical_only:{CHECK_FAILED}",
        }
    ]


def test_a_missing_condition_is_routed_with_its_own_failure_code(tmp_path) -> None:
    client = _failed_twice(_payload_with(None))

    result, error = _generate(client, tmp_path)

    assert error is None
    assert result is not None
    assert result.observation_assessment.disposition == "analytical_only"
    [change] = _claim_changes(tmp_path)
    assert change["reason"] == (
        "condition_dropped_analytical_only:discriminating_condition_missing"
    )
    assert "(discriminating_condition_missing)" in result.condition_omitted_reason


def test_a_scenario_with_a_valid_condition_keeps_its_command_attempt_claim(
    tmp_path,
) -> None:
    client = MockLLMClient()
    client.set_response_queue([_payload_with(_ownership_condition("ORD-2"))])

    result, error = _generate(client, tmp_path)

    assert error is None
    assert result is not None
    assert result.discriminating_condition is not None
    assert result.safe_observable_outcome.claim_level == "command_attempt"
    assert result.observation_assessment.disposition == "executable"
    assert not (tmp_path / "stage5-normalizations").exists()


def test_a_condition_less_reply_scenario_keeps_its_claim_and_its_note(
    tmp_path,
) -> None:
    payload = _payload_with(_ownership_condition("ORD-1"))
    payload["unsafe_outcome"]["observation_criteria"] = [dict(REPLY_CRITERION)]
    payload["unsafe_outcome"]["safe_observable_outcome"] = {
        "observable": True,
        "statement": "The assistant refuses the refund in its reply.",
        "claim_level": "reply",
        "evidence": "assistant_message",
    }

    result, error = _generate(_failed_twice(payload), tmp_path)

    assert error is None
    assert result is not None
    assert result.safe_observable_outcome.claim_level == "reply"
    assert result.observation_assessment.disposition == "executable"
    assert result.condition_omitted_reason == (
        f"The discriminating condition failed validation after one correction "
        f"({CHECK_FAILED}); the scenario is published without a condition."
    )
    assert not (tmp_path / "stage5-normalizations").exists()


def test_a_routed_draft_that_fails_validation_publishes_unrouted(
    tmp_path, monkeypatch
) -> None:
    from asago_scenario_generator.stpa.scenario_prod.stage5.condition_routing import (
        route_without_condition as real,
    )

    def broken(draft, contract, code):
        routed = real(draft, contract, code)
        routed.draft.unsafe_outcome.observation_criteria = []
        return routed

    monkeypatch.setattr(generate, "route_without_condition", broken)
    client = _failed_twice(_payload_with(_ownership_condition("ORD-1")))

    result, error = _generate(client, tmp_path)

    assert error is None
    assert result is not None
    assert result.safe_observable_outcome.claim_level == "command_attempt"
    assert result.condition_omitted_reason == (
        f"The discriminating condition failed validation after one correction "
        f"({CHECK_FAILED}); the scenario is published without a condition."
    )


def test_command_attempt_with_a_supported_reply_criterion_is_published_as_reply(
    tmp_path,
) -> None:
    payload = _with_reply_criterion(_payload_with(_ownership_condition("ORD-1")))

    result, error = _generate(_failed_twice(payload), tmp_path)

    assert error is None
    assert result is not None
    assert result.discriminating_condition is None
    assert result.observation_assessment.disposition == "executable"
    assert result.observation_assessment.supported_criteria == ("said",)
    safe = result.safe_observable_outcome
    assert (safe.observable, safe.claim_level, safe.evidence, safe.operation_name) == (
        True,
        "reply",
        "assistant_message",
        None,
    )
    assert [(c.criterion_id, c.observable) for c in result.observation_criteria] == [
        ("attempt", False),
        ("said", True),
    ]
    assert result.condition_omitted_reason == (
        f"The discriminating condition failed validation after one correction "
        f"({CHECK_FAILED}); the scenario is published without a condition and "
        "its claim moved from command_attempt to reply."
    )
    [change] = _claim_changes(tmp_path)
    assert change == {
        "field": "safe_observable_outcome.claim_level",
        "original": "command_attempt",
        "normalized": "reply",
        "reason": f"condition_dropped_reply:{CHECK_FAILED}",
    }


def test_reply_criterion_the_contract_does_not_support_routes_to_analytical_only(
    tmp_path,
) -> None:
    command_only = default_observation_contract().model_copy(
        update={"supported_claim_levels": ("command_attempt",), "content_digest": ""}
    )
    payload = _with_reply_criterion(_payload_with(_ownership_condition("ORD-1")))

    result, error = _generate(
        _failed_twice(payload), tmp_path, observation_contract=command_only.finalize()
    )

    assert error is None
    assert result is not None
    assert result.observation_assessment.disposition == "analytical_only"
    assert result.safe_observable_outcome.observable is False
    assert [item.observable for item in result.observation_criteria] == [False, False]
