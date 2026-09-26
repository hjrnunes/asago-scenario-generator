"""Tests for the scenario-specific Stage 5 safe outcome."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from asago_scenario_generator.stpa.observation_contract import (
    SafeObservableOutcome,
    default_observation_contract,
)
from asago_scenario_generator.stpa.scenario_prod.bdi_generation import (
    assemble_scenario_spec,
    generate_bdi_for_context,
)
from asago_scenario_generator.stpa.scenario_prod.assembly import assemble_envelope
from asago_scenario_generator.stpa.scenario_prod.handoff import build_scenario_handoff
from asago_scenario_generator.stpa.scenario_prod.presentation import (
    render_scenario_summary,
)
from tests.stpa.sp1_helpers import MockLLMClient

from .test_normal_authoring_wire import (
    _control_structure,
    _defender_bdi,
    _loss_analysis,
    _normal_payload,
    _record_observations,
    _target_operation,
    _wrong_timing_threat,
    _wrong_timing_context,
)


def test_stage5_materializes_the_supplied_safe_observable_outcome(tmp_path) -> None:
    payload = _normal_payload()
    payload["unsafe_outcome"]["observation_criteria"] = [
        {
            "criterion_id": "attempt",
            "outcome": "The refund_payment operation is attempted for the selected order.",
            "observable": True,
            "claim_level": "command_attempt",
            "evidence": "tool_call",
            "operation_name": "refund_payment",
            "reason": "The runtime captures decoded tool calls.",
        }
    ]
    payload["unsafe_outcome"]["safe_observable_outcome"] = {
        "observable": True,
        "statement": (
            "The refund_payment operation is attempted only for the selected "
            "order while preserving the required refund policy."
        ),
        "claim_level": "command_attempt",
        "evidence": "tool_call",
        "operation_name": "refund_payment",
        "record_refs": ["TARGET-STATE"],
        "fact_refs": [
            "TARGET-STATE.order_id",
            "TARGET-STATE.refund_eligible",
        ],
    }
    client = MockLLMClient()
    client.set_response_queue([payload])

    result, error = generate_bdi_for_context(
        client,
        _wrong_timing_context(),
        tmp_path,
        target_operation=_target_operation(),
        target_observations=_record_observations(),
        execution_design=False,
        observation_contract=default_observation_contract(),
    )

    assert error is None
    assert result is not None
    assert result.safe_observable_outcome is not None
    assert (
        result.safe_observable_outcome.statement
        == payload["unsafe_outcome"]["safe_observable_outcome"]["statement"]
    )
    assert result.safe_observable_outcome.operation_name == "refund_payment"


def test_handoff_and_gherkin_use_the_safe_outcome_statement(tmp_path) -> None:
    payload = _normal_payload()
    safe_statement = (
        "The refund_payment operation is attempted only for the selected order."
    )
    payload["unsafe_outcome"]["observation_criteria"] = [
        {
            "criterion_id": "attempt",
            "outcome": "The refund_payment operation is attempted.",
            "observable": True,
            "claim_level": "command_attempt",
            "evidence": "tool_call",
            "operation_name": "refund_payment",
            "reason": "The runtime captures decoded tool calls.",
        }
    ]
    payload["unsafe_outcome"]["safe_observable_outcome"] = {
        "observable": True,
        "statement": safe_statement,
        "claim_level": "command_attempt",
        "evidence": "tool_call",
        "operation_name": "refund_payment",
    }
    client = MockLLMClient()
    client.set_response_queue([payload])
    context = _wrong_timing_context(scenario_id="SCN-001")
    result, error = generate_bdi_for_context(
        client,
        context,
        tmp_path,
        target_operation=_target_operation(),
        target_observations=_record_observations(),
        execution_design=False,
        observation_contract=default_observation_contract(),
    )
    assert error is None
    assert result is not None

    spec = assemble_scenario_spec(
        _defender_bdi(context),
        result,
        _wrong_timing_threat(),
        _control_structure(),
        0,
        scenario_context=context,
    )
    narrative, tree, gherkin = render_scenario_summary(spec)
    envelope = assemble_envelope(
        scenario_id=spec.scenario_id,
        scenario_spec=spec,
        narrative=narrative,
        attack_tree=tree,
        gherkin_spec=gherkin,
        gherkin_raw=gherkin.to_feature_text(),
        control_structure=_control_structure(),
    )
    handoff = build_scenario_handoff(
        envelope,
        loss_analysis=_loss_analysis(),
        observed_operations=("refund_payment",),
    )

    assert handoff.safe_alternative == safe_statement
    assert handoff.safe_observable_outcome is not None
    assert handoff.safe_observable_outcome.statement == safe_statement
    assert handoff.gherkin.then_expected == [f"Then {safe_statement}"]
    assert [item.name for item in handoff.documented_operations] == [
        "refund_payment"
    ]


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        (
            "operation_name",
            "unlisted_operation",
            "operation_name",
        ),
        (
            "fact_refs",
            ["TARGET-STATE.not_supplied"],
            "fact_refs",
        ),
    ),
)
def test_safe_outcome_rejects_references_outside_supplied_inputs(
    tmp_path,
    field,
    value,
    message,
) -> None:
    payload = _normal_payload()
    payload["unsafe_outcome"]["observation_criteria"] = [
        {
            "criterion_id": "attempt",
            "outcome": "The refund_payment operation is attempted.",
            "observable": True,
            "claim_level": "command_attempt",
            "evidence": "tool_call",
            "operation_name": "refund_payment",
            "reason": "The runtime captures decoded tool calls.",
        }
    ]
    payload["unsafe_outcome"]["safe_observable_outcome"] = {
        "observable": True,
        "statement": "The selected refund operation remains policy-compliant.",
        "claim_level": "command_attempt",
        "evidence": "tool_call",
        "operation_name": "refund_payment",
        "record_refs": ["TARGET-STATE"],
        "fact_refs": ["TARGET-STATE.order_id"],
    }
    payload["unsafe_outcome"]["safe_observable_outcome"][field] = value
    client = MockLLMClient()
    client.set_response_queue([payload, payload])

    result, error = generate_bdi_for_context(
        client,
        _wrong_timing_context(),
        tmp_path,
        target_operation=_target_operation(),
        target_observations=_record_observations(),
        execution_design=False,
        observation_contract=default_observation_contract(),
    )

    assert result is None
    assert error is not None
    assert message in error


def test_analytical_only_safe_outcome_has_no_executable_references(tmp_path) -> None:
    payload = _normal_payload()
    payload["unsafe_outcome"]["observation_criteria"] = [
        {
            "criterion_id": "state",
            "outcome": "The backend record reaches the required state.",
            "observable": False,
            "claim_level": None,
            "evidence": None,
            "reason": "The live contract captures no backend state effect.",
        }
    ]
    payload["unsafe_outcome"]["safe_observable_outcome"] = {
        "observable": False,
        "statement": (
            "The backend state effect remains analytical because the supplied "
            "observation contract cannot capture it."
        ),
        "claim_level": None,
        "evidence": None,
        "operation_name": None,
        "record_refs": [],
        "fact_refs": [],
    }
    client = MockLLMClient()
    client.set_response_queue([payload])

    result, error = generate_bdi_for_context(
        client,
        _wrong_timing_context(),
        tmp_path,
        execution_design=False,
        observation_contract=default_observation_contract(),
    )

    assert error is None
    assert result is not None
    assert result.observation_assessment is not None
    assert result.observation_assessment.disposition == "analytical_only"
    assert result.safe_observable_outcome is not None
    assert not result.safe_observable_outcome.observable


def test_observable_safe_outcome_can_omit_operation_reference(tmp_path) -> None:
    payload = _normal_payload()
    payload["unsafe_outcome"]["observation_criteria"] = [
        {
            "criterion_id": "reply",
            "outcome": "The assistant reply remains within the required policy.",
            "observable": True,
            "claim_level": "reply",
            "evidence": "assistant_message",
            "reason": "The runtime captures assistant messages.",
        }
    ]
    payload["unsafe_outcome"]["safe_observable_outcome"] = {
        "observable": True,
        "statement": "The assistant reply remains within the required policy.",
        "claim_level": "reply",
        "evidence": "assistant_message",
    }
    client = MockLLMClient()
    client.set_response_queue([payload])

    result, error = generate_bdi_for_context(
        client,
        _wrong_timing_context(),
        tmp_path,
        execution_design=False,
        observation_contract=default_observation_contract(),
    )

    assert error is None
    assert result is not None
    assert result.safe_observable_outcome is not None
    assert result.safe_observable_outcome.operation_name is None


def test_command_attempt_observation_requires_exact_inventory_operation(tmp_path) -> None:
    payload = _normal_payload()
    payload["unsafe_outcome"]["observation_criteria"] = [
        {
            "criterion_id": "attempt",
            "outcome": "The selected operation is attempted.",
            "observable": True,
            "claim_level": "command_attempt",
            "evidence": "tool_call",
            "reason": "The runtime captures decoded tool calls.",
        }
    ]
    payload["unsafe_outcome"]["safe_observable_outcome"] = {
        "observable": True,
        "statement": "The selected operation remains within policy.",
        "claim_level": "command_attempt",
        "evidence": "tool_call",
        "operation_name": "refund_payment",
    }
    corrected = _normal_payload()
    corrected["unsafe_outcome"]["observation_criteria"] = [
        {
            **payload["unsafe_outcome"]["observation_criteria"][0],
            "operation_name": "refund_payment",
        }
    ]
    corrected["unsafe_outcome"]["safe_observable_outcome"] = (
        payload["unsafe_outcome"]["safe_observable_outcome"]
    )
    client = MockLLMClient()
    client.set_response_queue([payload, corrected])

    result, error = generate_bdi_for_context(
        client,
        _wrong_timing_context(),
        tmp_path,
        target_operation=_target_operation(),
        execution_design=False,
        observation_contract=default_observation_contract(),
    )

    assert error is None
    assert result is not None
    assert client.call_count == 2
    assert "exact operation from the supplied inventory" in client.calls[1].user_prompt


def test_non_null_reply_operation_must_be_in_inventory(tmp_path) -> None:
    payload = _normal_payload()
    payload["unsafe_outcome"]["observation_criteria"] = [
        {
            "criterion_id": "reply",
            "outcome": "The assistant reply remains within policy.",
            "observable": True,
            "claim_level": "reply",
            "evidence": "assistant_message",
            "operation_name": "unlisted_operation",
            "reason": "The runtime captures assistant messages.",
        }
    ]
    payload["unsafe_outcome"]["safe_observable_outcome"] = {
        "observable": True,
        "statement": "The assistant reply remains within policy.",
        "claim_level": "reply",
        "evidence": "assistant_message",
    }
    client = MockLLMClient()
    client.set_response_queue([payload, payload])

    result, error = generate_bdi_for_context(
        client,
        _wrong_timing_context(),
        tmp_path,
        target_operation=_target_operation(),
        execution_design=False,
        observation_contract=default_observation_contract(),
    )

    assert result is None
    assert error is not None
    assert "exact operation from the supplied inventory" in error


@pytest.mark.parametrize(
    "payload",
    (
        {
            "observable": True,
            "statement": "The selected operation remains safe.",
            "claim_level": "reply",
            "evidence": "tool_call",
        },
        {
            "observable": True,
            "statement": "The selected operation remains safe.",
            "claim_level": None,
            "evidence": "tool_call",
        },
        {
            "observable": False,
            "statement": "The state effect remains analytical.",
            "claim_level": None,
            "evidence": None,
            "operation_name": "refund_payment",
        },
    ),
)
def test_safe_observable_outcome_schema_rejects_invalid_boundaries(payload) -> None:
    with pytest.raises(ValidationError):
        SafeObservableOutcome.model_validate(payload)


def test_safe_observable_outcome_rejects_blank_reference_values() -> None:
    with pytest.raises(ValidationError):
        SafeObservableOutcome.model_validate(
            {
                "observable": True,
                "statement": "The assistant reply remains safe.",
                "claim_level": "reply",
                "evidence": "assistant_message",
                "operation_name": " ",
            }
        )
    with pytest.raises(ValidationError):
        SafeObservableOutcome.model_validate(
            {
                "observable": True,
                "statement": "The assistant reply remains safe.",
                "claim_level": "reply",
                "evidence": "assistant_message",
                "record_refs": [" "],
            }
        )
