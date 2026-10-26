"""A failure call of a recorded operation is an observable command attempt."""

from __future__ import annotations

import pytest

from asago_scenario_generator.stpa.observation_contract import (
    FailureCall,
    ObservationContract,
    ObservationCriterion,
    assess_observation_criteria,
    default_observation_contract,
    failure_call_criterion,
)

RECORDED = ("refund_payment", "lookup_order")


def _analytical(criterion_id: str = "obs_1") -> ObservationCriterion:
    return ObservationCriterion(
        criterion_id=criterion_id,
        outcome="The refund goes to an order the customer does not own.",
        observable=False,
        reason="The model judged the outcome outside the capture boundary.",
    )


def _contract_without(kind: str) -> ObservationContract:
    contract = default_observation_contract()
    capture = tuple(
        item.model_copy(update={"available": False}) if item.kind == kind else item
        for item in contract.capture
    )
    return contract.model_copy(
        update={"capture": capture, "content_digest": ""}
    ).finalize()


@pytest.mark.parametrize(
    ("kind", "outcome"),
    (
        (
            "incorrect_call",
            "refund_payment is called where the failure criterion states the "
            "call is incorrect.",
        ),
        (
            "missing_call",
            "refund_payment is not called where the failure criterion states "
            "the call is required.",
        ),
    ),
)
def test_a_failure_call_of_a_recorded_operation_is_a_command_attempt(
    kind, outcome
) -> None:
    criterion = failure_call_criterion(
        FailureCall(kind=kind, operation_name="refund_payment"),
        default_observation_contract(),
        RECORDED,
    )

    assert criterion == ObservationCriterion(
        criterion_id="failure_call",
        outcome=outcome,
        observable=True,
        claim_level="command_attempt",
        evidence="tool_call",
        operation_name="refund_payment",
        reason=(
            f"The failure call ({kind}) names refund_payment, an operation the "
            "target records, and the contract captures tool calls at claim "
            "level command_attempt."
        ),
    )


def test_the_failure_call_criterion_makes_an_analytical_scenario_executable() -> None:
    contract = default_observation_contract()
    added = failure_call_criterion(
        FailureCall(kind="incorrect_call", operation_name="refund_payment"),
        contract,
        RECORDED,
    )
    assert added is not None

    assessment = assess_observation_criteria([_analytical(), added], contract)

    assert assessment.disposition == "executable"
    assert assessment.supported_criteria == ("failure_call",)
    assert assessment.unsupported_criteria == ("obs_1",)


def test_without_a_failure_call_there_is_no_criterion() -> None:
    assert failure_call_criterion(None, default_observation_contract(), RECORDED) is (
        None
    )


def test_a_failure_call_of_an_operation_the_target_does_not_record_is_not_observable() -> (
    None
):
    criterion = failure_call_criterion(
        FailureCall(kind="incorrect_call", operation_name="delete_account"),
        default_observation_contract(),
        RECORDED,
    )

    assert criterion is None


def test_no_recorded_operation_means_no_criterion() -> None:
    criterion = failure_call_criterion(
        FailureCall(kind="missing_call", operation_name="refund_payment"),
        default_observation_contract(),
        (),
    )

    assert criterion is None


def test_a_contract_that_does_not_capture_tool_calls_observes_no_failure_call() -> None:
    criterion = failure_call_criterion(
        FailureCall(kind="incorrect_call", operation_name="refund_payment"),
        _contract_without("tool_call"),
        RECORDED,
    )

    assert criterion is None


def test_a_contract_without_command_attempts_observes_no_failure_call() -> None:
    contract = default_observation_contract()
    contract = contract.model_copy(
        update={"supported_claim_levels": ("reply",), "content_digest": ""}
    ).finalize()

    criterion = failure_call_criterion(
        FailureCall(kind="incorrect_call", operation_name="refund_payment"),
        contract,
        RECORDED,
    )

    assert criterion is None


def test_the_criterion_id_never_collides_with_a_provider_criterion() -> None:
    criterion = failure_call_criterion(
        FailureCall(kind="incorrect_call", operation_name="refund_payment"),
        default_observation_contract(),
        RECORDED,
        taken_ids=("failure_call", "failure_call_2"),
    )

    assert criterion is not None
    assert criterion.criterion_id == "failure_call_3"
