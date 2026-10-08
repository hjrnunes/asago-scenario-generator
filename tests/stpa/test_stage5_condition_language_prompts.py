"""Stage 5 corrections for the condition language: not_called, order, values.

Each test pins text in the correction the real flow sends. The fixed wording
of the first request sits in ``tests/phrases/stage5_context_*.yaml``.
"""

from __future__ import annotations

from tests.stpa.sp1_helpers import MockLLMClient

from tests.helpers.discriminating_condition import (
    _generate,
    _generate_plain,
    _payload_with,
    _placeholder_payload,
)


def _flat(text: str) -> str:
    return " ".join(text.split())


def _correction(tmp_path) -> str:
    """Return the correction request sent after a literal_unsupported failure."""
    client = MockLLMClient()
    client.set_response_queue([_placeholder_payload(), _placeholder_payload()])
    _generate_plain(client, tmp_path)
    assert client.call_count == 2
    return _flat(client.calls[1].user_prompt)


# --- P2: the literal_unsupported correction ---------------------------------


def test_literal_correction_limits_not_called_and_names_the_analytical_path(
    tmp_path,
) -> None:
    correction = _correction(tmp_path)
    for phrase in (
        "If no supplied value separates the unsafe call, use not_called only "
        "when the unsafe behavior is that the operation is never called, and "
        "use order only for a rule about call sequence.",
        "Otherwise declare the scenario analytical-only: set "
        "unsafe_outcome.discriminating_condition to null, and set observable "
        "to false, with claim_level, evidence and operation_name null, on "
        "every observation_criteria entry and on safe_observable_outcome.",
        "Keep observation_criteria and safe_observable_outcome unchanged "
        "unless you declare the scenario analytical-only.",
    ):
        assert phrase in correction, phrase


def test_literal_correction_no_longer_offers_a_statement_only_condition(
    tmp_path,
) -> None:
    correction = _correction(tmp_path)
    assert "statement only" not in correction
    assert "replace the comparison with an order or not_called" not in correction


def test_the_analytical_path_the_correction_names_validates_in_one_request(
    tmp_path,
) -> None:
    payload = _payload_with(None)
    outcome = payload["unsafe_outcome"]
    outcome["observation_criteria"] = [
        {
            "criterion_id": "attempt",
            "outcome": "The refund_payment operation is attempted for the order.",
            "observable": False,
            "claim_level": None,
            "evidence": None,
            "operation_name": None,
            "reason": "No supplied value separates the unsafe call.",
        }
    ]
    outcome["safe_observable_outcome"] = {
        "observable": False,
        "statement": "No supplied value separates the unsafe call.",
        "claim_level": None,
        "evidence": None,
        "operation_name": None,
    }
    client = MockLLMClient()
    client.set_response_queue([payload])

    result, error = _generate(client, tmp_path)

    assert error is None
    assert result is not None
    assert client.call_count == 1
    assert result.discriminating_condition is None
    assert result.observation_assessment.disposition == "analytical_only"
