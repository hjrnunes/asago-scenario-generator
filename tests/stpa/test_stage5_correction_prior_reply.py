"""The Stage 5 correction shows the model the reply it is asked to correct."""

from __future__ import annotations

import json

from asago_scenario_generator.stpa.observation_contract import (
    default_observation_contract,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.generate import (
    generate_bdi_for_context,
)
from tests.helpers.discriminating_condition import (
    _generate,
    _ownership_condition,
    _payload_with,
)
from tests.helpers.normal_authoring_wire import _wrong_timing_context
from tests.helpers.stage5_safe_outcome import _command_attempt_payload
from tests.stpa.sp1_helpers import MockLLMClient

PRIOR_BLOCK = "Prior structured response to correct in place:\n```json\n"
ERROR_BLOCK = "\n\nExact validation error from the prior response:\n"
ATTEMPT_OUTCOME = "The refund_payment operation is attempted for the order."


def _block(prompt: str) -> str:
    """Return the prior-reply text of a correction prompt."""
    head = prompt.index(PRIOR_BLOCK) + len(PRIOR_BLOCK)
    return prompt[head : prompt.index("\n```", head)]


def test_a_condition_correction_carries_the_first_reply(tmp_path) -> None:
    first = _payload_with(None)
    client = MockLLMClient()
    client.set_response_queue([first, _payload_with(_ownership_condition("ORD-2"))])

    result, error = _generate(client, tmp_path)

    assert error is None
    assert result is not None
    correction = client.calls[1].user_prompt
    assert correction.index(PRIOR_BLOCK) < correction.index(ERROR_BLOCK)
    sent = json.loads(_block(correction))
    criteria = sent["unsafe_outcome"]["observation_criteria"]
    assert [item["outcome"] for item in criteria] == [ATTEMPT_OUTCOME]
    assert sent["unsafe_outcome"]["safe_observable_outcome"]["claim_level"] == (
        "command_attempt"
    )


def test_a_non_condition_correction_carries_the_first_reply(tmp_path) -> None:
    first = _command_attempt_payload(["TARGET-STATE.not_supplied"], [])
    client = MockLLMClient()
    client.set_response_queue([first, first])

    result, _ = generate_bdi_for_context(
        client,
        _wrong_timing_context(),
        tmp_path,
        observation_contract=default_observation_contract(),
    )

    assert client.call_count == 2
    sent = json.loads(_block(client.calls[1].user_prompt))
    assert sent["unsafe_outcome"]["safe_observable_outcome"]["record_refs"] == [
        "TARGET-STATE.not_supplied"
    ]


def test_the_first_request_carries_no_prior_reply(tmp_path) -> None:
    client = MockLLMClient()
    client.set_response_queue([_payload_with(None)] * 2)

    _generate(client, tmp_path)

    assert PRIOR_BLOCK not in client.calls[0].user_prompt
