"""The provider adapter's single bounded ICA hazard correction call."""

from __future__ import annotations

import pytest

from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.obligation_aware.ica_verification import (
    IcaHazardVerificationCorrection,
    IcaHazardVerificationVerdict,
)
from asago_scenario_generator.stpa.obligation_aware.provider import (
    ObligationAwareLLMAdapter,
)
from tests.test_ica_hazard_verification import _request
from tests.helpers.obligation_aware import _controls


class _Client:
    model = "fake-stpa"

    def __init__(self, content: object) -> None:
        self.content = content
        self.calls: list[dict] = []

    def complete(self, **kwargs):
        self.calls.append(kwargs)
        return LLMResult(
            content=self.content,
            prompt_tokens=1,
            completion_tokens=1,
            duration_ms=1,
            system_prompt=kwargs["system_prompt"],
            user_prompt=kwargs["user_prompt"],
        )


def _verdict() -> IcaHazardVerificationVerdict:
    return IcaHazardVerificationVerdict(
        ica_id=_request().ica_id,
        verdict="insufficient_evidence",
        rationale="The deviation does not name the unchecked gate state.",
    )


def _correct(tmp_path, content: object):
    client = _Client(content)
    adapter = ObligationAwareLLMAdapter(client, run_dir=tmp_path, controls=_controls())
    return client, adapter.correct_ica_hazard(_request(), _verdict())


def test_correction_is_returned_for_the_same_ica(tmp_path) -> None:
    request = _request()
    correction = {
        "ica_id": request.ica_id,
        "deviation": "Approve a release while the gate check is still pending.",
        "rationale": "Name the unchecked gate state.",
    }

    client, result = _correct(tmp_path, {"correction": correction})

    assert result == IcaHazardVerificationCorrection.model_validate(correction)
    assert len(client.calls) == 1
    assert request.ica_id in client.calls[0]["user_prompt"]
    assert _verdict().rationale in client.calls[0]["user_prompt"]


def test_correction_for_another_ica_is_rejected(tmp_path) -> None:
    correction = {"ica_id": "RESP-1:CA-1:INCORRECT:9", "rationale": "Moved."}

    with pytest.raises(ValueError, match="changed the ICA identity"):
        _correct(tmp_path, {"correction": correction})


def test_invalid_payload_fails_without_a_retry(tmp_path) -> None:
    client = _Client({"correction": {"ica_id": _request().ica_id}})
    adapter = ObligationAwareLLMAdapter(client, run_dir=tmp_path, controls=_controls())

    with pytest.raises(ValueError) as raised:
        adapter.correct_ica_hazard(_request(), _verdict())

    assert "rationale" in str(raised.value)
    assert len(client.calls) == 1
