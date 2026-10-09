"""The provider adapter's single bounded ICA hazard correction call."""

from __future__ import annotations

import pytest

from asago_scenario_generator.stpa.obligation_aware.ica_verification import (
    IcaHazardVerificationCorrection,
    IcaHazardVerificationVerdict,
)
from asago_scenario_generator.stpa.obligation_aware.provider import (
    ObligationAwareLLMAdapter,
)
from tests.helpers.calls_log import read_calls_jsonl
from tests.helpers.ica_hazard_verification import _request
from tests.helpers.scripted_client import ScriptedClient
from tests.helpers.obligation_aware import _controls


def _Client(content: object) -> ScriptedClient:
    return ScriptedClient([content], model="fake-stpa")


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


def _correction_payload() -> dict:
    return {
        "correction": {
            "ica_id": _request().ica_id,
            "deviation": "Approve a release while the gate check is still pending.",
            "rationale": "Name the unchecked gate state.",
        }
    }


def test_first_correction_prompt_has_no_retry_block(tmp_path) -> None:
    client, _ = _correct(tmp_path, _correction_payload())

    prompt = client.calls[0]["user_prompt"]
    assert "previous correction" not in prompt
    assert prompt.endswith("use only the supplied STPA facts.\n")


def test_unchanged_retry_appends_one_block_to_the_same_prompt(tmp_path) -> None:
    first_client, _ = _correct(tmp_path, _correction_payload())
    client = _Client(_correction_payload())
    adapter = ObligationAwareLLMAdapter(client, run_dir=tmp_path, controls=_controls())

    adapter.correct_ica_hazard(_request(), _verdict(), unchanged_retry=True)

    first = first_client.calls[0]
    retry = client.calls[0]
    assert retry["system_prompt"] == first["system_prompt"]
    base = first["user_prompt"].rstrip("\n")
    assert retry["user_prompt"].startswith(base + "\n\n")
    block = retry["user_prompt"][len(base) :].strip()
    assert "previous correction" in block
    assert "identical" in block
    for way_out in ("not_applicable", "unresolved"):
        assert way_out in block
    assert retry["user_prompt"].endswith("\n")


def test_unchanged_retry_is_logged_under_its_own_step(tmp_path) -> None:
    client = ScriptedClient(
        [_correction_payload(), _correction_payload()], model="fake-stpa"
    )
    adapter = ObligationAwareLLMAdapter(client, run_dir=tmp_path, controls=_controls())
    ica_id = _request().ica_id

    adapter.correct_ica_hazard(_request(), _verdict())
    adapter.correct_ica_hazard(_request(), _verdict(), unchanged_retry=True)

    steps = [
        entry["step"]
        for entry in read_calls_jsonl(tmp_path)
        if entry["stage"].endswith("_ica_hazard_correction")
    ]
    assert steps == [ica_id, f"{ica_id}:unchanged-retry"]


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
