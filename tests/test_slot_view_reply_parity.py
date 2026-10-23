"""The report reads a slot decision the same way from the old and the new log.

The old call log stored each reply as ``response_content``: the JSON dump of
the model the client parsed it into, or the raw text when that parse failed.
The new log names the provider record instead, and the report rebuilds the
same values from the raw reply text there.
"""

from __future__ import annotations

import json
import unicodedata
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from asago_scenario_generator.report.run_data import _read_calls
from asago_scenario_generator.report.slot_view import ICA_STAGE, _call_answers
from asago_scenario_generator.stpa.infra.llm_helpers import (
    CorrectionPolicy,
    call_with_policy,
)
from asago_scenario_generator.stpa.infra.provider_record import ProviderCallSession
from asago_scenario_generator.stpa.obligation_aware.provider import (
    _slot_provider_payload_type,
)
from tests.helpers.provider_call_record import _client, _completion, _Provider, _records

SLOT = "RESP-1:CA-1-1:WRONG_TIMING"
DECOMPOSED = unicodedata.normalize("NFD", "Le café est fermé")


def _reply(**slot: Any) -> str:
    fields = {
        "slot_id": SLOT,
        "is_na": True,
        "na_rationale": DECOMPOSED,
        "findings": [],
        "consideration_results": [],
    }
    fields.update(slot)
    return json.dumps({"filled_slots": [fields]}, ensure_ascii=False)


def _log(run_dir: Path, content: str, *, recorded: bool) -> None:
    session = ProviderCallSession(record_dir=run_dir) if recorded else None
    call_with_policy(
        llm_client=_client(
            _Provider(lambda **_: _completion(content)), session=session
        ),
        system_prompt="system",
        user_prompt="user",
        response_format=_slot_provider_payload_type(1, 0),
        run_dir=run_dir,
        stage=ICA_STAGE,
        step="RESP-1",
        policy=CorrectionPolicy(),
    )


def _answers(run_dir: Path) -> Any:
    try:
        return _call_answers(SimpleNamespace(calls=_read_calls(run_dir)))
    except ValueError as error:
        return type(error)


def _both(tmp_path: Path, content: str) -> tuple[Path, Path]:
    old, new = tmp_path / "old", tmp_path / "new"
    _log(old, content, recorded=False)
    _log(new, content, recorded=True)
    (old_call,) = _read_calls(old)
    (new_call,) = _read_calls(new)
    assert old_call.success and new_call.success
    assert "response_content" in json.loads((old / "calls.jsonl").read_text())
    assert "response_content" not in json.loads((new / "calls.jsonl").read_text())
    return old, new


def test_a_decomposed_rationale_reads_as_the_parsed_model_stored_it(
    tmp_path: Path,
) -> None:
    old, new = _both(tmp_path, _reply())

    (record,) = _records(new)
    raw = record["response"]["body"]["choices"][0]["message"]["content"]
    assert DECOMPOSED in raw
    assert (
        _answers(new)
        == _answers(old)
        == {SLOT: (True, unicodedata.normalize("NFC", DECOMPOSED))}
    )


def test_a_coerced_boolean_reads_as_the_parsed_model_stored_it(
    tmp_path: Path,
) -> None:
    old, new = _both(tmp_path, _reply(is_na="true"))

    assert _answers(new) == _answers(old)
    assert _answers(new)[SLOT][0] is True


@pytest.mark.parametrize("fence", ["```json\n{}\n```", "```\n{}\n```"])
def test_a_fenced_reply_reads_as_the_raw_text_the_log_stored(
    tmp_path: Path, fence: str
) -> None:
    content = fence.replace("{}", _reply())
    old, new = _both(tmp_path, content)

    (old_call,) = _read_calls(old)
    (new_call,) = _read_calls(new)
    assert old_call.response_content == new_call.response_content == content
    assert new_call.response_parsed is False
    assert _answers(new) == _answers(old)
