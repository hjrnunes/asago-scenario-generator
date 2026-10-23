"""calls.jsonl names the provider records of a call instead of copying its text.

Publication appends an event rather than rewriting the file, and readers fold
it back into the call it marks.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from asago_scenario_generator.report.run_data import _read_calls
from asago_scenario_generator.stpa.infra.call_log import (
    CallLog,
    append_call_log,
    call_entries,
    make_call_log_entry,
    mark_call_published,
    read_call_entries,
)
from asago_scenario_generator.stpa.infra.llm_helpers import (
    CorrectionPolicy,
    call_with_policy,
    log_llm_call_failure,
)
from asago_scenario_generator.stpa.infra.manifest_helpers import count_calls_by_stage
from asago_scenario_generator.stpa.infra.provider_record import ProviderCallSession
from tests.helpers.provider_call_record import (
    _Answer,
    _answer,
    _client,
    _completion,
    _Provider,
    _records,
)
from tests.helpers.transport_retry import _connection_error, _failing_then

TEXT_FIELDS = {
    "system_prompt_text",
    "user_prompt_text",
    "raw_response",
    "cleaned_response",
    "response_content",
}
SYSTEM_PROMPT = "a distinctive system prompt"
USER_PROMPT = "a distinctive user prompt"


def _call(client: Any, run_dir: Path) -> Any:
    return call_with_policy(
        llm_client=client,
        system_prompt=SYSTEM_PROMPT,
        user_prompt=USER_PROMPT,
        response_format=_Answer,
        run_dir=run_dir,
        stage="stage_x",
        step="call_answer",
        policy=CorrectionPolicy(),
    )


def _joins(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {"sequence": r["sequence"], "request_sha256": r["request_sha256"]}
        for r in records
    ]


def _entries(run_dir: Path) -> list[dict[str, Any]]:
    entries = read_call_entries(run_dir)
    assert entries is not None
    return entries


def _session_entries(provider: _Provider, run_dir: Path) -> list[dict[str, Any]]:
    session = ProviderCallSession(record_dir=run_dir)
    _call(_client(provider, session=session), run_dir)
    entries = _entries(run_dir)
    assert entries == session.call_log.entries(run_dir)
    return entries


def test_a_session_call_names_its_provider_record_and_holds_no_text(
    tmp_path: Path,
) -> None:
    (entry,) = _session_entries(_Provider(_answer), tmp_path)

    assert entry["success"] is True
    assert TEXT_FIELDS.isdisjoint(entry)
    assert entry["provider_requests"] == _joins(_records(tmp_path))
    text = (tmp_path / "calls.jsonl").read_text(encoding="utf-8")
    assert SYSTEM_PROMPT not in text
    assert USER_PROMPT not in text
    assert '"answer"' not in text


def test_a_transport_retry_names_both_provider_records_in_order(
    tmp_path: Path,
) -> None:
    (entry,) = _session_entries(_failing_then(_connection_error()), tmp_path)

    records = _records(tmp_path)
    assert [r["outcome"] for r in records] == ["error", "response"]
    assert entry["provider_requests"] == _joins(records)


def test_a_failed_session_call_names_the_record_it_sent(tmp_path: Path) -> None:
    provider = _Provider(lambda **_: _completion('{"unexpected": 1}'))

    (entry,) = _session_entries(provider, tmp_path)

    assert entry["success"] is False
    assert entry["provider_response_received"] is True
    assert TEXT_FIELDS.isdisjoint(entry)
    assert entry["provider_requests"] == _joins(_records(tmp_path))


def test_a_failure_logged_before_dispatch_names_no_record(tmp_path: Path) -> None:
    log_llm_call_failure(
        "m",
        tmp_path,
        "stage",
        "step",
        "PromptContractError: blocked",
        system_prompt=SYSTEM_PROMPT,
        user_prompt=USER_PROMPT,
        call_log=CallLog(),
    )

    (entry,) = _entries(tmp_path)
    assert entry["provider_requests"] == []
    assert TEXT_FIELDS.isdisjoint(entry)
    assert entry["system_prompt_hash"]


def test_a_call_without_a_session_keeps_its_text(tmp_path: Path) -> None:
    _call(_client(_Provider(_answer)), tmp_path)

    (entry,) = _entries(tmp_path)
    assert "provider_requests" not in entry
    assert entry["system_prompt_text"] == SYSTEM_PROMPT
    assert entry["user_prompt_text"] == USER_PROMPT
    assert json.loads(entry["response_content"]) == {"answer": "42"}


def _validated(step: str) -> dict[str, Any]:
    return make_call_log_entry(
        stage="stage",
        step=step,
        model="m",
        semantic_validation_passed=True,
        compiled=False,
    )


@pytest.mark.parametrize("with_records", [True, False])
def test_publishing_appends_an_event_and_leaves_earlier_lines_alone(
    tmp_path: Path, with_records: bool
) -> None:
    log = CallLog() if with_records else None
    append_call_log([_validated("call"), _validated("other")], tmp_path, log)
    path = tmp_path / "calls.jsonl"
    before = path.read_bytes()

    mark_call_published(tmp_path, "stage", "call", log)

    after = path.read_bytes()
    assert after.startswith(before)
    event = json.loads(after[len(before) :])
    assert event == {
        "kind": "call-published",
        "attempt_id": json.loads(before.splitlines()[0])["attempt_id"],
    }
    entries = _entries(tmp_path)
    assert [e["published"] for e in entries] == [True, False]
    assert [e["compiled"] for e in entries] == [True, False]
    if log is not None:
        assert log.entries(tmp_path) == entries


def test_a_publication_marks_the_latest_call_before_it(tmp_path: Path) -> None:
    log = CallLog()
    append_call_log([_validated("call")], tmp_path, log)
    mark_call_published(tmp_path, "stage", "call", log)
    append_call_log([_validated("call")], tmp_path, log)

    entries = _entries(tmp_path)

    assert [e["published"] for e in entries] == [True, False]
    assert log.entries(tmp_path) == entries


def test_publication_events_are_not_counted_as_calls(tmp_path: Path) -> None:
    entry = _validated("call")
    entry["prompt_tokens"], entry["completion_tokens"] = 3, 4
    append_call_log([entry], tmp_path)
    before = count_calls_by_stage(tmp_path)

    mark_call_published(tmp_path, "stage", "call")

    assert count_calls_by_stage(tmp_path) == before
    assert before == {"stage": {"call_count": 1, "total_tokens": 7}}


def _old_entry(**fields: Any) -> dict[str, Any]:
    """A call entry as calls.jsonl held it before it named provider records."""
    entry = {
        "stage": "synthesis_obligation_aware_icas",
        "step": "CL-1",
        "attempt_id": "a1",
        "attempt_number": 1,
        "system_prompt_text": "system",
        "user_prompt_text": "user",
        "raw_response": '{"filled_slots": []}',
        "cleaned_response": {"filled_slots": []},
        "response_content": '{"filled_slots": []}',
        "prompt_tokens": 5,
        "completion_tokens": 6,
        "duration_ms": 7,
        "success": True,
        "published": True,
        "compiled": True,
    }
    entry.update(fields)
    return entry


def test_an_old_call_log_still_loads_in_the_report_and_the_stage_summary(
    tmp_path: Path,
) -> None:
    failed = _old_entry(attempt_id="a0", success=False, failure_class="answered")
    lines = [failed, _old_entry()]
    (tmp_path / "calls.jsonl").write_text(
        "".join(json.dumps(line) + "\n" for line in lines), encoding="utf-8"
    )

    calls = _read_calls(tmp_path)

    assert [(c.n, c.attempt_id, c.success) for c in calls] == [
        (1, "a0", False),
        (2, "a1", True),
    ]
    assert calls[1].response_content == '{"filled_slots": []}'
    assert calls[1].tokens == 11
    assert call_entries((tmp_path / "calls.jsonl").read_text()) == lines
    assert count_calls_by_stage(tmp_path) == {
        "synthesis_obligation_aware_icas": {"call_count": 2, "total_tokens": 22}
    }


def test_the_report_reads_a_reply_from_the_provider_record_it_names(
    tmp_path: Path,
) -> None:
    session = ProviderCallSession(record_dir=tmp_path)
    _call(_client(_Provider(_answer), session=session), tmp_path)
    mark_call_published(tmp_path, "stage_x", "call_answer", session.call_log)

    (call,) = _read_calls(tmp_path)

    assert call.n == 1
    assert call.provider_requests[0].sequence == 1
    assert call.response_content == '{"answer": "42"}'


def test_the_report_leaves_a_reply_unread_when_the_record_does_not_match(
    tmp_path: Path,
) -> None:
    session = ProviderCallSession(record_dir=tmp_path)
    _call(_client(_Provider(_answer), session=session), tmp_path)
    (record,) = _records(tmp_path)
    record["request_sha256"] = "0" * 64
    (tmp_path / "provider-calls.jsonl").write_text(json.dumps(record) + "\n")

    (call,) = _read_calls(tmp_path)

    assert call.response_content is None
