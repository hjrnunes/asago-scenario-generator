"""The session owns the call records that the manifest reads."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
from pydantic import BaseModel

from asago_scenario_generator.stpa.infra.call_log import (
    CallLog,
    append_call_log,
    call_log_of,
    make_call_log_entry,
    mark_call_published,
)
from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.infra.llm_helpers import (
    CorrectionPolicy,
    call_with_policy,
    log_llm_call_failure,
)
from asago_scenario_generator.stpa.infra.provider_record import (
    ProviderCallSession,
    provider_call_session,
)
from tests.helpers.calls_log import read_calls_jsonl


def _entry(step: str = "call", **fields: Any) -> dict[str, Any]:
    return make_call_log_entry(stage="stage", step=step, model="m", **fields)


def _file_entries(run_dir: Path) -> list[dict[str, Any]]:
    return read_calls_jsonl(run_dir)


def test_a_session_owns_a_call_log(tmp_path: Path) -> None:
    with provider_call_session(record_dir=tmp_path) as session:
        assert isinstance(session.call_log, CallLog)
    assert ProviderCallSession(record_dir=tmp_path).call_log is not session.call_log


def test_appended_entries_are_recorded_as_the_file_holds_them(tmp_path: Path) -> None:
    log = CallLog()
    assert log.entries(tmp_path) is None

    append_call_log([_entry("a", slot_id="s"), {"tuple": (1, 2)}], tmp_path, log)

    assert log.entries(tmp_path) == _file_entries(tmp_path)
    assert log.entries(tmp_path)[1] == {"tuple": [1, 2]}


def test_an_empty_append_records_nothing(tmp_path: Path) -> None:
    log = CallLog()
    append_call_log([], tmp_path, log)
    assert log.entries(tmp_path) is None


def test_records_are_kept_per_run_directory(tmp_path: Path) -> None:
    log = CallLog()
    append_call_log([_entry("a")], tmp_path / "one", log)
    append_call_log([_entry("b")], tmp_path / "two", log)

    assert [e["step"] for e in log.entries(tmp_path / "one")] == ["a"]
    assert [e["step"] for e in log.entries(tmp_path / "two")] == ["b"]


def test_returned_entries_are_copies(tmp_path: Path) -> None:
    log = CallLog()
    append_call_log([_entry("a")], tmp_path, log)

    log.entries(tmp_path)[0]["step"] = "changed"
    log.entries(tmp_path).append({})

    assert [e["step"] for e in log.entries(tmp_path)] == ["a"]


def test_publishing_updates_the_records_and_the_file(tmp_path: Path) -> None:
    log = CallLog()
    entries = [_entry(), _entry(), _entry("other")]
    for entry in entries:
        entry["semantic_validation_passed"] = True
    append_call_log(entries, tmp_path, log)

    mark_call_published(tmp_path, "stage", "call", log)

    recorded = log.entries(tmp_path)
    assert [e["published"] for e in recorded] == [False, True, False]
    assert recorded == _file_entries(tmp_path)


def test_publishing_reads_the_records_not_the_file(tmp_path: Path) -> None:
    log = CallLog()
    entry = _entry()
    entry["semantic_validation_passed"] = True
    append_call_log([entry], tmp_path, log)
    (tmp_path / "calls.jsonl").write_text("not json\n", encoding="utf-8")

    mark_call_published(tmp_path, "stage", "call", log)

    assert log.entries(tmp_path)[0]["published"] is True
    assert _file_entries(tmp_path)[0]["published"] is True


def test_publishing_rejects_a_missing_or_unvalidated_call(tmp_path: Path) -> None:
    log = CallLog()
    with pytest.raises(ValueError, match="missing call log"):
        mark_call_published(tmp_path, "stage", "call", log)
    append_call_log(
        [_entry(success=False, semantic_validation_passed=False)], tmp_path, log
    )
    with pytest.raises(ValueError, match="without semantic validation"):
        mark_call_published(tmp_path, "stage", "call", log)


def test_call_log_of_reads_a_clients_session(tmp_path: Path) -> None:
    session = ProviderCallSession(record_dir=tmp_path)

    assert call_log_of(SimpleNamespace(session=session)) is session.call_log
    assert call_log_of(SimpleNamespace()) is None
    assert call_log_of(SimpleNamespace(session=None)) is None
    assert call_log_of(MagicMock()) is None


class _Payload(BaseModel):
    value: int


class _SessionClient:
    model = "offline-test-model"

    def __init__(self, session: ProviderCallSession, fail: bool = False) -> None:
        self.session = session
        self.fail = fail

    def complete(self, **_: Any) -> LLMResult:
        if self.fail:
            raise RuntimeError("provider unavailable")
        return LLMResult(
            content='{"value": 3}', prompt_tokens=11, completion_tokens=7, duration_ms=3
        )


def _call(client: _SessionClient, run_dir: Path) -> Any:
    return call_with_policy(
        llm_client=client,
        system_prompt="system",
        user_prompt="user",
        response_format=_Payload,
        run_dir=run_dir,
        stage="stage",
        step="step",
        policy=CorrectionPolicy(),
    )


def test_a_call_through_a_session_client_is_recorded_in_the_session(
    tmp_path: Path,
) -> None:
    session = ProviderCallSession(record_dir=tmp_path)

    _call(_SessionClient(session), tmp_path)

    recorded = session.call_log.entries(tmp_path)
    assert [e["step"] for e in recorded] == ["step"]
    assert recorded == _file_entries(tmp_path)


def test_a_failed_call_through_a_session_client_is_recorded_in_the_session(
    tmp_path: Path,
) -> None:
    session = ProviderCallSession(record_dir=tmp_path)

    _call(_SessionClient(session, fail=True), tmp_path)

    recorded = session.call_log.entries(tmp_path)
    assert recorded and all(e["success"] is False for e in recorded)
    assert recorded == _file_entries(tmp_path)


def test_a_logged_failure_goes_to_the_log_it_is_given(tmp_path: Path) -> None:
    log = CallLog()

    log_llm_call_failure("m", tmp_path, "stage", "step", "boom", call_log=log)

    assert log.entries(tmp_path) == _file_entries(tmp_path)


def test_a_client_without_a_session_writes_only_the_file(tmp_path: Path) -> None:
    _call(_SessionClient(None), tmp_path)

    assert _file_entries(tmp_path)
