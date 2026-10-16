"""JSONL readers keep a record whole when its text holds a Unicode line separator.

``json.dumps(..., ensure_ascii=False)`` leaves U+0085, U+2028 and U+2029 raw,
and ``str.splitlines()`` splits on them, so a reader that uses it cuts one
record into fragments. Each test writes a record through the real writer and
reads it back through the reader under test.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from asago_scenario_generator.report.run_data import _read_calls
from asago_scenario_generator.stpa.infra.call_log import (
    append_call_log,
    jsonl_lines,
    make_call_log_entry,
    mark_call_published,
)
from asago_scenario_generator.stpa.infra.llm_helpers import (
    CorrectionPolicy,
    call_with_policy,
)
from asago_scenario_generator.stpa.infra.manifest_helpers import count_calls_by_stage
from asago_scenario_generator.stpa.infra.provider_record import (
    RECORD_FILENAME,
    provider_call_session,
)
from tests.helpers.calls_log import read_calls_jsonl
from tests.helpers.provider_call_record import (
    _Answer,
    _client,
    _completion,
    _Provider,
)

SEPARATORS = "\u0085\u2028\u2029"
TEXT = f"before{SEPARATORS}after"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("", []),
        ("\n\n", []),
        ('{"a": 1}\n{"b": 2}\n', ['{"a": 1}', '{"b": 2}']),
        ('{"a": 1}\n\n  \n{"b": 2}', ['{"a": 1}', '{"b": 2}']),
        ('{"a": 1}\r\n{"b": 2}\r\n', ['{"a": 1}\r', '{"b": 2}\r']),
        (f'{{"a": "x{SEPARATORS}y"}}\n', [f'{{"a": "x{SEPARATORS}y"}}']),
        ("a\x0bb\x0cc\x1cd\n", ["a\x0bb\x0cc\x1cd"]),
    ],
    ids=[
        "empty",
        "only-newlines",
        "two-records",
        "blank-lines",
        "crlf-kept-for-json",
        "unicode-separators",
        "other-splitlines-characters",
    ],
)
def test_jsonl_lines_splits_on_newline_only(text: str, expected: list[str]) -> None:
    assert jsonl_lines(text) == expected


def _entry(step: str, *, validated: bool = False) -> dict:
    return make_call_log_entry(
        stage="stage_x",
        step=step,
        model="m",
        user_prompt=TEXT,
        response_content=TEXT,
        prompt_tokens=3,
        completion_tokens=4,
        semantic_validation_passed=validated or None,
    )


def _write_log(run_dir: Path, *entries: dict) -> None:
    append_call_log(list(entries), run_dir)
    assert len(run_dir.joinpath("calls.jsonl").read_text("utf-8").split("\n")) == (
        len(entries) + 1
    )


def test_the_helper_reader_returns_each_record_intact(tmp_path: Path) -> None:
    _write_log(tmp_path, _entry("a"), _entry("b"))

    entries = read_calls_jsonl(tmp_path)

    assert [e["step"] for e in entries] == ["a", "b"]
    assert all(e["user_prompt_text"] == TEXT for e in entries)


def test_publishing_a_call_keeps_every_record(tmp_path: Path) -> None:
    _write_log(tmp_path, _entry("a"), _entry("b", validated=True))

    mark_call_published(tmp_path, "stage_x", "b")

    lines = (tmp_path / "calls.jsonl").read_text(encoding="utf-8").split("\n")
    entries = [json.loads(line) for line in lines if line]
    assert [e["step"] for e in entries] == ["a", "b"]
    assert [e["published"] for e in entries] == [False, True]
    assert entries[0]["response_content"] == TEXT


def test_counting_calls_by_stage_reads_every_record(tmp_path: Path) -> None:
    _write_log(tmp_path, _entry("a"), _entry("b"))

    assert count_calls_by_stage(tmp_path) == {
        "stage_x": {"call_count": 2, "total_tokens": 14}
    }


def test_the_report_reads_every_call(tmp_path: Path) -> None:
    _write_log(tmp_path, _entry("a"), _entry("b"))

    calls = _read_calls(tmp_path)

    assert [(c.n, c.step, c.response_content) for c in calls] == [
        (1, "a", TEXT),
        (2, "b", TEXT),
    ]


def test_replay_loads_a_record_that_holds_separators(tmp_path: Path) -> None:
    recorded = tmp_path / "recorded"
    provider = _Provider(lambda **_: _completion(json.dumps({"answer": TEXT})))

    def ask(session, run_dir: Path):
        return call_with_policy(
            llm_client=_client(provider, session=session),
            system_prompt="You answer.",
            user_prompt=f"Question{SEPARATORS}?",
            response_format=_Answer,
            run_dir=run_dir,
            stage="stage_x",
            step="call_answer",
            policy=CorrectionPolicy(),
        )

    with provider_call_session(record_dir=recorded) as session:
        assert ask(session, tmp_path / "first").value == _Answer(answer=TEXT)
    text = (recorded / RECORD_FILENAME).read_text(encoding="utf-8")
    assert len(text.split("\n")) == 2

    with provider_call_session(record_dir=None, replay_dir=recorded) as session:
        replayed = ask(session, tmp_path / "second")

    assert replayed.value == _Answer(answer=TEXT)
