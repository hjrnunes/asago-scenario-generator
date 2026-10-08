"""One stage-local parser hook: it receives the call's cleanup-transformation list."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.infra.llm_helpers import (
    CorrectionPolicy,
    call_with_policy,
    decode_content,
)
from tests.helpers.calls_log import read_calls_jsonl
from tests.helpers.provider_call_record import _Answer, _answer, _client, _Provider

SRC = Path(__file__).resolve().parents[2] / "src"
RETIRED_KEYWORDS = {"result_parser", "result_parser_with_cleanup"}


def _call(tmp_path: Path, parser: Any) -> Any:
    return call_with_policy(
        llm_client=_client(_Provider(_answer)),
        system_prompt="s",
        user_prompt="u",
        response_format=_Answer,
        run_dir=tmp_path,
        stage="stage_x",
        step="call_answer",
        policy=CorrectionPolicy(),
        response_parser=parser,
    )


def test_the_parser_records_a_correction_in_the_call_log(tmp_path: Path) -> None:
    def parse(result: LLMResult, cleanup: list[dict[str, Any]]) -> _Answer:
        cleanup.append({"kind": "test_correction"})
        return _Answer.model_validate(decode_content(result))

    outcome = _call(tmp_path, parse)

    assert outcome.value == _Answer(answer="42")
    [entry] = read_calls_jsonl(tmp_path)
    assert entry["cleanup_transformations"] == [{"kind": "test_correction"}]


def test_a_parser_that_ignores_the_list_publishes_its_model(tmp_path: Path) -> None:
    outcome = _call(tmp_path, lambda result, _cleanup: _Answer(answer="parsed"))

    assert outcome.value == _Answer(answer="parsed")
    [entry] = read_calls_jsonl(tmp_path)
    assert entry["cleanup_transformations"] == []


def test_a_failing_parser_is_an_answered_schema_failure(tmp_path: Path) -> None:
    def parse(result: LLMResult, cleanup: list[dict[str, Any]]) -> _Answer:
        raise ValueError("stage-local contract violated")

    outcome = _call(tmp_path, parse)

    assert outcome.value is None
    [entry] = read_calls_jsonl(tmp_path)
    assert entry["failure_class"] == "answered_schema_failure"


def test_no_source_call_passes_a_retired_parser_keyword() -> None:
    found = [
        f"{path.relative_to(SRC)}:{node.lineno} {keyword.arg}"
        for path in sorted(SRC.rglob("*.py"))
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
        if isinstance(node, ast.Call)
        for keyword in node.keywords
        if keyword.arg in RETIRED_KEYWORDS
    ]
    assert found == []
