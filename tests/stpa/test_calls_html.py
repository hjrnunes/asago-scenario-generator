"""Tests for the calls.jsonl log entries and their HTML report."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from asago_scenario_generator.stpa.infra.call_log import make_call_log_entry
from asago_scenario_generator.stpa.infra.calls_html import (
    _build_call_entry_html,
    _build_detail_html,
    _build_entry_cells,
    _compute_summary,
    _read_calls,
    render_calls_html,
)
from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.infra.llm_helpers import (
    log_llm_call,
    log_llm_call_failure,
)
from tests.helpers.calls_html import _write_calls_jsonl


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _default_entries() -> list[dict]:
    """Four entries: three successes and one timeout failure."""
    return [
        {
            "stage": "stage_1a",
            "step": "call_1a_losses",
            "model": "gemma-4-26b-a4b-it",
            "prompt_tokens": 4500,
            "completion_tokens": 1200,
            "duration_ms": 8500,
            "timestamp": "2026-08-08T12:00:00Z",
            "success": True,
        },
        {
            "stage": "stage_1b",
            "step": "call_1b_profile",
            "model": "gemma-4-26b-a4b-it",
            "prompt_tokens": 3200,
            "completion_tokens": 800,
            "duration_ms": 4200,
            "timestamp": "2026-08-08T12:01:00Z",
            "success": True,
        },
        {
            "stage": "stage_2",
            "step": "call_2a_responsibilities",
            "model": "gemma-4-26b-a4b-it",
            "prompt_tokens": 5100,
            "completion_tokens": 1500,
            "duration_ms": 9800,
            "timestamp": "2026-08-08T12:02:00Z",
            "success": True,
        },
        {
            "stage": "stage_2",
            "step": "call_2_requirements",
            "model": "gemma-4-26b-a4b-it",
            "prompt_tokens": 4800,
            "completion_tokens": 1300,
            "duration_ms": 7600,
            "timestamp": "2026-08-08T12:03:00Z",
            "success": False,
            "error": "timeout exceeded",
        },
    ]


def _basic_entry(**overrides) -> dict:
    entry = {
        "stage": "stage_2",
        "step": "call_1",
        "model": "test-model",
        "prompt_tokens": 100,
        "completion_tokens": 50,
        "duration_ms": 5000,
        "timestamp": "2026-08-08T12:00:00Z",
        "success": True,
        "system_prompt_hash": "abc123",
        "user_prompt_hash": "def456",
    }
    entry.update(overrides)
    return entry


def _render(tmp_path: Path, entries: list[dict] | None = None) -> str:
    """Render the entries (the default four when None) and return the HTML."""
    if entries is None:
        entries = _default_entries()
    calls_path = _write_calls_jsonl(tmp_path / "calls.jsonl", entries)
    output_path = tmp_path / "calls.html"
    render_calls_html(calls_path, output_path)
    return output_path.read_text(encoding="utf-8")


class TestCallLogEntries:
    """The call log stores the full prompt and response text."""

    @pytest.mark.parametrize(
        "field_name, field_value",
        [
            ("system_prompt_text", "You are a safety engineer"),
            ("user_prompt_text", "Analyze this system"),
            ("response_content", '{"gap_type": "missing_responsibility"}'),
        ],
    )
    def test_entry_contains_field(self, field_name, field_value):
        entry = make_call_log_entry(
            stage="stage_2",
            step="call_1",
            model="test-model",
            system_prompt="You are a safety engineer",
            user_prompt="Analyze this system",
            response_content='{"gap_type": "missing_responsibility"}',
        )
        assert entry[field_name] == field_value

    def test_log_llm_call_stores_full_content(self, tmp_path):
        result = LLMResult(
            content='{"result": true}',
            prompt_tokens=100,
            completion_tokens=50,
            duration_ms=5000,
            system_prompt="System instructions",
            user_prompt="User task",
        )
        log_llm_call(result, "test-model", tmp_path, "stage_2", "call_1")
        entries = _read_jsonl(tmp_path / "calls.jsonl")
        assert len(entries) == 1
        assert entries[0]["system_prompt_text"] == "System instructions"
        assert entries[0]["user_prompt_text"] == "User task"
        assert "result" in entries[0]["response_content"]

    def test_log_llm_call_failure_stores_prompts(self, tmp_path):
        log_llm_call_failure(
            "test-model",
            tmp_path,
            "stage_2",
            "call_1",
            "timeout",
            system_prompt="System prompt",
            user_prompt="User prompt",
        )
        entries = _read_jsonl(tmp_path / "calls.jsonl")
        assert len(entries) == 1
        assert entries[0]["system_prompt_text"] == "System prompt"
        assert entries[0]["user_prompt_text"] == "User prompt"


class TestReadCalls:
    @pytest.mark.parametrize(
        "content, expected_count",
        [
            (None, 0),
            (b"", 0),
            (b"\n", 0),
            # A one-byte file with JSON content is parsed, not skipped.
            (b"1", 1),
        ],
        ids=["missing", "empty", "newline", "single-byte-json"],
    )
    def test_file_content_decides_the_entry_count(
        self, tmp_path, content, expected_count
    ):
        calls_path = tmp_path / "calls.jsonl"
        if content is not None:
            calls_path.write_bytes(content)
        assert len(_read_calls(calls_path)) == expected_count


class TestRenderCallsHtml:
    def test_html_is_self_contained(self, tmp_path):
        calls_path = _write_calls_jsonl(tmp_path / "calls.jsonl", _default_entries())
        output_path = tmp_path / "calls.html"
        assert render_calls_html(calls_path, output_path) == output_path
        html = output_path.read_text(encoding="utf-8")
        assert "<style>" in html
        assert "<script>" in html
        assert 'rel="stylesheet"' not in html
        assert ".js" not in html or "src=" not in html

    def test_summary_table_shows_correct_totals(self, tmp_path):
        html = _render(tmp_path)
        for total in ("4", "3", "1", "17600", "4800", "30100"):
            assert total in html

    def test_detail_table_contains_all_entries(self, tmp_path):
        html = _render(tmp_path)
        for entry in _default_entries():
            assert entry["step"] in html
        assert html.count("gemma-4-26b-a4b-it") >= 4

    def test_failed_calls_are_marked_and_show_their_error(self, tmp_path):
        html = _render(tmp_path)
        assert "failed" in html.lower() or "error-row" in html.lower()
        assert "timeout exceeded" in html

    @pytest.mark.parametrize(
        "column",
        [
            "stage",
            "step",
            "model",
            "prompt_tokens",
            "completion_tokens",
            "duration_ms",
            "timestamp",
        ],
    )
    def test_detail_table_includes_expected_columns(self, tmp_path, column):
        assert column in _render(tmp_path)

    def test_empty_log_renders_zero_totals_and_no_detail_rows(self, tmp_path):
        html = _render(tmp_path, [])
        assert "<style>" in html
        assert "0" in html
        assert '<table class="detail">\n  </table>' in html
        assert "<thead>" not in html

    def test_only_successful_calls(self, tmp_path):
        entries = [
            _basic_entry(step="call_1a", prompt_tokens=1000, completion_tokens=500),
            _basic_entry(step="call_2", prompt_tokens=2000, completion_tokens=800),
        ]
        html = _render(tmp_path, entries)
        assert "2" in html
        assert "timeout" not in html

    def test_cli_invocation_renders_html(self, tmp_path):
        calls_path = _write_calls_jsonl(
            tmp_path / "cli_calls.jsonl", _default_entries()
        )
        output_path = tmp_path / "cli_output.html"
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "asago_scenario_generator.stpa.infra.calls_html",
                str(calls_path),
                str(output_path),
            ],
            capture_output=True,
            text=True,
            cwd=str(Path.cwd()),
        )
        assert result.returncode == 0, f"CLI failed: {result.stderr}"
        assert "<style>" in output_path.read_text(encoding="utf-8")

    def test_nested_output_path_is_created(self, tmp_path):
        calls_path = _write_calls_jsonl(tmp_path / "calls.jsonl", [_basic_entry()])
        nested_output = tmp_path / "subdir" / "deeper" / "calls.html"
        assert render_calls_html(calls_path, nested_output) == nested_output
        assert "<html" in nested_output.read_text(encoding="utf-8")

    def test_entry_without_content_fields_still_renders(self, tmp_path):
        html = _render(tmp_path, [_basic_entry()])
        assert "<style>" in html
        assert "1" in html

    def test_failed_entry_shows_error_in_its_call_entry_section(self, tmp_path):
        html = _render(
            tmp_path, [_basic_entry(success=False, error="Connection timeout")]
        )
        assert "FAILED" in html
        assert "Connection timeout" in html
        assert "call-entry failed" in html


class TestCollapsibleContent:
    @pytest.mark.parametrize(
        "field_name, text, shown_text, collapsible_name",
        [
            (
                "system_prompt_text",
                "You are a safety engineer",
                "You are a safety engineer",
                "system_prompt",
            ),
            (
                "user_prompt_text",
                "Analyze this system",
                "Analyze this system",
                "user_prompt",
            ),
            (
                "response_content",
                '{"gap_type": "missing_responsibility"}',
                "gap_type",
                "response_content",
            ),
        ],
    )
    def test_content_is_shown_in_a_collapsible_section(
        self, tmp_path, field_name, text, shown_text, collapsible_name
    ):
        html = _render(tmp_path, [_basic_entry(**{field_name: text})])
        assert shown_text in html
        assert collapsible_name in html
        assert "<details" in html

    def test_json_response_is_pretty_printed_in_a_pre_block(self, tmp_path):
        html = _render(
            tmp_path,
            [
                _basic_entry(
                    response_content='{"gap_type":"missing_responsibility","description":"test"}'
                )
            ],
        )
        assert "gap_type" in html
        assert "<pre" in html

    def test_plain_text_response_is_shown_in_a_pre_block(self, tmp_path):
        text = "This is a plain text response without JSON structure."
        html = _render(tmp_path, [_basic_entry(response_content=text)])
        assert "<pre" in html
        assert text in html

    def test_html_includes_a_search_filter(self, tmp_path):
        html = _render(
            tmp_path, [_basic_entry(stage="stage_1a"), _basic_entry(stage="stage_2")]
        )
        assert "<input" in html
        assert "<script" in html


class TestComputeSummary:
    def test_counts_success_failure_and_totals(self):
        entries = [
            {
                "success": True,
                "prompt_tokens": 2,
                "completion_tokens": 3,
                "duration_ms": 5,
            },
            {
                "success": False,
                "prompt_tokens": 7,
                "completion_tokens": 11,
                "duration_ms": 13,
            },
        ]
        assert _compute_summary(entries) == {
            "total_calls": 2,
            "success_count": 1,
            "failure_count": 1,
            "provider_response_count": 0,
            "semantic_validation_count": 0,
            "published_count": 0,
            "total_prompt_tokens": 9,
            "total_completion_tokens": 14,
            "total_duration_ms": 18,
        }

    def test_omitted_success_and_metrics_default_to_successful_zeroes(self):
        assert _compute_summary([{}]) == {
            "total_calls": 1,
            "success_count": 1,
            "failure_count": 0,
            "provider_response_count": 0,
            "semantic_validation_count": 0,
            "published_count": 0,
            "total_prompt_tokens": 0,
            "total_completion_tokens": 0,
            "total_duration_ms": 0,
        }

    def test_lifecycle_status_distinguishes_received_rejected_and_published(self):
        entries = [
            {
                "success": False,
                "provider_response_received": True,
                "draft_parsed": False,
                "semantic_validation_passed": False,
                "published": False,
                "terminal_error_codes": ["provider_contract_failure"],
            },
            {
                "success": True,
                "provider_response_received": True,
                "draft_parsed": True,
                "semantic_validation_passed": True,
                "published": True,
            },
        ]

        summary = _compute_summary(entries)
        assert summary["provider_response_count"] == 2
        assert summary["semantic_validation_count"] == 1
        assert summary["published_count"] == 1
        html = _build_detail_html(entries)
        assert "RESPONSE REJECTED" in html
        assert "PUBLISHED" in html


class TestEntryDefaults:
    def test_omitted_success_renders_an_ok_status_cell(self):
        for entry in ({"success": True}, {}):
            cells = _build_entry_cells(entry)
            assert cells[-1] == "<td>OK</td>"
            assert len(cells) == 8
            assert "FAILED" not in "".join(cells)
        assert 'class="failed"' not in _build_detail_html([{}])

    def test_call_entry_without_success_is_not_marked_failed(self):
        html = _build_call_entry_html(
            {
                "stage": "stage_2",
                "step": "call_1",
                "model": "test-model",
                "prompt_tokens": 100,
                "completion_tokens": 50,
            }
        )
        assert "failed" not in html
        assert "FAILED" not in html

    @pytest.mark.parametrize(
        "tokens, expected",
        [
            ({}, "tokens=0+0"),
            ({"prompt_tokens": 50}, "tokens=50+0"),
            ({"completion_tokens": 50}, "tokens=0+50"),
        ],
    )
    def test_call_entry_defaults_omitted_token_counts_to_zero(self, tokens, expected):
        entry = {"stage": "stage_2", "step": "call_1", "model": "m", "success": True}
        assert expected in _build_call_entry_html({**entry, **tokens})
