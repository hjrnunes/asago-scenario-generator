"""Tests for calls.jsonl HTML rendering (CH-01 through CH-12)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from asago_scenario_generator.stpa.infra.calls_html import (
    _build_entry_cells,
    _build_detail_html,
    _compute_summary,
    _read_calls,
    render_calls_html,
)


def _write_calls_jsonl(path: Path, entries: list[dict]) -> Path:
    """Write a JSONL file with the given entries."""
    with path.open("w", encoding="utf-8") as fh:
        for entry in entries:
            fh.write(json.dumps(entry) + "\n")
    return path


def _default_entries() -> list[dict]:
    """The 4 entries from the Background table."""
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


def _render(tmp_path: Path, entries: list[dict] | None = None) -> tuple[str, Path]:
    """Render calls to HTML and return (html_content, output_path)."""
    if entries is None:
        entries = _default_entries()
    calls_path = _write_calls_jsonl(tmp_path / "calls.jsonl", entries)
    output_path = tmp_path / "calls.html"
    result = render_calls_html(calls_path, output_path)
    html = output_path.read_text(encoding="utf-8")
    return html, result


class TestRenderCallsHtml:
    """CH-01 through CH-12 — render_calls_html function."""

    def test_ch01_produces_self_contained_html(self, tmp_path):
        """CH-01: HTML file produced with inline CSS, no external stylesheet."""
        html, output_path = _render(tmp_path)
        assert output_path.exists()
        assert "<style>" in html
        assert ".css" not in html or 'rel="stylesheet"' not in html

    def test_ch02_summary_table_shows_correct_totals(self, tmp_path):
        """CH-02: summary shows correct totals."""
        html, _ = _render(tmp_path)
        assert "4" in html  # total calls
        assert "3" in html  # success count
        assert "1" in html  # failure count
        assert "17600" in html  # total prompt tokens
        assert "4800" in html  # total completion tokens
        assert "30100" in html  # total duration

    def test_ch03_detail_table_contains_all_entries(self, tmp_path):
        """CH-03: detail table contains all call entries."""
        html, _ = _render(tmp_path)
        assert "call_1a_losses" in html
        assert "call_1b_profile" in html
        assert "call_2a_responsibilities" in html
        assert "call_2_requirements" in html

    def test_ch04_failed_calls_highlighted_in_red(self, tmp_path):
        """CH-04: failed calls have a failure indicator, successful calls don't."""
        html, _ = _render(tmp_path)
        # The failed row should have a failure class or indicator
        assert "call_2_requirements" in html
        # Check for a failure-related CSS class or style near the failed row
        assert (
            "failed" in html.lower()
            or "error-row" in html.lower()
            or "failure" in html.lower()
        )

    def test_ch05_error_messages_displayed_for_failed_calls(self, tmp_path):
        """CH-05: error messages are displayed for failed calls."""
        html, _ = _render(tmp_path)
        assert "timeout exceeded" in html

    @pytest.mark.parametrize(
        "column",
        [
            "model",
            "prompt_tokens",
            "completion_tokens",
            "duration_ms",
            "timestamp",
        ],
    )
    def test_ch06_detail_table_includes_expected_columns(self, tmp_path, column):
        """CH-06: detail table includes expected columns."""
        html, _ = _render(tmp_path)
        assert column in html

    def test_ch07_empty_calls_jsonl_produces_valid_html_with_zero_totals(
        self, tmp_path
    ):
        """CH-07: rendering an empty calls.jsonl produces valid HTML with zero totals."""
        calls_path = _write_calls_jsonl(tmp_path / "empty.jsonl", [])
        output_path = tmp_path / "empty.html"
        render_calls_html(calls_path, output_path)
        html = output_path.read_text(encoding="utf-8")
        assert "<style>" in html
        assert "0" in html  # total calls = 0

    def test_ch08_only_successful_calls(self, tmp_path):
        """CH-08: rendering only successful calls shows zero failures."""
        entries = [
            {
                "stage": "stage_1a",
                "step": "call_1a",
                "model": "model-a",
                "prompt_tokens": 1000,
                "completion_tokens": 500,
                "duration_ms": 3000,
                "timestamp": "2026-08-08T12:00:00Z",
                "success": True,
            },
            {
                "stage": "stage_2",
                "step": "call_2",
                "model": "model-a",
                "prompt_tokens": 2000,
                "completion_tokens": 800,
                "duration_ms": 5000,
                "timestamp": "2026-08-08T12:01:00Z",
                "success": True,
            },
        ]
        html, _ = _render(tmp_path, entries)
        # success count 2, failure count 0
        assert "2" in html
        # No failure indicator
        assert "timeout" not in html

    def test_ch09_cli_invocation_renders_html(self, tmp_path):
        """CH-09: CLI invocation renders calls.jsonl to HTML."""
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
        assert output_path.exists()
        html = output_path.read_text(encoding="utf-8")
        assert "<style>" in html

    def test_ch10_render_returns_output_path(self, tmp_path):
        """CH-10: render_calls_html returns the output path."""
        calls_path = _write_calls_jsonl(tmp_path / "calls.jsonl", _default_entries())
        output_path = tmp_path / "output.html"
        result = render_calls_html(calls_path, output_path)
        assert result == output_path

    def test_ch12_all_calls_have_same_model_in_detail_table(self, tmp_path):
        """CH-12: all calls have the same model shown in detail table."""
        html, _ = _render(tmp_path)
        # Count occurrences of the model name — should be in all 4 rows
        count = html.count("gemma-4-26b-a4b-it")
        assert count >= 4

    def test_missing_calls_file_is_treated_as_empty(self, tmp_path):
        """A missing calls log produces the same empty input as an empty file."""
        assert _read_calls(tmp_path / "missing.jsonl") == []

    def test_summary_counts_success_failure_and_totals(self):
        """Summary arithmetic preserves counts and token/duration totals."""
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

    def test_summary_defaults_missing_success_and_metrics(self):
        """Summary treats omitted success and metrics as successful zeroes."""
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
        """The report does not call every returned provider response a success."""
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

    def test_success_entry_uses_status_cell_and_default_values(self):
        """Successful rows render the status column as OK."""
        cells = _build_entry_cells({"success": True})
        assert cells[-1] == "<td>OK</td>"
        assert len(cells) == 8
        assert "FAILED" not in "".join(cells)

    def test_omitted_success_defaults_to_ok_in_detail_cells(self):
        """Detail cells use the successful default when success is omitted."""
        assert _build_entry_cells({})[-1] == "<td>OK</td>"

    def test_success_detail_row_has_no_failure_class(self):
        """Successful detail rows are not marked as failed."""
        html = _build_detail_html([{}])
        assert 'class="failed"' not in html

    def test_empty_render_omits_detail_headers(self, tmp_path):
        """An empty log has no fabricated detail rows or headers."""
        html, _ = _render(tmp_path, [])
        assert '<table class="detail">\n  </table>' in html
        assert "<thead>" not in html
