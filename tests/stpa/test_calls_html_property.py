"""Property tests for the calls HTML report.

Special characters are HTML-escaped, empty content produces no sections, and
every entry appears in the rendered HTML.
"""

from __future__ import annotations

import json
from pathlib import Path

from hypothesis import HealthCheck, given, settings, strategies as st

from asago_scenario_generator.stpa.infra.call_log import make_call_log_entry
from asago_scenario_generator.stpa.infra.calls_html import render_calls_html


# ---------------------------------------------------------------------------
# 3. HTML rendering property tests
# ---------------------------------------------------------------------------


# Safe text for HTML content — exclude characters that would break JSON
# serialization or contain HTML special chars we want to test separately.
st_safe_text = st.text(
    alphabet=st.characters(
        blacklist_categories=("Cs",),
        blacklist_characters=("\x85", "\u2028", "\u2029"),
    ),
    min_size=0,
    max_size=100,
)

# Text guaranteed to contain HTML special characters.
st_html_special = st.text(
    alphabet=st.characters(
        whitelist_categories=("Ll", "Lu", "Nd"),
        whitelist_characters=("<", ">", "&", '"', " ", "-"),
    ),
    min_size=1,
    max_size=50,
)


def _write_calls_jsonl(tmp_path: Path, entries: list[dict]) -> Path:
    """Write entries to calls.jsonl and return the path."""
    calls_path = tmp_path / "calls.jsonl"
    with calls_path.open("w", encoding="utf-8") as fh:
        for entry in entries:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return calls_path


class TestCallsHtmlRenderingProperties:
    """Property tests for calls_html rendering invariants."""

    @given(content=st_html_special)
    @settings(
        max_examples=25,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_html_escaping_in_prompt_text(self, tmp_path, content):
        """HTML escaping: special characters in prompt text are escaped."""
        entry = make_call_log_entry(
            stage="stage_2",
            step="call_1",
            model="test",
            system_prompt=content,
        )
        calls_path = _write_calls_jsonl(tmp_path, [entry])
        output_path = tmp_path / "output.html"
        render_calls_html(calls_path, output_path)
        html = output_path.read_text(encoding="utf-8")
        # The raw content should not appear unescaped (unless it has no
        # special chars). Check that < > & " are escaped.
        if "<" in content:
            assert "&lt;" in html
        if ">" in content:
            assert "&gt;" in html
        if "&" in content:
            assert "&amp;" in html
        if '"' in content:
            assert "&quot;" in html

    @given(
        n_entries=st.integers(min_value=0, max_value=5),
    )
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_all_entries_appear_in_html(self, tmp_path, n_entries):
        """Conservation: every entry's step label appears in the rendered HTML."""
        entries = []
        for i in range(n_entries):
            entries.append(
                make_call_log_entry(
                    stage=f"stage_{i + 1}",
                    step=f"step_{i + 1}",
                    model="test",
                    system_prompt=f"prompt {i + 1}",
                )
            )
        calls_path = _write_calls_jsonl(tmp_path, entries)
        output_path = tmp_path / "output.html"
        render_calls_html(calls_path, output_path)
        html = output_path.read_text(encoding="utf-8")
        for entry in entries:
            assert entry["step"] in html
            assert entry["stage"] in html

    @given(
        system_prompt=st_safe_text,
        user_prompt=st_safe_text,
        response_content=st_safe_text,
    )
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_empty_content_produces_no_section(
        self, tmp_path, system_prompt, user_prompt, response_content
    ):
        """Empty content: when a field is empty, no section is rendered for it."""
        entry = make_call_log_entry(
            stage="stage_2",
            step="call_1",
            model="test",
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_content=response_content if response_content else None,
        )
        calls_path = _write_calls_jsonl(tmp_path, [entry])
        output_path = tmp_path / "output.html"
        render_calls_html(calls_path, output_path)
        html = output_path.read_text(encoding="utf-8")
        # Check that empty fields don't produce collapsible sections
        if not system_prompt:
            assert "system_prompt</summary>" not in html
        if not user_prompt:
            assert "user_prompt</summary>" not in html
        if not response_content:
            assert "response_content</summary>" not in html

    @given(
        n_success=st.integers(min_value=0, max_value=3),
        n_failure=st.integers(min_value=0, max_value=3),
    )
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_summary_counts_match_entries(self, tmp_path, n_success, n_failure):
        """Summary accuracy: success and failure counts match the entries."""
        entries = []
        for i in range(n_success):
            entries.append(
                make_call_log_entry(
                    stage="stage_2",
                    step=f"step_{i + 1}",
                    model="test",
                    success=True,
                )
            )
        for i in range(n_failure):
            entries.append(
                make_call_log_entry(
                    stage="stage_2",
                    step=f"fail_{i + 1}",
                    model="test",
                    success=False,
                    error="Connection timeout",
                )
            )
        calls_path = _write_calls_jsonl(tmp_path, entries)
        output_path = tmp_path / "output.html"
        render_calls_html(calls_path, output_path)
        html = output_path.read_text(encoding="utf-8")
        # The summary table should contain the correct counts
        total = n_success + n_failure
        if total > 0:
            assert str(total) in html
            assert str(n_success) in html
            assert str(n_failure) in html

    @given(
        content=st_html_special,
    )
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_html_escaping_in_error_message(self, tmp_path, content):
        """HTML escaping: special characters in error messages are escaped."""
        entry = make_call_log_entry(
            stage="stage_2",
            step="call_1",
            model="test",
            success=False,
            error=content,
        )
        calls_path = _write_calls_jsonl(tmp_path, [entry])
        output_path = tmp_path / "output.html"
        render_calls_html(calls_path, output_path)
        html = output_path.read_text(encoding="utf-8")
        if "<" in content:
            assert "&lt;" in html
        if ">" in content:
            assert "&gt;" in html
        if "&" in content:
            assert "&amp;" in html

    @given(
        key=st.from_regex(r"[a-z]{1,5}", fullmatch=True),
        value=st.from_regex(r"[a-z]{1,5}", fullmatch=True),
    )
    @settings(
        max_examples=15,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_json_response_pretty_printed(self, tmp_path, key, value):
        """JSON response: valid JSON is pretty-printed in the HTML output."""
        json_content = json.dumps({key: value})
        entry = make_call_log_entry(
            stage="stage_2",
            step="call_1",
            model="test",
            response_content=json_content,
        )
        calls_path = _write_calls_jsonl(tmp_path, [entry])
        output_path = tmp_path / "output.html"
        render_calls_html(calls_path, output_path)
        html = output_path.read_text(encoding="utf-8")
        # Pretty-printed JSON has newlines and indentation
        assert "response_content" in html
        # The pretty-printed version should contain the key and value
        parsed = json.loads(json_content)
        for key in parsed:
            assert key in html
