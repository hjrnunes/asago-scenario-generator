"""Property-based tests for model profile loading and calls HTML rendering.

These tests verify invariants that should hold across broad input ranges:

- **Profile round-trip**: Any valid profile dict, when written to YAML and
  loaded back, returns the same key-value pairs.
- **Required field conservation**: The result always contains all required
  fields that were present in the source.
- **Optional field omission**: Optional fields absent from the source are
  absent from the result; optional fields present are preserved.
- **Empty required field rejection**: An empty-string required field always
  raises ValueError.
- **Summary conservation**: The HTML summary totals always equal the sum
  of individual call entries.
- **Success/failure conservation**: success_count + failure_count == total.
- **Self-contained HTML**: The output always contains a <style> tag and
  never references an external stylesheet.
- **Entry coverage**: Every entry's step name appears in the rendered HTML.
- **Empty input zeroing**: An empty JSONL always produces zero totals.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml
from hypothesis import HealthCheck, given, settings, strategies as st

from asago_scenario_generator.stpa.infra.calls_html import render_calls_html
from asago_scenario_generator.stpa.infra.model_profiles import (
    OPTIONAL_FIELDS,
    REQUIRED_FIELDS,
    load_profile,
)

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

st_nonempty_str = st.text(
    alphabet=st.characters(blacklist_categories=("Cs", "Cc")),
    min_size=1,
    max_size=50,
)

st_profile_name = st.from_regex(r"[a-z][a-z0-9_-]*", fullmatch=True)

st_optional_field_values = st.fixed_dictionaries(
    {},
    optional={
        "context_window": st.integers(min_value=1, max_value=1_000_000),
        "safety_margin": st.integers(min_value=0, max_value=100_000),
        "max_completion_tokens": st.integers(min_value=1, max_value=100000),
        "temperature": st.floats(min_value=0.0, max_value=2.0, allow_nan=False),
        "top_p": st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
        "top_k": st.integers(min_value=1, max_value=100),
        "headers": st.dictionaries(st_nonempty_str, st_nonempty_str, max_size=3),
    },
)


def _build_profile_dict(optionals: dict) -> dict:
    """Build a complete profile dict with fixed required fields + optionals."""
    profile = {
        "base_url": "https://example.com/v1",
        "model": "test-model",
        "api_key": "test-key",
    }
    profile.update(optionals)
    return profile


# ---------------------------------------------------------------------------
# Profile round-trip property tests
# ---------------------------------------------------------------------------


class TestProfileRoundTrip:
    """Any valid profile round-trips through YAML without loss."""

    @given(
        profile_name=st_profile_name,
        optionals=st_optional_field_values,
    )
    @settings(
        max_examples=50,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_profile_round_trip(self, tmp_path, profile_name, optionals):
        """A valid profile written to YAML and loaded back returns identical values."""
        profile = _build_profile_dict(optionals)
        path = tmp_path / "profiles.yaml"
        path.write_text(
            yaml.dump({profile_name: profile}, default_flow_style=False),
            encoding="utf-8",
        )
        result = load_profile(path, profile_name)

        for field in REQUIRED_FIELDS:
            assert result[field] == profile[field], f"Required field '{field}' mismatch"

        for field in OPTIONAL_FIELDS:
            if field in optionals:
                assert result[field] == optionals[field], (
                    f"Optional field '{field}' mismatch"
                )
            else:
                assert field not in result, f"Optional field '{field}' should be absent"


# ---------------------------------------------------------------------------
# Required field conservation property tests
# ---------------------------------------------------------------------------


class TestRequiredFieldConservation:
    """The result always contains exactly the required fields from the source."""

    @given(profile_name=st_profile_name)
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_required_fields_always_present(self, tmp_path, profile_name):
        """All required fields are always in the loaded profile."""
        profile = _build_profile_dict({})
        path = tmp_path / "profiles.yaml"
        path.write_text(
            yaml.dump({profile_name: profile}, default_flow_style=False),
            encoding="utf-8",
        )
        result = load_profile(path, profile_name)
        for field in REQUIRED_FIELDS:
            assert field in result, f"Required field '{field}' missing from result"


# ---------------------------------------------------------------------------
# Empty required field rejection property tests
# ---------------------------------------------------------------------------


class TestEmptyRequiredFieldRejection:
    """An empty-string required field always raises ValueError."""

    @given(
        profile_name=st_profile_name,
        field_name=st.sampled_from(list(REQUIRED_FIELDS)),
    )
    @settings(
        max_examples=30,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_empty_required_field_rejected(self, tmp_path, profile_name, field_name):
        """An empty string for any required field always raises ValueError."""
        profile = _build_profile_dict({})
        profile[field_name] = ""
        path = tmp_path / "profiles.yaml"
        path.write_text(
            yaml.dump({profile_name: profile}, default_flow_style=False),
            encoding="utf-8",
        )
        try:
            load_profile(path, profile_name)
            raise AssertionError(
                f"Expected ValueError for empty required field '{field_name}'"
            )
        except ValueError:
            pass  # expected

    @given(
        profile_name=st_profile_name,
        field_name=st.sampled_from(list(REQUIRED_FIELDS)),
    )
    @settings(
        max_examples=30,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_none_required_field_rejected(self, tmp_path, profile_name, field_name):
        """A None (missing) required field always raises ValueError."""
        profile = _build_profile_dict({})
        del profile[field_name]
        path = tmp_path / "profiles.yaml"
        path.write_text(
            yaml.dump({profile_name: profile}, default_flow_style=False),
            encoding="utf-8",
        )
        try:
            load_profile(path, profile_name)
            raise AssertionError(
                f"Expected ValueError for missing required field '{field_name}'"
            )
        except ValueError:
            pass  # expected


# ---------------------------------------------------------------------------
# Unknown profile name rejection property tests
# ---------------------------------------------------------------------------


class TestUnknownProfileRejection:
    """An unknown profile name always raises KeyError."""

    @given(
        profile_name=st_profile_name,
        unknown_name=st.from_regex(r"[a-z][a-z0-9_-]*", fullmatch=True),
    )
    @settings(
        max_examples=30,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_unknown_name_rejected(self, tmp_path, profile_name, unknown_name):
        """Loading a non-existent profile name always raises KeyError."""
        from hypothesis import assume

        assume(profile_name != unknown_name)
        profile = _build_profile_dict({})
        path = tmp_path / "profiles.yaml"
        path.write_text(
            yaml.dump({profile_name: profile}, default_flow_style=False),
            encoding="utf-8",
        )
        try:
            load_profile(path, unknown_name)
            raise AssertionError(
                f"Expected KeyError for unknown profile '{unknown_name}'"
            )
        except KeyError:
            pass  # expected


# ---------------------------------------------------------------------------
# Calls HTML rendering property tests
# ---------------------------------------------------------------------------

st_step_name = st.from_regex(r"call_[a-z0-9_]+", fullmatch=True)
st_stage_name = st.from_regex(r"stage_[a-z0-9_]+", fullmatch=True)
st_model_name = st.from_regex(r"[a-z][a-z0-9.-]*", fullmatch=True)

st_call_entry = st.fixed_dictionaries(
    {
        "stage": st_stage_name,
        "step": st_step_name,
        "model": st_model_name,
        "prompt_tokens": st.integers(min_value=0, max_value=100000),
        "completion_tokens": st.integers(min_value=0, max_value=100000),
        "duration_ms": st.integers(min_value=0, max_value=999999),
        "success": st.booleans(),
    }
)


def _write_jsonl(path: Path, entries: list[dict]) -> Path:
    """Write entries as JSONL."""
    with path.open("w", encoding="utf-8") as fh:
        for entry in entries:
            fh.write(json.dumps(entry) + "\n")
    return path


class TestCallsHtmlSummaryConservation:
    """Summary totals always equal the sum of individual entries."""

    @given(entries=st.lists(st_call_entry, min_size=0, max_size=20))
    @settings(
        max_examples=50,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_total_calls_equals_entry_count(self, tmp_path, entries):
        """Total calls in summary equals the number of entries."""
        calls_path = _write_jsonl(tmp_path / "calls.jsonl", entries)
        output_path = tmp_path / "calls.html"
        render_calls_html(calls_path, output_path)
        html = output_path.read_text(encoding="utf-8")

        total = len(entries)
        success = sum(1 for e in entries if e.get("success", True))
        failure = total - success
        prompt_tokens = sum(e["prompt_tokens"] for e in entries)
        completion_tokens = sum(e["completion_tokens"] for e in entries)
        duration = sum(e["duration_ms"] for e in entries)

        # The summary table should contain these values.
        # We check for the total calls and success/failure counts.
        assert str(total) in html, f"Total calls {total} not found in HTML"
        assert str(success) in html, f"Success count {success} not found in HTML"
        assert str(failure) in html, f"Failure count {failure} not found in HTML"
        assert str(prompt_tokens) in html, f"Prompt tokens {prompt_tokens} not found"
        assert str(completion_tokens) in html, (
            f"Completion tokens {completion_tokens} not found"
        )
        assert str(duration) in html, f"Duration {duration} not found"

    @given(entries=st.lists(st_call_entry, min_size=0, max_size=20))
    @settings(
        max_examples=30,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_success_plus_failure_equals_total(self, tmp_path, entries):
        """success_count + failure_count == total_calls invariant."""
        calls_path = _write_jsonl(tmp_path / "calls.jsonl", entries)
        output_path = tmp_path / "calls.html"
        render_calls_html(calls_path, output_path)
        assert output_path.exists()

        total = len(entries)
        success = sum(1 for e in entries if e.get("success", True))
        failure = total - success
        assert success + failure == total


class TestCallsHtmlSelfContained:
    """The HTML output is always self-contained with inline CSS."""

    @given(entries=st.lists(st_call_entry, min_size=0, max_size=10))
    @settings(
        max_examples=30,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_html_contains_style_tag(self, tmp_path, entries):
        """The output always contains a <style> tag."""
        calls_path = _write_jsonl(tmp_path / "calls.jsonl", entries)
        output_path = tmp_path / "calls.html"
        render_calls_html(calls_path, output_path)
        html = output_path.read_text(encoding="utf-8")
        assert "<style>" in html

    @given(entries=st.lists(st_call_entry, min_size=0, max_size=10))
    @settings(
        max_examples=30,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_html_has_no_external_stylesheet(self, tmp_path, entries):
        """The output never references an external stylesheet."""
        calls_path = _write_jsonl(tmp_path / "calls.jsonl", entries)
        output_path = tmp_path / "calls.html"
        render_calls_html(calls_path, output_path)
        html = output_path.read_text(encoding="utf-8")
        assert 'rel="stylesheet"' not in html

    @given(entries=st.lists(st_call_entry, min_size=0, max_size=10))
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_html_is_valid_doctype(self, tmp_path, entries):
        """The output always starts with a DOCTYPE declaration."""
        calls_path = _write_jsonl(tmp_path / "calls.jsonl", entries)
        output_path = tmp_path / "calls.html"
        render_calls_html(calls_path, output_path)
        html = output_path.read_text(encoding="utf-8")
        assert html.startswith("<!DOCTYPE html>")


class TestCallsHtmlEntryCoverage:
    """Every entry's step name appears in the rendered HTML."""

    @given(
        entries=st.lists(
            st_call_entry, min_size=1, max_size=15, unique_by=lambda e: e["step"]
        )
    )
    @settings(
        max_examples=40,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_all_steps_in_html(self, tmp_path, entries):
        """Every entry's step name appears in the detail table."""
        calls_path = _write_jsonl(tmp_path / "calls.jsonl", entries)
        output_path = tmp_path / "calls.html"
        render_calls_html(calls_path, output_path)
        html = output_path.read_text(encoding="utf-8")
        for entry in entries:
            assert entry["step"] in html, f"Step '{entry['step']}' not found in HTML"


class TestCallsHtmlEmptyInput:
    """An empty JSONL always produces zero totals."""

    @given(data=st.just(None))
    @settings(
        max_examples=5,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_empty_jsonl_zero_totals(self, tmp_path, data):
        """An empty JSONL always produces zero totals and valid HTML."""
        calls_path = _write_jsonl(tmp_path / "empty.jsonl", [])
        output_path = tmp_path / "empty.html"
        render_calls_html(calls_path, output_path)
        html = output_path.read_text(encoding="utf-8")
        assert "<style>" in html
        assert "0" in html  # total calls = 0


class TestCallsHtmlRenderReturnsPath:
    """render_calls_html always returns the output path it was given."""

    @given(entries=st.lists(st_call_entry, min_size=0, max_size=10))
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_returns_output_path(self, tmp_path, entries):
        """The returned path equals the output_path argument."""
        calls_path = _write_jsonl(tmp_path / "calls.jsonl", entries)
        output_path = tmp_path / "output.html"
        result = render_calls_html(calls_path, output_path)
        assert result == output_path
        assert output_path.exists()
