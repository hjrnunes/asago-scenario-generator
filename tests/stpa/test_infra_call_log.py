"""Tests for STPA infra call log (InfraCallLog-01 through InfraCallLog-04)."""

from __future__ import annotations

import json

import pytest

from asago_scenario_generator.stpa.infra.call_log import (
    append_call_log,
    make_call_log_entry,
    mark_call_published,
)


class TestInfraCallLog:
    """JSONL call logging."""

    def test_call_log_01_entry_written_as_jsonl(self, tmp_path):
        """InfraCallLog-01: entry written as JSONL with stage and step."""
        entry = make_call_log_entry(
            stage="stage_2",
            step="call_1",
            model="test-model",
            slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
            scenario_id=None,
        )
        append_call_log([entry], tmp_path)
        lines = (tmp_path / "calls.jsonl").read_text().strip().split("\n")
        assert len(lines) == 1
        parsed = json.loads(lines[0])
        assert parsed["stage"] == "stage_2"
        assert parsed["step"] == "call_1"
        assert parsed["slot_id"] == "RESP-1:CA-1-1:NOT_PROVIDED"
        assert parsed["scenario_id"] is None
        assert parsed["provider_response_received"] is True
        assert parsed["draft_parsed"] is True
        assert parsed["semantic_validation_passed"] is True
        assert parsed["compiled"] is True
        assert parsed["published"] is False
        assert parsed["terminal_error_codes"] == []

    def test_call_log_02_entry_with_scenario_id(self, tmp_path):
        """InfraCallLog-02: entry with scenario_id set."""
        entry = make_call_log_entry(
            stage="stage_6_narrative",
            step="call_a",
            model="test-model",
            slot_id=None,
            scenario_id="SCN-001",
        )
        append_call_log([entry], tmp_path)
        parsed = json.loads((tmp_path / "calls.jsonl").read_text().strip())
        assert parsed["scenario_id"] == "SCN-001"

    def test_call_log_03_multiple_entries_appended_sequentially(self, tmp_path):
        """InfraCallLog-03: multiple entries appended in order."""
        entries = [
            make_call_log_entry(stage="stage_2", step="call_1", model="m"),
            make_call_log_entry(stage="stage_3", step="call_1", model="m"),
            make_call_log_entry(stage="stage_5", step="call_1", model="m"),
        ]
        append_call_log(entries, tmp_path)
        lines = (tmp_path / "calls.jsonl").read_text().strip().split("\n")
        assert len(lines) == 3
        stages = [json.loads(line)["stage"] for line in lines]
        assert stages == ["stage_2", "stage_3", "stage_5"]

    def test_call_log_04_empty_list_does_not_create_file(self, tmp_path):
        """InfraCallLog-04: empty list does not create calls.jsonl."""
        append_call_log([], tmp_path)
        assert not (tmp_path / "calls.jsonl").exists()

    def test_call_log_05_creates_nested_run_dir(self, tmp_path):
        """InfraCallLog-05: append_call_log creates nested run_dir."""
        entry = make_call_log_entry(stage="stage_2", step="call_1", model="m")
        nested = tmp_path / "nested" / "run"
        append_call_log([entry], nested)
        assert (nested / "calls.jsonl").exists()

    def test_call_log_06_preserves_non_ascii_content(self, tmp_path):
        """InfraCallLog-06: JSONL preserves non-ASCII in direct fields."""
        entry = make_call_log_entry(
            stage="stage_2",
            step="call_1",
            model="tëst-mödél",
        )
        append_call_log([entry], tmp_path)
        raw = (tmp_path / "calls.jsonl").read_text()
        # With ensure_ascii=False, non-ASCII chars appear directly in the file
        assert "tëst-mödél" in raw

    def test_call_log_07_default_prompt_tokens_is_zero(self):
        """Default prompt_tokens is 0."""
        entry = make_call_log_entry(stage="s", step="c", model="m")
        assert entry["prompt_tokens"] == 0

    def test_call_log_08_default_completion_tokens_is_zero(self):
        """Default completion_tokens is 0."""
        entry = make_call_log_entry(stage="s", step="c", model="m")
        assert entry["completion_tokens"] == 0

    def test_call_log_09_default_duration_ms_is_zero(self):
        """Default duration_ms is 0."""
        entry = make_call_log_entry(stage="s", step="c", model="m")
        assert entry["duration_ms"] == 0

    def test_call_log_10_default_success_is_true(self):
        """Default success is True."""
        entry = make_call_log_entry(stage="s", step="c", model="m")
        assert entry["success"] is True

    def test_call_log_11_explicit_values_override_defaults(self):
        """Explicit values override defaults for all numeric/bool fields."""
        entry = make_call_log_entry(
            stage="s",
            step="c",
            model="m",
            prompt_tokens=100,
            completion_tokens=50,
            duration_ms=5000,
            success=False,
        )
        assert entry["prompt_tokens"] == 100
        assert entry["completion_tokens"] == 50
        assert entry["duration_ms"] == 5000
        assert entry["success"] is False

    def test_publish_marks_only_latest_exact_validated_call(self, tmp_path):
        """Publication follows exact stage/step identity and latest-call order."""
        entries = [
            make_call_log_entry(stage="stage", step="call", model="m"),
            make_call_log_entry(stage="other", step="call", model="m"),
            make_call_log_entry(stage="stage", step="call", model="m"),
        ]
        append_call_log(entries, tmp_path)

        mark_call_published(tmp_path, "stage", "call")

        persisted = [
            json.loads(line)
            for line in (tmp_path / "calls.jsonl").read_text().splitlines()
        ]
        assert persisted[0]["published"] is False
        assert persisted[1]["published"] is False
        assert persisted[2]["published"] is True

    def test_publish_rejects_missing_or_unvalidated_call(self, tmp_path):
        """A transport response cannot be relabelled as published evidence."""
        with pytest.raises(ValueError, match="missing call log"):
            mark_call_published(tmp_path, "stage", "call")
        append_call_log(
            [
                make_call_log_entry(
                    stage="stage",
                    step="call",
                    model="m",
                    success=False,
                    provider_response_received=True,
                    semantic_validation_passed=False,
                )
            ],
            tmp_path,
        )
        with pytest.raises(ValueError, match="without semantic validation"):
            mark_call_published(tmp_path, "stage", "call")
        with pytest.raises(ValueError, match="without semantic validation"):
            mark_call_published(tmp_path, "missing-stage", "call")
