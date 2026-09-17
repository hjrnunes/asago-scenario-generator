"""Deterministic offline qualification audit regressions."""

from __future__ import annotations

import json
from pathlib import Path

from scripts.qualification.audit_scenario_fidelity_evidence import (
    AUDIT_ARTIFACTS,
    build_completion_status,
    build_secret_scan,
    build_usage_ledger,
    write_audit_artifacts,
)


def test_audit_writes_the_complete_deterministic_artifact_set(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "calls.jsonl").write_text(
        '{"stage":"stage_5","prompt_tokens":3,"completion_tokens":2}\n',
        encoding="utf-8",
    )
    first = write_audit_artifacts(tmp_path / "first", source_roots=(source,))
    second = write_audit_artifacts(tmp_path / "second", source_roots=(source,))

    assert [path.name for path in first] == list(AUDIT_ARTIFACTS)
    assert [path.name for path in second] == list(AUDIT_ARTIFACTS)
    for left, right in zip(first, second):
        assert json.loads(left.read_text()) == json.loads(right.read_text())


def test_usage_ledger_keeps_provider_category_and_unavailable_denominators(
    tmp_path: Path,
) -> None:
    (tmp_path / "calls.jsonl").write_text(
        '{"stage":"stage_5","prompt_tokens":3,"completion_tokens":2}\n',
        encoding="utf-8",
    )

    ledger = build_usage_ledger((tmp_path,))

    assert ledger["category_totals"]["producer_provider"] == {
        "call_count": 1,
        "total_tokens": 5,
    }
    assert (
        ledger["denominators"]["consumer_authoring_attempts"]
        == "unavailable_without_consumer_records"
    )


def test_completion_status_does_not_claim_complete_without_consumer_accounting(
    tmp_path: Path,
) -> None:
    status = build_completion_status((tmp_path,))

    assert status["status"] == "blocked"
    assert any(
        item["code"] == "consumer_call_accounting_unavailable"
        for item in status["blockers"]
    )


def test_secret_scan_reports_locations_without_secret_values(tmp_path: Path) -> None:
    path = tmp_path / "evidence.json"
    path.write_text('{"token": "sk-secret-value-that-is-not-persisted"}\n', encoding="utf-8")

    report = build_secret_scan((tmp_path,))

    assert report["clean"] is False
    assert report["matches"][0]["path"].endswith("evidence.json")
    assert "secret-value" not in json.dumps(report)
