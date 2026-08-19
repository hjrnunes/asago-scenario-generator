#!/usr/bin/env python3
"""Offline end-to-end QA for nullable usage metrics through the public CLI."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from html.parser import HTMLParser
from pathlib import Path
from typing import Any


RUN_ID = "20260101T000000_abcdef0123456789abcdef0123456789"
METRIC_FIELDS = ("prompt_tokens", "completion_tokens", "duration_ms")
FORBIDDEN_ERRORS = ("unsupported operand type", "TypeError", "Traceback")
ROLE_METADATA = {
    "use-case.txt": ("use_case", "text/plain"),
    "capability-profile.yaml": ("capability_profile", "application/yaml"),
    "threat-surface.yaml": ("threat_surface", "application/yaml"),
    "coverage-gaps.json": ("coverage_report", "application/json"),
    "pipeline.log": ("pipeline_log", "text/plain"),
    "report.html": ("report", "text/html"),
    "calls.jsonl": ("pipeline_call_log", "application/jsonl"),
    "scenarios/calls.jsonl": ("scenario_call_log", "application/jsonl"),
}


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self.parts.append(data)


def _visible_text(document: str) -> str:
    parser = _TextExtractor()
    parser.feed(document)
    return " ".join(parser.parts)


def _uv_command() -> str:
    configured = os.environ.get("UV")
    candidates = (
        configured,
        shutil.which("uv"),
        "/opt/homebrew/bin/uv",
        "/usr/local/bin/uv",
    )
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return candidate
    raise RuntimeError("uv is required to run the public report command")


def _call(
    name: str,
    *,
    prompt_tokens: Any,
    completion_tokens: Any,
    duration_ms: Any,
    success: bool = True,
) -> dict[str, Any]:
    return {
        "call": name,
        "success": success,
        "error": "" if success else "synthetic failure",
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "duration_ms": duration_ms,
        "system_prompt": "",
        "user_prompt": "",
        "response": "",
    }


def _scenario(scenario_id: str, candidate_suffix: str) -> dict[str, Any]:
    return {
        "scenario_id": scenario_id,
        "candidate_id": f"cand:v2:{candidate_suffix * 32}",
        "priority": {"composite": 0.5},
        "narrative": {"title": scenario_id},
        "faceting": {"taxonomy_chain": {"agentic_threat_ids": []}},
        "validation": {
            "semantic": {
                "corpus_claim_applicability": [
                    {
                        "category": "entry_points",
                        "status": "not_applicable",
                        "reason": "Offline QA fixture",
                    },
                    {
                        "category": "tool_inventory",
                        "status": "not_applicable",
                        "reason": "Offline QA fixture",
                    },
                ]
            }
        },
    }


def _jsonl(records: list[dict[str, Any]]) -> str:
    return "".join(f"{json.dumps(record, ensure_ascii=False)}\n" for record in records)


def _write_fixture(
    root: Path,
    *,
    pipeline_calls: list[dict[str, Any]],
    scenarios: list[dict[str, Any]] | None = None,
    scenario_calls: list[dict[str, Any]] | None = None,
) -> Path:
    run_dir = root / "run"
    run_dir.mkdir(parents=True)
    fixture_scenarios = scenarios or [_scenario("reportable-scenario", "a")]
    contents = {
        "use-case.txt": "Offline nullable-metrics QA fixture\n",
        "capability-profile.yaml": "{}\n",
        "threat-surface.yaml": "{}\n",
        "coverage-gaps.json": "{}\n",
        "pipeline.log": "Offline nullable-metrics QA fixture\n",
        "report.html": "<html><body>Prior finalized report</body></html>\n",
        "calls.jsonl": _jsonl(pipeline_calls),
    }
    if scenario_calls is not None:
        contents["scenarios/calls.jsonl"] = _jsonl(scenario_calls)

    inventory: list[dict[str, Any]] = []
    for relative_path, content in contents.items():
        role, media_type = ROLE_METADATA[relative_path]
        _write_artifact(
            run_dir,
            inventory,
            relative_path,
            content,
            role,
            media_type,
        )

    for scenario in fixture_scenarios:
        scenario_id = str(scenario["scenario_id"])
        candidate_id = str(scenario["candidate_id"])
        yaml_path = f"scenarios/{scenario_id}.yaml"
        feature_path = f"scenarios/{scenario_id}.feature"
        _write_artifact(
            run_dir,
            inventory,
            yaml_path,
            f"{json.dumps(scenario, ensure_ascii=False)}\n",
            "scenario_yaml",
            "application/yaml",
            scenario_id=scenario_id,
            candidate_id=candidate_id,
        )
        _write_artifact(
            run_dir,
            inventory,
            feature_path,
            f"Feature: {scenario_id}\n  Scenario: offline report fixture\n",
            "scenario_feature",
            "text/plain",
            scenario_id=scenario_id,
            candidate_id=candidate_id,
        )

    manifest = {
        "manifest_version": "2",
        "status": "completed",
        "run_id": RUN_ID,
        "timestamp_start": "2026-01-01T00:00:00+00:00",
        "timestamp_end": "2026-01-01T00:01:00+00:00",
        "package_version": "0.1.0",
        "inventory": inventory,
    }
    (run_dir / "run-manifest.yaml").write_text(
        f"{json.dumps(manifest, indent=2)}\n",
        encoding="utf-8",
    )
    return run_dir


def _write_artifact(
    run_dir: Path,
    inventory: list[dict[str, Any]],
    relative_path: str,
    content: str,
    role: str,
    media_type: str,
    *,
    scenario_id: str | None = None,
    candidate_id: str | None = None,
) -> None:
    path = run_dir / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    entry: dict[str, Any] = {
        "role": role,
        "path": relative_path,
        "sha256": hashlib.sha256(content.encode()).hexdigest(),
        "schema_version": "1",
        "media_type": media_type,
    }
    if scenario_id is not None:
        entry["scenario_id"] = scenario_id
    if candidate_id is not None:
        entry["candidate_id"] = candidate_id
    inventory.append(entry)


def _run_report(
    fixture_root: Path, run_dir: Path
) -> tuple[subprocess.CompletedProcess[str], Path]:
    report_path = fixture_root / "generated" / "report.html"
    command = [
        _uv_command(),
        "run",
        "asago-scenario-generator",
        "report",
        "--output-dir",
        str(run_dir),
        "--output",
        str(report_path),
    ]
    result = subprocess.run(
        command,
        cwd=Path(__file__).resolve().parents[2],
        text=True,
        capture_output=True,
        check=False,
        env={**os.environ, "ASAGO_SCENARIO_GENERATOR_QA_PIPELINE": "0"},
    )
    return result, report_path


def _successful_report(
    fixture_root: Path,
    *,
    pipeline_calls: list[dict[str, Any]],
    scenarios: list[dict[str, Any]] | None = None,
    scenario_calls: list[dict[str, Any]] | None = None,
) -> str:
    run_dir = _write_fixture(
        fixture_root,
        pipeline_calls=pipeline_calls,
        scenarios=scenarios,
        scenario_calls=scenario_calls,
    )
    result, report_path = _run_report(fixture_root, run_dir)
    output = f"{result.stdout}\n{result.stderr}"
    assert result.returncode == 0, output
    assert report_path.is_file(), f"report was not created: {report_path}"
    document = report_path.read_text(encoding="utf-8")
    for fragment in FORBIDDEN_ERRORS:
        assert fragment not in output
        assert fragment not in document
    return _visible_text(document)


def _test_failed_call(root: Path) -> None:
    text = _successful_report(
        root,
        pipeline_calls=[
            _call(
                "failed_pipeline_call",
                prompt_tokens=None,
                completion_tokens=None,
                duration_ms=None,
                success=False,
            )
        ],
    )
    expected = (
        "failed_pipeline_call",
        "FAILED",
        "prompt_tokens=unavailable",
        "completion_tokens=unavailable",
        "duration_ms=unavailable",
        "0 prompt tokens",
        "0 completion tokens",
        "0ms total",
        "unavailable usage metrics",
    )
    assert all(fragment in text for fragment in expected)


def _test_mixed_call(root: Path, field: str, totals: tuple[int, int, int]) -> None:
    first = _call(
        "nullable_pipeline_call",
        prompt_tokens=5,
        completion_tokens=7,
        duration_ms=90,
    )
    first[field] = None
    text = _successful_report(
        root,
        pipeline_calls=[
            first,
            _call(
                "numeric_pipeline_call",
                prompt_tokens=11,
                completion_tokens=13,
                duration_ms=170,
            ),
        ],
    )
    prompt, completion, duration = totals
    expected = (
        "nullable_pipeline_call",
        "numeric_pipeline_call",
        f"{field}=unavailable",
        f"{prompt} prompt tokens",
        f"{completion} completion tokens",
        f"{duration}ms total",
        f"unavailable usage metrics: {field}",
    )
    assert all(fragment in text for fragment in expected)


def _test_scenario_calls(root: Path) -> None:
    scenarios = [
        _scenario("synthetic-scenario", "b"),
        _scenario("numeric-scenario", "c"),
    ]
    synthetic = _call(
        "synthetic_scenario_call",
        prompt_tokens=None,
        completion_tokens=None,
        duration_ms=None,
    )
    synthetic["scenario_id"] = "synthetic-scenario"
    numeric = _call(
        "numeric_scenario_call",
        prompt_tokens=19,
        completion_tokens=23,
        duration_ms=290,
    )
    numeric["scenario_id"] = "numeric-scenario"
    text = _successful_report(
        root,
        pipeline_calls=[],
        scenarios=scenarios,
        scenario_calls=[synthetic, numeric],
    )
    expected = (
        "synthetic-scenario",
        "numeric-scenario",
        "synthetic_scenario_call",
        "numeric_scenario_call",
        "prompt_tokens=unavailable",
        "completion_tokens=unavailable",
        "duration_ms=unavailable",
        "19 prompt / 23 completion tokens, 290ms",
        "unavailable usage metrics",
    )
    assert all(fragment in text for fragment in expected)


def _test_invalid_metric(root: Path, field: str, value: Any) -> None:
    call = _call(
        "invalid_pipeline_call",
        prompt_tokens=1,
        completion_tokens=1,
        duration_ms=1,
    )
    call[field] = value
    run_dir = _write_fixture(root, pipeline_calls=[call])
    result, report_path = _run_report(root, run_dir)
    output = f"{result.stdout}\n{result.stderr}"
    assert result.returncode != 0, output
    assert not report_path.exists(), (
        f"invalid report unexpectedly exists: {report_path}"
    )
    assert field in output
    assert repr(value) in output or json.dumps(value) in output
    assert "invalid_pipeline_call" in output
    assert "Invalid usage metric" in output
    assert all(fragment not in output for fragment in FORBIDDEN_ERRORS)


def _test_complete_call(root: Path) -> None:
    text = _successful_report(
        root,
        pipeline_calls=[
            _call(
                "complete_pipeline_call",
                prompt_tokens=31,
                completion_tokens=17,
                duration_ms=410,
            )
        ],
    )
    expected = (
        "complete_pipeline_call",
        "31 prompt tokens",
        "17 completion tokens",
        "410ms total",
    )
    assert all(fragment in text for fragment in expected)
    assert "unavailable usage metrics" not in text


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--keep-fixtures",
        action="store_true",
        help="Keep the temporary fixture directory for browser inspection.",
    )
    args = parser.parse_args()
    temporary = Path(tempfile.mkdtemp(prefix="asago-nullable-qa-"))
    try:
        _test_failed_call(temporary / "nlm-01")
        print("PASS QA-NLM-01 failed call with unavailable telemetry")

        mixed = {
            "prompt_tokens": (11, 20, 260),
            "completion_tokens": (16, 13, 260),
            "duration_ms": (16, 20, 170),
        }
        for field, totals in mixed.items():
            _test_mixed_call(temporary / f"nlm-02-{field}", field, totals)
            print(f"PASS QA-NLM-02 mixed telemetry: {field}")

        _test_scenario_calls(temporary / "nlm-03")
        print("PASS QA-NLM-03 scenario preservation")

        invalid = {
            "prompt_tokens": "many",
            "completion_tokens": {"count": 4},
            "duration_ms": [300],
        }
        for field, value in invalid.items():
            _test_invalid_metric(temporary / f"nlm-04-{field}", field, value)
            print(f"PASS QA-NLM-04 invalid diagnostic: {field}")

        _test_complete_call(temporary / "nlm-05")
        print("PASS QA-NLM-05 complete telemetry")
        if args.keep_fixtures:
            print(f"Fixtures retained at {temporary}")
        return 0
    finally:
        if not args.keep_fixtures:
            shutil.rmtree(temporary)


if __name__ == "__main__":
    raise SystemExit(main())
