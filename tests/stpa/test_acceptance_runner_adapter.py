"""Unit contracts for the mutation runner adapter outcome seam."""

from __future__ import annotations

import io
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = next(
    path
    for path in Path(__file__).resolve().parents
    if (path / "pyproject.toml").is_file()
)
sys.path.insert(0, str(ROOT / "acceptance"))

import runner_adapter  # noqa: E402


def test_main_keeps_non_object_json_inside_protocol(monkeypatch, capsys) -> None:
    monkeypatch.setattr(runner_adapter.sys, "stdin", io.StringIO("[]\n"))

    assert runner_adapter.main() == 0

    lines = capsys.readouterr().out.splitlines()
    response = json.loads(lines[0])
    assert response["id"] == "unknown"
    assert response["outcome"] == "infrastructure_error"


def test_run_job_keeps_standard_output_and_error_separate(
    monkeypatch,
    tmp_path: Path,
) -> None:
    def fake_run(*_args: object, **_kwargs: object) -> SimpleNamespace:
        return SimpleNamespace(
            returncode=0, stdout="worker stdout", stderr="worker stderr"
        )

    monkeypatch.setattr(runner_adapter.subprocess, "run", fake_run)

    response = runner_adapter.run_job(
        {
            "id": "job-1",
            "feature_json": str(tmp_path / "fixture.json"),
            "timeout": "1s",
        }
    )

    assert response["id"] == "job-1"
    assert response["outcome"] == "test_success"
    assert response["output"] == "worker stdout"
    assert response["error"] == "worker stderr"
    assert type(response["duration"]) is int
    assert response["duration"] >= 0


def test_run_job_maps_timeout_to_infrastructure_error(
    monkeypatch,
    tmp_path: Path,
) -> None:
    def fake_run(*_args: object, **_kwargs: object) -> SimpleNamespace:
        raise subprocess.TimeoutExpired("runtime", 1)

    monkeypatch.setattr(runner_adapter.subprocess, "run", fake_run)

    response = runner_adapter.run_job(
        {
            "id": "job-1",
            "feature_json": str(tmp_path / "fixture.json"),
            "timeout": "1s",
        }
    )

    assert response["id"] == "job-1"
    assert response["outcome"] == "infrastructure_error"
    assert type(response["duration"]) is int
    assert response["duration"] >= 0


@pytest.mark.parametrize(
    ("runtime", "outcome"),
    [
        (SimpleNamespace(returncode=1, stdout="o", stderr="e"), "test_failure"),
        (SimpleNamespace(returncode=7, stdout="o", stderr="e"), "infrastructure_error"),
        (RuntimeError("worker crashed"), "infrastructure_error"),
    ],
    ids=["status-1", "other-status", "execution-exception"],
)
def test_run_job_maps_every_other_runtime_result(
    monkeypatch, tmp_path: Path, runtime, outcome: str
) -> None:
    def fake_run(*_args: object, **_kwargs: object) -> SimpleNamespace:
        if isinstance(runtime, Exception):
            raise runtime
        return runtime

    monkeypatch.setattr(runner_adapter.subprocess, "run", fake_run)

    response = runner_adapter.run_job(
        {"id": "job-1", "feature_json": str(tmp_path / "fixture.json")}
    )

    assert response["id"] == "job-1"
    assert response["outcome"] == outcome
    assert type(response["duration"]) is int
    assert response["duration"] >= 0


def test_main_answers_a_malformed_line_and_keeps_serving(monkeypatch, capsys) -> None:
    jobs = '{"id": "job-2", "feature_json": "fixture.json"}\n'
    monkeypatch.setattr(runner_adapter.sys, "stdin", io.StringIO("{not json\n" + jobs))
    monkeypatch.setattr(
        runner_adapter,
        "run_job",
        lambda job: {"id": job["id"], "outcome": "test_success"},
    )

    assert runner_adapter.main() == 0

    lines = capsys.readouterr().out.splitlines()
    responses = [json.loads(line) for line in lines]
    assert len(responses) == 2
    assert responses[0]["id"] == "unknown"
    assert responses[0]["outcome"] == "infrastructure_error"
    assert responses[1] == {"id": "job-2", "outcome": "test_success"}
