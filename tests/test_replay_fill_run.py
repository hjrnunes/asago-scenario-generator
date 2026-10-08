"""The replay-fill flags and the manifest block of a replay-fill run."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
import yaml

from asago_scenario_generator.cli import app
from asago_scenario_generator.pipeline.synthesis import (
    MANIFEST_FILENAME,
    SynthesisAdapters,
    run_synthesis,
)
from asago_scenario_generator.stpa.infra.provider_record import (
    RECORD_FILENAME,
    LiveRequestBudgetError,
    ReplayFill,
)
from tests.cli_helpers import PlainCliRunner
from tests.helpers.synthesis_fixture import synthesis_inputs
from tests.helpers.provider_call_record import _completion
from tests.helpers.synthesis import _FakeAdapters

runner = PlainCliRunner()


def _write_recording(directory: Path, stages: tuple[str, ...]) -> None:
    directory.mkdir(parents=True)
    records = [
        {
            "kind": "provider-call-record-v1",
            "sequence": number,
            "identity": {
                "stage": stage,
                "step": "s",
                "slot_id": None,
                "scenario_id": None,
                "attempt_number": 1,
            },
            "request_sha256": f"{number:064x}",
            "outcome": "error",
            "error": {"type": "ValueError", "message": "x", "status_code": None},
        }
        for number, stage in enumerate(stages, start=1)
    ]
    (directory / RECORD_FILENAME).write_text(
        "".join(json.dumps(record) + "\n" for record in records), encoding="utf-8"
    )


def _run(tmp_path: Path, **changes: Any) -> Any:
    inputs = synthesis_inputs(tmp_path / "out", **changes)
    return run_synthesis(inputs, SynthesisAdapters.from_object(_FakeAdapters(calls=[])))


# --- manifest ------------------------------------------------------------------


def test_a_fill_run_states_its_mode_budget_and_counts_in_the_manifest(
    tmp_path: Path,
) -> None:
    recorded = tmp_path / "recorded"
    _write_recording(recorded, ("stage_a", "stage_a", "stage_b"))

    result = _run(
        tmp_path,
        replay_calls_dir=recorded,
        replay_fill=ReplayFill(max_live_requests=9, live_stages=frozenset({"stage_b"})),
    )

    expected = {
        "mode": "fill",
        "replay_source": str(recorded),
        "live_stages": ["stage_b"],
        "max_live_requests": 9,
        "served_requests": 0,
        "live_requests": 0,
        "live_requests_by_stage": {},
        "unused_recorded_responses": 3,
        "refused_requests": 0,
    }
    assert result.manifest["provider_replay_fill"] == expected
    persisted = yaml.safe_load((result.output_dir / MANIFEST_FILENAME).read_text())
    assert persisted["provider_replay_fill"] == expected


@pytest.mark.parametrize("replaying", [False, True], ids=["live", "strict-replay"])
def test_a_run_without_fill_has_no_fill_block(tmp_path: Path, replaying: bool) -> None:
    changes: dict[str, Any] = {}
    if replaying:
        recorded = tmp_path / "recorded"
        _write_recording(recorded, ("stage_a",))
        changes["replay_calls_dir"] = recorded

    result = _run(tmp_path, **changes)

    assert "provider_replay_fill" not in result.manifest


def test_a_run_that_spent_its_budget_ends_in_the_typed_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from asago_scenario_generator.pipeline import synthesis

    recorded = tmp_path / "recorded"
    _write_recording(recorded, ("stage_a",))

    def fake_body(inputs: Any, adapters: Any, session: Any) -> str:
        # A call site catches provider errors, so the refusal must not stop here.
        for question in ("first", "second"):
            try:
                session.exchange(
                    api="chat.completions.create",
                    request={"model": "m", "messages": [question]},
                    send=lambda: _completion("{}"),
                )
            except LiveRequestBudgetError:
                pass
        return "partial"

    monkeypatch.setattr(synthesis, "_run_synthesis", fake_body)
    inputs = synthesis_inputs(
        tmp_path / "out",
        replay_calls_dir=recorded,
        replay_fill=ReplayFill(max_live_requests=1),
    )

    with pytest.raises(LiveRequestBudgetError, match="budget of 1"):
        run_synthesis(inputs, None)


# --- command line --------------------------------------------------------------


@pytest.fixture
def generate_files(tmp_path: Path) -> list[str]:
    for name in ("risk.json", "facts.json", "mapping.tsv", "profiles.yaml"):
        (tmp_path / name).write_text("{}", encoding="utf-8")
    return [
        "generate",
        "--use-case",
        "a system",
        "--risk-extraction",
        str(tmp_path / "risk.json"),
        "--qualification-facts",
        str(tmp_path / "facts.json"),
        "--sssom",
        str(tmp_path / "mapping.tsv"),
        "--profiles-file",
        str(tmp_path / "profiles.yaml"),
        "--output-dir",
        str(tmp_path / "out"),
    ]


def _invoke(tmp_path: Path, arguments: list[str]) -> tuple[Any, list[Any]]:
    captured: list[Any] = []

    def capture(inputs: Any, adapter: Any) -> SimpleNamespace:
        captured.append(inputs)
        return SimpleNamespace(
            output_dir=tmp_path,
            artifact_paths={"taxonomy-obligation-plan.yaml": tmp_path / "p.yaml"},
            report_path=None,
            run_status="completed",
        )

    with (
        patch(
            "asago_scenario_generator.data.loaders.load_reviewed_risk_extraction",
            return_value=(),
        ),
        patch(
            "asago_scenario_generator.pipeline.synthesis.run_synthesis",
            side_effect=capture,
        ),
    ):
        return runner.invoke(app, arguments), captured


def test_the_fill_flags_reach_the_inputs(
    tmp_path: Path, generate_files: list[str]
) -> None:
    result, captured = _invoke(
        tmp_path,
        [
            *generate_files,
            "--profile",
            "p",
            "--replay-calls",
            str(tmp_path / "earlier"),
            "--replay-fill",
            "--live-stage",
            "stage_5",
            "--live-stage",
            "stage_2",
            "--max-live-requests",
            "40",
        ],
    )

    assert result.exit_code == 0, result.output
    assert captured[0].replay_fill == ReplayFill(
        max_live_requests=40, live_stages=frozenset({"stage_5", "stage_2"})
    )
    assert captured[0].replay_calls_dir == tmp_path / "earlier"


def test_a_run_without_the_fill_flag_has_no_fill_policy(
    tmp_path: Path, generate_files: list[str]
) -> None:
    result, captured = _invoke(
        tmp_path, [*generate_files, "--replay-calls", str(tmp_path / "earlier")]
    )

    assert result.exit_code == 0, result.output
    assert captured[0].replay_fill is None


@pytest.mark.parametrize(
    ("extra", "mention"),
    [
        (
            ["--replay-fill", "--profile", "p", "--max-live-requests", "1"],
            "--replay-calls",
        ),
        (
            ["--replay-fill", "--replay-calls", "r", "--max-live-requests", "1"],
            "--profile",
        ),
        (
            ["--replay-fill", "--replay-calls", "r", "--profile", "p"],
            "--max-live-requests",
        ),
        (["--live-stage", "stage_5", "--replay-calls", "r"], "--replay-fill"),
        (["--max-live-requests", "3", "--replay-calls", "r"], "--replay-fill"),
        (
            [
                "--replay-fill",
                "--replay-calls",
                "r",
                "--profile",
                "p",
                "--max-live-requests",
                "-1",
            ],
            "--max-live-requests",
        ),
    ],
    ids=[
        "fill-needs-replay-calls",
        "fill-needs-profile",
        "fill-needs-budget",
        "live-stage-needs-fill",
        "budget-needs-fill",
        "negative-budget",
    ],
)
def test_the_fill_flags_reject_an_incomplete_combination(
    tmp_path: Path, generate_files: list[str], extra: list[str], mention: str
) -> None:
    arguments = [
        str(tmp_path / "earlier") if value == "r" else value for value in extra
    ]

    result, captured = _invoke(tmp_path, [*generate_files, *arguments])

    assert result.exit_code != 0
    assert mention in result.output
    assert captured == []


def test_generate_help_lists_the_fill_flags() -> None:
    result = runner.invoke(app, ["generate", "--help"])

    assert result.exit_code == 0
    for option in ("--replay-fill", "--live-stage", "--max-live-requests"):
        assert option in result.stdout
