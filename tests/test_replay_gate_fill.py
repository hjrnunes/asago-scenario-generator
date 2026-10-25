"""Replay gate on a recording made with --replay-fill: strict replay, fill provenance."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
import yaml

import replay_gate
from asago_scenario_generator.cli import app
from asago_scenario_generator.pipeline.synthesis_manifest import (
    _MANIFEST_DOMAIN,
    _digest_payload,
)
from asago_scenario_generator.stpa.infra.provider_record import (
    RECORD_FILENAME,
    CallIdentity,
    ReplayMissError,
    call_identity,
    provider_call_session,
)
from replay_gate import (
    REPLAY_FILL_PROVENANCE,
    compare_trees,
    prepare_run,
    run_gate,
)
from tests.cli_helpers import PlainCliRunner

_FILL_ARGUMENTS = [
    "--replay-calls",
    "/elsewhere/empty-record",
    "--replay-fill",
    "--live-stage",
    "stage_5",
    "--max-live-requests=750",
]


def _jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    path.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")


def _record(sequence: int, stage: str | None, source: str | None) -> dict[str, Any]:
    record: dict[str, Any] = {
        "kind": "provider-call-record-v1",
        "sequence": sequence,
        "identity": None if stage is None else {"stage": stage, "step": "x"},
        "request_sha256": f"{sequence:064x}",
        "response": {"body": f"answer {sequence}"},
        "timestamp": f"t{sequence}",
        "duration_ms": sequence,
    }
    if source is not None:
        record["source"] = source
    return record


def _fill_block(**changes: Any) -> dict[str, Any]:
    block = {
        "mode": "fill",
        "replay_source": "/elsewhere/empty-record",
        "live_stages": ["stage_5"],
        "max_live_requests": 750,
        "served_requests": 1,
        "live_requests": 2,
        "live_requests_by_stage": {"stage_5": 1, "unattributed": 1},
        "unused_recorded_responses": 0,
        "refused_requests": 0,
    }
    block.update(changes)
    return block


def _manifest(
    root: Path,
    run_id: str,
    stamp: str,
    fill: dict[str, Any] | None = None,
    *,
    published: int = 2,
) -> None:
    payload: dict[str, Any] = {"run_id": run_id, "created_at": stamp}
    payload["scenario_counts"] = {"published": published}
    if fill is not None:
        payload[REPLAY_FILL_PROVENANCE.manifest_block] = fill
    payload["semantic_digest"] = _digest_payload(_MANIFEST_DOMAIN, payload)
    (root / "synthesis-manifest.yaml").write_text(
        yaml.safe_dump(payload, sort_keys=False)
    )


def _output(
    root: Path,
    *,
    run_id: str,
    stamp: str,
    sources: tuple[str | None, ...],
    fill: dict[str, Any] | None,
) -> Path:
    root.mkdir(parents=True)
    stages = ("stage_2", "stage_5", None)
    _jsonl(
        root / RECORD_FILENAME,
        [
            _record(number, stage, source)
            for number, (stage, source) in enumerate(zip(stages, sources), start=1)
        ],
    )
    _manifest(root, run_id, stamp, fill)
    return root


def _recorded(root: Path, **block: Any) -> Path:
    return _output(
        root,
        run_id="synthesis-20261001T000000Z",
        stamp="2026-10-01T00:00:00",
        sources=("replay", "live", "live"),
        fill=_fill_block(**block),
    )


def _replayed(root: Path) -> Path:
    """What a strict replay of the recording writes: no fill provenance."""
    return _output(
        root,
        run_id="synthesis-20261002T111111Z",
        stamp="2026-10-02T11:11:11.5",
        sources=(None, None, None),
        fill=None,
    )


@pytest.fixture
def fill_trees(tmp_path: Path) -> tuple[Path, Path]:
    return _recorded(tmp_path / "recorded"), _replayed(tmp_path / "replayed")


def _differences(recorded: Path, replayed: Path, *, replay_fill: bool) -> list[str]:
    _, differences = compare_trees(recorded, replayed, {}, replay_fill=replay_fill)
    return [str(item) for item in differences]


def test_a_fill_recording_matches_its_strict_replay(fill_trees) -> None:
    assert _differences(*fill_trees, replay_fill=True) == []


def test_the_fill_provenance_is_a_difference_without_the_recorded_fill_flag(
    fill_trees,
) -> None:
    assert _differences(*fill_trees, replay_fill=False) == [
        f"{RECORD_FILENAME}: $[0].source: only in recording",
        "synthesis-manifest.yaml: $.provider_replay_fill: only in recording",
    ]


def test_the_fill_provenance_does_not_hide_another_record_field(fill_trees) -> None:
    recorded, replayed = fill_trees
    records = [_record(1, "stage_2", None), _record(2, "stage_5", None)]
    records.append(dict(_record(3, None, None), response={"body": "changed"}))
    _jsonl(replayed / RECORD_FILENAME, records)

    assert _differences(recorded, replayed, replay_fill=True) == [
        # Records compare sorted by identity; the unattributed one sorts first.
        f'{RECORD_FILENAME}: $[0].response.body: "answer 3" != "changed"'
    ]


def test_the_fill_provenance_does_not_hide_another_manifest_field(fill_trees) -> None:
    recorded, replayed = fill_trees
    payload = yaml.safe_load((replayed / "synthesis-manifest.yaml").read_text())
    _manifest(replayed, payload["run_id"], payload["created_at"], published=3)

    assert _differences(recorded, replayed, replay_fill=True) == [
        "synthesis-manifest.yaml: $.scenario_counts.published: 2 != 3"
    ]


def test_a_replay_that_still_writes_a_source_fails(fill_trees) -> None:
    recorded, replayed = fill_trees
    records = [_record(1, "stage_2", None), _record(2, "stage_5", None)]
    records.append(_record(3, None, "replay"))
    _jsonl(replayed / RECORD_FILENAME, records)

    assert _differences(recorded, replayed, replay_fill=True) == [
        f"{RECORD_FILENAME}: $[0].source: only in replay"
    ]


def test_a_replay_that_still_writes_the_fill_block_fails(tmp_path: Path) -> None:
    recorded = _recorded(tmp_path / "recorded")
    replayed = _replayed(tmp_path / "replayed")
    payload = yaml.safe_load((replayed / "synthesis-manifest.yaml").read_text())
    _manifest(
        replayed,
        payload["run_id"],
        payload["created_at"],
        _fill_block(served_requests=3, live_requests=0, live_requests_by_stage={}),
    )

    assert _differences(recorded, replayed, replay_fill=True) == [
        "synthesis-manifest.yaml: $.provider_replay_fill.live_requests: 2 != 0"
    ]


def test_a_refused_record_is_not_fill_provenance(tmp_path: Path) -> None:
    recorded = _output(
        tmp_path / "recorded",
        run_id="synthesis-20261001T000000Z",
        stamp="2026-10-01T00:00:00",
        sources=("replay", "live", "refused"),
        fill=_fill_block(
            live_requests=1, live_requests_by_stage={"stage_5": 1}, refused_requests=1
        ),
    )
    replayed = _replayed(tmp_path / "replayed")

    assert _differences(recorded, replayed, replay_fill=True) == [
        f"{RECORD_FILENAME}: $[0].source: only in recording",
        "synthesis-manifest.yaml: $.provider_replay_fill: only in recording",
    ]


@pytest.mark.parametrize(
    "block",
    [
        {"served_requests": 0},
        {"live_requests": 3},
        {"live_requests_by_stage": {"stage_5": 2}},
        {"max_live_requests": 1},
        {"mode": "strict"},
    ],
)
def test_a_fill_block_that_does_not_count_its_records_fails(
    tmp_path: Path, block: dict[str, Any]
) -> None:
    recorded = _recorded(tmp_path / "recorded", **block)
    replayed = _replayed(tmp_path / "replayed")

    assert _differences(recorded, replayed, replay_fill=True) == [
        "synthesis-manifest.yaml: $.provider_replay_fill: only in recording"
    ]


# --- the replay arguments ----------------------------------------------------


def test_prepare_run_drops_the_fill_options(tmp_path: Path) -> None:
    recorded = tmp_path / "recorded"
    recorded.mkdir()
    (recorded / RECORD_FILENAME).write_text("")
    work = tmp_path / "work"
    arguments = [
        "generate",
        "--output-dir",
        "/runs/r1/output",
        "--profile",
        "p",
        *_FILL_ARGUMENTS,
        "--max-live-requests",
        "5",
        "--live-stage=stage_2",
    ]

    prepared = prepare_run(arguments, recorded=recorded, work=work)

    assert prepared.replay_fill
    assert prepared.arguments == [
        "generate",
        "--output-dir",
        str(work / "output"),
        "--profile",
        "p",
        "--replay-calls",
        str(work / "record"),
    ]


def test_prepare_run_without_the_fill_flag_is_not_a_fill_recording(
    tmp_path: Path,
) -> None:
    recorded = tmp_path / "recorded"
    recorded.mkdir()
    (recorded / RECORD_FILENAME).write_text("")
    arguments = ["generate", "--output-dir", "/runs/r1/output"]

    prepared = prepare_run(arguments, recorded=recorded, work=tmp_path / "work")

    assert not prepared.replay_fill


def _stage(recorded: Path, arguments: list[str]) -> Path:
    (recorded.parent / "stage.json").write_text(
        json.dumps(
            {
                "argv": ["/venv/bin/asago-scenario-generator", "generate"]
                + ["--output-dir", "/runs/r1/output", *arguments],
                "exit_code": 0,
            }
        )
    )
    return recorded


def test_run_gate_replays_a_fill_recording_strictly_and_passes(
    tmp_path: Path,
) -> None:
    recorded = _stage(_recorded(tmp_path / "run" / "recorded"), _FILL_ARGUMENTS)
    commands: list[list[str]] = []

    def strict_replay(command: list[str], env: dict[str, str]) -> int:
        commands.append(command)
        output = Path(command[command.index("--output-dir") + 1])
        shutil.copytree(_replayed(tmp_path / "strict"), output)
        return 0

    result = run_gate(recorded, work=tmp_path / "work", runner=strict_replay)

    assert result.passed, result.differences
    assert not {"--replay-fill", "--live-stage", "--max-live-requests=750"} & set(
        commands[0]
    )
    assert commands[0][-2:] == ["--replay-calls", str(tmp_path / "work" / "record")]


def test_run_gate_does_not_accept_fill_provenance_without_the_fill_flag(
    tmp_path: Path,
) -> None:
    recorded = _stage(_recorded(tmp_path / "run" / "recorded"), [])

    def strict_replay(command: list[str], env: dict[str, str]) -> int:
        output = Path(command[command.index("--output-dir") + 1])
        shutil.copytree(_replayed(tmp_path / "strict"), output)
        return 0

    result = run_gate(recorded, work=tmp_path / "work", runner=strict_replay)

    assert not result.passed
    assert [item.path for item in result.differences] == [
        RECORD_FILENAME,
        "synthesis-manifest.yaml",
    ]


# --- the replay is strict -----------------------------------------------------


def _generate_inputs(tmp_path: Path) -> list[str]:
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
        "/runs/r1/output",
        "--profile",
        "p",
        *_FILL_ARGUMENTS,
    ]


def _synthesis_inputs_of(arguments: list[str], tmp_path: Path) -> Any:
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
        result = PlainCliRunner().invoke(app, arguments)
    assert result.exit_code == 0, result.output
    return captured[0]


def test_a_request_the_fill_recording_lacks_misses_and_is_never_sent(
    tmp_path: Path,
) -> None:
    recorded = tmp_path / "recorded"
    recorded.mkdir()
    (recorded / RECORD_FILENAME).write_text(
        json.dumps(_record(1, "stage_2", "live")) + "\n", encoding="utf-8"
    )
    work = tmp_path / "work"
    prepared = prepare_run(_generate_inputs(tmp_path), recorded=recorded, work=work)

    inputs = _synthesis_inputs_of(prepared.arguments, tmp_path)

    assert inputs.replay_fill is None
    assert inputs.replay_calls_dir == work / "record"
    sent: list[str] = []
    with pytest.raises(ReplayMissError, match="no recorded response"):
        with provider_call_session(
            record_dir=tmp_path / "out",
            replay_dir=inputs.replay_calls_dir,
            fill=inputs.replay_fill,
        ) as session:
            assert session.replay_only
            with call_identity(CallIdentity(stage="stage_2", step="x")):
                session.exchange(
                    api="chat.completions.create",
                    request={"model": "m", "messages": [{"role": "user"}]},
                    send=lambda: sent.append("live"),
                )
    assert sent == []


def test_the_fill_provenance_states_its_reason() -> None:
    allowed = replay_gate.REPLAY_FILL_PROVENANCE
    assert allowed.reason and allowed.record_field and allowed.manifest_block
    assert allowed.record_sources == {"replay", "live"}
