"""Replay gate: argument rewriting, allowed differences, and the network guard."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest
import yaml

import replay_gate
from asago_scenario_generator.pipeline.synthesis_manifest import (
    _MANIFEST_DOMAIN,
    _digest_payload,
)
from replay_gate import (
    ALLOWED_DIFFERENCES,
    ALLOWED_FILE_CHANGES,
    ALLOWED_TEXT_DIFFERENCES,
    Difference,
    GateResult,
    _drop_field,
    _first_difference,
    _report,
    compare_file,
    compare_trees,
    main,
    prepare_run,
    replay_environment,
    run_gate,
)
from asago_scenario_generator.stpa.infra.provider_record import RECORD_FILENAME


def _jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    path.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")


def _manifest(
    run_id: str, created_at: str, *, call_evidence: list[Any] | None = None
) -> dict[str, Any]:
    payload: dict[str, Any] = {"run_id": run_id, "created_at": created_at}
    if call_evidence is not None:
        payload["prompt_call_evidence"] = call_evidence
    payload["scenario_counts"] = {"published": 2}
    payload["semantic_digest"] = _digest_payload(_MANIFEST_DOMAIN, payload)
    return payload


def _write_manifest(root: Path, payload: dict[str, Any]) -> None:
    (root / "synthesis-manifest.yaml").write_text(
        yaml.safe_dump(payload, sort_keys=False)
    )


def _provider_call(sequence: int, scenario: str, answer: str) -> dict[str, Any]:
    return {
        "kind": "provider-call-record-v1",
        "sequence": sequence,
        "identity": {"stage": "s", "step": "x", "scenario_id": scenario},
        "request_sha256": "d" * 64,
        "response": {"body": answer},
        "timestamp": f"t{sequence}",
        "duration_ms": sequence,
    }


def _output(
    root: Path,
    *,
    output_dir: str,
    run_id: str,
    stamp: str,
    order: tuple[int, int] = (1, 2),
) -> Path:
    root.mkdir(parents=True)
    (root / "scenarios").mkdir()
    (root / "scenarios" / "SCN-001.feature").write_text("Feature: f\n")
    _jsonl(
        root / "calls.jsonl",
        [{"step": "a", "timestamp": stamp, "duration_ms": len(stamp), "ok": True}],
    )
    calls = {1: _provider_call(1, "A", "for A"), 2: _provider_call(2, "B", "for B")}
    shifted = [dict(calls[n], sequence=i + 1) for i, n in enumerate(order)]
    _jsonl(root / RECORD_FILENAME, shifted if order != (1, 2) else list(calls.values()))
    (root / "run-manifest.yaml").write_text(
        yaml.safe_dump(
            {"run_id": run_id + ".1", "run_dir": output_dir, "created_at": stamp}
        )
    )
    _write_manifest(root, _manifest(run_id, stamp))
    (root / "synthesis-report.html").write_text(f"<p>Run: <code>{run_id}</code></p>\n")
    return root


@pytest.fixture
def trees(tmp_path: Path) -> tuple[Path, Path, dict[str, str]]:
    recorded = _output(
        tmp_path / "recorded",
        output_dir="/runs/r1/output",
        run_id="synthesis-20261001T000000Z",
        stamp="2026-10-01T00:00:00",
    )
    replayed = _output(
        tmp_path / "replayed",
        output_dir="/scratch/output",
        run_id="synthesis-20261002T111111Z",
        stamp="2026-10-02T11:11:11.5",
        order=(2, 1),
    )
    return recorded, replayed, {"/scratch/output": "/runs/r1/output"}


def test_a_replay_that_differs_only_in_allowed_ways_matches(trees) -> None:
    recorded, replayed, path_map = trees
    compared, differences = compare_trees(recorded, replayed, path_map)
    assert compared == 6
    assert differences == []


def test_a_jsonl_record_with_unicode_line_separators_parses_whole() -> None:
    record = {"text": "a\u0085b\u2028c\u2029d"}
    text = json.dumps(record, ensure_ascii=False) + "\n"

    assert replay_gate._parse(text, ".jsonl") == [record]


def test_an_unexplained_field_difference_is_reported_with_its_path(trees) -> None:
    recorded, replayed, path_map = trees
    _jsonl(
        replayed / "calls.jsonl",
        [{"step": "a", "timestamp": "x", "duration_ms": 1, "ok": False}],
    )
    _, differences = compare_trees(recorded, replayed, path_map)
    assert [str(d) for d in differences] == ["calls.jsonl: $[0].ok: true != false"]


def test_an_allowed_field_name_is_compared_outside_its_own_file(trees) -> None:
    recorded, replayed, path_map = trees
    (replayed / "scenarios" / "SCN-001.yaml").write_text("created_at: now\n")
    (recorded / "scenarios" / "SCN-001.yaml").write_text("created_at: then\n")
    _, differences = compare_trees(recorded, replayed, path_map)
    assert [str(d) for d in differences] == [
        'scenarios/SCN-001.yaml: $.created_at: "then" != "now"'
    ]


def test_provider_calls_must_pair_each_identity_with_its_recorded_response(
    trees,
) -> None:
    recorded, replayed, path_map = trees
    swapped = [_provider_call(1, "A", "for B"), _provider_call(2, "B", "for A")]
    _jsonl(replayed / RECORD_FILENAME, swapped)
    _, differences = compare_trees(recorded, replayed, path_map)
    assert [d.path for d in differences] == [RECORD_FILENAME]
    assert "response.body" in differences[0].detail


def test_missing_extra_and_text_files_are_reported(trees) -> None:
    recorded, replayed, path_map = trees
    (replayed / "scenarios" / "SCN-001.feature").unlink()
    (replayed / "extra.yaml").write_text("a: 1\n")
    (replayed / "synthesis-report.html").write_text("<p>Run: <code>other</code></p>\n")
    _, differences = compare_trees(recorded, replayed, path_map)
    assert [str(d) for d in differences] == [
        "scenarios/SCN-001.feature: only in recording",
        "extra.yaml: only in replay",
        "synthesis-report.html: line 1: '<p>Run: <code>synthesis-20261001T000000Z"
        "</code></p>' != '<p>Run: <code>other</code></p>'",
    ]


def test_a_recording_made_before_the_generate_report_moved_still_matches(
    trees,
) -> None:
    recorded, replayed, path_map = trees
    (replayed / "synthesis-report.html").unlink()
    (replayed / "report").mkdir()
    (replayed / "report" / "index.html").write_text("<html></html>\n")
    (replayed / "report" / "stage-summary.json").write_text("{}\n")
    (replayed / "policy-coverage.json").write_text("{}\n")
    _jsonl(
        replayed / "calls.jsonl",
        [
            {
                "step": "a",
                "timestamp": "x",
                "duration_ms": 1,
                "ok": True,
                "retry_of": 3,
            }
        ],
    )

    _, differences = compare_trees(recorded, replayed, path_map)

    assert differences == []


def _old_call(published: bool) -> dict[str, Any]:
    """A call entry as calls.jsonl held it before naming provider records."""
    return {
        "stage": "s",
        "step": "x",
        "scenario_id": "A",
        "system_prompt_hash": "h",
        "system_prompt_text": "system",
        "user_prompt_text": "user",
        "timestamp": "t1",
        "attempt_id": "s:x:A:1",
        "compiled": published,
        "published": published,
        "raw_response": "{}",
        "cleaned_response": {},
        "response_content": "{}",
    }


# Scenario A's provider record is sequence 1 in the recording and 2 in the
# replay, whose requests arrived in the other order.
_RECORDED_A, _REPLAYED_A, _REPLAYED_B = 1, 2, 1


def _new_call(*sequences: int, digest: str = "d" * 64) -> dict[str, Any]:
    """The same call as calls.jsonl holds it now, naming its provider records."""
    return {
        "stage": "s",
        "step": "x",
        "scenario_id": "A",
        "system_prompt_hash": "h",
        "provider_requests": [
            {"sequence": sequence, "request_sha256": digest} for sequence in sequences
        ],
        "response_parsed": True,
        "timestamp": "t2",
        "attempt_id": "s:x:A:1",
        "compiled": False,
        "published": False,
    }


_PUBLISHED = {"kind": "call-published", "attempt_id": "s:x:A:1"}


def _calls(root: Path, *records: dict[str, Any]) -> None:
    _jsonl(root / "calls.jsonl", list(records))


def test_a_recording_with_call_text_matches_a_replay_naming_provider_records(
    trees,
) -> None:
    recorded, replayed, path_map = trees
    _calls(recorded, _old_call(published=True))
    _calls(replayed, _new_call(_REPLAYED_A), _PUBLISHED)

    _, differences = compare_trees(recorded, replayed, path_map)

    assert differences == []


def test_a_publication_the_recording_lacks_is_a_difference(trees) -> None:
    recorded, replayed, path_map = trees
    _calls(recorded, _old_call(published=False))
    _calls(replayed, _new_call(_REPLAYED_A), _PUBLISHED)

    _, differences = compare_trees(recorded, replayed, path_map)

    assert [str(d) for d in differences] == [
        "calls.jsonl: $[0].compiled: false != true"
    ]


def test_links_that_resolve_on_each_side_match_across_sequence_numbers(
    trees,
) -> None:
    recorded, replayed, path_map = trees
    _calls(recorded, _new_call(_RECORDED_A))
    _calls(replayed, _new_call(_REPLAYED_A))

    _, differences = compare_trees(recorded, replayed, path_map)

    assert differences == []


@pytest.mark.parametrize(
    ("replayed_call", "detail"),
    [
        (_new_call(_REPLAYED_A, digest="e" * 64), "names no record"),
        (_new_call(7), "names no record"),
        (_new_call(_REPLAYED_B), "names the record of another call"),
    ],
    ids=["wrong-digest", "unknown-sequence", "other-call"],
)
def test_a_corrupted_link_fails_the_gate(
    trees, replayed_call: dict[str, Any], detail: str
) -> None:
    recorded, replayed, path_map = trees
    _calls(recorded, _new_call(_RECORDED_A))
    _calls(replayed, replayed_call)

    _, differences = compare_trees(recorded, replayed, path_map)

    assert [d.path for d in differences] == ["calls.jsonl"]
    assert differences[0].detail.startswith("replay $[0].provider_requests")
    assert detail in differences[0].detail


def test_a_corrupted_link_in_the_recording_fails_the_gate(trees) -> None:
    recorded, replayed, path_map = trees
    _calls(recorded, _new_call(7))
    _calls(replayed, _new_call(_REPLAYED_A))

    _, differences = compare_trees(recorded, replayed, path_map)

    assert [d.detail.split(" $")[0] for d in differences] == ["recording"]


def test_a_missing_link_between_new_entries_is_a_difference(trees) -> None:
    recorded, replayed, path_map = trees
    _calls(recorded, _new_call(_RECORDED_A))
    _calls(replayed, _new_call())

    _, differences = compare_trees(recorded, replayed, path_map)

    assert [str(d) for d in differences] == [
        "calls.jsonl: $[0].provider_requests: length 1 != 0"
    ]


def test_a_replay_that_kept_text_instead_of_links_is_a_difference(trees) -> None:
    recorded, replayed, path_map = trees
    _calls(recorded, _new_call(_RECORDED_A))
    _calls(replayed, dict(_old_call(published=False), provider_requests=[]))

    _, differences = compare_trees(recorded, replayed, path_map)

    assert [d.path for d in differences] == ["calls.jsonl"]


def test_a_changed_parse_flag_between_new_entries_is_a_difference(trees) -> None:
    recorded, replayed, path_map = trees
    _calls(recorded, _new_call(_RECORDED_A))
    _calls(replayed, dict(_new_call(_REPLAYED_A), response_parsed=False))

    _, differences = compare_trees(recorded, replayed, path_map)

    assert [str(d) for d in differences] == [
        "calls.jsonl: $[0].response_parsed: true != false"
    ]


def test_a_recording_whose_manifest_copies_the_call_records_still_matches(
    trees,
) -> None:
    recorded, replayed, path_map = trees
    _write_manifest(
        recorded,
        _manifest(
            "synthesis-20261001T000000Z",
            "2026-10-01T00:00:00",
            call_evidence=[{"step": "a", "duration_ms": 3}],
        ),
    )

    _, differences = compare_trees(recorded, replayed, path_map)

    assert differences == []


def test_only_the_named_report_files_may_appear_or_vanish(trees) -> None:
    recorded, replayed, path_map = trees
    (replayed / "report").mkdir()
    (replayed / "report" / "notes.html").write_text("<html></html>\n")
    (recorded / "policy-coverage.json").write_text("{}\n")

    _, differences = compare_trees(recorded, replayed, path_map)

    assert [str(d) for d in differences] == [
        "policy-coverage.json: only in recording",
        "report/notes.html: only in replay",
    ]


def test_a_self_digest_that_does_not_match_its_payload_fails(trees) -> None:
    recorded, replayed, path_map = trees
    manifest = yaml.safe_load((replayed / "synthesis-manifest.yaml").read_text())
    manifest["semantic_digest"] = "0" * 64
    (replayed / "synthesis-manifest.yaml").write_text(yaml.safe_dump(manifest))
    _, differences = compare_trees(recorded, replayed, path_map)
    assert [str(d) for d in differences] == [
        "synthesis-manifest.yaml: replay semantic_digest does not match its payload"
    ]


def _prompt_hashes(root: Path, hashes: dict[str, str]) -> None:
    manifest = yaml.safe_load((root / "run-manifest.yaml").read_text())
    manifest["prompt_hashes"] = hashes
    (root / "run-manifest.yaml").write_text(yaml.safe_dump(manifest))


def test_a_hash_for_a_template_removed_from_the_checkout_is_reported(trees) -> None:
    recorded, replayed, path_map = trees
    _prompt_hashes(recorded, {"kept.j2": "a" * 64, "gone.j2": "b" * 64})
    _prompt_hashes(replayed, {"kept.j2": "a" * 64})
    removed: set[str] = set()
    _, differences = compare_trees(
        recorded,
        replayed,
        path_map,
        present_templates=frozenset({"kept.j2"}),
        removed_templates=removed,
    )
    assert differences == []
    assert removed == {"gone.j2"}


def test_a_missing_hash_for_a_template_still_in_the_checkout_fails(trees) -> None:
    recorded, replayed, path_map = trees
    _prompt_hashes(recorded, {"kept.j2": "a" * 64, "gone.j2": "b" * 64})
    _prompt_hashes(replayed, {"kept.j2": "a" * 64})
    removed: set[str] = set()
    _, differences = compare_trees(
        recorded,
        replayed,
        path_map,
        present_templates=frozenset({"kept.j2", "gone.j2"}),
        removed_templates=removed,
    )
    assert [str(d) for d in differences] == [
        "run-manifest.yaml: $.prompt_hashes.gone.j2: only in recording"
    ]
    assert removed == set()


def test_a_changed_hash_for_a_kept_template_still_fails(trees) -> None:
    recorded, replayed, path_map = trees
    _prompt_hashes(recorded, {"kept.j2": "a" * 64})
    _prompt_hashes(replayed, {"kept.j2": "c" * 64})
    _, differences = compare_trees(
        recorded, replayed, path_map, present_templates=frozenset()
    )
    assert [d.path for d in differences] == ["run-manifest.yaml"]


def test_the_report_names_the_removed_templates(trees, tmp_path: Path) -> None:
    recorded = _stage(tmp_path, trees[0])
    _prompt_hashes(recorded, {"_stage6_projection_alignment_gone.j2": "b" * 64})

    def run(command: list[str], env: dict[str, str]) -> int:
        output = Path(command[command.index("--output-dir") + 1])
        shutil.copytree(recorded, output)
        _prompt_hashes(output, {})
        return 0

    result = run_gate(recorded, work=tmp_path / "work", runner=run)
    assert result.passed, result.differences
    assert result.removed_templates == ["_stage6_projection_alignment_gone.j2"]
    report = _report(result, tmp_path / "work", 10)
    assert (
        "removed templates: 1 recorded prompt hash(es) for templates absent "
        "from this checkout" in report
    )
    assert "  _stage6_projection_alignment_gone.j2" in report


def test_every_allowed_difference_states_a_reason() -> None:
    for allowed in ALLOWED_DIFFERENCES:
        assert allowed.file and allowed.fields and allowed.reason
    for text in ALLOWED_TEXT_DIFFERENCES:
        assert text.file and text.pattern.groups and text.reason
    for change in ALLOWED_FILE_CHANGES:
        assert change.file and change.side in {"recording", "replay"}
        assert change.reason


def test_prepare_run_copies_inputs_and_redirects_the_output(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "use-case.txt").write_text("a system")
    (source / "risk.json").write_text("{}")
    (source / "profiles.yaml").write_text("p: {}")
    recorded = tmp_path / "recorded"
    recorded.mkdir()
    (recorded / RECORD_FILENAME).write_text("")
    work = tmp_path / "work"
    arguments = [
        "generate",
        "--output-dir",
        "/runs/r1/output",
        "--use-case",
        f"@{source / 'use-case.txt'}",
        "--risk-extraction",
        str(source / "risk.json"),
        "--profiles-file",
        str(source / "profiles.yaml"),
        "--max-workers",
        "2",
        "--replay-calls",
        "/somewhere/else",
    ]

    prepared = prepare_run(arguments, recorded=recorded, work=work)

    copied_use_case = work / "inputs" / "00" / "use-case.txt"
    copied_risk = work / "inputs" / "01" / "risk.json"
    assert prepared.arguments == [
        "generate",
        "--output-dir",
        str(work / "output"),
        "--use-case",
        f"@{copied_use_case}",
        "--risk-extraction",
        str(copied_risk),
        "--profiles-file",
        str(source / "profiles.yaml"),
        "--max-workers",
        "2",
        "--replay-calls",
        str(work / "record"),
    ]
    assert copied_use_case.read_text() == "a system"
    assert (work / "record" / RECORD_FILENAME).exists()
    assert prepared.path_map[str(work / "output")] == "/runs/r1/output"
    assert prepared.path_map[str(copied_risk)] == str(source / "risk.json")


def test_prepare_run_keeps_each_input_file_name(tmp_path: Path) -> None:
    # The producer records an input's base name (policy-coverage.json names the
    # risk extraction file), so a renamed copy would differ from the recording.
    first, second = tmp_path / "a", tmp_path / "b"
    first.mkdir()
    second.mkdir()
    (first / "risk-extraction-fs-isac.json").write_text("{}")
    (second / "risk-extraction-fs-isac.json").write_text('{"b": 1}')
    recorded = tmp_path / "recorded"
    recorded.mkdir()
    (recorded / RECORD_FILENAME).write_text("")
    arguments = [
        "generate",
        "--output-dir",
        "/runs/r1/output",
        "--risk-extraction",
        str(first / "risk-extraction-fs-isac.json"),
        "--sssom",
        str(second / "risk-extraction-fs-isac.json"),
    ]

    prepared = prepare_run(arguments, recorded=recorded, work=tmp_path / "work")

    copies = [Path(prepared.arguments[4]), Path(prepared.arguments[6])]
    assert [copy.name for copy in copies] == ["risk-extraction-fs-isac.json"] * 2
    assert copies[0] != copies[1]
    assert [copy.read_text() for copy in copies] == ["{}", '{"b": 1}']


def test_replay_environment_drops_model_settings_and_credentials() -> None:
    env = replay_environment(
        {
            "PATH": "/bin",
            "ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL": "https://x",
            "ASAGO_SCENARIO_GENERATOR_TEMPERATURE": "0.1",
            "OPENAI_API_KEY": "k",
            "OPENROUTER_API_KEY": "k",
            "VENDOR_API_KEY": "k",
            "FORCE_COLOR": "1",
        }
    )
    assert env == {"PATH": "/bin"}


def test_the_network_guard_refuses_and_logs_outbound_connections(
    tmp_path: Path,
) -> None:
    log = tmp_path / "net.log"
    script = (
        "import socket, sys\n"
        "from pathlib import Path\n"
        f"sys.path.insert(0, {str(Path(replay_gate.__file__).parent)!r})\n"
        "from replay_gate import install_network_guard\n"
        f"install_network_guard(Path({str(log)!r}))\n"
        "try:\n"
        "    socket.create_connection(('127.0.0.1', 9), timeout=1)\n"
        "except ConnectionRefusedError as error:\n"
        "    print(error)\n"
        "a, b = socket.socketpair()\n"
        "a.sendall(b'ok'); print(b.recv(2).decode())\n"
    )
    done = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, check=True
    )
    assert "replay gate refused network access" in done.stdout
    assert done.stdout.strip().endswith("ok")
    assert "127.0.0.1" in log.read_text()


def _stage(tmp_path: Path, recorded: Path, exit_code: int = 0) -> Path:
    (recorded.parent / "stage.json").write_text(
        json.dumps(
            {
                "argv": ["/venv/bin/asago-scenario-generator", "generate"]
                + ["--output-dir", "/runs/r1/output"],
                "exit_code": exit_code,
            }
        )
    )
    return recorded


def _copying_runner(recorded: Path, network: list[str] | None = None):
    def run(command: list[str], env: dict[str, str]) -> int:
        output = Path(command[command.index("--output-dir") + 1])
        shutil.copytree(recorded, output)
        if network:
            log = Path(command[command.index("_guarded-run") + 1])
            log.write_text("".join(f"{item}\n" for item in network))
        return 0

    return run


def test_run_gate_passes_an_identical_replay(trees, tmp_path: Path) -> None:
    recorded = _stage(tmp_path, trees[0])
    result = run_gate(
        recorded, work=tmp_path / "work", runner=_copying_runner(recorded)
    )
    assert result.passed, result.differences
    assert result.files_compared == 6


def test_run_gate_fails_a_replay_that_touched_the_network(
    trees, tmp_path: Path
) -> None:
    recorded = _stage(tmp_path, trees[0])
    result = run_gate(
        recorded,
        work=tmp_path / "work",
        runner=_copying_runner(recorded, network=["('10.0.0.1', 443)"]),
    )
    assert not result.passed
    assert result.network_attempts == ["('10.0.0.1', 443)"]


def test_run_gate_fails_when_the_exit_code_differs_from_the_recording(
    trees, tmp_path: Path
) -> None:
    recorded = _stage(tmp_path, trees[0], exit_code=1)
    result = run_gate(
        recorded, work=tmp_path / "work", runner=_copying_runner(recorded)
    )
    assert not result.passed and result.differences == []


def test_cli_reads_run_arguments_after_a_separator(
    trees, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    recorded = trees[0]
    seen: dict[str, Any] = {}

    def fake_gate(path: Path, **kwargs: Any) -> Any:
        seen.update(kwargs, path=path)
        return run_gate(path, runner=_copying_runner(recorded), **kwargs)

    monkeypatch.setattr(replay_gate, "run_gate", fake_gate)
    code = main(
        [
            "check",
            str(recorded),
            "--work-dir",
            str(tmp_path / "work"),
            "--",
            "generate",
            "--output-dir",
            "/runs/r1/output",
        ]
    )
    assert code == 0, capsys.readouterr().out
    assert seen["arguments"] == ["generate", "--output-dir", "/runs/r1/output"]
    assert "PASS" in capsys.readouterr().out


@pytest.fixture
def scratch_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the default temporary directory at an empty folder."""
    root = tmp_path / "scratch-root"
    root.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(root))
    return root


def _gate_with_runner(recorded: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    real_gate = run_gate

    def fake_gate(path: Path, **kwargs: Any) -> Any:
        return real_gate(path, runner=_copying_runner(recorded), **kwargs)

    monkeypatch.setattr(replay_gate, "run_gate", fake_gate)


def test_run_gate_removes_the_scratch_directory_it_created(
    trees, tmp_path: Path, scratch_root: Path
) -> None:
    recorded = _stage(tmp_path, trees[0])
    result = run_gate(recorded, runner=_copying_runner(recorded))
    assert result.passed, result.differences
    assert list(scratch_root.iterdir()) == []


def test_cli_without_a_work_dir_removes_its_scratch_directory(
    trees,
    tmp_path: Path,
    scratch_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    recorded = _stage(tmp_path, trees[0])
    _gate_with_runner(recorded, monkeypatch)
    assert main(["check", str(recorded)]) == 0, capsys.readouterr().out
    assert list(scratch_root.iterdir()) == []
    assert "log:" not in capsys.readouterr().out


def test_cli_failure_without_a_work_dir_says_how_to_keep_the_scratch_files(
    trees,
    tmp_path: Path,
    scratch_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    recorded = _stage(tmp_path, trees[0], exit_code=1)
    _gate_with_runner(recorded, monkeypatch)
    assert main(["check", str(recorded)]) == 1
    assert list(scratch_root.iterdir()) == []
    out = capsys.readouterr().out
    assert "rerun with --work-dir DIR to keep the scratch files" in out
    assert out.splitlines()[-1] == "FAIL"


def test_cli_keeps_the_work_dir_it_was_given(
    trees,
    tmp_path: Path,
    scratch_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    recorded = _stage(tmp_path, trees[0])
    work = tmp_path / "work"
    _gate_with_runner(recorded, monkeypatch)
    assert main(["check", str(recorded), "--work-dir", str(work)]) == 0
    assert (work / "output").is_dir()
    assert f"(log: {work / 'run.log'})" in capsys.readouterr().out
    assert list(scratch_root.iterdir()) == []


def test_prepare_run_requires_a_recorded_output_dir(tmp_path: Path) -> None:
    recorded = tmp_path / "recorded"
    recorded.mkdir()
    (recorded / RECORD_FILENAME).write_text("")
    with pytest.raises(ValueError, match="the recorded arguments have no --output-dir"):
        prepare_run(["generate"], recorded=recorded, work=tmp_path / "work")


@pytest.mark.parametrize(
    ("value", "steps", "expected"),
    [
        ({"a": 1}, (), {"a": 1}),
        ({"a": 1}, ("[]", "a"), {"a": 1}),
        ([{"a": 1}], ("a",), [{"a": 1}]),
        ({"b": 1}, ("a",), {"b": 1}),
        (
            {"a": [{"x": 1, "y": 2}], "b": 3},
            ("a", "[]", "x"),
            {"a": [{"y": 2}], "b": 3},
        ),
    ],
)
def test_drop_field_removes_only_the_named_path(value, steps, expected) -> None:
    assert _drop_field(value, steps) == expected


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        (1, "1", '$: 1 != "1"'),
        ({"a": 1}, {"a": 1, "b": 2}, "$.b: only in replay"),
        ({"a": 1, "b": 2}, {"b": 2, "a": 1}, "$: key order ['a', 'b'] != ['b', 'a']"),
        ([1], [1, 2], "$: length 1 != 2"),
        ([1, {"a": 1}], [1, {"a": 2}], "$[1].a: 1 != 2"),
        ({"a": [1]}, {"a": [1]}, None),
    ],
)
def test_first_difference_names_the_first_differing_path(left, right, expected) -> None:
    assert _first_difference(left, right) == expected


@pytest.mark.parametrize(
    ("recorded", "replayed", "expected"),
    [
        (b"\xff\xfe", b"\xff\xff", "binary content differs"),
        (b"same\n", b"same\nmore\n", "content differs in length"),
    ],
)
def test_compare_file_reports_binary_and_length_differences(
    tmp_path: Path, recorded: bytes, replayed: bytes, expected: str
) -> None:
    left, right = tmp_path / "left.txt", tmp_path / "right.txt"
    left.write_bytes(recorded)
    right.write_bytes(replayed)
    assert compare_file(left, right, "left.txt", {}) == expected


def _effort_report(
    *, lead_seconds: int, row_seconds: int, requests: int = 84, tail: str = ""
) -> str:
    """The generate report's effort section as `report/effort_section.py` renders it."""
    return (
        '<section id="effort"><p><b data-metric="effort.requests" data-value="326">326</b>'
        ' requests, used <b data-metric="effort.tokens" data-value="3281448">3,281,448</b>'
        f' tokens and <b data-metric="effort.seconds" data-value="{lead_seconds}">'
        f"{lead_seconds:,}</b> seconds.</p>"
        '<table id="effort-table"><tbody><tr id="effort-scenario-writing">'
        f'<td>Scenario writing</td><td class="n" data-v="{requests}">{requests}</td>'
        '<td class="n" data-v="31">31</td><td class="n" data-v="1538316">1,538,316</td>'
        f'<td>47%</td><td class="n" data-v="{row_seconds}">{row_seconds:,}</td></tr>'
        '<tr id="effort-other"><td>Other</td><td class="n" data-v="1">1</td>'
        '<td class="n" data-v="0">0</td><td class="n" data-v="15405">15,405</td>'
        '<td>0%</td><td class="n" data-v="0">0</td></tr></tbody></table></section>'
        f"{tail}\n"
    )


def _compare_report(
    tmp_path: Path, recorded: str, replayed: str, name: str
) -> str | None:
    left, right = tmp_path / "recorded.html", tmp_path / "replayed.html"
    left.write_text(recorded, encoding="utf-8")
    right.write_text(replayed, encoding="utf-8")
    return compare_file(left, right, name, {})


def test_replay_seconds_in_the_report_effort_section_are_an_allowed_difference(
    tmp_path: Path,
) -> None:
    # A replayed call's duration is the local lookup time, so a step's summed
    # seconds round to 0 or 1 depending on machine load.
    recorded = _effort_report(lead_seconds=1, row_seconds=1)
    replayed = _effort_report(lead_seconds=0, row_seconds=0)
    assert _compare_report(tmp_path, recorded, replayed, "report/index.html") is None
    large = _effort_report(lead_seconds=1234, row_seconds=1001)
    assert _compare_report(tmp_path, large, replayed, "report/index.html") is None


_OTHER_ROW = '<tr id="other-row"><td class="n" data-v="{0}">{0}</td></tr>'


@pytest.mark.parametrize(
    ("recorded", "replayed", "name"),
    [
        (
            _effort_report(lead_seconds=1, row_seconds=1),
            _effort_report(lead_seconds=1, row_seconds=1, requests=85),
            "report/index.html",
        ),
        (
            _effort_report(lead_seconds=1, row_seconds=1, tail=_OTHER_ROW.format(1)),
            _effort_report(lead_seconds=1, row_seconds=1, tail=_OTHER_ROW.format(2)),
            "report/index.html",
        ),
        (
            _effort_report(lead_seconds=1, row_seconds=1),
            _effort_report(lead_seconds=0, row_seconds=0),
            "other/index.html",
        ),
    ],
    ids=["effort-requests", "last-cell-of-another-table", "another-file"],
)
def test_report_differences_outside_the_effort_seconds_still_fail(
    tmp_path: Path, recorded: str, replayed: str, name: str
) -> None:
    assert _compare_report(tmp_path, recorded, replayed, name) is not None


def test_the_report_lists_network_attempts_and_differences(tmp_path: Path) -> None:
    result = GateResult(
        tmp_path / "recorded",
        tmp_path / "replayed",
        0,
        1.0,
        network_attempts=["('10.0.0.1', 443)", "resolve example.com"],
        differences=[Difference("a.yaml", "$.x: 1 != 2"), Difference("b", "only")],
    )
    lines = _report(result, tmp_path / "work", 1).splitlines()
    assert lines[5:] == [
        "network:   2 refused attempt(s)",
        "  ('10.0.0.1', 443)",
        "differences: 2 file(s)",
        "  a.yaml: $.x: 1 != 2",
        "FAIL",
    ]
