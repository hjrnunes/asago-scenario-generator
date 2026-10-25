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
    EXPECTED_FILE_DIFFERENCES,
    Difference,
    GateResult,
    _drop_field,
    _expected_replay_miss_exit,
    _first_difference,
    _report,
    compare_file,
    compare_trees,
    main,
    prepare_run,
    replay_environment,
    run_gate,
)
from asago_scenario_generator.stpa.infra.provider_record import (
    RECORD_FILENAME,
    request_digest,
)


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


def _obligation_plan_from_paths(root: Path, *paths: list[dict[str, Any]]) -> None:
    obligations = [
        {
            "evidence": [
                {
                    "kind": "mapping",
                    "detail": json.dumps({"path": path}, separators=(",", ":")),
                }
            ]
        }
        for path in paths
    ]
    (root / "taxonomy-obligation-plan.yaml").write_text(
        yaml.safe_dump({"obligations": obligations}), encoding="utf-8"
    )


def _obligation_plan(root: Path, *edges: tuple[str, str]) -> None:
    _obligation_plan_from_paths(
        root,
        *(
            [
                {
                    "relation": "realized_by",
                    "source_id": source,
                    "target_id": target,
                }
            ]
            for source, target in edges
        ),
    )


def _strict_provider_record(
    sequence: int,
    *,
    outcome: str = "response",
    stage: str = "synthesis_obligation_aware_routing",
) -> dict[str, Any]:
    identity = {
        "stage": stage,
        "step": "initial-batch-1",
        "slot_id": None,
        "scenario_id": None,
        "attempt_number": 1,
    }
    request = {
        "api": "chat.completions.create",
        "model": "model",
        "messages": [{"role": "user", "content": f"request {sequence}"}],
        "parameters": {},
    }
    digest = request_digest(request)
    error = (
        {
            "type": "ReplayMissError",
            "message": f"no recorded response for request {digest} issued by {identity}",
            "status_code": None,
        }
        if outcome == "error"
        else None
    )
    return {
        "kind": "provider-call-record-v1",
        "sequence": sequence,
        "identity": identity,
        "request": request,
        "request_sha256": digest,
        "outcome": outcome,
        "response": None if error else {"body": "answer"},
        "error": error,
        "local_rejection": None,
        "timestamp": "now",
        "duration_ms": 0,
    }


def _expected_replay_miss(recorded: Path, replayed: Path) -> None:
    response = _strict_provider_record(1)
    _jsonl(recorded / RECORD_FILENAME, [response])
    _jsonl(
        replayed / RECORD_FILENAME,
        [response, _strict_provider_record(2, outcome="error")],
    )


def _strict_call(sequence: int, digest: str, *, success: bool) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "stage": "synthesis_obligation_aware_routing",
        "step": "initial-batch-1",
        "slot_id": None,
        "scenario_id": None,
        "attempt_number": 1,
        "provider_requests": [{"sequence": sequence, "request_sha256": digest}],
        "success": success,
        "response_parsed": success,
    }
    if not success:
        entry.update(
            terminal_error_codes=["provider_call_failure"],
            error="ReplayMissError: no recorded response",
        )
    return entry


def test_expected_files_change_for_only_the_named_edge_removal(trees) -> None:
    recorded, replayed, path_map = trees
    kept = ("LLM01", "AP-T2-02")
    removed = ("LLM02", "AP-T2-02")
    _obligation_plan(recorded, kept, removed)
    _obligation_plan(replayed, kept)
    _expected_replay_miss(recorded, replayed)
    for root, value in ((recorded, 1), (replayed, 2)):
        (root / "condition-families.yaml").write_text(
            yaml.safe_dump({"value": value}), encoding="utf-8"
        )
    expected: list[Difference] = []

    _, differences = compare_trees(
        recorded, replayed, path_map, expected_differences=expected
    )

    assert differences == []
    assert [item.path for item in expected] == [
        "condition-families.yaml",
        "provider-calls.jsonl",
        "taxonomy-obligation-plan.yaml",
    ]


def test_expected_files_do_not_hide_another_edge_change(trees) -> None:
    recorded, replayed, path_map = trees
    _obligation_plan(recorded, ("LLM01", "AP-T2-02"), ("LLM02", "AP-T2-02"))
    _obligation_plan(replayed)
    for root, value in ((recorded, 1), (replayed, 2)):
        (root / "condition-families.yaml").write_text(
            yaml.safe_dump({"value": value}), encoding="utf-8"
        )

    _, differences = compare_trees(recorded, replayed, path_map)

    assert {item.path for item in differences} == {
        "condition-families.yaml",
        "taxonomy-obligation-plan.yaml",
    }


def test_expected_files_do_not_hide_a_related_match_change(trees) -> None:
    recorded, replayed, path_map = trees
    kept = [
        {
            "relation": "skos:relatedMatch",
            "source": "sssom",
            "source_id": "risk-1",
            "target_id": "LLM01",
            "evidence": ["mapping.tsv"],
        },
        {
            "relation": "realized_by",
            "source": "cross-taxonomy",
            "source_id": "LLM01",
            "target_id": "AP-T2-02",
            "evidence": ["llm-to-attack-pattern.yaml"],
        },
    ]
    changed = json.loads(json.dumps(kept))
    changed[0]["relation"] = "skos:closeMatch"
    removed = [
        {
            "relation": "realized_by",
            "source_id": "LLM02",
            "target_id": "AP-T2-02",
        }
    ]
    _obligation_plan_from_paths(recorded, kept, removed)
    _obligation_plan_from_paths(replayed, changed)
    _expected_replay_miss(recorded, replayed)

    _, differences = compare_trees(recorded, replayed, path_map)

    assert "taxonomy-obligation-plan.yaml" in {item.path for item in differences}


@pytest.mark.parametrize("field", ["source", "evidence"])
def test_expected_files_do_not_hide_kept_edge_provenance_changes(
    trees, field: str
) -> None:
    recorded, replayed, path_map = trees
    kept = [
        {
            "relation": "realized_by",
            "source": "cross-taxonomy",
            "source_id": "LLM01",
            "target_id": "AP-T2-02",
            "evidence": ["llm-to-attack-pattern.yaml"],
        }
    ]
    changed = json.loads(json.dumps(kept))
    changed[0][field] = "other" if field == "source" else ["other.yaml"]
    removed = [
        {
            "relation": "realized_by",
            "source_id": "LLM02",
            "target_id": "AP-T2-02",
        }
    ]
    _obligation_plan_from_paths(recorded, kept, removed)
    _obligation_plan_from_paths(replayed, changed)
    _expected_replay_miss(recorded, replayed)

    _, differences = compare_trees(recorded, replayed, path_map)

    assert "taxonomy-obligation-plan.yaml" in {item.path for item in differences}


def test_expected_files_do_not_hide_integrity_failures(trees) -> None:
    recorded, replayed, path_map = trees
    _obligation_plan(recorded, ("LLM02", "AP-T2-02"))
    _obligation_plan(replayed)
    _expected_replay_miss(recorded, replayed)
    _calls(replayed, _new_call("A", 7), _new_call("B", 1))

    _, differences = compare_trees(recorded, replayed, path_map)

    assert [item.path for item in differences] == ["calls.jsonl"]
    assert "names no record" in differences[0].detail


def test_expected_miss_link_does_not_hide_another_broken_call_link(trees) -> None:
    recorded, replayed, path_map = trees
    _obligation_plan(recorded, ("LLM02", "AP-T2-02"))
    _obligation_plan(replayed)
    _expected_replay_miss(recorded, replayed)
    provider_records = [
        json.loads(line)
        for line in (replayed / RECORD_FILENAME).read_text().splitlines()
    ]
    first = _strict_call(1, provider_records[0]["request_sha256"], success=True)
    broken = json.loads(json.dumps(first))
    broken["provider_requests"][0]["sequence"] = 7
    miss = _strict_call(2, provider_records[1]["request_sha256"], success=False)
    _calls(recorded, first)
    _calls(replayed, broken, miss)

    _, differences = compare_trees(recorded, replayed, path_map)

    assert [item.path for item in differences] == ["calls.jsonl"]
    assert "names no record" in differences[0].detail


def test_expected_provider_difference_requires_a_valid_replay_miss(trees) -> None:
    recorded, replayed, path_map = trees
    _obligation_plan(recorded, ("LLM02", "AP-T2-02"))
    _obligation_plan(replayed)
    _expected_replay_miss(recorded, replayed)
    records = [
        json.loads(line)
        for line in (replayed / RECORD_FILENAME).read_text().splitlines()
    ]
    records[1]["request_sha256"] = "0" * 64
    _jsonl(replayed / RECORD_FILENAME, records)

    _, differences = compare_trees(recorded, replayed, path_map)

    assert [item.path for item in differences] == [RECORD_FILENAME]


def test_expected_provider_difference_does_not_hide_changed_responses(trees) -> None:
    recorded, replayed, path_map = trees
    _obligation_plan(recorded, ("LLM02", "AP-T2-02"))
    _obligation_plan(replayed)
    _expected_replay_miss(recorded, replayed)
    records = [
        json.loads(line)
        for line in (replayed / RECORD_FILENAME).read_text().splitlines()
    ]
    records[0]["response"]["body"] = "different"
    _jsonl(replayed / RECORD_FILENAME, records)

    _, differences = compare_trees(recorded, replayed, path_map)

    assert [item.path for item in differences] == [RECORD_FILENAME]


def test_only_named_downstream_files_may_be_absent_after_the_edge_removal(
    trees,
) -> None:
    recorded, replayed, path_map = trees
    _obligation_plan(recorded, ("LLM02", "AP-T2-02"))
    _obligation_plan(replayed)
    _expected_replay_miss(recorded, replayed)
    (replayed / "scenarios" / "SCN-001.feature").unlink()
    (recorded / "unrelated.yaml").write_text("value: 1\n")
    expected: list[Difference] = []

    _, differences = compare_trees(
        recorded, replayed, path_map, expected_differences=expected
    )

    assert "scenarios/SCN-001.feature" in {item.path for item in expected}
    assert [str(item) for item in differences] == ["unrelated.yaml: only in recording"]


def test_expected_edge_removal_accepts_only_its_replay_miss_exit(trees) -> None:
    recorded, replayed, path_map = trees
    _obligation_plan(recorded, ("LLM02", "AP-T2-02"))
    _obligation_plan(replayed)
    _expected_replay_miss(recorded, replayed)
    run_log = replayed.parent / "run.log"
    run_log.write_text(
        "Error: 1 request(s) had no recorded response: [request]\n",
        encoding="utf-8",
    )

    accepted = _expected_replay_miss_exit(recorded, replayed, path_map, run_log, 1, 0)

    assert accepted == "1 expected replay miss(es) after the obligation-plan change"


@pytest.mark.parametrize(
    "line",
    [
        "Error: unrelated failure\n",
        "Error: 2 request(s) had no recorded response: [request]\n",
    ],
)
def test_expected_edge_removal_does_not_hide_other_exit_failures(
    trees, line: str
) -> None:
    recorded, replayed, path_map = trees
    _obligation_plan(recorded, ("LLM02", "AP-T2-02"))
    _obligation_plan(replayed)
    _expected_replay_miss(recorded, replayed)
    run_log = replayed.parent / "run.log"
    run_log.write_text(line, encoding="utf-8")

    accepted = _expected_replay_miss_exit(recorded, replayed, path_map, run_log, 1, 0)

    assert accepted is None


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


def _old_call(scenario: str = "A", *, published: bool = False) -> dict[str, Any]:
    """A call entry as calls.jsonl held it before naming provider records."""
    return {
        "stage": "s",
        "step": "x",
        "scenario_id": scenario,
        "system_prompt_hash": "h",
        "system_prompt_text": "system",
        "user_prompt_text": "user",
        "timestamp": "t1",
        "attempt_id": f"s:x:{scenario}:1",
        "compiled": published,
        "published": published,
        "raw_response": "{}",
        "cleaned_response": {},
        "response_content": "{}",
    }


def _new_call(scenario: str, *sequences: int, digest: str = "d" * 64) -> dict[str, Any]:
    """The same call as calls.jsonl holds it now, naming its provider records."""
    return {
        "stage": "s",
        "step": "x",
        "scenario_id": scenario,
        "system_prompt_hash": "h",
        "provider_requests": [
            {"sequence": sequence, "request_sha256": digest} for sequence in sequences
        ],
        "response_parsed": True,
        "timestamp": "t2",
        "attempt_id": f"s:x:{scenario}:1",
        "compiled": False,
        "published": False,
    }


# The recording holds scenario A's provider record as sequence 1 and B's as
# 2; the replay, whose requests arrived in the other order, holds them as 2
# and 1.
def _recorded_calls(call: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    return [call or _new_call("A", 1), _new_call("B", 2)]


def _replayed_calls(call: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    return [call or _new_call("A", 2), _new_call("B", 1)]


_PUBLISHED = {"kind": "call-published", "attempt_id": "s:x:A:1"}


def _calls(root: Path, *records: dict[str, Any]) -> None:
    _jsonl(root / "calls.jsonl", list(records))


def _call_differences(
    trees: tuple[Path, Path, dict[str, str]],
    recorded_calls: list[dict[str, Any]],
    replayed_calls: list[dict[str, Any]],
) -> list[str]:
    recorded, replayed, path_map = trees
    _calls(recorded, *recorded_calls)
    _calls(replayed, *replayed_calls)
    _, differences = compare_trees(recorded, replayed, path_map)
    return [str(d) for d in differences]


def test_a_recording_with_call_text_matches_a_replay_naming_provider_records(
    trees,
) -> None:
    old = [_old_call("A", published=True), _old_call("B")]
    assert _call_differences(trees, old, [*_replayed_calls(), _PUBLISHED]) == []


def test_a_publication_the_recording_lacks_is_a_difference(trees) -> None:
    old = [_old_call("A"), _old_call("B")]
    assert _call_differences(trees, old, [*_replayed_calls(), _PUBLISHED]) == [
        "calls.jsonl: $[0].compiled: false != true"
    ]


def test_links_that_resolve_on_each_side_match_across_sequence_numbers(
    trees,
) -> None:
    assert _call_differences(trees, _recorded_calls(), _replayed_calls()) == []


@pytest.mark.parametrize(
    ("call", "detail"),
    [
        (_new_call("A", 2, digest="e" * 64), "names no record"),
        (_new_call("A", 7), "names no record"),
        (_new_call("A", 1), "names the record of another call"),
    ],
    ids=["wrong-digest", "unknown-sequence", "other-call"],
)
def test_a_corrupted_link_fails_the_gate(
    trees, call: dict[str, Any], detail: str
) -> None:
    (difference,) = _call_differences(
        trees, _recorded_calls(), _replayed_calls(call=call)
    )

    assert difference.startswith("calls.jsonl: replay $[0].provider_requests")
    assert detail in difference


def test_a_corrupted_link_in_the_recording_fails_the_gate(trees) -> None:
    (difference,) = _call_differences(
        trees, _recorded_calls(call=_new_call("A", 7)), _replayed_calls()
    )

    assert difference.startswith("calls.jsonl: recording $[0]")


def test_a_missing_link_between_new_entries_is_a_difference(trees) -> None:
    assert _call_differences(
        trees, _recorded_calls(), [_new_call("A"), _new_call("B", 1)]
    ) == ["calls.jsonl: $[0].provider_requests: length 1 != 0"]


def test_a_provider_record_that_no_call_names_passes(trees) -> None:
    recorded, replayed, _ = trees
    for root, order in ((recorded, ("A", "B")), (replayed, ("B", "A"))):
        records = [
            _provider_call(n, scenario, f"for {scenario}")
            for n, scenario in enumerate(order, 1)
        ]
        records.append(_provider_call(3, "C", "interrupted"))
        _jsonl(root / RECORD_FILENAME, records)

    assert _call_differences(trees, _recorded_calls(), _replayed_calls()) == []


def test_a_log_mixing_old_and_current_entries_passes(trees) -> None:
    assert (
        _call_differences(
            trees,
            [_old_call("A"), _new_call("B", 2)],
            [_old_call("A"), _new_call("B", 1)],
        )
        == []
    )


def test_an_unlinked_entry_without_a_provider_record_passes(trees) -> None:
    recorded, replayed, _ = trees
    for root in (recorded, replayed):
        (root / RECORD_FILENAME).unlink()
    unlinked = dict(_old_call("A"), provider_requests=[])

    assert _call_differences(trees, [unlinked], [unlinked]) == []


def test_a_record_named_by_two_calls_is_a_difference(trees) -> None:
    assert _call_differences(
        trees, _recorded_calls(), [_new_call("A", 2), dict(_new_call("A", 2))]
    ) == [
        "calls.jsonl: replay $[1].provider_requests names record 2, "
        "which $[0] names too"
    ]


def test_a_replay_that_kept_text_instead_of_links_is_a_difference(trees) -> None:
    unlinked = dict(_old_call("A"), provider_requests=[])
    differences = _call_differences(
        trees, _recorded_calls(), [unlinked, _new_call("B", 1)]
    )

    assert differences == ["calls.jsonl: $[0].cleaned_response: only in replay"]


def test_a_changed_parse_flag_between_new_entries_is_a_difference(trees) -> None:
    flipped = dict(_new_call("A", 2), response_parsed=False)
    assert _call_differences(
        trees, _recorded_calls(), _replayed_calls(call=flipped)
    ) == ["calls.jsonl: $[0].response_parsed: true != false"]


def _retry_records(root: Path) -> None:
    """Scenario A's request, its transport retry, then scenario B's request."""
    first, retry, other = (
        _provider_call(1, "A", "failed"),
        _provider_call(2, "A", "for A"),
        _provider_call(3, "B", "for B"),
    )
    retry["retry_of"] = {"type": "APIConnectionError", "status_code": None}
    _jsonl(root / RECORD_FILENAME, [first, retry, other])


@pytest.mark.parametrize(
    ("links", "expected"),
    [
        ((1, 2), []),
        (
            (2, 1),
            [
                "calls.jsonl: replay $[0].provider_requests [2, 1] does not rise "
                "in sequence without repeats"
            ],
        ),
        (
            (1, 1),
            [
                "calls.jsonl: replay $[0].provider_requests [1, 1] does not rise "
                "in sequence without repeats"
            ],
        ),
    ],
    ids=["in-order", "reversed", "duplicated"],
)
def test_retry_links_name_each_record_once_in_order(
    trees, links: tuple[int, ...], expected: list[str]
) -> None:
    recorded, replayed, _ = trees
    _retry_records(recorded)
    _retry_records(replayed)

    differences = _call_differences(
        trees,
        [_new_call("A", 1, 2), _new_call("B", 3)],
        [_new_call("A", *links), _new_call("B", 3)],
    )

    assert differences == expected


def _manifest_with_call_evidence(run_id: str, created_at: str) -> dict[str, Any]:
    return _manifest(
        run_id, created_at, call_evidence=[{"step": "a", "duration_ms": 3}]
    )


def test_a_recording_whose_manifest_copies_the_call_records_still_matches(
    trees,
) -> None:
    recorded, replayed, path_map = trees
    _write_manifest(
        recorded,
        _manifest_with_call_evidence(
            "synthesis-20261001T000000Z", "2026-10-01T00:00:00"
        ),
    )

    _, differences = compare_trees(recorded, replayed, path_map)

    assert differences == []


@pytest.mark.parametrize("recording_has_it", [True, False])
def test_a_replay_that_writes_the_retired_call_copy_fails(
    trees, recording_has_it: bool
) -> None:
    recorded, replayed, path_map = trees
    if recording_has_it:
        _write_manifest(
            recorded,
            _manifest_with_call_evidence(
                "synthesis-20261001T000000Z", "2026-10-01T00:00:00"
            ),
        )
    _write_manifest(
        replayed,
        _manifest_with_call_evidence(
            "synthesis-20261002T111111Z", "2026-10-02T11:11:11.5"
        ),
    )

    _, differences = compare_trees(recorded, replayed, path_map)

    assert [d.path for d in differences] == ["synthesis-manifest.yaml"]
    assert differences[0].detail.startswith("replay writes prompt_call_evidence")


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
    for expected in EXPECTED_FILE_DIFFERENCES:
        assert expected.source_id and expected.target_id
        assert expected.files and len(expected.files) == len(set(expected.files))
        assert expected.recording_only_files
        assert len(expected.recording_only_files) == len(
            set(expected.recording_only_files)
        )
        assert expected.allowed_stages
        assert expected.reason


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


def _versions(root: Path, files: dict[str, dict[str, Any]]) -> None:
    for name, document in files.items():
        (root / name).write_text(yaml.safe_dump(document))


def test_version_chains_compare_their_distinct_versions_not_their_names(
    trees,
) -> None:
    """A recording made before versions were skipped still matches."""
    recorded, replayed, path_map = trees
    draft, reviewed, bound = {"v": "draft"}, {"v": "reviewed"}, {"v": "bound"}
    # The recording wrote every step that ran; the replay writes a version
    # only when it differs from the next one.
    _versions(
        recorded,
        {
            "control-structure-draft.yaml": draft,
            "control-structure-reviewed.yaml": reviewed,
            "control-structure-revised.yaml": reviewed,
            "control-structure-placed.yaml": bound,
            "control-structure.yaml": bound,
        },
    )
    _versions(
        replayed,
        {
            "control-structure-draft.yaml": draft,
            "control-structure-revised.yaml": reviewed,
            "control-structure.yaml": bound,
        },
    )

    _, differences = compare_trees(recorded, replayed, path_map)

    assert differences == []


def test_a_version_chain_with_other_content_fails(trees) -> None:
    recorded, replayed, path_map = trees
    _versions(
        recorded,
        {"loss-analysis-draft.yaml": {"v": 1}, "loss-analysis.yaml": {"v": 2}},
    )
    _versions(replayed, {"loss-analysis.yaml": {"v": 2}})

    _, differences = compare_trees(recorded, replayed, path_map)

    assert [str(d) for d in differences] == [
        "loss-analysis.yaml versions: recording holds 2 distinct versions, "
        "replay 1; they first differ at version 1"
    ]


def test_copies_of_inputs_may_be_only_in_the_recording(trees) -> None:
    recorded, replayed, path_map = trees
    for name in (
        "observation-contract.yaml",
        "execution-target-profile.json",
        "target-evidence.yaml",
    ):
        (recorded / name).write_text("{}\n")

    _, differences = compare_trees(recorded, replayed, path_map)

    assert differences == []


def _run_manifest(root: Path, target_evidence: dict[str, Any]) -> None:
    document = yaml.safe_load((root / "run-manifest.yaml").read_text())
    document["stage_summary"] = {"stage_1a": {"target_evidence": target_evidence}}
    (root / "run-manifest.yaml").write_text(yaml.safe_dump(document))


def test_a_recorded_retired_field_is_compared_without_it(trees) -> None:
    recorded, replayed, path_map = trees
    _run_manifest(recorded, {"artifact": "target-evidence.yaml", "operations": 3})
    _run_manifest(replayed, {"operations": 3})

    _, differences = compare_trees(recorded, replayed, path_map)

    assert differences == []


def test_a_replay_that_writes_a_retired_field_fails(trees) -> None:
    recorded, replayed, path_map = trees
    _run_manifest(recorded, {"artifact": "target-evidence.yaml", "operations": 3})
    _run_manifest(replayed, {"artifact": "target-evidence.yaml", "operations": 3})

    _, differences = compare_trees(recorded, replayed, path_map)

    assert [d.path for d in differences] == ["run-manifest.yaml"]
    assert "stage_summary.stage_1a.target_evidence.artifact" in differences[0].detail


def _testability(root: Path, **blocks: Any) -> None:
    document = {"summary": {"total": 0}, **blocks}
    (root / "testability.yaml").write_text(yaml.safe_dump(document))


_NO_SPLITS = {"direct": 0, "indirect": 0, "forged_transcript": 0}


def test_a_recording_without_an_added_field_is_compared_without_it(trees) -> None:
    recorded, replayed, path_map = trees
    _testability(recorded)
    _testability(replayed, channel_splits=_NO_SPLITS)

    _, differences = compare_trees(recorded, replayed, path_map)

    assert differences == []


def test_an_added_field_a_recording_holds_is_compared(trees) -> None:
    recorded, replayed, path_map = trees
    _testability(recorded, channel_splits=_NO_SPLITS)
    _testability(replayed, channel_splits=dict(_NO_SPLITS, indirect=1))

    _, differences = compare_trees(recorded, replayed, path_map)

    assert [d.path for d in differences] == ["testability.yaml"]
    assert "channel_splits" in differences[0].detail


def test_a_replay_that_drops_an_added_field_a_recording_holds_fails(trees) -> None:
    recorded, replayed, path_map = trees
    _testability(recorded, channel_splits=_NO_SPLITS)
    _testability(replayed)

    _, differences = compare_trees(recorded, replayed, path_map)

    assert [d.path for d in differences] == ["testability.yaml"]


def test_an_added_field_does_not_excuse_other_differences(trees) -> None:
    recorded, replayed, path_map = trees
    _testability(recorded)
    (replayed / "testability.yaml").write_text(
        yaml.safe_dump({"summary": {"total": 1}, "channel_splits": _NO_SPLITS})
    )

    _, differences = compare_trees(recorded, replayed, path_map)

    assert [d.path for d in differences] == ["testability.yaml"]
    assert "summary.total" in differences[0].detail


_TARGET_PROFILE_ROW = (
    '<tr><td>Target profile</td><td><a class="artifact" '
    'href="../execution-target-profile.json">execution-target-profile.json</a>'
    "</td><td></td><td><code>execution-target-profile-v1</code></td>"
    "<td>Operations and state the target exposes.</td></tr>"
)


def _report_page(root: Path, rows: str) -> None:
    (root / "report").mkdir(exist_ok=True)
    (root / "report" / "index.html").write_text(f"<table>{rows}<tr></tr></table>\n")


def test_a_recorded_report_row_the_replay_no_longer_writes_is_removed(
    trees,
) -> None:
    recorded, replayed, path_map = trees
    _report_page(recorded, _TARGET_PROFILE_ROW)
    _report_page(replayed, "")

    _, differences = compare_trees(recorded, replayed, path_map)

    assert differences == []


def test_a_replay_that_writes_a_removed_report_row_fails(trees) -> None:
    recorded, replayed, path_map = trees
    _report_page(recorded, _TARGET_PROFILE_ROW)
    _report_page(replayed, _TARGET_PROFILE_ROW + "<tr>x</tr>")

    _, differences = compare_trees(recorded, replayed, path_map)

    assert [d.path for d in differences] == ["report/index.html"]
    assert "target profile" in differences[0].detail


# The fixed stop-reason order changes accounting outputs, not requests.

_STOP_PIN_DIGEST = "e" * 64


def _routed_accounting(
    mechanism: str = "absent_from_system", alignment: str = "supported"
) -> tuple[Any, Any, Any]:
    """Return a plan, its consideration, and the current accounting of one route."""
    from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
    from asago_scenario_generator.models.obligation_consideration import (
        ObligationRoute,
        ObligationSemanticAssessment,
    )
    from asago_scenario_generator.pipeline.obligation_consideration import (
        build_neutral_briefs,
    )
    from tests.helpers.governance import _plan_with_non_stpa_rows
    from tests.helpers.projection_factory import get_test_raw_pattern

    plan = _plan_with_non_stpa_rows()
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    briefs = build_neutral_briefs(plan, (pattern,))
    route = ObligationRoute(
        obligation_id=briefs[0].obligation_id,
        disposition="proposed_not_applicable",
        semantic_assessment=ObligationSemanticAssessment(
            mechanism_assessment=mechanism,
            risk_alignment=alignment,
            mapping_strength="broad_category_expansion",
            mechanism_rationale="The mechanism judgement.",
            risk_alignment_rationale="The alignment judgement.",
        ),
        rationale="The routing rationale.",
        evidence=("route evidence",),
    )
    return (plan, *_considered(plan, briefs, (route,)))


def _considered(plan: Any, briefs: Any, routes: tuple[Any, ...]) -> tuple[Any, Any]:
    """Return the consideration and the current accounting of *routes*."""
    from asago_scenario_generator.pipeline.obligation_consideration import (
        build_consideration_artifact,
        build_obligation_accounting,
    )
    from tests.helpers.governance import _accounting_pins

    consideration = build_consideration_artifact(
        plan=plan, briefs=briefs, initial_routes=routes, final_routes=routes
    )
    accounting = build_obligation_accounting(
        plan=plan,
        consideration=consideration,
        ica_considerations=(),
        source_pins=_accounting_pins(plan),
    )
    return consideration, accounting


def _row_as_recorded(accounting: Any, obligation_id: str, **fields: Any) -> Any:
    """Rewrite one row as an earlier order wrote it, with a fresh digest."""
    from asago_scenario_generator.models.obligation_accounting import (
        ObligationAccounting,
        ObligationAccountingRow,
        derive_obligation_accounting_summary,
    )

    rows = tuple(
        ObligationAccountingRow.model_validate({**row.model_dump(), **fields})
        if row.obligation_id == obligation_id
        else row
        for row in accounting.rows
    )
    values = accounting.model_dump(exclude={"semantic_digest"})
    values.update(rows=rows, summary=derive_obligation_accounting_summary(rows))
    return ObligationAccounting.model_validate(values)


def _old_mechanism_absent_row(accounting: Any) -> tuple[str, dict[str, Any]]:
    row = next(row for row in accounting.rows if row.stop_reason == "mechanism_absent")
    diagnostic = row.diagnostics[0].model_copy(
        update={
            "code": "incomplete_non_applicability",
            "detail": "every routed slot must have explicit structural N/A evidence",
        }
    )
    return row.obligation_id, {
        "stop_reason": "not_applicable_evidence_incomplete",
        "diagnostics": (diagnostic,),
    }


def _realization(accounting: Any) -> Any:
    from asago_scenario_generator.models.artifact_pin import ArtifactPin
    from asago_scenario_generator.models.scenario_realization import (
        ScenarioRealizationAssessment,
    )

    pins = (
        ("obligation-accounting", "stpa-obligation-accounting-v1"),
        ("ica-enumeration", "ica-enumeration-v1"),
        ("stpa-scenario-collection", "stpa-scenario-collection-v1"),
    )
    return ScenarioRealizationAssessment(
        source_pins=tuple(
            ArtifactPin(
                artifact_id=artifact_id,
                schema_version=schema,
                semantic_digest=(
                    accounting.semantic_digest
                    if artifact_id == "obligation-accounting"
                    else _STOP_PIN_DIGEST
                ),
            )
            for artifact_id, schema in pins
        ),
        records=(),
        summary={"total": 0, "realized": 0, "unresolved": 0, "not_requested": 0},
    )


def _accounting_manifest(
    root: Path, plan: Any, accounting: Any, realization: Any
) -> None:
    from types import SimpleNamespace

    from asago_scenario_generator.pipeline.synthesis_manifest import (
        _obligation_resolution_funnel,
        _obligation_scope_summary,
        _obligation_stop_reason_counts,
        _summary_dict,
    )

    document = yaml.safe_load((root / "synthesis-manifest.yaml").read_text())
    document.pop("semantic_digest")
    records = SimpleNamespace(records=realization.records)
    document.update(
        schema_version="synthesis-manifest-v1",
        run_status="completed",
        source_artifacts={
            "obligation_accounting": {
                "artifact_id": "obligation-accounting",
                "schema_version": "stpa-obligation-accounting-v1",
                "semantic_digest": accounting.semantic_digest,
            },
            "scenario_realization": {
                "artifact_id": "scenario-realization",
                "schema_version": "stpa-scenario-realization-v1",
                "semantic_digest": realization.semantic_digest,
            },
        },
        obligation_disposition_counts=_summary_dict(accounting.summary),
        obligation_stop_reason_counts=_obligation_stop_reason_counts(
            accounting, records
        ),
        obligation_resolution_funnel=_obligation_resolution_funnel(
            plan=plan, accounting=accounting, realization=records, scenario_count=0
        ),
        obligation_scope_summary=_obligation_scope_summary(
            plan=plan,
            accounting=accounting,
            realization=records,
            risk_actionability=None,
        ),
    )
    document["semantic_digest"] = _digest_payload(_MANIFEST_DOMAIN, document)
    _write_manifest(root, document)


def _obligation_report(
    root: Path, section: str | None = None, *, other: str = "same"
) -> None:
    """Write a report whose obligations section is *section*, or as rendered."""
    from asago_scenario_generator.report.obligation_section import (
        obligation_section,
    )
    from asago_scenario_generator.report.run_data import load_run

    if section is None:
        section = str(obligation_section(load_run(root)))
    (root / "report").mkdir(exist_ok=True)
    (root / "report" / "index.html").write_text(
        f'{section}\n<section id="failed"><h2>F</h2>{other}</section>\n'
    )


def _obligations_section(root: Path) -> str:
    text = (root / "report" / "index.html").read_text()
    return text[: text.index("</section>") + len("</section>")]


def _write_accounting_run(
    root: Path, plan: Any, consideration: Any, accounting: Any
) -> None:
    realization = _realization(accounting)
    # The report reads the call log; both sides log the same call.
    _jsonl(root / "calls.jsonl", [{"stage": "s", "step": "a", "success": True}])
    (root / "taxonomy-obligation-plan.yaml").write_text(plan.to_yaml())
    (root / "obligation-accounting.yaml").write_text(accounting.to_yaml())
    (root / "obligation-consideration.yaml").write_text(
        yaml.safe_dump(consideration.model_dump(mode="json"))
    )
    (root / "scenario-realization.yaml").write_text(realization.to_yaml())
    _accounting_manifest(root, plan, accounting, realization)
    _obligation_report(root)


@pytest.fixture
def stop_order_trees(trees) -> tuple[Path, Path, dict[str, str]]:
    """A recording made before the stop order and its replay through it."""
    recorded, replayed, path_map = trees
    plan, consideration, current = _routed_accounting()
    obligation_id, old_fields = _old_mechanism_absent_row(current)
    before = _row_as_recorded(current, obligation_id, **old_fields)
    _write_accounting_run(recorded, plan, consideration, before)
    _write_accounting_run(replayed, plan, consideration, current)
    return recorded, replayed, path_map


_STOP_ORDER_FILES = [
    "obligation-accounting.yaml",
    "report/index.html",
    "scenario-realization.yaml",
    "synthesis-manifest.yaml",
]


def test_the_stop_order_accepts_only_its_accounting_outputs(stop_order_trees) -> None:
    recorded, replayed, path_map = stop_order_trees
    expected: list[Difference] = []

    _, differences = compare_trees(
        recorded, replayed, path_map, expected_differences=expected
    )

    assert differences == []
    assert sorted(item.path for item in expected) == _STOP_ORDER_FILES


def test_the_stop_order_accepts_a_deduplicated_verifier_diagnostic(trees) -> None:
    recorded, replayed, path_map = trees
    plan, consideration, current = _routed_accounting()
    obligation_id, _ = _old_mechanism_absent_row(current)
    row = next(row for row in current.rows if row.obligation_id == obligation_id)
    before = _row_as_recorded(
        current, obligation_id, diagnostics=(row.diagnostics[0],) * 2
    )
    _write_accounting_run(recorded, plan, consideration, before)
    _write_accounting_run(replayed, plan, consideration, current)

    _, differences = compare_trees(recorded, replayed, path_map)

    assert differences == []


def test_the_stop_order_does_not_hide_a_request_difference(stop_order_trees) -> None:
    recorded, replayed, path_map = stop_order_trees
    records = [_provider_call(1, "A", "for A"), _provider_call(2, "B", "changed")]
    _jsonl(replayed / RECORD_FILENAME, records)

    _, differences = compare_trees(recorded, replayed, path_map)

    assert [item.path for item in differences] == [RECORD_FILENAME]


def test_the_stop_order_does_not_hide_another_accounting_field(trees) -> None:
    recorded, replayed, path_map = trees
    plan, consideration, current = _routed_accounting()
    obligation_id, old_fields = _old_mechanism_absent_row(current)
    before = _row_as_recorded(
        current, obligation_id, evidence=("other evidence",), **old_fields
    )
    _write_accounting_run(recorded, plan, consideration, before)
    _write_accounting_run(replayed, plan, consideration, current)

    _, differences = compare_trees(recorded, replayed, path_map)

    assert sorted(item.path for item in differences) == _STOP_ORDER_FILES


def test_the_stop_order_does_not_hide_a_reason_the_route_does_not_derive(
    trees,
) -> None:
    recorded, replayed, path_map = trees
    plan, consideration, current = _routed_accounting()
    obligation_id, old_fields = _old_mechanism_absent_row(current)
    row = next(row for row in current.rows if row.obligation_id == obligation_id)
    wrong = row.diagnostics[0].model_copy(
        update={"code": "mechanism_path_unsubstantiated"}
    )
    after = _row_as_recorded(
        current,
        obligation_id,
        stop_reason="mechanism_path_unsubstantiated",
        diagnostics=(wrong,),
    )
    before = _row_as_recorded(current, obligation_id, **old_fields)
    _write_accounting_run(recorded, plan, consideration, before)
    _write_accounting_run(replayed, plan, consideration, after)

    _, differences = compare_trees(recorded, replayed, path_map)

    assert sorted(item.path for item in differences) == _STOP_ORDER_FILES


def test_the_stop_order_does_not_hide_a_manifest_count_the_rows_do_not_give(
    stop_order_trees,
) -> None:
    recorded, replayed, path_map = stop_order_trees
    document = yaml.safe_load((replayed / "synthesis-manifest.yaml").read_text())
    document.pop("semantic_digest")
    document["obligation_stop_reason_counts"] = {"mechanism_absent": 2}
    document["semantic_digest"] = _digest_payload(_MANIFEST_DOMAIN, document)
    _write_manifest(replayed, document)
    _obligation_report(replayed)

    _, differences = compare_trees(recorded, replayed, path_map)

    assert [item.path for item in differences] == ["synthesis-manifest.yaml"]


def test_the_stop_order_does_not_hide_another_manifest_field(stop_order_trees) -> None:
    recorded, replayed, path_map = stop_order_trees
    document = yaml.safe_load((replayed / "synthesis-manifest.yaml").read_text())
    document.pop("semantic_digest")
    document["scenario_counts"] = {"published": 3}
    document["semantic_digest"] = _digest_payload(_MANIFEST_DOMAIN, document)
    _write_manifest(replayed, document)

    _, differences = compare_trees(recorded, replayed, path_map)

    assert [item.path for item in differences] == ["synthesis-manifest.yaml"]


def test_the_stop_order_does_not_hide_a_report_change_outside_its_section(
    stop_order_trees,
) -> None:
    recorded, replayed, path_map = stop_order_trees
    _obligation_report(replayed, other="changed")

    _, differences = compare_trees(recorded, replayed, path_map)

    assert [item.path for item in differences] == ["report/index.html"]


_OTHER_OBLIGATION = "ob:v1:" + "d" * 64


def _diagnostic(obligation_id: str, code: str, detail: str) -> Any:
    from asago_scenario_generator.models.obligation_consideration import (
        ConsiderationDiagnostic,
    )

    return ConsiderationDiagnostic(
        code=code,
        detail=detail,
        obligation_ids=(obligation_id,),
        gap_ids=("GAP-1",),
        refs=("ref-1",),
    )


def _diagnostic_trees(
    trees, before: Any, after: Any
) -> tuple[Path, Path, dict[str, str]]:
    """Record the old mechanism_absent row and replay it with these diagnostics.

    *before* and *after* each map the row's derived diagnostic and the
    obligation ID to the diagnostics that side's row carries.
    """
    recorded, replayed, path_map = trees
    plan, consideration, current = _routed_accounting()
    obligation_id, old_fields = _old_mechanism_absent_row(current)
    row = next(row for row in current.rows if row.obligation_id == obligation_id)
    derived = row.diagnostics[0]
    _write_accounting_run(
        recorded,
        plan,
        consideration,
        _row_as_recorded(
            current,
            obligation_id,
            stop_reason=old_fields["stop_reason"],
            diagnostics=before(derived, obligation_id),
        ),
    )
    _write_accounting_run(
        replayed,
        plan,
        consideration,
        _row_as_recorded(
            current, obligation_id, diagnostics=after(derived, obligation_id)
        ),
    )
    return recorded, replayed, path_map


def _superseded(obligation_id: str) -> Any:
    return _diagnostic(obligation_id, "incomplete_non_applicability", "superseded")


def _kept(obligation_id: str) -> Any:
    return _diagnostic(obligation_id, "slot_pair_unresolved", "kept")


def test_the_stop_order_keeps_other_diagnostics_and_drops_a_competing_one(
    trees,
) -> None:
    def before(derived, oid):
        stale = _diagnostic(oid, "mechanism_path_unsubstantiated", "stale")
        return (_kept(oid), stale, _superseded(oid))

    def after(derived, oid):
        return (_kept(oid), derived)

    recorded, replayed, path_map = _diagnostic_trees(trees, before, after)

    _, differences = compare_trees(recorded, replayed, path_map)

    assert differences == []


def test_the_stop_order_keeps_the_first_recorded_copy_of_its_diagnostic(
    trees,
) -> None:
    def before(derived, oid):
        first = _diagnostic(oid, "mechanism_absent", "first")
        second = _diagnostic(oid, "mechanism_absent", "second")
        return (first, _superseded(oid), second)

    def after(derived, oid):
        return (_diagnostic(oid, "mechanism_absent", "first"),)

    recorded, replayed, path_map = _diagnostic_trees(trees, before, after)

    _, differences = compare_trees(recorded, replayed, path_map)

    assert differences == []


_DIAGNOSTIC_EDITS = {
    "detail": {"detail": "changed detail"},
    "severity": {"severity": "error"},
    "obligation_ids": {"obligation_ids": (_OTHER_OBLIGATION,)},
    "gap_ids": {"gap_ids": ("GAP-2",)},
    "refs": {"refs": ("ref-2",)},
}


@pytest.mark.parametrize("edit", _DIAGNOSTIC_EDITS)
def test_the_stop_order_does_not_hide_an_edited_semantic_diagnostic(
    trees, edit: str
) -> None:
    def before(derived, oid):
        return (_kept(oid), _superseded(oid))

    def after(derived, oid):
        return (_kept(oid), derived.model_copy(update=_DIAGNOSTIC_EDITS[edit]))

    recorded, replayed, path_map = _diagnostic_trees(trees, before, after)

    _, differences = compare_trees(recorded, replayed, path_map)

    assert sorted(item.path for item in differences) == _STOP_ORDER_FILES


@pytest.mark.parametrize("edit", _DIAGNOSTIC_EDITS)
def test_the_stop_order_does_not_hide_an_edited_retained_diagnostic(
    trees, edit: str
) -> None:
    def before(derived, oid):
        return (_kept(oid), _superseded(oid))

    def after(derived, oid):
        return (_kept(oid).model_copy(update=_DIAGNOSTIC_EDITS[edit]), derived)

    recorded, replayed, path_map = _diagnostic_trees(trees, before, after)

    _, differences = compare_trees(recorded, replayed, path_map)

    assert sorted(item.path for item in differences) == _STOP_ORDER_FILES


def test_the_stop_order_does_not_hide_a_report_edit_without_accounting_drift(
    trees,
) -> None:
    recorded, replayed, path_map = trees
    plan, consideration, current = _routed_accounting()
    _write_accounting_run(recorded, plan, consideration, current)
    _write_accounting_run(replayed, plan, consideration, current)
    section = _obligations_section(replayed)
    _obligation_report(replayed, section.replace("</h2>", "</h2>edited", 1))

    _, differences = compare_trees(recorded, replayed, path_map)

    assert [item.path for item in differences] == ["report/index.html"]


def test_the_stop_order_does_not_hide_a_section_edit_the_rows_do_not_explain(
    stop_order_trees,
) -> None:
    recorded, replayed, path_map = stop_order_trees
    section = _obligations_section(replayed)
    _obligation_report(replayed, section.replace("</h2>", "</h2>edited", 1))

    _, differences = compare_trees(recorded, replayed, path_map)

    assert [item.path for item in differences] == ["report/index.html"]


def test_the_stop_order_states_its_reason() -> None:
    change = replay_gate.ACCOUNTING_STOP_REASON_CHANGE
    assert change.reason and change.stop_order and change.superseded_diagnostics
    assert len(change.files) == len(set(change.files))


# Counting a failed routing record as a provider contract failure moves
# accounting rows, not requests.

_RECORD_FAILED = "routing_record_validation_failed"
_BATCH_FAILED = "routing_validation_failed"


def _two_applicable_rows() -> tuple[Any, Any]:
    """Return a plan with a second applicable row and the plan's briefs."""
    from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
    from asago_scenario_generator.models.obligation_plan import (
        TaxonomyObligation,
        TaxonomyObligationPlan,
        derive_obligation_summary,
    )
    from asago_scenario_generator.pipeline.obligation_consideration import (
        build_neutral_briefs,
    )
    from tests.helpers.governance import _plan_with_non_stpa_rows
    from tests.helpers.projection_factory import get_test_raw_pattern

    plan = _plan_with_non_stpa_rows()
    source = next(
        row for row in plan.obligations if row.scope_disposition == "applicable"
    )
    payload = source.model_dump(mode="json")
    payload.update(obligation_id="ob:v1:" + "f" * 64)
    payload["risk_ref"] = {**payload["risk_ref"], "risk_id": "risk-second"}
    rows = (*plan.obligations, TaxonomyObligation.model_validate(payload))
    values = plan.model_dump(mode="json")
    values.update(
        obligations=[row.model_dump(mode="json") for row in rows],
        summary=derive_obligation_summary(rows),
    )
    unchecked = TaxonomyObligationPlan.model_validate(values)
    plan = TaxonomyObligationPlan.model_validate(
        {**values, "semantic_digest": unchecked.compute_semantic_digest()}
    )
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    return plan, build_neutral_briefs(plan, (pattern,))


def _failed_record_route(
    brief: Any,
    *codes: str,
    disposition: str = "unresolved",
    semantic_assessment: Any = None,
) -> Any:
    """Return a route whose routing diagnostics carry *codes*."""
    from asago_scenario_generator.models.obligation_consideration import (
        ConsiderationDiagnostic,
        ObligationRoute,
    )

    return ObligationRoute(
        obligation_id=brief.obligation_id,
        disposition=disposition,
        semantic_assessment=semantic_assessment,
        rationale="This obligation's routing record failed local validation.",
        evidence=("routing-validation",),
        diagnostics=tuple(
            ConsiderationDiagnostic(
                code=code,
                detail=f"ValueError: {code}",
                obligation_ids=(brief.obligation_id,),
                refs=("batch-1",),
            )
            for code in codes
        ),
    )


def _failed_record_accounting(*codes: str) -> tuple[Any, Any, Any, str]:
    """Return a plan, its consideration, its accounting, and the row's ID."""
    from asago_scenario_generator.pipeline.obligation_consideration import (
        build_neutral_briefs,
    )
    from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
    from tests.helpers.governance import _plan_with_non_stpa_rows
    from tests.helpers.projection_factory import get_test_raw_pattern

    plan = _plan_with_non_stpa_rows()
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    briefs = build_neutral_briefs(plan, (pattern,))
    route = _failed_record_route(briefs[0], *codes)
    consideration, accounting = _considered(plan, briefs, (route,))
    return plan, consideration, accounting, briefs[0].obligation_id


def _failed_record_run(
    trees, recorded_fields: dict[str, Any], replayed_fields: dict[str, Any], *codes
) -> tuple[Path, Path, dict[str, str]]:
    """Record and replay the failed-record row, each with these fields changed."""
    recorded, replayed, path_map = trees
    plan, consideration, current, obligation_id = _failed_record_accounting(
        *(codes or (_RECORD_FAILED,))
    )
    for root, fields in ((recorded, recorded_fields), (replayed, replayed_fields)):
        accounting = (
            _row_as_recorded(current, obligation_id, **fields) if fields else current
        )
        _write_accounting_run(root, plan, consideration, accounting)
    return recorded, replayed, path_map


_BEFORE_THE_FIX = {"stop_reason": "no_structural_route"}


@pytest.fixture
def failed_record_trees(trees) -> tuple[Path, Path, dict[str, str]]:
    """A recording made before the failed record counted and its replay."""
    return _failed_record_run(trees, _BEFORE_THE_FIX, {})


def test_the_failed_record_accepts_only_its_accounting_outputs(
    failed_record_trees,
) -> None:
    recorded, replayed, path_map = failed_record_trees
    rows = yaml.safe_load((replayed / "obligation-accounting.yaml").read_text())
    assert [row.get("stop_reason") for row in rows["rows"]].count(
        "provider_contract_failure"
    ) == 1
    expected: list[Difference] = []

    _, differences = compare_trees(
        recorded, replayed, path_map, expected_differences=expected
    )

    assert differences == []
    assert sorted(item.path for item in expected) == _STOP_ORDER_FILES


def test_the_failed_record_composes_with_the_stop_order(trees) -> None:
    from asago_scenario_generator.models.obligation_consideration import (
        ObligationRoute,
        ObligationSemanticAssessment,
    )

    recorded, replayed, path_map = trees
    plan, briefs = _two_applicable_rows()
    semantic = ObligationRoute(
        obligation_id=briefs[0].obligation_id,
        disposition="proposed_not_applicable",
        semantic_assessment=ObligationSemanticAssessment(
            mechanism_assessment="absent_from_system",
            risk_alignment="supported",
            mapping_strength="broad_category_expansion",
            mechanism_rationale="The mechanism judgement.",
            risk_alignment_rationale="The alignment judgement.",
        ),
        rationale="The routing rationale.",
        evidence=("route evidence",),
    )
    failed = _failed_record_route(briefs[1], _RECORD_FAILED)
    consideration, current = _considered(plan, briefs, (semantic, failed))
    obligation_id, old_fields = _old_mechanism_absent_row(current)
    before = _row_as_recorded(current, obligation_id, **old_fields)
    before = _row_as_recorded(before, briefs[1].obligation_id, **_BEFORE_THE_FIX)
    _write_accounting_run(recorded, plan, consideration, before)
    _write_accounting_run(replayed, plan, consideration, current)
    expected: list[Difference] = []

    _, differences = compare_trees(
        recorded, replayed, path_map, expected_differences=expected
    )

    assert differences == []
    assert sorted(item.path for item in expected) == _STOP_ORDER_FILES


@pytest.mark.parametrize(
    "reason", ["prompt_budget_exceeded", "ica_consideration_unresolved"]
)
def test_the_failed_record_does_not_hide_a_move_to_another_reason(
    trees, reason: str
) -> None:
    recorded, replayed, path_map = _failed_record_run(
        trees, _BEFORE_THE_FIX, {"stop_reason": reason}
    )

    _, differences = compare_trees(recorded, replayed, path_map)

    assert sorted(item.path for item in differences) == _STOP_ORDER_FILES


def test_the_failed_record_does_not_hide_a_move_from_another_reason(trees) -> None:
    recorded, replayed, path_map = _failed_record_run(
        trees, {"stop_reason": "ica_consideration_unresolved"}, {}
    )

    _, differences = compare_trees(recorded, replayed, path_map)

    assert sorted(item.path for item in differences) == _STOP_ORDER_FILES


@pytest.mark.parametrize(
    "codes",
    [
        ("slot_pair_unresolved",),
        (_BATCH_FAILED,),
        (_RECORD_FAILED, _BATCH_FAILED),
        (_RECORD_FAILED, "prompt_budget_exceeded"),
    ],
    ids=["other", "batch", "record-and-batch", "record-and-budget"],
)
def test_the_failed_record_does_not_hide_a_move_its_route_does_not_explain(
    trees, codes: tuple[str, ...]
) -> None:
    recorded, replayed, path_map = _failed_record_run(
        trees,
        _BEFORE_THE_FIX,
        {"stop_reason": "provider_contract_failure"},
        *codes,
    )

    _, differences = compare_trees(recorded, replayed, path_map)

    assert sorted(item.path for item in differences) == _STOP_ORDER_FILES


def test_the_failed_record_does_not_hide_a_route_of_another_disposition(
    trees,
) -> None:
    from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
    from asago_scenario_generator.pipeline.obligation_consideration import (
        build_neutral_briefs,
    )
    from tests.helpers.governance import _plan_with_non_stpa_rows
    from tests.helpers.projection_factory import get_test_raw_pattern

    recorded, replayed, path_map = trees
    plan = _plan_with_non_stpa_rows()
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    briefs = build_neutral_briefs(plan, (pattern,))
    route = _failed_record_route(
        briefs[0], _RECORD_FAILED, disposition="proposed_not_applicable"
    )
    consideration, current = _considered(plan, briefs, (route,))
    obligation_id = briefs[0].obligation_id
    for root, reason in (
        (recorded, "no_structural_route"),
        (replayed, "provider_contract_failure"),
    ):
        accounting = _row_as_recorded(current, obligation_id, stop_reason=reason)
        _write_accounting_run(root, plan, consideration, accounting)

    _, differences = compare_trees(recorded, replayed, path_map)

    assert sorted(item.path for item in differences) == _STOP_ORDER_FILES


@pytest.mark.parametrize(
    ("mechanism", "alignment", "semantic_reason"),
    [
        ("absent_from_system", "supported", "mechanism_absent"),
        ("plausible_in_system", "mismatch", "risk_pattern_mismatch"),
    ],
    ids=["mechanism_absent", "risk_pattern_mismatch"],
)
def test_the_failed_record_does_not_hide_a_route_whose_semantic_stop_wins(
    trees, mechanism: str, alignment: str, semantic_reason: str
) -> None:
    """A failed record keeps its semantic assessment, whose stop comes first."""
    from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
    from asago_scenario_generator.models.obligation_consideration import (
        ObligationSemanticAssessment,
    )
    from asago_scenario_generator.pipeline.obligation_consideration import (
        build_neutral_briefs,
    )
    from tests.helpers.governance import _plan_with_non_stpa_rows
    from tests.helpers.projection_factory import get_test_raw_pattern

    recorded, replayed, path_map = trees
    plan = _plan_with_non_stpa_rows()
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    briefs = build_neutral_briefs(plan, (pattern,))
    route = _failed_record_route(
        briefs[0],
        _RECORD_FAILED,
        semantic_assessment=ObligationSemanticAssessment(
            mechanism_assessment=mechanism,
            risk_alignment=alignment,
            mapping_strength="broad_category_expansion",
            mechanism_rationale="The mechanism judgement.",
            risk_alignment_rationale="The alignment judgement.",
        ),
    )
    consideration, current = _considered(plan, briefs, (route,))
    obligation_id = briefs[0].obligation_id
    row = next(row for row in current.rows if row.obligation_id == obligation_id)
    assert row.stop_reason == semantic_reason
    assert row.diagnostics[0] == route.diagnostics[0]
    for root, reason in (
        (recorded, "no_structural_route"),
        (replayed, "provider_contract_failure"),
    ):
        accounting = _row_as_recorded(current, obligation_id, stop_reason=reason)
        _write_accounting_run(root, plan, consideration, accounting)

    _, differences = compare_trees(recorded, replayed, path_map)

    assert sorted(item.path for item in differences) == _STOP_ORDER_FILES


def test_the_failed_record_does_not_hide_an_out_of_scope_row(trees) -> None:
    """An out-of-scope row stops at risk_out_of_scope or fails its integrity."""
    from asago_scenario_generator.models.canonical import compute_framed_digest
    from asago_scenario_generator.models.obligation_accounting import (
        OBLIGATION_ACCOUNTING_DIGEST_DOMAIN,
        ObligationAccounting,
    )

    recorded, replayed, path_map = _failed_record_run(trees, {}, {})
    current = ObligationAccounting.from_yaml(
        (replayed / "obligation-accounting.yaml").read_text()
    )
    obligation_id = next(
        row.obligation_id
        for row in current.rows
        if row.stop_reason == "provider_contract_failure"
    )
    for root, reason in (
        (recorded, "no_structural_route"),
        (replayed, "provider_contract_failure"),
    ):
        payload = current.model_dump(mode="json", exclude={"semantic_digest"})
        for row in payload["rows"]:
            if row["obligation_id"] == obligation_id:
                row.update(scope="outside_boundary", stop_reason=reason)
        payload["semantic_digest"] = compute_framed_digest(
            OBLIGATION_ACCOUNTING_DIGEST_DOMAIN, payload
        )
        text = yaml.safe_dump(payload, sort_keys=False)
        with pytest.raises(ValueError, match="must stop at risk_out_of_scope"):
            ObligationAccounting.from_yaml(text)
        (root / "obligation-accounting.yaml").write_text(text)

    _, differences = compare_trees(recorded, replayed, path_map)

    assert [item.path for item in differences] == ["obligation-accounting.yaml"]


def test_the_failed_record_does_not_hide_a_row_without_its_diagnostic(
    trees,
) -> None:
    other = _diagnostic(_OTHER_OBLIGATION, "slot_pair_unresolved", "other")
    recorded, replayed, path_map = _failed_record_run(
        trees,
        {**_BEFORE_THE_FIX, "diagnostics": (other,)},
        {"diagnostics": (other,)},
    )

    _, differences = compare_trees(recorded, replayed, path_map)

    assert sorted(item.path for item in differences) == _STOP_ORDER_FILES


@pytest.mark.parametrize(
    "fields",
    [
        {"evidence": ("other evidence",)},
        {"disposition": "upstream_gap"},
        {"route_refs": ("route-other",)},
    ],
    ids=["evidence", "disposition", "route_refs"],
)
def test_the_failed_record_does_not_hide_another_field_on_a_moved_row(
    trees, fields: dict[str, Any]
) -> None:
    recorded, replayed, path_map = _failed_record_run(
        trees, {**_BEFORE_THE_FIX, **fields}, {}
    )

    _, differences = compare_trees(recorded, replayed, path_map)

    assert sorted(item.path for item in differences) == _STOP_ORDER_FILES


def test_the_failed_record_does_not_hide_an_edited_routing_diagnostic(
    trees,
) -> None:
    recorded, replayed, path_map = trees
    plan, consideration, current, obligation_id = _failed_record_accounting(
        _RECORD_FAILED
    )
    row = next(row for row in current.rows if row.obligation_id == obligation_id)
    edited = row.diagnostics[0].model_copy(update={"detail": "changed detail"})
    before = _row_as_recorded(current, obligation_id, **_BEFORE_THE_FIX)
    after = _row_as_recorded(current, obligation_id, diagnostics=(edited,))
    _write_accounting_run(recorded, plan, consideration, before)
    _write_accounting_run(replayed, plan, consideration, after)

    _, differences = compare_trees(recorded, replayed, path_map)

    assert sorted(item.path for item in differences) == _STOP_ORDER_FILES


def _rewrite_manifest(root: Path, **fields: Any) -> None:
    document = yaml.safe_load((root / "synthesis-manifest.yaml").read_text())
    document.pop("semantic_digest")
    document.update(fields)
    document["semantic_digest"] = _digest_payload(_MANIFEST_DOMAIN, document)
    _write_manifest(root, document)


def test_the_failed_record_does_not_hide_counts_without_a_row_change(
    trees,
) -> None:
    recorded, replayed, path_map = _failed_record_run(trees, {}, {})
    _rewrite_manifest(
        replayed, obligation_stop_reason_counts={"no_structural_route": 1}
    )

    _, differences = compare_trees(recorded, replayed, path_map)

    assert [item.path for item in differences] == ["synthesis-manifest.yaml"]


def test_the_failed_record_does_not_hide_a_digest_without_a_row_change(
    trees,
) -> None:
    recorded, replayed, path_map = _failed_record_run(trees, {}, {})
    realization = yaml.safe_load((replayed / "scenario-realization.yaml").read_text())
    realization["semantic_digest"] = "f" * 64
    (replayed / "scenario-realization.yaml").write_text(yaml.safe_dump(realization))

    _, differences = compare_trees(recorded, replayed, path_map)

    assert [item.path for item in differences] == ["scenario-realization.yaml"]


def test_the_failed_record_does_not_hide_a_manifest_count_the_rows_do_not_give(
    failed_record_trees,
) -> None:
    recorded, replayed, path_map = failed_record_trees
    _rewrite_manifest(
        replayed, obligation_stop_reason_counts={"provider_contract_failure": 2}
    )
    _obligation_report(replayed)

    _, differences = compare_trees(recorded, replayed, path_map)

    assert [item.path for item in differences] == ["synthesis-manifest.yaml"]


def test_the_failed_record_does_not_hide_a_section_edit_the_rows_do_not_explain(
    failed_record_trees,
) -> None:
    recorded, replayed, path_map = failed_record_trees
    section = _obligations_section(replayed)
    _obligation_report(replayed, section.replace("</h2>", "</h2>edited", 1))

    _, differences = compare_trees(recorded, replayed, path_map)

    assert [item.path for item in differences] == ["report/index.html"]


def test_the_failed_record_does_not_hide_a_provider_record_difference(
    failed_record_trees,
) -> None:
    recorded, replayed, path_map = failed_record_trees
    records = [_provider_call(1, "A", "for A"), _provider_call(2, "B", "changed")]
    _jsonl(replayed / RECORD_FILENAME, records)

    _, differences = compare_trees(recorded, replayed, path_map)

    assert [item.path for item in differences] == [RECORD_FILENAME]


def test_the_failed_record_does_not_hide_a_call_log_difference(
    failed_record_trees,
) -> None:
    recorded, replayed, path_map = failed_record_trees
    _jsonl(replayed / "calls.jsonl", [{"stage": "s", "step": "b", "success": True}])
    _obligation_report(replayed)

    _, differences = compare_trees(recorded, replayed, path_map)

    assert "calls.jsonl" in [item.path for item in differences]


def test_the_failed_record_states_its_reason() -> None:
    change = replay_gate.ROUTING_RECORD_STOP_REASON_CHANGE
    assert change.reason and change.route_disposition
    assert change.recorded_reason != change.replayed_reason
    assert change.record_diagnostic not in change.earlier_diagnostics
