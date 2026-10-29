"""The offline script that compares the join with signature retrieval off and on."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import yaml

_SCRIPT = (
    Path(__file__).resolve().parents[1] / "scripts" / "signature_retrieval_measure.py"
)


def _script() -> ModuleType:
    name = "signature_retrieval_measure_script"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, _SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


def _channel(fb_id: str, pm_id: str, kind: str, authority: str | None = None) -> dict:
    channel: dict[str, Any] = {
        "fb_id": fb_id,
        "description": f"Signal {kind}",
        "updates": pm_id,
        "source": {"type": "controlled_process", "id": "CP-1"},
        "source_kind": kind,
    }
    if authority is not None:
        channel["authority_for_update"] = {"status": authority, "basis": "Backend."}
    return channel


def _structure() -> dict:
    """A user message, an authoritative operation result and an other report.

    One action reads all three variables.
    """
    return {
        "responsibilities": [
            {
                "resp_id": "RESP-1",
                "description": "Answer",
                "process_model_parts": [
                    {"pm_id": "PM-1-1", "description": "Claim"},
                    {"pm_id": "PM-1-2", "description": "Order state"},
                    {"pm_id": "PM-1-3", "description": "Refund sent"},
                ],
                "control_actions": [
                    {
                        "ca_id": "CA-1-1",
                        "description": "Refund",
                        "target": {"type": "controlled_process", "id": "CP-1"},
                        "effect_kind": "state_change",
                        "process_model_refs": ["PM-1-1", "PM-1-2", "PM-1-3"],
                    }
                ],
                "feedback_channels": [
                    _channel("FB-1-1", "PM-1-1", "user_message"),
                    _channel("FB-1-2", "PM-1-2", "operation_result", "authoritative"),
                    _channel("FB-1-3", "PM-1-3", "other"),
                ],
            }
        ],
        "controlled_processes": [{"cp_id": "CP-1", "description": "Store"}],
    }


def _verdict(fb_id: str, pm_id: str, relationship: str) -> dict:
    return {
        "path": {
            "feedback_channel_id": fb_id,
            "process_model_part_id": pm_id,
            "end_id": "CA-1-1",
        },
        "relationship": relationship,
        "rationale": "Recorded.",
    }


def _accounting(rows: list[dict]) -> dict:
    return {"schema_version": "stpa-mechanism-suggestion-accounting-v1", "rows": rows}


def _run(tmp_path: Path, name: str, accounting: dict | None = None) -> Path:
    folder = tmp_path / name
    folder.mkdir()
    path = folder / "control-structure.yaml"
    path.write_text(yaml.safe_dump(_structure()))
    if accounting is not None:
        (folder / "mechanism-suggestion-accounting.yaml").write_text(
            yaml.safe_dump(accounting)
        )
    return path


_USER_CLAIM = ("user_claim", ("FB-1-1", "PM-1-1", "CA-1-1"))
_STALE = ("stale_feedback", ("FB-1-2", "PM-1-2", "CA-1-1"))
_FORGED = ("forged_completion", ("FB-1-3", "PM-1-3", "CA-1-1"))


def test_off_and_on_candidates_and_the_new_ones(tmp_path: Path) -> None:
    script = _script()
    (unit,) = script.load_units([("u", _run(tmp_path, "r1"))])

    off, on = unit.modes["off"], unit.modes["on"]

    assert [(item.mechanism, item.path) for item in off.candidates] == [_USER_CLAIM]
    assert [(item.mechanism, item.path) for item in on.candidates] == [
        _USER_CLAIM,
        _STALE,
        _FORGED,
    ]
    assert [(item.mechanism, item.path) for item in unit.new_candidates()] == [
        _STALE,
        _FORGED,
    ]
    assert [item.candidate.mechanism for item in on.dropped] == ["forged_completion"]


def test_verifier_status_comes_only_from_recorded_replies(tmp_path: Path) -> None:
    accounting = _accounting(
        [
            {
                "mechanism_id": "user_claim",
                "slot_id": "RESP-1:CA-1-1:INCORRECT",
                "stop_reason": "verifier_unresolved",
                "path_verdicts": [
                    _verdict("FB-1-1", "PM-1-1", "insufficient_evidence")
                ],
            },
            {
                "mechanism_id": "forged_completion",
                "slot_id": "RESP-1:CA-1-1:INCORRECT",
                "stop_reason": "verifier_rejected",
                "path_verdicts": [_verdict("FB-1-3", "PM-1-3", "no_verdict")],
            },
        ]
    )
    script = _script()
    (unit,) = script.load_units([("u", _run(tmp_path, "r1", accounting))])

    row = script.unit_counts(unit, [unit])

    assert unit.verifier_status(_candidate(*_USER_CLAIM)) == "insufficient_evidence"
    assert unit.verifier_status(_candidate(*_FORGED)) == "unverified"
    assert unit.verifier_status(_candidate(*_STALE)) == "unverified"
    assert row["off"]["verifier"] == {
        "accepted": 0,
        "rejected": 0,
        "insufficient_evidence": 1,
        "conflicting": 0,
        "unverified": 0,
    }
    assert row["on"]["verifier"]["unverified"] == 2
    assert row["off"]["acceptance"] == 0.0
    assert row["verifier_replies"] == "recorded"


def test_conflicting_replies_and_acceptance(tmp_path: Path) -> None:
    accounting = _accounting(
        [
            {
                "mechanism_id": "user_claim",
                "slot_id": slot,
                "stop_reason": "verifier_unresolved",
                "path_verdicts": [_verdict("FB-1-1", "PM-1-1", relationship)],
            }
            for slot, relationship in (
                ("RESP-1:CA-1-1:INCORRECT", "mechanism_specific"),
                ("RESP-1:CA-1-1:NOT_PROVIDED", "adjacent_control"),
            )
        ]
        + [
            {
                "mechanism_id": "stale_feedback",
                "slot_id": "RESP-1:CA-1-1:INCORRECT",
                "stop_reason": "finding",
                "path_verdicts": [_verdict("FB-1-2", "PM-1-2", "mechanism_specific")],
            }
        ]
    )
    script = _script()
    (unit,) = script.load_units([("u", _run(tmp_path, "r1", accounting))])

    row = script.unit_counts(unit, [unit])

    assert unit.verifier_status(_candidate(*_USER_CLAIM)) == "conflicting"
    assert row["on"]["verifier"]["accepted"] == 1
    assert row["on"]["acceptance"] == 0.5


def test_no_accounting_leaves_every_candidate_unverified(tmp_path: Path) -> None:
    script = _script()
    (unit,) = script.load_units([("u", _run(tmp_path, "r1"))])

    row = script.unit_counts(unit, [unit])

    assert row["verifier_replies"] == "absent"
    assert row["on"]["verifier"]["unverified"] == 3
    assert row["on"]["acceptance"] is None


def test_usefulness_reads_labels_by_structure_digest(tmp_path: Path) -> None:
    script = _script()
    path = _run(tmp_path, "r1")
    (unit,) = script.load_units([("u", path)])
    labels_file = tmp_path / "labels.jsonl"
    rows = [
        {
            "sha256": unit.digest,
            "mechanism": "user_claim",
            "path": list(_USER_CLAIM[1]),
            "agreed": "correct",
        },
        {
            "sha256": unit.digest,
            "mechanism": "stale_feedback",
            "path": list(_STALE[1]),
            "agreed": "disagree",
        },
        {
            "sha256": "0" * 64,
            "mechanism": "forged_completion",
            "path": list(_FORGED[1]),
            "agreed": "incorrect",
        },
    ]
    labels_file.write_text("".join(json.dumps(row) + "\n" for row in rows))

    labels = script.load_labels([labels_file], "agreed")
    (unit,) = script.load_units([("u", path)], labels=labels)
    row = script.unit_counts(unit, [unit])

    assert row["off"]["usefulness"] == {
        "useful": 1,
        "not_useful": 0,
        "undecided": 0,
        "unlabeled": 0,
    }
    assert row["off"]["precision"] == 1.0
    assert row["on"]["usefulness"] == {
        "useful": 1,
        "not_useful": 0,
        "undecided": 1,
        "unlabeled": 1,
    }


def test_without_labels_usefulness_is_unavailable(tmp_path: Path) -> None:
    script = _script()
    (unit,) = script.load_units([("u", _run(tmp_path, "r1"))])
    rows = [script.unit_counts(unit, [unit])]

    aggregate = script.aggregate(rows, "on")

    assert rows[0]["on"]["precision"] is None
    assert aggregate["precision"] is None
    assert aggregate["candidates"]["total"] == 3
    assert aggregate["by_mechanism"] == {
        "user_claim": 1,
        "forged_completion": 1,
        "stale_feedback": 1,
    }


def test_live_check_lists_unverified_new_candidates_and_requests(
    tmp_path: Path,
) -> None:
    script = _script()
    units = script.load_units(
        [("a", _run(tmp_path, "r1")), ("b", _run(tmp_path, "r2"))]
    )

    check = script.live_check(units)

    # r2 is byte-identical to r1, so only r1's two new candidates need a reply.
    assert [(row["unit"], row["mechanism"]) for row in check["candidates"]] == [
        ("a", "stale_feedback"),
        ("a", "forged_completion"),
    ]
    assert check["requests"] == {"a": 1}
    assert check["total_requests"] == 1


def test_main_writes_every_output(tmp_path: Path, monkeypatch) -> None:
    script = _script()
    out = tmp_path / "out"
    monkeypatch.setattr(
        sys,
        "argv",
        ["measure", "--unit", "u", str(_run(tmp_path, "r1")), "--out-dir", str(out)],
    )

    script.main()

    names = sorted(item.name for item in out.iterdir())
    assert names == [
        "live-check-candidates.jsonl",
        "signature-retrieval-candidates.jsonl",
        "signature-retrieval-counts.json",
        "signature-retrieval-summary.md",
    ]
    summary = (out / "signature-retrieval-summary.md").read_text()
    assert "Reference only" in summary
    assert "unavailable" in summary
    counts = json.loads((out / "signature-retrieval-counts.json").read_text())
    assert counts["aggregates"]["distinct structures"]["on"]["candidates"]["total"] == 3


def _candidate(mechanism: str, path: tuple[str, str, str]) -> Any:
    from asago_scenario_generator.stpa.obligation_aware.stpa_index import (
        MechanismCandidate,
    )

    return MechanismCandidate(mechanism, path)  # type: ignore[arg-type]
