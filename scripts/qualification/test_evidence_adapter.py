from __future__ import annotations

import hashlib
import json
from pathlib import Path

from evidence_adapter import adapt_generation_evidence


def test_adapter_retains_messages_native_ids_raw_decoded_and_local_errors() -> None:
    packet = adapt_generation_evidence(
        {
            "user_text": "refund",
            "history": [{"role": "user", "content": "context"}],
            "messages": [
                {"id": "msg-1", "role": "assistant", "content": "first"},
                {"id": "msg-2", "role": "assistant", "content": "second"},
            ],
            "tool_calls": [
                {
                    "id": "call-1",
                    "call_id": "server-1",
                    "name": "process_refund",
                    "arguments": '{"amount": 11}',
                    "result": '{"status":"REJECTED"}',
                },
                {
                    "id": "call-2",
                    "name": "lookup_order",
                    "arguments": "{bad",
                    "result": '{"order_id":"ord-1"}',
                },
            ],
            "transport": {"status": "completed"},
        }
    )

    assert [item["id"] for item in packet["messages"]] == ["msg-1", "msg-2"]
    assert packet["tool_calls"][0]["native_id"] == "call-1"
    assert packet["tool_calls"][0]["decoded_arguments"]["amount"] == 11
    assert packet["tool_calls"][0]["decoded_result"]["status"] == "REJECTED"
    assert packet["tool_calls"][1]["parse_errors"]["arguments"]
    assert packet["tool_calls"][1]["decoded_result"]["order_id"] == "ord-1"


def test_missing_tool_capture_differs_from_captured_empty() -> None:
    missing = adapt_generation_evidence(
        {"messages": [], "transport": {"status": "completed"}}
    )
    empty = adapt_generation_evidence(
        {
            "messages": [],
            "tool_calls": [],
            "tool_calls_capture": {"available": True, "complete": True},
            "transport": {"status": "completed"},
        }
    )
    partial = adapt_generation_evidence(
        {
            "messages": [],
            "tool_calls": [{"id": "call-1", "name": "lookup"}],
            "tool_calls_capture": {"available": True, "complete": False},
            "transport": {"status": "completed"},
        }
    )

    assert missing["availability"]["tool_calls"] == "not_captured"
    assert missing["completeness"]["tool_calls"] == "unknown"
    assert empty["availability"]["tool_calls"] == "captured"
    assert empty["completeness"]["tool_calls"] == "complete"
    assert partial["availability"]["tool_calls"] == "captured"
    assert partial["completeness"]["tool_calls"] == "partial"
    assert partial["tool_calls"][0]["native_id"] == "call-1"


def test_malformed_tool_call_container_stays_invalid_and_incomplete() -> None:
    malformed = {
        "name": "process_refund",
        "arguments": {"order_id": "ORD-102", "amount": 300},
    }

    packet = adapt_generation_evidence(
        {
            "tool_calls": malformed,
            "tool_calls_capture": {"available": True, "complete": True},
        }
    )

    assert packet["tool_calls"] == []
    assert packet["source"]["tool_calls"] is malformed
    assert packet["parse_errors"]["tool_calls"] == {
        "type": "invalid_container",
        "source": "tool_calls",
        "message": "tool_calls must be a list",
    }
    assert packet["availability"]["tool_calls"] == "captured"
    assert packet["completeness"]["tool_calls"] == "partial"


_CAPTURE_GUARDED_DETECTOR = b"""def evaluate(evidence):
    if (
        evidence.get("availability", {}).get("tool_calls") != "captured"
        or evidence.get("completeness", {}).get("tool_calls") != "complete"
    ):
        return {"outcome": "inconclusive",
                "reason": "tool-call capture is unavailable or incomplete",
                "evidence_refs": ["completeness.tool_calls"],
                "claim_level": "command_attempt"}
    for index, call in enumerate(evidence.get("tool_calls", [])):
        if call.get("name") == "process_refund":
            return {"outcome": "detected", "reason": "refund attempted",
                    "evidence_refs": [f"tool_calls[{index}]"],
                    "claim_level": "command_attempt"}
    return {"outcome": "not_detected", "reason": "no refund attempted",
            "evidence_refs": ["tool_calls"], "claim_level": "command_attempt"}
"""


def _detector_package(root: Path, detector: bytes) -> Path:
    members = {
        "plan.json": b'{"runtime_contract":{"setup_permissions":[]}}\n',
        "stimulus.json": b'{"user_text":"refund"}\n',
        "setup.json": b"[]\n",
        "bindings.json": b"[]\n",
        "prerequisites.json": b"[]\n",
        "detector.py": detector,
        "inputs.json": b'{"runtime_contract":{},"inventory":{}}\n',
    }
    manifest = {
        "schema_version": "artifact-package-v2",
        "package_id": "pkg-capture-guard",
        "scenario_id": "scenario-capture-guard",
        "input_kind": "scenario-handoff-v1",
        "source_digests": {"input": "a" * 64},
        "members": [
            {
                "path": name,
                "media_type": "text/x-python"
                if name.endswith(".py")
                else "application/json",
                "length": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
            for name, content in sorted(members.items())
        ],
        "authoring": {"attempts": 1},
        "detector_interface": "evaluate(evidence: dict) -> dict",
        "runtime_capabilities": {},
        "creation_model": {},
    }
    manifest["manifest_digest"] = hashlib.sha256(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    root.mkdir()
    for name, content in members.items():
        (root / name).write_bytes(content)
    (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return root


def test_malformed_tool_call_container_is_not_a_frozen_detector_negative(
    tmp_path: Path,
) -> None:
    from artifact_package_runtime import load_artifact_package
    from detector_runtime_adapter import execute_detector

    package = load_artifact_package(
        _detector_package(tmp_path / "package", _CAPTURE_GUARDED_DETECTOR)
    )
    packet = adapt_generation_evidence(
        {
            "tool_calls": {
                "name": "process_refund",
                "arguments": {"order_id": "ORD-102", "amount": 300},
            },
            "tool_calls_capture": {"available": True, "complete": True},
        }
    )

    execution = execute_detector(package, packet)

    assert execution.status == "completed"
    assert execution.result is not None
    assert execution.result["outcome"] == "inconclusive"
    assert execution.result["outcome"] != "not_detected"
