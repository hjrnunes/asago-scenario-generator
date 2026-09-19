from __future__ import annotations

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


def test_malformed_tool_call_container_is_not_a_frozen_detector_negative() -> None:
    from artifact_package_runtime import load_artifact_package
    from detector_runtime_adapter import execute_detector

    package_path = (
        Path(__file__).resolve().parents[2].parent
        / "asago-artifact-generator"
        / "runs"
        / "authoring"
        / "g07-fresh-20260918"
        / "G07-fresh-20260918"
    )
    package = load_artifact_package(package_path)
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
