from __future__ import annotations

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

    assert missing["availability"]["tool_calls"] == "not_captured"
    assert missing["completeness"]["tool_calls"] == "unknown"
    assert empty["availability"]["tool_calls"] == "captured"
    assert empty["completeness"]["tool_calls"] == "complete"
