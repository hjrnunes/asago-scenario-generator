"""Lossless adapter from one Garak generation to the detector evidence packet."""

from __future__ import annotations

import json
from typing import Any


def adapt_generation_evidence(
    raw: dict[str, Any],
    *,
    bindings: dict[str, Any] | None = None,
    binding_provenance: dict[str, Any] | None = None,
    setup_outputs: dict[str, Any] | None = None,
    snapshots: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Normalize transport fields without dropping raw items or malformed siblings."""

    if not isinstance(raw, dict):
        raise TypeError("generation response must be an object")
    messages_raw = raw.get("messages", raw.get("assistant_messages", []))
    if not isinstance(messages_raw, list):
        messages_raw = []
    messages = [
        {
            "id": item.get("id", item.get("native_id"))
            if isinstance(item, dict)
            else None,
            "role": item.get("role") if isinstance(item, dict) else None,
            "content": item.get("content") if isinstance(item, dict) else item,
            "raw": item,
            "source_item": item,
        }
        for item in messages_raw
    ]
    has_tool_calls = "tool_calls" in raw or (
        isinstance(raw.get("notes"), dict) and "tool_calls" in raw["notes"]
    )
    calls_raw = raw.get("tool_calls")
    if calls_raw is None and isinstance(raw.get("notes"), dict):
        calls_raw = raw["notes"].get("tool_calls")
    if not isinstance(calls_raw, list):
        calls_raw = []
    tool_calls = [_adapt_tool_call(item) for item in calls_raw]
    capture = raw.get("tool_calls_capture")
    captured = bool(has_tool_calls)
    complete = (
        isinstance(capture, dict)
        and capture.get("available") is True
        and capture.get("complete") is True
    )
    messages_captured = "messages" in raw or "assistant_messages" in raw
    packet: dict[str, Any] = {
        "user_text": raw.get("user_text"),
        "history": list(raw.get("history", []))
        if isinstance(raw.get("history", []), list)
        else [],
        "messages": messages,
        "tool_calls": tool_calls,
        "bindings": dict(bindings or {}),
        "binding_provenance": dict(binding_provenance or {}),
        "setup_outputs": dict(setup_outputs or {}),
        "snapshots": dict(snapshots or {}),
        "transport": raw.get("transport", {}),
        "availability": {
            "messages": "captured" if messages_captured else "not_captured",
            "tool_calls": "captured" if captured else "not_captured",
            "snapshots": "captured" if snapshots is not None else "not_captured",
        },
        "completeness": {
            "messages": "complete" if messages_captured else "unknown",
            "tool_calls": "complete"
            if complete
            else ("unknown" if not captured else "partial"),
            "snapshots": "complete" if snapshots is not None else "unknown",
        },
        "source": raw,
    }
    packet["correlation"] = _correlations(tool_calls)
    return packet


def _adapt_tool_call(item: Any) -> dict[str, Any]:
    if not isinstance(item, dict):
        return {
            "native_id": None,
            "call_id": None,
            "name": None,
            "raw": item,
            "source_item": item,
            "decoded_arguments": None,
            "decoded_result": None,
            "parse_errors": {"item": "tool item is not an object"},
        }
    errors: dict[str, str] = {}
    raw_arguments = item.get("arguments", item.get("raw_arguments"))
    raw_result = item.get("result", item.get("output", item.get("raw_result")))
    decoded_arguments = _decode(raw_arguments, "arguments", errors)
    decoded_result = _decode(raw_result, "result", errors)
    return {
        "native_id": item.get("native_id", item.get("id")),
        "call_id": item.get("call_id"),
        "name": item.get("name", item.get("tool_name")),
        "raw_arguments": raw_arguments,
        "decoded_arguments": decoded_arguments,
        "raw_result": raw_result,
        "decoded_result": decoded_result,
        "status": item.get("status"),
        "error": item.get("error"),
        "parse_errors": errors,
        "raw": item,
        "source_item": item,
    }


def _decode(value: Any, label: str, errors: dict[str, str]) -> Any:
    if isinstance(value, (dict, list)) or value is None:
        return value
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except json.JSONDecodeError as exc:
        errors[label] = f"{type(exc).__name__}: {exc.msg}"
        return None


def _correlations(calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    correlations = []
    for call in calls:
        result = call.get("decoded_result")
        result_id = (
            result.get("id", result.get("native_id"))
            if isinstance(result, dict)
            else None
        )
        if call.get("native_id") is not None:
            mechanism = "native_id"
        elif result_id is not None:
            mechanism = "result_containment"
        elif call.get("call_id") is not None:
            mechanism = "call_id"
        else:
            mechanism = "unresolved"
        correlations.append(
            {
                "native_id": call.get("native_id"),
                "call_id": call.get("call_id"),
                "result_native_id": result_id,
                "result_correlation": mechanism,
            }
        )
    return correlations


__all__ = ["adapt_generation_evidence"]
