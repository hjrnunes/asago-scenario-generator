from __future__ import annotations

from garak_dispatch import PINNED_GARAK_REVISION, dispatch_pinned_garak
from request_ledger import RequestLedger


def test_pinned_dispatch_records_one_generation_and_every_server_command() -> None:
    ledger = RequestLedger("generation")
    generation = dispatch_pinned_garak(
        {"user_text": "hello"},
        target_url="http://127.0.0.1:8888/sse",
        model_url="http://127.0.0.1:8321/v1/",
        model="fixture",
        ledger=ledger,
        dispatch=lambda **kwargs: {
            "messages": [{"id": "m-1", "role": "assistant", "content": "ok"}],
            "tool_calls": [
                {"id": "call-1", "name": "lookup", "arguments": "{}", "result": "{}"},
                {"id": "call-2", "name": "refund", "arguments": "{}", "result": "{}"},
            ],
        },
    )

    assert generation.garak_revision == PINNED_GARAK_REVISION
    assert len(ledger.dispatches) == 1
    assert ledger.dispatches[0]["server_commands"] == 2
    assert ledger.dispatches[0]["refresh_models"] is False
    assert [item["id"] for item in generation.server_commands] == ["call-1", "call-2"]


def test_default_dispatch_requires_an_explicit_garak_checkout() -> None:
    import pytest

    ledger = RequestLedger("generation")
    with pytest.raises(RuntimeError, match="not configured"):
        dispatch_pinned_garak(
            {"user_text": "hello"},
            target_url="http://127.0.0.1:8888/sse",
            model_url="http://127.0.0.1:8321/v1/",
            model="fixture",
            ledger=ledger,
        )
    assert ledger.dispatches[0]["status"] == "failed"
