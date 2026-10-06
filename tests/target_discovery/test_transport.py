"""Live MCP transport adapter tests with an in-memory SDK stand-in."""

from __future__ import annotations

import sys
from contextlib import asynccontextmanager
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from asago_scenario_generator.target_discovery import transport
from asago_scenario_generator.target_discovery.contracts import McpInventoryPage
from asago_scenario_generator.target_discovery.transport import (
    HttpMcpInventoryAdapter,
    McpTransportError,
)


class _Sdk:
    """Records the calls the adapter makes against the fake MCP SDK."""

    def __init__(self, response: Any = None, failure: Exception | None = None) -> None:
        self.response = response if response is not None else {"tools": []}
        self.failure = failure
        self.connections: list[dict[str, Any]] = []
        self.list_calls: list[dict[str, Any]] = []
        self.initialized = 0


class _PaginatedRequestParams:
    def __init__(self, *, cursor: str) -> None:
        self.cursor = cursor


def _install_sdk(monkeypatch: pytest.MonkeyPatch, sdk: _Sdk) -> None:
    @asynccontextmanager
    async def sse_client(url: str, headers: dict[str, str]):
        sdk.connections.append({"url": url, "headers": headers})
        yield ("read-stream", "write-stream")

    class ClientSession:
        def __init__(self, *streams: Any) -> None:
            sdk.connections[-1]["streams"] = streams

        async def __aenter__(self) -> "ClientSession":
            return self

        async def __aexit__(self, *exc_info: Any) -> None:
            return None

        async def initialize(self) -> None:
            sdk.initialized += 1

        async def list_tools(self, **kwargs: Any) -> Any:
            sdk.list_calls.append(kwargs)
            if sdk.failure is not None:
                raise sdk.failure
            return sdk.response

    modules = {
        "mcp": ModuleType("mcp"),
        "mcp.client": ModuleType("mcp.client"),
        "mcp.client.sse": ModuleType("mcp.client.sse"),
        "mcp.types": ModuleType("mcp.types"),
    }
    modules["mcp"].ClientSession = ClientSession  # type: ignore[attr-defined]
    modules["mcp.client.sse"].sse_client = sse_client  # type: ignore[attr-defined]
    modules["mcp.types"].PaginatedRequestParams = _PaginatedRequestParams  # type: ignore[attr-defined]
    for name, module in modules.items():
        monkeypatch.setitem(sys.modules, name, module)


class TestAdapterConstruction:
    @pytest.mark.parametrize("server_url", ["", None, 7])
    def test_server_url_must_be_a_non_empty_string(self, server_url) -> None:
        with pytest.raises(ValueError, match="server_url must be a non-empty string"):
            HttpMcpInventoryAdapter(server_url)  # type: ignore[arg-type]

    @pytest.mark.parametrize("timeout", [0, -1.5])
    def test_timeout_must_be_positive(self, timeout) -> None:
        with pytest.raises(ValueError, match="timeout must be positive"):
            HttpMcpInventoryAdapter("http://127.0.0.1:1/sse", timeout=timeout)

    def test_headers_are_copied_and_default_to_empty(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        headers = {"Authorization": "Bearer token"}
        sdk = _Sdk()
        _install_sdk(monkeypatch, sdk)

        HttpMcpInventoryAdapter("http://host/sse", headers=headers).list_tools()
        headers["Authorization"] = "changed"
        HttpMcpInventoryAdapter("http://host/sse").list_tools()

        assert sdk.connections[0]["headers"] == {"Authorization": "Bearer token"}
        assert sdk.connections[1]["headers"] == {}


class TestListTools:
    def test_first_page_is_listed_without_paging_parameters(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sdk = _Sdk({"tools": [{"name": "get_payment"}, {"name": "refund"}]})
        _install_sdk(monkeypatch, sdk)

        page = HttpMcpInventoryAdapter("http://host/sse").list_tools()

        assert page.tools == ({"name": "get_payment"}, {"name": "refund"})
        assert page.next_cursor is None
        assert page.complete is True
        assert sdk.initialized == 1
        assert sdk.list_calls == [{}]
        assert sdk.connections[0]["url"] == "http://host/sse"
        assert sdk.connections[0]["streams"] == ("read-stream", "write-stream")

    def test_cursor_is_sent_as_paginated_request_params(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sdk = _Sdk({"tools": [], "nextCursor": "page-3"})
        _install_sdk(monkeypatch, sdk)

        page = HttpMcpInventoryAdapter("http://host/sse").list_tools("page-2")

        [call] = sdk.list_calls
        assert call["params"].cursor == "page-2"
        assert page.next_cursor == "page-3"
        assert page.complete is False

    def test_snake_case_next_cursor_marks_the_page_incomplete(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_sdk(monkeypatch, _Sdk({"tools": [], "next_cursor": "more"}))

        page = HttpMcpInventoryAdapter("http://host/sse").list_tools()

        assert page.next_cursor == "more"
        assert page.complete is False

    def test_sdk_model_responses_are_converted_to_plain_payloads(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class Dumped:
            def model_dump(self, mode: str) -> dict[str, Any]:
                assert mode == "python"
                return {"tools": [{"name": "dumped"}]}

        _install_sdk(monkeypatch, _Sdk(Dumped()))

        page = HttpMcpInventoryAdapter("http://host/sse").list_tools()

        assert page.tools == ({"name": "dumped"},)

    def test_response_without_tools_is_an_empty_complete_page(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_sdk(monkeypatch, _Sdk(SimpleNamespace()))

        page = HttpMcpInventoryAdapter("http://host/sse").list_tools()

        assert page.tools == ()
        assert page.complete is True

    def test_sdk_failure_is_normalized_without_the_server_url(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_sdk(monkeypatch, _Sdk(failure=RuntimeError("connection refused")))

        with pytest.raises(McpTransportError) as caught:
            HttpMcpInventoryAdapter("http://secret-host/sse").list_tools()

        assert str(caught.value) == (
            "MCP tools/list transport failed: RuntimeError: connection refused"
        )
        assert isinstance(caught.value.__cause__, RuntimeError)


def test_normalizers_cover_transport_shapes_and_failures():
    typed = transport.normalize_page(McpInventoryPage(tools=()))
    wrapped = transport.normalize_page({"result": {"tools": [], "nextCursor": "next"}})
    sequence = transport.normalize_page([])

    assert typed.complete is True
    assert wrapped.next_cursor == "next"
    assert wrapped.complete is False
    assert sequence.tools == ()
    with pytest.raises(ValueError, match="missing tools"):
        transport.normalize_page({"result": {}})
    with pytest.raises(TypeError, match="page, mapping, or sequence"):
        transport.normalize_page("invalid")


def test_tool_source_and_name_hint_cover_closed_input_shapes():
    class Dumped:
        def model_dump(self, *, mode):
            assert mode == "python"
            return {"name": "dumped"}

    assert transport._tool_source({"name": "mapping"}) == {"name": "mapping"}
    assert transport._tool_source(Dumped()) == {"name": "dumped"}
    assert transport._tool_source(SimpleNamespace(name="object")) == {"name": "object"}
    with pytest.raises(TypeError, match="mapping or model"):
        transport._tool_source(object())

    assert transport.tool_name_hint({"name": "mapping"}) == "mapping"
    assert transport.tool_name_hint({"name": 1}) is None
    assert transport.tool_name_hint(SimpleNamespace(name="object")) == "object"
    assert transport.tool_name_hint(SimpleNamespace()) is None


def test_transport_alias_conflicts_and_digest_payload_shapes_are_closed():
    assert transport._map_transport_key({}, "input_schema", "inputSchema") == {}
    assert transport._map_transport_key(
        {"inputSchema": {"type": "object"}}, "input_schema", "inputSchema"
    ) == {"inputSchema": {"type": "object"}, "input_schema": {"type": "object"}}
    with pytest.raises(ValueError, match="conflicting"):
        transport._map_transport_key(
            {"input_schema": {}, "inputSchema": {"type": "object"}},
            "input_schema",
            "inputSchema",
        )

    class DumpedJson:
        def model_dump(self, *, mode):
            assert mode == "json"
            return {"name": "dumped"}

    assert transport.tool_digest_payload({"name": "mapped"}) == {"name": "mapped"}
    assert transport.tool_digest_payload(DumpedJson()) == {"name": "dumped"}
    assert transport.tool_digest_payload(SimpleNamespace())


def test_canonical_tool_fields_add_snake_case_names_for_camel_case_rows():
    schema = {"type": "object"}
    assert transport.canonical_tool_fields(
        SimpleNamespace(name="read", inputSchema=schema, outputSchema=None)
    ) == {
        "name": "read",
        "inputSchema": schema,
        "outputSchema": None,
        "input_schema": schema,
        "output_schema": None,
    }
