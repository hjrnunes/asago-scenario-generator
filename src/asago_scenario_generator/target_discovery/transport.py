"""MCP wire format: the optional live transport adapter and row normalization.

The module has no import-time dependency on ``mcp``.  Deterministic tests use
the in-memory :class:`McpInventoryAdapter` protocol, while the live adapter is
only constructed by the standalone CLI or an explicitly opted-in caller.  The
normalization functions map the protocol's page and tool spellings
(``nextCursor``, ``inputSchema``, JSON-RPC ``result`` wrapping) to the
canonical names discovery reads.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from .contracts import McpInventoryPage


class McpTransportError(RuntimeError):
    """Normalized live-transport failure."""


class HttpMcpInventoryAdapter:
    """Synchronous facade over the optional MCP SSE client.

    ``server_url`` and ``headers`` stay on this runtime-only adapter and are
    never copied into discovery models or persisted call records.
    """

    def __init__(
        self,
        server_url: str,
        *,
        headers: Mapping[str, str] | None = None,
        timeout: float = 30.0,
    ) -> None:
        if not server_url or not isinstance(server_url, str):
            raise ValueError("server_url must be a non-empty string")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self._server_url = server_url
        self._headers = dict(headers or {})
        self._timeout = timeout

    def list_tools(self, cursor: str | None = None) -> McpInventoryPage:
        """Call MCP ``initialize`` + ``tools/list`` for one page."""
        return _run_sync(self._list_tools_async(cursor))

    async def _list_tools_async(self, cursor: str | None) -> McpInventoryPage:
        try:
            from mcp import ClientSession
            from mcp.client.sse import sse_client
        except ImportError as exc:  # pragma: no cover - exercised without extra
            raise McpTransportError(
                "live MCP scanning requires the optional 'target-discovery' extra"
            ) from exc
        try:
            async with sse_client(
                self._server_url, headers=self._headers, timeout=self._timeout
            ) as streams:
                async with ClientSession(*streams) as session:
                    await session.initialize()
                    # The installed SDK exposes paging through the
                    # PaginatedRequestParams object, not a bare cursor kwarg.
                    if cursor:
                        from mcp.types import PaginatedRequestParams

                        response = await session.list_tools(
                            params=PaginatedRequestParams(cursor=cursor)
                        )
                    else:
                        response = await session.list_tools()
        except Exception as exc:  # noqa: BLE001 - normalize SDK failures
            raise McpTransportError(
                f"MCP tools/list transport failed: {type(exc).__name__}: {exc}"
            ) from exc
        payload = _model_payload(response)
        tools = payload.get("tools", ())
        next_cursor = payload.get("nextCursor", payload.get("next_cursor"))
        return McpInventoryPage(
            tools=tuple(tools),
            next_cursor=next_cursor,
            complete=next_cursor is None,
        )


def _run_sync(awaitable: Any) -> Any:
    """Run one SDK coroutine from the synchronous scanner seam."""
    import anyio

    async def runner() -> Any:
        return await awaitable

    return anyio.run(runner)


def _model_payload(value: Any) -> dict[str, Any]:
    """Convert one MCP SDK result to a plain mapping without retaining it."""
    if isinstance(value, Mapping):
        return dict(value)
    if hasattr(value, "model_dump"):
        return dict(value.model_dump(mode="python"))
    if hasattr(value, "__dict__"):
        return dict(vars(value))
    raise McpTransportError("MCP SDK returned an unsupported response shape")


def canonical_tool_fields(raw_tool: Any) -> dict[str, Any]:
    """Copy one transport tool row with its camelCase fields in canonical names."""
    return _normalize_transport_fields(_tool_source(raw_tool))


def normalize_page(raw_page: Any) -> McpInventoryPage:
    """Map transport-specific MCP response spelling to the closed page model."""
    if isinstance(raw_page, McpInventoryPage):
        return raw_page
    if isinstance(raw_page, Mapping):
        return _normalize_page_mapping(raw_page)
    if _is_page_sequence(raw_page):
        return McpInventoryPage(tools=tuple(raw_page))
    raise TypeError("tools/list adapter must return a page, mapping, or sequence")


def _normalize_page_mapping(raw_page: Mapping[str, Any]) -> McpInventoryPage:
    """Normalize a mapping response, including JSON-RPC result wrapping."""
    payload = raw_page.get("result")
    if not isinstance(payload, Mapping):
        payload = raw_page
    tools = payload.get("tools")
    if tools is None:
        raise ValueError("tools/list response is missing tools")
    next_cursor = payload.get("next_cursor", payload.get("nextCursor"))
    complete = payload.get("complete")
    return McpInventoryPage(
        tools=tuple(tools),
        next_cursor=next_cursor,
        complete=complete if complete is not None else next_cursor is None,
    )


def _is_page_sequence(raw_page: Any) -> bool:
    """Return whether a transport value is a non-string page sequence."""
    return isinstance(raw_page, Sequence) and not isinstance(
        raw_page, (str, bytes, bytearray)
    )


def _tool_source(raw_tool: Any) -> dict[str, Any]:
    """Extract one transport row without retaining its original object."""
    if isinstance(raw_tool, Mapping):
        return dict(raw_tool)
    if hasattr(raw_tool, "model_dump"):
        return dict(raw_tool.model_dump(mode="python"))
    if hasattr(raw_tool, "__dict__"):
        return dict(vars(raw_tool))
    raise TypeError("MCP tool row must be a mapping or model object")


def _normalize_transport_fields(source: dict[str, Any]) -> dict[str, Any]:
    """Map all supported MCP camelCase fields into canonical names."""
    for canonical, transport in (
        ("input_schema", "inputSchema"),
        ("output_schema", "outputSchema"),
        ("name", "name"),
        ("title", "title"),
        ("description", "description"),
        ("annotations", "annotations"),
    ):
        source = _map_transport_key(source, canonical, transport)
    return source


def _map_transport_key(
    source: dict[str, Any], canonical: str, transport: str
) -> dict[str, Any]:
    """Copy one transport spelling while rejecting conflicting duplicates."""
    if (
        canonical in source
        and transport in source
        and source[canonical] != source[transport]
    ):
        raise ValueError(f"conflicting {canonical}/{transport} values")
    if canonical not in source and transport in source:
        source[canonical] = source[transport]
    return source


def tool_name_hint(raw_tool: Any) -> str | None:
    """Extract a non-authoritative name solely for a diagnostic label."""
    if isinstance(raw_tool, Mapping):
        value = raw_tool.get("name")
        return value if isinstance(value, str) and value else None
    value = getattr(raw_tool, "name", None)
    return value if isinstance(value, str) and value else None


def tool_digest_payload(raw_tool: Any) -> Any:
    """Build a digest-only representation of a raw page row."""
    if isinstance(raw_tool, Mapping):
        source = dict(raw_tool)
        normalized: dict[str, Any] = {}
        for canonical, transport in (
            ("name", "name"),
            ("title", "title"),
            ("description", "description"),
            ("input_schema", "inputSchema"),
            ("output_schema", "outputSchema"),
            ("annotations", "annotations"),
        ):
            if canonical in source:
                normalized[canonical] = source[canonical]
            elif transport in source:
                normalized[canonical] = source[transport]
        return normalized
    if hasattr(raw_tool, "model_dump"):
        return raw_tool.model_dump(mode="json")
    return repr(raw_tool)


def looks_like_incomplete_page(raw_page: Any) -> bool:
    """Recognize a malformed incomplete page without trusting its payload."""
    if not isinstance(raw_page, Mapping):
        return False
    cursor = raw_page.get("next_cursor", raw_page.get("nextCursor"))
    return raw_page.get("complete") is False and (cursor is None or cursor == "")


__all__ = [
    "HttpMcpInventoryAdapter",
    "McpTransportError",
    "canonical_tool_fields",
    "looks_like_incomplete_page",
    "normalize_page",
    "tool_digest_payload",
    "tool_name_hint",
]
