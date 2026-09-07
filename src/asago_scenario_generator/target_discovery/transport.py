"""Optional live MCP transport adapter for the standalone scanner.

The module has no import-time dependency on ``mcp``.  Deterministic tests use
the in-memory :class:`McpInventoryAdapter` protocol, while this adapter is
only constructed by the standalone CLI or an explicitly opted-in caller.
"""

from __future__ import annotations

from collections.abc import Mapping
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

    def call_tool(self, tool_name: str, arguments: Mapping[str, Any]) -> Any:
        """Call one tool for explicit disposable-test inspection."""
        return _run_sync(self._call_tool_async(tool_name, arguments))

    async def _list_tools_async(self, cursor: str | None) -> McpInventoryPage:
        try:
            from mcp import ClientSession
            from mcp.client.sse import sse_client
        except ImportError as exc:  # pragma: no cover - exercised without extra
            raise McpTransportError(
                "live MCP scanning requires the optional 'target-discovery' extra"
            ) from exc
        try:
            async with sse_client(self._server_url, headers=self._headers) as streams:
                async with ClientSession(*streams) as session:
                    await session.initialize()
                    response = await session.list_tools(cursor=cursor)
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

    async def _call_tool_async(
        self,
        tool_name: str,
        arguments: Mapping[str, Any],
    ) -> Any:
        try:
            from mcp import ClientSession
            from mcp.client.sse import sse_client
        except ImportError as exc:  # pragma: no cover - exercised without extra
            raise McpTransportError(
                "live MCP scanning requires the optional 'target-discovery' extra"
            ) from exc
        try:
            async with sse_client(self._server_url, headers=self._headers) as streams:
                async with ClientSession(*streams) as session:
                    await session.initialize()
                    response = await session.call_tool(tool_name, dict(arguments))
        except Exception as exc:  # noqa: BLE001 - normalize SDK failures
            raise McpTransportError(
                f"MCP tool call transport failed: {type(exc).__name__}: {exc}"
            ) from exc
        return _model_payload(response)


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


__all__ = ["HttpMcpInventoryAdapter", "McpTransportError"]
