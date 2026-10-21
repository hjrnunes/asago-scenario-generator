"""MCP wire format: inventory adapters and row normalization.

The module has no import-time dependency on ``mcp``.  Deterministic tests use
the in-memory :class:`McpInventoryAdapter` protocol, while the live adapter is
only constructed by the standalone CLI or an explicitly opted-in caller.  The
file adapter serves a declared ``tools/list`` result from disk and never
imports ``mcp``.  The normalization functions map the protocol's page and tool
spellings (``nextCursor``, ``inputSchema``, JSON-RPC ``result`` wrapping) to
the canonical names discovery reads.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
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


class McpToolsListFileError(ValueError):
    """A declared tools/list file that cannot be served as one inventory.

    The message always starts with the file path.
    """


class FileMcpInventoryAdapter:
    """Serve a declared MCP ``tools/list`` result from a JSON file.

    The file holds one ``tools/list`` result (``{"tools": [...]}``, optionally
    wrapped in a JSON-RPC ``result``) or a JSON list of such pages.  Pages are
    served in file order: the first page answers ``tools/list`` without a
    cursor, each page's ``nextCursor`` is the cursor that requests the page
    after it, and only the last page omits ``nextCursor``.  The whole file and
    its cursor chain are checked on construction, so a bad file fails before
    discovery runs.  Each tool row is given the shape the live adapter
    receives from the MCP SDK (see :func:`sdk_shaped_tool_row`), so a sparse
    file and a live scan of the same tools observe the same inventory.
    """

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        self._pages = _pages_by_cursor(self._path, _read_tools_list_file(self._path))

    def list_tools(self, cursor: str | None = None) -> McpInventoryPage:
        """Return the page the cursor names; ``None`` names the first page."""
        try:
            return self._pages[cursor]
        except KeyError:
            raise McpToolsListFileError(
                f"{self._path}: no page for cursor {cursor!r}"
            ) from None


def _read_tools_list_file(path: Path) -> list[Any]:
    """Read the file's JSON and return its raw pages."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise McpToolsListFileError(f"{path}: file not found") from None
    except (OSError, UnicodeDecodeError) as exc:
        raise McpToolsListFileError(f"{path}: cannot read file: {exc}") from None
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise McpToolsListFileError(f"{path}: invalid JSON: {exc}") from None
    if isinstance(payload, Mapping):
        return [payload]
    if isinstance(payload, list) and payload:
        return payload
    raise McpToolsListFileError(
        f"{path}: expected a tools/list result or a non-empty list of them"
    )


def _pages_by_cursor(
    path: Path, raw_pages: Sequence[Any]
) -> dict[str | None, McpInventoryPage]:
    """Normalize every page and index it by the cursor that requests it."""
    pages = [
        _file_page(path, index, raw_page) for index, raw_page in enumerate(raw_pages)
    ]
    by_cursor: dict[str | None, McpInventoryPage] = {None: pages[0]}
    named_page: dict[str, int] = {}
    for index, page in enumerate(pages):
        next_cursor = page.next_cursor
        following = len(pages) - index - 1
        if next_cursor is None:
            if following:
                raise McpToolsListFileError(
                    f"{path}: page {index} has no nextCursor "
                    f"but {following} more page(s) follow"
                )
            continue
        if next_cursor in named_page:
            raise McpToolsListFileError(
                f"{path}: page {index} nextCursor {next_cursor!r} loops back to "
                f"page {named_page[next_cursor]}"
            )
        if not following:
            raise McpToolsListFileError(
                f"{path}: page {index} nextCursor {next_cursor!r} names a missing page"
            )
        named_page[next_cursor] = index + 1
        by_cursor[next_cursor] = pages[index + 1]
    return by_cursor


def _file_page(path: Path, index: int, raw_page: Any) -> McpInventoryPage:
    """Normalize one file page or name why it is not a tools/list result."""
    problem = _tools_list_problem(raw_page)
    if problem is None:
        try:
            page = _normalize_page_mapping(raw_page)
        except ValueError as exc:
            problem = str(exc)
        else:
            return McpInventoryPage(
                tools=tuple(sdk_shaped_tool_row(tool) for tool in page.tools),
                next_cursor=page.next_cursor,
                complete=page.complete,
            )
    raise McpToolsListFileError(
        f"{path}: page {index} is not a tools/list result: {problem}"
    )


def _tools_list_problem(raw_page: Any) -> str | None:
    """Describe what keeps a JSON value from being a tools/list result."""
    if not isinstance(raw_page, Mapping):
        return f"expected a JSON object, got {type(raw_page).__name__}"
    payload = raw_page.get("result")
    if not isinstance(payload, Mapping):
        payload = raw_page
    tools = payload.get("tools")
    if not isinstance(tools, list):
        return "missing a tools list"
    for index, tool in enumerate(tools):
        if not isinstance(tool, Mapping):
            return f"tool {index} is not a JSON object"
    next_cursor = payload.get("nextCursor", payload.get("next_cursor"))
    if next_cursor is not None and not (isinstance(next_cursor, str) and next_cursor):
        return "nextCursor must be a non-empty string"
    if next_cursor is not None and payload.get("complete") is True:
        return "complete is true but nextCursor names another page"
    return None


# How the MCP SDK pinned in uv.lock (mcp 1.29.1) shapes a live tools/list row:
# the live adapter receives ``Tool.model_validate(row).model_dump(mode="python")``,
# which lists every declared field in this order, fills an absent optional one
# with None, emits ``_meta`` under its field name ``meta`` and keeps extra
# fields after them.  Nested ``ToolAnnotations``, ``Icon`` and ``ToolExecution``
# mappings are filled the same way.  Re-check these when the pin moves:
# test_file_inventory compares them with the SDK whenever the
# target-discovery extra is installed.
SDK_TOOL_FIELDS = (
    "name",
    "title",
    "description",
    "inputSchema",
    "outputSchema",
    "icons",
    "annotations",
    "meta",
    "execution",
)
SDK_TOOL_REQUIRED_FIELDS = frozenset({"name", "inputSchema"})
SDK_TOOL_FIELD_ALIASES = {"_meta": "meta"}
SDK_TOOL_ANNOTATION_FIELDS = (
    "title",
    "readOnlyHint",
    "destructiveHint",
    "idempotentHint",
    "openWorldHint",
)
SDK_ICON_FIELDS = ("src", "mimeType", "sizes")
SDK_TOOL_EXECUTION_FIELDS = ("taskSupport",)


def sdk_shaped_tool_row(raw_tool: Mapping[str, Any]) -> dict[str, Any]:
    """Shape one declared tool row as the live adapter receives it from the SDK.

    Explicit values and extra fields are preserved; a missing required field
    stays missing so discovery reports the row as malformed.
    """
    source = dict(raw_tool)
    for alias, field in SDK_TOOL_FIELD_ALIASES.items():
        if alias in source:
            source[field] = source.pop(alias)
    row = {
        field: source.pop(field, None)
        for field in SDK_TOOL_FIELDS
        if field in source or field not in SDK_TOOL_REQUIRED_FIELDS
    }
    row.update(source)
    for field, nested_fields in (
        ("annotations", SDK_TOOL_ANNOTATION_FIELDS),
        ("execution", SDK_TOOL_EXECUTION_FIELDS),
    ):
        if isinstance(row[field], Mapping):
            row[field] = _sdk_shaped_fields(row[field], nested_fields)
    if isinstance(row["icons"], list):
        row["icons"] = [
            _sdk_shaped_fields(icon, SDK_ICON_FIELDS)
            if isinstance(icon, Mapping)
            else icon
            for icon in row["icons"]
        ]
    return row


def _sdk_shaped_fields(
    source: Mapping[str, Any], fields: Sequence[str]
) -> dict[str, Any]:
    """Fill absent declared fields with None, keeping extra fields after them."""
    shaped = {field: source.get(field) for field in fields}
    shaped.update((key, value) for key, value in source.items() if key not in shaped)
    return shaped


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
    "FileMcpInventoryAdapter",
    "HttpMcpInventoryAdapter",
    "McpToolsListFileError",
    "McpTransportError",
    "SDK_ICON_FIELDS",
    "SDK_TOOL_ANNOTATION_FIELDS",
    "SDK_TOOL_EXECUTION_FIELDS",
    "SDK_TOOL_FIELDS",
    "canonical_tool_fields",
    "looks_like_incomplete_page",
    "normalize_page",
    "sdk_shaped_tool_row",
    "tool_digest_payload",
    "tool_name_hint",
]
