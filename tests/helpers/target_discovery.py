"""In-memory MCP inventory and interpreter fakes for target-discovery tests."""

from __future__ import annotations

import sys
from collections.abc import Callable
from contextlib import asynccontextmanager
from types import ModuleType
from typing import Any

import pytest

from asago_scenario_generator.stpa.models.execution_classification import (
    TargetInterpretationDisposition,
    TargetOperationEffect,
    TargetStateEffect,
)
from asago_scenario_generator.target_discovery import (
    TargetInterpretationDraft,
    TargetInterpretationRequest,
    TargetInterpretationResponse,
)

OBSERVER = "get_klarna_state_summary"


class FakeMcpSdk:
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


def install_fake_mcp_sdk(monkeypatch: pytest.MonkeyPatch, sdk: FakeMcpSdk) -> None:
    """Install an in-memory stand-in for the optional ``mcp`` SDK modules."""

    @asynccontextmanager
    async def sse_client(url: str, headers: dict[str, str], **kwargs: Any):
        sdk.connections.append({"url": url, "headers": headers, **kwargs})
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


class InMemoryInventory:
    """Serve *payload* as the tool list and record every call made to it."""

    def __init__(self, payload: dict) -> None:
        self.payload = payload
        self.list_calls: list[str | None] = []
        self.tool_calls: list[tuple[str, dict]] = []

    def list_tools(self, cursor: str | None = None):
        self.list_calls.append(cursor)
        return self.payload

    def call_tool(self, name: str, arguments: dict):
        self.tool_calls.append((name, arguments))
        return {"name": name}


class InMemoryInterpreter:
    """Interpret every tool as a supported read and answer verification with *verify*.

    *verify* receives the verification request and returns whatever the verifier
    adapter would: a bool, a verification object or a plain mapping. It defaults
    to agreeing with every interpretation.
    """

    def __init__(self, verify: Callable[[Any], Any] = lambda request: True) -> None:
        self.requests: list[TargetInterpretationRequest] = []
        self._verify = verify

    def interpret(self, request):
        self.requests.append(request)
        return TargetInterpretationResponse(
            interpretations=tuple(
                TargetInterpretationDraft(
                    tool_handle=tool.handle,
                    disposition=TargetInterpretationDisposition.supported,
                    likely_effect=(
                        TargetOperationEffect.observe
                        if tool.name == OBSERVER
                        else TargetOperationEffect.read
                    ),
                    likely_state_effect=TargetStateEffect.none,
                    semantic_roles=("observer",)
                    if tool.name == OBSERVER
                    else ("reader",),
                    observer_tool_handles=(),
                    evidence_refs=(f"inventory:tool:{tool.name}:description",),
                    rationale="The quoted description supports this bounded label.",
                )
                for tool in request.tools
            )
        )

    def verify(self, request, response):
        del response
        return self._verify(request)
