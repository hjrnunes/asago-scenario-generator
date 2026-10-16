"""In-memory MCP inventory and interpreter fakes for target-discovery tests."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

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
