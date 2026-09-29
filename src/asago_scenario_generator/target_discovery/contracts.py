"""Closed boundaries for independent MCP target discovery.

The discovery package deliberately owns a small protocol-neutral adapter
surface.  ``McpInventoryAdapter`` is responsible for transport and
``TargetInterpreterFactory`` is responsible for one typed interpretation
request; the composition seam in :mod:`discovery` owns validation, identity,
and profile construction.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Protocol, TypeAlias

from pydantic import Field, StrictBool, StrictInt, StrictStr, model_validator

from asago_scenario_generator.models.canonical import ClosedCanonicalModel
from asago_scenario_generator.stpa.models.execution_classification import (
    DiscoveryMode,
    DiscoveryProvenance,
    ExecutionTargetProfile,
    InterpreterVerifierAgreement,
    McpInventoryObservation,
    McpToolObservation,
    TargetInterpretationDisposition,
    TargetOperationEffect,
    TargetStateEffect,
    TargetDiscoveryDiagnostic,
)


class McpTargetDiscoveryInputs(ClosedCanonicalModel):
    """Non-secret controls and identity for one discovery run."""

    target_id: StrictStr = Field(min_length=1)
    authorization_scope_id: StrictStr = Field(min_length=1)
    mode: DiscoveryMode = DiscoveryMode.schema_only
    interpretation_batch_size: StrictInt = Field(default=8, gt=0, le=128)
    scanner_id: StrictStr = Field(default="asago-target-scan", min_length=1)
    interpreter_id: StrictStr = Field(
        default="asago-target-interpreter-v1", min_length=1
    )
    verifier_id: StrictStr = Field(default="asago-target-verifier-v1", min_length=1)
    model_profile: StrictStr | None = Field(default=None, min_length=1)
    model_name: StrictStr | None = Field(default=None, min_length=1)
    active_inspection_tool_names: tuple[StrictStr, ...] = ()
    max_active_inspection_calls: StrictInt = Field(default=8, ge=0, le=32)

    @model_validator(mode="after")
    def validate_active_inspection(self) -> "McpTargetDiscoveryInputs":
        names = tuple(sorted(self.active_inspection_tool_names))
        if len(names) != len(set(names)):
            raise ValueError("active_inspection_tool_names must be unique")
        if any(not name for name in names):
            raise ValueError("active_inspection_tool_names must be non-empty")
        object.__setattr__(self, "active_inspection_tool_names", names)
        if self.mode is DiscoveryMode.schema_only and names:
            raise ValueError(
                "active_inspection_tool_names require disposable_test_environment"
            )
        if names and self.max_active_inspection_calls == 0:
            raise ValueError(
                "active inspection names require max_active_inspection_calls > 0"
            )
        return self


class McpInventoryPage(ClosedCanonicalModel):
    """One adapter page of exact MCP tool rows."""

    tools: tuple[Mapping[str, Any] | McpToolObservation, ...] = ()
    next_cursor: StrictStr | None = Field(default=None, min_length=1)
    complete: StrictBool = True

    @model_validator(mode="after")
    def validate_page_cursor(self) -> "McpInventoryPage":
        """Require a cursor when a page is explicitly marked incomplete."""
        if not self.complete and self.next_cursor is None:
            raise ValueError("incomplete MCP inventory page requires next_cursor")
        return self


InventoryAdapterResponse: TypeAlias = (
    McpInventoryPage
    | Mapping[str, Any]
    | Sequence[Mapping[str, Any] | McpToolObservation]
)


class McpInventoryAdapter(Protocol):
    """Transport-only adapter for the MCP ``tools/list`` operation."""

    def list_tools(self, cursor: str | None = None) -> InventoryAdapterResponse:
        """Return one tools/list page; pagination is protocol-owned."""

    def call_tool(self, tool_name: str, arguments: Mapping[str, Any]) -> Any:
        """Call one tool only when disposable inspection is explicitly enabled."""


class TargetInterpretationRequest(ClosedCanonicalModel):
    """Request-local prompt view for one bounded interpretation batch."""

    batch_id: StrictStr = Field(min_length=1)
    tools: tuple["TargetToolPromptView", ...] = Field(min_length=1)


class TargetInterpretationDraft(ClosedCanonicalModel):
    """Request-local, handle-based interpretation returned by a model.

    The model never receives or returns executable resource identities.  The
    scanner maps ``tool_handle`` to an exact observed MCP name only after all
    fields and evidence references have been validated.
    """

    tool_handle: StrictStr = Field(pattern=r"^TOOL-[0-9]+$")
    disposition: TargetInterpretationDisposition = (
        TargetInterpretationDisposition.unresolved
    )
    likely_effect: TargetOperationEffect = TargetOperationEffect.unknown
    likely_state_effect: TargetStateEffect = TargetStateEffect.unknown
    semantic_roles: tuple[StrictStr, ...] = ()
    observer_tool_handles: tuple[StrictStr, ...] = ()
    evidence_refs: tuple[StrictStr, ...] = Field(min_length=1)
    rationale: StrictStr = Field(min_length=1)
    interpreter_verifier_agreement: InterpreterVerifierAgreement = (
        InterpreterVerifierAgreement.unverified
    )


class TargetInterpretationResponse(ClosedCanonicalModel):
    """Typed response returned by a model interpretation adapter."""

    interpretations: tuple[TargetInterpretationDraft, ...] = ()
    response_digest: StrictStr | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class TargetInterpretationVerdict(ClosedCanonicalModel):
    """The independent verifier's verdict on one request-local interpretation."""

    tool_handle: StrictStr = Field(pattern=r"^TOOL-[0-9]+$")
    reason: StrictStr = Field(min_length=1)
    agreement: InterpreterVerifierAgreement

    @model_validator(mode="after")
    def validate_agreement(self) -> "TargetInterpretationVerdict":
        if self.agreement is InterpreterVerifierAgreement.unverified:
            raise ValueError("a verifier verdict is agree or disagree")
        return self


class TargetInterpretationVerification(ClosedCanonicalModel):
    """Closed per-tool result returned by the independent interpretation verifier.

    Each interpretation record carries its own verdict, so a disputed record
    does not withdraw verification from the other records in its batch.
    """

    verdicts: tuple[TargetInterpretationVerdict, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_unique_handles(self) -> "TargetInterpretationVerification":
        handles = [item.tool_handle for item in self.verdicts]
        duplicates = sorted({handle for handle in handles if handles.count(handle) > 1})
        if duplicates:
            raise ValueError(f"duplicate verdict handles: {', '.join(duplicates)}")
        return self


class TargetInterpreterAdapter(Protocol):
    """One provider-capable typed interpretation adapter."""

    def interpret(
        self, request: TargetInterpretationRequest
    ) -> TargetInterpretationResponse | Mapping[str, Any]:
        """Interpret one request-local batch."""

    def verify(
        self,
        request: TargetInterpretationRequest,
        response: TargetInterpretationResponse,
    ) -> Any:
        """Optionally independently verify one interpretation response."""


class TargetInterpreterFactory(Protocol):
    """Zero-argument factory for one typed interpretation adapter."""

    def __call__(self) -> TargetInterpreterAdapter:
        """Construct the already-configured interpretation adapter."""


class TargetToolPromptView(ClosedCanonicalModel):
    """Small closed prompt view for one exact observed tool."""

    handle: StrictStr = Field(pattern=r"^TOOL-[0-9]+$")
    name: StrictStr = Field(min_length=1)
    title: StrictStr | None = None
    description: StrictStr | None = None
    input_schema: Mapping[str, Any]
    output_schema: Any = None
    annotations: Mapping[str, Any] | None = None
    argument_names: tuple[StrictStr, ...] = ()
    evidence_refs: tuple[StrictStr, ...] = ()


TargetInterpretationRequest.model_rebuild()


class TargetDiscoveryResult(ClosedCanonicalModel):
    """Result of one independent inventory/interpretation composition."""

    mode: DiscoveryMode | None = None
    controls: Mapping[str, Any] = Field(default_factory=dict)
    profile: ExecutionTargetProfile | None = None
    inventory: McpInventoryObservation | None = None
    provenance: DiscoveryProvenance | None = None
    diagnostics: tuple[TargetDiscoveryDiagnostic, ...] = ()
    calls: tuple[Mapping[str, Any], ...] = ()

    @property
    def valid(self) -> bool:
        """Return whether a complete profile was produced without errors."""
        return self.profile is not None and not any(
            item.severity.value == "error" for item in self.diagnostics
        )


__all__ = [
    "InventoryAdapterResponse",
    "McpInventoryAdapter",
    "McpInventoryPage",
    "McpTargetDiscoveryInputs",
    "TargetDiscoveryResult",
    "TargetInterpretationDraft",
    "TargetInterpretationRequest",
    "TargetInterpretationResponse",
    "TargetInterpretationVerdict",
    "TargetInterpretationVerification",
    "TargetInterpreterAdapter",
    "TargetInterpreterFactory",
    "TargetToolPromptView",
]
