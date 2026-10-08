"""Closed semantic execution contracts and deterministic classifications.

This module describes what a published STPA projection needs in order to be
exercised.  It deliberately stops at semantic resources: endpoints,
credentials, locators and platform-specific bindings belong to the consumer.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from enum import Enum
from typing import Any, ClassVar, Literal

from pydantic import Field, StrictBool, StrictStr, field_validator, model_validator

from asago_scenario_generator.models.canonical import (
    ClosedCanonicalModel,
    FrozenDict,
    FrozenList,
    SemanticDigestMixin,
    canonical_json_bytes,
)


EXECUTION_TARGET_PROFILE_SCHEMA_VERSION = "execution-target-profile-v1"
EXECUTION_TARGET_PROFILE_DIGEST_FRAME = EXECUTION_TARGET_PROFILE_SCHEMA_VERSION
MCP_INVENTORY_SCHEMA_VERSION = "mcp-inventory-v1"
MCP_INVENTORY_DIGEST_FRAME = MCP_INVENTORY_SCHEMA_VERSION
SHA256_PATTERN = r"^[0-9a-f]{64}$"


class _Model(ClosedCanonicalModel):
    """Immutable closed model for the execution classification contract."""


class _DigestModel(SemanticDigestMixin, _Model):
    """Closed model with an optional derived semantic digest."""

    _digest_domain: ClassVar[str]
    semantic_digest: StrictStr | None = Field(default=None, pattern=SHA256_PATTERN)

    def assert_integrity(self) -> None:
        """Raise when the recorded digest does not match model content."""
        if self.semantic_digest != self.compute_semantic_digest():
            raise ValueError("semantic_digest does not match model content")

    def canonical_json_bytes(self) -> bytes:
        """Return canonical JSON bytes including the derived digest."""
        return canonical_json_bytes(self.model_dump(mode="json"))


class ExecutionActionKind(str, Enum):
    """The semantic action whose unsafe outcome is observed."""

    model_output = "model_output"
    tool_call = "tool_call"
    state_change = "state_change"
    agent_message = "agent_message"
    environment_action = "environment_action"


class ExecutionResourceKind(str, Enum):
    """Platform-neutral kind of semantic resource."""

    surface = "surface"
    tool = "tool"
    integration = "integration"
    state_store = "state_store"
    agent_channel = "agent_channel"


class ProfileBasis(str, Enum):
    """The profile describes a real target or an explicit simulation."""

    target = "target"
    simulation = "simulation"


class InventoryAuthority(str, Enum):
    """Authority of the protocol inventory itself."""

    observed = "observed"


class SemanticAuthority(str, Enum):
    """Authority of semantic interpretations attached to an inventory."""

    inferred = "inferred"
    reviewed = "reviewed"


class SourceProtocol(str, Enum):
    """Protocol from which an execution target inventory was observed."""

    mcp = "mcp"
    simulation = "simulation"


class TargetInterpretationDisposition(str, Enum):
    """Closed interpretation outcome for one observed tool."""

    supported = "supported"
    ambiguous = "ambiguous"
    contradictory = "contradictory"
    unresolved = "unresolved"


class TargetOperationEffect(str, Enum):
    """Bounded likely effect vocabulary for an interpreted tool."""

    read = "read"
    create = "create"
    update = "update"
    delete = "delete"
    execute = "execute"
    notify = "notify"
    escalate = "escalate"
    observe = "observe"
    unknown = "unknown"


class TargetStateEffect(str, Enum):
    """Bounded likely state-effect vocabulary for an interpreted tool."""

    none = "none"
    may_change = "may_change"
    changes = "changes"
    unknown = "unknown"


class InterpreterVerifierAgreement(str, Enum):
    """Typed agreement state between the interpretation and verifier passes."""

    agree = "agree"
    disagree = "disagree"
    unverified = "unverified"


class AttackerInfluence(str, Enum):
    """Whether an adversary can influence a target resource."""

    none = "none"
    direct = "direct"
    indirect = "indirect"
    unknown = "unknown"


class ExecutionSurface(str, Enum):
    """Closed semantic surfaces exposed by a target resource."""

    user_input = "user_input"
    external_content = "external_content"
    conversation_context = "conversation_context"
    tool_call = "tool_call"
    tool_result = "tool_result"
    tool_definition = "tool_definition"
    state_observation = "state_observation"
    agent_message = "agent_message"
    environment_event = "environment_event"


class InventoryCompleteness(str, Enum):
    """Completeness of a protocol inventory observation."""

    unknown = "unknown"
    observed_partial = "observed_partial"
    observed_complete = "observed_complete"


class DiscoveryMode(str, Enum):
    """Whether discovery only observes the protocol or may call tools."""

    schema_only = "schema_only"


class TargetDiscoveryDiagnosticCode(str, Enum):
    """Closed scanner diagnostic vocabulary."""

    inventory_protocol_failure = "inventory_protocol_failure"
    unsupported_protocol = "unsupported_protocol"
    duplicate_tool_name = "duplicate_tool_name"
    malformed_tool = "malformed_tool"
    malformed_schema = "malformed_schema"
    incomplete_pagination = "incomplete_pagination"
    interpretation_missing = "interpretation_missing"
    interpretation_invalid = "interpretation_invalid"
    interpretation_unknown_reference = "interpretation_unknown_reference"
    interpretation_contradictory = "interpretation_contradictory"
    verifier_disagreement = "verifier_disagreement"
    interpreter_failure = "interpreter_failure"
    active_inspection_disabled = "active_inspection_disabled"
    active_inspection_failure = "active_inspection_failure"


class TargetDiscoverySeverity(str, Enum):
    """Severity of one scanner diagnostic."""

    warning = "warning"
    error = "error"


class DiscoveryProvenance(_Model):
    """Non-secret identities and prompt pins for one discovery run."""

    scanner_id: StrictStr = Field(min_length=1)
    interpreter_id: StrictStr = Field(min_length=1)
    verifier_id: StrictStr = Field(min_length=1)
    scanner_contract_version: StrictStr = Field(
        default=EXECUTION_TARGET_PROFILE_SCHEMA_VERSION, min_length=1
    )
    interpreter_prompt_hash: StrictStr | None = Field(
        default=None, pattern=SHA256_PATTERN
    )
    verifier_prompt_hash: StrictStr | None = Field(default=None, pattern=SHA256_PATTERN)
    model_profile: StrictStr | None = Field(default=None, min_length=1)
    model_name: StrictStr | None = Field(default=None, min_length=1)


class McpToolObservation(_Model):
    """Exact, semantic-neutral fields copied from one MCP ``tools/list`` row."""

    name: StrictStr = Field(min_length=1)
    source_observation_sha256: StrictStr = Field(pattern=SHA256_PATTERN)
    title: StrictStr | None = Field(default=None, min_length=1)
    description: StrictStr | None = None
    input_schema: dict[str, Any]
    output_schema: Any = None
    annotations: dict[str, Any] | None = None
    argument_names: tuple[StrictStr, ...] = ()

    @field_validator("input_schema", "output_schema", "annotations", mode="before")
    @classmethod
    def freeze_json_fields(cls, value: Any) -> Any:
        """Retain JSON shape while closing nested mutable values."""
        return _freeze_json(value)

    @model_validator(mode="after")
    def validate_observation(self) -> "McpToolObservation":
        """Validate the input schema and derive exact argument names."""
        _validate_json_schema(self.input_schema, "input_schema")
        if self.output_schema is not None and isinstance(self.output_schema, dict):
            _validate_json_schema(self.output_schema, "output_schema")
        properties = self.input_schema.get("properties", {})
        if properties is None:
            properties = {}
        if not isinstance(properties, Mapping):
            raise ValueError("input_schema.properties must be a mapping")
        names = tuple(sorted(str(name) for name in properties))
        if any(not name for name in names):
            raise ValueError("input_schema property names must be non-empty")
        object.__setattr__(self, "argument_names", names)
        return self

    @property
    def tool_name(self) -> str:
        """Return the protocol tool name under the resource vocabulary."""
        return self.name


class McpInventoryObservation(_DigestModel):
    """Content-addressed normalized result of one MCP ``tools/list``."""

    _digest_domain = MCP_INVENTORY_DIGEST_FRAME
    schema_version: Literal[MCP_INVENTORY_SCHEMA_VERSION] = MCP_INVENTORY_SCHEMA_VERSION
    target_id: StrictStr = Field(min_length=1)
    authorization_scope_id: StrictStr = Field(min_length=1)
    source_protocol: Literal["mcp"] = "mcp"
    tools: tuple[McpToolObservation, ...] = ()
    pagination_complete: StrictBool = True
    page_count: int = Field(default=1, ge=1)

    @model_validator(mode="after")
    def canonicalize_and_digest(self) -> "McpInventoryObservation":
        """Sort tools by exact protocol name and derive the inventory digest."""
        tools = tuple(sorted(self.tools, key=lambda item: item.name))
        names = tuple(item.name for item in tools)
        _ensure_unique_nonempty(names, "MCP tool names")
        object.__setattr__(self, "tools", tools)
        self._attest_semantic_digest(
            "semantic_digest does not match MCP inventory content"
        )
        return self


class TargetProfileOperation(_Model):
    """One exact operation exposed by a target resource.

    For an MCP resource the protocol tool name is the operation identity.  A
    separate semantic operation label is retained for simulation resources;
    MCP profile validation applies the exact-name rule at the resource/profile
    boundary.  Model output may describe MCP meaning only through
    ``TargetSemanticInterpretation``.
    """

    operation_id: StrictStr = Field(min_length=1)
    semantic_operation: StrictStr | None = Field(default=None, min_length=1)
    argument_names: tuple[StrictStr, ...] = ()
    observable_properties: tuple[StrictStr, ...] = ()

    @model_validator(mode="after")
    def validate_operation(self) -> "TargetProfileOperation":
        """Canonicalize operation metadata without changing its identity."""
        semantic_operation = self.semantic_operation or self.operation_id
        argument_names = tuple(sorted(self.argument_names))
        observable_properties = tuple(sorted(self.observable_properties))
        _ensure_unique_nonempty(argument_names, "argument_names")
        _ensure_unique_nonempty(observable_properties, "observable_properties")
        _ensure_lower_snake(observable_properties, "observable_properties")
        object.__setattr__(self, "semantic_operation", semantic_operation)
        object.__setattr__(self, "argument_names", argument_names)
        object.__setattr__(self, "observable_properties", observable_properties)
        return self


class SimulationBehavior(_Model):
    """Closed deterministic behavior of one simulated resource."""

    inputs: dict[str, Any] = Field(default_factory=dict)
    outputs: dict[str, Any] = Field(default_factory=dict)
    emitted_events: tuple[StrictStr, ...] = ()
    state_changes: dict[str, Any] = Field(default_factory=dict)
    observation_points: tuple[StrictStr, ...] = ()

    @field_validator("inputs", "outputs", "state_changes", mode="before")
    @classmethod
    def freeze_json_maps(cls, value: Mapping[str, Any]) -> dict[str, Any] | FrozenDict:
        return _freeze_json(value)

    @model_validator(mode="after")
    def validate_behavior(self) -> "SimulationBehavior":
        if not self.inputs or not self.outputs:
            raise ValueError("simulation behavior requires inputs and outputs")
        if not self.observation_points:
            raise ValueError("simulation behavior requires observation_points")
        for label, values in (
            ("emitted_events", self.emitted_events),
            ("observation_points", self.observation_points),
        ):
            _ensure_unique_nonempty(values, label)
        object.__setattr__(self, "emitted_events", tuple(sorted(self.emitted_events)))
        object.__setattr__(
            self, "observation_points", tuple(sorted(self.observation_points))
        )
        return self


class TargetProfileResource(_Model):
    """One semantic resource in either an MCP or simulation profile.

    MCP resources use the populated ``tool_name``/schema fields and exactly
    one operation.  Simulation resources retain the original generic resource
    vocabulary and must be paired with ``simulation_behavior`` by the profile
    branch; they do not need to pretend that an MCP inventory exists.
    """

    resource_id: StrictStr = Field(min_length=1)
    resource_kind: ExecutionResourceKind = ExecutionResourceKind.tool
    target_id: StrictStr | None = Field(default=None, min_length=1)
    tool_name: StrictStr | None = Field(default=None, min_length=1)
    title: StrictStr | None = Field(default=None, min_length=1)
    description: StrictStr | None = None
    input_schema: dict[str, Any] = Field(default_factory=dict)
    output_schema: Any = None
    annotations: dict[str, Any] | None = None
    argument_names: tuple[StrictStr, ...] = ()
    surfaces: tuple[ExecutionSurface, ...] = ()
    operations: tuple[TargetProfileOperation, ...] = ()
    evidence_refs: tuple[StrictStr, ...] = Field(min_length=1)
    # These fields remain semantic-resource conveniences used by the existing
    # execution matcher.  Discovery leaves them empty/unknown: interpretation
    # is represented by the separate typed record below.
    role_ids: tuple[StrictStr, ...] = ()
    structural_refs: tuple[StrictStr, ...] = ()
    attacker_influence: AttackerInfluence = AttackerInfluence.unknown
    simulation_behavior: SimulationBehavior | None = None

    @field_validator("input_schema", "output_schema", "annotations", mode="before")
    @classmethod
    def freeze_interface_json(cls, value: Any) -> Any:
        """Close exact interface JSON while retaining opaque output schemas."""
        return _freeze_json(value)

    @model_validator(mode="after")
    def validate_target_profile_resource(self) -> "TargetProfileResource":
        """Validate exact MCP fields while retaining generic simulation shape."""
        self._canonicalize_argument_names()
        self._canonicalize_resource_refs()
        operations = tuple(sorted(self.operations, key=lambda item: item.operation_id))
        _ensure_unique_ids(operations, "operation_id", "resource operations")
        if self.tool_name is not None:
            self._validate_mcp_tool(operations)
        object.__setattr__(self, "operations", operations)
        return self

    def _canonicalize_argument_names(self) -> None:
        _validate_json_schema(self.input_schema, "input_schema")
        if self.output_schema is not None and isinstance(self.output_schema, dict):
            _validate_json_schema(self.output_schema, "output_schema")
        derived_args = _input_schema_argument_names(self.input_schema)
        provided_args = tuple(sorted(self.argument_names))
        if provided_args and derived_args and provided_args != derived_args:
            raise ValueError("argument_names must match input_schema properties")
        effective_args = derived_args or provided_args
        _ensure_unique_nonempty(effective_args, "argument_names")
        object.__setattr__(self, "argument_names", effective_args)

    def _canonicalize_resource_refs(self) -> None:
        surfaces = tuple(sorted(set(self.surfaces), key=lambda item: item.value))
        object.__setattr__(self, "surfaces", surfaces)
        evidence_refs = tuple(sorted(self.evidence_refs))
        _ensure_unique_nonempty(evidence_refs, "evidence_refs")
        object.__setattr__(self, "evidence_refs", evidence_refs)
        for field_name in ("role_ids", "structural_refs"):
            values = tuple(sorted(getattr(self, field_name)))
            _ensure_unique_nonempty(values, field_name)
            object.__setattr__(self, field_name, values)

    def _validate_mcp_tool(
        self, operations: tuple[TargetProfileOperation, ...]
    ) -> None:
        if self.resource_kind is not ExecutionResourceKind.tool:
            raise ValueError("tool_name is only valid for tool resources")
        if self.target_id is None:
            raise ValueError("MCP tool resources require target_id")
        if not {
            ExecutionSurface.tool_call,
            ExecutionSurface.tool_result,
        }.issubset(self.surfaces):
            raise ValueError("MCP resources require tool_call and tool_result surfaces")
        if len(operations) != 1:
            raise ValueError("MCP resources require exactly one operation")
        operation = operations[0]
        if operation.operation_id != self.tool_name:
            raise ValueError("MCP operation_id must equal tool_name")
        if operation.semantic_operation != self.tool_name:
            raise ValueError("MCP semantic_operation must equal the exact tool name")
        if operation.argument_names != self.argument_names:
            raise ValueError("operation argument_names must match input schema")


def _input_schema_argument_names(input_schema: Mapping[str, Any]) -> tuple[str, ...]:
    """Return the sorted property names of an input schema; null means none."""
    schema_properties = input_schema.get("properties", {})
    if schema_properties is None:
        schema_properties = {}
    if not isinstance(schema_properties, Mapping):
        raise ValueError("input_schema.properties must be a mapping")
    return tuple(sorted(str(name) for name in schema_properties))


class TargetSemanticInterpretation(_Model):
    """Typed, model-assisted interpretation of one observed MCP tool."""

    resource_id: StrictStr = Field(min_length=1)
    tool_name: StrictStr = Field(min_length=1)
    disposition: TargetInterpretationDisposition
    likely_effect: TargetOperationEffect = TargetOperationEffect.unknown
    likely_state_effect: TargetStateEffect = TargetStateEffect.unknown
    semantic_roles: tuple[StrictStr, ...] = ()
    observer_resource_ids: tuple[StrictStr, ...] = ()
    evidence_refs: tuple[StrictStr, ...] = Field(min_length=1)
    rationale: StrictStr = Field(min_length=1)
    interpreter_verifier_agreement: InterpreterVerifierAgreement = (
        InterpreterVerifierAgreement.unverified
    )

    @model_validator(mode="after")
    def canonicalize_interpretation(self) -> "TargetSemanticInterpretation":
        """Canonicalize set-like labels and preserve typed agreement."""
        roles = tuple(sorted(self.semantic_roles))
        _ensure_unique_nonempty(roles, "semantic_roles")
        _ensure_lower_snake(roles, "semantic_roles")
        observers = tuple(sorted(self.observer_resource_ids))
        _ensure_unique_nonempty(observers, "observer_resource_ids")
        evidence = tuple(sorted(self.evidence_refs))
        _ensure_unique_nonempty(evidence, "evidence_refs")
        object.__setattr__(self, "semantic_roles", roles)
        object.__setattr__(self, "observer_resource_ids", observers)
        object.__setattr__(self, "evidence_refs", evidence)
        return self

    @property
    def agreement(self) -> InterpreterVerifierAgreement:
        """Compatibility spelling for the typed interpreter/verifier state."""
        return self.interpreter_verifier_agreement


class TargetDiscoveryDiagnostic(_Model):
    """One retained scanner or interpretation diagnostic."""

    code: TargetDiscoveryDiagnosticCode
    severity: TargetDiscoverySeverity = TargetDiscoverySeverity.error
    detail: StrictStr = Field(min_length=1)
    tool_name: StrictStr | None = Field(default=None, min_length=1)
    evidence_refs: tuple[StrictStr, ...] = ()

    @model_validator(mode="after")
    def canonicalize_evidence(self) -> "TargetDiscoveryDiagnostic":
        """Canonicalize evidence references without hiding diagnostics."""
        evidence_refs = tuple(sorted(self.evidence_refs))
        _ensure_unique_nonempty(evidence_refs, "evidence_refs")
        object.__setattr__(self, "evidence_refs", evidence_refs)
        return self


_MCP_INVENTORY_ERROR_CODES = frozenset(
    {
        TargetDiscoveryDiagnosticCode.inventory_protocol_failure,
        TargetDiscoveryDiagnosticCode.unsupported_protocol,
        TargetDiscoveryDiagnosticCode.duplicate_tool_name,
        TargetDiscoveryDiagnosticCode.malformed_tool,
        TargetDiscoveryDiagnosticCode.malformed_schema,
        TargetDiscoveryDiagnosticCode.incomplete_pagination,
    }
)

# Resource fields mirrored from the inventory tool, in check order.
_MCP_RESOURCE_MIRRORED_FIELDS = (
    "title",
    "description",
    "input_schema",
    "output_schema",
    "annotations",
    "argument_names",
)


def _mcp_profile_inventory(profile: ExecutionTargetProfile) -> McpInventoryObservation:
    """Return the embedded inventory after checking MCP provenance and identity."""
    if profile.basis is not ProfileBasis.target:
        raise ValueError("MCP profiles require basis=target")
    if profile.inventory_authority is not InventoryAuthority.observed:
        raise ValueError("MCP inventory authority must be observed")
    inventory = profile.inventory
    if inventory is None:
        raise ValueError("MCP profiles require an embedded inventory")
    if profile.source_inventory_digest is None:
        raise ValueError("MCP profiles require source_inventory_digest")
    if profile.discovery_provenance is None:
        raise ValueError("MCP profiles require discovery_provenance")
    if inventory.target_id != profile.target_id:
        raise ValueError("inventory target_id does not match profile target_id")
    if inventory.authorization_scope_id != profile.authorization_scope_id:
        raise ValueError(
            "inventory authorization_scope_id does not match profile scope"
        )
    if profile.source_inventory_digest != inventory.semantic_digest:
        raise ValueError("source_inventory_digest does not match embedded inventory")
    return inventory


def _validate_mcp_completeness(
    profile: ExecutionTargetProfile, inventory: McpInventoryObservation
) -> None:
    """Back an observed_complete claim with complete, error-free discovery."""
    if profile.inventory_completeness is not InventoryCompleteness.observed_complete:
        return
    if not inventory.pagination_complete:
        raise ValueError(
            "observed_complete profiles require complete inventory pagination"
        )
    if any(
        item.severity is TargetDiscoverySeverity.error
        and item.code in _MCP_INVENTORY_ERROR_CODES
        for item in profile.diagnostics
    ):
        raise ValueError("observed_complete profiles cannot contain discovery errors")


def _validate_mcp_resource(
    target_id: str, resource: TargetProfileResource, tool: McpToolObservation
) -> None:
    """Require one profile resource to mirror its inventory tool exactly.

    ``TargetProfileResource`` already holds an MCP resource (one with a
    ``tool_name``) to exactly one operation that names the tool and carries
    the resource's argument names.
    """
    if resource.target_id != target_id or resource.tool_name != tool.name:
        raise ValueError("profile resource does not match source inventory tool")
    for field_name in _MCP_RESOURCE_MIRRORED_FIELDS:
        if getattr(resource, field_name) != getattr(tool, field_name):
            raise ValueError(f"profile resource {field_name} drifted from inventory")
    if not set(resource.evidence_refs).issubset(
        set(mcp_inventory_evidence_refs(tool.name))
    ):
        raise ValueError("MCP resource evidence_refs must resolve to inventory fields")
    if resource.simulation_behavior is not None:
        raise ValueError("MCP resources cannot contain simulation_behavior")


def _validate_mcp_interpretations(
    interpretations: tuple[TargetSemanticInterpretation, ...],
    expected_resources: Mapping[str, McpToolObservation],
) -> None:
    """Require one interpretation per tool, citing only that tool's inventory."""
    resource_ids = set(expected_resources)
    if set(item.resource_id for item in interpretations) != resource_ids:
        raise ValueError(
            "profile interpretations must contain one record per inventory tool"
        )
    for interpretation in interpretations:
        expected_name = expected_resources[interpretation.resource_id].name
        if interpretation.tool_name != expected_name:
            raise ValueError("interpretation tool_name does not match resource")
        if not set(interpretation.evidence_refs).issubset(
            set(mcp_inventory_evidence_refs(expected_name))
        ):
            raise ValueError(
                "interpretation evidence_refs must resolve to inventory fields"
            )
        if any(ref not in resource_ids for ref in interpretation.observer_resource_ids):
            raise ValueError("interpretation observer references unknown resource")


class ExecutionTargetProfile(_DigestModel):
    """Closed, content-addressed execution target profile produced by discovery."""

    _digest_domain = EXECUTION_TARGET_PROFILE_DIGEST_FRAME
    schema_version: Literal[EXECUTION_TARGET_PROFILE_SCHEMA_VERSION] = (
        EXECUTION_TARGET_PROFILE_SCHEMA_VERSION
    )
    target_id: StrictStr = Field(min_length=1)
    authorization_scope_id: StrictStr = Field(min_length=1)
    basis: ProfileBasis = ProfileBasis.target
    inventory_authority: InventoryAuthority | None = None
    semantic_authority: SemanticAuthority
    inventory_completeness: InventoryCompleteness = InventoryCompleteness.unknown
    source_protocol: SourceProtocol
    source_inventory_digest: StrictStr | None = Field(
        default=None, pattern=SHA256_PATTERN
    )
    discovery_provenance: DiscoveryProvenance | None = None
    inventory: McpInventoryObservation | None = None
    resources: tuple[TargetProfileResource, ...] = ()
    interpretations: tuple[TargetSemanticInterpretation, ...] = ()
    diagnostics: tuple[TargetDiscoveryDiagnostic, ...] = ()

    @model_validator(mode="after")
    def validate_execution_target_profile(self) -> "ExecutionTargetProfile":
        """Enforce one closed MCP or simulation profile shape."""
        resources = tuple(sorted(self.resources, key=lambda item: item.resource_id))
        _ensure_unique_ids(resources, "resource_id", "profile resources")
        object.__setattr__(self, "resources", resources)

        if self.source_protocol is SourceProtocol.mcp:
            self._validate_mcp_branch(resources)
        elif self.source_protocol is SourceProtocol.simulation:
            self._validate_simulation_branch(resources)
        else:  # pragma: no cover - Enum validation closes this branch
            raise ValueError("unsupported execution target profile protocol")

        interpretations = tuple(
            sorted(self.interpretations, key=lambda item: item.resource_id)
        )
        _ensure_unique_ids(interpretations, "resource_id", "profile interpretations")
        object.__setattr__(self, "interpretations", interpretations)
        diagnostics = tuple(
            sorted(
                self.diagnostics,
                key=lambda item: (item.tool_name or "", item.code.value, item.detail),
            )
        )
        object.__setattr__(self, "diagnostics", diagnostics)
        self._attest_semantic_digest("semantic_digest does not match target profile")
        return self

    def _validate_mcp_branch(
        self, resources: tuple[TargetProfileResource, ...]
    ) -> None:
        """Require complete identity closure for an observed MCP inventory."""
        inventory = _mcp_profile_inventory(self)
        _validate_mcp_completeness(self, inventory)
        expected_resources = {
            mcp_resource_id(self.target_id, tool.name): tool for tool in inventory.tools
        }
        if set(item.resource_id for item in resources) != set(expected_resources):
            raise ValueError(
                "profile resources must close exactly over inventory tools"
            )
        for resource in resources:
            _validate_mcp_resource(
                self.target_id, resource, expected_resources[resource.resource_id]
            )
        _validate_mcp_interpretations(self.interpretations, expected_resources)

    def _validate_simulation_branch(
        self, resources: tuple[TargetProfileResource, ...]
    ) -> None:
        """Require explicit simulation behavior without fake MCP evidence."""
        if self.basis is not ProfileBasis.simulation:
            raise ValueError("simulation profiles require basis=simulation")
        if self.inventory_authority is not None:
            raise ValueError("simulation profiles cannot claim observed inventory")
        if self.source_inventory_digest is not None:
            raise ValueError("simulation profiles cannot carry source_inventory_digest")
        if self.discovery_provenance is not None:
            raise ValueError("simulation profiles cannot carry discovery_provenance")
        if self.inventory is not None:
            raise ValueError("simulation profiles cannot carry an MCP inventory")
        if self.inventory_completeness is not InventoryCompleteness.unknown:
            raise ValueError(
                "simulation profiles require unknown inventory_completeness"
            )
        if self.interpretations:
            raise ValueError("simulation profiles cannot carry MCP interpretations")
        for resource in resources:
            if resource.simulation_behavior is None:
                raise ValueError(
                    "simulation profiles require simulation_behavior for every resource"
                )

    @property
    def profile_id(self) -> str:
        """Return the target ID under the retired profile vocabulary."""
        return self.target_id

    @property
    def environment_id(self) -> str:
        """Return the target ID under the retired environment vocabulary."""
        return self.target_id

    @property
    def authority(self) -> SemanticAuthority:
        """Return semantic authority; the wire field is no longer overloaded."""
        return self.semantic_authority


def mcp_resource_id(target_id: str, tool_name: str) -> str:
    """Derive the stable resource ID from target and exact MCP tool identity."""
    if not target_id or not tool_name:
        raise ValueError("target_id and tool_name must be non-empty")
    return f"mcp:{target_id}:{tool_name}"


def mcp_inventory_evidence_refs(tool_name: str) -> tuple[str, ...]:
    """Return the closed inventory-field evidence namespace for one tool."""
    if not tool_name:
        raise ValueError("tool_name must be non-empty")
    prefix = f"inventory:tool:{tool_name}"
    return (
        prefix,
        f"{prefix}:name",
        f"{prefix}:title",
        f"{prefix}:description",
        f"{prefix}:input_schema",
        f"{prefix}:output_schema",
        f"{prefix}:annotations",
        f"{prefix}:argument_names",
    )


def _validate_json_schema(value: Mapping[str, Any], field_name: str) -> None:
    """Validate one observed JSON Schema without rewriting its object order."""
    if not isinstance(value, Mapping):
        raise ValueError(f"{field_name} must be a JSON object")
    try:
        import jsonschema

        jsonschema.Draft202012Validator.check_schema(dict(value))
    except Exception as exc:  # noqa: BLE001 - normalize validator exceptions
        raise ValueError(f"{field_name} is not a valid JSON Schema: {exc}") from exc


def _ensure_unique_nonempty(values: Sequence[str], label: str) -> None:
    """Validate stable nonempty set-like string collections."""
    if any(not value for value in values):
        raise ValueError(f"{label} must contain non-empty values")
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must contain unique values")


def _ensure_lower_snake(values: Sequence[str], label: str) -> None:
    """Require semantic labels to have canonical lower-snake spelling."""
    pattern = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$")
    if any(not pattern.fullmatch(value) for value in values):
        raise ValueError(f"{label} must use lower_snake_case values")


def _ensure_unique_ids(values: Sequence[Any], attribute: str, label: str) -> None:
    """Validate unique model identities."""
    identities = [getattr(value, attribute) for value in values]
    if len(identities) != len(set(identities)):
        raise ValueError(f"{label} must have unique {attribute} values")


def _freeze_json(value: Any) -> Any:
    """Recursively close JSON interface data while retaining JSON shape."""
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool, FrozenDict, FrozenList)):
        return _freeze_json_scalar(value)
    if isinstance(value, Mapping):
        return _freeze_json_mapping(value)
    if isinstance(value, (list, tuple)):
        return FrozenList(_freeze_json(item) for item in value)
    raise TypeError("interface JSON must contain only JSON values")


def _freeze_json_scalar(value: Any) -> Any:
    """Reject non-finite scalar values while retaining the scalar itself."""
    if isinstance(value, float) and value != value:
        raise ValueError("interface JSON cannot contain NaN")
    return value


def _freeze_json_mapping(value: Mapping[str, Any]) -> FrozenDict:
    """Recursively freeze a JSON mapping after checking its key types."""
    if any(not isinstance(key, str) for key in value):
        raise TypeError("interface JSON mapping keys must be strings")
    return FrozenDict({key: _freeze_json(item) for key, item in value.items()})


__all__ = [
    "AttackerInfluence",
    "ExecutionActionKind",
    "ExecutionResourceKind",
    "ExecutionSurface",
    "ExecutionTargetProfile",
    "DiscoveryMode",
    "DiscoveryProvenance",
    "InventoryAuthority",
    "InventoryCompleteness",
    "InterpreterVerifierAgreement",
    "McpInventoryObservation",
    "McpToolObservation",
    "ProfileBasis",
    "SemanticAuthority",
    "SourceProtocol",
    "TargetDiscoveryDiagnostic",
    "TargetDiscoveryDiagnosticCode",
    "TargetDiscoverySeverity",
    "TargetInterpretationDisposition",
    "TargetOperationEffect",
    "TargetProfileOperation",
    "TargetProfileResource",
    "TargetSemanticInterpretation",
    "TargetStateEffect",
    "SimulationBehavior",
    "mcp_inventory_evidence_refs",
    "mcp_resource_id",
    "EXECUTION_TARGET_PROFILE_SCHEMA_VERSION",
    "MCP_INVENTORY_SCHEMA_VERSION",
]
