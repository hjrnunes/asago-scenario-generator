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
    canonical_json_bytes,
    compute_framed_digest,
)


EXECUTION_CONTRACT_SCHEMA_VERSION = "stpa-execution-contract-v1"
EXECUTION_CLASSIFICATION_SCHEMA_VERSION = "stpa-execution-classification-v1"
EXECUTION_TARGET_PROFILE_SCHEMA_VERSION = "execution-target-profile-v1"
EXECUTION_CONTRACT_DIGEST_FRAME = EXECUTION_CONTRACT_SCHEMA_VERSION
EXECUTION_CLASSIFICATION_DIGEST_FRAME = EXECUTION_CLASSIFICATION_SCHEMA_VERSION
EXECUTION_TARGET_PROFILE_DIGEST_FRAME = EXECUTION_TARGET_PROFILE_SCHEMA_VERSION
SHA256_PATTERN = r"^[0-9a-f]{64}$"


class _Model(ClosedCanonicalModel):
    """Immutable closed model for the execution classification contract."""


class _DigestModel(_Model):
    """Closed model with an optional derived semantic digest."""

    semantic_digest: StrictStr | None = Field(default=None, pattern=SHA256_PATTERN)

    def semantic_payload(self) -> dict[str, Any]:
        """Return canonical content without the digest field."""
        return self.model_dump(mode="json", exclude={"semantic_digest"})

    def compute_semantic_digest(self) -> str:
        """Compute the model's version-framed semantic digest."""
        return compute_framed_digest(self._digest_frame, self.semantic_payload())

    def assert_integrity(self) -> None:
        """Raise when the recorded digest does not match model content."""
        if self.semantic_digest != self.compute_semantic_digest():
            raise ValueError("semantic_digest does not match model content")

    def canonical_json_bytes(self) -> bytes:
        """Return canonical JSON bytes including the derived digest."""
        return canonical_json_bytes(self.model_dump(mode="json"))


class _ClassificationDigestModel(_Model):
    """Closed model whose only digest field is ``classification_digest``."""

    classification_digest: StrictStr | None = Field(
        default=None, pattern=SHA256_PATTERN
    )
    _digest_frame: ClassVar[str] = EXECUTION_CLASSIFICATION_DIGEST_FRAME

    def semantic_payload(self) -> dict[str, Any]:
        """Return canonical classification content without its digest."""
        return self.model_dump(mode="json", exclude={"classification_digest"})

    def compute_classification_digest(self) -> str:
        """Compute the version-framed classification digest."""
        return compute_framed_digest(self._digest_frame, self.semantic_payload())

    def assert_integrity(self) -> None:
        """Raise when the classification digest does not match content."""
        if self.classification_digest != self.compute_classification_digest():
            raise ValueError(
                "classification_digest does not match classification content"
            )

    def canonical_json_bytes(self) -> bytes:
        """Return canonical JSON bytes including the classification digest."""
        return canonical_json_bytes(self.model_dump(mode="json"))


class ExecutionDeliveryClass(str, Enum):
    """The one producer-selected way an adversarial stimulus enters."""

    direct_prompt = "direct_prompt"
    indirect_content = "indirect_content"
    conversation_context = "conversation_context"


class ExecutionContractDisposition(str, Enum):
    """Whether Stage 5 supplied an executable route or a semantic gap."""

    executable_route = "executable_route"
    analytical_only = "analytical_only"


class ExecutionActionKind(str, Enum):
    """The semantic action whose unsafe outcome is observed."""

    model_output = "model_output"
    tool_call = "tool_call"
    state_change = "state_change"
    agent_message = "agent_message"
    environment_action = "environment_action"


class ExecutionResourcePurpose(str, Enum):
    """Why a semantic execution resource is needed."""

    stimulus_carrier = "stimulus_carrier"
    target_action = "target_action"
    state_resource = "state_resource"
    agent_channel = "agent_channel"


class ExecutionResourceKind(str, Enum):
    """Platform-neutral kind of semantic resource."""

    surface = "surface"
    tool = "tool"
    integration = "integration"
    state_store = "state_store"
    agent_channel = "agent_channel"


class RequestedEnvironmentBasis(str, Enum):
    """Environment basis explicitly selected by the producer caller."""

    target_profile = "target_profile"
    simulation_profile = "simulation_profile"
    target_agnostic = "target_agnostic"


class BindingCompleteness(str, Enum):
    """Whether semantic resource roles are completely resolved."""

    concrete = "concrete"
    parameterized = "parameterized"
    analytical_only = "analytical_only"


class EnvironmentBasis(str, Enum):
    """The evidence basis available for executing a semantic contract."""

    target_agnostic = "target_agnostic"
    target_profile = "target_profile"
    simulation_profile = "simulation_profile"
    none = "none"


class ExecutionProfileFit(str, Enum):
    """Deterministic fit of a contract against a selected profile."""

    not_required = "not_required"
    matched = "matched"
    needs_binding = "needs_binding"
    ambiguous = "ambiguous"
    unsupported = "unsupported"
    invalid = "invalid"


class ExecutionClaimScope(str, Enum):
    """The strongest claim a producer classification is allowed to make."""

    model_behavior_only = "model_behavior_only"
    target_specific_intent = "target_specific_intent"
    agent_behavior_with_simulated_tools = "agent_behavior_with_simulated_tools"
    no_execution_claim = "no_execution_claim"


class ProfileBasis(str, Enum):
    """The profile describes a real target or an explicit simulation."""

    target = "target"
    simulation = "simulation"


class ProfileAuthority(str, Enum):
    """How the profile's resource facts were established."""

    reviewed = "reviewed"
    inferred = "inferred"


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
    """Whether a role search can be treated as unique."""

    unknown = "unknown"
    inferred_partial = "inferred_partial"
    reviewed_complete = "reviewed_complete"


class ExecutionDiagnosticCode(str, Enum):
    """Closed deterministic diagnostic vocabulary."""

    environment_profile_not_supplied = "environment_profile_not_supplied"
    target_profile_not_supplied = "target_profile_not_supplied"
    target_resource_unresolved = "target_resource_unresolved"
    target_resource_ambiguous = "target_resource_ambiguous"
    operation_unsupported = "operation_unsupported"
    profile_inventory_unknown = "profile_inventory_unknown"
    profile_inferred_only = "profile_inferred_only"
    simulation_contract_missing = "simulation_contract_missing"
    oracle_missing = "oracle_missing"
    execution_route_missing = "execution_route_missing"
    explicit_target_ref_dangling = "explicit_target_ref_dangling"
    target_profile_digest_mismatch = "target_profile_digest_mismatch"


class ExecutionSemanticGapCode(str, Enum):
    """Closed reasons why a finding cannot describe an executable route."""

    delivery_path_missing = "delivery_path_missing"
    operation_missing = "operation_missing"
    resource_role_missing = "resource_role_missing"
    observable_oracle_missing = "observable_oracle_missing"


class SemanticExecutionDelivery(_Model):
    """One selected delivery route and its request-local factor handle."""

    delivery_class: ExecutionDeliveryClass
    factor_id: StrictStr = Field(pattern=r"^CF-\d+$")
    source_role: StrictStr = Field(
        min_length=1,
        pattern=r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$",
    )
    carrier_requirement_id: StrictStr | None = Field(
        default=None, pattern=r"^REQ-[A-Za-z0-9._-]+$"
    )


class SemanticExecutionGap(_Model):
    """Explicit evidence that a finding is analytical rather than executable."""

    code: ExecutionSemanticGapCode
    detail: StrictStr = Field(min_length=1)
    evidence_refs: tuple[StrictStr, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def canonicalize_evidence(self) -> "SemanticExecutionGap":
        values = tuple(sorted(self.evidence_refs))
        _ensure_unique_nonempty(values, "evidence_refs")
        object.__setattr__(self, "evidence_refs", values)
        return self


class ExecutionResourceRequirement(_Model):
    """One semantic resource role required by the selected execution path."""

    requirement_id: StrictStr = Field(pattern=r"^REQ-[A-Za-z0-9._-]+$")
    purpose: ExecutionResourcePurpose
    factor_id: StrictStr | None = Field(default=None, pattern=r"^CF-\d+$")
    owner_ref: StrictStr = Field(min_length=1)
    acceptable_resource_kinds: tuple[ExecutionResourceKind, ...] = Field(min_length=1)
    role_id: StrictStr = Field(
        min_length=1,
        pattern=r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$",
    )
    operation: StrictStr = Field(
        min_length=1,
        pattern=(
            r"^(?:[a-z][a-z0-9]*(?:_[a-z0-9]+)*|"
            r"(?:CA|CM)-[A-Za-z0-9._-]+)$"
        ),
    )
    required_surfaces: tuple[ExecutionSurface, ...] = Field(min_length=1)
    required_properties: tuple[StrictStr, ...] = ()
    required_attacker_influence: AttackerInfluence | None = None
    exact_resource_id: StrictStr | None = Field(default=None, min_length=1)
    late_bindable: StrictBool
    evidence_refs: tuple[StrictStr, ...] = ()

    @model_validator(mode="after")
    def validate_requirement(self) -> "ExecutionResourceRequirement":
        acceptable_kinds = tuple(
            sorted(self.acceptable_resource_kinds, key=lambda item: item.value)
        )
        required_surfaces = tuple(
            sorted(self.required_surfaces, key=lambda item: item.value)
        )
        required_properties = tuple(sorted(self.required_properties))
        evidence_refs = tuple(sorted(self.evidence_refs))
        _ensure_unique_nonempty(acceptable_kinds, "acceptable_resource_kinds")
        _ensure_unique_nonempty(required_surfaces, "required_surfaces")
        _ensure_unique_nonempty(required_properties, "required_properties")
        _ensure_lower_snake(required_properties, "required_properties")
        object.__setattr__(self, "acceptable_resource_kinds", acceptable_kinds)
        object.__setattr__(self, "required_surfaces", required_surfaces)
        _ensure_unique_nonempty(evidence_refs, "evidence_refs")
        object.__setattr__(self, "required_properties", required_properties)
        object.__setattr__(self, "evidence_refs", evidence_refs)
        if self.exact_resource_id is not None and self.late_bindable:
            raise ValueError("exact resource requirements cannot be late_bindable")
        if self.exact_resource_id is None and not self.late_bindable:
            raise ValueError("unresolved resource requirements must be late_bindable")
        return self


class SemanticExecutionContract(_DigestModel):
    """Closed scenario-owned semantic execution intent."""

    _digest_frame = EXECUTION_CONTRACT_DIGEST_FRAME
    schema_version: Literal[EXECUTION_CONTRACT_SCHEMA_VERSION] = (
        EXECUTION_CONTRACT_SCHEMA_VERSION
    )
    disposition: ExecutionContractDisposition = (
        ExecutionContractDisposition.executable_route
    )
    requested_environment_basis: RequestedEnvironmentBasis | None = None
    delivery: SemanticExecutionDelivery | None = None
    action_kind: ExecutionActionKind | None = None
    resource_requirements: tuple[ExecutionResourceRequirement, ...] = ()
    gaps: tuple[SemanticExecutionGap, ...] = ()

    @model_validator(mode="after")
    def validate_execution_contract(self) -> "SemanticExecutionContract":
        requirements = tuple(
            sorted(self.resource_requirements, key=lambda item: item.requirement_id)
        )
        _ensure_unique_ids(requirements, "requirement_id", "resource requirements")
        object.__setattr__(self, "resource_requirements", requirements)
        gaps = tuple(sorted(self.gaps, key=lambda item: (item.code.value, item.detail)))
        object.__setattr__(self, "gaps", gaps)
        _validate_contract_disposition(self, requirements, gaps)
        _validate_contract_basis(self, requirements)
        _validate_contract_delivery(self, requirements)
        _validate_contract_action(self, requirements)
        _validate_contract_agent_channel(self, requirements)
        expected = self.compute_semantic_digest()
        if self.semantic_digest is not None and self.semantic_digest != expected:
            raise ValueError("semantic_digest does not match execution contract")
        object.__setattr__(self, "semantic_digest", expected)
        return self


def _validate_contract_disposition(
    contract: SemanticExecutionContract,
    requirements: Sequence[ExecutionResourceRequirement],
    gaps: Sequence[SemanticExecutionGap],
) -> None:
    """Validate the mutually exclusive analytical and executable shapes."""
    if contract.disposition is ExecutionContractDisposition.analytical_only:
        _validate_analytical_disposition(contract, requirements, gaps)
        return
    _validate_executable_disposition(contract, gaps)


def _validate_analytical_disposition(
    contract: SemanticExecutionContract,
    requirements: Sequence[ExecutionResourceRequirement],
    gaps: Sequence[SemanticExecutionGap],
) -> None:
    """Require an analytical contract to contain only typed gap evidence."""
    if contract.delivery is not None or contract.action_kind is not None:
        raise ValueError("analytical_only contracts cannot contain an executable route")
    if requirements:
        raise ValueError(
            "analytical_only contracts cannot contain resource requirements"
        )
    if not gaps:
        raise ValueError("analytical_only contracts require semantic gaps")


def _validate_executable_disposition(
    contract: SemanticExecutionContract,
    gaps: Sequence[SemanticExecutionGap],
) -> None:
    """Require an executable contract to provide a route and no gap records."""
    if contract.delivery is None or contract.action_kind is None:
        raise ValueError("executable_route contracts require delivery and action_kind")
    if gaps:
        raise ValueError("executable_route contracts cannot contain semantic gaps")


def _validate_contract_basis(
    contract: SemanticExecutionContract,
    requirements: Sequence[ExecutionResourceRequirement],
) -> None:
    """Derive or validate the requested environment basis."""
    if contract.disposition is ExecutionContractDisposition.analytical_only:
        _validate_analytical_basis(contract)
        return
    _derive_executable_basis(contract, requirements)
    _reject_target_agnostic_resources(contract, requirements)


def _validate_analytical_basis(contract: SemanticExecutionContract) -> None:
    """Reject environment claims on analytical-only findings."""
    if contract.requested_environment_basis is not None:
        raise ValueError("analytical_only contracts cannot claim an environment basis")


def _derive_executable_basis(
    contract: SemanticExecutionContract,
    requirements: Sequence[ExecutionResourceRequirement],
) -> None:
    """Derive target-agnostic basis only for resource-free executable routes."""
    if contract.requested_environment_basis is not None:
        return
    if requirements:
        return
    object.__setattr__(
        contract,
        "requested_environment_basis",
        RequestedEnvironmentBasis.target_agnostic,
    )


def _reject_target_agnostic_resources(
    contract: SemanticExecutionContract,
    requirements: Sequence[ExecutionResourceRequirement],
) -> None:
    """Reject domain resource requirements on target-agnostic routes."""
    if (
        contract.requested_environment_basis
        is RequestedEnvironmentBasis.target_agnostic
        and requirements
    ):
        raise ValueError("target_agnostic contracts cannot require domain resources")


def _validate_contract_delivery(
    contract: SemanticExecutionContract,
    requirements: Sequence[ExecutionResourceRequirement],
) -> None:
    """Ensure any indirect delivery carrier names a compatible requirement."""
    carrier = contract.delivery.carrier_requirement_id if contract.delivery else None
    by_id = {item.requirement_id: item for item in requirements}
    if (
        contract.delivery is not None
        and contract.delivery.delivery_class is ExecutionDeliveryClass.indirect_content
    ):
        _validate_indirect_carrier(carrier, by_id)
        return
    _reject_unexpected_carrier(carrier)


def _validate_indirect_carrier(
    carrier: str | None,
    requirements: dict[str, ExecutionResourceRequirement],
) -> None:
    """Validate the requirement named by an indirect-content delivery."""
    if carrier is None:
        raise ValueError("indirect_content delivery requires a carrier requirement")
    if carrier not in requirements:
        raise ValueError("delivery carrier requirement does not resolve")
    requirement = requirements[carrier]
    if requirement.purpose is not ExecutionResourcePurpose.stimulus_carrier:
        raise ValueError("delivery carrier must have stimulus_carrier purpose")
    if requirement.required_attacker_influence not in {
        AttackerInfluence.indirect,
        AttackerInfluence.direct,
    }:
        raise ValueError(
            "indirect_content carrier requires direct or indirect attacker influence"
        )


def _reject_unexpected_carrier(carrier: str | None) -> None:
    """Reject carrier references on direct or conversation deliveries."""
    if carrier is not None:
        raise ValueError(
            "only indirect_content delivery may name a carrier requirement"
        )


def _validate_contract_action(
    contract: SemanticExecutionContract,
    requirements: Sequence[ExecutionResourceRequirement],
) -> None:
    """Require exactly the resource role needed by the selected action kind."""
    action_requirements = tuple(
        item
        for item in requirements
        if item.purpose is ExecutionResourcePurpose.target_action
    )
    if contract.disposition is ExecutionContractDisposition.analytical_only:
        _reject_analytical_action_requirements(action_requirements)
        return
    _require_external_action_requirement(contract.action_kind, action_requirements)


def _reject_analytical_action_requirements(
    action_requirements: Sequence[ExecutionResourceRequirement],
) -> None:
    """Reject target-action resources on analytical contracts."""
    if action_requirements:
        raise ValueError("target_action requirements are unused by this action kind")


def _require_external_action_requirement(
    action_kind: ExecutionActionKind | None,
    action_requirements: Sequence[ExecutionResourceRequirement],
) -> None:
    """Require one target action for externally visible action kinds."""
    if (
        action_kind
        in {
            ExecutionActionKind.tool_call,
            ExecutionActionKind.state_change,
            ExecutionActionKind.environment_action,
        }
        and len(action_requirements) != 1
    ):
        raise ValueError("external action routes require one target_action requirement")


def _validate_contract_agent_channel(
    contract: SemanticExecutionContract,
    requirements: Sequence[ExecutionResourceRequirement],
) -> None:
    """Require exactly one agent channel only for agent-message routes."""
    agent_requirements = tuple(
        item
        for item in requirements
        if item.purpose is ExecutionResourcePurpose.agent_channel
    )
    if contract.action_kind is ExecutionActionKind.agent_message:
        _require_agent_channel(agent_requirements)
        return
    _reject_unused_agent_channel(agent_requirements)


def _require_agent_channel(
    requirements: Sequence[ExecutionResourceRequirement],
) -> None:
    """Require one agent channel for agent-message routes."""
    if len(requirements) != 1:
        raise ValueError("agent_message routes require one agent_channel requirement")


def _reject_unused_agent_channel(
    requirements: Sequence[ExecutionResourceRequirement],
) -> None:
    """Reject agent-channel resources on non-agent-message routes."""
    if requirements:
        raise ValueError("agent_channel requirements are unused by this action kind")


class TargetProfileOperation(_Model):
    """One reviewed operation exposed by an execution target resource."""

    operation_id: StrictStr = Field(min_length=1)
    semantic_operation: StrictStr = Field(
        min_length=1,
        pattern=(
            r"^(?:[a-z][a-z0-9]*(?:_[a-z0-9]+)*|"
            r"(?:CA|CM)-[A-Za-z0-9._-]+)$"
        ),
    )
    argument_names: tuple[StrictStr, ...] = ()
    observable_properties: tuple[StrictStr, ...] = ()

    @model_validator(mode="after")
    def validate_operation(self) -> "TargetProfileOperation":
        argument_names = tuple(sorted(self.argument_names))
        observable_properties = tuple(sorted(self.observable_properties))
        _ensure_unique_nonempty(argument_names, "argument_names")
        _ensure_unique_nonempty(observable_properties, "observable_properties")
        _ensure_lower_snake(argument_names, "argument_names")
        _ensure_lower_snake(observable_properties, "observable_properties")
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
    """One semantic resource record in a target or simulation profile."""

    resource_id: StrictStr = Field(min_length=1)
    resource_kind: ExecutionResourceKind
    role_ids: tuple[StrictStr, ...] = ()
    structural_refs: tuple[StrictStr, ...] = ()
    attacker_influence: AttackerInfluence
    surfaces: tuple[ExecutionSurface, ...] = ()
    operations: tuple[TargetProfileOperation, ...] = ()
    interface_schema: dict[str, Any] = Field(default_factory=dict)
    evidence_refs: tuple[StrictStr, ...] = ()
    authority: ProfileAuthority = ProfileAuthority.reviewed
    simulation_behavior: SimulationBehavior | None = None

    @field_validator("interface_schema", mode="before")
    @classmethod
    def freeze_mapping(
        cls, value: Mapping[str, Any] | None
    ) -> dict[str, Any] | FrozenDict | None:
        return _freeze_json(value)

    @model_validator(mode="after")
    def validate_target_profile_resource(self) -> "TargetProfileResource":
        for field_name in (
            "role_ids",
            "structural_refs",
            "surfaces",
            "evidence_refs",
        ):
            _ensure_unique_nonempty(getattr(self, field_name), field_name)
        _ensure_lower_snake(self.role_ids, "role_ids")
        for field_name in ("role_ids", "structural_refs", "evidence_refs"):
            object.__setattr__(
                self, field_name, tuple(sorted(getattr(self, field_name)))
            )
        object.__setattr__(
            self,
            "surfaces",
            tuple(sorted(self.surfaces, key=lambda item: item.value)),
        )
        operations = tuple(sorted(self.operations, key=lambda item: item.operation_id))
        _ensure_unique_ids(operations, "operation_id", "resource operations")
        _ensure_unique_nonempty(
            tuple(item.semantic_operation for item in operations),
            "semantic_operation",
        )
        object.__setattr__(self, "operations", operations)
        if self.authority is ProfileAuthority.reviewed and not self.evidence_refs:
            raise ValueError("reviewed resources require evidence_refs")
        return self


class ExecutionTargetProfile(_DigestModel):
    """Reviewed, content-addressed semantic target or simulation inventory."""

    _digest_frame = EXECUTION_TARGET_PROFILE_DIGEST_FRAME
    schema_version: Literal[EXECUTION_TARGET_PROFILE_SCHEMA_VERSION] = (
        EXECUTION_TARGET_PROFILE_SCHEMA_VERSION
    )
    profile_id: StrictStr = Field(min_length=1)
    environment_id: StrictStr = Field(min_length=1)
    basis: ProfileBasis
    authority: ProfileAuthority
    inventory_completeness: InventoryCompleteness
    evidence_refs: tuple[StrictStr, ...] = ()
    resources: tuple[TargetProfileResource, ...] = ()

    @model_validator(mode="after")
    def validate_execution_target_profile(self) -> "ExecutionTargetProfile":
        evidence_refs = _canonicalize_profile_evidence(self.evidence_refs)
        object.__setattr__(self, "evidence_refs", evidence_refs)
        resources = _canonicalize_profile_resources(self.resources)
        object.__setattr__(self, "resources", resources)
        _validate_profile_simulation_shape(self.basis, resources)
        _validate_profile_authority(self.authority, evidence_refs)
        _set_profile_digest(self)
        return self


def _canonicalize_profile_evidence(values: Sequence[str]) -> tuple[str, ...]:
    """Return deterministic profile-level evidence references."""
    evidence_refs = tuple(sorted(values))
    _ensure_unique_nonempty(evidence_refs, "evidence_refs")
    return evidence_refs


def _canonicalize_profile_resources(
    values: Sequence[TargetProfileResource],
) -> tuple[TargetProfileResource, ...]:
    """Return deterministic, uniquely identified profile resources."""
    resources = tuple(sorted(values, key=lambda item: item.resource_id))
    _ensure_unique_ids(resources, "resource_id", "profile resources")
    return resources


def _validate_profile_simulation_shape(
    basis: ProfileBasis,
    resources: Sequence[TargetProfileResource],
) -> None:
    """Require simulation behavior exactly when the profile is a simulation."""
    if basis is ProfileBasis.simulation:
        _require_simulation_behavior(resources)
        return
    _reject_simulation_behavior(resources)


def _require_simulation_behavior(
    resources: Sequence[TargetProfileResource],
) -> None:
    """Require every simulated resource to define deterministic behavior."""
    missing = tuple(
        item.resource_id for item in resources if item.simulation_behavior is None
    )
    if missing:
        raise ValueError(
            "simulation profiles require simulation_behavior for every resource"
        )


def _reject_simulation_behavior(
    resources: Sequence[TargetProfileResource],
) -> None:
    """Reject simulation behavior in a real target profile."""
    if any(item.simulation_behavior is not None for item in resources):
        raise ValueError("target profiles cannot contain simulation_behavior")


def _validate_profile_authority(
    authority: ProfileAuthority,
    evidence_refs: Sequence[str],
) -> None:
    """Require evidence when the profile claims reviewed authority."""
    if authority is ProfileAuthority.reviewed and not evidence_refs:
        raise ValueError("reviewed profiles require evidence_refs")


def _set_profile_digest(profile: ExecutionTargetProfile) -> None:
    """Derive and verify the profile's content address."""
    expected = profile.compute_semantic_digest()
    if profile.semantic_digest is not None and profile.semantic_digest != expected:
        raise ValueError("semantic_digest does not match target profile")
    object.__setattr__(profile, "semantic_digest", expected)


class ResolvedExecutionBinding(_Model):
    """One exact requirement/resource/operation match."""

    requirement_id: StrictStr = Field(pattern=r"^REQ-[A-Za-z0-9._-]+$")
    resource_id: StrictStr = Field(min_length=1)
    operation_id: StrictStr = Field(min_length=1)


class AmbiguousExecutionMatch(_Model):
    """All exact candidates retained when a role is not uniquely resolved."""

    requirement_id: StrictStr = Field(pattern=r"^REQ-[A-Za-z0-9._-]+$")
    candidate_resource_ids: tuple[StrictStr, ...] = Field(min_length=2)

    @model_validator(mode="after")
    def canonicalize_candidates(self) -> "AmbiguousExecutionMatch":
        values = tuple(sorted(self.candidate_resource_ids))
        _ensure_unique_nonempty(values, "candidate_resource_ids")
        object.__setattr__(self, "candidate_resource_ids", values)
        return self


class ExecutionClassificationDiagnostic(_Model):
    """One deterministic reason a semantic contract is not fully bound."""

    code: ExecutionDiagnosticCode
    detail: StrictStr = Field(min_length=1)
    requirement_id: StrictStr | None = Field(
        default=None, pattern=r"^REQ-[A-Za-z0-9._-]+$"
    )
    candidate_resource_ids: tuple[StrictStr, ...] = ()

    @model_validator(mode="after")
    def canonicalize_candidates(self) -> "ExecutionClassificationDiagnostic":
        values = tuple(sorted(self.candidate_resource_ids))
        _ensure_unique_nonempty(values, "candidate_resource_ids")
        object.__setattr__(self, "candidate_resource_ids", values)
        return self


class ExecutionClassification(_ClassificationDigestModel):
    """Deterministic classification and evidence for one execution contract."""

    schema_version: Literal[EXECUTION_CLASSIFICATION_SCHEMA_VERSION] = (
        EXECUTION_CLASSIFICATION_SCHEMA_VERSION
    )
    binding_completeness: BindingCompleteness
    environment_basis: EnvironmentBasis
    profile_fit: ExecutionProfileFit
    claim_scope: ExecutionClaimScope
    resolved_bindings: tuple[ResolvedExecutionBinding, ...] = ()
    unresolved_requirement_ids: tuple[StrictStr, ...] = ()
    ambiguous_matches: tuple[AmbiguousExecutionMatch, ...] = ()
    unsupported_requirement_ids: tuple[StrictStr, ...] = ()
    diagnostics: tuple[ExecutionClassificationDiagnostic, ...] = ()
    target_profile_digest: StrictStr | None = Field(
        default=None, pattern=SHA256_PATTERN
    )

    @model_validator(mode="after")
    def canonicalize_and_digest(self) -> "ExecutionClassification":
        _ensure_unique_ids(
            tuple(self.resolved_bindings),
            "requirement_id",
            "resolved bindings",
        )
        for field_name in (
            "unresolved_requirement_ids",
            "unsupported_requirement_ids",
        ):
            _ensure_unique_nonempty(getattr(self, field_name), field_name)
        object.__setattr__(
            self,
            "unresolved_requirement_ids",
            tuple(sorted(self.unresolved_requirement_ids)),
        )
        object.__setattr__(
            self,
            "unsupported_requirement_ids",
            tuple(sorted(self.unsupported_requirement_ids)),
        )
        expected = self.compute_classification_digest()
        if (
            self.classification_digest is not None
            and self.classification_digest != expected
        ):
            raise ValueError(
                "classification_digest does not match classification content"
            )
        object.__setattr__(self, "classification_digest", expected)
        return self


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
    "AmbiguousExecutionMatch",
    "AttackerInfluence",
    "BindingCompleteness",
    "EnvironmentBasis",
    "ExecutionActionKind",
    "ExecutionClaimScope",
    "ExecutionClassification",
    "ExecutionClassificationDiagnostic",
    "ExecutionContractDisposition",
    "ExecutionDeliveryClass",
    "ExecutionDiagnosticCode",
    "ExecutionProfileFit",
    "ExecutionResourceKind",
    "ExecutionResourcePurpose",
    "ExecutionResourceRequirement",
    "ExecutionSemanticGapCode",
    "ExecutionSurface",
    "ExecutionTargetProfile",
    "InventoryCompleteness",
    "ProfileAuthority",
    "ProfileBasis",
    "RequestedEnvironmentBasis",
    "ResolvedExecutionBinding",
    "SemanticExecutionGap",
    "SemanticExecutionContract",
    "SemanticExecutionDelivery",
    "TargetProfileOperation",
    "TargetProfileResource",
    "SimulationBehavior",
    "EXECUTION_CLASSIFICATION_SCHEMA_VERSION",
    "EXECUTION_CONTRACT_SCHEMA_VERSION",
    "EXECUTION_TARGET_PROFILE_SCHEMA_VERSION",
]
