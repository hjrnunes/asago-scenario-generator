"""Stage 5 — Dual-BDI scenario specification.

Deterministic defender BDI pre-population from the control structure,
combined LLM call for vulnerability annotations + attacker BDI,
and deterministic assembly of the ScenarioSpec.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from functools import lru_cache
import json
from pathlib import Path
from collections.abc import Mapping, Sequence
from typing import Annotated, Callable, Literal, Union

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictStr,
    conlist,
    create_model,
    model_validator,
)

from asago_scenario_generator.stpa.infra.llm import LLMClient
from asago_scenario_generator.stpa.infra.llm_helpers import (
    parse_llm_result,
    safe_llm_call,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.stpa.models.causal_factor import (
    CausalEvidenceStatus,
    CausalFactor,
    CausalFactorKind,
    validate_causal_evidence_shape,
    validate_factor_sources,
)
from asago_scenario_generator.stpa.models.semantic_conditions import (
    AbsenceCondition,
    ActionPresenceCondition,
    ActionValueCondition,
    DelayCondition,
    DurationCondition,
    OrderingCondition,
    SemanticCondition,
    SemanticValue,
    StateValueCondition,
    WindowCondition,
    contains_binding_placeholder,
    normalize_semantic_proposition,
)
from asago_scenario_generator.stpa.models.execution_classification import (
    AttackerInfluence,
    ExecutionActionKind,
    ExecutionContractDisposition,
    ExecutionDeliveryClass,
    ExecutionResourceKind,
    ExecutionResourcePurpose,
    SemanticExecutionContract,
    SemanticExecutionDelivery,
    SemanticExecutionGap,
    ExecutionSemanticGapCode,
    ExecutionResourceRequirement,
    ExecutionSurface,
    RequestedEnvironmentBasis,
)
from asago_scenario_generator.stpa.scenario_prod.execution_classification import (
    resolve_contract_environment_request,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlStructure,
    CoordinationLink,
    ControlActionTemporality,
    Responsibility,
)
from asago_scenario_generator.stpa.models.enriched_threat_set import StructuralThreat
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.models.scenario_context import (
    DescribedElement,
    ScenarioGenerationContext,
    validate_factor_evidence,
)
from asago_scenario_generator.stpa.threat_enum.technology_context import context_for
from asago_scenario_generator.stpa.models.scenario_spec import (
    AttackerBDI,
    DefenderBDI,
    DefenderBelief,
    DefenderDesire,
    DefenderIntention,
    ScenarioSpec,
    ThreatSource,
)

from ._constants import PROMPTS_DIR

__all__ = [
    "AnalyticalOnlyRouteSelection",
    "BDIGenerationResult",
    "CausalEvidenceStatus",
    "CausalFactorDeclaration",
    "ExecutableRouteSelection",
    "ExecutionRouteSelectionValue",
    "StimulusCategory",
    "UnsafeOutcomeDeclaration",
    "populate_defender_bdi",
    "generate_bdi",
    "generate_bdi_for_context",
    "build_bdi_prompts",
    "build_context_bdi_prompts",
    "assemble_scenario_spec",
    "generate_scenario_id",
    "parse_ica_slot_id",
    "classify_control_action_kind",
]

_LENGTH_RETRY_MAX_COMPLETION_TOKENS = 2048
_LENGTH_RETRY_PROMPT = (
    "\n\nThe prior response was truncated. Return only a concise "
    "schema-matching response with no explanation."
)
_LENGTH_RETRY_EXHAUSTED_PREFIX = (
    "BDI generation retry exhausted after LengthFinishReasonError:"
)


# ControlAction is intentionally a small structural model in older input
# artifacts.  Newer producers may attach a typed effect/target annotation to
# it.  Keep the mapping here, at the Stage 5 boundary, so a provider cannot
# turn free-form action prose into an execution classification.
_ACTION_EFFECT_KINDS: dict[str, ExecutionActionKind] = {
    "assistant_output": ExecutionActionKind.model_output,
    "model_output": ExecutionActionKind.model_output,
    "response": ExecutionActionKind.model_output,
    "operation_invocation": ExecutionActionKind.tool_call,
    "tool_call": ExecutionActionKind.tool_call,
    "tool_invocation": ExecutionActionKind.tool_call,
    "state_mutation": ExecutionActionKind.state_change,
    "state_change": ExecutionActionKind.state_change,
    "persistent_state_change": ExecutionActionKind.state_change,
    "agent_message": ExecutionActionKind.agent_message,
    "message": ExecutionActionKind.agent_message,
    "environment_action": ExecutionActionKind.environment_action,
    "external_action": ExecutionActionKind.environment_action,
}
_RESPONSIBILITY_TARGET_NAMES = frozenset(
    {"responsibility", "controller", "agent", "agent_responsibility"}
)


class CausalFactorDeclaration(BaseModel):
    """One Stage 5 declaration of an evidence-backed causal factor.

    ``kind`` and ``source_id`` name the structural finding, ``evidence``
    carries the declared evidence description, and ``timing`` carries
    optional declared timing text (parsed into typed temporal
    constraints only at projection time; never inferred).  The evidence
    status distinguishes an existing structural failure from an explicitly
    reachable capability or a bounded assumption.  Capability and access
    references are resolved against the exact scenario context during
    deterministic assembly.
    """

    model_config = ConfigDict(extra="forbid")

    kind: CausalFactorKind
    source_id: str = Field(min_length=1)
    evidence: str = Field(min_length=1)
    timing: str | None = None
    # V2 provider contract.  ``timing`` remains a compatibility field for
    # historical direct callers; corrected context requests require this
    # field (including explicit ``null``) through their dynamic response
    # model.
    temporal_condition: SemanticCondition | None = None
    evidence_status: CausalEvidenceStatus = CausalEvidenceStatus.structural_failure
    capability_refs: tuple[str, ...] = ()
    access_refs: tuple[str, ...] = ()
    bounded_assumption: str | None = None

    @model_validator(mode="after")
    def validate_evidence_shape(self) -> "CausalFactorDeclaration":
        """Require supporting material for capability and assumption claims."""
        validate_causal_evidence_shape(
            self.evidence_status,
            self.capability_refs,
            self.access_refs,
            self.bounded_assumption,
        )
        return self


class UnsafeOutcomeDeclaration(BaseModel):
    """Stage 5's semantic unsafe-outcome condition.

    The condition family, subject and operator are provider-authored.  Any
    value absent from source evidence is represented by a typed placeholder;
    the binding flag is derived and cannot be used to hide a placeholder.
    """

    model_config = ConfigDict(extra="forbid")

    condition: SemanticCondition
    semantic_proposition: StrictStr | None = None
    semantic_binding_required: StrictBool | None = None
    # These fields remain only for non-contextual compatibility callers.  The
    # corrected contextual wire model never exposes or accepts them.
    hazard_refs: tuple[str, ...] = ()
    constraint_refs: tuple[str, ...] = ()

    @model_validator(mode="after")
    def derive_binding_state(self) -> "UnsafeOutcomeDeclaration":
        expected = contains_binding_placeholder(self.condition)
        if (
            self.semantic_binding_required is not None
            and self.semantic_binding_required is not expected
        ):
            raise ValueError(
                "semantic_binding_required must match typed placeholder presence"
            )
        object.__setattr__(self, "semantic_binding_required", expected)
        if self.semantic_proposition is not None:
            object.__setattr__(
                self,
                "semantic_proposition",
                normalize_semantic_proposition(
                    self.semantic_proposition,
                    required=True,
                ),
            )
        return self


class _ContextUnsafeOutcomeDraft(BaseModel):
    """Provider-owned unsafe semantics without compiler-derived state."""

    model_config = ConfigDict(extra="forbid")

    condition: SemanticCondition
    semantic_proposition: StrictStr | None


class _ContextActionPresenceConditionWire(BaseModel):
    """Strict provider wire shape for a NOT_PROVIDED unsafe condition."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["action_presence"]
    control_action_id: StrictStr = Field(min_length=1)
    expected: Literal["not_provided"]


class _ContextActionValueConditionWire(BaseModel):
    """Strict provider wire shape for an action-value unsafe condition."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["action_value"]
    control_action_id: StrictStr = Field(min_length=1)
    property: StrictStr = Field(min_length=1)
    operator: Literal[
        "equals",
        "not_equals",
        "contains",
        "not_contains",
        "greater_than",
        "greater_than_or_equal",
        "less_than",
        "less_than_or_equal",
    ]
    expected: SemanticValue


class _ContextStateValueConditionWire(BaseModel):
    """Strict provider wire shape for an exact state-value condition."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["state_value"]
    subject_ref: StrictStr = Field(min_length=1)
    property: StrictStr = Field(min_length=1)
    operator: Literal[
        "equals",
        "not_equals",
        "contains",
        "not_contains",
        "greater_than",
        "greater_than_or_equal",
        "less_than",
        "less_than_or_equal",
    ]
    expected: SemanticValue


class _ContextOrderingConditionWire(BaseModel):
    """Strict provider wire shape for an ordering unsafe condition."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["ordering"]
    reference_step_id: StrictStr = Field(min_length=1, pattern=r"^S-\d+$")
    relation: Literal["before", "after"]


class _ContextDelayConditionWire(BaseModel):
    """Strict provider wire shape for a delay unsafe condition."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["delay"]
    reference_ref: StrictStr = Field(min_length=1)
    delay_ms: SemanticValue


class _ContextDurationConditionWire(BaseModel):
    """Strict provider wire shape for a duration unsafe condition."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["duration"]
    reference_ref: StrictStr = Field(min_length=1)
    duration_ms: SemanticValue


class _ContextWindowConditionWire(BaseModel):
    """Strict provider wire shape for a timing-window unsafe condition."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["window"]
    reference_ref: StrictStr = Field(min_length=1)
    window_from_ms: SemanticValue
    window_to_ms: SemanticValue


class _ContextAbsenceConditionWire(BaseModel):
    """Strict provider wire shape for an absence unsafe condition."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["absence"]
    reference_ref: StrictStr = Field(min_length=1)
    until_step_id: StrictStr = Field(min_length=1, pattern=r"^S-\d+$")


class _ContextTemporalConditionWire(BaseModel):
    """Marker base for strict, request-local temporal factor branches."""

    model_config = ConfigDict(extra="forbid")


class _ContextOrderingTemporalWire(_ContextTemporalConditionWire):
    """Provider ordering condition using request-local step handles."""

    type: Literal["ordering"]
    reference_handle: StrictStr = Field(min_length=1)
    relation: Literal["before", "after"]


class _ContextDelayTemporalWire(_ContextTemporalConditionWire):
    """Provider delay condition using a request-local reference handle."""

    type: Literal["delay"]
    reference_handle: StrictStr = Field(min_length=1)
    delay_ms: SemanticValue


class _ContextDurationTemporalWire(_ContextTemporalConditionWire):
    """Provider duration condition using a request-local reference handle."""

    type: Literal["duration"]
    reference_handle: StrictStr = Field(min_length=1)
    duration_ms: SemanticValue


class _ContextWindowTemporalWire(_ContextTemporalConditionWire):
    """Provider window condition using a request-local reference handle."""

    type: Literal["window"]
    reference_handle: StrictStr = Field(min_length=1)
    window_from_ms: SemanticValue
    window_to_ms: SemanticValue


class _ContextAbsenceTemporalWire(_ContextTemporalConditionWire):
    """Provider absence condition using local reference and step handles."""

    type: Literal["absence"]
    reference_handle: StrictStr = Field(min_length=1)
    until_step_handle: StrictStr = Field(min_length=1)


class _ContextCausalFactorWireBase(BaseModel):
    """Common provider factor fields before evidence-status branching."""

    model_config = ConfigDict(extra="forbid")

    source_handle: StrictStr = Field(pattern=r"^cause_\d+$")
    evidence: StrictStr = Field(min_length=1)


class StimulusCategory(str, Enum):
    """Provider-only description of how the adversarial stimulus enters."""

    user_message = "user_message"
    conversation = "conversation"
    # ``conversation_context`` is accepted for captured callers that used the
    # execution-delivery spelling.  It is still mapped to the same supported
    # conversation primitive and never treated as a distinct route.
    conversation_context = "conversation_context"
    retrieved_content = "retrieved_content"
    tool_content = "tool_content"
    file_upload = "file_upload"
    traffic_load = "traffic_load"
    unknown = "unknown"


class _ContextStimulusDraft(BaseModel):
    """Request-local stimulus description; it is not persisted."""

    model_config = ConfigDict(extra="forbid")

    category: StimulusCategory
    description: StrictStr = Field(min_length=1, max_length=600)


class _ContextTemporalConditionDraft(BaseModel):
    """Temporal condition using explained request-local references.

    The canonical semantic-condition models intentionally reject local
    ``cause_*`` handles.  Keeping this draft provider-only lets the response
    validator close the request-local namespace before deterministic code
    constructs a canonical condition.
    """

    model_config = ConfigDict(extra="forbid")

    type: Literal["ordering", "delay", "duration", "window", "absence"]
    reference_handle: StrictStr | None = Field(default=None, min_length=1)
    relation: Literal["before", "after"] | None = None
    delay_ms: SemanticValue | None = None
    duration_ms: SemanticValue | None = None
    window_from_ms: SemanticValue | None = None
    window_to_ms: SemanticValue | None = None
    until_step_handle: StrictStr | None = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def validate_shape(self) -> "_ContextTemporalConditionDraft":
        """Require only the fields meaningful for the selected condition."""
        if self.type == "ordering":
            _require_temporal_field(self.reference_handle, "reference_handle")
            _require_temporal_field(self.relation, "relation")
        elif self.type == "delay":
            _require_temporal_field(self.reference_handle, "reference_handle")
            _require_temporal_field(self.delay_ms, "delay_ms")
        elif self.type == "duration":
            _require_temporal_field(self.reference_handle, "reference_handle")
            _require_temporal_field(self.duration_ms, "duration_ms")
        elif self.type == "window":
            _require_temporal_field(self.reference_handle, "reference_handle")
            _require_temporal_field(self.window_from_ms, "window_from_ms")
            _require_temporal_field(self.window_to_ms, "window_to_ms")
        elif self.type == "absence":
            _require_temporal_field(self.reference_handle, "reference_handle")
            _require_temporal_field(self.until_step_handle, "until_step_handle")
        return self


def _require_temporal_field(value: object | None, field_name: str) -> None:
    """Require a provider temporal field without accepting an empty value."""
    if value is None or (isinstance(value, str) and not value.strip()):
        raise ValueError(
            f"{field_name} is required for the selected temporal condition"
        )


class _ContextExecutableRouteDraft(BaseModel):
    """Provider route choice without deterministic resource bookkeeping."""

    model_config = ConfigDict(extra="forbid")

    disposition: Literal["executable_route"] = "executable_route"
    delivery_class: ExecutionDeliveryClass
    selected_factor_handle: StrictStr = Field(pattern=r"^cause_\d+$")
    action_kind: ExecutionActionKind
    reason: StrictStr = Field(min_length=1, max_length=600)


class ExecutableRouteSelection(BaseModel):
    """Provider-selected execution route using request-local handles only.

    This is deliberately not a classification.  It is the small choice the
    provider is allowed to make from the exact handles shown in the prompt;
    deterministic assembly turns it into a :class:`SemanticExecutionContract`.
    """

    model_config = ConfigDict(extra="forbid")

    disposition: Literal["executable_route"] = "executable_route"
    delivery_class: ExecutionDeliveryClass
    selected_factor_handle: StrictStr = Field(pattern=r"^cause_\d+$")
    action_kind: ExecutionActionKind
    resource_role_handles: tuple[StrictStr, ...] = ()
    carrier_attacker_influence: AttackerInfluence = AttackerInfluence.none
    reason: StrictStr = Field(min_length=1, max_length=600)

    @model_validator(mode="after")
    def validate_handles(self) -> "ExecutableRouteSelection":
        handles = tuple(self.resource_role_handles)
        if len(handles) != len(set(handles)):
            raise ValueError("resource_role_handles must be unique")
        if any(not handle.startswith("role_") for handle in handles):
            raise ValueError("resource_role_handles must be request-local role handles")
        if "role_stimulus_carrier" in handles:
            if self.carrier_attacker_influence not in {
                AttackerInfluence.direct,
                AttackerInfluence.indirect,
            }:
                raise ValueError(
                    "a stimulus carrier requires direct or indirect attacker influence"
                )
        elif self.carrier_attacker_influence is not AttackerInfluence.none:
            raise ValueError(
                "attacker influence is only allowed for a stimulus carrier"
            )
        object.__setattr__(self, "resource_role_handles", handles)
        return self


class _AnalyticalGapDraft(BaseModel):
    """Provider-local analytical gap with request-local evidence handles."""

    model_config = ConfigDict(extra="forbid")

    code: ExecutionSemanticGapCode
    detail: StrictStr = Field(min_length=1, max_length=400)
    evidence_handles: tuple[StrictStr, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_handles(self) -> "_AnalyticalGapDraft":
        handles = tuple(self.evidence_handles)
        if len(handles) != len(set(handles)):
            raise ValueError("analytical gap evidence_handles must be unique")
        if any(not handle.startswith("cause_") for handle in handles):
            raise ValueError(
                "analytical gap evidence_handles must be local causal handles"
            )
        object.__setattr__(self, "evidence_handles", handles)
        return self


class AnalyticalOnlyRouteSelection(BaseModel):
    """Provider-selected explanation for a route that cannot be executed."""

    model_config = ConfigDict(extra="forbid")

    disposition: Literal["analytical_only"] = "analytical_only"
    gaps: tuple[_AnalyticalGapDraft, ...] = Field(min_length=1)
    reason: StrictStr = Field(min_length=1, max_length=600)

    @model_validator(mode="after")
    def validate_gaps(self) -> "AnalyticalOnlyRouteSelection":
        identities = tuple((gap.code, gap.detail) for gap in self.gaps)
        if len(identities) != len(set(identities)):
            raise ValueError("analytical route gaps must be unique")
        return self


ExecutionRouteSelectionValue = Annotated[
    Union[ExecutableRouteSelection, AnalyticalOnlyRouteSelection],
    Field(discriminator="disposition"),
]


class BDIGenerationResult(BaseModel):
    """LLM response model for the combined BDI generation call."""

    model_config = ConfigDict(extra="forbid")

    defender_vulnerabilities: dict[str, str] = Field(default_factory=dict)
    attacker_bdi: AttackerBDI
    causal_factors: list[CausalFactorDeclaration] = Field(min_length=1)
    # Optional only for historical direct callers.  Corrected context
    # requests use a strict dynamic subtype where this field is required.
    unsafe_outcome: UnsafeOutcomeDeclaration | None = None
    # ``execution_route`` is provider-local and is consumed immediately by
    # corrected contextual assembly.  Materialized results retain only the
    # deterministic semantic contract below.
    execution_route: ExecutionRouteSelectionValue | None = None
    execution_contract: SemanticExecutionContract | None = None


class _ContextCausalFactorDraft(BaseModel):
    """Provider-only factor whose structural identity is a local handle."""

    model_config = ConfigDict(extra="forbid")

    source_handle: StrictStr = Field(pattern=r"^cause_\d+$")
    evidence: str = Field(min_length=1)
    temporal_condition: _ContextTemporalConditionDraft | None = None
    evidence_status: CausalEvidenceStatus = CausalEvidenceStatus.structural_failure
    capability_refs: tuple[str, ...] = ()
    access_refs: tuple[str, ...] = ()
    bounded_assumption: str | None = None

    @model_validator(mode="after")
    def validate_evidence(self) -> "_ContextCausalFactorDraft":
        """Reject unsupported evidence claims during response validation."""
        try:
            validate_causal_evidence_shape(
                self.evidence_status,
                self.capability_refs,
                self.access_refs,
                self.bounded_assumption,
            )
        except ValueError:
            # Historical direct fixtures sometimes supply the explicit
            # assumption while leaving the status at its structural default.
            # Materialization deterministically promotes that unambiguous
            # shape; other evidence/status contradictions remain provider
            # failures inside the bounded validation path.
            if not (
                self.evidence_status is CausalEvidenceStatus.structural_failure
                and self.bounded_assumption is not None
                and not self.capability_refs
                and not self.access_refs
            ):
                raise
        return self


class _ContextDefenderVulnerabilityDraft(BaseModel):
    """Provider prose attached to a compiler-owned defender-belief handle."""

    model_config = ConfigDict(extra="forbid")

    belief_handle: str
    vulnerability: str = Field(min_length=1)


class _ContextAttackerIntentionDraft(BaseModel):
    """Provider prose with compiler-owned structural references."""

    model_config = ConfigDict(extra="forbid")

    description: str = Field(min_length=1)
    source_handles: tuple[str, ...] = Field(min_length=1)


class _ContextAttackerBDIDraft(BaseModel):
    """Provider-only attacker BDI using local causal-source handles."""

    model_config = ConfigDict(extra="forbid")

    beliefs: list[str]
    desires: list[str]
    intentions: list[_ContextAttackerIntentionDraft]


class _ContextBDIProviderPayload(BaseModel):
    """Base response body for one exact scenario-context request."""

    model_config = ConfigDict(extra="forbid")

    stimulus: _ContextStimulusDraft
    defender_vulnerabilities: list[_ContextDefenderVulnerabilityDraft]
    attacker_bdi: _ContextAttackerBDIDraft
    causal_factors: list[_ContextCausalFactorDraft]
    unsafe_outcome: _ContextUnsafeOutcomeDraft
    execution_route: Annotated[
        Union[_ContextExecutableRouteDraft, AnalyticalOnlyRouteSelection],
        Field(discriminator="disposition"),
    ]

    @model_validator(mode="after")
    def validate_unique_belief_handles(self) -> "_ContextBDIProviderPayload":
        """Require one vulnerability record for each distinct selected belief."""
        handles = [item.belief_handle for item in self.defender_vulnerabilities]
        if len(handles) != len(set(handles)):
            raise ValueError("defender vulnerability handles must be unique")
        return self


@dataclass(frozen=True)
class _CausalSourceChoice:
    """One request-local handle bound to an exact structural factor source."""

    handle: str
    kind: CausalFactorKind
    source_id: str
    description: str


@dataclass(frozen=True)
class _ExecutionRoleChoice:
    """One request-local role handle offered to the route selector."""

    handle: str
    purpose: ExecutionResourcePurpose
    description: str


_EXECUTION_ROLE_CHOICES = (
    _ExecutionRoleChoice(
        "role_stimulus_carrier",
        ExecutionResourcePurpose.stimulus_carrier,
        "A logical source that brings attacker-influenced content into model context.",
    ),
    _ExecutionRoleChoice(
        "role_target_action",
        ExecutionResourcePurpose.target_action,
        "The exact target control action resource.",
    ),
    _ExecutionRoleChoice(
        "role_state",
        ExecutionResourcePurpose.state_resource,
        "A state resource whose value is part of the unsafe outcome.",
    ),
    _ExecutionRoleChoice(
        "role_agent_channel",
        ExecutionResourcePurpose.agent_channel,
        "The logical agent-message channel through which the unsafe action is observed.",
    ),
)


def generate_scenario_id(index: int = 0) -> str:
    """Generate a deterministic scenario ID.

    Args:
        index: Zero-based scenario index.

    Returns:
        A scenario ID in the format ``SCN-NNN`` (zero-padded).
    """
    return f"SCN-{index + 1:03d}"


def parse_ica_slot_id(slot_id: str) -> dict[str, str]:
    """Parse an ICA slot ID into its components.

    Supports two formats:
    - ``RESP-X:CA-Y:TYPE-Z`` (responsibility slot)
    - ``CL-X:CM-Y:TYPE-Z`` (coordination link slot)

    Args:
        slot_id: The ICA slot ID string.

    Returns:
        A dict with keys ``controller``, ``control_action``, and ``ica_type``.
    """
    parts = slot_id.split(":")
    if len(parts) != 3:
        raise ValueError(f"Invalid ICA slot ID format: {slot_id}")
    return {
        "controller": parts[0],
        "control_action": parts[1],
        "ica_type": parts[2],
    }


def populate_defender_bdi(
    control_structure: ControlStructure,
    target_resp_id: str,
) -> DefenderBDI:
    """Deterministically derive defender BDI from the control structure.

    Extracts beliefs from process model parts, desires from the
    responsibility description, and intentions from control actions.

    Args:
        control_structure: The control structure.
        target_resp_id: The responsibility ID to extract from.

    Returns:
        A :class:`DefenderBDI` with empty vulnerability fields.

    Raises:
        ValueError: If ``target_resp_id`` is not found in the control structure.
    """
    if target_resp_id.startswith("CL-"):
        return _populate_coordination_bdi(control_structure, target_resp_id)

    resp = _find_responsibility(control_structure, target_resp_id)

    beliefs = [
        DefenderBelief(
            pm_id=pm.pm_id,
            content=pm.description,
            vulnerability="",
        )
        for pm in resp.process_model_parts
    ]

    desires = [
        DefenderDesire(
            resp_id=resp.resp_id,
            content=resp.description,
        )
    ]

    intentions = [
        DefenderIntention(
            ca_id=ca.ca_id,
            content=ca.description,
        )
        for ca in resp.control_actions
    ]

    return DefenderBDI(beliefs=beliefs, desires=desires, intentions=intentions)


def _populate_coordination_bdi(
    control_structure: ControlStructure,
    link_id: str,
) -> DefenderBDI:
    """Derive one defender BDI from both exact endpoints of a CL path."""
    responsibilities = _coordination_responsibilities(control_structure, link_id)
    return DefenderBDI(
        beliefs=_coordination_beliefs(responsibilities),
        desires=_coordination_desires(responsibilities),
        intentions=_coordination_intentions(responsibilities),
    )


def _coordination_responsibilities(
    control_structure: ControlStructure,
    link_id: str,
) -> tuple[Responsibility, Responsibility]:
    """Resolve the two exact responsibility endpoints of one CL link."""
    links = [
        item for item in control_structure.coordination_links if item.link_id == link_id
    ]
    if len(links) != 1:
        raise ValueError(
            f"Coordination link '{link_id}' not found in control structure."
        )
    link: CoordinationLink = links[0]
    return (
        _find_responsibility(control_structure, link.source),
        _find_responsibility(control_structure, link.target),
    )


def _coordination_beliefs(
    responsibilities: tuple[Responsibility, Responsibility],
) -> list[DefenderBelief]:
    """Build belief records for both coordination endpoints."""
    return [
        DefenderBelief(pm_id=part.pm_id, content=part.description, vulnerability="")
        for responsibility in responsibilities
        for part in responsibility.process_model_parts
    ]


def _coordination_desires(
    responsibilities: tuple[Responsibility, Responsibility],
) -> list[DefenderDesire]:
    """Build desire records for both coordination endpoints."""
    return [
        DefenderDesire(
            resp_id=responsibility.resp_id, content=responsibility.description
        )
        for responsibility in responsibilities
    ]


def _coordination_intentions(
    responsibilities: tuple[Responsibility, Responsibility],
) -> list[DefenderIntention]:
    """Build intention records for every action on both endpoints."""
    return [
        DefenderIntention(ca_id=action.ca_id, content=action.description)
        for responsibility in responsibilities
        for action in responsibility.control_actions
    ]


def _find_responsibility(
    control_structure: ControlStructure,
    resp_id: str,
) -> Responsibility:
    """Find a responsibility by ID in the control structure."""
    for resp in control_structure.responsibilities:
        if resp.resp_id == resp_id:
            return resp
    raise ValueError(f"Responsibility '{resp_id}' not found in control structure.")


def generate_bdi(
    llm_client: LLMClient,
    defender_bdi: DefenderBDI,
    threat: StructuralThreat,
    control_structure: ControlStructure,
    run_dir: Path,
    loader: TemplateLoader | None = None,
    stage: str = "stage_5",
    step: str = "bdi_generation",
    temperature: float = 0.4,
    capability_profile: CapabilityProfile | None = None,
) -> tuple[BDIGenerationResult | None, str | None]:
    """Run the legacy direct Stage 5 adapter.

    Corrected SP3 runs use :func:`generate_bdi_for_context`; this explicitly
    isolated adapter keeps historical direct callers operational without
    making it the production seam.  It accepts only the legacy BDI content:
    compiler-owned ``execution_route`` and ``execution_contract`` fields are
    rejected before the result is returned.  Contextual Stage 5 output must
    therefore go through the local-handle validator and materializer.

    Args:
        llm_client: LLM client for making the completion call.
        defender_bdi: Pre-populated defender BDI with empty vulnerabilities.
        threat: The structural threat for this scenario.
        control_structure: The full control structure.
        run_dir: Directory for call logging.
        loader: Template loader (default: SP3 prompts directory).
        stage: Pipeline stage label.
        step: Sub-step label.
        temperature: LLM temperature.
        capability_profile: Optional capability profile used to ground
            technology-specific feedback mechanisms in the prompt.

    Returns:
        A tuple of (BDIGenerationResult or None, error_message or None).
    """
    if loader is None:
        loader = TemplateLoader(PROMPTS_DIR)

    slot_parts = parse_ica_slot_id(threat.ica_slot_id)
    target_resp_id = slot_parts["controller"]

    system_prompt, user_prompt = build_bdi_prompts(
        defender_bdi,
        threat,
        control_structure,
        target_resp_id,
        loader,
        capability_profile=capability_profile,
    )

    result, _llm_result, error = safe_llm_call(
        llm_client=llm_client,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_format=BDIGenerationResult,
        run_dir=run_dir,
        stage=stage,
        step=step,
        slot_id=threat.ica_slot_id,
        temperature=temperature,
    )

    if _is_length_finish_reason_error(error):
        retry_result, _retry_llm_result, retry_error = safe_llm_call(
            llm_client=llm_client,
            system_prompt=system_prompt,
            user_prompt=user_prompt + _LENGTH_RETRY_PROMPT,
            response_format=BDIGenerationResult,
            run_dir=run_dir,
            stage=stage,
            step=step,
            slot_id=threat.ica_slot_id,
            temperature=temperature,
            max_completion_tokens=_LENGTH_RETRY_MAX_COMPLETION_TOKENS,
        )
        if retry_error is None:
            return _finish_legacy_bdi_result(retry_result, None)
        return (
            None,
            f"{_LENGTH_RETRY_EXHAUSTED_PREFIX} {retry_error}",
        )

    if error is not None:
        return None, error
    return _finish_legacy_bdi_result(result, None)


def _finish_legacy_bdi_result(
    result: BDIGenerationResult | None,
    error: str | None,
) -> tuple[BDIGenerationResult | None, str | None]:
    """Keep compiler-owned fields out of the legacy direct adapter output."""
    if error is not None or result is None:
        return result, error
    if result.execution_route is not None or result.execution_contract is not None:
        return (
            None,
            "ValueError: legacy generate_bdi accepts BDI content only; use "
            "generate_bdi_for_context for execution routes and contracts",
        )
    return result, None


def generate_bdi_for_context(
    llm_client: LLMClient,
    scenario_context: ScenarioGenerationContext,
    run_dir: Path,
    loader: TemplateLoader | None = None,
    stage: str = "stage_5",
    step: str = "bdi_generation",
    temperature: float = 0.4,
    requested_environment_basis: RequestedEnvironmentBasis | None = None,
) -> tuple[BDIGenerationResult | None, str | None]:
    """Execute corrected Stage 5 with one caller-selected environment basis."""
    if loader is None:
        loader = TemplateLoader(PROMPTS_DIR)
    choices = _causal_source_choices(scenario_context)
    if not choices:
        return (
            None,
            "No valid causal-factor sources exist in the selected control path.",
        )
    system_prompt, user_prompt = build_context_bdi_prompts(scenario_context, loader)
    belief_choices = _defender_belief_choices(scenario_context)
    expected_action_kind = classify_control_action_kind(
        scenario_context.target_control_path.control_action
    )
    response_format = _context_bdi_provider_payload_type(
        len(choices),
        len(belief_choices),
        expected_action_kind,
        **_context_provider_schema_kwargs(scenario_context, choices),
    )
    validation_retry_feedback = _context_validation_retry_feedback(
        scenario_context, choices
    )
    draft, error = _call_bdi_with_bounded_length_retry(
        llm_client,
        system_prompt,
        user_prompt,
        run_dir,
        response_format=response_format,
        stage=stage,
        step=step,
        slot_id=scenario_context.scenario_identity.ica_slot_id,
        scenario_id=scenario_context.scenario_identity.scenario_id,
        temperature=temperature,
        validation_retry_feedback=validation_retry_feedback,
        result_validator=lambda value: _validate_context_provider_payload(
            value,
            scenario_context,
        ),
    )
    return _finish_context_bdi(
        draft,
        error,
        choices,
        belief_choices,
        scenario_context,
        requested_environment_basis,
    )


def _finish_context_bdi(
    draft: BaseModel | None,
    error: str | None,
    choices: tuple[_CausalSourceChoice, ...],
    belief_choices: tuple[tuple[str, DescribedElement], ...],
    context: ScenarioGenerationContext,
    requested_environment_basis: RequestedEnvironmentBasis | None,
) -> tuple[BDIGenerationResult | None, str | None]:
    """Compile one parsed provider draft or preserve its closed failure."""
    if error is not None or draft is None:
        return None, error
    try:
        return (
            _materialize_context_bdi(
                draft,
                choices,
                belief_choices,
                context,
                requested_environment_basis,
            ),
            None,
        )
    except (KeyError, TypeError, ValueError) as exc:
        return None, f"{type(exc).__name__}: {exc}"


def _call_bdi_with_bounded_length_retry(
    llm_client: LLMClient,
    system_prompt: str,
    user_prompt: str,
    run_dir: Path,
    *,
    response_format: type[BaseModel],
    stage: str,
    step: str,
    temperature: float,
    slot_id: str | None = None,
    scenario_id: str | None = None,
    result_validator: Callable[[BaseModel], None] | None = None,
    validation_retry_feedback: str | None = None,
) -> tuple[BaseModel | None, str | None]:
    """Call the closed Stage 5 contract with its one length-only retry."""
    retry_feedback = validation_retry_feedback or (
        " Return only a closed JSON object with every required field. "
        "Include causal_factors, explicit temporal_condition (including "
        "null), unsafe_outcome with its typed condition, and one "
        "execution_route. Do not return semantic_binding_required; "
        "deterministic code derives it."
    )
    result, _llm_result, error = safe_llm_call(
        llm_client=llm_client,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_format=response_format,
        run_dir=run_dir,
        stage=stage,
        step=step,
        slot_id=slot_id,
        scenario_id=scenario_id,
        temperature=temperature,
        validation_retries=1,
        validation_retry_include_schema=False,
        validation_retry_feedback=retry_feedback,
        result_validator=result_validator,
        result_parser=lambda value: _parse_context_bdi_result(value, response_format),
    )
    if not _is_length_finish_reason_error(error):
        return (None, error) if error is not None else (result, None)
    retry_result, _retry_llm_result, retry_error = safe_llm_call(
        llm_client=llm_client,
        system_prompt=system_prompt,
        user_prompt=user_prompt + _LENGTH_RETRY_PROMPT,
        response_format=response_format,
        run_dir=run_dir,
        stage=stage,
        step=step,
        slot_id=slot_id,
        scenario_id=scenario_id,
        temperature=temperature,
        max_completion_tokens=_LENGTH_RETRY_MAX_COMPLETION_TOKENS,
        validation_retries=1,
        validation_retry_include_schema=False,
        validation_retry_feedback=retry_feedback,
        result_validator=result_validator,
        result_parser=lambda value: _parse_context_bdi_result(value, response_format),
    )
    if retry_error is None:
        return retry_result, None
    return None, f"{_LENGTH_RETRY_EXHAUSTED_PREFIX} {retry_error}"


def _parse_context_bdi_result(result, response_format: type[BaseModel]) -> BaseModel:
    """Parse the contextual provider payload without compiler-owned fields.

    A small compatibility adapter recognizes the pre-recovery fixture shape
    only when it carries the now-removed role/influence fields.  Ordinary
    responses must provide the typed ``stimulus`` object; there is no default
    stimulus fallback for the normal provider contract.
    """
    content = result.content
    if isinstance(content, BaseModel):
        payload = content.model_dump(mode="json")
    elif isinstance(content, Mapping):
        payload = dict(content)
    elif isinstance(content, str):
        payload = json.loads(_decode_provider_json_text(content))
    else:
        return parse_llm_result(result, response_format)
    if isinstance(payload, Mapping):
        payload = _migrate_legacy_context_payload(payload)
    return response_format.model_validate(payload)


def _decode_provider_json_text(value: str) -> str:
    """Remove only an exact JSON Markdown fence before provider parsing."""
    stripped = value.strip()
    lines = stripped.splitlines()
    if (
        len(lines) >= 3
        and lines[0].strip().lower() in {"```json", "```"}
        and lines[-1].strip() == "```"
    ):
        return "\n".join(lines[1:-1])
    return stripped


def _migrate_legacy_context_payload(payload: Mapping[str, object]) -> dict[str, object]:
    """Keep historical test fixtures usable without weakening new responses."""
    updated = dict(payload)
    _normalize_legacy_temporal_fields(updated)
    route = updated.get("execution_route")
    if "stimulus" in updated or not isinstance(route, Mapping):
        return updated
    legacy_fields = {"resource_role_handles", "carrier_attacker_influence"}
    if not legacy_fields.intersection(route):
        return updated
    delivery = route.get("delivery_class")
    category = {
        ExecutionDeliveryClass.direct_prompt.value: StimulusCategory.user_message.value,
        ExecutionDeliveryClass.conversation_context.value: StimulusCategory.conversation.value,
        ExecutionDeliveryClass.indirect_content.value: StimulusCategory.tool_content.value,
    }.get(delivery)
    if category is None:
        return updated
    updated["stimulus"] = {
        "category": category,
        "description": (
            "Compatibility stimulus for the historical execution route fixture."
        ),
    }
    cleaned_route = dict(route)
    for field_name in legacy_fields:
        cleaned_route.pop(field_name, None)
    updated["execution_route"] = cleaned_route
    return updated


def _normalize_legacy_temporal_fields(payload: dict[str, object]) -> None:
    """Translate old canonical temporal field names into local draft names."""
    factors = payload.get("causal_factors")
    if not isinstance(factors, Sequence) or isinstance(factors, (str, bytes)):
        return
    for factor in factors:
        _normalize_legacy_temporal_factor(factor)


def _normalize_legacy_temporal_factor(factor: object) -> None:
    """Normalize one historical factor mapping in place when possible."""
    if not isinstance(factor, Mapping):
        return
    temporal = factor.get("temporal_condition")
    if not isinstance(temporal, Mapping):
        return
    normalized = dict(temporal)
    _copy_first_legacy_temporal_field(
        normalized,
        "reference_handle",
        (
            "reference_ref",
            "reference_step_id",
            "reference_step_handle",
            "source_handle",
        ),
    )
    _copy_first_legacy_temporal_field(
        normalized,
        "until_step_handle",
        ("until_step_id", "until_step"),
    )
    if isinstance(factor, dict):
        factor["temporal_condition"] = normalized


def _copy_first_legacy_temporal_field(
    values: dict[str, object],
    target_name: str,
    legacy_names: Sequence[str],
) -> None:
    """Copy and remove the first matching historical temporal field."""
    if target_name in values:
        return
    for old_name in legacy_names:
        if old_name in values:
            values[target_name] = values.pop(old_name)
            return


def _validate_context_provider_payload(
    value: BaseModel,
    context: ScenarioGenerationContext,
) -> None:
    """Validate request-local unsafe semantics before Stage 5 succeeds."""
    stimulus, unsafe_outcome, route = _context_provider_required_parts(value)
    choices = _causal_source_choices(context)
    allowed_handles = {choice.handle for choice in choices}
    declared_handles = _declared_causal_handles(value.causal_factors)
    if not declared_handles <= allowed_handles:
        unknown = sorted(declared_handles - allowed_handles)
        raise ValueError(
            "causal factor source handles must name supplied context choices: "
            + ", ".join(unknown)
        )
    _validate_intention_factor_handles(value.attacker_bdi, value.causal_factors)
    _validate_intention_choice_handles(value.attacker_bdi, allowed_handles)
    _validate_defender_vulnerability_handles(value, context)
    _validate_context_provider_temporal_conditions(
        value.causal_factors, choices, context
    )
    _validate_execution_route(
        route,
        value.causal_factors,
        context,
        unsafe_outcome,
        stimulus=stimulus,
    )
    _validate_unsafe_outcome_for_target(
        unsafe_outcome,
        context.ica.uca_type,
        context.target_control_path.control_action.action_id,
    )


def _context_provider_required_parts(
    value: BaseModel,
) -> tuple[_ContextStimulusDraft, _ContextUnsafeOutcomeDraft, BaseModel]:
    """Return the provider-owned fields required by corrected Stage 5."""
    stimulus = getattr(value, "stimulus", None)
    if not isinstance(stimulus, _ContextStimulusDraft):
        raise ValueError("stimulus is required in corrected Stage 5 output")
    unsafe_outcome = getattr(value, "unsafe_outcome", None)
    if not isinstance(unsafe_outcome, _ContextUnsafeOutcomeDraft):
        raise ValueError("unsafe_outcome is required in corrected Stage 5 output")
    route = getattr(value, "execution_route", None)
    if route is None:
        raise ValueError("execution_route is required in corrected Stage 5 output")
    return stimulus, unsafe_outcome, route


def _validate_context_provider_temporal_conditions(
    factor_drafts: Sequence[BaseModel],
    choices: Sequence[_CausalSourceChoice],
    context: ScenarioGenerationContext,
) -> None:
    """Resolve every local temporal reference before provider success."""
    factor_order = {
        factor.source_handle: index
        for index, factor in enumerate(factor_drafts, start=1)
    }
    for factor in factor_drafts:
        _resolve_temporal_condition(
            factor.temporal_condition,
            factor.source_handle,
            choices,
            context,
            factor_order=factor_order,
        )


def _validate_stimulus_route(
    route: BaseModel,
    stimulus: _ContextStimulusDraft,
) -> None:
    """Require supported typed stimuli to use their one matching delivery."""
    if isinstance(route, AnalyticalOnlyRouteSelection):
        return
    expected_delivery = _stimulus_delivery(stimulus.category)
    if expected_delivery is None:
        raise ValueError(
            f"stimulus category {stimulus.category.value} has no supported delivery; "
            "use an analytical_only route with delivery_path_missing"
        )
    if route.delivery_class.value != expected_delivery:
        raise ValueError(
            f"stimulus category {stimulus.category.value} requires "
            f"delivery_class={expected_delivery}, received {route.delivery_class.value}"
        )


def _validate_intention_choice_handles(
    attacker_draft: BaseModel,
    allowed_handles: set[str],
) -> None:
    """Reject intentions that cite a request-local handle not offered in context."""
    unknown = sorted(
        {
            handle
            for intention in attacker_draft.intentions
            for handle in intention.source_handles
            if handle not in allowed_handles
        }
    )
    if unknown:
        raise ValueError(
            "intention source handles must name supplied context choices: "
            + ", ".join(unknown)
        )


def _validate_defender_vulnerability_handles(
    value: BaseModel,
    context: ScenarioGenerationContext,
) -> None:
    """Require exactly one vulnerability annotation per supplied belief handle."""
    expected = {handle for handle, _belief in _defender_belief_choices(context)}
    actual = {item.belief_handle for item in value.defender_vulnerabilities}
    if actual != expected:
        missing = ", ".join(sorted(expected - actual)) or "none"
        extra = ", ".join(sorted(actual - expected)) or "none"
        raise ValueError(
            "defender_vulnerabilities must cover each supplied belief handle "
            f"(missing: {missing}; extra: {extra})"
        )


def _resolve_temporal_condition(
    draft: _ContextTemporalConditionDraft | SemanticCondition | None,
    factor_handle: str,
    choices: Sequence[_CausalSourceChoice],
    context: ScenarioGenerationContext,
    *,
    factor_order: Mapping[str, int] | None = None,
) -> SemanticCondition | None:
    """Resolve one provider temporal draft into a canonical condition.

    ``factor_order`` is the declaration order used by the later execution
    projection (``S-1`` … ``S-N`` and the final UCA step).  Structural IDs are
    accepted only as a compatibility path when they are already present in
    this exact selected context; no provider-authored identity is invented.
    """
    if draft is None:
        return None
    if not isinstance(
        draft, (_ContextTemporalConditionDraft, _ContextTemporalConditionWire)
    ):
        # Direct callers may already hold a canonical condition.  It has
        # already passed the structural-reference validators and remains
        # compatible with the historical non-contextual path.
        return draft
    by_handle = {choice.handle: choice for choice in choices}
    factor_order = factor_order or {factor_handle: 1}
    reference_handle = draft.reference_handle
    if reference_handle is None:
        raise ValueError("temporal condition requires a reference_handle")
    resolved_reference = _temporal_structural_reference_for_draft(
        draft, reference_handle, by_handle, choices, context
    )
    return _build_temporal_condition(
        draft,
        reference_handle,
        resolved_reference,
        factor_order,
        by_handle,
    )


def _temporal_structural_reference(
    handle: str,
    by_handle: Mapping[str, _CausalSourceChoice],
    choices: Sequence[_CausalSourceChoice],
    context: ScenarioGenerationContext,
) -> str:
    """Resolve a local structural temporal reference to an exact ID."""
    if handle == "target_action":
        return context.target_control_path.control_action.action_id
    if handle in by_handle:
        return by_handle[handle].source_id
    if handle in {choice.source_id for choice in choices}:
        return handle
    raise ValueError(
        "temporal reference_handle must name a supplied target_action or cause handle"
    )


def _temporal_structural_reference_for_draft(
    draft: _ContextTemporalConditionDraft,
    reference_handle: str,
    by_handle: Mapping[str, _CausalSourceChoice],
    choices: Sequence[_CausalSourceChoice],
    context: ScenarioGenerationContext,
) -> str | None:
    """Resolve only condition families that carry a structural reference."""
    if draft.type == "ordering":
        return None
    return _temporal_structural_reference(reference_handle, by_handle, choices, context)


def _temporal_step_index(handle: str) -> int | None:
    """Parse one explicitly named local step, if its prefix is recognized."""
    if handle.startswith("step_"):
        prefix = "step_"
    elif handle.startswith("S-"):
        prefix = "S-"
    else:
        return None
    try:
        return int(handle.removeprefix(prefix))
    except ValueError as exc:
        raise ValueError("temporal step reference is malformed") from exc


def _temporal_step_reference(
    handle: str,
    factor_order: Mapping[str, int],
    by_handle: Mapping[str, _CausalSourceChoice],
) -> str:
    """Resolve a local step reference without inventing undeclared steps."""
    if handle == "target_action":
        return f"S-{len(factor_order) + 1}"
    if handle in factor_order:
        return f"S-{factor_order[handle]}"
    if handle in by_handle:
        raise ValueError("temporal step reference must name a declared causal factor")
    index = _temporal_step_index(handle)
    if index is not None and 1 <= index <= len(factor_order) + 1:
        return f"S-{index}"
    raise ValueError(
        "temporal step reference must name target_action or a declared cause handle"
    )


def _build_temporal_condition(
    draft: _ContextTemporalConditionDraft,
    reference_handle: str,
    resolved_reference: str | None,
    factor_order: Mapping[str, int],
    by_handle: Mapping[str, _CausalSourceChoice],
) -> SemanticCondition:
    """Construct one canonical semantic condition from resolved references."""
    if draft.type == "ordering":
        return OrderingCondition(
            reference_step_id=_temporal_step_reference(
                reference_handle, factor_order, by_handle
            ),
            relation=draft.relation,  # type: ignore[arg-type]
        )
    if draft.type == "delay":
        return DelayCondition(
            reference_ref=resolved_reference,
            delay_ms=draft.delay_ms,  # type: ignore[arg-type]
        )
    if draft.type in {"duration", "window"}:
        return _build_duration_or_window_condition(draft, resolved_reference)
    if draft.type == "absence":
        return AbsenceCondition(
            reference_ref=resolved_reference,
            until_step_id=_temporal_step_reference(
                draft.until_step_handle or "", factor_order, by_handle
            ),
        )
    raise ValueError(f"unsupported temporal condition type: {draft.type}")


def _build_duration_or_window_condition(
    draft: _ContextTemporalConditionDraft,
    resolved_reference: str | None,
) -> SemanticCondition:
    """Build the bounded temporal families sharing one structural reference."""
    if draft.type == "duration":
        return DurationCondition(
            reference_ref=resolved_reference,  # type: ignore[arg-type]
            duration_ms=draft.duration_ms,  # type: ignore[arg-type]
        )
    return WindowCondition(
        reference_ref=resolved_reference,  # type: ignore[arg-type]
        window_from_ms=draft.window_from_ms,  # type: ignore[arg-type]
        window_to_ms=draft.window_to_ms,  # type: ignore[arg-type]
    )


def _is_length_finish_reason_error(error: str | None) -> bool:
    """Return whether a safe-call error came from completion length exhaustion."""
    if error is None:
        return False
    error_type, _, _message = error.partition(":")
    return error_type == "LengthFinishReasonError"


def is_bdi_length_retry_exhausted(error: str | None) -> bool:
    """Return whether both bounded structured-output length attempts failed."""
    return bool(error and error.startswith(_LENGTH_RETRY_EXHAUSTED_PREFIX))


def build_bdi_prompts(
    defender_bdi: DefenderBDI,
    threat: StructuralThreat,
    control_structure: ControlStructure,
    target_resp_id: str,
    loader: TemplateLoader,
    capability_profile: CapabilityProfile | None = None,
) -> tuple[str, str]:
    """Build historical Stage 5 prompts for compatibility-only direct callers.

    When supplied, ``capability_profile`` is rendered as technology context
    so attacker intentions stay grounded in declared AI surfaces.  When
    omitted, the technology-context section is left out of the user prompt.
    """
    defender_bdi_yaml = yaml.dump(
        defender_bdi.model_dump(mode="json"),
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
    )
    control_structure_yaml = yaml.dump(
        control_structure.model_dump(mode="json", exclude_none=True),
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
    )
    catalog_context = (
        yaml.dump(
            [m.model_dump(mode="json") for m in threat.catalog_mappings],
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
        )
        if threat.catalog_mappings
        else "No catalog mappings."
    )
    technology_context = context_for(capability_profile)

    system_prompt = loader.render_prompt("stage5_system.j2")
    user_prompt = loader.render_prompt(
        "stage5_user.j2",
        defender_bdi_yaml=defender_bdi_yaml,
        ica_text=threat.ica_text,
        hazardous_context=threat.hazardous_context,
        loss_scenario=threat.loss_scenario,
        control_structure_yaml=control_structure_yaml,
        target_resp_id=target_resp_id,
        catalog_context=catalog_context,
        technology_context=technology_context,
    )

    return system_prompt, user_prompt


def build_context_bdi_prompts(
    scenario_context: ScenarioGenerationContext,
    loader: TemplateLoader,
) -> tuple[str, str]:
    """Render Stage 5 from only the immutable context and output contract."""
    scenario_context_yaml = yaml.dump(
        _stage5_prompt_context(scenario_context),
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
    )
    source_choices = _causal_source_choices(scenario_context)
    if not source_choices:
        raise ValueError("selected scenario context has no valid causal-factor sources")
    source_choices_yaml = _context_source_choices_yaml(source_choices)
    belief_choices_yaml = _context_belief_choices_yaml(scenario_context)
    stimulus_choices_yaml = _stimulus_choices_yaml()
    temporal_reference_choices_yaml = _temporal_reference_choices_yaml(
        scenario_context, source_choices
    )
    expected_action_kind = _context_expected_action_kind(scenario_context)
    schema_kwargs = _context_provider_schema_kwargs(scenario_context, source_choices)
    provider_types = _context_bdi_provider_wire_types(
        len(source_choices),
        len(_defender_belief_choices(scenario_context)),
        expected_action_kind,
        **schema_kwargs,
    )
    prompt_examples = _context_prompt_examples(
        scenario_context,
        source_choices,
        provider_types,
    )
    return (
        loader.render_prompt(
            "stage5_context_system.j2",
            target_action_id=scenario_context.target_control_path.control_action.action_id,
            expected_action_kind=(
                expected_action_kind.value if expected_action_kind is not None else None
            ),
            unsafe_condition_example_json=prompt_examples["unsafe_condition"],
            execution_route_example_json=prompt_examples["execution_route"],
            analytical_route_example_json=prompt_examples["analytical_route"],
            temporal_condition_examples_json=prompt_examples["temporal_conditions"],
            evidence_examples_json=prompt_examples["evidence"],
        ),
        loader.render_prompt(
            "stage5_context_user.j2",
            scenario_context_yaml=scenario_context_yaml,
            causal_source_choices_yaml=source_choices_yaml,
            defender_belief_choices_yaml=belief_choices_yaml,
            stimulus_choices_yaml=stimulus_choices_yaml,
            temporal_reference_choices_yaml=temporal_reference_choices_yaml,
            target_action_id=scenario_context.target_control_path.control_action.action_id,
            selected_uca_type=scenario_context.ica.uca_type.value,
            expected_action_kind=(
                expected_action_kind.value if expected_action_kind is not None else None
            ),
            unsafe_condition_example_json=prompt_examples["unsafe_condition"],
            execution_route_example_json=prompt_examples["execution_route"],
            analytical_route_example_json=prompt_examples["analytical_route"],
            temporal_condition_examples_json=prompt_examples["temporal_conditions"],
            evidence_examples_json=prompt_examples["evidence"],
        ),
    )


def _yaml_dump(value: object) -> str:
    """Dump one prompt view with the stable Stage 5 YAML options."""
    return yaml.dump(
        value,
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
    )


def _context_prompt_temporal_examples(
    context: ScenarioGenerationContext,
    choices: Sequence[_CausalSourceChoice],
    provider_types: Mapping[str, type[BaseModel]],
    *,
    condition: Mapping[str, object],
    route_delivery: str,
) -> list[dict[str, object]]:
    """Render validated temporal-factor examples available to the request."""
    source = choices[0]
    examples: list[dict[str, object]] = []
    for branch in ("ordering", "delay", "duration", "window", "absence"):
        type_name = _find_wire_type(provider_types, "_ContextTemporal", branch)
        if type_name is None:
            continue
        temporal = _prompt_temporal_fixture(branch, source.handle)
        factor_payload = _prompt_provider_payload(
            provider_types,
            context,
            condition=condition,
            temporal_condition=temporal,
            route={
                "disposition": "executable_route",
                "delivery_class": route_delivery,
                "selected_factor_handle": source.handle,
                "action_kind": _prompt_action_kind(context),
                "reason": "The selected typed factor explains this supported route.",
            },
            stimulus={
                "category": _prompt_stimulus_category(route_delivery),
                "description": "A typed request-local stimulus reaches the selected route.",
            },
        )
        examples.append(
            _json_value(factor_payload.causal_factors[0].temporal_condition)
        )
    return examples


def _context_prompt_evidence_examples(
    context: ScenarioGenerationContext,
    choices: Sequence[_CausalSourceChoice],
    provider_types: Mapping[str, type[BaseModel]],
    *,
    condition: Mapping[str, object],
    route_delivery: str,
) -> list[dict[str, object]]:
    """Render validated evidence-status examples available to the request."""
    source = choices[0]
    examples: list[dict[str, object]] = []
    factor_type_names = {
        "structural_failure": "structural_failure",
        "reachable_capability": "reachable_capability",
        "bounded_assumption": "bounded_assumption",
    }
    for status, type_name in factor_type_names.items():
        if provider_types.get(type_name) is None:
            continue
        if status == "reachable_capability" and not context.reachable_capabilities:
            continue
        factor = _prompt_factor_fixture(status, context, source.handle)
        factor_payload = _prompt_provider_payload(
            provider_types,
            context,
            factor=factor,
            condition=condition,
            route={
                "disposition": "executable_route",
                "delivery_class": route_delivery,
                "selected_factor_handle": source.handle,
                "action_kind": _prompt_action_kind(context),
                "reason": "The selected typed factor explains this supported route.",
            },
            stimulus={
                "category": _prompt_stimulus_category(route_delivery),
                "description": "A typed request-local stimulus reaches the selected route.",
            },
        )
        examples.append(_json_value(factor_payload.causal_factors[0]))
    return examples


def _context_prompt_examples(
    context: ScenarioGenerationContext,
    choices: Sequence[_CausalSourceChoice],
    provider_types: Mapping[str, type[BaseModel]],
) -> dict[str, str]:
    """Render JSON fixtures validated by the exact request wire model."""
    source = choices[0]
    action_id = context.target_control_path.control_action.action_id
    condition_kind = _prompt_condition_kind(context, provider_types)
    condition = _prompt_condition_fixture(condition_kind, context, action_id)
    route_delivery = _compatible_delivery_classes(source.kind)[0].value
    structural = _prompt_provider_payload(
        provider_types,
        context,
        condition=condition,
        route={
            "disposition": "executable_route",
            "delivery_class": route_delivery,
            "selected_factor_handle": source.handle,
            "action_kind": _prompt_action_kind(context),
            "reason": "The selected typed factor explains this supported route.",
        },
        stimulus={
            "category": _prompt_stimulus_category(route_delivery),
            "description": "A typed request-local stimulus reaches the selected route.",
        },
    )
    executable = _json_fixture(structural.execution_route)

    analytical_payload = _prompt_provider_payload(
        provider_types,
        context,
        condition=condition,
        route={
            "disposition": "analytical_only",
            "gaps": [
                {
                    "code": "delivery_path_missing",
                    "detail": "The available evidence does not establish a supported delivery path.",
                    "evidence_handles": [source.handle],
                }
            ],
            "reason": "The finding remains analytical because the delivery path is unsupported.",
        },
        stimulus={
            "category": "file_upload",
            "description": "An attachment is the actual but unsupported stimulus.",
        },
    )
    analytical = _json_fixture(analytical_payload.execution_route)

    temporal_examples = _context_prompt_temporal_examples(
        context,
        choices,
        provider_types,
        condition=condition,
        route_delivery=route_delivery,
    )
    evidence_examples = _context_prompt_evidence_examples(
        context,
        choices,
        provider_types,
        condition=condition,
        route_delivery=route_delivery,
    )

    return {
        "unsafe_condition": _json_fixture(structural.unsafe_outcome.condition),
        "execution_route": executable,
        "analytical_route": analytical,
        "temporal_conditions": _json_dumps(temporal_examples),
        "evidence": _json_dumps(evidence_examples),
    }


def _context_validation_retry_feedback(
    context: ScenarioGenerationContext,
    choices: Sequence[_CausalSourceChoice],
) -> str:
    """Describe stable, field-specific repairs for one bounded correction."""
    expected_action_kind = _context_expected_action_kind(context)
    provider_types = _context_bdi_provider_wire_types(
        len(choices),
        len(_defender_belief_choices(context)),
        expected_action_kind,
        **_context_provider_schema_kwargs(context, choices),
    )
    examples = _context_prompt_examples(context, choices, provider_types)
    return (
        " Correct only the fields identified by the exact validation error; "
        "keep all request-local identities, choices, and semantic meaning unchanged. "
        "Do not infer the missing tag or any other discriminator from prose or neighboring fields.\n"
        "Stable repair codes:\n"
        "- missing_execution_route_disposition: set execution_route.disposition "
        "to the selected literal branch and preserve its complete branch shape.\n"
        "- missing_unsafe_condition_type: set unsafe_outcome.condition.type to "
        "the one permitted branch; do not change the condition fields.\n"
        "- missing_route_rationale: add a concise non-empty route reason.\n"
        "- missing_temporal_branch_field: add only the required field for the "
        "named temporal type (reference_handle, relation, delay_ms, duration_ms, "
        "window bounds, or until_step_handle).\n"
        "- incomplete_evidence_status_branch: include the required evidence_status "
        "and only its supporting capability/access references or bounded-assumption text.\n"
        "- copied_opaque_identity_mismatch: restore the exact supplied opaque handle; "
        "never normalize, substitute, or invent an identity.\n"
        "Relevant validated route fixture:\n"
        f"```json\n{examples['execution_route']}\n```\n"
        "Relevant validated unsafe-condition fixture:\n"
        f"```json\n{examples['unsafe_condition']}\n```\n"
        "Return one complete provider response after this single bounded correction."
    )


def _prompt_provider_payload(
    provider_types: Mapping[str, type[BaseModel]],
    context: ScenarioGenerationContext,
    *,
    condition: Mapping[str, object],
    route: Mapping[str, object],
    stimulus: Mapping[str, object],
    factor: Mapping[str, object] | None = None,
    temporal_condition: Mapping[str, object] | None = None,
) -> BaseModel:
    """Build one complete fixture and validate it through the request model."""
    source_handle = next(
        item["source_handle"] for item in _context_source_choice_records(context)
    )
    factor_data = dict(
        factor
        or {
            "source_handle": source_handle,
            "evidence": "The selected structural condition explains the finding.",
            "temporal_condition": temporal_condition,
            "evidence_status": "structural_failure",
        }
    )
    if temporal_condition is not None:
        factor_data["temporal_condition"] = temporal_condition
    payload = {
        "stimulus": dict(stimulus),
        "defender_vulnerabilities": [
            {
                "belief_handle": handle,
                "vulnerability": "The selected belief can be stale.",
            }
            for handle, _belief in _defender_belief_choices(context)
        ],
        "attacker_bdi": {
            "beliefs": ["The selected control-loop state can be stale."],
            "desires": ["Induce the selected unsafe action."],
            "intentions": [
                {
                    "description": "Rely on the selected causal factor.",
                    "source_handles": [source_handle],
                }
            ],
        },
        "causal_factors": [factor_data],
        "unsafe_outcome": {
            "condition": dict(condition),
            "semantic_proposition": (
                "The selected response exhibits the unsafe semantic behavior."
                if _context_expected_action_kind(context)
                is ExecutionActionKind.model_output
                else None
            ),
        },
        "execution_route": dict(route),
    }
    return provider_types["payload"].model_validate(payload)


def _context_source_choice_records(
    context: ScenarioGenerationContext,
) -> list[dict[str, str]]:
    """Return one small local source view for prompt fixture construction."""
    return [{"source_handle": item.handle} for item in _causal_source_choices(context)]


def _prompt_factor_fixture(
    status: str,
    context: ScenarioGenerationContext,
    source_handle: str,
) -> dict[str, object]:
    """Build one evidence-status fixture without inventing authority."""
    factor: dict[str, object] = {
        "source_handle": source_handle,
        "evidence": "The selected structural condition explains the finding.",
        "temporal_condition": None,
        "evidence_status": status,
    }
    if status == "reachable_capability":
        capability = context.reachable_capabilities[0]
        factor.update(
            capability_refs=[capability.capability_id],
            access_refs=[capability.access_path[0]],
        )
    elif status == "bounded_assumption":
        factor["bounded_assumption"] = (
            "Assume the selected connection can occur within this bounded analysis."
        )
    return factor


def _prompt_condition_kind(
    context: ScenarioGenerationContext,
    provider_types: Mapping[str, type[BaseModel]],
) -> str:
    """Select one permitted condition branch for the current request fixture."""
    preferred = {
        UCAType.not_provided: "action_presence",
        UCAType.incorrect: "action_value",
        UCAType.wrong_timing: "delay",
        UCAType.wrong_duration: "duration",
    }[context.ica.uca_type]
    if preferred in provider_types:
        return preferred
    if context.ica.uca_type is UCAType.incorrect and "state_value" in provider_types:
        return "state_value"
    raise ValueError("provider schema has no condition branch for the selected UCA")


def _prompt_condition_fixture(
    kind: str,
    context: ScenarioGenerationContext,
    action_id: str,
) -> dict[str, object]:
    """Return a small branch fixture using only exact context references."""
    if kind == "action_presence":
        return {
            "type": kind,
            "control_action_id": action_id,
            "expected": "not_provided",
        }
    if kind == "action_value":
        if _context_expected_action_kind(context) is ExecutionActionKind.model_output:
            property_name = "semantic_proposition"
            expected: object = True
        else:
            property_name = "action_argument"
            expected = "approved"
        return {
            "type": kind,
            "control_action_id": action_id,
            "property": property_name,
            "operator": "equals",
            "expected": expected,
        }
    if kind == "state_value":
        state = context.target_control_path.process_model_parts[0].element_id
        return {
            "type": kind,
            "subject_ref": state,
            "property": "state_value",
            "operator": "equals",
            "expected": True,
        }
    if kind == "ordering":
        return {"type": kind, "reference_step_id": "S-1", "relation": "before"}
    if kind == "delay":
        return {"type": kind, "reference_ref": action_id, "delay_ms": 1}
    if kind == "duration":
        return {"type": kind, "reference_ref": action_id, "duration_ms": 1}
    if kind == "window":
        return {
            "type": kind,
            "reference_ref": action_id,
            "window_from_ms": 0,
            "window_to_ms": 1,
        }
    if kind == "absence":
        return {
            "type": kind,
            "reference_ref": action_id,
            "until_step_id": "S-1",
        }
    raise ValueError(f"unsupported prompt condition branch: {kind}")


def _prompt_temporal_fixture(kind: str, source_handle: str) -> dict[str, object]:
    """Return one exact temporal-factor branch fixture."""
    base = {"type": kind, "reference_handle": source_handle}
    if kind == "ordering":
        base["relation"] = "before"
    elif kind == "delay":
        base["delay_ms"] = 1
    elif kind == "duration":
        base["duration_ms"] = 1
    elif kind == "window":
        base.update(window_from_ms=0, window_to_ms=1)
    elif kind == "absence":
        base["until_step_handle"] = source_handle
    return base


def _prompt_action_kind(context: ScenarioGenerationContext) -> str:
    """Use the authoritative action kind or a neutral legacy fixture value."""
    return (
        _context_expected_action_kind(context) or ExecutionActionKind.model_output
    ).value


def _prompt_stimulus_category(delivery_class: str) -> str:
    """Map one deterministic delivery primitive to its fixture category."""
    return {
        ExecutionDeliveryClass.direct_prompt.value: StimulusCategory.user_message.value,
        ExecutionDeliveryClass.conversation_context.value: StimulusCategory.conversation.value,
        ExecutionDeliveryClass.indirect_content.value: StimulusCategory.retrieved_content.value,
    }[delivery_class]


def _find_wire_type(
    provider_types: Mapping[str, type[BaseModel]],
    prefix: str,
    branch: str,
) -> str | None:
    """Find a dynamic wire model by its stable semantic branch prefix."""
    expected = f"{prefix}{branch.title().replace('_', '')}Draft"
    for name in provider_types:
        if name.startswith(expected):
            return name
    return None


def _json_fixture(value: object) -> str:
    """Serialize a validated provider-wire value for prompt rendering."""
    return json.dumps(_json_value(value), ensure_ascii=False, indent=2)


def _json_dumps(value: object) -> str:
    """Serialize a validated provider-wire collection as readable JSON."""
    return json.dumps(_json_value(value), ensure_ascii=False, indent=2)


def _json_value(value: object) -> object:
    """Convert a provider-wire value to JSON-compatible plain data."""
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    return value


def _context_source_choices_yaml(
    source_choices: Sequence[_CausalSourceChoice],
) -> str:
    """Render local causal handles and their typed delivery compatibility."""
    return _yaml_dump(
        [
            {
                "source_handle": choice.handle,
                "source_type": _source_type_explanation(choice.kind),
                "description": choice.description,
                "select_when": _source_selection_guidance(choice.kind),
                "compatible_delivery_classes": [
                    item.value for item in _compatible_delivery_classes(choice.kind)
                ],
            }
            for choice in source_choices
        ]
    )


def _context_belief_choices_yaml(context: ScenarioGenerationContext) -> str:
    """Render the compiler-owned defender belief handles."""
    return _yaml_dump(
        [
            {
                "belief_handle": handle,
                "description": belief.description,
            }
            for handle, belief in _defender_belief_choices(context)
        ]
    )


def _context_expected_action_kind(
    context: ScenarioGenerationContext,
) -> ExecutionActionKind | None:
    """Return the fixed typed action kind expected by the provider route."""
    return classify_control_action_kind(context.target_control_path.control_action)


def _context_provider_schema_kwargs(
    context: ScenarioGenerationContext,
    choices: Sequence[_CausalSourceChoice],
) -> dict[str, object]:
    """Return exact authority used to close the contextual provider schema."""
    action = context.target_control_path.control_action
    action_id = action.action_id
    source_ids = tuple(choice.source_id for choice in choices)
    condition_refs = tuple(dict.fromkeys((action_id, *source_ids)))
    return {
        "target_action_id": action_id,
        "uca_type": context.ica.uca_type,
        "state_subject_refs": tuple(
            item.element_id for item in context.target_control_path.process_model_parts
        ),
        "temporal_reference_handles": (
            "target_action",
            *(choice.handle for choice in choices),
        ),
        "condition_reference_refs": condition_refs,
        "condition_step_refs": tuple(
            f"S-{index}" for index in range(1, len(choices) + 2)
        ),
        "duration_eligible": _action_duration_eligible(action),
    }


def _action_duration_eligible(action: object) -> bool:
    """Return whether typed action temporality permits a duration condition."""
    value = getattr(action, "temporality", None)
    try:
        temporality = ControlActionTemporality(value)
    except (TypeError, ValueError):
        return False
    return temporality in {
        ControlActionTemporality.continuous,
        ControlActionTemporality.bounded_duration,
    }


def _stage5_prompt_context(
    context: ScenarioGenerationContext,
) -> Mapping[str, object]:
    """Project authority into only the facts Stage 5 can interpret or copy."""
    return {
        "unsafe_control_action": {
            "category": context.ica.uca_type.value,
            "category_meaning": context.ica.uca_type_definition,
            "statement": context.ica.exact_ica_text,
            "hazardous_context": context.ica.hazardous_context,
            "loss_consequence": context.ica.loss_consequence,
        },
        "selected_control_path": _stage5_control_path(context),
        "unsafe_results": _stage5_unsafe_results(context),
        "taxonomy_considerations": _stage5_taxonomy_considerations(context),
        "reachable_capabilities": _stage5_reachable_capabilities(context),
    }


def _stage5_control_path(context: ScenarioGenerationContext) -> Mapping[str, object]:
    """Describe the selected owner, action, and controlled processes."""
    path = context.target_control_path
    action_view: dict[str, object] = {
        "reference": path.control_action.action_id,
        "description": path.control_action.description,
    }
    action_semantics = _control_action_semantics(path.control_action)
    if action_semantics:
        action_view.update(action_semantics)
    return {
        "owner_description": _stage5_owner_description(context),
        "target_action": action_view,
        "controlled_processes": _stage5_controlled_processes(context),
    }


def _control_action_semantics(action: object) -> dict[str, str]:
    """Expose typed target/effect facts when the input model carries them.

    The structural model used by historical runs has only a target reference.
    Newer control-structure producers may provide ``target_kind`` and
    ``effect_kind`` (or the equivalent nested target/effect values).  This
    adapter intentionally reads only those typed values and never classifies
    an action from its description.
    """
    semantics: dict[str, str] = {}
    target_kind = _typed_control_action_target_kind(action)
    effect_kind = _typed_control_action_effect(action)
    if target_kind is not None:
        semantics["target_kind"] = target_kind
    if effect_kind is not None:
        semantics["effect_kind"] = effect_kind
    return semantics


def _typed_control_action_target_kind(action: object) -> str | None:
    """Return the normalized typed target kind, if one is supplied."""
    value = _first_typed_attribute(
        action,
        "target_kind",
        "target_type",
        "target_role",
        "target_element_type",
    )
    if value is None:
        target = getattr(action, "target", None)
        value = _first_typed_attribute(target, "kind", "type", "target_kind")
    return _normalize_typed_value(value)


def _typed_control_action_effect(action: object) -> str | None:
    """Return the normalized typed effect, if one is supplied."""
    value = _first_typed_attribute(
        action,
        "effect_kind",
        "action_effect",
        "effect",
        "semantic_effect",
        "action_kind",
    )
    return _normalize_typed_value(value)


def _first_typed_attribute(value: object, *names: str) -> object | None:
    """Read the first explicitly populated attribute from a typed object."""
    if value is None:
        return None
    for name in names:
        candidate = getattr(value, name, None)
        if candidate is not None:
            return candidate
    return None


def _normalize_typed_value(value: object | None) -> str | None:
    """Normalize enum-like typed values without interpreting free text."""
    if value is None:
        return None
    nested = _first_typed_attribute(value, "kind", "value")
    if nested is not None and nested is not value:
        value = nested
    raw = getattr(value, "value", value)
    if not isinstance(raw, str):
        return None
    return raw.strip().lower().replace("-", "_").replace(" ", "_") or None


def classify_control_action_kind(action: object) -> ExecutionActionKind | None:
    """Derive the observed action kind from typed target/effect facts.

    ``None`` means that the legacy action shape does not contain enough typed
    information to classify it.  An explicitly supplied ``unknown`` effect is
    also returned as ``None``; callers can distinguish it with
    :func:`_control_action_has_unknown_effect` and retain the finding as
    analytical rather than guessing a route.
    """
    effect = _typed_control_action_effect(action)
    if effect in _ACTION_EFFECT_KINDS:
        return _ACTION_EFFECT_KINDS[effect]
    target_kind = _typed_control_action_target_kind(action)
    if target_kind in _RESPONSIBILITY_TARGET_NAMES:
        return ExecutionActionKind.agent_message
    return None


def _control_action_has_unknown_effect(action: object) -> bool:
    """Return whether an explicit but unsupported/unknown effect was supplied."""
    effect = _typed_control_action_effect(action)
    return effect is not None and effect not in _ACTION_EFFECT_KINDS


def _stage5_owner_description(context: ScenarioGenerationContext) -> str:
    """Return the one validated responsibility or coordination owner."""
    path = context.target_control_path
    if path.responsibility is not None:
        return path.responsibility.description
    if path.coordination_path is not None:
        return path.coordination_path.description
    raise ValueError("selected control path has no owner")


def _stage5_controlled_processes(context: ScenarioGenerationContext) -> list[str]:
    """Return plain controlled-process descriptions for either path shape."""
    path = context.target_control_path
    if path.coordination_path is not None:
        return [
            item.description for item in path.coordination_path.controlled_processes
        ]
    if path.controlled_process is not None:
        return [path.controlled_process.description]
    return []


def _stage5_unsafe_results(context: ScenarioGenerationContext) -> Mapping[str, object]:
    """Expose consequence descriptions; lineage IDs remain compiler-owned."""
    return {
        "losses": [item.description for item in context.losses],
        "hazards": [item.description for item in context.hazards],
        "constraints": [item.description for item in context.constraints],
    }


def _stage5_taxonomy_considerations(
    context: ScenarioGenerationContext,
) -> list[Mapping[str, object]]:
    """Keep taxonomy meaning while removing its bookkeeping identities."""
    return [
        {
            "pattern_name": item.attack_pattern_name,
            "concern": item.concise_concern,
            "review_outcome": item.disposition,
            "review_reason": item.rationale,
        }
        for item in context.obligation_considerations
    ]


def _stage5_reachable_capabilities(
    context: ScenarioGenerationContext,
) -> list[Mapping[str, object]]:
    """Expose capability references only because provider output may copy them."""
    return [
        {
            "capability_ref": item.capability_id,
            "description": item.description,
            "evidence": item.evidence,
            "access_refs": list(item.access_path),
        }
        for item in context.reachable_capabilities
    ]


def _defender_belief_choices(
    context: ScenarioGenerationContext,
) -> tuple[tuple[str, DescribedElement], ...]:
    """Bind every selected process-model belief to a request-local handle."""
    return tuple(
        (f"belief_{index}", belief)
        for index, belief in enumerate(
            context.target_control_path.process_model_parts, start=1
        )
    )


def _causal_source_choices(
    context: ScenarioGenerationContext,
) -> tuple[_CausalSourceChoice, ...]:
    """Project the selected path into request-local executable source choices."""
    path = context.target_control_path
    candidates: list[tuple[CausalFactorKind, str, str]] = []
    candidates.extend(
        (CausalFactorKind.process_model_flaw, item.element_id, item.description)
        for item in path.process_model_parts
    )
    for item in path.feedback:
        candidates.extend(
            (
                (CausalFactorKind.feedback_delay, item.element_id, item.description),
                (CausalFactorKind.sensor_anomaly, item.element_id, item.description),
            )
        )
    actions = (path.control_action, *path.related_control_actions)
    candidates.extend(
        (CausalFactorKind.actuator_anomaly, item.action_id, item.description)
        for item in actions
        if item.action_id.startswith("CA-")
    )
    unique = tuple(dict.fromkeys(candidates))
    return tuple(
        _CausalSourceChoice(
            handle=f"cause_{index}",
            kind=kind,
            source_id=source_id,
            description=description,
        )
        for index, (kind, source_id, description) in enumerate(unique, start=1)
    )


_STIMULUS_CATEGORY_DESCRIPTIONS = {
    StimulusCategory.user_message: (
        "one adversarial user message delivered as direct prompt input"
    ),
    StimulusCategory.conversation: (
        "earlier conversation turns that establish context before the target action"
    ),
    StimulusCategory.conversation_context: (
        "earlier conversation turns (compatibility spelling for conversation)"
    ),
    StimulusCategory.retrieved_content: (
        "attacker-influenced content returned by retrieval and inserted into context"
    ),
    StimulusCategory.tool_content: (
        "attacker-influenced content returned by a tool and inserted into context"
    ),
    StimulusCategory.file_upload: (
        "a file-upload event or attachment, which has no supported Stage 5 delivery primitive"
    ),
    StimulusCategory.traffic_load: (
        "a high-volume or rate-based traffic/load event, which has no supported primitive"
    ),
    StimulusCategory.unknown: "an unspecified or unsupported stimulus delivery",
}


def _stimulus_choices_yaml() -> str:
    """Render the closed provider-only stimulus vocabulary."""
    return yaml.dump(
        [
            {
                "category": category.value,
                "description": description,
                "supported_delivery": _stimulus_delivery(category),
            }
            for category, description in _STIMULUS_CATEGORY_DESCRIPTIONS.items()
        ],
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
    )


def _stimulus_delivery(category: StimulusCategory) -> str | None:
    """Return the sole supported delivery primitive for a stimulus category."""
    return {
        StimulusCategory.user_message: ExecutionDeliveryClass.direct_prompt.value,
        StimulusCategory.conversation: ExecutionDeliveryClass.conversation_context.value,
        StimulusCategory.conversation_context: ExecutionDeliveryClass.conversation_context.value,
        StimulusCategory.retrieved_content: ExecutionDeliveryClass.indirect_content.value,
        StimulusCategory.tool_content: ExecutionDeliveryClass.indirect_content.value,
    }.get(category)


def _temporal_reference_choices_yaml(
    context: ScenarioGenerationContext,
    choices: Sequence[_CausalSourceChoice],
) -> str:
    """Explain local temporal handles without exposing hidden identities."""
    references = [
        {
            "reference_handle": "target_action",
            "meaning": "the selected unsafe control action",
            "allowed_for": "reference_handle and until_step_handle",
        }
    ]
    references.extend(
        {
            "reference_handle": choice.handle,
            "meaning": (
                f"the selected {_source_type_explanation(choice.kind)} source "
                f"({choice.description})"
            ),
            "allowed_for": "reference_handle and until_step_handle",
        }
        for choice in choices
    )
    return yaml.dump(
        {
            "choices": references,
            "resolution": (
                "Deterministic compilation resolves these handles to exact structural "
                "or projected step references; do not emit structural IDs here."
            ),
        },
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
    )


def _source_type_explanation(kind: CausalFactorKind) -> str:
    """Describe a source category without exposing its structural identity."""
    return {
        CausalFactorKind.process_model_flaw: "a process-model belief or state",
        CausalFactorKind.feedback_delay: "a feedback update or timing condition",
        CausalFactorKind.sensor_anomaly: "a feedback observation anomaly",
        CausalFactorKind.actuator_anomaly: "a control-action execution condition",
    }[kind]


def _source_selection_guidance(kind: CausalFactorKind) -> str:
    """Explain when a structurally valid causal category is meaningful."""
    return {
        CausalFactorKind.process_model_flaw: (
            "Select only for an incorrect, missing, or stale controller belief/state."
        ),
        CausalFactorKind.feedback_delay: (
            "Select only when timing, lateness, staleness, or missing feedback is "
            "part of the causal explanation."
        ),
        CausalFactorKind.sensor_anomaly: (
            "Select only when the observed feedback value is incorrect, corrupted, "
            "or misleading; do not use it merely for delay."
        ),
        CausalFactorKind.actuator_anomaly: (
            "Select only for failure or distortion while executing the selected "
            "control action."
        ),
    }[kind]


def _validate_execution_route(
    route: ExecutionRouteSelectionValue | _ContextExecutableRouteDraft,
    factor_drafts: Sequence[BaseModel],
    context: ScenarioGenerationContext,
    unsafe_outcome: _ContextUnsafeOutcomeDraft | UnsafeOutcomeDeclaration,
    *,
    stimulus: _ContextStimulusDraft | None = None,
) -> None:
    """Validate provider route choices against one exact request context."""
    declared_handles = _declared_causal_handles(factor_drafts)
    if isinstance(route, AnalyticalOnlyRouteSelection):
        _validate_analytical_route_gaps(route, declared_handles)
        return
    _validate_selected_factor_handle(route, declared_handles)
    _validate_action_kind_against_control_action(route, context)
    _validate_delivery_factor_fidelity(route, context)
    _validate_model_output_outcome(route, unsafe_outcome)
    if stimulus is not None:
        _validate_stimulus_route(route, stimulus)
    # Role handles and carrier influence are deliberately absent from the
    # normal provider route.  Keep the old checks only for direct callers that
    # explicitly construct the public compatibility model.
    if isinstance(route, ExecutableRouteSelection):
        role_handles = set(route.resource_role_handles)
        _validate_route_role_names(role_handles)
        _validate_route_state_role(role_handles, unsafe_outcome)
        _validate_route_required_roles(route, role_handles, context, unsafe_outcome)


_DELIVERY_FACTOR_KINDS = {
    ExecutionDeliveryClass.direct_prompt: frozenset(
        {CausalFactorKind.process_model_flaw}
    ),
    ExecutionDeliveryClass.conversation_context: frozenset(
        {
            CausalFactorKind.process_model_flaw,
            CausalFactorKind.feedback_delay,
        }
    ),
    ExecutionDeliveryClass.indirect_content: frozenset(
        {
            CausalFactorKind.process_model_flaw,
            CausalFactorKind.sensor_anomaly,
        }
    ),
}


def _compatible_delivery_classes(
    kind: CausalFactorKind,
) -> tuple[ExecutionDeliveryClass, ...]:
    """Return delivery classes accepted for one typed causal-factor kind."""
    return tuple(
        delivery
        for delivery in ExecutionDeliveryClass
        if kind in _DELIVERY_FACTOR_KINDS[delivery]
    )


def _validate_delivery_factor_fidelity(
    route: ExecutableRouteSelection | _ContextExecutableRouteDraft,
    context: ScenarioGenerationContext,
) -> None:
    """Require the chosen stimulus route to exercise its selected factor."""
    kinds = {choice.handle: choice.kind for choice in _causal_source_choices(context)}
    selected_kind = kinds.get(route.selected_factor_handle)
    if selected_kind in _DELIVERY_FACTOR_KINDS[route.delivery_class]:
        return
    allowed = ", ".join(
        item.value
        for item in sorted(
            _DELIVERY_FACTOR_KINDS[route.delivery_class], key=lambda item: item.value
        )
    )
    actual = selected_kind.value if selected_kind is not None else "unknown"
    raise ValueError(
        f"{route.delivery_class.value} cannot exercise selected factor kind "
        f"{actual}; choose one of [{allowed}] or an analytical route"
    )


def _validate_model_output_outcome(
    route: ExecutableRouteSelection | _ContextExecutableRouteDraft,
    unsafe_outcome: _ContextUnsafeOutcomeDraft | UnsafeOutcomeDeclaration,
) -> None:
    """Keep model-output judgments semantic instead of deployment-string bound."""
    condition = unsafe_outcome.condition
    if route.action_kind is not ExecutionActionKind.model_output:
        return
    proposition = getattr(unsafe_outcome, "semantic_proposition", None)
    normalize_semantic_proposition(proposition, required=True)
    if getattr(condition, "type", None) != "action_value":
        return
    if not (
        getattr(condition, "property", None) == "semantic_proposition"
        and getattr(condition, "operator", None) == "equals"
        and type(getattr(condition, "expected", None)) is bool
        and getattr(condition, "expected", None) is True
    ):
        raise ValueError(
            "model_output action_value must use the fixed semantic proposition "
            "condition (property=semantic_proposition, operator=equals, expected=true)"
        )


def _declared_causal_handles(factor_drafts: Sequence[BaseModel]) -> set[str]:
    """Return the unique request-local handles declared by provider factors."""
    handles = {item.source_handle for item in factor_drafts}
    if len(handles) != len(factor_drafts):
        raise ValueError("causal factor source handles must be unique")
    return handles


def _validate_analytical_route_gaps(
    route: AnalyticalOnlyRouteSelection,
    declared_handles: set[str],
) -> None:
    """Require analytical gap evidence to refer to declared local factors."""
    for gap in route.gaps:
        if not set(gap.evidence_handles) <= declared_handles:
            raise ValueError(
                "analytical gap evidence handles must name declared causal factors"
            )


def _validate_selected_factor_handle(
    route: ExecutableRouteSelection | _ContextExecutableRouteDraft,
    declared_handles: set[str],
) -> None:
    """Require an executable route to select one declared local factor."""
    if route.selected_factor_handle not in declared_handles:
        raise ValueError(
            "execution route selected_factor_handle must name a declared causal factor"
        )


def _validate_action_kind_against_control_action(
    route: ExecutableRouteSelection | _ContextExecutableRouteDraft,
    context: ScenarioGenerationContext,
) -> None:
    """Validate the provider's action choice against typed action semantics.

    The route schema performs cross-field checks (for example, whether a
    target-action role accompanies ``tool_call``).  That is not enough: an
    action can be internally coherent while observing the wrong effect.  When
    the selected control action carries typed effect/target facts, those facts
    are authoritative.  Legacy contexts without them retain their historical
    compatibility behavior.
    """
    action = context.target_control_path.control_action
    if _control_action_has_unknown_effect(action):
        raise ValueError(
            "control action has an unknown typed effect; use an analytical route"
        )
    expected = classify_control_action_kind(action)
    if expected is None:
        return
    if route.action_kind is not expected:
        raise ValueError(
            "execution route action_kind does not match the selected control "
            f"action's typed effect/target ({expected.value})"
        )


def _validate_route_role_names(role_handles: set[str]) -> None:
    """Reject role handles that were not offered by the deterministic prompt."""
    valid_roles = {choice.handle for choice in _EXECUTION_ROLE_CHOICES}
    if not role_handles <= valid_roles:
        raise ValueError("execution route contains an unknown resource role handle")


def _validate_route_state_role(
    role_handles: set[str],
    unsafe_outcome: _ContextUnsafeOutcomeDraft | UnsafeOutcomeDeclaration,
) -> None:
    """Allow a state role only for state-valued unsafe outcomes."""
    if "role_state" in role_handles and not isinstance(
        unsafe_outcome.condition, StateValueCondition
    ):
        raise ValueError(
            "role_state is only valid when the state identity or behavior is part "
            "of the unsafe outcome"
        )


def _validate_route_required_roles(
    route: ExecutableRouteSelection | _ContextExecutableRouteDraft,
    role_handles: set[str],
    context: ScenarioGenerationContext,
    unsafe_outcome: _ContextUnsafeOutcomeDraft | UnsafeOutcomeDeclaration,
) -> None:
    """Require exactly the semantic roles needed by route and outcome."""
    expected_roles = _required_execution_role_handles(route, context, unsafe_outcome)
    optional_roles = (
        {"role_state"}
        if isinstance(unsafe_outcome.condition, StateValueCondition)
        else set()
    )
    if role_handles - optional_roles == expected_roles:
        return
    expected = ", ".join(sorted(expected_roles | optional_roles)) or "none"
    actual = ", ".join(sorted(role_handles)) or "none"
    raise ValueError(
        "execution route resource role handles must be exactly "
        f"the required roles [{expected}], received [{actual}]"
    )


def _required_execution_role_handles(
    route: ExecutableRouteSelection | _ContextExecutableRouteDraft,
    context: ScenarioGenerationContext,
    unsafe_outcome: _ContextUnsafeOutcomeDraft | UnsafeOutcomeDeclaration,
) -> set[str]:
    """Return the role handles required by the chosen action and outcome."""
    roles: set[str] = set()
    if route.delivery_class is ExecutionDeliveryClass.indirect_content:
        roles.add("role_stimulus_carrier")
    # Conversation context is a standard runtime surface, not a domain
    # resource.  It therefore contributes no semantic resource requirement.

    if route.action_kind in {
        ExecutionActionKind.tool_call,
        ExecutionActionKind.state_change,
        ExecutionActionKind.environment_action,
    }:
        roles.add("role_target_action")
    if route.action_kind is ExecutionActionKind.agent_message:
        roles.add("role_agent_channel")
    if isinstance(unsafe_outcome.condition, StateValueCondition):
        roles.add("role_state")
    return roles


def _factor_ids_by_handle(factor_drafts: Sequence[BaseModel]) -> dict[str, str]:
    """Assign canonical CF identities in provider declaration order."""
    return {
        item.source_handle: f"CF-{index}"
        for index, item in enumerate(factor_drafts, start=1)
    }


def _materialize_execution_contract(
    route: ExecutionRouteSelectionValue | _ContextExecutableRouteDraft,
    factor_drafts: Sequence[BaseModel],
    choices: dict[str, _CausalSourceChoice],
    unsafe_outcome: UnsafeOutcomeDeclaration,
    context: ScenarioGenerationContext,
    requested_environment_basis: RequestedEnvironmentBasis | None,
    *,
    stimulus: _ContextStimulusDraft | None = None,
) -> SemanticExecutionContract:
    """Resolve provider-local route handles into the semantic contract."""
    factor_ids = _factor_ids_by_handle(factor_drafts)
    if isinstance(route, AnalyticalOnlyRouteSelection):
        gaps = tuple(
            SemanticExecutionGap(
                code=gap.code,
                detail=gap.detail,
                evidence_refs=tuple(factor_ids[item] for item in gap.evidence_handles),
            )
            for gap in route.gaps
        )
        return SemanticExecutionContract(
            disposition=ExecutionContractDisposition.analytical_only,
            gaps=gaps,
        )

    _validate_execution_route(route, factor_drafts, context, unsafe_outcome)
    selected_factor_id = factor_ids[route.selected_factor_handle]
    selected_source_id = choices[route.selected_factor_handle].source_id
    requirements = _materialize_execution_requirements(
        route,
        selected_factor_id,
        selected_source_id,
        unsafe_outcome,
        context,
        stimulus=stimulus,
    )
    basis = resolve_contract_environment_request(
        requirements, requested_environment_basis
    )
    return SemanticExecutionContract(
        requested_environment_basis=basis,
        delivery=SemanticExecutionDelivery(
            delivery_class=route.delivery_class,
            factor_id=selected_factor_id,
            source_role=_source_role_for_delivery(route.delivery_class),
            carrier_requirement_id=(
                "REQ-carrier"
                if route.delivery_class is ExecutionDeliveryClass.indirect_content
                else None
            ),
        ),
        action_kind=route.action_kind,
        resource_requirements=requirements,
    )


def _source_role_for_delivery(delivery_class: ExecutionDeliveryClass) -> str:
    """Return the canonical semantic source role for a delivery class."""
    return {
        ExecutionDeliveryClass.direct_prompt: "direct_user_input",
        ExecutionDeliveryClass.indirect_content: "attacker_influenced_content",
        ExecutionDeliveryClass.conversation_context: "conversation_context",
    }[delivery_class]


def _materialize_execution_requirements(
    route: ExecutableRouteSelection | _ContextExecutableRouteDraft,
    selected_factor_id: str,
    selected_source_id: str,
    unsafe_outcome: UnsafeOutcomeDeclaration,
    context: ScenarioGenerationContext,
    *,
    stimulus: _ContextStimulusDraft | None = None,
) -> tuple[ExecutionResourceRequirement, ...]:
    """Build semantic requirements from typed route/action/outcome values."""
    requirements: list[ExecutionResourceRequirement] = []
    handles, carrier_influence = _execution_requirement_inputs(
        route, context, unsafe_outcome, stimulus
    )
    if "role_stimulus_carrier" in handles:
        requirements.append(
            ExecutionResourceRequirement(
                requirement_id="REQ-carrier",
                purpose=ExecutionResourcePurpose.stimulus_carrier,
                factor_id=selected_factor_id,
                owner_ref=selected_source_id,
                acceptable_resource_kinds=(
                    ExecutionResourceKind.integration,
                    ExecutionResourceKind.tool,
                ),
                role_id="attacker_influenced_content_source",
                operation="retrieve_content",
                required_surfaces=(ExecutionSurface.tool_result,),
                required_properties=("content_reaches_model_context",),
                required_attacker_influence=carrier_influence,
                late_bindable=True,
                evidence_refs=(selected_factor_id,),
            )
        )
    if "role_target_action" in handles:
        action_id = context.target_control_path.control_action.action_id
        requirements.append(
            ExecutionResourceRequirement(
                requirement_id="REQ-target-action",
                purpose=ExecutionResourcePurpose.target_action,
                owner_ref=action_id,
                acceptable_resource_kinds=(
                    ExecutionResourceKind.integration,
                    ExecutionResourceKind.tool,
                ),
                role_id="target_control_action",
                operation=action_id,
                required_surfaces=(ExecutionSurface.tool_call,),
                required_properties=(),
                required_attacker_influence="none",
                late_bindable=True,
                evidence_refs=(action_id,),
            )
        )
    if "role_state" in handles:
        subject_ref = getattr(unsafe_outcome.condition, "subject_ref", None)
        requirements.append(
            ExecutionResourceRequirement(
                requirement_id="REQ-state",
                purpose=ExecutionResourcePurpose.state_resource,
                owner_ref=subject_ref
                or context.target_control_path.control_action.action_id,
                acceptable_resource_kinds=(ExecutionResourceKind.state_store,),
                role_id="unsafe_state",
                operation="read_unsafe_state",
                required_surfaces=(ExecutionSurface.state_observation,),
                required_properties=("unsafe_state_observable",),
                required_attacker_influence="none",
                late_bindable=True,
                evidence_refs=(selected_factor_id,),
            )
        )
    if "role_agent_channel" in handles:
        requirements.append(
            ExecutionResourceRequirement(
                requirement_id="REQ-agent-channel",
                purpose=ExecutionResourcePurpose.agent_channel,
                owner_ref=_agent_channel_owner_ref(context),
                acceptable_resource_kinds=(ExecutionResourceKind.agent_channel,),
                role_id="agent_message",
                operation="deliver_agent_message",
                required_surfaces=(ExecutionSurface.agent_message,),
                required_properties=("agent_message_observable",),
                required_attacker_influence="direct",
                late_bindable=True,
                evidence_refs=(selected_factor_id,),
            )
        )
    return tuple(requirements)


def _execution_requirement_inputs(
    route: ExecutableRouteSelection | _ContextExecutableRouteDraft,
    context: ScenarioGenerationContext,
    unsafe_outcome: UnsafeOutcomeDeclaration,
    stimulus: _ContextStimulusDraft | None,
) -> tuple[set[str], AttackerInfluence]:
    """Select compatibility roles or derive roles from typed provider fields."""
    if isinstance(route, ExecutableRouteSelection):
        # Compatibility callers may still supply the old public route model;
        # contextual provider responses use only the derived branch below.
        return set(route.resource_role_handles), route.carrier_attacker_influence
    return (
        _required_execution_role_handles(route, context, unsafe_outcome),
        _stimulus_attacker_influence(stimulus),
    )


def _stimulus_attacker_influence(
    stimulus: _ContextStimulusDraft | None,
) -> AttackerInfluence:
    """Derive carrier influence from the typed stimulus category only."""
    if stimulus is None:
        return AttackerInfluence.unknown
    if stimulus.category in {
        StimulusCategory.retrieved_content,
        StimulusCategory.tool_content,
    }:
        return AttackerInfluence.indirect
    return AttackerInfluence.unknown


def _agent_channel_owner_ref(context: ScenarioGenerationContext) -> str:
    """Resolve the exact responsibility target for an agent-message action."""
    action = context.target_control_path.control_action
    target_kind = _typed_control_action_target_kind(action)
    target = getattr(action, "target", None)
    target_id = _first_typed_attribute(action, "target_id", "target_ref")
    if target_id is None:
        target_id = _first_typed_attribute(target, "id", "element_id")
    if target_kind in _RESPONSIBILITY_TARGET_NAMES and isinstance(target_id, str):
        return target_id
    return context.target_control_path.controller.element_id


@lru_cache(maxsize=64)
def _context_bdi_provider_wire_types(
    choice_count: int,
    belief_count: int,
    expected_action_kind: ExecutionActionKind | None = None,
    *,
    target_action_id: str | None = None,
    uca_type: UCAType | None = None,
    state_subject_refs: tuple[str, ...] = (),
    temporal_reference_handles: tuple[str, ...] = (),
    condition_reference_refs: tuple[str, ...] = (),
    condition_step_refs: tuple[str, ...] = (),
    duration_eligible: bool = False,
) -> dict[str, type[BaseModel]]:
    """Build the strict provider wire types for one exact request.

    The public/inward models intentionally retain compatibility defaults.  A
    contextual provider response instead uses this request-specific factory so
    every discriminator is required and each conditional branch contains only
    its meaningful fields.
    """
    _require_positive_schema_count(choice_count, "choice_count")
    _require_positive_schema_count(belief_count, "belief_count")
    handles = tuple(f"cause_{index}" for index in range(1, choice_count + 1))
    handle_type = Literal.__getitem__(handles)
    temporal_handles = temporal_reference_handles or ("target_action", *handles)
    temporal_handle_type = Literal.__getitem__(tuple(temporal_handles))

    temporal_types = _context_temporal_wire_types(
        choice_count,
        temporal_handle_type,
        temporal_handles,
        duration_eligible=duration_eligible,
    )
    temporal_union = _discriminated_union(tuple(temporal_types.values()), "type")
    factor_types = _context_causal_factor_wire_types(
        choice_count,
        handle_type,
        temporal_union,
    )
    factor_union = _discriminated_union(tuple(factor_types.values()), "evidence_status")

    source_handle_list = conlist(handle_type, min_length=1)
    intention_type = create_model(
        f"_ContextAttackerIntentionDraft{choice_count}",
        __base__=_ContextAttackerIntentionDraft,
        source_handles=(source_handle_list, ...),
    )
    attacker_type = create_model(
        f"_ContextAttackerBDIDraft{choice_count}",
        __base__=_ContextAttackerBDIDraft,
        intentions=(list[intention_type], ...),
    )
    factor_list = conlist(factor_union, min_length=1)
    belief_handles = tuple(f"belief_{index}" for index in range(1, belief_count + 1))
    belief_handle_type = Literal.__getitem__(belief_handles)
    vulnerability_type = create_model(
        f"_ContextDefenderVulnerabilityDraft{belief_count}",
        __base__=_ContextDefenderVulnerabilityDraft,
        belief_handle=(belief_handle_type, ...),
    )
    vulnerability_list = conlist(
        vulnerability_type,
        min_length=belief_count,
        max_length=belief_count,
    )
    unsafe_condition_types = _context_unsafe_condition_wire_types(
        choice_count,
        uca_type=uca_type,
        expected_action_kind=expected_action_kind,
        target_action_id=target_action_id,
        state_subject_refs=state_subject_refs,
        condition_reference_refs=condition_reference_refs,
        condition_step_refs=condition_step_refs,
        duration_eligible=duration_eligible,
    )
    if not unsafe_condition_types:
        raise ValueError(
            "selected UCA has no provider unsafe-condition branch supported by the request"
        )
    unsafe_condition_union = _discriminated_union(
        tuple(unsafe_condition_types.values()), "type"
    )
    unsafe_outcome_type = create_model(
        f"_ContextUnsafeOutcomeDraft{choice_count}",
        __base__=_ContextUnsafeOutcomeDraft,
        condition=(unsafe_condition_union, ...),
        semantic_proposition=(StrictStr | None, Field(max_length=600)),
    )
    route_type, executable_route_type, analytical_route_type = (
        _context_route_wire_types(
            choice_count,
            handle_type,
            expected_action_kind,
        )
    )
    payload_type = create_model(
        f"_ContextBDIProviderPayload{choice_count}x{belief_count}",
        __base__=_ContextBDIProviderPayload,
        stimulus=(_ContextStimulusDraft, ...),
        defender_vulnerabilities=(vulnerability_list, ...),
        attacker_bdi=(attacker_type, ...),
        causal_factors=(factor_list, ...),
        unsafe_outcome=(unsafe_outcome_type, ...),
        execution_route=(route_type, ...),
    )
    return {
        "payload": payload_type,
        "temporal": create_model(
            f"_ContextTemporalConditionDraft{choice_count}",
            __base__=_ContextTemporalConditionWire,
            # A discriminated union is represented by its annotation below;
            # this marker is returned for prompt/schema fixture helpers only.
        ),
        **factor_types,
        **temporal_types,
        **unsafe_condition_types,
        "unsafe_outcome": unsafe_outcome_type,
        "executable_route": executable_route_type,
        "analytical_route": analytical_route_type,
    }


def _context_route_wire_types(
    choice_count: int,
    handle_type: object,
    expected_action_kind: ExecutionActionKind | None,
) -> tuple[object, type[BaseModel], type[BaseModel]]:
    """Build the closed provider route union for one request."""
    route_fields: dict[str, tuple[object, object]] = {
        # This is intentionally repeated on the dynamic subtype.  The inward
        # route keeps a default for compatibility; provider output may not.
        "disposition": (Literal["executable_route"], ...),
        "selected_factor_handle": (handle_type, ...),
    }
    if expected_action_kind is not None:
        exact_action_kind = Literal.__getitem__((expected_action_kind,))
        route_fields["action_kind"] = (exact_action_kind, ...)
    executable_route_type = create_model(
        f"_ExecutableRouteSelection{choice_count}",
        __base__=_ContextExecutableRouteDraft,
        **route_fields,
    )
    analytical_route_type = create_model(
        f"_AnalyticalOnlyRouteSelection{choice_count}",
        __base__=AnalyticalOnlyRouteSelection,
        disposition=(Literal["analytical_only"], ...),
    )
    return (
        _discriminated_union(
            (executable_route_type, analytical_route_type), "disposition"
        ),
        executable_route_type,
        analytical_route_type,
    )


@lru_cache(maxsize=64)
def _context_bdi_provider_payload_type(
    choice_count: int,
    belief_count: int,
    expected_action_kind: ExecutionActionKind | None = None,
    *,
    target_action_id: str | None = None,
    uca_type: UCAType | None = None,
    state_subject_refs: tuple[str, ...] = (),
    temporal_reference_handles: tuple[str, ...] = (),
    condition_reference_refs: tuple[str, ...] = (),
    condition_step_refs: tuple[str, ...] = (),
    duration_eligible: bool = False,
) -> type[BaseModel]:
    """Return one strict response schema over request-local provider handles."""
    return _context_bdi_provider_wire_types(
        choice_count,
        belief_count,
        expected_action_kind,
        target_action_id=target_action_id,
        uca_type=uca_type,
        state_subject_refs=state_subject_refs,
        temporal_reference_handles=temporal_reference_handles,
        condition_reference_refs=condition_reference_refs,
        condition_step_refs=condition_step_refs,
        duration_eligible=duration_eligible,
    )["payload"]


def _discriminated_union(
    models: tuple[type[BaseModel], ...], discriminator: str
) -> object:
    """Return an annotated union with a required discriminator."""
    return Annotated[Union.__getitem__(models), Field(discriminator=discriminator)]


def _context_temporal_wire_types(
    choice_count: int,
    handle_type: object,
    handles: tuple[str, ...],
    *,
    duration_eligible: bool,
) -> dict[str, type[BaseModel]]:
    """Create exact request-local temporal branches for causal factors."""
    branch_specs: list[
        tuple[str, type[BaseModel], dict[str, tuple[object, object]]]
    ] = [
        (
            "ordering",
            _ContextOrderingTemporalWire,
            {
                "reference_handle": (handle_type, ...),
            },
        ),
        (
            "delay",
            _ContextDelayTemporalWire,
            {
                "reference_handle": (handle_type, ...),
            },
        ),
        (
            "window",
            _ContextWindowTemporalWire,
            {
                "reference_handle": (handle_type, ...),
            },
        ),
        (
            "absence",
            _ContextAbsenceTemporalWire,
            {
                "reference_handle": (handle_type, ...),
                "until_step_handle": (handle_type, ...),
            },
        ),
    ]
    if duration_eligible:
        branch_specs.insert(
            2,
            (
                "duration",
                _ContextDurationTemporalWire,
                {
                    "reference_handle": (handle_type, ...),
                },
            ),
        )
    result: dict[str, type[BaseModel]] = {}
    for branch, base, fields in branch_specs:
        fields = {
            "type": (Literal.__getitem__((branch,)), ...),
            **fields,
        }
        result[branch] = create_model(
            f"_ContextTemporal{branch.title().replace('_', '')}Draft{choice_count}",
            __base__=base,
            **fields,
        )
    return result


def _context_causal_factor_wire_types(
    choice_count: int,
    handle_type: object,
    temporal_union: object,
) -> dict[str, type[BaseModel]]:
    """Create evidence-status branches with status-specific requirements."""
    nonempty_refs = conlist(StrictStr, min_length=1)
    common = {
        "source_handle": (handle_type, ...),
        "temporal_condition": (temporal_union | None, ...),
    }
    return {
        "structural_failure": create_model(
            f"_ContextCausalFactorDraft{choice_count}",
            __base__=_ContextCausalFactorWireBase,
            **common,
            evidence_status=(Literal["structural_failure"], ...),
        ),
        "reachable_capability": create_model(
            f"_ContextReachableCausalFactorDraft{choice_count}",
            __base__=_ContextCausalFactorWireBase,
            **common,
            evidence_status=(Literal["reachable_capability"], ...),
            capability_refs=(nonempty_refs, ...),
            access_refs=(nonempty_refs, ...),
        ),
        "bounded_assumption": create_model(
            f"_ContextBoundedCausalFactorDraft{choice_count}",
            __base__=_ContextCausalFactorWireBase,
            **common,
            evidence_status=(Literal["bounded_assumption"], ...),
            bounded_assumption=(StrictStr, Field(min_length=1)),
        ),
    }


def _context_unsafe_condition_branch_names(
    uca_type: UCAType | None,
    *,
    expected_action_kind: ExecutionActionKind | None,
    state_subject_refs: tuple[str, ...],
    duration_eligible: bool,
    allowed_branches: tuple[str, ...],
) -> tuple[str, ...]:
    """Select condition families permitted by the request authority."""
    by_uca = {
        UCAType.not_provided: ("action_presence",),
        UCAType.incorrect: ("action_value", "state_value"),
        UCAType.wrong_timing: ("ordering", "delay", "window", "absence"),
        UCAType.wrong_duration: ("duration",),
    }
    branches = list(by_uca.get(uca_type, allowed_branches))
    if (
        uca_type is UCAType.incorrect
        and expected_action_kind is ExecutionActionKind.model_output
    ):
        branches = ["action_value"]
    if uca_type is UCAType.incorrect and not state_subject_refs:
        branches = [item for item in branches if item != "state_value"]
    if uca_type is UCAType.wrong_duration and not duration_eligible:
        branches = []
    if not branches:
        raise ValueError(
            "selected UCA has no supported provider unsafe-condition branch"
        )
    return tuple(branches)


def _context_unsafe_condition_branch_is_available(
    branch: str,
    *,
    condition_reference_refs: tuple[str, ...],
    condition_step_refs: tuple[str, ...],
) -> bool:
    """Check whether a branch has the references needed to be request-valid."""
    if branch == "ordering":
        return bool(condition_step_refs)
    if branch in {"delay", "duration", "window", "absence"}:
        return bool(condition_reference_refs)
    return True


def _context_unsafe_condition_branch_fields(
    branch: str,
    *,
    expected_action_kind: ExecutionActionKind | None,
    target_action_id: str | None,
    state_subject_refs: tuple[str, ...],
    condition_reference_refs: tuple[str, ...],
    condition_step_refs: tuple[str, ...],
) -> dict[str, tuple[object, object]]:
    """Build exact request-local fields for one unsafe condition branch."""
    fields: dict[str, tuple[object, object]] = {
        "type": (Literal.__getitem__((branch,)), ...),
    }
    if branch in {"action_presence", "action_value"}:
        fields["control_action_id"] = (
            Literal.__getitem__((target_action_id,)) if target_action_id else StrictStr,
            ...,
        )
    if (
        branch == "action_value"
        and expected_action_kind is ExecutionActionKind.model_output
    ):
        fields["property"] = (Literal["semantic_proposition"], ...)
        fields["operator"] = (Literal["equals"], ...)
        fields["expected"] = (Literal[True], ...)
    if branch == "state_value" and state_subject_refs:
        fields["subject_ref"] = (
            Literal.__getitem__(state_subject_refs),
            ...,
        )
    if (
        branch in {"delay", "duration", "window", "absence"}
        and condition_reference_refs
    ):
        fields["reference_ref"] = (
            Literal.__getitem__(condition_reference_refs),
            ...,
        )
    if branch == "ordering" and condition_step_refs:
        fields["reference_step_id"] = (
            Literal.__getitem__(condition_step_refs),
            ...,
        )
    return fields


def _context_unsafe_condition_wire_types(
    choice_count: int,
    *,
    uca_type: UCAType | None,
    expected_action_kind: ExecutionActionKind | None = None,
    target_action_id: str | None,
    state_subject_refs: tuple[str, ...],
    condition_reference_refs: tuple[str, ...],
    condition_step_refs: tuple[str, ...],
    duration_eligible: bool,
) -> dict[str, type[BaseModel]]:
    """Create only condition families permitted by this request's authority."""
    allowed: dict[str, type[BaseModel]] = {
        "action_presence": _ContextActionPresenceConditionWire,
        "action_value": _ContextActionValueConditionWire,
        "state_value": _ContextStateValueConditionWire,
        "ordering": _ContextOrderingConditionWire,
        "delay": _ContextDelayConditionWire,
        "duration": _ContextDurationConditionWire,
        "window": _ContextWindowConditionWire,
        "absence": _ContextAbsenceConditionWire,
    }
    branches = _context_unsafe_condition_branch_names(
        uca_type,
        expected_action_kind=expected_action_kind,
        state_subject_refs=state_subject_refs,
        duration_eligible=duration_eligible,
        allowed_branches=tuple(allowed),
    )
    result: dict[str, type[BaseModel]] = {}
    for branch in branches:
        if not _context_unsafe_condition_branch_is_available(
            branch,
            condition_reference_refs=condition_reference_refs,
            condition_step_refs=condition_step_refs,
        ):
            continue
        base = allowed[branch]
        fields = _context_unsafe_condition_branch_fields(
            branch,
            expected_action_kind=expected_action_kind,
            target_action_id=target_action_id,
            state_subject_refs=state_subject_refs,
            condition_reference_refs=condition_reference_refs,
            condition_step_refs=condition_step_refs,
        )
        result[branch] = create_model(
            f"_ContextUnsafe{branch.title().replace('_', '')}Condition{choice_count}",
            __base__=base,
            **fields,
        )
    return result


def _require_positive_schema_count(value: int, name: str) -> None:
    """Reject booleans and non-positive dynamic-schema counts."""
    if type(value) is not int or value <= 0:
        raise ValueError(f"{name} must be a positive integer")


def _materialize_context_bdi(
    draft: BaseModel,
    choices: tuple[_CausalSourceChoice, ...],
    belief_choices: tuple[tuple[str, DescribedElement], ...],
    context: ScenarioGenerationContext,
    requested_environment_basis: RequestedEnvironmentBasis | None,
) -> BDIGenerationResult:
    """Resolve provider-local handles to exact context-owned structural IDs."""
    choices_by_handle = {choice.handle: choice for choice in choices}
    attacker_bdi = _materialize_context_attacker_bdi(draft, choices_by_handle)
    factors = _materialize_context_factors(draft, choices, choices_by_handle, context)
    unsafe_outcome = _materialize_context_unsafe_outcome(draft, context)
    execution_contract = _materialize_execution_contract(
        draft.execution_route,
        draft.causal_factors,
        choices_by_handle,
        unsafe_outcome,
        context,
        requested_environment_basis,
        stimulus=draft.stimulus,
    )
    return BDIGenerationResult(
        defender_vulnerabilities=_materialize_context_vulnerabilities(
            draft, belief_choices
        ),
        attacker_bdi=attacker_bdi,
        causal_factors=factors,
        unsafe_outcome=unsafe_outcome,
        execution_contract=execution_contract,
    )


def _materialize_context_attacker_bdi(
    draft: BaseModel,
    choices_by_handle: Mapping[str, _CausalSourceChoice],
) -> AttackerBDI:
    """Compile provider attacker prose and local intention handles."""
    attacker_draft = draft.attacker_bdi
    _validate_intention_factor_handles(attacker_draft, draft.causal_factors)
    return AttackerBDI(
        beliefs=list(attacker_draft.beliefs),
        desires=list(attacker_draft.desires),
        intentions=[
            _materialize_intention(item, choices_by_handle)
            for item in attacker_draft.intentions
        ],
    )


def _materialize_context_factors(
    draft: BaseModel,
    choices: tuple[_CausalSourceChoice, ...],
    choices_by_handle: Mapping[str, _CausalSourceChoice],
    context: ScenarioGenerationContext,
) -> list[CausalFactorDeclaration]:
    """Compile causal factors and close their temporal references."""
    factor_order = {
        factor.source_handle: index
        for index, factor in enumerate(draft.causal_factors, start=1)
    }
    return [
        _materialize_causal_factor(
            item,
            choices_by_handle,
            temporal_condition=_resolve_temporal_condition(
                item.temporal_condition,
                item.source_handle,
                choices,
                context,
                factor_order=factor_order,
            ),
        )
        for item in draft.causal_factors
    ]


def _materialize_context_unsafe_outcome(
    draft: BaseModel,
    context: ScenarioGenerationContext,
) -> UnsafeOutcomeDeclaration:
    """Compile the provider semantic outcome and derive binding state."""
    return UnsafeOutcomeDeclaration(
        condition=_materialize_provider_condition(draft.unsafe_outcome.condition),
        semantic_proposition=draft.unsafe_outcome.semantic_proposition,
        hazard_refs=tuple(item.hazard_id for item in context.hazards),
        constraint_refs=tuple(item.constraint_id for item in context.constraints),
    )


def _materialize_provider_condition(value: object) -> SemanticCondition:
    """Convert a strict provider-wire condition into the inward value model."""
    if isinstance(
        value,
        (
            OrderingCondition,
            DelayCondition,
            DurationCondition,
            WindowCondition,
            AbsenceCondition,
            ActionValueCondition,
            StateValueCondition,
            ActionPresenceCondition,
        ),
    ):
        return value
    if not isinstance(value, BaseModel):
        raise TypeError("unsafe_outcome condition must be a provider-wire model")
    models = {
        "ordering": OrderingCondition,
        "delay": DelayCondition,
        "duration": DurationCondition,
        "window": WindowCondition,
        "absence": AbsenceCondition,
        "action_presence": ActionPresenceCondition,
        "action_value": ActionValueCondition,
        "state_value": StateValueCondition,
    }
    condition_type = getattr(value, "type", None)
    model = models.get(condition_type)
    if model is None:
        raise ValueError(
            f"unsupported provider unsafe condition type: {condition_type}"
        )
    return model.model_validate(value.model_dump(mode="json"))


def _materialize_context_vulnerabilities(
    draft: BaseModel,
    belief_choices: tuple[tuple[str, DescribedElement], ...],
) -> dict[str, str]:
    """Bind provider vulnerability prose to deterministic belief IDs."""
    belief_ids = {handle: belief.element_id for handle, belief in belief_choices}
    return {
        belief_ids[item.belief_handle]: item.vulnerability.strip()
        for item in draft.defender_vulnerabilities
    }


def _validate_intention_factor_handles(
    attacker_draft: BaseModel,
    factor_drafts: list[BaseModel],
) -> None:
    """Require every intention source to have an explicit causal declaration."""
    declared = {item.source_handle for item in factor_drafts}
    missing = sorted(
        {
            handle
            for intention in attacker_draft.intentions
            for handle in intention.source_handles
            if handle not in declared
        }
    )
    if missing:
        raise ValueError(
            "intention source handles must have declared causal factors: "
            + ", ".join(missing)
        )


def _materialize_intention(
    draft: BaseModel,
    choices: dict[str, _CausalSourceChoice],
) -> str:
    """Attach exact structural identities to one model-authored intention."""
    source_ids = tuple(
        dict.fromkeys(choices[handle].source_id for handle in draft.source_handles)
    )
    return f"{draft.description.strip()} [structural sources: {', '.join(source_ids)}]"


def _materialize_causal_factor(
    draft: BaseModel,
    choices: dict[str, _CausalSourceChoice],
    *,
    temporal_condition: SemanticCondition | None = None,
) -> CausalFactorDeclaration:
    """Compile one local causal-source handle into the closed domain record."""
    choice = choices[draft.source_handle]
    evidence_status = draft.evidence_status
    bounded_assumption = getattr(draft, "bounded_assumption", None)
    capability_refs = tuple(getattr(draft, "capability_refs", ()))
    access_refs = tuple(getattr(draft, "access_refs", ()))
    if (
        bounded_assumption is not None
        and evidence_status is CausalEvidenceStatus.structural_failure
        and not capability_refs
        and not access_refs
    ):
        evidence_status = CausalEvidenceStatus.bounded_assumption
    return CausalFactorDeclaration(
        kind=choice.kind,
        source_id=choice.source_id,
        evidence=draft.evidence,
        temporal_condition=(
            temporal_condition
            if temporal_condition is not None
            else getattr(draft, "temporal_condition", None)
        ),
        evidence_status=evidence_status,
        capability_refs=capability_refs,
        access_refs=access_refs,
        bounded_assumption=bounded_assumption,
    )


def assemble_scenario_spec(
    defender_bdi: DefenderBDI,
    llm_result: BDIGenerationResult,
    threat: StructuralThreat,
    control_structure: ControlStructure,
    scenario_index: int = 0,
    *,
    scenario_context: ScenarioGenerationContext | None = None,
    requested_environment_basis: RequestedEnvironmentBasis | None = None,
) -> ScenarioSpec:
    """Assemble a ScenarioSpec from the defender BDI and LLM result.

    Merges vulnerability annotations into the defender BDI and combines
    with the attacker BDI. The defender BDI IDs are NOT trusted from the
    LLM — the original deterministic values are used, and vulnerabilities
    are extracted by matching to the original pm_id values.

    Declared causal factors are selected in declared order with their
    evidence descriptions and optional timing; every factor reference is
    validated against the control structure (a ``ValueError`` names the
    invalid causal-factor reference) so unbacked structural presence
    never invents a factor.

    Args:
        defender_bdi: Pre-populated defender BDI (will be mutated in place).
        llm_result: The LLM generation result.
        threat: The structural threat.
        control_structure: The full control structure.
        scenario_index: Zero-based index for scenario ID generation.

    Returns:
        A :class:`ScenarioSpec`.
    """
    slot_parts = parse_ica_slot_id(threat.ica_slot_id)
    _validate_optional_assembly_context(scenario_context, threat, scenario_index)
    _merge_defender_vulnerabilities(defender_bdi, llm_result)
    causal_factors = _materialize_causal_factors(llm_result)
    _validate_assembled_factors(causal_factors, control_structure, scenario_context)
    _validate_assembled_execution_contract(
        llm_result.execution_contract,
        causal_factors,
        scenario_context,
        requested_environment_basis,
    )
    unsafe_condition = _validated_unsafe_condition(
        llm_result, UCAType(slot_parts["ica_type"]), slot_parts["control_action"]
    )
    if scenario_context is not None:
        # Context is the only authoritative source for selected consequence
        # lineage.  The contextual provider wire carries descriptions only;
        # deterministic assembly derives the exact IDs here.
        hazard_refs = [item.hazard_id for item in scenario_context.hazards]
        constraint_refs = [item.constraint_id for item in scenario_context.constraints]
    else:
        hazard_refs, constraint_refs = _unsafe_outcome_refs(llm_result, threat)

    return ScenarioSpec(
        scenario_id=generate_scenario_id(scenario_index),
        threat_source=ThreatSource(
            ica_slot_id=threat.ica_slot_id,
            provenance=threat.provenance,
            ica_id=threat.ica_id,
        ),
        target_controller=slot_parts["controller"],
        target_control_action=slot_parts["control_action"],
        ica_type=UCAType(slot_parts["ica_type"]),
        defender_bdi=defender_bdi,
        attacker_bdi=llm_result.attacker_bdi,
        catalog_context=threat.catalog_mappings,
        loss_scenario=threat.loss_scenario,
        causal_factors=causal_factors,
        unsafe_outcome_condition=unsafe_condition,
        unsafe_outcome_semantic_proposition=(
            llm_result.unsafe_outcome.semantic_proposition
            if llm_result.unsafe_outcome is not None
            else None
        ),
        unsafe_outcome_hazard_refs=hazard_refs,
        unsafe_outcome_constraint_refs=constraint_refs,
        scenario_context=scenario_context,
        execution_contract=llm_result.execution_contract,
    )


def _validate_assembled_execution_contract(
    contract: SemanticExecutionContract | None,
    causal_factors: Sequence[CausalFactor],
    context: ScenarioGenerationContext | None,
    requested_environment_basis: RequestedEnvironmentBasis | None,
) -> None:
    """Require corrected contextual assembly to retain an exact route contract."""
    if context is None:
        return
    if contract is None:
        raise ValueError("corrected Stage 5 output must include execution_contract")
    _validate_assembled_delivery_factor(contract, causal_factors)
    _validate_assembled_environment_basis(contract, requested_environment_basis)


def _validate_assembled_delivery_factor(
    contract: SemanticExecutionContract,
    causal_factors: Sequence[CausalFactor],
) -> None:
    """Require a contextual delivery to bind to one assembled factor."""
    if contract.delivery is None:
        return
    factor_ids = {
        f"CF-{index}" for index, _factor in enumerate(causal_factors, start=1)
    }
    if contract.delivery.factor_id not in factor_ids:
        raise ValueError(
            "execution contract delivery factor_id must resolve to a declared factor"
        )


def _validate_assembled_environment_basis(
    contract: SemanticExecutionContract,
    requested_environment_basis: RequestedEnvironmentBasis | None,
) -> None:
    """Require the assembled contract to retain the caller's selected basis."""
    if not _assembly_basis_check_applies(contract, requested_environment_basis):
        return
    if not _assembly_basis_matches(contract, requested_environment_basis):
        raise ValueError(
            "execution contract requested_environment_basis does not match "
            "the caller-selected environment basis"
        )


def _assembly_basis_check_applies(
    contract: SemanticExecutionContract,
    requested_environment_basis: RequestedEnvironmentBasis | None,
) -> bool:
    """Return whether assembly supplied enough context to compare the basis."""
    return requested_environment_basis is not None and contract.delivery is not None


def _assembly_basis_matches(
    contract: SemanticExecutionContract,
    requested_environment_basis: RequestedEnvironmentBasis,
) -> bool:
    """Compare the assembled contract basis with the caller's selected basis."""
    expected_basis = (
        RequestedEnvironmentBasis.target_agnostic
        if not contract.resource_requirements
        else requested_environment_basis
    )
    return contract.requested_environment_basis is expected_basis


def _validate_context_matches_threat(
    context: ScenarioGenerationContext,
    threat: StructuralThreat,
    scenario_index: int,
) -> None:
    """Reject an attempt to assemble provider output under different authority."""
    if _context_threat_identity(context) != _threat_identity(threat, scenario_index):
        raise ValueError("scenario context does not match selected structural threat")


def _context_threat_identity(
    context: ScenarioGenerationContext,
) -> tuple[str, str | None, str, str, str, str]:
    """Return the context identity fields used for threat pinning."""
    identity = context.scenario_identity
    return (
        identity.scenario_id,
        identity.ica_id,
        identity.ica_slot_id,
        context.ica.exact_ica_text,
        context.ica.hazardous_context,
        context.ica.loss_consequence,
    )


def _threat_identity(
    threat: StructuralThreat,
    scenario_index: int,
) -> tuple[str, str | None, str, str, str, str]:
    """Return the threat identity in the context comparison order."""
    return (
        generate_scenario_id(scenario_index),
        threat.ica_id,
        threat.ica_slot_id,
        threat.ica_text,
        threat.hazardous_context,
        threat.loss_scenario,
    )


def _validate_optional_assembly_context(
    context: ScenarioGenerationContext | None,
    threat: StructuralThreat,
    scenario_index: int,
) -> None:
    """Validate a supplied scenario context before compiling provider output."""
    if context is not None:
        _validate_context_matches_threat(context, threat, scenario_index)


def _merge_defender_vulnerabilities(
    defender_bdi: DefenderBDI,
    llm_result: BDIGenerationResult,
) -> None:
    """Attach provider vulnerability prose to deterministic belief IDs."""
    for belief in defender_bdi.beliefs:
        belief.vulnerability = llm_result.defender_vulnerabilities.get(belief.pm_id, "")


def _materialize_causal_factors(
    llm_result: BDIGenerationResult,
) -> list[CausalFactor]:
    """Compile the declared Stage 5 factor records without inference."""
    return [
        CausalFactor(
            kind=declaration.kind,
            source_id=declaration.source_id,
            description=declaration.evidence,
            declared_timing=declaration.timing,
            evidence_status=declaration.evidence_status,
            capability_refs=declaration.capability_refs,
            access_refs=declaration.access_refs,
            bounded_assumption=declaration.bounded_assumption,
            temporal_condition=declaration.temporal_condition,
        )
        for declaration in llm_result.causal_factors
    ]


def _validate_assembled_factors(
    causal_factors: list[CausalFactor],
    control_structure: ControlStructure,
    context: ScenarioGenerationContext | None,
) -> None:
    """Validate factor references against structure and optional context."""
    validate_factor_sources(control_structure, causal_factors)
    if context is None:
        return
    validate_factor_evidence(context, causal_factors)
    _validate_context_factor_sources(context, causal_factors)


def _validated_unsafe_condition(
    llm_result: BDIGenerationResult,
    uca_type: UCAType,
    control_action_id: str,
) -> SemanticCondition | None:
    """Validate and return the provider's typed unsafe condition when present."""
    outcome = llm_result.unsafe_outcome
    if outcome is None:
        return None
    _validate_unsafe_outcome_for_target(outcome, uca_type, control_action_id)
    return outcome.condition


def _unsafe_outcome_refs(
    llm_result: BDIGenerationResult,
    threat: StructuralThreat,
) -> tuple[list[str], list[str]]:
    """Use validated provider refs or the threat's authoritative fallback refs."""
    outcome = llm_result.unsafe_outcome
    if outcome is None:
        return list(threat.related_hazards), list(threat.related_constraints)
    return list(outcome.hazard_refs), list(outcome.constraint_refs)


def _validate_unsafe_outcome_for_target(
    unsafe_outcome: UnsafeOutcomeDeclaration,
    uca_type: UCAType,
    control_action_id: str,
) -> None:
    """Keep provider-authored unsafe semantics inside the requested ICA."""
    accepted = {
        UCAType.not_provided: {"action_presence"},
        UCAType.incorrect: {"action_value", "state_value"},
        UCAType.wrong_timing: {"ordering", "delay", "window", "absence"},
        UCAType.wrong_duration: {"duration"},
    }
    condition = unsafe_outcome.condition
    if condition.type not in accepted[uca_type]:
        raise ValueError(
            f"unsafe outcome condition '{condition.type}' is incompatible with "
            f"the selected UCA '{uca_type.value}'"
        )
    # A typed action condition is the one place the provider may repeat the
    # target action identity.  It remains semantic condition data, never a
    # causal-source selection; deterministic code requires exact equality.
    condition_action = getattr(condition, "control_action_id", None)
    if condition_action is not None and condition_action != control_action_id:
        raise ValueError(
            "unsafe outcome condition control_action_id must equal the selected "
            "target action"
        )


def _validate_context_factor_sources(
    context: ScenarioGenerationContext,
    causal_factors: list[CausalFactor],
) -> None:
    """Keep every declared cause inside the selected control-path slice."""
    path = context.target_control_path
    allowed = {
        *(item.element_id for item in path.process_model_parts),
        *(item.element_id for item in path.feedback),
        path.control_action.action_id,
        *(item.action_id for item in path.related_control_actions),
    }
    for factor in causal_factors:
        if factor.source_id not in allowed:
            raise ValueError(
                f"Causal factor source {factor.source_id!r} is outside the "
                "selected scenario control path."
            )
