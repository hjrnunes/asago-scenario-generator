"""Stage 5 — Dual-BDI scenario specification.

Deterministic defender BDI pre-population from the control structure,
combined LLM call for vulnerability annotations + attacker BDI,
and deterministic assembly of the ScenarioSpec.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
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
    ActionValueCondition,
    SemanticBindingPlaceholder,
    SemanticCondition,
    StateValueCondition,
    contains_binding_placeholder,
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
from asago_scenario_generator.stpa.models.control_structure import (
    ControlStructure,
    CoordinationLink,
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
    "UnsafeOutcomeDeclaration",
    "populate_defender_bdi",
    "generate_bdi",
    "generate_bdi_for_context",
    "build_bdi_prompts",
    "build_context_bdi_prompts",
    "assemble_scenario_spec",
    "generate_scenario_id",
    "parse_ica_slot_id",
]

_LENGTH_RETRY_MAX_COMPLETION_TOKENS = 2048
_LENGTH_RETRY_PROMPT = (
    "\n\nThe prior response was truncated. Return only a concise "
    "schema-matching response with no explanation."
)
_LENGTH_RETRY_EXHAUSTED_PREFIX = (
    "BDI generation retry exhausted after LengthFinishReasonError:"
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
    semantic_binding_required: StrictBool | None = None
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
        return self


class _ContextUnsafeOutcomeDraft(BaseModel):
    """Provider-owned unsafe semantics without compiler-derived state."""

    model_config = ConfigDict(extra="forbid")

    condition: SemanticCondition
    hazard_refs: tuple[str, ...] = ()
    constraint_refs: tuple[str, ...] = ()


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

    source_handle: str
    evidence: str = Field(min_length=1)
    temporal_condition: SemanticCondition | None = None
    evidence_status: CausalEvidenceStatus = CausalEvidenceStatus.structural_failure
    capability_refs: tuple[str, ...] = ()
    access_refs: tuple[str, ...] = ()
    bounded_assumption: str | None = None


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

    defender_vulnerabilities: list[_ContextDefenderVulnerabilityDraft]
    attacker_bdi: _ContextAttackerBDIDraft
    causal_factors: list[_ContextCausalFactorDraft]
    unsafe_outcome: _ContextUnsafeOutcomeDraft
    execution_route: ExecutionRouteSelectionValue

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
    requested_environment_basis: RequestedEnvironmentBasis = (
        RequestedEnvironmentBasis.target_profile
    ),
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
    response_format = _context_bdi_provider_payload_type(
        len(choices), len(belief_choices)
    )
    draft, error = _call_bdi_with_bounded_length_retry(
        llm_client,
        system_prompt,
        user_prompt,
        run_dir,
        response_format=response_format,
        stage=stage,
        step=step,
        temperature=temperature,
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
    requested_environment_basis: RequestedEnvironmentBasis,
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
    result_validator: Callable[[BaseModel], None] | None = None,
) -> tuple[BaseModel | None, str | None]:
    """Call the closed Stage 5 contract with its one length-only retry."""
    result, _llm_result, error = safe_llm_call(
        llm_client=llm_client,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_format=response_format,
        run_dir=run_dir,
        stage=stage,
        step=step,
        temperature=temperature,
        validation_retries=1,
        validation_retry_include_schema=False,
        validation_retry_feedback=(
            " Return only a closed JSON object with every required field. "
            "Include causal_factors, explicit temporal_condition (including "
            "null), unsafe_outcome with its typed condition, and one "
            "execution_route. Do not return semantic_binding_required; "
            "deterministic code derives it."
        ),
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
        temperature=temperature,
        max_completion_tokens=_LENGTH_RETRY_MAX_COMPLETION_TOKENS,
        validation_retries=1,
        validation_retry_include_schema=False,
        validation_retry_feedback=(
            " Return only a closed JSON object with every required field. "
            "Include causal_factors, explicit temporal_condition (including "
            "null), unsafe_outcome with its typed condition, and one "
            "execution_route. Do not return semantic_binding_required; "
            "deterministic code derives it."
        ),
        result_validator=result_validator,
        result_parser=lambda value: _parse_context_bdi_result(value, response_format),
    )
    if retry_error is None:
        return retry_result, None
    return None, f"{_LENGTH_RETRY_EXHAUSTED_PREFIX} {retry_error}"


def _parse_context_bdi_result(result, response_format: type[BaseModel]) -> BaseModel:
    """Parse the contextual provider payload without compiler-owned fields."""
    return parse_llm_result(result, response_format)


def _validate_context_provider_payload(
    value: BaseModel,
    context: ScenarioGenerationContext,
) -> None:
    """Validate request-local unsafe semantics before Stage 5 succeeds."""
    unsafe_outcome = getattr(value, "unsafe_outcome", None)
    if not isinstance(unsafe_outcome, _ContextUnsafeOutcomeDraft):
        raise ValueError("unsafe_outcome is required in corrected Stage 5 output")
    route = getattr(value, "execution_route", None)
    if route is None:
        raise ValueError("execution_route is required in corrected Stage 5 output")
    _validate_execution_route(route, value.causal_factors, context, unsafe_outcome)
    _validate_unsafe_outcome_for_target(
        unsafe_outcome,
        context.ica.uca_type,
        context.target_control_path.control_action.action_id,
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
    source_choices_yaml = yaml.dump(
        [
            {
                "source_handle": choice.handle,
                "source_type": _source_type_explanation(choice.kind),
                "description": choice.description,
                "select_when": _source_selection_guidance(choice.kind),
            }
            for choice in source_choices
        ],
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
    )
    belief_choices_yaml = yaml.dump(
        [
            {
                "belief_handle": handle,
                "description": belief.description,
            }
            for handle, belief in _defender_belief_choices(scenario_context)
        ],
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
    )
    execution_role_choices_yaml = _execution_role_choices_yaml()
    return (
        loader.render_prompt(
            "stage5_context_system.j2",
            target_action_id=scenario_context.target_control_path.control_action.action_id,
        ),
        loader.render_prompt(
            "stage5_context_user.j2",
            scenario_context_yaml=scenario_context_yaml,
            causal_source_choices_yaml=source_choices_yaml,
            defender_belief_choices_yaml=belief_choices_yaml,
            execution_role_choices_yaml=execution_role_choices_yaml,
            target_action_id=scenario_context.target_control_path.control_action.action_id,
            selected_uca_type=scenario_context.ica.uca_type.value,
        ),
    )


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
    return {
        "owner_description": _stage5_owner_description(context),
        "target_action": {
            "reference": path.control_action.action_id,
            "description": path.control_action.description,
        },
        "controlled_processes": _stage5_controlled_processes(context),
    }


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
    """Expose consequence prose and only references copied by provider output."""
    return {
        "losses": [item.description for item in context.losses],
        "hazards": [
            {"reference": item.hazard_id, "description": item.description}
            for item in context.hazards
        ],
        "constraints": [
            {"reference": item.constraint_id, "description": item.description}
            for item in context.constraints
        ],
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


def _execution_role_choices_yaml() -> str:
    """Render only semantic role handles offered to the Stage 5 selector."""
    return yaml.dump(
        [
            {
                "role_handle": choice.handle,
                "purpose": choice.purpose.value,
                "description": choice.description,
            }
            for choice in _EXECUTION_ROLE_CHOICES
        ],
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
    route: ExecutionRouteSelectionValue,
    factor_drafts: Sequence[BaseModel],
    context: ScenarioGenerationContext,
    unsafe_outcome: _ContextUnsafeOutcomeDraft | UnsafeOutcomeDeclaration,
) -> None:
    """Validate provider route choices against one exact request context."""
    declared_handles = _declared_causal_handles(factor_drafts)
    if isinstance(route, AnalyticalOnlyRouteSelection):
        _validate_analytical_route_gaps(route, declared_handles)
        return
    _validate_selected_factor_handle(route, declared_handles)
    _validate_delivery_factor_fidelity(route, context)
    _validate_model_output_outcome(route, unsafe_outcome)
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


def _validate_delivery_factor_fidelity(
    route: ExecutableRouteSelection,
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
    route: ExecutableRouteSelection,
    unsafe_outcome: _ContextUnsafeOutcomeDraft | UnsafeOutcomeDeclaration,
) -> None:
    """Keep model-output judgments semantic instead of deployment-string bound."""
    condition = unsafe_outcome.condition
    if (
        route.action_kind is ExecutionActionKind.model_output
        and isinstance(condition, ActionValueCondition)
        and isinstance(condition.expected, SemanticBindingPlaceholder)
    ):
        raise ValueError(
            "model_output action_value must use a literal semantic proposition; "
            "use a specific property such as reveals_restricted_information with "
            "expected true instead of a deployment value placeholder"
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
    route: ExecutableRouteSelection,
    declared_handles: set[str],
) -> None:
    """Require an executable route to select one declared local factor."""
    if route.selected_factor_handle not in declared_handles:
        raise ValueError(
            "execution route selected_factor_handle must name a declared causal factor"
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
    route: ExecutableRouteSelection,
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
    route: ExecutableRouteSelection,
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
    return roles


def _factor_ids_by_handle(factor_drafts: Sequence[BaseModel]) -> dict[str, str]:
    """Assign canonical CF identities in provider declaration order."""
    return {
        item.source_handle: f"CF-{index}"
        for index, item in enumerate(factor_drafts, start=1)
    }


def _materialize_execution_contract(
    route: ExecutionRouteSelectionValue,
    factor_drafts: Sequence[BaseModel],
    choices: dict[str, _CausalSourceChoice],
    unsafe_outcome: UnsafeOutcomeDeclaration,
    context: ScenarioGenerationContext,
    requested_environment_basis: RequestedEnvironmentBasis,
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
    )
    basis = (
        RequestedEnvironmentBasis.target_agnostic
        if not requirements
        else requested_environment_basis
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
    route: ExecutableRouteSelection,
    selected_factor_id: str,
    selected_source_id: str,
    unsafe_outcome: UnsafeOutcomeDeclaration,
    context: ScenarioGenerationContext,
) -> tuple[ExecutionResourceRequirement, ...]:
    """Build deterministic semantic requirement records from role handles."""
    requirements: list[ExecutionResourceRequirement] = []
    handles = set(route.resource_role_handles)
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
                required_attacker_influence=route.carrier_attacker_influence,
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
                owner_ref=context.target_control_path.controller.element_id,
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


@lru_cache(maxsize=32)
def _context_bdi_provider_payload_type(
    choice_count: int,
    belief_count: int,
) -> type[BaseModel]:
    """Build a strict response schema over one request's local source handles."""
    _require_positive_schema_count(choice_count, "choice_count")
    _require_positive_schema_count(belief_count, "belief_count")
    handles = tuple(f"cause_{index}" for index in range(1, choice_count + 1))
    handle_type = Literal.__getitem__(handles)
    factor_type = create_model(
        f"_ContextCausalFactorDraft{choice_count}",
        __base__=_ContextCausalFactorDraft,
        source_handle=(handle_type, ...),
        # Presence is part of the provider contract: ``null`` means that no
        # separately supported temporal constraint exists.  A missing field
        # is malformed and must receive the bounded structured retry.
        temporal_condition=(SemanticCondition | None, ...),
    )
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
    factor_list = conlist(factor_type, min_length=1)
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
    unsafe_outcome_type = create_model(
        f"_ContextUnsafeOutcomeDraft{choice_count}",
        __base__=_ContextUnsafeOutcomeDraft,
    )
    role_handles = tuple(choice.handle for choice in _EXECUTION_ROLE_CHOICES)
    role_handle_type = Literal.__getitem__(role_handles)
    role_handle_list = conlist(role_handle_type, max_length=len(role_handles))
    executable_route_type = create_model(
        f"_ExecutableRouteSelection{choice_count}",
        __base__=ExecutableRouteSelection,
        selected_factor_handle=(handle_type, ...),
        resource_role_handles=(role_handle_list, ...),
        carrier_attacker_influence=(AttackerInfluence, ...),
    )
    route_type = Annotated[
        Union[executable_route_type, AnalyticalOnlyRouteSelection],
        Field(discriminator="disposition"),
    ]
    return create_model(
        f"_ContextBDIProviderPayload{choice_count}x{belief_count}",
        __base__=_ContextBDIProviderPayload,
        defender_vulnerabilities=(vulnerability_list, ...),
        attacker_bdi=(attacker_type, ...),
        causal_factors=(factor_list, ...),
        unsafe_outcome=(unsafe_outcome_type, ...),
        execution_route=(route_type, ...),
    )


def _require_positive_schema_count(value: int, name: str) -> None:
    """Reject booleans and non-positive dynamic-schema counts."""
    if type(value) is not int or value <= 0:
        raise ValueError(f"{name} must be a positive integer")


def _materialize_context_bdi(
    draft: BaseModel,
    choices: tuple[_CausalSourceChoice, ...],
    belief_choices: tuple[tuple[str, DescribedElement], ...],
    context: ScenarioGenerationContext,
    requested_environment_basis: RequestedEnvironmentBasis,
) -> BDIGenerationResult:
    """Resolve provider-local handles to exact context-owned structural IDs."""
    choices_by_handle = {choice.handle: choice for choice in choices}
    attacker_draft = draft.attacker_bdi
    _validate_intention_factor_handles(attacker_draft, draft.causal_factors)
    attacker_bdi = AttackerBDI(
        beliefs=list(attacker_draft.beliefs),
        desires=list(attacker_draft.desires),
        intentions=[
            _materialize_intention(item, choices_by_handle)
            for item in attacker_draft.intentions
        ],
    )
    factors = [
        _materialize_causal_factor(item, choices_by_handle)
        for item in draft.causal_factors
    ]
    belief_ids = {handle: belief.element_id for handle, belief in belief_choices}
    unsafe_outcome = UnsafeOutcomeDeclaration(
        condition=draft.unsafe_outcome.condition,
        hazard_refs=draft.unsafe_outcome.hazard_refs,
        constraint_refs=draft.unsafe_outcome.constraint_refs,
    )
    execution_contract = _materialize_execution_contract(
        draft.execution_route,
        draft.causal_factors,
        choices_by_handle,
        unsafe_outcome,
        context,
        requested_environment_basis,
    )
    return BDIGenerationResult(
        defender_vulnerabilities={
            belief_ids[item.belief_handle]: item.vulnerability.strip()
            for item in draft.defender_vulnerabilities
        },
        attacker_bdi=attacker_bdi,
        causal_factors=factors,
        unsafe_outcome=unsafe_outcome,
        execution_contract=execution_contract,
    )


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
) -> CausalFactorDeclaration:
    """Compile one local causal-source handle into the closed domain record."""
    choice = choices[draft.source_handle]
    evidence_status = draft.evidence_status
    if (
        draft.bounded_assumption is not None
        and evidence_status is CausalEvidenceStatus.structural_failure
        and not draft.capability_refs
        and not draft.access_refs
    ):
        evidence_status = CausalEvidenceStatus.bounded_assumption
    return CausalFactorDeclaration(
        kind=choice.kind,
        source_id=choice.source_id,
        evidence=draft.evidence,
        temporal_condition=draft.temporal_condition,
        evidence_status=evidence_status,
        capability_refs=draft.capability_refs,
        access_refs=draft.access_refs,
        bounded_assumption=draft.bounded_assumption,
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
