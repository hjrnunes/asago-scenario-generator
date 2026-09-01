"""Stage 5 — Dual-BDI scenario specification.

Deterministic defender BDI pre-population from the control structure,
combined LLM call for vulnerability annotations + attacker BDI,
and deterministic assembly of the ScenarioSpec.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Literal

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
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
from .context import render_scenario_generation_context

__all__ = [
    "BDIGenerationResult",
    "CausalEvidenceStatus",
    "CausalFactorDeclaration",
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


class BDIGenerationResult(BaseModel):
    """LLM response model for the combined BDI generation call."""

    model_config = ConfigDict(extra="forbid")

    defender_vulnerabilities: dict[str, str] = Field(default_factory=dict)
    attacker_bdi: AttackerBDI
    causal_factors: list[CausalFactorDeclaration] = Field(min_length=1)


class _ContextCausalFactorDraft(BaseModel):
    """Provider-only factor whose structural identity is a local handle."""

    model_config = ConfigDict(extra="forbid")

    source_handle: str
    evidence: str = Field(min_length=1)
    timing: str | None = None
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


class _ContextBDIProviderPayload(BDIGenerationResult):
    """Base response body for one exact scenario-context request."""

    model_config = ConfigDict(extra="forbid")

    defender_vulnerabilities: list[_ContextDefenderVulnerabilityDraft]
    attacker_bdi: _ContextAttackerBDIDraft
    causal_factors: list[_ContextCausalFactorDraft]

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
    links = [
        item for item in control_structure.coordination_links if item.link_id == link_id
    ]
    if len(links) != 1:
        raise ValueError(
            f"Coordination link '{link_id}' not found in control structure."
        )
    link: CoordinationLink = links[0]
    source = _find_responsibility(control_structure, link.source)
    target = _find_responsibility(control_structure, link.target)
    responsibilities = (source, target)

    beliefs = [
        DefenderBelief(
            pm_id=part.pm_id,
            content=part.description,
            vulnerability="",
        )
        for responsibility in responsibilities
        for part in responsibility.process_model_parts
    ]
    desires = [
        DefenderDesire(
            resp_id=responsibility.resp_id, content=responsibility.description
        )
        for responsibility in responsibilities
    ]
    intentions = [
        DefenderIntention(ca_id=action.ca_id, content=action.description)
        for responsibility in responsibilities
        for action in responsibility.control_actions
    ]
    return DefenderBDI(beliefs=beliefs, desires=desires, intentions=intentions)


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
    """Compatibility adapter for the historical direct Stage 5 interface.

    Corrected SP3 runs use :func:`generate_bdi_for_context`; this adapter keeps
    existing direct callers operational without making it the production seam.

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
            return retry_result, None
        return (
            None,
            f"{_LENGTH_RETRY_EXHAUSTED_PREFIX} {retry_error}",
        )

    if error is not None:
        return None, error
    return result, None


def generate_bdi_for_context(
    llm_client: LLMClient,
    scenario_context: ScenarioGenerationContext,
    run_dir: Path,
    loader: TemplateLoader | None = None,
    stage: str = "stage_5",
    step: str = "bdi_generation",
    temperature: float = 0.4,
) -> tuple[BDIGenerationResult | None, str | None]:
    """Execute corrected Stage 5 with only the immutable scenario context."""
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
    )
    return _finish_context_bdi(draft, error, choices, belief_choices)


def _finish_context_bdi(
    draft: BaseModel | None,
    error: str | None,
    choices: tuple[_CausalSourceChoice, ...],
    belief_choices: tuple[tuple[str, DescribedElement], ...],
) -> tuple[BDIGenerationResult | None, str | None]:
    """Compile one parsed provider draft or preserve its closed failure."""
    if error is not None or draft is None:
        return None, error
    if type(draft) is BDIGenerationResult:
        return draft, None
    try:
        return _materialize_context_bdi(draft, choices, belief_choices), None
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
        result_parser=lambda value: _parse_context_bdi_result(value, response_format),
    )
    if retry_error is None:
        return retry_result, None
    return None, f"{_LENGTH_RETRY_EXHAUSTED_PREFIX} {retry_error}"


def _parse_context_bdi_result(result, response_format: type[BaseModel]) -> BaseModel:
    """Retain already-typed compatibility responses; parse provider drafts strictly."""
    if type(result.content) is BDIGenerationResult:
        return result.content
    return parse_llm_result(result, response_format)


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
    scenario_context_yaml = render_scenario_generation_context(scenario_context)
    source_choices = _causal_source_choices(scenario_context)
    if not source_choices:
        raise ValueError("selected scenario context has no valid causal-factor sources")
    source_choices_yaml = yaml.dump(
        [
            {
                "source_handle": choice.handle,
                "kind": choice.kind.value,
                "source_id": choice.source_id,
                "description": choice.description,
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
    return (
        loader.render_prompt("stage5_context_system.j2"),
        loader.render_prompt(
            "stage5_context_user.j2",
            scenario_context_yaml=scenario_context_yaml,
            causal_source_choices_yaml=source_choices_yaml,
            defender_belief_choices_yaml=belief_choices_yaml,
        ),
    )


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
    return create_model(
        f"_ContextBDIProviderPayload{choice_count}x{belief_count}",
        __base__=_ContextBDIProviderPayload,
        defender_vulnerabilities=(vulnerability_list, ...),
        attacker_bdi=(attacker_type, ...),
        causal_factors=(factor_list, ...),
    )


def _require_positive_schema_count(value: int, name: str) -> None:
    """Reject booleans and non-positive dynamic-schema counts."""
    if type(value) is not int or value <= 0:
        raise ValueError(f"{name} must be a positive integer")


def _materialize_context_bdi(
    draft: BaseModel,
    choices: tuple[_CausalSourceChoice, ...],
    belief_choices: tuple[tuple[str, DescribedElement], ...],
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
    return BDIGenerationResult(
        defender_vulnerabilities={
            belief_ids[item.belief_handle]: item.vulnerability.strip()
            for item in draft.defender_vulnerabilities
        },
        attacker_bdi=attacker_bdi,
        causal_factors=factors,
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
        timing=draft.timing,
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
    if scenario_context is not None:
        _validate_context_matches_threat(scenario_context, threat, scenario_index)

    # Merge vulnerability annotations — use original deterministic pm_ids
    for belief in defender_bdi.beliefs:
        belief.vulnerability = llm_result.defender_vulnerabilities.get(belief.pm_id, "")

    # Select exactly the declared, evidence-backed causal factors.
    # References must resolve against the control structure; invalid
    # references stop Stage 5 with a causal-factor reference validation
    # error before any Stage 6 call can run.
    causal_factors = [
        CausalFactor(
            kind=declaration.kind,
            source_id=declaration.source_id,
            description=declaration.evidence,
            declared_timing=declaration.timing,
            evidence_status=declaration.evidence_status,
            capability_refs=declaration.capability_refs,
            access_refs=declaration.access_refs,
            bounded_assumption=declaration.bounded_assumption,
        )
        for declaration in llm_result.causal_factors
    ]
    validate_factor_sources(control_structure, causal_factors)
    if scenario_context is not None:
        validate_factor_evidence(scenario_context, causal_factors)
        _validate_context_factor_sources(scenario_context, causal_factors)

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
        scenario_context=scenario_context,
    )


def _validate_context_matches_threat(
    context: ScenarioGenerationContext,
    threat: StructuralThreat,
    scenario_index: int,
) -> None:
    """Reject an attempt to assemble provider output under different authority."""
    identity = context.scenario_identity
    if (
        identity.scenario_id != generate_scenario_id(scenario_index)
        or identity.ica_slot_id != threat.ica_slot_id
        or identity.ica_id != threat.ica_id
        or context.ica.exact_ica_text != threat.ica_text
        or context.ica.hazardous_context != threat.hazardous_context
        or context.ica.loss_consequence != threat.loss_scenario
    ):
        raise ValueError("scenario context does not match selected structural threat")


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
