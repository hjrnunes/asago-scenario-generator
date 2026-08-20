"""Stage 5 — Dual-BDI scenario specification.

Deterministic defender BDI pre-population from the control structure,
combined LLM call for vulnerability annotations + attacker BDI,
and deterministic assembly of the ScenarioSpec.
"""

from __future__ import annotations

import yaml
from pathlib import Path
from pydantic import BaseModel, Field

from asago_scenario_generator.stpa.infra.llm import LLMClient
from asago_scenario_generator.stpa.infra.llm_helpers import safe_llm_call
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.stpa.models.causal_factor import (
    CausalFactor,
    CausalFactorKind,
    validate_factor_sources,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlStructure,
    Responsibility,
)
from asago_scenario_generator.stpa.models.enriched_threat_set import StructuralThreat
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
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
    "BDIGenerationResult",
    "CausalFactorDeclaration",
    "populate_defender_bdi",
    "generate_bdi",
    "build_bdi_prompts",
    "assemble_scenario_spec",
    "generate_scenario_id",
    "parse_ica_slot_id",
]

_LENGTH_RETRY_MAX_COMPLETION_TOKENS = 2048
_LENGTH_RETRY_PROMPT = (
    "\n\nThe prior response was truncated. Return only a concise "
    "schema-matching response with no explanation."
)


class CausalFactorDeclaration(BaseModel):
    """One Stage 5 declaration of an evidence-backed causal factor.

    ``kind`` and ``source_id`` name the structural finding, ``evidence``
    carries the declared evidence description, and ``timing`` carries
    optional declared timing text (parsed into typed temporal
    constraints only at projection time; never inferred).
    """

    kind: CausalFactorKind
    source_id: str = Field(min_length=1)
    evidence: str = Field(min_length=1)
    timing: str | None = None


class BDIGenerationResult(BaseModel):
    """LLM response model for the combined BDI generation call."""

    defender_vulnerabilities: dict[str, str] = Field(default_factory=dict)
    attacker_bdi: AttackerBDI
    # Declared, evidence-backed causal factors in declared order.  An
    # absent or empty list is the explicit empty contract: structural
    # presence alone must never select a factor.
    causal_factors: list[CausalFactorDeclaration] = Field(default_factory=list)


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
    """Execute the combined LLM call for vulnerability annotations + attacker BDI.

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
            "BDI generation retry exhausted after "
            f"LengthFinishReasonError: {retry_error}",
        )

    if error is not None:
        return None, error
    return result, None


def _is_length_finish_reason_error(error: str | None) -> bool:
    """Return whether a safe-call error came from completion length exhaustion."""
    if error is None:
        return False
    error_type, _, _message = error.partition(":")
    return error_type == "LengthFinishReasonError"


def build_bdi_prompts(
    defender_bdi: DefenderBDI,
    threat: StructuralThreat,
    control_structure: ControlStructure,
    target_resp_id: str,
    loader: TemplateLoader,
    capability_profile: CapabilityProfile | None = None,
) -> tuple[str, str]:
    """Build the system and user prompts for the BDI generation call.

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


def assemble_scenario_spec(
    defender_bdi: DefenderBDI,
    llm_result: BDIGenerationResult,
    threat: StructuralThreat,
    control_structure: ControlStructure,
    scenario_index: int = 0,
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
        )
        for declaration in llm_result.causal_factors
    ]
    validate_factor_sources(control_structure, causal_factors)

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
    )


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-19T13:04:28Z","module_hash":"cf8714929ce4efac88e19b1a7b79b482fbfebb6872f379a591486eee96608134","source_sha256":"d3ffa67ac78d0720163a69aac96ad9be7e4edcd8cfb55acc52edf5b6b34a08f4","functions":[{"id":"func/generate_scenario_id","name":"generate_scenario_id","line":61,"end_line":70,"hash":"530efa395a985f80bec7697e91e2a58ea143f9407ee1e32542f30b6fc43b8348"},{"id":"func/parse_ica_slot_id","name":"parse_ica_slot_id","line":73,"end_line":93,"hash":"a414c48cebfc7adc3589764e920f3181d7eccc71a3a5f86880cb39b36b221670"},{"id":"func/populate_defender_bdi","name":"populate_defender_bdi","line":96,"end_line":141,"hash":"f1beb2a9519da247cf720b1a6f684bb3d46c2e8d8e3405337b0e9f6cfe66ec4f"},{"id":"func/_find_responsibility","name":"_find_responsibility","line":144,"end_line":152,"hash":"d049061f7dd1686e0e9cb5a856b073db342800b7a83098911ba067f75c94b415"},{"id":"func/generate_bdi","name":"generate_bdi","line":155,"end_line":233,"hash":"5ae1d0511d3084a579d3de35b581902b80417d0ab9394f89a465b7c07383f445"},{"id":"func/_is_length_finish_reason_error","name":"_is_length_finish_reason_error","line":236,"end_line":241,"hash":"e2a3a36b18c4db163ef2bcac8c86b2de581cc0381c345e0067418e595a15fa79"},{"id":"func/build_bdi_prompts","name":"build_bdi_prompts","line":244,"end_line":295,"hash":"5957583f79b2943fb2faf38468e65f7995a606fe427800178dbc406fc04ccab7"},{"id":"func/assemble_scenario_spec","name":"assemble_scenario_spec","line":298,"end_line":342,"hash":"dc3abfa5cb86f9cfe4dab0414493baef561212a0fe62f7766e9291bc4fd916c9"}]}
# mutate4py-manifest-end
