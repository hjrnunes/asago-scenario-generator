"""Stage 6 Call A — Attack narrative and temporal execution projection.

One LLM call per scenario produces a 7-step attack narrative as a
dialectic between attacker and defender BDIs.  The post-SP3 execution
projection is deterministic: causal factors translate into executable
temporal assertions and ordered scenario steps without any LLM call.
"""

from __future__ import annotations

from collections.abc import Sequence

import yaml
from pathlib import Path

from asago_scenario_generator.stpa.infra.llm import LLMClient
from asago_scenario_generator.stpa.infra.llm_helpers import safe_llm_call_raw
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.stpa.models.execution_envelope import (
    CausalFactor,
    CausalFactorKind,
    ScenarioStep,
    ScenarioStepKind,
    TemporalActionVector,
    TemporalAssertion,
    candidate_id_for,
    predicate_for,
    step_kind_for,
)
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.models.scenario_spec import ScenarioSpec
from asago_scenario_generator.stpa.threat_enum.technology_context import context_for

from ._constants import PROMPTS_DIR

__all__ = [
    "generate_narrative",
    "build_narrative_prompts",
    "derive_temporal_action_vector",
]


def generate_narrative(
    llm_client: LLMClient,
    scenario_spec: ScenarioSpec,
    run_dir: Path,
    loader: TemplateLoader | None = None,
    stage: str = "stage_6",
    step: str = "narrative",
    temperature: float = 0.4,
    capability_profile: CapabilityProfile | None = None,
) -> tuple[str | None, str | None]:
    """Execute the narrative LLM call.

    Args:
        llm_client: LLM client for making the completion call.
        scenario_spec: The scenario specification.
        run_dir: Directory for call logging.
        loader: Template loader (default: SP3 prompts directory).
        stage: Pipeline stage label.
        step: Sub-step label.
        temperature: LLM temperature.
        capability_profile: Optional capability profile used to ground
            technology-specific feedback mechanisms in the prompt.

    Returns:
        A tuple of (narrative_text or None, error_message or None).
    """
    if loader is None:
        loader = TemplateLoader(PROMPTS_DIR)

    system_prompt, user_prompt = build_narrative_prompts(
        scenario_spec,
        loader,
        capability_profile=capability_profile,
    )

    text, _result, error = safe_llm_call_raw(
        llm_client=llm_client,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        run_dir=run_dir,
        stage=stage,
        step=step,
        temperature=temperature,
    )

    if error is not None:
        return None, error
    return text, None


def build_narrative_prompts(
    scenario_spec: ScenarioSpec,
    loader: TemplateLoader,
    capability_profile: CapabilityProfile | None = None,
    projection_alignment: str | None = None,
) -> tuple[str, str]:
    """Build the system and user prompts for the narrative call.

    Args:
        scenario_spec: The scenario specification.
        loader: Template loader.
        capability_profile: Optional capability profile used to ground
            technology-specific feedback mechanisms in the prompt.
        projection_alignment: Optional rendered STPA projection alignment
            table shared by every Stage 6 prompt.  When ``None`` no table
            is included (backward compatible default).

    Returns:
        A tuple of (system_prompt, user_prompt).
    """
    scenario_spec_yaml = yaml.dump(
        scenario_spec.model_dump(mode="json", exclude_none=True),
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
    )

    loss_scenario = scenario_spec.loss_scenario
    ica_text = f"ICA type: {scenario_spec.ica_type.value} on {scenario_spec.target_control_action}"
    technology_context = context_for(capability_profile)

    system_prompt = loader.render_prompt(
        "stage6a_narrative_system.j2",
        projection_alignment=projection_alignment,
    )
    user_prompt = loader.render_prompt(
        "stage6a_narrative_user.j2",
        scenario_spec_yaml=scenario_spec_yaml,
        ica_text=ica_text,
        loss_scenario=loss_scenario,
        technology_context=technology_context,
        projection_alignment=projection_alignment,
    )

    return system_prompt, user_prompt


_STEP_TEXTS: dict[CausalFactorKind, str] = {
    CausalFactorKind.process_model_flaw: (
        "Process model part {source} is flawed before control action {action} is issued"
    ),
    CausalFactorKind.feedback_delay: (
        "Feedback channel {source} is delayed before control action {action} is issued"
    ),
    CausalFactorKind.sensor_anomaly: (
        "Sensor reporting through {source} is anomalous before control "
        "action {action} is issued"
    ),
    CausalFactorKind.actuator_anomaly: (
        "Actuator {source} is anomalous before control action {action} is issued"
    ),
}


def derive_temporal_action_vector(
    causal_factors: Sequence[CausalFactor],
    *,
    controller_id: str,
    control_action_id: str,
    uca_type: UCAType,
) -> TemporalActionVector:
    """Derive the deterministic temporal action vector for causal factors.

    Each causal factor maps to one executable temporal assertion and one
    ordered scenario step; a non-empty vector ends with the unsafe
    control action step for *control_action_id*.  The vector is linked
    to the canonical candidate identifier for the given controller,
    control action, and UCA type.

    Empty *causal_factors* produce an empty vector — no assertions and
    no steps are invented.

    Args:
        causal_factors: The mapped structural causal factors, in
            causal-factor order.
        controller_id: The owning responsibility identifier (RESP-N).
        control_action_id: The targeted control action (CA-X-Y).
        uca_type: The unsafe control action type.

    Returns:
        A :class:`TemporalActionVector` with canonical assertions and
        steps.
    """
    factors = list(causal_factors)
    assertions = [
        TemporalAssertion(
            assertion_id=f"TA-{index + 1}",
            order_index=index,
            kind=factor.kind,
            source_id=factor.source_id,
            predicate=predicate_for(factor.kind),
        )
        for index, factor in enumerate(factors)
    ]
    steps = [
        ScenarioStep(
            step_id=f"S-{index + 1}",
            order_index=index,
            kind=step_kind_for(factor.kind),
            source_id=factor.source_id,
            text=_STEP_TEXTS[factor.kind].format(
                source=factor.source_id,
                action=control_action_id,
            ),
        )
        for index, factor in enumerate(factors)
    ]
    if factors:
        steps.append(
            ScenarioStep(
                step_id=f"S-{len(factors) + 1}",
                order_index=len(factors),
                kind=ScenarioStepKind.unsafe_control_action,
                source_id=control_action_id,
                text=(
                    f"Unsafe control action {control_action_id} executes "
                    f"with {uca_type.value}"
                ),
            )
        )
    candidate_id = candidate_id_for(controller_id, control_action_id, uca_type)
    return TemporalActionVector(
        candidate_id=candidate_id,
        control_action_id=control_action_id,
        assertions=assertions,
        steps=steps,
    )


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-20T20:28:40Z","module_hash":"408de2fe35590fdecbdf0703f010f1130f657cf11ffcc8c4bdda35b32b0bc2c7","functions":[{"id":"func/generate_narrative","name":"generate_narrative","line":44,"end_line":91,"hash":"45b1b3df64e80ba8fb67270e38c724c45d26465aab5ef860721774f9e98b9a65"},{"id":"func/build_narrative_prompts","name":"build_narrative_prompts","line":94,"end_line":138,"hash":"3ef51999b5007904f372d31b08d352898c0c08679855caffc2cc181abe99c49e"},{"id":"func/derive_temporal_action_vector","name":"derive_temporal_action_vector","line":158,"end_line":230,"hash":"c9c3815f942598ff9bd6b67ca02a2cbcd446dd9934b5ee68957152a9653b9b63"}]}
# mutate4py-manifest-end
