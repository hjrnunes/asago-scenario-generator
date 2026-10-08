"""SP3 run orchestration — Stage 5 → Stage 6 → Stage 7.

Orchestrates the full SP3 pipeline:
  Stage 5: BDI generation (1 LLM call per scenario)
  Stage 6: Deterministic narrative, attack tree and Gherkin summary, then the
    scenario handoff (0 LLM calls)
  Stage 7: Validators + eval metrics + coverage gap analysis (0 LLM calls)

All LLM calls are logged to ``calls.jsonl``. A run manifest is written
at run end with stage summary, validation results, eval scorecard,
coverage gaps, input hashes, and prompt hashes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Sequence

import yaml

from asago_scenario_generator.stpa.infra.llm import (
    DEFAULT_TEMPERATURE as LLM_DEFAULT_TEMPERATURE,
    LLMClient,
    effective_model_config,
    effective_temperature,
)
from asago_scenario_generator.stpa.infra.manifest_helpers import (
    count_calls_by_stage,
    hash_model,
)
from asago_scenario_generator.stpa.infra.templates import (
    TemplateLoader,
    hash_prompt_templates,
)
from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.models.target_realization import (
    TargetOperationObservation,
    TargetRealizationResult,
)
from asago_scenario_generator.stpa.infra.yaml_io import write_yaml
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.enriched_threat_set import EnrichedThreatSet
from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionTargetProfile,
)
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.models.run_identity import ExecutionRunIdentity
from asago_scenario_generator.stpa.models.scenario_envelope import (
    GherkinSpec,
    ScenarioEnvelope,
)
from asago_scenario_generator.stpa.models.scenario_spec import DefenderBDI, ScenarioSpec
from asago_scenario_generator.stpa.models.scenario_context import (
    ScenarioGenerationContext,
)

from ._constants import PROMPTS_DIR
from .assembly import assemble_envelope
from .condition_family import (
    CONDITION_FAMILIES_FILENAME,
    CONDITION_FAMILIES_SCHEMA_VERSION,
    CandidateFamilyPlan,
    ConditionFamily,
    family_honoured,
)
from .content_surface import ContentSurfaceFacts, content_surface_facts
from .deduplication import (
    ScenarioDeduplication,
    build_testability_summary,
    deduplicate_scenario_specs,
)
from .stage5.wire import BDIGenerationResult
from .stage5.assemble import assemble_scenario_spec, parse_ica_slot_id
from .stage5.generate import generate_bdi_for_context, is_bdi_length_retry_exhausted
from .stage5.defender import populate_defender_bdi
from .stage5.shape_step import (
    ShapeStepConfig,
    apply_shape_step,
    observed_operation_names,
)
from .context import build_scenario_generation_context
from .coverage import compute_coverage_gaps, write_coverage_gaps
from .eval_metrics import compute_eval_scorecard, write_eval_scorecard
from .realized_operation import realized_operation
from .target_profile_publication import publish_execution_target_profile
from .presentation import render_scenario_summary, validate_scenario_summary
from .handoff import (
    ScenarioHandoff,
    Stage1aSource,
    build_scenario_handoff,
    handoff_ownership_violations,
    write_scenario_handoff,
)
from .target_observations import (
    TARGET_OBSERVATIONS_FILENAME,
    TargetObservationSnapshot,
)
from asago_scenario_generator.stpa.observation_contract import (
    OBSERVATION_CONTRACT_FILENAME,
    ObservationContract,
    default_observation_contract,
    write_observation_contract,
)
from .validators import (
    TraceabilityError,
    ValidationResult,
    validate_bdi_grounding,
    validate_loss_hazard_id_references,
    validate_traceability,
    validate_tree_factor_evidence_coverage,
    validate_vulnerability_completeness,
)

DEFAULT_TEMPERATURE = LLM_DEFAULT_TEMPERATURE
TESTABILITY_FILENAME = "testability.yaml"

__all__ = [
    "SP3CandidateOutcome",
    "SP3CandidateStatus",
    "SP3RunResult",
    "run_sp3",
]


class SP3CandidateStatus(str, Enum):
    """One terminal lifecycle status for a requested SP3 candidate."""

    published = "published"
    # Phase 3.2: ``kind: none`` marks a functional test.  It is persisted for
    # the owner's information but never enters the execution bundle.
    functional_test = "functional_test"
    generation_failed = "generation_failed"
    rendering_failed = "rendering_failed"
    publication_failed = "publication_failed"
    skipped = "skipped"


@dataclass(frozen=True)
class SP3CandidateOutcome:
    """Terminal outcome for one exact scenario/slot/ICA candidate."""

    scenario_id: str
    ica_slot_id: str
    ica_id: str | None
    status: SP3CandidateStatus
    diagnostics: tuple[str, ...] = ()


@dataclass
class SP3RunResult:
    """Result of a full SP3 run."""

    scenario_specs: list[ScenarioSpec] = field(default_factory=list)
    scenario_envelopes: list[ScenarioEnvelope] = field(default_factory=list)
    eval_scorecard: dict = field(default_factory=dict)
    coverage_gaps: dict = field(default_factory=dict)
    stage_errors: list[str] = field(default_factory=list)
    validation_errors: list[str] = field(default_factory=list)
    # Phase 3.2 functional-test specs (``kind: none``).  They are persisted
    # under scenarios/ but never enter scenario_specs, the bundle, or the
    # obligation accounting above.
    functional_test_specs: list[ScenarioSpec] = field(default_factory=list)
    # A real SP3 run always returns a tuple, including ``()`` when no
    # candidates were requested.  Legacy adapters that predate this field may
    # leave it absent/None; synthesis accounting treats that as unknown.
    candidate_outcomes: tuple[SP3CandidateOutcome, ...] = ()


@dataclass
class _CandidateOutcomeBuilder:
    """Mutable assembly state kept private until a run reaches its return."""

    scenario_id: str
    ica_slot_id: str
    ica_id: str | None
    status: SP3CandidateStatus | None = None
    diagnostics: list[str] = field(default_factory=list)

    def terminal(self) -> SP3CandidateOutcome:
        """Freeze this candidate exactly once for public result accounting."""
        return SP3CandidateOutcome(
            scenario_id=self.scenario_id,
            ica_slot_id=self.ica_slot_id,
            ica_id=self.ica_id,
            status=self.status or SP3CandidateStatus.skipped,
            diagnostics=tuple(self.diagnostics),
        )


@dataclass(frozen=True)
class _Stage5ThreatResult:
    """One threat outcome plus whether provider failures should open the circuit."""

    scenario_spec: ScenarioSpec | None
    abort_remaining: bool = False


def run_sp3(
    *,
    llm_client: LLMClient,
    enriched_threat_set: EnrichedThreatSet,
    control_structure: ControlStructure,
    loss_analysis: LossAnalysis,
    run_dir: Path,
    capability_profile: CapabilityProfile | None = None,
    max_workers: int = 1,
    temperature: float | None = None,
    scenario_contexts: Mapping[str, ScenarioGenerationContext] | None = None,
    execution_target_profile: ExecutionTargetProfile | None = None,
    target_realization: TargetRealizationResult | None = None,
    target_observations: TargetObservationSnapshot | None = None,
    observation_contract: ObservationContract | None = None,
    enriched_operations: Mapping[str, str] | None = None,
    stage_1a_source: Stage1aSource | None = None,
    condition_families: Sequence[CandidateFamilyPlan] | None = None,
    shape_config: ShapeStepConfig = ShapeStepConfig(),
) -> SP3RunResult:
    """Run the full SP3 pipeline: Stage 5 → Stage 6 → Stage 7.

    Args:
        llm_client: LLM client for making completion calls.
        enriched_threat_set: SP2 enriched threat set.
        control_structure: SP1 control structure.
        loss_analysis: SP1 loss analysis.
        run_dir: Directory for output artifacts.
        capability_profile: Optional SP1 capability profile for Stage 5
            prompt grounding and envelope enrichment.  When provided,
            envelopes are enriched with ``system_context`` and
            ``consumer_hints`` blocks.
        max_workers: Worker count recorded in the run manifest.
        temperature: Explicit LLM temperature override. When omitted, use the
            resolved client temperature (default 0.4).
        scenario_contexts: Optional exact contexts keyed by scenario ID
            (``SCN-NNN``) or, for callers with one candidate per ICA, by ICA
            ID. This is the inward synthesis adapter for routed obligations
            and proven reachable capabilities; ordinary standalone runs build
            the same closed context from their SP1/SP2 authority.
        execution_target_profile: Optional typed target or simulation inventory
            used only for deterministic producer classification. Runtime
            bindings and endpoints remain consumer-owned.
        target_realization: Optional intact additive realization artifact. It
            supplies only the exact operation already selected for each
            baseline control action; Stage 5 cannot remap it.
        target_observations: Optional target-only state/read observations
            paired with ``execution_target_profile``. They supplement Stage 5
            comparison grounding without changing the systemic context.
        observation_contract: Optional gold-free, target-agnostic capture
            contract. Normal handoff synthesis uses the frozen live
            qualification contract when this is omitted; historical
            execution-design callers may omit it to preserve legacy metadata
            behavior.
        enriched_operations: Verified operation view assembled from the run's
            ``control-action-enrichment.yaml`` sidecar and independently
            verified target-realization baseline rows. It maps each eligible
            control-action id to its exact documented operation identity.
            Only these verified mappings name an operation in the published
            handoff's ``documented_operations``; absent rows leave the list
            unchanged.
        stage_1a_source: The run's Stage 1a acceptance record (``pinned``
            when the loss-analysis graph was supplied, ``derived`` when it
            was generated).  The published handoff's constraint authorities
            derive from it and from the actual loss-analysis constraint
            records, so a derived/proposed constraint never publishes as
            reviewed.  ``None`` leaves the derivation to the constraint
            records alone.
        condition_families: Optional family plans aligned with
            ``enriched_threat_set.structural_threats``. Each plan's family is
            rendered as a Stage 5 condition hint, and the run writes
            ``condition-families.yaml`` with the hint, the capped-out
            families, and whether the published condition honoured the hint.
        shape_config: Switches for the shape step that runs after Stage 5
            compiles each adversarial spec. The default keeps the
            forged-transcript channel out of the shape request.

    Returns:
        An :class:`SP3RunResult` with artifacts and diagnostics.
    """
    run_dir.mkdir(parents=True, exist_ok=True)
    effective_observation_contract = (
        observation_contract or default_observation_contract()
    )
    effective_observation_contract.verify_digest()
    write_observation_contract(
        effective_observation_contract,
        run_dir / OBSERVATION_CONTRACT_FILENAME,
    )
    run_started = datetime.now(timezone.utc)
    run_identity = ExecutionRunIdentity(
        run_id=f"synthesis-{run_started.strftime('%Y%m%dT%H%M%S.%fZ')}"
    )
    scenarios_dir = run_dir / "scenarios"
    scenarios_dir.mkdir(parents=True, exist_ok=True)
    loader = TemplateLoader(PROMPTS_DIR)
    temperature = effective_temperature(llm_client, temperature)

    stage_errors: list[str] = []
    candidate_builders = _candidate_outcome_builders(
        enriched_threat_set.structural_threats
    )
    _verify_sp3_target_inputs(
        run_dir=run_dir,
        structural_threats=enriched_threat_set.structural_threats,
        condition_families=condition_families,
        execution_target_profile=execution_target_profile,
        target_observations=target_observations,
        target_realization=target_realization,
    )
    profile_published = _publish_execution_target_profile(
        run_dir, execution_target_profile, stage_errors
    )
    if profile_published:
        inputs = _SP3Inputs(
            llm_client=llm_client,
            enriched_threat_set=enriched_threat_set,
            control_structure=control_structure,
            loss_analysis=loss_analysis,
            run_dir=run_dir,
            scenarios_dir=scenarios_dir,
            loader=loader,
            temperature=temperature,
            capability_profile=capability_profile,
            scenario_contexts=scenario_contexts,
            execution_target_profile=execution_target_profile,
            target_realization=target_realization,
            target_observations=target_observations,
            observation_contract=effective_observation_contract,
            enriched_operations=enriched_operations,
            stage_1a_source=stage_1a_source,
            condition_families=condition_families,
            shape_config=shape_config,
        )
        scenario_specs, scenario_envelopes, functional_test_specs = _run_stages_5_and_6(
            inputs, stage_errors, candidate_builders
        )
    else:
        scenario_specs = []
        scenario_envelopes = []
        functional_test_specs = []
    all_validation_errors, coverage_gaps, eval_scorecard = _stage7_outputs(
        scenario_envelopes,
        enriched_threat_set,
        control_structure,
        loss_analysis,
    )

    write_eval_scorecard(eval_scorecard, run_dir)
    write_coverage_gaps(coverage_gaps, run_dir)
    _write_manifest(
        run_dir=run_dir,
        llm_client=llm_client,
        enriched_threat_set=enriched_threat_set,
        control_structure=control_structure,
        loss_analysis=loss_analysis,
        scenario_envelopes=scenario_envelopes,
        validation_errors=all_validation_errors,
        max_workers=max_workers,
        temperature=temperature,
        stage_errors=stage_errors,
        run_identity=run_identity,
        run_started=run_started,
        target_observations=target_observations,
    )

    return SP3RunResult(
        scenario_specs=scenario_specs,
        scenario_envelopes=scenario_envelopes,
        eval_scorecard=eval_scorecard,
        coverage_gaps=coverage_gaps,
        stage_errors=stage_errors,
        validation_errors=all_validation_errors,
        candidate_outcomes=tuple(builder.terminal() for builder in candidate_builders),
        functional_test_specs=functional_test_specs,
    )


def _verify_sp3_target_inputs(
    *,
    run_dir: Path,
    structural_threats: Sequence[Any],
    condition_families: Sequence[CandidateFamilyPlan] | None,
    execution_target_profile: ExecutionTargetProfile | None,
    target_observations: TargetObservationSnapshot | None,
    target_realization: TargetRealizationResult | None,
) -> None:
    """Check the supplied target inputs.

    Accepted target observations are written before the realization is
    verified, so a later realization failure still leaves them in the run
    directory.
    """
    if condition_families is not None and len(condition_families) != len(
        structural_threats
    ):
        raise ValueError("condition_families must align with the structural threats")
    if execution_target_profile is not None:
        if not isinstance(execution_target_profile, ExecutionTargetProfile):
            raise TypeError(
                "execution_target_profile must be an ExecutionTargetProfile"
            )
        execution_target_profile.assert_integrity()
    if target_observations is not None:
        _verify_target_observations(target_observations, execution_target_profile)
        write_yaml(
            target_observations,
            run_dir / TARGET_OBSERVATIONS_FILENAME,
        )
    if target_realization is not None:
        _verify_target_realization(target_realization, execution_target_profile)


def _verify_target_observations(
    target_observations: TargetObservationSnapshot,
    execution_target_profile: ExecutionTargetProfile | None,
) -> None:
    """Require intact observations pinned to the supplied target profile."""
    if not isinstance(target_observations, TargetObservationSnapshot):
        raise TypeError("target_observations must be a TargetObservationSnapshot")
    target_observations.assert_integrity()
    if execution_target_profile is None:
        raise ValueError("target_observations requires execution_target_profile")
    if (
        target_observations.target_profile_digest
        != execution_target_profile.semantic_digest
    ):
        raise ValueError(
            "target_observations profile pin does not match target profile"
        )


def _verify_target_realization(
    target_realization: TargetRealizationResult,
    execution_target_profile: ExecutionTargetProfile | None,
) -> None:
    """Require an intact realization pinned to the supplied target profile."""
    if not isinstance(target_realization, TargetRealizationResult):
        raise TypeError("target_realization must be a TargetRealizationResult")
    target_realization.assert_integrity()
    if execution_target_profile is None:
        raise ValueError("target_realization requires execution_target_profile")
    if target_realization.profile_digest != execution_target_profile.semantic_digest:
        raise ValueError("target_realization profile pin does not match target profile")


@dataclass(frozen=True)
class _SP3Inputs:
    """The resolved run_sp3 inputs Stages 5 and 6 read; never mutated."""

    llm_client: LLMClient
    enriched_threat_set: EnrichedThreatSet
    control_structure: ControlStructure
    loss_analysis: LossAnalysis
    run_dir: Path
    scenarios_dir: Path
    loader: TemplateLoader
    temperature: float | None
    capability_profile: CapabilityProfile | None
    scenario_contexts: Mapping[str, ScenarioGenerationContext] | None
    execution_target_profile: ExecutionTargetProfile | None
    target_realization: TargetRealizationResult | None
    target_observations: TargetObservationSnapshot | None
    observation_contract: ObservationContract
    enriched_operations: Mapping[str, str] | None
    stage_1a_source: Stage1aSource | None
    condition_families: Sequence[CandidateFamilyPlan] | None
    shape_config: ShapeStepConfig


def _run_stages_5_and_6(
    inputs: _SP3Inputs,
    stage_errors: list[str],
    candidate_builders: list[_CandidateOutcomeBuilder],
) -> tuple[list[ScenarioSpec], list[Any], list[ScenarioSpec]]:
    """Generate Stage 5 specs, persist functional tests, and build envelopes.

    Returns the non-functional scenario specs, their Stage 6 envelopes, and
    the functional-test specs.
    """
    run_dir = inputs.run_dir
    profile = inputs.execution_target_profile
    observed_operations = observed_operation_names(profile)
    scenario_specs = _collect_stage5_specs(
        inputs.llm_client,
        inputs.enriched_threat_set,
        inputs.control_structure,
        inputs.loss_analysis,
        run_dir,
        inputs.loader,
        inputs.temperature,
        stage_errors,
        capability_profile=inputs.capability_profile,
        scenario_contexts=inputs.scenario_contexts,
        execution_target_profile=profile,
        target_realization=inputs.target_realization,
        target_observations=inputs.target_observations,
        observation_contract=inputs.observation_contract,
        candidate_builders=candidate_builders,
        content_surface=content_surface_facts(inputs.capability_profile),
        condition_families=inputs.condition_families,
    )
    functional_test_specs = [spec for spec in scenario_specs if spec.is_functional_test]
    shaped_specs = apply_shape_step(
        [spec for spec in scenario_specs if not spec.is_functional_test],
        llm_client=inputs.llm_client,
        run_dir=run_dir,
        execution_target_profile=profile,
        config=inputs.shape_config,
        temperature=inputs.temperature,
        loader=inputs.loader,
    )
    # Deduplication follows the shape step: a duplicate group keeps the
    # scenario whose shape the model proposed.
    shaped_by_id = {spec.scenario_id: spec for spec in shaped_specs}
    deduplication_by_scenario = deduplicate_scenario_specs(
        [shaped_by_id.get(spec.scenario_id, spec) for spec in scenario_specs]
    )
    (run_dir / TESTABILITY_FILENAME).write_text(
        yaml.safe_dump(
            build_testability_summary(deduplication_by_scenario),
            sort_keys=False,
            allow_unicode=True,
        ),
        encoding="utf-8",
    )
    if inputs.condition_families is not None:
        _write_condition_families(
            run_dir, candidate_builders, inputs.condition_families, scenario_specs
        )
    _persist_functional_test_candidates(
        functional_test_specs,
        inputs.scenarios_dir,
        inputs.capability_profile,
        inputs.control_structure,
        stage_errors,
        candidate_builders,
        loss_analysis=inputs.loss_analysis,
        environment_bound=profile is not None,
        enriched_operations=inputs.enriched_operations,
        observed_operations=observed_operations,
        stage_1a_source=inputs.stage_1a_source,
        deduplication_by_scenario=deduplication_by_scenario,
    )
    scenario_envelopes = _collect_stage6_artifacts(
        shaped_specs,
        inputs.control_structure,
        inputs.loss_analysis,
        inputs.scenarios_dir,
        stage_errors,
        capability_profile=inputs.capability_profile,
        candidate_builders=candidate_builders,
        environment_bound=profile is not None,
        enriched_operations=inputs.enriched_operations,
        observed_operations=observed_operations,
        stage_1a_source=inputs.stage_1a_source,
        deduplication_by_scenario=deduplication_by_scenario,
    )
    return shaped_specs, scenario_envelopes, functional_test_specs


def _candidate_outcome_builders(threats: list[Any]) -> list[_CandidateOutcomeBuilder]:
    """Create one stable candidate identity before any provider call."""
    return [
        _CandidateOutcomeBuilder(
            scenario_id=f"SCN-{index + 1:03d}",
            ica_slot_id=threat.ica_slot_id,
            ica_id=threat.ica_id,
        )
        for index, threat in enumerate(threats)
    ]


def _write_condition_families(
    run_dir: Path,
    candidate_builders: list[_CandidateOutcomeBuilder],
    condition_families: Sequence[CandidateFamilyPlan],
    scenario_specs: Sequence[ScenarioSpec],
) -> None:
    """Write each candidate's family hint and whether its condition used it."""
    specs = {spec.scenario_id: spec for spec in scenario_specs}
    rows = []
    for builder, plan in zip(candidate_builders, condition_families, strict=True):
        family = plan.family
        spec = specs.get(builder.scenario_id)
        if family is None:
            honoured = None
        elif spec is None:
            honoured = "no_scenario"
        else:
            honoured = family_honoured(family, spec.discriminating_condition)
        rows.append(
            {
                "scenario_id": builder.scenario_id,
                "ica_id": builder.ica_id,
                "family": family.as_log() if family is not None else None,
                "binding": family.binding if family is not None else None,
                "capped_out": [item.as_log() for item in plan.capped_out],
                "honoured": honoured,
            }
        )
    (run_dir / CONDITION_FAMILIES_FILENAME).write_text(
        yaml.safe_dump(
            {"schema_version": CONDITION_FAMILIES_SCHEMA_VERSION, "scenarios": rows},
            sort_keys=False,
            allow_unicode=True,
        ),
        encoding="utf-8",
    )


def _candidate_builder_at(
    candidate_builders: list[_CandidateOutcomeBuilder] | None,
    index: int,
) -> _CandidateOutcomeBuilder | None:
    """Resolve one candidate outcome by the stable threat order."""
    if candidate_builders is None or index >= len(candidate_builders):
        return None
    return candidate_builders[index]


def _record_stage5_candidate(
    result: _Stage5ThreatResult,
    builder: _CandidateOutcomeBuilder | None,
    stage_errors: list[str],
    prior_error_count: int,
) -> None:
    """Record Stage 5 diagnostics while leaving valid specs available to Stage 6."""
    if builder is None:
        return
    diagnostics = stage_errors[prior_error_count:]
    if result.scenario_spec is not None:
        if diagnostics:
            builder.status = SP3CandidateStatus.generation_failed
            builder.diagnostics.extend(diagnostics)
        else:
            # Stage 6 assigns the terminal rendering/publication result.
            builder.status = None
        return
    builder.status = SP3CandidateStatus.generation_failed
    builder.diagnostics.extend(
        diagnostics or ["Stage 5 did not produce a scenario specification"]
    )


def _skip_stage5_remaining_candidates(
    candidate_builders: list[_CandidateOutcomeBuilder] | None,
    index: int,
) -> None:
    """Mark candidates after a bounded Stage 5 length circuit break."""
    if candidate_builders is None:
        return
    diagnostic = (
        "Not attempted after the bounded Stage 5 structured-output "
        "length-failure circuit breaker."
    )
    for remaining in candidate_builders[index + 1 :]:
        if remaining.status is None:
            remaining.status = SP3CandidateStatus.skipped
            remaining.diagnostics.append(diagnostic)


def _run_stage5_candidate(
    llm_client: LLMClient,
    threat: Any,
    control_structure: ControlStructure,
    loss_analysis: LossAnalysis,
    run_dir: Path,
    index: int,
    loader: TemplateLoader,
    temperature: float,
    stage_errors: list[str],
    *,
    capability_profile: CapabilityProfile | None,
    scenario_contexts: Mapping[str, ScenarioGenerationContext] | None,
    execution_target_profile: ExecutionTargetProfile | None = None,
    target_realization: TargetRealizationResult | None = None,
    target_observations: TargetObservationSnapshot | None = None,
    observation_contract: ObservationContract | None = None,
    candidate_builders: list[_CandidateOutcomeBuilder] | None = None,
    content_surface: ContentSurfaceFacts | None = None,
    condition_family: ConditionFamily | None = None,
) -> _Stage5ThreatResult:
    """Run one isolated Stage 5 candidate and record its outcome evidence."""
    prior_error_count = len(stage_errors)
    try:
        result = _run_stage5_for_threat(
            llm_client,
            threat,
            control_structure,
            run_dir,
            index,
            loader,
            temperature,
            stage_errors,
            loss_analysis=loss_analysis,
            capability_profile=capability_profile,
            scenario_contexts=scenario_contexts,
            execution_target_profile=execution_target_profile,
            target_realization=target_realization,
            target_observations=target_observations,
            observation_contract=observation_contract,
            content_surface=content_surface,
            condition_family=condition_family,
        )
    except Exception as exc:  # noqa: BLE001 - isolate one candidate
        stage_errors.append(f"Stage 5 candidate failed for SCN-{index + 1:03d}: {exc}")
        result = _Stage5ThreatResult(None)
    _record_stage5_candidate(
        result,
        _candidate_builder_at(candidate_builders, index),
        stage_errors,
        prior_error_count,
    )
    return result


def _collect_stage5_specs(
    llm_client: LLMClient,
    enriched_threat_set: EnrichedThreatSet,
    control_structure: ControlStructure,
    loss_analysis: LossAnalysis,
    run_dir: Path,
    loader: TemplateLoader,
    temperature: float,
    stage_errors: list[str],
    *,
    capability_profile: CapabilityProfile | None,
    scenario_contexts: Mapping[str, ScenarioGenerationContext] | None,
    execution_target_profile: ExecutionTargetProfile | None = None,
    target_realization: TargetRealizationResult | None = None,
    target_observations: TargetObservationSnapshot | None = None,
    observation_contract: ObservationContract | None = None,
    candidate_builders: list[_CandidateOutcomeBuilder] | None = None,
    content_surface: ContentSurfaceFacts | None = None,
    condition_families: Sequence[CandidateFamilyPlan] | None = None,
) -> list[ScenarioSpec]:
    """Generate and retain the valid Stage 5 specs in threat order."""
    specs: list[ScenarioSpec] = []
    threats = enriched_threat_set.structural_threats
    for index, threat in enumerate(threats):
        plan = condition_families[index] if condition_families is not None else None
        result = _run_stage5_candidate(
            llm_client,
            threat,
            control_structure,
            loss_analysis,
            run_dir,
            index,
            loader,
            temperature,
            stage_errors,
            capability_profile=capability_profile,
            scenario_contexts=scenario_contexts,
            execution_target_profile=execution_target_profile,
            target_realization=target_realization,
            target_observations=target_observations,
            observation_contract=observation_contract,
            candidate_builders=candidate_builders,
            content_surface=content_surface,
            condition_family=plan.family if plan is not None else None,
        )
        if result.scenario_spec is not None:
            specs.append(result.scenario_spec)
        if result.abort_remaining:
            _record_stage5_abort(stage_errors, len(threats) - index - 1)
            _skip_stage5_remaining_candidates(candidate_builders, index)
            break
    return specs


def _record_stage5_abort(stage_errors: list[str], remaining: int) -> None:
    """Record a bounded Stage 5 circuit-breaker diagnostic when needed."""
    if remaining:
        stage_errors.append(
            "Stage 5 aborted "
            f"{remaining} remaining threats after repeated structured-output "
            "length failures. Verify the serving runtime's structured-output "
            "configuration before retrying the run."
        )


def _write_scenario_handoff_artifacts(
    envelope: ScenarioEnvelope,
    scenarios_dir: Path,
    *,
    loss_analysis: LossAnalysis | None,
    environment_bound: bool,
    enriched_operations: Mapping[str, str] | None = None,
    observed_operations: tuple[str, ...] | None = None,
    stage_1a_source: Stage1aSource | None = None,
    deduplication: ScenarioDeduplication | None = None,
) -> ScenarioHandoff:
    """Write the versioned scenario handoff for one published scenario.

    The normal product run publishes scenario meaning only: narrative, attack
    tree, Gherkin and necessary metadata, with the semantic failure criterion
    and the safe alternative retained. No execution projection, prepared text,
    delivery route, oracle selection, detector expression or judge prompt is
    written.
    """
    handoff = build_scenario_handoff(
        envelope,
        loss_analysis=loss_analysis,
        environment_bound=environment_bound,
        enriched_operations=enriched_operations,
        observed_operations=observed_operations,
        stage_1a_source=stage_1a_source,
        deduplication=deduplication,
    )
    violations = handoff_ownership_violations(handoff.model_dump(mode="json"))
    if violations:
        raise ValueError(
            "scenario handoff carries artifact-design content: " + "; ".join(violations)
        )
    write_scenario_handoff(handoff, scenarios_dir)
    return handoff


def _publish_stage6_artifacts(
    envelope: ScenarioEnvelope,
    scenarios_dir: Path,
    stage_errors: list[str],
    prior_error_count: int,
    builder: _CandidateOutcomeBuilder | None,
    *,
    loss_analysis: LossAnalysis | None = None,
    environment_bound: bool = False,
    enriched_operations: Mapping[str, str] | None = None,
    observed_operations: tuple[str, ...] | None = None,
    stage_1a_source: Stage1aSource | None = None,
    deduplication: ScenarioDeduplication | None = None,
) -> None:
    """Write one scenario companion set and assign its publication status."""
    try:
        _write_scenario_handoff_artifacts(
            envelope,
            scenarios_dir,
            loss_analysis=loss_analysis,
            environment_bound=environment_bound,
            enriched_operations=enriched_operations,
            observed_operations=observed_operations,
            stage_1a_source=stage_1a_source,
            deduplication=deduplication,
        )
    except Exception as exc:  # noqa: BLE001 - isolate publication failure
        diagnostic = (
            f"Stage 6 artifact publication failed for {envelope.scenario_id}: {exc}"
        )
        stage_errors.append(diagnostic)
        _mark_candidate_failure(
            [builder] if builder is not None else None,
            envelope.scenario_id,
            SP3CandidateStatus.publication_failed,
            tuple(stage_errors[prior_error_count:]),
        )
        return
    if builder is not None:
        builder.status = SP3CandidateStatus.published
        builder.diagnostics.extend(stage_errors[prior_error_count:])


def _persist_functional_test_candidates(
    specs: list[ScenarioSpec],
    scenarios_dir: Path,
    capability_profile: CapabilityProfile | None,
    control_structure: ControlStructure,
    stage_errors: list[str],
    candidate_builders: list[_CandidateOutcomeBuilder] | None,
    *,
    loss_analysis: LossAnalysis | None = None,
    environment_bound: bool = False,
    enriched_operations: Mapping[str, str] | None = None,
    observed_operations: tuple[str, ...] | None = None,
    stage_1a_source: Stage1aSource | None = None,
    deduplication_by_scenario: Mapping[str, ScenarioDeduplication] | None = None,
) -> None:
    """Persist ``kind: none`` candidates without any execution projection.

    Phase 3.2: a functional test is retained in the run for the owner's
    information.  It renders deterministically (no provider calls), never
    prepares an execution projection, and never enters the bundle index.  A
    functional scenario is *not* rejected for lacking an attacker.
    """
    for spec in specs:
        prior_error_count = len(stage_errors)
        try:
            narrative, tree, gherkin = render_scenario_summary(spec)
            envelope = assemble_envelope(
                scenario_id=spec.scenario_id,
                scenario_spec=spec,
                narrative=narrative,
                attack_tree=tree,
                gherkin_spec=gherkin,
                gherkin_raw=gherkin.to_feature_text(),
                capability_profile=capability_profile,
                control_structure=control_structure,
            )
            _write_scenario_handoff_artifacts(
                envelope,
                scenarios_dir,
                loss_analysis=loss_analysis,
                environment_bound=environment_bound,
                enriched_operations=enriched_operations,
                observed_operations=observed_operations,
                stage_1a_source=stage_1a_source,
                deduplication=(
                    deduplication_by_scenario.get(spec.scenario_id)
                    if deduplication_by_scenario is not None
                    else None
                ),
            )
        except Exception as exc:  # noqa: BLE001 - isolate publication failure
            diagnostic = (
                f"Functional-test publication failed for {spec.scenario_id}: {exc}"
            )
            stage_errors.append(diagnostic)
            _mark_candidate_failure(
                candidate_builders,
                spec.scenario_id,
                SP3CandidateStatus.publication_failed,
                tuple(stage_errors[prior_error_count:]),
            )
            continue
        builder = _candidate_builder_for(candidate_builders, spec.scenario_id)
        if builder is not None:
            builder.status = SP3CandidateStatus.functional_test
            builder.diagnostics.append(f"adversary kind none: {spec.adversary.gain}")


def _render_stage6_candidate(
    spec: ScenarioSpec,
    control_structure: ControlStructure,
    loss_analysis: LossAnalysis,
    scenarios_dir: Path,
    stage_errors: list[str],
    *,
    capability_profile: CapabilityProfile | None,
    candidate_builders: list[_CandidateOutcomeBuilder] | None = None,
    environment_bound: bool = False,
    enriched_operations: Mapping[str, str] | None = None,
    observed_operations: tuple[str, ...] | None = None,
    stage_1a_source: Stage1aSource | None = None,
    deduplication_by_scenario: Mapping[str, ScenarioDeduplication] | None = None,
) -> ScenarioEnvelope | None:
    """Render and persist one Stage 6 candidate, isolating all failure kinds."""
    prior_error_count = len(stage_errors)
    try:
        envelope = _run_stage6_for_spec(
            spec,
            control_structure,
            capability_profile=capability_profile,
        )
    except Exception as exc:  # noqa: BLE001 - isolate one candidate
        diagnostic = f"Stage 6 rendering failed for {spec.scenario_id}: {exc}"
        stage_errors.append(diagnostic)
        _mark_candidate_failure(
            candidate_builders,
            spec.scenario_id,
            SP3CandidateStatus.rendering_failed,
            tuple(stage_errors[prior_error_count:]),
        )
        return None
    builder = _candidate_builder_for(candidate_builders, spec.scenario_id)
    _publish_stage6_artifacts(
        envelope,
        scenarios_dir,
        stage_errors,
        prior_error_count,
        builder,
        loss_analysis=loss_analysis,
        environment_bound=environment_bound,
        enriched_operations=enriched_operations,
        observed_operations=observed_operations,
        stage_1a_source=stage_1a_source,
        deduplication=(
            deduplication_by_scenario.get(spec.scenario_id)
            if deduplication_by_scenario is not None
            else None
        ),
    )
    return envelope


def _mark_unresolved_stage6_candidates(
    candidate_builders: list[_CandidateOutcomeBuilder] | None,
) -> None:
    """Close any candidate left without a Stage 6 terminal status."""
    if candidate_builders is None:
        return
    for builder in candidate_builders:
        if builder.status is None:
            builder.status = SP3CandidateStatus.rendering_failed
            builder.diagnostics.append(
                "Stage 6 did not produce a terminal candidate outcome"
            )


def _collect_stage6_artifacts(
    scenario_specs: list[ScenarioSpec],
    control_structure: ControlStructure,
    loss_analysis: LossAnalysis,
    scenarios_dir: Path,
    stage_errors: list[str],
    *,
    capability_profile: CapabilityProfile | None,
    candidate_builders: list[_CandidateOutcomeBuilder] | None = None,
    environment_bound: bool = False,
    enriched_operations: Mapping[str, str] | None = None,
    observed_operations: tuple[str, ...] | None = None,
    stage_1a_source: Stage1aSource | None = None,
    deduplication_by_scenario: Mapping[str, ScenarioDeduplication] | None = None,
) -> list[ScenarioEnvelope]:
    """Concretize specs and write each accepted scenario companion set."""
    envelopes: list[ScenarioEnvelope] = []
    for spec in scenario_specs:
        envelope = _render_stage6_candidate(
            spec,
            control_structure,
            loss_analysis,
            scenarios_dir,
            stage_errors,
            capability_profile=capability_profile,
            candidate_builders=candidate_builders,
            environment_bound=environment_bound,
            enriched_operations=enriched_operations,
            observed_operations=observed_operations,
            stage_1a_source=stage_1a_source,
            deduplication_by_scenario=deduplication_by_scenario,
        )
        if envelope is not None:
            envelopes.append(envelope)
    _mark_unresolved_stage6_candidates(candidate_builders)
    return envelopes


def _candidate_builder_for(
    candidate_builders: list[_CandidateOutcomeBuilder] | None,
    scenario_id: str,
) -> _CandidateOutcomeBuilder | None:
    """Resolve one mutable outcome by exact scenario identity."""
    if candidate_builders is None:
        return None
    return next(
        (item for item in candidate_builders if item.scenario_id == scenario_id),
        None,
    )


def _mark_candidate_failure(
    candidate_builders: list[_CandidateOutcomeBuilder] | None,
    scenario_id: str,
    status: SP3CandidateStatus,
    diagnostics: tuple[str, ...],
) -> None:
    """Assign one terminal failure without creating duplicate candidate rows."""
    builder = _candidate_builder_for(candidate_builders, scenario_id)
    if builder is None:
        return
    builder.status = status
    builder.diagnostics.extend(diagnostics)


def _publish_execution_target_profile(
    run_dir: Path,
    profile: ExecutionTargetProfile | None,
    stage_errors: list[str],
) -> bool:
    """Persist the verified profile before any scenario work."""
    if profile is None:
        return True
    try:
        publish_execution_target_profile(run_dir, profile)
    except Exception as exc:  # noqa: BLE001 - isolate profile publication failure
        stage_errors.append(f"Execution target profile publication failed: {exc}")
        return False
    return True


def _stage7_outputs(
    scenario_envelopes: list[ScenarioEnvelope],
    enriched_threat_set: EnrichedThreatSet,
    control_structure: ControlStructure,
    loss_analysis: LossAnalysis,
) -> tuple[list[str], dict, dict]:
    """Validate accepted scenarios and derive coverage/evaluation outputs."""
    validation_errors: list[str] = []
    for envelope in scenario_envelopes:
        _validate_envelope_stage7(envelope, loss_analysis, validation_errors)
    trace_errors = validate_traceability(
        scenario_envelopes, enriched_threat_set, control_structure, loss_analysis
    )
    trace_error_msgs = _format_traceability_errors(trace_errors)
    all_validation_errors = validation_errors + trace_error_msgs
    coverage_gaps = compute_coverage_gaps(
        enriched_threat_set,
        control_structure,
        scenario_envelopes,
        loss_analysis,
        precomputed_trace_errors=trace_errors,
    )
    eval_scorecard = compute_eval_scorecard(
        scenario_envelopes,
        enriched_threat_set,
        control_structure,
        loss_analysis,
        stage_local_errors=validation_errors,
        traceability_errors=trace_error_msgs,
        coverage_gaps=coverage_gaps,
        precomputed_trace_errors=trace_errors,
    )
    return all_validation_errors, coverage_gaps, eval_scorecard


def _format_traceability_errors(errors: list[TraceabilityError]) -> list[str]:
    """Format traceability errors as human-readable messages."""
    return [f"{e.scenario_id}: broken {e.broken_link}" for e in errors]


def _run_stage5_for_threat(
    llm_client: LLMClient,
    threat,
    control_structure: ControlStructure,
    run_dir: Path,
    scenario_index: int,
    loader: TemplateLoader,
    temperature: float,
    stage_errors: list[str],
    *,
    loss_analysis: LossAnalysis,
    capability_profile: CapabilityProfile | None = None,
    scenario_contexts: Mapping[str, ScenarioGenerationContext] | None = None,
    execution_target_profile: ExecutionTargetProfile | None = None,
    target_realization: TargetRealizationResult | None = None,
    target_observations: TargetObservationSnapshot | None = None,
    observation_contract: ObservationContract | None = None,
    content_surface: ContentSurfaceFacts | None = None,
    condition_family: ConditionFamily | None = None,
) -> _Stage5ThreatResult:
    """Run Stage 5 BDI generation for a single threat."""
    slot_parts = parse_ica_slot_id(threat.ica_slot_id)
    target_resp_id = slot_parts["controller"]
    context = _stage5_context(
        threat,
        control_structure,
        loss_analysis,
        scenario_index,
        scenario_contexts,
        stage_errors,
    )
    if context is None:
        return _Stage5ThreatResult(None)
    defender_bdi = _stage5_defender_bdi(
        control_structure,
        target_resp_id,
        stage_errors,
        constraints=context.constraints,
    )
    if defender_bdi is None:
        return _Stage5ThreatResult(None)

    target_operation = _target_operation_for_context(target_realization, context)

    llm_result, failure = _stage5_bdi(
        llm_client,
        context,
        run_dir,
        loader,
        temperature,
        stage_errors,
        execution_target_profile=execution_target_profile,
        target_operation=target_operation,
        target_observations=target_observations,
        observation_contract=observation_contract,
        content_surface=content_surface,
        condition_family=condition_family,
    )
    if failure is not None:
        return failure

    spec = _stage5_spec(
        defender_bdi,
        llm_result,
        threat,
        control_structure,
        scenario_index,
        context,
        stage_errors,
    )
    if spec is None:
        return _Stage5ThreatResult(None)
    prior_error_count = len(stage_errors)
    _validate_stage5_spec(spec, control_structure, stage_errors)
    if len(stage_errors) != prior_error_count:
        return _Stage5ThreatResult(None)
    return _Stage5ThreatResult(spec)


def _stage5_bdi(
    llm_client: LLMClient,
    context: ScenarioGenerationContext,
    run_dir: Path,
    loader: TemplateLoader,
    temperature: float,
    stage_errors: list[str],
    *,
    target_operation: TargetOperationObservation | None,
    execution_target_profile: ExecutionTargetProfile | None,
    target_observations: TargetObservationSnapshot | None,
    observation_contract: ObservationContract | None,
    content_surface: ContentSurfaceFacts | None = None,
    condition_family: ConditionFamily | None = None,
) -> tuple[BDIGenerationResult | None, _Stage5ThreatResult | None]:
    """Generate one closed BDI result or one typed local failure."""
    llm_result, error = generate_bdi_for_context(
        llm_client,
        context,
        run_dir,
        loader=loader,
        temperature=temperature,
        target_operation=target_operation,
        execution_target_profile=execution_target_profile,
        target_observations=target_observations,
        observation_contract=observation_contract,
        content_surface=content_surface,
        condition_family=condition_family,
    )
    if error is None and llm_result is not None:
        return llm_result, None
    stage_errors.append(f"Stage 5 BDI generation failed: {error}")
    return None, _Stage5ThreatResult(
        None,
        abort_remaining=is_bdi_length_retry_exhausted(error),
    )


def _stage5_defender_bdi(
    control_structure: ControlStructure,
    target_resp_id: str,
    stage_errors: list[str],
    *,
    constraints=(),
) -> DefenderBDI | None:
    """Build deterministic defender BDI and retain a local failure."""
    try:
        return populate_defender_bdi(
            control_structure,
            target_resp_id,
            constraints,
        )
    except ValueError as exc:
        stage_errors.append(f"Stage 5: {exc}")
        return None


def _stage5_context(
    threat,
    control_structure: ControlStructure,
    loss_analysis: LossAnalysis,
    scenario_index: int,
    supplied: Mapping[str, ScenarioGenerationContext] | None,
    stage_errors: list[str],
) -> ScenarioGenerationContext | None:
    """Build or select one exact context and retain a local failure."""
    try:
        return _scenario_context_for_threat(
            threat,
            control_structure,
            loss_analysis,
            scenario_index,
            supplied,
        )
    except ValueError as exc:
        stage_errors.append(f"Stage 5 context: {exc}")
        return None


def _target_operation_for_context(
    realization: TargetRealizationResult | None,
    context: ScenarioGenerationContext,
) -> TargetOperationObservation | None:
    """Resolve the one exact operation already selected for this action."""
    return realized_operation(
        realization, context.target_control_path.control_action.action_id
    )


def _stage5_spec(
    defender_bdi: DefenderBDI,
    llm_result: BDIGenerationResult,
    threat,
    control_structure: ControlStructure,
    scenario_index: int,
    context: ScenarioGenerationContext,
    stage_errors: list[str],
) -> ScenarioSpec | None:
    """Compile one Stage 5 draft and retain an assembly failure locally."""
    try:
        return assemble_scenario_spec(
            defender_bdi,
            llm_result,
            threat,
            control_structure,
            scenario_index,
            scenario_context=context,
        )
    except ValueError as exc:
        stage_errors.append(f"Stage 5: {exc}")
        return None


def _scenario_context_for_threat(
    threat,
    control_structure: ControlStructure,
    loss_analysis: LossAnalysis,
    scenario_index: int,
    supplied: Mapping[str, ScenarioGenerationContext] | None,
) -> ScenarioGenerationContext:
    """Use an exact supplied context or build the standalone STPA adapter view."""
    context = _select_scenario_context(
        threat,
        control_structure,
        loss_analysis,
        scenario_index,
        supplied,
    )
    if not _scenario_context_matches_threat(context, threat, scenario_index):
        raise ValueError("supplied scenario context does not match selected threat")
    return context


def _select_scenario_context(
    threat,
    control_structure: ControlStructure,
    loss_analysis: LossAnalysis,
    scenario_index: int,
    supplied: Mapping[str, ScenarioGenerationContext] | None,
) -> ScenarioGenerationContext:
    """Select a supplied context or build the exact standalone adapter view.

    A context keyed by scenario ID wins, so several candidates of one ICA
    each keep their own identity; an ICA-keyed context is the fallback.
    """
    scenario_id = f"SCN-{scenario_index + 1:03d}"
    if supplied is not None:
        if scenario_id in supplied:
            return supplied[scenario_id]
        context_key = threat.ica_id or threat.ica_slot_id
        if context_key in supplied:
            return supplied[context_key]
    return build_scenario_generation_context(
        threat,
        control_structure,
        loss_analysis,
        scenario_id=scenario_id,
    )


def _scenario_context_matches_threat(
    context: ScenarioGenerationContext,
    threat,
    scenario_index: int,
) -> bool:
    """Check the context identity and exact ICA prose against one threat."""
    identity = context.scenario_identity
    return (
        identity.scenario_id == f"SCN-{scenario_index + 1:03d}"
        and identity.ica_slot_id == threat.ica_slot_id
        and identity.ica_id == threat.ica_id
        and context.ica.exact_ica_text == threat.ica_text
    )


def _validate_stage5_spec(
    spec: ScenarioSpec,
    control_structure: ControlStructure,
    stage_errors: list[str],
) -> None:
    """Run stage-local validators for a Stage 5 scenario spec."""
    _extend_validation_errors(
        (
            validate_bdi_grounding(spec, control_structure),
            validate_vulnerability_completeness(spec),
        ),
        stage_errors,
    )


def _run_stage6_for_spec(
    spec: ScenarioSpec,
    control_structure: ControlStructure,
    *,
    capability_profile: CapabilityProfile | None = None,
) -> ScenarioEnvelope:
    """Render one scenario's deterministic summary into its envelope.

    No execution projection is prepared: the scenario handoff does not carry
    one, so a scenario whose failure criterion has no downstream-compilable
    detector is still rendered and published, with the limitation reported
    downstream.
    """
    narrative, tree, gherkin = render_scenario_summary(spec)
    return assemble_envelope(
        scenario_id=spec.scenario_id,
        scenario_spec=spec,
        narrative=narrative,
        attack_tree=tree,
        gherkin_spec=gherkin,
        gherkin_raw=gherkin.to_feature_text(),
        capability_profile=capability_profile,
        control_structure=control_structure,
    )


def _validate_envelope_stage7(
    envelope: ScenarioEnvelope,
    loss_analysis: LossAnalysis,
    validation_errors: list[str],
) -> None:
    """Run stage-local validators for a single envelope in Stage 7."""
    _extend_validation_errors(
        (
            validate_tree_factor_evidence_coverage(
                envelope.attack_tree, envelope.scenario_spec
            ),
        ),
        validation_errors,
    )
    validation_errors.extend(validate_scenario_summary(envelope))

    id_text = _envelope_gherkin_text(envelope)
    if id_text:
        id_result = validate_loss_hazard_id_references(id_text, loss_analysis)
        if not id_result.passed:
            validation_errors.extend(id_result.errors)


def _extend_validation_errors(
    results: tuple[ValidationResult, ...],
    errors: list[str],
) -> None:
    """Append errors from each failed ValidationResult to *errors*."""
    for result in results:
        if not result.passed:
            errors.extend(result.errors)


def _envelope_gherkin_text(envelope: ScenarioEnvelope) -> str:
    """Extract Gherkin feature text from an envelope.

    Prefers ``gherkin_spec.to_feature_text()`` when the spec was
    successfully parsed (non-empty ``feature`` name) — this is guaranteed
    valid Gherkin ``.feature`` syntax. Falls back to ``gherkin_raw`` (the
    raw LLM response, which may be YAML rather than Gherkin) only when
    spec parsing failed, or to an empty string when neither is available.
    """
    spec = envelope.gherkin_spec
    if isinstance(spec, GherkinSpec) and spec.feature:
        return spec.to_feature_text()
    return envelope.gherkin_raw or ""


def _load_yaml_mapping(path: Path) -> dict | None:
    """Return the mapping in ``path``, or None if it is absent, malformed, or not one."""
    if not path.is_file():
        return None
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError:
        return None
    return data if isinstance(data, dict) else None


def _stage_1a_gate_statuses(run_dir: Path) -> dict[str, object]:
    """Carry the Stage 1a gate evidence into the product manifest.

    The SP1 manifest that first records the gate statuses is replaced by
    this one, so read them back from the persisted gates artifact rather
    than losing them (re-review should-fix item).
    """
    gates = _load_yaml_mapping(run_dir / "loss-analysis-gates.yaml")
    if gates is None:
        return {}
    statuses: dict[str, object] = {
        "risk_accounting": "passed"
        if gates.get("risk_accounting", {}).get("passed")
        else "failed",
        "hazard_graph_density": "passed" if gates.get("passed") else "failed",
    }
    if gates.get("revision_attempted"):
        statuses["graph_revision_call_count"] = gates.get("revision_call_count", 0)
        if gates.get("revision_applied"):
            statuses["hazard_graph_density"] = "passed_after_revision"
    if gates.get("normalization_warnings"):
        statuses["accounting_normalizations"] = len(gates["normalization_warnings"])
    return statuses


@dataclass(frozen=True)
class _PreservedStageKeys:
    """SP1-owned manifest keys this final manifest write must keep."""

    stage_1a: dict[str, Any] = field(default_factory=dict)
    post_review_loss_analysis_digest: str | None = None
    uncited_security_constraints: list[str] | None = None
    loss_analysis_input_hash: str | None = None


def _preserved_stage_keys(run_dir: Path) -> _PreservedStageKeys:
    """Read the SP1 manifest keys that ``count_calls_by_stage`` cannot rebuild.

    ``scenario_prod`` writes the last ``run-manifest.yaml`` of a product run
    and rebuilds ``stage_summary`` from ``calls.jsonl``.  That rebuild drops
    the keys SP1 owns: the Stage 1a ``source`` and call count, the advisory
    coverage-review record, the Stage 2 post-review digest, and the Stage 2
    uncited security constraints.  A pinned run
    also owns ``input_hashes.loss_analysis``, which must stay the digest of
    the supplied file rather than the canonical model hash.
    """
    manifest = _load_yaml_mapping(run_dir / "run-manifest.yaml") or {}
    stage_summary = manifest.get("stage_summary")
    if not isinstance(stage_summary, dict):
        return _PreservedStageKeys()
    stage_1a = dict(_mapping_or_empty(stage_summary.get("stage_1a")))
    stage_2 = _mapping_or_empty(stage_summary.get("stage_2"))
    uncited = stage_2.get("uncited_security_constraints")
    input_hashes = _mapping_or_empty(manifest.get("input_hashes"))
    pinned_hash = (
        input_hashes.get("loss_analysis")
        if stage_1a.get("source") == "pinned"
        else None
    )
    return _PreservedStageKeys(
        stage_1a=stage_1a,
        post_review_loss_analysis_digest=_text_or_none(
            stage_2.get("post_review_loss_analysis_digest")
        ),
        uncited_security_constraints=(
            [str(item) for item in uncited] if isinstance(uncited, list) else None
        ),
        loss_analysis_input_hash=_text_or_none(pinned_hash),
    )


def _mapping_or_empty(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _text_or_none(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _manifest_input_hashes(
    enriched_threat_set: EnrichedThreatSet,
    control_structure: ControlStructure,
    loss_analysis: LossAnalysis,
    preserved: _PreservedStageKeys,
    target_observations: TargetObservationSnapshot | None,
) -> dict[str, str]:
    input_hashes = {
        "enriched_threat_set": hash_model(enriched_threat_set),
        "control_structure": hash_model(control_structure),
        "loss_analysis": hash_model(loss_analysis),
    }
    if preserved.loss_analysis_input_hash is not None:
        # A pinned run's manifest input hash is the digest of the supplied
        # file, not the canonical model hash (spec Phase 5, qualification
        # rule 1: a qualifying run's manifest shows the pinned digest).
        input_hashes["loss_analysis"] = preserved.loss_analysis_input_hash
    if target_observations is not None:
        # The observation set's content digest pins the exact Stage 5
        # companion this run consumed (round 48 ruling 1); it is run-manifest
        # bookkeeping, not a schema field on any provider wire.
        input_hashes["target_observations"] = target_observations.content_digest
    return input_hashes


def _manifest_stage_summary(
    run_dir: Path, preserved: _PreservedStageKeys
) -> dict[str, Any]:
    stage_summary = count_calls_by_stage(run_dir)
    stage_summary["stage_2"] = dict(stage_summary.get("stage_2") or {})
    if preserved.post_review_loss_analysis_digest is not None:
        stage_summary["stage_2"]["post_review_loss_analysis_digest"] = (
            preserved.post_review_loss_analysis_digest
        )
    if preserved.uncited_security_constraints is not None:
        stage_summary["stage_2"]["uncited_security_constraints"] = (
            preserved.uncited_security_constraints
        )
    stage_1a_summary = dict(stage_summary.get("stage_1a") or {})
    # ``count_calls_by_stage`` owns the call and token totals; the SP1 block
    # supplies every key it cannot rebuild (``source``, the review record,
    # the pinned zero count) without overriding a counted total.
    for key, value in preserved.stage_1a.items():
        if key in ("call_count", "total_tokens") and key in stage_1a_summary:
            continue
        stage_1a_summary[key] = value
    stage_1a_summary.update(_stage_1a_gate_statuses(run_dir))
    if stage_1a_summary:
        stage_summary["stage_1a"] = stage_1a_summary
    return stage_summary


def _write_manifest(
    run_dir: Path,
    llm_client: LLMClient,
    enriched_threat_set: EnrichedThreatSet,
    control_structure: ControlStructure,
    loss_analysis: LossAnalysis,
    scenario_envelopes: list[ScenarioEnvelope],
    validation_errors: list[str],
    max_workers: int,
    temperature: float,
    stage_errors: list[str],
    run_identity: ExecutionRunIdentity,
    run_started: datetime,
    target_observations: TargetObservationSnapshot | None = None,
) -> None:
    """Write the run manifest YAML."""
    preserved = _preserved_stage_keys(run_dir)
    input_hashes = _manifest_input_hashes(
        enriched_threat_set,
        control_structure,
        loss_analysis,
        preserved,
        target_observations,
    )
    prompt_hashes = hash_prompt_templates(PROMPTS_DIR)
    stage_summary = _manifest_stage_summary(run_dir, preserved)

    manifest = {
        "run_id": run_identity.run_id,
        "run_dir": str(run_dir),
        "created_at": run_started.isoformat(),
        "model_config": effective_model_config(
            llm_client,
            temperature=temperature,
        ),
        "input_hashes": input_hashes,
        "prompt_hashes": prompt_hashes,
        "stage_summary": stage_summary,
        "scenario_count": len(scenario_envelopes),
        "validation_error_count": len(validation_errors),
        "validation_errors": validation_errors,
        "max_workers": max_workers,
        "stage_errors": stage_errors,
        "eval_scorecard_path": "eval-scorecard.yaml",
    }

    manifest_path = run_dir / "run-manifest.yaml"
    manifest_path.write_text(
        yaml.dump(
            manifest, default_flow_style=False, sort_keys=False, allow_unicode=True
        ),
        encoding="utf-8",
    )
