"""SP3 run orchestration — Stage 5 → Stage 6 → Stage 7.

Orchestrates the full SP3 pipeline:
  Stage 5: BDI generation (1 LLM call per scenario)
  Stage 6: Narrative + attack tree + Gherkin (3 LLM calls per scenario, parallelizable)
  Stage 7: Validators + eval metrics + coverage gap analysis (0 LLM calls)

All LLM calls are logged to ``calls.jsonl``. A run manifest is written
at run end with stage summary, validation results, eval scorecard,
coverage gaps, input hashes, and prompt hashes.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Mapping

import yaml

from asago_scenario_generator.stpa.infra.llm import (
    DEFAULT_TEMPERATURE as LLM_DEFAULT_TEMPERATURE,
    LLMClient,
    effective_model_config,
    effective_temperature,
)
from asago_scenario_generator.stpa.infra.llm_helpers import (
    safe_llm_call,
    safe_llm_call_raw,
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
    TargetRealizationDisposition,
    TargetRealizationRow,
    TargetRealizationResult,
)
from asago_scenario_generator.stpa.infra.yaml_io import write_yaml
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.enriched_threat_set import EnrichedThreatSet
from asago_scenario_generator.stpa.models.execution_projection_v2 import (
    ExecutionRunIdentity,
)
from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionTargetProfile,
    ProfileBasis,
    RequestedEnvironmentBasis,
)
from asago_scenario_generator.stpa.models.loss_analysis import (
    LossAnalysis,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.models.scenario_envelope import (
    GherkinSpec,
    ScenarioEnvelope,
)
from asago_scenario_generator.stpa.models.scenario_spec import DefenderBDI, ScenarioSpec
from asago_scenario_generator.stpa.models.scenario_context import (
    ScenarioGenerationContext,
)

from ._constants import PROMPTS_DIR
from .authoring import (
    AUTHORING_STAGE,
    AUTHORED_STAGE_SUMMARY_KEY,
    assemble_authored_scenario_spec,
)
from .assembly import assemble_envelope
from .attack_tree import (
    ATTACK_TREE_MAX_COMPLETION_TOKENS,
    build_attack_tree_prompts,
    parse_attack_tree,
)
from .content_surface import ContentSurfaceFacts, content_surface_facts
from .bdi_generation import (
    BDIGenerationResult,
    assemble_scenario_spec,
    generate_bdi_for_context,
    is_bdi_length_retry_exhausted,
    parse_ica_slot_id,
    populate_defender_bdi,
)
from .context import build_scenario_generation_context
from .coverage import compute_coverage_gaps, write_coverage_gaps
from .execution_bundle import (
    ExecutionBundlePublication,
    publish_execution_bundle,
    publish_execution_target_profile,
)
from .execution_projection import (
    ExecutionProjectionPreparationError,
    ValidatedExecutionProjection,
    prepare_execution_projection,
)
from .eval_metrics import compute_eval_scorecard, write_eval_scorecard
from .gherkin import (
    GHERKIN_MAX_COMPLETION_TOKENS,
    apply_gherkin_identity_scaffold,
    build_gherkin_identity_scaffold,
    build_gherkin_prompts,
    find_security_constraint,
    parse_gherkin_spec,
)
from .narrative import (
    NARRATIVE_MAX_COMPLETION_TOKENS,
    build_narrative_prompts,
)
from .projection import (
    canonical_projection_data,
    export_projection_json,
    export_projection_yaml,
    project_execution,
)
from .prompt_alignment import render_projection_alignment_table
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
from .validators import (
    TraceabilityError,
    ValidationResult,
    validate_attack_tree_root_label,
    validate_bdi_grounding,
    validate_gherkin_structure,
    validate_loss_hazard_id_references,
    validate_traceability,
    validate_tree_factor_evidence_coverage,
    validate_tree_id_references,
    validate_vulnerability_completeness,
)

DEFAULT_TEMPERATURE = LLM_DEFAULT_TEMPERATURE

# Stage 6 produces rendering artifacts, not a second analysis.  Keep each
# provider response bounded by the artifact it is asked to render.  The
# values are also passed to prompt preflight so a configured model reserves
# enough room for its response before dispatch.
STAGE6_MAX_COMPLETION_TOKENS = {
    "narrative": NARRATIVE_MAX_COMPLETION_TOKENS,
    "attack_tree": ATTACK_TREE_MAX_COMPLETION_TOKENS,
    "gherkin": GHERKIN_MAX_COMPLETION_TOKENS,
}

__all__ = [
    "SP3CandidateOutcome",
    "SP3CandidateStatus",
    "SP3RunResult",
    "run_sp3",
]

_EMPTY_ATTACK_TREE: dict = {"root": "", "branches": [], "leaves": []}
_EMPTY_GHERKIN_SPEC = GherkinSpec(
    feature="",
    scenario="",
    given=[],
    when=[],
    then_expected=[],
    then_actual=[],
)


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


def _resolve_requested_environment_basis(
    profile: ExecutionTargetProfile | None,
    requested: RequestedEnvironmentBasis | None,
) -> RequestedEnvironmentBasis | None:
    """Derive Stage 5's basis without exposing profile facts to the model."""
    if profile is None:
        return requested
    profile_basis = (
        RequestedEnvironmentBasis.simulation_profile
        if profile.basis is ProfileBasis.simulation
        else RequestedEnvironmentBasis.target_profile
    )
    if requested is not None and requested is not profile_basis:
        raise ValueError(
            "requested_environment_basis does not match execution target profile"
        )
    return profile_basis


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
    requested_environment_basis: RequestedEnvironmentBasis | None = None,
    target_realization: TargetRealizationResult | None = None,
    target_observations: TargetObservationSnapshot | None = None,
    render_presentation: bool = False,
    authored_scenarios: Mapping[str, Any] | None = None,
    publish_execution_bundle: bool = True,
    enriched_operations: Mapping[str, str] | None = None,
    stage_1a_source: Stage1aSource | None = None,
) -> SP3RunResult:
    """Run the full SP3 pipeline: Stage 5 → Stage 6 → Stage 7.

    Args:
        llm_client: LLM client for making completion calls.
        enriched_threat_set: SP2 enriched threat set.
        control_structure: SP1 control structure.
        loss_analysis: SP1 loss analysis.
        run_dir: Directory for output artifacts.
        capability_profile: Optional SP1 capability profile for Stage 5/6
            prompt grounding and envelope enrichment.  When provided,
            envelopes are enriched with ``system_context`` and
            ``consumer_hints`` blocks.
        max_workers: Maximum parallel workers for LLM calls.
        temperature: Explicit LLM temperature override. When omitted, use the
            resolved client temperature (default 0.4).
        scenario_contexts: Optional exact contexts keyed by ICA ID. This is the
            inward synthesis adapter for routed obligations and proven reachable
            capabilities; ordinary standalone runs build the same closed context
            from their SP1/SP2 authority.
        execution_target_profile: Optional typed target or simulation inventory
            used only for deterministic producer classification. Runtime
            bindings and endpoints remain consumer-owned.
        requested_environment_basis: Optional explicit target or simulation
            basis for Stage 5 route materialization. When a profile is
            supplied, its basis is authoritative and must agree with this
            selection.
        render_presentation: Opt in to three additional model-authored renderings.
            Default summaries are deterministic and do not call a provider.
        target_realization: Optional intact additive realization artifact. It
            supplies only the exact operation already selected for each
            baseline control action; Stage 5 cannot remap it.
        target_observations: Optional target-only state/read observations
            paired with ``execution_target_profile``. They supplement Stage 5
            comparison grounding without changing the systemic context.
        authored_scenarios: Optional Phase 4 authored bundles keyed by exact
            ICA ID (target-derived mode).  When a threat's ICA ID is present,
            Stage 5 assembles its spec deterministically from the validated
            authoring record instead of calling the BDI provider; other
            threats produce no scenario.
        publish_execution_bundle: Publish the execution projection/bundle
            companions.  The normal product run sets this to ``False`` and
            publishes the versioned scenario handoff instead: narrative,
            attack tree, Gherkin and necessary metadata only, with no
            prepared message, delivery route, oracle selection, detector
            expression or executable setup.  The historical reader path and
            the ``stpa-run`` diagnostic keep the default ``True``.
        enriched_operations: Verified view of the run's
            ``control-action-enrichment.yaml`` sidecar, mapping each enriched
            control-action id to its exact documented operation identity.
            Only these verified rows name an operation in the published
            handoff's ``documented_operations``; absent rows leave the list
            unchanged.
        stage_1a_source: The run's Stage 1a acceptance record (``pinned``
            when the loss-analysis graph was supplied, ``derived`` when it
            was generated).  The published handoff's constraint authorities
            derive from it and from the actual loss-analysis constraint
            records, so a derived/proposed constraint never publishes as
            reviewed.  ``None`` leaves the derivation to the constraint
            records alone.

    Returns:
        An :class:`SP3RunResult` with artifacts and diagnostics.
    """
    run_dir.mkdir(parents=True, exist_ok=True)
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
    if execution_target_profile is not None:
        if not isinstance(execution_target_profile, ExecutionTargetProfile):
            raise TypeError(
                "execution_target_profile must be an ExecutionTargetProfile"
            )
        execution_target_profile.assert_integrity()
    if target_observations is not None:
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
        write_yaml(
            target_observations,
            run_dir / TARGET_OBSERVATIONS_FILENAME,
        )
    requested_basis = _resolve_requested_environment_basis(
        execution_target_profile, requested_environment_basis
    )
    if target_realization is not None:
        if not isinstance(target_realization, TargetRealizationResult):
            raise TypeError("target_realization must be a TargetRealizationResult")
        target_realization.assert_integrity()
        if execution_target_profile is None:
            raise ValueError("target_realization requires execution_target_profile")
        if (
            target_realization.profile_digest
            != execution_target_profile.semantic_digest
        ):
            raise ValueError(
                "target_realization profile pin does not match target profile"
            )
    profile_published = _publish_execution_target_profile(
        run_dir, execution_target_profile, stage_errors
    )
    functional_test_specs: list[ScenarioSpec] = []
    handoff_publication = not publish_execution_bundle
    environment_bound = execution_target_profile is not None
    if profile_published:
        scenario_specs = _collect_stage5_specs(
            llm_client,
            enriched_threat_set,
            control_structure,
            loss_analysis,
            run_dir,
            loader,
            temperature,
            stage_errors,
            capability_profile=capability_profile,
            scenario_contexts=scenario_contexts,
            requested_environment_basis=requested_basis,
            target_realization=target_realization,
            target_observations=target_observations,
            candidate_builders=candidate_builders,
            content_surface=content_surface_facts(capability_profile),
            authored_scenarios=authored_scenarios,
            # The normal handoff publication requests scenario semantics only;
            # the historical bundle-publication path keeps the execution wire.
            execution_design=publish_execution_bundle,
        )
        # The run-level wire branch is fixed here, before any Stage 6 work:
        # one structured omission basis anywhere in the assembled specs
        # upgrades every published projection in the run to v3 (bundle v2);
        # a run with none keeps the legacy v2/v1 pair unchanged.
        structured_omission = any(
            spec.omission_evidence_basis is not None for spec in scenario_specs
        )
        observation_snapshot_digest = (
            target_observations.content_digest
            if target_observations is not None
            else None
        )
        functional_test_specs = [
            spec for spec in scenario_specs if spec.is_functional_test
        ]
        _persist_functional_test_candidates(
            functional_test_specs,
            scenarios_dir,
            capability_profile,
            control_structure,
            stage_errors,
            candidate_builders,
            handoff_publication=handoff_publication,
            loss_analysis=loss_analysis,
            environment_bound=environment_bound,
            enriched_operations=enriched_operations,
            stage_1a_source=stage_1a_source,
        )
        scenario_specs = [
            spec for spec in scenario_specs if not spec.is_functional_test
        ]
        scenario_envelopes, validated_projections = _collect_stage6_artifacts(
            llm_client,
            scenario_specs,
            control_structure,
            loss_analysis,
            run_dir,
            scenarios_dir,
            loader,
            temperature,
            max_workers,
            stage_errors,
            capability_profile=capability_profile,
            run_identity=run_identity,
            execution_target_profile=execution_target_profile,
            target_realization=target_realization,
            render_presentation=render_presentation,
            candidate_builders=candidate_builders,
            structured_omission=structured_omission,
            observation_snapshot_digest=observation_snapshot_digest,
            handoff_publication=handoff_publication,
            environment_bound=environment_bound,
            enriched_operations=enriched_operations,
            stage_1a_source=stage_1a_source,
        )
    else:
        scenario_specs = []
        scenario_envelopes = []
        validated_projections = []
    successful_candidate_ids = {
        envelope.scenario_id for envelope, _projection in validated_projections
    }
    if not profile_published:
        publication_error = _latest_stage_error(stage_errors)
    elif handoff_publication:
        # The normal product run publishes the scenario handoff and no
        # execution projection or bundle.
        successful_candidate_ids = {
            envelope.scenario_id for envelope in scenario_envelopes
        }
        publication_error = None
    else:
        publication_error = _publish_validated_projections(
            run_dir, run_identity, validated_projections, stage_errors
        )
    if publication_error is not None:
        _mark_publication_failures(
            candidate_builders,
            successful_candidate_ids,
            publication_error,
        )
    all_validation_errors, coverage_gaps, eval_scorecard = _stage7_outputs(
        scenario_envelopes,
        scenario_specs,
        enriched_threat_set,
        control_structure,
        loss_analysis,
        deterministic_presentation=not render_presentation,
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
        authored_scenarios=authored_scenarios,
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


def _latest_stage_error(stage_errors: list[str]) -> str | None:
    """Return the most recent publication diagnostic when one was appended."""
    return stage_errors[-1] if stage_errors else None


def _mark_publication_failures(
    candidate_builders: list[_CandidateOutcomeBuilder],
    scenario_ids: set[str],
    diagnostic: str,
) -> None:
    """Convert each affected successful candidate to one publication failure."""
    for builder in candidate_builders:
        if builder.scenario_id not in scenario_ids:
            continue
        if builder.status is SP3CandidateStatus.published:
            builder.status = SP3CandidateStatus.publication_failed
            builder.diagnostics.append(diagnostic)


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
    requested_environment_basis: RequestedEnvironmentBasis | None,
    target_realization: TargetRealizationResult | None = None,
    target_observations: TargetObservationSnapshot | None = None,
    candidate_builders: list[_CandidateOutcomeBuilder] | None = None,
    content_surface: ContentSurfaceFacts | None = None,
    authored_scenarios: Mapping[str, Any] | None = None,
    execution_design: bool = True,
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
            requested_environment_basis=requested_environment_basis,
            target_realization=target_realization,
            target_observations=target_observations,
            content_surface=content_surface,
            authored_scenarios=authored_scenarios,
            execution_design=execution_design,
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
    requested_environment_basis: RequestedEnvironmentBasis | None,
    target_realization: TargetRealizationResult | None = None,
    target_observations: TargetObservationSnapshot | None = None,
    candidate_builders: list[_CandidateOutcomeBuilder] | None = None,
    content_surface: ContentSurfaceFacts | None = None,
    authored_scenarios: Mapping[str, Any] | None = None,
    execution_design: bool = True,
) -> list[ScenarioSpec]:
    """Generate and retain the valid Stage 5 specs in threat order."""
    specs: list[ScenarioSpec] = []
    threats = enriched_threat_set.structural_threats
    for index, threat in enumerate(threats):
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
            requested_environment_basis=requested_environment_basis,
            target_realization=target_realization,
            target_observations=target_observations,
            candidate_builders=candidate_builders,
            content_surface=content_surface,
            authored_scenarios=authored_scenarios,
            execution_design=execution_design,
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


def _stage6_diagnostics(
    stage_errors: list[str],
    prior_error_count: int,
    fallback: str,
) -> tuple[str, ...]:
    """Return new Stage 6 diagnostics, retaining one fallback when absent."""
    return tuple(stage_errors[prior_error_count:]) or (fallback,)


def _write_scenario_handoff_artifacts(
    envelope: ScenarioEnvelope,
    scenarios_dir: Path,
    *,
    loss_analysis: LossAnalysis | None,
    environment_bound: bool,
    enriched_operations: Mapping[str, str] | None = None,
    stage_1a_source: Stage1aSource | None = None,
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
        stage_1a_source=stage_1a_source,
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
    projection_doc: ValidatedExecutionProjection | dict | None,
    scenarios_dir: Path,
    stage_errors: list[str],
    prior_error_count: int,
    builder: _CandidateOutcomeBuilder | None,
    *,
    handoff_publication: bool = False,
    loss_analysis: LossAnalysis | None = None,
    environment_bound: bool = False,
    enriched_operations: Mapping[str, str] | None = None,
    stage_1a_source: Stage1aSource | None = None,
) -> None:
    """Write one scenario companion set and assign its publication status."""
    try:
        if handoff_publication:
            _write_scenario_handoff_artifacts(
                envelope,
                scenarios_dir,
                loss_analysis=loss_analysis,
                environment_bound=environment_bound,
                enriched_operations=enriched_operations,
                stage_1a_source=stage_1a_source,
            )
        else:
            _write_scenario_artifacts(envelope, scenarios_dir, projection_doc)
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
    handoff_publication: bool = False,
    loss_analysis: LossAnalysis | None = None,
    environment_bound: bool = False,
    enriched_operations: Mapping[str, str] | None = None,
    stage_1a_source: Stage1aSource | None = None,
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
            if handoff_publication:
                _write_scenario_handoff_artifacts(
                    envelope,
                    scenarios_dir,
                    loss_analysis=loss_analysis,
                    environment_bound=environment_bound,
                    enriched_operations=enriched_operations,
                    stage_1a_source=stage_1a_source,
                )
            else:
                _write_scenario_artifacts(envelope, scenarios_dir, None)
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
    llm_client: LLMClient,
    spec: ScenarioSpec,
    control_structure: ControlStructure,
    loss_analysis: LossAnalysis,
    run_dir: Path,
    scenarios_dir: Path,
    loader: TemplateLoader,
    temperature: float,
    max_workers: int,
    stage_errors: list[str],
    *,
    capability_profile: CapabilityProfile | None,
    run_identity: ExecutionRunIdentity,
    execution_target_profile: ExecutionTargetProfile | None,
    target_realization: TargetRealizationResult | None = None,
    render_presentation: bool = False,
    candidate_builders: list[_CandidateOutcomeBuilder] | None = None,
    structured_omission: bool = False,
    observation_snapshot_digest: str | None = None,
    handoff_publication: bool = False,
    environment_bound: bool = False,
    enriched_operations: Mapping[str, str] | None = None,
    stage_1a_source: Stage1aSource | None = None,
) -> tuple[ScenarioEnvelope, ValidatedExecutionProjection | dict | None] | None:
    """Render and persist one Stage 6 candidate, isolating all failure kinds."""
    prior_error_count = len(stage_errors)
    try:
        envelope, projection_doc = _run_stage6_for_spec(
            llm_client,
            spec,
            control_structure,
            loss_analysis,
            run_dir,
            loader,
            temperature,
            max_workers,
            stage_errors,
            capability_profile=capability_profile,
            run_identity=run_identity,
            execution_target_profile=execution_target_profile,
            target_realization=target_realization,
            render_presentation=render_presentation,
            structured_omission=structured_omission,
            observation_snapshot_digest=observation_snapshot_digest,
            handoff_publication=handoff_publication,
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
    if envelope is None:
        diagnostics = _stage6_diagnostics(
            stage_errors,
            prior_error_count,
            f"Stage 6 rendering produced no envelope for {spec.scenario_id}",
        )
        _mark_candidate_failure(
            candidate_builders,
            spec.scenario_id,
            SP3CandidateStatus.rendering_failed,
            diagnostics,
        )
        return None
    _publish_stage6_artifacts(
        envelope,
        projection_doc,
        scenarios_dir,
        stage_errors,
        prior_error_count,
        builder,
        handoff_publication=handoff_publication,
        loss_analysis=loss_analysis,
        environment_bound=environment_bound,
        enriched_operations=enriched_operations,
        stage_1a_source=stage_1a_source,
    )
    return envelope, projection_doc


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
    llm_client: LLMClient,
    scenario_specs: list[ScenarioSpec],
    control_structure: ControlStructure,
    loss_analysis: LossAnalysis,
    run_dir: Path,
    scenarios_dir: Path,
    loader: TemplateLoader,
    temperature: float,
    max_workers: int,
    stage_errors: list[str],
    *,
    capability_profile: CapabilityProfile | None,
    run_identity: ExecutionRunIdentity,
    execution_target_profile: ExecutionTargetProfile | None,
    target_realization: TargetRealizationResult | None = None,
    render_presentation: bool = False,
    candidate_builders: list[_CandidateOutcomeBuilder] | None = None,
    structured_omission: bool = False,
    observation_snapshot_digest: str | None = None,
    handoff_publication: bool = False,
    environment_bound: bool = False,
    enriched_operations: Mapping[str, str] | None = None,
    stage_1a_source: Stage1aSource | None = None,
) -> tuple[
    list[ScenarioEnvelope],
    list[tuple[ScenarioEnvelope, ValidatedExecutionProjection]],
]:
    """Concretize specs and write each accepted scenario companion set."""
    envelopes: list[ScenarioEnvelope] = []
    validated: list[tuple[ScenarioEnvelope, ValidatedExecutionProjection]] = []
    for spec in scenario_specs:
        artifact = _render_stage6_candidate(
            llm_client,
            spec,
            control_structure,
            loss_analysis,
            run_dir,
            scenarios_dir,
            loader,
            temperature,
            max_workers,
            stage_errors,
            capability_profile=capability_profile,
            run_identity=run_identity,
            execution_target_profile=execution_target_profile,
            target_realization=target_realization,
            render_presentation=render_presentation,
            candidate_builders=candidate_builders,
            structured_omission=structured_omission,
            observation_snapshot_digest=observation_snapshot_digest,
            handoff_publication=handoff_publication,
            environment_bound=environment_bound,
            enriched_operations=enriched_operations,
            stage_1a_source=stage_1a_source,
        )
        if artifact is None:
            continue
        envelope, projection_doc = artifact
        envelopes.append(envelope)
        if isinstance(projection_doc, ValidatedExecutionProjection):
            validated.append((envelope, projection_doc))
    _mark_unresolved_stage6_candidates(candidate_builders)
    return envelopes, validated


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


def _publish_validated_projections(
    run_dir: Path,
    run_identity: ExecutionRunIdentity,
    validated_projections: list[tuple[ScenarioEnvelope, ValidatedExecutionProjection]],
    stage_errors: list[str],
) -> str | None:
    """Publish the v2 bundle after all accepted pairs have passed preflight."""
    if not validated_projections:
        return None
    try:
        publish_execution_bundle(
            run_dir,
            run_identity,
            tuple(
                _bundle_publication(envelope, projection)
                for envelope, projection in validated_projections
            ),
        )
    except Exception as exc:  # noqa: BLE001 - isolate bundle publication failure
        diagnostic = f"Execution bundle publication failed: {exc}"
        stage_errors.append(diagnostic)
        return diagnostic
    return None


def _publish_execution_target_profile(
    run_dir: Path,
    profile: ExecutionTargetProfile | None,
    stage_errors: list[str],
) -> bool:
    """Persist the verified profile before publishing the bundle index."""
    if profile is None:
        return True
    try:
        publish_execution_target_profile(run_dir, profile)
    except Exception as exc:  # noqa: BLE001 - isolate profile publication failure
        stage_errors.append(f"Execution target profile publication failed: {exc}")
        return False
    return True


def _bundle_publication(
    envelope: ScenarioEnvelope,
    projection: ValidatedExecutionProjection,
) -> ExecutionBundlePublication:
    """Create the stable bundle paths for one validated scenario pair."""
    scenario_id = envelope.scenario_id
    return ExecutionBundlePublication(
        scenario_envelope=envelope,
        validated_projection=projection,
        scenario_path=f"scenarios/{scenario_id}.scenario.json",
        projection_path=f"scenarios/canonical/{scenario_id}.projection.json",
    )


def _stage7_outputs(
    scenario_envelopes: list[ScenarioEnvelope],
    scenario_specs: list[ScenarioSpec],
    enriched_threat_set: EnrichedThreatSet,
    control_structure: ControlStructure,
    loss_analysis: LossAnalysis,
    *,
    deterministic_presentation: bool = False,
) -> tuple[list[str], dict, dict]:
    """Validate accepted scenarios and derive coverage/evaluation outputs."""
    validation_errors: list[str] = []
    _run_stage7_validations(
        scenario_envelopes,
        scenario_specs,
        control_structure,
        loss_analysis,
        validation_errors,
        deterministic_presentation=deterministic_presentation,
    )
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
    requested_environment_basis: RequestedEnvironmentBasis | None = None,
    target_realization: TargetRealizationResult | None = None,
    target_observations: TargetObservationSnapshot | None = None,
    content_surface: ContentSurfaceFacts | None = None,
    authored_scenarios: Mapping[str, Any] | None = None,
    execution_design: bool = True,
) -> _Stage5ThreatResult:
    """Run Stage 5 BDI generation for a single threat."""
    slot_parts = parse_ica_slot_id(threat.ica_slot_id)
    target_resp_id = slot_parts["controller"]
    defender_bdi = _stage5_defender_bdi(control_structure, target_resp_id, stage_errors)
    if defender_bdi is None:
        return _Stage5ThreatResult(None)
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

    authored = authored_scenarios.get(threat.ica_id) if authored_scenarios else None
    if authored is not None:
        return _stage5_authored_spec(
            authored,
            threat,
            control_structure,
            scenario_index,
            context,
            requested_environment_basis,
            stage_errors,
        )
    if authored_scenarios is not None:
        # Authored mode replaces Stage 5 for every threat (spec 4.6): a
        # threat without an authored bundle produces no scenario and never
        # falls through to the target-blind BDI call.
        stage_errors.append(
            f"{threat.ica_id}: no authored scenario bundle in target-derived mode"
        )
        return _Stage5ThreatResult(None)

    target_operation = _target_operation_for_context(target_realization, context)

    llm_result, failure = _stage5_bdi(
        llm_client,
        context,
        run_dir,
        loader,
        temperature,
        stage_errors,
        requested_environment_basis=requested_environment_basis,
        target_operation=target_operation,
        target_observations=target_observations,
        content_surface=content_surface,
        execution_design=execution_design,
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
        requested_environment_basis=requested_environment_basis,
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
    requested_environment_basis: RequestedEnvironmentBasis | None,
    target_operation: TargetOperationObservation | None,
    target_observations: TargetObservationSnapshot | None,
    content_surface: ContentSurfaceFacts | None = None,
    execution_design: bool = True,
) -> tuple[BDIGenerationResult | None, _Stage5ThreatResult | None]:
    """Generate one closed BDI result or one typed local failure."""
    llm_result, error = generate_bdi_for_context(
        llm_client,
        context,
        run_dir,
        loader=loader,
        temperature=temperature,
        requested_environment_basis=requested_environment_basis,
        target_operation=target_operation,
        target_observations=target_observations,
        content_surface=content_surface,
        execution_design=execution_design,
    )
    if error is None and llm_result is not None:
        return llm_result, None
    stage_errors.append(f"Stage 5 BDI generation failed: {error}")
    return None, _Stage5ThreatResult(
        None,
        abort_remaining=is_bdi_length_retry_exhausted(error),
    )


def _stage5_authored_spec(
    bundle: Any,
    threat: Any,
    control_structure: ControlStructure,
    scenario_index: int,
    context: ScenarioGenerationContext,
    requested_environment_basis: RequestedEnvironmentBasis | None,
    stage_errors: list[str],
) -> _Stage5ThreatResult:
    """Assemble one deterministic spec from a validated authored scenario."""
    try:
        spec = assemble_authored_scenario_spec(
            bundle,
            threat,
            control_structure,
            context,
            scenario_index,
            requested_environment_basis=requested_environment_basis,
        )
        prior_error_count = len(stage_errors)
        _validate_stage5_spec(spec, control_structure, stage_errors)
        if len(stage_errors) != prior_error_count:
            return _Stage5ThreatResult(None)
    except Exception as exc:  # noqa: BLE001 - one candidate, typed local failure
        stage_errors.append(
            f"Stage 5 authored assembly failed for threat {threat.ica_id}: {exc}"
        )
        return _Stage5ThreatResult(None)
    return _Stage5ThreatResult(spec)


def _stage5_defender_bdi(
    control_structure: ControlStructure,
    target_resp_id: str,
    stage_errors: list[str],
) -> DefenderBDI | None:
    """Build deterministic defender BDI and retain a local failure."""
    try:
        return populate_defender_bdi(control_structure, target_resp_id)
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
    if realization is None:
        return None
    action_id = context.target_control_path.control_action.action_id
    row = _supported_target_row(realization, action_id)
    if row is None:
        return _target_derived_operation(realization, action_id)
    return _operation_for_supported_row(realization, row)


def _supported_target_row(
    realization: TargetRealizationResult,
    action_id: str,
) -> TargetRealizationRow | None:
    """Return the sole supported baseline row for one control action."""
    rows = tuple(
        row
        for row in realization.rows
        if row.control_action_id == action_id
        and row.disposition is TargetRealizationDisposition.supported
    )
    if not rows:
        return None
    if len(rows) != 1 or rows[0].selected_operation is None:
        raise ValueError("target realization has conflicting supported action rows")
    return rows[0]


def _target_derived_operation(
    realization: TargetRealizationResult,
    action_id: str,
) -> TargetOperationObservation | None:
    """Resolve one exact operation for a target-derived control action."""
    derived = tuple(
        record.operation
        for record in realization.operation_records
        if record.target_derived_control_action_id == action_id
        and record.disposition is TargetRealizationDisposition.supported
    )
    if len(derived) > 1:
        raise ValueError("target-derived action has conflicting exact operations")
    if not derived:
        return None
    return derived[0]


def _operation_for_supported_row(
    realization: TargetRealizationResult,
    row: TargetRealizationRow,
) -> TargetOperationObservation:
    """Resolve the operation record named by a supported baseline row."""
    selected = row.selected_operation
    if selected is None:  # pragma: no cover - guarded by _supported_target_row
        raise ValueError("target realization has no selected supported operation")
    identity = selected.identity
    operations = tuple(
        record.operation
        for record in realization.operation_records
        if record.operation_ref.identity == identity
    )
    if len(operations) != 1:
        raise ValueError(
            "target realization selected operation is not uniquely recorded"
        )
    return operations[0]


def _stage5_spec(
    defender_bdi: DefenderBDI,
    llm_result: BDIGenerationResult,
    threat,
    control_structure: ControlStructure,
    scenario_index: int,
    context: ScenarioGenerationContext,
    stage_errors: list[str],
    *,
    requested_environment_basis: RequestedEnvironmentBasis | None,
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
            requested_environment_basis=requested_environment_basis,
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
    """Select a supplied context or build the exact standalone adapter view."""
    context_key = threat.ica_id or threat.ica_slot_id
    if supplied is not None and context_key in supplied:
        return supplied[context_key]
    return build_scenario_generation_context(
        threat,
        control_structure,
        loss_analysis,
        scenario_id=f"SCN-{scenario_index + 1:03d}",
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
    context = spec.scenario_context
    if context is not None:
        stage_errors.extend(_contextual_stage5_errors(spec))


def _contextual_stage5_errors(spec: ScenarioSpec) -> list[str]:
    """Validate exact intention references in one context."""
    context = spec.scenario_context
    if context is None:
        return []
    return _intention_reference_errors(spec, _allowed_intention_refs(context))


def _allowed_intention_refs(context: ScenarioGenerationContext) -> set[str]:
    """Return exact structural IDs that an intention may cite."""
    path = context.target_control_path
    return {
        *(item.element_id for item in path.process_model_parts),
        *(item.element_id for item in path.feedback),
        path.control_action.action_id,
        *(item.action_id for item in path.related_control_actions),
    }


def _intention_reference_errors(
    spec: ScenarioSpec,
    allowed_refs: set[str],
) -> list[str]:
    """Report intentions that cite none of the selected path identities."""
    return [
        "Attacker BDI intention has no exact structural reference "
        f"from the selected scenario context: {intention!r}"
        for intention in spec.attacker_bdi.intentions
        if not any(reference in intention for reference in allowed_refs)
    ]


def _stage6_projection(
    spec: ScenarioSpec,
    control_structure: ControlStructure,
    stage_errors: list[str],
    run_identity: ExecutionRunIdentity | None,
    execution_target_profile: ExecutionTargetProfile | None,
    target_realization: TargetRealizationResult | None = None,
    *,
    structured_omission: bool = False,
    observation_snapshot_digest: str | None = None,
) -> tuple[ValidatedExecutionProjection | dict | None, str | None]:
    """Prepare one Stage 6 projection and its shared prompt alignment."""
    if run_identity is not None:
        try:
            projection = prepare_execution_projection(
                spec,
                control_structure,
                run_identity,
                target_profile=execution_target_profile,
                target_realization=target_realization,
                structured_omission=structured_omission,
                observation_snapshot_digest=observation_snapshot_digest,
            )
        except ExecutionProjectionPreparationError as exc:
            stage_errors.append(
                f"Stage 6 projection failed for {spec.scenario_id}: {exc}"
            )
            return None, None
        return projection, projection.alignment_view

    # Only an explicitly direct diagnostic caller (which omits the run
    # identity) may exercise the historical v1 projection path.  Product
    # ``run_sp3`` always supplies an identity and therefore fails closed
    # when Stage 5 omitted the required unsafe outcome.
    try:
        legacy_projection = project_execution(spec, control_structure)
    except ValueError as exc:
        stage_errors.append(f"Stage 6 projection failed for {spec.scenario_id}: {exc}")
        return None, None
    projection = canonical_projection_data(legacy_projection)
    return projection, render_projection_alignment_table(projection)


def _stage6_prompts_or_none(
    spec: ScenarioSpec,
    control_structure: ControlStructure,
    loss_analysis: LossAnalysis,
    loader: TemplateLoader,
    stage_errors: list[str],
    projection_alignment: str | None,
    capability_profile: CapabilityProfile | None,
) -> _Stage6Prompts | None:
    """Build Stage 6 prompts while converting context errors into diagnostics."""
    try:
        return _build_stage6_prompts(
            spec,
            control_structure,
            loss_analysis,
            loader,
            projection_alignment=projection_alignment,
            capability_profile=capability_profile,
        )
    except ValueError as exc:
        stage_errors.append(f"Stage 6 context failed for {spec.scenario_id}: {exc}")
        return None


def _run_stage6_for_spec(
    llm_client: LLMClient,
    spec: ScenarioSpec,
    control_structure: ControlStructure,
    loss_analysis: LossAnalysis,
    run_dir: Path,
    loader: TemplateLoader,
    temperature: float,
    max_workers: int,
    stage_errors: list[str],
    *,
    capability_profile: CapabilityProfile | None = None,
    run_identity: ExecutionRunIdentity | None = None,
    execution_target_profile: ExecutionTargetProfile | None = None,
    target_realization: TargetRealizationResult | None = None,
    render_presentation: bool = False,
    structured_omission: bool = False,
    observation_snapshot_digest: str | None = None,
    handoff_publication: bool = False,
) -> tuple[ScenarioEnvelope | None, ValidatedExecutionProjection | dict | None]:
    """Run Stage 6 concretization for a single scenario spec.

    The projection is derived once (deterministically, from the Stage 5
    declared factors) and its validator-derived alignment table is passed
    to every Stage 6 prompt, so the narrative, attack-tree, and Gherkin
    calls all receive the same projection.  Corrected contextual specs return
    an immutable v2 projection; historical specs retain their v1 diagnostic
    document for read/validation compatibility.  A structured-omission run
    returns an immutable v3 projection for every spec, including specs whose
    outcome is not an omission.

    On the handoff publication path the execution projection is not part of
    the product at all, so it is never prepared and never gates rendering: a
    scenario whose failure criterion has no downstream-compilable detector is
    still rendered and published, with the limitation reported downstream.

    Returns:
        A ``(envelope, projection)`` pair; ``None`` envelope means the
        scenario was rejected before any Stage 6 provider call and no
        artifact is written.
    """
    needs_projection = not handoff_publication or render_presentation
    if needs_projection:
        projection_doc, projection_alignment = _stage6_projection(
            spec,
            control_structure,
            stage_errors,
            run_identity,
            execution_target_profile,
            target_realization,
            structured_omission=structured_omission,
            observation_snapshot_digest=observation_snapshot_digest,
        )
        if projection_doc is None:
            return None, None
    else:
        projection_doc, projection_alignment = None, None
    if not render_presentation:
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
            execution_projection=(
                projection_doc.projection
                if isinstance(projection_doc, ValidatedExecutionProjection)
                else None
            ),
        ), projection_doc
    prompts = _stage6_prompts_or_none(
        spec,
        control_structure,
        loss_analysis,
        loader,
        stage_errors,
        projection_alignment,
        capability_profile,
    )
    if prompts is None:
        return None, None

    gherkin_security_constraint = find_security_constraint(spec, loss_analysis)
    results = _parallel_stage6_calls(
        llm_client=llm_client,
        run_dir=run_dir,
        prompts=prompts,
        temperature=temperature,
        max_workers=max_workers,
        slot_id=spec.threat_source.ica_slot_id,
        scenario_id=spec.scenario_id,
        gherkin_scaffold=build_gherkin_identity_scaffold(
            spec,
            gherkin_security_constraint,
            loss_analysis,
        ),
        gherkin_scenario_spec=spec,
        gherkin_security_constraint=gherkin_security_constraint,
        gherkin_loss_analysis=loss_analysis,
    )

    prior_error_count = len(stage_errors)
    _collect_stage6_errors(spec.scenario_id, results, stage_errors)

    narrative_text, attack_tree, gherkin_spec, gherkin_raw = _parse_stage6_results(
        results
    )

    _validate_stage6_artifacts(
        attack_tree,
        gherkin_spec,
        gherkin_raw,
        control_structure,
        loss_analysis,
        spec,
        stage_errors,
        narrative_text=narrative_text,
    )
    stage6_errors = stage_errors[prior_error_count:]
    if stage6_errors and not _stage6_quality_errors_are_nonblocking(stage6_errors):
        return None, None

    envelope = assemble_envelope(
        scenario_id=spec.scenario_id,
        scenario_spec=spec,
        narrative=narrative_text,
        attack_tree=attack_tree,
        gherkin_spec=gherkin_spec,
        gherkin_raw=gherkin_raw,
        capability_profile=capability_profile,
        control_structure=control_structure,
        execution_projection=(
            projection_doc.projection
            if isinstance(projection_doc, ValidatedExecutionProjection)
            else None
        ),
    )
    return envelope, projection_doc


def _stage6_quality_errors_are_nonblocking(errors: list[str]) -> bool:
    """Keep a valid STPA scenario when only factor coverage is incomplete.

    A rendering omission is useful analytical evidence and should be visible
    in the run diagnostics, but it must not erase the ordinary STPA finding.
    Unsupported structural bridges remain fatal so a renderer cannot widen
    the scenario's causal authority.
    """
    return bool(errors) and all(
        error.startswith("Attack tree does not cover declared causal factor")
        for error in errors
    )


@dataclass
class _Stage6Prompts:
    """Container for the three Stage 6 prompt pairs."""

    narrative: tuple[str, str]
    attack_tree: tuple[str, str]
    gherkin: tuple[str, str]


def _build_stage6_prompts(
    spec: ScenarioSpec,
    control_structure: ControlStructure,
    loss_analysis: LossAnalysis,
    loader: TemplateLoader,
    *,
    projection_alignment: str | None = None,
    capability_profile: CapabilityProfile | None = None,
) -> _Stage6Prompts:
    """Build system/user prompt pairs for all three Stage 6 calls.

    When a validated ``projection_alignment`` table is supplied, every
    Stage 6 prompt receives the same table; otherwise the prompts render
    without one (backward compatible default).
    """
    nar_prompts = build_narrative_prompts(
        spec,
        loader,
        capability_profile=capability_profile,
        projection_alignment=projection_alignment,
    )
    tree_prompts = build_attack_tree_prompts(
        spec, control_structure, loader, projection_alignment=projection_alignment
    )
    sc = find_security_constraint(spec, loss_analysis)
    ghk_prompts = build_gherkin_prompts(
        spec, sc, loss_analysis, loader, projection_alignment=projection_alignment
    )

    return _Stage6Prompts(
        narrative=nar_prompts,
        attack_tree=tree_prompts,
        gherkin=ghk_prompts,
    )


def _collect_stage6_errors(
    scenario_id: str,
    results: dict[str, tuple[Any | None, str | None]],
    stage_errors: list[str],
) -> None:
    """Append error messages from Stage 6 call results."""
    for step in ("narrative", "attack_tree", "gherkin"):
        _text, err = results[step]
        if err:
            stage_errors.append(f"Stage 6 {step} failed for {scenario_id}: {err}")


def _parse_stage6_results(
    results: dict[str, tuple[Any | None, str | None]],
) -> tuple[str, dict, GherkinSpec | None, str]:
    """Parse Stage 6 call results with fallbacks for missing artifacts."""
    narrative_raw, _ = results["narrative"]
    attack_tree_raw, _ = results["attack_tree"]
    gherkin_raw, _ = results["gherkin"]

    narrative_text = narrative_raw or ""
    gherkin_text = gherkin_raw or ""
    attack_tree = parse_attack_tree(attack_tree_raw) or dict(_EMPTY_ATTACK_TREE)

    gherkin_spec = parse_gherkin_spec(gherkin_text) or _EMPTY_GHERKIN_SPEC

    return narrative_text, attack_tree, gherkin_spec, gherkin_text


def _validate_stage6_artifacts(
    attack_tree: dict,
    gherkin_spec: GherkinSpec | None,
    gherkin_raw: str,
    control_structure: ControlStructure,
    loss_analysis: LossAnalysis,
    spec: ScenarioSpec,
    stage_errors: list[str],
    *,
    narrative_text: str = "",
) -> None:
    """Run stage-local validators for Stage 6 artifacts."""
    _validate_stage6_tree(attack_tree, control_structure, spec, stage_errors)
    _validate_stage6_gherkin(gherkin_spec, gherkin_raw, loss_analysis, stage_errors)


def _validate_stage6_tree(
    attack_tree: dict,
    control_structure: ControlStructure,
    spec: ScenarioSpec,
    stage_errors: list[str],
) -> None:
    """Run tree-related validators for Stage 6 artifacts."""
    _extend_validation_errors(
        (
            validate_tree_factor_evidence_coverage(attack_tree, spec),
            validate_tree_id_references(attack_tree, control_structure),
            validate_attack_tree_root_label(
                attack_tree,
                spec.ica_type.value,
                spec.target_control_action,
            ),
        ),
        stage_errors,
    )


def _validate_stage6_gherkin(
    gherkin_spec: GherkinSpec | None,
    gherkin_raw: str,
    loss_analysis: LossAnalysis,
    stage_errors: list[str],
) -> None:
    """Run Gherkin-related validators for Stage 6 artifacts."""
    gherkin_for_validation: GherkinSpec | str = (
        gherkin_spec if gherkin_spec is not None else gherkin_raw
    )
    ghk_result = validate_gherkin_structure(gherkin_for_validation)
    if not ghk_result.passed:
        stage_errors.extend(ghk_result.errors)

    if gherkin_raw:
        id_result = validate_loss_hazard_id_references(gherkin_raw, loss_analysis)
        if not id_result.passed:
            stage_errors.extend(id_result.errors)


def _stage6_gherkin_parser(
    gherkin_scaffold: GherkinSpec | None,
    gherkin_scenario_spec: ScenarioSpec | None,
    gherkin_security_constraint: SecurityConstraint | None,
    gherkin_loss_analysis: LossAnalysis | None,
):
    """Select the identity-preserving parser for a contextual Gherkin call."""
    if gherkin_scaffold is None or gherkin_scenario_spec is None:
        return _parse_gherkin_result

    def _parse_result(result: Any) -> GherkinSpec:
        parsed = _parse_gherkin_result(result)
        return apply_gherkin_identity_scaffold(
            parsed,
            gherkin_scenario_spec,
            gherkin_security_constraint,
            gherkin_loss_analysis,
        )

    return _parse_result


def _run_stage6_gherkin_call(
    *,
    llm_client: LLMClient,
    run_dir: Path,
    prompt_pair: tuple[str, str],
    temperature: float,
    slot_id: str | None,
    scenario_id: str | None,
    gherkin_scaffold: GherkinSpec | None,
    gherkin_scenario_spec: ScenarioSpec | None,
    gherkin_security_constraint: SecurityConstraint | None,
    gherkin_loss_analysis: LossAnalysis | None,
) -> tuple[str | None, str | None]:
    """Run one structured Gherkin rendering call with bounded correction."""
    sys_prompt, user_prompt = prompt_pair
    spec, _result, error = safe_llm_call(
        llm_client=llm_client,
        system_prompt=sys_prompt,
        user_prompt=user_prompt,
        response_format=GherkinSpec,
        run_dir=run_dir,
        stage="stage_6",
        step="gherkin",
        slot_id=slot_id,
        scenario_id=scenario_id,
        temperature=temperature,
        max_completion_tokens=STAGE6_MAX_COMPLETION_TOKENS["gherkin"],
        validation_retries=1,
        validation_retry_include_schema=False,
        validation_retry_feedback=(
            ' Return one closed JSON object with fields "feature", '
            '"scenario", "given", "when", "then_expected", and '
            '"then_actual". Every list item must be a separate JSON '
            "string; do not emit YAML-only continuation syntax."
        ),
        result_parser=_stage6_gherkin_parser(
            gherkin_scaffold,
            gherkin_scenario_spec,
            gherkin_security_constraint,
            gherkin_loss_analysis,
        ),
        result_validator=_validate_gherkin_result,
    )
    if error is not None or spec is None:
        return None, error or "Gherkin provider returned no result"
    return (
        yaml.safe_dump(
            spec.model_dump(mode="json"),
            sort_keys=False,
            allow_unicode=True,
        ),
        None,
    )


def _run_stage6_raw_call(
    *,
    llm_client: LLMClient,
    run_dir: Path,
    step: str,
    prompt_pair: tuple[str, str],
    temperature: float,
    slot_id: str | None,
    scenario_id: str | None,
) -> tuple[str | None, str | None]:
    """Run one raw Stage 6 rendering call."""
    sys_prompt, user_prompt = prompt_pair
    text, _result, error = safe_llm_call_raw(
        llm_client=llm_client,
        system_prompt=sys_prompt,
        user_prompt=user_prompt,
        run_dir=run_dir,
        stage="stage_6",
        step=step,
        slot_id=slot_id,
        scenario_id=scenario_id,
        temperature=temperature,
        max_completion_tokens=STAGE6_MAX_COMPLETION_TOKENS[step],
    )
    if error is not None:
        return None, error
    return text, None


def _parallel_stage6_calls(
    *,
    llm_client: LLMClient,
    run_dir: Path,
    prompts: _Stage6Prompts,
    temperature: float,
    max_workers: int,
    slot_id: str | None = None,
    scenario_id: str | None = None,
    gherkin_scaffold: GherkinSpec | None = None,
    gherkin_scenario_spec: ScenarioSpec | None = None,
    gherkin_security_constraint: SecurityConstraint | None = None,
    gherkin_loss_analysis: LossAnalysis | None = None,
) -> dict[str, tuple[str | None, str | None]]:
    """Execute the 3 Stage 6 calls, optionally in parallel.

    Uses :func:`safe_llm_call_raw` for each call to ensure proper call
    logging and error handling. The calls are independent and can be
    parallelized via ``ThreadPoolExecutor``.
    """
    call_specs = [
        ("narrative", prompts.narrative),
        ("attack_tree", prompts.attack_tree),
        ("gherkin", prompts.gherkin),
    ]

    def _run_call(
        step: str, prompt_pair: tuple[str, str]
    ) -> tuple[str | None, str | None]:
        if step == "gherkin":
            return _run_stage6_gherkin_call(
                llm_client=llm_client,
                run_dir=run_dir,
                prompt_pair=prompt_pair,
                temperature=temperature,
                slot_id=slot_id,
                scenario_id=scenario_id,
                gherkin_scaffold=gherkin_scaffold,
                gherkin_scenario_spec=gherkin_scenario_spec,
                gherkin_security_constraint=gherkin_security_constraint,
                gherkin_loss_analysis=gherkin_loss_analysis,
            )
        return _run_stage6_raw_call(
            llm_client=llm_client,
            run_dir=run_dir,
            step=step,
            prompt_pair=prompt_pair,
            temperature=temperature,
            slot_id=slot_id,
            scenario_id=scenario_id,
        )

    if max_workers > 1:
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                step: executor.submit(_run_call, step, pair)
                for step, pair in call_specs
            }
            return {step: f.result() for step, f in futures.items()}
    else:
        return {step: _run_call(step, pair) for step, pair in call_specs}


def _parse_gherkin_result(result: Any) -> GherkinSpec:
    """Accept a closed model, mapping, JSON, or legacy YAML into one draft."""
    content = result.content
    if isinstance(content, GherkinSpec):
        return content
    if isinstance(content, dict):
        return GherkinSpec.model_validate(content)
    if isinstance(content, str):
        parsed = parse_gherkin_spec(content)
        if parsed is not None:
            return parsed
        raise ValueError("response is not a valid GherkinSpec object")
    raise TypeError(
        "Gherkin response must be a GherkinSpec, mapping, JSON, or YAML object"
    )


def _validate_gherkin_result(value: GherkinSpec) -> None:
    """Raise the exact structural errors so the bounded retry can correct them."""
    validation = validate_gherkin_structure(value)
    if not validation.passed:
        raise ValueError("; ".join(validation.errors))


def _run_stage7_validations(
    envelopes: list[ScenarioEnvelope],
    specs: list[ScenarioSpec],
    control_structure: ControlStructure,
    loss_analysis: LossAnalysis,
    validation_errors: list[str],
    *,
    deterministic_presentation: bool = False,
) -> None:
    """Run Stage 7 validations on all specs and envelopes."""
    for spec in specs:
        _validate_spec_stage7(spec, control_structure, validation_errors)

    for env in envelopes:
        _validate_envelope_stage7(
            env,
            loss_analysis,
            validation_errors,
            deterministic_presentation=deterministic_presentation,
        )


def _validate_spec_stage7(
    spec: ScenarioSpec,
    control_structure: ControlStructure,
    validation_errors: list[str],
) -> None:
    """Run stage-local validators for a single spec in Stage 7."""
    _extend_validation_errors(
        (
            validate_bdi_grounding(spec, control_structure),
            validate_vulnerability_completeness(spec),
        ),
        validation_errors,
    )


def _validate_envelope_stage7(
    envelope: ScenarioEnvelope,
    loss_analysis: LossAnalysis,
    validation_errors: list[str],
    *,
    deterministic_presentation: bool = False,
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
    if deterministic_presentation:
        validation_errors.extend(validate_scenario_summary(envelope))
    else:
        _extend_validation_errors(
            (
                validate_attack_tree_root_label(
                    envelope.attack_tree,
                    envelope.ica_type.value,
                    envelope.scenario_spec.target_control_action,
                ),
            ),
            validation_errors,
        )
        ghk_for_validation: GherkinSpec | str = (
            envelope.gherkin_spec
            if isinstance(envelope.gherkin_spec, GherkinSpec)
            else envelope.gherkin_raw
        )
        ghk_result = validate_gherkin_structure(ghk_for_validation)
        if not ghk_result.passed:
            validation_errors.extend(ghk_result.errors)

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


def _write_scenario_artifacts(
    envelope: ScenarioEnvelope,
    scenarios_dir: Path,
    projection_doc: dict | ValidatedExecutionProjection | None = None,
) -> None:
    """Write scenario YAML, .feature, and canonical projection artifacts.

    The canonical projection document is exported as standalone JSON and YAML
    under ``scenarios/canonical/`` beside the legacy scenario YAML and Gherkin
    feature, so legacy ``*.yaml`` readers keep seeing only envelope documents.
    The writer is version-aware without dispatch: the bytes and dump come from
    the document itself, so a v2 projection persists as
    ``stpa-execution-projection-v2`` and a v3 projection persists as
    ``stpa-execution-projection-v3`` under the same file layout. A v1
    dictionary uses the historical exporter. When no projection is supplied
    only legacy artifacts are written.
    """
    write_yaml(envelope, scenarios_dir / f"{envelope.scenario_id}.yaml")
    feature_text = _envelope_gherkin_text(envelope)
    (scenarios_dir / f"{envelope.scenario_id}.feature").write_text(
        feature_text, encoding="utf-8"
    )
    if projection_doc is not None:
        # Once a bundle index exists, its canonical JSON paths are immutable
        # members of the currently published generation.  Updates are staged
        # by ``publish_execution_bundle`` under a new content-addressed
        # generation and swap the index last; do not overwrite the old
        # projection bytes while Stage 6 is still collecting companions.
        if (
            isinstance(projection_doc, ValidatedExecutionProjection)
            and (scenarios_dir.parent / "execution-bundle.json").is_file()
        ):
            return
        canonical_dir = scenarios_dir / "canonical"
        canonical_dir.mkdir(parents=True, exist_ok=True)
        if isinstance(projection_doc, ValidatedExecutionProjection):
            json_text = projection_doc.canonical_json_bytes.decode("utf-8")
            yaml_text = yaml.safe_dump(
                projection_doc.projection.model_dump(mode="json"),
                sort_keys=True,
                allow_unicode=True,
            )
        else:
            json_text = export_projection_json(projection_doc)
            yaml_text = export_projection_yaml(projection_doc)
        (canonical_dir / f"{envelope.scenario_id}.projection.json").write_text(
            json_text, encoding="utf-8"
        )
        (canonical_dir / f"{envelope.scenario_id}.projection.yaml").write_text(
            yaml_text, encoding="utf-8"
        )


def _stage_1a_gate_statuses(run_dir: Path) -> dict[str, object]:
    """Carry the Stage 1a gate evidence into the product manifest.

    The SP1 manifest that first records the gate statuses is replaced by
    this one, so read them back from the persisted gates artifact rather
    than losing them (re-review should-fix item).
    """
    gates_path = run_dir / "loss-analysis-gates.yaml"
    if not gates_path.is_file():
        return {}
    try:
        gates = yaml.safe_load(gates_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError:
        return {}
    if not isinstance(gates, dict):
        return {}
    statuses: dict[str, object] = {
        "risk_accounting": "passed"
        if gates.get("risk_accounting", {}).get("passed")
        else "failed",
        "hazard_graph_density": "passed" if gates.get("passed") else "failed",
    }
    if gates.get("revision_attempted"):
        statuses["graph_revision_call_count"] = 1
        if gates.get("revision_applied"):
            statuses["hazard_graph_density"] = "passed_after_revision"
    if gates.get("normalization_warnings"):
        statuses["accounting_normalizations"] = len(gates["normalization_warnings"])
    return statuses


def _stage_2_mode(run_dir: Path) -> str:
    """Return the single unified Stage 2 analysis mode.

    There is one adaptive analysis, so the run manifest records no
    algorithm-selecting field; this helper remains for callers that need the
    named value.
    """
    return "target_blind"


@dataclass(frozen=True)
class _PreservedStageKeys:
    """SP1-owned manifest keys this final manifest write must keep."""

    stage_1a: dict[str, Any] = field(default_factory=dict)
    post_review_loss_analysis_digest: str | None = None
    loss_analysis_input_hash: str | None = None
    reviewed_obligation_bindings_input_hash: str | None = None
    target_subject_model_input_hash: str | None = None


def _preserved_stage_keys(run_dir: Path) -> _PreservedStageKeys:
    """Read the SP1 manifest keys that ``count_calls_by_stage`` cannot rebuild.

    ``scenario_prod`` writes the last ``run-manifest.yaml`` of a product run
    and rebuilds ``stage_summary`` from ``calls.jsonl``.  That rebuild drops
    the keys SP1 owns: the Stage 1a ``source`` and call count, the advisory
    coverage-review record, and the Stage 2 post-review digest.  A pinned run
    also owns ``input_hashes.loss_analysis``, which must stay the digest of
    the supplied file rather than the canonical model hash.  The same applies
    to ``input_hashes.reviewed_obligation_bindings``: the row is the digest
    of a supplied file with no canonical model-hash equivalent, so it
    survives only through this preservation path.  The same applies to the
    optional target-subject-model companion.
    """
    manifest_path = run_dir / "run-manifest.yaml"
    if not manifest_path.is_file():
        return _PreservedStageKeys()
    try:
        manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError:
        return _PreservedStageKeys()
    if not isinstance(manifest, dict):
        return _PreservedStageKeys()
    stage_summary = manifest.get("stage_summary")
    if not isinstance(stage_summary, dict):
        return _PreservedStageKeys()
    stage_1a = stage_summary.get("stage_1a")
    stage_1a = dict(stage_1a) if isinstance(stage_1a, dict) else {}
    stage_2 = stage_summary.get("stage_2")
    stage_2 = stage_2 if isinstance(stage_2, dict) else {}
    post_review = stage_2.get("post_review_loss_analysis_digest")
    input_hashes = manifest.get("input_hashes")
    input_hashes = input_hashes if isinstance(input_hashes, dict) else {}
    pinned_hash = (
        input_hashes.get("loss_analysis")
        if stage_1a.get("source") == "pinned"
        else None
    )
    bindings_hash = input_hashes.get("reviewed_obligation_bindings")
    return _PreservedStageKeys(
        stage_1a=stage_1a,
        post_review_loss_analysis_digest=(
            post_review if isinstance(post_review, str) else None
        ),
        loss_analysis_input_hash=(
            pinned_hash if isinstance(pinned_hash, str) else None
        ),
        reviewed_obligation_bindings_input_hash=(
            bindings_hash if isinstance(bindings_hash, str) else None
        ),
        target_subject_model_input_hash=(
            input_hashes.get("target_subject_model")
            if isinstance(input_hashes.get("target_subject_model"), str)
            else None
        ),
    )


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
    authored_scenarios: Mapping[str, Any] | None = None,
    target_observations: TargetObservationSnapshot | None = None,
) -> None:
    """Write the run manifest YAML."""
    preserved = _preserved_stage_keys(run_dir)
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
    if preserved.reviewed_obligation_bindings_input_hash is not None:
        # The bindings row is the digest of the supplied file (Q30 ruling);
        # no canonical model hash exists, so the SP1 value carries through.
        input_hashes["reviewed_obligation_bindings"] = (
            preserved.reviewed_obligation_bindings_input_hash
        )
    if preserved.target_subject_model_input_hash is not None:
        # The subject-model row is the digest of the supplied companion file;
        # the canonical framed model digest on the sidecar does not replace
        # this supplied-file byte pin, so the SP1 value carries through.
        input_hashes["target_subject_model"] = preserved.target_subject_model_input_hash
    prompt_hashes = hash_prompt_templates(PROMPTS_DIR)
    stage_summary = count_calls_by_stage(run_dir)
    stage_summary["stage_2"] = dict(stage_summary.get("stage_2") or {})
    if preserved.post_review_loss_analysis_digest is not None:
        stage_summary["stage_2"]["post_review_loss_analysis_digest"] = (
            preserved.post_review_loss_analysis_digest
        )
    if authored_scenarios:
        stage_summary[AUTHORED_STAGE_SUMMARY_KEY] = {
            "mode": "authored",
            "authored_scenario_count": len(authored_scenarios),
        }
        stage_summary[AUTHORING_STAGE] = dict(stage_summary.get(AUTHORING_STAGE) or {})
    stage_1a_summary = dict(stage_summary.get("stage_1a") or {})
    # ``count_calls_by_stage`` owns the call and token totals; the SP1 block
    # supplies every key it cannot rebuild (``source``, the review record,
    # the pinned zero count) without overriding a counted total.
    for key, value in preserved.stage_1a.items():
        if key in ("call_count", "total_tokens") and key in stage_1a_summary:
            continue
        stage_1a_summary[key] = value
    gate_statuses = _stage_1a_gate_statuses(run_dir)
    if gate_statuses:
        stage_1a_summary.update(gate_statuses)
    if stage_1a_summary:
        stage_summary["stage_1a"] = stage_1a_summary

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
