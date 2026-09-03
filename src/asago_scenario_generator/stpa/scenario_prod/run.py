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
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
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
from .attack_tree import build_attack_tree_prompts, parse_attack_tree
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
    ExecutionBundlePublicationError,
    publish_execution_bundle,
    publish_execution_target_profile,
)
from .execution_projection import (
    ExecutionProjectionPreparationError,
    ValidatedExecutionProjection,
    prepare_execution_projection,
)
from .eval_metrics import compute_eval_scorecard, write_eval_scorecard
from .gherkin import build_gherkin_prompts, find_security_constraint, parse_gherkin_spec
from .narrative import build_narrative_prompts
from .projection import (
    canonical_projection_data,
    export_projection_json,
    export_projection_yaml,
    project_execution,
)
from .prompt_alignment import render_projection_alignment_table
from .validators import (
    TraceabilityError,
    ValidationResult,
    validate_attack_tree_root_label,
    validate_bdi_grounding,
    validate_gherkin_structure,
    validate_loss_hazard_id_references,
    validate_traceability,
    validate_tree_branch_coverage,
    validate_tree_id_references,
    validate_vulnerability_completeness,
)

DEFAULT_TEMPERATURE = LLM_DEFAULT_TEMPERATURE

__all__ = ["SP3RunResult", "run_sp3"]

_EMPTY_ATTACK_TREE: dict = {"root": "", "branches": [], "leaves": []}
_EMPTY_GHERKIN_SPEC = GherkinSpec(
    feature="",
    scenario="",
    given=[],
    when=[],
    then_expected=[],
    then_actual=[],
)


@dataclass
class SP3RunResult:
    """Result of a full SP3 run."""

    scenario_specs: list[ScenarioSpec] = field(default_factory=list)
    scenario_envelopes: list[ScenarioEnvelope] = field(default_factory=list)
    eval_scorecard: dict = field(default_factory=dict)
    coverage_gaps: dict = field(default_factory=dict)
    stage_errors: list[str] = field(default_factory=list)
    validation_errors: list[str] = field(default_factory=list)


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
    requested_basis = _resolve_requested_environment_basis(
        execution_target_profile, requested_environment_basis
    )
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
    )
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
    )
    profile_published = _publish_execution_target_profile(
        run_dir, execution_target_profile, stage_errors
    )
    if profile_published:
        _publish_validated_projections(
            run_dir, run_identity, validated_projections, stage_errors
        )
    all_validation_errors, coverage_gaps, eval_scorecard = _stage7_outputs(
        scenario_envelopes,
        scenario_specs,
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
    )

    return SP3RunResult(
        scenario_specs=scenario_specs,
        scenario_envelopes=scenario_envelopes,
        eval_scorecard=eval_scorecard,
        coverage_gaps=coverage_gaps,
        stage_errors=stage_errors,
        validation_errors=all_validation_errors,
    )


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
) -> list[ScenarioSpec]:
    """Generate and retain the valid Stage 5 specs in threat order."""
    specs: list[ScenarioSpec] = []
    threats = enriched_threat_set.structural_threats
    for index, threat in enumerate(threats):
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
        )
        if result.scenario_spec is not None:
            specs.append(result.scenario_spec)
        if result.abort_remaining:
            _record_stage5_abort(stage_errors, len(threats) - index - 1)
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
) -> tuple[
    list[ScenarioEnvelope],
    list[tuple[ScenarioEnvelope, ValidatedExecutionProjection]],
]:
    """Concretize specs and write each accepted scenario companion set."""
    envelopes: list[ScenarioEnvelope] = []
    validated: list[tuple[ScenarioEnvelope, ValidatedExecutionProjection]] = []
    for spec in scenario_specs:
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
        )
        if envelope is None:
            continue
        envelopes.append(envelope)
        if isinstance(projection_doc, ValidatedExecutionProjection):
            validated.append((envelope, projection_doc))
        _write_scenario_artifacts(envelope, scenarios_dir, projection_doc)
    return envelopes, validated


def _publish_validated_projections(
    run_dir: Path,
    run_identity: ExecutionRunIdentity,
    validated_projections: list[tuple[ScenarioEnvelope, ValidatedExecutionProjection]],
    stage_errors: list[str],
) -> None:
    """Publish the v2 bundle after all accepted pairs have passed preflight."""
    if not validated_projections:
        return
    try:
        publish_execution_bundle(
            run_dir,
            run_identity,
            tuple(
                _bundle_publication(envelope, projection)
                for envelope, projection in validated_projections
            ),
        )
    except (OSError, ValueError) as exc:
        stage_errors.append(f"Execution bundle publication failed: {exc}")


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
    except (ExecutionBundlePublicationError, OSError, ValueError) as exc:
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
) -> tuple[list[str], dict, dict]:
    """Validate accepted scenarios and derive coverage/evaluation outputs."""
    validation_errors: list[str] = []
    _run_stage7_validations(
        scenario_envelopes,
        scenario_specs,
        control_structure,
        loss_analysis,
        validation_errors,
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

    llm_result, failure = _stage5_bdi(
        llm_client,
        context,
        run_dir,
        loader,
        temperature,
        stage_errors,
        requested_environment_basis=requested_environment_basis,
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
) -> tuple[BDIGenerationResult | None, _Stage5ThreatResult | None]:
    """Generate one closed BDI result or one typed local failure."""
    llm_result, error = generate_bdi_for_context(
        llm_client,
        context,
        run_dir,
        loader=loader,
        temperature=temperature,
        requested_environment_basis=(
            requested_environment_basis or RequestedEnvironmentBasis.target_profile
        ),
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
) -> tuple[ScenarioEnvelope | None, ValidatedExecutionProjection | dict | None]:
    """Run Stage 6 concretization for a single scenario spec.

    The projection is derived once (deterministically, from the Stage 5
    declared factors) and its validator-derived alignment table is passed
    to every Stage 6 prompt, so the narrative, attack-tree, and Gherkin
    calls all receive the same projection.  Corrected contextual specs return
    an immutable v2 projection; historical specs retain their v1 diagnostic
    document for read/validation compatibility.

    Returns:
        A ``(envelope, projection)`` pair; ``None`` envelope means the
        scenario was rejected before any Stage 6 provider call and no
        artifact is written.
    """
    projection_doc: ValidatedExecutionProjection | dict | None
    if run_identity is not None:
        try:
            projection_doc = prepare_execution_projection(
                spec,
                control_structure,
                run_identity,
                target_profile=execution_target_profile,
            )
        except ExecutionProjectionPreparationError as exc:
            stage_errors.append(
                f"Stage 6 projection failed for {spec.scenario_id}: {exc}"
            )
            return None, None
        projection_alignment = projection_doc.alignment_view
    else:
        # Only an explicitly direct diagnostic caller (which omits the run
        # identity) may exercise the historical v1 projection path.  Product
        # ``run_sp3`` always supplies an identity and therefore fails closed
        # when Stage 5 omitted the required unsafe outcome.
        try:
            legacy_projection = project_execution(spec, control_structure)
        except ValueError as e:
            stage_errors.append(
                f"Stage 6 projection failed for {spec.scenario_id}: {e}"
            )
            return None, None
        projection_doc = canonical_projection_data(legacy_projection)
        projection_alignment = render_projection_alignment_table(projection_doc)

    try:
        prompts = _build_stage6_prompts(
            spec,
            control_structure,
            loss_analysis,
            loader,
            projection_alignment=projection_alignment,
            capability_profile=capability_profile,
        )
    except ValueError as e:
        stage_errors.append(f"Stage 6 context failed for {spec.scenario_id}: {e}")
        return None, None

    results = _parallel_stage6_calls(
        llm_client=llm_client,
        run_dir=run_dir,
        prompts=prompts,
        temperature=temperature,
        max_workers=max_workers,
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
    if len(stage_errors) != prior_error_count:
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
    )
    return envelope, projection_doc


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
            validate_tree_branch_coverage(attack_tree),
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


def _parallel_stage6_calls(
    *,
    llm_client: LLMClient,
    run_dir: Path,
    prompts: _Stage6Prompts,
    temperature: float,
    max_workers: int,
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
        sys_prompt, user_prompt = prompt_pair
        if step == "gherkin":
            spec, _result, error = safe_llm_call(
                llm_client=llm_client,
                system_prompt=sys_prompt,
                user_prompt=user_prompt,
                response_format=GherkinSpec,
                run_dir=run_dir,
                stage="stage_6",
                step=step,
                temperature=temperature,
                validation_retries=1,
                validation_retry_feedback=(
                    " Return one closed GherkinSpec object. Every list item "
                    "must be a separate JSON string; do not emit YAML-only "
                    "continuation syntax."
                ),
                result_parser=_parse_gherkin_result,
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
        text, _result, error = safe_llm_call_raw(
            llm_client=llm_client,
            system_prompt=sys_prompt,
            user_prompt=user_prompt,
            run_dir=run_dir,
            stage="stage_6",
            step=step,
            temperature=temperature,
        )
        if error is not None:
            return None, error
        return text, None

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
) -> None:
    """Run Stage 7 validations on all specs and envelopes."""
    for spec in specs:
        _validate_spec_stage7(spec, control_structure, validation_errors)

    for env in envelopes:
        _validate_envelope_stage7(env, loss_analysis, validation_errors)


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
) -> None:
    """Run stage-local validators for a single envelope in Stage 7."""
    _extend_validation_errors(
        (
            validate_tree_branch_coverage(envelope.attack_tree),
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
    V2 bytes come from the immutable validated value; a v1 dictionary uses the
    historical exporter. When no projection is supplied only legacy artifacts
    are written.
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
) -> None:
    """Write the run manifest YAML."""
    input_hashes = {
        "enriched_threat_set": hash_model(enriched_threat_set),
        "control_structure": hash_model(control_structure),
        "loss_analysis": hash_model(loss_analysis),
    }
    prompt_hashes = hash_prompt_templates(PROMPTS_DIR)
    stage_summary = count_calls_by_stage(run_dir)

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
