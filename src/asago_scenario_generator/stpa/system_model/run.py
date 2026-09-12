"""SP1 run orchestration — Stages 1a → 1b → 2.

Orchestrates the full SP1 pipeline:
  Stage 1a: Loss analysis derivation
  Stage 1b: Capability profile inference (or load with --profile)
  Stage 2: Control structure derivation (4 calls + heuristics + critic + revision)
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    inject_kc_subcodes_display,
)
from asago_scenario_generator.models.risk_card import RiskCard
from asago_scenario_generator.stpa.infra.llm import (
    DEFAULT_TEMPERATURE as LLM_DEFAULT_TEMPERATURE,
    LLMClient,
    effective_model_config,
    effective_temperature,
)
from asago_scenario_generator.stpa.infra.llm_helpers import StageError
from asago_scenario_generator.stpa.infra.manifest import STPARunManifest
from asago_scenario_generator.stpa.infra.parallel_llm import (  # noqa: F401 — imported for patchability
    parallel_safe_llm_calls,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.infra.yaml_io import write_yaml
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionTargetProfile,
)
from asago_scenario_generator.stpa.models.loss_analysis import (
    LossAnalysis,
    stamp_proposed_direction,
)
from asago_scenario_generator.stpa.models.target_derived_structure import (
    ConstraintActionRelevance,
    ReviewedObligationBinding,
    TargetDerivedStructure,
)
from asago_scenario_generator.stpa.models.target_subject_model import (
    SubjectModelError,
    TargetSubjectModel,
    verify_target_subject_model,
)
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.control_structure import (
    ControlStructureDerivationResult,
    STAGE_2_CALL_COUNT,
    derive_control_structure,
)
from asago_scenario_generator.stpa.system_model.critic import (
    CriticFindings,
    has_unjustified_gaps,
    run_completeness_critic,
    run_revision,
    sanitize_critic_ids,
    strip_empty_responsibilities,
)
from asago_scenario_generator.stpa.system_model.heuristics import (
    check_solution_neutrality,
    run_heuristics,
)
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    diagnose_loss_analysis_semantics,
    derive_loss_analysis,
)
from asago_scenario_generator.stpa.system_model.loss_analysis_repair import (
    RepairRecord,
)
from asago_scenario_generator.stpa.system_model.loss_analysis_gates import (
    LossAnalysisGateError,
    gate_loss_analysis,
    gate_pinned_loss_analysis,
    verify_reviewed_density,
)
from asago_scenario_generator.stpa.system_model.profile import (
    derive_capability_profile,
    load_capability_profile,
)
from asago_scenario_generator.stpa.system_model.risk_coverage_review import (
    STATUS_PARTIAL,
    STATUS_SKIPPED_PINNED,
    STATUS_UNAVAILABLE,
    RiskCoverageReviewOutcome,
    canonical_graph_digest,
    graph_digest,
    run_risk_coverage_review,
)
from asago_scenario_generator.stpa.system_model.target_derived_structure import (
    derive_target_structure,
    target_derived_stage2_mode,
)

if TYPE_CHECKING:
    # The observation snapshot is an already-validated scenario_prod value;
    # system_model receives it through this seam without a runtime dependency.
    from asago_scenario_generator.stpa.scenario_prod.target_observations import (
        TargetObservationSnapshot,
    )

DEFAULT_TEMPERATURE = LLM_DEFAULT_TEMPERATURE


@dataclass
class SP1RunResult:
    """Result of a full SP1 run.

    On partial failure, ``loss_analysis``, ``capability_profile``, and
    ``control_structure`` may be ``None`` and ``stage_errors`` lists
    the failures that occurred.
    """

    loss_analysis: LossAnalysis | None = None
    capability_profile: CapabilityProfile | None = None
    control_structure: ControlStructure | None = None
    target_derived_structure: TargetDerivedStructure | None = None
    constraint_action_relevance: ConstraintActionRelevance | None = None
    critic_findings: CriticFindings | None = None
    heuristic_errors: list[str] = field(default_factory=list)
    heuristic_warnings: list[str] = field(default_factory=list)
    solution_neutrality_warnings: list[str] = field(default_factory=list)
    post_revision_warnings: list[str] = field(default_factory=list)
    revised: bool = False
    stage_errors: list[str] = field(default_factory=list)
    stage_warnings: list[str] = field(default_factory=list)


def run_sp1(
    *,
    llm_client: LLMClient,
    use_case_text: str,
    risk_cards: list[RiskCard],
    run_dir: Path,
    profile_path: Path | None = None,
    temperature: float | None = None,
    profile_name: str | None = None,
    max_workers: int = 1,
    execution_target_profile: ExecutionTargetProfile | None = None,
    target_observations: TargetObservationSnapshot | None = None,
    loss_analysis_path: Path | None = None,
    reviewed_obligation_bindings: tuple[ReviewedObligationBinding, ...] = (),
    reviewed_obligation_bindings_path: Path | None = None,
    target_subject_model: TargetSubjectModel | None = None,
    target_subject_model_path: Path | None = None,
) -> SP1RunResult:
    """Run the full SP1 pipeline: Stages 1b → 1a → 2.

    Pipeline ordering: Stage 1b (capability profile) runs first, then
    Stage 1a (loss analysis, two calls: risk_derivation + gap_analysis).
    Stage 1a-2 (gap analysis) receives the capability profile as input.
    Stage 2 runs after both 1a and 1b complete.

    Stage 2 runs in one of two modes.  With no execution target profile, a
    simulation basis, or a multi-agent capability profile, the target-blind
    four-call derivation runs unchanged.  When an observed target profile is
    supplied and the capability profile says ``multi_agent: false``, Stage 2
    is derived deterministically from the target (Phase 2 of the
    target-grounded scenario generation spec) with two bounded model calls.

    Args:
        llm_client: LLM client for making completion calls.
        use_case_text: Free-text use-case description.
        risk_cards: List of RiskCard objects from risk extraction.
        run_dir: Directory for output artifacts.
        profile_path: Optional path to a pre-built capability-profile.yaml.
            When provided, Stage 1b LLM call is skipped.
        temperature: Explicit LLM temperature override. When omitted, use the
            resolved client temperature (default 0.4).
        profile_name: Optional model profile name for manifest recording.
        max_workers: Maximum parallel workers for LLM calls (default 1 =
            sequential, backwards compatible). SP1's sequential stages do
            not use parallel execution yet; this parameter is recorded in
            the manifest and available for future use.
        execution_target_profile: Optional observed target profile. It never
            enters Stage 1a; only the Stage 2 mode decision and structure
            derivation see it.
        target_observations: Optional target-only observations paired with
            ``execution_target_profile``; they ground the session identity
            process-model entry.
        loss_analysis_path: Optional pinned loss-analysis.yaml. When
            provided, Stage 1a makes zero model calls: the pinned graph is
            validated, gated offline (accounting + five density checks, no
            bounded revision), and re-published as the canonical
            ``loss-analysis.yaml``. A failing gate is a fatal stage error.
        reviewed_obligation_bindings: Optional reviewed obligation-to-action
            bindings (owner ruling Q30(c)). They apply only to the
            target-derived Stage 2 mode, are validated offline against the
            loss analysis and the derived actions, and ride on the
            content-pinned target-derived-structure sidecar. Supplying them
            for a target-blind run is a fatal stage error.
        target_subject_model: Optional accepted ``target-subject-model-v1``
            companion (correction spec 2026-09-12). It applies only to the
            target-derived Stage 2 mode: its declared ``session_path``
            drives the session-subject record, and its content digest plus
            reviewer stamps ride on the sidecar. Supplying one for a
            target-blind run is a fatal stage error.
        target_subject_model_path: Optional path the accepted model was
            loaded from; hashed into the run manifest when present.

    Returns:
        SP1RunResult with all artifacts and diagnostic info. On partial
        failure, returns a partial result with ``stage_errors`` populated
        and remaining artifacts as None.
    """
    run_dir.mkdir(parents=True, exist_ok=True)
    if target_subject_model is not None:
        # The Python composition seam receives already parsed values, so it
        # must repeat the CLI loader's acceptance check against the actual
        # target authorities before any provider-backed stage starts.  A
        # target subject model is never silently treated as absent.
        if execution_target_profile is None or target_observations is None:
            return SP1RunResult(
                stage_errors=[
                    "stage_2/subject_model: an accepted target subject model "
                    "requires the target-derived Stage 2 mode (observed "
                    "single-controller target)"
                ]
            )
        try:
            verify_target_subject_model(
                target_subject_model,
                observations=target_observations,
                profile=execution_target_profile,
            )
        except SubjectModelError as exc:
            return SP1RunResult(stage_errors=[f"stage_2/subject_model: {exc}"])

    loader = TemplateLoader(PROMPTS_DIR)
    temperature = effective_temperature(llm_client, temperature)

    stage_errors: list[str] = []
    stage_warnings: list[str] = []

    # --- Stage 1b: Capability Profile (runs BEFORE Stage 1a) ---
    capability_profile = _try_derive_capability_profile(
        llm_client,
        use_case_text,
        run_dir,
        loader,
        temperature,
        profile_path,
        stage_errors,
    )

    # --- Stage 1a: Loss Analysis ---
    # Either a caller-pinned graph (zero model calls, offline gates only) or
    # the derived two-call analysis, followed by the deterministic gates.
    loss_analysis: LossAnalysis | None = None
    loss_analysis_gates: dict | None = None
    stage_1a_repair_record: RepairRecord | None = None
    if loss_analysis_path is not None:
        loss_analysis, loss_analysis_gates = _try_load_pinned_loss_analysis(
            loss_analysis_path,
            risk_cards,
            run_dir,
            stage_errors,
        )
    else:
        # --- Stage 1a: Loss Analysis (two calls, receives capability profile) ---
        (
            loss_analysis,
            accounting_normalization_warnings,
            stage_1a_repair_record,
        ) = _try_derive_loss_analysis(
            llm_client,
            use_case_text,
            risk_cards,
            run_dir,
            loader,
            temperature,
            stage_errors,
            capability_profile,
            stage_warnings,
        )

        # --- Stage 1a gates: deterministic risk accounting + hazard graph density.
        # A failing graph gets one bounded revision call; a second failure is a
        # fatal stage error recorded with the exact failing checks.
        if loss_analysis is not None:
            loss_analysis, loss_analysis_gates = _try_gate_loss_analysis(
                llm_client,
                loss_analysis,
                use_case_text,
                risk_cards,
                run_dir,
                loader,
                temperature,
                stage_errors,
                accounting_normalization_warnings,
            )

    # --- Stage 1a advisory risk-coverage review (spec deviation 10) ---
    # One bounded call reviews the gated graph against the risk cards.  It is
    # advisory: it never changes the graph and never blocks the run.  Pinned
    # runs skip it because the supplied graph was already reviewed.
    if loss_analysis_path is not None:
        risk_coverage_review = RiskCoverageReviewOutcome(
            status=STATUS_SKIPPED_PINNED,
            call_count=0,
        )
    elif loss_analysis is not None:
        risk_coverage_review = _try_run_risk_coverage_review(
            llm_client,
            loss_analysis,
            risk_cards,
            use_case_text,
            run_dir,
            loader,
            temperature,
            stage_warnings,
        )
    else:
        risk_coverage_review = None

    # --- Stage 2: Control Structure + heuristics + critic + revision ---
    stage2_result = _run_stage_2_block(
        llm_client,
        use_case_text,
        loss_analysis,
        capability_profile,
        run_dir,
        loader,
        temperature,
        stage_errors,
        stage_warnings,
        execution_target_profile=execution_target_profile,
        target_observations=target_observations,
        reviewed_obligation_bindings=reviewed_obligation_bindings,
        target_subject_model=target_subject_model,
    )

    # Write run manifest (always, even on partial failure)
    _profile_skipped = profile_path is not None
    _write_manifest(
        run_dir=run_dir,
        llm_client=llm_client,
        use_case_text=use_case_text,
        risk_cards=risk_cards,
        loader=loader,
        critic_findings=stage2_result.critic_findings,
        revised=stage2_result.revised,
        post_revision_warnings=stage2_result.post_revision_warnings,
        temperature=temperature,
        profile_skipped=_profile_skipped,
        stage_errors=stage_errors,
        stage_warnings=stage_warnings,
        profile_name=profile_name,
        max_workers=max_workers,
        stage_1a_gates=loss_analysis_gates,
        stage_1a_pinned=loss_analysis_path is not None,
        loss_analysis_path=loss_analysis_path,
        risk_coverage_review=risk_coverage_review,
        stage_2_mode=stage2_result.mode,
        stage_2_call_count=stage2_result.model_call_count,
        reviewed_obligation_bindings_path=reviewed_obligation_bindings_path,
        target_subject_model_path=target_subject_model_path,
        stage_1a_repair=stage_1a_repair_record,
    )

    return SP1RunResult(
        loss_analysis=(
            stage2_result.loss_analysis
            if stage2_result.loss_analysis is not None
            else loss_analysis
        ),
        capability_profile=capability_profile,
        control_structure=stage2_result.control_structure,
        target_derived_structure=stage2_result.target_derived,
        constraint_action_relevance=stage2_result.relevance,
        critic_findings=stage2_result.critic_findings,
        heuristic_errors=stage2_result.heuristic_errors,
        heuristic_warnings=stage2_result.heuristic_warnings,
        solution_neutrality_warnings=stage2_result.solution_neutrality_warnings,
        post_revision_warnings=stage2_result.post_revision_warnings,
        revised=stage2_result.revised,
        stage_errors=stage_errors,
        stage_warnings=stage_warnings,
    )


@dataclass
class _Stage2Result:
    """Internal result container for the Stage 2 block."""

    loss_analysis: LossAnalysis | None = None
    control_structure: ControlStructure | None = None
    target_derived: TargetDerivedStructure | None = None
    relevance: ConstraintActionRelevance | None = None
    critic_findings: CriticFindings | None = None
    heuristic_errors: list[str] = field(default_factory=list)
    heuristic_warnings: list[str] = field(default_factory=list)
    solution_neutrality_warnings: list[str] = field(default_factory=list)
    post_revision_warnings: list[str] = field(default_factory=list)
    revised: bool = False
    mode: str = "target_blind"
    model_call_count: int = STAGE_2_CALL_COUNT


def _try_derive_loss_analysis(
    llm_client: LLMClient,
    use_case_text: str,
    risk_cards: list[RiskCard],
    run_dir: Path,
    loader: TemplateLoader,
    temperature: float,
    stage_errors: list[str],
    capability_profile: CapabilityProfile | None = None,
    stage_warnings: list[str] | None = None,
) -> tuple[LossAnalysis | None, list[str], RepairRecord]:
    """Run Stage 1a (two calls), recording errors on failure.

    Returns the analysis (or ``None``), any accounting-normalization warnings
    produced while parsing the provider responses, and the accumulating
    repair record the run manifest summarizes.
    """
    normalization_warnings: list[str] = []
    repair_record = RepairRecord()
    try:
        analysis = derive_loss_analysis(
            llm_client=llm_client,
            use_case_text=use_case_text,
            risk_cards=risk_cards,
            run_dir=run_dir,
            template_loader=loader,
            temperature=temperature,
            capability_profile=capability_profile,
            normalization_warnings=normalization_warnings,
            repair_record=repair_record,
        )
        # Deterministic code owns the direction-authority stamp: entries on
        # a derived graph are proposals until a human reviews them (owner
        # ruling Q30, 2026-09-10).
        stamp_proposed_direction(analysis)
        if stage_warnings is not None:
            stage_warnings.extend(normalization_warnings)
            stage_warnings.extend(
                str(item)
                for item in diagnose_loss_analysis_semantics(
                    analysis,
                    use_case_text=use_case_text,
                    risk_cards=risk_cards,
                )
            )
        return analysis, normalization_warnings, repair_record
    except StageError as exc:
        stage_errors.append(str(exc))
        return None, normalization_warnings, repair_record


def _try_gate_loss_analysis(
    llm_client: LLMClient,
    loss_analysis: LossAnalysis,
    use_case_text: str,
    risk_cards: list[RiskCard],
    run_dir: Path,
    loader: TemplateLoader,
    temperature: float,
    stage_errors: list[str],
    accounting_normalization_warnings: list[str] | None = None,
) -> tuple[LossAnalysis | None, dict]:
    """Run the deterministic Stage 1a gates, recording failures as stage errors.

    On a gate failure the loss analysis is dropped so Stage 2 never runs on a
    graph that cannot tell scenarios apart; the exact failing checks stay in
    the stage errors and in ``loss-analysis-gates.yaml``.
    """
    try:
        outcome = gate_loss_analysis(
            llm_client=llm_client,
            loss_analysis=loss_analysis,
            use_case_text=use_case_text,
            risk_cards=risk_cards,
            run_dir=run_dir,
            template_loader=loader,
            temperature=temperature,
            accounting_normalization_warnings=accounting_normalization_warnings,
        )
    except StageError as exc:
        # Includes LossAnalysisGateError and a revision call that itself
        # failed; the gates artifact is always persisted before this raise.
        stage_errors.append(str(exc))
        if isinstance(exc, LossAnalysisGateError):
            accounting = "failed" if exc.gate == "risk_accounting" else "passed"
            density = "failed" if exc.gate == "hazard_graph_density" else "passed"
        else:
            accounting = "passed"
            density = "failed"
        revision_count = 1 if getattr(exc, "revision_attempted", False) else 0
        return None, {
            "risk_accounting": accounting,
            "hazard_graph_density": density,
            "graph_revision_call_count": revision_count,
        }
    gates = {
        "risk_accounting": ("passed" if outcome.accounting.passed else "failed"),
        "hazard_graph_density": (
            "passed_after_revision"
            if outcome.revision_applied
            else ("failed" if not outcome.density.passed else "passed")
        ),
        "graph_revision_call_count": 1 if outcome.revision_attempted else 0,
    }
    # The bounded revision call re-derives constraints; restamp so no
    # revised entry can carry a reviewed claim out of the derived path.
    stamp_proposed_direction(outcome.loss_analysis)
    return outcome.loss_analysis, gates


def _try_load_pinned_loss_analysis(
    loss_analysis_path: Path,
    risk_cards: list[RiskCard],
    run_dir: Path,
    stage_errors: list[str],
) -> tuple[LossAnalysis | None, dict]:
    """Accept a caller-pinned loss analysis with zero Stage 1a model calls.

    The pinned bytes are validated, gated offline (no bounded revision), and
    re-published as the canonical ``loss-analysis.yaml`` exactly as the
    derived paths write it.  A malformed file or a failing gate is a fatal
    stage error recorded with the exact failing checks; Stage 2 then sees no
    loss analysis, mirroring the derived gate-failure behavior.
    """
    try:
        payload = yaml.safe_load(loss_analysis_path.read_text(encoding="utf-8"))
        loss_analysis = LossAnalysis.model_validate(payload)
    except Exception as exc:  # noqa: BLE001 - recorded as a stage error
        stage_errors.append(f"stage_1a/pinned: {exc}")
        return None, {
            "risk_accounting": "passed",
            "hazard_graph_density": "passed",
            "graph_revision_call_count": 0,
        }
    try:
        gate_pinned_loss_analysis(
            loss_analysis=loss_analysis,
            risk_cards=risk_cards,
            run_dir=run_dir,
        )
    except LossAnalysisGateError as exc:
        stage_errors.append(str(exc))
        accounting = "failed" if exc.gate == "risk_accounting" else "passed"
        density = "failed" if exc.gate == "hazard_graph_density" else "passed"
        return None, {
            "risk_accounting": accounting,
            "hazard_graph_density": density,
            "graph_revision_call_count": 0,
        }
    write_yaml(loss_analysis, run_dir / "loss-analysis.yaml")
    return loss_analysis, {
        "risk_accounting": "passed",
        "hazard_graph_density": "passed",
        "graph_revision_call_count": 0,
    }


def _try_run_risk_coverage_review(
    llm_client: LLMClient,
    loss_analysis: LossAnalysis,
    risk_cards: list[RiskCard],
    use_case_text: str,
    run_dir: Path,
    loader: TemplateLoader,
    temperature: float,
    stage_warnings: list[str],
) -> RiskCoverageReviewOutcome:
    """Run the advisory Stage 1a risk-coverage review without blocking the run.

    The review is advisory (spec deviation 10): it never changes the graph,
    never raises, and records an ``unavailable`` verdict with the typed
    reason when its single bounded call fails.  The digest pins the review
    to the exact gated graph bytes.
    """
    digest = graph_digest(loss_analysis)
    outcome = run_risk_coverage_review(
        llm_client=llm_client,
        loss_analysis=loss_analysis,
        risk_cards=risk_cards,
        use_case_text=use_case_text,
        run_dir=run_dir,
        template_loader=loader,
        temperature=temperature,
        reviewed_loss_analysis_digest=digest,
    )
    if outcome.status in (STATUS_UNAVAILABLE, STATUS_PARTIAL):
        stage_warnings.append(
            f"stage_1a/risk_coverage_review {outcome.status}: "
            f"{outcome.failure_reason or 'invalid or missing rows'}"
        )
    return outcome


def _try_derive_capability_profile(
    llm_client: LLMClient,
    use_case_text: str,
    run_dir: Path,
    loader: TemplateLoader,
    temperature: float,
    profile_path: Path | None,
    stage_errors: list[str],
) -> CapabilityProfile | None:
    """Run Stage 1b (or load a pre-built profile), recording errors on failure."""
    if profile_path is not None:
        capability_profile = load_capability_profile(profile_path)
        write_yaml(
            capability_profile,
            run_dir / "capability-profile.yaml",
            post_process=inject_kc_subcodes_display,
        )
        return capability_profile
    try:
        return derive_capability_profile(
            llm_client=llm_client,
            use_case_text=use_case_text,
            run_dir=run_dir,
            template_loader=loader,
            temperature=temperature,
        )
    except StageError as exc:
        stage_errors.append(str(exc))
        return None


def _stage2_prerequisites_missing(
    loss_analysis: LossAnalysis | None,
    capability_profile: CapabilityProfile | None,
) -> bool:
    """Return whether Stage 2 lacks either required upstream artifact."""
    return loss_analysis is None or capability_profile is None


def _derive_stage2_control_structure(
    llm_client: LLMClient,
    use_case_text: str,
    loss_analysis: LossAnalysis,
    capability_profile: CapabilityProfile,
    run_dir: Path,
    loader: TemplateLoader,
    temperature: float,
    stage_errors: list[str],
) -> ControlStructureDerivationResult | None:
    """Derive Stage 2's structure while retaining a graceful failure result."""
    try:
        return derive_control_structure(
            llm_client=llm_client,
            use_case_text=use_case_text,
            loss_analysis=loss_analysis,
            capability_profile=capability_profile,
            run_dir=run_dir,
            template_loader=loader,
            temperature=temperature,
            post_review_density_check=lambda reviewed: verify_reviewed_density(
                reviewed, run_dir=run_dir
            ),
        )
    except StageError as exc:
        stage_errors.append(str(exc))
        return None


def _maybe_apply_revision(
    control_structure: ControlStructure,
    *,
    critic_findings: CriticFindings,
    llm_client: LLMClient,
    use_case_text: str,
    run_dir: Path,
    loss_analysis: LossAnalysis,
    loader: TemplateLoader,
    temperature: float,
) -> tuple[ControlStructure, list[str], bool]:
    """Apply a critic revision only when unjustified gaps are present."""
    if not has_unjustified_gaps(critic_findings):
        return control_structure, [], False

    # Keep the baseline identity for the applied/not-applied decision.
    # ``run_revision`` retains that object on provider, validation, or
    # merge failure; an attempted call must not be reported as an applied
    # revision in the result or manifest.
    baseline_control_structure = control_structure
    control_structure, post_revision_warnings = run_revision(
        llm_client=llm_client,
        control_structure=control_structure,
        critic_findings=critic_findings,
        use_case_text=use_case_text,
        run_dir=run_dir,
        loss_analysis=loss_analysis,
        template_loader=loader,
        temperature=temperature,
    )
    # Strip empty responsibilities that revision may have introduced
    control_structure, strip_warnings = strip_empty_responsibilities(control_structure)
    post_revision_warnings.extend(strip_warnings)
    revised = control_structure != baseline_control_structure
    write_yaml(control_structure, run_dir / "control-structure.yaml")
    return control_structure, post_revision_warnings, revised


def _run_stage_2_block(
    llm_client: LLMClient,
    use_case_text: str,
    loss_analysis: LossAnalysis | None,
    capability_profile: CapabilityProfile | None,
    run_dir: Path,
    loader: TemplateLoader,
    temperature: float,
    stage_errors: list[str],
    stage_warnings: list[str] | None = None,
    *,
    execution_target_profile: ExecutionTargetProfile | None = None,
    target_observations: TargetObservationSnapshot | None = None,
    reviewed_obligation_bindings: tuple[ReviewedObligationBinding, ...] = (),
    target_subject_model: TargetSubjectModel | None = None,
) -> _Stage2Result:
    """Run Stage 2: control structure derivation, heuristics, critic, and revision.

    Returns an empty result when prerequisites are missing or derivation fails.
    In target-derived mode (observed single-controller target), the structure
    is derived deterministically from the target with two bounded model calls,
    and the completeness critic and revision are skipped: nothing was
    invented that needs reviewing, and the Phase 1 gates already ran.
    """
    if _stage2_prerequisites_missing(loss_analysis, capability_profile):
        return _Stage2Result()

    stage_warnings = [] if stage_warnings is None else stage_warnings
    mode = target_derived_stage2_mode(capability_profile, execution_target_profile)
    if reviewed_obligation_bindings and mode != "target_derived":
        # Reviewed bindings bind obligations to observed target actions; a
        # target-blind structure has nothing to bind them to, so accepting
        # them here would silently discard a reviewed input.
        stage_errors.append(
            "stage_2/bindings: reviewed obligation bindings require the "
            "target-derived Stage 2 mode (observed single-controller target)"
        )
        return _Stage2Result(mode=mode, model_call_count=0)
    if target_subject_model is not None and mode != "target_derived":
        # An accepted subject model declares roles against an observed
        # target; a target-blind structure has nothing to bind it to.
        stage_errors.append(
            "stage_2/subject_model: an accepted target subject model "
            "requires the target-derived Stage 2 mode (observed "
            "single-controller target)"
        )
        return _Stage2Result(mode=mode, model_call_count=0)
    if mode == "target_derived":
        return _run_target_derived_stage_2(
            llm_client,
            use_case_text,
            loss_analysis,
            capability_profile,
            run_dir,
            loader,
            temperature,
            stage_errors,
            stage_warnings,
            execution_target_profile=execution_target_profile,
            target_observations=target_observations,
            reviewed_obligation_bindings=reviewed_obligation_bindings,
            target_subject_model=target_subject_model,
        )

    derivation = _derive_stage2_control_structure(
        llm_client,
        use_case_text,
        loss_analysis,
        capability_profile,
        run_dir,
        loader,
        temperature,
        stage_errors,
    )
    if derivation is None:
        return _Stage2Result()
    loss_analysis = derivation.loss_analysis
    control_structure = derivation.control_structure
    merge_warnings = list(derivation.warnings)
    stage_warnings.extend(merge_warnings)

    # Structural heuristics (always run after Call 3)
    heuristic_result = run_heuristics(control_structure, loss_analysis)
    solution_neutrality_warnings = check_solution_neutrality(control_structure)

    # Completeness critic (graceful — returns empty findings on failure)
    critic_findings = run_completeness_critic(
        llm_client=llm_client,
        control_structure=control_structure,
        capability_profile=capability_profile,
        use_case_text=use_case_text,
        run_dir=run_dir,
        template_loader=loader,
        temperature=temperature,
        loss_analysis=loss_analysis,
        call3_warnings=merge_warnings,
    )

    # Sanitize non-conforming IDs from critic remedies before revision
    critic_findings = sanitize_critic_ids(critic_findings)

    # Revision (single attempt if unjustified gaps; graceful on failure)
    control_structure, post_revision_warnings, revised = _maybe_apply_revision(
        control_structure,
        critic_findings=critic_findings,
        llm_client=llm_client,
        use_case_text=use_case_text,
        run_dir=run_dir,
        loss_analysis=loss_analysis,
        loader=loader,
        temperature=temperature,
    )

    return _Stage2Result(
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        critic_findings=critic_findings,
        heuristic_errors=list(heuristic_result.errors),
        heuristic_warnings=list(heuristic_result.warnings),
        solution_neutrality_warnings=solution_neutrality_warnings,
        post_revision_warnings=post_revision_warnings,
        revised=revised,
        mode="target_blind",
        model_call_count=STAGE_2_CALL_COUNT,
    )


def _run_target_derived_stage_2(
    llm_client: LLMClient,
    use_case_text: str,
    loss_analysis: LossAnalysis | None,
    capability_profile: CapabilityProfile | None,
    run_dir: Path,
    loader: TemplateLoader,
    temperature: float,
    stage_errors: list[str],
    stage_warnings: list[str],
    *,
    execution_target_profile: ExecutionTargetProfile,
    target_observations: TargetObservationSnapshot | None,
    reviewed_obligation_bindings: tuple[ReviewedObligationBinding, ...] = (),
    target_subject_model: TargetSubjectModel | None = None,
) -> _Stage2Result:
    """Run the deterministic target-derived Stage 2 derivation path."""
    if loss_analysis is None or capability_profile is None:
        return _Stage2Result()
    try:
        derived_result = derive_target_structure(
            llm_client=llm_client,
            use_case_text=use_case_text,
            loss_analysis=loss_analysis,
            capability_profile=capability_profile,
            execution_target_profile=execution_target_profile,
            target_observations=target_observations,
            reviewed_obligation_bindings=reviewed_obligation_bindings,
            run_dir=run_dir,
            template_loader=loader,
            temperature=temperature if temperature is not None else 0.4,
            target_subject_model=target_subject_model,
        )
    except StageError as exc:
        stage_errors.append(str(exc))
        return _Stage2Result(
            mode="target_derived",
            # Logical calls are 0 (the stage failed); the manifest's
            # count_calls_by_stage still records every provider attempt.
            model_call_count=0,
        )
    except ValueError as exc:
        # A malformed profile (for example one with no observed operations)
        # fails deterministically before any model call; record it as a
        # stage error instead of crashing the run after ICA spend.
        stage_errors.append(f"stage_2/target_derived: {exc}")
        return _Stage2Result(mode="target_derived", model_call_count=0)
    heuristic_result = run_heuristics(
        derived_result.control_structure, derived_result.loss_analysis
    )
    solution_neutrality_warnings = check_solution_neutrality(
        derived_result.control_structure
    )
    stage_warnings.extend(derived_result.warnings)
    return _Stage2Result(
        loss_analysis=derived_result.loss_analysis,
        control_structure=derived_result.control_structure,
        target_derived=derived_result.derived,
        relevance=derived_result.relevance,
        heuristic_errors=list(heuristic_result.errors),
        heuristic_warnings=list(heuristic_result.warnings),
        solution_neutrality_warnings=solution_neutrality_warnings,
        mode="target_derived",
        model_call_count=derived_result.derived.model_call_count,
    )


def _compute_input_hashes(
    use_case_text: str,
    risk_cards: list[RiskCard],
    loss_analysis_path: Path | None = None,
    reviewed_obligation_bindings_path: Path | None = None,
    target_subject_model_path: Path | None = None,
) -> dict[str, str]:
    """Compute SHA-256 hashes of input artifacts for the manifest."""
    hashes = {
        "use_case_text": hashlib.sha256(use_case_text.encode("utf-8")).hexdigest()
    }
    if risk_cards:
        risk_ids = ",".join(rc.risk_id for rc in risk_cards)
        hashes["risk_extraction"] = hashlib.sha256(risk_ids.encode("utf-8")).hexdigest()
    else:
        hashes["risk_extraction"] = hashlib.sha256(b"").hexdigest()
    if loss_analysis_path is not None:
        hashes["loss_analysis"] = hashlib.sha256(
            loss_analysis_path.read_bytes()
        ).hexdigest()
    if reviewed_obligation_bindings_path is not None:
        hashes["reviewed_obligation_bindings"] = hashlib.sha256(
            reviewed_obligation_bindings_path.read_bytes()
        ).hexdigest()
    if target_subject_model_path is not None:
        hashes["target_subject_model"] = hashlib.sha256(
            target_subject_model_path.read_bytes()
        ).hexdigest()
    return hashes


def _summarize_critic_findings(critic_findings: CriticFindings | None) -> list[str]:
    """Build a human-readable summary list from critic findings."""
    if critic_findings is None:
        return []
    return [f"{gap.gap_type}: {gap.description}" for gap in critic_findings.gaps]


def _write_manifest(
    *,
    run_dir: Path,
    llm_client: LLMClient,
    use_case_text: str,
    risk_cards: list[RiskCard],
    loader: TemplateLoader,
    critic_findings: CriticFindings | None,
    revised: bool = False,
    post_revision_warnings: list[str] | None = None,
    temperature: float,
    profile_skipped: bool,
    stage_errors: list[str] | None = None,
    stage_warnings: list[str] | None = None,
    profile_name: str | None = None,
    max_workers: int = 1,
    stage_1a_gates: dict | None = None,
    stage_1a_pinned: bool = False,
    loss_analysis_path: Path | None = None,
    risk_coverage_review: RiskCoverageReviewOutcome | None = None,
    stage_2_mode: str = "target_blind",
    stage_2_call_count: int = STAGE_2_CALL_COUNT,
    reviewed_obligation_bindings_path: Path | None = None,
    target_subject_model_path: Path | None = None,
    stage_1a_repair: RepairRecord | None = None,
) -> None:
    """Write the run manifest with stage summary, input hashes, and prompt hashes."""
    input_hashes = _compute_input_hashes(
        use_case_text,
        risk_cards,
        loss_analysis_path,
        reviewed_obligation_bindings_path,
        target_subject_model_path,
    )
    prompt_hashes = loader.hash_prompt_templates()
    critic_summary = _summarize_critic_findings(critic_findings)
    stage_1b_calls = 0 if profile_skipped else 1
    _stage_1a_call_count = 0 if stage_1a_pinned else 2
    _stage_2_call_count = stage_2_call_count

    stage_1a_summary: dict[str, object] = {
        "call_count": _stage_1a_call_count,
        "source": "pinned" if stage_1a_pinned else "derived",
    }
    if stage_1a_repair is not None and stage_1a_repair.entries:
        # The run-level, cross-stage repair record: path, filename, and
        # per-stage counts by outcome, so a reviewer can see every
        # transformation without opening calls.jsonl.
        stage_1a_summary["repair"] = {
            "artifact": "loss-analysis-repair.yaml",
            "record_path": str(run_dir / "loss-analysis-repair.yaml"),
            "counts_by_stage": stage_1a_repair.counts_by_stage(),
        }
    if stage_1a_gates is not None:
        stage_1a_summary.update(stage_1a_gates)
        # The bounded graph-revision call is a third Stage 1a model call.
        stage_1a_summary["call_count"] = _stage_1a_call_count + stage_1a_gates.get(
            "graph_revision_call_count", 0
        )
    if risk_coverage_review is not None:
        review_summary: dict[str, object] = {
            "status": risk_coverage_review.status,
            "call_count": risk_coverage_review.call_count,
            "failure_reason": risk_coverage_review.failure_reason,
            "reviewed_loss_analysis_digest": (
                risk_coverage_review.reviewed_loss_analysis_digest
            ),
        }
        artifact = risk_coverage_review.artifact
        if artifact is not None:
            review_summary["rows_valid"] = artifact.summary.rows_valid
            review_summary["rows_invalid"] = artifact.summary.rows_invalid
            review_summary["rows_missing"] = artifact.summary.rows_missing
        stage_1a_summary["risk_coverage_review"] = review_summary
        stage_1a_summary["call_count"] = (
            int(stage_1a_summary["call_count"]) + risk_coverage_review.call_count
        )

    stage_2_summary: dict[str, object] = {
        "call_count": _stage_2_call_count,
        "mode": stage_2_mode,
    }
    # Target-blind Call 3 may reword the graph after the review.  Record the
    # final published digest whenever it differs from the reviewed one, so a
    # reviewer can see that the review covered a different graph.
    if (
        risk_coverage_review is not None
        and risk_coverage_review.reviewed_loss_analysis_digest
        and not stage_1a_pinned
    ):
        published_digest = canonical_graph_digest(run_dir)
        if published_digest != risk_coverage_review.reviewed_loss_analysis_digest:
            stage_2_summary["post_review_loss_analysis_digest"] = published_digest

    model_config_dict = effective_model_config(llm_client, temperature=temperature)
    model_config_dict["max_workers"] = max_workers
    if profile_name is not None:
        model_config_dict["profile"] = profile_name

    manifest = STPARunManifest(
        run_id=run_dir.name,
        run_dir=str(run_dir),
        created_at=datetime.now(timezone.utc).isoformat(),
        **{  # type: ignore[arg-type]
            "model_config": model_config_dict,
        },
        input_hashes=input_hashes,
        prompt_hashes=prompt_hashes,
        stage_summary={
            "stage_1a": stage_1a_summary,
            "stage_1b": {"call_count": stage_1b_calls},
            "stage_2": stage_2_summary,
        },
        critic_findings=critic_summary,
        revised=revised,
        post_revision_warnings=post_revision_warnings or [],
        stage_warnings=stage_warnings or [],
    )
    if stage_errors:
        manifest.stage_errors = stage_errors
    write_yaml(manifest, run_dir / "run-manifest.yaml")
