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

import yaml

from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    inject_kc_subcodes_display,
)
from asago_scenario_generator.models.risk_card import RiskCard
from asago_scenario_generator.stpa.infra.llm import (
    LLMClient,
    effective_model_config,
    effective_temperature,
)
from asago_scenario_generator.stpa.infra.llm_helpers import (
    RequestTally,
    StageError,
    count_requests,
)
from asago_scenario_generator.stpa.infra.manifest import STPARunManifest
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.infra.yaml_io import write_yaml
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.loss_analysis import (
    LossAnalysis,
    stamp_proposed_direction,
)
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.control_structure import (
    ControlStructureDerivationResult,
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
    uncited_security_constraints,
)
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    diagnose_loss_analysis_semantics,
    derive_loss_analysis,
)
from asago_scenario_generator.stpa.system_model.loss_analysis_repair import (
    RepairRecord,
)
from asago_scenario_generator.stpa.system_model.reply_constraint_placement import (
    attach_to_sole_reply_responsibility,
    with_reply_placement_gaps,
)
from asago_scenario_generator.stpa.system_model.loss_analysis_gates import (
    LossAnalysisGateError,
    StatedRuleCheck,
    gate_loss_analysis,
    gate_pinned_loss_analysis,
    verify_reviewed_density,
)
from asago_scenario_generator.stpa.system_model.rule_span_repair import (
    RULE_SPAN_REPAIR_KIND,
)
from asago_scenario_generator.stpa.system_model.risk_actionability import (
    ARTIFACT_FILENAME as RISK_ACTIONABILITY_FILENAME,
    RiskActionabilityRecord,
    classify_risk_actionability,
)
from asago_scenario_generator.stpa.system_model.stated_rule_coverage import (
    StatedRuleCoverageArtifact,
    StatedRuleFinding,
    StatedRuleRevision,
    assess_stated_rules,
    coverage_warnings,
    finalize_stated_rule_coverage,
    manifest_summary as stated_rule_manifest_summary,
)
from asago_scenario_generator.stpa.system_model.target_evidence import (
    check_evidence_bindings,
    TargetEvidence,
)
from asago_scenario_generator.stpa.system_model.profile import (
    derive_capability_profile,
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
    capability_profile: CapabilityProfile | None = None,
    temperature: float | None = None,
    profile_name: str | None = None,
    max_workers: int = 1,
    loss_analysis_path: Path | None = None,
    target_evidence: TargetEvidence | None = None,
) -> SP1RunResult:
    """Run the full SP1 pipeline: Stages 1b → 1a → 2.

    Pipeline ordering: Stage 1b (capability profile) runs first, then
    Stage 1a (loss analysis, two calls: risk_derivation + gap_analysis).
    Stage 1a-2 (gap analysis) receives the capability profile as input.
    Stage 2 runs after both 1a and 1b complete.

    Stage 2 runs one unified analysis for every supplied input. Observed
    profiles, tool definitions, policies, state observations, simulation
    bases and multi-agent capability flags enrich that analysis; they never
    select a different derivation.

    Before a derived Stage 1a, one bounded classification applies the STPA
    boundary test to every risk card (``risk-actionability.yaml``); only
    actionable cards feed loss derivation, its gates, and the coverage
    review.  Discovered target evidence, when supplied, grounds the Stage 1a
    hazards and constraints and every Stage 2 call; losses stay derived from
    risk cards.

    Args:
        llm_client: LLM client for making completion calls.
        use_case_text: Free-text use-case description.
        risk_cards: List of RiskCard objects from risk extraction.
        run_dir: Directory for output artifacts.
        capability_profile: Optional pre-built capability profile. When
            provided, the Stage 1b LLM call is skipped and the profile is
            published as ``capability-profile.yaml`` in *run_dir*.
        temperature: Explicit LLM temperature override. When omitted, use the
            resolved client temperature (default 0.4).
        profile_name: Optional model profile name for manifest recording.
        max_workers: Worker count recorded in the run manifest. SP1's
            stages run sequentially; the value does not change execution.
        loss_analysis_path: Optional pinned loss-analysis.yaml. When
            provided, Stage 1a makes zero model calls: the pinned graph is
            validated, gated offline (accounting + structural density checks,
            with subject-phrase mismatches recorded as advisory evidence and no
            bounded revision), and re-published as the canonical
            ``loss-analysis.yaml``. A failing gate is a fatal stage error.
        target_evidence: Optional discovered target evidence (inventory,
            state schema, session fields, policy text).  Persisted as
            ``target-evidence.yaml``.

    Returns:
        SP1RunResult with all artifacts and diagnostic info. On partial
        failure, returns a partial result with ``stage_errors`` populated
        and remaining artifacts as None.
    """
    run_dir.mkdir(parents=True, exist_ok=True)

    loader = TemplateLoader(PROMPTS_DIR)
    temperature = effective_temperature(llm_client, temperature)

    stage_errors: list[str] = []
    stage_warnings: list[str] = []

    if target_evidence is not None:
        target_evidence.write(run_dir / "target-evidence.yaml")
        stage_warnings.extend(
            f"target_evidence: {item}" for item in target_evidence.diagnostics
        )

    # --- Stage 1b: Capability Profile (runs BEFORE Stage 1a) ---
    with count_requests() as stage_1b_sent:
        capability_profile = _try_derive_capability_profile(
            llm_client,
            use_case_text,
            run_dir,
            loader,
            temperature,
            capability_profile,
            stage_errors,
        )

    # --- Stage 1a: Loss Analysis ---
    # Either a caller-pinned graph (zero model calls, offline gates only) or
    # the derived two-call analysis, followed by the deterministic gates.
    loss_analysis: LossAnalysis | None = None
    loss_analysis_gates: dict | None = None
    stage_1a_repair_record: RepairRecord | None = None
    risk_actionability: RiskActionabilityRecord | None = None
    stated_rule_coverage: StatedRuleCoverageArtifact | None = None
    derivation_sent = RequestTally()
    # A pinned graph already accounts for every supplied card.
    stage_1a_cards = risk_cards
    if loss_analysis_path is None:
        actionability = classify_risk_actionability(
            llm_client=llm_client,
            use_case_text=use_case_text,
            risk_cards=risk_cards,
            run_dir=run_dir,
            template_loader=loader,
            temperature=temperature,
            target_evidence=target_evidence,
        )
        risk_actionability = actionability.record
        stage_1a_cards = actionability.actionable_cards
        stage_warnings.extend(
            f"stage_1a/risk_actionability: {item}"
            for item in actionability.record.warnings
        )
    if loss_analysis_path is not None:
        loss_analysis, loss_analysis_gates = _try_load_pinned_loss_analysis(
            loss_analysis_path,
            risk_cards,
            run_dir,
            stage_errors,
        )
    else:
        (
            loss_analysis,
            loss_analysis_gates,
            stage_1a_repair_record,
            stated_rule_coverage,
        ) = _run_derived_stage_1a(
            llm_client,
            use_case_text,
            stage_1a_cards,
            run_dir,
            loader,
            temperature,
            stage_errors,
            stage_warnings,
            capability_profile,
            target_evidence,
            derivation_sent,
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
            stage_1a_cards,
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
        target_evidence=target_evidence,
    )

    # Write run manifest (always, even on partial failure)
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
        stage_1a_requests=derivation_sent.requests,
        stage_1b_requests=stage_1b_sent.requests,
        stage_errors=stage_errors,
        stage_warnings=stage_warnings,
        profile_name=profile_name,
        max_workers=max_workers,
        stage_1a_gates=loss_analysis_gates,
        stage_1a_pinned=loss_analysis_path is not None,
        loss_analysis_path=loss_analysis_path,
        risk_coverage_review=risk_coverage_review,
        stage_2_call_count=stage2_result.model_call_count,
        stage_1a_repair=stage_1a_repair_record,
        risk_actionability=risk_actionability,
        target_evidence=target_evidence,
        stated_rule_coverage=stated_rule_coverage,
        uncited_constraints=stage2_result.uncited_constraints,
    )

    return SP1RunResult(
        loss_analysis=(
            stage2_result.loss_analysis
            if stage2_result.loss_analysis is not None
            else loss_analysis
        ),
        capability_profile=capability_profile,
        control_structure=stage2_result.control_structure,
        critic_findings=stage2_result.critic_findings,
        heuristic_errors=stage2_result.heuristic_errors,
        heuristic_warnings=stage2_result.heuristic_warnings,
        solution_neutrality_warnings=stage2_result.solution_neutrality_warnings,
        post_revision_warnings=stage2_result.post_revision_warnings,
        revised=stage2_result.revised,
        stage_errors=stage_errors,
        stage_warnings=stage_warnings,
    )


def _run_derived_stage_1a(
    llm_client: LLMClient,
    use_case_text: str,
    cards: list[RiskCard],
    run_dir: Path,
    loader: TemplateLoader,
    temperature: float,
    stage_errors: list[str],
    stage_warnings: list[str],
    capability_profile: CapabilityProfile | None,
    target_evidence: TargetEvidence | None,
    derivation_sent: RequestTally,
) -> tuple[
    LossAnalysis | None,
    dict | None,
    RepairRecord,
    StatedRuleCoverageArtifact | None,
]:
    """Derive Stage 1a (two calls, receives the capability profile) and gate it.

    Returns the gated analysis, the gate record, the repair record, and the
    stated-rule coverage artifact; the last two entries stay ``None`` when
    derivation produced no analysis.  ``derivation_sent`` collects the
    requests the derivation sent, its repairs included.
    """
    with count_requests(derivation_sent):
        (
            loss_analysis,
            accounting_normalization_warnings,
            repair_record,
        ) = _try_derive_loss_analysis(
            llm_client,
            use_case_text,
            cards,
            run_dir,
            loader,
            temperature,
            stage_errors,
            capability_profile,
            stage_warnings,
            target_evidence=target_evidence,
        )
    if loss_analysis is None:
        return None, None, repair_record, None

    # Stage 1a gates: deterministic risk accounting + hazard graph density.
    # A failing graph gets bounded revision rounds; a failure after them is
    # a fatal stage error recorded with the exact failing checks.  Stated
    # use-case rules that no constraint carries get their own
    # addition-only revision on a graph that passes density; that round
    # never fails the stage.
    draft_loss_analysis = loss_analysis
    stated_rules = assess_stated_rules(
        llm_client=llm_client,
        use_case_text=use_case_text,
        loss_analysis=draft_loss_analysis,
        loss_analysis_digest=graph_digest(draft_loss_analysis),
        run_dir=run_dir,
        template_loader=loader,
        temperature=temperature,
    )

    def check_rule_revision(revised: LossAnalysis) -> str | None:
        return stated_rules.check_revision(
            revised,
            revised_digest=graph_digest(revised),
            llm_client=llm_client,
            run_dir=run_dir,
            template_loader=loader,
            temperature=temperature,
        )

    loss_analysis, gates, rule_revision = _try_gate_loss_analysis(
        llm_client,
        loss_analysis,
        use_case_text,
        cards,
        run_dir,
        loader,
        temperature,
        stage_errors,
        accounting_normalization_warnings,
        repair_record=repair_record,
        stated_rule_findings=stated_rules.findings,
        stated_rule_check=check_rule_revision,
    )
    coverage = finalize_stated_rule_coverage(
        stated_rules,
        draft=draft_loss_analysis,
        final=loss_analysis,
        final_digest=(
            graph_digest(loss_analysis) if loss_analysis is not None else None
        ),
        revision=rule_revision,
        run_dir=run_dir,
    )
    stage_warnings.extend(coverage_warnings(coverage))
    return loss_analysis, gates, repair_record, coverage


@dataclass
class _Stage2Result:
    """Internal result container for the Stage 2 block."""

    loss_analysis: LossAnalysis | None = None
    control_structure: ControlStructure | None = None
    critic_findings: CriticFindings | None = None
    heuristic_errors: list[str] = field(default_factory=list)
    heuristic_warnings: list[str] = field(default_factory=list)
    solution_neutrality_warnings: list[str] = field(default_factory=list)
    post_revision_warnings: list[str] = field(default_factory=list)
    revised: bool = False
    model_call_count: int = 0
    uncited_constraints: list[str] = field(default_factory=list)


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
    *,
    target_evidence: TargetEvidence | None = None,
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
            target_evidence=target_evidence,
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
    repair_record: RepairRecord | None = None,
    stated_rule_findings: tuple[StatedRuleFinding, ...] = (),
    stated_rule_check: StatedRuleCheck | None = None,
) -> tuple[LossAnalysis | None, dict, StatedRuleRevision]:
    """Run the deterministic Stage 1a gates, recording failures as stage errors.

    On a gate failure the loss analysis is dropped so Stage 2 never runs on a
    graph that cannot tell scenarios apart; the exact failing checks stay in
    the stage errors and in ``loss-analysis-gates.yaml``.  The third element
    reports how the revision handled ``stated_rule_findings``.
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
            repair_record=repair_record,
            stated_rule_findings=stated_rule_findings,
            stated_rule_check=stated_rule_check,
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
        revision_count = getattr(exc, "revision_call_count", 0)
        return (
            None,
            {
                "risk_accounting": accounting,
                "hazard_graph_density": density,
                "graph_revision_call_count": revision_count,
            },
            # A failed gate never ran the stated-rule revision.
            StatedRuleRevision(),
        )
    gates = {
        "risk_accounting": ("passed" if outcome.accounting.passed else "failed"),
        "hazard_graph_density": (
            "passed_after_revision"
            if outcome.revision_applied
            else ("failed" if not outcome.density.passed else "passed")
        ),
        "graph_revision_call_count": outcome.revision_call_count,
    }
    # The bounded revision call re-derives constraints; restamp so no
    # revised entry can carry a reviewed claim out of the derived path.
    stamp_proposed_direction(outcome.loss_analysis)
    return outcome.loss_analysis, gates, outcome.stated_rule_revision


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
    capability_profile: CapabilityProfile | None,
    stage_errors: list[str],
) -> CapabilityProfile | None:
    """Run Stage 1b (or publish a pre-built profile), recording errors on failure."""
    if capability_profile is not None:
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
    target_evidence: TargetEvidence | None = None,
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
            target_evidence=target_evidence,
            post_review_density_check=lambda reviewed, correct, unresolved: (
                verify_reviewed_density(
                    reviewed,
                    run_dir=run_dir,
                    draft=loss_analysis,
                    correct=correct,
                    unresolved=unresolved,
                )
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
    target_evidence: TargetEvidence | None = None,
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
        target_evidence=target_evidence,
    )
    # Strip empty responsibilities that revision may have introduced
    control_structure, strip_warnings = strip_empty_responsibilities(control_structure)
    post_revision_warnings.extend(strip_warnings)
    if control_structure != baseline_control_structure:
        control_structure, binding_warnings = check_evidence_bindings(
            control_structure, target_evidence
        )
        post_revision_warnings.extend(binding_warnings)
    revised = control_structure != baseline_control_structure
    write_yaml(control_structure, run_dir / "control-structure-revised.yaml")
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
    target_evidence: TargetEvidence | None = None,
) -> _Stage2Result:
    """Run Stage 2: control structure derivation, heuristics, critic, and revision.

    Returns an empty result when prerequisites are missing or derivation fails.
    One unified analysis runs for every supplied input: observed profiles,
    simulation bases and multi-agent capability flags enrich the analysis and
    never select a different derivation.  ``model_call_count`` is the number
    of requests the block sent, retries included; a failed derivation still
    reports what it sent.
    """
    with count_requests() as sent:
        result = _run_stage_2_steps(
            llm_client,
            use_case_text,
            loss_analysis,
            capability_profile,
            run_dir,
            loader,
            temperature,
            stage_errors,
            stage_warnings,
            target_evidence=target_evidence,
        )
    result.model_call_count = sent.requests
    return result


def _run_stage_2_steps(
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
    target_evidence: TargetEvidence | None = None,
) -> _Stage2Result:
    """Run the Stage 2 steps; the caller counts the requests they send."""
    if _stage2_prerequisites_missing(loss_analysis, capability_profile):
        return _Stage2Result()

    stage_warnings = [] if stage_warnings is None else stage_warnings

    derivation = _derive_stage2_control_structure(
        llm_client,
        use_case_text,
        loss_analysis,
        capability_profile,
        run_dir,
        loader,
        temperature,
        stage_errors,
        target_evidence=target_evidence,
    )
    if derivation is None:
        return _Stage2Result()
    loss_analysis = derivation.loss_analysis
    control_structure, binding_warnings = check_evidence_bindings(
        derivation.control_structure, target_evidence
    )
    if control_structure != derivation.control_structure:
        write_yaml(control_structure, run_dir / "control-structure-evidence-bound.yaml")
    merge_warnings = list(derivation.warnings)
    stage_warnings.extend(merge_warnings)
    stage_warnings.extend(binding_warnings)

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
        target_evidence=target_evidence,
    )

    # Sanitize non-conforming IDs from critic remedies before revision
    critic_findings = sanitize_critic_ids(critic_findings)
    critic_findings = with_reply_placement_gaps(
        critic_findings, control_structure, loss_analysis
    )

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
        target_evidence=target_evidence,
    )

    placed, placement_warnings = attach_to_sole_reply_responsibility(
        control_structure, loss_analysis
    )
    if placed != control_structure:
        control_structure = placed
        write_yaml(control_structure, run_dir / "control-structure-placed.yaml")
    stage_warnings.extend(placement_warnings)

    # Every step above kept its own named version; the canonical name is the
    # structure in force when the stage ends.
    write_yaml(control_structure, run_dir / "control-structure.yaml")

    # Advisory, code-only: a Stage 1a constraint that no responsibility cites
    # reaches no control action, so its rule produces no scenario.
    uncited = uncited_security_constraints(control_structure, loss_analysis)
    stage_warnings.extend(
        f"stage_2/constraint_citation: security constraint {constraint_id} is "
        "not cited by any Stage 2 responsibility"
        for constraint_id in uncited
    )

    return _Stage2Result(
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        uncited_constraints=uncited,
        critic_findings=critic_findings,
        heuristic_errors=list(heuristic_result.errors),
        heuristic_warnings=list(heuristic_result.warnings),
        solution_neutrality_warnings=solution_neutrality_warnings,
        post_revision_warnings=post_revision_warnings,
        revised=revised,
    )


def _compute_input_hashes(
    use_case_text: str,
    risk_cards: list[RiskCard],
    loss_analysis_path: Path | None = None,
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
    stage_1a_requests: int = 0,
    stage_1b_requests: int = 0,
    stage_errors: list[str] | None = None,
    stage_warnings: list[str] | None = None,
    profile_name: str | None = None,
    max_workers: int = 1,
    stage_1a_gates: dict | None = None,
    stage_1a_pinned: bool = False,
    loss_analysis_path: Path | None = None,
    risk_coverage_review: RiskCoverageReviewOutcome | None = None,
    stage_2_call_count: int = 0,
    stage_1a_repair: RepairRecord | None = None,
    risk_actionability: RiskActionabilityRecord | None = None,
    target_evidence: TargetEvidence | None = None,
    stated_rule_coverage: StatedRuleCoverageArtifact | None = None,
    uncited_constraints: list[str] | None = None,
) -> None:
    """Write the run manifest with stage summary, input hashes, and prompt hashes."""
    input_hashes = _compute_input_hashes(
        use_case_text,
        risk_cards,
        loss_analysis_path,
    )
    prompt_hashes = loader.hash_prompt_templates()
    critic_summary = _summarize_critic_findings(critic_findings)
    _stage_2_call_count = stage_2_call_count

    stage_1a_summary: dict[str, object] = {
        "call_count": stage_1a_requests,
        "source": "pinned" if stage_1a_pinned else "derived",
    }
    _add_stage_1a_repair_summary(stage_1a_summary, run_dir, stage_1a_repair)
    if stage_1a_gates is not None:
        stage_1a_summary.update(stage_1a_gates)
        # The bounded graph-revision requests add to the derivation's.
        stage_1a_summary["call_count"] = stage_1a_requests + stage_1a_gates.get(
            "graph_revision_call_count", 0
        )
    _add_stage_1a_advisory_summaries(
        stage_1a_summary,
        risk_coverage_review=risk_coverage_review,
        risk_actionability=risk_actionability,
        stated_rule_coverage=stated_rule_coverage,
    )
    if target_evidence is not None:
        stage_1a_summary["target_evidence"] = {
            "artifact": "target-evidence.yaml",
            "operations": len(target_evidence.operations),
            "session_fields": len(target_evidence.session_fields),
            "resources": len(target_evidence.resources),
            "policies": len(target_evidence.policies),
        }

    stage_2_summary = _stage_2_summary(
        run_dir,
        stage_2_call_count=_stage_2_call_count,
        uncited_constraints=uncited_constraints,
        risk_coverage_review=risk_coverage_review,
        stage_1a_pinned=stage_1a_pinned,
    )

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
            "stage_1b": {"call_count": stage_1b_requests},
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


def _add_stage_1a_repair_summary(
    stage_1a_summary: dict[str, object],
    run_dir: Path,
    stage_1a_repair: RepairRecord | None,
) -> None:
    """Add the repair record path, counts, and rule-span repairs when any ran."""
    if stage_1a_repair is None or not stage_1a_repair.entries:
        return
    # The run-level, cross-stage repair record: path, filename, and
    # per-stage counts by outcome, so a reviewer can see every
    # transformation without opening calls.jsonl.
    stage_1a_summary["repair"] = {
        "artifact": "loss-analysis-repair.yaml",
        "record_path": str(run_dir / "loss-analysis-repair.yaml"),
        "counts_by_stage": stage_1a_repair.counts_by_stage(),
    }
    span_repairs = [
        {
            "step": entry.stage,
            "attempt": entry.attempt,
            "identity": entry.identity,
            "match": entry.applied.get("match"),
            "outcome": entry.outcome,
        }
        for entry in stage_1a_repair.entries
        if entry.kind == RULE_SPAN_REPAIR_KIND
    ]
    if span_repairs:
        stage_1a_summary["rule_span_repairs"] = span_repairs


def _add_stage_1a_advisory_summaries(
    stage_1a_summary: dict[str, object],
    *,
    risk_coverage_review: RiskCoverageReviewOutcome | None,
    risk_actionability: RiskActionabilityRecord | None,
    stated_rule_coverage: StatedRuleCoverageArtifact | None,
) -> None:
    """Add each advisory Stage 1a review that ran, and count its model calls."""
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
    if risk_actionability is not None:
        stage_1a_summary["risk_actionability"] = {
            "artifact": RISK_ACTIONABILITY_FILENAME,
            "status": risk_actionability.status,
            "call_count": risk_actionability.call_count,
            "counts": dict(risk_actionability.counts),
        }
        stage_1a_summary["call_count"] = (
            int(stage_1a_summary["call_count"]) + risk_actionability.call_count
        )
    if stated_rule_coverage is not None:
        stage_1a_summary["stated_rule_coverage"] = stated_rule_manifest_summary(
            stated_rule_coverage
        )
        stage_1a_summary["call_count"] = (
            int(stage_1a_summary["call_count"]) + stated_rule_coverage.call_count
        )


def _stage_2_summary(
    run_dir: Path,
    *,
    stage_2_call_count: int,
    uncited_constraints: list[str] | None,
    risk_coverage_review: RiskCoverageReviewOutcome | None,
    stage_1a_pinned: bool,
) -> dict[str, object]:
    """Summarize Stage 2 calls, uncited constraints, and a post-review digest."""
    stage_2_summary: dict[str, object] = {
        "call_count": stage_2_call_count,
    }
    if uncited_constraints:
        stage_2_summary["uncited_security_constraints"] = list(uncited_constraints)
    # One adaptive analysis: the manifest records no generation-mode field,
    # because no supplied input selects a different generation algorithm.
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
    return stage_2_summary
