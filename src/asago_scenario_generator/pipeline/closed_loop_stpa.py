"""Bounded Phase 3 composition over the existing ledger and analysis seams."""

from __future__ import annotations

from collections.abc import Callable, Sequence

from asago_scenario_generator.models.challenge_analysis import (
    ChallengeAnalysisControls,
    ChallengeAnalysisResult,
)
from asago_scenario_generator.models.challenge_ledger import (
    EXPLICIT_PRIORITY_POLICY_VERSION,
    ChallengeEligibility,
    ChallengeRecord,
    StpaChallengeLedger,
)
from asago_scenario_generator.models.closed_loop_stpa import ClosedLoopStpaRun
from asago_scenario_generator.models.correspondence import compute_loss_analysis_digest
from asago_scenario_generator.models.hybrid_coverage import HybridCoverageAssessment
from asago_scenario_generator.models.system_resource_map import (
    compute_control_structure_digest,
)
from asago_scenario_generator.pipeline.challenge_analysis import (
    ChallengeAnalysisAdapter,
    reconsider_stpa_challenge,
)
from asago_scenario_generator.pipeline.challenge_ledger import (
    build_stpa_challenge_ledger,
)
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis


ChallengeAdapterFactory = Callable[[ChallengeRecord], ChallengeAnalysisAdapter]


def _validate_prior_context(
    prior_run: ClosedLoopStpaRun,
    controls: ChallengeAnalysisControls,
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
) -> None:
    loss_digest = compute_loss_analysis_digest(loss_analysis)
    control_digest = compute_control_structure_digest(control_structure)
    for result in prior_run.analyses:
        if result.request.controls != controls:
            raise ValueError("prior closed-loop run used different analysis controls")
        if result.request.context.loss_analysis_pin.semantic_digest != loss_digest:
            raise ValueError("prior closed-loop run used a different loss analysis")
        if (
            result.request.context.control_structure_pin.semantic_digest
            != control_digest
        ):
            raise ValueError("prior closed-loop run used a different control structure")


def _validate_opt_in(opted_in: bool) -> None:
    if type(opted_in) is not bool:
        raise TypeError("opted_in must be a strict boolean")


def _prior_by_id(
    prior_run: ClosedLoopStpaRun | None,
) -> dict[str, ChallengeAnalysisResult]:
    analyses = () if prior_run is None else prior_run.analyses
    return {result.request.challenge_id: result for result in analyses}


def _analyze_selected(
    ledger: StpaChallengeLedger,
    assessment: HybridCoverageAssessment,
    *,
    opted_in: bool,
    controls: ChallengeAnalysisControls,
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
    adapter_factory: ChallengeAdapterFactory,
    prior_by_id: dict[str, ChallengeAnalysisResult],
) -> tuple[ChallengeAnalysisResult, ...]:
    analyses: list[ChallengeAnalysisResult] = []
    for record in ledger.records:
        if record.selection_status != "selected":
            continue
        prior = prior_by_id.get(record.challenge_id)
        if prior is not None:
            analyses.append(prior)
            continue
        result = reconsider_stpa_challenge(
            ledger,
            assessment,
            record.challenge_id,
            opted_in=opted_in,
            controls=controls,
            loss_analysis=loss_analysis,
            control_structure=control_structure,
            adapter_factory=lambda record=record: adapter_factory(record),
        )
        if result is not None:
            analyses.append(result)
    return tuple(analyses)


def run_closed_loop_stpa(
    assessment: HybridCoverageAssessment,
    eligibility: Sequence[ChallengeEligibility],
    *,
    challenge_budget: int,
    assessment_artifact_id: str,
    opted_in: bool,
    controls: ChallengeAnalysisControls,
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
    adapter_factory: ChallengeAdapterFactory,
    prior_run: ClosedLoopStpaRun | None = None,
) -> ClosedLoopStpaRun:
    """Select explicit targets and optionally reconsider each selected pair once."""
    _validate_opt_in(opted_in)
    ledger = build_stpa_challenge_ledger(
        assessment,
        eligibility,
        challenge_budget=challenge_budget,
        assessment_artifact_id=assessment_artifact_id,
        selection_policy_version=EXPLICIT_PRIORITY_POLICY_VERSION,
    )
    if prior_run is not None:
        prior_run.assert_integrity()
        if prior_run.ledger != ledger:
            raise ValueError("prior closed-loop run does not match the selected ledger")
        _validate_prior_context(prior_run, controls, loss_analysis, control_structure)
    analyses = _analyze_selected(
        ledger,
        assessment,
        opted_in=opted_in,
        controls=controls,
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        adapter_factory=adapter_factory,
        prior_by_id=_prior_by_id(prior_run),
    )
    return ClosedLoopStpaRun(
        ledger=ledger,
        analysis_opt_in=opted_in,
        analyses=analyses,
    )


__all__ = ["ChallengeAdapterFactory", "run_closed_loop_stpa"]
