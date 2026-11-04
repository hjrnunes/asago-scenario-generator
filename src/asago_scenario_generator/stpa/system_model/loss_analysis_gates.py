"""Deterministic gates on the loss-analysis hazard graph.

After the Stage 1a loss analysis is accepted, offline code checks that the
hazard graph is dense enough to tell scenarios apart:

1. every loss has at least one hazard;
2. every constraint has at least one hazard;
3. every hazard has at least one constraint;
4. every distinct behavior class present in the constraints has its own
   hazard, so two constraints in different classes never share their only
   hazard.
The fixed-rule subject-phrase check remains recorded evidence, but a mismatch
is advisory and does not block the structural gate.

Each revision round ends in a named decision from
:mod:`asago_scenario_generator.stpa.system_model.loss_analysis_gate_decisions`:
the gate accepts the revision, keeps it without the records it broke, keeps
the prior graph, asks for another round, or stops the run.  The rules that
produce those values are pure; the revision runner in
:mod:`asago_scenario_generator.stpa.system_model.loss_analysis_gate_runner`
makes the calls, and
:mod:`asago_scenario_generator.stpa.system_model.loss_analysis_gate_publication`
writes the evidence.  This module runs the gate, the stated-rule round trigger,
the post-review correction and the failure policy.

A graph with a failing structural check receives a bounded revision request
that reports the exact failing checks; a response that fails validation gets
one correction call.  A valid revision that still fails a structural check
gets one further round on the revised graph, with the checks the first round
introduced labelled as such; a failure after that round is a fatal stage
error.  The reviewed Stage 2 graph gets the same kind of bounded correction
when the review breaks a structural check.  The gates never call a taxonomy
service or infer a taxonomy mechanism.
"""

from __future__ import annotations

from collections.abc import Callable, Collection, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path

from asago_scenario_generator.models.risk_card import RiskCard
from asago_scenario_generator.stpa.infra.llm import LLMClient
from asago_scenario_generator.stpa.infra.llm_helpers import StageError
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.system_model.control_structure_review import (
    ReviewCorrection,
    ReviewOutcome,
)
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    STAGE,
    STEP_GAP,
    RevisionConstraintEdit,
    Stage1aRevisionPatch,
)
from asago_scenario_generator.stpa.system_model.loss_analysis_gate_checks import (
    UNCLASSIFIED as UNCLASSIFIED,
    BehaviorClassOwnHazardCheck as BehaviorClassOwnHazardCheck,
    ConstraintSubjectCheck as ConstraintSubjectCheck,
    HazardGraphDensityReport,
    RiskAccountingReport,
    check_hazard_graph_density,
    check_loss_analysis_graph,
    check_risk_accounting as check_risk_accounting,
    extract_subject_phrases as extract_subject_phrases,
)
from asago_scenario_generator.stpa.system_model.loss_analysis_gate_publication import (
    GATES_ARTIFACT,
    STEP_GRAPH_REVISION,
    revision_round_record,
    write_gates_artifact,
    write_post_review_density,
)
from asago_scenario_generator.stpa.system_model.loss_analysis_gate_runner import (
    GRAPH_REVISION_ROUNDS as GRAPH_REVISION_ROUNDS,
    REVISION_CORRECTION_FEEDBACK as REVISION_CORRECTION_FEEDBACK,
    REVISION_CORRECTION_SCOPE as REVISION_CORRECTION_SCOPE,
    StatedRuleCheck as StatedRuleCheck,
    _GateInputs,
    _GateProgress,
    _RevisionAttempt as _RevisionAttempt,
    _addition_only_constraint_edit as _addition_only_constraint_edit,
    _draft_from_analysis as _draft_from_analysis,
    _droppable_final_patch as _droppable_final_patch,
    _revise_stated_rules,
    _revised_analysis as _revised_analysis,
    _revision_patch_to_draft as _revision_patch_to_draft,
    _revision_policy as _revision_policy,
    _run_density_revision,
    _run_graph_revision_call as _run_graph_revision_call,
    _run_stated_rule_revision as _run_stated_rule_revision,
    _unknown_edit_targets as _unknown_edit_targets,
    _validate_revision as _validate_revision,
    _warn_unclassified_constraints,
)
from asago_scenario_generator.stpa.system_model.loss_analysis_repair import (
    RepairRecord,
)
from asago_scenario_generator.stpa.system_model.stated_rule_coverage import (
    StatedRuleFinding,
    StatedRuleRevision,
)

# The old import path for the revision request models; the runner imports the
# public names from ``loss_analysis``.
_RevisionConstraintEdit = RevisionConstraintEdit
_Stage1aRevisionPatch = Stage1aRevisionPatch

POST_REVIEW_CORRECTION_ROUNDS = 1
# () -> (unresolved hazard IDs, unresolved constraint IDs) of the review in force.
UnresolvedReviewIds = Callable[[], tuple[frozenset[str], frozenset[str]]]


class LossAnalysisGateError(StageError):
    """A loss-analysis gate failed after its bounded repair budget.

    ``gate`` names the failed check group (``risk_accounting`` or
    ``hazard_graph_density``) so the run manifest can report statuses without
    parsing the message text.
    """

    def __init__(
        self,
        *,
        stage: str,
        step: str,
        message: str,
        gate: str,
        failing_checks: tuple[str, ...] = (),
        revision_attempted: bool = False,
        revision_call_count: int = 0,
    ) -> None:
        super().__init__(stage=stage, step=step, message=message)
        self.gate = gate
        self.failing_checks = failing_checks
        self.revision_attempted = revision_attempted
        self.revision_call_count = revision_call_count


@dataclass(frozen=True)
class LossAnalysisGateOutcome:
    """The complete gate result returned to the SP1 orchestrator."""

    loss_analysis: LossAnalysis
    accounting: RiskAccountingReport
    density: HazardGraphDensityReport
    revision_attempted: bool
    revision_applied: bool
    revision_call_count: int = 0
    stated_rule_revision: StatedRuleRevision = field(default_factory=StatedRuleRevision)

    @property
    def passed(self) -> bool:
        return self.accounting.passed and self.density.passed


def _correction_scope_constraints(
    report: HazardGraphDensityReport,
    draft: LossAnalysis,
    orphan_hazards: set[str],
) -> set[str]:
    failing_classes = {
        check.behavior_class
        for check in report.class_own_hazard_checks
        if not check.passed
    }
    constraints = set(report.constraints_without_hazard)
    constraints.update(
        constraint_id
        for constraint_id, behavior_class in report.constraint_classes
        if behavior_class in failing_classes
    )
    constraints.update(
        constraint.constraint_id
        for constraint in draft.security_constraints
        if orphan_hazards.intersection(constraint.related_hazards)
    )
    return constraints


def post_review_correction_scope(
    report: HazardGraphDensityReport,
    draft: LossAnalysis,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Return the hazard and constraint IDs a post-review correction may touch.

    The scope is every record a failing structural check names, plus the
    constraints whose pre-review edges reached an orphaned hazard and the
    hazards those constraints reached before the review.  The review cannot
    change loss membership, so a loss without a hazard adds nothing.
    """
    orphan_hazards = set(report.hazards_without_constraint)
    constraints = _correction_scope_constraints(report, draft, orphan_hazards)
    hazards = set(orphan_hazards)
    hazards.update(
        hazard_id
        for constraint in draft.security_constraints
        if constraint.constraint_id in constraints
        for hazard_id in constraint.related_hazards
    )
    return (
        tuple(h.hazard_id for h in draft.hazards if h.hazard_id in hazards),
        tuple(
            c.constraint_id
            for c in draft.security_constraints
            if c.constraint_id in constraints
        ),
    )


def _exempt_unresolved(
    report: HazardGraphDensityReport,
    unresolved: UnresolvedReviewIds,
) -> tuple[HazardGraphDensityReport, tuple[str, ...]]:
    """Remove records the review explicitly marked unresolved from the checks.

    An unresolved record names a fact the sources lack, so it cannot carry a
    grounded edge.  Only that record is exempt: a kept record left without its
    partner is still a structural failure.
    """
    hazards, constraints = unresolved()
    kept_hazards, exempt_hazards = _partition_unresolved(
        report.hazards_without_constraint,
        hazards,
        "hazard {} has no constraint; the review marked it unresolved",
    )
    kept_constraints, exempt_constraints = _partition_unresolved(
        report.constraints_without_hazard,
        constraints,
        "constraint {} has no hazard; the review marked it unresolved",
    )
    return (
        replace(
            report,
            hazards_without_constraint=kept_hazards,
            constraints_without_hazard=kept_constraints,
        ),
        exempt_hazards + exempt_constraints,
    )


def _partition_unresolved(
    ids: tuple[str, ...], unresolved: Collection[str], message: str
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Split *ids* into those still checked and exemption notes for the rest."""
    return (
        tuple(item for item in ids if item not in unresolved),
        tuple(message.format(item) for item in ids if item in unresolved),
    )


def verify_reviewed_density(
    outcome: ReviewOutcome,
    *,
    run_dir: Path,
    draft: LossAnalysis,
    correct: ReviewCorrection,
) -> ReviewOutcome:
    """Re-run the offline density checks on the reviewed graph.

    The Stage 2 semantic review may reword hazards/constraints or replace
    constraint hazard edges, so the persisted reviewed graph is re-checked
    before it replaces the canonical ``loss-analysis.yaml``.  The outcome's
    review names the hazard and constraint records it marks unresolved; a
    missing edge on exactly those records is recorded as a post-review
    advisory instead of a failure.  When the review breaks a structural check,
    it gets :data:`POST_REVIEW_CORRECTION_ROUNDS` correction round: ``correct``
    receives the failing checks and the hazard and constraint IDs of
    :func:`post_review_correction_scope`, and returns the corrected outcome or
    raises :class:`StageError` when the correction cannot be made.  Every
    report and correction round is recorded in the gates artifact; structural
    failures left after the last round come back on the returned outcome with
    the exact still-failing checks, while subject mismatches are recorded as
    post-review advisories.  Returns the outcome holding the graph in force and
    its verdict.
    """
    report, exempted = _exempt_unresolved(
        check_hazard_graph_density(outcome.loss_analysis),
        outcome.review.unresolved_ids,
    )
    first_report = report
    corrections: list[dict] = []
    correction_error: str | None = None
    if not report.passed:
        outcome, report, exempted, correction_error = _run_post_review_corrections(
            outcome,
            report,
            exempted,
            draft=draft,
            correct=correct,
            corrections_out=corrections,
        )
    write_post_review_density(
        run_dir / GATES_ARTIFACT,
        report=report,
        first_report=first_report,
        corrections=corrections,
        exempted=exempted,
    )
    if report.passed:
        return outcome
    message = "hazard graph density gate failed after review: " + "; ".join(
        report.failing_checks
    )
    if corrections and report is not first_report:
        message += " (after one review correction round)"
    elif correction_error is not None:
        message += f" (review correction failed: {correction_error})"
    return replace(
        outcome,
        failure=LossAnalysisGateError(
            stage="stage_2",
            step="semantic_review",
            message=message,
            gate="hazard_graph_density",
            failing_checks=report.failing_checks,
        ),
    )


def _run_post_review_corrections(
    outcome: ReviewOutcome,
    report: HazardGraphDensityReport,
    exempted: tuple[str, ...],
    *,
    draft: LossAnalysis,
    correct: ReviewCorrection,
    corrections_out: list[dict],
) -> tuple[ReviewOutcome, HazardGraphDensityReport, tuple[str, ...], str | None]:
    """Run the bounded post-review correction rounds and record each one.

    Returns the latest outcome, its report, its exempted checks, and the
    correction error when a round raised :class:`StageError`.
    """
    first_report = report
    for round_number in range(1, POST_REVIEW_CORRECTION_ROUNDS + 1):
        hazard_ids, constraint_ids = post_review_correction_scope(report, draft)
        if not hazard_ids and not constraint_ids:
            break
        try:
            corrected = correct(report.failing_checks, hazard_ids, constraint_ids)
        except StageError as exc:
            corrections_out.append(
                {
                    **revision_round_record(
                        round_number,
                        before=report,
                        after=None,
                        original=first_report,
                    ),
                    "error": str(exc),
                }
            )
            return outcome, report, exempted, str(exc)
        after, exempted = _exempt_unresolved(
            check_hazard_graph_density(corrected.loss_analysis),
            corrected.review.unresolved_ids,
        )
        corrections_out.append(
            revision_round_record(
                round_number,
                before=report,
                after=after,
                original=first_report,
            )
        )
        outcome, report = corrected, after
        if report.passed:
            break
    return outcome, report, exempted, None


def gate_loss_analysis(
    *,
    llm_client: LLMClient,
    loss_analysis: LossAnalysis,
    use_case_text: str,
    risk_cards: list[RiskCard],
    run_dir: Path,
    template_loader: TemplateLoader,
    temperature: float,
    accounting_normalization_warnings: list[str] | None = None,
    repair_record: RepairRecord | None = None,
    stated_rule_findings: Sequence[StatedRuleFinding] = (),
    stated_rule_check: StatedRuleCheck | None = None,
) -> LossAnalysisGateOutcome:
    """Run the offline structural density gate with bounded revision rounds.

    ``stated_rule_findings`` are stated use-case rules that no constraint
    carries.  They never fail the gate and never reach the density revision,
    which runs exactly as it does without them.  Once the graph passes
    density (at once or after revision), the findings get one revision round
    of their own (trigger ``stated_rules``) that may only add records and
    extend constraint rules; see :func:`_run_stated_rule_revision`.  That
    round is non-fatal: any rejection keeps the graph that passed density.
    ``stated_rule_check`` receives an otherwise acceptable revised graph and
    returns a reason to reject it, or ``None``.

    The 1.1 risk-accounting gate already ran against the Call 1 response;
    this artifact-level report records its persisted outcome.  A failing
    structural graph receives a revision request that receives the exact
    failing checks; subject-phrase mismatches are recorded as advisory
    evidence and never trigger that request.  A revision response that fails
    validation gets one correction call.  A valid revision that still fails
    gets one more round (:data:`GRAPH_REVISION_ROUNDS`) on the revised graph;
    a structural failure after the last round raises
    :class:`LossAnalysisGateError` and keeps the unrevised graph.  The evidence artifact is written before
    any failure is raised, so a run never stops without its recorded evidence.
    A revision that still fails validation after its correction only because
    some constraint records carry a ``rule_span`` outside their rule loses
    those records and keeps the rest (see :func:`_run_density_revision`).
    Deterministic ``rule_span`` repairs are appended to ``repair_record``
    (kind ``rule_span_repaired``), which is rewritten to the run directory.
    """
    findings = check_loss_analysis_graph(loss_analysis, risk_cards)
    accounting = findings.accounting
    density = findings.density
    progress = _GateProgress(
        loss_analysis=loss_analysis,
        final_density=density,
        failing=list(density.failing_checks),
    )
    if not accounting.passed:
        _raise_accounting_failure(
            run_dir, accounting, density, accounting_normalization_warnings
        )
    inputs = _GateInputs(
        llm_client=llm_client,
        use_case_text=use_case_text,
        run_dir=run_dir,
        template_loader=template_loader,
        temperature=temperature,
        accounting=accounting,
        accounting_normalization_warnings=accounting_normalization_warnings,
        repair_record=repair_record,
    )
    if not density.passed:
        _run_density_revision(progress, inputs, density)

    sent_findings, rule_revision = _revise_stated_rules(
        progress, inputs, tuple(stated_rule_findings), stated_rule_check
    )

    if progress.revision_applied or rule_revision.applied:
        _warn_unclassified_constraints(progress)
    normalization = (
        list(accounting_normalization_warnings or []) + progress.revision_warnings
    )

    write_gates_artifact(
        run_dir,
        accounting=accounting,
        density=progress.final_density,
        failing_checks=progress.failing,
        revision_attempted=progress.revision_attempted,
        revision_applied=progress.revision_applied,
        normalization_warnings=normalization,
        revision_call_count=progress.revision_call_count,
        revision_rounds=progress.rounds,
        stated_rule_findings=sent_findings,
        stated_rule_revision=rule_revision if sent_findings else None,
    )

    if progress.failing:
        raise LossAnalysisGateError(
            stage=STAGE,
            step=STEP_GRAPH_REVISION,
            message="hazard graph density gate failed: " + "; ".join(progress.failing),
            gate="hazard_graph_density",
            failing_checks=tuple(progress.failing),
            revision_attempted=progress.revision_attempted,
            revision_call_count=progress.revision_call_count,
        )
    return LossAnalysisGateOutcome(
        loss_analysis=progress.loss_analysis,
        accounting=accounting,
        density=progress.final_density,
        revision_attempted=progress.revision_attempted,
        revision_applied=progress.revision_applied,
        revision_call_count=progress.revision_call_count,
        stated_rule_revision=rule_revision,
    )


def _raise_accounting_failure(
    run_dir: Path,
    accounting: RiskAccountingReport,
    density: HazardGraphDensityReport,
    accounting_normalization_warnings: list[str] | None,
) -> None:
    """Record the accounting failure and raise without any revision call."""
    write_gates_artifact(
        run_dir,
        accounting=accounting,
        density=density,
        failing_checks=[],
        revision_attempted=False,
        revision_applied=False,
        normalization_warnings=accounting_normalization_warnings,
    )
    failing_checks = accounting.failing_checks
    raise LossAnalysisGateError(
        stage=STAGE,
        step=STEP_GAP,
        message="risk accounting gate failed: "
        + "; ".join(dict.fromkeys(failing_checks)),
        gate="risk_accounting",
        failing_checks=failing_checks,
    )


def gate_pinned_loss_analysis(
    *,
    loss_analysis: LossAnalysis,
    risk_cards: list[RiskCard],
    run_dir: Path,
) -> None:
    """Run the offline Stage 1a gates on a caller-pinned analysis.

    A pinned loss analysis is accepted verbatim: the accounting and structural
    density checks run exactly as they do for a derived graph, subject-phrase
    mismatches are advisory, and any other failing check is immediately fatal
    because no bounded revision call exists.  The evidence artifact is written
    before any failure is raised.
    """
    findings = check_loss_analysis_graph(loss_analysis, risk_cards)
    accounting = findings.accounting
    density = findings.density
    if not accounting.passed:
        _raise_accounting_failure(run_dir, accounting, density, None)
    if not density.passed:
        write_gates_artifact(
            run_dir,
            accounting=accounting,
            density=density,
            failing_checks=list(density.failing_checks),
            revision_attempted=False,
            revision_applied=False,
        )
        raise LossAnalysisGateError(
            stage=STAGE,
            step=STEP_GRAPH_REVISION,
            message="hazard graph density gate failed: "
            + "; ".join(density.failing_checks),
            gate="hazard_graph_density",
            failing_checks=density.failing_checks,
        )
    write_gates_artifact(
        run_dir,
        accounting=accounting,
        density=density,
        failing_checks=[],
        revision_attempted=False,
        revision_applied=False,
    )
