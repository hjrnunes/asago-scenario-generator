"""Publication of the Stage 1a gate's evidence.

The gate and its revision runner hand every recorded outcome to this module:
the ``loss-analysis-gates.yaml`` artifact, one round record per revision
attempt, the post-review density report, and the ``rule_span`` repairs.  The
module reads typed reports and writes files; it sends no request and holds no
gate decision.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from asago_scenario_generator.stpa.infra.yaml_io import write_yaml
from asago_scenario_generator.stpa.system_model.loss_analysis_gate_checks import (
    HazardGraphDensityReport,
    RiskAccountingReport,
)
from asago_scenario_generator.stpa.system_model.loss_analysis_repair import (
    RepairRecord,
)
from asago_scenario_generator.stpa.system_model.rule_span_repair import (
    RuleSpanRepairRecord,
    record_rule_span_repairs,
)
from asago_scenario_generator.stpa.system_model.stated_rule_coverage import (
    StatedRuleFinding,
    StatedRuleRevision,
)

STEP_GRAPH_REVISION = "hazard_graph_revision"
GATES_ARTIFACT = "loss-analysis-gates.yaml"


class _SubjectCheckRecord(BaseModel):
    constraint_id: str
    hazard_id: str
    shared_phrases: list[str]
    passed: bool


class _ClassOwnHazardRecord(BaseModel):
    behavior_class: str
    owned_hazards: list[str]
    passed: bool


class LossAnalysisGatesArtifact(BaseModel):
    """The persisted ``loss-analysis-gates.yaml`` evidence."""

    risk_accounting: dict = Field(description="Risk-accounting report fields.")
    hazard_graph_density: dict = Field(
        description="Density report fields, including shared subject phrases."
    )
    failing_checks: list[str] = Field(default_factory=list)
    advisory_checks: list[str] = Field(
        default_factory=list,
        description=(
            "Subject-phrase mismatches recorded for reviewers; these mismatches "
            "do not block the gate."
        ),
    )
    revision_attempted: bool = False
    revision_applied: bool = False
    revision_call_count: int = Field(
        default=0,
        description="Graph-revision provider calls, including a correction call.",
    )
    passed: bool = False
    normalization_warnings: list[str] = Field(
        default_factory=list,
        description="Deterministic accounting normalizations applied to the "
        "provider response, recorded for reviewer visibility.",
    )
    post_review_density: dict | None = Field(
        default=None,
        description="Density re-check recorded after the Stage 2 semantic review.",
    )
    revision_rounds: list[dict] = Field(
        default_factory=list,
        description=(
            "One entry per graph-revision round: the checks sent, the checks "
            "left afterwards, and the checks the round introduced."
        ),
    )
    post_review_corrections: list[dict] = Field(
        default_factory=list,
        description=(
            "One entry per post-review density correction round: the checks "
            "sent, the checks left afterwards, and the checks it introduced."
        ),
    )
    stated_rule_findings: list[str] = Field(
        default_factory=list,
        description=(
            "Stated use-case rules no constraint carried, sent to the graph "
            "revision.  Advisory: they never fail the gate."
        ),
    )
    stated_rule_revision: dict | None = Field(
        default=None,
        description="Trigger, outcome, and calls of the stated-rule revision.",
    )


def _density_report_dict(report: HazardGraphDensityReport) -> dict:
    """Serialize a density report for the gates artifact."""
    return {
        "losses_without_hazard": list(report.losses_without_hazard),
        "constraints_without_hazard": list(report.constraints_without_hazard),
        "hazards_without_constraint": list(report.hazards_without_constraint),
        "subject_checks": [
            _SubjectCheckRecord(
                constraint_id=check.constraint_id,
                hazard_id=check.hazard_id,
                shared_phrases=list(check.shared_phrases),
                passed=check.passed,
            ).model_dump(mode="json")
            for check in report.subject_checks
        ],
        "class_own_hazard_checks": [
            _ClassOwnHazardRecord(
                behavior_class=check.behavior_class,
                owned_hazards=list(check.owned_hazards),
                passed=check.passed,
            ).model_dump(mode="json")
            for check in report.class_own_hazard_checks
        ],
        "constraint_classes": [
            {"constraint_id": cid, "behavior_class": cls}
            for cid, cls in report.constraint_classes
        ],
        "unclassified_constraints": list(report.unclassified_constraints),
    }


def write_gates_artifact(
    run_dir: Path,
    *,
    accounting: RiskAccountingReport,
    density: HazardGraphDensityReport,
    failing_checks: list[str],
    revision_attempted: bool,
    revision_applied: bool,
    normalization_warnings: list[str] | None = None,
    revision_call_count: int = 0,
    revision_rounds: list[dict] | None = None,
    stated_rule_findings: Sequence[StatedRuleFinding] = (),
    stated_rule_revision: StatedRuleRevision | None = None,
) -> None:
    """Persist structural failures and subject advisories before any failure."""
    artifact = LossAnalysisGatesArtifact(
        risk_accounting={
            "missing_dispositions": list(accounting.missing_dispositions),
            "unaccounted_risk_refs": list(accounting.unaccounted_risk_refs),
            "not_applicable_refs": list(accounting.not_applicable_refs),
            "cited_refs": list(accounting.cited_refs),
            "contradictions": list(accounting.contradictions),
            "passed": accounting.passed,
        },
        hazard_graph_density=_density_report_dict(density),
        failing_checks=failing_checks,
        advisory_checks=list(density.advisory_checks),
        revision_attempted=revision_attempted,
        revision_applied=revision_applied,
        revision_call_count=revision_call_count,
        passed=not failing_checks and accounting.passed,
        normalization_warnings=normalization_warnings or [],
        revision_rounds=revision_rounds or [],
        stated_rule_findings=[
            f"{finding.rule_id}: {finding.quote}" for finding in stated_rule_findings
        ],
        stated_rule_revision=(
            stated_rule_revision.model_dump(mode="json")
            if stated_rule_revision is not None
            else None
        ),
    )
    write_yaml(artifact, run_dir / GATES_ARTIFACT)


def revision_round_record(
    round_number: int,
    *,
    before: HazardGraphDensityReport,
    after: HazardGraphDensityReport | None,
    original: HazardGraphDensityReport,
) -> dict:
    """Record one revision round; ``after`` is None when the call failed."""
    after_checks = list(after.failing_checks) if after is not None else []
    return {
        "round": round_number,
        "failing_checks_before": list(before.failing_checks),
        "failing_checks_after": after_checks,
        "introduced_checks": [
            check
            for check in after_checks
            if check not in before.failing_checks
            and check not in original.failing_checks
        ],
        "revision_valid": after is not None,
    }


def write_post_review_density(
    artifact_path: Path,
    *,
    report: HazardGraphDensityReport,
    first_report: HazardGraphDensityReport,
    corrections: list[dict],
    exempted: tuple[str, ...],
) -> None:
    """Add the post-review report and corrections to an existing gates artifact."""
    if not artifact_path.is_file():
        return
    artifact = LossAnalysisGatesArtifact.model_validate(
        yaml.safe_load(artifact_path.read_text(encoding="utf-8"))
    )
    artifact.post_review_density = _density_report_dict(report)
    artifact.post_review_corrections = corrections
    artifact.advisory_checks = (
        artifact.advisory_checks
        + [f"post-review: {check}" for check in report.advisory_checks]
        + [f"post-review unresolved: {check}" for check in exempted]
    )
    if report.failing_checks:
        artifact.failing_checks = artifact.failing_checks + [
            f"post-review regression: {check}" for check in first_report.failing_checks
        ]
        if corrections and report is not first_report:
            artifact.failing_checks += [
                f"post-review correction still failing: {check}"
                for check in report.failing_checks
            ]
        artifact.passed = False
    write_yaml(artifact, artifact_path)


def write_revision_span_repairs(
    repair_record: RepairRecord | None,
    run_dir: Path,
    revisions: Sequence[Sequence[RuleSpanRepairRecord]],
    *,
    accepted: bool,
) -> None:
    """Record every attempt's span repairs and rewrite the repair artifact.

    ``revisions`` holds the repairs of each parsed attempt, in order.  Repairs
    on the final attempt are ``applied`` when its revised graph is kept; every
    other attempt's repairs are ``discarded``.  A run without a repair record
    writes nothing.
    """
    if repair_record is None:
        return
    for number, repairs in enumerate(revisions, 1):
        applied = accepted and number == len(revisions)
        record_rule_span_repairs(
            repair_record,
            step=STEP_GRAPH_REVISION,
            attempt="first" if number == 1 else "correction",
            repairs=list(repairs),
            outcome="applied" if applied else "discarded",
        )
    repair_record.write(run_dir)
