"""Human-readable projection of the normative hybrid assessment domain."""

from __future__ import annotations

from collections.abc import Sequence

from asago_scenario_generator.models.hybrid_coverage import HybridCoverageAssessment


def _ids(values: Sequence[str]) -> str:
    """Render an exact identity collection without deriving a claim."""
    return ", ".join(values) if values else "—"


def _trace_ids(row: object) -> str:
    """Render the exact artifact/version/record traces carried by a row."""
    return ", ".join(
        f"{item.artifact_id}@{item.schema_version}#{item.record_id}"
        for item in row.trace_refs  # type: ignore[attr-defined]
    )


def _structural_consideration(assessment: HybridCoverageAssessment) -> list[str]:
    """Render structural consideration directly from its domain rows."""
    lines = [
        "## Structural consideration",
        "| Row | Slot | Controller | Control action | UCA type | Disposition | ICAs | Evidence | Trace |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in assessment.structural_consideration:
        lines.append(
            "| "
            + " | ".join(
                (
                    row.row_id,
                    row.slot_id,
                    row.controller_id,
                    row.control_action_id,
                    row.uca_type,
                    row.disposition,
                    _ids(row.ica_ids),
                    _ids(row.evidence),
                    _trace_ids(row),
                )
            )
            + " |"
        )
    return lines


def _taxonomy_correspondence(assessment: HybridCoverageAssessment) -> list[str]:
    """Render taxonomy correspondence directly from its domain rows."""
    lines = [
        "## Taxonomy correspondence",
        "| Row | Obligation | Risk | Pattern | Taxonomy candidates | Scope | Qualification | Accepted relations | Disposition | Gap | Trace |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in assessment.taxonomy_correspondence:
        lines.append(
            "| "
            + " | ".join(
                (
                    row.row_id,
                    row.obligation_id,
                    row.risk_id,
                    row.attack_pattern_id or "—",
                    _ids(row.taxonomy_candidate_ids),
                    row.scope_disposition,
                    row.qualification_disposition,
                    _ids(row.accepted_relation_ids),
                    row.correspondence_disposition,
                    row.gap_reason or "—",
                    _trace_ids(row),
                )
            )
            + " |"
        )
    return lines


def _scenario_realization(assessment: HybridCoverageAssessment) -> list[str]:
    """Render scenario realization directly from its domain rows."""
    lines = [
        "## Scenario realization",
        "| Row | Relation | Proposal | Obligation | Risk | Pattern | Taxonomy candidates | Relation kind | Legacy scenarios | Hybrid generation | Hybrid admission | Trace |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in assessment.scenario_realization:
        lines.append(
            "| "
            + " | ".join(
                (
                    row.row_id,
                    row.relation_id,
                    row.proposal_id,
                    row.obligation_id,
                    row.risk_id,
                    row.attack_pattern_id,
                    _ids(row.taxonomy_candidate_ids),
                    row.correspondence_relation_kind,
                    _ids(row.legacy_scenario_ids),
                    row.hybrid_generation_status,
                    row.hybrid_admission_status,
                    _trace_ids(row),
                )
            )
            + " |"
        )
    return lines


def _diagnostics(assessment: HybridCoverageAssessment) -> list[str]:
    """Render separate counts already reconciled by the domain artifact."""
    values = assessment.diagnostics.model_dump(mode="json")
    lines = [
        "## Diagnostics (counts only)",
        "| Diagnostic | Count |",
        "| --- | --- |",
    ]
    lines.extend(f"| {name} | {value} |" for name, value in values.items())
    return lines


def _audit_diagnostics(assessment: HybridCoverageAssessment) -> list[str]:
    """Render proposal outcomes and findings without promoting either to coverage."""
    lines = [
        "## Non-coverage audit records",
        "| Record | Kind/status | Risk | Pattern | Taxonomy candidates | Trace |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    lines.extend(_proposal_lines(assessment))
    lines.extend(_finding_lines(assessment))
    if not assessment.proposal_outcomes and not assessment.findings:
        lines.append("| — | none | — | — | — | — |")
    return lines


def _proposal_lines(assessment: HybridCoverageAssessment) -> tuple[str, ...]:
    """Render non-confirmed proposal diagnostics exactly as stored."""
    return tuple(
        "| "
        + " | ".join(
            (
                item.proposal_id,
                f"proposal:{item.status}",
                item.risk_id,
                item.attack_pattern_id,
                _ids(item.taxonomy_candidate_ids),
                _trace_ids(item),
            )
        )
        + " |"
        for item in assessment.proposal_outcomes
    )


def _finding_lines(assessment: HybridCoverageAssessment) -> tuple[str, ...]:
    """Render noncoverage and contradiction findings exactly as stored."""
    return tuple(
        f"| {item.finding_id} | finding:{item.kind} | — | — | — | {_trace_ids(item)} |"
        for item in assessment.findings
    )


def render_hybrid_coverage_report(assessment: HybridCoverageAssessment) -> str:
    """Render all claims solely from a validated domain assessment."""
    if not isinstance(assessment, HybridCoverageAssessment):
        raise TypeError("assessment must be a HybridCoverageAssessment")
    assessment.assert_integrity()
    lines = [
        "# Hybrid coverage assessment",
        "",
        f"Artifact: {assessment.schema_version} / {assessment.semantic_digest}",
        "",
        f"Structural inventory: {assessment.structural_inventory_status}",
        "",
        "## Source artifacts",
        "",
    ]
    lines.extend(
        f"- {pin.artifact_id}@{pin.schema_version}: {pin.semantic_digest}"
        for pin in assessment.source_pins
    )
    for section in (
        _structural_consideration(assessment),
        _taxonomy_correspondence(assessment),
        _scenario_realization(assessment),
        _diagnostics(assessment),
        _audit_diagnostics(assessment),
    ):
        lines.extend(("", *section))
    return "\n".join(lines) + "\n"


__all__ = ["render_hybrid_coverage_report"]
