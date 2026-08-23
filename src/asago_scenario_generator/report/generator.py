"""Report generator — builds a self-contained HTML report from ReportData."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from asago_scenario_generator.report.data import ReportData, load_report_data
from asago_scenario_generator.report.scorecard import build_scorecard_section
from asago_scenario_generator.report.template import (
    build_attacker_diversity_section,
    build_capability_profile_section,
    build_coverage_section,
    build_full_page,
    build_methodology_section,
    build_pipeline_calls_section,
    build_raw_data_section,
    build_run_summary_section,
    build_scenarios_section,
    build_threat_surface_section,
    build_threat_technique_section,
    build_use_case_section,
)

logger = logging.getLogger(__name__)


def _reconcile_corpus_claims(
    scenarios: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Reconcile typed corpus claim applicability across all scenarios.

    All scenarios share the same capability profile, so their corpus claim
    records must be consistent.  This function validates every scenario's
    semantic block, requires a complete valid pair (entry_points +
    tool_inventory), compares records across scenarios, and fails loudly
    on missing/malformed/duplicate/conflicting data (cmps.9 third review
    correction 1).

    Returns:
        A deterministic-category-ordered list of corpus claim dicts.

    Raises:
        ValueError: On missing, malformed, duplicate, or conflicting records.
    """
    from asago_scenario_generator.models.scenario import (
        CorpusClaimApplicability,
        CorpusClaimCategory,
    )

    if not scenarios:
        return []

    # Collect validated records from every scenario.
    per_scenario: list[list[CorpusClaimApplicability]] = []
    for idx, s in enumerate(scenarios):
        val = s.get("validation")
        if not val or not isinstance(val, dict):
            raise ValueError(
                f"Scenario {idx} is missing a validation block for "
                f"corpus claim reconciliation."
            )
        semantic = val.get("semantic")
        if not semantic or not isinstance(semantic, dict):
            raise ValueError(
                f"Scenario {idx} is missing a semantic validation block "
                f"for corpus claim reconciliation."
            )
        raw_claims = semantic.get("corpus_claim_applicability")
        if not raw_claims or not isinstance(raw_claims, list):
            raise ValueError(
                f"Scenario {idx} is missing corpus_claim_applicability "
                f"records for reconciliation."
            )
        # Validate each record through Pydantic to enforce status-appropriate
        # payloads and category completeness.
        try:
            records = [CorpusClaimApplicability.model_validate(r) for r in raw_claims]
        except Exception as exc:
            raise ValueError(
                f"Scenario {idx} has malformed corpus_claim_applicability "
                f"records: {exc}"
            ) from exc
        per_scenario.append(records)

    # Index records by category for cross-scenario comparison.
    canonical_order = [
        CorpusClaimCategory.entry_points,
        CorpusClaimCategory.tool_inventory,
    ]

    # Build a canonical representation from the first scenario.
    first = per_scenario[0]
    first_by_cat: dict[str, CorpusClaimApplicability] = {}
    for r in first:
        if r.category.value in first_by_cat:
            raise ValueError(
                f"Scenario 0 has duplicate corpus claim category '{r.category.value}'."
            )
        first_by_cat[r.category.value] = r

    # Verify the first scenario has both required categories.
    for cat in canonical_order:
        if cat.value not in first_by_cat:
            raise ValueError(
                f"Scenario 0 is missing corpus claim category "
                f"'{cat.value}' during reconciliation."
            )

    # Compare all subsequent scenarios against the first.
    for idx, records in enumerate(per_scenario[1:], 1):
        by_cat: dict[str, CorpusClaimApplicability] = {}
        for r in records:
            if r.category.value in by_cat:
                raise ValueError(
                    f"Scenario {idx} has duplicate corpus claim category "
                    f"'{r.category.value}'."
                )
            by_cat[r.category.value] = r
        for cat in canonical_order:
            cat_val = cat.value
            if cat_val not in by_cat:
                raise ValueError(
                    f"Scenario {idx} is missing corpus claim category "
                    f"'{cat_val}' during reconciliation."
                )
            if cat_val not in first_by_cat:
                raise ValueError(
                    f"Scenario 0 is missing corpus claim category "
                    f"'{cat_val}' during reconciliation."
                )
            r1 = first_by_cat[cat_val]
            r2 = by_cat[cat_val]
            if r1.status != r2.status or r1.reason != r2.reason:
                raise ValueError(
                    f"Corpus claim category '{cat_val}' conflicts between "
                    f"scenario 0 (status={r1.status.value}, "
                    f"reason={r1.reason!r}) and scenario {idx} "
                    f"(status={r2.status.value}, reason={r2.reason!r})."
                )
            if sorted(r1.evidence) != sorted(r2.evidence):
                raise ValueError(
                    f"Corpus claim category '{cat_val}' evidence conflicts "
                    f"between scenario 0 and scenario {idx}."
                )

    # Return in deterministic category order.
    result: list[dict[str, Any]] = []
    for cat in canonical_order:
        r = first_by_cat.get(cat.value)
        if r is None:
            raise ValueError(
                f"Missing corpus claim category '{cat.value}' in reconciled records."
            )
        result.append(r.model_dump(mode="json"))
    return result


def generate_report(report_data: ReportData, output_dir: Path) -> Path:
    """Build the HTML report from *report_data* and write it to *output_dir*.

    This function performs no filesystem reads -- all data comes from the
    :class:`ReportData` object.  The only I/O is writing ``report.html``.

    Args:
        report_data: Pre-loaded report inputs (see :func:`load_report_data`).
        output_dir: Directory where ``report.html`` will be written.

    Returns:
        Path to the generated ``report.html``.
    """
    output_dir = Path(output_dir)

    # Unpack data for readability
    profile_data = report_data.profile_data
    ts_data = report_data.threat_surface_data
    scenarios = list(report_data.scenarios)  # copy so sort is non-destructive
    feature_files = report_data.feature_files
    call_logs = report_data.call_logs
    pipeline_call_logs = report_data.pipeline_call_logs
    coverage_data = report_data.coverage_data
    scorecard_data = report_data.scorecard_data
    manifest_data = report_data.manifest_data
    use_case_text = report_data.use_case_text
    raw_files = report_data.raw_files

    # Sort scenarios by priority (descending)
    scenarios.sort(
        key=lambda s: s.get("priority", {}).get("composite", 0),
        reverse=True,
    )

    # --- Compute priority breakdown for run summary ---
    high_count = 0
    medium_count = 0
    low_count = 0
    for s in scenarios:
        composite = s.get("priority", {}).get("composite", 0)
        if composite >= 0.7:
            high_count += 1
        elif composite >= 0.4:
            medium_count += 1
        else:
            low_count += 1

    # Coverage gaps count (from coverage-gaps.json if available)
    coverage_gaps_count: int | None = None
    if coverage_data:
        gaps = coverage_data.get("coverage_gaps", {})
        coverage_gaps_count = (
            len(gaps.get("uncovered_entry_points", []))
            + len(gaps.get("uncovered_zones", []))
            + len(gaps.get("uncovered_threats", []))
        )

    # --- Build HTML sections ---
    run_summary_html = (
        build_run_summary_section(
            manifest_data,
            len(scenarios),
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            coverage_gaps=coverage_gaps_count,
        )
        if manifest_data
        else ""
    )
    methodology_html = build_methodology_section()
    use_case_html = build_use_case_section(use_case_text) if use_case_text else ""
    # Reconcile typed corpus claim applicability across all scenarios
    # (cmps.9 third review correction 1).  All scenarios share the same
    # profile, so records must be consistent.  Fail loudly on
    # missing/malformed/duplicate/conflicting data rather than first-wins.
    corpus_claims = _reconcile_corpus_claims(scenarios)

    profile_html = build_capability_profile_section(
        profile_data, corpus_claims=corpus_claims
    )
    threats_html = build_threat_surface_section(ts_data, scenarios=scenarios)

    coverage_html = ""
    if coverage_data:
        coverage_html = build_coverage_section(coverage_data)

    diversity_html = build_attacker_diversity_section(scenarios)

    threat_technique_html = build_threat_technique_section(scenarios)

    scorecard_html = build_scorecard_section(scorecard_data) if scorecard_data else ""

    pipeline_calls_html = (
        build_pipeline_calls_section(pipeline_call_logs) if pipeline_call_logs else ""
    )

    scenarios_html = build_scenarios_section(
        scenarios,
        feature_files,
        call_logs,
        threat_surface=ts_data,
        capability_profile=profile_data,
        scenarios_generated=manifest_data.get("scenarios_generated")
        if manifest_data
        else None,
        scorecard_data=scorecard_data,
    )
    raw_html = build_raw_data_section(raw_files)

    # --- Assemble full page ---
    page_html = build_full_page(
        profile_html=profile_html,
        threats_html=threats_html,
        scenarios_html=scenarios_html,
        raw_html=raw_html,
        coverage_html=coverage_html,
        diversity_html=diversity_html,
        use_case_html=use_case_html,
        scorecard_html=scorecard_html,
        threat_technique_html=threat_technique_html,
        run_summary_html=run_summary_html,
        methodology_html=methodology_html,
        pipeline_calls_html=pipeline_calls_html,
    )

    # --- Write output ---
    report_path = output_dir / "report.html"
    report_path.write_text(page_html, encoding="utf-8")
    logger.info("Report written to %s (%d bytes)", report_path, len(page_html))

    return report_path


def generate_report_from_dir(output_dir: Path) -> Path:
    """Convenience wrapper: load artifacts from *output_dir* and generate the report.

    Equivalent to::

        data = load_report_data(output_dir)
        return generate_report(data, output_dir)
    """
    data = load_report_data(output_dir)
    return generate_report(data, output_dir)
