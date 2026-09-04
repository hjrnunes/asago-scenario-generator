"""Read-only HTML reporting for an obligation-aware synthesis run."""

from __future__ import annotations

from html import escape
from pathlib import Path
from typing import Any, Mapping

from asago_scenario_generator.manifest import atomic_write_text

REPORT_FILENAME = "synthesis-report.html"


def render_synthesis_report(
    output_dir: Path,
    *,
    manifest: Any,
    plan: Any,
    consideration: Any,
    accounting: Any,
    realization: Any,
    scenario_result: Any,
    phase2_verification: Any,
) -> Path:
    """Render synthesis results together with non-blocking Phase 2 verification."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    rows = _items(plan, "obligations")
    accounting_rows = _items(accounting, "rows")
    scenarios = _items(scenario_result, "scenario_envelopes", "envelopes")
    summary = _mapping(_value(accounting, "summary"))
    realization_summary = _mapping(_value(realization, "summary"))
    realization_records = _items(realization, "records")
    revision_value = _value(consideration, "revision")
    revision = _value(revision_value, "status")
    scenario_counts = _mapping(_value(manifest, "scenario_counts"))
    run_status = str(
        _value(manifest, "run_status", "scenario_generation_status") or "unknown"
    )
    run_status_reason = str(_value(manifest, "run_status_reason") or "unknown")
    final_routes = {
        str(_value(item, "obligation_id", "id")): item
        for item in _items(consideration, "final_routes", "routes")
    }
    accounting_by_id = {
        str(_value(item, "obligation_id", "id")): item for item in accounting_rows
    }
    title = escape(str(_value(manifest, "run_id") or "Synthesis run"))
    summary_rows = [
        _row("Scenario generation status", run_status),
        _row("Scenario status reason", run_status_reason),
        _row("Obligations", len(rows)),
        _row("Accounting rows", len(accounting_rows)),
        _row(
            "Requested candidates",
            _known_count(scenario_counts.get("requested")),
        ),
        _row(
            "Attempted candidates",
            _known_count(scenario_counts.get("attempted")),
        ),
        _row(
            "Published candidates",
            _known_count(scenario_counts.get("generated", len(scenarios))),
        ),
        _row(
            "Generated scenarios",
            _known_count(scenario_counts.get("generated", len(scenarios))),
        ),
        _row("Failed candidates", _known_count(scenario_counts.get("failed"))),
        _row("Skipped candidates", _known_count(scenario_counts.get("skipped"))),
        _row(
            "Diagnostic messages",
            _known_count(scenario_counts.get("diagnostic_count")),
        ),
        _row("Revision", revision or "not_required"),
    ]
    accounting_table = [_row(key, value) for key, value in sorted(summary.items())]
    stop_reason_counts = _stop_reason_counts(accounting_rows, realization_records)
    body = "\n".join(
        [
            "<h1>Obligation-aware synthesis</h1>",
            f'<p class="run-id">Run: <code>{title}</code></p>',
            f'<p class="notice">{escape(_scenario_status_notice(run_status))} Phase 2 verification is reported separately and never removes scenarios.</p>',
            "<h2>Run summary</h2>",
            "<table><tbody>",
            *summary_rows,
            "</tbody></table>",
            "<h2>Provisional accounting</h2>",
            "<table><thead><tr><th>Disposition</th><th>Count</th></tr></thead><tbody>",
            *accounting_table,
            "</tbody></table>",
            "<h2>Where analysis stopped</h2>",
            "<p>Each applicable obligation has a plain terminal explanation. Scenario outcomes replace the earlier addressed marker when scenario production was requested.</p>",
            "<table><thead><tr><th>Stop reason</th><th>Count</th></tr></thead><tbody>",
            *(_row(key, value) for key, value in sorted(stop_reason_counts.items())),
            "</tbody></table>",
            "<h2>Obligations</h2>",
            "<table><thead><tr><th>Obligation</th><th>Outcome</th><th>Stop reason</th><th>Route / gaps</th><th>STPA findings</th></tr></thead><tbody>",
            *(
                _obligation_row(
                    row,
                    final_routes.get(str(_value(row, "obligation_id", "id"))),
                    accounting_by_id.get(str(_value(row, "obligation_id", "id"))),
                )
                for row in rows
            ),
            "</tbody></table>",
            "<h2>Revision</h2>",
            _revision_html(revision_value),
            "<h2>Scenario realization</h2>",
            "<p>Scenario realization is reported separately from provisional obligation accounting.</p>",
            "<table><thead><tr><th>Status</th><th>Count</th></tr></thead><tbody>",
            *(_row(key, value) for key, value in sorted(realization_summary.items())),
            "</tbody></table>",
            _realization_html(realization_records),
            _candidate_outcomes_html(_value(manifest, "candidate_outcomes")),
            _phase2_html(phase2_verification),
            _scenario_html(scenarios),
        ]
    )
    content = (
        '<!doctype html>\n<html lang="en"><head><meta charset="utf-8">\n'
        "<title>Obligation-aware synthesis</title>\n<style>\n"
        "body{font:15px system-ui,sans-serif;max-width:980px;margin:2rem auto;padding:0 1rem;color:#202124}"
        "table{border-collapse:collapse;width:100%;margin:1rem 0 2rem}"
        "th,td{border:1px solid #ccd0d5;padding:.45rem;text-align:left;vertical-align:top}"
        "th{background:#f1f3f4}.notice{padding:.7rem 1rem;background:#fff4ce;"
        "border-left:4px solid #d79b00}.run-id{color:#5f6368}"
        "code{font-family:ui-monospace,monospace}\n</style></head><body>"
        + body
        + "</body></html>\n"
    )
    return atomic_write_text(output_dir / REPORT_FILENAME, content)


def _phase2_html(value: Any) -> str:
    """Explain correspondence verification without turning it into generation status."""
    status = str(_value(value, "status") or "failed")
    assessment = _value(value, "assessment")
    diagnostics = _mapping(_value(assessment, "diagnostics"))
    explanation = {
        "verified": "At least one correspondence has explicit accepted evidence.",
        "awaiting_review": (
            "The run found exact obligation-to-STPA review candidates, but none "
            "counts as taxonomy coverage until it is explicitly reviewed."
        ),
        "awaiting_evidence": (
            "Phase 2 completed, but the run did not contain the independently "
            "reviewed resource and mechanism evidence needed to confirm a "
            "correspondence."
        ),
        "failed": (
            "Phase 2 could not complete. The scenarios above remain valid outputs "
            "of the synthesis run."
        ),
    }.get(status, "Phase 2 returned an unknown status.")
    rows = "".join(
        _row(key.replace("_", " ").title(), item)
        for key, item in sorted(diagnostics.items())
    )
    error = _value(value, "error")
    error_html = f"<p>Error: {escape(str(error))}</p>" if error else ""
    diagnostics_html = "<table><tbody>" + rows + "</tbody></table>" if rows else ""
    return (
        "<h2>Phase 2: taxonomy–STPA verification</h2>"
        f"<p>Status: <code>{escape(status)}</code></p>"
        f"<p>{escape(explanation)}</p>" + error_html + diagnostics_html
    )


def _known_count(value: Any) -> Any:
    """Render absent legacy candidate counts as unknown rather than zero."""
    return "unknown" if value is None else value


def _scenario_status_notice(status: str) -> str:
    """Describe scenario yield without conflating diagnostics with candidates."""
    return {
        "completed": "Scenario generation completed for all requested candidates.",
        "no_candidates": (
            "No eligible scenario candidates were available. The analysis "
            "completed without scenario generation."
        ),
        "failed": (
            "Scenario generation failed. No scenarios were published after "
            "attempting candidates. Diagnostic and accounting artifacts were "
            "preserved."
        ),
        "degraded": (
            "Scenario generation completed with degraded yield: some requested "
            "candidates were failed or skipped."
        ),
    }.get(
        status,
        "Scenario generation status is unknown because candidate outcomes were "
        "not reported.",
    )


def render_report(*args: Any, **kwargs: Any) -> Path:
    """Compatibility alias used by report adapters."""
    return render_synthesis_report(*args, **kwargs)


def _value(value: Any, *names: str) -> Any:
    if value is None:
        return None
    for name in names:
        if isinstance(value, Mapping) and name in value:
            return value[name]
        result = getattr(value, name, None)
        if result is not None:
            return result
    return None


def _items(value: Any, *names: str) -> tuple[Any, ...]:
    result = _value(value, *names)
    if result is None:
        return ()
    if isinstance(result, (list, tuple, set, frozenset)):
        return tuple(result)
    return ()


def _mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return {str(key): item for key, item in value.items()}
    if value is None:
        return {}
    values = getattr(value, "__dict__", {})
    return {str(key): item for key, item in values.items() if not key.startswith("_")}


def _row(label: Any, value: Any) -> str:
    return f"<tr><th>{escape(str(label))}</th><td>{escape(str(value))}</td></tr>"


def _obligation_row(row: Any, route: Any = None, accounting: Any = None) -> str:
    identifier = _value(row, "obligation_id", "id") or ""
    scope = _value(row, "scope_disposition") or ""
    qualification = _value(row, "qualification_disposition") or ""
    disposition = _value(accounting, "disposition") or scope or "unresolved"
    stop_reason = _value(accounting, "stop_reason") or "not applicable to this row"
    route_disposition = _value(route, "disposition") or ""
    gap_items = _items(route, "missing_concepts", "gaps")
    gap_text = ", ".join(
        str(
            _value(item, "gap_id", "concept_id") or _value(item, "description") or "gap"
        )
        for item in gap_items
    )
    route_text = (
        " / ".join(item for item in (route_disposition, gap_text) if item) or "—"
    )
    finding_parts = []
    for label, field in (
        ("slots", "slot_ids"),
        ("ICAs", "ica_ids"),
        ("EXEC", "exec_candidate_ids"),
        ("hazards", "hazard_ids"),
        ("constraints", "constraint_ids"),
    ):
        values = _value(accounting, field) or _value(route, field) or ()
        if values:
            finding_parts.append(f"{label}: {', '.join(map(str, values))}")
    findings = "<br>".join(escape(item) for item in finding_parts) or "—"
    outcome = f"{disposition} ({scope}; {qualification})"
    return (
        "<tr>"
        f"<td><code>{escape(str(identifier))}</code></td>"
        f"<td>{escape(outcome)}</td>"
        f"<td>{escape(str(stop_reason))}</td>"
        f"<td>{escape(route_text)}</td>"
        f"<td>{findings}</td>"
        "</tr>"
    )


def _stop_reason_counts(
    accounting_rows: tuple[Any, ...], realization_records: tuple[Any, ...]
) -> dict[str, int]:
    """Reconcile accounting stops with later per-finding scenario outcomes."""
    realization_by_obligation = _report_realization_reasons(realization_records)
    counts: dict[str, int] = {}
    for row in accounting_rows:
        reason = _report_terminal_reason(row, realization_by_obligation)
        if reason is not None:
            counts[str(reason)] = counts.get(str(reason), 0) + 1
    return counts


def _report_realization_reasons(
    realization_records: tuple[Any, ...],
) -> dict[str, set[str]]:
    """Index report-facing realization reasons by obligation."""
    result: dict[str, set[str]] = {}
    for item in realization_records:
        reason = _value(item, "stop_reason")
        if reason is not None:
            result.setdefault(str(_value(item, "obligation_id")), set()).add(
                str(reason)
            )
    return result


def _report_terminal_reason(
    row: Any, realization_by_obligation: Mapping[str, set[str]]
) -> Any:
    """Prefer a later scenario result over the accounting result."""
    obligation_id = str(_value(row, "obligation_id"))
    realization_reasons = realization_by_obligation.get(obligation_id, set())
    return _terminal_realization_reason(realization_reasons) or _value(
        row, "stop_reason"
    )


def _terminal_realization_reason(reasons: set[str]) -> str | None:
    """Collapse multiple findings to one obligation-level terminal outcome."""
    for reason in (
        "scenario_realized",
        "scenario_generation_failure",
        "scenario_not_requested",
    ):
        if reason in reasons:
            return reason
    return None


def _revision_html(value: Any) -> str:
    if value is None:
        return "<p>No structural revision was required.</p>"
    status = _value(value, "status") or "not_required"
    accepted = _items(_value(value, "accepted_delta"), "additions")
    rejected = _items(value, "rejected_additions")
    additions = [
        str(_value(item, "addition_id", "description") or item) for item in accepted
    ]
    rejected_text = [
        str(_value(item, "addition_id", "description") or item) for item in rejected
    ]
    parts = [f"<p>Status: <code>{escape(str(status))}</code></p>"]
    if additions:
        parts.append("<p>Accepted additions: " + escape(", ".join(additions)) + "</p>")
    if rejected_text:
        parts.append(
            "<p>Rejected additions: " + escape(", ".join(rejected_text)) + "</p>"
        )
    return "".join(parts)


def _scenario_html(scenarios: tuple[Any, ...]) -> str:
    if not scenarios:
        return "<p>No scenario envelopes were produced.</p>"
    rows = []
    for item in scenarios:
        identifier = _value(item, "scenario_id", "id") or "(unidentified)"
        refs = _value(item, "obligation_ids", "obligation_refs", "trace_refs") or ()
        rows.append(
            "<tr>"
            f"<td><code>{escape(str(identifier))}</code></td>"
            f"<td>{escape(', '.join(map(str, refs)) or '—')}</td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>Scenario</th><th>Trace references</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def _candidate_outcomes_html(outcomes: Any) -> str:
    """Render exact candidate terminal records when the adapter supplied them."""
    values = _candidate_outcome_items(outcomes)
    if values:
        return _candidate_outcomes_table(values)
    return _empty_candidate_outcomes_html(outcomes)


def _candidate_outcome_items(outcomes: Any) -> tuple[Any, ...]:
    """Accept the manifest's direct sequence as well as object wrappers."""
    if isinstance(outcomes, (list, tuple, set, frozenset)):
        return tuple(outcomes)
    return _items(outcomes)


def _empty_candidate_outcomes_html(outcomes: Any) -> str:
    """Explain whether candidate records were empty or unavailable."""
    if outcomes is None:
        message = "Candidate outcomes were not reported by this adapter."
    else:
        message = "No scenario candidates were requested."
    return f"<h2>Candidate outcomes</h2><p>{message}</p>"


def _candidate_outcomes_table(values: tuple[Any, ...]) -> str:
    """Render one table row for each exact candidate terminal record."""
    rows = "".join(_candidate_outcome_row(item) for item in values)
    return (
        "<h2>Candidate outcomes</h2>"
        "<table><thead><tr><th>Scenario</th><th>ICA slot</th><th>ICA</th>"
        "<th>Status</th><th>Diagnostics</th></tr></thead><tbody>"
        + rows
        + "</tbody></table>"
    )


def _candidate_outcome_row(item: Any) -> str:
    """Render one candidate record without interpreting diagnostic content."""
    return (
        "<tr>"
        f"<td><code>{_candidate_field(item, 'scenario_id', '')}</code></td>"
        f"<td><code>{_candidate_field(item, 'ica_slot_id', '')}</code></td>"
        f"<td><code>{_candidate_field(item, 'ica_id', '—')}</code></td>"
        f"<td>{_candidate_field(item, 'status', 'unknown')}</td>"
        f"<td>{_candidate_diagnostics(item)}</td>"
        "</tr>"
    )


def _candidate_field(item: Any, name: str, fallback: str) -> str:
    """Escape one optional candidate field while retaining its fallback."""
    return escape(str(_value(item, name) or fallback))


def _candidate_diagnostics(item: Any) -> str:
    """Escape all diagnostics for one candidate as a single report cell."""
    diagnostics = _value(item, "diagnostics") or ()
    return escape("; ".join(map(str, diagnostics)) or "—")


def _realization_html(records: tuple[Any, ...]) -> str:
    if not records:
        return "<p>No obligation-to-scenario realization records were produced.</p>"
    rows = []
    for item in records:
        rows.append(
            "<tr>"
            f"<td><code>{escape(str(_value(item, 'obligation_id') or ''))}</code></td>"
            f"<td><code>{escape(str(_value(item, 'ica_id') or ''))}</code></td>"
            f"<td>{escape(str(_value(item, 'status') or 'unresolved'))}</td>"
            f"<td>{escape(str(_value(item, 'stop_reason') or '—'))}</td>"
            f"<td>{escape(', '.join(map(str, _value(item, 'scenario_ids') or ())) or '—')}</td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>Obligation</th><th>ICA</th><th>Realization</th>"
        "<th>Stop reason</th><th>Scenarios</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


__all__ = ["REPORT_FILENAME", "render_report", "render_synthesis_report"]
