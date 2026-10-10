"""The generate report: ``report/index.html`` and ``report/stage-summary.json``.

Both files come from one read of the run, and the stage summary is checked
against the page before either is written.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from asago_scenario_generator.report.effort_section import effort_section
from asago_scenario_generator.report.failure_section import failure_section
from asago_scenario_generator.report.handoff_section import handoff_section
from asago_scenario_generator.report.obligation_section import obligation_section
from asago_scenario_generator.report.overview_section import (
    Counts,
    answer_section,
    counts,
    how_section,
)
from asago_scenario_generator.report.policy_section import policy_section
from asago_scenario_generator.report.run_data import RunData, load_run
from asago_scenario_generator.report.scenario_section import scenario_section
from asago_scenario_generator.report.slot_section import slot_section
from asago_scenario_generator.report.steps import step_label
from asago_scenario_generator.report.target_section import target_section
from asago_scenario_generator.report.testability_section import testability_section
from asago_scenario_generator.report.warning_section import warning_section
from asago_scenario_generator.report_kit import (
    Markup,
    check_headline,
    page,
)

REPORT_DIR = "report"
INDEX = "index.html"
SUMMARY = "stage-summary.json"
SCHEMA = (
    Path(__file__).resolve().parent.parent
    / "report_kit"
    / "stage-summary-v1.schema.json"
)
EXTRA_CSS = ""
RUN_STATUS = {
    "completed": "pass",
    "degraded": "warn",
    "failed": "fail",
    "no_candidates": "skip",
}
ITEM = {
    "canonical": ("pass", "Sent to authoring"),
    "duplicate": ("skip", "Duplicate of {of}"),
    "analytical_only": ("skip", "Analytical only"),
}


@dataclass(frozen=True)
class Written:
    """Where a report was written."""

    index: Path
    summary: Path


def _identity(run: RunData, n: Counts) -> list[tuple[str, Any]]:
    manifest = run.manifest
    return [
        ("Stage", "generate"),
        ("Owner", "producer (asago-scenario-generator)"),
        ("Run", manifest.run_id),
        ("Model profile", manifest.model_controls.get("profile", "unknown")),
        ("Model requests", f"{n.requests:,}"),
        ("Run status", manifest.run_status),
    ]


def _sections(run: RunData) -> list[Markup]:
    return [
        answer_section(run),
        how_section(),
        policy_section(run),
        slot_section(run),
        testability_section(run),
        obligation_section(run),
        failure_section(run),
        warning_section(run),
        scenario_section(run),
        target_section(run),
        handoff_section(run),
        effort_section(run),
    ]


def _headline(n: Counts) -> list[dict[str, Any]]:
    values = [
        {
            "key": "scenarios.written",
            "label": "Scenarios written",
            "value": n.written,
            "unit": "scenarios",
        },
        {
            "key": "scenarios.sent",
            "label": "Sent to authoring",
            "value": n.sent,
            "of": n.written,
            "unit": "scenarios",
        },
    ]
    if n.risks is not None:
        values.append(
            {
                "key": "policy.reached",
                "label": "Policy risks with a scenario",
                "value": n.reached,
                "of": n.risks,
                "unit": "risks",
            }
        )
    return values


def _alerts(n: Counts) -> list[dict[str, str]]:
    lost = [
        {
            "status": "fail",
            "text": f"Request #{f.first.n} ({step_label(f.first)}) failed and nothing "
            "replaced it" + (f": {f.short}" if f.short else ""),
            "href": f"{INDEX}#failed",
        }
        for f in n.lost
    ]
    degraded = [
        {"status": "warn", "text": f.effect, "href": f"{INDEX}#failed"}
        for f in n.degraded
    ]
    return lost + degraded


def _items(run: RunData) -> list[dict[str, str]]:
    items = []
    for scenario_id, row in sorted((run.testability or {}).items()):
        status, label = ITEM[row.status]
        items.append(
            {
                "scenario_id": scenario_id,
                "status": status,
                "label": label.format(of=row.duplicate_of),
                "code": row.status,
                "href": f"{INDEX}#{scenario_id}",
            }
        )
    return items


def _summary(run: RunData, n: Counts) -> dict[str, Any]:
    status = RUN_STATUS.get(run.manifest.run_status, "unknown")
    if status == "pass" and (n.lost or n.degraded):
        status = "warn"
    return {
        "schema_version": "stage-summary-v1",
        "stage": "generate",
        "owner": "producer",
        "status": status,
        "report": INDEX,
        "headline": _headline(n),
        "alerts": _alerts(n),
        "items": _items(run),
        "usage": {
            "model_requests": n.requests,
            "failed_requests": n.failed,
            "tokens": sum(
                (c.prompt_tokens or 0) + (c.completion_tokens or 0) for c in run.calls
            ),
        },
    }


def build_report(run: RunData) -> tuple[Markup, dict[str, Any]]:
    """Render the page and its stage summary from one loaded run."""
    n = counts(run)
    html = page(
        "Generate report",
        "developer",
        _identity(run, n),
        _sections(run),
        footer="Reads the generate stage output only.",
        extra_css=EXTRA_CSS,
    )
    return html, _summary(run, n)


def write_report(output_dir: Path | str) -> Written:
    """Write ``report/index.html`` and ``report/stage-summary.json`` under *output_dir*."""
    output = Path(output_dir)
    (output / REPORT_DIR).mkdir(exist_ok=True)
    html, summary = build_report(load_run(output))
    Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8"))).validate(
        summary
    )
    check_headline(summary, html)
    index = output / REPORT_DIR / INDEX
    index.write_text(html, encoding="utf-8")
    path = output / REPORT_DIR / SUMMARY
    path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return Written(index, path)
