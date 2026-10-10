"""What authoring receives from generation, and whether the manifest agrees with it."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from asago_scenario_generator.report.common import code_id, plural
from asago_scenario_generator.report.run_data import RunData
from asago_scenario_generator.report_kit import (
    Column,
    Markup,
    Row,
    artifact,
    callout,
    esc,
    join,
    section,
    table,
)

QUESTION = "Which files does the producer hand on, and does the manifest count what is on disk?"
COUNT_LABEL = {
    "requested": "requested",
    "attempted": "attempted",
    "generated": "generated",
    "functional_test": "functional test",
    "failed": "failed",
    "skipped": "skipped",
    "diagnostic_count": "diagnostic",
}


def schema_of(path: Path) -> str:
    """Read the ``schema_version`` a YAML or JSON file declares."""
    if not path.exists():
        return ""
    text = path.read_text(encoding="utf-8")
    value = json.loads(text) if path.suffix == ".json" else yaml.safe_load(text)
    return str(value.get("schema_version", "")) if isinstance(value, dict) else ""


def _link(run: RunData, name: str) -> Markup:
    return artifact(f"../{name}", run.output_dir / "report", name)


def _rows(run: RunData) -> list[Row]:
    out = run.output_dir
    first = next(iter(sorted(run.scenarios)), None)
    scenario_schema = "" if first is None else run.scenarios[first].schema_version
    pinned = len(run.manifest.source_artifacts)
    return [
        Row(
            [
                "Scenarios",
                _link(run, "scenarios/"),
                f"{len(run.scenarios)} files",
                code_id(scenario_schema),
                "Every scenario, including duplicates and analytical ones.",
            ]
        ),
        Row(
            [
                "Feature files",
                _link(run, "scenarios/"),
                f"{len(run.features)} files",
                "",
                "The Gherkin authoring reads in place of the YAML block.",
            ]
        ),
        Row(
            [
                "Testability",
                _link(run, "testability.yaml"),
                "",
                code_id(schema_of(out / "testability.yaml")),
                "Which scenarios authoring takes.",
            ]
        ),
        Row(
            [
                "Target profile",
                _link(run, "execution-target-profile.json"),
                "",
                code_id(schema_of(out / "execution-target-profile.json")),
                "Operations and state the target exposes.",
            ]
        ),
        Row(
            [
                "Run manifest",
                _link(run, "synthesis-manifest.yaml"),
                f"{pinned} pinned inputs",
                code_id(run.manifest.schema_version),
                "Inputs, digests, and counts of the run.",
            ]
        ),
    ]


def _counts_line(run: RunData) -> Markup:
    shown = [
        f"{n:,} {COUNT_LABEL.get(k, k.replace('_', ' '))}"
        for k, n in run.manifest.scenario_counts.items()
        if n
    ]
    if not shown:
        return Markup("")
    return Markup(f"<p>The manifest counts {esc(', '.join(shown))}.</p>")


def _disagreement(run: RunData) -> Markup:
    counted = run.manifest.scenario_counts.get("generated")
    if counted is None or counted == len(run.scenarios):
        return Markup("")
    body = Markup(
        f"<p>The manifest counts {counted} generated scenarios; "
        f"{len(run.scenarios)} scenario files are on disk.</p>"
    )
    return callout("warning", "Manifest and files disagree", body)


PUBLISHED = ("published", "functional_test")


def _unpublished(run: RunData) -> Markup:
    missed = [c for c in run.manifest.candidate_outcomes if c.status not in PUBLISHED]
    if not missed:
        return Markup("")
    rows = [
        Row(
            [
                code_id(c.scenario_id),
                code_id(c.ica_slot_id or "none"),
                c.status or "not reported",
                "; ".join(c.diagnostics) or "none",
            ],
            id=f"unpublished-{c.scenario_id}",
        )
        for c in missed
    ]
    columns = [
        Column("Candidate"),
        Column("Slot"),
        Column("Status"),
        Column("Diagnostics", sortable=False),
    ]
    lead = Markup(
        f"<p>{plural(len(missed), 'candidate')} did not publish a scenario.</p>"
    )
    return join([lead, table(columns, rows, "unpublished-candidates")])


def handoff_section(run: RunData) -> Markup:
    """Render the files the producer hands on, with schema versions."""
    columns = [
        Column("What", sortable=False),
        Column("File", sortable=False),
        Column("Size", sortable=False),
        Column("Schema", sortable=False),
        Column("Use", sortable=False),
    ]
    body = join(
        [
            Markup(
                "<p>The producer's contract ends here. Authoring reads these files "
                "and nothing else from generation.</p>"
            ),
            table(columns, _rows(run), "handoff-files"),
            _counts_line(run),
            _disagreement(run),
            _unpublished(run),
        ]
    )
    return section("handoff", "What authoring receives", QUESTION, body)
