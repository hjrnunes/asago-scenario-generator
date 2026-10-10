"""Warnings the producer recorded without stopping, grouped by source and kind."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from asago_scenario_generator.report.common import code_ids, counted
from asago_scenario_generator.report.run_data import RunData
from asago_scenario_generator.report_kit import (
    Column,
    Markup,
    Row,
    chip,
    esc,
    join,
    section,
    table,
)

QUESTION = "What did the producer flag without stopping?"
SOURCE_LABEL = {
    "Baseline stage_warnings": "Baseline",
    "Baseline post_revision_warnings": "After revision",
}
KIND_LABEL = {"hazard_state_unspecified": "Hazard states no system condition"}
_KIND = re.compile(r"^(?P<kind>[\w/]+)(?: \((?P<severity>\w+)\))?: (?P<rest>.*)$", re.S)
_ID = re.compile(r"\b(?:H|SC|CA|CM|L|RESP|CL)-\d+(?:-\d+)*\b")


@dataclass
class Group:
    """Warnings that differ only in one identifier."""

    source: str
    kind: str
    template: str
    ids: list[str] = field(default_factory=list)


def _split(warning: str) -> tuple[str, str, str]:
    source, sep, rest = warning.partition(": ")
    if not sep:
        return "", "", warning
    kind = _KIND.match(rest)
    if kind and ("/" in kind["kind"] or kind["severity"]):
        return source, kind["kind"], kind["rest"]
    return source, "", rest


def _templated(text: str) -> tuple[str, str | None]:
    found = _ID.search(text)
    if found is None:
        return text, None
    return text[: found.start()] + "{ids}" + text[found.end() :], found.group(0)


def groups(warnings: list[str]) -> list[Group]:
    """Group *warnings* by source, kind, and text with its first identifier removed."""
    found: dict[tuple[str, str, str], Group] = {}
    for warning in warnings:
        source, kind, text = _split(warning)
        template, ident = _templated(text)
        group = found.setdefault(
            (source, kind, template), Group(source, kind, template)
        )
        if ident is not None:
            group.ids.append(ident)
    return list(found.values())


def _text(group: Group) -> Markup:
    kind = KIND_LABEL.get(group.kind, group.kind.replace("_", " "))
    ids = code_ids(sorted(set(group.ids)))
    if "{ids}" not in group.template:
        shown = esc(group.template)
        return Markup(f"<b>{esc(kind)}</b> {shown}" if kind else shown)
    before, after = group.template.split("{ids}", 1)
    if group.kind in KIND_LABEL:
        return Markup(
            f'<b>{esc(kind)}:</b> {ids}<div class="nm">{esc(after.lstrip())}</div>'
        )
    return Markup(f"{esc(before)}{ids}{esc(after)}")


def _source(group: Group) -> Markup:
    return chip(SOURCE_LABEL.get(group.source, group.source or "Producer"), "outline")


def warning_section(run: RunData) -> Markup:
    """Render the manifest's warnings, one row per group."""
    warnings = run.manifest.stage_warnings
    if not warnings:
        body = Markup("<p>No warnings.</p>")
    else:
        rows = [
            Row(
                [_source(g), _text(g), len(g.ids) or 1],
                id=f"warning-{n}",
            )
            for n, g in enumerate(groups(warnings), 1)
        ]
        columns = [
            Column("Source"),
            Column("Warning", sortable=False),
            Column("Count", numeric=True),
        ]
        body = join(
            [
                Markup(f"<p>{counted('warnings.total', len(warnings))} warnings.</p>"),
                table(columns, rows, "warnings-table"),
            ]
        )
    return section("warnings", "Warnings", QUESTION, body)
