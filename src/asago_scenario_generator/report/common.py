"""Small renderers every section of the generate report shares."""

from __future__ import annotations

from typing import Any, Iterable

from asago_scenario_generator.report.run_data import RunData
from asago_scenario_generator.report_kit import Markup, badge, callout, chip, esc, join

ATTACK = "adversarial"


def code_id(value: Any) -> Markup:
    """Render an identifier in monospace."""
    return Markup(f"<code>{esc(value)}</code>")


def code_ids(values: Iterable[Any]) -> Markup:
    """Render identifiers in monospace, separated by spaces."""
    return join((code_id(v) for v in values), " ")


def kind_word(kind: str) -> str:
    """Name a handoff kind the way a reader does: attack or everyday check."""
    return "attack" if kind == ATTACK else "everyday"


def kind_chip(kind: str) -> Markup:
    """Render a scenario's kind as a chip."""
    return chip(kind_word(kind), "violet" if kind == ATTACK else "blue")


def scenario_link(run: RunData, scenario_id: str) -> Markup:
    """Link a scenario id to its row, colored by kind."""
    scenario = run.scenarios.get(scenario_id)
    tone = (
        None if scenario is None else ("violet" if scenario.kind == ATTACK else "blue")
    )
    return Markup(f'<a href="#{esc(scenario_id)}">{chip(scenario_id, tone)}</a>')


def scenario_links(run: RunData, scenario_ids: Iterable[str]) -> Markup:
    """Link several scenarios, separated by spaces."""
    return join((scenario_link(run, s) for s in scenario_ids), " ")


def sendable(run: RunData, scenario_id: str) -> bool:
    """Tell whether authoring takes the scenario (testable and not a duplicate)."""
    row = None if run.testability is None else run.testability.get(scenario_id)
    return row is not None and row.status == "canonical"


def plural(count: int, singular: str, many: str | None = None) -> str:
    """Return ``1 risk`` or ``2 risks``."""
    return f"{count} {singular if count == 1 else many or singular + 's'}"


def missing(name: str) -> Markup:
    """Say that a file the section reads is absent from the run."""
    return callout(
        "limit",
        "Not in this run",
        Markup(
            f'<p><span class="artifact missing">{esc(name)}: not in this run</span></p>'
        ),
    )


def status_badge(ok: bool, good: str, bad: str) -> Markup:
    """Render a pass or warn badge from a flag."""
    return badge("pass", good) if ok else badge("warn", bad)
