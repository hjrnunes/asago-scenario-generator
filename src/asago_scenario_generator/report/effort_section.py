"""Where the effort went: requests, failures, tokens, and time per step."""

from __future__ import annotations

from collections import defaultdict

from asago_scenario_generator.report.common import counted
from asago_scenario_generator.report.run_data import CallRecord, RunData
from asago_scenario_generator.report.steps import GROUPS, OTHER, group_of
from asago_scenario_generator.report_kit import (
    Column,
    Markup,
    Row,
    join,
    section,
    table,
)

QUESTION = "How many model requests, tokens, and seconds did each step use?"


def _by_group(calls: tuple[CallRecord, ...]) -> dict[str, list[CallRecord]]:
    found: dict[str, list[CallRecord]] = defaultdict(list)
    for call in calls:
        found[group_of(call)[0]].append(call)
    return found


def _rows(run: RunData) -> list[Row]:
    found = _by_group(run.calls)
    total = sum(c.tokens for c in run.calls) or 1
    labels = [(key, label) for key, label, _ in GROUPS] + [OTHER]
    rows = []
    for key, label in labels:
        calls = found.get(key)
        if not calls:
            continue
        tokens = sum(c.tokens for c in calls)
        rows.append(
            Row(
                [
                    label,
                    len(calls),
                    sum(not c.success for c in calls),
                    tokens,
                    f"{100 * tokens / total:.0f}%",
                    round(sum(c.duration_ms for c in calls) / 1000),
                ],
                id=f"effort-{key}",
            )
        )
    return rows


def effort_section(run: RunData) -> Markup:
    """Render requests, failures, tokens, share, and seconds per pipeline step."""
    calls = run.calls
    columns = [
        Column("Step", sortable=False),
        Column("Requests", numeric=True),
        Column("Failed", numeric=True),
        Column("Tokens", numeric=True),
        Column("Share of tokens", sortable=False),
        Column("Seconds", numeric=True),
    ]
    lead = Markup(
        f"<p>{counted('effort.requests', len(calls))} requests, "
        f"{counted('effort.failed', sum(not c.success for c in calls))} failed, used "
        f"{counted('effort.tokens', sum(c.tokens for c in calls))} tokens and "
        f"{counted('effort.seconds', round(sum(c.duration_ms for c in calls) / 1000))} seconds.</p>"
    )
    body = join([lead, table(columns, _rows(run), "effort-table")])
    return section("effort", "Where did the effort go?", QUESTION, body)
