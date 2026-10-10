"""Failed model requests: one row per chain of a request and its retries."""

from __future__ import annotations

from collections import Counter, defaultdict

from asago_scenario_generator.report.common import counted
from asago_scenario_generator.report.failures import (
    OUTCOME_ORDER,
    Failure,
    error_parts,
    failure_chains,
)
from asago_scenario_generator.report.run_data import RunData
from asago_scenario_generator.report.slot_view import slot_views
from asago_scenario_generator.report.steps import step_label
from asago_scenario_generator.report_kit import (
    Column,
    Markup,
    Row,
    badge,
    esc,
    join,
    section,
    table,
    truncate,
)

QUESTION = "Which requests failed, and what did each failure cost the output?"
OUTCOME_BADGE = {
    "lost": ("fail", "lost"),
    "degraded": ("warn", "degraded"),
    "repaired": ("pass", "repaired"),
    "recovered": ("pass", "recovered on retry"),
}


def _errors(failure: Failure) -> Markup:
    grouped: dict[tuple[str, str], list] = defaultdict(list)
    for call in failure.calls:
        if not call.success:
            grouped[error_parts(call)].append(call)
    lines = []
    for (code, message), calls in grouped.items():
        numbers = ", ".join(f"#{c.n}" for c in calls)
        label = Markup(f"<code>{esc(code)}</code> ") if code else ""
        lines.append(
            Markup(
                f'<div><span class="nm">{numbers}:</span> {label}{truncate(message, 200)}</div>'
            )
        )
    return join(lines)


def _request(failure: Failure) -> Markup:
    first = failure.first
    what = step_label(first) + (f" · {first.scenario_id}" if first.scenario_id else "")
    numbers = ", ".join(f"#{c.n}" for c in failure.calls)
    return Markup(f'{esc(what)}<div class="nm">requests {numbers}</div>')


def _row(failure: Failure) -> Row:
    tone, text = OUTCOME_BADGE[failure.outcome]
    return Row(
        [badge(tone, text), _request(failure), _errors(failure), failure.effect],
        id=f"failure-{failure.first.n}",
    )


def _lead(run: RunData, chains: list[Failure]) -> Markup:
    failed = sum(not c.success for c in run.calls)
    by_outcome = Counter(f.outcome for f in chains)
    parts = ", ".join(
        f"{counted(f'failures.{o}', by_outcome[o])} {OUTCOME_BADGE[o][1]}"
        for o in OUTCOME_ORDER
    )
    return Markup(
        f"<p>{counted('failures.failed', failed)} of {counted('failures.requests', len(run.calls))} "
        f"requests failed, in {counted('failures.chains', len(chains))} chains of a request "
        f"and its retries: {parts}.</p>"
    )


def failure_section(run: RunData) -> Markup:
    """Render the failure chains of a run, lost ones first."""
    chains = failure_chains(run, slot_views(run))
    if not chains:
        body = Markup("<p>No model request failed.</p>")
    else:
        columns = [
            Column("Outcome", sortable=False),
            Column("Request", sortable=False),
            Column("Error", sortable=False),
            Column("Effect on the output", sortable=False),
        ]
        body = join(
            [
                _lead(run, chains),
                table(columns, [_row(f) for f in chains], "failures-table"),
            ]
        )
    return section("failed", "Failed model requests", QUESTION, body)
