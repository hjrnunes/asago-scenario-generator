"""Where did the mechanism suggestions stop? One row per mechanism and slot.

A mechanism suggestion makes no coverage claim, so this section reads
``mechanism-suggestion-accounting.yaml`` alone and never joins the obligation
counts.
"""

from __future__ import annotations

from collections import Counter, defaultdict

from asago_scenario_generator.models.mechanism_suggestion_accounting import (
    MECHANISM_SUGGESTION_ACCOUNTING_FILENAME,
    STOP_REASONS,
    MechanismSuggestionAccounting,
    MechanismSuggestionRow,
)
from asago_scenario_generator.report.common import (
    code_id,
    code_ids,
    counted,
    missing,
    plural,
)
from asago_scenario_generator.report.run_data import RunData
from asago_scenario_generator.report_kit import (
    Column,
    Markup,
    Row,
    badge,
    disclosure,
    esc,
    join,
    section,
    table,
)
from asago_scenario_generator.stpa.mechanism_library import bundled_mechanism_library

STOP_MEANING = {
    "not_proposed": (
        "Not proposed",
        "No join path, filtered or not, reaches the slot with this mechanism.",
    ),
    "authority_filtered": (
        "Dropped by the authority filter",
        "Only the unfiltered join reaches the slot; the authority filter dropped every path.",
    ),
    "slot_not_analyzed": (
        "Slot not analyzed",
        "The structure alone decides the slot, so no request carries the suggestion.",
    ),
    "verifier_rejected": (
        "Verifier rejected",
        "The mechanism verifier judged every path an adjacent control.",
    ),
    "verifier_unresolved": (
        "Verifier unresolved",
        "No path was judged mechanism-specific, and at least one lacked evidence or a verdict.",
    ),
    "over_cap": (
        "Over the slot's cap",
        "Verified, but the slot already carried the most suggestions it may.",
    ),
    "prompt_budget_exceeded": (
        "Request too large",
        "Verified and within the cap, but the slot request could not carry it within its prompt budget.",
    ),
    "slot_fill_unresolved": (
        "Slot filling unresolved",
        "Slot filling left the suggestion unresolved.",
    ),
    "slot_fill_not_applicable": (
        "Slot filling found it not applicable",
        "Slot filling proposed the suggestion not applicable.",
    ),
    "ica_verifier_rejected": (
        "Finding excluded by the verifier",
        "Slot filling found it, but the independent verifier excluded every finding.",
    ),
    "finding": (
        "Became a finding",
        "A verified finding (ICA) expresses the suggestion.",
    ),
}
# The bulk of the pairs; its group comes last and stays collapsed.
BULK = "not_proposed"
QUESTION = (
    "Each row pairs one mechanism of the library with one slot and names the "
    "single reason it stopped. A suggestion makes no coverage claim, so these "
    "rows are counted apart from the attack-pattern obligations."
)


def _slug(reason: str) -> str:
    return reason.replace("_", "-")


def _mechanisms(accounting: MechanismSuggestionAccounting) -> list[str]:
    """The mechanisms the rows name, in library order."""
    present = {row.mechanism_id for row in accounting.rows}
    return [
        str(entry.id)
        for entry in bundled_mechanism_library().mechanisms
        if entry.id in present
    ]


def _reasons(accounting: MechanismSuggestionAccounting) -> list[str]:
    """The stop reasons the summary lists, in their fixed order."""
    return [r for r in STOP_REASONS if r in accounting.summary.stop_reasons]


def _reason_cell(reason: str) -> Markup:
    return join([STOP_MEANING[reason][0], " ", code_id(reason)])


def _summary_table(accounting: MechanismSuggestionAccounting) -> Markup:
    counts = accounting.summary.stop_reasons
    rows = [
        Row(
            [
                _reason_cell(reason),
                counted(f"mechanism_suggestions.{reason}", counts[reason]),
                STOP_MEANING[reason][1],
            ],
            id=f"mech-stop-{_slug(reason)}",
        )
        for reason in _reasons(accounting)
    ]
    columns = [
        Column("Stop reason", sortable=False),
        Column("Rows", sortable=False),
        Column("Meaning", sortable=False),
    ]
    return table(columns, rows, "mechanism-suggestions-summary-table")


def _breakdown_table(accounting: MechanismSuggestionAccounting) -> Markup:
    mechanisms = _mechanisms(accounting)
    pairs = Counter((str(row.mechanism_id), row.stop_reason) for row in accounting.rows)
    rows = [
        Row(
            [
                _reason_cell(reason),
                *(pairs[(m, reason)] for m in mechanisms),
                accounting.summary.stop_reasons[reason],
            ],
            id=f"mech-breakdown-{_slug(reason)}",
        )
        for reason in _reasons(accounting)
    ]
    columns = [
        Column("Stop reason", sortable=False),
        *(Column(m, numeric=True) for m in mechanisms),
        Column("All mechanisms", numeric=True),
    ]
    return table(
        columns,
        rows,
        "mechanism-suggestions-breakdown-table",
        caption="Rows per mechanism and stop reason",
    )


def _detail(row: MechanismSuggestionRow) -> Markup:
    return join(
        [part for part in (code_ids(row.ica_ids), esc(row.detail or "")) if part], " "
    )


def _rows_table(reason: str, members: list[MechanismSuggestionRow]) -> Markup:
    rows = [
        Row([code_id(row.mechanism_id), code_id(row.slot_id), _detail(row)])
        for row in members
    ]
    columns = [
        Column("Mechanism"),
        Column("Slot"),
        Column("Detail", sortable=False),
    ]
    return table(columns, rows, f"mechanism-suggestions-{_slug(reason)}-table")


def _row_disclosure(reason: str, members: list[MechanismSuggestionRow]) -> Markup:
    label, meaning = STOP_MEANING[reason]
    tone = "pass" if reason == "finding" else ("skip" if reason == BULK else "warn")
    slots = len({row.slot_id for row in members})
    summary = join(
        [
            badge(tone, label),
            " ",
            code_id(reason),
            Markup(
                f' <span class="nm">{plural(len(members), "row")} over '
                f"{plural(slots, 'slot')}. {esc(meaning)}</span>"
            ),
        ]
    )
    return disclosure(
        summary,
        _rows_table(reason, members),
        f"mech-{_slug(reason)}",
        open=reason != BULK,
    )


def _lead(accounting: MechanismSuggestionAccounting) -> Markup:
    rows = accounting.rows
    mechanisms = len({row.mechanism_id for row in rows})
    slots = len({row.slot_id for row in rows})
    return Markup(
        f"<p>{counted('mechanism_suggestions.rows', accounting.summary.rows)} "
        f"mechanism and slot pairs: {plural(mechanisms, 'mechanism')} across "
        f"{plural(slots, 'slot')}.</p>"
    )


def _body(accounting: MechanismSuggestionAccounting) -> Markup:
    by_reason: dict[str, list[MechanismSuggestionRow]] = defaultdict(list)
    for row in accounting.rows:
        by_reason[row.stop_reason].append(row)
    ordered = [r for r in STOP_REASONS if r in by_reason and r != BULK]
    if BULK in by_reason:
        ordered.append(BULK)
    parts = [_lead(accounting), _summary_table(accounting)]
    if accounting.rows:
        parts.append(_breakdown_table(accounting))
    parts.extend(_row_disclosure(r, by_reason[r]) for r in ordered)
    return join(parts)


def mechanism_section(run: RunData) -> Markup:
    """Render the section that groups mechanism and slot pairs by stop reason."""
    if run.mechanisms is None:
        body = missing(run, MECHANISM_SUGGESTION_ACCOUNTING_FILENAME)
    else:
        body = _body(run.mechanisms)
    return section(
        "mechanism-suggestions",
        "Where did the mechanism suggestions stop?",
        QUESTION,
        body,
    )
