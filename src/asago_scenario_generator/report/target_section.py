"""Target mapping: baseline control actions, observed operations, and capabilities.

The three lists count different things, so the section counts each on its own
and never adds them together.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Iterable

from asago_scenario_generator.report.common import code_id, counted, missing
from asago_scenario_generator.report.run_data import RunData
from asago_scenario_generator.report_kit import (
    Column,
    Markup,
    Row,
    badge,
    esc,
    join,
    section,
    table,
)

QUESTION = (
    "Which of the baseline's control actions did the producer map onto the target's "
    "observed operations, and what does the target expose beyond them?"
)
SUPPORTED = {"supported"}


def _value(item: Any) -> str:
    return str(getattr(item, "value", item))


def _label(item: Any) -> str:
    return _value(item).replace("_", " ")


def _tone(disposition: str) -> str:
    return "pass" if disposition in SUPPORTED else "warn"


def _breakdown(prefix: str, dispositions: Iterable[str]) -> Markup:
    count = Counter(dispositions)
    return join(
        [
            Markup(f" {counted(f'{prefix}.{key}', n)} {esc(key.replace('_', ' '))}")
            for key, n in sorted(count.items())
        ],
        ",",
    )


def _action_rows(result: Any) -> list[Row]:
    rows = []
    for row in sorted(result.rows, key=lambda r: r.control_action_id):
        selected = row.selected_operation
        operation = selected.operation_id if selected is not None else "none"
        disposition = _value(row.disposition)
        rows.append(
            Row(
                [
                    code_id(row.control_action_id),
                    row.controller_id,
                    badge(_tone(disposition), _label(disposition)),
                    operation,
                    row.rationale,
                ],
                id=f"target-action-{row.control_action_id}",
            )
        )
    return rows


def _operation_rows(result: Any) -> list[Row]:
    rows = []
    for record in sorted(
        result.operation_records, key=lambda r: r.operation.reference.operation_id
    ):
        operation = record.operation
        disposition = _value(record.disposition)
        rows.append(
            Row(
                [
                    code_id(operation.reference.operation_id),
                    operation.description,
                    f"{operation.effect}{' · changes state' if operation.state_changing else ''}",
                    badge(_tone(disposition), _label(disposition)),
                    " ".join(record.baseline_control_action_ids) or "none",
                ],
                id=f"target-operation-{operation.reference.operation_id}",
            )
        )
    return rows


def _capability_rows(result: Any) -> list[Row]:
    rows = []
    for item in sorted(result.capability_reconciliation, key=lambda r: r.capability):
        disposition = _value(item.disposition)
        rows.append(
            Row(
                [
                    item.capability,
                    "declared" if item.declared else "not declared",
                    "observed" if item.observed else "not observed",
                    badge("warn" if item.conflicting else "info", _label(disposition)),
                ]
            )
        )
    return rows


def _actions_block(result: Any) -> Markup:
    lead = Markup(
        f"<p>{counted('target.actions', len(result.rows))} baseline control actions:"
        f"{_breakdown('target.actions', (_value(r.disposition) for r in result.rows))}.</p>"
    )
    columns = [
        Column("Control action"),
        Column("Responsibility"),
        Column("Disposition"),
        Column("Selected operation"),
        Column("Rationale", sortable=False),
    ]
    return join([lead, table(columns, _action_rows(result), "target-actions")])


def _operations_block(result: Any) -> Markup:
    records = result.operation_records
    lead = Markup(
        f"<p>{counted('target.operations', len(records))} operations the target exposes:"
        f"{_breakdown('target.operations', (_value(r.disposition) for r in records))}.</p>"
    )
    columns = [
        Column("Operation"),
        Column("Description", sortable=False),
        Column("Effect"),
        Column("Disposition"),
        Column("Baseline actions"),
    ]
    return join([lead, table(columns, _operation_rows(result), "target-operations")])


def _capabilities_block(result: Any) -> Markup:
    items = result.capability_reconciliation
    lead = Markup(
        f"<p>{counted('target.capabilities', len(items))} capabilities compared with "
        "what the target exposes.</p>"
    )
    columns = [
        Column("Capability"),
        Column("Declared"),
        Column("Observed"),
        Column("Reconciliation"),
    ]
    return join([lead, table(columns, _capability_rows(result), "target-capabilities")])


def _hidden(values: list[Any]) -> str:
    named = (
        f"{v['process_model_id']}: {v['value']}" if isinstance(v, dict) else str(v)
        for v in values
    )
    return ", ".join(named) or "none"


def _context_rows(tables: dict[str, Any]) -> list[Row]:
    rows = []
    for action in tables.get("actions", []):
        unseen = action["combinations"] - action["rows_shown"]
        note = (
            badge("warn", f"{unseen} combinations not shown")
            if unseen > 0
            else badge("pass", "all shown")
        )
        rows.append(
            Row(
                [
                    code_id(action["control_action"]),
                    action["combinations"],
                    action["rows_shown"],
                    _hidden(action.get("hidden_values") or []),
                    note,
                ],
                id=f"context-{action['control_action']}",
            )
        )
    return rows


def _context_block(run: RunData) -> Markup:
    tables = run.manifest.context_tables
    if not tables:
        return Markup("")
    hidden = sum(a["combinations"] > a["rows_shown"] for a in tables.get("actions", []))
    lead = Markup(
        "<h3>Context tables</h3><p>The scenario writer sees at most "
        f"{counted('context.budget', tables['row_budget'])} context rows per control action; "
        f"{counted('context.hidden', hidden)} actions have combinations it did not see.</p>"
    )
    columns = [
        Column("Control action"),
        Column("Combinations", numeric=True),
        Column("Rows shown", numeric=True),
        Column("Values left out", sortable=False),
        Column("Coverage", sortable=False),
    ]
    return join([lead, table(columns, _context_rows(tables), "context-tables")])


def target_section(run: RunData) -> Markup:
    """Render the target-mapping counts and the context-table coverage."""
    result = run.realization
    if result is None:
        body = missing("target-realization.yaml")
    else:
        body = join(
            [
                _actions_block(result),
                _operations_block(result),
                _capabilities_block(result),
                _context_block(run),
            ]
        )
    return section("target", "How was the target mapped?", QUESTION, body)
