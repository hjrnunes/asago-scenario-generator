"""The deterministic slot/hazard check and its coverage diagnostic, apart.

Final-ICA verification records both in its batch diagnostics. A slot/hazard
flag says a finding cites a hazard about an operation its own control action
does not reach. A coverage finding says a cited hazard names an operation no
control action invokes: the gap is in the control structure, not the tie.
"""

from __future__ import annotations

from asago_scenario_generator.report.common import code_id, counted
from asago_scenario_generator.report.run_data import RunData
from asago_scenario_generator.report_kit import (
    Column,
    Markup,
    Row,
    esc,
    join,
    section,
    table,
)
from asago_scenario_generator.stpa.obligation_aware.slot_hazard_ownership import (
    SLOT_HAZARD_MISMATCH_CODE,
    UNINVOKED_HAZARD_OPERATION_CODE,
)

SLOT_QUESTION = (
    "Which findings cite a hazard about an operation their own control action "
    "does not reach? Each flagged finding stays in its slot."
)
COVERAGE_QUESTION = (
    "Which cited hazards name a target operation no control action invokes? "
    "No slot owns such an operation, so the control structure leaves it uncovered."
)


def _rows(run: RunData, code: str, prefix: str) -> list[Row]:
    diagnostics = [
        item
        for item in run.manifest.provider_evidence.ica.ica_hazard_verification.diagnostics
        if item.code == code
    ]
    return [
        Row(
            [join((code_id(ref) for ref in item.refs), " "), esc(item.detail)],
            id=f"{prefix}-{n}",
        )
        for n, item in enumerate(diagnostics, 1)
    ]


def _body(rows: list[Row], key: str, what: str, table_id: str) -> Markup:
    if not rows:
        return Markup(f"<p>No {what}.</p>")
    columns = [Column("Finding"), Column("Reason", sortable=False)]
    return join(
        [
            Markup(f"<p>{counted(key, len(rows))} {what}.</p>"),
            table(columns, rows, table_id),
        ]
    )


def slot_hazard_section(run: RunData) -> Markup:
    """Render the slot/hazard check's flags, one row per finding and hazard."""
    rows = _rows(run, SLOT_HAZARD_MISMATCH_CODE, "slot-hazard")
    body = _body(rows, "slot_hazard.flags", "slot/hazard flags", "slot-hazard-table")
    return section(
        "slot-hazard-ties", "Hazards outside the finding's slot", SLOT_QUESTION, body
    )


def uninvoked_operation_section(run: RunData) -> Markup:
    """Render the coverage findings, one row per finding and hazard."""
    rows = _rows(run, UNINVOKED_HAZARD_OPERATION_CODE, "uninvoked-operation")
    body = _body(
        rows,
        "coverage.uninvoked_operations",
        "hazards naming an operation no action invokes",
        "uninvoked-operation-table",
    )
    return section(
        "uninvoked-operations",
        "Hazard operations no action invokes",
        COVERAGE_QUESTION,
        body,
    )
