"""Which actions can go wrong, and how: a matrix of actions by failure type."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from asago_scenario_generator.report.common import (
    code_id,
    code_ids,
    counted,
    scenario_links,
)
from asago_scenario_generator.report.run_data import RunData
from asago_scenario_generator.report.slot_view import Finding, SlotView, slot_views
from asago_scenario_generator.report_kit import (
    Column,
    Markup,
    Row,
    badge,
    chip,
    disclosure,
    esc,
    join,
    section,
    table,
)

UCA_TYPES = ("NOT_PROVIDED", "INCORRECT", "WRONG_TIMING", "WRONG_DURATION")
UCA_LABEL = {
    "NOT_PROVIDED": "Not done",
    "INCORRECT": "Done unsafely",
    "WRONG_TIMING": "Wrong time or order",
    "WRONG_DURATION": "Wrong duration",
}
QUESTION = (
    "Every slot the producer considered, and the scenarios each one produced. "
    "A slot pairs one action with one way it can go wrong."
)


@dataclass(frozen=True)
class ActionRow:
    """One control action or coordination message, with where it comes from."""

    action_id: str
    description: str
    detail: str


def action_rows(run: RunData, slots: list[SlotView]) -> list[ActionRow]:
    """List the actions in control-structure order, then any a slot names alone."""
    rows: list[ActionRow] = []
    structure = run.structure
    if structure is not None:
        for resp in structure.responsibilities:
            for ca in resp.control_actions:
                how = f"tool {ca.operation}" if ca.operation else "reply"
                rows.append(
                    ActionRow(ca.ca_id, ca.description, f"{resp.resp_id} · {how}")
                )
        for link in structure.coordination_links:
            cm = link.coordination_mechanism
            detail = f"{link.link_id} · {link.source} ↔ {link.target} (coordination)"
            rows.append(ActionRow(cm.cm_id, cm.description, detail))
    known = {r.action_id for r in rows}
    extra = sorted({s.action_id for s in slots} - known)
    return rows + [ActionRow(a, "", "") for a in extra]


def _finding_line(run: RunData, finding: Finding) -> Markup:
    if finding.disposition == "supported":
        if finding.scenarios:
            return scenario_links(run, finding.scenarios)
        return chip("supported, no scenario", "outline")
    label = "excluded" if finding.disposition == "excluded" else "verification failed"
    return Markup(
        f'<span class="xb" title="{esc(finding.rationale)}">{chip(label, "outline")}</span>'
    )


def _cell(run: RunData, slot: SlotView | None) -> Markup:
    if slot is None:
        return Markup("")
    if slot.decision == "na":
        return Markup(f'<span class="na" title="{esc(slot.rationale)}">N/A</span>')
    if slot.decision == "none":
        return badge("fail", "no decision")
    if slot.decision == "unresolved":
        return Markup(
            f'<span title="{esc(slot.rationale)}">{badge("warn", "unresolved")}</span>'
        )
    return join(Markup(f"<div>{_finding_line(run, f)}</div>") for f in slot.findings)


def _matrix(run: RunData, slots: list[SlotView]) -> Markup:
    by_action: dict[tuple[str, str], SlotView] = {
        (s.action_id, s.uca): s for s in slots
    }
    rows = []
    for action in action_rows(run, slots):
        name = Markup(
            f"{code_id(action.action_id)} {esc(action.description)}"
            f'<div class="nm">{esc(action.detail)}</div>'
        )
        cells = [_cell(run, by_action.get((action.action_id, u))) for u in UCA_TYPES]
        rows.append(Row([name, *cells], id=f"action-{action.action_id}"))
    columns = [Column("Action", sortable=False)] + [
        Column(UCA_LABEL[u], sortable=False) for u in UCA_TYPES
    ]
    return table(columns, rows, "slots-matrix")


def _tally(slots: list[SlotView]) -> Markup:
    decisions = Counter(s.decision for s in slots)
    findings = [f for s in slots for f in s.findings]
    disposition = Counter(f.disposition for f in findings)
    failed = len(findings) - disposition["supported"] - disposition["excluded"]
    became = sum(len(f.scenarios) for f in findings if f.disposition == "supported")
    return Markup(
        f"<p>{counted('slots.total', len(slots))} slots: "
        f"{counted('slots.na', decisions['na'])} judged not applicable, "
        f"{counted('slots.findings', decisions['findings'])} with findings, "
        f"{counted('slots.unresolved', decisions['unresolved'])} unresolved, "
        f"{counted('slots.none', decisions['none'])} without a decision. "
        f"The findings number {counted('findings.total', len(findings))}: "
        f"{counted('findings.supported', disposition['supported'])} supported, "
        f"{counted('findings.excluded', disposition['excluded'])} excluded by the verifier, "
        f"{counted('findings.failed', failed)} whose verification failed. "
        f"Supported findings became {counted('findings.scenarios', became)} scenario links.</p>"
    )


def _na_list(slots: list[SlotView]) -> Markup:
    na = [s for s in slots if s.decision == "na"]
    items = join(
        Markup(
            f'<li class="na-reason">{code_id(s.slot_id)} {esc(s.rationale or "no reason recorded")}</li>'
        )
        for s in na
    )
    return disclosure(
        f"Why {len(na)} slots are not applicable",
        Markup(f"<ul>{items}</ul>"),
        "slots-na",
    )


def _rejected(slots: list[SlotView]) -> Markup:
    rejected = [f for s in slots for f in s.findings if f.disposition != "supported"]
    items = join(
        Markup(
            f'<li class="rejected">{code_id(f.ica_id)} {badge("warn", f.disposition.replace("_", " "))}'
            f"<div><b>Claim:</b> {esc(f.text)}</div>"
            f"<div><b>Verifier:</b> {esc(f.rationale)}</div></li>"
        )
        for f in rejected
    )
    return disclosure(
        f"Findings the verifier did not support ({len(rejected)})",
        Markup(f"<ul>{items}</ul>"),
        "slots-rejected",
    )


def _shrink(run: RunData) -> Markup:
    offers = run.offers
    if offers is None:
        return Markup("")
    shrunk = [o for o in offers.slots if o.shrunk]
    lines = join(
        Markup(
            f"<li>{code_id(o.slot_id)} lost hazard {code_ids(o.missing_own_hazard_ids)}"
            " from the offer the model saw.</li>"
        )
        for o in shrunk
    )
    return Markup(
        f"<p>{counted('slots.shrunk', offers.summary.shrunk_slots)} slots had a hazard of "
        "their own missing from the offer the model saw "
        f"({offers.summary.shrunk_slots_under_main_rule} under the earlier rule).</p>"
        + (f"<ul>{lines}</ul>" if shrunk else "")
    )


def slot_section(run: RunData) -> Markup:
    """Render the matrix, the tally, and the lists behind it."""
    slots = slot_views(run)
    body = join(
        [
            _tally(slots),
            _matrix(run, slots),
            _shrink(run),
            _na_list(slots),
            _rejected(slots),
        ]
    )
    return section("slots", "Which actions can go wrong, and how?", QUESTION, body)
