"""Trace one scenario back to the policy risks, losses, hazards, and slot it came from."""

from __future__ import annotations

from asago_scenario_generator.report.common import ATTACK, code_id, kind_chip
from asago_scenario_generator.report.run_data import RunData
from asago_scenario_generator.report.slot_section import UCA_LABEL, action_rows
from asago_scenario_generator.report.slot_view import Finding, SlotView, slot_views
from asago_scenario_generator.report.steps import step_label
from asago_scenario_generator.report.testability_section import (
    CHECK_LABEL,
    check_of,
    omitted_reason,
    tool_of,
)
from asago_scenario_generator.report_kit import (
    Markup,
    badge,
    esc,
    join,
    truncate,
)

CONDITION_LIMIT = 300
TOOL_TONE = {"bound": "pass"}


def _div(*parts: object) -> Markup:
    return Markup(f"<div>{join(parts)}</div>")


def policy_risk_names(run: RunData, loss_ids: list[str]) -> list[str]:
    """Name the policy risks that the scenario's losses cite."""
    if run.policy is None:
        return sorted(
            {r for loss in _losses(run, loss_ids) for r in loss.source_risk_cards}
        )
    names = {
        r["risk_id"]: r.get("display_name") or r["name"] for r in run.policy["risks"]
    }
    wanted = {
        r
        for h in run.policy["harms"]
        if h["loss_id"] in loss_ids
        for r in h["risk_ids"]
    }
    return sorted({names.get(r, r) for r in wanted}, key=str.lower)


def _losses(run: RunData, loss_ids: list[str]) -> list:
    if run.loss is None:
        return []
    every = [*run.loss.risk_card_losses, *run.loss.use_case_losses]
    return [loss for loss in every if loss.loss_id in loss_ids]


def _hazards(run: RunData, hazard_ids: list[str]) -> list:
    return (
        [h for h in run.loss.hazards if h.hazard_id in hazard_ids] if run.loss else []
    )


def _slot(slot: SlotView | None, run: RunData) -> Markup:
    if slot is None:
        return Markup("")
    names = {a.action_id: a.description for a in action_rows(run, [slot])}
    way = UCA_LABEL.get(slot.uca, slot.uca).lower()
    return _div(
        code_id(slot.slot_id), f" {way}: ", names.get(slot.action_id, slot.action_id)
    )


def _finding(finding: Finding | None, ica_id: str) -> Markup:
    if finding is None:
        return _div(code_id(ica_id), " (no verification record)")
    after = " after correction" if finding.corrected else ""
    return Markup(
        f"{_div(code_id(ica_id), f' {finding.text}, when {finding.context}')}"
        f'<div class="nm">Verifier: {esc(finding.verdict)}{after}. {esc(finding.rationale)}</div>'
    )


def _kind(run: RunData, scenario_id: str) -> Markup:
    scenario = run.scenarios[scenario_id]
    outcome = next(
        (c for c in run.manifest.candidate_outcomes if c.scenario_id == scenario_id),
        None,
    )
    if scenario.kind == ATTACK:
        why = "Published as an attack: an adversary gains from this outcome."
    else:
        diagnostics = outcome.diagnostics if outcome else []
        why = (
            diagnostics[0].split(": ", 1)[-1]
            if diagnostics
            else "Published as an everyday check."
        )
    return Markup(f'{kind_chip(scenario.kind)} <span class="nm">{esc(why)}</span>')


def _condition(run: RunData, scenario_id: str) -> Markup:
    scenario = run.scenarios[scenario_id]
    condition = scenario.discriminating_condition
    check = check_of(run, scenario_id)
    status, detail = tool_of(run, scenario_id)
    statement = (
        condition.statement
        if condition
        else omitted_reason(run, scenario_id) or "None."
    )
    tone = (
        "pass"
        if check == "satisfied"
        else "info"
        if check == "not_checkable"
        else "skip"
    )
    return Markup(
        f"{truncate(statement, CONDITION_LIMIT)} {badge(tone, CHECK_LABEL.get(check, check))} "
        f"{badge(TOOL_TONE.get(status, 'warn'), f'tool call {status}')}"
        f'<div class="nm">{esc(detail)}</div>'
    )


def _testability(run: RunData, scenario_id: str) -> Markup:
    row = None if run.testability is None else run.testability.get(scenario_id)
    if row is None:
        return badge("unknown", "testability unknown")
    if row.status == "canonical":
        return badge("pass", "sent to authoring")
    if row.status == "duplicate":
        return badge("skip", f"duplicate of {row.duplicate_of}")
    return badge("skip", "analytical only")


def _requests(run: RunData, scenario_id: str) -> Markup:
    calls = [c for c in run.calls if c.scenario_id == scenario_id]
    if not calls:
        return Markup('<span class="nm">none recorded per scenario</span>')
    lines = []
    for call in calls:
        result = (
            badge("pass", "ok")
            if call.success
            else badge("fail", call.failure_class or "failed")
        )
        error = "" if call.success else f" {call.error or ''}"
        lines.append(
            Markup(
                f'<div class="nm">#{call.n} {esc(step_label(call))} attempt {call.attempt_number} '
                f"{result}{truncate(error, 160) if error else ''}</div>"
            )
        )
    return join(lines)


def lineage_steps(run: RunData, scenario_id: str) -> list[tuple[str, Markup]]:
    """Return ``(level, content)`` pairs from policy risk down to the scenario's requests."""
    scenario = run.scenarios[scenario_id]
    lineage = scenario.lineage
    slots = {s.slot_id: s for s in slot_views(run)}
    slot = slots.get(lineage.ica_slot_id)
    finding = (
        next((f for f in slot.findings if f.ica_id == lineage.ica_id), None)
        if slot
        else None
    )
    return [
        (
            "Policy risks",
            Markup(esc(", ".join(policy_risk_names(run, lineage.loss_ids))) or "none"),
        ),
        (
            "Loss",
            join(
                _div(code_id(x.loss_id), f" {x.description}")
                for x in _losses(run, lineage.loss_ids)
            ),
        ),
        (
            "Hazard",
            join(
                _div(code_id(x.hazard_id), f" {x.description}")
                for x in _hazards(run, lineage.hazard_ids)
            ),
        ),
        (
            "Constraint",
            join(
                _div(code_id(r.constraint_id), f" {r.statement}")
                for r in scenario.governing_rules
            ),
        ),
        ("Slot", _slot(slot, run)),
        ("Finding", _finding(finding, lineage.ica_id or "")),
        ("Kind", _kind(run, scenario_id)),
        ("Condition", _condition(run, scenario_id)),
        ("Testability", _testability(run, scenario_id)),
        ("Requests", _requests(run, scenario_id)),
    ]
