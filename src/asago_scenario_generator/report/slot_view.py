"""One decision per slot, and the findings behind it.

A slot pairs one control action (or coordination message) with one of four
ways it can go wrong. The model decides whether the slot applies. If it does,
the model writes findings (ICAs), and an independent request verifies each.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from asago_scenario_generator.report.run_data import RunData

ICA_STAGE = "synthesis_obligation_aware_icas"


@dataclass(frozen=True)
class Finding:
    """One verified-or-rejected unsafe case in a slot."""

    ica_id: str
    text: str
    disposition: str
    verdict: str | None
    rationale: str
    corrected: bool
    scenarios: list[str] = field(default_factory=list)
    context: str = ""


@dataclass(frozen=True)
class SlotView:
    """The model's decision for one slot.

    ``decision`` is ``na`` (judged not applicable), ``findings``,
    ``unresolved`` (every finding failed verification), or ``none`` (the run
    holds no decision).
    """

    slot_id: str
    owner: str
    action_id: str
    uca: str
    decision: str
    rationale: str
    findings: list[Finding]


def _call_answers(run: RunData) -> dict[str, tuple[bool, str]]:
    """Map slot id to ``(is_na, reason)`` from the successful slot-analysis calls."""
    answers: dict[str, tuple[bool, str]] = {}
    for call in run.calls:
        if call.stage == ICA_STAGE and call.success and call.response_content:
            for item in json.loads(call.response_content).get("filled_slots", []):
                answers[item["slot_id"]] = (
                    bool(item.get("is_na")),
                    item.get("na_rationale") or "",
                )
    return answers


def _enumerated(run: RunData) -> dict[str, tuple[bool, str, str | None]]:
    """Map slot id to ``(is_na, justification, unresolved_reason)`` when a target ran."""
    view = None if run.realization is None else run.realization.effective_view
    if view is None:
        return {}
    return {
        slot.slot_id: (slot.is_na, slot.na_justification or "", slot.unresolved_reason)
        for slot in view.effective_ica_enumeration.slots
    }


def _scenarios_by_ica(run: RunData) -> dict[str, list[str]]:
    scenarios: dict[str, list[str]] = {}
    for outcome in run.manifest.candidate_outcomes:
        if outcome.ica_id and outcome.scenario_id in run.scenarios:
            scenarios.setdefault(outcome.ica_id, []).append(outcome.scenario_id)
    return scenarios


def _finding(record, scenarios: list[str]) -> Finding:
    verdict = record.final_verdict or {}
    request = record.corrected_request or record.request or {}
    return Finding(
        ica_id=record.ica_id,
        text=request.get("deviation") or "",
        disposition=record.disposition,
        verdict=verdict.get("verdict"),
        rationale=verdict.get("rationale") or "",
        corrected=bool(record.correction),
        scenarios=sorted(scenarios),
        context=request.get("hazardous_context") or "",
    )


def _findings(run: RunData) -> dict[str, list[Finding]]:
    scenarios = _scenarios_by_ica(run)
    found: dict[str, list[Finding]] = {}
    for record in run.manifest.verifications:
        found.setdefault(record.slot_id, []).append(
            _finding(record, scenarios.get(record.ica_id, []))
        )
    for items in found.values():
        items.sort(key=lambda f: int(f.ica_id.rsplit(":", 1)[1]))
    return found


def _decision(
    slot_id: str,
    enumerated: dict[str, tuple[bool, str, str | None]],
    answers: dict[str, tuple[bool, str]],
    findings: list[Finding],
) -> tuple[str, str]:
    if slot_id in enumerated:
        is_na, why, unresolved = enumerated[slot_id]
        if unresolved:
            return "unresolved", unresolved
        return ("na", why) if is_na else ("findings", "")
    if slot_id in answers:
        is_na, why = answers[slot_id]
        return ("na", why) if is_na else ("findings", "")
    return ("findings", "") if findings else ("none", "")


def slot_views(run: RunData) -> list[SlotView]:
    """Return one view per slot, ordered by slot id."""
    enumerated = _enumerated(run)
    answers = _call_answers(run)
    found = _findings(run)
    ids = set(enumerated) | set(found)
    if run.offers is not None:
        ids |= {offer.slot_id for offer in run.offers.slots}
    views = []
    for slot_id in sorted(ids):
        owner, action_id, uca = slot_id.split(":")
        findings = found.get(slot_id, [])
        decision, rationale = _decision(slot_id, enumerated, answers, findings)
        views.append(
            SlotView(slot_id, owner, action_id, uca, decision, rationale, findings)
        )
    return views
