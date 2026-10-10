"""Group failed model requests into chains and say what each chain cost.

A chain is a failed request plus its retries. ``calls.jsonl`` links a retry to
the attempt it repeats with ``retry_of``; an older log has no link, so the
chain is inferred: within one (stage, step, scenario) group, a request with
``attempt_number`` above 1 continues the open chain.

Each chain gets one outcome:

* ``recovered``: a later attempt succeeded;
* ``repaired``: a ``<step>_repair`` request succeeded;
* ``degraded``: the output exists without what the request should have added;
* ``lost``: nothing replaced the request.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from asago_scenario_generator.report.run_data import CallRecord, RunData
from asago_scenario_generator.report.slot_view import ICA_STAGE, SlotView

OUTCOME_ORDER = {"lost": 0, "degraded": 1, "repaired": 2, "recovered": 3}
REVIEW_STEP = "risk_coverage_review"


@dataclass(frozen=True)
class Failure:
    """One chain of attempts that started with a failed request."""

    calls: tuple[CallRecord, ...]
    outcome: str
    effect: str
    short: str
    code: str
    message: str

    @property
    def first(self) -> CallRecord:
        return self.calls[0]

    @property
    def stage(self) -> str:
        return self.first.stage

    @property
    def step(self) -> str:
        return self.first.step

    @property
    def scenario(self) -> str | None:
        return self.first.scenario_id

    @property
    def failed_numbers(self) -> list[int]:
        return [c.n for c in self.calls if not c.success]


def error_parts(call: CallRecord) -> tuple[str, str]:
    """Split a producer error string into a code and a one-line message."""
    text = call.error or ""
    if match := re.search(r"Value error, (.+?)(?: \[type=|$)", text, re.S):
        code, message = "", match.group(1).strip()
    elif match := re.match(r"\w+Error: ([a-z_]+): (.+)", text, re.S):
        code, message = match.group(1), match.group(2).split("\n")[0].strip()
    else:
        first = text.split("\n")[0]
        code, message = "", first.split(": ", 1)[-1] if ": " in first else first
    if not code and call.terminal_error_codes:
        code = call.terminal_error_codes[0]
    return code, message


def _chains(calls: Iterable[CallRecord]) -> list[list[CallRecord]]:
    """Group the requests into attempt chains that contain a failure."""
    chains: list[list[CallRecord]] = []
    by_attempt: dict[str, list[CallRecord]] = {}
    open_by_group: dict[tuple, list[CallRecord]] = {}
    for call in calls:
        group = (call.stage, call.step, call.scenario_id)
        chain = by_attempt.get(call.retry_of) if call.retry_of else None
        if chain is None and call.retry_of is None and call.attempt_number > 1:
            chain = open_by_group.get(group)
        if chain is None:
            chain = [call]
            if not call.success:
                chains.append(chain)
        else:
            chain.append(call)
        if call.attempt_id:
            by_attempt[call.attempt_id] = chain
        if call.success:
            open_by_group.pop(group, None)
        else:
            open_by_group[group] = chain
    return chains


def _lost_slot_effect(
    chain: list[CallRecord], slots: list[SlotView]
) -> tuple[str, str, str]:
    open_slots = [
        s.slot_id for s in slots if s.owner == chain[0].step and s.decision == "none"
    ]
    if not open_slots:
        return (
            "recovered",
            f"Every slot of {chain[0].step} has a decision from another request.",
            "",
        )
    names = ", ".join(open_slots)
    return (
        "lost",
        f"Slot {names} has no decision, so it yields no finding and no scenario.",
        f"the decision for slot {names}",
    )


def _scenario_effect(run: RunData, scenario: str) -> tuple[str, str, str]:
    status = None if run.testability is None else run.testability.get(scenario)
    if run.testability is not None and status is None:
        return ("lost", f"{scenario} was not written.", f"{scenario}")
    if status is not None and status.status == "analytical_only":
        return (
            "lost",
            f"{scenario} has no discriminating condition and became analytical only, "
            "so it is not sent to authoring.",
            f"a testable {scenario}",
        )
    return (
        "degraded",
        f"{scenario} was published without a discriminating condition; it still goes to authoring.",
        f"the condition of {scenario}",
    )


def _classify(
    run: RunData,
    chain: list[CallRecord],
    slots: list[SlotView],
    repaired: set[tuple[str, str]],
) -> tuple[str, str, str]:
    first, last = chain[0], chain[-1]
    if last.success:
        return "recovered", "The retry succeeded.", ""
    if (first.stage, f"{first.step}_repair") in repaired:
        return (
            "repaired",
            "A targeted repair request fixed the draft; the malformed entry was dropped and repaired.",
            "",
        )
    if first.step == REVIEW_STEP:
        planned = (
            sum(run.coverage_review.batching.planned_batch_sizes)
            if run.coverage_review
            else 0
        )
        return (
            "lost",
            f"The risk coverage review did not run, so none of the {planned} in-scope risks "
            "was checked against the loss analysis.",
            "the risk coverage review",
        )
    if first.stage == ICA_STAGE:
        return _lost_slot_effect(chain, slots)
    if first.scenario_id:
        return _scenario_effect(run, first.scenario_id)
    return "lost", "No later request replaced this one.", ""


def failure_chains(run: RunData, slots: list[SlotView]) -> list[Failure]:
    """Return every failure chain, lost first and then in request order."""
    repaired = {(c.stage, c.step) for c in run.calls if c.success}
    failures = []
    for chain in _chains(run.calls):
        outcome, effect, short = _classify(run, chain, slots, repaired)
        code, message = error_parts(next(c for c in chain if not c.success))
        failures.append(Failure(tuple(chain), outcome, effect, short, code, message))
    return sorted(failures, key=lambda f: (OUTCOME_ORDER[f.outcome], f.first.n))
