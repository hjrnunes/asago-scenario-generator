"""Where the policy risks went: boundary decision, loss analysis, scenarios, testability."""

from __future__ import annotations

from collections import Counter
from typing import Any

from asago_scenario_generator.report.common import (
    ATTACK,
    code_ids,
    missing,
    plural,
    sendable,
)
from asago_scenario_generator.report.run_data import RunData
from asago_scenario_generator.report_kit import (
    Column,
    Drop,
    FunnelStep,
    Markup,
    Row,
    callout,
    disclosure,
    esc,
    funnel,
    join,
    section,
    table,
)

STEPS = (
    ("boundary", "boundary_decision", "Boundary decision"),
    ("loss", "loss_analysis", "Loss analysis"),
    ("scenarios", "scenario_writing", "Scenario writing"),
)
STEP_NAME = {
    "boundary_decision": "the boundary decision",
    "loss_analysis": "loss analysis",
}
DROP_LABEL = {
    "outside_boundary": ("outside what the assistant controls", "neutral-soft"),
    "not_applicable": ("judged not applicable", "warn"),
    "not_reached": ("a loss cites it, but no scenario was written", "warn"),
}
QUESTION = (
    "Each row takes in what the row above passed on, so the numbers foot; "
    "every drop states why."
)


def _name(risk: dict[str, Any]) -> str:
    return risk.get("display_name") or risk["name"]


def risk_scenarios(policy: dict[str, Any], risk: dict[str, Any]) -> list[str]:
    """List the scenarios written for the losses that cite *risk*."""
    losses = set(risk["loss_ids"])
    found = {
        s for h in policy["harms"] if h["loss_id"] in losses for s in h["scenario_ids"]
    }
    return sorted(found)


def _drop_label(step: str, coverage: str) -> str:
    label = DROP_LABEL[coverage][0]
    return f"{STEP_NAME[step]} {label}" if coverage == "not_applicable" else label


def _step_drops(risks: list[dict[str, Any]], step: str) -> list[Drop]:
    counts = Counter(r["coverage"] for r in risks if r["reason"]["step"] == step)
    return [
        Drop(
            coverage.replace("_", "-"),
            DROP_LABEL[coverage][0],
            count,
            "#risks-outside" if coverage == "outside_boundary" else None,
            DROP_LABEL[coverage][1],
        )
        for coverage, count in sorted(counts.items())
    ]


def _policy_steps(policy: dict[str, Any]) -> list[FunnelStep]:
    risks = [r for r in policy["risks"] if r["coverage"] != "scenarios"]
    remaining = len(policy["risks"])
    steps = []
    for key, step, label in STEPS:
        drops = _step_drops(risks, step)
        left = remaining - sum(d.count for d in drops)
        steps.append(FunnelStep(key, label, remaining, left, drops))
        remaining = left
    return steps


def _testability_step(reached: int, held_back: int) -> FunnelStep:
    drop = Drop(
        "unsendable",
        "every scenario is a duplicate or analytical only",
        held_back,
        None,
        "warn",
    )
    return FunnelStep(
        "testability", "Testability", reached, reached - held_back, [drop]
    )


def _held_back(run: RunData) -> int:
    policy = run.policy or {}
    risks = [r for r in policy.get("risks", []) if r["coverage"] == "scenarios"]
    return sum(
        not any(sendable(run, s) for s in risk_scenarios(policy, r)) for r in risks
    )


def _funnel(run: RunData) -> Markup:
    steps = _policy_steps(run.policy)
    if run.testability is not None:
        steps.append(_testability_step(steps[-1].output, _held_back(run)))
    return funnel(steps, key="policy", label="Where the policy risks went")


def _kept_then_dropped(policy: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        r
        for r in policy["risks"]
        if r["coverage"] == "not_applicable" and r["reason"]["step"] == "loss_analysis"
    ]


def _review_sentence(run: RunData) -> str:
    review = run.coverage_review
    if review is None:
        return "No risk coverage review is in this run, so nothing checked the drop."
    if review.status == "completed":
        return "The risk coverage review completed."
    why = f": {review.failure_reason}" if review.failure_reason else ""
    return (
        f"The risk coverage review ended {review.status}{why}. "
        "It is the check that compares in-scope risks with the losses."
    )


def _contradiction(run: RunData) -> Markup:
    dropped = _kept_then_dropped(run.policy)
    if not dropped:
        return Markup("")
    items = join(
        (
            Markup(f"<li><b>{esc(_name(r))}</b>: {esc(r['reason']['text'])}</li>")
            for r in dropped
        )
    )
    body = Markup(
        f"<p>The boundary decision kept {plural(len(dropped), 'risk')} in scope and "
        f"loss analysis dropped {'it' if len(dropped) == 1 else 'them'}.</p>"
        f"<ul>{items}</ul><p>{esc(_review_sentence(run))}</p>"
    )
    return callout(
        "warning", "Kept by the boundary decision, dropped by loss analysis", body
    )


def _cited_rows(run: RunData) -> list[Row]:
    rows = []
    for risk in sorted(run.policy["risks"], key=lambda r: _name(r).lower()):
        if risk["coverage"] != "scenarios":
            continue
        found = risk_scenarios(run.policy, risk)
        attack = [s for s in found if run.scenarios[s].kind == ATTACK]
        sent = [s for s in found if sendable(run, s)]
        rows.append(
            Row(
                [
                    Markup(f"{esc(_name(risk))} {code_ids([risk['risk_id']])}"),
                    code_ids(risk["loss_ids"]),
                    len(found),
                    len(attack),
                    len(sent),
                ]
            )
        )
    return rows


def _cited_table(run: RunData) -> Markup:
    columns = [
        Column("Risk"),
        Column("Losses", sortable=False),
        Column("Scenarios", numeric=True),
        Column("Attack", numeric=True),
        Column("Sent to authoring", numeric=True),
    ]
    return table(columns, _cited_rows(run), "risks-cited-table")


def _dropped_table(policy: dict[str, Any], coverage: str, ident: str) -> Markup:
    rows = [
        Row([_name(r), r["reason"]["text"]])
        for r in sorted(policy["risks"], key=lambda r: _name(r).lower())
        if r["coverage"] == coverage
    ]
    return table([Column("Risk"), Column("Reason", sortable=False)], rows, ident)


def _body(run: RunData) -> Markup:
    policy = run.policy
    outside = sum(r["coverage"] == "outside_boundary" for r in policy["risks"])
    cited = sum(r["coverage"] == "scenarios" for r in policy["risks"])
    return join(
        [
            _funnel(run),
            _contradiction(run),
            disclosure(
                f"In-scope risks that reached a scenario ({cited})",
                _cited_table(run),
                "risks-cited",
            ),
            disclosure(
                f"Outside what the assistant controls ({outside})",
                _dropped_table(policy, "outside_boundary", "risks-outside-table"),
                "risks-outside",
            ),
        ]
    )


def policy_section(run: RunData) -> Markup:
    """Render the section that follows each policy risk to where it stopped."""
    body = missing(run, "policy-coverage.json") if run.policy is None else _body(run)
    return section("risks", "Where did the policy risks go?", QUESTION, body)
