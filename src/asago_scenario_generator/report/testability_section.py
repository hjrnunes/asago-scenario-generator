"""Which scenarios go to authoring: duplicates, analytical-only ones, and conditions."""

from __future__ import annotations

from collections import Counter, defaultdict

from asago_scenario_generator.report.common import (
    code_id,
    counted,
    missing,
    scenario_link,
)
from asago_scenario_generator.report.run_data import RunData
from asago_scenario_generator.report_kit import (
    Column,
    Markup,
    Row,
    Segment,
    badge,
    callout,
    disclosure,
    join,
    section,
    stacked_bar,
    table,
)

QUESTION = (
    "Duplicates and scenarios without a testable condition stay behind; "
    "the rest go to authoring."
)
CHECK_LABEL = {
    "satisfied": "holds in the seeded state",
    "not_checkable": "decided at run time",
    "none": "no condition",
}


def _value(item: object) -> str:
    return str(getattr(item, "value", item))


def check_of(run: RunData, scenario_id: str) -> str:
    check = run.scenarios[scenario_id].condition_check
    return "none" if check is None else _value(check.status)


def tool_of(run: RunData, scenario_id: str) -> tuple[str, str]:
    status = run.scenarios[scenario_id].tool_call_condition_status
    return _value(status.status), status.detail or status.reason or ""


def _rules(run: RunData, scenario_id: str) -> list[str]:
    scenario = run.scenarios.get(scenario_id)
    if scenario is None:
        return []
    return sorted({r.constraint_id for r in scenario.governing_rules})


def omitted_reason(run: RunData, scenario_id: str) -> str:
    return (
        run.scenarios[scenario_id].condition_omitted_reason
        or tool_of(run, scenario_id)[1]
    )


def _with_status(run: RunData, status: str) -> list:
    rows = [r for r in run.testability.values() if r.status == status]
    return sorted(rows, key=lambda r: r.scenario_id)


def _differing(run: RunData) -> list[tuple[str, str]]:
    pairs = [(r.scenario_id, r.duplicate_of) for r in _with_status(run, "duplicate")]
    return [(d, k) for d, k in pairs if _rules(run, d) != _rules(run, k)]


def _lead(run: RunData) -> Markup:
    count = Counter(r.status for r in run.testability.values())
    return Markup(
        f"<p>{counted('testability.sent', count['canonical'])} of "
        f"{counted('testability.total', len(run.testability))} scenarios go to authoring. "
        f"{counted('testability.duplicate', count['duplicate'])} duplicate another "
        "scenario's slot, claim, and condition; "
        f"{counted('testability.analytical', count['analytical_only'])} have no "
        "discriminating condition, so no run could tell a pass from a fail.</p>"
    )


def _bar(run: RunData) -> Markup:
    count = Counter(r.status for r in run.testability.values())
    segments = [
        Segment("sent", "sent to authoring", count["canonical"], "pass"),
        Segment("duplicate", "duplicate", count["duplicate"], "skip"),
        Segment(
            "analytical", "analytical only", count["analytical_only"], "neutral-soft"
        ),
    ]
    return stacked_bar(
        segments, key="testability.bar", label="Scenarios by testability"
    )


def _differ_note(run: RunData) -> Markup:
    differ = _differing(run)
    if not differ:
        return Markup("")
    body = Markup(
        f"<p>{counted('testability.rule_differs', len(differ))} of "
        f"{len(_with_status(run, 'duplicate'))} duplicates govern a different constraint "
        "from the scenario kept, so authoring never receives the rule they test.</p>"
    )
    return callout("warning", "Duplicate of a scenario with another rule", body)


def _duplicate_table(run: RunData) -> Markup:
    rows = []
    for row in _with_status(run, "duplicate"):
        mine, kept = _rules(run, row.scenario_id), _rules(run, row.duplicate_of)
        note = (
            "" if mine == kept else f"governs {', '.join(mine)}; kept {', '.join(kept)}"
        )
        rows.append(
            Row(
                [
                    scenario_link(run, row.scenario_id),
                    scenario_link(run, row.duplicate_of),
                    f"{row.key.uca_id} · claim {row.key.claim_level}",
                    badge("warn", note) if note else "same rule",
                ],
                id=f"dup-{row.scenario_id}",
            )
        )
    columns = [Column("Dropped"), Column("Kept"), Column("Shared key"), Column("Rule")]
    return table(columns, rows, "testability-duplicates")


def _analytical_table(run: RunData) -> Markup:
    rows = [
        Row(
            [scenario_link(run, r.scenario_id), omitted_reason(run, r.scenario_id)],
            id=f"analytical-{r.scenario_id}",
        )
        for r in _with_status(run, "analytical_only")
    ]
    columns = [Column("Scenario"), Column("Why", sortable=False)]
    return table(columns, rows, "testability-analytical")


def _rule_text(run: RunData, constraint_id: str) -> str:
    for constraint in run.loss.security_constraints if run.loss else ():
        if constraint.constraint_id == constraint_id:
            return constraint.rule
    return ""


def _rule_rows(run: RunData) -> list[Row]:
    by_rule: dict[str, Counter] = defaultdict(Counter)
    for row in run.testability.values():
        for rule in _rules(run, row.scenario_id):
            by_rule[rule][row.status] += 1
    rows = []
    for rule, count in sorted(by_rule.items()):
        flag = (
            badge("warn", "one scenario left")
            if count["canonical"] == 1
            and (count["duplicate"] or count["analytical_only"])
            else ""
        )
        rows.append(
            Row(
                [
                    code_id(rule),
                    _rule_text(run, rule),
                    count["canonical"],
                    count["duplicate"],
                    count["analytical_only"],
                    flag,
                ],
                id=f"rule-{rule}",
            )
        )
    return rows


def _rules_table(run: RunData) -> Markup:
    columns = [
        Column("Constraint"),
        Column("Rule", sortable=False),
        Column("Sent", numeric=True),
        Column("Duplicate", numeric=True),
        Column("Analytical", numeric=True),
        Column("Note", sortable=False),
    ]
    return table(columns, _rule_rows(run), "testability-rules")


def _grid(run: RunData) -> Markup:
    cells = Counter(
        (check_of(run, s), tool_of(run, s)[0])
        for s in run.testability
        if s in run.scenarios
    )
    tools = sorted({t for _, t in cells})
    checks = sorted({c for c, _ in cells})
    rows = [
        Row(
            [
                CHECK_LABEL.get(c, c),
                *(
                    counted(f"conditions.{c}.{t}", cells[(c, t)])
                    if cells[(c, t)]
                    else ""
                    for t in tools
                ),
            ]
        )
        for c in checks
    ]
    columns = [Column("Check before the run", sortable=False)] + [
        Column(f"tool-call condition: {t}", sortable=False) for t in tools
    ]
    return table(columns, rows, "testability-conditions")


def _weak(run: RunData, scenario_id: str) -> tuple[str, str] | None:
    if check_of(run, scenario_id) == "none":
        return "No discriminating condition", omitted_reason(run, scenario_id)
    status, detail = tool_of(run, scenario_id)
    if status != "bound":
        return f"Tool-call condition is {status}", detail
    return None


def _weak_table(run: RunData) -> Markup:
    rows = []
    for row in _with_status(run, "canonical"):
        weak = row.scenario_id in run.scenarios and _weak(run, row.scenario_id)
        if weak:
            rows.append(
                Row(
                    [
                        scenario_link(run, row.scenario_id),
                        badge("warn", weak[0]),
                        weak[1],
                    ],
                    id=f"weak-{row.scenario_id}",
                )
            )
    columns = [Column("Scenario"), Column("Signal"), Column("Detail", sortable=False)]
    return table(columns, rows, "testability-weak")


def _body(run: RunData) -> Markup:
    return join(
        [
            _lead(run),
            _bar(run),
            _differ_note(run),
            disclosure(
                "Duplicates and the scenario kept",
                _duplicate_table(run),
                "testability-dups",
            ),
            disclosure(
                "Analytical-only scenarios",
                _analytical_table(run),
                "testability-analytical-list",
            ),
            Markup("<h3>Rules reaching authoring</h3>"),
            _rules_table(run),
            Markup(
                "<h3>Conditions</h3><p>The discriminating condition says what separates an "
                "unsafe run from a safe one. The producer checks it against the seeded target "
                "state where it can; the tool-call condition binds it to an observable tool "
                "call.</p>"
            ),
            _grid(run),
            Markup("<h3>Sent to authoring with a weak condition</h3>"),
            _weak_table(run),
        ]
    )


def testability_section(run: RunData) -> Markup:
    """Render the section on duplicates, analytical-only scenarios, and conditions."""
    body = missing("testability.yaml") if run.testability is None else _body(run)
    return section("testability", "Which scenarios go to authoring?", QUESTION, body)
