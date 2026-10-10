"""Scenarios: a filterable list, and for each scenario its text and lineage."""

from __future__ import annotations

from asago_scenario_generator.report.common import (
    code_id,
    kind_chip,
    kind_word,
    missing,
)
from asago_scenario_generator.report.run_data import RunData
from asago_scenario_generator.report.scenario_lineage import lineage_steps
from asago_scenario_generator.report.scenario_panels import (
    Panel,
    panel_stats,
    scenario_panels,
)
from asago_scenario_generator.report.slot_section import UCA_LABEL
from asago_scenario_generator.report.testability_section import CHECK_LABEL, check_of
from asago_scenario_generator.report_kit import (
    Column,
    Filter,
    Markup,
    Row,
    artifact,
    badge,
    chain,
    disclosure,
    esc,
    expand_controls,
    join,
    section,
    table,
    truncate,
)

QUESTION = (
    "What did the producer write for each scenario, and where did it come from? "
    "Open a scenario for its narrative, attack tree, Gherkin, and lineage."
)
TEST_KEY = {
    "canonical": "sent",
    "duplicate": "duplicate",
    "analytical_only": "analytical",
}
RULE_LIMIT = 160


def _test_key(run: RunData, scenario_id: str) -> str:
    row = None if run.testability is None else run.testability.get(scenario_id)
    return TEST_KEY.get(row.status, "unknown") if row else "unknown"


def _test_badge(key: str, run: RunData, scenario_id: str) -> Markup:
    if key == "duplicate":
        return badge(
            "skip", f"duplicate of {run.testability[scenario_id].duplicate_of}"
        )
    return {
        "sent": badge("pass", "sent to authoring"),
        "analytical": badge("skip", "analytical only"),
    }.get(key, badge("unknown", "testability unknown"))


def _slot_cell(run: RunData, scenario_id: str) -> Markup:
    lineage = run.scenarios[scenario_id].lineage
    uca = lineage.ica_slot_id.rsplit(":", 1)[-1]
    way = UCA_LABEL.get(uca, uca).lower()
    return Markup(f"{code_id(lineage.control_action_id)} {esc(way)}")


def _rule_cell(run: RunData, scenario_id: str) -> Markup:
    rules = run.scenarios[scenario_id].governing_rules
    if not rules:
        return Markup("")
    ids = " ".join(r.constraint_id for r in rules)
    return Markup(f"{esc(ids)}: {truncate(rules[0].statement, RULE_LIMIT)}")


def _requests(run: RunData, scenario_id: str) -> int:
    return sum(c.scenario_id == scenario_id for c in run.calls)


def _row(run: RunData, scenario_id: str) -> Row:
    scenario = run.scenarios[scenario_id]
    key, check = _test_key(run, scenario_id), check_of(run, scenario_id)
    return Row(
        [
            Markup(f'<a href="#{scenario_id}">{esc(scenario_id)}</a>'),
            kind_chip(scenario.kind),
            _slot_cell(run, scenario_id),
            _rule_cell(run, scenario_id),
            _test_badge(key, run, scenario_id),
            badge(
                "pass" if check == "satisfied" else "skip",
                CHECK_LABEL.get(check, check),
            ),
            _requests(run, scenario_id),
        ],
        id=f"row-{scenario_id}",
        facets={"kind": kind_word(scenario.kind), "test": key, "cond": check},
    )


def _filters() -> list[Filter]:
    return [
        Filter("kind", "Kind", [("attack", "attack"), ("everyday", "everyday")]),
        Filter("test", "Testability", [(k, k) for k in TEST_KEY.values()]),
        Filter("cond", "Condition", [(k, v) for k, v in CHECK_LABEL.items()]),
    ]


def _list(run: RunData) -> Markup:
    columns = [
        Column("Scenario"),
        Column("Kind"),
        Column("Action"),
        Column("Rule tested", sortable=False),
        Column("Testability"),
        Column("Condition"),
        Column("Requests", numeric=True),
    ]
    rows = [_row(run, s) for s in sorted(run.scenarios)]
    return table(columns, rows, "scenarios-table", filters=_filters(), search=True)


def _panel(scenario_id: str, panel: Panel) -> Markup:
    summary = Markup(
        f'<b>{esc(panel.title)}</b> <span class="nm">{esc(panel.preview)}</span>'
        + (f" {badge('warn', 'differs from YAML')}" if panel.differs else "")
    )
    return disclosure(summary, panel.body, f"{scenario_id}-{panel.key}", mini=False)


def _links(run: RunData, scenario_id: str) -> Markup:
    base = run.output_dir / "report"
    return Markup(
        f"<p>{artifact(f'../scenarios/{scenario_id}.yaml', base, 'handoff YAML')} "
        f"{artifact(f'../scenarios/{scenario_id}.feature', base, 'feature file')}</p>"
    )


def _detail(run: RunData, scenario_id: str) -> Markup:
    panels = join(_panel(scenario_id, p) for p in scenario_panels(run, scenario_id))
    body = join(
        [
            Markup("<h4>As written</h4>"),
            panels,
            Markup("<h4>Lineage</h4>"),
            chain(lineage_steps(run, scenario_id)),
            _links(run, scenario_id),
        ]
    )
    scenario = run.scenarios[scenario_id]
    summary = Markup(
        f"<b>{esc(scenario_id)}</b> {kind_chip(scenario.kind)} "
        f'<span class="nm">{esc(scenario.lineage.ica_slot_id)}</span>'
    )
    return disclosure(summary, body, scenario_id, level="scenario")


def _intro(run: RunData) -> Markup:
    stats = panel_stats(run)
    all_flat = f"{stats.flat} of {stats.trees}"
    return Markup(
        "<p>Each scenario holds the three artifacts the producer wrote, as authoring reads "
        f"them. {all_flat} attack trees are flat, with no AND or OR between nodes; "
        f"{stats.single_leaf} have exactly one leaf. {stats.matching} of {stats.features} "
        "feature files match the gherkin block of their handoff YAML.</p>"
    )


def scenario_section(run: RunData) -> Markup:
    """Render the scenario list and one expandable detail per scenario."""
    if not run.scenarios:
        body = missing(run, "scenarios/")
    else:
        details = join(_detail(run, s) for s in sorted(run.scenarios))
        body = join(
            [
                _intro(run),
                _list(run),
                expand_controls("scenario-details", "scenario"),
                Markup(f'<div id="scenario-details">{details}</div>'),
            ]
        )
    return section("scenarios", "Scenarios", QUESTION, body)
