"""Did the attack patterns become scenarios? One row per obligation stop reason."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from functools import cache

from asago_scenario_generator.data.loaders import load_attack_patterns
from asago_scenario_generator.report.common import (
    code_id,
    missing,
    plural,
    scenario_links,
)
from asago_scenario_generator.report.run_data import RunData
from asago_scenario_generator.report_kit import (
    Column,
    Markup,
    Row,
    badge,
    callout,
    disclosure,
    esc,
    join,
    section,
    table,
)

STOP_MEANING = {
    "scenario_realized": (
        "Realized by a scenario",
        "A slot finding realizes the attack pattern and a scenario carries it.",
    ),
    "addressed": (
        "Realized by a scenario",
        "A slot finding realizes the attack pattern and a scenario carries it.",
    ),
    "scenario_functional_test": (
        "Became an everyday check",
        "The slot's scenario was written as an everyday check, not as an attack.",
    ),
    "scenario_generation_failure": (
        "Scenario writing failed",
        "A finding realizes the attack pattern, but the scenario-writing requests failed.",
    ),
    "scenario_not_requested": (
        "No scenario requested",
        "The run did not ask for a scenario for this obligation.",
    ),
    "risk_pattern_mismatch": (
        "Route found, wrong mechanism",
        "The routed slot supports an ordinary STPA finding but does not realize this attack pattern.",
    ),
    "no_structural_route": (
        "No route in the control structure",
        "The control structure lacks the path the attack pattern needs, such as a tool chain or a reachable control interface.",
    ),
    "ica_consideration_unresolved": (
        "Slot left unresolved",
        "A route exists, but at least one routed slot stayed analytically unresolved.",
    ),
    "mechanism_path_unsubstantiated": (
        "Path does not prove the mechanism",
        "The finding is kept, but the selected path does not establish the attack mechanism.",
    ),
    "not_applicable_proven": (
        "Proven not applicable",
        "The producer showed the attack pattern cannot apply to the routed slot.",
    ),
    "not_applicable_evidence_incomplete": (
        "Not applicable, evidence incomplete",
        "The producer judged the pattern not applicable but did not gather enough evidence to prove it.",
    ),
    "ica_hazard_contradictory": (
        "Verifier contradicted the finding",
        "The independent verification returned contradictory verdicts for the routed finding.",
    ),
    "ica_hazard_insufficient_evidence": (
        "Too little evidence",
        "The verifier found too little evidence to support the routed finding.",
    ),
    "ica_hazard_absence_evidence_missing": (
        "Absence claim lacks evidence",
        "The finding claims something is absent without evidence for the absence.",
    ),
    "ica_hazard_verification_provider_failure": (
        "Verification request failed",
        "The request that verifies the routed finding failed.",
    ),
    "ica_hazard_correction_exhausted": (
        "Corrections ran out",
        "The verifier asked for corrections and the allowed corrections did not satisfy it.",
    ),
    "unsafe_outcome_lineage_incomplete": (
        "Unsafe outcome not traced",
        "The finding's unsafe outcome does not trace back to a hazard.",
    ),
    "provider_contract_failure": (
        "Model reply unusable",
        "The model's reply did not meet the request's format.",
    ),
    "prompt_budget_exceeded": (
        "Request too large",
        "The request would exceed the model's prompt budget.",
    ),
    "governance_routed_no_finding": (
        "Routed, no finding",
        "The risk was routed to a slot, and the slot produced no finding.",
    ),
    "governance_only": (
        "No attack pattern",
        "The risk maps to no attack pattern in the catalog, so it has nothing to route.",
    ),
}
ORDER = list(STOP_MEANING)
REALIZED = {"scenario_realized", "addressed"}
QUESTION = (
    "Each obligation pairs a policy risk with one attack pattern from the "
    "catalog. Rows group the obligations by where each one stopped."
)


@dataclass(frozen=True)
class ObligationRow:
    """One attack-pattern obligation as the report shows it."""

    stop: str
    risk_name: str
    outside: bool
    pattern_id: str | None
    pattern_name: str
    detail: str
    ica_ids: tuple[str, ...]


@cache
def pattern_names() -> dict[str, str]:
    """Map attack pattern ids to their catalog names."""
    return {pid: p.get("name", "") for pid, p in load_attack_patterns().items()}


def stop_key(stop: str) -> str:
    """Name a stop reason once: accounting says addressed, the manifest scenario_realized."""
    return "scenario_realized" if stop in REALIZED else stop


def _policy_risks(run: RunData) -> dict[str, dict]:
    index = {}
    for risk in (run.policy or {}).get("risks", []):
        for rid in [risk["risk_id"], *risk["merged_ids"]]:
            index[rid] = risk
    return index


def _detail(row) -> str:
    if row.diagnostics:
        return row.diagnostics[0].detail
    return (row.evidence[0] if row.evidence else "").removeprefix("phase1:governance:")


def obligation_rows(run: RunData) -> list[ObligationRow]:
    """Join the accounting rows with the plan, the catalog, and the policy risks."""
    plan = {o.obligation_id: o for o in run.plan or ()}
    risks = _policy_risks(run)
    rows = []
    for row in run.accounting.rows:
        obligation = plan[row.obligation_id]
        risk = risks.get(obligation.risk_ref.risk_id)
        name = (risk or {}).get("display_name") or obligation.risk_ref.risk_name
        pattern = obligation.attack_pattern_id
        rows.append(
            ObligationRow(
                stop_key(row.stop_reason or row.disposition),
                name,
                risk is not None and risk["coverage"] == "outside_boundary",
                pattern,
                pattern_names().get(pattern or "", ""),
                _detail(row),
                tuple(row.ica_ids),
            )
        )
    return rows


def _counted(key: str, count: int) -> Markup:
    return Markup(
        f'<b data-metric="obligations.{key}" data-value="{count}">{count:,}</b>'
    )


def _detail_table(members: list[ObligationRow], key: str) -> Markup:
    ordered = sorted(members, key=lambda o: (o.risk_name.lower(), o.pattern_id or ""))
    rows = [
        Row(
            [
                join(
                    [o.risk_name, " ", badge("skip", "outside boundary")]
                    if o.outside
                    else [o.risk_name]
                ),
                join([code_id(o.pattern_id), " ", o.pattern_name])
                if o.pattern_id
                else "none",
                o.detail,
            ]
        )
        for o in ordered
    ]
    columns = [
        Column("Risk"),
        Column("Attack pattern"),
        Column("Producer detail", sortable=False),
    ]
    return table(columns, rows, f"obligations-{key.replace('_', '-')}-table")


def _row_disclosure(key: str, members: list[ObligationRow]) -> Markup:
    label, meaning = STOP_MEANING[key]
    risks = len({o.risk_name for o in members})
    outside = sum(o.outside for o in members)
    tone = (
        "pass" if key in REALIZED else ("skip" if key == "governance_only" else "warn")
    )
    summary = join(
        [
            badge(tone, label),
            " ",
            _counted(key, len(members)),
            Markup(
                f' <span class="nm">{plural(risks, "risk")}, {outside} outside the boundary. '
                f"{esc(meaning)}</span>"
            ),
        ]
    )
    return disclosure(
        summary, _detail_table(members, key), f"ob-{key.replace('_', '-')}"
    )


def _realized_scenarios(run: RunData, rows: list[ObligationRow]) -> list[str]:
    icas = {i for o in rows if o.stop == "scenario_realized" for i in o.ica_ids}
    found = {
        c.scenario_id
        for c in run.manifest.candidate_outcomes
        if c.ica_id in icas and c.scenario_id in run.scenarios
    }
    return sorted(found)


def _lead(run: RunData, rows: list[ObligationRow], by_stop: dict) -> Markup:
    governance = len(by_stop.get("governance_only", []))
    realized = by_stop.get("scenario_realized", [])
    routed = len(rows) - governance
    scenarios = _realized_scenarios(run, rows)
    verb = "was" if len(realized) == 1 else "were"
    by = f", by {scenario_links(run, scenarios)}" if scenarios else ""
    return Markup(
        f"<p>{len(rows)} attack-pattern obligations from {len({o.risk_name for o in rows})} "
        f"risks: {governance} map to no attack pattern, and {routed} were routed to the "
        f"control structure. {len(realized)} {verb} realized{by}; the other "
        f"{routed - len(realized)} stopped. The other "
        f"{len(run.scenarios) - len(scenarios)} scenarios come from the loss analysis alone.</p>"
    )


def _outside_note(rows: list[ObligationRow]) -> Markup:
    routed = [o for o in rows if o.stop != "governance_only"]
    outside = [o for o in routed if o.outside]
    if not outside:
        return Markup("")
    return callout(
        "warning",
        "Boundary decision and obligation planner disagree",
        f"{len(outside)} of the {len(routed)} routed obligations belong to risks the "
        "boundary decision put outside the assistant's control.",
    )


def _disagreements(run: RunData, by_stop: dict) -> Markup:
    notes = []
    for raw, count in sorted(run.manifest.obligation_stop_reason_counts.items()):
        have = len(by_stop.get(stop_key(raw), []))
        if have != count:
            notes.append(
                f"The manifest counts {count} {raw} obligations; the accounting holds {have}."
            )
    if not notes:
        return Markup("")
    return callout(
        "warning", "Counts disagree", join(Markup(f"<p>{esc(n)}</p>") for n in notes)
    )


def _body(run: RunData) -> Markup:
    rows = obligation_rows(run)
    by_stop = defaultdict(list)
    for row in rows:
        by_stop[row.stop].append(row)
    ordered = [k for k in dict.fromkeys(stop_key(k) for k in ORDER) if k in by_stop]
    return join(
        [
            _lead(run, rows, by_stop),
            _outside_note(rows),
            _disagreements(run, by_stop),
            *(_row_disclosure(key, by_stop[key]) for key in ordered),
        ]
    )


def obligation_section(run: RunData) -> Markup:
    """Render the section that groups attack-pattern obligations by stop reason."""
    if run.accounting is None or run.plan is None:
        body = missing("obligation-accounting.yaml")
    else:
        body = _body(run)
    return section(
        "obligations", "Did the attack patterns become scenarios?", QUESTION, body
    )
