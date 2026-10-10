"""The opening of the report: the outcome in a sentence and four numbers.

``how_section`` follows it with the path a policy risk takes and the words
the rest of the report uses.
"""

from __future__ import annotations

from dataclasses import dataclass

from asago_scenario_generator.report.common import ATTACK, plural
from asago_scenario_generator.report.failures import Failure, failure_chains
from asago_scenario_generator.report.run_data import RunData
from asago_scenario_generator.report.slot_view import slot_views
from asago_scenario_generator.report_kit import (
    Markup,
    callout,
    chain,
    esc,
    glossary,
    join,
    metric,
    metrics,
    section,
    term,
)

GLOSSARY = {
    "slot": (
        "One control action paired with one of four ways it can go wrong: not "
        "provided, incorrect, wrong timing, or wrong duration."
    ),
    "finding": (
        "A case the model writes for a slot where the action is unsafe; the "
        "producer calls it an ICA. An independent request verifies it against "
        "the hazards."
    ),
    "attack pattern": (
        "An entry in the producer's catalog of ways to attack an assistant. An "
        "obligation pairs one risk with one pattern."
    ),
    "obligation": (
        "A policy risk paired with one attack pattern; the producer tries to "
        "route each one to a slot."
    ),
    "loss": "Something the assistant's owner or user must not lose, from loss analysis.",
    "hazard": "A system state that can lead to a loss.",
}
QUESTION = "How many scenarios came out, and what limited the number?"
HOW_QUESTION = "What path does a policy risk take to become a scenario?"


@dataclass(frozen=True)
class Counts:
    """The numbers the opening and the stage summary state."""

    written: int
    attack: int
    sent: int
    duplicate: int
    analytical: int
    requests: int
    failed: int
    lost: tuple[Failure, ...]
    degraded: tuple[Failure, ...]
    risks: int | None
    reached: int | None
    outside: int | None

    @property
    def everyday(self) -> int:
        return self.written - self.attack


def counts(run: RunData) -> Counts:
    """Count scenarios, policy risks, and requests once, for every place they appear."""
    chains = failure_chains(run, slot_views(run))
    status = [t.status for t in (run.testability or {}).values()]
    total, reached, outside = _policy_counts(run)
    return Counts(
        written=len(run.scenarios),
        attack=sum(s.kind == ATTACK for s in run.scenarios.values()),
        sent=status.count("canonical"),
        duplicate=status.count("duplicate"),
        analytical=status.count("analytical_only"),
        requests=len(run.calls),
        failed=sum(not c.success for c in run.calls),
        lost=tuple(f for f in chains if f.outcome == "lost"),
        degraded=tuple(f for f in chains if f.outcome == "degraded"),
        risks=total,
        reached=reached,
        outside=outside,
    )


def _policy_counts(run: RunData) -> tuple[int | None, int | None, int | None]:
    if run.policy is None:
        return None, None, None
    coverage = [r["coverage"] for r in run.policy["risks"]]
    return (
        len(coverage),
        coverage.count("scenarios"),
        coverage.count("outside_boundary"),
    )


def _cost(n: Counts) -> str:
    if not n.failed:
        return "No model request failed."
    cost = plural(len(n.lost), "failure cost", "failures cost")
    return f"{n.failed} of {n.requests} model requests failed; {cost} output."


def _ended(run: RunData) -> str:
    manifest = run.manifest
    if manifest.run_status == "completed":
        return ""
    why = f": {manifest.run_status_reason}" if manifest.run_status_reason else ""
    return f"Scenario generation ended {manifest.run_status}{why}. "


def _unreadable(run: RunData) -> Markup:
    if not run.unreadable:
        return Markup("")
    items = join(
        Markup(f"<li><code>{esc(name)}</code>: {esc(why)}</li>")
        for name, why in sorted(run.unreadable.items())
    )
    return callout(
        "warning",
        "Files that could not be read",
        Markup(
            f"<p>The sections that read these files say so; the rest of the report "
            f"stands.</p><ul>{items}</ul>"
        ),
    )


def _risk_sentence(n: Counts) -> str:
    if n.risks is None:
        return ""
    return (
        f"{n.outside} policy risks fall outside what the assistant controls; "
        f"{n.reached} in-scope risks reach a scenario. "
    )


def _tiles(n: Counts) -> Markup:
    tiles = [
        metric(
            "scenarios.written",
            "scenarios written",
            n.written,
            unit="scenarios",
            source=f"{n.attack} attack, {n.everyday} everyday",
        ),
        metric(
            "scenarios.sent",
            "sent to authoring",
            n.sent,
            of=n.written,
            unit="scenarios",
            source=f"{plural(n.duplicate, 'duplicate')}, {n.analytical} analytical only",
        ),
    ]
    if n.risks is not None:
        tiles.append(
            metric(
                "policy.reached",
                "policy risks with a scenario",
                n.reached,
                of=n.risks,
                unit="risks",
                source=f"{n.outside} outside the boundary",
            )
        )
    tiles.append(
        metric(
            "requests.failed",
            "model requests failed",
            n.failed,
            of=n.requests,
            unit="requests",
            status="warn" if n.lost else None,
            source=f"{len(n.lost)} cost output",
        )
    )
    return metrics(tiles)


def answer_section(run: RunData) -> Markup:
    """Render the outcome sentence and the headline tiles."""
    n = counts(run)
    origin = "" if n.risks is None else f" from {plural(n.risks, 'policy risk')}"
    sentence = (
        f"{plural(n.written, 'scenario')} written{origin}: "
        f"{plural(n.attack, 'attack scenario')} and {plural(n.everyday, 'everyday check')}. "
        f"{n.sent} go to authoring."
    )
    detail = f"{_ended(run)}{_risk_sentence(n)}{_cost(n)}"
    body = join(
        [
            Markup(f"<p><b>{esc(sentence)}</b></p><p>{esc(detail)}</p>"),
            _tiles(n),
            _unreadable(run),
        ]
    )
    return section("answer", "What did generation produce?", QUESTION, body)


def how_section() -> Markup:
    """Render the path from policy risk to scenario and the glossary."""
    steps = [
        ("Policy risks", Markup("The risks the use case is checked against.")),
        ("Boundary decision", Markup("Which risks the assistant can affect.")),
        (
            "Loss analysis",
            Markup(
                f"Losses, hazards, and constraints for the in-scope risks; each "
                f"{term('loss', GLOSSARY['loss'])} follows from a "
                f"{term('hazard', GLOSSARY['hazard'])}."
            ),
        ),
        ("Control structure", Markup("The actions the assistant takes.")),
        (
            "Slots",
            Markup(
                f"Each action paired with each way it goes wrong is a "
                f"{term('slot', GLOSSARY['slot'])}. The model decides whether a slot "
                "applies."
            ),
        ),
        (
            "Findings",
            Markup(
                f"For a slot that applies the model writes "
                f"{term('finding', GLOSSARY['finding'])}s, and an independent request "
                "verifies each one against the hazards."
            ),
        ),
        ("Scenarios", Markup("Each supported finding becomes one or more scenarios.")),
        (
            "Testability",
            Markup(
                "Duplicates and scenarios without a testable condition stay behind."
            ),
        ),
    ]
    aside = Markup(
        "<p>Separately, the producer pairs each risk with "
        f"{term('attack pattern', GLOSSARY['attack pattern'])}s as "
        f"{term('obligation', GLOSSARY['obligation'])}s and tries to route each one "
        "to a slot.</p>"
    )
    return section(
        "how",
        "How generation works",
        HOW_QUESTION,
        join([chain(steps), aside, glossary(GLOSSARY)]),
    )
