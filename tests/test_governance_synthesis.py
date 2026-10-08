"""The synthesis run hands governance routes to ICA filling, scenarios, and accounting."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from asago_scenario_generator.models.obligation_consideration import ObligationRoute
from asago_scenario_generator.pipeline.synthesis import run_synthesis
from asago_scenario_generator.pipeline.synthesis_types import SynthesisAdapters
from asago_scenario_generator.stpa.models.loss_analysis import RiskDisposition
from asago_scenario_generator.stpa.obligation_aware.governance_routing import (
    GovernanceRoutingResult,
)
from tests.helpers.synthesis_fixture import baseline_loss_analysis
from tests.helpers.synthesis import _FakeAdapters, _inputs

_GOVERNANCE_RISK = "risk-governance"


def _cited_loss():
    return baseline_loss_analysis().model_copy(
        update={
            "risk_dispositions": [
                RiskDisposition(
                    risk_ref=_GOVERNANCE_RISK, disposition="cited", loss_ids=["L-1"]
                )
            ]
        }
    )


@dataclass
class _GovernedAdapters(_FakeAdapters):
    """Route every governance brief to one slot and record what later stages see."""

    declines: bool = False
    seen: dict[str, Any] = field(default_factory=dict)

    def govern(self, *, briefs, paths, **_) -> GovernanceRoutingResult:
        briefs = tuple(briefs)
        self.seen["govern_paths"] = dict(paths)
        if self.declines:
            return GovernanceRoutingResult(routed_briefs=briefs, declined=_ids(briefs))
        routes = tuple(
            ObligationRoute(
                obligation_id=brief.obligation_id,
                disposition="targeted",
                slot_ids=("RESP-1:CA-1-1:NOT_PROVIDED",),
                hazard_ids=("H-1",),
                constraint_ids=("SC-1",),
                rationale="The control action could bring about the reviewed risk.",
                evidence=("governance: reviewed risk",),
            )
            for brief in briefs
        )
        return GovernanceRoutingResult(routes=routes, routed_briefs=briefs)

    def fill_icas(self, *, routes, briefs, **kwargs) -> object:
        self.seen["fill_routes"] = tuple(routes)
        self.seen["fill_briefs"] = tuple(briefs)
        return super().fill_icas(routes=routes, briefs=briefs, **kwargs)

    def scenarios(self, *, routes, briefs, **kwargs) -> object:
        self.seen["scenario_routes"] = tuple(routes)
        self.seen["scenario_briefs"] = tuple(briefs)
        return super().scenarios(routes=routes, briefs=briefs, **kwargs)

    def account(self, **kwargs) -> object:
        self.seen["account_kwargs"] = kwargs
        return super().account(**kwargs)


def _ids(briefs) -> tuple[str, ...]:
    return tuple(brief.obligation_id for brief in briefs)


def _run(tmp_path, *, declines: bool = False) -> _GovernedAdapters:
    fake = _GovernedAdapters(calls=[], loss_analysis=_cited_loss(), declines=declines)
    run_synthesis(_inputs(tmp_path), SynthesisAdapters.from_object(fake))
    return fake


def test_governance_routes_reach_ica_filling_and_scenarios(tmp_path) -> None:
    fake = _run(tmp_path)

    governance_ids = {
        brief.obligation_id
        for brief in fake.seen["fill_briefs"]
        if getattr(brief, "kind", "pattern") == "governance"
    }
    assert len(governance_ids) == 1
    for stage in ("fill", "scenario"):
        routes = fake.seen[f"{stage}_routes"]
        assert governance_ids <= {route.obligation_id for route in routes}
        assert any(route.obligation_id not in governance_ids for route in routes)
    assert governance_ids <= {
        brief.obligation_id for brief in fake.seen["scenario_briefs"]
    }


def test_accounting_receives_the_governance_routes_apart(tmp_path) -> None:
    fake = _run(tmp_path)

    governance = fake.seen["account_kwargs"]["governance_routes"]
    assert [route.disposition for route in governance] == ["targeted"]
    assert not {route.obligation_id for route in governance} & {
        route.obligation_id for route in fake.seen["account_kwargs"]["routes"]
    }


def test_a_declined_governance_row_adds_no_route_anywhere(tmp_path) -> None:
    fake = _run(tmp_path, declines=True)

    assert "governance_routes" not in fake.seen["account_kwargs"]
    assert not any(
        getattr(brief, "kind", "pattern") == "governance"
        for brief in fake.seen["fill_briefs"]
    )
    assert len(fake.seen["fill_routes"]) == len(fake.seen["account_kwargs"]["routes"])


def test_a_run_without_cited_risks_is_unchanged(tmp_path) -> None:
    fake = _GovernedAdapters(calls=[])
    run_synthesis(_inputs(tmp_path), SynthesisAdapters.from_object(fake))

    assert "govern_paths" not in fake.seen
    assert "governance_routes" not in fake.seen["account_kwargs"]
    assert all(
        getattr(brief, "kind", "pattern") == "pattern"
        for brief in fake.seen["fill_briefs"]
    )
