"""The Stage 1a risk scope applies before obligation routing.

An applicable obligation whose risk is out of scope is never sent to a routing
request; accounting still records it, with its scope, at
``risk_out_of_scope``.  Batches are formed before the withheld briefs leave
them, so a batch that never held one keeps its request.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
from asago_scenario_generator.models.obligation_consideration import (
    ObligationRoute,
    ObligationSemanticAssessment,
)
from asago_scenario_generator.pipeline.obligation_consideration import (
    build_consideration_artifact,
    build_neutral_briefs,
    build_obligation_accounting,
    out_of_scope_obligation_ids,
)
from asago_scenario_generator.pipeline.obligation_planner import (
    plan_taxonomy_obligations,
)
from asago_scenario_generator.pipeline.synthesis import run_synthesis
from asago_scenario_generator.pipeline.synthesis_defaults import _default_account
from asago_scenario_generator.pipeline.synthesis_types import SynthesisAdapters
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    StructuralRoutingResponse,
)
from asago_scenario_generator.stpa.obligation_aware.routing import route_obligations
from asago_scenario_generator.stpa.system_model.risk_actionability import (
    RiskActionabilityEntry,
    RiskActionabilityRecord,
)
from asago_scenario_generator.stpa.system_model.run import SP1RunResult

from tests.helpers.governance import _accounting_pins, _plan_with_non_stpa_rows
from tests.helpers.obligation_aware import (
    _control_structure,
    _controls,
    _loss_analysis,
)
from tests.helpers.obligation_factory import make_plan
from tests.helpers.projection_factory import get_test_raw_pattern
from tests.helpers.synthesis import _FakeAdapters, _inputs
from tests.helpers.synthesis_fixture import synthesis_taxonomy_inputs

_RISKS = ("risk-a", "risk-b", "risk-c", "risk-d")


class _RecordingAdapter:
    """Answer every routing request with a valid route and keep the request."""

    def __init__(self) -> None:
        self.requests: list[Any] = []

    def route(self, request, *, correction_feedback=None):
        self.requests.append(request)
        return StructuralRoutingResponse(
            adapter_kind="fake",
            request_digest=request.semantic_digest,
            routes=tuple(
                ObligationRoute(
                    obligation_id=brief.obligation_id,
                    disposition="proposed_not_applicable",
                    semantic_assessment=ObligationSemanticAssessment(
                        mechanism_assessment="absent_from_system",
                        risk_alignment="supported",
                        mapping_strength="direct_curated_pair",
                        mechanism_rationale="The system has no such mechanism.",
                        risk_alignment_rationale="The risk is relevant.",
                    ),
                    rationale="The system has no such mechanism.",
                    evidence=("system-inventory",),
                )
                for brief in request.briefs
            ),
        )


def _briefs() -> tuple[Any, ...]:
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    return build_neutral_briefs(make_plan(risk_ids=_RISKS), (pattern,))


def _ids_of(briefs: Any, *risks: str) -> frozenset[str]:
    return frozenset(
        brief.obligation_id for brief in briefs if brief.risk_ref.risk_id in risks
    )


def _route(withheld: frozenset[str] = frozenset()) -> tuple[Any, _RecordingAdapter]:
    adapter = _RecordingAdapter()
    result = route_obligations(
        adapter,
        briefs=_briefs(),
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
        controls=_controls(),
        max_batch_size=2,
        withheld_obligation_ids=withheld,
    )
    return result, adapter


def _sent_ids(adapter: _RecordingAdapter) -> set[str]:
    return {brief.obligation_id for item in adapter.requests for brief in item.briefs}


def test_routing_sends_no_withheld_brief() -> None:
    briefs = _briefs()
    withheld = _ids_of(briefs, "risk-b")

    result, adapter = _route(withheld)

    assert _sent_ids(adapter) == {item.obligation_id for item in briefs} - withheld
    assert {item.obligation_id for item in result.briefs}.isdisjoint(withheld)
    assert [route.obligation_id for route in result.routes] == [
        item.obligation_id for item in result.briefs
    ]


def test_a_batch_of_withheld_briefs_sends_no_request() -> None:
    briefs = _briefs()

    result, adapter = _route(_ids_of(briefs, "risk-c", "risk-d"))

    assert [item.batch_id for item in adapter.requests] == ["initial-batch-1"]
    assert len(result.requests) == 1
    assert len(result.call_evidence) == 1


def test_a_batch_without_withheld_briefs_keeps_its_request() -> None:
    briefs = _briefs()
    _, unfiltered = _route()

    _, filtered = _route(_ids_of(briefs, "risk-a"))

    # The second batch never held the withheld brief: same number, same
    # content.  The first batch keeps only its in-scope brief.
    assert [item.batch_id for item in filtered.requests] == [
        "initial-batch-1",
        "initial-batch-2",
    ]
    assert filtered.requests[1] == unfiltered.requests[1]
    assert filtered.requests[1].semantic_digest == (
        unfiltered.requests[1].semantic_digest
    )
    assert [item.risk_ref.risk_id for item in filtered.requests[0].briefs] == ["risk-b"]


def test_withholding_every_brief_sends_nothing() -> None:
    briefs = _briefs()

    result, adapter = _route(_ids_of(briefs, *_RISKS))

    assert adapter.requests == []
    assert result.briefs == () and result.routes == () and result.requests == ()


def test_only_applicable_out_of_scope_obligations_are_withheld() -> None:
    plan = _plan_with_non_stpa_rows()
    every_risk = {row.risk_ref.risk_id: "outside_boundary" for row in plan.obligations}

    withheld = out_of_scope_obligation_ids(plan, every_risk)

    assert withheld == {
        row.obligation_id
        for row in plan.obligations
        if row.scope_disposition == "applicable"
    }
    assert out_of_scope_obligation_ids(plan, {}) == frozenset()
    in_scope = {risk: "actionable" for risk in every_risk}
    assert out_of_scope_obligation_ids(plan, in_scope) == frozenset()


@pytest.mark.parametrize("scope", ["outside_boundary", "not_applicable"])
def test_a_withheld_obligation_is_accounted_at_out_of_scope(scope: str) -> None:
    plan = _plan_with_non_stpa_rows()
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    briefs = build_neutral_briefs(plan, (pattern,))
    risk = briefs[0].risk_ref.risk_id
    withheld = out_of_scope_obligation_ids(plan, {risk: scope})
    routed = tuple(item for item in briefs if item.obligation_id not in withheld)
    consideration = build_consideration_artifact(
        plan=plan, briefs=routed, initial_routes=(), final_routes=()
    )

    accounting = build_obligation_accounting(
        plan=plan,
        consideration=consideration,
        source_pins=_accounting_pins(plan),
        risk_scopes={risk: scope},
    )

    assert len(accounting.rows) == len(plan.obligations)
    assert accounting.summary.total == len(plan.obligations)
    [row] = [item for item in accounting.rows if item.obligation_id in withheld]
    assert row.scope == scope
    assert row.disposition == "unresolved"
    assert row.stop_reason == "risk_out_of_scope"
    assert row.route_refs == () and row.slot_ids == ()
    assert [item.code for item in row.diagnostics] == ["risk_out_of_scope"]


def test_an_in_scope_obligation_without_a_route_still_lost_its_route() -> None:
    plan = _plan_with_non_stpa_rows()
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    briefs = build_neutral_briefs(plan, (pattern,))
    risk = briefs[0].risk_ref.risk_id
    consideration = build_consideration_artifact(
        plan=plan, briefs=(), initial_routes=(), final_routes=()
    )

    accounting = build_obligation_accounting(
        plan=plan,
        consideration=consideration,
        source_pins=_accounting_pins(plan),
        risk_scopes={risk: "actionable"},
    )

    [row] = [
        item
        for item in accounting.rows
        if item.obligation_id == briefs[0].obligation_id
    ]
    assert row.stop_reason == "no_structural_route"
    assert [item.code for item in row.diagnostics] == ["missing_final_route"]


def _decisions(**decisions: str) -> RiskActionabilityRecord:
    return RiskActionabilityRecord(
        status="completed",
        call_count=1,
        counts={},
        entries=[
            RiskActionabilityEntry(
                risk_id=risk,
                decision=decision,
                reason="The boundary decision.",
                source="model",
                **(
                    {"system_action": "replying", "affected_stakeholder": "users"}
                    if decision == "actionable"
                    else {}
                ),
            )
            for risk, decision in decisions.items()
        ],
    )


def _synthesize(
    tmp_path: Path, record: RiskActionabilityRecord, *, gap: bool = False
) -> dict[str, Any]:
    """Run synthesis with *record* as the Stage 1a decision; keep what ports saw."""
    seen: dict[str, Any] = {"consider": [], "recheck": []}

    class Adapters(_FakeAdapters):
        def baseline(self, **kwargs: object) -> object:
            result = super().baseline(**kwargs)
            assert isinstance(result, SP1RunResult)
            result.risk_actionability = record
            return result

        def consider(self, **kwargs: Any) -> object:
            seen["consider"].append(kwargs["withheld_obligation_ids"])
            return super().consider(**kwargs)

        def recheck(self, **kwargs: Any) -> object:
            seen["recheck"].append(kwargs["withheld_obligation_ids"])
            return super().recheck(**kwargs)

        def account(self, **kwargs: Any) -> object:
            seen["accounting"] = _default_account(**kwargs)
            return seen["accounting"]

    adapters = Adapters(calls=[], gap=gap)
    run_synthesis(_inputs(tmp_path), SynthesisAdapters.from_object(adapters))
    seen["routed"] = [
        brief.obligation_id
        for name, values in adapters.calls
        if name in {"consider", "recheck"}
        for brief in values[0]
    ]
    return seen


def test_synthesis_withholds_out_of_scope_obligations_from_routing(
    tmp_path: Path,
) -> None:
    in_scope = _synthesize(
        tmp_path / "in-scope",
        _decisions(**{"risk-a": "actionable", "risk-b": "actionable"}),
    )
    scoped = _synthesize(
        tmp_path / "scoped",
        _decisions(**{"risk-a": "outside_boundary", "risk-b": "actionable"}),
    )
    accounting = scoped["accounting"]
    plan = plan_taxonomy_obligations(synthesis_taxonomy_inputs())
    plan_rows = {row.obligation_id: row for row in plan.obligations}
    withheld = {
        oid for oid, row in plan_rows.items() if row.risk_ref.risk_id == "risk-a"
    }

    assert scoped["consider"] == [frozenset(withheld)]
    assert withheld and withheld.isdisjoint(scoped["routed"])
    assert in_scope["consider"] == [frozenset()]
    assert len(accounting.rows) == len(plan_rows)
    assert accounting.summary.total == len(plan_rows)
    for row in accounting.rows:
        if row.obligation_id in withheld:
            assert row.scope == "outside_boundary"
            assert row.stop_reason == "risk_out_of_scope"
            assert row.disposition == "unresolved"
    before = {row.obligation_id: row for row in in_scope["accounting"].rows}
    for row in accounting.rows:
        if plan_rows[row.obligation_id].risk_ref.risk_id == "risk-b":
            assert row == before[row.obligation_id]


def test_the_recheck_withholds_the_same_obligations(tmp_path: Path) -> None:
    scoped = _synthesize(
        tmp_path,
        _decisions(**{"risk-a": "outside_boundary", "risk-b": "actionable"}),
        gap=True,
    )
    plan = plan_taxonomy_obligations(synthesis_taxonomy_inputs())
    withheld = frozenset(
        row.obligation_id
        for row in plan.obligations
        if row.risk_ref.risk_id == "risk-a" and row.scope_disposition == "applicable"
    )

    assert scoped["recheck"] == [withheld]
    assert withheld.isdisjoint(scoped["routed"])
    rows = {row.obligation_id: row for row in scoped["accounting"].rows}
    assert all(rows[oid].stop_reason == "risk_out_of_scope" for oid in withheld)
