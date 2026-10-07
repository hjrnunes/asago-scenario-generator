"""Governance routing places governance-only risks on control actions."""

from __future__ import annotations

from asago_scenario_generator.pipeline.governance_rows import (
    select_governance_risks,
)
from asago_scenario_generator.pipeline.obligation_consideration import (
    build_governance_briefs,
)
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    AnalysisControls,
)
from asago_scenario_generator.stpa.obligation_aware.governance_routing import (
    GovernancePlacement,
    GovernanceRoutingResponse,
    GovernanceTarget,
    route_governance_rows,
)
from asago_scenario_generator.stpa.threat_enum.slot_creation import create_slots
from tests.stpa.helpers import (
    make_minimal_control_structure,
    make_minimal_loss_analysis,
)
from tests.test_governance_brief import _pattern
from tests.helpers.obligation_factory import make_plan
from asago_scenario_generator.stpa.models.loss_analysis import RiskDisposition


def _setup(*risk_ids: str):
    mappings = [
        {
            "source_id": "risk-a",
            "target_id": _pattern().id,
            "relation": "exact_match",
            "confidence": 1.0,
        }
    ]
    plan = make_plan(risk_ids=("risk-a", *risk_ids), mappings=mappings)
    loss_analysis = make_minimal_loss_analysis().model_copy(
        update={
            "risk_dispositions": [
                RiskDisposition(risk_ref=risk_id, disposition="cited", loss_ids=["L-1"])
                for risk_id in risk_ids
            ]
        }
    )
    selection = select_governance_risks(plan, loss_analysis)
    briefs = build_governance_briefs(plan, selection.risk_ids)
    return briefs, selection, loss_analysis, make_minimal_control_structure()


def _controls(batch: int = 8) -> AnalysisControls:
    return AnalysisControls(
        model_profile="test",
        model_name="fake",
        deadline_seconds=10.0,
        temperature=0.0,
        max_batch_size=batch,
    )


class _Adapter:
    """Answers each governance request from a script of target lists."""

    def __init__(self, *answers):
        self.answers = list(answers)
        self.requests = []
        self.feedback = []

    def route_governance(self, request, *, correction_feedback=None):
        self.requests.append(request)
        self.feedback.append(correction_feedback)
        answer = self.answers.pop(0)
        return GovernanceRoutingResponse(
            request_digest=request.semantic_digest,
            placements=answer(request),
        )


def _place(*target_ids: str, reason: str = "the action changes the risky state"):
    def answer(request):
        return tuple(
            GovernancePlacement(
                risk_id=brief.risk_ref.risk_id,
                targets=tuple(
                    GovernanceTarget(target_id=item, reason=reason)
                    for item in target_ids
                ),
            )
            for brief in request.briefs
        )

    return answer


def _route(adapter, briefs, selection, loss_analysis, structure, batch=8):
    return route_governance_rows(
        adapter,
        briefs=briefs,
        paths=selection.paths,
        loss_analysis=loss_analysis,
        control_structure=structure,
        controls=_controls(batch),
    )


def test_a_control_action_places_the_risk_on_every_slot_of_that_action() -> None:
    briefs, selection, loss, structure = _setup("risk-b")
    adapter = _Adapter(_place("CA-1-1"))

    result = _route(adapter, briefs, selection, loss, structure)

    expected = tuple(sorted(slot.slot_id for slot in create_slots(structure)))
    (route,) = result.routes
    assert route.disposition == "targeted"
    assert route.obligation_id == briefs[0].obligation_id
    assert route.slot_ids == expected
    assert route.hazard_ids == ("H-1",)
    assert route.constraint_ids == ("SC-1",)
    assert any("the action changes the risky state" in item for item in route.evidence)
    assert result.routed_briefs == briefs
    assert len(result.requests) == 1
    assert result.declined == ()
    assert result.unresolved == {}


def test_a_slot_identifier_places_the_risk_on_that_slot_only() -> None:
    briefs, selection, loss, structure = _setup("risk-b")
    slot = create_slots(structure)[0]

    result = _route(_Adapter(_place(slot.slot_id)), briefs, selection, loss, structure)

    assert result.routes[0].slot_ids == (slot.slot_id,)


def test_a_risk_with_no_target_is_declined_without_a_route() -> None:
    briefs, selection, loss, structure = _setup("risk-b")

    result = _route(_Adapter(_place()), briefs, selection, loss, structure)

    assert result.routes == ()
    assert result.routed_briefs == ()
    assert result.declined == ("risk-b",)


def test_an_unknown_identifier_is_repaired_once_with_exact_feedback() -> None:
    briefs, selection, loss, structure = _setup("risk-b")
    adapter = _Adapter(_place("CA-9-9"), _place("CA-1-1"))

    result = _route(adapter, briefs, selection, loss, structure)

    assert len(adapter.requests) == 2
    assert adapter.feedback[0] is None
    assert "CA-9-9" in adapter.feedback[1]
    assert "risk-b" in adapter.feedback[1]
    assert len(result.routes) == 1


def test_an_identifier_that_stays_invalid_leaves_the_risk_unresolved() -> None:
    briefs, selection, loss, structure = _setup("risk-b")
    adapter = _Adapter(_place("CA-9-9"), _place("CA-9-9"))

    result = _route(adapter, briefs, selection, loss, structure)

    assert result.routes == ()
    assert list(result.unresolved) == ["risk-b"]
    assert "CA-9-9" in result.unresolved["risk-b"]
    assert result.diagnostics


def test_valid_siblings_survive_an_invalid_row() -> None:
    briefs, selection, loss, structure = _setup("risk-b", "risk-c")

    def mixed(request):
        return tuple(
            GovernancePlacement(
                risk_id=brief.risk_ref.risk_id,
                targets=(
                    GovernanceTarget(
                        target_id="CA-1-1"
                        if brief.risk_ref.risk_id == "risk-b"
                        else "CA-9-9",
                        reason="bears on the action",
                    ),
                ),
            )
            for brief in request.briefs
        )

    result = _route(_Adapter(mixed, mixed), briefs, selection, loss, structure)

    risk_b = next(item for item in briefs if item.risk_ref.risk_id == "risk-b")
    assert [route.obligation_id for route in result.routes] == [risk_b.obligation_id]
    assert list(result.unresolved) == ["risk-c"]


def test_a_response_that_omits_a_risk_is_a_batch_failure() -> None:
    briefs, selection, loss, structure = _setup("risk-b", "risk-c")

    def omit(request):
        return _place("CA-1-1")(request)[:1]

    adapter = _Adapter(omit, omit)
    result = _route(adapter, briefs, selection, loss, structure)

    assert result.routes == ()
    assert sorted(result.unresolved) == ["risk-b", "risk-c"]
    assert "risk_id" in adapter.feedback[1]


def test_rows_are_batched_by_the_batch_size_control() -> None:
    briefs, selection, loss, structure = _setup("risk-b", "risk-c", "risk-d")
    adapter = _Adapter(_place("CA-1-1"), _place("CA-1-1"))

    result = _route(adapter, briefs, selection, loss, structure, batch=2)

    assert [len(item.briefs) for item in adapter.requests] == [2, 1]
    assert [item.batch_id for item in result.requests] == [
        "governance-batch-1",
        "governance-batch-2",
    ]
    assert len(result.routes) == 3
    assert len(result.call_evidence) == 2


def test_no_rows_make_no_request() -> None:
    _, selection, loss, structure = _setup()
    adapter = _Adapter()

    result = _route(adapter, (), selection, loss, structure)

    assert result.requests == ()
    assert adapter.requests == []
