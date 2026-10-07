"""The governance routing stage of the synthesis run."""

from __future__ import annotations

from types import SimpleNamespace

from asago_scenario_generator.pipeline.synthesis_defaults import (
    _default_govern,
    _production_defaults,
)
from asago_scenario_generator.pipeline.synthesis_governance import (
    _run_governance_routing,
)
from asago_scenario_generator.pipeline.synthesis_types import SynthesisAdapters
from asago_scenario_generator.stpa.models.loss_analysis import RiskDisposition
from asago_scenario_generator.stpa.obligation_aware.governance_routing import (
    GovernancePlacement,
    GovernanceRoutingResponse,
    GovernanceRoutingResult,
)
from tests.helpers.obligation_factory import make_plan
from tests.helpers.synthesis_fixture import synthesis_inputs
from tests.stpa.helpers import (
    make_minimal_control_structure,
    make_minimal_loss_analysis,
)
from tests.helpers.governance import _controls, _pattern, _setup


def _plan(*risk_ids: str):
    mappings = [
        {
            "source_id": "risk-a",
            "target_id": _pattern().id,
            "relation": "exact_match",
            "confidence": 1.0,
        }
    ]
    return make_plan(risk_ids=("risk-a", *risk_ids), mappings=mappings)


def _loss(*cited: str):
    return make_minimal_loss_analysis().model_copy(
        update={
            "risk_dispositions": [
                RiskDisposition(risk_ref=item, disposition="cited", loss_ids=["L-1"])
                for item in cited
            ]
        }
    )


class _Govern:
    def __init__(self, result=None, error=None):
        self.result = result if result is not None else GovernanceRoutingResult()
        self.error = error
        self.calls = []

    def __call__(self, **kwargs):
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return self.result


def _run(govern, plan, loss, tmp_path):
    adapters = SynthesisAdapters(govern=govern, obligation_adapter="adapter")
    inputs = synthesis_inputs(tmp_path)
    return _run_governance_routing(
        plan=plan,
        loss_analysis=loss,
        control_structure=make_minimal_control_structure(),
        inputs=inputs,
        adapters=adapters,
    )


def test_the_govern_port_is_read_from_an_adapter_object() -> None:
    port = _Govern()

    assert SynthesisAdapters.from_object(SimpleNamespace(govern=port)).govern is port
    assert _production_defaults().govern is _default_govern


def test_no_governance_row_makes_no_call(tmp_path) -> None:
    govern = _Govern()

    run = _run(govern, _plan(), _loss(), tmp_path)

    assert govern.calls == []
    assert run.calls == ()
    assert run.value.result.routes == ()


def test_a_risk_without_a_cited_disposition_makes_no_call(tmp_path) -> None:
    govern = _Govern()

    run = _run(govern, _plan("risk-b"), _loss(), tmp_path)

    assert govern.calls == []
    assert run.value.selection.skipped == {"risk-b": "no_risk_disposition"}


def test_a_cited_governance_risk_is_routed_with_its_derived_path(tmp_path) -> None:
    govern = _Govern()

    run = _run(govern, _plan("risk-b"), _loss("risk-b"), tmp_path)

    (call,) = govern.calls
    assert [item.risk_ref.risk_id for item in call["briefs"]] == ["risk-b"]
    assert call["paths"]["risk-b"].hazard_ids == ("H-1",)
    assert call["obligation_adapter"] == "adapter"
    assert run.value.selection.risk_ids == ("risk-b",)


def test_a_failing_port_leaves_the_run_with_a_warning_and_no_routes(tmp_path) -> None:
    govern = _Govern(error=RuntimeError("provider unavailable"))

    run = _run(govern, _plan("risk-b"), _loss("risk-b"), tmp_path)

    assert run.value.result.routes == ()
    assert run.diagnostics == ()
    assert any("provider unavailable" in item for item in run.value.warnings)


class _RoutingAdapter:
    """Declines every risk through the routing call the default port makes."""

    def __init__(self, *, controls=None):
        self.controls = controls
        self.requests = []

    def route_governance(self, request, *, correction_feedback=None):
        self.requests.append(request)
        return GovernanceRoutingResponse(
            request_digest=request.semantic_digest,
            placements=tuple(
                GovernancePlacement(risk_id=brief.risk_ref.risk_id, targets=())
                for brief in request.briefs
            ),
        )


def _default_port_call(adapter, tmp_path):
    briefs, selection, loss, structure = _setup("risk-b")
    result = _default_govern(
        briefs=briefs,
        paths=selection.paths,
        loss_analysis=loss,
        control_structure=structure,
        inputs=synthesis_inputs(tmp_path),
        obligation_adapter=adapter,
        output_dir=tmp_path,
    )
    return briefs, result


def test_the_default_port_routes_through_an_adapter_that_has_the_stage(
    tmp_path,
) -> None:
    adapter = _RoutingAdapter(controls=_controls())

    briefs, result = _default_port_call(adapter, tmp_path)

    assert result.declined == ("risk-b",)
    assert result.routes == ()
    assert [item.risk_ref.risk_id for item in adapter.requests[0].briefs] == ["risk-b"]
    assert [item.risk_ref.risk_id for item in briefs] == ["risk-b"]


def test_the_default_port_builds_controls_when_the_adapter_has_none(tmp_path) -> None:
    adapter = _RoutingAdapter()

    _, result = _default_port_call(adapter, tmp_path)

    assert result.declined == ("risk-b",)
    assert len(adapter.requests) == 1


def test_the_default_port_does_nothing_for_an_adapter_without_the_stage() -> None:
    assert (
        _default_govern(
            briefs=(),
            paths={},
            loss_analysis=None,
            control_structure=None,
            inputs=None,
            obligation_adapter=object(),
            output_dir="/tmp/unused",
        )
        is None
    )
    assert (
        _default_govern(
            briefs=(),
            paths={},
            loss_analysis=None,
            control_structure=None,
            inputs=None,
            obligation_adapter=None,
            output_dir="/tmp/unused",
        )
        is None
    )
