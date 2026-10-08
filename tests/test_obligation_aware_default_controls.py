"""Stages called without controls share one default synthesis control set."""

from __future__ import annotations

from asago_scenario_generator.models.obligation_consideration import (
    MissingStructuralConcept,
)
from asago_scenario_generator.stpa.infra.llm import DEFAULT_TEMPERATURE
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    AnalysisControls,
    StructuralRoutingResponse,
    default_synthesis_controls,
)
from asago_scenario_generator.stpa.obligation_aware.revision import (
    revise_structure_once,
)
from asago_scenario_generator.stpa.obligation_aware.routing import (
    build_neutral_briefs,
    route_obligations,
)
from asago_scenario_generator.stpa.obligation_aware.slot_filling import (
    build_synthesis_slot_requests,
)
from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
from tests.helpers.obligation_aware import _control_structure, _loss_analysis
from tests.helpers.obligation_factory import make_plan
from tests.helpers.projection_factory import get_test_raw_pattern


def _briefs():
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    return build_neutral_briefs(make_plan(risk_ids=("risk-a",)), (pattern,))


def test_the_default_controls_name_the_caller_supplied_synthesis_model() -> None:
    assert default_synthesis_controls() == AnalysisControls(
        model_profile="synthesis",
        model_name="caller-supplied",
        deadline_seconds=300.0,
        temperature=DEFAULT_TEMPERATURE,
    )
    assert default_synthesis_controls(max_batch_size=3).max_batch_size == 3


def test_routing_without_controls_uses_the_defaults_at_its_batch_size() -> None:
    sent = []

    class Adapter:
        def route(self, request, *, correction_feedback=None):
            sent.append(request)
            return StructuralRoutingResponse(
                adapter_kind="fake", request_digest=request.semantic_digest
            )

    route_obligations(
        Adapter(),
        briefs=_briefs()[:1],
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
        max_batch_size=1,
    )

    assert sent
    assert {item.controls for item in sent} == {
        default_synthesis_controls(max_batch_size=1)
    }


def test_slot_requests_without_controls_use_the_defaults() -> None:
    requests = build_synthesis_slot_requests(
        briefs=(),
        routes=(),
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
    )

    assert requests
    assert {item.controls for item in requests} == {default_synthesis_controls()}


def test_revision_without_controls_uses_the_defaults() -> None:
    sent = []

    class Adapter:
        def revise(self, request):
            sent.append(request)
            raise RuntimeError("no revision in this test")

    revise_structure_once(
        Adapter(),
        gaps=(
            MissingStructuralConcept(
                concept_type="responsibility",
                description="A reviewing responsibility is missing.",
                evidence_refs=("review-gap",),
            ),
        ),
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
    )

    assert [item.controls for item in sent] == [default_synthesis_controls()]
