"""Focused regressions for independent routing judgements and batch retention."""

from __future__ import annotations

from asago_scenario_generator.models.obligation_consideration import (
    ObligationRoute,
    ObligationSemanticAssessment,
)
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    StructuralRoutingResponse,
)
from asago_scenario_generator.stpa.obligation_aware.routing import (
    build_neutral_briefs,
    route_obligations,
)
from asago_scenario_generator.stpa.threat_enum.slot_creation import create_slots
from tests.helpers.obligation_factory import make_plan
from tests.helpers.projection_factory import get_test_raw_pattern
from tests.test_obligation_aware_stpa import (
    _control_structure,
    _controls,
    _loss_analysis,
)
from asago_scenario_generator.models.attack_pattern_chain import AttackPattern


def _briefs():
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    return build_neutral_briefs(
        make_plan(risk_ids=("risk-a", "risk-b")),
        (pattern,),
    )


def _assessment(*, mechanism: str, risk: str) -> ObligationSemanticAssessment:
    return ObligationSemanticAssessment(
        mechanism_assessment=mechanism,
        risk_alignment=risk,
        mapping_strength="direct_curated_pair",
        mechanism_rationale="The mechanism evidence is explicit.",
        risk_alignment_rationale="The reviewed risk is conceptually relevant.",
    )


def test_supported_risk_with_absent_mechanism_is_valid_nonapplicability() -> None:
    """Independent risk relevance does not invalidate a proposed N/A route."""
    brief = _briefs()[0]
    route = ObligationRoute(
        obligation_id=brief.obligation_id,
        disposition="proposed_not_applicable",
        semantic_assessment=_assessment(
            mechanism="absent_from_system",
            risk="supported",
        ),
        rationale="The concern is relevant, but this system has no such mechanism.",
        evidence=("system-inventory",),
    )

    class Adapter:
        def route(self, request, *, correction_feedback=None):
            return StructuralRoutingResponse(
                request_digest=request.semantic_digest,
                routes=(route,),
            )

    result = route_obligations(
        Adapter(),
        briefs=(brief,),
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
        controls=_controls(),
        max_batch_size=1,
    )

    assert result.routes[0].disposition == "proposed_not_applicable"
    assert result.routes[0].semantic_assessment is not None
    assert result.routes[0].semantic_assessment.risk_alignment == "supported"


def test_invalid_route_is_unresolved_without_discarding_valid_batch_sibling() -> None:
    """One bad semantic record cannot turn every route in its batch unresolved."""
    briefs = _briefs()
    slot = create_slots(_control_structure())[0]
    valid = ObligationRoute(
        obligation_id=briefs[0].obligation_id,
        disposition="targeted",
        semantic_assessment=_assessment(
            mechanism="plausible_in_system",
            risk="supported",
        ),
        slot_ids=(slot.slot_id,),
        controller_ids=("RESP-1",),
        responsibility_ids=("RESP-1",),
        control_action_ids=("CA-1-1",),
        controlled_process_ids=("CP-1",),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        rationale="The supplied control path is relevant.",
        evidence=("system-path",),
    )
    invalid = ObligationRoute(
        obligation_id=briefs[1].obligation_id,
        disposition="targeted",
        semantic_assessment=_assessment(
            mechanism="absent_from_system",
            risk="supported",
        ),
        slot_ids=(slot.slot_id,),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        rationale="The concern is relevant but the route is incorrectly targeted.",
        evidence=("bad-route",),
    )

    class Adapter:
        def route(self, request, *, correction_feedback=None):
            return StructuralRoutingResponse(
                request_digest=request.semantic_digest,
                routes=(valid, invalid),
            )

    controls = _controls().model_copy(update={"validation_retries": 0})
    result = route_obligations(
        Adapter(),
        briefs=briefs,
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
        controls=controls,
        max_batch_size=2,
    )

    by_id = {route.obligation_id: route for route in result.routes}
    assert by_id[valid.obligation_id].disposition == "targeted"
    assert by_id[invalid.obligation_id].disposition == "unresolved"
    assert by_id[invalid.obligation_id].semantic_assessment is not None
    assert (
        by_id[invalid.obligation_id].semantic_assessment.risk_alignment == "supported"
    )
    assert by_id[invalid.obligation_id].diagnostics[0].code == (
        "routing_record_validation_failed"
    )
    assert result.call_evidence[0].outcome == "unresolved"
