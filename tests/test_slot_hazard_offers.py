"""Each slot request's hazard offer is reported beside the earlier rule's offer."""

from __future__ import annotations

import pytest

from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
from asago_scenario_generator.models.slot_hazard_offer import (
    SlotHazardOfferReport,
    SlotHazardOfferSummary,
)
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.obligation_aware.contracts import ObligationRoute
from asago_scenario_generator.stpa.obligation_aware.hazard_offer import (
    build_slot_hazard_offer_report,
    main_rule_offer,
    own_offer,
    slot_offer,
)
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    build_synthesis_slot_prompts,
)
from asago_scenario_generator.stpa.obligation_aware.routing import build_neutral_briefs
from asago_scenario_generator.stpa.obligation_aware.slot_filling import (
    _budgeted_synthesis_slot_requests,
    build_synthesis_slot_requests,
)
from asago_scenario_generator.stpa.threat_enum.slot_creation import create_slots
from tests.helpers.obligation_aware import _control_structure, _controls, _loss_analysis
from tests.helpers.obligation_factory import make_plan
from tests.helpers.projection_factory import get_test_raw_pattern

_OBLIGATION_ID = "ob:v1:" + "c" * 64


def two_hazard_loss_analysis():
    """Add a second hazard and its constraint that no route names."""
    base = _loss_analysis()
    return base.model_copy(
        update={
            "hazards": [
                *base.hazards,
                Hazard(
                    hazard_id="H-2",
                    description="Request details reach a caller who does not own them.",
                    related_losses=("L-1",),
                ),
            ],
            "security_constraints": [
                *base.security_constraints,
                SecurityConstraint(
                    constraint_id="SC-2",
                    rule="Only the owner may read request details.",
                    related_hazards=("H-2",),
                ),
            ],
        }
    )


def first_slot_id() -> str:
    return create_slots(_control_structure())[0].slot_id


def route_to_first_slot(obligation_id: str = _OBLIGATION_ID) -> ObligationRoute:
    return ObligationRoute(
        obligation_id=obligation_id,
        disposition="targeted",
        slot_ids=(first_slot_id(),),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        evidence=("route",),
    )


def routed_requests(*, routed: bool = True):
    """Build the single-slot requests the slot filler would send."""
    briefs = build_neutral_briefs(
        make_plan(risk_ids=("risk-a",)),
        (AttackPattern.model_validate(get_test_raw_pattern()),),
    )
    routes = (route_to_first_slot(briefs[0].obligation_id),) if routed else ()
    requests = build_synthesis_slot_requests(
        briefs=briefs,
        routes=routes,
        loss_analysis=two_hazard_loss_analysis(),
        control_structure=_control_structure(),
        controls=_controls(),
    )
    return _budgeted_synthesis_slot_requests(object(), requests)


def report_for(*, routed: bool) -> SlotHazardOfferReport:
    """Report the hazard offers of those requests."""
    return build_slot_hazard_offer_report(routed_requests(routed=routed))


def test_a_slot_request_without_routes_is_offered_every_hazard() -> None:
    offer = own_offer(two_hazard_loss_analysis())

    assert offer.hazard_ids == ("H-1", "H-2")
    assert offer.constraint_ids == ("SC-1", "SC-2")
    assert main_rule_offer(two_hazard_loss_analysis(), ()) == offer


def test_the_earlier_rule_offers_only_the_routed_hazards() -> None:
    offer = main_rule_offer(two_hazard_loss_analysis(), (route_to_first_slot(),))

    assert offer.hazard_ids == ("H-1",)
    assert offer.constraint_ids == ("SC-1",)


def test_the_report_lists_every_slot_with_its_own_and_offered_hazards() -> None:
    report = report_for(routed=False)

    slot_ids = {slot.slot_id for slot in create_slots(_control_structure())}
    assert {item.slot_id for item in report.slots} == slot_ids
    for item in report.slots:
        assert item.own_hazard_ids == ("H-1", "H-2")
        assert item.offered_hazard_ids == ("H-1", "H-2")
        assert item.missing_own_hazard_ids == ()
        assert item.main_rule_missing_own_hazard_ids == ()
    assert report.summary == SlotHazardOfferSummary(
        slots=len(slot_ids),
        routed_slots=0,
        shrunk_slots=0,
        shrunk_slots_under_main_rule=0,
    )


def test_the_report_counts_a_routed_slot_that_shrinks_under_the_earlier_rule() -> None:
    report = report_for(routed=True)

    routed = next(item for item in report.slots if item.slot_id == first_slot_id())
    assert len(routed.routed_obligation_ids) == 1
    assert routed.main_rule_offered_hazard_ids == ("H-1",)
    assert routed.main_rule_missing_own_hazard_ids == ("H-2",)
    assert routed.main_rule_missing_own_constraint_ids == ("SC-2",)
    assert report.summary.routed_slots == 1
    assert report.summary.shrunk_slots_under_main_rule == 1


def test_the_report_round_trips_through_yaml() -> None:
    report = report_for(routed=True)

    assert SlotHazardOfferReport.from_yaml(report.to_yaml()) == report


def test_a_summary_that_does_not_match_the_slots_is_rejected() -> None:
    report = report_for(routed=True)
    data = report.model_dump(mode="json")
    data["summary"]["shrunk_slots_under_main_rule"] = 0

    with pytest.raises(ValueError, match="does not reconcile"):
        SlotHazardOfferReport.model_validate(data)


def test_a_report_with_another_schema_version_is_rejected() -> None:
    data = (
        report_for(routed=False)
        .to_yaml()
        .replace("stpa-slot-hazard-offers-v1", "stpa-slot-hazard-offers-v0")
    )

    with pytest.raises(ValueError, match="Unsupported schema version"):
        SlotHazardOfferReport.from_yaml(data)


def test_routing_keeps_a_slots_own_hazards_in_its_offer() -> None:
    offer = slot_offer(two_hazard_loss_analysis(), (route_to_first_slot(),))

    assert offer.hazard_ids == ("H-1", "H-2")
    assert offer.constraint_ids == ("SC-1", "SC-2")


def test_routing_adds_a_routed_hazard_the_slot_does_not_own() -> None:
    route = route_to_first_slot().model_copy(
        update={"hazard_ids": ("H-9",), "constraint_ids": ("SC-9",)}
    )

    offer = slot_offer(two_hazard_loss_analysis(), (route,))

    assert offer.hazard_ids == ("H-1", "H-2", "H-9")
    assert offer.constraint_ids == ("SC-1", "SC-2", "SC-9")


def test_a_routed_slot_no_longer_shrinks_and_the_earlier_rule_stays_counted() -> None:
    report = report_for(routed=True)

    routed = next(item for item in report.slots if item.slot_id == first_slot_id())
    assert routed.offered_hazard_ids == ("H-1", "H-2")
    assert routed.missing_own_hazard_ids == ()
    assert routed.missing_own_constraint_ids == ()
    assert routed.main_rule_missing_own_hazard_ids == ("H-2",)
    assert report.summary.shrunk_slots == 0
    assert report.summary.shrunk_slots_under_main_rule == 1


def test_a_routed_slot_prompt_shows_the_hazards_no_route_names() -> None:
    request = next(
        item
        for item in routed_requests()
        if first_slot_id() in {slot.slot_id for slot in item.slots}
    )

    _system, user = build_synthesis_slot_prompts(
        target_id=request.target_id,
        slots=request.slots,
        routed_briefs=request.routed_briefs,
        routed_routes=request.routed_routes,
        loss_analysis=request.loss_analysis,
        control_structure=request.control_structure,
    )

    index = user.split("Compact target STPA index:", 1)[1].split("Obligation", 1)[0]
    assert "id: H-2" in index
    assert "id: SC-2" in index
