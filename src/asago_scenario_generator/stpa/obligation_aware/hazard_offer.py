"""The hazards and constraints an ICA slot request offers the model.

A slot's own offer is what its request shows when no obligation is routed to
it: every hazard and security constraint of the loss analysis.  The earlier
rule (``main_rule_offer``) replaced that offer with the routed obligations'
hazards and constraints whenever a route named the slot, so routing could
hide the slot's own hazards from ICA analysis.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from asago_scenario_generator.models.slot_hazard_offer import (
    SlotHazardOffer,
    SlotHazardOfferReport,
    summarize_slot_hazard_offers,
)


@dataclass(frozen=True)
class HazardOffer:
    """Sorted hazard and constraint identities shown to one slot request."""

    hazard_ids: tuple[str, ...]
    constraint_ids: tuple[str, ...]


def own_offer(loss_analysis: Any) -> HazardOffer:
    """Return what a slot request shows without routing: everything."""
    return HazardOffer(
        tuple(sorted(item.hazard_id for item in loss_analysis.hazards)),
        tuple(
            sorted(item.constraint_id for item in loss_analysis.security_constraints)
        ),
    )


def _routed_ids(routes: Iterable[Any], field: str) -> tuple[str, ...]:
    return tuple(sorted({value for route in routes for value in getattr(route, field)}))


def main_rule_offer(loss_analysis: Any, routes: Sequence[Any]) -> HazardOffer:
    """Return the earlier rule's offer: the routed identities, if any."""
    own = own_offer(loss_analysis)
    return HazardOffer(
        _routed_ids(routes, "hazard_ids") or own.hazard_ids,
        _routed_ids(routes, "constraint_ids") or own.constraint_ids,
    )


def slot_offer(loss_analysis: Any, routes: Sequence[Any]) -> HazardOffer:
    """Return the hazards and constraints a slot request shows."""
    return main_rule_offer(loss_analysis, routes)


def _union(offers: Iterable[HazardOffer]) -> HazardOffer:
    values = tuple(offers)
    return HazardOffer(
        tuple(sorted({item for offer in values for item in offer.hazard_ids})),
        tuple(sorted({item for offer in values for item in offer.constraint_ids})),
    )


def _missing(own: tuple[str, ...], offered: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(sorted(set(own) - set(offered)))


def _slot_entry(slot_id: str, requests: Sequence[Any]) -> SlotHazardOffer:
    """Describe one slot over every request part that carried it."""
    own = own_offer(requests[0].loss_analysis)
    offered = _union(
        slot_offer(request.loss_analysis, request.routed_routes) for request in requests
    )
    main = _union(
        main_rule_offer(request.loss_analysis, request.routed_routes)
        for request in requests
    )
    return SlotHazardOffer(
        slot_id=slot_id,
        routed_obligation_ids=tuple(
            sorted(
                {
                    route.obligation_id
                    for request in requests
                    for route in request.routed_routes
                }
            )
        ),
        own_hazard_ids=own.hazard_ids,
        offered_hazard_ids=offered.hazard_ids,
        missing_own_hazard_ids=_missing(own.hazard_ids, offered.hazard_ids),
        missing_own_constraint_ids=_missing(own.constraint_ids, offered.constraint_ids),
        main_rule_offered_hazard_ids=main.hazard_ids,
        main_rule_missing_own_hazard_ids=_missing(own.hazard_ids, main.hazard_ids),
        main_rule_missing_own_constraint_ids=_missing(
            own.constraint_ids, main.constraint_ids
        ),
    )


def build_slot_hazard_offer_report(
    requests: Sequence[Any],
) -> SlotHazardOfferReport:
    """Report every slot's hazard offer from the slot requests sent for it."""
    by_slot: dict[str, list[Any]] = {}
    for request in requests:
        for slot in request.slots:
            by_slot.setdefault(slot.slot_id, []).append(request)
    offers = tuple(
        _slot_entry(slot_id, parts) for slot_id, parts in sorted(by_slot.items())
    )
    return SlotHazardOfferReport(
        slots=offers, summary=summarize_slot_hazard_offers(offers)
    )


__all__ = [
    "HazardOffer",
    "build_slot_hazard_offer_report",
    "main_rule_offer",
    "own_offer",
    "slot_offer",
]
