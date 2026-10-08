"""The hazards and constraints each ICA slot request offered the model.

A slot's own offer is what its request shows without routing.  Routing may
add routed obligations' hazards and constraints to it.  The report lists, per
slot, the own and offered hazards and any own hazard the offer lacks, beside
what the earlier rule offered (only the routed hazards whenever a route named
the slot), so a run under either rule shows how many slots shrank.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field, model_validator

from asago_scenario_generator.models.canonical import (
    CanonicalYamlMixin,
    ClosedCanonicalModel,
)

SLOT_HAZARD_OFFER_SCHEMA_VERSION = "stpa-slot-hazard-offers-v1"


class SlotHazardOffer(ClosedCanonicalModel):
    """One slot's own offer, its actual offer, and the earlier rule's offer."""

    slot_id: str = Field(min_length=1)
    routed_obligation_ids: tuple[str, ...] = ()
    own_hazard_ids: tuple[str, ...]
    offered_hazard_ids: tuple[str, ...]
    missing_own_hazard_ids: tuple[str, ...] = ()
    missing_own_constraint_ids: tuple[str, ...] = ()
    main_rule_offered_hazard_ids: tuple[str, ...]
    main_rule_missing_own_hazard_ids: tuple[str, ...] = ()
    main_rule_missing_own_constraint_ids: tuple[str, ...] = ()

    @property
    def shrunk(self) -> bool:
        """Tell whether the actual offer lacks an own hazard."""
        return bool(self.missing_own_hazard_ids)

    @property
    def shrunk_under_main_rule(self) -> bool:
        """Tell whether the earlier rule's offer lacks an own hazard."""
        return bool(self.main_rule_missing_own_hazard_ids)


class SlotHazardOfferSummary(ClosedCanonicalModel):
    """Slot counts derived from the per-slot offers."""

    slots: int = Field(ge=0, strict=True)
    routed_slots: int = Field(ge=0, strict=True)
    shrunk_slots: int = Field(ge=0, strict=True)
    shrunk_slots_under_main_rule: int = Field(ge=0, strict=True)


def summarize_slot_hazard_offers(
    offers: tuple[SlotHazardOffer, ...],
) -> SlotHazardOfferSummary:
    """Count slots, routed slots, and shrunk slots under each rule."""
    return SlotHazardOfferSummary(
        slots=len(offers),
        routed_slots=sum(bool(item.routed_obligation_ids) for item in offers),
        shrunk_slots=sum(item.shrunk for item in offers),
        shrunk_slots_under_main_rule=sum(
            item.shrunk_under_main_rule for item in offers
        ),
    )


class SlotHazardOfferReport(CanonicalYamlMixin, ClosedCanonicalModel):
    """Every slot request's hazard offer, with a reconciled summary."""

    schema_version: Literal["stpa-slot-hazard-offers-v1"] = (
        SLOT_HAZARD_OFFER_SCHEMA_VERSION
    )
    slots: tuple[SlotHazardOffer, ...] = ()
    summary: SlotHazardOfferSummary

    @model_validator(mode="after")
    def order_and_reconcile(self) -> "SlotHazardOfferReport":
        ordered = tuple(sorted(self.slots, key=lambda item: item.slot_id))
        if len({item.slot_id for item in ordered}) != len(ordered):
            raise ValueError("slot hazard offers must name each slot once")
        object.__setattr__(self, "slots", ordered)
        self.assert_integrity()
        return self

    def assert_integrity(self) -> None:
        """Require the summary to match the per-slot offers."""
        if self.summary != summarize_slot_hazard_offers(self.slots):
            raise ValueError("slot hazard offer summary does not reconcile")

    @classmethod
    def _load_checked(cls, data: dict[str, Any]) -> "SlotHazardOfferReport":
        if data.get("schema_version") != SLOT_HAZARD_OFFER_SCHEMA_VERSION:
            raise ValueError(
                f"Unsupported schema version: '{data.get('schema_version')}'"
            )
        return cls.model_validate(data)


SLOT_HAZARD_OFFERS_FILENAME = "slot-hazard-offers.yaml"

__all__ = [
    "SLOT_HAZARD_OFFERS_FILENAME",
    "SLOT_HAZARD_OFFER_SCHEMA_VERSION",
    "SlotHazardOffer",
    "SlotHazardOfferReport",
    "SlotHazardOfferSummary",
    "summarize_slot_hazard_offers",
]
