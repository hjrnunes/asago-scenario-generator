"""Finding-pair evidence must match the filled slot it cites."""

from __future__ import annotations

from typing import Any

import pytest

from asago_scenario_generator.models.obligation_consideration import (
    ObligationIcaConsideration,
)
from asago_scenario_generator.stpa.models.ica_enumeration import (
    ICA,
    ICASlot,
    candidate_id_for,
)
from asago_scenario_generator.stpa.obligation_aware.contracts import ObligationRoute
from asago_scenario_generator.stpa.obligation_aware.slot_filling import _validate_pair
from asago_scenario_generator.stpa.threat_enum.slot_creation import create_slots

from tests.helpers.obligation_aware import _control_structure

_SLOT = create_slots(_control_structure())[0]
_ICA_ID = f"{_SLOT.slot_id}:1"


def _route() -> ObligationRoute:
    return ObligationRoute(
        obligation_id="ob:v1:" + "a" * 64,
        disposition="targeted",
        slot_ids=(_SLOT.slot_id,),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        evidence=("route",),
    )


def _filled(*, is_na: bool = False) -> ICASlot:
    return ICASlot(
        slot_id=_SLOT.slot_id,
        responsibility=_SLOT.responsibility,
        coordination_link=_SLOT.coordination_link,
        control_action=_SLOT.control_action,
        uca_type=_SLOT.uca_type,
        is_na=is_na,
        na_justification="No finding applies." if is_na else None,
        icas=[]
        if is_na
        else [
            ICA(
                ica_id=_ICA_ID,
                ica_text="An unsafe action is issued.",
                hazardous_context="The request is unsafe.",
                loss_scenario="The operation is harmed.",
                related_hazards=["H-1"],
                related_constraints=["SC-1"],
            )
        ],
    )


def _pair(**overrides: Any) -> ObligationIcaConsideration:
    route = _route()
    fields: dict[str, Any] = {
        "route_id": route.route_id,
        "obligation_id": route.obligation_id,
        "slot_id": _SLOT.slot_id,
        "disposition": "finding",
        "ica_ids": (_ICA_ID,),
        "exec_candidate_ids": (
            candidate_id_for(
                _SLOT.responsibility or _SLOT.coordination_link,
                _SLOT.control_action,
                _SLOT.uca_type,
            ),
        ),
        "hazard_ids": ("H-1",),
        "constraint_ids": ("SC-1",),
        "evidence": ("pair",),
    }
    fields.update(overrides)
    return ObligationIcaConsideration(**fields)


def _validate(pair: ObligationIcaConsideration, filled: ICASlot | None):
    filled_by_id = {} if filled is None else {_SLOT.slot_id: filled}
    return _validate_pair(pair, _route(), _SLOT, filled_by_id)


class TestFindingPairValidation:
    def test_pair_matching_its_ica_is_returned(self) -> None:
        pair = _pair()

        assert _validate(pair, _filled()) is pair

    def test_exec_identity_must_be_the_slot_canonical_one(self) -> None:
        pair = _pair(exec_candidate_ids=("EXEC:RESP-9:CA-9-9:INCORRECT",))

        with pytest.raises(ValueError, match="canonical EXEC identity"):
            _validate(pair, _filled())

    def test_missing_filled_slot_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="requires a non-N/A filled slot"):
            _validate(_pair(), None)

    def test_na_filled_slot_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="requires a non-N/A filled slot"):
            _validate(_pair(), _filled(is_na=True))

    def test_ica_outside_the_slot_is_rejected(self) -> None:
        pair = _pair(ica_ids=(f"{_SLOT.slot_id}:2",))

        with pytest.raises(ValueError, match="ICA outside its slot"):
            _validate(pair, _filled())

    def test_hazards_must_match_the_referenced_ica(self) -> None:
        pair = _pair(hazard_ids=("H-1", "H-extra"))

        with pytest.raises(ValueError, match="hazards must exactly match"):
            _validate(pair, _filled())

    def test_constraints_must_match_the_referenced_ica(self) -> None:
        pair = _pair(constraint_ids=("SC-1", "SC-extra"))

        with pytest.raises(ValueError, match="constraints must exactly match"):
            _validate(pair, _filled())
