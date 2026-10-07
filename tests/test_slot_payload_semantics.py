"""Semantic checks on a provider slot payload before it is compiled."""

from __future__ import annotations

from typing import Any

import pytest

from asago_scenario_generator.stpa.obligation_aware.contracts import ObligationRoute
from asago_scenario_generator.stpa.obligation_aware.provider import (
    _SlotProviderPayload,
    _validate_slot_payload_semantics,
)
from asago_scenario_generator.stpa.threat_enum.slot_creation import create_slots

from tests.helpers.obligation_aware import _control_structure, _provider_slot_request

_OBLIGATION_ID = "ob:v1:" + "b" * 64
_HANDLE = _OBLIGATION_ID


def _slot_id() -> str:
    return create_slots(_control_structure())[0].slot_id


def _route() -> ObligationRoute:
    return ObligationRoute(
        obligation_id=_OBLIGATION_ID,
        disposition="targeted",
        slot_ids=(_slot_id(),),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        evidence=("provider-route",),
    )


def _finding() -> dict[str, Any]:
    return {
        "deviation": "Validation is not provided before the request is accepted.",
        "hazardous_context": "An unsafe request reaches the process unvalidated.",
        "loss_consequence": "A protected operation is harmed.",
        "related_hazard_ids": ["H-1"],
        "related_constraint_ids": ["SC-1"],
        "process_model_refs": ["PM-1-1"],
        "feedback_refs": ["FB-1-1"],
        "context_row": None,
    }


def _result(disposition: str, *indexes: int) -> dict[str, Any]:
    return {
        "obligation_handle": _HANDLE,
        "disposition": disposition,
        "finding_indexes": list(indexes),
        "rationale": "The structure decides this.",
    }


def _payload(
    *,
    is_na: bool = False,
    results: tuple[dict[str, Any], ...] = (),
    slot_id: str | None = None,
) -> _SlotProviderPayload:
    return _SlotProviderPayload.model_validate(
        {
            "filled_slots": [
                {
                    "slot_id": slot_id or _slot_id(),
                    "is_na": is_na,
                    "na_rationale": "No finding applies." if is_na else None,
                    "findings": [] if is_na else [_finding()],
                    "consideration_results": list(results),
                }
            ]
        }
    )


class TestValidateSlotPayloadSemantics:
    def test_finding_result_with_a_valid_index_passes(self) -> None:
        request = _provider_slot_request(routed_routes=(_route(),))

        _validate_slot_payload_semantics(
            _payload(results=(_result("finding", 0),)), request
        )

    def test_not_applicable_result_on_an_na_slot_passes(self) -> None:
        request = _provider_slot_request(routed_routes=(_route(),))

        _validate_slot_payload_semantics(
            _payload(is_na=True, results=(_result("proposed_not_applicable"),)),
            request,
        )

    def test_unresolved_result_passes_for_either_slot_shape(self) -> None:
        request = _provider_slot_request(routed_routes=(_route(),))

        _validate_slot_payload_semantics(
            _payload(results=(_result("unresolved"),)), request
        )
        _validate_slot_payload_semantics(
            _payload(is_na=True, results=(_result("unresolved"),)), request
        )

    def test_payload_without_results_passes_with_no_routes(self) -> None:
        _validate_slot_payload_semantics(_payload(), _provider_slot_request())

    def test_unknown_slot_is_rejected(self) -> None:
        request = _provider_slot_request(routed_routes=(_route(),))

        with pytest.raises(ValueError, match="references unknown slot RESP-9:CA-9"):
            _validate_slot_payload_semantics(_payload(slot_id="RESP-9:CA-9"), request)

    def test_result_for_an_unrouted_pair_is_rejected(self) -> None:
        request = _provider_slot_request()

        with pytest.raises(ValueError, match="that is not routed to this target"):
            _validate_slot_payload_semantics(
                _payload(results=(_result("finding", 0),)), request
            )

    def test_finding_result_on_an_na_slot_is_rejected(self) -> None:
        request = _provider_slot_request(routed_routes=(_route(),))

        with pytest.raises(ValueError, match="requires a non-N/A slot draft"):
            _validate_slot_payload_semantics(
                _payload(is_na=True, results=(_result("finding", 0),)), request
            )

    def test_finding_index_outside_the_slot_is_rejected(self) -> None:
        request = _provider_slot_request(routed_routes=(_route(),))

        with pytest.raises(ValueError, match="finding index is outside its slot"):
            _validate_slot_payload_semantics(
                _payload(results=(_result("finding", 0, 1),)), request
            )

    def test_not_applicable_result_on_a_findings_slot_is_rejected(self) -> None:
        request = _provider_slot_request(routed_routes=(_route(),))

        with pytest.raises(ValueError, match="requires an N/A slot draft"):
            _validate_slot_payload_semantics(
                _payload(results=(_result("proposed_not_applicable"),)), request
            )
