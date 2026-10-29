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
        "governing_pairs": ["SC-1/H-1"],
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


# --- a NOT_PROVIDED finding that repeats an INCORRECT finding --------------

_ROW_VALID = "CA-1-1:ctx-1"
_ROW_INVALID = "CA-1-1:ctx-2"


def _valued_structure():
    """CA-1-1 reads PM-1-1, so its context table has one row per value."""
    structure = _control_structure()
    [resp] = structure.responsibilities
    [part] = resp.process_model_parts
    [action] = resp.control_actions
    return structure.model_copy(
        update={
            "responsibilities": (
                resp.model_copy(
                    update={
                        "process_model_parts": (
                            part.model_copy(update={"values": ["valid", "invalid"]}),
                        ),
                        "control_actions": (
                            action.model_copy(
                                update={"process_model_refs": ["PM-1-1"]}
                            ),
                        ),
                    }
                ),
            )
        }
    )


def _two_slot_request() -> Any:
    structure = _valued_structure()
    by_type = {slot.uca_type.value: slot for slot in create_slots(structure)}
    base = _provider_slot_request()
    return base.model_copy(
        update={
            "slots": (by_type["INCORRECT"], by_type["NOT_PROVIDED"]),
            "control_structure": structure,
        }
    )


def _slot_finding(deviation: str, row: str | None) -> dict[str, Any]:
    return {**_finding(), "deviation": deviation, "context_row": row}


def _two_slot_payload(
    incorrect_row: str | None, omitted_row: str | None
) -> _SlotProviderPayload:
    request = _two_slot_request()
    incorrect, omitted = request.slots
    return _SlotProviderPayload.model_validate(
        {
            "filled_slots": [
                {
                    "slot_id": incorrect.slot_id,
                    "is_na": False,
                    "na_rationale": None,
                    "findings": [
                        _slot_finding(
                            "The request is validated against the wrong rule.",
                            incorrect_row,
                        )
                    ],
                    "consideration_results": [],
                },
                {
                    "slot_id": omitted.slot_id,
                    "is_na": False,
                    "na_rationale": None,
                    "findings": [
                        _slot_finding(
                            "The request is not validated before it is accepted.",
                            omitted_row,
                        )
                    ],
                    "consideration_results": [],
                },
            ]
        }
    )


class TestInvertedOmission:
    def test_an_omission_repeating_an_incorrect_finding_is_corrected(self) -> None:
        request = _two_slot_request()
        incorrect, omitted = request.slots

        with pytest.raises(ValueError) as raised:
            _validate_slot_payload_semantics(
                _two_slot_payload(_ROW_INVALID, _ROW_INVALID), request
            )

        assert str(raised.value) == (
            f"{omitted.slot_id} finding 0 repeats {incorrect.slot_id} finding 0: "
            f"both cite context row {_ROW_INVALID}, hazards H-1 and constraints "
            "SC-1. The NOT_PROVIDED finding states that omitting the action in "
            "that context causes the hazard, and the INCORRECT finding that "
            "providing it does. If providing the action in that context is the "
            "hazard, remove the NOT_PROVIDED finding (set the slot to N/A when "
            "no finding remains). Keep it only when the omission itself leads to "
            "a hazard or constraint the INCORRECT finding does not cite, and "
            "cite only those."
        )

    def test_findings_on_different_rows_pass(self) -> None:
        _validate_slot_payload_semantics(
            _two_slot_payload(_ROW_VALID, _ROW_INVALID), _two_slot_request()
        )

    def test_findings_that_cite_no_row_pass(self) -> None:
        _validate_slot_payload_semantics(
            _two_slot_payload(None, None), _two_slot_request()
        )
