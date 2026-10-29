"""A correct control action that does not take effect is out of scope.

A finding whose controller issues the right action, which then has no effect
or is not carried out, describes a failure downstream of the controller, not
an unsafe control action.  The generator does not produce scenarios for it.

The fixture follows a recorded case: an INCORRECT slot whose bounded
correction rewrote the deviation to "the action is performed but fails to
prevent the harm", which the verifier then accepted as ``performed_unsafe``.
The verifier now reports such a review as ``performed_without_effect``, and
code rejects it deterministically: the verdict is ``contradictory`` with the
rejection reason ``correct_action_without_effect``, the rejection is final,
and the finding stops at ``ica_hazard_correct_action_without_effect``.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from asago_scenario_generator.stpa.obligation_aware.ica_verification import (
    CORRECT_ACTION_WITHOUT_EFFECT_CODE,
    ICA_VERIFICATION_EXCLUSION_CODES,
    IcaHazardVerificationCorrection,
    IcaHazardVerificationRequest,
    IcaHazardVerificationVerdict,
    filter_ica_considerations,
    verify_final_ica_batch,
)
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    build_ica_hazard_verification_prompts,
)
from tests.helpers.ica_hazard_verification import (
    _finding_pair,
    _request,
    _single_ica_inputs,
)
from tests.test_ica_absence_losses import _adapter, _Client
from tests.test_ica_hazard_attribution_canary import (
    _accounting_from_verified_consideration,
    _artifacts,
    _control_structure,
)

_WITHOUT_EFFECT = "correct_action_without_effect"
_STOP_REASON = "ica_hazard_correct_action_without_effect"


def _without_effect_request(
    uca_type: str = "INCORRECT",
) -> IcaHazardVerificationRequest:
    """A synthetic release-gate ICA whose rewritten deviation is ineffective."""
    base = _request().model_dump(exclude={"semantic_digest"})
    return IcaHazardVerificationRequest.model_validate(
        {
            **base,
            "slot_id": f"RESP-1:CA-1:{uca_type}",
            "ica_id": f"RESP-1:CA-1:{uca_type}:1",
            "uca_type": uca_type,
            "control_action_description": "Reject the release and raise a hold",
            "deviation": (
                "The control action 'Reject the release and raise a hold' is "
                "performed but fails to prevent the unsafe release from proceeding."
            ),
            "hazardous_context": "an unsafe release request is not rejected",
        }
    )


def _review(action_state: str, hazard_path: str = "supported") -> dict:
    return {
        "review_ref": "review-1",
        "rationale": (
            "The named action 'Reject the release and raise a hold' is performed "
            "as required but does not stop the release."
        ),
        "action_state": action_state,
        "hazard_path": hazard_path,
    }


@pytest.mark.parametrize("uca_type", ["INCORRECT", "NOT_PROVIDED", "WRONG_TIMING"])
def test_the_provider_rejects_a_correct_action_without_effect(
    tmp_path, uca_type: str
) -> None:
    request = _without_effect_request(uca_type)
    client = _Client(_review("performed_without_effect"))

    (result,) = _adapter(client, tmp_path).verify_ica_hazards((request,))

    assert result.verdict == "contradictory"
    assert result.rejection_reason == _WITHOUT_EFFECT
    assert result.rationale.startswith(
        "Observed action state: performed_without_effect;"
    )
    assert len(client.user_prompts) == 1


def test_an_unsafe_performance_is_still_supported(tmp_path) -> None:
    request = _without_effect_request()
    client = _Client(_review("performed_unsafe"))

    (result,) = _adapter(client, tmp_path).verify_ica_hazards((request,))

    assert result.verdict == "supported"
    assert result.rejection_reason is None
    assert "rejection_reason" not in result.model_dump(mode="json")


def test_the_rejection_reason_belongs_to_contradictory_only() -> None:
    for verdict in ("supported", "insufficient_evidence"):
        with pytest.raises(ValidationError, match="contradictory"):
            IcaHazardVerificationVerdict(
                ica_id="i",
                verdict=verdict,
                rationale="r",
                rejection_reason=_WITHOUT_EFFECT,
            )


def test_the_prompt_names_the_state_and_explains_it() -> None:
    system, _ = build_ica_hazard_verification_prompts((_without_effect_request(),))

    assert "`performed_without_effect`" in system
    assert "one of the seven states above" in system


_REJECTED = {
    "verdict": "contradictory",
    "rejection_reason": _WITHOUT_EFFECT,
    "rationale": "Observed action state: performed_without_effect; the hold is "
    "raised but the release proceeds.",
}


class _RejectingVerifier:
    """Rejects the first verdict; a correction round gets the given verdict."""

    def __init__(self, first: dict | None = None, second: dict | None = None) -> None:
        self.first = first or _REJECTED
        self.second = second
        self.verification_calls = 0
        self.corrections = 0

    def verify_ica_hazards(self, requests, *, correction=False):
        self.verification_calls += 1
        verdict = self.second if correction else self.first
        assert verdict is not None
        return [{"ica_id": request.ica_id, **verdict} for request in requests]

    def correct_ica_hazard(self, request, verdict):
        self.corrections += 1
        return IcaHazardVerificationCorrection(
            ica_id=request.ica_id,
            deviation=(
                "The control action is performed but fails to prevent the unsafe "
                "release from proceeding."
            ),
            rationale="Make the action occur and fail to take effect.",
        )


def _verify(adapter):
    enumeration, loss_analysis, control_structure = _single_ica_inputs()
    filtered, batch = verify_final_ica_batch(
        adapter,
        enumeration,
        loss_analysis=loss_analysis,
        control_structure=control_structure,
    )
    return enumeration, filtered, batch


def _codes(batch) -> set[str]:
    return {item.code for item in batch.diagnostics}


def test_the_rejection_is_final_and_earns_no_author_correction() -> None:
    adapter = _RejectingVerifier()

    _, filtered, batch = _verify(adapter)

    (record,) = batch.records
    assert adapter.verification_calls == 1 and adapter.corrections == 0
    assert record.disposition == "excluded"
    assert record.final_verdict.rejection_reason == _WITHOUT_EFFECT
    assert len(record.attempts) == 1 and record.corrected_request is None
    assert _codes(batch) == {_STOP_REASON}
    assert filtered.slots[0].icas == []


def test_a_correction_that_makes_the_action_ineffective_is_rejected() -> None:
    """The recorded shape: the correction rewrites the deviation, then fails."""
    first = {"verdict": "contradictory", "rationale": "The rejection is not sent."}
    adapter = _RejectingVerifier(first=first, second=_REJECTED)

    enumeration, filtered, batch = _verify(adapter)

    (record,) = batch.records
    assert adapter.corrections == 1
    assert record.disposition == "excluded"
    assert record.final_verdict.rejection_reason == _WITHOUT_EFFECT
    assert _STOP_REASON in _codes(batch)
    pair = filter_ica_considerations(
        (_finding_pair(enumeration),), batch, enumeration=filtered
    )[0]
    assert pair.disposition == "unresolved"
    assert [item.code for item in pair.diagnostics] == [_STOP_REASON]


def test_the_filtered_consideration_carries_the_rejection_code() -> None:
    enumeration, filtered, batch = _verify(_RejectingVerifier())

    pair = filter_ica_considerations(
        (_finding_pair(enumeration),), batch, enumeration=filtered
    )[0]

    assert pair.disposition == "unresolved"
    assert [item.code for item in pair.diagnostics] == [_STOP_REASON]


def test_the_rejection_code_is_a_verifier_exclusion() -> None:
    assert CORRECT_ACTION_WITHOUT_EFFECT_CODE == _STOP_REASON
    assert _STOP_REASON in ICA_VERIFICATION_EXCLUSION_CODES


class _RejectsEveryICA:
    def verify_ica_hazards(self, requests, *, correction=False):
        del correction
        return [{"ica_id": request.ica_id, **_REJECTED} for request in requests]


def test_the_obligation_is_accounted_under_the_rejection_stop_reason() -> None:
    inputs, plan, loss, enumeration, pair = _artifacts()
    filtered, verification = verify_final_ica_batch(
        _RejectsEveryICA(),
        enumeration,
        loss_analysis=loss,
        control_structure=_control_structure(),
    )
    filtered_pairs = filter_ica_considerations(
        (pair,), verification, enumeration=filtered
    )

    accounting = _accounting_from_verified_consideration(
        inputs, plan, pair, filtered_pairs, verification, filtered
    )

    (row,) = accounting.rows
    assert row.disposition == "unresolved"
    assert row.stop_reason == _STOP_REASON
