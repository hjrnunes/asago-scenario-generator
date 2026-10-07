"""A hazardous absence names the losses it leads to and one consequence."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.obligation_aware.contracts import AnalysisControls
from asago_scenario_generator.stpa.obligation_aware.ica_verification import (
    IcaConstraintContext,
    IcaHazardContext,
    IcaHazardVerificationRequest,
    IcaHazardVerificationVerdict,
    IcaLossContext,
    _coerce_provider_result,
    absence_evidence_defects,
    requires_absence_evidence,
)
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    build_ica_hazard_verification_prompts,
)
from asago_scenario_generator.stpa.obligation_aware.provider import (
    ObligationAwareLLMAdapter,
)
from tests.test_ica_hazard_verification import _request

_CONSEQUENCE = "No approval is requested, so the release proceeds unchecked."


def _absence_request(uca_type: str = "NOT_PROVIDED") -> IcaHazardVerificationRequest:
    base = _request().model_dump(exclude={"semantic_digest"})
    return IcaHazardVerificationRequest.model_validate(
        {
            **base,
            "slot_id": f"RESP-1:CA-1:{uca_type}",
            "ica_id": f"RESP-1:CA-1:{uca_type}:1",
            "uca_type": uca_type,
            "hazards": (
                IcaHazardContext(
                    hazard_id="H-1",
                    description="An unsafe release is accepted.",
                    related_loss_ids=("L-1",),
                ),
                IcaHazardContext(
                    hazard_id="H-2",
                    description="A release is delayed.",
                    related_loss_ids=("L-2",),
                ),
            ),
            "constraints": (
                IcaConstraintContext(
                    constraint_id="SC-1",
                    description="The release gate must be satisfied before approval.",
                    related_hazard_ids=("H-1", "H-2"),
                ),
            ),
            "losses": (
                IcaLossContext(loss_id="L-1", description="Integrity is lost."),
                IcaLossContext(loss_id="L-2", description="Availability is lost."),
            ),
        }
    )


def _verdict(**extra) -> dict:
    return {
        "review_ref": "review-1",
        "rationale": "The approval is never requested.",
        "action_state": "absent",
        "hazard_path": "supported",
        **extra,
    }


class _Client:
    model = "absence-offline"

    def __init__(self, *responses: dict) -> None:
        self.responses = list(responses)
        self.user_prompts: list[str] = []

    def complete(self, **kwargs):
        self.user_prompts.append(kwargs["user_prompt"])
        return LLMResult(
            content={"verdicts": [self.responses.pop(0)]},
            prompt_tokens=1,
            completion_tokens=1,
            duration_ms=1,
            system_prompt=kwargs["system_prompt"],
            user_prompt=kwargs["user_prompt"],
        )


def _adapter(client, tmp_path) -> ObligationAwareLLMAdapter:
    return ObligationAwareLLMAdapter(
        client,
        run_dir=tmp_path,
        controls=AnalysisControls(
            model_profile="offline",
            model_name=client.model,
            temperature=0.0,
            deadline_seconds=30.0,
        ),
    )


def test_only_a_supported_absence_needs_evidence() -> None:
    absent = _absence_request("NOT_PROVIDED")
    other = _absence_request("INCORRECT")

    assert requires_absence_evidence(absent, "supported")
    assert not requires_absence_evidence(absent, "contradictory")
    assert not requires_absence_evidence(absent, "insufficient_evidence")
    assert not requires_absence_evidence(other, "supported")


def test_complete_evidence_has_no_defects() -> None:
    request = _absence_request()

    assert (
        absence_evidence_defects(
            request, loss_ids=("L-1", "L-2"), consequence=_CONSEQUENCE
        )
        == ()
    )


@pytest.mark.parametrize(
    ("loss_ids", "consequence", "needle"),
    [
        ((), _CONSEQUENCE, "at least one loss"),
        (("L-9",), _CONSEQUENCE, "L-9"),
        (("L-1",), "", "consequence"),
        (("L-1",), "   ", "consequence"),
        (("L-1",), "first line\nsecond line", "one line"),
        (("L-1",), "x" * 301, "300"),
    ],
)
def test_each_defect_is_named(loss_ids, consequence, needle) -> None:
    defects = absence_evidence_defects(
        _absence_request(), loss_ids=loss_ids, consequence=consequence
    )

    assert len(defects) == 1
    assert needle in defects[0]


def test_an_unreachable_loss_is_reported_with_the_reachable_ones() -> None:
    (defect,) = absence_evidence_defects(
        _absence_request(), loss_ids=("L-9",), consequence=_CONSEQUENCE
    )

    assert "L-1" in defect and "L-2" in defect


def test_the_verdict_carries_the_evidence_only_when_it_is_given() -> None:
    plain = IcaHazardVerificationVerdict(
        ica_id="i", verdict="supported", rationale="r"
    ).model_dump(mode="json")
    full = IcaHazardVerificationVerdict(
        ica_id="i",
        verdict="supported",
        rationale="r",
        absence_loss_ids=("L-2", "L-1"),
        absence_consequence=_CONSEQUENCE,
    )

    assert set(plain) == {"ica_id", "request_digest", "verdict", "rationale"}
    assert full.absence_loss_ids == ("L-1", "L-2")
    assert full.model_dump(mode="json")["absence_consequence"] == _CONSEQUENCE


@pytest.mark.parametrize(
    "extra",
    [
        {"absence_loss_ids": ("L-1",)},
        {"absence_consequence": _CONSEQUENCE},
        {"absence_loss_ids": (), "absence_consequence": _CONSEQUENCE},
    ],
)
def test_the_verdict_takes_both_pieces_of_evidence_or_neither(extra) -> None:
    with pytest.raises(ValidationError, match="together"):
        IcaHazardVerificationVerdict(
            ica_id="i", verdict="supported", rationale="r", **extra
        )


@pytest.mark.parametrize("verdict", ["contradictory", "insufficient_evidence"])
def test_only_a_supported_verdict_carries_evidence(verdict) -> None:
    with pytest.raises(ValidationError, match="supported"):
        IcaHazardVerificationVerdict(
            ica_id="i",
            verdict=verdict,
            rationale="r",
            absence_loss_ids=("L-1",),
            absence_consequence=_CONSEQUENCE,
        )


def test_the_provider_returns_the_named_losses_and_consequence(tmp_path) -> None:
    request = _absence_request()
    client = _Client(
        _verdict(
            absence_loss_ids=["L-2", "L-1", "L-2"], absence_consequence=_CONSEQUENCE
        )
    )

    (result,) = _adapter(client, tmp_path).verify_ica_hazards((request,))

    assert result.verdict == "supported"
    assert result.absence_loss_ids == ("L-1", "L-2")
    assert result.absence_consequence == _CONSEQUENCE
    assert len(client.user_prompts) == 1


def test_a_missing_loss_earns_one_repair_with_the_exact_feedback(tmp_path) -> None:
    request = _absence_request()
    client = _Client(
        _verdict(),
        _verdict(absence_loss_ids=["L-1"], absence_consequence=_CONSEQUENCE),
    )

    (result,) = _adapter(client, tmp_path).verify_ica_hazards((request,))

    assert len(client.user_prompts) == 2
    repair = client.user_prompts[1]
    assert client.user_prompts[0] in repair
    assert "review-1" in repair
    assert "at least one loss" in repair
    assert "L-1" in repair and "L-2" in repair
    assert request.ica_id not in repair
    assert "NOT_PROVIDED" not in repair
    assert result.absence_loss_ids == ("L-1",)


def test_an_unreachable_loss_is_repaired_once_and_then_fails(tmp_path) -> None:
    request = _absence_request()
    bad = _verdict(absence_loss_ids=["L-9"], absence_consequence=_CONSEQUENCE)
    client = _Client(bad, bad, bad)

    with pytest.raises(ValueError, match="L-9"):
        _adapter(client, tmp_path).verify_ica_hazards((request,))

    assert len(client.user_prompts) == 2


def test_a_verdict_without_a_hazardous_absence_needs_no_evidence(tmp_path) -> None:
    for request, response in (
        (_absence_request("INCORRECT"), _verdict(action_state="performed_unsafe")),
        (_absence_request("NOT_PROVIDED"), _verdict(hazard_path="contradictory")),
        (
            _absence_request("NOT_PROVIDED"),
            _verdict(hazard_path="insufficient_evidence"),
        ),
    ):
        client = _Client(response)

        (result,) = _adapter(client, tmp_path).verify_ica_hazards((request,))

        assert len(client.user_prompts) == 1
        assert result.absence_loss_ids == ()
        assert result.absence_consequence is None


def test_evidence_on_a_verdict_that_does_not_need_it_is_not_kept(tmp_path) -> None:
    request = _absence_request("INCORRECT")
    client = _Client(
        _verdict(
            action_state="performed_unsafe",
            absence_loss_ids=["L-9"],
            absence_consequence=_CONSEQUENCE,
        )
    )

    (result,) = _adapter(client, tmp_path).verify_ica_hazards((request,))

    assert result.absence_loss_ids == ()
    assert len(client.user_prompts) == 1


def test_the_prompt_explains_the_new_fields_and_keeps_the_reviewer_blind() -> None:
    request = _absence_request()

    system, user = build_ica_hazard_verification_prompts((request,))

    for field in ("absence_loss_ids", "absence_consequence"):
        assert f"`{field}`" in system
    assert "loss_id" in user
    assert "uca_type" not in user
    assert "NOT_PROVIDED" not in system + user


def test_the_seam_rejects_a_supported_absence_without_evidence() -> None:
    request = _absence_request()
    bare = IcaHazardVerificationVerdict(
        ica_id=request.ica_id, verdict="supported", rationale="r"
    )

    with pytest.raises(ValueError, match="at least one loss"):
        _coerce_provider_result((bare,), (request,))


def test_the_seam_rejects_an_unreachable_loss() -> None:
    request = _absence_request()
    stray = IcaHazardVerificationVerdict(
        ica_id=request.ica_id,
        verdict="supported",
        rationale="r",
        absence_loss_ids=("L-9",),
        absence_consequence=_CONSEQUENCE,
    )

    with pytest.raises(ValueError, match="L-9"):
        _coerce_provider_result((stray,), (request,))


def test_the_seam_accepts_complete_evidence_and_other_verdicts() -> None:
    absent = _absence_request()
    other = _absence_request("INCORRECT")
    full = IcaHazardVerificationVerdict(
        ica_id=absent.ica_id,
        verdict="supported",
        rationale="r",
        absence_loss_ids=("L-1",),
        absence_consequence=_CONSEQUENCE,
    )
    plain = IcaHazardVerificationVerdict(
        ica_id=other.ica_id, verdict="supported", rationale="r"
    )

    results = _coerce_provider_result((full, plain), (absent, other))

    assert [item.absence_loss_ids for item in results] == [("L-1",), ()]
