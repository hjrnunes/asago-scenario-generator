"""A hazardous absence names the losses it leads to and one consequence."""

from __future__ import annotations


import pytest
from pydantic import ValidationError

from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.infra.provider_record import ProviderCallSession
from asago_scenario_generator.stpa.obligation_aware.contracts import AnalysisControls
from asago_scenario_generator.stpa.obligation_aware.ica_verification import (
    IcaConstraintContext,
    IcaHazardContext,
    IcaHazardVerificationBatch,
    IcaHazardVerificationCorrection,
    IcaHazardVerificationRequest,
    IcaHazardVerificationVerdict,
    IcaLossContext,
    _coerce_provider_result,
    absence_evidence_defects,
    filter_ica_considerations,
    requires_absence_evidence,
    verify_final_ica_batch,
)
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    build_ica_hazard_verification_prompts,
)
from asago_scenario_generator.stpa.obligation_aware.provider import (
    ObligationAwareLLMAdapter,
)
from tests.helpers.calls_log import read_calls_jsonl
from tests.helpers.ica_hazard_verification import (
    _finding_pair,
    _request,
    _single_ica_inputs,
)

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

    def __init__(self, *responses: dict | list[dict]) -> None:
        self.responses = list(responses)
        self.user_prompts: list[str] = []

    def complete(self, **kwargs):
        self.user_prompts.append(kwargs["user_prompt"])
        response = self.responses.pop(0)
        return LLMResult(
            content={
                "verdicts": response if isinstance(response, list) else [response]
            },
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


def _assert_downgraded(result: IcaHazardVerificationVerdict, needle: str) -> None:
    assert result.verdict == "insufficient_evidence"
    assert result.downgrade_reason == "absence_evidence_missing"
    assert result.absence_loss_ids == ()
    assert result.absence_consequence is None
    assert needle in result.rationale


def test_an_unreachable_loss_is_repaired_once_and_then_downgraded(tmp_path) -> None:
    request = _absence_request()
    bad = _verdict(absence_loss_ids=["L-9"], absence_consequence=_CONSEQUENCE)
    client = _Client(bad, bad, bad)

    (result,) = _adapter(client, tmp_path).verify_ica_hazards((request,))

    assert len(client.user_prompts) == 2
    _assert_downgraded(result, "L-9")


def test_missing_evidence_after_the_repair_downgrades_the_verdict(tmp_path) -> None:
    request = _absence_request()
    client = _Client(_verdict(), _verdict(absence_loss_ids=["L-1"]), _verdict())

    (result,) = _adapter(client, tmp_path).verify_ica_hazards((request,))

    assert len(client.user_prompts) == 2
    _assert_downgraded(result, "consequence")


def test_a_downgrade_keeps_the_verifiers_rationale(tmp_path) -> None:
    client = _Client(_verdict(), _verdict())

    (result,) = _adapter(client, tmp_path).verify_ica_hazards((_absence_request(),))

    assert "The approval is never requested." in result.rationale


def test_other_verdicts_stand_when_one_is_downgraded(tmp_path) -> None:
    absent, other = _absence_request(), _absence_request("INCORRECT")
    first = _verdict()
    second = _verdict(review_ref="review-2", action_state="performed_unsafe")
    client = _Client([first, second], [first, second])

    results = {
        item.ica_id: item
        for item in _adapter(client, tmp_path).verify_ica_hazards((absent, other))
    }

    assert len(client.user_prompts) == 2
    _assert_downgraded(results[absent.ica_id], "at least one loss")
    assert results[other.ica_id].verdict == "supported"
    assert results[other.ica_id].downgrade_reason is None
    feedback = client.user_prompts[1].split("Exact validation error")[1]
    assert "review-1" in feedback
    assert "review-2" not in feedback


def test_a_repair_that_fixes_the_evidence_is_not_downgraded(tmp_path) -> None:
    client = _Client(
        _verdict(),
        _verdict(absence_loss_ids=["L-1"], absence_consequence=_CONSEQUENCE),
    )

    (result,) = _adapter(client, tmp_path).verify_ica_hazards((_absence_request(),))

    assert result.verdict == "supported"
    assert result.downgrade_reason is None


def test_a_response_that_fails_its_schema_still_leaves_one_repair_for_evidence(
    tmp_path,
) -> None:
    broken = _verdict(action_state="not-a-state")
    client = _Client(broken, _verdict(), _verdict())

    (result,) = _adapter(client, tmp_path).verify_ica_hazards((_absence_request(),))

    assert len(client.user_prompts) == 2
    _assert_downgraded(result, "at least one loss")


def test_the_repair_response_is_logged_as_a_published_call(tmp_path) -> None:
    client = _Client(_verdict(), _verdict())

    _adapter(client, tmp_path).verify_ica_hazards((_absence_request(),))

    entries = read_calls_jsonl(tmp_path)
    assert [item["success"] for item in entries] == [False, True]
    assert entries[-1]["published"] is True


def test_the_repair_through_a_session_is_one_published_record_in_the_session(
    tmp_path,
) -> None:
    session = ProviderCallSession(record_dir=tmp_path)
    client = _Client(_verdict(), _verdict())
    client.session = session

    _adapter(client, tmp_path).verify_ica_hazards((_absence_request(),))

    recorded = session.call_log.entries(tmp_path)
    assert len(client.user_prompts) == 2
    assert [item["success"] for item in recorded] == [False, True]
    assert recorded[-1]["published"] is True
    assert recorded == read_calls_jsonl(tmp_path)


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


def test_the_seam_downgrades_a_supported_absence_without_evidence() -> None:
    request = _absence_request()
    bare = IcaHazardVerificationVerdict(
        ica_id=request.ica_id, verdict="supported", rationale="r"
    )

    (result,) = _coerce_provider_result((bare,), (request,))

    _assert_downgraded(result, "at least one loss")
    assert result.request_digest == request.semantic_digest


def test_the_seam_downgrades_an_unreachable_loss() -> None:
    request = _absence_request()
    stray = IcaHazardVerificationVerdict(
        ica_id=request.ica_id,
        verdict="supported",
        rationale="r",
        absence_loss_ids=("L-9",),
        absence_consequence=_CONSEQUENCE,
    )

    (result,) = _coerce_provider_result((stray,), (request,))

    _assert_downgraded(result, "L-9")


def test_the_seam_leaves_a_downgraded_verdict_as_it_is() -> None:
    request = _absence_request()
    (first,) = _coerce_provider_result(
        (
            IcaHazardVerificationVerdict(
                ica_id=request.ica_id, verdict="supported", rationale="r"
            ),
        ),
        (request,),
    )

    assert _coerce_provider_result((first,), (request,)) == (first,)


def test_a_downgrade_reason_belongs_to_insufficient_evidence_only() -> None:
    for verdict in ("supported", "contradictory"):
        with pytest.raises(ValidationError, match="insufficient_evidence"):
            IcaHazardVerificationVerdict(
                ica_id="i",
                verdict=verdict,
                rationale="r",
                downgrade_reason="absence_evidence_missing",
            )


def test_the_downgrade_reason_is_left_out_when_absent() -> None:
    plain = IcaHazardVerificationVerdict(
        ica_id="i", verdict="insufficient_evidence", rationale="r"
    )
    downgraded = plain.model_copy(
        update={"downgrade_reason": "absence_evidence_missing"}
    )

    assert "downgrade_reason" not in plain.model_dump(mode="json")
    assert (
        downgraded.model_dump(mode="json")["downgrade_reason"]
        == "absence_evidence_missing"
    )


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


_DOWNGRADED = {
    "verdict": "insufficient_evidence",
    "downgrade_reason": "absence_evidence_missing",
    "rationale": "The absence names no loss it leads to.",
}


class _DowngradingVerifier:
    """Downgrades the first verdict; a correction round gets the given verdict."""

    def __init__(self, second: dict | None = None) -> None:
        self.second = second
        self.verification_calls = 0
        self.corrections = 0

    def verify_ica_hazards(self, requests, *, correction_feedback=None):
        self.verification_calls += 1
        verdict = self.second if correction_feedback else _DOWNGRADED
        assert verdict is not None
        return [{"ica_id": request.ica_id, **verdict} for request in requests]

    def correct_ica_hazard(self, request, verdict):
        self.corrections += 1
        return IcaHazardVerificationCorrection(
            ica_id=request.ica_id,
            deviation=request.deviation + " with the missing timing fact",
            rationale="Add the missing typed timing fact.",
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


def test_a_downgraded_verdict_is_final_and_earns_no_author_correction() -> None:
    adapter = _DowngradingVerifier()

    _, filtered, batch = _verify(adapter)

    (record,) = batch.records
    assert adapter.verification_calls == 1 and adapter.corrections == 0
    assert record.disposition == "excluded"
    assert record.final_verdict is not None
    assert record.final_verdict.downgrade_reason == "absence_evidence_missing"
    assert len(record.attempts) == 1 and record.corrected_request is None
    assert filtered.slots[0].icas == []
    assert filtered.slots[0].unresolved_reason


def test_a_downgrade_is_counted_and_named_apart_from_insufficient_evidence() -> None:
    _, _, batch = _verify(_DowngradingVerifier())

    assert batch.absence_evidence_missing_count == 1
    assert batch.unsupported_count == 1 and batch.provider_failure_count == 0
    assert _codes(batch) == {"ica_hazard_absence_evidence_missing"}
    assert batch.model_dump(mode="json")["absence_evidence_missing_count"] == 1


def test_the_count_is_left_out_when_nothing_was_downgraded() -> None:
    class Supports:
        def verify_ica_hazards(self, requests, *, correction_feedback=None):
            return [
                {"ica_id": item.ica_id, "verdict": "supported", "rationale": "r"}
                for item in requests
            ]

    class Contradicts:
        def verify_ica_hazards(self, requests, *, correction_feedback=None):
            return [
                {"ica_id": item.ica_id, "verdict": "contradictory", "rationale": "r"}
                for item in requests
            ]

    _, _, batch = _verify(Supports())
    contradicts = _verify(Contradicts())[2]

    assert batch.absence_evidence_missing_count == 0
    assert "absence_evidence_missing_count" not in batch.model_dump(mode="json")
    assert "absence_evidence_missing_count" not in contradicts.model_dump(mode="json")


def test_a_wrong_supplied_count_is_rejected() -> None:
    _, _, batch = _verify(_DowngradingVerifier())

    with pytest.raises(ValidationError, match="absence_evidence_missing_count"):
        IcaHazardVerificationBatch(
            batch_id=batch.batch_id,
            records=batch.records,
            absence_evidence_missing_count=2,
        )


def test_a_downgrade_in_the_second_round_is_named_the_same_way() -> None:
    first = {"verdict": "contradictory", "rationale": "The first verdict rejects it."}

    class Rejects(_DowngradingVerifier):
        def verify_ica_hazards(self, requests, *, correction_feedback=None):
            if correction_feedback:
                return super().verify_ica_hazards(
                    requests, correction_feedback=correction_feedback
                )
            return [{"ica_id": item.ica_id, **first} for item in requests]

    adapter = Rejects(_DOWNGRADED)

    _, _, batch = _verify(adapter)

    (record,) = batch.records
    assert adapter.corrections == 1
    assert record.final_verdict.downgrade_reason == "absence_evidence_missing"
    assert batch.absence_evidence_missing_count == 1
    assert "ica_hazard_absence_evidence_missing" in _codes(batch)
    assert "ica_hazard_insufficient_evidence" not in _codes(batch)


def test_the_filtered_consideration_carries_the_downgrade_code() -> None:
    adapter = _DowngradingVerifier()
    enumeration, filtered, batch = _verify(adapter)

    pair = filter_ica_considerations(
        (_finding_pair(enumeration),), batch, enumeration=filtered
    )[0]

    assert pair.disposition == "unresolved"
    assert [item.code for item in pair.diagnostics] == [
        "ica_hazard_absence_evidence_missing"
    ]
