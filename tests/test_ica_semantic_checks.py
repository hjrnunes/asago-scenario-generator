"""The existing ICA verifier must judge action, category and harm separately."""

import pytest

from asago_scenario_generator.stpa.infra.llm_helpers import CallOutcome
from asago_scenario_generator.stpa.obligation_aware.provider import (
    _IcaHazardProviderVerdict,
    ObligationAwareLLMAdapter,
)
from tests.helpers.ica_hazard_verification import _request, _stpa_inputs
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    build_ica_hazard_verification_prompts,
)
from asago_scenario_generator.stpa.models.ica_enumeration import ICA
from asago_scenario_generator.stpa.obligation_aware.ica_verification import (
    build_ica_hazard_verification_request,
    IcaHazardVerificationRequest,
)
from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.obligation_aware.contracts import AnalysisControls
from types import SimpleNamespace
from asago_scenario_generator.stpa.obligation_aware import provider


@pytest.mark.parametrize(
    "state,category,path,expected",
    [
        ("performed_unsafe", "INCORRECT", "supported", "supported"),
        ("different_action", "NOT_PROVIDED", "supported", "contradictory"),
        ("absent", "INCORRECT", "supported", "contradictory"),
        (
            "performed_unsafe",
            "INCORRECT",
            "insufficient_evidence",
            "insufficient_evidence",
        ),
        ("undetermined", "INCORRECT", "contradictory", "contradictory"),
        ("absent", "NOT_PROVIDED", "supported", "supported"),
        ("wrong_timing", "WRONG_TIMING", "supported", "supported"),
        ("wrong_duration", "WRONG_DURATION", "supported", "supported"),
        ("undetermined", "INCORRECT", "supported", "insufficient_evidence"),
    ],
)
def test_a_plausible_hazard_cannot_override_a_different_action_or_category(
    state, category, path, expected
):
    result = _IcaHazardProviderVerdict.model_validate(
        {
            "review_ref": "review-1",
            "action_state": state,
            "hazard_path": path,
            "rationale": "Judge the fixed action, its category and the supplied harm separately.",
        }
    )
    assert result.verdict_for(category) == expected


def test_verifier_classifies_without_seeing_the_proposed_category():

    request = _request()
    _, user = build_ica_hazard_verification_prompts((request,))
    assert "review_ref: review-1" in user
    assert request.ica_id not in user
    assert "uca_type:" not in user
    assert "uca_definition:" not in user
    assert "slot_id:" not in user
    corrected_prompts = build_ica_hazard_verification_prompts(
        (request,),
        correction_feedback={request.ica_id: "Previously rejected as INCORRECT"},
    )
    assert corrected_prompts == build_ica_hazard_verification_prompts((request,))


def test_unqualified_supported_claim_cannot_skip_semantic_checks():
    with pytest.raises(ValueError):
        _IcaHazardProviderVerdict.model_validate(
            {"ica_id": "test", "verdict": "supported", "rationale": "Looks plausible"}
        )


def test_verifier_receives_deviation_without_controller_sentence_frame():

    enumeration, losses, structure = _stpa_inputs()
    slot = enumeration.slots[0]
    original = slot.icas[0]
    raw = {**original.model_dump(), "deviation": "the release gate is unsatisfied"}
    ica = ICA.model_validate(raw)
    request = build_ica_hazard_verification_request(ica, slot, losses, structure)
    assert request.deviation == "the release gate is unsatisfied"
    assert request.control_action_description == "Approve release"


@pytest.mark.parametrize("corrected", [False, True])
def test_saved_klarna_counterexamples_keep_their_action_and_independent_classification(
    tmp_path,
    corrected,
):
    """Replay calibrated semantic labels; live-model accuracy is checked separately."""

    cases = (
        (
            "Execute high-value financial transaction",
            "multi-factor authorization or human approval is not requested for a high-value financial transaction",
            "NOT_PROVIDED",
            "performed_unsafe",
            "contradictory",
        ),
        (
            "Escalate conversation to human agent",
            "escalation is not triggered when the conversation contains regulated keywords or high-ambiguity sentiment",
            "INCORRECT",
            "absent",
            "contradictory",
        ),
        (
            "Signal mismatch between session and target account",
            "a mismatch between the authenticated session token and the target account ID is not signaled",
            "INCORRECT",
            "absent",
            "contradictory",
        ),
        (
            "Return conversational output to user",
            "conversational output contains demographic biases or toxic content",
            "INCORRECT",
            "performed_unsafe",
            "supported",
        ),
    )
    base = _request().model_dump(exclude={"semantic_digest"})
    requests = tuple(
        IcaHazardVerificationRequest.model_validate(
            {
                **base,
                "ica_id": f"RESP-1:CA-1-1:{category}:{index}",
                "slot_id": f"RESP-1:CA-1-1:{category}",
                "uca_type": category,
                "control_action_description": action,
                "deviation": deviation,
            }
        )
        for index, (action, deviation, category, _, _) in enumerate(cases, 1)
    )

    class ReplayClient:
        model = "offline-calibrated-replay"
        calls = 0

        def complete(self, **kwargs):
            self.calls += 1
            for request in requests:
                assert request.control_action_description in kwargs["user_prompt"]
                assert request.ica_id not in kwargs["user_prompt"]
            return LLMResult(
                content={
                    "verdicts": [
                        {
                            "review_ref": f"review-{index}",
                            "action_state": state,
                            "hazard_path": "supported",
                            "rationale": action,
                        }
                        for index, (action, _, _, state, _) in enumerate(cases, 1)
                    ]
                },
                prompt_tokens=1,
                completion_tokens=1,
                duration_ms=1,
                system_prompt=kwargs["system_prompt"],
                user_prompt=kwargs["user_prompt"],
            )

    client = ReplayClient()
    adapter = ObligationAwareLLMAdapter(
        client,
        run_dir=tmp_path,
        controls=AnalysisControls(
            model_profile="offline",
            model_name=client.model,
            temperature=0.0,
            deadline_seconds=30.0,
        ),
    )
    results = adapter.verify_ica_hazards(
        requests,
        correction_feedback={requests[0].ica_id: "Prior rejected label"}
        if corrected
        else None,
    )
    assert client.calls == 1
    assert {result.ica_id: result.verdict for result in results} == {
        request.ica_id: case[-1] for request, case in zip(requests, cases, strict=True)
    }


def test_absent_original_deviation_preserves_historical_ica_bytes():
    enumeration, _, _ = _stpa_inputs()
    ica = enumeration.slots[0].icas[0]
    assert ica.deviation is None
    assert "deviation" not in ica.model_dump(mode="json")


@pytest.mark.parametrize(
    "mode",
    [
        "empty",
        "duplicate_request",
        "foreign_ref",
        "duplicate_ref",
        "provider_error",
        "missing_payload",
    ],
)
def test_review_accounting_does_not_admit_unbound_results(mode, monkeypatch, tmp_path):

    request = _request()
    verdict = provider._IcaHazardProviderVerdict(
        review_ref="other" if mode == "foreign_ref" else "review-1",
        rationale="Saved labelled observation",
        action_state="performed_unsafe",
        hazard_path="supported",
    )
    payload = provider._IcaHazardProviderPayload(
        verdicts=(verdict, verdict) if mode == "duplicate_ref" else (verdict,),
    )
    if mode in {"provider_error", "missing_payload"}:
        payload = None
    calls = []

    def fake_call(**kwargs):
        calls.append(kwargs)
        error = "provider failed" if mode == "provider_error" else None
        return CallOutcome(payload, None, error, 1)

    monkeypatch.setattr(provider, "call_with_policy", fake_call)
    adapter = provider.ObligationAwareLLMAdapter(
        SimpleNamespace(model="offline"),
        run_dir=tmp_path,
        controls=AnalysisControls(
            model_profile="offline",
            model_name="offline",
            temperature=0.0,
            deadline_seconds=30.0,
        ),
    )
    if mode == "empty":
        assert adapter.verify_ica_hazards(()) == ()
        assert calls == []
        return
    requests = (request, request) if mode == "duplicate_request" else (request,)
    with pytest.raises(ValueError):
        adapter.verify_ica_hazards(requests)
    assert len(calls) == (0 if mode == "duplicate_request" else 1)
