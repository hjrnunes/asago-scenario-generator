"""Verified mechanism suggestions as a third consideration kind in slot filling."""

from __future__ import annotations

import json
from typing import Any

import pytest

from asago_scenario_generator.models.mechanism_suggestion import (
    MechanismIcaConsideration,
    MechanismSuggestion,
    MechanismSuggestionPath,
)
from asago_scenario_generator.models.obligation_consideration import (
    SLOT_PROMPT_BUDGET_EXCEEDED,
    ObligationRoute,
)
from asago_scenario_generator.stpa.infra.prompt_preflight import (
    PromptBudget,
    estimate_prompt_tokens,
)
from asago_scenario_generator.stpa.mechanism_library import (
    MechanismId,
    bundled_mechanism_library,
)
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    IcaDeviationDraft,
    IcaFindingDraft,
    ObligationIcaDraft,
    SlotIcaDraft,
    SynthesisSlotRequest,
    SynthesisSlotResponse,
)
from asago_scenario_generator.stpa.obligation_aware.ica_verification import (
    ICA_VERIFICATION_EXCLUSION_CODES,
    filter_mechanism_considerations,
    verify_final_ica_batch,
)
from asago_scenario_generator.stpa.obligation_aware.mechanism_suggestions import (
    MECHANISM_SUGGESTIONS_PER_SLOT,
    MechanismProposal,
    ProposedSuggestion,
    SuggestionVerdict,
    select_mechanism_suggestions,
)
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    build_ica_hazard_verification_prompts,
    build_synthesis_slot_prompts,
)
from asago_scenario_generator.stpa.obligation_aware.provider import (
    ObligationAwareLLMAdapter,
)
from asago_scenario_generator.stpa.obligation_aware.slot_filling import (
    build_synthesis_slot_requests,
    fill_synthesis_slots,
)
from asago_scenario_generator.stpa.obligation_aware.stpa_index import (
    MechanismCandidate,
)
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from tests.helpers.mechanism_suggestions import (
    ACTION_PATH,
    LINK_PATH,
    suggestion_structure,
)
from tests.helpers.mechanism_verifier_handles import _single_brief
from tests.helpers.obligation_aware import _controls, _loss_analysis, wire_pairs
from tests.helpers.scripted_client import ScriptedClient

_SLOT = "RESP-1:CA-1-1:NOT_PROVIDED"
_LINK_SLOT = "CL-1:CM-1:NOT_PROVIDED"
_DEVIATION = {
    UCAType.not_provided: "not_provided_context",
    UCAType.incorrect: "incorrect_value_or_effect",
    UCAType.wrong_timing: "timing_deviation",
    UCAType.wrong_duration: "duration_deviation",
}


def _suggestion(
    mechanism: str = "user_claim",
    slot_id: str = _SLOT,
    path: tuple[str, str, str] = ACTION_PATH,
) -> MechanismSuggestion:
    return MechanismSuggestion(
        mechanism_id=mechanism,
        slot_id=slot_id,
        paths=(
            MechanismSuggestionPath(
                feedback_channel_id=path[0],
                process_model_part_id=path[1],
                end_id=path[2],
            ),
        ),
    )


def _route(brief) -> ObligationRoute:
    return ObligationRoute(
        obligation_id=brief.obligation_id,
        disposition="targeted",
        slot_ids=(_SLOT,),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        rationale="The supplied control path is relevant to the concern.",
        evidence=("provider-route",),
    )


def _request(*suggestions: MechanismSuggestion, routed: bool = False):
    briefs = tuple(_single_brief()) if routed else ()
    routes = tuple(_route(brief) for brief in briefs)
    (request,) = (
        item
        for item in build_synthesis_slot_requests(
            briefs=briefs,
            routes=routes,
            loss_analysis=_loss_analysis(),
            control_structure=suggestion_structure(),
            controls=_controls(),
        )
        if item.target_id == "RESP-1"
    )
    slot = next(item for item in request.slots if item.slot_id == _SLOT)
    return SynthesisSlotRequest(
        target_id=request.target_id,
        target_kind=request.target_kind,
        slots=(slot,),
        routed_briefs=request.routed_briefs,
        routed_routes=request.routed_routes,
        loss_analysis=request.loss_analysis,
        control_structure=request.control_structure,
        controls=request.controls,
        mechanism_suggestions=suggestions,
    )


def _prompts(request: SynthesisSlotRequest) -> tuple[str, str]:
    return build_synthesis_slot_prompts(
        target_id=request.target_id,
        slots=request.slots,
        routed_briefs=request.routed_briefs,
        routed_routes=request.routed_routes,
        loss_analysis=request.loss_analysis,
        control_structure=request.control_structure,
        mechanism_suggestions=request.mechanism_suggestions,
    )


# --- cap and ordering ------------------------------------------------------


def _verdict(mechanism: str, path, relationship) -> SuggestionVerdict:
    return SuggestionVerdict(
        MechanismCandidate(MechanismId(mechanism), path), relationship, "r"
    )


def test_a_slot_keeps_its_verified_suggestions_in_library_order_up_to_the_cap() -> None:
    mechanisms = ("user_claim", "retrieved_instructions", "stale_history")
    proposal = MechanismProposal(
        proposed=tuple(
            ProposedSuggestion(MechanismId(name), _SLOT, (ACTION_PATH,))
            for name in mechanisms
        )
    )
    verdicts = [
        _verdict(name, ACTION_PATH, "mechanism_specific") for name in mechanisms
    ]

    selection = select_mechanism_suggestions(proposal, verdicts)

    assert MECHANISM_SUGGESTIONS_PER_SLOT == 2
    assert [item.mechanism_id.value for item in selection.survivors] == [
        "user_claim",
        "retrieved_instructions",
    ]
    assert [item.mechanism_id.value for item in selection.over_cap] == ["stale_history"]


def test_only_paths_judged_mechanism_specific_survive() -> None:
    other = ("FB-9", "PM-1-1", "CA-1-1")
    proposal = MechanismProposal(
        proposed=(
            ProposedSuggestion(MechanismId.user_claim, _SLOT, (ACTION_PATH, other)),
            ProposedSuggestion(
                MechanismId.delegated_authority, _LINK_SLOT, (LINK_PATH,)
            ),
            ProposedSuggestion(MechanismId.user_claim, _LINK_SLOT, (LINK_PATH,)),
        )
    )
    verdicts = [
        _verdict("user_claim", ACTION_PATH, "adjacent_control"),
        _verdict("user_claim", other, "mechanism_specific"),
        _verdict("delegated_authority", LINK_PATH, "insufficient_evidence"),
        _verdict("user_claim", LINK_PATH, None),
    ]

    selection = select_mechanism_suggestions(proposal, verdicts)

    (survivor,) = selection.survivors
    assert survivor.slot_id == _SLOT
    assert [path.feedback_channel_id for path in survivor.paths] == ["FB-9"]
    assert selection.over_cap == ()


def test_a_request_orders_its_suggestions_by_slot_then_library_order() -> None:
    request = _request(_suggestion("delegated_authority"), _suggestion("user_claim"))

    assert [item.mechanism_id.value for item in request.mechanism_suggestions] == [
        "user_claim",
        "delegated_authority",
    ]


def test_a_request_rejects_a_suggestion_for_another_slot() -> None:
    with pytest.raises(ValueError, match="outside the request"):
        _request(_suggestion(slot_id=_LINK_SLOT, path=LINK_PATH))


# --- the slot prompt --------------------------------------------------------


def test_without_suggestions_the_request_and_prompts_keep_their_bytes() -> None:
    plain = _request(routed=True)
    rebuilt = SynthesisSlotRequest.model_validate(
        plain.model_dump(mode="python", exclude={"semantic_digest"})
    )

    assert "mechanism_suggestions" not in plain.model_dump(mode="json")
    assert rebuilt.semantic_digest == plain.semantic_digest
    system, user = _prompts(plain)
    assert (system, user) == build_synthesis_slot_prompts(
        target_id=plain.target_id,
        slots=plain.slots,
        routed_briefs=plain.routed_briefs,
        routed_routes=plain.routed_routes,
        loss_analysis=plain.loss_analysis,
        control_structure=plain.control_structure,
    )
    for text in (system, user):
        assert "Mechanism suggestions" not in text
        assert "mechanism_handle" not in text


def test_a_suggestion_adds_its_section_and_never_displaces_hazards_or_obligations() -> (
    None
):
    plain_system, plain_user = _prompts(_request(routed=True))
    system, user = _prompts(_request(_suggestion(), routed=True))

    closing = "Return the structured slot-draft schema described above.\n"
    assert plain_user.endswith(closing)
    assert user.startswith(plain_user[: -len(closing)])
    assert user.endswith(closing)
    added = user[len(plain_user) - len(closing) : -len(closing)]
    entry = bundled_mechanism_library().entry("user_claim")
    assert "Mechanism suggestions for this target" in added
    assert "mechanism_handle: M1" in added
    assert entry.name in added
    assert "Requested refund amount" in added
    assert "Required mechanism consideration pairs:" in added
    for hidden in (*entry.required_evidence, *entry.counterexamples):
        assert " ".join(hidden.split())[:40] not in " ".join(user.split())
    assert system.startswith(plain_system)
    assert "Mechanism suggestions for this target" in system[len(plain_system) :]


# --- outcomes through the provider ------------------------------------------


def _finding(slot_type: UCAType) -> dict[str, Any]:
    return {
        "deviation": "the refund amount is not checked against the order",
        "hazardous_context": "an unchecked amount is refunded",
        "loss_consequence": "the protected operation is harmed",
        "governing_pairs": wire_pairs(("SC-1",), ("H-1",)),
        "process_model_refs": ["PM-1-1"],
        "feedback_refs": [],
        "context_row": None,
    }


def _reply(results: dict[str, dict], *, is_na: bool = False) -> str:
    slot: dict[str, Any] = {"slot_id": _SLOT, "is_na": is_na}
    if is_na:
        slot.update(na_rationale="The action has a complete structural guard.")
        slot["findings"] = []
    else:
        slot.update(na_rationale=None, findings=[_finding(UCAType.not_provided)])
    slot["consideration_results"] = results
    return json.dumps({"filled_slots": [slot]})


@pytest.mark.parametrize(
    ("result", "is_na", "disposition"),
    [
        ({"disposition": "finding", "finding_indexes": [0]}, False, "finding"),
        (
            {"disposition": "proposed_not_applicable", "finding_indexes": []},
            True,
            "proposed_not_applicable",
        ),
        ({"disposition": "unresolved", "finding_indexes": []}, False, "unresolved"),
    ],
)
def test_a_suggestion_reuses_the_obligation_outcomes(
    tmp_path, result, is_na, disposition
) -> None:
    request = _request(_suggestion())
    client = ScriptedClient(
        [_reply({"M1": {**result, "rationale": "why"}}, is_na=is_na)]
    )
    adapter = ObligationAwareLLMAdapter(client, run_dir=tmp_path, controls=_controls())

    response = adapter.fill(request)

    assert response.considerations == ()
    (pair,) = response.mechanism_considerations
    assert pair.disposition == disposition
    assert pair.mechanism_id is MechanismId.user_claim
    assert pair.suggestion_id == request.mechanism_suggestions[0].suggestion_id
    if disposition == "finding":
        assert pair.ica_ids and pair.hazard_ids == ("H-1",)
    schema = client.calls[0]["response_format"].model_json_schema()
    assert "M1" in json.dumps(schema)


def test_a_suggestion_result_sits_beside_the_routed_obligation(tmp_path) -> None:
    request = _request(_suggestion(), routed=True)
    finding = {"disposition": "finding", "finding_indexes": [0], "rationale": "why"}
    client = ScriptedClient([_reply({"R1": finding, "M1": finding})])
    adapter = ObligationAwareLLMAdapter(client, run_dir=tmp_path, controls=_controls())

    response = adapter.fill(request)

    (obligation,) = response.considerations
    (mechanism,) = response.mechanism_considerations
    assert obligation.obligation_id == request.routed_routes[0].obligation_id
    assert obligation.ica_ids == mechanism.ica_ids
    assert "R1" in client.calls[0]["user_prompt"]


def test_a_reply_that_omits_the_suggestion_is_repaired_with_its_local_handle(
    tmp_path,
) -> None:
    request = _request(_suggestion())
    good = {"M1": {"disposition": "unresolved", "rationale": "no evidence"}}
    client = ScriptedClient([_reply({}), _reply(good)])
    adapter = ObligationAwareLLMAdapter(client, run_dir=tmp_path, controls=_controls())

    response = adapter.fill(request)

    assert len(client.calls) == 2
    assert (
        request.mechanism_suggestions[0].suggestion_id
        not in (client.calls[1]["user_prompt"])
    )
    assert response.mechanism_considerations[0].disposition == "unresolved"


# --- outcomes through slot filling -----------------------------------------


class _DraftSlots:
    """Answer each slot with one finding; mechanism results as scripted."""

    def __init__(self, disposition: str = "finding", fail: bool = False) -> None:
        self.disposition = disposition
        self.fail = fail
        self.requests: list[SynthesisSlotRequest] = []

    def fill(self, request: SynthesisSlotRequest) -> SynthesisSlotResponse:
        self.requests.append(request)
        if self.fail and request.mechanism_suggestions:
            raise ValueError("the provider call failed")
        drafts = []
        for slot in request.slots:
            findings = (
                IcaFindingDraft(
                    deviation=IcaDeviationDraft(
                        **{_DEVIATION[slot.uca_type]: "the request is not reviewed"}
                    ),
                    hazardous_context="the unreviewed request reaches the process",
                    loss_consequence="the protected operation is harmed",
                    related_hazard_ids=("H-1",),
                    related_constraint_ids=("SC-1",),
                ),
            )
            results = tuple(
                ObligationIcaDraft(
                    obligation_handle=str(item.suggestion_id),
                    disposition=self.disposition,
                    finding_indexes=(0,) if self.disposition == "finding" else (),
                    rationale="The finding expresses the mechanism.",
                )
                for item in request.mechanism_suggestions
                if item.slot_id == slot.slot_id
            )
            drafts.append(
                SlotIcaDraft(
                    slot_id=slot.slot_id,
                    is_na=False,
                    findings=findings,
                    consideration_results=results,
                )
            )
        return SynthesisSlotResponse(
            request_digest=request.semantic_digest,
            filled_slots=tuple(drafts),
            adapter_kind="fake",
        )


def _fill(adapter, *suggestions: MechanismSuggestion):
    return fill_synthesis_slots(
        adapter,
        briefs=(),
        routes=(),
        loss_analysis=_loss_analysis(),
        control_structure=suggestion_structure(),
        controls=_controls(),
        mechanism_suggestions=suggestions,
    )


def test_each_suggestion_rides_on_its_slot_request_and_gets_one_result() -> None:
    adapter = _DraftSlots()
    suggestions = (
        _suggestion(),
        _suggestion("user_claim", _LINK_SLOT, LINK_PATH),
        _suggestion("delegated_authority", _LINK_SLOT, LINK_PATH),
    )

    result = _fill(adapter, *suggestions)

    carried = {
        request.slots[0].slot_id: [
            item.mechanism_id.value for item in request.mechanism_suggestions
        ]
        for request in adapter.requests
        if request.mechanism_suggestions
    }
    assert carried == {
        _SLOT: ["user_claim"],
        _LINK_SLOT: ["user_claim", "delegated_authority"],
    }
    assert result.considerations == ()
    assert {
        (item.slot_id, item.mechanism_id.value, item.disposition)
        for item in result.mechanism_considerations
    } == {
        (_SLOT, "user_claim", "finding"),
        (_LINK_SLOT, "user_claim", "finding"),
        (_LINK_SLOT, "delegated_authority", "finding"),
    }


def test_without_suggestions_slot_filling_is_unchanged() -> None:
    plain = _DraftSlots()
    with_default = fill_synthesis_slots(
        plain,
        briefs=(),
        routes=(),
        loss_analysis=_loss_analysis(),
        control_structure=suggestion_structure(),
        controls=_controls(),
    )
    explicit = _DraftSlots()

    empty = _fill(explicit)

    assert [item.semantic_digest for item in plain.requests] == [
        item.semantic_digest for item in explicit.requests
    ]
    assert empty.result == with_default.result
    assert "mechanism_considerations" not in empty.result.model_dump(mode="json")


def test_a_failed_request_leaves_its_suggestions_unresolved() -> None:
    result = _fill(_DraftSlots(fail=True), _suggestion())

    (pair,) = result.mechanism_considerations
    assert pair.disposition == "unresolved"
    assert pair.diagnostics[0].code == "slot_pair_unresolved"
    assert result.ica_enumeration.slots


def test_a_suggestion_that_would_break_the_budget_is_dropped_not_the_obligation() -> (
    None
):
    with_it = _request(_suggestion())
    without = _request()

    def tokens(request):
        system, user = _prompts(request)
        return estimate_prompt_tokens(f"{system}\n{user}")

    window = 8192 + tokens(without) + (tokens(with_it) - tokens(without)) // 2
    adapter = _DraftSlots()
    adapter.prompt_budget = PromptBudget(
        context_window=window, maximum_completion_tokens=8192, safety_margin=0
    )

    result = _fill(adapter, _suggestion())

    assert all(not request.mechanism_suggestions for request in adapter.requests)
    (pair,) = result.mechanism_considerations
    assert pair.disposition == "unresolved"
    assert pair.diagnostics[0].code == SLOT_PROMPT_BUDGET_EXCEEDED


# --- the independent ICA verifier -------------------------------------------


class _VerifierSpy:
    def __init__(self, verdict: str) -> None:
        self.verdict = verdict
        self.requests: list[Any] = []

    def verify_ica_hazards(self, requests, *, correction=False):
        del correction
        self.requests.extend(requests)
        return [
            {"ica_id": item.ica_id, "verdict": self.verdict, "rationale": "r"}
            for item in requests
        ]


def _verified(verdict: str):
    # An INCORRECT slot: a supported NOT_PROVIDED verdict would also need the
    # absence evidence this fake verifier does not give.
    result = _fill(_DraftSlots(), _suggestion(slot_id="RESP-1:CA-1-1:INCORRECT"))
    spy = _VerifierSpy(verdict)
    filtered, batch = verify_final_ica_batch(
        spy,
        result.ica_enumeration,
        loss_analysis=_loss_analysis(),
        control_structure=suggestion_structure(),
    )
    pairs = filter_mechanism_considerations(
        result.mechanism_considerations, batch, enumeration=filtered
    )
    return result, spy, pairs


def test_a_supported_mechanism_finding_passes_the_ica_verifier() -> None:
    _result, _spy, (pair,) = _verified("supported")

    assert pair.disposition == "finding"


def test_an_ica_verifier_rejection_withholds_the_mechanism_finding() -> None:
    _result, _spy, (pair,) = _verified("contradictory")

    assert isinstance(pair, MechanismIcaConsideration)
    assert pair.disposition == "unresolved"
    assert pair.ica_ids == ()
    assert pair.diagnostics[-1].code in ICA_VERIFICATION_EXCLUSION_CODES
    assert pair.diagnostics[-1].obligation_ids == ()


def test_no_mechanism_material_reaches_the_ica_verifier_prompt() -> None:
    _result, spy, _pairs = _verified("supported")
    entry = bundled_mechanism_library().entry("user_claim")

    system, user = build_ica_hazard_verification_prompts(tuple(spy.requests))

    assert spy.requests
    for text in (system, user):
        for marker in (entry.name, entry.question, "user_claim", "msug:", "M1"):
            assert marker not in text
