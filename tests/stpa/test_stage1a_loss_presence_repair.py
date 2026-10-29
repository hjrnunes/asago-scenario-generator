"""Stage 1a: one targeted repair for a risk-derivation reply with no grounded loss.

The fixture is the recorded reply (GLM, an Airbnb unit, 2026-10-10) that
spent its tokens on reasoning and then wrote all five collections empty
while risk cards were supplied.  The loss-presence validator already writes
exact feedback for that failure; the repair sends it once with the prior
reply.  Card texts are neutralized.  Every test uses a fake client and
contacts no network.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from asago_scenario_generator.models.risk_card import RiskCard
from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.infra.llm_helpers import StageError
from asago_scenario_generator.stpa.models.loss_analysis import Hazard, LossAnalysisDraft
from asago_scenario_generator.stpa.system_model import loss_analysis
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    _ProviderSecurityConstraint,
    _Stage1aRiskRepairDraft,
    derive_loss_analysis,
)
from asago_scenario_generator.stpa.system_model.loss_analysis_repair import (
    LOSS_PRESENCE_REPAIR_IDENTITY,
    UnsupportedRepair,
    salvage_corrected_reply,
)
from tests.helpers.stage1a_targeted_repair import (
    _USE_CASE,
    _attempt_two_response,
    _client,
    _occiai_cards,
    _repair_record,
    _stage1a_entries,
)
from tests.stpa.sp1_helpers import MockLLMClient

# The recorded reply, byte for byte.
_EMPTY_REPLY = (
    "{\n"
    '  "hazards": [],\n'
    '  "risk_card_losses": [],\n'
    '  "risk_dispositions": [],\n'
    '  "security_constraints": [],\n'
    '  "use_case_losses": []\n'
    "}"
)

_FEEDBACK = (
    "Declare at least one grounded risk-card loss with non-empty "
    "source_risk_cards before writing hazards or security constraints."
)

_CARD_IDS = ("mit-ai-risk-subdomain-2.2", "credo-risk-037", "credo-risk-050")


def _cards() -> list[RiskCard]:
    return [
        RiskCard(
            risk_id=risk_id,
            risk_name=f"Neutralized risk {index}",
            risk_description=f"Neutralized description {index} for analysis.",
            taxonomy="ibm-risk-atlas",
            confidence=0.9,
            grounding_confidence="high",
            consequence=f"Neutralized consequence {index}.",
        )
        for index, risk_id in enumerate(_CARD_IDS, start=1)
    ]


def _corrected_reply() -> str:
    """One grounded loss and every supplied card accounted for."""
    return json.dumps(
        {
            "hazards": [],
            "risk_card_losses": [
                {
                    "handle": "reservation_privacy_loss",
                    "description": "Reservation data reaches a non-party.",
                    "provenance": "risk_card",
                    "source_risk_cards": list(_CARD_IDS[:2]),
                }
            ],
            "risk_dispositions": [
                {
                    "risk_ref": _CARD_IDS[0],
                    "disposition": "cited",
                    "loss_ids": ["reservation_privacy_loss"],
                },
                {
                    "risk_ref": _CARD_IDS[1],
                    "disposition": "cited",
                    "loss_ids": ["reservation_privacy_loss"],
                },
                {
                    "risk_ref": _CARD_IDS[2],
                    "disposition": "not_applicable",
                    "loss_ids": [],
                    "reason": "Neutralized reason: no declared loss here.",
                },
            ],
            "security_constraints": [],
            "use_case_losses": [],
        }
    )


def _gap_reply() -> str:
    return json.dumps(
        {
            "risk_card_losses": [],
            "use_case_losses": [],
            "hazards": [
                {
                    "handle": "privacy_exposure_hazard",
                    "description": "The assistant returns a record to a non-party.",
                    "related_losses": ["L-1"],
                }
            ],
            "security_constraints": [
                {
                    "handle": "privacy_constraint",
                    "rule": "The assistant must return a record only to a party.",
                    "applies_when": [],
                    "behavior_class": "disclosure",
                    "related_hazards": ["privacy_exposure_hazard"],
                    "obligations": [],
                }
            ],
        }
    )


def _derive(client: MockLLMClient, tmp_path):
    return derive_loss_analysis(
        llm_client=client,
        use_case_text="A neutralized lodging assistant answers guest questions.",
        risk_cards=_cards(),
        run_dir=tmp_path,
    )


def _repair_entries(tmp_path) -> list[dict]:
    return [
        entry
        for entry in _repair_record(tmp_path)["records"]
        if entry["identity"] == LOSS_PRESENCE_REPAIR_IDENTITY
    ]


def test_empty_reply_gets_one_correction_carrying_the_feedback(tmp_path):
    client = _client(_EMPTY_REPLY, _corrected_reply(), _gap_reply())

    result = _derive(client, tmp_path)

    entries = _stage1a_entries(tmp_path)
    assert [entry["step"] for entry in entries] == [
        "risk_derivation",
        "risk_derivation_repair",
        "gap_analysis",
    ]
    first, correction = client.calls[0], client.calls[1]
    assert correction.system_prompt == first.system_prompt
    assert correction.response_format is first.response_format
    assert correction.user_prompt.startswith(first.user_prompt)
    feedback = correction.user_prompt[len(first.user_prompt) :]
    assert _FEEDBACK in " ".join(feedback.split())
    assert "no grounded losses were declared" in feedback
    assert _EMPTY_REPLY in feedback
    assert [loss.loss_id for loss in result.risk_card_losses] == ["L-1"]
    assert {row.risk_ref for row in result.risk_dispositions} == set(_CARD_IDS)
    (record,) = _repair_entries(tmp_path)
    assert record["stage"] == "risk_derivation"
    assert record["attempt"] == "repair"
    assert record["kind"] == "repair"
    assert record["outcome"] == "repaired"
    assert record["raw_step"] == "risk_derivation_repair"
    assert "no grounded losses were declared" in record["reason"]
    assert not [
        entry
        for entry in _repair_record(tmp_path)["records"]
        if entry["outcome"] == "unsupported"
    ]


def test_second_empty_reply_stops_typed_after_two_requests(tmp_path):
    client = _client(_EMPTY_REPLY, _EMPTY_REPLY, _gap_reply())

    with pytest.raises(StageError) as exc_info:
        _derive(client, tmp_path)

    message = str(exc_info.value)
    assert "targeted repair failed" in message
    assert "no grounded losses were declared" in message
    assert "loss_presence failure class" in message
    assert len(client.calls) == 2
    assert [entry["step"] for entry in _stage1a_entries(tmp_path)] == [
        "risk_derivation",
        "risk_derivation_repair",
    ]
    (record,) = _repair_entries(tmp_path)
    assert record["outcome"] == "failed"
    assert record["applied"] == {}
    finding = (
        "risk_derivation must return a complete loss -> hazard -> security "
        "constraint chain anchor: no grounded losses were declared"
    )
    assert record["reason"] == f"{finding}; _LossPresenceError: {finding}"


def test_other_semantic_failures_still_get_no_repair(tmp_path):
    draft = _attempt_two_response()
    draft["hazards"][6]["description"] = (
        "The model fails and the service becomes unavailable."
    )
    client = MockLLMClient()
    client.set_response_for(LossAnalysisDraft, [draft])

    with pytest.raises(StageError) as exc_info:
        derive_loss_analysis(
            llm_client=client,
            use_case_text=_USE_CASE,
            risk_cards=_occiai_cards(),
            run_dir=tmp_path,
        )

    assert "targeted repair unsupported" in str(exc_info.value)
    assert "draft_semantics failure class" in str(exc_info.value)
    assert len(client.calls) == 1


# Source: a recorded OcciAI fill, attempt 1, call 26 (risk_derivation_repair),
# trimmed to one loss, one hazard, three constraints, and three cards.  The
# recorded reply carried paraphrased rule_span values on three obligations of
# its nine constraints.  The cards here are neutral; the loss, hazard, rules,
# and spans are the recorded text.
_HAZARD = "cross_patient_tool_use"
_SESSION_RULE = (
    "Every portal operation the assistant invokes (get_referral, "
    "get_education, ask_clinical_question, submit_questionnaire, "
    "summarize_for_ehr, commit_to_ehr, generate_education_video, "
    "escalate_to_clinician) must pass the session's authenticated_patient_id "
    "as the patient_id argument, regardless of what patient_id the requester "
    "supplies."
)
_MATERIAL_RULE = (
    "Education content served through get_education, ask_clinical_question, "
    "or generate_education_video must come only from an education record "
    "with approved=true in the patient's referral specialty; material whose "
    "approved flag is false, or whose specialty differs from the patient's "
    "referral specialty, must not be presented as care guidance."
)
_GATE_RULE = (
    "The assistant must not commit a draft to the EHR unless that draft "
    "exists, belongs to the authenticated patient, and carries status "
    "REVIEWED; unreviewed commit attempts must be rejected and recorded in "
    "the commit ledger."
)
_SESSION_SPAN = "must pass the session's authenticated_patient_id"
_MATERIAL_VALID_SPAN = (
    "or whose specialty differs from the patient's referral specialty"
)
_MATERIAL_PARAPHRASE = (
    "must not present material whose education record has approved=false"
)
_GATE_PARAPHRASE = (
    "must not commit a draft unless it exists, belongs to the authenticated "
    "patient, and carries status REVIEWED"
)


def _obligation(obligation_id: str, rule_span: str) -> dict:
    return {
        "obligation_id": obligation_id,
        "kind": "forbidden",
        "behavior": "act against the rule",
        "rule_span": rule_span,
        "violated_via": "tool_call",
    }


def _constraint_row(handle: str, rule: str, *obligations: dict) -> dict:
    return {
        "handle": handle,
        "rule": rule,
        "applies_when": [],
        "behavior_class": "disclosure",
        "related_hazards": [_HAZARD],
        "obligations": list(obligations),
    }


def _chain_reply(*, constraints: list[dict] | None = None, **overrides: object) -> str:
    """A corrected reply with a complete chain and every card accounted for."""
    body = json.loads(_corrected_reply())
    body["hazards"] = [
        {
            "handle": _HAZARD,
            "description": (
                "The assistant invokes get_referral or commit_to_ehr with a "
                "patient_id other than the session's authenticated_patient_id."
            ),
            "related_losses": ["reservation_privacy_loss"],
        }
    ]
    body["security_constraints"] = constraints or [
        _constraint_row(
            "session_binding_constraint",
            _SESSION_RULE,
            _obligation("O1", _SESSION_SPAN),
        ),
        _constraint_row(
            "approved_material_constraint",
            _MATERIAL_RULE,
            _obligation("O1", _MATERIAL_PARAPHRASE),
            _obligation("O2", _MATERIAL_VALID_SPAN),
        ),
        _constraint_row(
            "review_gate_constraint",
            _GATE_RULE,
            _obligation("O1", _GATE_PARAPHRASE),
        ),
    ]
    body.update(overrides)
    return json.dumps(body)


def _entries_of_kind(tmp_path, kind: str) -> list[dict]:
    return [
        entry for entry in _repair_record(tmp_path)["records"] if entry["kind"] == kind
    ]


def test_paraphrased_spans_in_the_correction_are_removed_and_recorded(tmp_path):
    client = _client(_EMPTY_REPLY, _chain_reply(), _gap_reply())

    result = _derive(client, tmp_path)

    assert len(client.calls) == 3
    assert [entry["step"] for entry in _stage1a_entries(tmp_path)] == [
        "risk_derivation",
        "risk_derivation_repair",
        "gap_analysis",
    ]
    # Canonical IDs follow the handles in alphabetical order.
    assert {
        constraint.constraint_id: [
            obligation.obligation_id for obligation in constraint.obligations
        ]
        for constraint in result.security_constraints[:3]
    } == {"SC-1": ["O2"], "SC-2": [], "SC-3": ["O1"]}
    removed = _entries_of_kind(tmp_path, "salvage")
    assert [entry["identity"] for entry in removed] == ["SC-1/O1", "SC-2/O1"]
    for entry in removed:
        assert entry["stage"] == "risk_derivation"
        assert entry["attempt"] == "repair"
        assert entry["outcome"] == "removed"
        assert entry["raw_step"] == "risk_derivation_repair"
        assert "rule_span must be a contiguous substring" in entry["reason"]
    (repaired,) = _repair_entries(tmp_path)
    assert repaired["outcome"] == "repaired"


def test_whitespace_span_in_the_correction_is_repaired_not_removed(tmp_path):
    spaced = (
        _GATE_RULE[: _GATE_RULE.index("a draft")]
        + " "
        + _GATE_RULE[_GATE_RULE.index("a draft") : _GATE_RULE.index(" unless that")]
    )
    client = _client(
        _EMPTY_REPLY,
        _chain_reply(
            constraints=[
                _constraint_row(
                    "review_gate_constraint", _GATE_RULE, _obligation("O1", spaced)
                )
            ]
        ),
        _gap_reply(),
    )

    result = _derive(client, tmp_path)

    (obligation,) = result.security_constraints[0].obligations
    assert obligation.rule_span in _GATE_RULE
    assert obligation.rule_span != spaced
    assert not _entries_of_kind(tmp_path, "salvage")
    (record,) = _entries_of_kind(tmp_path, "rule_span_repaired")
    assert record["attempt"] == "repair"
    assert record["identity"] == "SC-1/O1"
    assert record["raw_step"] == "risk_derivation_repair"
    assert record["proposed"] == {"rule_span": spaced}
    assert record["applied"]["rule_span"] == obligation.rule_span
    assert record["outcome"] == "applied"


def test_dropped_row_for_an_unsupplied_card_is_removed_and_recorded(tmp_path):
    body = json.loads(_chain_reply())
    body["risk_dispositions"].append(
        {"risk_ref": "unsupplied-risk", "disposition": "cited", "loss_ids": []}
    )
    client = _client(_EMPTY_REPLY, json.dumps(body), _gap_reply())

    result = _derive(client, tmp_path)

    assert {row.risk_ref for row in result.risk_dispositions} == set(_CARD_IDS)
    labels = [entry["identity"] for entry in _entries_of_kind(tmp_path, "salvage")]
    assert "unsupplied-risk" in labels
    assert all(
        entry["attempt"] == "repair" for entry in _entries_of_kind(tmp_path, "salvage")
    )


def _damage_container(body: dict) -> None:
    body["hazards"] = "none"


def _damage_disposition_container(body: dict) -> None:
    body["risk_dispositions"] = "none"


def _damage_loss_row(body: dict) -> None:
    body["risk_card_losses"][0]["provenance"] = "invented"


def _break_a_supplied_disposition(body: dict) -> None:
    body["risk_dispositions"][0] = {"risk_ref": _CARD_IDS[0], "disposition": "cited"}


def _repeat_an_obligation_id(body: dict) -> None:
    body["security_constraints"][1]["obligations"][1]["obligation_id"] = "O1"


def _cite_an_undeclared_hazard(body: dict) -> None:
    body["security_constraints"][0]["related_hazards"] = ["never_declared"]


@pytest.mark.parametrize(
    ("damage", "finding"),
    [
        pytest.param(_damage_container, "hazards", id="container-damage"),
        pytest.param(
            _damage_disposition_container,
            "ValidationError",
            id="disposition-container-damage",
        ),
        pytest.param(_damage_loss_row, "provenance", id="malformed-loss-row"),
        pytest.param(
            _break_a_supplied_disposition,
            "risk_dispositions",
            id="malformed-supplied-disposition",
        ),
        pytest.param(
            _repeat_an_obligation_id,
            "duplicate obligation ids",
            id="duplicate-obligation-ids",
        ),
        pytest.param(
            _cite_an_undeclared_hazard, "never_declared", id="unresolved-reference"
        ),
    ],
)
def test_damaged_correction_beside_a_bad_span_stops_after_two_requests(
    tmp_path, damage, finding
):
    body = json.loads(_chain_reply())
    damage(body)
    client = _client(_EMPTY_REPLY, json.dumps(body), _gap_reply())

    with pytest.raises(StageError) as exc_info:
        _derive(client, tmp_path)

    message = str(exc_info.value)
    assert "targeted repair failed" in message
    assert finding in message
    assert "loss_presence failure class" in message
    assert len(client.calls) == 2
    assert [entry["step"] for entry in _stage1a_entries(tmp_path)] == [
        "risk_derivation",
        "risk_derivation_repair",
    ]
    assert not _entries_of_kind(tmp_path, "salvage")
    (record,) = _repair_entries(tmp_path)
    assert record["outcome"] == "failed"
    assert record["applied"] == {}


def _digest(value: object) -> str:
    text = json.dumps(value, sort_keys=True) if not isinstance(value, str) else value
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


# Digests taken at producer e21ba7cf, before the correction salvaged a reply.
# The risk request and its correction follow the later labelling of the card
# evidence; the gap request, the draft and the record are unchanged.
_CLEAN_REQUEST_DIGESTS = ["20a4fc93c0bd", "af63ccd21898", "e012f7f0fe48"]
_CLEAN_DRAFT_DIGEST = "9a06ccbe22a79f92"
_CLEAN_RECORD_DIGEST = "ecbb3e315958b957"


def test_clean_correction_sends_the_same_requests_and_gives_the_same_draft(tmp_path):
    clean = _chain_reply(
        constraints=[
            _constraint_row(
                "session_binding_constraint",
                _SESSION_RULE,
                _obligation("O1", _SESSION_SPAN),
            )
        ]
    )
    client = _client(_EMPTY_REPLY, clean, _gap_reply())

    result = _derive(client, tmp_path)

    assert [
        hashlib.sha256(call.user_prompt.encode("utf-8")).hexdigest()[:12]
        for call in client.calls
    ] == _CLEAN_REQUEST_DIGESTS
    assert _digest(result.model_dump(mode="json")) == _CLEAN_DRAFT_DIGEST
    records = _repair_record(tmp_path)["records"]
    assert _digest(records) == _CLEAN_RECORD_DIGEST
    assert [(entry["kind"], entry["outcome"]) for entry in records] == [
        ("repair", "repaired")
    ]


def test_salvage_of_a_reply_with_no_failing_row_is_unsupported():
    reply = LLMResult(
        content={
            "risk_card_losses": [],
            "use_case_losses": [],
            "hazards": [],
            "security_constraints": [],
            "risk_dispositions": [],
        },
        duration_ms=0,
    )

    outcome = salvage_corrected_reply(
        reply,
        constraint_wire_model=_ProviderSecurityConstraint,
        response_format=_Stage1aRiskRepairDraft,
        gap_wire=False,
    )

    assert isinstance(outcome, UnsupportedRepair)
    assert "no record-level row" in outcome.reason


def test_salvage_of_a_reply_with_a_malformed_hazard_is_unsupported():
    reply = LLMResult(
        content={
            "risk_card_losses": [],
            "use_case_losses": [],
            "hazards": [{"hazard_id": "H-1"}],
            "security_constraints": [],
            "risk_dispositions": [],
        },
        duration_ms=0,
    )

    outcome = salvage_corrected_reply(
        reply,
        constraint_wire_model=_ProviderSecurityConstraint,
        response_format=_Stage1aRiskRepairDraft,
        gap_wire=False,
    )

    assert isinstance(outcome, UnsupportedRepair)
    assert "outside the approved repair scope" in outcome.reason
    assert "H-1" in outcome.reason


def test_salvaged_draft_that_leaves_the_provider_schema_stops_the_unit(
    tmp_path, monkeypatch
):
    # Salvage builds its draft from valid rows, so only a faulty salvage can
    # exceed the schema; the check is the boundary that catches it.
    oversized = LossAnalysisDraft.model_construct(
        risk_card_losses=[],
        use_case_losses=[],
        hazards=[
            Hazard(hazard_id=f"H-{index}", description="d", related_losses=["L-1"])
            for index in range(1, 18)
        ],
        security_constraints=[],
        risk_dispositions=[],
    )
    real = loss_analysis.salvage_corrected_reply

    def faulty(reply, **kwargs):
        outcome = real(reply, **kwargs)
        return (oversized, outcome[1])

    monkeypatch.setattr(loss_analysis, "salvage_corrected_reply", faulty)
    client = _client(_EMPTY_REPLY, _chain_reply(), _gap_reply())

    with pytest.raises(StageError) as exc_info:
        _derive(client, tmp_path)

    assert "no longer satisfies the original provider schema" in str(exc_info.value)
    assert len(client.calls) == 2
