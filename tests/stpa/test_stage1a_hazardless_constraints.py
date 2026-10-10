"""Stage 1a: a risk-derivation reply whose constraints cite no declared hazard.

The fixture is a trimmed copy of a recorded risk-derivation reply (GLM, an
Airbnb unit, 2026-10-10): the reply wrote ``"hazards": []`` first, then its
losses, dispositions covering every supplied card, and constraints that each
cite a hazard handle declared nowhere.  One of those constraints also carries
a required obligation with ``violated_via``, a record-level wire error.  Only
the fields the code reads are kept; card texts are neutralized.  Every test
uses a fake client and contacts no network.
"""

from __future__ import annotations

import json
from copy import deepcopy

import pytest

from asago_scenario_generator.models.risk_card import RiskCard
from asago_scenario_generator.stpa.infra.llm_helpers import StageError
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysisDraft
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    derive_loss_analysis,
)
from asago_scenario_generator.stpa.system_model.loss_analysis_repair import (
    HAZARDLESS_CONSTRAINT_DROP_KIND,
    ReferenceRepairResponse,
    drop_hazardless_constraints,
)
from tests.helpers.stage1a_targeted_repair import _repair_record, _stage1a_entries
from tests.stpa.sp1_helpers import MockLLMClient

_USE_CASE = (
    "A neutralized lodging assistant answers guest and host questions about "
    "reservations and listings and escalates safety concerns."
)

_CARD_IDS = (
    "mit-ai-risk-subdomain-2.2",
    "credo-risk-037",
    "credo-risk-041",
    "credo-risk-002",
)


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


_PRIVACY_CONSTRAINT = {
    "applies_when": [],
    "behavior_class": "disclosure",
    "handle": "privacy_access_constraint",
    "obligations": [
        {
            "behavior": (
                "calling get_reservation for a reservation the session actor "
                "is not a party to"
            ),
            "kind": "forbidden",
            "obligation_id": "O1",
            "rule_span": (
                "Reservation or listing details may be returned only to the "
                "session actor who is the guest or host recorded on that record"
            ),
            "violated_via": "tool_call",
        }
    ],
    "related_hazards": ["privacy_exposure_hazard"],
    "rule": (
        "Reservation or listing details may be returned only to the session "
        "actor who is the guest or host recorded on that record."
    ),
}

# The recorded wire error: a required entry that names violated_via.
_ESCALATION_CONSTRAINT = {
    "applies_when": [
        "a conversation message, reservation detail, or user report contains "
        "a scam indication, wire-transfer request, off-platform payment "
        "attempt, harassment, or safety concern"
    ],
    "behavior_class": "missed_escalation",
    "handle": "escalation_constraint",
    "obligations": [
        {
            "behavior": (
                "opening a trust-and-safety case with escalate_trust_safety "
                "for a reportable topic"
            ),
            "kind": "required",
            "obligation_id": "O1",
            "rule_span": (
                "the assistant must open a trust-and-safety case via "
                "escalate_trust_safety for the affected reservation"
            ),
            "source_outcome": "",
            "violated_via": "tool_call",
        }
    ],
    "related_hazards": ["missed_trust_safety_escalation_hazard"],
    "rule": (
        "When a scam indication, wire-transfer request, or off-platform "
        "payment attempt involves a reservation, the assistant must open a "
        "trust-and-safety case via escalate_trust_safety for the affected "
        "reservation."
    ),
}


def _hazardless_reply() -> dict:
    """The trimmed recorded reply, top-level keys in the recorded order."""
    return {
        "hazards": [],
        "risk_card_losses": [
            {
                "description": (
                    "Reservation, listing, or message data is disclosed to a "
                    "session actor who is not a party to that reservation."
                ),
                "handle": "reservation_privacy_loss",
                "provenance": "risk_card",
                "source_risk_cards": [
                    "mit-ai-risk-subdomain-2.2",
                    "credo-risk-037",
                ],
            },
            {
                "description": (
                    "A stay or listing is changed against the rules governing it."
                ),
                "handle": "property_integrity_loss",
                "provenance": "risk_card",
                "source_risk_cards": [
                    "mit-ai-risk-subdomain-2.2",
                    "credo-risk-041",
                    "credo-risk-002",
                ],
            },
        ],
        "risk_dispositions": [
            {
                "disposition": "cited",
                "loss_ids": ["reservation_privacy_loss", "property_integrity_loss"],
                "risk_ref": "mit-ai-risk-subdomain-2.2",
            },
            {
                "disposition": "cited",
                "loss_ids": ["reservation_privacy_loss"],
                "risk_ref": "credo-risk-037",
            },
            {
                "disposition": "cited",
                "loss_ids": ["property_integrity_loss"],
                "risk_ref": "credo-risk-041",
            },
            {
                "disposition": "cited",
                "loss_ids": ["property_integrity_loss"],
                "risk_ref": "credo-risk-002",
            },
        ],
        "security_constraints": [
            deepcopy(_PRIVACY_CONSTRAINT),
            deepcopy(_ESCALATION_CONSTRAINT),
        ],
        "use_case_losses": [],
    }


def _gap_reply() -> dict:
    """A gap reply that derives one hazard and one constraint per loss.

    Canonical loss IDs follow the sorted handles, so the property loss is
    ``L-1`` and the privacy loss ``L-2``.
    """
    return {
        "risk_card_losses": [],
        "use_case_losses": [],
        "hazards": [
            {
                "handle": "privacy_exposure_hazard",
                "description": "The assistant returns a record to a non-party.",
                "related_losses": ["L-2"],
            },
            {
                "handle": "unauthorized_change_hazard",
                "description": "The assistant applies a change a rule forbids.",
                "related_losses": ["L-1"],
            },
        ],
        "security_constraints": [
            {
                "handle": "privacy_constraint",
                "rule": "The assistant must return a record only to a party.",
                "applies_when": [],
                "behavior_class": "disclosure",
                "related_hazards": ["privacy_exposure_hazard"],
                "obligations": [],
            },
            {
                "handle": "change_constraint",
                "rule": "The assistant must apply only permitted changes.",
                "applies_when": [],
                "behavior_class": "unauthorized_write",
                "related_hazards": ["unauthorized_change_hazard"],
                "obligations": [],
            },
        ],
    }


def _client(*replies) -> MockLLMClient:
    client = MockLLMClient()
    client.set_response_for(LossAnalysisDraft, [json.dumps(reply) for reply in replies])
    return client


def _derive(client: MockLLMClient, tmp_path):
    return derive_loss_analysis(
        llm_client=client,
        use_case_text=_USE_CASE,
        risk_cards=_cards(),
        run_dir=tmp_path,
    )


def _drop_records(tmp_path) -> list[dict]:
    path = tmp_path / "loss-analysis-repair.yaml"
    if not path.exists():
        return []
    return [
        entry
        for entry in _repair_record(tmp_path)["records"]
        if entry["kind"] == HAZARDLESS_CONSTRAINT_DROP_KIND
    ]


def test_hazardless_constraints_are_dropped_and_gap_analysis_runs(tmp_path):
    client = _client(_hazardless_reply(), _gap_reply())

    result = _derive(client, tmp_path)

    entries = _stage1a_entries(tmp_path)
    assert [entry["step"] for entry in entries] == [
        "risk_derivation",
        "gap_analysis",
    ]
    assert len(client.calls) == 2
    # Canonical IDs follow the sorted handles: property_integrity_loss is L-1.
    assert {
        loss.loss_id: loss.description[:12] for loss in result.risk_card_losses
    } == {
        "L-1": "A stay or li",
        "L-2": "Reservation,",
    }
    assert {row.risk_ref for row in result.risk_dispositions} == set(_CARD_IDS)
    # Only the gap reply's constraints survive.
    rules = [constraint.rule for constraint in result.security_constraints]
    assert rules == [
        "The assistant must return a record only to a party.",
        "The assistant must apply only permitted changes.",
    ]
    gap_prompt = client.calls[1].user_prompt
    assert "privacy_access_constraint" not in gap_prompt
    assert "escalation_constraint" not in gap_prompt
    (record,) = _drop_records(tmp_path)
    assert record["stage"] == "risk_derivation"
    assert record["outcome"] == "applied"
    assert record["applied"]["dropped_constraints"] == [
        "privacy_access_constraint",
        "escalation_constraint",
    ]
    assert record["proposed"]["undeclared_hazards"] == [
        "privacy_exposure_hazard",
        "missed_trust_safety_escalation_hazard",
    ]
    cleanup_names = [
        item["name"] for item in entries[0].get("cleanup_transformations", [])
    ]
    assert HAZARDLESS_CONSTRAINT_DROP_KIND in cleanup_names


def test_declared_hazard_with_an_unknown_reference_keeps_todays_routing(tmp_path):
    reply = _hazardless_reply()
    reply["hazards"] = [
        {
            "handle": "privacy_exposure_hazard",
            "description": "The assistant returns a record to a non-party.",
            "related_losses": ["reservation_privacy_loss"],
        }
    ]
    reply["security_constraints"] = [
        dict(deepcopy(_PRIVACY_CONSTRAINT), related_hazards=["unknown_hazard"])
    ]
    client = _client(reply, _gap_reply())

    # The reference repair is requested; the fake client has no reply for it.
    with pytest.raises(StageError, match="draft_references failure class"):
        _derive(client, tmp_path)

    assert [call.response_format for call in client.calls][1:] == [
        ReferenceRepairResponse
    ]
    assert _drop_records(tmp_path) == []


def test_hazardless_reply_without_constraints_records_no_drop(tmp_path):
    reply = _hazardless_reply()
    reply["security_constraints"] = []
    client = _client(reply, _gap_reply())

    result = _derive(client, tmp_path)

    assert [entry["step"] for entry in _stage1a_entries(tmp_path)] == [
        "risk_derivation",
        "gap_analysis",
    ]
    assert len(result.security_constraints) == 2
    assert _drop_records(tmp_path) == []


def _pp_s7_shaped_reply() -> dict:
    """Hazards declared and every constraint citing one of them."""
    reply = _hazardless_reply()
    reply["hazards"] = [
        {
            "handle": "privacy_exposure_hazard",
            "description": "The assistant returns a record to a non-party.",
            "related_losses": ["reservation_privacy_loss"],
        },
        {
            "handle": "unauthorized_change_hazard",
            "description": "The assistant applies a change a rule forbids.",
            "related_losses": ["property_integrity_loss"],
        },
    ]
    change = dict(
        deepcopy(_PRIVACY_CONSTRAINT),
        handle="change_access_constraint",
        related_hazards=["unauthorized_change_hazard"],
    )
    reply["security_constraints"] = [deepcopy(_PRIVACY_CONSTRAINT), change]
    return reply


def test_reply_with_declared_hazards_passes_through_unchanged(tmp_path):
    empty_gap = {
        "risk_card_losses": [],
        "use_case_losses": [],
        "hazards": [],
        "security_constraints": [],
    }
    client = _client(_pp_s7_shaped_reply(), empty_gap)

    result = _derive(client, tmp_path)

    assert len(result.hazards) == 2
    assert [c.related_hazards for c in result.security_constraints] == [
        ["H-1"],
        ["H-2"],
    ]
    assert _drop_records(tmp_path) == []
    cleanup_names = [
        item["name"]
        for item in _stage1a_entries(tmp_path)[0].get("cleanup_transformations", [])
    ]
    assert HAZARDLESS_CONSTRAINT_DROP_KIND not in cleanup_names


@pytest.mark.parametrize(
    "body,allowed,expected",
    [
        pytest.param(
            {
                "hazards": [],
                "security_constraints": [{"handle": "a", "related_hazards": ["x"]}],
            },
            set(),
            ("a",),
            id="dangling",
        ),
        pytest.param(
            {
                "hazards": [],
                "security_constraints": [{"handle": "a", "related_hazards": ["H-1"]}],
            },
            {"H-1"},
            None,
            id="allowed-hazard",
        ),
        pytest.param(
            {
                "hazards": [],
                "security_constraints": [
                    {"handle": "a", "related_hazards": ["x"]},
                    {"handle": "b", "related_hazards": ["H-1"]},
                ],
            },
            {"H-1"},
            None,
            id="one-reference-resolves",
        ),
        pytest.param(
            {
                "hazards": [{"handle": "h"}],
                "security_constraints": [{"handle": "a", "related_hazards": ["x"]}],
            },
            set(),
            None,
            id="hazard-declared",
        ),
        pytest.param(
            {"hazards": [], "security_constraints": []},
            set(),
            None,
            id="no-constraints",
        ),
        pytest.param(
            {"security_constraints": [{"handle": "a"}]},
            set(),
            None,
            id="no-hazards-key",
        ),
        pytest.param([], set(), None, id="not-an-object"),
        pytest.param(
            {"hazards": [], "security_constraints": "x"},
            set(),
            None,
            id="constraints-not-a-list",
        ),
    ],
)
def test_drop_applies_only_when_no_reference_can_resolve(body, allowed, expected):
    dropped = drop_hazardless_constraints(body, allowed_hazard_ids=allowed)

    if expected is None:
        assert dropped is None
    else:
        body_after, drop = dropped
        assert body_after["security_constraints"] == []
        assert drop.dropped_constraints == expected
