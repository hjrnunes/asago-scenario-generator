"""Stage 1a: the loss-presence correction's reply gets the hazard-less drop.

A risk-derivation reply that declares no grounded loss gets one correction.
That correction can answer with ``"hazards": []`` and constraints citing
hazards declared nowhere, the failure the first reply's drop already
rescues.  The drop applies to the corrected reply's decoded body too, with no
extra request, and the record names the repair attempt.  Every test uses a
fake client and contacts no network.
"""

from __future__ import annotations

import json

import pytest

from asago_scenario_generator.stpa.infra.llm_helpers import StageError
from asago_scenario_generator.stpa.system_model.loss_analysis_repair import (
    HAZARDLESS_CONSTRAINT_DROP_KIND,
)
from tests.helpers.stage1a_targeted_repair import _repair_record, _stage1a_entries
from tests.stpa.test_stage1a_loss_presence_repair import (
    _CARD_IDS,
    _EMPTY_REPLY,
    _client,
    _corrected_reply,
    _derive,
    _gap_reply,
)

_CITED_ONLY = ("privacy_exposure_hazard", "missed_escalation_hazard")


def _constraint(handle: str, hazard: str) -> dict:
    return {
        "handle": handle,
        "rule": f"Neutralized rule for {handle}.",
        "applies_when": [],
        "behavior_class": "disclosure",
        "related_hazards": [hazard],
        "obligations": [],
    }


def _correction_with_constraints(*, declare_hazard: bool = False) -> str:
    reply = json.loads(_corrected_reply())
    if declare_hazard:
        reply["hazards"] = [
            {
                "handle": "privacy_exposure_hazard",
                "description": "The assistant returns a record to a non-party.",
                "related_losses": ["reservation_privacy_loss"],
            }
        ]
        reply["security_constraints"] = [
            _constraint("privacy_access_constraint", "privacy_exposure_hazard")
        ]
    else:
        reply["security_constraints"] = [
            _constraint("privacy_access_constraint", _CITED_ONLY[0]),
            _constraint("escalation_constraint", _CITED_ONLY[1]),
        ]
    return json.dumps(reply)


def _empty_gap() -> str:
    return json.dumps(
        {
            "risk_card_losses": [],
            "use_case_losses": [],
            "hazards": [],
            "security_constraints": [],
        }
    )


def _drops(tmp_path) -> list[dict]:
    return [
        entry
        for entry in _repair_record(tmp_path)["records"]
        if entry["kind"] == HAZARDLESS_CONSTRAINT_DROP_KIND
    ]


def test_hazardless_correction_reply_is_dropped_with_no_extra_request(tmp_path):
    client = _client(_EMPTY_REPLY, _correction_with_constraints(), _gap_reply())

    result = _derive(client, tmp_path)

    entries = _stage1a_entries(tmp_path)
    assert [entry["step"] for entry in entries] == [
        "risk_derivation",
        "risk_derivation_repair",
        "gap_analysis",
    ]
    assert len(client.calls) == 3
    assert [constraint.rule for constraint in result.security_constraints] == [
        "The assistant must return a record only to a party."
    ]
    assert "privacy_access_constraint" not in client.calls[2].user_prompt
    assert "escalation_constraint" not in client.calls[2].user_prompt
    (drop,) = _drops(tmp_path)
    assert drop["stage"] == "risk_derivation"
    assert drop["attempt"] == "repair"
    assert drop["raw_step"] == "risk_derivation_repair"
    assert drop["outcome"] == "applied"
    assert drop["applied"]["dropped_constraints"] == [
        "privacy_access_constraint",
        "escalation_constraint",
    ]
    assert drop["proposed"]["undeclared_hazards"] == list(_CITED_ONLY)
    kinds = [
        (entry["kind"], entry["outcome"])
        for entry in _repair_record(tmp_path)["records"]
    ]
    assert kinds == [
        (HAZARDLESS_CONSTRAINT_DROP_KIND, "applied"),
        ("repair", "repaired"),
    ]
    cleanup_names = [
        item["name"] for item in entries[1].get("cleanup_transformations", [])
    ]
    assert HAZARDLESS_CONSTRAINT_DROP_KIND in cleanup_names
    first_cleanup = [
        item["name"] for item in entries[0].get("cleanup_transformations", [])
    ]
    assert HAZARDLESS_CONSTRAINT_DROP_KIND not in first_cleanup


def test_correction_citing_a_declared_hazard_is_not_dropped(tmp_path):
    client = _client(
        _EMPTY_REPLY, _correction_with_constraints(declare_hazard=True), _empty_gap()
    )

    result = _derive(client, tmp_path)

    assert len(client.calls) == 3
    assert [
        constraint.related_hazards for constraint in result.security_constraints
    ] == [["H-1"]]
    assert _drops(tmp_path) == []


def test_other_defects_in_the_dropped_correction_still_stop_the_unit(tmp_path):
    reply = json.loads(_correction_with_constraints())
    reply["risk_dispositions"] = reply["risk_dispositions"][:2]
    client = _client(_EMPTY_REPLY, json.dumps(reply), _gap_reply())

    with pytest.raises(StageError, match="targeted repair failed"):
        _derive(client, tmp_path)

    assert len(client.calls) == 2
    assert set(_CARD_IDS) - {row["risk_ref"] for row in reply["risk_dispositions"]}
    (repair,) = [
        entry
        for entry in _repair_record(tmp_path)["records"]
        if entry["kind"] == "repair"
    ]
    assert repair["outcome"] == "failed"
