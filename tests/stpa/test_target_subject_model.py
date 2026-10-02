"""Session-subject discovery and the record index over TARGET-STATE.

Saved MiniOcciAI inputs come from the byte-identical fixture copies under
``tests/fixtures/miniocciai-baseline-rev2/``; tests never write to them or
to the frozen run directory they mirror.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from asago_scenario_generator.stpa.models.target_subject_model import (
    RecordIndex,
    resolve_session_subject,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "miniocciai-baseline-rev2"

MINIKLARNA_STATE = {
    "authenticated_customer_id": "CUST001",
    "orders": {
        "ORD-101": {"customer_id": "CUST001", "refund_eligible": True},
        "ORD-201": {"customer_id": "CUST002", "refund_eligible": True},
    },
}


def _occiai_state() -> dict:
    payload = yaml.safe_load((FIXTURES / "target-observations.yaml").read_text())
    (state_record,) = [
        record
        for record in payload["observations"]
        if record["observation_ref"] == "TARGET-STATE"
    ]
    return json.loads(state_record["content"])


# The session subject: one discovery rule


def test_saved_occiai_discovers_the_single_session_key():
    session = resolve_session_subject(_occiai_state())
    assert session.status == "observed"
    assert session.path == ("authenticated_patient_id",)
    assert session.value == "PAT-104"


def test_dropping_the_session_key_is_unobserved_not_an_error():
    state = _occiai_state()
    state.pop("authenticated_patient_id")
    session = resolve_session_subject(state)
    assert session.status == "unobserved"
    assert session.path is None
    assert session.value is None


def test_a_second_session_key_is_ambiguous_never_guessed():
    state = _occiai_state()
    state["authenticated_customer_id"] = "CUST001"
    session = resolve_session_subject(state)
    assert session.status == "ambiguous"
    assert session.value is None
    assert session.candidates == (
        "authenticated_customer_id",
        "authenticated_patient_id",
    )


def test_miniklarna_discovers_the_customer_key():
    session = resolve_session_subject(MINIKLARNA_STATE)
    assert session.status == "observed"
    assert session.path == ("authenticated_customer_id",)
    assert session.value == "CUST001"


def test_non_mapping_state_and_non_string_ids_are_unobserved():
    assert resolve_session_subject(["not", "a", "mapping"]).status == "unobserved"
    session = resolve_session_subject({"authenticated_customer_id": 17})
    assert session.status == "unobserved"


# The record index: addressability only


def test_only_the_saved_occiai_mapping_collections_are_addressable():
    # ehr_drafts is a sequence and ehr_records maps to empty lists: neither
    # is a record collection.
    index = RecordIndex(_occiai_state())
    assert set(index.collections) == {"education", "patients", "referrals"}


def test_a_sequence_of_records_is_not_addressable():
    index = RecordIndex({"queue": [{"qid": "Q1", "note": "first"}]})
    assert index.collections == ()


def test_a_mapping_of_scalars_is_not_a_record_collection():
    index = RecordIndex({"config": {"retries": 3}})
    assert index.collections == ()


def test_non_mapping_state_has_no_collections():
    assert RecordIndex(["not", "a", "mapping"]).collections == ()
