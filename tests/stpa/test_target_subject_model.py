"""The closed ``target-subject-model-v1`` companion (correction spec 2026-09-12).

Offline acceptance cases P1-P8 (session-path precedence, spec 6.1), the
record-index units (M-S9, M-S10), the structural loader cases (M-S11,
M-S12), and the acceptance-envelope fail-closed cases (M-S19 through
M-S23).  Saved MiniOcciAI inputs come from the byte-identical fixture
copies under ``tests/fixtures/miniocciai-baseline-rev2/``; tests never
write to them or to the frozen run directory they mirror.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest
import yaml

from asago_scenario_generator.stpa.models.target_subject_model import (
    RecordIndex,
    SubjectArgumentRole,
    SubjectModelCollection,
    SubjectModelError,
    SubjectRelation,
    TargetSubjectModel,
    TargetSubjectModelAcceptance,
    load_target_subject_model,
    parse_target_subject_model,
    resolve_comparable_string,
    resolve_session_subject,
)

from tests.stpa.test_authoring_validation import (
    STATE as MINIKLARNA_STATE,
    _accepted_model,
    _observations,
    _profile,
)

FIXTURES = (
    Path(__file__).resolve().parents[1] / "fixtures" / "miniocciai-baseline-rev2"
)


def _occiai_state() -> dict:
    payload = yaml.safe_load((FIXTURES / "target-observations.yaml").read_text())
    (state_record,) = [
        record
        for record in payload["observations"]
        if record["observation_ref"] == "TARGET-STATE"
    ]
    return json.loads(state_record["content"])


# P1-P8: the single session-subject precedence rule (spec 6.1)


def test_p1_saved_occiai_discovers_the_single_session_key():
    session = resolve_session_subject(_occiai_state())
    assert session.status == "observed"
    assert session.path == ("authenticated_patient_id",)
    assert session.value == "PAT-104"
    assert session.rule == "discovered"


def test_p2_dropping_the_key_is_unobserved_not_an_error():
    state = _occiai_state()
    state.pop("authenticated_patient_id")
    session = resolve_session_subject(state)
    assert session.status == "unobserved"
    assert session.rule == "discovered"
    assert session.value is None


def test_p3_a_second_session_key_is_ambiguous_never_guessed():
    state = _occiai_state()
    state["authenticated_customer_id"] = "CUST001"
    session = resolve_session_subject(state)
    assert session.status == "ambiguous"
    assert session.value is None
    assert session.candidates == (
        "authenticated_customer_id",
        "authenticated_patient_id",
    )


def test_p4_a_declared_path_wins_over_ambiguous_discovery():
    state = _occiai_state()
    state["authenticated_customer_id"] = "CUST001"
    session = resolve_session_subject(
        state, session_path=("authenticated_patient_id",)
    )
    assert session.status == "observed"
    assert session.value == "PAT-104"
    assert session.rule == "declared"


def test_p5_a_declared_path_has_no_discovery_fallback():
    session = resolve_session_subject(
        _occiai_state(), session_path=("authenticated_customer_id",)
    )
    assert session.status == "unobserved"
    assert session.rule == "declared"


@pytest.mark.parametrize("bad_value", [17, ""])
def test_p6_a_declared_path_with_a_non_string_value_is_unobserved(bad_value):
    state = _occiai_state()
    state["authenticated_patient_id"] = bad_value
    session = resolve_session_subject(
        state, session_path=("authenticated_patient_id",)
    )
    assert session.status == "unobserved"
    assert session.rule == "declared"


def test_p7_miniklarna_discovers_the_customer_key():
    session = resolve_session_subject(MINIKLARNA_STATE)
    assert session.status == "observed"
    assert session.path == ("authenticated_customer_id",)
    assert session.value == "CUST001"
    assert session.rule == "discovered"


def test_p8_non_mapping_state_and_non_string_ids_are_unobserved():
    assert resolve_session_subject(["not", "a", "mapping"]).status == "unobserved"
    session = resolve_session_subject({"authenticated_customer_id": 17})
    assert session.status == "unobserved"


# The record index (spec 1.2): addressability only


def test_m9_a_sequence_without_identifier_field_is_not_addressable():
    state = {"queue": [{"qid": "Q1", "note": "first"}]}
    index = RecordIndex(state)
    assert not index.is_addressable("queue")
    assert index.lookup("queue", "Q1").status == "not_addressable"


def test_m9_a_declared_identifier_field_makes_a_sequence_addressable():
    model = TargetSubjectModel(
        collections=(
            SubjectModelCollection(name="queue", identifier_field="qid"),
        ),
    )
    state = {"queue": [{"qid": "Q1", "note": "first"}]}
    index = RecordIndex(state, model)
    lookup = index.lookup("queue", "Q1")
    assert lookup.status == "found"
    assert lookup.record["note"] == "first"


def test_m10_duplicate_list_identifiers_make_that_address_ambiguous():
    model = TargetSubjectModel(
        collections=(
            SubjectModelCollection(name="queue", identifier_field="qid"),
        ),
    )
    state = {
        "queue": [
            {"qid": "Q1", "note": "first"},
            {"qid": "Q1", "note": "second"},
            {"qid": "Q2", "note": "unique"},
        ]
    }
    index = RecordIndex(state, model)
    assert index.lookup("queue", "Q1").status == "ambiguous"
    assert index.lookup("queue", "Q2").status == "found"


def test_a_mapping_of_scalars_is_not_a_record_collection():
    index = RecordIndex({"config": {"retries": 3}})
    assert not index.is_addressable("config")


# Comparable-string resolution typed statuses (spec 1.4)


def test_resolution_without_a_model_is_no_role():
    index = RecordIndex(MINIKLARNA_STATE)
    resolution = resolve_comparable_string(
        model=None,
        index=index,
        session=resolve_session_subject(MINIKLARNA_STATE),
        tool="process_refund",
        argument="order_id",
        value="ORD-201",
    )
    assert resolution.status == "no_role"


def test_resolution_without_a_declared_relation_is_unresolved_not_guessed():
    model = TargetSubjectModel(
        collections=(SubjectModelCollection(name="orders"),),
        argument_roles=(
            SubjectArgumentRole(
                tool="process_refund",
                argument="order_id",
                role="record_address",
                collections=("orders",),
            ),
        ),
    )
    resolution = resolve_comparable_string(
        model=model,
        index=RecordIndex(MINIKLARNA_STATE, model),
        session=resolve_session_subject(MINIKLARNA_STATE),
        tool="process_refund",
        argument="order_id",
        value="ORD-201",
    )
    assert resolution.status == "unresolved"
    assert "no record-subject relation" in resolution.detail


# Structural loader cases (M-S11, M-S12) and target-input validation


def _miniklarna_model_payload() -> dict:
    return _accepted_model().model_dump(mode="json", exclude_none=True)


def test_m11_competing_relations_on_one_collection_are_invalid_at_load():
    payload = _miniklarna_model_payload()
    payload["relations"].append(
        {
            "id": "orders-owner-2",
            "collection": "orders",
            "field": "channel",
            "kind": "record_subject",
            "source": "test fixture",
        }
    )
    with pytest.raises(SubjectModelError) as excinfo:
        parse_target_subject_model(payload)
    assert excinfo.value.reason == "subject_model_invalid"


def test_m12_an_argument_role_without_a_tool_is_invalid_at_load():
    payload = _miniklarna_model_payload()
    payload["argument_roles"].append(
        {
            "argument": "order_id",
            "role": "record_address",
            "collections": ["orders"],
        }
    )
    with pytest.raises(SubjectModelError) as excinfo:
        parse_target_subject_model(payload)
    assert excinfo.value.reason == "subject_model_invalid"


def test_a_non_mapping_payload_is_invalid():
    with pytest.raises(SubjectModelError) as excinfo:
        parse_target_subject_model(["not", "a", "mapping"])
    assert excinfo.value.reason == "subject_model_invalid"


def test_target_input_validation_rejects_an_unknown_collection():
    model = _accepted_model().model_copy(
        update={
            "collections": (
                SubjectModelCollection(name="orders"),
                SubjectModelCollection(name="payment_plans"),
                SubjectModelCollection(name="invoices"),
            )
        }
    )
    with pytest.raises(SubjectModelError) as excinfo:
        model.validate_against_target(MINIKLARNA_STATE, _profile())
    assert excinfo.value.reason == "subject_model_invalid"
    assert "invoices" in excinfo.value.detail


def test_target_input_validation_rejects_an_unknown_tool_role():
    payload = _miniklarna_model_payload()
    payload["argument_roles"].append(
        {
            "tool": "delete_order",
            "argument": "order_id",
            "role": "record_address",
            "collections": ["orders"],
        }
    )
    parsed = parse_target_subject_model(payload)
    with pytest.raises(SubjectModelError) as excinfo:
        parsed.validate_against_target(MINIKLARNA_STATE, _profile())
    assert excinfo.value.reason == "subject_model_invalid"
    assert "delete_order" in excinfo.value.detail


def test_target_input_validation_rejects_identifier_field_on_a_mapping():
    payload = _miniklarna_model_payload()
    payload["collections"][0]["identifier_field"] = "order_id"
    parsed = parse_target_subject_model(payload)
    with pytest.raises(SubjectModelError) as excinfo:
        parsed.validate_against_target(MINIKLARNA_STATE, _profile())
    assert excinfo.value.reason == "subject_model_invalid"


# Acceptance-envelope fail-closed cases (M-S19 through M-S23)


def _write_model(tmp_path: Path, payload: dict) -> Path:
    path = tmp_path / "target-subject-model.yaml"
    path.write_text(yaml.safe_dump(payload, sort_keys=True), encoding="utf-8")
    return path


def _load_kwargs() -> dict:
    return {
        "observations_digest": _observations().content_digest,
        "execution_target_profile_digest": _profile().semantic_digest,
        "state": MINIKLARNA_STATE,
        "profile": _profile(),
    }


def test_an_accepted_model_file_loads(tmp_path):
    path = _write_model(tmp_path, _miniklarna_model_payload())
    model = load_target_subject_model(path, **_load_kwargs())
    assert model.acceptance is not None
    assert model.session_path == ("authenticated_customer_id",)


def test_m19_a_structurally_valid_file_without_stamps_is_unreviewed(tmp_path):
    payload = _miniklarna_model_payload()
    del payload["acceptance"]
    path = _write_model(tmp_path, payload)
    with pytest.raises(SubjectModelError) as excinfo:
        load_target_subject_model(path, **_load_kwargs())
    assert excinfo.value.reason == "subject_model_unreviewed"


def test_m19_an_envelope_with_digests_but_no_stamps_is_proposed(tmp_path):
    """Spec 1.3: both stamps absent is proposed (unreviewed), not invalid;
    one without the other is invalid (M-S23)."""
    payload = _miniklarna_model_payload()
    del payload["acceptance"]["reviewed_by"]
    del payload["acceptance"]["reviewed_on"]
    path = _write_model(tmp_path, payload)
    with pytest.raises(SubjectModelError) as excinfo:
        load_target_subject_model(path, **_load_kwargs())
    assert excinfo.value.reason == "subject_model_unreviewed"


def test_m20_edited_content_without_restamping_fails_closed(tmp_path):
    payload = _miniklarna_model_payload()
    payload["relations"][0]["field"] = "account_id"
    path = _write_model(tmp_path, payload)
    with pytest.raises(SubjectModelError) as excinfo:
        load_target_subject_model(path, **_load_kwargs())
    assert excinfo.value.reason == "subject_model_content_mismatch"


def _restamped_payload(**acceptance_overrides) -> dict:
    """An accepted payload whose content digest matches its own edits."""
    acceptance = {
        "observations_digest": _observations().content_digest,
        "execution_target_profile_digest": _profile().semantic_digest,
        "reviewed_by": "owner:test",
        "reviewed_on": "2026-09-12",
        "content_digest": "0" * 64,
    }
    acceptance.update(acceptance_overrides)
    model = _accepted_model().model_copy(update={"acceptance": None})
    payload = model.model_dump(mode="json", exclude_none=True)
    payload["acceptance"] = acceptance
    parsed = parse_target_subject_model(payload)
    payload["acceptance"]["content_digest"] = parsed.compute_content_digest()
    return payload


def test_m21_a_foreign_observations_digest_fails_closed(tmp_path):
    payload = _restamped_payload(observations_digest="1" * 64)
    path = _write_model(tmp_path, payload)
    with pytest.raises(SubjectModelError) as excinfo:
        load_target_subject_model(path, **_load_kwargs())
    assert excinfo.value.reason == "subject_model_observations_mismatch"


def test_m22_a_foreign_profile_digest_fails_closed(tmp_path):
    payload = _restamped_payload(execution_target_profile_digest="2" * 64)
    path = _write_model(tmp_path, payload)
    with pytest.raises(SubjectModelError) as excinfo:
        load_target_subject_model(path, **_load_kwargs())
    assert excinfo.value.reason == "subject_model_profile_mismatch"


def test_m23_one_reviewer_stamp_without_the_other_is_invalid(tmp_path):
    payload = _miniklarna_model_payload()
    del payload["acceptance"]["reviewed_on"]
    path = _write_model(tmp_path, payload)
    with pytest.raises(SubjectModelError) as excinfo:
        load_target_subject_model(path, **_load_kwargs())
    assert excinfo.value.reason == "subject_model_invalid"


def test_an_unreadable_or_malformed_file_is_invalid(tmp_path):
    path = tmp_path / "target-subject-model.yaml"
    path.write_text("schema_version: [unclosed", encoding="utf-8")
    with pytest.raises(SubjectModelError) as excinfo:
        load_target_subject_model(path, **_load_kwargs())
    assert excinfo.value.reason == "subject_model_invalid"
    with pytest.raises(SubjectModelError) as excinfo:
        load_target_subject_model(tmp_path / "missing.yaml", **_load_kwargs())
    assert excinfo.value.reason == "subject_model_invalid"


def test_accepted_model_reviewed_stamp_types():
    acceptance = _accepted_model().acceptance
    assert acceptance is not None
    assert acceptance.reviewed_by == "owner:test"
    assert acceptance.reviewed_on == date(2026, 9, 12)
    # The framed content digest is stable and self-excluding.
    assert acceptance.content_digest == _accepted_model().compute_content_digest()
