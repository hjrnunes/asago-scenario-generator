"""The mechanism library: entries as data, validated against code-owned IDs."""

from __future__ import annotations

import copy
from pathlib import Path
import re

from pydantic import ValidationError
import pytest
import yaml

from asago_scenario_generator.stpa.mechanism_library import (
    MECHANISM_LIBRARY_PATH,
    ControllerCrossing,
    MechanismId,
    bundled_mechanism_library,
    load_mechanism_library,
)
from asago_scenario_generator.stpa.models.control_structure import (
    FeedbackAuthorityStatus,
)


def _raw() -> dict:
    return yaml.safe_load(MECHANISM_LIBRARY_PATH.read_text())


def _load(tmp_path: Path, raw: dict):
    path = tmp_path / "library.yaml"
    path.write_text(yaml.safe_dump(raw))
    return load_mechanism_library(path)


def test_the_bundled_library_holds_one_entry_per_code_owned_id() -> None:
    library = bundled_mechanism_library()

    assert [entry.id for entry in library.mechanisms] == list(MechanismId)
    for mechanism_id in MechanismId:
        assert library.entry(mechanism_id).id is mechanism_id


def test_an_unknown_id_fails(tmp_path: Path) -> None:
    raw = _raw()
    raw["mechanisms"][0]["id"] = "fabricated_approval"

    with pytest.raises(ValidationError, match="fabricated_approval"):
        _load(tmp_path, raw)


def test_a_repeated_id_fails(tmp_path: Path) -> None:
    raw = _raw()
    raw["mechanisms"].append(copy.deepcopy(raw["mechanisms"][0]))

    with pytest.raises(ValidationError, match="repeats IDs: \\['user_claim'\\]"):
        _load(tmp_path, raw)


def test_a_missing_entry_fails(tmp_path: Path) -> None:
    raw = _raw()
    raw["mechanisms"] = [
        item for item in raw["mechanisms"] if item["id"] != "stale_feedback"
    ]

    with pytest.raises(ValidationError, match="lacks entries for: \\['stale_feedback'"):
        _load(tmp_path, raw)


@pytest.mark.parametrize(
    "field",
    [
        "name",
        "question",
        "signature",
        "required_evidence",
        "counterexamples",
        "safe_behavior",
    ],
)
def test_a_missing_field_fails(tmp_path: Path, field: str) -> None:
    raw = _raw()
    del raw["mechanisms"][1][field]

    with pytest.raises(ValidationError, match=field):
        _load(tmp_path, raw)


@pytest.mark.parametrize(
    "field", ["source_kinds", "authority", "process_model_refs", "crossing"]
)
def test_a_missing_signature_field_fails(tmp_path: Path, field: str) -> None:
    raw = _raw()
    del raw["mechanisms"][1]["signature"][field]

    with pytest.raises(ValidationError, match=field):
        _load(tmp_path, raw)


def test_an_unknown_field_fails(tmp_path: Path) -> None:
    raw = _raw()
    raw["mechanisms"][0]["notes"] = "free text"

    with pytest.raises(ValidationError, match="notes"):
        _load(tmp_path, raw)


@pytest.mark.parametrize("field", ["required_evidence", "counterexamples"])
def test_empty_evidence_or_counterexamples_fail(tmp_path: Path, field: str) -> None:
    raw = _raw()
    raw["mechanisms"][0][field] = []

    with pytest.raises(ValidationError, match=field):
        _load(tmp_path, raw)


def test_a_repeated_signature_value_fails(tmp_path: Path) -> None:
    raw = _raw()
    raw["mechanisms"][0]["signature"]["source_kinds"] = ["user_message"] * 2

    with pytest.raises(ValidationError, match="must not repeat a value"):
        _load(tmp_path, raw)


def test_an_unknown_source_kind_fails(tmp_path: Path) -> None:
    raw = _raw()
    raw["mechanisms"][0]["signature"]["source_kinds"] = ["email"]

    with pytest.raises(ValidationError, match="source_kinds"):
        _load(tmp_path, raw)


def test_the_safe_behavior_is_never_named_a_mitigation() -> None:
    """The prompt preflight rejects any field with the word ``mitigation``."""
    text = MECHANISM_LIBRARY_PATH.read_text().lower()

    assert "mitigation" not in text
    assert "safe_behavior" in text


def test_prompt_facing_text_names_no_use_case_identifier() -> None:
    reference = re.compile(r"\b(?:RESP|CA|FB|CP|PM|SC|H|L|CL|CM|AP)-\d")
    for entry in bundled_mechanism_library().mechanisms:
        for text in (entry.question, *entry.required_evidence, *entry.counterexamples):
            assert not reference.search(text), (entry.id, text)


def test_only_stale_feedback_applies_to_an_authoritative_channel() -> None:
    """An entitled channel can still report a state that has since changed."""
    authoritative = [
        entry.id
        for entry in bundled_mechanism_library().mechanisms
        if FeedbackAuthorityStatus.authoritative in entry.signature.authority
    ]

    assert authoritative == [MechanismId.stale_feedback]


def test_only_delegated_authority_must_cross_controllers() -> None:
    crossing = {
        entry.id: entry.signature.crossing
        for entry in bundled_mechanism_library().mechanisms
    }

    assert [
        mechanism
        for mechanism, value in crossing.items()
        if value is ControllerCrossing.must_cross
    ] == [MechanismId.delegated_authority]
