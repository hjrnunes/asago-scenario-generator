"""Acceptance tests for the producer-owned scenario-handoff contract kit.

The kit is the producer's versioned handoff envelope: narrative, attack path,
Gherkin and necessary metadata, with a lock/digest record the consumer vendors
byte-for-byte. These tests assert the kit's content, its schema, its canonical
digests, and the exact ownership-boundary violations the invalid fixtures
retain. They also assert the kit introduces no fourth authoritative scenario
representation. The invalid shape fixtures are checked in
``test_scenario_handoff_kit.py``.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from asago_contracts_core import spec_digest
from asago_scenario_generator.models.canonical import canonical_json_bytes
from asago_scenario_generator.stpa.observation_contract import SafeObservableOutcome
from asago_scenario_generator.stpa.scenario_prod.handoff import (
    HANDOFF_SCHEMA_VERSION_V6,
    HandoffGherkin,
    ScenarioHandoffV6,
    _FORBIDDEN_KEYS,
    _FORBIDDEN_VALUE_PATTERNS,
    handoff_ownership_violations,
    handoff_payload_digest,
    handoff_schema_violations,
    verify_handoff_digest,
)
from asago_scenario_generator.stpa.scenario_prod.handoff_schema import handoff_schema

CONTRACT_ROOT = Path(__file__).resolve().parents[2] / "data/contracts/scenario-handoff"
VERSION_DIR = CONTRACT_ROOT / HANDOFF_SCHEMA_VERSION_V6
# The cases live under the version directory; these tests read them by their
# paths relative to it.
KIT = VERSION_DIR / "cases"


def _lock() -> dict:
    return json.loads((CONTRACT_ROOT / "CONTRACT.lock").read_text(encoding="utf-8"))


def _spec() -> dict:
    return json.loads((VERSION_DIR / "spec.json").read_text(encoding="utf-8"))


def _digests() -> dict:
    return json.loads((KIT / "canonical-digests.json").read_text(encoding="utf-8"))


def _expected_violations() -> dict:
    return json.loads((KIT / "expected-violations.json").read_text(encoding="utf-8"))


def _schema() -> dict:
    return json.loads((VERSION_DIR / "schema.json").read_text(encoding="utf-8"))


def _valid_fixtures() -> list[Path]:
    return sorted((KIT / "valid").glob("*.json"))


def test_the_spec_identifies_the_published_version() -> None:
    spec = _spec()
    schema_bytes = (VERSION_DIR / "schema.json").read_bytes()

    assert (spec["contract"], spec["version"]) == (
        "scenario-handoff",
        HANDOFF_SCHEMA_VERSION_V6,
    )
    assert (spec["status"], spec["envelope"]) == ("published", "required")
    assert spec["supports"] == []
    assert spec["extensions"] == []
    assert spec["schema"] == "schema.json"
    assert spec["cases"] == "cases"
    assert spec["docs"] == "README.md"
    body = {name: value for name, value in spec.items() if name != "spec_digest"}
    assert spec["spec_digest"] == spec_digest(body, schema_bytes)


def test_the_lock_pins_every_file_beside_it() -> None:
    lock = _lock()
    on_disk = {
        path.relative_to(CONTRACT_ROOT).as_posix(): hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
        for path in CONTRACT_ROOT.rglob("*")
        if path.is_file() and path.name != "CONTRACT.lock"
    }

    assert (lock["authority"], lock["contract"]) == (
        "asago-scenario-generator",
        "scenario-handoff",
    )
    # The lock names the published version.
    assert lock["schema_version"] == HANDOFF_SCHEMA_VERSION_V6
    assert lock["files"] == on_disk


def test_schema_matches_the_published_handoff_schema() -> None:
    assert _schema() == handoff_schema()


def test_schema_file_is_the_published_schema_byte_for_byte() -> None:
    committed = (VERSION_DIR / "schema.json").read_text(encoding="utf-8")

    rendered = json.dumps(handoff_schema(), indent=2) + "\n"

    assert rendered == committed
    assert list(ScenarioHandoffV6.model_fields) == list(_schema()["properties"])


def test_the_published_schema_adds_only_its_rule_assertions() -> None:
    model = ScenarioHandoffV6.model_json_schema()
    published = _schema()

    assert published["properties"] == model["properties"]
    assert published["required"] == model["required"]
    assert set(published["$defs"]) == set(model["$defs"])


def test_kit_introduces_no_fourth_scenario_representation() -> None:
    representations = {"narrative", "attack_path", "gherkin"}
    # Every top-level schema property is one of the three representations or a
    # named metadata field; the spec adds nothing else.
    schema = _schema()
    assert representations <= set(schema["properties"])
    assert set(schema["properties"]) == set(ScenarioHandoffV6.model_fields)
    assert schema["additionalProperties"] is False


@pytest.mark.parametrize("fixture", _valid_fixtures(), ids=lambda path: path.name)
def test_valid_handoff_fixtures_round_trip_with_digests(fixture: Path) -> None:
    payload = json.loads(fixture.read_text(encoding="utf-8"))
    relative = f"valid/{fixture.name}"

    assert not list(Draft202012Validator(_schema()).iter_errors(payload))
    assert handoff_schema_violations(payload) == []
    verify_handoff_digest(ScenarioHandoffV6.model_validate(payload))
    assert handoff_ownership_violations(payload) == []
    # The semantic failure criterion and the safe alternative are retained.
    assert payload["semantic_failure_criterion"].strip()
    assert payload["safe_alternative"].strip()
    assert payload["hypothesis_framing"] == payload["hypothesis_framing"].strip()
    # The three representations are all present, and the .feature companion
    # renders from the handoff alone.
    assert payload["narrative"].strip()
    assert payload["attack_path"]
    gherkin = HandoffGherkin.model_validate(payload["gherkin"])
    assert gherkin.feature.strip()
    assert gherkin.to_feature_text().startswith("Feature: ")
    # The digest is reproducible from the payload without its own digest.
    payload_without_digest = {
        key: value for key, value in payload.items() if key != "content_digest"
    }
    assert handoff_payload_digest(payload_without_digest) == payload["content_digest"]
    digests = _digests()
    assert digests["handoff_digests"][relative] == payload["content_digest"]
    assert (
        digests["content_sha256"][relative]
        == hashlib.sha256(fixture.read_bytes()).hexdigest()
    )
    # Canonical JSON is stable for the envelope payload.
    assert canonical_json_bytes(payload_without_digest)


def test_valid_fixtures_cover_adversarial_and_functional_cases() -> None:
    kinds = set()
    for fixture in _valid_fixtures():
        payload = json.loads(fixture.read_text(encoding="utf-8"))
        kinds.add(payload["kind"])
    assert kinds == {"adversarial", "functional"}


def test_valid_fixtures_cover_every_condition_shape() -> None:
    shapes = set()
    for fixture in _valid_fixtures():
        payload = json.loads(fixture.read_text(encoding="utf-8"))
        assert payload["schema_version"] == HANDOFF_SCHEMA_VERSION_V6
        condition = payload.get("discriminating_condition")
        if condition is None:
            assert "condition_check" not in payload
            shapes.add("omitted" if "condition_omitted_reason" in payload else "absent")
            continue
        assert "condition_omitted_reason" not in payload
        assert payload["condition_check"]["status"] in {
            "satisfied",
            "violated",
            "not_checkable",
        }
        shapes.add(condition["record_selection"]["status"])
        shapes.update(item["kind"] for item in condition["comparisons"])
    assert shapes == {
        "observed",
        "unavailable",
        "absent",
        "omitted",
        "value",
        "order",
        "not_called",
    }


def test_handoff_rejects_an_omission_note_beside_a_condition() -> None:
    payload = json.loads(
        (KIT / "valid/adversarial-observed-record.json").read_text(encoding="utf-8")
    )
    payload["condition_omitted_reason"] = "The condition was omitted."
    assert handoff_schema_violations(payload) == ["schema_violation:<root>"]


def test_valid_fixtures_cover_bound_and_not_executable() -> None:
    statuses = set()
    for fixture in _valid_fixtures():
        payload = json.loads(fixture.read_text(encoding="utf-8"))
        status = payload["tool_call_condition_status"]
        statuses.add(status["status"])
        assert ("tool_call_condition" in payload) == (status["status"] == "bound")
        if status["status"] == "bound":
            assert status["reason"] == "bound"
            operands = [
                side
                for comparison in payload["tool_call_condition"]["comparisons"]
                for side in (comparison.get("left"), comparison.get("right"))
                if side is not None
            ]
            assert {side["source"] for side in operands} <= {"argument", "literal"}
    assert statuses == {"bound", "not_executable"}


KEY = "artifact_design_field:"
PROSE = "prose_hiding:"
SCHEMA = "schema_violation:"

# Ownership cases the kit carries: fixture -> typed codes.
OWNERSHIP_CASES: dict[str, list[str]] = {
    "narrative-role-serialization.json": [PROSE + "role_serialization"],
    "narrative-turn-array.json": [PROSE + "turn_array"],
    "ownership-oracle-kind-key.json": [KEY + "oracle_kind"],
    "ownership-oracle-observes-key.json": [KEY + "oracle_observes"],
    "ownership-oracle-basis-key.json": [KEY + "oracle_basis"],
    "ownership-deliver-this-message.json": [PROSE + "ready_to_send_instruction"],
    "ownership-system-prompt-is.json": [PROSE + "ready_to_send_instruction"],
    "ownership-judge-prompt.json": [PROSE + "judge_prompt"],
    "ownership-key-name-pattern.json": [PROSE + "detector_expression"],
    "ownership-dotted-key.json": [KEY + "role"],
    "prepared-message-field.json": [PROSE + "prepared_message_field"],
    "role-turn-array.json": [PROSE + "role_serialization"],
    "smuggled-prose.json": [
        PROSE + "detector_expression",
        PROSE + "ready_to_send_instruction",
    ],
    "stimulus-turn-field.json": [KEY + "stimulus_turns", KEY + "role"],
}


# Ownership cases that add a key to the closed attack path, which the schema
# rejects as well.
ATTACK_PATH_KEY_CASES = {
    "ownership-oracle-kind-key.json",
    "ownership-oracle-observes-key.json",
    "ownership-oracle-basis-key.json",
    "ownership-key-name-pattern.json",
    "ownership-dotted-key.json",
    "stimulus-turn-field.json",
}


@pytest.mark.parametrize("name", list(OWNERSHIP_CASES))
def test_ownership_cases_are_rejected_for_the_producers_reason(name: str) -> None:
    expected = OWNERSHIP_CASES[name]
    payload = json.loads((KIT / "invalid" / name).read_text(encoding="utf-8"))
    in_path = name in ATTACK_PATH_KEY_CASES

    assert handoff_ownership_violations(payload) == expected
    assert _expected_violations()[f"invalid/{name}"] == expected + (
        [SCHEMA + "attack_path"] if in_path else []
    )
    assert bool(list(Draft202012Validator(_schema()).iter_errors(payload))) is in_path


def test_the_kit_exercises_every_prose_pattern_and_oracle_key() -> None:
    recorded = {code for codes in _expected_violations().values() for code in codes}
    required = {PROSE + slug for slug, _ in _FORBIDDEN_VALUE_PATTERNS} | {
        KEY + key for key in _FORBIDDEN_KEYS if key.startswith("oracle_")
    }

    assert required <= recorded


def test_expected_violations_name_every_invalid_fixture() -> None:
    named = set(_expected_violations())
    present = {f"invalid/{path.name}" for path in (KIT / "invalid").glob("*.json")}
    assert named == present


OBSERVATION = [SCHEMA + "observation"]
DEDUPLICATION = [SCHEMA + "deduplication"]
SAFE_OUTCOME = [SCHEMA + "safe_observable_outcome"]
TOOL_CALL_STATUS = [SCHEMA + "tool_call_condition_status"]

# Schema-level cases, each one broken field of a bound adversarial handoff:
# fixture stem -> codes.
SCHEMA_CASES: dict[str, list[str]] = {
    # See ``handoff._OTHER_VERSION_VIOLATIONS`` for the second code.
    "schema-unknown-version": [SCHEMA + "schema_version", SCHEMA + "attack_shape"],
    "schema-missing-narrative": [SCHEMA + "narrative"],
    "schema-unknown-field": [SCHEMA + "bogus"],
    "schema-kind-not-enumerated": [SCHEMA + "kind"],
    "schema-blank-narrative": [SCHEMA + "narrative"],
    "schema-safe-alternative-not-text": [SCHEMA + "safe_alternative"],
    "schema-scenario-version-not-integer": [SCHEMA + "scenario_version"],
    "schema-unknown-not-text": [SCHEMA + "assumptions_and_unknowns"],
    "schema-attack-path-not-object": [SCHEMA + "attack_path"],
    "schema-lineage-not-object": [SCHEMA + "lineage"],
    "schema-lineage-detector-field": [KEY + "detector", SCHEMA + "lineage"],
    "schema-gherkin-not-object": [SCHEMA + "gherkin"],
    "schema-gherkin-scenario-null": [SCHEMA + "gherkin"],
    "schema-gherkin-unknown-field": [SCHEMA + "gherkin"],
    "schema-gherkin-given-not-list": [SCHEMA + "gherkin"],
    "schema-observation-not-object": OBSERVATION,
    "schema-observation-missing-criteria": OBSERVATION,
    "schema-observation-unknown-field": OBSERVATION,
    "schema-observation-criteria-empty": OBSERVATION,
    "schema-observation-criterion-not-object": OBSERVATION,
    "schema-criterion-missing-reason": OBSERVATION,
    "schema-criterion-unknown-field": OBSERVATION,
    "schema-criterion-blank-outcome": OBSERVATION,
    "schema-criterion-observable-not-boolean": OBSERVATION,
    "schema-criterion-observable-without-claim": OBSERVATION,
    "schema-criterion-analytical-with-operation": OBSERVATION,
    "schema-assessment-not-object": OBSERVATION,
    "schema-assessment-missing-reason": OBSERVATION,
    "schema-assessment-disposition-not-enumerated": OBSERVATION,
    "schema-assessment-blank-reason": OBSERVATION,
    "schema-assessment-supported-not-list": OBSERVATION,
    "schema-deduplication-not-object": DEDUPLICATION,
    "schema-deduplication-missing-key": DEDUPLICATION,
    "schema-deduplication-unknown-field": DEDUPLICATION,
    "schema-deduplication-blank-scenario-id": DEDUPLICATION,
    "schema-deduplication-status-not-enumerated": DEDUPLICATION,
    "schema-deduplication-key-not-object": DEDUPLICATION,
    "schema-deduplication-key-missing-claim": DEDUPLICATION,
    "schema-deduplication-key-blank-operation": DEDUPLICATION,
    "schema-deduplication-key-claim-not-enumerated": DEDUPLICATION,
    "schema-deduplication-key-constraint-ids-not-list": DEDUPLICATION,
    "schema-deduplication-key-constraint-id-blank": DEDUPLICATION,
    "schema-safe-outcome-not-object": SAFE_OUTCOME,
    "schema-safe-outcome-unknown-field": SAFE_OUTCOME,
    "schema-safe-outcome-empty": SAFE_OUTCOME,
    "schema-safe-outcome-blank-statement": SAFE_OUTCOME,
    "schema-safe-outcome-analytical-with-refs": SAFE_OUTCOME,
    "schema-condition-not-object": [SCHEMA + "discriminating_condition"],
    "schema-missing-tool-call-status": TOOL_CALL_STATUS,
    "schema-tool-call-status-not-enumerated": TOOL_CALL_STATUS,
    "schema-tool-call-reason-not-bound": TOOL_CALL_STATUS,
    "schema-tool-call-condition-empty": [SCHEMA + "tool_call_condition"],
    "schema-bound-without-tool-call-condition": [SCHEMA + "<root>"],
    "schema-not-executable-with-tool-call-condition": [SCHEMA + "<root>"],
    # The top-level variant of stimulus-turn-field. The closed schema
    # rejects the unknown field before a reader's ownership scan runs.
    "schema-stimulus-turn-field-top-level": [
        KEY + "stimulus_turns",
        KEY + "role",
        SCHEMA + "stimulus_turns",
    ],
}
# Cases the producer model rejects through a validator the JSON schema cannot
# express; a reader that checks only schema.json accepts them.
MODEL_ONLY_SCHEMA_CASES = {
    "schema-blank-narrative",
    "schema-criterion-blank-outcome",
    "schema-criterion-observable-without-claim",
    "schema-criterion-analytical-with-operation",
    "schema-assessment-blank-reason",
    "schema-tool-call-reason-not-bound",
}


def test_the_schema_states_the_taxonomy_reference_uniqueness_rule() -> None:
    """The schema rejects a repeated reference; it cannot state their order."""

    payload = json.loads((KIT / "valid/taxonomy-block.json").read_text("utf-8"))
    references = payload["taxonomy"]["references"]
    references.append(dict(references[0]))

    assert list(Draft202012Validator(_schema()).iter_errors(payload))


def test_the_schema_treats_an_empty_call_argument_list_as_absent() -> None:
    """The model turns an empty list into an absent field; the schema agrees."""

    payload = json.loads((KIT / "valid/safe-call-arguments.json").read_text("utf-8"))
    outcome = payload["safe_observable_outcome"]
    outcome["call_arguments"] = []

    assert not list(Draft202012Validator(_schema()).iter_errors(payload))
    SafeObservableOutcome.model_validate(outcome)


def test_the_schema_requires_the_operation_a_call_names() -> None:
    """A call stays bound to its operation; the schema and the model both refuse."""

    payload = json.loads((KIT / "valid/safe-call-arguments.json").read_text("utf-8"))
    outcome = payload["safe_observable_outcome"]
    del outcome["operation_name"]

    assert list(Draft202012Validator(_schema()).iter_errors(payload))
    with pytest.raises(ValidationError):
        SafeObservableOutcome.model_validate(outcome)


def test_each_schema_case_is_rejected_with_its_recorded_codes() -> None:
    present = {path.stem for path in (KIT / "invalid").glob("schema-*.json")}
    assert present == set(SCHEMA_CASES)
    validator = Draft202012Validator(_schema())
    for name, codes in SCHEMA_CASES.items():
        payload = json.loads((KIT / "invalid" / f"{name}.json").read_text("utf-8"))
        found = handoff_ownership_violations(payload)
        found += handoff_schema_violations(payload)
        assert found == codes, name
        assert _expected_violations()[f"invalid/{name}.json"] == codes, name
        schema_rejects = bool(list(validator.iter_errors(payload)))
        assert schema_rejects is (name not in MODEL_ONLY_SCHEMA_CASES), name
        if name != "schema-unknown-version":
            # Signed, so a reader that checks the digest first reaches the field.
            unsigned = {k: v for k, v in payload.items() if k != "content_digest"}
            assert payload["content_digest"] == handoff_payload_digest(unsigned), name
