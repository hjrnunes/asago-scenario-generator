"""Acceptance tests for the producer-owned scenario-handoff contract kit.

The kit is the producer's versioned handoff envelope: narrative, attack tree,
Gherkin and necessary metadata, with a lock/digest record the consumer vendors
byte-for-byte. These tests assert the kit's content, its schema, its canonical
digests, and the exact ownership-boundary violations the invalid fixtures
retain. They also assert the kit introduces no fourth authoritative scenario
representation.

Four kits coexist: ``handoff-v1``, ``handoff-v2`` and ``handoff-v3`` stay
byte-identical for consumers that still read them, and the producer no longer
has a model for them: their fixtures are checked against their own
``schema.json``, the ownership scan, the framed digest, and their recorded
codes. ``handoff-v2`` adds the Stage 5 discriminating condition and its
code-owned check; ``handoff-v3`` adds the condition's binding to a
ready-to-evaluate tool-call condition; ``handoff-v4`` adds the
``attack_shape``. The v4 invalid fixtures are checked in
``test_scenario_handoff_v4_kit.py``.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from asago_scenario_generator.models.canonical import canonical_json_bytes
from asago_scenario_generator.stpa.scenario_prod.handoff import (
    HANDOFF_SCHEMA_VERSION,
    HANDOFF_SCHEMA_VERSION_V2,
    HANDOFF_SCHEMA_VERSION_V4,
    HandoffGherkin,
    ScenarioHandoffV4,
    _FORBIDDEN_KEYS,
    _FORBIDDEN_VALUE_PATTERNS,
    handoff_ownership_violations,
    handoff_payload_digest,
    handoff_schema_violations,
    verify_handoff_digest,
)

CONTRACT_ROOT = Path(__file__).resolve().parents[2] / "data/contracts/scenario-handoff"
KIT_ROOT = CONTRACT_ROOT / "handoff-v1"
KIT_V2_ROOT = CONTRACT_ROOT / "handoff-v2"
KIT_V3_ROOT = CONTRACT_ROOT / "handoff-v3"
KIT_V4_ROOT = CONTRACT_ROOT / "handoff-v4"
KITS = (KIT_ROOT, KIT_V2_ROOT, KIT_V3_ROOT, KIT_V4_ROOT)
FROZEN_KITS = (KIT_ROOT, KIT_V2_ROOT, KIT_V3_ROOT)
V2_FIELDS = {"discriminating_condition", "condition_check", "condition_omitted_reason"}
V3_FIELDS = {"tool_call_condition_status", "tool_call_condition"}
V4_FIELDS = {"attack_shape"}


def _lock() -> dict:
    return json.loads((CONTRACT_ROOT / "CONTRACT.lock").read_text(encoding="utf-8"))


def _digests(kit: Path = KIT_ROOT) -> dict:
    return json.loads((kit / "canonical-digests.json").read_text(encoding="utf-8"))


def _expected_violations(kit: Path = KIT_ROOT) -> dict:
    return json.loads((kit / "expected-violations.json").read_text(encoding="utf-8"))


def _schema(kit: Path) -> dict:
    return json.loads((kit / "schema.json").read_text(encoding="utf-8"))


def _kit_fixtures(kind: str) -> list[tuple[Path, Path]]:
    return [
        (kit, fixture)
        for kit in KITS
        for fixture in sorted((kit / kind).glob("*.json"))
    ]


def _fixture_id(value: object) -> str:
    return value.name if isinstance(value, Path) else str(value)


def test_v4_schema_matches_the_producer_model() -> None:
    assert _schema(KIT_V4_ROOT) == ScenarioHandoffV4.model_json_schema()


def test_v4_schema_file_is_the_models_schema_byte_for_byte() -> None:
    committed = (KIT_V4_ROOT / "schema.json").read_text(encoding="utf-8")

    rendered = json.dumps(ScenarioHandoffV4.model_json_schema(), indent=2) + "\n"

    assert rendered == committed
    assert list(ScenarioHandoffV4.model_fields) == list(
        _schema(KIT_V4_ROOT)["properties"]
    )


def test_kit_introduces_no_fourth_scenario_representation() -> None:
    lock = _lock()
    assert lock["representations"] == ["narrative", "attack_tree", "gherkin"]
    # Every top-level schema property is one of the three representations or a
    # named metadata field; the envelope adds nothing else.
    declared = set(lock["representations"]) | set(lock["metadata_fields"])
    v1_schema = _schema(KIT_ROOT)
    v2_schema = _schema(KIT_V2_ROOT)
    v3_schema = _schema(KIT_V3_ROOT)
    v4_schema = _schema(KIT_V4_ROOT)
    assert set(v4_schema["properties"]) == declared
    assert set(v3_schema["properties"]) == declared - V4_FIELDS
    assert set(v2_schema["properties"]) == declared - V4_FIELDS - V3_FIELDS
    assert set(v1_schema["properties"]) == declared - V4_FIELDS - V3_FIELDS - V2_FIELDS
    for schema in (v1_schema, v2_schema, v3_schema, v4_schema):
        assert schema["additionalProperties"] is False


@pytest.mark.parametrize(("kit", "fixture"), _kit_fixtures("valid"), ids=_fixture_id)
def test_valid_handoff_fixtures_round_trip_with_digests(
    kit: Path, fixture: Path
) -> None:
    payload = json.loads(fixture.read_text(encoding="utf-8"))
    relative = f"valid/{fixture.name}"

    assert not list(Draft202012Validator(_schema(kit)).iter_errors(payload))
    if kit == KIT_V4_ROOT:
        assert handoff_schema_violations(payload) == []
        verify_handoff_digest(ScenarioHandoffV4.model_validate(payload))
    assert handoff_ownership_violations(payload) == []
    # The semantic failure criterion and the safe alternative are retained.
    assert payload["semantic_failure_criterion"].strip()
    assert payload["safe_alternative"].strip()
    assert payload["hypothesis_framing"] == payload["hypothesis_framing"].strip()
    # The three representations are all present, and the .feature companion
    # renders from the handoff alone.
    assert payload["narrative"].strip()
    assert payload["attack_tree"]
    gherkin = HandoffGherkin.model_validate(payload["gherkin"])
    assert gherkin.feature.strip()
    assert gherkin.to_feature_text().startswith("Feature: ")
    # The digest is reproducible from the payload without its own digest.
    payload_without_digest = {
        key: value for key, value in payload.items() if key != "content_digest"
    }
    assert handoff_payload_digest(payload_without_digest) == payload["content_digest"]
    digests = _digests(kit)
    assert digests["handoff_digests"][relative] == payload["content_digest"]
    assert (
        digests["content_sha256"][relative]
        == hashlib.sha256(fixture.read_bytes()).hexdigest()
    )
    # Canonical JSON is stable for the envelope payload.
    assert canonical_json_bytes(payload_without_digest)


@pytest.mark.parametrize("kit", KITS, ids=_fixture_id)
def test_valid_fixtures_cover_adversarial_and_functional_cases(kit: Path) -> None:
    kinds = set()
    for fixture in (kit / "valid").glob("*.json"):
        payload = json.loads(fixture.read_text(encoding="utf-8"))
        kinds.add(payload["kind"])
    assert kinds == {"adversarial", "functional"}


@pytest.mark.parametrize(
    ("kit", "version"),
    [
        (KIT_V2_ROOT, HANDOFF_SCHEMA_VERSION_V2),
        (KIT_V3_ROOT, HANDOFF_SCHEMA_VERSION),
        (KIT_V4_ROOT, HANDOFF_SCHEMA_VERSION_V4),
    ],
    ids=_fixture_id,
)
def test_valid_fixtures_cover_every_condition_shape(kit: Path, version: str) -> None:
    shapes = set()
    for fixture in (kit / "valid").glob("*.json"):
        payload = json.loads(fixture.read_text(encoding="utf-8"))
        assert payload["schema_version"] == version
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
        (KIT_V4_ROOT / "valid/adversarial-observed-record.json").read_text(
            encoding="utf-8"
        )
    )
    payload["condition_omitted_reason"] = "The condition was omitted."
    assert handoff_schema_violations(payload) == ["schema_violation:<root>"]


def test_v3_valid_fixtures_cover_bound_and_not_executable() -> None:
    statuses = set()
    for fixture in (KIT_V3_ROOT / "valid").glob("*.json"):
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


@pytest.mark.parametrize(
    ("kit", "fixture"),
    [pair for pair in _kit_fixtures("invalid") if pair[0] in FROZEN_KITS],
    ids=_fixture_id,
)
def test_frozen_invalid_fixtures_keep_their_recorded_codes(
    kit: Path, fixture: Path
) -> None:
    """The ownership scan finds the recorded ownership codes; the kit's own
    schema rejects the fixture exactly when a schema code is recorded and the
    retired model, not the schema, was the one to reject it."""
    payload = json.loads(fixture.read_text(encoding="utf-8"))
    expected = _expected_violations(kit)[f"invalid/{fixture.name}"]
    schema_codes = [code for code in expected if code.startswith(SCHEMA)]

    assert expected
    assert handoff_ownership_violations(payload) == [
        code for code in expected if not code.startswith(SCHEMA)
    ]
    if kit != KIT_ROOT:
        schema_rejects = bool(
            list(Draft202012Validator(_schema(kit)).iter_errors(payload))
        )
        assert schema_rejects is (
            bool(schema_codes) and fixture.stem not in MODEL_ONLY_SCHEMA_CASES
        )


KEY = "artifact_design_field:"
PROSE = "prose_hiding:"
SCHEMA = "schema_violation:"

# Ownership cases the v3 and v4 kits both carry: fixture -> typed codes. The
# last four are the handoff-v1 ownership cases.
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


@pytest.mark.parametrize(
    ("kit", "name"),
    [(kit, name) for kit in (KIT_V3_ROOT, KIT_V4_ROOT) for name in OWNERSHIP_CASES],
    ids=lambda value: _fixture_id(value),
)
def test_ownership_cases_are_rejected_for_the_producers_reason(
    kit: Path, name: str
) -> None:
    expected = OWNERSHIP_CASES[name]
    payload = json.loads((kit / "invalid" / name).read_text(encoding="utf-8"))

    assert handoff_ownership_violations(payload) == expected
    assert _expected_violations(kit)[f"invalid/{name}"] == expected
    assert not list(Draft202012Validator(_schema(kit)).iter_errors(payload))


@pytest.mark.parametrize("kit", [KIT_V3_ROOT, KIT_V4_ROOT])
def test_the_kit_exercises_every_prose_pattern_and_oracle_key(kit: Path) -> None:
    recorded = {code for codes in _expected_violations(kit).values() for code in codes}
    required = {PROSE + slug for slug, _ in _FORBIDDEN_VALUE_PATTERNS} | {
        KEY + key for key in _FORBIDDEN_KEYS if key.startswith("oracle_")
    }

    assert required <= recorded


def test_expected_violations_name_every_invalid_fixture() -> None:
    for kit in KITS:
        named = set(_expected_violations(kit))
        present = {f"invalid/{path.name}" for path in (kit / "invalid").glob("*.json")}
        assert named == present, kit.name


def test_invalid_fixture_carrying_a_prepared_message_field_is_rejected() -> None:
    payload = json.loads(
        (KIT_ROOT / "invalid/stimulus-turn-field.json").read_text(encoding="utf-8")
    )
    assert "artifact_design_field:stimulus_turns" in handoff_ownership_violations(
        payload
    )
    schema = json.loads((KIT_ROOT / "schema.json").read_text(encoding="utf-8"))
    assert list(Draft202012Validator(schema).iter_errors(payload))


OBSERVATION = [SCHEMA + "observation"]
DEDUPLICATION = [SCHEMA + "deduplication"]
SAFE_OUTCOME = [SCHEMA + "safe_observable_outcome"]
TOOL_CALL_STATUS = [SCHEMA + "tool_call_condition_status"]

# Schema-level cases the v3 and v4 kits both carry, each one broken field of a
# bound adversarial handoff: fixture stem -> codes.
SCHEMA_CASES: dict[str, list[str]] = {
    "schema-unknown-version": [SCHEMA + "schema_version"],
    "schema-missing-narrative": [SCHEMA + "narrative"],
    "schema-unknown-field": [SCHEMA + "bogus"],
    "schema-kind-not-enumerated": [SCHEMA + "kind"],
    "schema-blank-narrative": [SCHEMA + "narrative"],
    "schema-safe-alternative-not-text": [SCHEMA + "safe_alternative"],
    "schema-scenario-version-not-integer": [SCHEMA + "scenario_version"],
    "schema-unknown-not-text": [SCHEMA + "assumptions_and_unknowns"],
    "schema-attack-tree-not-object": [SCHEMA + "attack_tree"],
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
    # Decision 182: the top-level variant of stimulus-turn-field. The closed
    # schema rejects the unknown field before a reader's ownership scan runs.
    "schema-stimulus-turn-field-top-level": [
        KEY + "stimulus_turns",
        KEY + "role",
        SCHEMA + "stimulus_turns",
    ],
}
# The v4 kit records two codes for an unknown version: the retired v3 model
# also rejected the attack_shape key, and the producer keeps those codes.
SCHEMA_CASES_V4 = SCHEMA_CASES | {
    "schema-unknown-version": [SCHEMA + "schema_version", SCHEMA + "attack_shape"],
    "schema-deduplication-key-constraint-ids-not-list": DEDUPLICATION,
    "schema-deduplication-key-constraint-id-blank": DEDUPLICATION,
}
# Cases the producer model rejects through a validator the JSON schema cannot
# express; a reader that checks only schema.json accepts them.
MODEL_ONLY_SCHEMA_CASES = {
    "schema-blank-narrative",
    "schema-criterion-blank-outcome",
    "schema-criterion-observable-without-claim",
    "schema-criterion-analytical-with-operation",
    "schema-assessment-blank-reason",
    "schema-safe-outcome-blank-statement",
    "schema-safe-outcome-analytical-with-refs",
    "schema-tool-call-reason-not-bound",
}


@pytest.mark.parametrize(
    ("kit", "cases"),
    [(KIT_V3_ROOT, SCHEMA_CASES), (KIT_V4_ROOT, SCHEMA_CASES_V4)],
    ids=lambda value: _fixture_id(value) if isinstance(value, Path) else "",
)
def test_each_schema_case_is_rejected_with_its_recorded_codes(
    kit: Path, cases: dict[str, list[str]]
) -> None:
    present = {path.stem for path in (kit / "invalid").glob("schema-*.json")}
    assert present == set(cases)
    validator = Draft202012Validator(_schema(kit))
    for name, codes in cases.items():
        payload = json.loads((kit / "invalid" / f"{name}.json").read_text("utf-8"))
        found = handoff_ownership_violations(payload)
        if kit == KIT_V4_ROOT:
            found += handoff_schema_violations(payload)
        else:
            found += [code for code in codes if code.startswith(SCHEMA)]
        assert found == codes, name
        assert _expected_violations(kit)[f"invalid/{name}.json"] == codes, name
        schema_rejects = bool(list(validator.iter_errors(payload)))
        assert schema_rejects is (name not in MODEL_ONLY_SCHEMA_CASES), name
        if name != "schema-unknown-version":
            # Signed, so a reader that checks the digest first reaches the field.
            unsigned = {k: v for k, v in payload.items() if k != "content_digest"}
            assert payload["content_digest"] == handoff_payload_digest(unsigned), name


def test_the_refund_bound_case_is_bound_without_a_discriminating_condition() -> None:
    payload = json.loads(
        (KIT_V3_ROOT / "valid/refund-bound.json").read_text(encoding="utf-8")
    )

    assert "discriminating_condition" not in payload
    assert payload["tool_call_condition_status"]["status"] == "bound"
    assert payload["tool_call_condition"]["comparisons"][0]["right"] == {
        "source": "literal",
        "value": 100,
    }
