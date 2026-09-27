"""Acceptance tests for the producer-owned scenario-handoff contract kit.

The kit is the producer's versioned handoff envelope: narrative, attack tree,
Gherkin and necessary metadata, with a lock/digest record the consumer vendors
byte-for-byte. These tests assert the kit's content, its schema, its canonical
digests, and the exact ownership-boundary violations the invalid fixtures
retain. They also assert the kit introduces no fourth authoritative scenario
representation.

Two kits coexist: ``handoff-v1`` stays byte-identical for consumers that still
read v1, and ``handoff-v2`` adds the Stage 5 discriminating condition and its
code-owned check.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from asago_scenario_generator.models.canonical import canonical_json_bytes
from asago_scenario_generator.stpa.scenario_prod.handoff import (
    HANDOFF_DIGEST_DOMAIN,
    HANDOFF_DIGEST_DOMAIN_V1,
    HANDOFF_SCHEMA_VERSION,
    HANDOFF_SCHEMA_VERSION_V1,
    ScenarioHandoff,
    ScenarioHandoffV1,
    handoff_ownership_violations,
    handoff_payload_digest,
    handoff_schema_violations,
    render_handoff_feature,
    verify_handoff_digest,
)

CONTRACT_ROOT = Path(__file__).resolve().parents[2] / "data/contracts/scenario-handoff"
KIT_ROOT = CONTRACT_ROOT / "handoff-v1"
KIT_V2_ROOT = CONTRACT_ROOT / "handoff-v2"
KIT_MODELS: dict[Path, type[ScenarioHandoffV1]] = {
    KIT_ROOT: ScenarioHandoffV1,
    KIT_V2_ROOT: ScenarioHandoff,
}


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
        for kit in KIT_MODELS
        for fixture in sorted((kit / kind).glob("*.json"))
    ]


def _fixture_id(value: object) -> str:
    return value.name if isinstance(value, Path) else str(value)


def test_lock_records_the_version_and_every_kit_file_digest() -> None:
    lock = _lock()
    assert lock["contract"] == "scenario-handoff"
    assert lock["authority"] == "asago-scenario-generator"
    # The singular fields keep their v1 values so v1-only readers still match;
    # the plural fields enumerate every supported version.
    assert lock["handoff_schema_version"] == HANDOFF_SCHEMA_VERSION_V1
    assert lock["digest_domain"] == HANDOFF_DIGEST_DOMAIN_V1
    assert lock["handoff_schema_versions"] == [
        HANDOFF_SCHEMA_VERSION_V1,
        HANDOFF_SCHEMA_VERSION,
    ]
    assert lock["digest_domains"] == {
        HANDOFF_SCHEMA_VERSION_V1: HANDOFF_DIGEST_DOMAIN_V1,
        HANDOFF_SCHEMA_VERSION: HANDOFF_DIGEST_DOMAIN,
    }
    kit_files = {
        f"{kit.name}/{path.relative_to(kit).as_posix()}"
        for kit in KIT_MODELS
        for path in kit.rglob("*.json")
    }
    assert set(lock["files"]) == kit_files
    for relative, expected in lock["files"].items():
        payload = (CONTRACT_ROOT / relative).read_bytes()
        assert hashlib.sha256(payload).hexdigest() == expected, relative


def test_v2_schema_matches_the_producer_model() -> None:
    assert _schema(KIT_V2_ROOT) == ScenarioHandoff.model_json_schema()


def test_kit_introduces_no_fourth_scenario_representation() -> None:
    lock = _lock()
    assert lock["representations"] == ["narrative", "attack_tree", "gherkin"]
    # Every top-level schema property is one of the three representations or a
    # named metadata field; the envelope adds nothing else.
    declared = set(lock["representations"]) | set(lock["metadata_fields"])
    v1_schema = _schema(KIT_ROOT)
    v2_schema = _schema(KIT_V2_ROOT)
    assert set(v2_schema["properties"]) == declared
    assert set(v1_schema["properties"]) == declared - {
        "discriminating_condition",
        "condition_check",
        "condition_omitted_reason",
    }
    assert v1_schema["additionalProperties"] is False
    assert v2_schema["additionalProperties"] is False


@pytest.mark.parametrize(("kit", "fixture"), _kit_fixtures("valid"), ids=_fixture_id)
def test_valid_handoff_fixtures_round_trip_with_digests(
    kit: Path, fixture: Path
) -> None:
    payload = json.loads(fixture.read_text(encoding="utf-8"))
    relative = f"valid/{fixture.name}"

    assert not list(Draft202012Validator(_schema(kit)).iter_errors(payload))
    assert handoff_schema_violations(payload) == []

    handoff = KIT_MODELS[kit].model_validate(payload)
    verify_handoff_digest(handoff)
    assert handoff_ownership_violations(payload) == []
    # The semantic failure criterion and the safe alternative are retained.
    assert handoff.semantic_failure_criterion.strip()
    assert handoff.safe_alternative.strip()
    assert handoff.hypothesis_framing == handoff.hypothesis_framing.strip()
    # The three representations are all present, and the .feature companion
    # renders from the handoff alone.
    assert handoff.narrative.strip()
    assert handoff.attack_tree
    assert handoff.gherkin.feature.strip()
    assert render_handoff_feature(handoff).startswith("Feature: ")
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


@pytest.mark.parametrize("kit", list(KIT_MODELS), ids=_fixture_id)
def test_valid_fixtures_cover_adversarial_and_functional_cases(kit: Path) -> None:
    kinds = set()
    for fixture in (kit / "valid").glob("*.json"):
        payload = json.loads(fixture.read_text(encoding="utf-8"))
        kinds.add(payload["kind"])
    assert kinds == {"adversarial", "functional"}


def test_v2_valid_fixtures_cover_every_condition_shape() -> None:
    shapes = set()
    for fixture in (KIT_V2_ROOT / "valid").glob("*.json"):
        payload = json.loads(fixture.read_text(encoding="utf-8"))
        assert payload["schema_version"] == HANDOFF_SCHEMA_VERSION
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


def test_v2_handoff_rejects_an_omission_note_beside_a_condition() -> None:
    payload = json.loads(
        (KIT_V2_ROOT / "valid/adversarial-observed-record.json").read_text(
            encoding="utf-8"
        )
    )
    payload["condition_omitted_reason"] = "The condition was omitted."
    assert handoff_schema_violations(payload) == ["schema_violation:<root>"]


def test_functional_successor_fixture_keeps_failure_meaning_consistent() -> None:
    payload = json.loads(
        (KIT_ROOT / "valid/functional-no-attacker-v2.json").read_text(encoding="utf-8")
    )
    failure = payload["semantic_failure_criterion"]
    narrative = payload["narrative"]
    root = payload["attack_tree"]["root"]
    gherkin = payload["gherkin"]

    assert payload["kind"] == "functional"
    assert "issues a refund command exceeding" in failure
    assert "issues a refund command exceeding" in narrative
    assert "issues an amount above" in root
    assert "refuses the refund" in gherkin["then_expected"][0]
    assert "issues the refund" in gherkin["then_unsafe_alternative"][0]


@pytest.mark.parametrize(("kit", "fixture"), _kit_fixtures("invalid"), ids=_fixture_id)
def test_invalid_handoff_fixtures_fail_with_expected_codes(
    kit: Path, fixture: Path
) -> None:
    payload = json.loads(fixture.read_text(encoding="utf-8"))
    expected = _expected_violations(kit)[f"invalid/{fixture.name}"]
    violations = handoff_ownership_violations(payload)
    if kit == KIT_V2_ROOT:
        violations += handoff_schema_violations(payload)
        assert list(Draft202012Validator(_schema(kit)).iter_errors(payload))
    assert violations
    assert violations == expected


def test_expected_violations_name_every_invalid_fixture() -> None:
    for kit in KIT_MODELS:
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
