"""Acceptance tests for the producer-owned scenario-handoff contract kit.

The kit is the producer's versioned handoff envelope: narrative, attack tree,
Gherkin and necessary metadata, with a lock/digest record the consumer vendors
byte-for-byte. These tests assert the kit's content, its schema, its canonical
digests, and the exact ownership-boundary violations the invalid fixtures
retain. They also assert the kit introduces no fourth authoritative scenario
representation.
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
    HANDOFF_SCHEMA_VERSION,
    ScenarioHandoff,
    handoff_ownership_violations,
    handoff_payload_digest,
    render_handoff_feature,
    verify_handoff_digest,
)

CONTRACT_ROOT = (
    Path(__file__).resolve().parents[2] / "data/contracts/scenario-handoff"
)
KIT_ROOT = CONTRACT_ROOT / "handoff-v1"


def _lock() -> dict:
    return json.loads((CONTRACT_ROOT / "CONTRACT.lock").read_text(encoding="utf-8"))


def _digests() -> dict:
    return json.loads(
        (KIT_ROOT / "canonical-digests.json").read_text(encoding="utf-8")
    )


def _expected_violations() -> dict:
    return json.loads(
        (KIT_ROOT / "expected-violations.json").read_text(encoding="utf-8")
    )


def test_lock_records_the_version_and_every_kit_file_digest() -> None:
    lock = _lock()
    assert lock["contract"] == "scenario-handoff"
    assert lock["authority"] == "asago-scenario-generator"
    assert lock["handoff_schema_version"] == HANDOFF_SCHEMA_VERSION
    assert lock["handoff_schema_versions"] == [HANDOFF_SCHEMA_VERSION]
    assert lock["digest_domain"] == HANDOFF_DIGEST_DOMAIN
    for relative, expected in lock["files"].items():
        payload = (CONTRACT_ROOT / relative).read_bytes()
        assert hashlib.sha256(payload).hexdigest() == expected, relative


def test_kit_introduces_no_fourth_scenario_representation() -> None:
    lock = _lock()
    schema = json.loads((KIT_ROOT / "schema.json").read_text(encoding="utf-8"))
    assert lock["representations"] == ["narrative", "attack_tree", "gherkin"]
    # Every top-level schema property is one of the three representations or a
    # named metadata field; the envelope adds nothing else.
    declared = set(lock["representations"]) | set(lock["metadata_fields"])
    assert set(schema["properties"]) == declared
    assert schema["additionalProperties"] is False


@pytest.mark.parametrize(
    "fixture",
    sorted((KIT_ROOT / "valid").glob("*.json")),
    ids=lambda path: path.name,
)
def test_valid_handoff_fixtures_round_trip_with_digests(fixture: Path) -> None:
    payload = json.loads(fixture.read_text(encoding="utf-8"))
    relative = f"valid/{fixture.name}"

    schema = json.loads((KIT_ROOT / "schema.json").read_text(encoding="utf-8"))
    assert not list(Draft202012Validator(schema).iter_errors(payload))

    handoff = ScenarioHandoff.model_validate(payload)
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
    for fixture in (KIT_ROOT / "valid").glob("*.json"):
        payload = json.loads(fixture.read_text(encoding="utf-8"))
        kinds.add(payload["kind"])
    assert kinds == {"adversarial", "functional"}


def test_functional_successor_fixture_keeps_failure_meaning_consistent() -> None:
    payload = json.loads(
        (
            KIT_ROOT / "valid/functional-no-attacker-v2.json"
        ).read_text(encoding="utf-8")
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


@pytest.mark.parametrize(
    "fixture",
    sorted((KIT_ROOT / "invalid").glob("*.json")),
    ids=lambda path: path.name,
)
def test_invalid_handoff_fixtures_fail_with_expected_codes(fixture: Path) -> None:
    payload = json.loads(fixture.read_text(encoding="utf-8"))
    expected = _expected_violations()[f"invalid/{fixture.name}"]
    violations = handoff_ownership_violations(payload)
    assert violations
    assert violations == expected


def test_invalid_fixture_carrying_a_prepared_message_field_is_rejected() -> None:
    payload = json.loads(
        (KIT_ROOT / "invalid/stimulus-turn-field.json").read_text(encoding="utf-8")
    )
    assert "artifact_design_field:stimulus_turns" in handoff_ownership_violations(
        payload
    )
    schema = json.loads((KIT_ROOT / "schema.json").read_text(encoding="utf-8"))
    assert list(Draft202012Validator(schema).iter_errors(payload))
