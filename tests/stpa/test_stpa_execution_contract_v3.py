"""Contract-kit acceptance for the paired projection-v3 and bundle-v2 kits.

The kits add the structured omission-evidence carrier from the approved
proposal in
``build/qualification/current-interface-followup-20260913/structured-evidence-proposal.md``.
The standalone v3 verifier is built against these fixtures; the settled
model-error to violation-code mapping it must implement is pinned by
``MODEL_ERROR_MESSAGES`` and ``EXPECTED_CODES`` below.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from asago_scenario_generator.models.canonical import canonical_json_bytes
from asago_scenario_generator.stpa.models.execution_projection_v3 import (
    ExecutionBundleIndexV2,
    ExecutionProjectionV3,
)

CONTRACT_ROOT = Path(__file__).resolve().parents[2] / "data/contracts/stpa-execution"
PROJECTION_V3_ROOT = CONTRACT_ROOT / "projection-v3"
BUNDLE_V2_ROOT = CONTRACT_ROOT / "bundle-v2"

# Settled mapping from the single pydantic error each invalid fixture raises to
# the violation code recorded in projection-v3/expected-violations.json.  The
# standalone verifier maps by error message for cross-field model ValueErrors
# and by pydantic error type for constraint and extra-field errors:
#
# | model error                                                  | code                            |
# | "action-presence outcomes require omission_evidence"         | omission_evidence_missing       |
# | "omission_evidence is allowed only on action-presence ..."   | omission_evidence_unexpected    |
# | "omission_evidence_digest does not match the carrier ..."    | omission_evidence_digest_mismatch |
# | any error under unsafe_outcome.omission_evidence.* that is   | omission_evidence_invalid       |
# | not an extra-forbidden error (bounds, patterns, shapes)      |                                 |
# | "direct_prompt stimuli require prepared_user_text"           | required_field_missing          |
# | extra_forbidden under unsafe_outcome.omission_evidence.*     | unexpected_field                |
MODEL_ERROR_TO_CODE = {
    "action-presence outcomes require omission_evidence": ("omission_evidence_missing"),
    "omission_evidence is allowed only on action-presence outcomes": (
        "omission_evidence_unexpected"
    ),
    "omission_evidence_digest does not match the carrier content": (
        "omission_evidence_digest_mismatch"
    ),
    "direct_prompt stimuli require prepared_user_text": "required_field_missing",
}
FIXTURE_MESSAGES = {
    "omission-evidence-missing.json": (
        "action-presence outcomes require omission_evidence"
    ),
    "carrier-on-non-omission.json": (
        "omission_evidence is allowed only on action-presence outcomes"
    ),
    "carrier-digest-mismatch.json": (
        "omission_evidence_digest does not match the carrier content"
    ),
    "carrier-field-invalid.json": "at most 256 characters",
    "prepared-text-missing.json": "direct_prompt stimuli require prepared_user_text",
    "unknown-carrier-field.json": "Extra inputs are not permitted",
}
FIXTURE_CODES = {
    "omission-evidence-missing.json": "omission_evidence_missing",
    "carrier-on-non-omission.json": "omission_evidence_unexpected",
    "carrier-digest-mismatch.json": "omission_evidence_digest_mismatch",
    "carrier-field-invalid.json": "omission_evidence_invalid",
    "prepared-text-missing.json": "required_field_missing",
    "unknown-carrier-field.json": "unexpected_field",
}


def _read(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.parametrize(
    "fixture",
    sorted((PROJECTION_V3_ROOT / "valid").glob("*.json")),
    ids=lambda p: p.name,
)
def test_valid_v3_fixtures_round_trip_with_recorded_digests(fixture: Path) -> None:
    """Every valid v3 fixture parses with its recorded semantic digest."""
    payload = _read(fixture)
    projection = ExecutionProjectionV3.model_validate(payload)

    assert payload["semantic_digest"] == projection.semantic_digest
    assert projection.semantic_digest == projection.compute_semantic_digest()

    digests = _read(PROJECTION_V3_ROOT / "canonical-digests.json")
    relative = f"valid/{fixture.name}"
    assert digests["semantic_digests"][relative] == projection.semantic_digest
    assert digests["files"][relative] == _sha256(fixture)

    outcome = payload["unsafe_outcome"]
    if "omission_evidence" in outcome:
        carrier = projection.unsafe_outcome.omission_evidence
        assert outcome["omission_evidence_digest"] == carrier.compute_carrier_digest()


@pytest.mark.parametrize(
    "fixture",
    sorted((PROJECTION_V3_ROOT / "valid").glob("*.json")),
    ids=lambda p: p.name,
)
def test_valid_v3_fixtures_match_the_v3_schema(fixture: Path) -> None:
    """Every valid v3 fixture also satisfies the closed JSON schema."""
    schema = _read(PROJECTION_V3_ROOT / "schema.json")
    errors = list(Draft202012Validator(schema).iter_errors(_read(fixture)))
    assert not [error.message for error in errors]


@pytest.mark.parametrize(
    "fixture",
    sorted((PROJECTION_V3_ROOT / "invalid").glob("*.json")),
    ids=lambda path: path.name,
)
def test_invalid_v3_fixtures_fail_with_expected_codes(fixture: Path) -> None:
    """Each invalid fixture fails the model with its settled violation code."""
    payload = _read(fixture)
    expected_codes = _read(PROJECTION_V3_ROOT / "expected-violations.json")

    with pytest.raises(ValidationError) as exc_info:
        ExecutionProjectionV3.model_validate(payload)

    errors = exc_info.value.errors()
    assert len(errors) == 1
    message = FIXTURE_MESSAGES[fixture.name]
    assert message in errors[0]["msg"]
    if message in MODEL_ERROR_TO_CODE:
        assert MODEL_ERROR_TO_CODE[message] == FIXTURE_CODES[fixture.name]
    assert expected_codes[fixture.name] == [FIXTURE_CODES[fixture.name]]


# The standalone verifier's own settled code per invalid fixture.  It agrees
# with expected-violations.json everywhere except prepared-text-missing,
# where the kit records the model-level required-field code while the
# verifier's delivery binding owns the failure.


@pytest.mark.parametrize(
    "fixture",
    sorted((PROJECTION_V3_ROOT / "invalid").glob("*.json")),
    ids=lambda p: p.name,
)
def test_schema_rejects_schema_level_v3_violations(fixture: Path) -> None:
    """The schema rejects every violation except digest recomputation."""
    schema = _read(PROJECTION_V3_ROOT / "schema.json")
    errors = list(Draft202012Validator(schema).iter_errors(_read(fixture)))
    if fixture.name == "carrier-digest-mismatch.json":
        # The schema cannot recompute framed digests; the model owns that rule.
        assert not errors
    else:
        assert [error.message for error in errors]


def test_v3_schema_encodes_omission_presence_rules() -> None:
    """Carrier presence follows the outcome condition and evidence kinds."""
    schema = _read(PROJECTION_V3_ROOT / "schema.json")
    validator = Draft202012Validator(schema)
    direct = _read(PROJECTION_V3_ROOT / "valid/structured-omission-direct.json")
    plain = _read(PROJECTION_V3_ROOT / "valid/plain-non-omission.json")

    # An action_presence outcome without its carrier is a schema violation.
    missing = json.loads(json.dumps(direct))
    del missing["unsafe_outcome"]["omission_evidence"]
    del missing["unsafe_outcome"]["omission_evidence_digest"]
    assert list(validator.iter_errors(missing))

    # Any other condition type must not carry the carrier or its digest.
    unexpected = json.loads(json.dumps(plain))
    outcome = unexpected["unsafe_outcome"]
    outcome["omission_evidence"] = direct["unsafe_outcome"]["omission_evidence"]
    outcome["omission_evidence_digest"] = direct["unsafe_outcome"][
        "omission_evidence_digest"
    ]
    assert list(validator.iter_errors(unexpected))

    # Snapshot digest is required with state evidence and forbidden without.
    without_snapshot = json.loads(json.dumps(direct))
    del without_snapshot["unsafe_outcome"]["omission_evidence"][
        "observation_snapshot_digest"
    ]
    assert list(validator.iter_errors(without_snapshot))

    stimulus_only = json.loads(json.dumps(direct))
    evidence = stimulus_only["unsafe_outcome"]["omission_evidence"]["evidence"]
    stimulus_only["unsafe_outcome"]["omission_evidence"]["evidence"] = [
        entry for entry in evidence if entry["source"] == "stimulus"
    ]
    assert list(validator.iter_errors(stimulus_only))
    del stimulus_only["unsafe_outcome"]["omission_evidence"][
        "observation_snapshot_digest"
    ]
    assert not list(validator.iter_errors(stimulus_only))


def test_bundle_v2_valid_fixture_round_trips_with_matching_digest() -> None:
    """The bundle-v2 index pairs exactly with its v3 projection and scenario."""
    bundle_dir = BUNDLE_V2_ROOT / "valid/minimal-run"
    payload = _read(bundle_dir / "execution-bundle.json")
    index = ExecutionBundleIndexV2.model_validate(payload)

    assert payload["bundle_digest"] == index.compute_bundle_digest()
    entry = index.entries[0]
    assert entry.validation.validator_version == "stpa-execution-projection-v3"
    assert entry.projection.schema_version == "stpa-execution-projection-v3"

    scenario_path = bundle_dir / entry.scenario.path
    projection_path = bundle_dir / entry.projection.path
    assert entry.scenario.content_sha256 == _sha256(scenario_path)
    assert entry.projection.content_sha256 == _sha256(projection_path)

    projection = ExecutionProjectionV3.model_validate(_read(projection_path))
    assert entry.projection.semantic_digest == projection.semantic_digest
    assert entry.scenario_id == projection.scenario_id
    assert entry.candidate_id == projection.candidate_id
    assert entry.ica_slot_id == projection.ica_slot_id
    assert entry.ica_id == projection.ica_id

    # The referenced projection is the committed structured-omission-direct
    # fixture, persisted as the exact canonical encoding the reload verifier
    # requires (the kit fixture file itself keeps its own formatting).
    kit_projection = ExecutionProjectionV3.model_validate(
        _read(PROJECTION_V3_ROOT / "valid/structured-omission-direct.json")
    )
    assert projection.model_dump(mode="json") == kit_projection.model_dump(
        mode="json"
    )
    assert projection_path.read_bytes() == projection.canonical_json_bytes()

    # The scenario envelope carries the omission identity of its projection:
    # NOT_PROVIDED identities throughout and the projection's exact short
    # structured proposition (never the long evidence-carrying text).
    scenario = _read(scenario_path)
    spec = scenario["scenario_spec"]
    assert scenario["ica_type"] == "NOT_PROVIDED"
    assert spec["ica_type"] == "NOT_PROVIDED"
    assert spec["threat_source"]["ica_slot_id"] == projection.ica_slot_id
    assert spec["threat_source"]["ica_id"] == projection.ica_id
    assert (
        spec["unsafe_outcome_semantic_proposition"]
        == projection.unsafe_outcome.semantic_proposition
    )
    assert "Inconclusive unless" in spec["unsafe_outcome_semantic_proposition"]

    # The index and the projection share one run identity.
    assert payload["run_id"] == projection.run_id


def test_bundle_v2_invalid_fixtures_fail_with_expected_codes() -> None:
    """The bundle-v2 invalid fixtures reproduce the bundle-v1 mutations."""
    valid_projection_bytes = (
        BUNDLE_V2_ROOT / "valid/minimal-run/scenarios/canonical/SCN-001.projection.json"
    ).read_bytes()
    valid_scenario_bytes = (
        BUNDLE_V2_ROOT / "valid/minimal-run/scenarios/SCN-001.scenario.json"
    ).read_bytes()

    # hash-mismatch: the index references digests the files do not have.
    mismatch_dir = BUNDLE_V2_ROOT / "invalid/hash-mismatch"
    mismatch = _read(mismatch_dir / "execution-bundle.json")
    entry = mismatch["entries"][0]
    assert entry["scenario"]["content_sha256"] != _sha256(
        mismatch_dir / "scenarios/SCN-001.scenario.json"
    )
    assert entry["projection"]["content_sha256"] != _sha256(
        mismatch_dir / "scenarios/canonical/SCN-001.projection.json"
    )
    projection = json.loads(valid_projection_bytes)
    assert entry["projection"]["semantic_digest"] != projection["semantic_digest"]
    assert (mismatch_dir / "scenarios/SCN-001.scenario.json").read_bytes() == (
        valid_scenario_bytes
    )

    # pair-mismatch: file digests match, but the scenario envelope identity
    # no longer matches the referenced projection's controller.
    pair_dir = BUNDLE_V2_ROOT / "invalid/pair-mismatch"
    pair = _read(pair_dir / "execution-bundle.json")
    pair_entry = pair["entries"][0]
    assert pair_entry["scenario"]["content_sha256"] == _sha256(
        pair_dir / "scenarios/SCN-001.scenario.json"
    )
    assert pair_entry["projection"]["content_sha256"] == _sha256(
        pair_dir / "scenarios/canonical/SCN-001.projection.json"
    )
    scenario = json.loads((pair_dir / "scenarios/SCN-001.scenario.json").read_text())
    assert scenario["target_responsibility"] != projection["controller_id"]

    expected = _read(BUNDLE_V2_ROOT / "expected-violations.json")
    assert expected["invalid/hash-mismatch"] == [
        "content_digest_mismatch",
        "content_digest_mismatch",
        "semantic_digest_mismatch",
    ]
    # One violation per mismatching field, all sharing the pair code.
    assert expected["invalid/pair-mismatch"] == ["pair_identity_mismatch"] * 6


def test_contract_lock_pins_every_v3_and_bundle_v2_file() -> None:
    """The lock covers both new kits exactly, with unchanged legacy scalars."""
    lock = _read(CONTRACT_ROOT / "CONTRACT.lock")

    expected_entries: set[str] = set()
    for kit_root in (PROJECTION_V3_ROOT, BUNDLE_V2_ROOT):
        for path in kit_root.rglob("*.json"):
            expected_entries.add(
                f"{kit_root.name}/{path.relative_to(kit_root).as_posix()}"
            )

    pinned = {
        name
        for name in lock["files"]
        if name.startswith(("projection-v3/", "bundle-v2/"))
    }
    assert pinned == expected_entries
    for name in pinned:
        assert lock["files"][name] == _sha256(CONTRACT_ROOT / name)

    # The legacy generation scalars stay unchanged for v1/v2 readers.
    assert lock["bundle_schema_version"] == "stpa-execution-bundle-v1"
    assert lock["projection_schema_version"] == "stpa-execution-projection-v2"
    assert lock["bundle_schema_versions"] == [
        "stpa-execution-bundle-v1",
        "stpa-execution-bundle-v2",
    ]
    assert lock["projection_schema_versions"] == [
        "stpa-execution-projection-v2",
        "stpa-execution-projection-v3",
    ]


def test_bundle_v2_index_bytes_are_canonical() -> None:
    """Bundle-v2 index fixtures use exact canonical JSON bytes like bundle-v1."""
    for relative in (
        "valid/minimal-run",
        "invalid/hash-mismatch",
        "invalid/pair-mismatch",
    ):
        path = BUNDLE_V2_ROOT / relative / "execution-bundle.json"
        assert canonical_json_bytes(_read(path)) == path.read_bytes()
