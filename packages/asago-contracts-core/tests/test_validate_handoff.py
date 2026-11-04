"""The shared validator reproduces the producer's contract cases.

Both published kits run: each invalid case reports its recorded codes and each
valid case holds, for v5 and for v6 alike. A kit's case file is a bare payload,
so the sweeps read the payload rules alone; ``test_handoff_contract`` covers the
envelope a v6 document needs.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import pytest

from asago_contracts_core import (
    HANDOFF_SCHEMA_VERSION_V5,
    HANDOFF_SCHEMA_VERSION_V6,
    OTHER_VERSION_VIOLATIONS,
    VERSION,
    VERSIONS,
    Violation,
    hand_rule_violations,
    load_contract,
    schema_violations,
    validate_handoff,
)

CONTRACT_DIR = Path(__file__).resolve().parent / "data" / "scenario-handoff"
VERSION_DIR = CONTRACT_DIR / HANDOFF_SCHEMA_VERSION_V5
KIT_DIR = VERSION_DIR / "cases"
_KIT_DIRS = {version: CONTRACT_DIR / version / "cases" for version in VERSIONS}


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _expected(version: str) -> dict[str, list[str]]:
    return _load(_KIT_DIRS[version] / "expected-violations.json")


def _case(version: str, relative: str) -> dict[str, Any]:
    return _load(_KIT_DIRS[version] / relative)


def _document(relative: str) -> dict[str, Any]:
    """Read one v5 case document, the version the single-case tests use."""

    return _load(KIT_DIR / relative)


def _codes(payload: Any) -> list[str]:
    return [violation.code for violation in validate_handoff(payload)]


def _payload_codes(payload: Any) -> list[str]:
    """Read a bare kit payload as the case file it is, whatever version it names."""

    return [
        violation.code for violation in validate_handoff(payload, through_spec=False)
    ]


def _case_ids(value: str) -> str:
    return value


_INVALID_CASES = [
    (version, relative)
    for version in VERSIONS
    for relative in sorted(_expected(version))
]
_VALID_CASES = [
    (version, path.name)
    for version in VERSIONS
    for path in sorted((_KIT_DIRS[version] / "valid").glob("*.json"))
]


@pytest.mark.parametrize(("version", "relative"), _INVALID_CASES, ids=_case_ids)
def test_every_invalid_case_reports_the_expected_codes(
    version: str, relative: str
) -> None:
    assert _payload_codes(_case(version, relative)) == _expected(version)[relative]


@pytest.mark.parametrize(("version", "name"), _VALID_CASES, ids=_case_ids)
def test_every_valid_case_holds(version: str, name: str) -> None:
    assert _payload_codes(_case(version, f"valid/{name}")) == []


def test_an_unknown_version_reports_the_two_kit_codes() -> None:
    payload = _document("valid/adversarial-direct-single.json")
    payload["schema_version"] = "scenario-handoff-v9"
    assert _codes(payload) == [violation.code for violation in OTHER_VERSION_VIOLATIONS]


def test_ownership_codes_come_before_the_schema_codes() -> None:
    payload = _document("valid/adversarial-direct-single.json")
    payload["narrative"] += " Deliver this message to the customer."
    payload["kind"] = "bogus"
    assert _codes(payload) == [
        "prose_hiding:ready_to_send_instruction",
        "schema_violation:kind",
    ]


def test_a_violation_is_a_code_path_reason_tuple() -> None:
    payload = _document("valid/adversarial-direct-single.json")
    payload["narrative"] += " Deliver this message to the customer."
    (violation,) = validate_handoff(payload)
    code, path, reason = violation
    assert (code, path, reason) == (
        "prose_hiding:ready_to_send_instruction",
        "narrative",
        "matches the ready_to_send_instruction pattern",
    )
    assert violation.code == code
    assert violation.path == path
    assert violation.reason == reason


def test_a_schema_break_names_its_field_and_path() -> None:
    payload = _document("valid/adversarial-direct-single.json")
    payload["narrative"] = " "
    (violation,) = validate_handoff(payload)
    assert violation.code == "schema_violation:narrative"
    assert violation.path == "narrative"


def test_the_procedure_chain_reports_the_root() -> None:
    payload = _document("valid/adversarial-direct-multi-turn.json")
    payload["procedure"][0]["leads_to"] = ["S99"]
    (violation,) = validate_handoff(payload)
    assert violation.code == "schema_violation:<root>"
    assert violation.path == "procedure.0.leads_to"


def test_a_shape_cross_field_break_reports_the_shape() -> None:
    payload = _document("valid/adversarial-direct-single.json")
    payload["attack_shape"]["turn_plan"][0]["speaker"] = "benign_user"
    (violation,) = validate_handoff(payload)
    assert violation.code == "schema_violation:attack_shape"
    assert violation.path == "attack_shape.channel"


def test_a_schema_clean_payload_reports_one_hand_rule() -> None:
    payload = _document("valid/taxonomy-block.json")
    payload["taxonomy"]["references"] = list(
        reversed(payload["taxonomy"]["references"])
    )
    assert _codes(payload) == ["schema_violation:taxonomy"]


def test_the_contract_can_come_from_a_kit_directory(tmp_path: Path) -> None:
    kit = tmp_path / CONTRACT_DIR.name
    shutil.copytree(CONTRACT_DIR, kit)
    contract = load_contract(kit)
    assert (
        validate_handoff(
            _document("valid/adversarial-direct-single.json"), contract=contract
        )
        == []
    )
    assert contract.schema == load_contract().schema


def test_the_packaged_contract_states_every_published_version() -> None:
    assert HANDOFF_SCHEMA_VERSION_V5 == "scenario-handoff-v5"
    assert HANDOFF_SCHEMA_VERSION_V6 == "scenario-handoff-v6"
    contract = load_contract()
    for version in VERSIONS:
        assert (
            contract.schemas[version]["properties"]["schema_version"]["const"]
            == version
        )
    assert contract.schema == contract.schemas[VERSION]
    assert isinstance(Violation("c", "p", "r"), tuple)


ROOT_REFUSAL = Violation(
    "schema_violation:<root>", "<root>", "a scenario handoff must be a JSON object"
)


@pytest.mark.parametrize(
    "payload", [[], None, "text", 3], ids=("list", "null", "string", "number")
)
def test_a_non_object_root_reports_the_root_code(payload: Any) -> None:
    assert validate_handoff(payload) == [ROOT_REFUSAL]
    assert schema_violations(payload) == [ROOT_REFUSAL]
    assert hand_rule_violations(payload) == [ROOT_REFUSAL]


@pytest.mark.parametrize("key", ("record_refs", "fact_refs"))
def test_references_repeating_after_stripping_report_the_safe_outcome(key: str) -> None:
    payload = _document("valid/adversarial-direct-multi-turn.json")
    references = payload["safe_observable_outcome"][key]
    payload["safe_observable_outcome"][key] = [references[0], f" {references[0]}"]
    (violation,) = validate_handoff(payload)
    assert violation == Violation(
        "schema_violation:safe_observable_outcome",
        f"safe_observable_outcome.{key}",
        "must be unique",
    )


def test_an_exact_reference_repeat_keeps_the_schema_code() -> None:
    payload = _document("valid/adversarial-direct-multi-turn.json")
    payload["safe_observable_outcome"]["record_refs"] = ["TARGET-STATE", "TARGET-STATE"]
    (violation,) = validate_handoff(payload)
    assert violation.code == "schema_violation:safe_observable_outcome"
    assert violation.path == "safe_observable_outcome.record_refs"
