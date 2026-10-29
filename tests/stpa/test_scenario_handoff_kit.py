"""The scenario-handoff-v5 contract kit: fixtures, codes and reproducibility.

Every invalid fixture breaks one thing. The table below names the typed codes
the kit records, the cross-field rule or field error the model reports, and
whether the JSON schema alone rejects it. A schema-only reader cannot see rules
R2-R6 and R9; the consumer enforces them in its nested validation.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
from pathlib import Path
from types import ModuleType

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from asago_scenario_generator.stpa.scenario_prod.handoff import (
    ScenarioHandoffV5,
    handoff_ownership_violations,
    handoff_schema_violations,
    verify_handoff_digest,
)

ROOT = Path(__file__).resolve().parents[2]
CONTRACT_ROOT = ROOT / "data/contracts/scenario-handoff"
KIT = CONTRACT_ROOT / "handoff-v5"

VALID = {
    "adversarial-condition-omitted.json",
    "adversarial-direct-multi-turn.json",
    "adversarial-direct-single.json",
    "adversarial-downgraded.json",
    "adversarial-forged-transcript.json",
    "adversarial-indirect-listing.json",
    "adversarial-indirect-policy-operator.json",
    "adversarial-observed-record.json",
    "adversarial-stated-beliefs.json",
    "analytical-only.json",
    "failure-call.json",
    "functional-not-called.json",
    "functional-null-shape.json",
    "functional-record-unavailable.json",
    "functional-stated-belief.json",
    "safe-call-arguments.json",
    "safe-call-not-made.json",
    "taxonomy-block.json",
}

SHAPE = "schema_violation:attack_shape"
PATH = "schema_violation:attack_path"
ROOT_CODE = "schema_violation:<root>"
TAXONOMY = "schema_violation:taxonomy"
FAILURE_CALL = "schema_violation:semantic_failure_call"
SAFE_OUTCOME = "schema_violation:safe_observable_outcome"

# fixture -> (typed codes, rule named by the model error or None, schema rejects)
INVALID: dict[str, tuple[list[str], str | None, bool]] = {
    "shape-purpose-free-text.json": ([SHAPE], None, True),
    "shape-turn-text-field.json": ([SHAPE], None, True),
    "shape-turn-role-key.json": (["artifact_design_field:role", SHAPE], None, True),
    "shape-delivery-key.json": (["artifact_design_field:delivery", SHAPE], None, True),
    "shape-turns-array-key.json": (["artifact_design_field:turns", SHAPE], None, True),
    "shape-turn-count-zero.json": ([SHAPE], None, True),
    "shape-turn-count-five.json": ([SHAPE], None, True),
    "shape-plan-length-mismatch.json": ([SHAPE], "R1", True),
    "shape-positions-not-sequential.json": ([SHAPE], "R2", False),
    "shape-direct-with-benign-speaker.json": ([SHAPE], "R3", False),
    "shape-direct-with-indirect-block.json": ([SHAPE], "R3", True),
    "shape-indirect-without-block.json": ([SHAPE], "R4", True),
    "shape-indirect-attacker-speaker.json": ([SHAPE], "R4", False),
    "shape-indirect-no-read-turn.json": ([SHAPE], "R4", False),
    "shape-carrier-with-prose.json": ([SHAPE], None, True),
    "shape-record-ref-with-prose.json": ([SHAPE], None, True),
    "shape-forged-without-label.json": ([SHAPE], "R5", True),
    "shape-forged-speaker-on-direct.json": ([SHAPE], "R3", False),
    "shape-forged-last-not-attacker.json": ([SHAPE], "R5", False),
    "shape-purpose-speaker-mismatch.json": ([SHAPE], "R6", False),
    "shape-adversarial-null.json": ([ROOT_CODE], "R7", True),
    "shape-functional-with-shape.json": ([ROOT_CODE], "R7", True),
    "shape-missing.json": ([SHAPE], None, True),
    "shape-downgrade-without-default.json": ([SHAPE], "R9", False),
    "narrative-turn-array.json": (["prose_hiding:turn_array"], None, False),
    "narrative-role-serialization.json": (
        ["prose_hiding:role_serialization"],
        None,
        False,
    ),
    "ownership-oracle-kind-key.json": (
        ["artifact_design_field:oracle_kind", PATH],
        None,
        True,
    ),
    "ownership-oracle-observes-key.json": (
        ["artifact_design_field:oracle_observes", PATH],
        None,
        True,
    ),
    "ownership-oracle-basis-key.json": (
        ["artifact_design_field:oracle_basis", PATH],
        None,
        True,
    ),
    "ownership-deliver-this-message.json": (
        ["prose_hiding:ready_to_send_instruction"],
        None,
        False,
    ),
    "ownership-system-prompt-is.json": (
        ["prose_hiding:ready_to_send_instruction"],
        None,
        False,
    ),
    "ownership-judge-prompt.json": (["prose_hiding:judge_prompt"], None, False),
    "ownership-key-name-pattern.json": (
        ["prose_hiding:detector_expression", PATH],
        None,
        True,
    ),
    "ownership-dotted-key.json": (["artifact_design_field:role", PATH], None, True),
    "prepared-message-field.json": (
        ["prose_hiding:prepared_message_field"],
        None,
        False,
    ),
    "role-turn-array.json": (["prose_hiding:role_serialization"], None, False),
    "smuggled-prose.json": (
        ["prose_hiding:detector_expression", "prose_hiding:ready_to_send_instruction"],
        None,
        False,
    ),
    "stimulus-turn-field.json": (
        ["artifact_design_field:stimulus_turns", "artifact_design_field:role", PATH],
        None,
        True,
    ),
    "taxonomy-unknown-scheme.json": ([TAXONOMY], None, True),
    "taxonomy-bad-edition.json": ([TAXONOMY], None, True),
    "taxonomy-extra-key.json": ([TAXONOMY], None, True),
    "taxonomy-asi-scheme-llm-id.json": ([TAXONOMY], "belong", True),
    "taxonomy-llm-scheme-asi-id.json": ([TAXONOMY], "belong", True),
    # The schema cannot state the order; the model and the consumer's hand rule do.
    "taxonomy-unsorted-references.json": ([TAXONOMY], "sorted", False),
    "failure-call-kind-not-enumerated.json": ([FAILURE_CALL], None, True),
    "failure-call-blank-operation.json": ([FAILURE_CALL], "blank", False),
    "safe-call-argument-value-not-scalar.json": ([SAFE_OUTCOME], None, True),
    "safe-call-argument-blank-name.json": ([SAFE_OUTCOME], "blank", False),
    "safe-call-not-made-with-arguments.json": (
        [SAFE_OUTCOME],
        "call_made false",
        False,
    ),
    "safe-call-made-not-boolean.json": ([SAFE_OUTCOME], None, True),
}


def _load(relative: str) -> dict:
    return json.loads((KIT / relative).read_text(encoding="utf-8"))


def _validator() -> Draft202012Validator:
    return Draft202012Validator(_load("schema.json"))


def test_the_kit_holds_exactly_the_listed_fixtures() -> None:
    assert {path.name for path in (KIT / "valid").glob("*.json")} == VALID
    # The schema-* cases are listed in test_scenario_handoff_contract_kit.py
    # and the v5-* cases in test_scenario_handoff_v5.py.
    listed = {
        path.name
        for path in (KIT / "invalid").glob("*.json")
        if not path.name.startswith(("schema-", "v5-"))
    }
    assert listed == set(INVALID)
    assert len(INVALID) == 50


@pytest.mark.parametrize("name", sorted(VALID))
def test_valid_fixtures_pass_every_check_and_keep_their_digest(name: str) -> None:
    payload = _load(f"valid/{name}")

    assert payload["schema_version"] == "scenario-handoff-v5"
    assert list(_validator().iter_errors(payload)) == []
    assert handoff_schema_violations(payload) == []
    assert handoff_ownership_violations(payload) == []
    verify_handoff_digest(ScenarioHandoffV5.model_validate(payload))
    assert "attack_shape" in payload


def test_valid_fixtures_cover_each_channel_and_the_downgrade_and_null_cases() -> None:
    shapes = {name: _load(f"valid/{name}")["attack_shape"] for name in VALID}

    channels = {shape["channel"] for shape in shapes.values() if shape}
    assert channels == {"direct", "indirect", "forged_transcript"}
    assert shapes["functional-null-shape.json"] is None
    assert {shape["turn_count"] for shape in shapes.values() if shape} >= {1, 2, 3}
    downgraded = shapes["adversarial-downgraded.json"]
    assert downgraded["source"] == "code_default"
    assert downgraded["downgrade_reason"] == "no_attacker_influenced_operation"
    operator = shapes["adversarial-indirect-policy-operator.json"]["indirect"]
    assert operator["party_relation"]["controller"] == "operator_insider"
    assert operator["data_item"]["record_ref"] is None
    forged = shapes["adversarial-forged-transcript.json"]
    assert forged["threat_label"] == "forged_transcript_threat"
    assert forged["turn_plan"][-1]["speaker"] == "attacker_user"


def test_only_the_failure_call_fixture_carries_a_failure_call() -> None:
    carrying = {
        name for name in VALID if "semantic_failure_call" in _load(f"valid/{name}")
    }

    assert carrying == {"failure-call.json"}
    assert _load("valid/failure-call.json")["semantic_failure_call"] == {
        "kind": "incorrect_call",
        "operation_name": "update_item",
    }


def test_only_the_safe_call_fixture_carries_call_arguments() -> None:
    carrying = {
        name
        for name in VALID
        if "call_arguments"
        in (_load(f"valid/{name}").get("safe_observable_outcome") or {})
    }

    assert carrying == {"safe-call-arguments.json"}
    assert _load("valid/safe-call-arguments.json")["safe_observable_outcome"][
        "call_arguments"
    ] == [{"argument": "item_id", "value": "ITEM-2"}]


def test_only_the_not_made_fixture_carries_call_made() -> None:
    carrying = {
        name
        for name in VALID
        if "call_made" in (_load(f"valid/{name}").get("safe_observable_outcome") or {})
    }

    assert carrying == {"safe-call-not-made.json"}
    outcome = _load("valid/safe-call-not-made.json")["safe_observable_outcome"]
    assert outcome["call_made"] is False
    assert "call_arguments" not in outcome


def test_only_the_taxonomy_fixture_carries_the_optional_block() -> None:
    carrying = {name for name in VALID if "taxonomy" in _load(f"valid/{name}")}

    assert carrying == {"taxonomy-block.json"}
    block = _load("valid/taxonomy-block.json")["taxonomy"]
    assert [(ref["scheme"], ref["id"]) for ref in block["references"]] == [
        ("owasp-asi", "ASI02"),
        ("owasp-llm", "LLM03"),
    ]


@pytest.mark.parametrize("name", sorted(INVALID))
def test_each_invalid_fixture_is_rejected_with_its_recorded_codes(name: str) -> None:
    codes, rule, schema_rejects = INVALID[name]
    payload = _load(f"invalid/{name}")

    found = handoff_ownership_violations(payload) + handoff_schema_violations(payload)

    assert found == codes
    assert _load("expected-violations.json")[f"invalid/{name}"] == codes
    assert bool(list(_validator().iter_errors(payload))) is schema_rejects
    if rule is not None:
        with pytest.raises(ValidationError, match=rf"\b{rule}\b"):
            ScenarioHandoffV5.model_validate(payload)


def test_every_invalid_fixture_breaks_one_thing_in_a_valid_base() -> None:
    names = {name for name in INVALID if name.startswith("shape-")}
    assert len(names) == 24
    for name in INVALID:
        assert _load(f"invalid/{name}")["schema_version"] == "scenario-handoff-v5"


def test_the_ownership_scan_still_catches_prose_in_a_payload() -> None:
    assert "turns:" in _load("invalid/narrative-turn-array.json")["narrative"]
    leaf = json.dumps(_load("invalid/narrative-role-serialization.json")["attack_path"])
    assert "role: user" in leaf


def _generator(tmp: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "gen_handoff_kit_under_test", ROOT / "scripts/gen_handoff_kit.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    root = tmp / "scenario-handoff"
    shutil.copytree(CONTRACT_ROOT, root)
    module.ROOT = root
    return module


def test_the_generator_reproduces_every_committed_kit_byte_for_byte(
    tmp_path: Path,
) -> None:
    module = _generator(tmp_path)
    shutil.rmtree(module.ROOT / module.KIT_NAME)

    module.main()

    committed = sorted(
        path.relative_to(CONTRACT_ROOT)
        for path in CONTRACT_ROOT.rglob("*")
        if path.is_file()
    )
    regenerated = sorted(
        path.relative_to(module.ROOT)
        for path in module.ROOT.rglob("*")
        if path.is_file()
    )
    assert regenerated == committed
    differing = [
        str(relative)
        for relative in committed
        if (CONTRACT_ROOT / relative).read_bytes()
        != (module.ROOT / relative).read_bytes()
    ]
    assert differing == []
