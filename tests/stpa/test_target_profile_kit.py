"""The target-profile-v1 contract kit: vectors, codes and reproducibility."""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path
from types import ModuleType

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionTargetProfile,
)

ROOT = Path(__file__).resolve().parents[2]
CONTRACT_ROOT = ROOT / "data/contracts/target-profile"
KIT = CONTRACT_ROOT / "target-profile-v1"
SCRIPT = ROOT / "scripts/gen_target_profile_kit.py"

# code -> a fragment of the model's rejection
CODE_MESSAGES = {
    "unexpected_field": "Extra inputs are not permitted",
    "value_fact_without_declaration": "declares a record_kind, a format, or both",
    "value_fact_unknown_argument": (
        "argument value facts must name an argument of a profile operation"
    ),
}
# Rules the JSON Schema cannot state; only the model enforces them.
MODEL_ONLY = {"value_fact_unknown_argument"}


def _generator() -> ModuleType:
    name = "gen_target_profile_kit_script"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


def _load(relative: str) -> dict:
    return json.loads((KIT / relative).read_text(encoding="utf-8"))


def _validator() -> Draft202012Validator:
    return Draft202012Validator(_load("schema.json"))


def _expected() -> dict[str, list[str]]:
    return _load("expected-violations.json")


def test_the_generator_reproduces_every_kit_file_byte_for_byte(tmp_path) -> None:
    copy = tmp_path / "target-profile"
    shutil.copytree(CONTRACT_ROOT, copy)

    _generator().main(copy)

    for path in sorted(CONTRACT_ROOT.rglob("*")):
        if path.is_file():
            relative = path.relative_to(CONTRACT_ROOT)
            assert (copy / relative).read_bytes() == path.read_bytes(), relative
    assert sorted(p.relative_to(copy) for p in copy.rglob("*")) == sorted(
        p.relative_to(CONTRACT_ROOT) for p in CONTRACT_ROOT.rglob("*")
    )


def test_expected_violations_list_exactly_the_invalid_vectors() -> None:
    invalid = {path.relative_to(KIT).as_posix() for path in KIT.glob("invalid/*.json")}

    assert set(_expected()) == invalid
    assert {code for codes in _expected().values() for code in codes} == set(
        CODE_MESSAGES
    )


@pytest.mark.parametrize(
    "relative",
    sorted(path.relative_to(KIT).as_posix() for path in KIT.glob("valid/*.json")),
)
def test_valid_vectors_pass_the_schema_and_the_model(relative: str) -> None:
    payload = _load(relative)
    digests = _load("canonical-digests.json")["semantic_digests"]

    assert list(_validator().iter_errors(payload)) == []
    profile = ExecutionTargetProfile.model_validate(payload)
    assert profile.semantic_digest == payload["semantic_digest"] == digests[relative]


@pytest.mark.parametrize("relative", sorted(_expected()))
def test_each_invalid_vector_is_rejected_for_its_code(relative: str) -> None:
    payload = _load(relative)
    (code,) = _expected()[relative]

    with pytest.raises(ValidationError, match=CODE_MESSAGES[code]):
        ExecutionTargetProfile.model_validate(payload)
    schema_rejects = bool(list(_validator().iter_errors(payload)))
    assert schema_rejects is (code not in MODEL_ONLY)
