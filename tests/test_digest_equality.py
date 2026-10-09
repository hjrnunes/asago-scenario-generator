"""Pin recorded plan bytes and digests across the canonical-JSON helpers.

The fixtures under ``tests/fixtures/digest_equality`` come from the six
``pp-int38m`` replay recordings at producer ``8e108133``: each unit's
capability profile, its target's qualification facts and reviewed risk
records (only the fields ``load_reviewed_risk_extraction`` reads), the shared
SSSOM file, and every ``scenario_context.semantic_digest`` payload a strict
replay of the unit computed. ``expected.json`` holds the recorded plan's
sha256, semantic digest and candidate IDs, the synthesis manifest's
``taxonomy_inputs_digest``, and the bundled taxonomy pins.

The ``taxonomy_inputs_digest`` values come from the ``synthesis-manifest.yaml``
of the six ``pp-s3`` strict replays (recorded at ``w4/int-b`` ``9a642ef2``,
which includes P5-11 ``352cfefa``). The same fixture inputs rebuild them, so
no extra fixture data exists. The ``pp-int38m`` recordings at ``8e108133``
predate P5-11 and hold different values for the same inputs, because the
planner input model dropped its ``compatibility_policy`` field; their plan
digests are unchanged.

A change to canonical JSON, NFC normalization or digest framing that alters
any recorded byte fails here. Update the expected values only for an
intended contract change, never to make a refactor pass.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import math
import re
import unicodedata
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import BaseModel

from asago_scenario_generator.cli.synthesis import (
    _DEFAULT_LLM_PATTERN_TABLE,
    build_taxonomy_inputs,
)
from asago_scenario_generator.data.loaders import load_reviewed_risk_extraction
from asago_scenario_generator.data.taxonomy_pins import (
    compute_mapping_set_digest,
    load_atlas_pin,
)
from asago_scenario_generator.models.attack_pattern_digests import (
    _canonical_json as attack_pattern_canonical_json,
)
from asago_scenario_generator.models.canonical import (
    canonical_json,
    canonical_json_bytes,
)
from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.pipeline import obligation_contracts, projection_contracts
from asago_scenario_generator.pipeline.obligation_contracts import (
    QualificationFactsInput,
    TaxonomyObligationInputs,
)
from asago_scenario_generator.pipeline.obligation_planner import (
    plan_taxonomy_obligations,
)
from asago_scenario_generator.pipeline.projection_contracts import (
    capture_capability_snapshot,
)
from asago_scenario_generator.pipeline.synthesis_baseline import _evaluated_facts
from asago_scenario_generator.pipeline.synthesis_manifest import (
    _canonical_json as manifest_canonical_json,
)
from asago_scenario_generator.pipeline.synthesis_manifest import (
    _manifest_artifact_identity,
)
from asago_scenario_generator.stpa.models.scenario_context import semantic_digest
from asago_scenario_generator.target_discovery.prompts import (
    _canonical_json as prompt_canonical_json,
)

FIXTURES = Path(__file__).parent / "fixtures" / "digest_equality"
EXPECTED: dict[str, Any] = json.loads((FIXTURES / "expected.json").read_text())
UNITS = sorted(EXPECTED["units"])


@pytest.fixture(scope="module")
def planner_inputs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Decompress the risk records and the SSSOM file the loaders read by path."""
    root = tmp_path_factory.mktemp("digest_equality")
    for source in (
        FIXTURES / "risk-to-llm.sssom.tsv.gz",
        *FIXTURES.glob("*/*.json.gz"),
    ):
        target = root / source.relative_to(FIXTURES).with_suffix("")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(gzip.decompress(source.read_bytes()))
    return root


def _taxonomy_inputs(unit: str, inputs_root: Path) -> TaxonomyObligationInputs:
    target = EXPECTED["units"][unit]["target"]
    profile = CapabilityProfile.model_validate(
        yaml.safe_load((FIXTURES / unit / "capability-profile.yaml").read_text())
    )
    facts = QualificationFactsInput.model_validate(
        yaml.safe_load((FIXTURES / target / "qualification-facts.yaml").read_text())
    )
    risks = tuple(
        load_reviewed_risk_extraction(inputs_root / target / "risk-records.json")
    )
    return build_taxonomy_inputs(
        capability_profile=profile,
        capability_snapshot=capture_capability_snapshot(
            profile, _evaluated_facts(facts)
        ),
        risk_cards=risks,
        qualification_facts=facts,
        sssom_path=inputs_root / "risk-to-llm.sssom.tsv",
        llm_pattern_path=_DEFAULT_LLM_PATTERN_TABLE,
    )


def _plan_yaml(unit: str, inputs_root: Path) -> str:
    return plan_taxonomy_obligations(_taxonomy_inputs(unit, inputs_root)).to_yaml()


def _digest_records(unit: str) -> list[dict[str, Any]]:
    text = gzip.decompress((FIXTURES / unit / "semantic-digests.jsonl.gz").read_bytes())
    return [json.loads(line) for line in text.decode("utf-8").splitlines()]


@pytest.mark.parametrize("unit", UNITS)
def test_the_rebuilt_plan_keeps_the_recorded_bytes(
    unit: str, planner_inputs: Path
) -> None:
    expected = EXPECTED["units"][unit]
    text = _plan_yaml(unit, planner_inputs)

    assert hashlib.sha256(text.encode("utf-8")).hexdigest() == expected["plan_sha256"]
    assert yaml.safe_load(text)["semantic_digest"] == expected["plan_semantic_digest"]
    assert (
        sorted(set(re.findall(r"cand:v2:[0-9a-f]{32}", text)))
        == expected["candidate_ids"]
    )


@pytest.mark.parametrize("unit", UNITS)
def test_the_rebuilt_taxonomy_inputs_keep_the_recorded_manifest_digest(
    unit: str, planner_inputs: Path
) -> None:
    identity = _manifest_artifact_identity(
        "taxonomy-obligation-inputs",
        "taxonomy-obligation-inputs-v1",
        _taxonomy_inputs(unit, planner_inputs),
    )

    assert (
        identity["semantic_digest"] == EXPECTED["units"][unit]["taxonomy_inputs_digest"]
    )


@pytest.mark.parametrize("unit", UNITS)
def test_scenario_context_digests_keep_their_recorded_values(unit: str) -> None:
    records = _digest_records(unit)

    assert len(records) == EXPECTED["units"][unit]["semantic_digest_count"]
    mismatched = [
        (record["frame"], record["digest"])
        for record in records
        if semantic_digest(record["value"], frame=record["frame"]) != record["digest"]
    ]
    assert mismatched == []


@pytest.mark.parametrize(
    ("payload", "error"),
    [({"café": 1, "cafe\u0301": 2}, ValueError), ({1: "a"}, TypeError)],
    ids=["nfc_collision", "non_string_key"],
)
def test_scenario_context_digest_rejects_keys_canonical_json_cannot_hold(
    payload: dict[Any, Any], error: type[Exception]
) -> None:
    with pytest.raises(error):
        semantic_digest(payload, frame="asago-scenario-generator:test:v1")


def test_bundled_taxonomy_pins_keep_their_values() -> None:
    pins = EXPECTED["taxonomy_pins"]

    assert load_atlas_pin().model_dump(mode="json") == pins["atlas_pin"]
    assert compute_mapping_set_digest() == pins["mapping_set_digest"]


class _Entry(BaseModel):
    second: int = 1
    first: tuple[str, ...] = ("z", "a")


_NFD = unicodedata.normalize("NFD", "café")
_CANONICAL_INPUTS: dict[str, Any] = {
    "ascii": {"b": 1, "a": [1, 2], "Cc": {"y": None, "X": True}},
    "non_ascii": {"naïve": "日本語 \U0001f600", "é": "ü"},
    "nfd_value": {"k": _NFD},
    "nfd_key": {_NFD: 1},
    "nfc_collision": {"café": 1, _NFD: 2},
    "floats": [1.0, 0.1, 1e22, 1e-7, -0.0, 3.14159, 10**20],
    "nan": [math.nan],
    "infinity": [math.inf],
    "nested_keys": {"z": {"b": 1, "a": {"d": 1, "c": 2}}, "a": []},
    "set": {"s": {3, 1, 2}},
    "tuple": {"t": (1, 2)},
    "int_key": {1: "a"},
    "bool_key": {True: "a"},
    "model": _Entry(),
    "unordered_field": {"allowed_resource_ids": ["b", "a"], "other": ["b", "a"]},
    "scalar": "x",
    "none": None,
    "object": object,
}


def _outcome(encode: Callable[[Any], str], value: Any) -> tuple[str, str]:
    try:
        return "ok", encode(value)
    except Exception as error:  # the differential compares failures too
        return "error", type(error).__name__


def _shared_text(value: Any) -> str:
    return canonical_json_bytes(value).decode("utf-8")


# Private encoders that stay because their bytes differ from the shared one.
# Each row lists the inputs on which they differ; every other input matches.
_KEPT_ENCODERS: dict[str, tuple[Callable[[Any], str], frozenset[str]]] = {
    "attack_pattern_digests": (
        attack_pattern_canonical_json,
        frozenset({"nfc_collision", "int_key", "bool_key", "unordered_field"}),
    ),
    "synthesis_manifest": (
        manifest_canonical_json,
        frozenset(
            {
                "nfd_value",
                "nfd_key",
                "nfc_collision",
                "nan",
                "infinity",
                "set",
                "int_key",
                "bool_key",
                "object",
            }
        ),
    ),
    "target_discovery.prompts": (
        prompt_canonical_json,
        frozenset(
            {
                "nfd_value",
                "nfd_key",
                "nfc_collision",
                "nan",
                "infinity",
                "int_key",
                "bool_key",
                "model",
            }
        ),
    ),
}


@pytest.mark.parametrize("helper", sorted(_KEPT_ENCODERS))
def test_kept_private_encoders_differ_from_the_shared_one_on_exactly_these_inputs(
    helper: str,
) -> None:
    encode, expected = _KEPT_ENCODERS[helper]

    differing = {
        name
        for name, value in _CANONICAL_INPUTS.items()
        if _outcome(encode, value) != _outcome(_shared_text, value)
    }

    assert differing == expected


@pytest.mark.parametrize("name", sorted(_CANONICAL_INPUTS))
def test_canonical_json_is_the_shared_bytes_as_text(name: str) -> None:
    value = _CANONICAL_INPUTS[name]

    assert _outcome(canonical_json, value) == _outcome(_shared_text, value)


@pytest.mark.parametrize(
    "module",
    [obligation_contracts, projection_contracts],
    ids=["obligation_contracts", "projection_contracts"],
)
def test_contract_modules_use_the_shared_canonical_json(module: Any) -> None:
    assert not hasattr(module, "_canonical_json")
    assert module.canonical_json is canonical_json
