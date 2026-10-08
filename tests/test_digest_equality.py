"""Pin recorded plan bytes and digests across the canonical-JSON helpers.

The fixtures under ``tests/fixtures/digest_equality`` come from the six
``pp-int38m`` replay recordings at producer ``8e108133``: each unit's
capability profile, its target's qualification facts and reviewed risk
records (only the fields ``load_reviewed_risk_extraction`` reads), the shared
SSSOM file, and every ``scenario_context.semantic_digest`` payload a strict
replay of the unit computed. ``expected.json`` holds the recorded plan's
sha256, semantic digest and candidate IDs, and the bundled taxonomy pins.

A change to canonical JSON, NFC normalization or digest framing that alters
any recorded byte fails here. Update the expected values only for an
intended contract change, never to make a refactor pass.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from asago_scenario_generator.cli.synthesis import (
    _DEFAULT_LLM_PATTERN_TABLE,
    build_taxonomy_inputs,
)
from asago_scenario_generator.data.loaders import load_reviewed_risk_extraction
from asago_scenario_generator.data.taxonomy_pins import (
    compute_mapping_set_digest,
    load_atlas_pin,
)
from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.pipeline.obligation_contracts import (
    QualificationFactsInput,
)
from asago_scenario_generator.pipeline.obligation_planner import (
    plan_taxonomy_obligations,
)
from asago_scenario_generator.pipeline.projection_contracts import (
    capture_capability_snapshot,
)
from asago_scenario_generator.pipeline.synthesis_baseline import _evaluated_facts
from asago_scenario_generator.stpa.models.scenario_context import semantic_digest

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


def _plan_yaml(unit: str, inputs_root: Path) -> str:
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
    inputs = build_taxonomy_inputs(
        capability_profile=profile,
        capability_snapshot=capture_capability_snapshot(
            profile, _evaluated_facts(facts)
        ),
        risk_cards=risks,
        qualification_facts=facts,
        sssom_path=inputs_root / "risk-to-llm.sssom.tsv",
        llm_pattern_path=_DEFAULT_LLM_PATTERN_TABLE,
    )
    return plan_taxonomy_obligations(inputs).to_yaml()


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
