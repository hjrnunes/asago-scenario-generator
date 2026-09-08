"""Public persistence tests for the Phase 4 projection-set artifact."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

import asago_scenario_generator.manifest as manifest_module
import asago_scenario_generator.pipeline.hybrid_scenario_projection_persistence as persistence
from asago_scenario_generator.models.hybrid_scenario_projection import (
    HybridScenarioProjectionSet,
)
from asago_scenario_generator.pipeline.hybrid_scenario_projection import (
    build_hybrid_scenario_projection_set,
)
from asago_scenario_generator.pipeline.hybrid_scenario_projection_persistence import (
    HYBRID_SCENARIO_PROJECTION_SET_FILENAME,
    read_hybrid_scenario_projection_set,
    write_hybrid_scenario_projection_set,
)
from tests.test_hybrid_scenario_projection import _task1_authority_fixture


FIXTURE_PATH = (
    Path(__file__).parent / "fixtures" / "hybrid-scenario-projection-set.yaml"
)
EXPECTED_FIXTURE_DIGEST = (
    "e7b3c0511b3e06ba5f8da285b3ae348b8cc0dd324471f008ea126163e1c65944"
)


@pytest.fixture
def projection_set() -> HybridScenarioProjectionSet:
    """Build the shared normative bookkeeping fixture through public seams."""
    inputs, _relation, _candidate = _task1_authority_fixture()
    return build_hybrid_scenario_projection_set(inputs)


def test_projection_set_yaml_round_trip_is_canonical(
    projection_set: HybridScenarioProjectionSet,
) -> None:
    serialized = projection_set.to_yaml()

    loaded = HybridScenarioProjectionSet.from_yaml(serialized)

    assert loaded == projection_set
    assert loaded.to_yaml() == serialized
    assert loaded.evidence_class == "normative_bookkeeping_fixture"


def test_projection_set_parser_rejects_missing_or_tampered_digest(
    projection_set: HybridScenarioProjectionSet,
) -> None:
    payload = yaml.safe_load(projection_set.to_yaml())

    missing_digest = dict(payload)
    del missing_digest["semantic_digest"]
    with pytest.raises(ValueError, match="requires semantic_digest"):
        HybridScenarioProjectionSet.from_yaml(yaml.safe_dump(missing_digest))

    tampered_digest = dict(payload)
    tampered_digest["semantic_digest"] = "f" * 64
    with pytest.raises(ValueError, match="digest mismatch|does not match content"):
        HybridScenarioProjectionSet.from_yaml(yaml.safe_dump(tampered_digest))


def test_projection_set_parser_rejects_missing_nested_digest(
    projection_set: HybridScenarioProjectionSet,
) -> None:
    payload = yaml.safe_load(projection_set.to_yaml())
    del payload["projections"][0]["bridge_links"][0]["semantic_digest"]

    with pytest.raises(ValueError, match="semantic_digest"):
        HybridScenarioProjectionSet.from_yaml(yaml.safe_dump(payload))


@pytest.mark.parametrize(
    "duplicate_yaml",
    [
        lambda serialized: serialized + f"semantic_digest: '{'0' * 64}'\n",
        lambda serialized: serialized.replace(
            "      artifact_id: control-structure\n",
            "      artifact_id: control-structure\n"
            "      artifact_id: control-structure\n",
            1,
        ),
    ],
    ids=["top_level", "nested"],
)
def test_projection_set_parser_rejects_duplicate_yaml_keys(
    projection_set: HybridScenarioProjectionSet,
    duplicate_yaml,
) -> None:
    with pytest.raises(ValueError, match="duplicate key"):
        HybridScenarioProjectionSet.from_yaml(duplicate_yaml(projection_set.to_yaml()))


def test_reordered_yaml_input_reloads_to_the_same_canonical_bytes(
    projection_set: HybridScenarioProjectionSet,
) -> None:
    serialized = projection_set.to_yaml()
    payload = yaml.safe_load(serialized)
    reordered = dict(reversed(tuple(payload.items())))

    loaded = HybridScenarioProjectionSet.from_yaml(
        yaml.dump(reordered, default_flow_style=False, sort_keys=False)
    )

    assert loaded == projection_set
    assert loaded.to_yaml() == serialized


def test_empty_projection_set_preserves_explicit_exclusions() -> None:
    inputs, _relation, _candidate = _task1_authority_fixture()
    empty = build_hybrid_scenario_projection_set(
        inputs.model_copy(
            update={"requested_relation_ids": ("correlation:v1:" + "f" * 64,)}
        )
    )

    restored = HybridScenarioProjectionSet.from_yaml(empty.to_yaml())

    assert restored.projections == ()
    assert restored.exclusions == empty.exclusions
    assert restored.exclusions[0].reason == "relation_not_accepted"


def test_model_yaml_parser_accepts_bytes(
    projection_set: HybridScenarioProjectionSet,
) -> None:
    assert (
        HybridScenarioProjectionSet.from_yaml(projection_set.to_yaml().encode("utf-8"))
        == projection_set
    )


def test_persistence_writer_publishes_and_reads_the_normative_artifact(
    tmp_path, projection_set: HybridScenarioProjectionSet
) -> None:
    path = write_hybrid_scenario_projection_set(tmp_path, projection_set)

    assert path == tmp_path / HYBRID_SCENARIO_PROJECTION_SET_FILENAME
    assert path.name == "hybrid-scenario-projection-set.yaml"
    assert read_hybrid_scenario_projection_set(path) == projection_set


def test_reader_requires_the_exact_normative_filename(
    tmp_path, projection_set: HybridScenarioProjectionSet
) -> None:
    wrong_path = tmp_path / "projection-set.yaml"
    wrong_path.write_text(projection_set.to_yaml(), encoding="utf-8")

    with pytest.raises(
        ValueError, match="expected hybrid-scenario-projection-set.yaml"
    ):
        read_hybrid_scenario_projection_set(wrong_path)


def test_atomic_interruption_preserves_previous_valid_file_and_cleans_temp(
    tmp_path,
    projection_set: HybridScenarioProjectionSet,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = write_hybrid_scenario_projection_set(tmp_path, projection_set)
    previous_bytes = path.read_bytes()

    def interrupted_replace(_source: str, _destination: str) -> None:
        raise OSError("simulated interruption")

    monkeypatch.setattr(manifest_module.os, "replace", interrupted_replace)
    with pytest.raises(OSError, match="simulated interruption"):
        write_hybrid_scenario_projection_set(tmp_path, projection_set)

    assert path.read_bytes() == previous_bytes
    assert read_hybrid_scenario_projection_set(path) == projection_set
    assert not list(tmp_path.glob("*.tmp"))


def test_invalid_input_is_not_partially_published(
    tmp_path, projection_set: HybridScenarioProjectionSet
) -> None:
    invalid = projection_set.model_copy(update={"semantic_digest": "f" * 64})

    with pytest.raises(ValueError, match="digest mismatch"):
        write_hybrid_scenario_projection_set(tmp_path, invalid)

    assert not (tmp_path / HYBRID_SCENARIO_PROJECTION_SET_FILENAME).exists()
    assert not list(tmp_path.glob("*.tmp"))


def test_writer_rejects_a_reload_discrepancy(
    tmp_path,
    projection_set: HybridScenarioProjectionSet,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    write_hybrid_scenario_projection_set(tmp_path, projection_set)
    discrepancy = projection_set.model_copy(update={"semantic_digest": "f" * 64})
    monkeypatch.setattr(
        persistence,
        "read_hybrid_scenario_projection_set",
        lambda _path: discrepancy,
    )

    with pytest.raises(ValueError, match="digest changed on round-trip"):
        write_hybrid_scenario_projection_set(tmp_path, projection_set)


def test_committed_normative_fixture_is_exact_canonical_output(
    projection_set: HybridScenarioProjectionSet,
) -> None:
    fixture_bytes = FIXTURE_PATH.read_bytes()

    loaded = read_hybrid_scenario_projection_set(FIXTURE_PATH)

    assert fixture_bytes == projection_set.to_yaml().encode("utf-8")
    assert loaded == projection_set
    assert loaded.to_yaml().encode("utf-8") == fixture_bytes
    assert loaded.semantic_digest == EXPECTED_FIXTURE_DIGEST
    assert loaded.evidence_class == "normative_bookkeeping_fixture"
