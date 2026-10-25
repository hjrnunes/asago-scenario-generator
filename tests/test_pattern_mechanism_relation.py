"""The pinned, digested relation from attack pattern to mechanism."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from pydantic import ValidationError
import pytest
import yaml

from asago_scenario_generator.models.canonical import compute_framed_digest
from asago_scenario_generator.pipeline.taxonomy_inputs import (
    bundled_attack_pattern_catalog,
)
from asago_scenario_generator.stpa.mechanism_library import (
    PATTERN_MECHANISM_DIGEST_DOMAIN,
    PATTERN_MECHANISM_RELATION_PATH,
    MechanismId,
    bundled_mechanism_library,
    bundled_pattern_mechanism_relation,
    load_pattern_mechanism_relation,
    pattern_mechanisms,
)


def _raw() -> dict:
    return yaml.safe_load(PATTERN_MECHANISM_RELATION_PATH.read_text())


def _redigested(raw: dict) -> dict:
    content = {key: value for key, value in raw.items() if key != "semantic_digest"}
    return {
        **content,
        "semantic_digest": compute_framed_digest(
            PATTERN_MECHANISM_DIGEST_DOMAIN, content
        ),
    }


def _load(tmp_path: Path, raw: dict):
    path = tmp_path / "relation.yaml"
    path.write_text(yaml.safe_dump(raw))
    return load_pattern_mechanism_relation(path)


def test_every_linked_pattern_resolves_to_its_pinned_catalog_revision() -> None:
    catalog, _pin = bundled_attack_pattern_catalog()

    assert bundled_pattern_mechanism_relation().pattern_reference_errors(catalog) == []


def test_every_linked_mechanism_resolves_to_a_library_entry() -> None:
    library = bundled_mechanism_library()
    for link in bundled_pattern_mechanism_relation().links:
        for mechanism_id in link.mechanisms:
            assert library.entry(mechanism_id).id is mechanism_id


@pytest.mark.parametrize("pattern_id", ["AP-T6-03", "AP-T2-05"])
def test_the_retrieved_instruction_patterns_link_to_their_mechanism(
    pattern_id: str,
) -> None:
    entries = pattern_mechanisms(pattern_id)

    assert [entry.id for entry in entries] == [MechanismId.retrieved_instructions]


def test_an_unlinked_pattern_realizes_no_known_mechanism() -> None:
    assert pattern_mechanisms("AP-T1-01") == ()
    assert pattern_mechanisms("AP-UNKNOWN") == ()


def test_mechanisms_without_a_fitting_pattern_have_no_link() -> None:
    linked = {
        mechanism_id
        for link in bundled_pattern_mechanism_relation().links
        for mechanism_id in link.mechanisms
    }

    assert set(MechanismId) - linked == {
        MechanismId.stale_history,
        MechanismId.stale_feedback,
        MechanismId.forged_completion,
    }


def test_the_recorded_digest_covers_the_content(tmp_path: Path) -> None:
    raw = _raw()
    assert _redigested(raw)["semantic_digest"] == raw["semantic_digest"]
    raw["links"][0]["mechanisms"] = ["user_claim"]

    with pytest.raises(ValidationError, match="semantic_digest does not match"):
        _load(tmp_path, raw)


def test_an_unknown_mechanism_fails(tmp_path: Path) -> None:
    raw = _raw()
    raw["links"][0]["mechanisms"] = ["fabricated_approval"]

    with pytest.raises(ValidationError, match="fabricated_approval"):
        _load(tmp_path, _redigested(raw))


def test_a_repeated_pattern_fails(tmp_path: Path) -> None:
    raw = _raw()
    raw["links"].append(dict(raw["links"][0]))

    with pytest.raises(ValidationError, match="repeats patterns: \\['AP-T1-06'\\]"):
        _load(tmp_path, _redigested(raw))


def test_a_repeated_mechanism_in_one_link_fails(tmp_path: Path) -> None:
    raw = _raw()
    raw["links"][0]["mechanisms"] = ["stale_history", "stale_history"]

    with pytest.raises(ValidationError, match="must not repeat a mechanism"):
        _load(tmp_path, _redigested(raw))


def test_a_link_without_a_pin_fails(tmp_path: Path) -> None:
    raw = _raw()
    del raw["links"][0]["pattern_semantic_digest"]

    with pytest.raises(ValidationError, match="pattern_semantic_digest"):
        _load(tmp_path, _redigested(raw))


def test_reference_errors_name_a_missing_and_a_revised_pattern() -> None:
    relation = bundled_pattern_mechanism_relation()
    catalog, _pin = bundled_attack_pattern_catalog()
    revised = [
        SimpleNamespace(
            id=pattern.id,
            canonical_chain=SimpleNamespace(semantic_digest="f" * 64),
        )
        if pattern.id == "AP-T6-03"
        else pattern
        for pattern in catalog
        if pattern.id != "AP-T2-05"
    ]

    errors = relation.pattern_reference_errors(revised)

    assert errors == [
        "AP-T2-05: not in the attack-pattern catalog",
        "AP-T6-03: pinned digest "
        "9e960c940518164d7028183882883d2d7b5cb5e16c9ec9543087fae115628ade"
        f" != catalog digest {'f' * 64}",
    ]
