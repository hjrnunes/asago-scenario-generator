"""The production taxonomy adapter closes the reviewed planner graph."""

from __future__ import annotations

from pathlib import Path

import pytest

from asago_scenario_generator.cli.synthesis import (
    _DEFAULT_CROSS_TAXONOMY,
    build_taxonomy_inputs,
)
from asago_scenario_generator.data.threat_gating import determine_threat_scope
from asago_scenario_generator.pipeline.obligation_contracts import (
    compute_mapping_bundle_digest,
)
from tests.helpers.obligation_factory import make_inputs

_ALL_KC_SUBCODES = [
    *(f"KC1.{index}" for index in range(1, 5)),
    *(f"KC2.{index}" for index in range(1, 4)),
    *(f"KC3.{index}" for index in range(1, 5)),
    *(f"KC4.{index}" for index in range(1, 7)),
    *(f"KC5.{index}" for index in range(1, 4)),
    *(f"KC6.{index}" for index in range(1, 8)),
]
_HEADER = (
    "subject_id\tsubject_source\tpredicate_id\tobject_id\tobject_source\t"
    "mapping_justification"
)
_ROWS = (
    # Kept: a reviewed risk, an OWASP LLM object, and a threat path (LLM01).
    "risk-a\tcredo-ucf\tskos:relatedMatch\tllm012025-prompt-injection\towasp-llm-2.0\tj",
    # Dropped by closure: LLM02 has no threat in the bundled mappings.
    "risk-a\tcredo-ucf\tskos:relatedMatch\t"
    "llm022025-sensitive-information-disclosure\towasp-llm-2.0\tj",
    # Dropped: not an OWASP LLM object.
    "risk-a\tcredo-ucf\tskos:relatedMatch\tail-hate\tailuminate-v1.0\tj",
    # Dropped: a no-match predicate.
    "risk-a\tcredo-ucf\tsemapv:NoMatch\tllm062025-excessive-agency\towasp-llm-2.0\tj",
    # Dropped: not a reviewed risk card.
    "risk-z\tcredo-ucf\tskos:relatedMatch\tllm092025-misinformation\towasp-llm-2.0\tj",
)


def _sssom(tmp_path: Path) -> Path:
    path = tmp_path / "risk-to-llm.sssom.tsv"
    path.write_text("\n".join(("# reviewed", _HEADER, *_ROWS)) + "\n")
    return path


def _build(tmp_path: Path, *, profile=None, cross_taxonomy_path=None):
    base = make_inputs()
    if profile is None:
        profile = base.capability_snapshot.profile.model_copy(
            update={"kc_subcodes": _ALL_KC_SUBCODES}
        )
    return (
        build_taxonomy_inputs(
            capability_profile=profile,
            capability_snapshot=base.capability_snapshot,
            risk_cards=base.risk_cards,
            qualification_facts=base.qualification_facts,
            sssom_path=_sssom(tmp_path),
            cross_taxonomy_path=cross_taxonomy_path or _DEFAULT_CROSS_TAXONOMY,
            output_dir=tmp_path,
        ),
        profile,
    )


def test_only_reviewed_owasp_llm_rows_with_a_threat_path_are_kept(tmp_path) -> None:
    value, _ = _build(tmp_path)

    assert [
        (row.subject_id, row.object_id, row.object_source)
        for row in value.sssom_mappings
    ] == [("risk-a", "LLM01", "owasp-llm-2.0")]


def test_cross_taxonomy_edges_close_over_risk_llm_threat_pattern_paths(
    tmp_path,
) -> None:
    value, profile = _build(tmp_path)
    edges = value.cross_taxonomy_mappings
    llm_edges = [edge for edge in edges if edge.target_id.startswith("T")]
    threat_edges = [edge for edge in edges if edge.target_id.startswith("AP-")]
    in_scope = {entry.threat_id for entry in determine_threat_scope(profile).in_scope}

    assert len(llm_edges) + len(threat_edges) == len(edges)
    assert {edge.source_id for edge in llm_edges} == {"LLM01"}
    assert {edge.target_id for edge in llm_edges} <= {"T6", "T11"}
    assert {edge.source_id for edge in threat_edges} == {
        edge.target_id for edge in llm_edges
    }
    assert {edge.source_id for edge in threat_edges} <= in_scope
    assert {edge.relation for edge in threat_edges} == {"attacks_via"}
    assert {tuple(edge.evidence) for edge in llm_edges} == {
        ("cross-taxonomy-mappings.yaml:t_to_llm",)
    }


def test_pins_identify_the_catalog_and_the_closed_mapping_bundle(tmp_path) -> None:
    value, _ = _build(tmp_path)
    release = value.attack_pattern_catalog[0].canonical_chain.taxonomy_context
    dumped = value.model_dump(mode="json")

    assert value.catalog_pins["atlas"].release == release.atlas.release
    assert value.mapping_pins["sssom"].digest == release.mapping_set_digest
    assert value.mapping_pins["obligation_edges"].release == (
        "obligation-mapping-bundle-v1"
    )
    assert value.mapping_pins["obligation_edges"].digest == (
        compute_mapping_bundle_digest(
            dumped["cross_taxonomy_mappings"], dumped["sssom_mappings"]
        )
    )


def test_out_of_scope_threats_close_the_graph_to_nothing(tmp_path) -> None:
    narrow = make_inputs().capability_snapshot.profile.model_copy(
        update={"kc_subcodes": []}
    )

    value, _ = _build(tmp_path, profile=narrow)

    assert value.sssom_mappings == ()
    assert value.cross_taxonomy_mappings == ()


def test_untyped_capability_profile_is_rejected(tmp_path) -> None:
    with pytest.raises(TypeError, match="requires a typed capability profile"):
        _build(tmp_path, profile={"kc_subcodes": _ALL_KC_SUBCODES})


def test_non_object_cross_taxonomy_file_is_rejected(tmp_path) -> None:
    cross = tmp_path / "cross.yaml"
    cross.write_text("- not an object\n")

    with pytest.raises(ValueError, match="must contain an object"):
        _build(tmp_path, cross_taxonomy_path=cross)


def test_empty_bundled_catalog_is_rejected(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(
        "asago_scenario_generator.data.loaders.load_attack_patterns", lambda: {}
    )

    with pytest.raises(ValueError, match="bundled attack-pattern catalog is empty"):
        _build(tmp_path)
