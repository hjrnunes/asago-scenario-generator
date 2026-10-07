"""The planner input graph closes over values, without reading files."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from asago_scenario_generator.data.loaders import load_attack_patterns
from asago_scenario_generator.data.sssom import SSSOMMapping
from asago_scenario_generator.data.threat_gating import determine_threat_scope
from asago_scenario_generator.pipeline.taxonomy_inputs import (
    OBLIGATION_EDGES_RELEASE,
    bundled_attack_pattern_catalog,
    close_reviewed_graph,
    llm_pattern_edges,
    reviewed_owasp_llm_rows,
    taxonomy_obligation_inputs,
)
from tests.helpers.obligation_factory import make_inputs


def _edge(source: str, target: str) -> dict:
    return {"source_id": source, "target_id": target}


def _mapping(subject: str, predicate: str, obj: str, source: str) -> SSSOMMapping:
    return SSSOMMapping(
        subject_id=subject,
        subject_source="credo-ucf",
        predicate_id=predicate,
        object_id=obj,
        object_source=source,
        mapping_justification="j",
    )


def test_closure_keeps_only_complete_risk_llm_pattern_paths() -> None:
    rows = [{"object_id": "LLM01"}, {"object_id": "LLM02"}]
    edges = [
        _edge("LLM01", "AP-1"),
        _edge("LLM01", "AP-2"),
        _edge("LLM03", "AP-1"),
    ]

    closed_rows, closed_edges = close_reviewed_graph(rows, edges)

    assert closed_rows == [{"object_id": "LLM01"}]
    assert closed_edges == [_edge("LLM01", "AP-1"), _edge("LLM01", "AP-2")]


def test_reviewed_rows_keep_reviewed_owasp_llm_matches_only() -> None:
    mappings = [
        _mapping("risk-a", "skos:relatedMatch", "llm012025-x", "owasp-llm-2.0"),
        _mapping("risk-a", "skos:relatedMatch", "ail-hate", "ailuminate-v1.0"),
        _mapping("risk-a", "semapv:NoMatch", "llm062025-x", "owasp-llm-2.0"),
        _mapping("risk-z", "skos:relatedMatch", "llm092025-x", "owasp-llm-2.0"),
    ]

    rows = reviewed_owasp_llm_rows(mappings, [SimpleNamespace(risk_id="risk-a")])

    assert [(row["subject_id"], row["object_id"]) for row in rows] == [
        ("risk-a", "LLM01")
    ]


def _table(*entries: tuple[str, list[str]]) -> dict:
    return {
        "predicate": "realized_by",
        "patterns": [
            {"id": pattern, "llm": llm, "rationale": "r"} for pattern, llm in entries
        ],
    }


def test_llm_pattern_edges_cover_in_scope_patterns_only() -> None:
    profile = make_inputs().capability_snapshot.profile.model_copy(
        update={"kc_subcodes": [f"KC6.{index}" for index in range(1, 8)]}
    )
    in_scope = {
        pattern
        for entry in determine_threat_scope(profile).in_scope
        for pattern in entry.attack_pattern_ids
    }
    out_of_scope = sorted(set(load_attack_patterns()) - in_scope)[0]
    inside = sorted(in_scope)[0]

    edges = llm_pattern_edges(
        _table(
            (inside, ["LLM01", "LLM06"]), (out_of_scope, ["LLM01"]), ("AP-T8-01", [])
        ),
        profile,
    )

    assert [(e["source_id"], e["target_id"], e["relation"]) for e in edges] == [
        ("LLM01", inside, "realized_by"),
        ("LLM06", inside, "realized_by"),
    ]
    assert {tuple(e["evidence"]) for e in edges} == {("llm-to-attack-pattern.yaml",)}
    with pytest.raises(ValueError, match="must contain an object"):
        llm_pattern_edges(["not an object"], profile)


def test_planner_inputs_pin_the_closed_bundle_from_loaded_values() -> None:
    base = make_inputs()
    catalog, catalog_pin = bundled_attack_pattern_catalog()

    value = taxonomy_obligation_inputs(
        capability_profile=base.capability_snapshot.profile.model_copy(
            update={"kc_subcodes": []}
        ),
        capability_snapshot=base.capability_snapshot,
        risk_cards=base.risk_cards,
        qualification_facts=base.qualification_facts,
        catalog=catalog,
        catalog_pin=catalog_pin,
        sssom_mappings=(),
        llm_pattern_table=_table(),
    )

    assert value.sssom_mappings == ()
    assert value.cross_taxonomy_mappings == ()
    assert value.catalog_pins["atlas"].digest == catalog_pin
    assert value.mapping_pins["obligation_edges"].release == OBLIGATION_EDGES_RELEASE
