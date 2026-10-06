"""The planner input graph closes over values, without reading files."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from asago_scenario_generator.data.sssom import SSSOMMapping
from asago_scenario_generator.pipeline.taxonomy_inputs import (
    OBLIGATION_EDGES_RELEASE,
    bundled_attack_pattern_catalog,
    close_reviewed_graph,
    llm_threat_edges,
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


def test_closure_keeps_only_complete_risk_llm_threat_pattern_paths() -> None:
    rows = [{"object_id": "LLM01"}, {"object_id": "LLM02"}]
    edges = [
        _edge("LLM01", "T1"),
        _edge("LLM01", "T9"),
        _edge("LLM02", "T2"),
        _edge("LLM03", "T1"),
        _edge("T1", "AP-1"),
        _edge("T2", "OTHER"),
        _edge("T7", "AP-7"),
    ]

    closed_rows, closed_edges = close_reviewed_graph(rows, edges)

    assert closed_rows == [{"object_id": "LLM01"}]
    assert closed_edges == [_edge("LLM01", "T1"), _edge("T1", "AP-1")]


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


def test_llm_threat_edges_reverse_the_cross_taxonomy_rows() -> None:
    edges = llm_threat_edges(
        {
            "t_to_llm": [
                {"source": "T6", "target": "LLM01"},
                {
                    "source": "T11",
                    "target": "LLM01",
                    "predicate": "exact_match",
                },
            ]
        }
    )

    assert [(e["source_id"], e["target_id"], e["relation"]) for e in edges] == [
        ("LLM01", "T6", "related_match"),
        ("LLM01", "T11", "exact_match"),
    ]
    with pytest.raises(ValueError, match="must contain an object"):
        llm_threat_edges(["not an object"])


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
        cross_taxonomy={},
    )

    assert value.sssom_mappings == ()
    assert value.cross_taxonomy_mappings == ()
    assert value.catalog_pins["atlas"].digest == catalog_pin
    assert value.mapping_pins["obligation_edges"].release == OBLIGATION_EDGES_RELEASE
