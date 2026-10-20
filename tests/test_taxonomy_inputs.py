"""The planner input graph closes over values, without reading files."""

from __future__ import annotations

import pytest

from asago_scenario_generator.data.loaders import load_attack_patterns
from asago_scenario_generator.data.threat_gating import in_scope_attack_pattern_ids
from asago_scenario_generator.pipeline.taxonomy_inputs import (
    OBLIGATION_EDGES_RELEASE,
    bundled_attack_pattern_catalog,
    close_reviewed_graph,
    llm_pattern_edges,
    taxonomy_obligation_inputs,
)
from tests.helpers.obligation_factory import make_inputs


def _edge(source: str, target: str) -> dict:
    return {"source_id": source, "target_id": target}


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


def _table(*entries: tuple[str, list[str]]) -> dict:
    return {
        "edition": "2026",
        "predicate": "realized_by",
        "patterns": [
            {"id": pattern, "llm": llm, "rationale": "r"} for pattern, llm in entries
        ],
    }


def test_llm_pattern_edges_cover_in_scope_patterns_only() -> None:
    profile = make_inputs().capability_snapshot.profile.model_copy(
        update={"kc_subcodes": [f"KC6.{index}" for index in range(1, 8)]}
    )
    in_scope = set(in_scope_attack_pattern_ids(profile))
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


@pytest.mark.parametrize("edition", ["2025", None], ids=["2025", "missing"])
def test_a_table_of_another_edition_is_refused(edition: str | None) -> None:
    profile = make_inputs().capability_snapshot.profile
    table = _table(("AP-T8-01", []))
    if edition is None:
        del table["edition"]
    else:
        table["edition"] = edition

    with pytest.raises(ValueError, match="2026") as caught:
        llm_pattern_edges(table, profile)

    assert repr(edition) in str(caught.value)


def test_a_table_code_outside_the_llm_vocabulary_is_refused() -> None:
    profile = make_inputs().capability_snapshot.profile

    with pytest.raises(ValueError, match="LLM11"):
        llm_pattern_edges(_table(("AP-T8-01", ["LLM01", "LLM11"])), profile)


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
