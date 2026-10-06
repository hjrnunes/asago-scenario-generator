"""The closed planner input graph: risk -> OWASP LLM -> threat -> attack pattern.

``taxonomy_obligation_inputs`` builds the planner's typed input from values a
caller has already loaded: the reviewed SSSOM mappings, the parsed
cross-taxonomy document, and the bundled attack-pattern catalog. It keeps only
the rows and edges on a complete path and pins the catalog and the closed
mapping bundle. ``bundled_attack_pattern_catalog`` loads the catalog shipped
with the package.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from asago_scenario_generator.pipeline.obligation_contracts import (
    TaxonomyObligationInputs,
    compute_mapping_bundle_digest,
)

OBLIGATION_EDGES_RELEASE = "obligation-mapping-bundle-v1"
_LLM_THREAT_EVIDENCE = "cross-taxonomy-mappings.yaml:t_to_llm"
_THREAT_PATTERN_EVIDENCE = "owasp-agentic-threats-v1.1.yaml"


def bundled_attack_pattern_catalog() -> tuple[tuple[Any, ...], str]:
    """Return the validated bundled attack-pattern catalog and its pin."""
    from asago_scenario_generator.data.loaders import load_attack_patterns
    from asago_scenario_generator.data.taxonomy_pins import load_taxonomy_resolver
    from asago_scenario_generator.models.attack_pattern_validation import (
        validate_attack_pattern,
    )
    from asago_scenario_generator.pipeline.projection_qualification import (
        compute_authoritative_catalog_pin,
    )

    resolver = load_taxonomy_resolver()
    catalog_records = list(load_attack_patterns().values())
    catalog = tuple(validate_attack_pattern(item, resolver) for item in catalog_records)
    if not catalog:
        raise ValueError("bundled attack-pattern catalog is empty")
    return catalog, compute_authoritative_catalog_pin(catalog_records, resolver)


def taxonomy_obligation_inputs(
    *,
    capability_profile: Any,
    capability_snapshot: Any,
    risk_cards: Any,
    qualification_facts: Any,
    catalog: tuple[Any, ...],
    catalog_pin: str,
    sssom_mappings: Iterable[Any],
    cross_taxonomy: Any,
) -> TaxonomyObligationInputs:
    """Close the reviewed graph and pin it as the planner's typed input."""
    context = catalog[0].canonical_chain.taxonomy_context
    sssom_rows = reviewed_owasp_llm_rows(sssom_mappings, risk_cards)
    cross_edges = llm_threat_edges(cross_taxonomy)
    cross_edges.extend(threat_pattern_edges(capability_profile))
    closed_sssom, cross_edges = close_reviewed_graph(sssom_rows, cross_edges)

    return TaxonomyObligationInputs(
        risk_cards=tuple(risk_cards),
        capability_snapshot=capability_snapshot,
        attack_pattern_catalog=catalog,
        cross_taxonomy_mappings=tuple(cross_edges),
        sssom_mappings=tuple(closed_sssom),
        catalog_pins={
            "atlas": {"release": context.atlas.release, "digest": catalog_pin}
        },
        mapping_pins={
            "sssom": {
                "release": context.atlas.release,
                "digest": context.mapping_set_digest,
            },
            "obligation_edges": {
                "release": OBLIGATION_EDGES_RELEASE,
                "digest": compute_mapping_bundle_digest(cross_edges, closed_sssom),
            },
        },
        qualification_facts=qualification_facts,
    )


def reviewed_owasp_llm_rows(
    sssom_mappings: Iterable[Any], risk_cards: Any
) -> list[dict]:
    """Return reviewed risks' OWASP LLM matches with normalized LLM IDs."""
    from asago_scenario_generator.data.sssom import normalize_llm_id

    risk_ids = {str(item.risk_id) for item in risk_cards}
    rows = []
    for mapping in sssom_mappings:
        row = mapping.model_dump(mode="json")
        if row["subject_id"] not in risk_ids:
            continue
        if "owasp-llm" not in str(row["object_source"]):
            continue
        if "nomatch" in str(row["predicate_id"]).lower():
            continue
        row["object_id"] = normalize_llm_id(str(row["object_id"]))
        rows.append(row)
    return rows


def llm_threat_edges(cross_taxonomy: Any) -> list[dict]:
    """Return the LLM-to-threat edges of a parsed cross-taxonomy document."""
    if not isinstance(cross_taxonomy, dict):
        raise ValueError("cross-taxonomy mapping file must contain an object")
    return [
        {
            "source_id": item["target"],
            "target_id": item["source"],
            "relation": item.get("predicate", "related_match"),
            "evidence": [_LLM_THREAT_EVIDENCE],
        }
        for item in cross_taxonomy.get("t_to_llm", ())
    ]


def threat_pattern_edges(capability_profile: Any) -> list[dict]:
    """Return the threat-to-attack-pattern edges of the in-scope threats."""
    from asago_scenario_generator.data.threat_gating import determine_threat_scope

    scope = determine_threat_scope(capability_profile)
    return [
        {
            "source_id": entry.threat_id,
            "target_id": pattern_id,
            "relation": "attacks_via",
            "evidence": [_THREAT_PATTERN_EVIDENCE],
        }
        for entry in scope.in_scope
        for pattern_id in entry.attack_pattern_ids
    ]


def close_reviewed_graph(
    sssom_rows: list[dict], cross_edges: list[dict]
) -> tuple[list[dict], list[dict]]:
    """Keep only rows and edges on a risk -> LLM -> threat -> pattern path.

    Threat IDs start with ``T`` and attack-pattern IDs with ``AP-``; an edge's
    target prefix tells the LLM-to-threat edges from the threat-to-pattern ones.
    """
    llm_edges = _edges_where(
        cross_edges, "target_id", lambda value: value.startswith("T")
    )
    threat_edges = _edges_where(
        cross_edges, "target_id", lambda value: value.startswith("AP-")
    )
    llm_objects = _field_values(sssom_rows, "object_id")
    kept_llm = _edges_where(llm_edges, "source_id", llm_objects.__contains__)
    threat_ids = _field_values(kept_llm, "target_id")
    kept_threat = _edges_where(threat_edges, "source_id", threat_ids.__contains__)
    ap_sources = _field_values(kept_threat, "source_id")
    kept_llm = _edges_where(kept_llm, "target_id", ap_sources.__contains__)
    llm_sources = _field_values(kept_llm, "source_id")
    closed_sssom = _edges_where(sssom_rows, "object_id", llm_sources.__contains__)
    return closed_sssom, kept_llm + kept_threat


def _field_values(rows: list[dict], key: str) -> set[str]:
    """Return the string form of one field across rows."""
    return {str(row[key]) for row in rows}


def _edges_where(rows: list[dict], key: str, keep: Callable[[str], bool]) -> list[dict]:
    """Return the rows whose field, as a string, satisfies *keep*."""
    return [row for row in rows if keep(str(row[key]))]


__all__ = [
    "OBLIGATION_EDGES_RELEASE",
    "bundled_attack_pattern_catalog",
    "close_reviewed_graph",
    "llm_threat_edges",
    "reviewed_owasp_llm_rows",
    "taxonomy_obligation_inputs",
    "threat_pattern_edges",
]
