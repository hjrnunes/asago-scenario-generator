"""The closed planner input graph: risk -> OWASP LLM -> attack pattern.

``taxonomy_obligation_inputs`` builds the planner's typed input from values a
caller has already loaded: the reviewed SSSOM mappings, the parsed
LLM-to-attack-pattern table, and the bundled attack-pattern catalog. It keeps
only the rows and edges on a complete path and pins the catalog and the closed
mapping bundle. ``bundled_attack_pattern_catalog`` loads the catalog shipped
with the package.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from asago_scenario_generator.data.risk_schemes import (
    EDITION,
    OWASP_LLM_SCHEME,
    is_edition_scheme,
    load_vocabulary,
    parse_object_id,
)
from asago_scenario_generator.pipeline.obligation_contracts import (
    TaxonomyObligationInputs,
    compute_mapping_bundle_digest,
)

OBLIGATION_EDGES_RELEASE = "obligation-mapping-bundle-v2"
_LLM_PATTERN_EVIDENCE = "llm-to-attack-pattern.yaml"


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
    llm_pattern_table: Any,
) -> TaxonomyObligationInputs:
    """Close the reviewed graph and pin it as the planner's typed input."""
    context = catalog[0].canonical_chain.taxonomy_context
    sssom_rows = reviewed_owasp_llm_rows(sssom_mappings, risk_cards)
    cross_edges = llm_pattern_edges(llm_pattern_table, capability_profile)
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
    """Return reviewed risks' OWASP LLM 2026 matches with their LLM codes.

    A row of another OWASP LLM edition, or an ``owasp-llm-2026`` row whose
    object ID is not in the pinned vocabulary, raises ``ValueError``. Rows of
    other schemes are skipped.
    """
    risk_ids = {str(item.risk_id) for item in risk_cards}
    rows = []
    for mapping in sssom_mappings:
        row = mapping.model_dump(mode="json")
        if not _is_current_owasp_llm_row(row):
            continue
        code = parse_object_id(OWASP_LLM_SCHEME, str(row["object_id"])).code
        if row["subject_id"] not in risk_ids:
            continue
        if "nomatch" in str(row["predicate_id"]).lower():
            continue
        row["object_id"] = code
        rows.append(row)
    return rows


def _is_current_owasp_llm_row(row: dict) -> bool:
    """Whether ``row`` is an OWASP LLM 2026 row; raise for another edition."""
    source = str(row["object_source"])
    if source == OWASP_LLM_SCHEME:
        return True
    if is_edition_scheme(source) and source.startswith("owasp-llm"):
        raise ValueError(
            f"SSSOM row for {row['subject_id']!r} has object_source {source!r}; "
            f"expected {OWASP_LLM_SCHEME!r}"
        )
    return False


def llm_pattern_edges(llm_pattern_table: Any, capability_profile: Any) -> list[dict]:
    """Return the LLM-to-attack-pattern edges of the in-scope patterns.

    The table must declare ``edition: "2026"`` and list only OWASP LLM 2026
    codes; anything else raises ``ValueError``.
    """
    from asago_scenario_generator.data.threat_gating import in_scope_attack_pattern_ids

    if not isinstance(llm_pattern_table, dict):
        raise ValueError("LLM-to-attack-pattern table must contain an object")
    edition = llm_pattern_table.get("edition")
    if edition != EDITION:
        raise ValueError(
            f"LLM-to-attack-pattern table declares edition {edition!r}; "
            f"expected {EDITION!r}"
        )
    codes = {entry.code for entry in load_vocabulary(OWASP_LLM_SCHEME).values()}
    for entry in llm_pattern_table["patterns"]:
        unknown = sorted(set(entry["llm"]) - codes)
        if unknown:
            raise ValueError(
                f"LLM-to-attack-pattern entry {entry['id']!r} lists {unknown}; "
                f"expected codes of {OWASP_LLM_SCHEME!r}: {sorted(codes)}"
            )
    in_scope = set(in_scope_attack_pattern_ids(capability_profile))
    relation = llm_pattern_table["predicate"]
    return [
        {
            "source_id": llm_id,
            "target_id": entry["id"],
            "relation": relation,
            "evidence": [_LLM_PATTERN_EVIDENCE],
        }
        for entry in llm_pattern_table["patterns"]
        if entry["id"] in in_scope
        for llm_id in entry["llm"]
    ]


def close_reviewed_graph(
    sssom_rows: list[dict], cross_edges: list[dict]
) -> tuple[list[dict], list[dict]]:
    """Keep only rows and edges on a complete risk -> LLM -> pattern path."""
    llm_objects = _field_values(sssom_rows, "object_id")
    kept = _edges_where(cross_edges, "source_id", llm_objects.__contains__)
    llm_sources = _field_values(kept, "source_id")
    closed_sssom = _edges_where(sssom_rows, "object_id", llm_sources.__contains__)
    return closed_sssom, kept


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
    "llm_pattern_edges",
    "reviewed_owasp_llm_rows",
    "taxonomy_obligation_inputs",
]
