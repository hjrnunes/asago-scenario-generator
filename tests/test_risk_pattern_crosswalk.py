"""Public-seam tests for conservative risk-to-pattern path classification."""

from __future__ import annotations

import pytest

from asago_scenario_generator.pipeline.risk_pattern_crosswalk import (
    resolve_risk_pattern_mapping_strength,
)


@pytest.mark.parametrize(
    ("paths", "expected"),
    [
        (((),), "direct_curated_pair"),
        ((("skos:exactMatch",),), "direct_curated_pair"),
        ((("skos:closeMatch",),), "direct_curated_pair"),
        ((("skos:broadMatch",),), "broad_category_expansion"),
        ((("skos:relatedMatch",),), "related_category_expansion"),
        (
            (("skos:exactMatch", "attacks_via"),),
            "exact_then_category_expansion",
        ),
        (
            (("skos:closeMatch", "attacks_via"),),
            "exact_then_category_expansion",
        ),
        (
            (("skos:closeMatch", "skos:relatedMatch"),),
            "related_category_expansion",
        ),
        (
            (("skos:closeMatch",), ("skos:broadMatch", "attacks_via")),
            "broad_category_expansion",
        ),
        (
            (("skos:exactMatch", "skos:relatedMatch"),),
            "related_category_expansion",
        ),
        (
            (("skos:exactMatch",), ("skos:broadMatch", "attacks_via")),
            "broad_category_expansion",
        ),
        ((("unreviewed_relation",),), "related_category_expansion"),
    ],
)
def test_resolves_all_edges_and_paths_conservatively(paths, expected) -> None:
    assert resolve_risk_pattern_mapping_strength(paths) == expected


@pytest.mark.parametrize("paths", [(), (("",),), ((1,),)])
def test_rejects_missing_or_malformed_relationships(paths) -> None:
    with pytest.raises(ValueError, match="mapping"):
        resolve_risk_pattern_mapping_strength(paths)
