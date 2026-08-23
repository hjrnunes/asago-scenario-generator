"""Tests for the direct T-threat mapping path (bypassing LLM hop).

Verifies that agentic-only threats (T7-T10, T14-T16) are reachable
through the direct path when they pass KC-based threat gating.
Profile matching is no longer done here — it's handled by
determine_threat_scope via KC sub-codes.
"""

from __future__ import annotations

import pytest

from asago_scenario_generator.pipeline.threats import (
    _build_t_to_atlas_index,
    _resolve_direct_threats,
)


# ---------------------------------------------------------------------------
# Fixtures: minimal cross-taxonomy data with t_direct section
# ---------------------------------------------------------------------------

CROSS_TAXONOMY_WITH_DIRECT = {
    "t_to_llm": [
        {"source": "T1", "target": "LLM04"},
        {"source": "T6", "target": "LLM01"},
    ],
    "t_direct": [
        {
            "source": "T7",
            "source_name": "Misaligned & Deceptive Behaviors",
        },
        {
            "source": "T8",
            "source_name": "Repudiation & Untraceability",
        },
        {
            "source": "T9",
            "source_name": "Identity Spoofing & Impersonation",
        },
        {
            "source": "T10",
            "source_name": "Overwhelming Human in the Loop",
        },
        {
            "source": "T14",
            "source_name": "Human Attacks on Multi-Agent Systems",
        },
        {
            "source": "T15",
            "source_name": "Human Manipulation",
        },
        {
            "source": "T16",
            "source_name": "Insecure Inter-Agent Protocol Abuse",
        },
    ],
}


# ---------------------------------------------------------------------------
# Tests: _resolve_direct_threats
# ---------------------------------------------------------------------------


class TestResolveDirectThreats:
    """Tests for resolving which direct-path threats are in scope."""

    def test_all_in_scope_resolves_all_seven(self) -> None:
        """When all direct threats pass KC gating, all seven are resolved."""
        in_scope = {"T7", "T8", "T9", "T10", "T14", "T15", "T16"}
        result = _resolve_direct_threats(CROSS_TAXONOMY_WITH_DIRECT, in_scope)
        assert result == {"T7", "T8", "T9", "T10", "T14", "T15", "T16"}

    def test_gating_filters_out_threats(self) -> None:
        """Threats not in scope (KC gating excluded them) are not resolved."""
        in_scope = {"T7", "T8"}
        result = _resolve_direct_threats(CROSS_TAXONOMY_WITH_DIRECT, in_scope)
        assert result == {"T7", "T8"}

    def test_no_direct_section_yields_empty(self) -> None:
        result = _resolve_direct_threats({"t_to_llm": []}, {"T7", "T8"})
        assert result == set()

    def test_partial_scope_resolves_matching_subset(self) -> None:
        """Only direct threats that pass KC gating are resolved."""
        in_scope = {"T7", "T8", "T9", "T15"}
        result = _resolve_direct_threats(CROSS_TAXONOMY_WITH_DIRECT, in_scope)
        assert result == {"T7", "T8", "T9", "T15"}

    def test_non_direct_threats_ignored(self) -> None:
        """Threats not in t_direct (e.g. T1, T6) are not returned."""
        in_scope = {"T1", "T6", "T7"}
        result = _resolve_direct_threats(CROSS_TAXONOMY_WITH_DIRECT, in_scope)
        assert result == {"T7"}


# ---------------------------------------------------------------------------
# Tests: integration with real cross-taxonomy YAML
# ---------------------------------------------------------------------------


class TestDirectMappingYAMLIntegration:
    """Tests that the actual cross-taxonomy-mappings.yaml contains valid t_direct data."""

    @pytest.fixture()
    def cross_taxonomy(self) -> dict:
        import yaml
        from pathlib import Path

        yaml_path = (
            Path(__file__).resolve().parents[1]
            / "data"
            / "taxonomies"
            / "mappings"
            / "cross-taxonomy-mappings.yaml"
        )
        with open(yaml_path) as f:
            return yaml.safe_load(f)

    def test_t_direct_section_exists(self, cross_taxonomy: dict) -> None:
        assert "t_direct" in cross_taxonomy
        assert len(cross_taxonomy["t_direct"]) == 7

    def test_all_agentic_only_threats_have_direct_mapping(
        self, cross_taxonomy: dict
    ) -> None:
        """Every threat listed in agentic_only_threats must have a t_direct entry."""
        agentic_only_ids = {
            t["id"] for t in cross_taxonomy["agentic_only_threats"]["threats"]
        }
        direct_ids = {m["source"] for m in cross_taxonomy["t_direct"]}
        assert agentic_only_ids == direct_ids

    def test_all_direct_entries_have_source(
        self, cross_taxonomy: dict
    ) -> None:
        """Every t_direct entry must have a source field."""
        for mapping in cross_taxonomy["t_direct"]:
            assert "source" in mapping, (
                f"t_direct entry missing 'source': {mapping}"
            )

    def test_full_scope_resolves_all_seven(
        self, cross_taxonomy: dict
    ) -> None:
        """All seven direct threats resolved when all are in scope."""
        in_scope = {"T7", "T8", "T9", "T10", "T14", "T15", "T16"}
        result = _resolve_direct_threats(cross_taxonomy, in_scope)
        assert result == {"T7", "T8", "T9", "T10", "T14", "T15", "T16"}

    def test_partial_scope_resolves_subset(
        self, cross_taxonomy: dict
    ) -> None:
        """Only in-scope direct threats are resolved."""
        in_scope = {"T7", "T8", "T15"}
        result = _resolve_direct_threats(cross_taxonomy, in_scope)
        assert result == {"T7", "T8", "T15"}

    def test_t_to_atlas_section_exists(self, cross_taxonomy: dict) -> None:
        """The t_to_atlas section must exist with entries for all 17 T-threats."""
        assert "t_to_atlas" in cross_taxonomy
        t_ids = {m["source"] for m in cross_taxonomy["t_to_atlas"]}
        expected = {f"T{i}" for i in range(1, 18)}
        assert t_ids == expected, f"Missing T-threats: {expected - t_ids}"

    def test_t_to_atlas_all_entries_have_targets(
        self, cross_taxonomy: dict
    ) -> None:
        """Every t_to_atlas entry must have non-empty targets list."""
        for mapping in cross_taxonomy["t_to_atlas"]:
            assert mapping.get("targets"), (
                f"{mapping['source']} has empty targets"
            )
            assert all(
                t.startswith("AML.T") for t in mapping["targets"]
            ), f"{mapping['source']} has non-ATLAS technique ID in targets"

    def test_build_t_to_atlas_index(self, cross_taxonomy: dict) -> None:
        """_build_t_to_atlas_index produces a correct index."""
        index = _build_t_to_atlas_index(cross_taxonomy)
        assert len(index) == 17
        assert "AML.T0051.000" in index["T6"]
        assert "AML.T0054" in index["T6"]
        assert "AML.T0029" in index["T4"]
        assert "AML.T0034" in index["T4"]
