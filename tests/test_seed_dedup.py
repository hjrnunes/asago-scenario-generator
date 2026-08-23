"""Tests for scenario seed deduplication in expand_seeds().

Verifies that when multiple risk cards map to the same attack pattern IDs,
expand_seeds() produces one seed per unique seed_id with merged taxonomy IDs
and all contributing risk cards preserved.
"""

from __future__ import annotations

from unittest.mock import patch

from asago_scenario_generator.models.capability_profile import ConfidenceLevel
from asago_scenario_generator.models.scenario import RiskCardRef
from asago_scenario_generator.pipeline.seeds import ScenarioSeed, expand_seeds
from asago_scenario_generator.models import ThreatSurface, ThreatSurfaceEntry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_ref(risk_id: str = "risk-1", confidence: float = 0.9) -> RiskCardRef:
    return RiskCardRef(
        risk_id=risk_id,
        risk_name=f"Risk {risk_id}",
        risk_description=f"Description for {risk_id}",
        taxonomy="ibm-risk-atlas",
        confidence=confidence,
        grounding_confidence=ConfidenceLevel.high,
    )


def _make_entry(
    risk_id: str,
    owasp_llm_ids: list[str],
    agentic_threat_ids: list[str],
    attack_pattern_ids: list[str],
    atlas_technique_ids: list[str] | None = None,
    governance_only: bool = False,
) -> ThreatSurfaceEntry:
    return ThreatSurfaceEntry(
        risk_card=_make_ref(risk_id),
        owasp_llm_ids=owasp_llm_ids,
        agentic_threat_ids=agentic_threat_ids,
        atlas_technique_ids=atlas_technique_ids or [],
        attack_pattern_ids=attack_pattern_ids,
        governance_only=governance_only,
    )


# Minimal threat data sufficient for threat name lookup.
_FAKE_THREATS = {
    "T1": {
        "name": "Threat One",
        "description": "Threat One description",
    },
    "T2": {
        "name": "Threat Two",
        "description": "Threat Two description",
    },
}

# Minimal attack pattern data keyed by AP-* ID.
_FAKE_PATTERNS = {
    "AP-T1-01": {
        "threat_id": "T1",
        "name": "Pattern One",
        "description": "Desc one",
    },
    "AP-T1-02": {
        "threat_id": "T1",
        "name": "Pattern Two",
        "description": "Desc two",
    },
    "AP-T2-01": {
        "threat_id": "T2",
        "name": "Pattern Three",
        "description": "Desc three",
    },
}


def _run_expand(entries: list[ThreatSurfaceEntry]) -> list[ScenarioSeed]:
    """Run expand_seeds with fake threat data, bypassing file I/O."""
    ts = ThreatSurface(entries=entries, governance_only=[])
    with (
        patch(
            "asago_scenario_generator.pipeline.seeds.load_agentic_threats",
            return_value=_FAKE_THREATS,
        ),
        patch(
            "asago_scenario_generator.pipeline.seeds.load_attack_patterns",
            return_value=_FAKE_PATTERNS,
        ),
        patch(
            "asago_scenario_generator.pipeline.seeds.load_attack_pattern_provenance",
            side_effect=FileNotFoundError,
        ),
    ):
        return expand_seeds(ts)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestSeedDeduplication:
    """Core deduplication behaviour."""

    def test_overlapping_attack_patterns_deduplicated(self):
        """Two entries sharing AP-T1-01 produce only one seed for AP-T1-01."""
        entry_a = _make_entry("risk-a", ["LLM01"], ["T1"], ["AP-T1-01", "AP-T1-02"])
        entry_b = _make_entry("risk-b", ["LLM02"], ["T1"], ["AP-T1-01"])

        seeds = _run_expand([entry_a, entry_b])

        seed_ids = [s.seed_id for s in seeds]
        assert seed_ids.count("AP-T1-01") == 1, "AP-T1-01 should appear exactly once"
        # AP-T1-02 only appears in entry_a, so it should still be present.
        assert "AP-T1-02" in seed_ids

    def test_merged_taxonomy_ids_are_unioned(self):
        """Merged seed has the union of owasp and agentic IDs.

        atlas_technique_ids comes from SSSOM provenance (not the broad risk
        pool), so without provenance data it is empty.
        """
        entry_a = _make_entry(
            "risk-a", ["LLM01"], ["T1"], ["AP-T1-01"], atlas_technique_ids=["AML.T0051"]
        )
        entry_b = _make_entry(
            "risk-b",
            ["LLM02", "LLM01"],
            ["T1", "T2"],
            ["AP-T1-01"],
            atlas_technique_ids=["AML.T0054"],
        )

        seeds = _run_expand([entry_a, entry_b])

        merged = next(s for s in seeds if s.seed_id == "AP-T1-01")
        assert merged.owasp_llm_ids == ["LLM01", "LLM02"]
        assert merged.agentic_threat_ids == ["T1", "T2"]
        # No SSSOM provenance loaded in _run_expand, so atlas_technique_ids
        # is empty (provenance-sourced, not from the broad risk pool).
        assert merged.atlas_technique_ids == []

    def test_contributing_risk_cards_preserved(self):
        """Merged seed lists all contributing risk cards."""
        entry_a = _make_entry("risk-a", ["LLM01"], ["T1"], ["AP-T1-01"])
        entry_b = _make_entry("risk-b", ["LLM02"], ["T1"], ["AP-T1-01"])

        seeds = _run_expand([entry_a, entry_b])

        merged = next(s for s in seeds if s.seed_id == "AP-T1-01")
        contrib_ids = {r.risk_id for r in merged.contributing_risk_cards}
        assert contrib_ids == {"risk-a", "risk-b"}
        # Primary ref is the first one encountered.
        assert merged.risk_card_ref.risk_id == "risk-a"

    def test_non_overlapping_entries_produce_separate_seeds(self):
        """Entries with disjoint attack patterns produce separate seeds."""
        entry_a = _make_entry("risk-a", ["LLM01"], ["T1"], ["AP-T1-01"])
        entry_b = _make_entry("risk-b", ["LLM02"], ["T2"], ["AP-T2-01"])

        seeds = _run_expand([entry_a, entry_b])

        seed_ids = sorted(s.seed_id for s in seeds)
        assert seed_ids == ["AP-T1-01", "AP-T2-01"]

    def test_governance_only_entries_skipped(self):
        """Governance-only entries do not produce seeds."""
        entry = _make_entry(
            "risk-gov", ["LLM01"], ["T1"], ["AP-T1-01"], governance_only=True
        )

        seeds = _run_expand([entry])
        assert seeds == []

    def test_duplicate_risk_card_not_added_twice(self):
        """If the same risk_id appears in multiple entries for the same
        attack pattern, contributing_risk_cards does not duplicate it."""
        entry_a = _make_entry("risk-a", ["LLM01"], ["T1"], ["AP-T1-01"])
        entry_b = _make_entry("risk-a", ["LLM02"], ["T1"], ["AP-T1-01"])

        seeds = _run_expand([entry_a, entry_b])

        merged = next(s for s in seeds if s.seed_id == "AP-T1-01")
        assert len(merged.contributing_risk_cards) == 1
        assert merged.contributing_risk_cards[0].risk_id == "risk-a"

    def test_single_entry_produces_contributing_risk_cards(self):
        """Even without dedup, a seed's contributing_risk_cards includes its own ref."""
        entry = _make_entry("risk-a", ["LLM01"], ["T1"], ["AP-T1-01"])

        seeds = _run_expand([entry])

        seed = seeds[0]
        assert len(seed.contributing_risk_cards) == 1
        assert seed.contributing_risk_cards[0].risk_id == "risk-a"

    def test_taxonomy_id_order_preserved(self):
        """Union preserves insertion order (first-seen wins)."""
        entry_a = _make_entry("risk-a", ["LLM03", "LLM01"], ["T1"], ["AP-T1-01"])
        entry_b = _make_entry("risk-b", ["LLM02", "LLM01"], ["T2", "T1"], ["AP-T1-01"])

        seeds = _run_expand([entry_a, entry_b])

        merged = next(s for s in seeds if s.seed_id == "AP-T1-01")
        # LLM03 first (from entry_a), then LLM01 (from entry_a), then LLM02 (new from entry_b)
        assert merged.owasp_llm_ids == ["LLM03", "LLM01", "LLM02"]
        # T1 first (from entry_a), then T2 (new from entry_b)
        assert merged.agentic_threat_ids == ["T1", "T2"]

    def test_three_way_merge(self):
        """Three entries sharing the same attack pattern merge correctly."""
        entry_a = _make_entry("risk-a", ["LLM01"], ["T1"], ["AP-T1-01"])
        entry_b = _make_entry("risk-b", ["LLM02"], ["T1"], ["AP-T1-01"])
        entry_c = _make_entry("risk-c", ["LLM03"], ["T2"], ["AP-T1-01"])

        seeds = _run_expand([entry_a, entry_b, entry_c])

        assert len(seeds) == 1
        merged = seeds[0]
        assert merged.owasp_llm_ids == ["LLM01", "LLM02", "LLM03"]
        assert merged.agentic_threat_ids == ["T1", "T2"]
        contrib_ids = [r.risk_id for r in merged.contributing_risk_cards]
        assert contrib_ids == ["risk-a", "risk-b", "risk-c"]


class TestScenarioSeedModel:
    """ScenarioSeed model backwards compatibility."""

    def test_contributing_risk_cards_defaults_empty(self):
        """contributing_risk_cards defaults to empty list for backwards compat."""
        seed = ScenarioSeed(
            seed_id="AP-T1-01",
            threat_id="T1",
            threat_name="Test",
            attack_pattern_name="Sub",
            attack_pattern_description="Desc",
            risk_card_ref=_make_ref("risk-1"),
            owasp_llm_ids=["LLM01"],
            agentic_threat_ids=["T1"],
        )
        assert seed.contributing_risk_cards == []
