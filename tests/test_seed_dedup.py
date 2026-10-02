"""Tests for scenario seed deduplication in expand_seeds().

Verifies that when multiple risk cards map to the same attack pattern IDs,
expand_seeds() produces one seed per unique seed_id with merged taxonomy IDs
and all contributing risk cards preserved.
"""

from __future__ import annotations


from asago_scenario_generator.models.capability_profile import ConfidenceLevel
from asago_scenario_generator.models.scenario import RiskCardRef
from asago_scenario_generator.pipeline.seeds import ScenarioSeed
from asago_scenario_generator.models import ThreatSurfaceEntry


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


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


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
