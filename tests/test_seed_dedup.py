"""Tests for the ScenarioSeed contributing-risk-card default."""

from __future__ import annotations


from asago_scenario_generator.models.capability_profile import ConfidenceLevel
from asago_scenario_generator.models.scenario import RiskCardRef
from asago_scenario_generator.pipeline.seeds import ScenarioSeed


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
