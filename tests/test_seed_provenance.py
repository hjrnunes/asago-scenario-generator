"""Tests for the SSSOM provenance field defaults on ScenarioSeed."""

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


class TestSeedProvenanceFields:
    """Verify owasp_origin, laaf_technique_ids, atlas_provenance_ids on seeds."""

    def test_provenance_defaults_on_model(self):
        """New provenance fields have sensible defaults for backwards compat."""
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
        assert seed.owasp_origin is None
        assert seed.laaf_technique_ids == []
        assert seed.atlas_provenance_ids == []

