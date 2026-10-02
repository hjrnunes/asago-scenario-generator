"""Tests for the traceability and identity contract (STPA-TRACEABILITY).

Canonical projection validation fails closed for absent vector keys while
present-empty vectors remain valid.  Candidate identity, ICA identity,
and scenario identity are distinct fields in the canonical exports, and
exports round-trip through standard readers under the same typed rules.
"""

from __future__ import annotations



from asago_scenario_generator.stpa.models.execution_envelope import (
    CausalFactor,
)
from asago_scenario_generator.stpa.models.execution_projection import (
    StpaProjectionTraceabilityViolationCode,
)
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.models.scenario_spec import (
    AttackerBDI,
    DefenderBDI,
    DefenderBelief,
    DefenderDesire,
    DefenderIntention,
    ScenarioSpec,
    ThreatSource,
)

UCA_SLOT = "RESP-1:CA-1-1:WRONG_TIMING"
ICA_ID = "RESP-1:CA-1-1:WRONG_TIMING:1"
CANDIDATE_ID = "EXEC:RESP-1:CA-1-1:WRONG_TIMING"
def _spec(causal_factors: list[CausalFactor] | None = None) -> ScenarioSpec:
    return ScenarioSpec(
        scenario_id="SCN-001",
        threat_source=ThreatSource(
            ica_slot_id=UCA_SLOT,
            provenance="structural",
            ica_id=ICA_ID,
        ),
        target_controller="RESP-1",
        target_control_action="CA-1-1",
        ica_type=UCAType.wrong_timing,
        defender_bdi=DefenderBDI(
            beliefs=[DefenderBelief(pm_id="PM-1-1", content="b", vulnerability="v")],
            desires=[DefenderDesire(resp_id="RESP-1", content="d")],
            intentions=[DefenderIntention(ca_id="CA-1-1", content="i")],
        ),
        attacker_bdi=AttackerBDI(beliefs=["b"], desires=["d"], intentions=["i"]),
        loss_scenario="loss",
        causal_factors=causal_factors or [],
    )






class TestViolationCodesStable:
    """New fail-closed codes are typed and stable."""

    def test_missing_vector_codes_exist(self):
        """The three missing-vector codes are part of the enum."""
        assert (
            StpaProjectionTraceabilityViolationCode.causal_factors_missing.value
            == "causal_factors_missing"
        )
        assert (
            StpaProjectionTraceabilityViolationCode.assertions_missing.value
            == "assertions_missing"
        )
        assert (
            StpaProjectionTraceabilityViolationCode.steps_missing.value
            == "steps_missing"
        )
        assert (
            StpaProjectionTraceabilityViolationCode.uca_constraint_mismatch.value
            == "uca_constraint_mismatch"
        )
