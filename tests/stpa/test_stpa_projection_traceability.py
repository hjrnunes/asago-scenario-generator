"""Tests for the typed STPA projection traceability result models.

The violation codes stay aligned with the taxonomy ``projection_validation``
contract.
"""

from __future__ import annotations

from asago_scenario_generator.stpa.models.execution_envelope import (
    CausalFactor,
    CausalFactorKind,
)
from asago_scenario_generator.stpa.models.execution_projection import (
    StpaProjectionTraceabilityResult,
    StpaProjectionTraceabilityViolation,
    StpaProjectionTraceabilityViolationCode,
)
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType

CONTROLLER = "RESP-1"
CONTROL_ACTION = "CA-1-1"
UCA_TYPE = UCAType.wrong_timing
CANDIDATE_ID = "EXEC:RESP-1:CA-1-1:WRONG_TIMING"


def _factor(kind: CausalFactorKind, source_id: str) -> CausalFactor:
    return CausalFactor(kind=kind, source_id=source_id, description=source_id)




def _mutate(doc: dict, mutation: str) -> str:
    """Apply one named temporal-projection mutation, returning the expected element id."""
    if mutation == "omitting the PM-1-1 assertion":
        doc["assertions"] = [
            a for a in doc["assertions"] if a["source_id"] != "PM-1-1"
        ]
        return "TA-1"
    if mutation == "reordering the PM-1-1 and FB-1-1 assertions":
        doc["assertions"][0], doc["assertions"][1] = (
            doc["assertions"][1],
            doc["assertions"][0],
        )
        return "TA-1"
    if mutation == "changing TA-2 source to PM-1-1":
        _by_id(doc["assertions"], "TA-2")["source_id"] = "PM-1-1"
        return "TA-2"
    if mutation == "changing S-2 source to PM-1-1":
        _by_id(doc["steps"], "S-2")["source_id"] = "PM-1-1"
        return "S-2"
    if mutation == "changing TA-1 predicate to FEEDBACK_DELAYED":
        _by_id(doc["assertions"], "TA-1")["predicate"] = "FEEDBACK_DELAYED"
        return "TA-1"
    if mutation == "changing the final step source to CA-9-9":
        doc["steps"][-1]["source_id"] = "CA-9-9"
        return "S-3"
    raise AssertionError(f"Unknown mutation {mutation!r}")


def _by_id(items: list[dict], identifier: str) -> dict:
    for item in items:
        if item.get("assertion_id") == identifier or item.get("step_id") == identifier:
            return item
    raise AssertionError(f"No projection element {identifier}")


class TestTraceabilityViolationModels:
    """Typed violation codes align with the taxonomy projection_validation shape."""

    def test_violation_codes_are_typed_and_stable(self):
        """Stream B violations use stable snake_case typed codes."""
        assert (
            StpaProjectionTraceabilityViolationCode.omitted_causal_factor.value
            == "omitted_causal_factor"
        )
        assert (
            StpaProjectionTraceabilityViolationCode.reordered_causal_factor.value
            == "reordered_causal_factor"
        )
        assert (
            StpaProjectionTraceabilityViolationCode.assertion_source_mismatch.value
            == "assertion_source_mismatch"
        )
        assert (
            StpaProjectionTraceabilityViolationCode.step_source_mismatch.value
            == "step_source_mismatch"
        )
        assert (
            StpaProjectionTraceabilityViolationCode.assertion_predicate_mismatch.value
            == "assertion_predicate_mismatch"
        )
        assert (
            StpaProjectionTraceabilityViolationCode.uca_step_mismatch.value
            == "uca_step_mismatch"
        )
        assert (
            StpaProjectionTraceabilityViolationCode.candidate_identity_mismatch.value
            == "candidate_identity_mismatch"
        )
        assert (
            StpaProjectionTraceabilityViolationCode.typed_provenance_mismatch.value
            == "typed_provenance_mismatch"
        )
        assert (
            StpaProjectionTraceabilityViolationCode.schema_version_missing.value
            == "schema_version_missing"
        )

    def test_violation_carries_code_detail_and_element_id(self):
        """A violation identifies the affected projection element."""
        violation = StpaProjectionTraceabilityViolation(
            code=StpaProjectionTraceabilityViolationCode.omitted_causal_factor,
            detail="TA-1 is missing",
            element_id="TA-1",
        )
        assert violation.element_id == "TA-1"
        assert violation.detail

    def test_result_flips_valid_when_violations_exist(self):
        """A result with violations is invalid, mirroring the taxonomy contract."""
        result = StpaProjectionTraceabilityResult(
            violations=[
                StpaProjectionTraceabilityViolation(
                    code=StpaProjectionTraceabilityViolationCode.uca_step_mismatch,
                    detail="Final step is missing",
                    element_id="S-3",
                )
            ]
        )
        assert result.valid is False
        assert StpaProjectionTraceabilityResult().valid is True


