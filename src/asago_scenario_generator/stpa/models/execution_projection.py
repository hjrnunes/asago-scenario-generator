"""Typed traceability contract for the STPA execution projection.

Aligned with the taxonomy ``projection_validation`` contract: validation
results carry typed violation codes and identify the earliest affected
projection element.  The STPA codes are specific to the deterministic
execution projection (causal factors, temporal assertions, scenario
steps, and the canonical candidate identity).
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StpaProjectionTraceabilityViolationCode(str, Enum):
    """Typed violation codes for STPA execution projection traceability."""

    omitted_causal_factor = "omitted_causal_factor"
    reordered_causal_factor = "reordered_causal_factor"
    assertion_source_mismatch = "assertion_source_mismatch"
    step_source_mismatch = "step_source_mismatch"
    assertion_predicate_mismatch = "assertion_predicate_mismatch"
    uca_step_mismatch = "uca_step_mismatch"
    candidate_identity_mismatch = "candidate_identity_mismatch"
    typed_provenance_mismatch = "typed_provenance_mismatch"
    schema_version_missing = "schema_version_missing"
    causal_factors_missing = "causal_factors_missing"
    assertions_missing = "assertions_missing"
    steps_missing = "steps_missing"
    uca_constraint_mismatch = "uca_constraint_mismatch"


class StpaProjectionTraceabilityViolation(BaseModel):
    """One typed traceability violation for the execution projection.

    ``element_id`` names the earliest affected projection element — a
    canonical assertion ID (``TA-*``), step ID (``S-*``), or the offending
    candidate identifier — so consumers can locate the broken link without
    re-deriving it.
    """

    model_config = ConfigDict(extra="forbid")

    code: StpaProjectionTraceabilityViolationCode
    detail: str = Field(min_length=1)
    element_id: str = Field(min_length=1)


class StpaProjectionTraceabilityResult(BaseModel):
    """Aggregated traceability validation result for the execution projection."""

    model_config = ConfigDict(extra="forbid")

    valid: bool = Field(default=True)
    violations: list[StpaProjectionTraceabilityViolation] = Field(default_factory=list)

    @model_validator(mode="after")
    def _sync_valid(self) -> StpaProjectionTraceabilityResult:
        if self.violations:
            self.valid = False
        return self


__all__ = [
    "StpaProjectionTraceabilityResult",
    "StpaProjectionTraceabilityViolation",
    "StpaProjectionTraceabilityViolationCode",
]


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-20T20:27:50Z","module_hash":"9a864036293f2c6809c203916a58eb4a9a5d4a08c83e83dcdf5394acd435dfa4","functions":[{"id":"func/StpaProjectionTraceabilityResult._sync_valid","name":"_sync_valid","line":56,"end_line":59,"hash":"1dbd5734c1931688dd12f6e456ce7391a6cf0916043f02ff9617a980c967bad5"}]}
# mutate4py-manifest-end
