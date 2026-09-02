"""SP3 — Scenario Production (Stages 5, 6, 7).

This package implements the scenario production pipeline:
  Stage 5: Dual-BDI scenario specification (deterministic defender + LLM attacker)
  Stage 6: Narrative + attack tree + Gherkin (3 LLM calls per scenario)
  Stage 7: Validators + deterministic eval metrics + coverage gap analysis
"""

from .execution_bundle import (
    ExecutionBundlePublication,
    ExecutionBundlePublicationError,
    publish_execution_bundle,
    read_execution_bundle,
    verify_execution_bundle,
)
from .execution_projection import (
    ExecutionProjectionPreparationError,
    ValidatedExecutionProjection,
    parse_execution_projection,
    prepare_execution_projection,
    validate_execution_projection,
)

__all__ = [
    "ExecutionBundlePublication",
    "ExecutionBundlePublicationError",
    "ExecutionProjectionPreparationError",
    "ValidatedExecutionProjection",
    "parse_execution_projection",
    "prepare_execution_projection",
    "publish_execution_bundle",
    "read_execution_bundle",
    "validate_execution_projection",
    "verify_execution_bundle",
]
