"""SP3 — Scenario Production (Stages 5, 6, 7).

This package implements the scenario production pipeline:
  Stage 5: Dual-BDI scenario specification (deterministic defender + LLM attacker)
  Stage 6: Narrative + attack tree + Gherkin (3 LLM calls per scenario)
  Stage 7: Validators + deterministic eval metrics + coverage gap analysis
"""

__all__ = [
    "ExecutionBundlePublication",
    "ExecutionBundlePublicationError",
    "ExecutionProjectionPreparationError",
    "ValidatedExecutionProjection",
    "parse_execution_projection",
    "prepare_execution_projection",
    "publish_execution_bundle",
    "publish_execution_target_profile",
    "read_execution_bundle",
    "validate_execution_projection",
    "verify_execution_bundle",
    "classify_scenario_execution",
]


def __getattr__(name: str):
    """Load the legacy package exports without importing the full pipeline."""

    if name in {
        "ExecutionBundlePublication",
        "ExecutionBundlePublicationError",
        "publish_execution_bundle",
        "publish_execution_target_profile",
        "read_execution_bundle",
        "verify_execution_bundle",
    }:
        from . import execution_bundle

        return getattr(execution_bundle, name)
    if name in {
        "ExecutionProjectionPreparationError",
        "ValidatedExecutionProjection",
        "parse_execution_projection",
        "prepare_execution_projection",
        "validate_execution_projection",
    }:
        from . import execution_projection

        return getattr(execution_projection, name)
    if name == "classify_scenario_execution":
        from .execution_classification import classify_scenario_execution

        return classify_scenario_execution
    raise AttributeError(name)
