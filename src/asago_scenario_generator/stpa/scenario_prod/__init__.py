"""SP3 — Scenario Production (Stages 5, 6, 7).

This package implements the scenario production pipeline:
  Stage 5: Dual-BDI scenario specification (deterministic defender + LLM attacker)
  Stage 6: Deterministic narrative, attack tree and Gherkin summary
  Stage 7: Validators + deterministic eval metrics + coverage gap analysis
"""

__all__ = [
    "ExecutionProjectionPreparationError",
    "ValidatedExecutionProjection",
    "prepare_execution_projection",
    "publish_execution_target_profile",
    "classify_scenario_execution",
]


def __getattr__(name: str):
    """Load the legacy package exports without importing the full pipeline."""

    if name == "publish_execution_target_profile":
        from .target_profile_publication import publish_execution_target_profile

        return publish_execution_target_profile
    if name in {
        "ExecutionProjectionPreparationError",
        "ValidatedExecutionProjection",
        "prepare_execution_projection",
    }:
        from . import execution_projection

        return getattr(execution_projection, name)
    if name == "classify_scenario_execution":
        from .execution_classification import classify_scenario_execution

        return classify_scenario_execution
    raise AttributeError(name)
