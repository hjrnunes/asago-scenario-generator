"""SP3 — Scenario Production (Stages 5, 6, 7).

This package implements the scenario production pipeline:
  Stage 5: Dual-BDI scenario specification (deterministic defender + LLM attacker)
  Stage 6: Deterministic narrative, attack tree and Gherkin summary
  Stage 7: Validators + deterministic eval metrics + coverage gap analysis
"""

__all__ = ["publish_execution_target_profile"]


def __getattr__(name: str):
    """Load the package export without importing the full pipeline."""

    if name == "publish_execution_target_profile":
        from .target_profile_publication import publish_execution_target_profile

        return publish_execution_target_profile
    raise AttributeError(name)
