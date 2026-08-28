"""STPA end-to-end pipeline orchestration.

This package chains SP1 (system model), SP2 (threat enumeration), and
SP3 (scenario production) into a single ``run_stpa_pipeline`` call,
followed by STPA HTML report generation.
"""

from asago_scenario_generator.stpa.pipeline.runner import (
    STPARunResult,
    run_stpa_pipeline,
)

__all__ = ["STPARunResult", "run_stpa_pipeline"]
