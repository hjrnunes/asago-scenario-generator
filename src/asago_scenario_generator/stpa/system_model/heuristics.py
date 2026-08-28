"""Structural heuristics and solution-neutrality post-checks.

Wraps the foundation's ``check_structural_heuristics`` and adds the
solution-neutrality keyword scan. These are deterministic post-checks
run after Stage 2 Call 3 assembles the ControlStructure.
"""

from __future__ import annotations

from asago_scenario_generator.stpa.models.control_structure import (
    ControlStructure,
    HeuristicResult,
    check_structural_heuristics,
)
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis

# Component names that violate solution-neutrality (case-insensitive).
_SOLUTION_NEUTRALITY_KEYWORDS: tuple[str, ...] = (
    "LLM",
    "proxy",
    "orchestrator",
    "guardrail",
    "prompt",
    "API",
)


def run_heuristics(
    cs: ControlStructure,
    loss_analysis: LossAnalysis | None = None,
) -> HeuristicResult:
    """Run structural heuristics on a control structure.

    Wraps the foundation's ``check_structural_heuristics``. When
    ``loss_analysis`` is provided, the hazard tracing check is included.

    Args:
        cs: The control structure to check.
        loss_analysis: Optional loss analysis for hazard tracing.

    Returns:
        A HeuristicResult with errors and warnings.
    """
    return check_structural_heuristics(cs, loss_analysis)


def check_solution_neutrality(cs: ControlStructure) -> list[str]:
    """Check control structure descriptions for solution-neutrality violations.

    Scans responsibility, process model part, control action, and feedback
    channel descriptions for implementation-specific component names
    (LLM, proxy, orchestrator, guardrail, prompt, API). Case-insensitive.

    Args:
        cs: The control structure to check.

    Returns:
        A list of warning messages for each violation found.
    """
    warnings: list[str] = []
    for resp in cs.responsibilities:
        _scan_description(resp.description, "responsibility", resp.resp_id, warnings)
        for pm in resp.process_model_parts:
            _scan_description(pm.description, "PM", pm.pm_id, warnings)
        for ca in resp.control_actions:
            _scan_description(ca.description, "CA", ca.ca_id, warnings)
        for fb in resp.feedback_channels:
            _scan_description(fb.description, "FB", fb.fb_id, warnings)
    return warnings


def _scan_description(
    description: str,
    element_type: str,
    element_id: str,
    warnings: list[str],
) -> None:
    """Scan a description for solution-neutrality violations and append warnings."""
    desc_lower = description.lower()
    for keyword in _SOLUTION_NEUTRALITY_KEYWORDS:
        if keyword.lower() in desc_lower:
            warnings.append(
                f"{element_type} {element_id} description contains "
                f"solution-specific term '{keyword}'."
            )
