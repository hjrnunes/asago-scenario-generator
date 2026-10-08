"""Stage 2 advisory post-checks: uncited constraints and solution neutrality.

These deterministic checks run after Stage 2 Call 3 assembles the
ControlStructure; the structural checks live in
``stpa.models.control_structure.check_structural_heuristics``.
"""

from __future__ import annotations

from asago_scenario_generator.stpa.models.control_structure import ControlStructure
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


def uncited_security_constraints(
    cs: ControlStructure, loss_analysis: LossAnalysis
) -> list[str]:
    """Return Stage 1a constraint IDs that no Stage 2 responsibility cites.

    A constraint no responsibility implements yields no control action to
    analyze, so its rule reaches no scenario.  The result is advisory.
    """
    cited = {
        ref
        for responsibility in cs.responsibilities
        for ref in responsibility.security_constraint_refs
    }
    return [
        constraint.constraint_id
        for constraint in loss_analysis.security_constraints
        if constraint.constraint_id not in cited
    ]


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
