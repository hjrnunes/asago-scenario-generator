"""Plausibility checks for scenario evaluation.

Cross-validates scenario fields for implausible combinations that
indicate generation errors (e.g. novice actors with high attack
complexity, or nation-state actors at novice capability level).
"""

from __future__ import annotations

from typing import Any


# Actor types that should be advanced or expert
_SOPHISTICATED_ACTORS = {"nation-state", "supply-chain-actor"}

# Capability levels considered "high skill"
_HIGH_SKILL_LEVELS = {"advanced", "expert"}


def _sophisticated_actor_violation(
    actor_type: str, capability_level: str
) -> str | None:
    """Skill-floor violation for sophisticated actor types, or None."""
    if actor_type == "nation-state" and capability_level not in _HIGH_SKILL_LEVELS:
        return (
            f"nation-state actor has capability_level '{capability_level}'"
            f" (expected advanced or expert)"
        )
    if (
        actor_type == "supply-chain-actor"
        and capability_level not in _HIGH_SKILL_LEVELS
    ):
        return (
            f"supply-chain-actor has capability_level '{capability_level}'"
            f" (expected advanced or expert)"
        )
    return None


def capability_complexity_violations(scenario: dict[str, Any]) -> list[str]:
    """Check for implausible capability-complexity combinations.

    Rules:
    - nation-state actors should be advanced or expert
    - novice actors should not have high attack_complexity
    - supply-chain-actor should be advanced or expert

    Returns list of violation descriptions (empty = no violations).
    """
    violations: list[str] = []

    actor_profile = scenario.get("actor_profile")
    if not actor_profile or not isinstance(actor_profile, dict):
        return violations

    actor_type = actor_profile.get("actor_type", "")
    capability_level = actor_profile.get("capability_level", "")

    # Extract attack_complexity from priority.signals
    priority = scenario.get("priority", {})
    signals = priority.get("signals", {})
    attack_complexity = signals.get("attack_complexity", "")

    # Rules 1 & 2: sophisticated actors should be advanced or expert
    actor_violation = _sophisticated_actor_violation(actor_type, capability_level)
    if actor_violation is not None:
        violations.append(actor_violation)

    # Rule 3: novice actors should not have high attack_complexity
    if capability_level == "novice" and attack_complexity == "high":
        violations.append("novice actor has high attack_complexity")

    return violations


def score_plausibility(
    scenarios: list[dict[str, Any]],
) -> dict[str, Any]:
    """Compute plausibility metrics across a batch of scenarios.

    Args:
        scenarios: List of scenario dicts (parsed YAML).

    Returns:
        Dict with total violation count and per-scenario details.
    """
    total_violations = 0
    per_scenario: dict[str, list[str]] = {}

    for scenario in scenarios:
        scenario_id = scenario.get("scenario_id", "unknown")
        violations = capability_complexity_violations(scenario)
        if violations:
            total_violations += len(violations)
            per_scenario[scenario_id] = violations

    result: dict[str, Any] = {
        "capability_complexity_violation_count": total_violations,
    }
    if per_scenario:
        result["per_scenario"] = per_scenario

    return result
