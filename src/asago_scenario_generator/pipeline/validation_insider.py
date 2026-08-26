"""Structured insider-access floor validation."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from asago_scenario_generator.models.scenario import ScenarioEnvelope

logger = logging.getLogger(__name__)

# Insider access floor validation (cmps.6 — structured evidence)
# ---------------------------------------------------------------------------

# Insider actor types that require structured material insider advantage
# when using direct/public ingress.
_INSIDER_ACTOR_TYPES: frozenset[str] = frozenset(
    {"malicious-insider", "negligent-insider"}
)


@dataclass
class InsiderAccessViolation:
    """A malicious-insider scenario lacking structured insider advantage evidence."""

    scenario_id: str
    actor_type: str
    reason: str


@dataclass
class InsiderAccessResult:
    """Result of insider access floor validation across a batch."""

    clean_scenarios: list[ScenarioEnvelope] = field(default_factory=list)
    flagged_scenarios: list[tuple[ScenarioEnvelope, InsiderAccessViolation]] = field(
        default_factory=list
    )

    @property
    def flagged_count(self) -> int:
        return len(self.flagged_scenarios)

    @property
    def clean_count(self) -> int:
        return len(self.clean_scenarios)


def _has_insider_access_markers(text: str) -> bool:
    """Check whether text contains keywords indicating insider-specific access.

    Deprecated: retained for backward-compatible test compatibility only.
    The cmps.6 policy uses structured ``material_insider_advantage`` evidence
    instead of keyword matching.  See :func:`validate_insider_access_floor`.
    """
    # Kept as a no-op stub so legacy imports don't break; the real check
    # is now structured-evidence-based.
    return False


def _insider_access_violation(
    scenario_id: str, actor: Any, access: Any
) -> InsiderAccessViolation | None:
    """Violation for one insider actor, or None when the floor is met."""
    if access is None:
        return InsiderAccessViolation(
            scenario_id=scenario_id,
            actor_type=actor.actor_type,
            reason=(
                f"Insider actor '{actor.actor_type}' has no typed access "
                f"provenance — material_insider_advantage evidence is "
                f"required (cmps.6)."
            ),
        )
    if access.ingress_mode == "direct":
        advantage = access.material_insider_advantage
        if not advantage or not advantage.strip():
            return InsiderAccessViolation(
                scenario_id=scenario_id,
                actor_type=actor.actor_type,
                reason=(
                    f"Insider actor '{actor.actor_type}' using "
                    f"direct ingress lacks structured "
                    f"material_insider_advantage evidence regardless "
                    f"of access_class '{access.access_class}' — enum "
                    f"choice is not evidence (cmps.6)."
                ),
            )
    return None


def validate_insider_access_floor(
    scenarios: list[ScenarioEnvelope],
) -> InsiderAccessResult:
    """Flag insider scenarios lacking structured material insider advantage.

    Replaces the former keyword-based check (cmps.6).  When the actor type
    is an insider (``malicious-insider`` or ``negligent-insider``) using
    direct ingress with ``public``/``authenticated`` access, the
    ``access.material_insider_advantage`` field must be present and
    nonblank.

    Scenarios without an ``access`` provenance block are flagged — the
    policy is authoritative, not optional.

    Returns an :class:`InsiderAccessResult` with clean and flagged scenarios.
    """
    result = InsiderAccessResult()

    for scenario in scenarios:
        actor = scenario.actor_profile
        if actor is None or actor.actor_type not in _INSIDER_ACTOR_TYPES:
            result.clean_scenarios.append(scenario)
            continue

        access = actor.access
        violation = _insider_access_violation(scenario.scenario_id, actor, access)
        if violation is None:
            # Direct ingress with evidence, or indirect ingress — validated
            # via influence evidence in the shared access-policy validator.
            result.clean_scenarios.append(scenario)
        else:
            logger.warning(
                "Insider access floor: scenario %s actor_type='%s' %s",
                scenario.scenario_id,
                actor.actor_type,
                "has no access provenance"
                if access is None
                else "using direct ingress without material_insider_advantage",
            )
            result.flagged_scenarios.append((scenario, violation))

    return result
