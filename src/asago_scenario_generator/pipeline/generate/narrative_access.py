"""Narrative access-provenance validation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from asago_scenario_generator.models.scenario import (
    ActorProfile,
    NarrativeAccessRealization,
    NarrativeLayer,
)


@dataclass
class NarrativeRealizationViolation:
    """A narrative access-realization mismatch (cmps.6)."""

    rule: str
    message: str


def _missing_access_realization_violation() -> NarrativeRealizationViolation:
    """Narrative without typed access provenance (cmps.6)."""
    return NarrativeRealizationViolation(
        rule="missing_access_realization",
        message=(
            "Narrative lacks typed access_realization — required "
            "when actor access provenance is present (cmps.6)."
        ),
    )


def _entry_point_mismatch_violation(
    realization: NarrativeAccessRealization, access: Any
) -> list[NarrativeRealizationViolation]:
    """initial_entry_point_id mismatches."""
    if realization.initial_entry_point_id != access.initial_entry_point_id:
        return [
            NarrativeRealizationViolation(
                rule="realization_entry_point_mismatch",
                message=(
                    f"Narrative access_realization initial_entry_point_id "
                    f"'{realization.initial_entry_point_id}' does not match "
                    f"actor access provenance "
                    f"'{access.initial_entry_point_id}'."
                ),
            )
        ]
    return []


def _source_id_mismatch(
    realization: NarrativeAccessRealization, access: Any
) -> list[NarrativeRealizationViolation]:
    """Legacy source identity mismatch against actor provenance."""
    realization_source_id = (
        realization.influence_source_id or realization.influence_source
    )
    access_source_id = access.influence_source_id or access.influence_source
    if (realization_source_id or None) != (access_source_id or None):
        return [
            NarrativeRealizationViolation(
                rule="realization_influence_source_mismatch",
                message=(
                    f"Narrative access_realization influence_source "
                    f"'{realization_source_id}' does not match actor "
                    f"access provenance '{access_source_id}'."
                ),
            )
        ]
    return []


def _source_kind_mismatch(
    realization: NarrativeAccessRealization, access: Any
) -> list[NarrativeRealizationViolation]:
    """Source-kind mismatch against actor provenance."""
    if (realization.influence_source_kind or None) != (
        access.influence_source_kind or None
    ):
        return [
            NarrativeRealizationViolation(
                rule="realization_influence_source_mismatch",
                message=(
                    "Narrative access_realization source kind does not match "
                    "actor access provenance."
                ),
            )
        ]
    return []


def _influence_source_violations(
    realization: NarrativeAccessRealization, access: Any
) -> list[NarrativeRealizationViolation]:
    """Source identity and kind mismatches."""
    return _source_id_mismatch(realization, access) + _source_kind_mismatch(
        realization, access
    )


def _trust_boundary_violation(
    realization: NarrativeAccessRealization, access: Any
) -> list[NarrativeRealizationViolation]:
    """trust_boundary_id mismatch."""
    if (realization.trust_boundary_id or None) != (access.trust_boundary_id or None):
        return [
            NarrativeRealizationViolation(
                rule="realization_trust_boundary_mismatch",
                message=(
                    f"Narrative access_realization trust_boundary_id "
                    f"'{realization.trust_boundary_id}' does not match actor "
                    f"access provenance '{access.trust_boundary_id}'."
                ),
            )
        ]
    return []


def _step_not_found_violation(
    realization: NarrativeAccessRealization, step_numbers: set[int]
) -> list[NarrativeRealizationViolation]:
    """responsible_step_number without a matching narrative step."""
    if realization.responsible_step_number not in step_numbers:
        return [
            NarrativeRealizationViolation(
                rule="realization_step_not_found",
                message=(
                    f"Narrative access_realization responsible_step_number "
                    f"{realization.responsible_step_number} does not refer "
                    f"to any narrative step (valid: {sorted(step_numbers)})."
                ),
            )
        ]
    return []


def _direct_access_violations(
    realization: NarrativeAccessRealization, access: Any
) -> list[NarrativeRealizationViolation]:
    """Direct ingress must omit indirect-only references."""
    if access.ingress_mode != "direct":
        return []
    violations: list[NarrativeRealizationViolation] = []
    if (
        realization.influence_source is not None
        or realization.influence_source_id is not None
    ):
        violations.append(
            NarrativeRealizationViolation(
                rule="direct_realization_has_indirect_ref",
                message=(
                    "Narrative access_realization has influence_source "
                    "but actor access provenance is direct ingress — "
                    "direct access must omit indirect-only references."
                ),
            )
        )
    if realization.trust_boundary_id is not None:
        violations.append(
            NarrativeRealizationViolation(
                rule="direct_realization_has_indirect_ref",
                message=(
                    "Narrative access_realization has trust_boundary_id "
                    "but actor access provenance is direct ingress — "
                    "direct access must omit indirect-only references."
                ),
            )
        )
    return violations


def validate_narrative_access_realization(
    narrative: NarrativeLayer,
    actor_profile: ActorProfile | None,
) -> list[NarrativeRealizationViolation]:
    """Validate that the narrative's access realization matches actor provenance.

    Pure function — no I/O, no keyword matching.  Compares the typed
    ``NarrativeAccessRealization`` on the narrative against the
    ``ActorAccessProvenance`` on the actor profile.  Returns a list of
    violations (empty if valid).
    """
    access = actor_profile.access if actor_profile else None
    if access is None:
        return []  # Actor access missing is flagged separately.

    realization = narrative.access_realization
    if realization is None:
        return [_missing_access_realization_violation()]

    violations: list[NarrativeRealizationViolation] = []
    violations.extend(_entry_point_mismatch_violation(realization, access))
    violations.extend(_influence_source_violations(realization, access))
    violations.extend(_trust_boundary_violation(realization, access))
    step_numbers = {s.step_number for s in narrative.steps}
    violations.extend(_step_not_found_violation(realization, step_numbers))
    violations.extend(_direct_access_violations(realization, access))
    return violations
