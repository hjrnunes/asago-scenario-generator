"""Pure narrative access-realization and step-bound checks.

These validators are the inward leaf for Call-1 output-shape and cmps.6
realization policy. Generation, finalization, and semantic validation
depend on this module instead of the IO-near ``generate.narrative`` façade.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from asago_scenario_generator.models.scenario import (
    ActorAccessProvenance,
    ActorProfile,
    NarrativeAccessRealization,
    NarrativeLayer,
)

# Conservative finite static maxima for the structured Call 1 schema.
# Finalization gates apply the same bound dynamically to selected_step_count + 2.
MAX_NARRATIVE_STEPS = 16
NARRATIVE_CONNECTOR_STEPS = 2


def validate_narrative_step_bounds(
    narrative: NarrativeLayer,
    selected_step_ids: Sequence[str],
) -> list[tuple[str, str]]:
    """Validate the Call 1 output shape against the projection selection.

    Returns ``(code, detail)`` pairs:

    - ``narrative_step_coverage``: every selected canonical step ID must be
      realized by at least one narrative step.
    - ``narrative_step_bound``: the narrative contains no more than
      ``min(MAX_NARRATIVE_STEPS, selected_step_count + NARRATIVE_CONNECTOR_STEPS)``
      steps — at most two connector steps beyond the selected steps and never
      more than 16.

    Pure function: finalization gates translate the codes into Lifecycle
    violations owned by the narrative stage.
    """
    violations: list[tuple[str, str]] = []
    selected = set(selected_step_ids)
    covered = {sid for step in narrative.steps for sid in step.projected_step_ids}
    missing = sorted(selected - covered)
    if missing:
        violations.append(
            (
                "narrative_step_coverage",
                f"narrative does not realize selected canonical steps: {missing}",
            )
        )
    maximum = min(MAX_NARRATIVE_STEPS, len(selected) + NARRATIVE_CONNECTOR_STEPS)
    if len(narrative.steps) > maximum:
        violations.append(
            (
                "narrative_step_bound",
                f"narrative has {len(narrative.steps)} steps; the bound for "
                f"{len(selected)} selected steps is {maximum}",
            )
        )
    return violations


@dataclass
class NarrativeRealizationViolation:
    """A narrative access-realization mismatch (cmps.6)."""

    rule: str
    message: str


def _source_identity(
    typed_id: str | None,
    legacy_name: str | None,
) -> str | None:
    """Prefer the canonical typed identity over the legacy display field."""
    return typed_id if typed_id is not None else legacy_name


def _entry_point_violation(
    realization: NarrativeAccessRealization,
    access: ActorAccessProvenance,
) -> NarrativeRealizationViolation | None:
    if realization.initial_entry_point_id == access.initial_entry_point_id:
        return None
    return NarrativeRealizationViolation(
        rule="realization_entry_point_mismatch",
        message=(
            "Narrative access_realization initial_entry_point_id "
            f"'{realization.initial_entry_point_id}' does not match "
            f"actor access provenance '{access.initial_entry_point_id}'."
        ),
    )


def _source_id_violation(
    realization: NarrativeAccessRealization,
    access: ActorAccessProvenance,
) -> NarrativeRealizationViolation | None:
    realization_source_id = _source_identity(
        realization.influence_source_id,
        realization.influence_source,
    )
    access_source_id = _source_identity(
        access.influence_source_id,
        access.influence_source,
    )
    if realization_source_id == access_source_id:
        return None
    return NarrativeRealizationViolation(
        rule="realization_influence_source_mismatch",
        message=(
            f"Narrative access_realization influence_source "
            f"'{realization_source_id}' does not match actor "
            f"access provenance '{access_source_id}'."
        ),
    )


def _source_kind_violation(
    realization: NarrativeAccessRealization,
    access: ActorAccessProvenance,
) -> NarrativeRealizationViolation | None:
    if realization.influence_source_kind == access.influence_source_kind:
        return None
    return NarrativeRealizationViolation(
        rule="realization_influence_source_mismatch",
        message=(
            "Narrative access_realization source kind does not match "
            "actor access provenance."
        ),
    )


def _trust_boundary_violation(
    realization: NarrativeAccessRealization,
    access: ActorAccessProvenance,
) -> NarrativeRealizationViolation | None:
    if realization.trust_boundary_id == access.trust_boundary_id:
        return None
    return NarrativeRealizationViolation(
        rule="realization_trust_boundary_mismatch",
        message=(
            f"Narrative access_realization trust_boundary_id "
            f"'{realization.trust_boundary_id}' does not match actor "
            f"access provenance '{access.trust_boundary_id}'."
        ),
    )


def _responsible_step_violation(
    narrative: NarrativeLayer,
    realization: NarrativeAccessRealization,
) -> NarrativeRealizationViolation | None:
    step_numbers = {step.step_number for step in narrative.steps}
    if realization.responsible_step_number in step_numbers:
        return None
    return NarrativeRealizationViolation(
        rule="realization_step_not_found",
        message=(
            f"Narrative access_realization responsible_step_number "
            f"{realization.responsible_step_number} does not refer "
            f"to any narrative step (valid: {sorted(step_numbers)})."
        ),
    )


def _direct_source_violation(
    realization: NarrativeAccessRealization,
    access: ActorAccessProvenance,
) -> NarrativeRealizationViolation | None:
    if access.ingress_mode != "direct" or (
        realization.influence_source is None and realization.influence_source_id is None
    ):
        return None
    return NarrativeRealizationViolation(
        rule="direct_realization_has_indirect_ref",
        message=(
            "Narrative access_realization has influence_source "
            "but actor access provenance is direct ingress — "
            "direct access must omit indirect-only references."
        ),
    )


def _direct_boundary_violation(
    realization: NarrativeAccessRealization,
    access: ActorAccessProvenance,
) -> NarrativeRealizationViolation | None:
    if access.ingress_mode != "direct" or realization.trust_boundary_id is None:
        return None
    return NarrativeRealizationViolation(
        rule="direct_realization_has_indirect_ref",
        message=(
            "Narrative access_realization has trust_boundary_id "
            "but actor access provenance is direct ingress — "
            "direct access must omit indirect-only references."
        ),
    )


def _realization_violations(
    narrative: NarrativeLayer,
    realization: NarrativeAccessRealization,
    access: ActorAccessProvenance,
) -> list[NarrativeRealizationViolation]:
    """Collect independent identity and access checks in stable order."""
    identity_checks = (
        _entry_point_violation(realization, access),
        _source_id_violation(realization, access),
        _source_kind_violation(realization, access),
        _trust_boundary_violation(realization, access),
        _responsible_step_violation(narrative, realization),
        _direct_source_violation(realization, access),
        _direct_boundary_violation(realization, access),
    )
    return [violation for violation in identity_checks if violation is not None]


def validate_narrative_access_realization(
    narrative: NarrativeLayer,
    actor_profile: ActorProfile | None,
) -> list[NarrativeRealizationViolation]:
    """Validate that the narrative's access realization matches actor provenance.

    Pure function — no I/O, no keyword matching.  Compares the typed
    ``NarrativeAccessRealization`` on the narrative against the
    ``ActorAccessProvenance`` on the actor profile.  Returns a list of
    violations (empty if valid).

    Checks:
    1. If actor access provenance exists, the narrative must carry an
       access_realization.
    2. ``initial_entry_point_id`` must match.
    3. ``influence_source`` must match (or both be None).
    4. ``trust_boundary_id`` must match (or both be None).
    5. ``responsible_step_number`` must refer to an existing narrative step.
    6. Direct access must omit indirect-only references (influence_source,
       trust_boundary_id must be None when ingress_mode is direct).
    """
    violations: list[NarrativeRealizationViolation] = []

    access = actor_profile.access if actor_profile else None
    if access is None:
        return violations  # Actor access missing is flagged separately.

    realization = narrative.access_realization
    if realization is None:
        violations.append(
            NarrativeRealizationViolation(
                rule="missing_access_realization",
                message=(
                    "Narrative lacks typed access_realization — required "
                    "when actor access provenance is present (cmps.6)."
                ),
            )
        )
        return violations

    return violations + _realization_violations(narrative, realization, access)
