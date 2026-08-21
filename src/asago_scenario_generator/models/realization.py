"""Per-projected-step canonical realization record.

Shared by :mod:`asago_scenario_generator.models.scenario` (NarrativeStep,
BehaviorAction) and :mod:`asago_scenario_generator.models.attack_tree`
(AttackTreeNode) so that all three generated artifact boundaries carry
the same typed canonical semantics for validation to reconcile against
the embedded :class:`~asago_scenario_generator.models.projection_envelope.ProjectionEnvelopeBlock`.

Pre-alpha: all fields are required (no defaults).  A field may be an
empty tuple when the canonical step genuinely has no entries of that
kind, but the field must be present and explicitly provided.

This module is the **single source of truth** for canonical realization
derivation (:func:`extract_resource_id`, :func:`derive_step_realization`).
Generation, validation, and test helpers all import from here so that
there is no duplicate derivation path.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any

from pydantic import BaseModel, ConfigDict, Field

from asago_scenario_generator.models.attack_pattern import (
    AgentInternalResourceReference,
    EntryPointResourceReference,
    IntegrationResourceReference,
    OutputSurfaceResourceReference,
    ToolResourceReference,
    TrustBoundaryResourceReference,
)

if TYPE_CHECKING:
    from asago_scenario_generator.models.attack_pattern import CanonicalChainStep


_REALIZATION_ID_MAX_LENGTH = 200
_REALIZATION_KIND_MAX_LENGTH = 32
_REALIZATION_REFS_MAX_ITEMS = 16
_RealizationId = Annotated[
    str,
    Field(min_length=1, max_length=_REALIZATION_ID_MAX_LENGTH),
]


class ProjectedStepRealization(BaseModel):
    """Per-projected-step canonical realization record on generated elements.

    Carries the canonical step semantics that validation reconciles
    against the embedded projection block.  Prose may explain but cannot
    be the authority -- these typed fields are the authority.

    One record per ``projected_step_id``, supporting controlled
    many-to-many realization (a generated element may carry multiple
    records when it combines multiple projected steps; a projected step
    may be realized by multiple elements when it is split).
    """

    model_config = ConfigDict(extra="forbid")

    # Conservative static maxima so every generated realization field has a
    # finite schema bound regardless of the transport (LLM response_format
    # schemas include these nested records verbatim).
    projected_step_id: _RealizationId = Field(
        description="Canonical projected step ID this record realizes.",
    )
    action_kind: str = Field(
        min_length=1,
        max_length=_REALIZATION_KIND_MAX_LENGTH,
        description=(
            "Canonical action kind from the projected step (prepare, deliver, "
            "invoke, transform, persist, observe, impact)."
        ),
    )
    executor_role: str = Field(
        min_length=1,
        max_length=_REALIZATION_KIND_MAX_LENGTH,
        description="Canonical executor role from the projected step (attacker, system, operator).",
    )
    boundary_position: str = Field(
        min_length=1,
        max_length=_REALIZATION_KIND_MAX_LENGTH,
        description="Canonical boundary position from the projected step (outside, crossing, inside).",
    )
    resource_ref_ids: tuple[_RealizationId, ...] = Field(
        max_length=_REALIZATION_REFS_MAX_ITEMS,
        description="Concrete resource reference IDs for this step's resource_links.",
    )
    consumed_ref_ids: tuple[_RealizationId, ...] = Field(
        max_length=_REALIZATION_REFS_MAX_ITEMS,
        description="Consumed reference IDs (must match step.consumed[*].ref_id).",
    )
    produced_ref_ids: tuple[_RealizationId, ...] = Field(
        max_length=_REALIZATION_REFS_MAX_ITEMS,
        description="Produced reference IDs (must match step.produced[*].ref_id).",
    )
    produced_effect_ids: tuple[_RealizationId, ...] = Field(
        max_length=_REALIZATION_REFS_MAX_ITEMS,
        description="Produced effect IDs (subset of produced where kind == 'effect').",
    )
    outcome_link_pc_ids: tuple[_RealizationId, ...] = Field(
        max_length=_REALIZATION_REFS_MAX_ITEMS,
        description="Observable outcome link postcondition IDs.",
    )
    postcondition_ids: tuple[_RealizationId, ...] = Field(
        max_length=_REALIZATION_REFS_MAX_ITEMS,
        description="Owned observable postcondition IDs.",
    )


# ---------------------------------------------------------------------------#
# Canonical derivation — single source of truth
# ---------------------------------------------------------------------------#


def extract_resource_id(ref: Any) -> str:
    """Extract the typed opaque resource ID from a ``CanonicalResourceReference``.

    Exhaustively matches every discriminated subtype of the
    ``CanonicalResourceReference`` union.  Raises ``TypeError`` for
    unsupported types — never silently defaults.

    For ``AgentInternalResourceReference`` (which has no ID field),
    returns ``"agent_internal"``.
    """
    if isinstance(ref, EntryPointResourceReference):
        return ref.entry_point_id
    if isinstance(ref, ToolResourceReference):
        return ref.tool_id
    if isinstance(ref, IntegrationResourceReference):
        return ref.integration_id
    if isinstance(ref, TrustBoundaryResourceReference):
        return ref.trust_boundary_id
    if isinstance(ref, OutputSurfaceResourceReference):
        return ref.entry_point_id
    if isinstance(ref, AgentInternalResourceReference):
        return "agent_internal"
    raise TypeError(
        f"Unsupported resource reference type {type(ref).__name__}: "
        f"expected a CanonicalResourceReference subtype"
    )


def derive_step_realization(
    step: CanonicalChainStep,
    binding_by_slot: dict[str, Any],
) -> ProjectedStepRealization:
    """Build the canonical ``ProjectedStepRealization`` for *step*.

    This is the **single source of truth** for what a correct realization
    record looks like.  Generation, validation, and test helpers all use
    this function so that there is no duplicate derivation path.

    Uses :func:`extract_resource_id` for typed opaque resource-ID
    extraction.  Tuples preserve canonical order (step order), enabling
    direct ``==`` comparison without sorting.
    """
    resource_ref_ids = tuple(
        extract_resource_id(binding_by_slot[link.slot_id])
        for link in step.resource_links
        if link.slot_id in binding_by_slot
    )
    return ProjectedStepRealization(
        projected_step_id=step.step_id,
        action_kind=step.action_kind,
        executor_role=step.executor_role,
        boundary_position=step.boundary_position,
        resource_ref_ids=resource_ref_ids,
        consumed_ref_ids=tuple(c.ref_id for c in step.consumed),
        produced_ref_ids=tuple(p.ref_id for p in step.produced),
        produced_effect_ids=tuple(
            p.ref_id for p in step.produced if p.kind == "effect"
        ),
        outcome_link_pc_ids=tuple(
            ol.postcondition_id for ol in step.observable_outcome_links
        ),
        postcondition_ids=tuple(
            pc.postcondition_id for pc in step.observable_postconditions
        ),
    )
