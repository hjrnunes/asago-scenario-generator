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

from collections.abc import Sequence
from typing import TYPE_CHECKING, Annotated, Any

from pydantic import BaseModel, ConfigDict, Field

from asago_scenario_generator.models.attack_pattern_projection import (
    AgentInternalResourceReference,
    EntryPointResourceReference,
    IntegrationResourceReference,
    OutputSurfaceResourceReference,
    ToolResourceReference,
    TrustBoundaryResourceReference,
)

if TYPE_CHECKING:
    from asago_scenario_generator.models.attack_pattern_chain import CanonicalChainStep


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

# Opaque resource-ID field per CanonicalResourceReference subtype, in
# exhaustive match order.  ``AgentInternalResourceReference`` has no ID
# field; the value ``None`` marks its fixed literal return.
_RESOURCE_ID_FIELDS: tuple[tuple[type[Any], str | None], ...] = (
    (EntryPointResourceReference, "entry_point_id"),
    (ToolResourceReference, "tool_id"),
    (IntegrationResourceReference, "integration_id"),
    (TrustBoundaryResourceReference, "trust_boundary_id"),
    (OutputSurfaceResourceReference, "entry_point_id"),
    (AgentInternalResourceReference, None),
)


def extract_resource_id(ref: Any) -> str:
    """Extract the typed opaque resource ID from a ``CanonicalResourceReference``.

    Exhaustively matches every discriminated subtype of the
    ``CanonicalResourceReference`` union.  Raises ``TypeError`` for
    unsupported types — never silently defaults.

    For ``AgentInternalResourceReference`` (which has no ID field),
    returns ``"agent_internal"``.
    """
    for ref_type, field in _RESOURCE_ID_FIELDS:
        if isinstance(ref, ref_type):
            return "agent_internal" if field is None else getattr(ref, field)
    raise TypeError(
        f"Unsupported resource reference type {type(ref).__name__}: "
        f"expected a CanonicalResourceReference subtype"
    )


def _resource_ref_ids(
    step: CanonicalChainStep,
    binding_by_slot: dict[str, Any],
) -> tuple[str, ...]:
    """Opaque resource IDs for the step's resource links, in link order.

    Only links whose slot has a concrete binding contribute; the fallback
    realization records used by isolated model tests have no bindings.
    """
    return tuple(
        extract_resource_id(binding_by_slot[link.slot_id])
        for link in step.resource_links
        if link.slot_id in binding_by_slot
    )


def _consumed_ref_ids(step: CanonicalChainStep) -> tuple[str, ...]:
    """Consumed reference IDs, in canonical step order."""
    return tuple(c.ref_id for c in step.consumed)


def _produced_ref_ids(step: CanonicalChainStep) -> tuple[str, ...]:
    """Produced reference IDs, in canonical step order."""
    return tuple(p.ref_id for p in step.produced)


def _produced_effect_ids(step: CanonicalChainStep) -> tuple[str, ...]:
    """Produced effect IDs — the subset of produced refs with kind 'effect'."""
    return tuple(p.ref_id for p in step.produced if p.kind == "effect")


def _outcome_link_pc_ids(step: CanonicalChainStep) -> tuple[str, ...]:
    """Observable outcome-link postcondition IDs, in step order."""
    return tuple(ol.postcondition_id for ol in step.observable_outcome_links)


def _postcondition_ids(step: CanonicalChainStep) -> tuple[str, ...]:
    """Owned observable postcondition IDs, in step order."""
    return tuple(pc.postcondition_id for pc in step.observable_postconditions)


def _realization_cover_error(
    realizations: Sequence[Any],
    projected_step_ids: Sequence[str],
    subject: str,
) -> str | None:
    """Error message when realization records do not cover projected step IDs.

    Returns ``None`` when every projected step ID has exactly one
    realization record (including the both-empty case).  ``subject`` names
    the owning element in the message (e.g. ``"narrative step 2"`` or
    ``"LEAF node 'n1.1'"``).
    """
    real_ids = [r.projected_step_id for r in realizations]
    projected_ids = set(projected_step_ids)
    if len(set(real_ids)) != len(real_ids):
        return (
            f"{subject} has duplicate realization records (same "
            f"projected_step_id appears more than once)"
        )
    if len(real_ids) != len(projected_ids):
        return (
            f"{subject} has {len(real_ids)} realization records but "
            f"{len(projected_ids)} projected_step_ids — exactly one "
            f"record per projected_step_id is required"
        )
    if set(real_ids) != projected_ids:
        return (
            f"{subject} realization IDs {set(real_ids)} do not match "
            f"projected_step_ids {projected_ids}"
        )
    return None


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
    return ProjectedStepRealization(
        projected_step_id=step.step_id,
        action_kind=step.action_kind,
        executor_role=step.executor_role,
        boundary_position=step.boundary_position,
        resource_ref_ids=_resource_ref_ids(step, binding_by_slot),
        consumed_ref_ids=_consumed_ref_ids(step),
        produced_ref_ids=_produced_ref_ids(step),
        produced_effect_ids=_produced_effect_ids(step),
        outcome_link_pc_ids=_outcome_link_pc_ids(step),
        postcondition_ids=_postcondition_ids(step),
    )


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-26T15:47:53Z","module_hash":"e2d8b0d12d682275ed1ea739de2e0025679d31512c55ee74539176dba53693da","source_sha256":"a25925856b2312211568f6a0514e161b8c6f8eb13ce9f2ca1d766992fefb2cf5","functions":[{"id":"func/extract_resource_id","name":"extract_resource_id","line":130,"end_line":146,"hash":"79cef2bb4d2e18da4d723b6bbd2a809c8033c0cc495e14d9cd253b26d59343d7"},{"id":"func/_resource_ref_ids","name":"_resource_ref_ids","line":149,"end_line":162,"hash":"653758b15bd6b06a768b2f8fba8e7e7c8ceb00e389803bfef1d8a1eef96af6c0"},{"id":"func/_consumed_ref_ids","name":"_consumed_ref_ids","line":165,"end_line":167,"hash":"d162c74ca6df197018efb5a91c66a64b8ed3272a92c83f697350f9aa0933b7aa"},{"id":"func/_produced_ref_ids","name":"_produced_ref_ids","line":170,"end_line":172,"hash":"bff203fac91ade483574b6dbc7b7c9501a7e06e006e6ce448544b232fcac63e9"},{"id":"func/_produced_effect_ids","name":"_produced_effect_ids","line":175,"end_line":177,"hash":"1aad79a2beae9196cdbec0e2dce76c92515c73b3f919e594c91c5e8d3d042af0"},{"id":"func/_outcome_link_pc_ids","name":"_outcome_link_pc_ids","line":180,"end_line":182,"hash":"5d7a013bebb65138a3720898049fc19a02fb3dc78bb8e1f88b4d41506df027f7"},{"id":"func/_postcondition_ids","name":"_postcondition_ids","line":185,"end_line":187,"hash":"fca345acf41c1396c19f9c1e30dff141c5cbfb94e70b40132a0b1643fcb88a21"},{"id":"func/_realization_cover_error","name":"_realization_cover_error","line":190,"end_line":220,"hash":"3cb129fb3317ab349230e67f0688496dc2bad4b2341839f5bad853c5cc598229"},{"id":"func/derive_step_realization","name":"derive_step_realization","line":223,"end_line":248,"hash":"d4fcb234c3f321cd0e8a0159d8ca57ea8bd36393ad4b7f390f7362c8329daca2"}]}
# mutate4py-manifest-end
