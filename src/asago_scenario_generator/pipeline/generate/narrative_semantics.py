"""Semantic narrative draft contracts and validation.

The provider authors causal meaning over request-local handles.  This module
keeps that semantic contract separate from legacy response mapping, prompt
assembly, and access-provenance adapters.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, create_model

from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.models.realization import ProjectedStepRealization
from asago_scenario_generator.models.scenario import (
    ActorProfile,
    NarrativeAccessRealization,
    NarrativeLayer,
    NarrativeStep,
)
from asago_scenario_generator.pipeline.generate.canonical_projection import (
    derive_canonical_projection_semantics,
)
from asago_scenario_generator.pipeline.generate.narrative_access import (
    MAX_NARRATIVE_STEPS,
)
from asago_scenario_generator.pipeline.seeds import ScenarioSeed

_CALL1_TITLE_MAX_LENGTH = 200
_CALL1_PROSE_MAX_LENGTH = 2000
_NARRATIVE_DRAFT_TRANSITION_MAX_LENGTH = 500

_NarrativeDraftProse = Annotated[
    str, Field(min_length=1, max_length=_CALL1_PROSE_MAX_LENGTH)
]


class NarrativeCausalBeatV2(BaseModel):
    """One provider-authored causal beat over request-local step handles."""

    model_config = ConfigDict(extra="forbid")

    step_handles: list[Annotated[str, Field(min_length=1, max_length=32)]] = Field(
        min_length=1, max_length=MAX_NARRATIVE_STEPS
    )
    action: _NarrativeDraftProse
    consequence: _NarrativeDraftProse
    transition: str | None = Field(
        default=None,
        min_length=1,
        max_length=_NARRATIVE_DRAFT_TRANSITION_MAX_LENGTH,
    )


class NarrativeDraftV2(BaseModel):
    """Provider-authored narrative meaning without canonical transport data."""

    model_config = ConfigDict(extra="forbid")

    title: str | None = Field(
        default=None, min_length=1, max_length=_CALL1_TITLE_MAX_LENGTH
    )
    summary: _NarrativeDraftProse
    beats: list[NarrativeCausalBeatV2] = Field(
        min_length=1, max_length=MAX_NARRATIVE_STEPS
    )


class NarrativeDraftV3(BaseModel):
    """Provider-authored narrative partitioned by canonical regions."""

    model_config = ConfigDict(extra="forbid")

    title: str | None = Field(
        default=None, min_length=1, max_length=_CALL1_TITLE_MAX_LENGTH
    )
    summary: _NarrativeDraftProse
    regions: dict[str, list[NarrativeCausalBeatV2]]


@dataclass(frozen=True)
class NarrativeProjectedStep:
    """Canonical projection data hidden behind one local narrative handle."""

    projected_step_id: str
    order: int
    zone: str
    realization: ProjectedStepRealization
    region: str = "r0"

    def __post_init__(self) -> None:
        if self.realization.projected_step_id != self.projected_step_id:
            raise ValueError(
                "narrative projected-step realization must match its canonical ID"
            )


def _unique_step_handles(ordered_step_handles: Sequence[str]) -> None:
    """Raise unless the ordered handles are non-empty and unique."""
    if not ordered_step_handles:
        raise ValueError("narrative context requires at least one projected step")
    if len(set(ordered_step_handles)) != len(ordered_step_handles):
        raise ValueError("narrative context has duplicate projected-step handles")


def _matching_projected_inventory(
    ordered_step_handles: Sequence[str],
    projected_steps: dict[str, NarrativeProjectedStep],
) -> None:
    """Raise unless ordered handles exactly match the projected inventory."""
    if set(ordered_step_handles) != set(projected_steps):
        raise ValueError(
            "ordered narrative handles must exactly match projected-step inventory"
        )


def _unique_canonical_ids(
    ordered_step_handles: Sequence[str],
    projected_steps: dict[str, NarrativeProjectedStep],
) -> None:
    """Raise when two handles resolve to the same canonical step ID."""
    canonical_ids = [
        projected_steps[handle].projected_step_id for handle in ordered_step_handles
    ]
    if len(set(canonical_ids)) != len(canonical_ids):
        raise ValueError("narrative context has duplicate canonical step IDs")


def _append_region_if_new(region: str, seen_regions: list[str]) -> None:
    """Record a region in first-occurrence order, rejecting revisit."""
    if not seen_regions or seen_regions[-1] != region:
        if region in seen_regions:
            raise ValueError("narrative compatibility regions must be contiguous")
        seen_regions.append(region)


def _contiguous_regions(
    ordered_step_handles: Sequence[str],
    projected_steps: dict[str, NarrativeProjectedStep],
) -> None:
    """Raise unless each region forms one contiguous handle run."""
    seen_regions: list[str] = []
    for handle in ordered_step_handles:
        _append_region_if_new(projected_steps[handle].region, seen_regions)


@dataclass(frozen=True)
class NarrativeDraftContext:
    """Canonical inventory used to compile one narrative semantic draft."""

    title_fallback: str
    entry_point: str
    ordered_step_handles: tuple[str, ...]
    projected_steps: dict[str, NarrativeProjectedStep]
    access_realization: NarrativeAccessRealization | None = None
    presentation_fallback_allowed: bool = True

    def __post_init__(self) -> None:
        _unique_step_handles(self.ordered_step_handles)
        _matching_projected_inventory(self.ordered_step_handles, self.projected_steps)
        _unique_canonical_ids(self.ordered_step_handles, self.projected_steps)
        _contiguous_regions(self.ordered_step_handles, self.projected_steps)

    @property
    def ordered_region_handles(self) -> tuple[str, ...]:
        """Return canonical region handles in first-occurrence order."""

        return tuple(
            dict.fromkeys(
                self.projected_steps[handle].region
                for handle in self.ordered_step_handles
            )
        )

    def handles_for_region(self, region: str) -> tuple[str, ...]:
        """Return the ordered step inventory owned by one region."""

        return tuple(
            handle
            for handle in self.ordered_step_handles
            if self.projected_steps[handle].region == region
        )


@dataclass(frozen=True)
class NarrativeDraftViolation:
    """Machine-readable narrative violation for a correction request."""

    code: str
    detail: str


class NarrativeSemanticDraftError(ValueError):
    """A narrative draft cannot compile without semantic repair."""

    def __init__(self, violations: Sequence[NarrativeDraftViolation]) -> None:
        self.violations = tuple(violations)
        super().__init__("; ".join(item.detail for item in self.violations))


def _narrative_handle_literal(handles: Sequence[str]) -> Any:
    values = tuple(handles)
    if not values or len(set(values)) != len(values):
        raise ValueError("narrative handle inventory must be non-empty and unique")
    return Literal.__getitem__(values)


def create_narrative_draft_model(
    step_handles: Sequence[str],
) -> type[NarrativeDraftV2]:
    """Build a finite provider schema for one candidate's narrative draft."""
    values = tuple(step_handles)
    handle_type = _narrative_handle_literal(values)
    beat_model = create_model(
        "NarrativeCausalBeatV2ForCandidate",
        __base__=NarrativeCausalBeatV2,
        step_handles=(
            list[handle_type],
            Field(min_length=1, max_length=len(values)),
        ),
    )
    return create_model(
        "NarrativeDraftV2ForCandidate",
        __base__=NarrativeDraftV2,
        beats=(
            list[beat_model],
            Field(min_length=1, max_length=len(values)),
        ),
    )


def create_narrative_draft_v3_model(
    context: NarrativeDraftContext,
) -> type[NarrativeDraftV3]:
    """Build an exact-key region schema with finite per-region handles."""

    region_fields: dict[str, Any] = {}
    for region in context.ordered_region_handles:
        handles = context.handles_for_region(region)
        handle_type = _narrative_handle_literal(handles)
        beat_model = create_model(
            f"NarrativeCausalBeatV3For{region}",
            __base__=NarrativeCausalBeatV2,
            step_handles=(
                list[handle_type],
                Field(min_length=1, max_length=len(handles)),
            ),
        )
        region_fields[region] = (
            list[beat_model],
            Field(min_length=1, max_length=len(handles)),
        )
    regions_model = create_model(
        "NarrativeRegionsV3ForCandidate",
        __config__=ConfigDict(extra="forbid"),
        **region_fields,
    )
    return create_model(
        "NarrativeDraftV3ForCandidate",
        __base__=NarrativeDraftV3,
        regions=(regions_model, ...),
    )


def _draft_region_mapping(
    draft: NarrativeDraftV3,
) -> dict[str, list[NarrativeCausalBeatV2]]:
    regions = draft.regions
    if isinstance(regions, BaseModel):
        return {
            key: list(value)
            for key, value in regions.__dict__.items()
            if isinstance(value, list)
        }
    return dict(regions)


def _region_set_violations(
    actual: set[str], expected: set[str]
) -> list[NarrativeDraftViolation]:
    """Unknown/missing region handle violations."""
    violations: list[NarrativeDraftViolation] = []
    if unknown := sorted(actual - expected):
        violations.append(
            NarrativeDraftViolation(
                "unknown_region_handle", f"unknown narrative region(s): {unknown}"
            )
        )
    if missing := sorted(expected - actual):
        violations.append(
            NarrativeDraftViolation(
                "missing_region_handle", f"missing narrative region(s): {missing}"
            )
        )
    return violations


def _cross_region_handles(
    region_beats: list[NarrativeCausalBeatV2], allowed: set[str]
) -> list[str]:
    """Handles used inside one region that belong to another region."""
    return sorted(
        {
            handle
            for beat in region_beats
            for handle in beat.step_handles
            if handle not in allowed
        }
    )


def _cross_region_step_violations(
    regions: dict[str, list[NarrativeCausalBeatV2]],
    context: NarrativeDraftContext,
) -> list[NarrativeDraftViolation]:
    """Beats referencing handles owned by another region."""
    violations: list[NarrativeDraftViolation] = []
    for region in context.ordered_region_handles:
        allowed = set(context.handles_for_region(region))
        invalid = _cross_region_handles(regions.get(region, []), allowed)
        if invalid:
            violations.append(
                NarrativeDraftViolation(
                    "cross_region_step_handle",
                    f"region '{region}' contains step handle(s) owned by another "
                    f"region: {invalid}",
                )
            )
    return violations


def _ordered_draft_beats(
    context: NarrativeDraftContext, draft: NarrativeDraftV2 | NarrativeDraftV3
) -> tuple[list[NarrativeCausalBeatV2], list[NarrativeDraftViolation]]:
    if isinstance(draft, NarrativeDraftV2):
        return list(draft.beats), []

    regions = _draft_region_mapping(draft)
    expected = set(context.ordered_region_handles)
    violations = _region_set_violations(set(regions), expected)
    violations.extend(_cross_region_step_violations(regions, context))
    beats: list[NarrativeCausalBeatV2] = []
    for region in context.ordered_region_handles:
        beats.extend(regions.get(region, []))
    return beats, violations


def _step_handle_coverage_violations(
    flattened: list[str], expected: set[str]
) -> list[NarrativeDraftViolation]:
    """Unknown, missing, and duplicated step handle violations."""
    violations: list[NarrativeDraftViolation] = []
    unknown = sorted(set(flattened) - expected)
    missing = sorted(expected - set(flattened))
    duplicate = sorted(
        handle for handle in set(flattened) if flattened.count(handle) > 1
    )
    if unknown:
        violations.append(
            NarrativeDraftViolation(
                "unknown_step_handle", f"unknown projected-step handle(s): {unknown}"
            )
        )
    if missing:
        violations.append(
            NarrativeDraftViolation(
                "missing_step_handle", f"missing projected-step handle(s): {missing}"
            )
        )
    if duplicate:
        violations.append(
            NarrativeDraftViolation(
                "duplicate_step_handle",
                f"duplicate projected-step handle(s): {duplicate}",
            )
        )
    return violations


def _step_order_violations(
    known_handles: list[str], positions: dict[str, int]
) -> list[NarrativeDraftViolation]:
    """Canonical partial-order violations among known handles."""
    if any(
        positions[current] >= positions[following]
        for current, following in zip(known_handles, known_handles[1:])
        if current != following
    ):
        return [
            NarrativeDraftViolation(
                "illegal_step_order",
                "projected-step handles violate the canonical partial order",
            )
        ]
    return []


def _beat_zone_violations(
    beats: list[NarrativeCausalBeatV2], context: NarrativeDraftContext
) -> list[NarrativeDraftViolation]:
    """Beats that combine incompatible canonical zones."""
    violations: list[NarrativeDraftViolation] = []
    for index, beat in enumerate(beats, start=1):
        zones = {
            context.projected_steps[handle].zone
            for handle in beat.step_handles
            if handle in context.projected_steps
        }
        if len(zones) > 1:
            violations.append(
                NarrativeDraftViolation(
                    "mixed_step_zones",
                    f"causal beat {index} combines incompatible canonical zones: "
                    f"{sorted(zones)}",
                )
            )
    return violations


def _beat_boundary_violations(
    beats: list[NarrativeCausalBeatV2], context: NarrativeDraftContext
) -> list[NarrativeDraftViolation]:
    """Beats that combine incompatible boundary positions."""
    violations: list[NarrativeDraftViolation] = []
    for index, beat in enumerate(beats, start=1):
        boundaries = {
            context.projected_steps[handle].realization.boundary_position
            for handle in beat.step_handles
            if handle in context.projected_steps
        }
        if len(boundaries) > 1:
            violations.append(
                NarrativeDraftViolation(
                    "mixed_boundary_positions",
                    f"causal beat {index} combines incompatible canonical "
                    f"boundary positions: {sorted(boundaries)}",
                )
            )
    return violations


def _missing_title_violation(
    context: NarrativeDraftContext, draft: NarrativeDraftV2 | NarrativeDraftV3
) -> list[NarrativeDraftViolation]:
    """Title-required-when-fallback-forbidden violation."""
    if draft.title is None and not context.presentation_fallback_allowed:
        return [
            NarrativeDraftViolation(
                "missing_title",
                "narrative title is required when fallback is forbidden",
            )
        ]
    return []


def _validate_narrative_draft(
    context: NarrativeDraftContext, draft: NarrativeDraftV2 | NarrativeDraftV3
) -> list[NarrativeDraftViolation]:
    beats, violations = _ordered_draft_beats(context, draft)
    flattened = [handle for beat in beats for handle in beat.step_handles]
    expected = set(context.ordered_step_handles)
    violations.extend(_step_handle_coverage_violations(flattened, expected))

    known_handles = [handle for handle in flattened if handle in expected]
    positions = {
        handle: index for index, handle in enumerate(context.ordered_step_handles)
    }
    violations.extend(_step_order_violations(known_handles, positions))
    violations.extend(_beat_zone_violations(beats, context))
    violations.extend(_beat_boundary_violations(beats, context))
    violations.extend(_missing_title_violation(context, draft))
    return violations


def _narrative_step_from_beat(
    context: NarrativeDraftContext, beat: NarrativeCausalBeatV2, number: int
) -> NarrativeStep:
    """One canonical narrative step compiled from a causal beat."""
    projected = [context.projected_steps[handle] for handle in beat.step_handles]
    effect = beat.consequence
    if beat.transition:
        effect = f"{effect} {beat.transition}"
    return NarrativeStep(
        step_number=number,
        zone=projected[0].zone,
        action=beat.action,
        effect=effect,
        projected_step_ids=tuple(item.projected_step_id for item in projected),
        realizations=tuple(item.realization for item in projected),
    )


def _derive_zone_sequence(steps: Sequence[Any]) -> list[str]:
    """Derive a traversal sequence while collapsing adjacent duplicate zones."""
    sequence: list[str] = []
    for step in steps:
        if not sequence or sequence[-1] != step.zone:
            sequence.append(step.zone)
    return sequence


def compile_narrative_draft(
    context: NarrativeDraftContext, draft: NarrativeDraftV2 | NarrativeDraftV3
) -> NarrativeLayer:
    """Attach projection truth while preserving provider-authored causality."""
    violations = _validate_narrative_draft(context, draft)
    if violations:
        raise NarrativeSemanticDraftError(violations)

    beats, _ = _ordered_draft_beats(context, draft)
    steps = [
        _narrative_step_from_beat(context, beat, number)
        for number, beat in enumerate(beats, start=1)
    ]
    return NarrativeLayer(
        title=draft.title or context.title_fallback,
        summary=draft.summary,
        entry_point=context.entry_point,
        zone_sequence=_derive_zone_sequence(steps),
        steps=steps,
        access_realization=(
            context.access_realization.model_copy(deep=True)
            if context.access_realization is not None
            else None
        ),
    )


def _narrative_projected_steps(
    handles: tuple[str, ...], semantics: Any
) -> dict[str, NarrativeProjectedStep]:
    """Allocate one projected-step record per handle from semantics."""
    projected_steps: dict[str, NarrativeProjectedStep] = {}
    for handle, semantic in zip(handles, semantics.steps):
        projected_steps[handle] = NarrativeProjectedStep(
            projected_step_id=semantic.projected_step_id,
            order=semantic.order,
            zone=semantic.zone,
            realization=semantic.realization,
            region=semantic.narrative_region,
        )
    return projected_steps


def _resolved_entry_point(
    pinned_entry_point: str | None, ingress_id: Any, profile: CapabilityProfile
) -> str:
    """Displayable entry point: pin wins, else resolved ingress name."""
    entry_point = pinned_entry_point
    if not entry_point and isinstance(ingress_id, str):
        resolved = profile.resolve_entry_point(ingress_id)
        entry_point = resolved.name if resolved is not None else ingress_id
    return entry_point


def _narrative_access_realization(
    actor_profile: ActorProfile | None,
) -> NarrativeAccessRealization | None:
    """Typed access realization mirrored from actor provenance, or None."""
    if actor_profile is None or actor_profile.access is None:
        return None
    access = actor_profile.access
    return NarrativeAccessRealization(
        initial_entry_point_id=access.initial_entry_point_id,
        influence_source=access.influence_source,
        influence_source_kind=access.influence_source_kind,
        influence_source_id=access.influence_source_id,
        trust_boundary_id=access.trust_boundary_id,
        responsible_step_number=1,
    )


def _build_narrative_draft_context(
    *,
    seed: ScenarioSeed,
    profile: CapabilityProfile,
    actor_profile: ActorProfile | None,
    pinned_entry_point: str | None,
    projection_context: dict[str, Any],
    presentation_fallback_allowed: bool = True,
) -> NarrativeDraftContext:
    """Allocate handles and canonical compilation data for one narrative."""
    selected_ids = tuple(projection_context.get("selected_step_ids", ()))
    if not selected_ids:
        raise ValueError("projection has no selected steps for narrative generation")
    semantics = derive_canonical_projection_semantics(projection_context, profile)
    handles = tuple(f"s{index}" for index in range(len(selected_ids)))
    projected_steps = _narrative_projected_steps(handles, semantics)

    ingress_id = projection_context.get("canonical_ingress", {}).get("entry_point_id")
    entry_point = _resolved_entry_point(pinned_entry_point, ingress_id, profile)
    if not entry_point:
        raise ValueError("projection lacks a displayable canonical entry point")

    return NarrativeDraftContext(
        title_fallback=seed.attack_pattern_name,
        entry_point=entry_point,
        ordered_step_handles=handles,
        projected_steps=projected_steps,
        access_realization=_narrative_access_realization(actor_profile),
        presentation_fallback_allowed=presentation_fallback_allowed,
    )


def _narrative_draft_prompt(context: NarrativeDraftContext) -> str:
    """Render the request-local region and step inventory for V3."""
    lines = [
        "\n\n## Semantic Draft V3 Response Protocol (MANDATORY)",
        "Author title, summary, causal grouping, actions, consequences, and transitions.",
        "Return every required region key. Inside each region, reference every "
        "step handle exactly once and preserve the listed order.",
        "Never move a step handle to another region or combine steps across regions.",
        "The application owns entry point, zones, IDs, realizations, and access provenance.",
        "Do not return canonical IDs, zones, zone_sequence, or access_realization.",
        "Compatibility regions and projected-step handles:",
    ]
    for region in context.ordered_region_handles:
        lines.append(f"- {region}:")
        for handle in context.handles_for_region(region):
            step = context.projected_steps[handle]
            lines.append(
                f"  - {handle}: order={step.order}; zone={step.zone}; "
                f"action_kind={step.realization.action_kind}; "
                f"boundary={step.realization.boundary_position}"
            )
    return "\n".join(lines)
