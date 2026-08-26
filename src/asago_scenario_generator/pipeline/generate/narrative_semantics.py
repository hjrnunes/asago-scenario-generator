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


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-26T11:26:41Z","module_hash":"4d3665d70808e8bc890e79e42c02c7e6d4d65f92ff25cb83d36b6b0766ab1aa0","source_sha256":"d33395d6969e766269f5fc855bee99907abd42c19d82978c3d27a5a37c6ce7ef","functions":[{"id":"func/NarrativeProjectedStep.__post_init__","name":"__post_init__","line":94,"end_line":98,"hash":"bdeeb3448e7ae9d8f8c06ebfa5544c692aa2dd606878e6380852cd9de5d13cfa"},{"id":"func/_unique_step_handles","name":"_unique_step_handles","line":101,"end_line":106,"hash":"6c965bcd495e3b158031ff3201d973626d1638ce1280659c99093b7f02543d3b"},{"id":"func/_matching_projected_inventory","name":"_matching_projected_inventory","line":109,"end_line":117,"hash":"3b6b512371390d5859d7b6e5375be42773e81a14bab4a9496e41b7749eb0765c"},{"id":"func/_unique_canonical_ids","name":"_unique_canonical_ids","line":120,"end_line":129,"hash":"262a6d188038aa372e2da4f66298e119059ba50c193f66ad76972bd51c90aa04"},{"id":"func/_append_region_if_new","name":"_append_region_if_new","line":132,"end_line":137,"hash":"1f51e1995d7a56959a4a4750bfda288eb383a0cbcf0a845222871b904c88f30a"},{"id":"func/_contiguous_regions","name":"_contiguous_regions","line":140,"end_line":147,"hash":"760915be52258ab32a0051d58f6a633056b7f0d1c24dcc26f3187883398bf9a7"},{"id":"func/NarrativeDraftContext.__post_init__","name":"__post_init__","line":161,"end_line":165,"hash":"2d467e6d2cc1c822638070aeb659cb6a3ba5eb1809c9a79ee0b80a7b2fc219df"},{"id":"func/NarrativeDraftContext.ordered_region_handles","name":"ordered_region_handles","line":168,"end_line":176,"hash":"87c6017e728d0f961f18cc9b159364bab7cabb79625d2905c1145e2ad45d7c32"},{"id":"func/NarrativeDraftContext.handles_for_region","name":"handles_for_region","line":178,"end_line":185,"hash":"aea28391ec6803c163a228e558ff08e08db7b3d1e2d484f0cc535fb75a6e860c"},{"id":"func/NarrativeSemanticDraftError.__init__","name":"__init__","line":199,"end_line":201,"hash":"54ce9a2918a526fac1597b31384c24e8f7e561a9b30207cb49f6cb1e73e2d7bc"},{"id":"func/_narrative_handle_literal","name":"_narrative_handle_literal","line":204,"end_line":208,"hash":"665c10da3969cfb86de00494b22f7e99520299b7ccf6486f99a6425b14a27af7"},{"id":"func/create_narrative_draft_model","name":"create_narrative_draft_model","line":211,"end_line":232,"hash":"33b5bee075ed6c1af219a6ceab884f0579359ca1dbea64e4b296d3412aef7ab3"},{"id":"func/create_narrative_draft_v3_model","name":"create_narrative_draft_v3_model","line":235,"end_line":265,"hash":"0e5c4e8259e4342b1d7ec2a2a840e79fe114dfad287f57db84ffb5e154c098c3"},{"id":"func/_draft_region_mapping","name":"_draft_region_mapping","line":268,"end_line":278,"hash":"80f17a2641986776df98d40ce829135791b5a038f55a2d39f69e33c08966c4c0"},{"id":"func/_region_set_violations","name":"_region_set_violations","line":281,"end_line":298,"hash":"aaf3b65ddb60478521f8abb8f2ed64d358ba910d49ff44d039e9b0d9c3837156"},{"id":"func/_cross_region_handles","name":"_cross_region_handles","line":301,"end_line":312,"hash":"fd18152aaed79a1bbaf72a532217e51cc79b0d98dd771705d456a61bc2c0c1c4"},{"id":"func/_cross_region_step_violations","name":"_cross_region_step_violations","line":315,"end_line":332,"hash":"a731c2dca82082eb7f0fce0b9f1507077bb673e980e45b50aa12e42047a87e14"},{"id":"func/_ordered_draft_beats","name":"_ordered_draft_beats","line":335,"end_line":348,"hash":"e5c2c613a534703219bebf700072baecd09f9b17d1a9a8c7ef1a99a9099df441"},{"id":"func/_step_handle_coverage_violations","name":"_step_handle_coverage_violations","line":351,"end_line":380,"hash":"43a175148f134b95c7cdae28f1e8a0ac42a28d81ce1831991d39eb2e1f292396"},{"id":"func/_step_order_violations","name":"_step_order_violations","line":383,"end_line":398,"hash":"2594186ddeba92d90be141e4093d48449f5c758973566f190cdc199f73b119ab"},{"id":"func/_beat_zone_violations","name":"_beat_zone_violations","line":401,"end_line":420,"hash":"5b486f683d9ccbdd4305ab58ea67712f35937051fc56e44d301f7211b23ec6e3"},{"id":"func/_beat_boundary_violations","name":"_beat_boundary_violations","line":423,"end_line":442,"hash":"63b074b8fe389b195bdfbe008a99f8fc09bee1818d4f0569b3852e73b58f4a1e"},{"id":"func/_missing_title_violation","name":"_missing_title_violation","line":445,"end_line":456,"hash":"d5f8b7f754adec8d35f6a65581836e9a749c701946ea97094fbe9853e4f7f141"},{"id":"func/_validate_narrative_draft","name":"_validate_narrative_draft","line":459,"end_line":475,"hash":"d3fef86da537fd945a0a2e27c1b532f9de3f5c199f2d6e94e48f3aafa98feca0"},{"id":"func/_narrative_step_from_beat","name":"_narrative_step_from_beat","line":478,"end_line":493,"hash":"8b78e77bd68d9504489722677e9ce9c7b1a434b5d357cf91018846f21a28ae7b"},{"id":"func/_derive_zone_sequence","name":"_derive_zone_sequence","line":496,"end_line":502,"hash":"6d9cf76e43d5dd53fcba633d20610c8b0de075a39529f9f753b6f70b928af808"},{"id":"func/compile_narrative_draft","name":"compile_narrative_draft","line":505,"end_line":529,"hash":"0624e26514f97c81fd7a776d3fea7b27ab2728c74d585e63db8c2c0770d16e62"},{"id":"func/_narrative_projected_steps","name":"_narrative_projected_steps","line":532,"end_line":545,"hash":"c7616ee00443d896c24d7cfb275d1d864f8cebc017e4785cda2e100671443928"},{"id":"func/_resolved_entry_point","name":"_resolved_entry_point","line":548,"end_line":556,"hash":"d065fec69decfeb5b54371b3f2e33a1bce09e7bd7ebfeb51254afd6f3dd1937c"},{"id":"func/_narrative_access_realization","name":"_narrative_access_realization","line":559,"end_line":573,"hash":"1ca007465861b5afc0be987c7906d8f3df9acde11943347a8c9bc0b9f5d1b720"},{"id":"func/_build_narrative_draft_context","name":"_build_narrative_draft_context","line":576,"end_line":605,"hash":"10881411f1add3432d4997248d9809b5d12c4c9ae845fc69cfd4d88a0d3924d1"},{"id":"func/_narrative_draft_prompt","name":"_narrative_draft_prompt","line":608,"end_line":629,"hash":"1fe6010dd7795fb7c7dcdb03945bb27ecd04c3d30fca0af9f56c089f29846210"}]}
# mutate4py-manifest-end
