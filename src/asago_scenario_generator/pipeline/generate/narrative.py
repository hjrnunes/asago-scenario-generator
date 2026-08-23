"""Call 1: Narrative generation logic."""

from __future__ import annotations

import logging
import re
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, create_model, field_validator

from asago_scenario_generator.llm.client import LLMClient, LLMResult
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
from asago_scenario_generator.pipeline.generate.constants import _OWASP_LLM_NAMES
from asago_scenario_generator.pipeline.generate.diversity import (
    _format_structural_exclusions,
)
from asago_scenario_generator.pipeline.generate.alignment import (
    derive_projection_alignment_rows_from_context,
)
from asago_scenario_generator.pipeline.generate.ontology import (
    _build_ontology_context,
    _build_technique_context_block,
    _format_taxonomy_ids,
    _lookup_entry_point_controllability,
    _lookup_entry_point_direction,
    build_kc_definitions_block,
)
from asago_scenario_generator.pipeline.generate.step_ids import (
    normalize_projected_step_ids,
)
from asago_scenario_generator.pipeline.generate.zones import (
    _enforce_zones_narrative,
    enforce_narrative_projection_zones,
    projected_boundary_by_id,
)
from asago_scenario_generator.pipeline.seeds import ScenarioSeed
from asago_scenario_generator.prompts import render_prompt

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Intermediate models for structured output
# ---------------------------------------------------------------------------


# Conservative finite static maxima for the structured Call 1 schema, which
# is sent to the provider via response_format.  The narrative step list is
# additionally bounded dynamically to selected_step_count + 2 (capped at
# MAX_NARRATIVE_STEPS) by finalization gates.
MAX_NARRATIVE_STEPS = 16
NARRATIVE_CONNECTOR_STEPS = 2
_CALL1_TITLE_MAX_LENGTH = 200
_CALL1_PROSE_MAX_LENGTH = 2000
_CALL1_ENTRY_MAX_LENGTH = 200
_CALL1_ZONE_MAX_LENGTH = 64
_CALL1_STEP_IDS_MAX_ITEMS = 16
_CALL1_STEP_ID_MAX_LENGTH = 200

_Call1Zone = Annotated[str, Field(min_length=1, max_length=_CALL1_ZONE_MAX_LENGTH)]
_Call1StepId = Annotated[str, Field(min_length=1, max_length=_CALL1_STEP_ID_MAX_LENGTH)]


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
        if not self.ordered_step_handles:
            raise ValueError("narrative context requires at least one projected step")
        if len(set(self.ordered_step_handles)) != len(self.ordered_step_handles):
            raise ValueError("narrative context has duplicate projected-step handles")
        if set(self.ordered_step_handles) != set(self.projected_steps):
            raise ValueError(
                "ordered narrative handles must exactly match projected-step inventory"
            )
        canonical_ids = [
            self.projected_steps[handle].projected_step_id
            for handle in self.ordered_step_handles
        ]
        if len(set(canonical_ids)) != len(canonical_ids):
            raise ValueError("narrative context has duplicate canonical step IDs")
        seen_regions: list[str] = []
        for handle in self.ordered_step_handles:
            region = self.projected_steps[handle].region
            if not seen_regions or seen_regions[-1] != region:
                if region in seen_regions:
                    raise ValueError(
                        "narrative compatibility regions must be contiguous"
                    )
                seen_regions.append(region)

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


def _ordered_draft_beats(
    context: NarrativeDraftContext, draft: NarrativeDraftV2 | NarrativeDraftV3
) -> tuple[list[NarrativeCausalBeatV2], list[NarrativeDraftViolation]]:
    if isinstance(draft, NarrativeDraftV2):
        return list(draft.beats), []

    regions = _draft_region_mapping(draft)
    expected = set(context.ordered_region_handles)
    actual = set(regions)
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
    beats: list[NarrativeCausalBeatV2] = []
    for region in context.ordered_region_handles:
        allowed = set(context.handles_for_region(region))
        region_beats = regions.get(region, [])
        invalid = sorted(
            {
                handle
                for beat in region_beats
                for handle in beat.step_handles
                if handle not in allowed
            }
        )
        if invalid:
            violations.append(
                NarrativeDraftViolation(
                    "cross_region_step_handle",
                    f"region '{region}' contains step handle(s) owned by another "
                    f"region: {invalid}",
                )
            )
        beats.extend(region_beats)
    return beats, violations


def _validate_narrative_draft(
    context: NarrativeDraftContext, draft: NarrativeDraftV2 | NarrativeDraftV3
) -> list[NarrativeDraftViolation]:
    beats, violations = _ordered_draft_beats(context, draft)
    flattened = [handle for beat in beats for handle in beat.step_handles]
    expected = set(context.ordered_step_handles)
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

    known_handles = [handle for handle in flattened if handle in expected]
    positions = {
        handle: index for index, handle in enumerate(context.ordered_step_handles)
    }
    if any(
        positions[current] >= positions[following]
        for current, following in zip(known_handles, known_handles[1:])
        if current != following
    ):
        violations.append(
            NarrativeDraftViolation(
                "illegal_step_order",
                "projected-step handles violate the canonical partial order",
            )
        )

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
    if draft.title is None and not context.presentation_fallback_allowed:
        violations.append(
            NarrativeDraftViolation(
                "missing_title",
                "narrative title is required when fallback is forbidden",
            )
        )
    return violations


def compile_narrative_draft(
    context: NarrativeDraftContext, draft: NarrativeDraftV2 | NarrativeDraftV3
) -> NarrativeLayer:
    """Attach projection truth while preserving provider-authored causality."""
    violations = _validate_narrative_draft(context, draft)
    if violations:
        raise NarrativeSemanticDraftError(violations)

    beats, _ = _ordered_draft_beats(context, draft)
    steps: list[NarrativeStep] = []
    for number, beat in enumerate(beats, start=1):
        projected = [context.projected_steps[handle] for handle in beat.step_handles]
        effect = beat.consequence
        if beat.transition:
            effect = f"{effect} {beat.transition}"
        steps.append(
            NarrativeStep(
                step_number=number,
                zone=projected[0].zone,
                action=beat.action,
                effect=effect,
                projected_step_ids=tuple(item.projected_step_id for item in projected),
                realizations=tuple(item.realization for item in projected),
            )
        )
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
    projected_steps: dict[str, NarrativeProjectedStep] = {}
    for handle, semantic in zip(handles, semantics.steps):
        projected_steps[handle] = NarrativeProjectedStep(
            projected_step_id=semantic.projected_step_id,
            order=semantic.order,
            zone=semantic.zone,
            realization=semantic.realization,
            region=semantic.narrative_region,
        )

    ingress_id = projection_context.get("canonical_ingress", {}).get("entry_point_id")
    entry_point = pinned_entry_point
    if not entry_point and isinstance(ingress_id, str):
        resolved = profile.resolve_entry_point(ingress_id)
        entry_point = resolved.name if resolved is not None else ingress_id
    if not entry_point:
        raise ValueError("projection lacks a displayable canonical entry point")

    access_realization = None
    if actor_profile is not None and actor_profile.access is not None:
        access = actor_profile.access
        access_realization = NarrativeAccessRealization(
            initial_entry_point_id=access.initial_entry_point_id,
            influence_source=access.influence_source,
            influence_source_kind=access.influence_source_kind,
            influence_source_id=access.influence_source_id,
            trust_boundary_id=access.trust_boundary_id,
            responsible_step_number=1,
        )
    return NarrativeDraftContext(
        title_fallback=seed.attack_pattern_name,
        entry_point=entry_point,
        ordered_step_handles=handles,
        projected_steps=projected_steps,
        access_realization=access_realization,
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


class Call1Step(BaseModel):
    """Model-owned fields returned by Call 1 for one narrative step.

    Canonical realization records are deliberately absent from this
    provider-facing model.  They are derived after parsing from the
    immutable projection context.  ``extra='ignore'`` keeps older fixtures
    and defensive extra-field injections from becoming published data.
    """

    model_config = {"extra": "ignore"}

    step_number: int
    zone: _Call1Zone
    action: str = Field(max_length=_CALL1_PROSE_MAX_LENGTH)
    effect: str = Field(max_length=_CALL1_PROSE_MAX_LENGTH)
    control_point: str | None = Field(default=None, max_length=_CALL1_ZONE_MAX_LENGTH)
    # --- Projection traceability fields (422o.4) ---
    # Required on every step; the LLM receives the IDs as opaque
    # constraints and must echo them back.  No defaults -- a missing
    # field is a typed violation, not an acceptable empty value.
    projected_step_ids: tuple[_Call1StepId, ...] = Field(
        min_length=1,
        max_length=_CALL1_STEP_IDS_MAX_ITEMS,
        description=(
            "Canonical projected step IDs that this narrative step realizes. "
            "Must be echoed from the projection context constraints."
        ),
    )

    @field_validator("projected_step_ids")
    @classmethod
    def _reject_duplicate_projected_step_ids(
        cls, value: tuple[str, ...]
    ) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError("duplicate projected step ID in narrative response")
        return value


class Call1Response(BaseModel):
    title: str = Field(max_length=_CALL1_TITLE_MAX_LENGTH)
    summary: str = Field(max_length=_CALL1_PROSE_MAX_LENGTH)
    entry_point: str = Field(max_length=_CALL1_ENTRY_MAX_LENGTH)
    zone_sequence: list[_Call1Zone] = Field(
        min_length=1,
        max_length=MAX_NARRATIVE_STEPS,
        description=(
            "Ordered attack propagation path through zones, including"
            " revisitations. E.g. [input, reasoning, tool_execution,"
            " reasoning] not just [input, reasoning, tool_execution]."
        ),
    )
    steps: list[Call1Step] = Field(
        min_length=1,
        max_length=MAX_NARRATIVE_STEPS,
        description=(
            "Narrative steps.  Must cover every selected canonical step and "
            "stay within selected_step_count + 2 steps (capped at 16)."
        ),
    )
    access_realization: NarrativeAccessRealization | None = None


def build_call1_response_model(
    selected_step_count: int | None = None,
) -> type[Call1Response]:
    """Build the provider-facing Call 1 schema for the current candidate.

    Narrative steps include at most two connector steps beyond the selected
    canonical projection steps, capped at ``MAX_NARRATIVE_STEPS``.  The
    dynamic bound is applied to the schema sent to the provider, not only to
    post-response finalization.
    """
    if selected_step_count is None:
        return Call1Response
    if selected_step_count < 0:
        raise ValueError("selected_step_count must be non-negative")
    maximum_steps = min(
        MAX_NARRATIVE_STEPS,
        selected_step_count + NARRATIVE_CONNECTOR_STEPS,
    )
    model_name = f"Call1ResponseSelected{selected_step_count}"
    return create_model(
        model_name,
        __base__=Call1Response,
        steps=(
            list[Call1Step],
            Field(
                min_length=1,
                max_length=maximum_steps,
                description=(
                    "Narrative steps. Must cover every selected canonical "
                    "step and stay within the candidate-specific bound."
                ),
            ),
        ),
    )


# ---------------------------------------------------------------------------
# Non-Latin script sanitization
# ---------------------------------------------------------------------------


def _is_latin_or_common(char: str) -> bool:
    """Return True if a character is Latin, Common, or Inherited script."""
    # ASCII printable and whitespace are always kept
    if char.isascii():
        return True
    # Use Unicode character name to detect Latin letters
    name = unicodedata.name(char, "")
    # Common punctuation/symbols/digits — keep
    cat = unicodedata.category(char)
    if cat[0] in ("P", "S", "N", "Z"):
        return True
    # Latin letters (accented, extended) have "LATIN" in their Unicode name
    return "LATIN" in name


def _sanitize_non_latin(text: str) -> str:
    """Remove non-Latin script characters that leak into English output.

    CJK, Cyrillic, Arabic, and other non-Latin characters are stripped.
    Accented Latin characters (French/Spanish/etc.) are preserved.
    ASCII and common punctuation/symbols are always preserved.
    Multiple consecutive spaces left after removal are collapsed.

    Returns the cleaned text.
    """
    if not text:
        return text
    cleaned = "".join(ch for ch in text if _is_latin_or_common(ch))
    # Collapse runs of spaces (but preserve newlines and other whitespace)
    cleaned = re.sub(r"[ \t]+", " ", cleaned)
    # Strip leading/trailing space from each line
    cleaned = "\n".join(line.strip() for line in cleaned.split("\n"))
    return cleaned.strip()


def _sanitize_narrative(narrative: NarrativeLayer) -> NarrativeLayer:
    """Apply non-Latin sanitization to narrative text fields.

    Logs a warning when sanitization modifies any field.
    Returns a (possibly modified) copy of the narrative.

    Uses model_copy(update=...) to preserve projection metadata fields
    (projected_step_ids, canonical_action_kind, etc.) — only prose text
    fields are sanitized (422o.4 blocker #4: no semantic repair).
    """
    changed = False
    title = _sanitize_non_latin(narrative.title)
    summary = _sanitize_non_latin(narrative.summary)

    if title != narrative.title or summary != narrative.summary:
        changed = True

    new_steps = []
    for step in narrative.steps:
        action = _sanitize_non_latin(step.action)
        effect = _sanitize_non_latin(step.effect)
        if action != step.action or effect != step.effect:
            changed = True
            # Use model_copy to preserve all projection metadata fields.
            new_steps.append(
                step.model_copy(update={"action": action, "effect": effect})
            )
        else:
            new_steps.append(step)

    if changed:
        logger.warning(
            "Sanitized non-Latin characters from narrative fields "
            "(CJK/Cyrillic/Arabic leak from LLM output)"
        )
        return narrative.model_copy(
            update={
                "title": title,
                "summary": summary,
                "steps": new_steps,
            }
        )
    return narrative


# ---------------------------------------------------------------------------
# Zone sequence derivation
# ---------------------------------------------------------------------------


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


def _derive_zone_sequence(steps: list[Call1Step] | list[NarrativeStep]) -> list[str]:
    """Derive zone_sequence from step zone fields.

    Preserves traversal order including revisitations (non-consecutive
    duplicates), but collapses consecutive duplicate zones.

    Example:
        [input, input, reasoning, reasoning, tool_execution]
        -> [input, reasoning, tool_execution]

        [input, reasoning, tool_execution, reasoning]
        -> [input, reasoning, tool_execution, reasoning]  (revisit preserved)
    """
    sequence: list[str] = []
    for step in steps:
        if not sequence or sequence[-1] != step.zone:
            sequence.append(step.zone)
    return sequence


def _selected_projection_steps_by_id(
    projection_context: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Index selected projection steps while validating their identities."""
    selected_steps_by_id: dict[str, dict[str, Any]] = {}
    for selected_step in projection_context.get("selected_steps", []):
        if not isinstance(selected_step, dict):
            raise ValueError("invalid projected step context entry")
        step_id = selected_step.get("step_id")
        if not isinstance(step_id, str):
            raise ValueError("invalid projected step context ID")
        if step_id in selected_steps_by_id:
            raise ValueError(
                f"duplicate projected step ID '{step_id}' in projection context"
            )
        selected_steps_by_id[step_id] = selected_step
    return selected_steps_by_id


def _canonical_realizations_for_step(
    step: Call1Step,
    selected_steps_by_id: dict[str, dict[str, Any]],
) -> tuple[ProjectedStepRealization, ...]:
    """Resolve one response step to immutable canonical realizations."""
    realizations: list[ProjectedStepRealization] = []
    for projected_step_id in step.projected_step_ids:
        selected_step = selected_steps_by_id.get(projected_step_id)
        if selected_step is None:
            raise ValueError(
                f"unknown projected step ID '{projected_step_id}' in narrative response"
            )
        raw_realization = selected_step.get("realization")
        if not isinstance(raw_realization, dict):
            raise ValueError(
                f"missing canonical realization for projected step ID "
                f"'{projected_step_id}'"
            )
        realization = ProjectedStepRealization.model_validate(raw_realization)
        if realization.projected_step_id != projected_step_id:
            raise ValueError(
                f"semantically incompatible projected step ID "
                f"'{projected_step_id}' in narrative mapping"
            )
        realizations.append(realization)
    return tuple(realizations)


def _map_call1_to_narrative(
    resp: Call1Response,
    projection_context: dict[str, Any] | None = None,
) -> NarrativeLayer:
    selected_steps_by_id = (
        _selected_projection_steps_by_id(projection_context)
        if projection_context is not None
        else None
    )
    steps = [
        NarrativeStep(
            step_number=s.step_number,
            zone=s.zone,
            action=s.action,
            effect=s.effect,
            control_point=s.control_point,
            projected_step_ids=s.projected_step_ids,
            realizations=(
                _canonical_realizations_for_step(s, selected_steps_by_id)
                if selected_steps_by_id is not None
                else ()
            ),
        )
        for s in resp.steps
    ]
    if projection_context is not None:
        selected_step_ids = set(projection_context.get("selected_step_ids", ()))
        covered_step_ids = {
            projected_step_id
            for step in steps
            for projected_step_id in step.projected_step_ids
        }
        missing = sorted(selected_step_ids - covered_step_ids)
        if missing:
            raise ValueError(
                "omitted projected step ID(s) from narrative response: "
                + ", ".join(missing)
            )
    # Derive zone_sequence from step zones rather than using the LLM's
    # zone_sequence field, which tends to collapse return traversals.
    zone_sequence = _derive_zone_sequence(resp.steps)
    return NarrativeLayer(
        title=resp.title,
        summary=resp.summary,
        entry_point=resp.entry_point,
        zone_sequence=zone_sequence,
        steps=steps,
        access_realization=resp.access_realization,
    )


# ---------------------------------------------------------------------------
# Narrative access realization validation (cmps.6)
# ---------------------------------------------------------------------------


@dataclass
class NarrativeRealizationViolation:
    """A narrative access-realization mismatch (cmps.6)."""

    rule: str
    message: str


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

    # 2. initial_entry_point_id must match.
    if realization.initial_entry_point_id != access.initial_entry_point_id:
        violations.append(
            NarrativeRealizationViolation(
                rule="realization_entry_point_mismatch",
                message=(
                    f"Narrative access_realization initial_entry_point_id "
                    f"'{realization.initial_entry_point_id}' does not match "
                    f"actor access provenance "
                    f"'{access.initial_entry_point_id}'."
                ),
            )
        )

    # 3. The legacy source field and the typed source identity must match.
    realization_source_id = (
        realization.influence_source_id or realization.influence_source
    )
    access_source_id = access.influence_source_id or access.influence_source
    if (realization_source_id or None) != (access_source_id or None):
        violations.append(
            NarrativeRealizationViolation(
                rule="realization_influence_source_mismatch",
                message=(
                    f"Narrative access_realization influence_source "
                    f"'{realization_source_id}' does not match actor "
                    f"access provenance '{access_source_id}'."
                ),
            )
        )
    if (realization.influence_source_kind or None) != (
        access.influence_source_kind or None
    ):
        violations.append(
            NarrativeRealizationViolation(
                rule="realization_influence_source_mismatch",
                message=(
                    "Narrative access_realization source kind does not match "
                    "actor access provenance."
                ),
            )
        )

    # 4. trust_boundary_id must match (or both None).
    if (realization.trust_boundary_id or None) != (access.trust_boundary_id or None):
        violations.append(
            NarrativeRealizationViolation(
                rule="realization_trust_boundary_mismatch",
                message=(
                    f"Narrative access_realization trust_boundary_id "
                    f"'{realization.trust_boundary_id}' does not match actor "
                    f"access provenance '{access.trust_boundary_id}'."
                ),
            )
        )

    # 5. responsible_step_number must refer to an existing step.
    step_numbers = {s.step_number for s in narrative.steps}
    if realization.responsible_step_number not in step_numbers:
        violations.append(
            NarrativeRealizationViolation(
                rule="realization_step_not_found",
                message=(
                    f"Narrative access_realization responsible_step_number "
                    f"{realization.responsible_step_number} does not refer "
                    f"to any narrative step (valid: {sorted(step_numbers)})."
                ),
            )
        )

    # 6. Direct access must omit indirect-only references.
    if access.ingress_mode == "direct":
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


# ---------------------------------------------------------------------------
# Context builder and LLM call
# ---------------------------------------------------------------------------


def build_call1_context(
    seed: ScenarioSeed,
    profile: CapabilityProfile,
    use_case: str,
    actor_profile: ActorProfile | None = None,
    preferred_entry_point: str | None = None,
    excluded_entry_points: list[str] | None = None,
    excluded_patterns: list[str] | None = None,
    excluded_structural_patterns: list[str] | None = None,
    pinned_entry_point: str | None = None,
    pinned_technique_ids: list[str] | None = None,
    prior_titles: list[str] | None = None,
    pinned_entry_point_id: str | None = None,
    access_feedback: str | None = None,
    realization_feedback: str | None = None,
    projection_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build prompt template variables for Call 1 (Narrative).

    Pure data-preparation function that constructs all template variables
    needed by ``call1_user.j2``.  No LLM calls.

    Returns:
        Dict mapping template variable names to their values.
    """
    # Build entry point diversity guidance section
    diversity_section = ""
    if pinned_entry_point:
        # Hard constraint from candidate filter — overrides soft hints
        diversity_section = (
            "\n## Entry Point Guidance\n"
            f"- You MUST use this entry point: {pinned_entry_point}. "
            "This is a hard constraint, not a suggestion.\n"
        )
    elif preferred_entry_point or excluded_entry_points:
        diversity_lines = ["\n## Entry Point Guidance"]
        if preferred_entry_point:
            diversity_lines.append(
                f"- Preferred entry point: {preferred_entry_point} "
                "(use this unless it would be unnatural for the attack)"
            )
        if excluded_entry_points:
            diversity_lines.append(
                f"- Avoid these overused entry points: {excluded_entry_points}"
            )
        diversity_section = "\n".join(diversity_lines) + "\n"

    # Build title diversity section when prior titles exist
    if prior_titles:
        title_list = "\n".join(f"  {i}. {t}" for i, t in enumerate(prior_titles, 1))
        diversity_section += (
            "\n## Previously Generated Titles (avoid duplication)\n"
            "The following titles have already been used in this generation "
            "run. Your title MUST be substantially different — do not reuse "
            'the same structure, key phrases, or "[Mechanism] for [Goal]" '
            "pattern:\n"
            f"{title_list}\n"
        )

    # Build attack pattern diversity section
    pattern_section = ""
    if excluded_patterns:
        pattern_section = (
            "\n## Attack Pattern Diversity\n"
            "Avoid these attack patterns which are already well-represented "
            "in this batch:\n"
            f"- Overused patterns: {', '.join(excluded_patterns)}\n"
            "Find a DIFFERENT attack approach. Use a different vulnerability "
            "mechanism, a different propagation path, or a different impact "
            "chain. Creativity and variety are essential.\n"
        )

    # Build structural pattern diversity section
    structural_section = ""
    if excluded_structural_patterns:
        structural_section = _format_structural_exclusions(excluded_structural_patterns)

    # Build actor profile section for narrative grounding
    actor_section = ""
    if actor_profile is not None:
        resources_str = ", ".join(actor_profile.resources)
        actor_section = (
            "\n## Actor Profile (ground the narrative in this actor)\n"
            "The narrative's attacker must match this actor's capability level, "
            "resources, and motivations.\n"
            f"- Actor type: {actor_profile.actor_type}\n"
            f"- Capability level: {actor_profile.capability_level}\n"
            f"- Beliefs about the target:\n"
            + "".join(f"  - {b}\n" for b in actor_profile.beliefs)
            + "- Desires:\n"
            + "".join(f"  - {d}\n" for d in actor_profile.desires)
            + "- Intentions:\n"
            + "".join(f"  - {i}\n" for i in actor_profile.intentions)
            + f"- Resources: {resources_str}\n"
        )

    # Build structured access provenance block (cmps.6) — using names (Phase 3)
    access_provenance_block = ""
    if actor_profile is not None and actor_profile.access is not None:
        from asago_scenario_generator.pipeline.generate.names import (
            access_provenance_block_with_names,
        )

        access_provenance_block = access_provenance_block_with_names(
            actor_profile.access,
            profile,
            header=(
                "\n## Actor Access Provenance (AUTHORITATIVE — cmps.6)\n"
                "This structured block is authoritative over any advisory "
                "kill-chain wording. The narrative must be consistent with "
                "this evidence.\n"
            ),
        )

    # Build goal category section for narrative grounding
    goal_section = ""
    if actor_profile is not None and actor_profile.goal_category:
        goal_section = (
            "\n## Attack Goal Guidance (SHOULD)\n"
            f"**Category:** {actor_profile.goal_category_parent}\n"
            f"**Specific Goal:** {actor_profile.goal_category}: "
            f"{actor_profile.goal_category_name}\n\n"
            "The narrative's terminal attack outcome SHOULD align with this goal "
            "when it is compatible with the seed attack pattern's mechanism. "
            "If satisfying this goal would require abandoning the seed's core "
            "attack mechanism, prioritise seed fidelity — the goal is a guiding "
            "preference, not a hard override. The seed's 'Seed Attack Objective "
            "Fidelity (INVARIANT)' constraint always takes precedence.\n"
        )

    # Resolve creativity-vs-simplicity conflict for novice actors
    if (
        diversity_section
        and actor_profile is not None
        and actor_profile.capability_level == "novice"
    ):
        diversity_section += (
            "\n\n**Capability-level priority:** The actor is a NOVICE. "
            "Diversity constraints are secondary to capability-level constraints. "
            "Do NOT generate a complex attack just because simpler patterns have "
            "been excluded. Instead, use a DIFFERENT simple pattern or a different "
            "angle on the same simple technique."
        )

    # Build technique context — pin to specific techniques if set
    tech_ids_for_narrative = (
        pinned_technique_ids if pinned_technique_ids else seed.atlas_technique_ids
    )
    technique_context_1 = _build_technique_context_block(tech_ids_for_narrative)
    if pinned_technique_ids:
        technique_framing_1 = (
            "You MUST use these ATLAS technique(s) in the narrative. "
            "Reference them in narrative step actions and annotate with the ID "
            "in square brackets, e.g. [AML.T0054]. This is a hard constraint.\n"
        )
    else:
        technique_framing_1 = (
            "Reference these techniques in narrative step actions where applicable. "
            "Annotate technique usage with the ID in square brackets, "
            "e.g. [AML.T0054].\n"
            if seed.atlas_technique_ids
            else ""
        )

    owasp_llm_formatted = _format_taxonomy_ids(seed.owasp_llm_ids, _OWASP_LLM_NAMES)

    # Look up entry point direction and controllability from the capability profile
    pinned_entry_point_direction = _lookup_entry_point_direction(
        profile,
        pinned_entry_point,
        pinned_entry_point_id,
    )
    pinned_entry_point_controllability = _lookup_entry_point_controllability(
        profile,
        pinned_entry_point,
        pinned_entry_point_id,
    )

    # Build KC/KCX definition block for the prompt
    kc_definitions = build_kc_definitions_block(profile.kc_subcodes)

    # Build focused ontology context block for this seed
    ontology_context = _build_ontology_context(
        entry_point_name=pinned_entry_point or "",
        entry_point_direction=pinned_entry_point_direction,
        zones=profile.zones_active,
        technique_ids=list(tech_ids_for_narrative) if tech_ids_for_narrative else [],
        entry_point_controllability=pinned_entry_point_controllability,
    )

    # Humanize projection context for the template (Phase 3)
    from asago_scenario_generator.pipeline.generate.names import (
        humanize_projection_context,
    )

    humanized_projection = (
        humanize_projection_context(projection_context, profile)
        if projection_context is not None
        else projection_context
    )

    # Validator-derived compact alignment table (one row per selected step).
    alignment_rows = derive_projection_alignment_rows_from_context(humanized_projection)

    return {
        "use_case": use_case,
        "seed": seed,
        "profile": profile,
        "owasp_llm_formatted": owasp_llm_formatted,
        "technique_context": technique_context_1,
        "technique_framing": technique_framing_1,
        "actor_section": actor_section,
        "access_provenance_block": access_provenance_block,
        "goal_section": goal_section,
        "diversity_section": diversity_section,
        "pattern_section": pattern_section,
        "structural_section": structural_section,
        "pinned_entry_point": pinned_entry_point,
        "pinned_entry_point_direction": pinned_entry_point_direction,
        "kc_definitions": kc_definitions,
        "ontology_context": ontology_context,
        "tool_inventory": profile.tool_inventory or [],
        "kill_chain": seed.kill_chain,
        "access_feedback": access_feedback or "",
        "realization_feedback": realization_feedback or "",
        "projection_context": humanized_projection,
        "projection_alignment_rows": alignment_rows,
    }


def _apply_projection_access_realization(
    narrative: NarrativeLayer,
    projection_context: dict[str, Any] | None,
) -> None:
    """Replace model-selected access IDs with the projected typed relation."""
    if projection_context is None:
        return
    canonical_ingress = projection_context["canonical_ingress"]["entry_point_id"]
    paths = projection_context.get("source_influence_paths", [])
    if len(paths) > 1:
        raise ValueError("projection context contains multiple source-influence paths")
    current = narrative.access_realization
    step_numbers = {step.step_number for step in narrative.steps}
    responsible_step = (
        current.responsible_step_number
        if current is not None and current.responsible_step_number in step_numbers
        else min(step_numbers)
    )
    path = paths[0] if paths else None
    if current is None:
        current = NarrativeAccessRealization(
            initial_entry_point_id=canonical_ingress,
            responsible_step_number=responsible_step,
        )
        narrative.access_realization = current
    current.initial_entry_point_id = canonical_ingress
    current.influence_source = path["source_id"] if path else None
    current.influence_source_kind = path["source_identity_kind"] if path else None
    current.influence_source_id = path["source_id"] if path else None
    current.trust_boundary_id = path["boundary_id"] if path else None


def _call_narrative(
    seed: ScenarioSeed,
    profile: CapabilityProfile,
    client: LLMClient,
    use_case: str,
    actor_profile: ActorProfile | None = None,
    preferred_entry_point: str | None = None,
    excluded_entry_points: list[str] | None = None,
    excluded_patterns: list[str] | None = None,
    excluded_structural_patterns: list[str] | None = None,
    pinned_entry_point: str | None = None,
    pinned_technique_ids: list[str] | None = None,
    prior_titles: list[str] | None = None,
    pinned_entry_point_id: str | None = None,
    access_feedback: str | None = None,
    realization_feedback: str | None = None,
    completion_length_feedback: str | None = None,
    max_completion_tokens: int | None = None,
    projection_context: dict[str, Any] | None = None,
    presentation_fallback_allowed: bool = True,
) -> tuple[NarrativeLayer, LLMResult]:
    """Generate an attack narrative for a scenario seed (Call 1).

    Delegates context building to :func:`build_call1_context`, then renders
    templates, calls the LLM, and post-processes the narrative.

    ``completion_length_feedback`` (the finalization-owned length-retry
    suffix) is appended verbatim to the end of the rendered user prompt,
    after every semantic section.

    Returns:
        Tuple of (NarrativeLayer, LLMResult).
    """
    ctx = build_call1_context(
        seed=seed,
        profile=profile,
        use_case=use_case,
        actor_profile=actor_profile,
        preferred_entry_point=preferred_entry_point,
        excluded_entry_points=excluded_entry_points,
        excluded_patterns=excluded_patterns,
        excluded_structural_patterns=excluded_structural_patterns,
        pinned_entry_point=pinned_entry_point,
        pinned_technique_ids=pinned_technique_ids,
        prior_titles=prior_titles,
        pinned_entry_point_id=pinned_entry_point_id,
        access_feedback=access_feedback,
        realization_feedback=realization_feedback,
        projection_context=projection_context,
    )

    semantic_draft_v2 = projection_context is not None
    user_prompt = render_prompt(
        "call1_user.j2", **ctx, semantic_draft_v2=semantic_draft_v2
    )
    draft_context: NarrativeDraftContext | None = None
    response_model: type[BaseModel]
    if semantic_draft_v2:
        assert projection_context is not None
        draft_context = _build_narrative_draft_context(
            seed=seed,
            profile=profile,
            actor_profile=actor_profile,
            pinned_entry_point=pinned_entry_point,
            projection_context=projection_context,
            presentation_fallback_allowed=presentation_fallback_allowed,
        )
        response_model = create_narrative_draft_v3_model(draft_context)
        user_prompt += _narrative_draft_prompt(draft_context)
    else:
        response_model = build_call1_response_model(None)
    if completion_length_feedback:
        user_prompt = f"{user_prompt}{completion_length_feedback}"
    result = client.complete(
        system_prompt=render_prompt(
            "call1_system.j2",
            has_persistent_memory=profile.has_persistent_memory,
            multi_agent=profile.multi_agent,
            hitl=profile.hitl,
            zones_active=profile.zones_active,
            kc_subcodes=profile.kc_subcodes,
            tool_inventory=ctx["tool_inventory"],
            semantic_draft_v2=semantic_draft_v2,
        ),
        user_prompt=user_prompt,
        response_format=response_model,
        max_completion_tokens=max_completion_tokens,
    )
    if isinstance(result.content, (NarrativeDraftV2, NarrativeDraftV3)):
        assert draft_context is not None
        narrative = compile_narrative_draft(draft_context, result.content)
    else:
        # Scripted fixtures using the historical response remain supported
        # while live projected requests advertise only NarrativeDraftV3.
        # Normalize echoed step-ID transport shapes to canonical IDs before
        # deriving deterministic realizations.
        if projection_context is not None:
            canonical_ids = projection_context.get("selected_step_ids", [])
            for step in result.content.steps:
                step.projected_step_ids = normalize_projected_step_ids(
                    step.projected_step_ids, canonical_ids
                )
        narrative = _map_call1_to_narrative(result.content, projection_context)
    # Normalize echoed step-ID transport shapes to canonical IDs before
    # deriving deterministic realizations. Unknown, ambiguous, or duplicate
    # legacy echoes raise a stable ValueError, so no defective narrative is
    # finalized.
    _apply_projection_access_realization(narrative, projection_context)
    narrative = _sanitize_narrative(narrative)
    if projection_context is not None:
        # Stage-specific boundary validation: literal 'outside' is allowed
        # only for steps mapping only outside-boundary projected steps;
        # inside/crossing steps must use active Schneider zones.
        boundary_by_id = projected_boundary_by_id(
            projection_context.get("selected_steps", [])
        )
        narrative = enforce_narrative_projection_zones(
            narrative, profile.zones_active, boundary_by_id
        )
    else:
        narrative = _enforce_zones_narrative(narrative, profile.zones_active)

    # Phase 3: resolve human-readable names to canonical hex IDs in
    # the narrative's access_realization.
    if narrative.access_realization is not None:
        from asago_scenario_generator.pipeline.generate.names import (
            resolve_name_to_entry_point_id,
            resolve_name_to_trust_boundary_id,
        )

        ar = narrative.access_realization
        resolved_ep = resolve_name_to_entry_point_id(ar.initial_entry_point_id, profile)
        if resolved_ep is not None:
            ar.initial_entry_point_id = resolved_ep
        if ar.influence_source is not None:
            resolved_src = resolve_name_to_entry_point_id(ar.influence_source, profile)
            if resolved_src is not None:
                ar.influence_source = resolved_src
        if ar.trust_boundary_id is not None:
            resolved_tb = resolve_name_to_trust_boundary_id(
                ar.trust_boundary_id, profile
            )
            if resolved_tb is not None:
                ar.trust_boundary_id = resolved_tb

    return narrative, result
