"""Call 1: Narrative generation logic."""

from __future__ import annotations

import logging
import re
import unicodedata
from typing import Annotated, Any

from pydantic import BaseModel, Field, create_model, field_validator

from asago_scenario_generator.llm.client import LLMClient, LLMResult
from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.models.realization import ProjectedStepRealization
from asago_scenario_generator.models.scenario import (
    ActorProfile,
    NarrativeAccessRealization,
    NarrativeLayer,
    NarrativeStep,
)
from asago_scenario_generator.pipeline.generate.constants import _OWASP_LLM_NAMES

# Semantic drafting and access validation are kept in focused leaf modules;
# these imports preserve the historical narrative-module seams.
from asago_scenario_generator.pipeline.generate.narrative_semantics import (  # noqa: F401
    NarrativeCausalBeatV2,
    NarrativeDraftContext,
    NarrativeDraftV2,
    NarrativeDraftV3,
    NarrativeDraftViolation,
    NarrativeProjectedStep,
    NarrativeSemanticDraftError,
    _append_region_if_new,
    _beat_boundary_violations,
    _beat_zone_violations,
    _build_narrative_draft_context,
    _contiguous_regions,
    _cross_region_handles,
    _cross_region_step_violations,
    _derive_zone_sequence,
    _draft_region_mapping,
    _matching_projected_inventory,
    _missing_title_violation,
    _narrative_access_realization,
    _narrative_draft_prompt,
    _narrative_handle_literal,
    _narrative_projected_steps,
    _narrative_step_from_beat,
    _ordered_draft_beats,
    _region_set_violations,
    _resolved_entry_point,
    _step_handle_coverage_violations,
    _step_order_violations,
    _unique_canonical_ids,
    _unique_step_handles,
    _validate_narrative_draft,
    compile_narrative_draft,
    create_narrative_draft_model,
    create_narrative_draft_v3_model,
    _CALL1_PROSE_MAX_LENGTH,
    _CALL1_TITLE_MAX_LENGTH,
)
from asago_scenario_generator.pipeline.generate.narrative_access import (  # noqa: F401
    MAX_NARRATIVE_STEPS,
    NARRATIVE_CONNECTOR_STEPS,
    NarrativeRealizationViolation,
    _direct_boundary_violation,
    _direct_source_violation,
    _entry_point_violation,
    _realization_violations,
    _responsible_step_violation,
    _source_id_violation,
    _source_identity,
    _source_kind_violation,
    _trust_boundary_violation,
    validate_narrative_access_realization,
    validate_narrative_step_bounds,
)
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


# Provider-facing legacy response bounds.
_CALL1_ENTRY_MAX_LENGTH = 200
_CALL1_ZONE_MAX_LENGTH = 64
_CALL1_STEP_IDS_MAX_ITEMS = 16
_CALL1_STEP_ID_MAX_LENGTH = 200

_Call1Zone = Annotated[str, Field(min_length=1, max_length=_CALL1_ZONE_MAX_LENGTH)]
_Call1StepId = Annotated[str, Field(min_length=1, max_length=_CALL1_STEP_ID_MAX_LENGTH)]


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


def _sanitize_step(step: NarrativeStep) -> NarrativeStep:
    """Sanitized copy of one step, or the same instance when unchanged."""
    action = _sanitize_non_latin(step.action)
    effect = _sanitize_non_latin(step.effect)
    if action != step.action or effect != step.effect:
        return step.model_copy(update={"action": action, "effect": effect})
    return step


def _sanitize_narrative(narrative: NarrativeLayer) -> NarrativeLayer:
    """Apply non-Latin sanitization to narrative text fields.

    Logs a warning when sanitization modifies any field.
    Returns a (possibly modified) copy of the narrative.

    Uses model_copy(update=...) to preserve projection metadata fields
    (projected_step_ids, canonical_action_kind, etc.) — only prose text
    fields are sanitized (422o.4 blocker #4: no semantic repair).
    """
    title = _sanitize_non_latin(narrative.title)
    summary = _sanitize_non_latin(narrative.summary)
    changed = title != narrative.title or summary != narrative.summary

    new_steps = []
    for step in narrative.steps:
        sanitized = _sanitize_step(step)
        if sanitized is not step:
            changed = True
        new_steps.append(sanitized)

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
# Narrative response validation
# ---------------------------------------------------------------------------


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


def _narrative_steps_from_response(
    resp: Call1Response, selected_steps_by_id: dict[str, dict[str, Any]] | None
) -> list[NarrativeStep]:
    """One narrative step per response step, with canonical realizations."""
    return [
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


def _verify_full_projection_coverage(
    steps: list[NarrativeStep], projection_context: dict[str, Any]
) -> None:
    """Raise when any selected projected step is omitted from the response."""
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


def _map_call1_to_narrative(
    resp: Call1Response,
    projection_context: dict[str, Any] | None = None,
) -> NarrativeLayer:
    selected_steps_by_id = (
        _selected_projection_steps_by_id(projection_context)
        if projection_context is not None
        else None
    )
    steps = _narrative_steps_from_response(resp, selected_steps_by_id)
    if projection_context is not None:
        _verify_full_projection_coverage(steps, projection_context)
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
# Context builder and LLM call
# ---------------------------------------------------------------------------


def _prior_titles_section(prior_titles: list[str] | None) -> str:
    """Previously-generated-titles guidance, or empty."""
    if prior_titles:
        title_list = "\n".join(f"  {i}. {t}" for i, t in enumerate(prior_titles, 1))
        return (
            "\n## Previously Generated Titles (avoid duplication)\n"
            "The following titles have already been used in this generation "
            "run. Your title MUST be substantially different — do not reuse "
            'the same structure, key phrases, or "[Mechanism] for [Goal]" '
            "pattern:\n"
            f"{title_list}\n"
        )
    return ""


def _entry_point_diversity_section(
    pinned_entry_point: str | None,
    preferred_entry_point: str | None,
    excluded_entry_points: list[str] | None,
    prior_titles: list[str] | None,
) -> str:
    """Entry-point and title diversity guidance for the Call 1 prompt."""
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
    diversity_section += _prior_titles_section(prior_titles)
    return diversity_section


def _excluded_pattern_section(excluded_patterns: list[str] | None) -> str:
    """Attack-pattern diversity guidance for the Call 1 prompt."""
    if excluded_patterns:
        return (
            "\n## Attack Pattern Diversity\n"
            "Avoid these attack patterns which are already well-represented "
            "in this batch:\n"
            f"- Overused patterns: {', '.join(excluded_patterns)}\n"
            "Find a DIFFERENT attack approach. Use a different vulnerability "
            "mechanism, a different propagation path, or a different impact "
            "chain. Creativity and variety are essential.\n"
        )
    return ""


def _actor_grounding_section(actor_profile: ActorProfile | None) -> str:
    """Actor-profile grounding block for the narrative prompt."""
    if actor_profile is None:
        return ""
    resources_str = ", ".join(actor_profile.resources)
    return (
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


def _goal_guidance_section(actor_profile: ActorProfile | None) -> str:
    """Attack-goal SHOULD block for the narrative prompt."""
    if actor_profile is None or not actor_profile.goal_category:
        return ""
    return (
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


def _novice_diversity_priority(
    diversity_section: str, actor_profile: ActorProfile | None
) -> str:
    """Append the novice capability-level priority note when applicable."""
    if (
        diversity_section
        and actor_profile is not None
        and actor_profile.capability_level == "novice"
    ):
        return diversity_section + (
            "\n\n**Capability-level priority:** The actor is a NOVICE. "
            "Diversity constraints are secondary to capability-level constraints. "
            "Do NOT generate a complex attack just because simpler patterns have "
            "been excluded. Instead, use a DIFFERENT simple pattern or a different "
            "angle on the same simple technique."
        )
    return diversity_section


def _technique_framing_for_narrative(
    pinned_technique_ids: list[str] | None, seed: ScenarioSeed
) -> str:
    """Technique framing: hard pin when pinned, else seed guidance."""
    if pinned_technique_ids:
        return (
            "You MUST use these ATLAS technique(s) in the narrative. "
            "Reference them in narrative step actions and annotate with the ID "
            "in square brackets, e.g. [AML.T0054]. This is a hard constraint.\n"
        )
    if seed.atlas_technique_ids:
        return (
            "Reference these techniques in narrative step actions where applicable. "
            "Annotate technique usage with the ID in square brackets, "
            "e.g. [AML.T0054].\n"
        )
    return ""


def _prompt_text(feedback: str | None) -> str:
    """Feedback or fallback text for the prompt template."""
    return feedback or ""


def _structural_section(
    excluded_structural_patterns: list[str] | None,
) -> str:
    """Structural-pattern diversity guidance, or empty."""
    if excluded_structural_patterns:
        return _format_structural_exclusions(excluded_structural_patterns)
    return ""


def _access_provenance_block(
    actor_profile: ActorProfile | None, profile: CapabilityProfile
) -> str:
    """Structured cmps.6 access provenance block, or empty."""
    if actor_profile is not None and actor_profile.access is not None:
        from asago_scenario_generator.pipeline.generate.names import (
            access_provenance_block_with_names,
        )

        return access_provenance_block_with_names(
            actor_profile.access,
            profile,
            header=(
                "\n## Actor Access Provenance (AUTHORITATIVE — cmps.6)\n"
                "This structured block is authoritative over any advisory "
                "kill-chain wording. The narrative must be consistent with "
                "this evidence.\n"
            ),
        )
    return ""


def _technique_id_list(tech_ids: list[str] | None) -> list[str]:
    """Technique ids for the ontology context, or empty."""
    return list(tech_ids) if tech_ids else []


def _tool_inventory_list(tool_inventory: list[str]) -> list[str]:
    """Tool inventory for the prompt template, or empty."""
    return tool_inventory or []


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
    diversity_section = _entry_point_diversity_section(
        pinned_entry_point, preferred_entry_point, excluded_entry_points, prior_titles
    )

    # Build attack pattern diversity section
    pattern_section = _excluded_pattern_section(excluded_patterns)

    # Build structural pattern diversity section
    structural_section = _structural_section(excluded_structural_patterns)

    # Build actor profile section for narrative grounding
    actor_section = _actor_grounding_section(actor_profile)

    # Build structured access provenance block (cmps.6) — using names (Phase 3)
    access_provenance_block = _access_provenance_block(actor_profile, profile)

    # Build goal category section for narrative grounding
    goal_section = _goal_guidance_section(actor_profile)

    # Resolve creativity-vs-simplicity conflict for novice actors
    diversity_section = _novice_diversity_priority(diversity_section, actor_profile)

    # Build technique context — pin to specific techniques if set
    tech_ids_for_narrative = (
        pinned_technique_ids if pinned_technique_ids else seed.atlas_technique_ids
    )
    technique_context_1 = _build_technique_context_block(tech_ids_for_narrative)
    technique_framing_1 = _technique_framing_for_narrative(pinned_technique_ids, seed)

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
        entry_point_name=_prompt_text(pinned_entry_point),
        entry_point_direction=pinned_entry_point_direction,
        zones=profile.zones_active,
        technique_ids=_technique_id_list(tech_ids_for_narrative),
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
        "tool_inventory": _tool_inventory_list(profile.tool_inventory),
        "kill_chain": seed.kill_chain,
        "access_feedback": _prompt_text(access_feedback),
        "realization_feedback": _prompt_text(realization_feedback),
        "projection_context": humanized_projection,
        "projection_alignment_rows": alignment_rows,
    }


def _responsible_step_for(
    current: NarrativeAccessRealization | None, step_numbers: set[int]
) -> int:
    """Canonical responsible step: the current one when valid, else the first."""
    if current is not None and current.responsible_step_number in step_numbers:
        return current.responsible_step_number
    return min(step_numbers)


def _access_realization_from_path(
    canonical_ingress: str, responsible_step: int, path: dict[str, Any] | None
) -> NarrativeAccessRealization:
    """Typed realization derived from the projected source-influence path."""
    if path is None:
        return NarrativeAccessRealization(
            initial_entry_point_id=canonical_ingress,
            responsible_step_number=responsible_step,
        )
    return NarrativeAccessRealization(
        initial_entry_point_id=canonical_ingress,
        responsible_step_number=responsible_step,
        influence_source=path["source_id"],
        influence_source_kind=path["source_identity_kind"],
        influence_source_id=path["source_id"],
        trust_boundary_id=path["boundary_id"],
    )


def _apply_path_fields(
    current: NarrativeAccessRealization, path: dict[str, Any] | None
) -> None:
    """Overwrite the typed relation fields from the projected path."""
    current.influence_source = path["source_id"] if path else None
    current.influence_source_kind = path["source_identity_kind"] if path else None
    current.influence_source_id = path["source_id"] if path else None
    current.trust_boundary_id = path["boundary_id"] if path else None


def _single_source_path(paths: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The lone projected source-influence path, or None."""
    if len(paths) > 1:
        raise ValueError("projection context contains multiple source-influence paths")
    return paths[0] if paths else None


def _apply_projection_access_realization(
    narrative: NarrativeLayer,
    projection_context: dict[str, Any] | None,
) -> None:
    """Replace model-selected access IDs with the projected typed relation."""
    if projection_context is None:
        return
    canonical_ingress = projection_context["canonical_ingress"]["entry_point_id"]
    path = _single_source_path(projection_context.get("source_influence_paths", []))
    current = narrative.access_realization
    step_numbers = {step.step_number for step in narrative.steps}
    responsible_step = _responsible_step_for(current, step_numbers)
    if current is None:
        current = _access_realization_from_path(
            canonical_ingress, responsible_step, path
        )
        narrative.access_realization = current
    current.initial_entry_point_id = canonical_ingress
    _apply_path_fields(current, path)


def _normalize_echoed_step_ids(content: Any, canonical_ids: list[str]) -> None:
    """Normalize one response's echoed transport shapes to canonical IDs."""
    for step in content.steps:
        step.projected_step_ids = normalize_projected_step_ids(
            step.projected_step_ids, canonical_ids
        )


def _normalize_legacy_step_ids(
    result: LLMResult, projection_context: dict[str, Any] | None
) -> None:
    """Normalize echoed legacy transport step-ID shapes to canonical IDs."""
    if projection_context is not None:
        _normalize_echoed_step_ids(
            result.content, projection_context.get("selected_step_ids", [])
        )


def _compile_legacy_narrative(
    result: LLMResult, projection_context: dict[str, Any] | None
) -> NarrativeLayer:
    """Compile a scripted historical response into a narrative layer."""
    # Scripted fixtures using the historical response remain supported
    # while live projected requests advertise only NarrativeDraftV3.
    # Normalize echoed step-ID transport shapes to canonical IDs before
    # deriving deterministic realizations.
    _normalize_legacy_step_ids(result, projection_context)
    return _map_call1_to_narrative(result.content, projection_context)


def _enforce_narrative_zones(
    narrative: NarrativeLayer,
    profile: CapabilityProfile,
    projection_context: dict[str, Any] | None,
) -> NarrativeLayer:
    """Enforce zone boundaries against the projection or the bare profile."""
    if projection_context is not None:
        # Stage-specific boundary validation: literal 'outside' is allowed
        # only for steps mapping only outside-boundary projected steps;
        # inside/crossing steps must use active Schneider zones.
        boundary_by_id = projected_boundary_by_id(
            projection_context.get("selected_steps", [])
        )
        return enforce_narrative_projection_zones(
            narrative, profile.zones_active, boundary_by_id
        )
    return _enforce_zones_narrative(narrative, profile.zones_active)


def _resolve_initial_entry_point_name(
    realization: Any, profile: CapabilityProfile
) -> None:
    """Resolve a human-readable entry-point name to its canonical ID."""
    from asago_scenario_generator.pipeline.generate.names import (
        resolve_name_to_entry_point_id,
    )

    resolved = resolve_name_to_entry_point_id(
        realization.initial_entry_point_id, profile
    )
    if resolved is not None:
        realization.initial_entry_point_id = resolved


def _resolve_influence_source_name(
    realization: Any, profile: CapabilityProfile
) -> None:
    """Resolve a human-readable influence-source name to its canonical ID."""
    from asago_scenario_generator.pipeline.generate.names import (
        resolve_name_to_entry_point_id,
    )

    if realization.influence_source is None:
        return
    resolved = resolve_name_to_entry_point_id(realization.influence_source, profile)
    if resolved is not None:
        realization.influence_source = resolved


def _resolve_trust_boundary_name(realization: Any, profile: CapabilityProfile) -> None:
    """Resolve a human-readable trust-boundary name to its canonical ID."""
    from asago_scenario_generator.pipeline.generate.names import (
        resolve_name_to_trust_boundary_id,
    )

    if realization.trust_boundary_id is None:
        return
    resolved = resolve_name_to_trust_boundary_id(realization.trust_boundary_id, profile)
    if resolved is not None:
        realization.trust_boundary_id = resolved


def _resolve_narrative_access_names(
    narrative: NarrativeLayer, profile: CapabilityProfile
) -> None:
    """Resolve human-readable names to canonical hex IDs (Phase 3)."""
    if narrative.access_realization is None:
        return
    realization = narrative.access_realization
    _resolve_initial_entry_point_name(realization, profile)
    _resolve_influence_source_name(realization, profile)
    _resolve_trust_boundary_name(realization, profile)


def _narrative_from_draft_or_legacy(
    draft_context: NarrativeDraftContext | None,
    result: LLMResult,
    projection_context: dict[str, Any] | None,
) -> NarrativeLayer:
    """Compile a draft response, or the legacy response shape."""
    if isinstance(result.content, (NarrativeDraftV2, NarrativeDraftV3)):
        assert draft_context is not None
        return compile_narrative_draft(draft_context, result.content)
    return _compile_legacy_narrative(result, projection_context)


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
    narrative = _narrative_from_draft_or_legacy(
        draft_context, result, projection_context
    )
    # Normalize echoed step-ID transport shapes to canonical IDs before
    # deriving deterministic realizations. Unknown, ambiguous, or duplicate
    # legacy echoes raise a stable ValueError, so no defective narrative is
    # finalized.
    _apply_projection_access_realization(narrative, projection_context)
    narrative = _sanitize_narrative(narrative)
    narrative = _enforce_narrative_zones(narrative, profile, projection_context)

    # Phase 3: resolve human-readable names to canonical hex IDs in
    # the narrative's access_realization.
    _resolve_narrative_access_names(narrative, profile)

    return narrative, result


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-26T17:46:15Z","module_hash":"ca9aeee5bd3ea7cd04620f146e0141a2169971147a95b9ca871d85624dc65afd","source_sha256":"1735e7e4418ae919a0a0cbe739e7b449cac12879712f7b4283f52dc172cff170","functions":[{"id":"func/Call1Step._reject_duplicate_projected_step_ids","name":"_reject_duplicate_projected_step_ids","line":148,"end_line":153,"hash":"9016621860f718063e3c5106d02f1a8d22d7afc1357f3d653afe8b6cfd3acaed"},{"id":"func/build_call1_response_model","name":"build_call1_response_model","line":180,"end_line":213,"hash":"6cc5c69259b02bc742d4c47e9e3ed5c18a62eb836aa669e723ea5e05d52bc012"},{"id":"func/_is_latin_or_common","name":"_is_latin_or_common","line":221,"end_line":233,"hash":"1e2308cb7d63e0460f5ff94ef774fd41e6d370123274fdd13270e0873fe8182c"},{"id":"func/_sanitize_non_latin","name":"_sanitize_non_latin","line":236,"end_line":253,"hash":"57c4179773905e8eb10e521f6553d47a6c68f1454354fbae27c35bea7e7219fb"},{"id":"func/_sanitize_step","name":"_sanitize_step","line":256,"end_line":262,"hash":"320f07093b6809f4ac9b473b614ebd927e1d3ee3b6072f6b2ddf3a62754c4174"},{"id":"func/_sanitize_narrative","name":"_sanitize_narrative","line":265,"end_line":298,"hash":"10bf32afb41abfea9ae0732eac6209513f7d8a7e2b70943dc49e0d0f3188689c"},{"id":"func/_selected_projection_steps_by_id","name":"_selected_projection_steps_by_id","line":306,"end_line":322,"hash":"e7a784d0bfb1a69dcb7524720e694ab3a83c1a1bda5387ce85bef2e8ebb78747"},{"id":"func/_canonical_realizations_for_step","name":"_canonical_realizations_for_step","line":325,"end_line":350,"hash":"eb8c9fb40d81faeac51e450addde58835a980a89a30c06498a9aaf480d9d6fa8"},{"id":"func/_narrative_steps_from_response","name":"_narrative_steps_from_response","line":353,"end_line":372,"hash":"f9da3a2dbd19f242768436d4f4a639fedcb47013d89cf2237259a751b9bbf476"},{"id":"func/_verify_full_projection_coverage","name":"_verify_full_projection_coverage","line":375,"end_line":390,"hash":"6df74e647605248af89776e5788162ab5102b683f3ffdd523a8cf2bae95da473"},{"id":"func/_map_call1_to_narrative","name":"_map_call1_to_narrative","line":393,"end_line":415,"hash":"ac2dcb05772a856409a3d67c8fa15a809c9cc96fd3c88fa0feab733060eb3684"},{"id":"func/_prior_titles_section","name":"_prior_titles_section","line":423,"end_line":435,"hash":"624b7b7bff860722f7d403b92cb992a7beed70346945fded6a1353a8f9df5373"},{"id":"func/_entry_point_diversity_section","name":"_entry_point_diversity_section","line":438,"end_line":468,"hash":"8011a7fbf6b82473fb2d72dd5ff17153d54bd0484ff7af99ce4a9b2709fdd96a"},{"id":"func/_excluded_pattern_section","name":"_excluded_pattern_section","line":471,"end_line":483,"hash":"b6027fbce2cbb4482d19362b5642692ca79415bb930a4c5e00d343b031ae20a7"},{"id":"func/_actor_grounding_section","name":"_actor_grounding_section","line":486,"end_line":504,"hash":"e113da7da3abe607128a2ea69c2a1e221a3ba2f9b78bdcc03e3d381c6db6bf82"},{"id":"func/_goal_guidance_section","name":"_goal_guidance_section","line":507,"end_line":522,"hash":"4200495824162a93ab111cc9926054221bb7406e1aad01ce2f41e8824757b8e0"},{"id":"func/_novice_diversity_priority","name":"_novice_diversity_priority","line":525,"end_line":541,"hash":"a4ca17e2ee023c8799c514bdfaf7a473396de46918bfa67883ed8d6cc1abf55b"},{"id":"func/_technique_framing_for_narrative","name":"_technique_framing_for_narrative","line":544,"end_line":560,"hash":"422e2dd560616cb5a969d5bbef47bac9d31a59976fea521664a137c0def4d20c"},{"id":"func/_prompt_text","name":"_prompt_text","line":563,"end_line":565,"hash":"4e42f6de9af652d0b83cc5d2ccd7e0ed3dc5d61db9512f19c0b0fb8df39a5393"},{"id":"func/_structural_section","name":"_structural_section","line":568,"end_line":574,"hash":"8dee84ecef969c433a425d8e618b75d7d197e5c88198068e0495ec68c3f18136"},{"id":"func/_access_provenance_block","name":"_access_provenance_block","line":577,"end_line":596,"hash":"a6d7e6352073fe78e5e086b852f3375ed5ea97f6dd55aff06a532a1baeb9b3a3"},{"id":"func/_technique_id_list","name":"_technique_id_list","line":599,"end_line":601,"hash":"b5898eaa285367f4708c873610be1ae00029bfaf4d67c6131c4ab8d793caf80a"},{"id":"func/_tool_inventory_list","name":"_tool_inventory_list","line":604,"end_line":606,"hash":"fcde35660fef3a780a43da902cf9dc8d1e81434231ed1a149d00a5d7cd0e1e17"},{"id":"func/build_call1_context","name":"build_call1_context","line":609,"end_line":727,"hash":"053ca19472a65af3463c467e669d00d53f35e333d273e506be56667a736e0759"},{"id":"func/_responsible_step_for","name":"_responsible_step_for","line":730,"end_line":736,"hash":"f7d2529027667aa54c4d43c4568eb0008587e1be9d1babcd0aa1ffff82dabce7"},{"id":"func/_access_realization_from_path","name":"_access_realization_from_path","line":739,"end_line":755,"hash":"afe63eac3d89de37be3352583fecf47fa208116de2214e3177175845cd1af6cd"},{"id":"func/_apply_path_fields","name":"_apply_path_fields","line":758,"end_line":765,"hash":"5aeab73a9691696547a24282f9cd632f8dbbcdda2d664a10e02025c548b46489"},{"id":"func/_single_source_path","name":"_single_source_path","line":768,"end_line":772,"hash":"2ee22384e9fce2a9ecc07878a05eac16188773126d1642c824b70f286a9b6d86"},{"id":"func/_apply_projection_access_realization","name":"_apply_projection_access_realization","line":775,"end_line":793,"hash":"dba538ef9a0b061f02a7d6a2b3b2afbdc538652d951e1ef4ac8a14615f04b85d"},{"id":"func/_normalize_echoed_step_ids","name":"_normalize_echoed_step_ids","line":796,"end_line":801,"hash":"92779b577c23a3b04c3c61030014535450260afec00e48680c530ff7c59fbf74"},{"id":"func/_normalize_legacy_step_ids","name":"_normalize_legacy_step_ids","line":804,"end_line":811,"hash":"d90b486016ba755546bcd4bacf8cd6fc7d2aa0dc9338ff2395b139df429566e3"},{"id":"func/_compile_legacy_narrative","name":"_compile_legacy_narrative","line":814,"end_line":823,"hash":"a3cdbfbe2eb80cd3ef0a65ca55a7c76b2d0ac2a4e41dfa4142ae58d98fb7fc85"},{"id":"func/_enforce_narrative_zones","name":"_enforce_narrative_zones","line":826,"end_line":842,"hash":"8d4b8c0d4a79e5c9c557b91a0688e62daaa28c9332d519c7103ad41eadacec2e"},{"id":"func/_resolve_initial_entry_point_name","name":"_resolve_initial_entry_point_name","line":845,"end_line":857,"hash":"e5e0446f02b6ee94468b0185003d729039e13e504a82ee9ae09027c5c82ff6ca"},{"id":"func/_resolve_influence_source_name","name":"_resolve_influence_source_name","line":860,"end_line":872,"hash":"17f533dc30b748d0ce240ec39f7ccec12a1cb0c2ed720bbe7942d2899feff389"},{"id":"func/_resolve_trust_boundary_name","name":"_resolve_trust_boundary_name","line":875,"end_line":885,"hash":"d9a62c041066f1cb68832c027af3140c23b8d34d15d7052c020dec6ada2938cd"},{"id":"func/_resolve_narrative_access_names","name":"_resolve_narrative_access_names","line":888,"end_line":897,"hash":"ba0141a83cc8182198f127fe05d5bd84e1f0a0e343f15bfd150b52c363f768e7"},{"id":"func/_narrative_from_draft_or_legacy","name":"_narrative_from_draft_or_legacy","line":900,"end_line":909,"hash":"6900786e337a157ada11bff0156bc1d2ec8a10ee55b6cbc308d959b8b4972cb8"},{"id":"func/_call_narrative","name":"_call_narrative","line":912,"end_line":1015,"hash":"b118575b8bd89cd23d866b4c1f4e8fe29d635df638c74fcb5fa340c43780ba0f"}]}
# mutate4py-manifest-end
