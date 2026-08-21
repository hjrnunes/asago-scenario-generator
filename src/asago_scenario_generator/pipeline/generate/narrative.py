"""Call 1: Narrative generation logic."""

from __future__ import annotations

import logging
import re
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, Field

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
_CALL1_REALIZATIONS_MAX_ITEMS = 16


class Call1Step(BaseModel):
    step_number: int
    zone: str = Field(max_length=_CALL1_ZONE_MAX_LENGTH)
    action: str = Field(max_length=_CALL1_PROSE_MAX_LENGTH)
    effect: str = Field(max_length=_CALL1_PROSE_MAX_LENGTH)
    control_point: str | None = Field(default=None, max_length=_CALL1_ZONE_MAX_LENGTH)
    # --- Projection traceability fields (422o.4) ---
    # Required on every step; the LLM receives the IDs as opaque
    # constraints and must echo them back.  No defaults -- a missing
    # field is a typed violation, not an acceptable empty value.
    projected_step_ids: tuple[str, ...] = Field(
        min_length=1,
        max_length=_CALL1_STEP_IDS_MAX_ITEMS,
        description=(
            "Canonical projected step IDs that this narrative step realizes. "
            "Must be echoed from the projection context constraints."
        ),
    )
    realizations: tuple[ProjectedStepRealization, ...] = Field(
        default=(),
        max_length=_CALL1_REALIZATIONS_MAX_ITEMS,
        description=(
            "Per-projected-step canonical realization records.  Ignored "
            "from LLM output — post-processing derives these "
            "deterministically from the projection context."
        ),
    )


class Call1Response(BaseModel):
    title: str = Field(max_length=_CALL1_TITLE_MAX_LENGTH)
    summary: str = Field(max_length=_CALL1_PROSE_MAX_LENGTH)
    entry_point: str = Field(max_length=_CALL1_ENTRY_MAX_LENGTH)
    zone_sequence: list[str] = Field(
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


def _map_call1_to_narrative(resp: Call1Response) -> NarrativeLayer:
    steps = [
        NarrativeStep(
            step_number=s.step_number,
            zone=s.zone,
            action=s.action,
            effect=s.effect,
            control_point=s.control_point,
            projected_step_ids=s.projected_step_ids,
            realizations=s.realizations,
        )
        for s in resp.steps
    ]
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


# ---------------------------------------------------------------------------
# Post-processing: deterministic realization derivation
# ---------------------------------------------------------------------------


def _fill_call1_realizations(
    response: Call1Response,
    projection_context: dict[str, Any] | None,
) -> None:
    """Derive realizations deterministically and set them on each Call1Step.

    Ignores whatever the LLM returned for realizations.  For each step,
    looks up the canonical realization record from the projection context
    (which was built by ``_build_projection_context`` using
    ``derive_step_realization``).

    Mutates ``response.steps`` in place.
    """
    if projection_context is None:
        return

    step_data_by_id: dict[str, dict[str, Any]] = {
        sd["step_id"]: sd for sd in projection_context.get("selected_steps", [])
    }

    for step in response.steps:
        realizations: list[ProjectedStepRealization] = []
        for psid in step.projected_step_ids:
            sd = step_data_by_id.get(psid)
            if sd is None:
                logger.warning(
                    "Call1Step %d references unknown projected step '%s' "
                    "— cannot derive realization",
                    step.step_number,
                    psid,
                )
                continue
            realizations.append(
                ProjectedStepRealization.model_validate(sd["realization"])
            )
        step.realizations = tuple(realizations)


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
    projection_context: dict[str, Any] | None = None,
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

    user_prompt = render_prompt("call1_user.j2", **ctx)
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
        ),
        user_prompt=user_prompt,
        response_format=Call1Response,
    )
    # Post-processing: normalize echoed step-ID transport shapes to the
    # canonical IDs before deterministic realization derivation.  Unknown,
    # ambiguous, or duplicate echoes raise a stable ValueError here so no
    # defective narrative is finalized.
    if projection_context is not None:
        canonical_ids = projection_context.get("selected_step_ids", [])
        for step in result.content.steps:
            step.projected_step_ids = normalize_projected_step_ids(
                step.projected_step_ids, canonical_ids
            )
    # Post-processing: derive realizations deterministically from
    # the projection context, ignoring whatever the LLM returned.
    _fill_call1_realizations(result.content, projection_context)
    narrative = _map_call1_to_narrative(result.content)
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
