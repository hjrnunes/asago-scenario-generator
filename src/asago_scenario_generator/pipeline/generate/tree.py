"""Call 2: Attack Tree generation logic."""

from __future__ import annotations

import logging
import json
from collections import Counter
from typing import Any

from asago_scenario_generator.data.atlas import TECHNIQUE_ZONE_CONSTRAINTS
from asago_scenario_generator.llm.client import LLMClient, LLMResult
from asago_scenario_generator.models.attack_tree import (
    AttackTree,
    AttackTreeNode,
    GateType,
)
from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    is_attacker_accessible_ingress,
)
from asago_scenario_generator.models.scenario import (
    ActorProfile,
    CallName,
    NarrativeLayer,
)
from asago_scenario_generator.pipeline.generate.alignment import (
    derive_projection_alignment_rows_from_context,
)
from asago_scenario_generator.pipeline.generate.constants import compute_leaf_budget
from asago_scenario_generator.pipeline.generate.ontology import (
    _build_ontology_context,
    _build_technique_context_block,
    _lookup_entry_point_controllability,
    _lookup_entry_point_direction,
)
from asago_scenario_generator.pipeline.generate.tree_transport import (
    _parse_attack_tree_yaml,
)
from asago_scenario_generator.pipeline.generate.tree_validation import (
    _validate_pinned_ingress,
    _validate_tree_against_projection,
)
from asago_scenario_generator.pipeline.generate.zones import (
    _enforce_zones_attack_tree,
    active_narrative_zones,
)
from asago_scenario_generator.pipeline.seeds import ScenarioSeed
from asago_scenario_generator.prompts import render_prompt

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Post-generation threat_id cross-reference validation
# ---------------------------------------------------------------------------


def _collect_threat_ids_from_tree(node: AttackTreeNode) -> list[str | None]:
    """Collect all threat_id values from an attack tree (depth-first)."""
    ids: list[str | None] = [node.threat_id]
    if node.children:
        for child in node.children:
            ids.extend(_collect_threat_ids_from_tree(child))
    return ids


def _warn_dominant_threat_id_crossref(
    tree: AttackTree,
    parent_threat_id: str,
    scenario_id: str,
) -> None:
    """Log a warning if a dominant cross-ref threat_id differs from the parent.

    Flags trees where >50% of nodes share the same threat_id AND that
    threat_id differs from the scenario's parent threat. This catches the
    "everything is T1" pattern where the LLM defaults to tagging most
    nodes with T1 regardless of the actual threat context.

    This is warning-level only -- it does NOT reject or modify the tree.
    """
    all_ids = _collect_threat_ids_from_tree(tree.root)
    # Only consider nodes that actually have a threat_id set
    non_null_ids = [tid for tid in all_ids if tid is not None]

    if not non_null_ids:
        return

    counts = Counter(non_null_ids)
    dominant_id, dominant_count = counts.most_common(1)[0]

    total_with_id = len(non_null_ids)
    ratio = dominant_count / total_with_id

    if ratio > 0.5 and dominant_id != parent_threat_id:
        logger.warning(
            "threat_id cross-ref anomaly in %s: %.0f%% of nodes (%d/%d) "
            "tagged as %s but parent threat is %s",
            scenario_id,
            ratio * 100,
            dominant_count,
            total_with_id,
            dominant_id,
            parent_threat_id,
        )


# ---------------------------------------------------------------------------
# YAML sanitization
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Tree skeleton builder
# ---------------------------------------------------------------------------


def _match_zone_for_technique(
    narrative: NarrativeLayer,
    tid: str,
    tname: str,
    fallback_zone: str,
) -> str:
    """Zone of the first narrative step mentioning the technique, else fallback."""
    tid_lower = tid.lower()
    tname_lower = tname.lower()
    for step in narrative.steps:
        haystack = f"{step.action} {step.effect}".lower()
        if tid_lower in haystack or tname_lower in haystack:
            return step.zone
    return fallback_zone


def _constrain_zone_to_technique(zone: str, tid: str) -> str:
    """Pick the first valid zone when the narrative-derived zone is invalid."""
    valid_zones = TECHNIQUE_ZONE_CONSTRAINTS.get(tid)
    if valid_zones is not None and zone not in valid_zones:
        return min(valid_zones)
    return zone


def _build_tree_skeleton(
    narrative: NarrativeLayer,
    pinned_technique_ids: list[str],
    pinned_technique_names: list[str],
) -> list[dict[str, str]]:
    """Build mandatory leaf-node specs from pinned techniques and narrative.

    Each pinned technique is matched against the narrative steps by checking
    whether the technique ID or name appears in the step's ``action`` or
    ``effect`` text (case-insensitive).  The zone of the first matching step
    is assigned to the leaf.  If no step matches, the narrative's first zone
    is used as a fallback.

    Returns a list of dicts, each with keys:
      ``id``, ``technique_id``, ``technique_name``, ``zone``
    """
    if not pinned_technique_ids:
        return []

    # The fallback zone is the first ACTIVE narrative zone — the literal
    # 'outside' zone never becomes a tree skeleton zone.
    active_sequence = active_narrative_zones(narrative.zone_sequence)
    fallback_zone = active_sequence[0] if active_sequence else "input"

    leaves: list[dict[str, str]] = []
    for idx, (tid, tname) in enumerate(
        zip(pinned_technique_ids, pinned_technique_names), start=1
    ):
        matched_zone = _match_zone_for_technique(narrative, tid, tname, fallback_zone)
        zone = _constrain_zone_to_technique(matched_zone, tid)

        leaves.append(
            {
                "id": f"n0.{idx}",
                "technique_id": tid,
                "technique_name": tname,
                "zone": zone,
            }
        )

    return leaves


def _format_skeleton_yaml(skeleton: list[dict[str, str]]) -> str:
    """Format mandatory leaf specs as a YAML block for prompt injection."""
    if not skeleton:
        return ""
    lines = ["## Mandatory Leaf Nodes"]
    lines.append(
        "Your tree MUST include ALL of the leaf nodes listed below with their "
        "exact technique_id and zone. Each mandatory leaf MUST have gate: LEAF "
        "and use a valid node id (e.g. n1.1, n1.2.1). Reassign the placeholder "
        "ids below to match your tree's numbering scheme. You may add up to "
        f"{len(skeleton) + 2} additional connector/setup leaves "
        "beyond these mandatory ones. Organize them into a coherent AND/OR "
        "tree with meaningful labels and gate structure."
    )
    lines.append("")
    lines.append("```yaml")
    lines.append("mandatory_leaves:")
    for leaf in skeleton:
        lines.append(f"  - id: {leaf['id']}")
        lines.append(f"    technique_id: {leaf['technique_id']}")
        lines.append(f"    technique_name: {leaf['technique_name']}")
        lines.append(f"    zone: {leaf['zone']}")
    lines.append("```")
    lines.append("")
    return "\n".join(lines) + "\n"


def _validate_mandatory_leaves(
    tree: AttackTree,
    skeleton: list[dict[str, str]],
    seed_id: str,
) -> None:
    """Warn if any mandatory leaf techniques are missing from the parsed tree.

    This is a post-generation check: it logs warnings but does not reject
    the tree, since this is a first-pass implementation.
    """
    if not skeleton:
        return

    tree_technique_ids = set(tree.collect_technique_ids())
    for leaf in skeleton:
        if leaf["technique_id"] not in tree_technique_ids:
            logger.warning(
                "Mandatory leaf technique %s (%s) missing from attack tree "
                "for seed %s — tree has: %s",
                leaf["technique_id"],
                leaf["technique_name"],
                seed_id,
                sorted(tree_technique_ids),
            )


# ---------------------------------------------------------------------------
# Context builder and LLM call
# ---------------------------------------------------------------------------


def _technique_constraint_text(
    tech_ids_for_tree: list[str],
    pinned_technique_ids: list[str] | None,
) -> str:
    """Prompt constraint text for the ATLAS technique ID policy."""
    if not tech_ids_for_tree:
        return (
            "\n## ATLAS Technique Constraint\n"
            "No ATLAS technique IDs are available for this seed. "
            "Do NOT add technique_id to any node.\n"
        )
    allowed_ids = ", ".join(tech_ids_for_tree)
    if pinned_technique_ids:
        return (
            "\n## ATLAS Technique Constraint\n"
            f"You MUST use this ATLAS technique: {allowed_ids}\n\n"
            "Only assign a technique_id to a node if the technique's "
            "description semantically matches the attack action described "
            "in the node's label.\n"
            "Use ONLY this technique ID on leaf nodes. "
            "Do NOT invent or hallucinate new technique IDs. "
            "If the ID does not fit a particular node, omit technique_id "
            "from that node rather than inventing one.\n"
        )
    return (
        "\n## ATLAS Technique Constraint\n"
        f"Allowed technique_id values: {allowed_ids}\n\n"
        "Only assign a technique_id to a node if the technique's "
        "description semantically matches the attack action described "
        "in the node's label. For example, 'AI Agent Tool Invocation' "
        "should only be used for nodes that involve invoking or "
        "manipulating tools, not for prompt injection or hallucination "
        "steps.\n"
        "Use ONLY these technique IDs on leaf nodes. "
        "Do NOT invent or hallucinate new technique IDs. "
        "If none of these IDs fit a particular node, omit technique_id "
        "from that node rather than inventing one.\n"
    )


def _architecture_section_text(profile: CapabilityProfile | None) -> str:
    """Optional target-system architecture section for Call 2."""
    if profile is None:
        return ""
    entry_point_names = [ep.name for ep in profile.entry_points]
    return (
        "\n## Target System Architecture\n"
        "Every node's zone must be drawn from these active zones.\n"
        f"- Active zones: {profile.zones_active}\n"
        f"- Entry points: {entry_point_names}\n"
    )


def _actor_section_text(actor_profile: ActorProfile | None) -> str:
    """Optional actor profile section for Call 2."""
    if actor_profile is None:
        return ""
    return (
        "\n## Actor Profile\n"
        "The tree's depth and complexity must be commensurate with "
        "the actor's capability level.\n"
        f"- Actor type: {actor_profile.actor_type}\n"
        f"- Capability level: {actor_profile.capability_level}\n"
    )


def _access_provenance_block_text(
    actor_profile: ActorProfile | None,
    profile: CapabilityProfile | None,
) -> str:
    """Structured access provenance block (cmps.6) using names (Phase 3)."""
    if actor_profile is None or actor_profile.access is None:
        return ""
    if profile is None:
        return ""
    from asago_scenario_generator.pipeline.generate.names import (
        access_provenance_block_with_names,
    )

    return access_provenance_block_with_names(actor_profile.access, profile)


def _skeleton_and_section(
    narrative: NarrativeLayer,
    pinned_technique_ids: list[str] | None,
    pinned_technique_names: list[str] | None,
) -> tuple[list[dict[str, str]], str]:
    """Skeleton leaf specs and their YAML prompt section."""
    skeleton: list[dict[str, str]] = []
    if pinned_technique_ids and pinned_technique_names:
        skeleton = _build_tree_skeleton(
            narrative, pinned_technique_ids, pinned_technique_names
        )
    return skeleton, _format_skeleton_yaml(skeleton)


def _ontology_context_for(
    profile: CapabilityProfile | None,
    narrative: NarrativeLayer,
    tech_ids_for_tree: list[str],
) -> dict[str, Any]:
    """Focused ontology context block for this seed."""
    # Use narrative.entry_point for the entry point (it was pinned upstream)
    _tree_ep_direction = (
        _lookup_entry_point_direction(profile, narrative.entry_point)
        if profile
        else None
    )
    _tree_ep_controllability = (
        _lookup_entry_point_controllability(profile, narrative.entry_point)
        if profile
        else None
    )
    return _build_ontology_context(
        entry_point_name=narrative.entry_point or "",
        entry_point_direction=_tree_ep_direction,
        zones=profile.zones_active if profile else [],
        technique_ids=list(tech_ids_for_tree) if tech_ids_for_tree else [],
        entry_point_controllability=_tree_ep_controllability,
    )


def _ensure_accessible_pinned_entry(
    profile: CapabilityProfile | None,
    entry_points: list[Any],
    pinned_entry_point_id: str,
) -> None:
    """Reject pinned entry points that are not attacker-accessible (cmps.9)."""
    if profile is None or len(entry_points) != 1:
        return
    active_zones = set(profile.zones_active) if profile.zones_active else set()
    if not is_attacker_accessible_ingress(entry_points[0], active_zones):
        from asago_scenario_generator.pipeline.generate.assembly import (
            GenerationError,
        )

        raise GenerationError(
            f"Pinned entry point '{pinned_entry_point_id}' "
            f"('{entry_points[0].name}') is not an attacker-accessible "
            f"ingress route (output-only, system-controlled, or "
            f"inactive ingress zone)."
        )


def _entry_points_for_template(
    profile: CapabilityProfile | None,
    pinned_entry_point_id: str | None,
) -> list[Any]:
    """Entry points for the template, filtered to the pinned one."""
    entry_points = (profile.entry_points if profile else None) or []
    if pinned_entry_point_id is None:
        return entry_points
    filtered = [
        entry_point
        for entry_point in entry_points
        if entry_point.entry_point_id == pinned_entry_point_id
    ]
    # Defense-in-depth: reject inaccessible pinned entry points before
    # exposing them to the LLM (cmps.9 third review correction 2).
    _ensure_accessible_pinned_entry(profile, filtered, pinned_entry_point_id)
    return filtered


def _pinned_entry_point_name_value(
    pinned_entry_point_id: str | None,
    profile: CapabilityProfile | None,
) -> str | None:
    """Convert the pinned entry point ID to a name for the template (Phase 3)."""
    from asago_scenario_generator.pipeline.generate.names import (
        pinned_entry_point_name_from_id,
    )

    return pinned_entry_point_name_from_id(pinned_entry_point_id, profile)


def _humanized_projection_value(
    projection_context: dict[str, Any] | None,
    profile: CapabilityProfile | None,
) -> dict[str, Any] | None:
    """Humanize the projection context for the template (Phase 3)."""
    if projection_context is not None and profile is not None:
        from asago_scenario_generator.pipeline.generate.names import (
            humanize_projection_context,
        )

        return humanize_projection_context(projection_context, profile)
    return projection_context


def build_call2_context(
    seed: ScenarioSeed,
    narrative: NarrativeLayer,
    use_case: str,
    profile: CapabilityProfile | None = None,
    actor_profile: ActorProfile | None = None,
    pinned_technique_ids: list[str] | None = None,
    pinned_technique_names: list[str] | None = None,
    consistency_feedback: str | None = None,
    pinned_entry_point_id: str | None = None,
    projection_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build prompt template variables for Call 2 (Attack Tree).

    Pure data-preparation function that constructs all template variables
    needed by ``call2_user.j2``.  No LLM calls.

    Returns:
        Dict mapping template variable names to their values.  Also
        includes ``skeleton`` (the raw leaf-node spec list) for use in
        post-generation validation.
    """
    # Pin to specific techniques if set
    tech_ids_for_tree = (
        pinned_technique_ids if pinned_technique_ids else seed.atlas_technique_ids
    )
    technique_context = _build_technique_context_block(tech_ids_for_tree)
    technique_constraint = _technique_constraint_text(
        tech_ids_for_tree, pinned_technique_ids
    )

    # Build optional architecture and actor profile sections for Call 2
    arch_section = _architecture_section_text(profile)
    actor_section = _actor_section_text(actor_profile)
    access_provenance_block = _access_provenance_block_text(actor_profile, profile)

    # Compute concrete leaf budget so the LLM sees the exact number
    technique_count = _technique_count_for(tech_ids_for_tree)
    leaf_budget = compute_leaf_budget(technique_count)

    # Build tree skeleton from pinned techniques (tree-anchored flow)
    skeleton, skeleton_section = _skeleton_and_section(
        narrative, pinned_technique_ids, pinned_technique_names
    )

    # Build focused ontology context block for this seed
    ontology_context = _ontology_context_for(profile, narrative, tech_ids_for_tree)

    entry_points = _entry_points_for_template(profile, pinned_entry_point_id)
    pinned_entry_point_name = _pinned_entry_point_name_value(
        pinned_entry_point_id, profile
    )

    # Humanize projection context for the template (Phase 3)
    humanized_projection = _humanized_projection_value(projection_context, profile)

    # Validator-derived compact alignment table (one row per selected step).
    alignment_rows = derive_projection_alignment_rows_from_context(humanized_projection)

    return {
        "seed": seed,
        "use_case": use_case,
        "arch_section": arch_section,
        "actor_section": actor_section,
        "access_provenance_block": access_provenance_block,
        "technique_context": technique_context,
        "technique_constraint": technique_constraint,
        "narrative": narrative,
        "technique_count": technique_count,
        "leaf_budget": leaf_budget,
        "skeleton_section": skeleton_section,
        "ontology_context": ontology_context,
        "tool_inventory": _tool_inventory_for(profile),
        "external_integrations": _external_integrations_for(profile),
        "entry_points": entry_points,
        "pinned_entry_point_name": pinned_entry_point_name,
        "kill_chain": seed.kill_chain,
        "consistency_feedback": consistency_feedback,
        # Non-template data for post-generation validation
        "skeleton": skeleton,
        "projection_context": humanized_projection,
        "projection_alignment_rows": alignment_rows,
    }


# ---------------------------------------------------------------------------
# Post-processing: deterministic realization derivation for tree leaves
# ---------------------------------------------------------------------------


def _derive_leaf_realizations(
    node: AttackTreeNode,
    step_data_by_id: dict[str, dict[str, Any]],
) -> tuple[Any, ...]:
    """Derive canonical realization records for one leaf's projected steps."""
    from asago_scenario_generator.models.realization import ProjectedStepRealization

    realizations: list[ProjectedStepRealization] = []
    for psid in node.projected_step_ids:
        sd = step_data_by_id.get(psid)
        if sd is None:
            logger.warning(
                "Tree leaf '%s' references unknown projected step "
                "'%s' — cannot derive realization",
                node.id,
                psid,
            )
            continue
        realizations.append(ProjectedStepRealization.model_validate(sd["realization"]))
    return tuple(realizations)


def _fill_realization_node(
    node: AttackTreeNode,
    step_data_by_id: dict[str, dict[str, Any]],
) -> None:
    """Set realizations on one node and recurse into its children."""
    if node.gate == GateType.LEAF:
        if not node.projected_step_ids:
            # External preconditions and unmapped leaves stay empty.
            node.realizations = ()
            return
        node.realizations = _derive_leaf_realizations(node, step_data_by_id)
        return
    if node.children:
        for child in node.children:
            _fill_realization_node(child, step_data_by_id)


def _fill_tree_realizations(
    tree: AttackTree,
    projection_context: dict[str, Any] | None,
) -> None:
    """Derive realizations deterministically and set them on each tree leaf.

    Ignores whatever the LLM returned for realizations.  For each
    security-bearing leaf (non-external_precondition with projected_step_ids),
    looks up the canonical realization record from the projection context.

    Mutates tree nodes in place.
    """
    if projection_context is None:
        return

    step_data_by_id: dict[str, dict[str, Any]] = {
        sd["step_id"]: sd for sd in projection_context.get("selected_steps", [])
    }

    _fill_realization_node(tree.root, step_data_by_id)


def _validate_and_postprocess_tree(
    tree: AttackTree,
    profile: CapabilityProfile | None,
    pinned_entry_point_id: str | None,
    skeleton: list[dict[str, str]],
    seed: ScenarioSeed,
    projection_context: dict[str, Any] | None,
) -> AttackTree:
    """Run all post-parse validations and zone enforcement on *tree*.

    Raises ``ValueError`` on any violation — no semantic repair.
    Called on both first-attempt and retry outputs so that projection
    validation failures participate in the single retry (422o.4 blocker #2).
    """
    # Post-processing: derive realizations deterministically from the
    # projection context, ignoring whatever the LLM returned.
    _fill_tree_realizations(tree, projection_context)
    if profile is not None:
        id_violations = resolve_action_ids(tree, profile)
        if id_violations:
            raise ValueError(
                "Unresolved typed action IDs in attack tree: "
                + "; ".join(id_violations)
            )
    tree = _enforce_zones_attack_tree(
        tree,
        profile.zones_active if profile else None,
    )
    ingress_violations = _validate_pinned_ingress(tree, pinned_entry_point_id, profile)
    if ingress_violations:
        raise ValueError(
            "Invalid initial ingress in attack tree: " + "; ".join(ingress_violations)
        )
    _validate_mandatory_leaves(tree, skeleton, seed.seed_id)
    _validate_tree_against_projection(tree, projection_context)
    return tree


def _tool_inventory_for(profile: CapabilityProfile | None) -> list[Any]:
    """Tool inventory for the template, or an empty list."""
    return (profile.tool_inventory if profile else None) or []


def _external_integrations_for(profile: CapabilityProfile | None) -> list[Any]:
    """External integrations for the template, or an empty list."""
    return (profile.external_integrations if profile else None) or []


def _technique_count_for(tech_ids_for_tree: list[str]) -> int:
    """Number of pinned techniques for the leaf budget."""
    return len(tech_ids_for_tree) if tech_ids_for_tree else 0


def _semantic_user_prompt(
    use_case: str,
    seed: ScenarioSeed,
    narrative: NarrativeLayer,
    inventory: list[dict[str, Any]],
    consistency_feedback: str | None,
) -> str:
    """User prompt for the semantic grouping flow."""
    user_prompt = (
        f"Use case:\n{use_case}\n\n"
        f"Attack goal: {seed.attack_pattern_name}\n"
        f"Narrative title: {narrative.title}\n"
        f"Narrative summary: {narrative.summary}\n\n"
        "Canonical leaf inventory (respond with handles only):\n"
        f"{json.dumps(inventory, ensure_ascii=False, indent=2)}\n"
    )
    if consistency_feedback:
        user_prompt += f"\nCorrection required:\n{consistency_feedback}\n"
    return user_prompt


def _semantic_draft_flow(
    seed: ScenarioSeed,
    narrative: NarrativeLayer,
    use_case: str,
    consistency_feedback: str | None,
    projection_context: dict[str, Any],
    profile: CapabilityProfile,
) -> tuple[Any, Any, list[dict[str, str]], str, str] | None:
    """Build the semantic grouping prompt flow, or None when unavailable."""
    if projection_context is None or profile is None:
        return None
    from asago_scenario_generator.pipeline.generate.tree_semantics import (
        build_attack_tree_draft_response_model,
        derive_canonical_leaf_specs,
    )

    semantic_leaf_specs = derive_canonical_leaf_specs(
        projection_context, narrative, profile
    )
    response_format = build_attack_tree_draft_response_model(
        [spec.leaf_handle for spec in semantic_leaf_specs]
    )
    system_prompt = (
        "You author the semantic grouping of one concrete attack tree. "
        "Return only the structured response. Partition every supplied "
        "leaf handle into one or more ordered groups, use every handle "
        "exactly once, and preserve the listed order across groups. You "
        "control the root and group labels and descriptions. Never emit "
        "nested nodes, canonical IDs, actions, zones, "
        "techniques, or realizations; the compiler owns them."
    )
    inventory = [
        {
            "handle": spec.leaf_handle,
            "meaning": spec.label,
            "action_kind": spec.action.kind,
            "position": index,
        }
        for index, spec in enumerate(semantic_leaf_specs)
    ]
    user_prompt = _semantic_user_prompt(
        use_case, seed, narrative, inventory, consistency_feedback
    )
    return semantic_leaf_specs, response_format, [], system_prompt, user_prompt


def _legacy_prompt_flow(
    seed: ScenarioSeed,
    narrative: NarrativeLayer,
    use_case: str,
    profile: CapabilityProfile | None,
    actor_profile: ActorProfile | None,
    pinned_technique_ids: list[str] | None,
    pinned_technique_names: list[str] | None,
    consistency_feedback: str | None,
    pinned_entry_point_id: str | None,
    projection_context: dict[str, Any] | None,
) -> tuple[list[dict[str, str]], str, str]:
    """Build the compatibility prompt flow variables."""
    ctx = build_call2_context(
        seed=seed,
        narrative=narrative,
        use_case=use_case,
        profile=profile,
        actor_profile=actor_profile,
        pinned_technique_ids=pinned_technique_ids,
        pinned_technique_names=pinned_technique_names,
        consistency_feedback=consistency_feedback,
        pinned_entry_point_id=pinned_entry_point_id,
        projection_context=projection_context,
    )
    skeleton = ctx["skeleton"]
    system_prompt = render_prompt(
        "call2_system.j2",
        zones_active=profile.zones_active if profile else [],
        tool_inventory=ctx["tool_inventory"],
        external_integrations=ctx["external_integrations"],
        entry_points=ctx["entry_points"],
        pinned_entry_point_name=ctx.get("pinned_entry_point_name"),
    )
    user_prompt = render_prompt("call2_user.j2", **ctx)
    return skeleton, system_prompt, user_prompt


def _compile_tree_response(
    content: Any,
    semantic_leaf_specs: Any,
    seed: ScenarioSeed,
    projection_context: dict[str, Any] | None,
) -> AttackTree:
    """Compile an LLM response into an attack tree."""
    if semantic_leaf_specs is not None and not isinstance(content, str):
        from asago_scenario_generator.pipeline.generate.tree_semantics import (
            AttackTreeDraftV2,
            AttackTreeDraftV3,
            compile_flat_attack_tree_draft,
            compile_attack_tree_draft,
        )

        if isinstance(content, AttackTreeDraftV3):
            return compile_flat_attack_tree_draft(
                seed_id=seed.seed_id,
                goal=seed.attack_pattern_name,
                draft=content,
                leaf_specs=semantic_leaf_specs,
                threat_id=seed.threat_id,
            )
        draft = (
            content
            if isinstance(content, AttackTreeDraftV2)
            else AttackTreeDraftV2.model_validate(content)
        )
        return compile_attack_tree_draft(
            seed_id=seed.seed_id,
            goal=seed.attack_pattern_name,
            draft=draft,
            leaf_specs=semantic_leaf_specs,
            threat_id=seed.threat_id,
        )
    # Compatibility for recorded/scripted legacy YAML responses. New
    # provider requests always use AttackTreeDraftV2 when projection
    # context is available.
    return _parse_attack_tree_yaml(content, seed, projection_context)


def _invoke_attack_tree(
    client: LLMClient,
    system_prompt: str,
    user_prompt: str,
    response_format: Any,
    temperature: float | None,
    max_completion_tokens: int | None,
) -> LLMResult:
    """Perform exactly one LLM invocation for an attack-tree attempt."""
    try:
        return client.complete(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_format=response_format,
            temperature=temperature,
            max_completion_tokens=max_completion_tokens,
        )
    except Exception as exc:
        from asago_scenario_generator.pipeline.generate.stages import (
            stage_attempt_failure,
        )

        raise stage_attempt_failure(
            CallName.attack_tree,
            exc,
            phase="invocation",
            invoked=True,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        ) from exc


def _postprocess_attack_tree_response(
    result: LLMResult,
    semantic_leaf_specs: Any,
    seed: ScenarioSeed,
    projection_context: dict[str, Any] | None,
    profile: CapabilityProfile | None,
    pinned_entry_point_id: str | None,
    skeleton: list[dict[str, str]],
    system_prompt: str,
    user_prompt: str,
) -> AttackTree:
    """Compile and validate the attack tree from one LLM response."""
    try:
        tree = _compile_tree_response(
            result.content, semantic_leaf_specs, seed, projection_context
        )
        return _validate_and_postprocess_tree(
            tree, profile, pinned_entry_point_id, skeleton, seed, projection_context
        )
    except Exception as exc:
        from asago_scenario_generator.pipeline.generate.stages import (
            stage_attempt_failure,
        )

        raise stage_attempt_failure(
            CallName.attack_tree,
            exc,
            phase="post_response",
            invoked=True,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            result=result,
            raw_response=result.content,
        ) from exc


def _call_attack_tree_once(
    seed: ScenarioSeed,
    narrative: NarrativeLayer,
    client: LLMClient,
    use_case: str,
    profile: CapabilityProfile | None = None,
    actor_profile: ActorProfile | None = None,
    pinned_technique_ids: list[str] | None = None,
    pinned_technique_names: list[str] | None = None,
    consistency_feedback: str | None = None,
    completion_length_feedback: str | None = None,
    temperature: float | None = None,
    max_completion_tokens: int | None = None,
    pinned_entry_point_id: str | None = None,
    projection_context: dict[str, Any] | None = None,
) -> tuple[AttackTree, LLMResult]:
    """Generate and validate one attack-tree attempt (Call 2).

    This is the lifecycle primitive: it performs exactly one LLM invocation
    and never retries.  Retry ownership belongs to the caller.

    ``completion_length_feedback`` (the finalization-owned length-retry
    suffix) is appended verbatim to the end of the rendered user prompt.
    """
    semantic_leaf_specs = None
    response_format: Any = None
    skeleton: list[dict[str, str]] = []
    if projection_context is not None and profile is not None:
        semantic_leaf_specs, response_format, skeleton, system_prompt, user_prompt = (
            _semantic_draft_flow(
                seed,
                narrative,
                use_case,
                consistency_feedback,
                projection_context,
                profile,
            )
        )
    else:
        skeleton, system_prompt, user_prompt = _legacy_prompt_flow(
            seed,
            narrative,
            use_case,
            profile,
            actor_profile,
            pinned_technique_ids,
            pinned_technique_names,
            consistency_feedback,
            pinned_entry_point_id,
            projection_context,
        )
    if completion_length_feedback:
        user_prompt = f"{user_prompt}{completion_length_feedback}"
    result = _invoke_attack_tree(
        client,
        system_prompt,
        user_prompt,
        response_format,
        temperature,
        max_completion_tokens,
    )
    tree = _postprocess_attack_tree_response(
        result,
        semantic_leaf_specs,
        seed,
        projection_context,
        profile,
        pinned_entry_point_id,
        skeleton,
        system_prompt,
        user_prompt,
    )
    return tree, result


def _call_attack_tree(
    seed: ScenarioSeed,
    narrative: NarrativeLayer,
    client: LLMClient,
    use_case: str,
    profile: CapabilityProfile | None = None,
    actor_profile: ActorProfile | None = None,
    pinned_technique_ids: list[str] | None = None,
    pinned_technique_names: list[str] | None = None,
    consistency_feedback: str | None = None,
    pinned_entry_point_id: str | None = None,
    projection_context: dict[str, Any] | None = None,
) -> tuple[AttackTree, LLMResult]:
    """Compatibility Call 2 with the historical internal parse retry.

    The retry preserves the original projection-rich user prompt and appends
    feedback only.  New lifecycle code must use :func:`_call_attack_tree_once`.

    Returns:
        Tuple of (AttackTree, LLMResult).
    """
    ctx = build_call2_context(
        seed=seed,
        narrative=narrative,
        use_case=use_case,
        profile=profile,
        actor_profile=actor_profile,
        pinned_technique_ids=pinned_technique_ids,
        pinned_technique_names=pinned_technique_names,
        consistency_feedback=consistency_feedback,
        pinned_entry_point_id=pinned_entry_point_id,
        projection_context=projection_context,
    )

    skeleton = ctx["skeleton"]

    call2_system = render_prompt(
        "call2_system.j2",
        zones_active=profile.zones_active if profile else [],
        tool_inventory=ctx["tool_inventory"],
        external_integrations=ctx["external_integrations"],
        entry_points=ctx["entry_points"],
        pinned_entry_point_name=ctx.get("pinned_entry_point_name"),
    )

    original_user_prompt = render_prompt("call2_user.j2", **ctx)

    result = client.complete(
        system_prompt=call2_system,
        user_prompt=original_user_prompt,
        response_format=None,
    )

    # First attempt: parse + validate.  Both YAML parse errors and
    # projection/validation failures trigger the single retry.
    try:
        tree = _parse_attack_tree_yaml(result.content, seed, projection_context)
        tree = _validate_and_postprocess_tree(
            tree, profile, pinned_entry_point_id, skeleton, seed, projection_context
        )
    except Exception as first_error:  # noqa: BLE001
        logger.warning("Attack tree first attempt failed, retrying: %s", first_error)

        retry_user_prompt = (
            original_user_prompt + "\n\n## Feedback\n"
            f"Your previous output was rejected. The error was:\n"
            f"  {first_error}\n\n"
            "Please produce valid YAML following the same structure "
            "and projection constraints described above. Use the same "
            "seed_id, goal, and narrative context from the original "
            "request.\n\n"
            f'seed_id={seed.seed_id}, tree id="tree-{seed.seed_id}".'
        )

        retry_result = client.complete(
            system_prompt=call2_system,
            user_prompt=retry_user_prompt,
            response_format=None,
        )

        try:
            tree = _parse_attack_tree_yaml(
                retry_result.content, seed, projection_context
            )
            tree = _validate_and_postprocess_tree(
                tree,
                profile,
                pinned_entry_point_id,
                skeleton,
                seed,
                projection_context,
            )
        except Exception:  # noqa: BLE001
            raise first_error

        return tree, retry_result

    return tree, result


# ---------------------------------------------------------------------------
# Post-processing: strip non-skeleton technique IDs
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Post-generation: technique-zone compatibility validation
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Post-generation consistency enforcement
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Post-generation canonical ID resolution (cmps.9)
# ---------------------------------------------------------------------------


def _resolve_initial_ingress_action(
    node: AttackTreeNode,
    action: Any,
    profile: CapabilityProfile,
    violations: list[str],
) -> None:
    """Resolve and validate an initial_ingress action's entry point ID."""
    from asago_scenario_generator.pipeline.generate.names import (
        resolve_name_to_entry_point_id,
    )

    # Resolve name → hex ID
    resolved_id = resolve_name_to_entry_point_id(action.entry_point_id, profile)
    if resolved_id is not None:
        action.entry_point_id = resolved_id
    # Validate
    ep = profile.resolve_entry_point(action.entry_point_id)
    if ep is None:
        violations.append(
            f"unresolved-entry-point-id: leaf '{node.id}' has "
            f"initial_ingress action with entry_point_id "
            f"'{action.entry_point_id}' that does not resolve to "
            f"any entry point in the capability profile."
        )


def _resolve_tool_invocation_integration(
    node: AttackTreeNode,
    action: Any,
    profile: CapabilityProfile,
    violations: list[str],
) -> None:
    """Resolve and validate a tool_invocation action's integration ID."""
    if action.integration_id is not None:
        from asago_scenario_generator.pipeline.generate.names import (
            resolve_name_to_integration_id,
        )

        resolved_int = resolve_name_to_integration_id(action.integration_id, profile)
        if resolved_int is not None:
            action.integration_id = resolved_int
        integ = profile.resolve_integration(action.integration_id)
        if integ is None:
            violations.append(
                f"unresolved-integration-id: leaf '{node.id}' has "
                f"tool_invocation action with integration_id "
                f"'{action.integration_id}' that does not resolve "
                f"to any integration in the capability profile."
            )


def _resolve_tool_invocation_action(
    node: AttackTreeNode,
    action: Any,
    profile: CapabilityProfile,
    violations: list[str],
) -> None:
    """Resolve and validate a tool_invocation action's tool and integration."""
    from asago_scenario_generator.pipeline.generate.names import (
        resolve_name_to_tool_id,
    )

    # Resolve name → hex ID
    resolved_tool = resolve_name_to_tool_id(action.tool_id, profile)
    if resolved_tool is not None:
        action.tool_id = resolved_tool
    # Validate
    tool = profile.resolve_tool(action.tool_id)
    if tool is None:
        violations.append(
            f"unresolved-tool-id: leaf '{node.id}' has "
            f"tool_invocation action with tool_id "
            f"'{action.tool_id}' that does not resolve to "
            f"any tool in the capability profile."
        )
    _resolve_tool_invocation_integration(node, action, profile, violations)


def _resolve_integration_interaction_action(
    node: AttackTreeNode,
    action: Any,
    profile: CapabilityProfile,
    violations: list[str],
) -> None:
    """Resolve and validate an integration_interaction action."""
    from asago_scenario_generator.pipeline.generate.names import (
        resolve_name_to_integration_id,
    )

    # Resolve name → hex ID
    resolved_int = resolve_name_to_integration_id(action.integration_id, profile)
    if resolved_int is not None:
        action.integration_id = resolved_int
    # Validate
    integ = profile.resolve_integration(action.integration_id)
    if integ is None:
        violations.append(
            f"unresolved-integration-id: leaf '{node.id}' has "
            f"integration_interaction action with integration_id "
            f"'{action.integration_id}' that does not resolve "
            f"to any integration in the capability profile."
        )


def _resolve_action_ids_node(
    node: AttackTreeNode,
    profile: CapabilityProfile,
    violations: list[str],
) -> None:
    """Resolve one node's human-readable names to canonical hex IDs."""
    if node.gate != GateType.LEAF or node.action is None:
        return
    action = node.action
    kind = action.kind
    if kind == "initial_ingress":
        _resolve_initial_ingress_action(node, action, profile, violations)
    elif kind == "tool_invocation":
        _resolve_tool_invocation_action(node, action, profile, violations)
    elif kind == "integration_interaction":
        _resolve_integration_interaction_action(node, action, profile, violations)


def _resolve_tree_action_ids(
    node: AttackTreeNode,
    profile: CapabilityProfile,
    violations: list[str],
) -> None:
    """Resolve action IDs for a node and all of its descendants."""
    _resolve_action_ids_node(node, profile, violations)
    if node.children:
        for child in node.children:
            _resolve_tree_action_ids(child, profile, violations)


def resolve_action_ids(
    tree: AttackTree,
    profile: CapabilityProfile,
) -> list[str]:
    """Resolve names to IDs and verify all typed action IDs in the tree.

    Phase 3: First resolves human-readable names to canonical hex IDs,
    then validates that all IDs resolve to profile resources.
    Returns a list of violation descriptions (empty if all IDs resolve).
    """
    violations: list[str] = []
    _resolve_tree_action_ids(tree.root, profile, violations)
    return violations


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-26T22:21:03Z","module_hash":"dc4c0c1a60e903016de92d6a1268eca6e88af3036dea44943ef8cde2590c1ab0","source_sha256":"0a312c174a676df49c4b58074072cb04f2cf33570ba5804c53477b7245e504d9","functions":[{"id":"func/_collect_threat_ids_from_tree","name":"_collect_threat_ids_from_tree","line":58,"end_line":64,"hash":"1d652b14b2b20d68ec6007c855787bcb5afb53b4572ebbd9ec895ee4e36e9716"},{"id":"func/_warn_dominant_threat_id_crossref","name":"_warn_dominant_threat_id_crossref","line":67,"end_line":104,"hash":"9ef132c3585fd97284f11c801ed277715c08f25de0e408db705639871eb55981"},{"id":"func/_match_zone_for_technique","name":"_match_zone_for_technique","line":117,"end_line":130,"hash":"ad17fabe759503b847b161a58bf7554573a87aebb712cfbb51837982554d50c1"},{"id":"func/_constrain_zone_to_technique","name":"_constrain_zone_to_technique","line":133,"end_line":138,"hash":"934651657eca121e2f94a0159edfdad9e1510f2607149ab44d8141c0d330f3ff"},{"id":"func/_build_tree_skeleton","name":"_build_tree_skeleton","line":141,"end_line":181,"hash":"8deb0a592edc19428b57883a2a7ef589235ca909cc9f5152adaa84f97c8e36a1"},{"id":"func/_format_skeleton_yaml","name":"_format_skeleton_yaml","line":184,"end_line":208,"hash":"d27267be0e9d7f2650412ab47ab39e25b8e8658655bf26efe785c33cd6fdab5b"},{"id":"func/_validate_mandatory_leaves","name":"_validate_mandatory_leaves","line":211,"end_line":234,"hash":"e831ac0f95848e4cd091951d8786f71767159682f06ef1f0ef75ba5b108629a2"},{"id":"func/_technique_constraint_text","name":"_technique_constraint_text","line":242,"end_line":279,"hash":"735d9c6b6ffb4ae6716ee36578dbc1b10b3ab33d74d0e47069afcc1098596ffb"},{"id":"func/_architecture_section_text","name":"_architecture_section_text","line":282,"end_line":292,"hash":"793be5e2c677d7e7dd7dd67097b1a6dbf631220f44025f1474555db6bf46d8c4"},{"id":"func/_actor_section_text","name":"_actor_section_text","line":295,"end_line":305,"hash":"14cdd631ad3367c72d1eb09930be5e47cccb86f31c6c2ef2f1eebe35df2d4b98"},{"id":"func/_access_provenance_block_text","name":"_access_provenance_block_text","line":308,"end_line":321,"hash":"150af11b8c863e054b0992a3dd979d67331bc85e0881859ef39c96f82a73e4d3"},{"id":"func/_skeleton_and_section","name":"_skeleton_and_section","line":324,"end_line":335,"hash":"278579323ee0b970e337ac00889b177a7a93f576d0aaa766a8c011ce358e489d"},{"id":"func/_ontology_context_for","name":"_ontology_context_for","line":338,"end_line":361,"hash":"558e47bf94db4c84e2096787405d6e988fdf685ed23b105ed90fd1fde51e0f04"},{"id":"func/_ensure_accessible_pinned_entry","name":"_ensure_accessible_pinned_entry","line":364,"end_line":383,"hash":"ded6f621fce794b48ffa566993e6a49df0891c8e0795ff0eba4ace6de5fbe803"},{"id":"func/_entry_points_for_template","name":"_entry_points_for_template","line":386,"end_line":402,"hash":"1ef163334cc9024d9d9ee5b0aec693aa070c43ac21ed861a4bb28c9e1be14dda"},{"id":"func/_pinned_entry_point_name_value","name":"_pinned_entry_point_name_value","line":405,"end_line":414,"hash":"770f3a66e7c4ad1c617b7aa4d067a2f548608606bd8c4cda4f7bbd8ab330076b"},{"id":"func/_humanized_projection_value","name":"_humanized_projection_value","line":417,"end_line":428,"hash":"07bf6fcef38f13c3bd27b4f951d9ff6cb3f4ffd67d013bee55c9fb65e1c727bb"},{"id":"func/build_call2_context","name":"build_call2_context","line":431,"end_line":513,"hash":"3d838f792528a24b2cff6a94f7268b6c6dbdcec56ca0bc7d2464b9fba80c1e25"},{"id":"func/_derive_leaf_realizations","name":"_derive_leaf_realizations","line":521,"end_line":540,"hash":"e3030b1a643dff28caa6303b6601bbfd2c6ab158dbc00d306a3103fda402ff3f"},{"id":"func/_fill_realization_node","name":"_fill_realization_node","line":543,"end_line":557,"hash":"04ec8a2c8a9135a21070ad20d5a71f34c28d135227594a0e312977508fd9a533"},{"id":"func/_fill_tree_realizations","name":"_fill_tree_realizations","line":560,"end_line":579,"hash":"64643ffedcf52c9d86355c22659ba0b7b41b418af8ebaca4ddee42379188b4c3"},{"id":"func/_validate_and_postprocess_tree","name":"_validate_and_postprocess_tree","line":582,"end_line":617,"hash":"37b137ad7d03c57fe8a6b9a424f5d48e645228f7e75e288c6f3e5954d89617ce"},{"id":"func/_tool_inventory_for","name":"_tool_inventory_for","line":620,"end_line":622,"hash":"3c737307478e35d622013d2db27f96ef0ed4d360e9134fb9a22f43587d86cf3f"},{"id":"func/_external_integrations_for","name":"_external_integrations_for","line":625,"end_line":627,"hash":"dbc23b6a1e52033141948f2f9051ecb4ce002c013c41a0f7197d12d2bd1fb496"},{"id":"func/_technique_count_for","name":"_technique_count_for","line":630,"end_line":632,"hash":"f29d67f17290c139eb3de160b75a97b01116dc85d2f81ec66efb159acbe999a4"},{"id":"func/_semantic_user_prompt","name":"_semantic_user_prompt","line":635,"end_line":653,"hash":"f7971f219688f8c58370a5a1bfc8ce71711200d9bd10c03dfe27b61e361625cf"},{"id":"func/_semantic_draft_flow","name":"_semantic_draft_flow","line":656,"end_line":699,"hash":"68f14282572d9cb46b8b86ed2a61f531797ad3ea3c7c1352e8146637f30548ea"},{"id":"func/_legacy_prompt_flow","name":"_legacy_prompt_flow","line":702,"end_line":737,"hash":"17d8658d4833309fce96ed87c3fd7428f4f3af2557e803e63118a854cc391d89"},{"id":"func/_compile_tree_response","name":"_compile_tree_response","line":740,"end_line":778,"hash":"9386dea2dde0f94b110cce04d50c29fdbc7692b0232eb6ab94246238e40b3c75"},{"id":"func/_invoke_attack_tree","name":"_invoke_attack_tree","line":781,"end_line":810,"hash":"e64fbc3e257aca7d3fec90a66570a471b424ac0f183cb0687a15de463d99c4c0"},{"id":"func/_postprocess_attack_tree_response","name":"_postprocess_attack_tree_response","line":813,"end_line":846,"hash":"6edb5492906c8a77630a4006e40f7b27a8cee9f4fa11f9da98b0355bceab6dd3"},{"id":"func/_call_attack_tree_once","name":"_call_attack_tree_once","line":849,"end_line":921,"hash":"0774517c218aeaf5ecb6cce05318fdabb695db30677d900d71e586a516b6f808"},{"id":"func/_call_attack_tree","name":"_call_attack_tree","line":924,"end_line":1021,"hash":"a0188b8833c927d29579945515f96ea5a356afe66bc92119eb13f2d1c63dd805"},{"id":"func/_resolve_initial_ingress_action","name":"_resolve_initial_ingress_action","line":1044,"end_line":1067,"hash":"1b0e76541f083ab0668024d6e3a344684a8e17232dc4bb2fb89d29ebd015d150"},{"id":"func/_resolve_tool_invocation_integration","name":"_resolve_tool_invocation_integration","line":1070,"end_line":1092,"hash":"95a915cf955e2477d37d722349574a912e90e4d43894ad825d14dc532b91913e"},{"id":"func/_resolve_tool_invocation_action","name":"_resolve_tool_invocation_action","line":1095,"end_line":1119,"hash":"7478ae6904e50b5184e739a0a290588bd0497a7c49bd1ae4eb2393e6d2510364"},{"id":"func/_resolve_integration_interaction_action","name":"_resolve_integration_interaction_action","line":1122,"end_line":1145,"hash":"f3574c328a7119d8eee9e390b60787b8713db0ad9e4e5a0382ec5e8c632caa02"},{"id":"func/_resolve_action_ids_node","name":"_resolve_action_ids_node","line":1148,"end_line":1163,"hash":"854f993e5f521148ec037f4aeaa7840b2029041802ed9193339de0752bcf8cd5"},{"id":"func/_resolve_tree_action_ids","name":"_resolve_tree_action_ids","line":1166,"end_line":1175,"hash":"41f93dd1cf99a238002f51c3c2a60fe0bec1030fc7559f2d831be2e161c7bbd1"},{"id":"func/resolve_action_ids","name":"resolve_action_ids","line":1178,"end_line":1190,"hash":"c18265d9af68d25a604936e0657f6f85e0a56f690728bdbafdd0b3618bcb861f"}]}
# mutate4py-manifest-end
