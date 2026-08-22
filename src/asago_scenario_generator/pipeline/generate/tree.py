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
    normalize_attack_tree_transport,
)
from asago_scenario_generator.pipeline.generate.tree_validation import (
    _check_tool_execution_leaf_grounding,
    _enumerate_root_to_leaf_paths,
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

__all__ = [
    "_check_tool_execution_leaf_grounding",
    "_enumerate_root_to_leaf_paths",
    "normalize_attack_tree_transport",
]


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
        # Match technique against narrative steps by ID or name
        matched_zone: str | None = None
        tid_lower = tid.lower()
        tname_lower = tname.lower()
        for step in narrative.steps:
            haystack = f"{step.action} {step.effect}".lower()
            if tid_lower in haystack or tname_lower in haystack:
                matched_zone = step.zone
                break

        zone = matched_zone if matched_zone is not None else fallback_zone

        # Validate zone against technique-zone semantic constraints.
        # If the narrative-derived zone is invalid for this technique,
        # pick the first valid zone from the constraint set.
        valid_zones = TECHNIQUE_ZONE_CONSTRAINTS.get(tid)
        if valid_zones is not None and zone not in valid_zones:
            zone = min(valid_zones)

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
    # Build shared technique context + Call 2-specific constraint rules
    # Pin to specific techniques if set
    tech_ids_for_tree = (
        pinned_technique_ids if pinned_technique_ids else seed.atlas_technique_ids
    )
    technique_context = _build_technique_context_block(tech_ids_for_tree)
    if tech_ids_for_tree:
        allowed_ids = ", ".join(tech_ids_for_tree)
        if pinned_technique_ids:
            technique_constraint = (
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
        else:
            technique_constraint = (
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
    else:
        technique_constraint = (
            "\n## ATLAS Technique Constraint\n"
            "No ATLAS technique IDs are available for this seed. "
            "Do NOT add technique_id to any node.\n"
        )

    # Build optional architecture and actor profile sections for Call 2
    arch_section = ""
    if profile is not None:
        entry_point_names = [ep.name for ep in profile.entry_points]
        arch_section = (
            "\n## Target System Architecture\n"
            "Every node's zone must be drawn from these active zones.\n"
            f"- Active zones: {profile.zones_active}\n"
            f"- Entry points: {entry_point_names}\n"
        )

    actor_section = ""
    if actor_profile is not None:
        actor_section = (
            "\n## Actor Profile\n"
            "The tree's depth and complexity must be commensurate with "
            "the actor's capability level.\n"
            f"- Actor type: {actor_profile.actor_type}\n"
            f"- Capability level: {actor_profile.capability_level}\n"
        )

    # Build structured access provenance block (cmps.6) — using names (Phase 3)
    access_provenance_block = ""
    if actor_profile is not None and actor_profile.access is not None:
        from asago_scenario_generator.pipeline.generate.names import (
            access_provenance_block_with_names,
        )

        access_provenance_block = (
            access_provenance_block_with_names(
                actor_profile.access,
                profile,
            )
            if profile is not None
            else ""
        )

    # Compute concrete leaf budget so the LLM sees the exact number
    technique_count = len(tech_ids_for_tree) if tech_ids_for_tree else 0
    leaf_budget = compute_leaf_budget(technique_count)

    # Build tree skeleton from pinned techniques (tree-anchored flow)
    skeleton: list[dict[str, str]] = []
    if pinned_technique_ids and pinned_technique_names:
        skeleton = _build_tree_skeleton(
            narrative, pinned_technique_ids, pinned_technique_names
        )
    skeleton_section = _format_skeleton_yaml(skeleton)

    # Build focused ontology context block for this seed
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
    ontology_context = _build_ontology_context(
        entry_point_name=narrative.entry_point or "",
        entry_point_direction=_tree_ep_direction,
        zones=profile.zones_active if profile else [],
        technique_ids=list(tech_ids_for_tree) if tech_ids_for_tree else [],
        entry_point_controllability=_tree_ep_controllability,
    )

    entry_points = (profile.entry_points if profile else None) or []
    if pinned_entry_point_id is not None:
        entry_points = [
            entry_point
            for entry_point in entry_points
            if entry_point.entry_point_id == pinned_entry_point_id
        ]
        # Defense-in-depth: reject inaccessible pinned entry points before
        # exposing them to the LLM (cmps.9 third review correction 2).
        if profile is not None and len(entry_points) == 1:
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

    # Convert pinned_entry_point_id to name for the template (Phase 3)
    from asago_scenario_generator.pipeline.generate.names import (
        humanize_projection_context,
        pinned_entry_point_name_from_id,
    )

    pinned_entry_point_name = pinned_entry_point_name_from_id(
        pinned_entry_point_id, profile
    )

    # Humanize projection context for the template (Phase 3)
    humanized_projection = (
        humanize_projection_context(projection_context, profile)
        if projection_context is not None and profile is not None
        else projection_context
    )

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
        "tool_inventory": (profile.tool_inventory if profile else None) or [],
        "external_integrations": (profile.external_integrations if profile else None)
        or [],
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

    from asago_scenario_generator.models.realization import ProjectedStepRealization

    step_data_by_id: dict[str, dict[str, Any]] = {
        sd["step_id"]: sd for sd in projection_context.get("selected_steps", [])
    }

    def _fill_node(node: AttackTreeNode) -> None:
        if node.gate == GateType.LEAF:
            if not node.projected_step_ids:
                # External preconditions and unmapped leaves stay empty.
                node.realizations = ()
                return
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
                realizations.append(
                    ProjectedStepRealization.model_validate(sd["realization"])
                )
            node.realizations = tuple(realizations)
        elif node.children:
            for child in node.children:
                _fill_node(child)

    _fill_node(tree.root)


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
    if projection_context is not None and profile is not None:
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
        skeleton: list[dict[str, str]] = []
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
    else:
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
    if completion_length_feedback:
        user_prompt = f"{user_prompt}{completion_length_feedback}"
    try:
        result = client.complete(
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
    try:
        if semantic_leaf_specs is not None and not isinstance(result.content, str):
            from asago_scenario_generator.pipeline.generate.tree_semantics import (
                AttackTreeDraftV2,
                AttackTreeDraftV3,
                compile_flat_attack_tree_draft,
                compile_attack_tree_draft,
            )

            if isinstance(result.content, AttackTreeDraftV3):
                tree = compile_flat_attack_tree_draft(
                    seed_id=seed.seed_id,
                    goal=seed.attack_pattern_name,
                    draft=result.content,
                    leaf_specs=semantic_leaf_specs,
                    threat_id=seed.threat_id,
                )
            else:
                draft = (
                    result.content
                    if isinstance(result.content, AttackTreeDraftV2)
                    else AttackTreeDraftV2.model_validate(result.content)
                )
                tree = compile_attack_tree_draft(
                    seed_id=seed.seed_id,
                    goal=seed.attack_pattern_name,
                    draft=draft,
                    leaf_specs=semantic_leaf_specs,
                    threat_id=seed.threat_id,
                )
        else:
            # Compatibility for recorded/scripted legacy YAML responses. New
            # provider requests always use AttackTreeDraftV2 when projection
            # context is available.
            tree = _parse_attack_tree_yaml(result.content, seed, projection_context)
        tree = _validate_and_postprocess_tree(
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


def _resolve_action_ids_node(
    node: AttackTreeNode,
    profile: CapabilityProfile,
    violations: list[str],
) -> None:
    """Resolve human-readable names to canonical hex IDs, then validate.

    Phase 3: The LLM outputs names (e.g. "process_refund") instead of
    hex IDs (e.g. "tool:v1:abc123...").  This function resolves names
    to canonical IDs in place, then validates that all IDs resolve to
    profile resources.  If a name doesn't match any resource, it's
    recorded as a violation.
    """
    from asago_scenario_generator.pipeline.generate.names import (
        resolve_name_to_entry_point_id,
        resolve_name_to_integration_id,
        resolve_name_to_tool_id,
    )

    if node.gate == GateType.LEAF and node.action is not None:
        action = node.action
        kind = action.kind

        if kind == "initial_ingress":
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

        elif kind == "tool_invocation":
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
            if action.integration_id is not None:
                resolved_int = resolve_name_to_integration_id(
                    action.integration_id, profile
                )
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

        elif kind == "integration_interaction":
            # Resolve name → hex ID
            resolved_int = resolve_name_to_integration_id(
                action.integration_id, profile
            )
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

    if node.children:
        for child in node.children:
            _resolve_action_ids_node(child, profile, violations)


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
    _resolve_action_ids_node(tree.root, profile, violations)
    return violations
