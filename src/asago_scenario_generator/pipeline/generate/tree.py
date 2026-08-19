"""Call 2: Attack Tree generation logic."""

from __future__ import annotations

import logging
import re
from collections import Counter
from typing import Any

import yaml

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
from asago_scenario_generator.pipeline.generate.constants import (
    _STEP_NODE_CORRESPONDENCE_FLOOR,
    compute_leaf_budget,
)
from asago_scenario_generator.pipeline.generate.ontology import (
    _build_ontology_context,
    _build_technique_context_block,
    _lookup_entry_point_controllability,
    _lookup_entry_point_direction,
)
from asago_scenario_generator.pipeline.generate.zones import (
    _collect_zones_from_tree,
    _enforce_zones_attack_tree,
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


def _sanitize_yaml_colons(raw_yaml: str) -> str:
    """Quote YAML values that contain unquoted colons.

    LLM-generated YAML often contains values like:
        description: Human-in-the-loop: Investigator/Supervisor approval
    which fails parsing because the second colon starts a new mapping.

    This function finds lines matching ``<indent><key>: <value>`` where
    ``<value>`` itself contains a ``:`` and is not already quoted, then wraps
    the value in double quotes (escaping any internal double quotes).

    Lines that are pure mapping keys (value is empty or only whitespace, i.e.
    the value starts on the next indented line) are left untouched.
    """
    # Pattern: optional leading whitespace, a YAML key (``- `` list prefix
    # allowed), then ``: ``, then a value that contains another ``:``.
    # We only act when the value is *not* already wrapped in quotes.
    _KEY_VALUE_RE = re.compile(
        r"^(?P<prefix>\s*(?:-\s+)?)(?P<key>[A-Za-z_][\w.]*):\s+(?P<value>.+)$"
    )

    sanitized_lines: list[str] = []
    for line in raw_yaml.split("\n"):
        m = _KEY_VALUE_RE.match(line)
        if m:
            value = m.group("value")
            # Only act if the value contains another colon AND is not already
            # quoted (single or double).
            if (
                ":" in value
                and not (value.startswith('"') and value.endswith('"'))
                and not (value.startswith("'") and value.endswith("'"))
            ):
                # Escape existing double quotes inside the value, then wrap.
                escaped = value.replace("\\", "\\\\").replace('"', '\\"')
                line = f'{m.group("prefix")}{m.group("key")}: "{escaped}"'
        sanitized_lines.append(line)
    return "\n".join(sanitized_lines)


def _resolve_projected_step_ids(
    result: dict[str, Any],
    canonical_by_id: dict[str, dict[str, Any]],
) -> None:
    """Validate and replace model-supplied realizations from projected IDs.

    Raises ValueError if any projected step ID is not in the canonical set.
    """
    projected_ids = result.get("projected_step_ids", ())
    if not projected_ids:
        return
    missing = set(projected_ids) - set(canonical_by_id)
    if missing:
        raise ValueError(
            "Attack tree references unknown projected step ID(s): "
            + ", ".join(sorted(missing))
        )
    # Model-supplied realization semantics are transport-only. Replace
    # them before strict validation, including omitted or duplicate
    # records.
    result["realizations"] = [canonical_by_id[sid] for sid in projected_ids]


def normalize_attack_tree_transport(
    data: Any,
    projection_context: dict[str, Any] | None,
) -> Any:
    """Normalize relaxed transport fields before strict attack-tree parsing."""
    if projection_context is None or not isinstance(data, dict):
        return data
    normalized = dict(data)
    if isinstance(normalized.get("attack_tree"), dict):
        normalized["attack_tree"] = normalize_attack_tree_transport(
            normalized["attack_tree"], projection_context
        )
        return normalized

    canonical_by_id = {
        item["step_id"]: item["realization"]
        for item in projection_context.get("selected_steps", [])
        if isinstance(item, dict)
        and isinstance(item.get("step_id"), str)
        and isinstance(item.get("realization"), dict)
    }

    def normalize_node(node: Any) -> Any:
        if not isinstance(node, dict):
            return node
        result = dict(node)
        _resolve_projected_step_ids(result, canonical_by_id)
        if isinstance(result.get("children"), list):
            result["children"] = [normalize_node(c) for c in result["children"]]
        return result

    if isinstance(normalized.get("root"), dict):
        normalized["root"] = normalize_node(normalized["root"])
    return normalized


def _parse_attack_tree_yaml(
    raw: str,
    seed: ScenarioSeed,
    projection_context: dict[str, Any] | None = None,
) -> AttackTree:
    """Parse YAML text into an AttackTree model.

    Strips markdown code fences if present, then validates through Pydantic.
    If the initial parse fails due to YAML syntax errors (commonly from
    unquoted colons in LLM-generated values), the raw text is sanitized
    and parsing is retried once.
    """
    cleaned = raw.strip()
    if cleaned.startswith("```"):
        lines = cleaned.split("\n")
        lines = lines[1:]  # drop opening fence
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        cleaned = "\n".join(lines)

    try:
        data = yaml.safe_load(cleaned)
    except yaml.YAMLError:
        logger.warning(
            "YAML parse failed for seed %s; attempting colon sanitization",
            seed.seed_id,
        )
        sanitized = _sanitize_yaml_colons(cleaned)
        try:
            data = yaml.safe_load(sanitized)
        except yaml.YAMLError as exc:
            raise yaml.YAMLError(
                f"Failed to parse attack tree YAML for seed {seed.seed_id} "
                f"even after colon sanitization: {exc}"
            ) from exc

    if isinstance(data, dict) and "attack_tree" in data:
        data = data["attack_tree"]

    # Strict typed normal generation: do NOT repair single-child AND/OR
    # gates before Pydantic validation.  Malformed gates must be rejected
    # by the model validator so the caller retries or rejects — no silent
    # structural mutation (cmps.9 review correction 3).
    # repair_attack_tree_dict is retained only for post-pruning repair in
    # validation.py (explicit parsimony boundary).

    data = normalize_attack_tree_transport(data, projection_context)
    return AttackTree.model_validate(data)


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

    fallback_zone = narrative.zone_sequence[0] if narrative.zone_sequence else "input"

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


def _enumerate_root_to_leaf_paths(node: AttackTreeNode) -> list[list[AttackTreeNode]]:
    """Enumerate all root-to-leaf paths through the attack tree.

    Each path is a list of leaf nodes.  AND gates contribute all children
    to the same path(s); OR gates create one branch per child.
    """
    if node.gate == GateType.LEAF:
        return [[node]]
    if not node.children:
        return []
    if node.gate == GateType.AND:
        # All children must succeed — merge their paths.
        merged: list[list[AttackTreeNode]] = [[]]
        for child in node.children:
            child_paths = _enumerate_root_to_leaf_paths(child)
            if not child_paths:
                continue
            merged = [m + cp for m in merged for cp in child_paths]
        return merged
    # OR gate: each child is a separate branch.
    paths: list[list[AttackTreeNode]] = []
    for child in node.children:
        paths.extend(_enumerate_root_to_leaf_paths(child))
    return paths


def _collect_all_leaves(node: AttackTreeNode) -> list[AttackTreeNode]:
    """Collect all LEAF nodes from the tree (depth-first)."""
    if node.gate == GateType.LEAF:
        return [node]
    leaves: list[AttackTreeNode] = []
    if node.children:
        for child in node.children:
            leaves.extend(_collect_all_leaves(child))
    return leaves


def _validate_tree_against_projection(
    tree: AttackTree,
    projection_context: dict[str, Any] | None,
) -> None:
    """Validate parsed attack tree against the immutable projection context.

    422o.4 blocker #2: On candidate-v2 paths, every non-external_precondition
    security leaf MUST have nonempty projected_step_ids, exactly one complete
    canonical realization per projected ID, and exact realization equality
    to the canonical projection context.  OR nodes are prohibited.

    Raises ``ValueError`` on any violation — no semantic repair.
    """
    if projection_context is None:
        return

    selected_step_ids = set(projection_context.get("selected_step_ids", []))

    # Realization records are now derived in post-processing by
    # _fill_tree_realizations() — no need to rebuild them here for
    # equality comparison.  We still validate projected_step_id
    # validity and realization coverage.

    def _check_node(node: AttackTreeNode) -> None:
        # OR nodes are prohibited in v1.
        if node.gate == GateType.OR:
            raise ValueError(
                f"Attack tree node '{node.id}' uses OR gate — OR is "
                f"prohibited in v1 (one concrete execution only)"
            )
        if node.gate == GateType.LEAF:
            action_kind = node.action.kind if node.action else ""
            is_external = action_kind == "external_precondition"

            if is_external:
                # External preconditions must remain unmapped — both IDs
                # and realizations must be empty.
                if node.projected_step_ids:
                    raise ValueError(
                        f"External precondition leaf '{node.id}' has "
                        f"projected_step_ids {list(node.projected_step_ids)} "
                        f"— external preconditions must be unmapped"
                    )
                if node.realizations:
                    raise ValueError(
                        f"External precondition leaf '{node.id}' has "
                        f"{len(node.realizations)} realization records "
                        f"— external preconditions must have empty "
                        f"realizations"
                    )
            else:
                # Every non-external leaf must have nonempty projected IDs.
                if not node.projected_step_ids:
                    raise ValueError(
                        f"Security-bearing leaf '{node.id}' has no "
                        f"projected_step_ids — every non-external_precondition "
                        f"leaf must map to projected steps"
                    )
                # All IDs must be in the selected set.
                for sid in node.projected_step_ids:
                    if sid not in selected_step_ids:
                        raise ValueError(
                            f"Tree leaf '{node.id}' references unprojected "
                            f"step '{sid}' — not in selected_step_ids"
                        )
                # Must have exactly one realization per projected ID.
                if not node.realizations:
                    raise ValueError(
                        f"Security-bearing leaf '{node.id}' has "
                        f"projected_step_ids but no realizations"
                    )
                real_ids = [r.projected_step_id for r in node.realizations]
                if len(set(real_ids)) != len(real_ids):
                    raise ValueError(
                        f"Leaf '{node.id}' has duplicate realization records"
                    )
                if len(real_ids) != len(node.projected_step_ids):
                    raise ValueError(
                        f"Leaf '{node.id}' has {len(real_ids)} realization "
                        f"records but {len(node.projected_step_ids)} "
                        f"projected_step_ids — exactly one per ID required"
                    )
                if set(real_ids) != set(node.projected_step_ids):
                    raise ValueError(
                        f"Leaf '{node.id}' realization IDs {sorted(set(real_ids))} "
                        f"do not match projected_step_ids "
                        f"{sorted(set(node.projected_step_ids))}"
                    )
                # Realization equality check is now a no-op sanity check:
                # post-processing derives realizations from the same
                # projection context, so both sides are computed by
                # derive_step_realization().  We keep the projected_step_id
                # validity and coverage checks above.

        if node.children:
            for child in node.children:
                _check_node(child)

    _check_node(tree.root)


def _validate_pinned_ingress(
    tree: AttackTree,
    pinned_entry_point_id: str | None,
    profile: CapabilityProfile | None = None,
) -> list[str]:
    """Validate that every root-to-leaf path has an initial_ingress leaf.

    When ``pinned_entry_point_id`` is supplied, every initial_ingress action
    in the tree must use that exact entry point ID.  Every final attack path
    must contain at least one initial_ingress leaf.

    When *profile* is supplied, each initial_ingress leaf's zone must match
    the resolved entry point's canonical ``effective_ingress_zone``.  A
    mismatch is a violation — the zone is never silently repaired from a
    label (cmps.9 review correction 3).
    """
    paths = _enumerate_root_to_leaf_paths(tree.root)
    violations: list[str] = []

    for path_idx, path in enumerate(paths, 1):
        ingress_leaves = [
            leaf
            for leaf in path
            if leaf.action is not None and leaf.action.kind == "initial_ingress"
        ]
        if not ingress_leaves:
            violations.append(
                f"missing-initial-ingress: attack path {path_idx} has no "
                f"initial_ingress leaf action. Every root-to-leaf path must "
                f"contain an initial ingress."
            )

    if pinned_entry_point_id is not None:
        all_ingress = [
            leaf
            for leaf in _collect_all_leaves(tree.root)
            if leaf.action is not None and leaf.action.kind == "initial_ingress"
        ]
        for leaf in all_ingress:
            action = leaf.action
            assert action is not None  # guarded by filter above
            if action.entry_point_id != pinned_entry_point_id:
                violations.append(
                    f"pinned-entry-point-mismatch: initial_ingress action uses "
                    f"entry_point_id '{action.entry_point_id}', expected "
                    f"'{pinned_entry_point_id}'."
                )

    # Validate ingress zone against canonical entry-point zone (cmps.9 review 3).
    # Also reject ingress-capable entries whose effective canonical ingress
    # zone is not active in the profile (cmps.9 review correction 5).
    # Use the centralized attacker-accessible ingress predicate so that
    # output-only, system-controlled, missing-zone, and inactive-zone entry
    # points are all rejected through one authority (cmps.9 third review 2).
    if profile is not None:
        active_zones = set(profile.zones_active) if profile.zones_active else set()
        for leaf in _collect_all_leaves(tree.root):
            action = leaf.action
            if action is None or action.kind != "initial_ingress":
                continue
            resolved_ep = profile.resolve_entry_point(action.entry_point_id)
            if resolved_ep is None:
                violations.append(
                    f"unresolved-ingress-zone: initial_ingress leaf '{leaf.id}' "
                    f"references entry_point_id '{action.entry_point_id}' "
                    f"that has no canonical ingress zone."
                )
                continue
            if not is_attacker_accessible_ingress(resolved_ep, active_zones):
                violations.append(
                    f"inaccessible-ingress-entry-point: initial_ingress leaf "
                    f"'{leaf.id}' references entry point "
                    f"'{resolved_ep.name}' (entry_point_id "
                    f"'{action.entry_point_id}') which is not an "
                    f"attacker-accessible ingress route (output-only, "
                    f"system-controlled, or inactive ingress zone)."
                )
                continue
            expected_zone = resolved_ep.effective_ingress_zone
            assert expected_zone is not None  # predicate guarantees this
            if leaf.zone != expected_zone:
                violations.append(
                    f"ingress-zone-mismatch: initial_ingress leaf '{leaf.id}' "
                    f"has zone '{leaf.zone}' but entry point "
                    f"'{action.entry_point_id}' requires zone "
                    f"'{expected_zone}'. The zone must match the canonical "
                    f"entry-point ingress zone, not be inferred from a label."
                )

    return violations


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
    pinned_entry_point_id: str | None = None,
    projection_context: dict[str, Any] | None = None,
) -> tuple[AttackTree, LLMResult]:
    """Generate and validate one attack-tree attempt (Call 2).

    This is the lifecycle primitive: it performs exactly one LLM invocation
    and never retries.  Retry ownership belongs to the caller.
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
    system_prompt = render_prompt(
        "call2_system.j2",
        zones_active=profile.zones_active if profile else [],
        tool_inventory=ctx["tool_inventory"],
        external_integrations=ctx["external_integrations"],
        entry_points=ctx["entry_points"],
        pinned_entry_point_name=ctx.get("pinned_entry_point_name"),
    )
    user_prompt = render_prompt("call2_user.j2", **ctx)
    try:
        result = client.complete(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_format=None,
        )
    except Exception as exc:
        from asago_scenario_generator.pipeline.generate.stages import (
            StageAttemptFailure,
        )

        raise StageAttemptFailure(
            call_name=CallName.attack_tree,
            exception=exc,
            phase="invocation",
            invoked=True,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        ) from exc
    try:
        tree = _parse_attack_tree_yaml(result.content, seed, projection_context)
        tree = _validate_and_postprocess_tree(
            tree, profile, pinned_entry_point_id, skeleton, seed, projection_context
        )
    except Exception as exc:
        from asago_scenario_generator.pipeline.generate.stages import (
            StageAttemptFailure,
        )

        raise StageAttemptFailure(
            call_name=CallName.attack_tree,
            exception=exc,
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


def _strip_non_skeleton_techniques_node(
    node: AttackTreeNode, skeleton_technique_ids: set[str]
) -> int:
    """Recursively strip technique_id from non-skeleton leaf nodes.

    Returns the number of technique_ids stripped.
    """
    stripped = 0
    if node.gate == GateType.LEAF:
        if (
            node.technique_id is not None
            and node.technique_id not in skeleton_technique_ids
        ):
            logger.debug(
                "Stripping non-skeleton technique_id '%s' from leaf '%s'",
                node.technique_id,
                node.id,
            )
            node.technique_id = None
            stripped += 1
    elif node.children:
        for child in node.children:
            stripped += _strip_non_skeleton_techniques_node(
                child, skeleton_technique_ids
            )
    return stripped


def _strip_non_skeleton_techniques(
    tree: AttackTree, skeleton_technique_ids: set[str]
) -> int:
    """Remove technique_id from leaves that are not in the skeleton.

    The skeleton builder places pinned techniques on mandatory leaves.
    The LLM tree generator often copies those technique IDs onto additional
    leaves it creates, producing decorative/semantically incorrect annotations.
    Only skeleton leaves (those whose technique_id is in the pinned set) should
    retain their technique annotations.

    Args:
        tree: The attack tree to post-process (mutated in place).
        skeleton_technique_ids: Set of pinned technique IDs that are allowed
            to remain on leaves. If empty, ALL leaf technique_ids are stripped.

    Returns:
        The number of technique_ids stripped.
    """
    return _strip_non_skeleton_techniques_node(tree.root, skeleton_technique_ids)


# ---------------------------------------------------------------------------
# Post-generation: technique-zone compatibility validation
# ---------------------------------------------------------------------------


def _validate_technique_zone_node(node: AttackTreeNode) -> int:
    """Recursively strip technique_ids that violate zone constraints.

    Returns the number of technique_ids stripped.

    Action-aware (cmps.9): nodes with zone=None (external preconditions,
    external impacts) are skipped — they are outside the AI boundary.
    """
    stripped = 0
    if node.gate == GateType.LEAF:
        if node.technique_id is not None and node.zone is not None:
            valid_zones = TECHNIQUE_ZONE_CONSTRAINTS.get(node.technique_id)
            if valid_zones is not None and node.zone not in valid_zones:
                logger.warning(
                    "Technique-zone mismatch: stripping %s from node %s "
                    "(zone=%s, valid_zones=%s)",
                    node.technique_id,
                    node.id,
                    node.zone,
                    sorted(valid_zones),
                )
                node.technique_id = None
                stripped += 1
    elif node.children:
        for child in node.children:
            stripped += _validate_technique_zone_node(child)
    return stripped


def _validate_technique_zone_compatibility(tree: AttackTree) -> int:
    """Strip technique_ids that violate TECHNIQUE_ZONE_CONSTRAINTS.

    Walks the tree and removes technique_id from any leaf node where
    the technique is not valid in the node's zone per the constraint map.
    Techniques absent from the map are unconstrained and pass.

    Returns the number of technique_ids stripped.
    """
    return _validate_technique_zone_node(tree.root)


# ---------------------------------------------------------------------------
# Post-generation consistency enforcement
# ---------------------------------------------------------------------------


def _count_leaves(node: AttackTreeNode) -> int:
    """Count leaf nodes in an attack tree rooted at *node*."""
    if node.gate == GateType.LEAF:
        return 1
    total = 0
    if node.children:
        for child in node.children:
            total += _count_leaves(child)
    return total


def _check_non_actionable_leaves(root: AttackTreeNode, violations: list[str]) -> None:
    """Check 6: flag non-actionable observation leaves.

    Walks the tree collecting LEAF nodes without a technique_id whose
    labels match observation-pattern keywords.  If >=2 such leaves exist,
    appends a violation describing them.
    """
    _OBSERVATION_KEYWORDS = [
        "confirm",
        "observe",
        "verify",
        "monitor",
        "validate",
        "note ",
        "detect ",
        "assess ",
    ]

    def _collect_leaves_recursive(node: AttackTreeNode) -> list[AttackTreeNode]:
        if node.gate == GateType.LEAF:
            return [node]
        leaves: list[AttackTreeNode] = []
        if node.children:
            for child in node.children:
                leaves.extend(_collect_leaves_recursive(child))
        return leaves

    leaves = _collect_leaves_recursive(root)
    matching_ids: list[str] = []
    for leaf in leaves:
        if leaf.technique_id:
            continue
        label_lower = leaf.label.lower()
        if any(kw in label_lower for kw in _OBSERVATION_KEYWORDS):
            matching_ids.append(leaf.id)

    if len(matching_ids) >= 2:
        violations.append(
            f"non-actionable-leaves: {len(matching_ids)} leaf node(s) appear "
            f"to describe observations rather than attacker actions "
            f"({', '.join(matching_ids)}). Remove non-actionable leaves or "
            f"assign a technique_id."
        )


def _check_consistency(
    tree: AttackTree,
    narrative: NarrativeLayer,
    parsimony_budget: int,
    step_node_floor: float = _STEP_NODE_CORRESPONDENCE_FLOOR,
    threat_id: str | None = None,
    tool_names: list[str] | None = None,
    pinned_technique_ids: list[str] | None = None,
) -> list[str]:
    """Run post-generation consistency checks on the attack tree.

    Returns a list of violation descriptions (empty if all checks pass).
    Checks:
      1. Parsimony — leaf count must not exceed budget.
      2. Zone-sequence — every narrative zone must appear in the tree.
      3. Step-node correspondence — ratio must meet the floor.
      4. Missing scenario threat_id — at least one tree node must carry the
         scenario's assigned threat_id.
      5. Tool-execution leaf grounding — every leaf in tool_execution zone
         must reference a tool from the inventory.
      6. Non-actionable leaf padding.
      7. Technique coverage — every pinned technique must appear on at least
         one leaf node.
    """
    violations: list[str] = []

    # Check 1: parsimony
    leaf_count = _count_leaves(tree.root)
    if leaf_count > parsimony_budget:
        violations.append(f"parsimony: {leaf_count} leaves > {parsimony_budget} budget")

    # Check 2: zone-sequence consistency
    narrative_zones = set(narrative.zone_sequence)
    tree_zones = _collect_zones_from_tree(tree.root)
    missing_zones = narrative_zones - tree_zones
    if missing_zones:
        violations.append(
            f"zone-sequence: zones {missing_zones} in narrative but not tree; "
            f"add at least one node in each missing zone: "
            f"{', '.join(sorted(missing_zones))}"
        )

    # Check 3: step-node correspondence
    step_count = len(narrative.steps)
    if leaf_count > 0 and step_count > 0:
        correspondence = min(step_count, leaf_count) / max(step_count, leaf_count)
        if correspondence < step_node_floor:
            violations.append(
                f"step-node: {correspondence:.2f} < {step_node_floor} floor"
            )
    elif step_count == 0:
        # No steps — cannot compute, not a violation
        pass
    elif leaf_count == 0:
        violations.append("step-node: 0 leaves in tree")

    # Check 4: missing scenario threat_id
    if threat_id is not None:
        all_threat_ids = {
            tid
            for tid in (n_tid for n_tid in _collect_threat_ids_from_tree_set(tree.root))
        }
        if threat_id not in all_threat_ids:
            violations.append(
                f"missing-scenario-threat-id: no tree node carries "
                f"threat_id '{threat_id}'; tree has "
                f"{sorted(all_threat_ids) if all_threat_ids else 'none'}. "
                f"At least one node must have threat_id='{threat_id}'"
            )

    # Check 5: tool-execution leaf grounding (typed action check)
    if tool_names is not None:
        _check_tool_execution_leaf_grounding(tree.root, violations)

    # Check 6: non-actionable leaf padding
    _check_non_actionable_leaves(tree.root, violations)

    # Check 7: pinned technique coverage
    if pinned_technique_ids:
        tree_technique_ids = set(tree.collect_technique_ids())
        missing_techniques = set(pinned_technique_ids) - tree_technique_ids
        if missing_techniques:
            violations.append(
                f"missing-pinned-technique: pinned technique(s) "
                f"{sorted(missing_techniques)} not found on any tree leaf; "
                f"tree has {sorted(tree_technique_ids) if tree_technique_ids else 'none'}. "
                f"Assign each missing technique_id to the leaf whose action "
                f"best matches the technique's mechanism."
            )

    return violations


def _collect_threat_ids_from_tree_set(
    node: AttackTreeNode,
) -> set[str]:
    """Collect all non-None threat_id values from tree nodes as a set."""
    ids: set[str] = set()
    if node.threat_id is not None:
        ids.add(node.threat_id)
    if node.children:
        for child in node.children:
            ids.update(_collect_threat_ids_from_tree_set(child))
    return ids


def _check_tool_execution_leaf_grounding(
    node: AttackTreeNode,
    violations: list[str],
) -> None:
    """Check that tool_execution leaf nodes have a resolvable typed action (cmps.9).

    Uses typed action data, not label matching.  Per the authoritative
    ``ACTION_ZONE_RULES`` matrix, both ``tool_invocation`` and
    ``integration_interaction`` are valid in ``tool_execution``:

    - Leaves in ``tool_execution`` zone without a typed action whose kind
      is ``tool_invocation`` or ``integration_interaction``: flag as
      untyped-tool-execution.
    """
    if node.gate == GateType.LEAF:
        if node.zone == "tool_execution":
            action = node.action
            if action is None or action.kind not in (
                "tool_invocation",
                "integration_interaction",
            ):
                violations.append(
                    f"untyped-tool-execution: leaf '{node.id}' in "
                    f"tool_execution zone has no tool_invocation or "
                    f"integration_interaction action. Every tool_execution "
                    f"leaf must carry a resolvable typed action."
                )
    elif node.children:
        for child in node.children:
            _check_tool_execution_leaf_grounding(child, violations)


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
