"""Call 3: Behavior Spec (Gherkin) generation logic.

Action-aware Gherkin projection (cmps.9):
- ``external_precondition`` → Given / Background
- ``initial_ingress`` and attack actions (ai_system_action, tool_invocation,
  integration_interaction) → When / And
- ``impact`` → Then (projected before the LLM assertion block)
- Human labels remain display text only; the action discriminator
  determines step kind, not label text.

Call 3 now requests semantic interactions through request-local action and
assertion handles.  The provider authors grouping, wording, and examples;
canonical actions, postconditions, IDs, and Gherkin syntax are compiler-owned.
Legacy assertions-only scripted responses remain readable for compatibility.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field

from asago_scenario_generator.data.atlas import ATLAS_TECHNIQUE_NAMES
from asago_scenario_generator.llm.client import LLMClient, LLMResult
from asago_scenario_generator.models.attack_tree import (
    AttackTree,
    AttackTreeNode,
    GateType,
)
from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.models.realization import ProjectedStepRealization
from asago_scenario_generator.models.scenario import (
    BehaviorAction,
    BehaviorAssertion,
    BehaviorSpec,
    NarrativeLayer,
)
from asago_scenario_generator.pipeline.generate.constants import (
    _ASSERTIONS_MARKER,
    THREAT_VIOLATION_CATEGORY,
)
from asago_scenario_generator.pipeline.seeds import ScenarioSeed
from asago_scenario_generator.prompts import render_prompt

logger = logging.getLogger(__name__)

# Maximum number of Scenario blocks generated from OR-gate cross-products.
# Beyond this, paths are truncated to avoid Gherkin explosion.
MAX_OR_PATHS = 6


# ---------------------------------------------------------------------------#
# Structured Call 3 response model (422o.4)
# ---------------------------------------------------------------------------#


_CALL3_ASSERTIONS_MAX_ITEMS = 32
_CALL3_IDS_MAX_ITEMS = 16
_CALL3_ID_MAX_LENGTH = 200
_CALL3_TEXT_MAX_LENGTH = 1000

_Call3Id = Annotated[str, Field(min_length=1, max_length=_CALL3_ID_MAX_LENGTH)]


class Call3Assertion(BaseModel):
    """A structured behavior assertion from Call 3, keyed by postcondition IDs."""

    model_config = ConfigDict(extra="forbid")

    assertion_id: _Call3Id
    source_step_ids: tuple[_Call3Id, ...] = Field(
        min_length=1, max_length=_CALL3_IDS_MAX_ITEMS
    )
    projected_postcondition_ids: tuple[_Call3Id, ...] = Field(
        min_length=1, max_length=_CALL3_IDS_MAX_ITEMS
    )
    text: str = Field(min_length=1, max_length=_CALL3_TEXT_MAX_LENGTH)


class Call3Response(BaseModel):
    """Assertions-only response; finalized-tree actions are immutable."""

    model_config = ConfigDict(extra="forbid")

    assertions: list[Call3Assertion] = Field(
        default_factory=list, max_length=_CALL3_ASSERTIONS_MAX_ITEMS
    )


class CompactCall3Response(Call3Response):
    """Provider schema name for the one causal compact-response experiment."""


# ---------------------------------------------------------------------------
# Leaf-action step classification (cmps.9)
# ---------------------------------------------------------------------------

# Step kinds derived from action discriminator, not labels.
_STEP_KIND_GIVEN = "given"  # external_precondition
_STEP_KIND_WHEN = "when"  # ingress, attacker/system actions, tools, integrations
_STEP_KIND_THEN = "then"  # impact


def _leaf_step_kind(leaf: AttackTreeNode) -> str:
    """Classify a leaf node's Gherkin step kind from its typed action.

    Returns one of ``_STEP_KIND_GIVEN``, ``_STEP_KIND_WHEN``, ``_STEP_KIND_THEN``.
    The classification is based solely on the action discriminator — never
    on label/description text.
    """
    action = leaf.action
    if action is None:
        # Should not happen — LEAF nodes require actions.  Defensive default.
        return _STEP_KIND_WHEN
    kind = action.kind
    if kind == "external_precondition":
        return _STEP_KIND_GIVEN
    if kind == "impact":
        return _STEP_KIND_THEN
    # initial_ingress, attacker_action, ai_system_action, tool_invocation,
    # integration_interaction
    return _STEP_KIND_WHEN


def _collect_leaf_nodes_dfs(node: AttackTreeNode) -> list[AttackTreeNode]:
    """Collect leaf nodes from an attack tree in depth-first order.

    Leaf nodes are nodes with ``gate == GateType.LEAF`` (no children).
    The ordering matches the narrative's attack-phase sequence.
    """
    leaves: list[AttackTreeNode] = []
    if node.gate == GateType.LEAF:
        leaves.append(node)
    elif node.children:
        for child in node.children:
            leaves.extend(_collect_leaf_nodes_dfs(child))
    return leaves


def _and_gate_paths(node: AttackTreeNode) -> list[list[AttackTreeNode]]:
    """Combine child paths via cross-product for an AND gate.

    All children are required — each resulting path contains leaves
    from every child.
    """
    result: list[list[AttackTreeNode]] = [[]]
    for child in node.children:
        child_paths = _enumerate_paths(child)
        new_result: list[list[AttackTreeNode]] = []
        for existing in result:
            for cp in child_paths:
                new_result.append(existing + cp)
        result = new_result
    return result


def _or_gate_paths(node: AttackTreeNode) -> list[list[AttackTreeNode]]:
    """Collect each child's alternative paths for an OR gate."""
    result: list[list[AttackTreeNode]] = []
    for child in node.children:
        result.extend(_enumerate_paths(child))
    return result


def _enumerate_paths(node: AttackTreeNode) -> list[list[AttackTreeNode]]:
    """Enumerate all distinct attack paths through an AND/OR tree.

    At AND gates, all children are required — their paths are combined via
    cross-product (each resulting path contains leaves from every child).
    At OR gates, each child is an alternative — their paths are appended
    as separate alternatives.

    Returns a list of paths, where each path is a list of leaf nodes
    in depth-first order.
    """
    if node.gate == GateType.LEAF:
        return [[node]]

    if not node.children:
        return [[]]

    if node.gate == GateType.AND:
        return _and_gate_paths(node)

    # node.gate == GateType.OR — each child is an alternative.
    return _or_gate_paths(node)


def _ingress_entry_point(leaf: AttackTreeNode, profile: CapabilityProfile) -> Any:
    """Resolve the canonical entry point referenced by an ingress action."""
    return next(
        (
            candidate
            for candidate in profile.entry_points
            if candidate.entry_point_id == leaf.action.entry_point_id
        ),
        None,
    )


def _resolve_ingress_step_text(
    leaf: AttackTreeNode, profile: CapabilityProfile | None
) -> tuple[str, str | None]:
    """Resolve display text and zone for a typed initial-ingress action.

    The display name and zone must come from the resolved canonical
    entry-point ID — never from the leaf label.  If the ID cannot be
    resolved and a profile is supplied, this is a fatal error (unknown
    IDs are never silently replaced by prose).
    """
    if (
        leaf.action is not None
        and leaf.action.kind == "initial_ingress"
        and profile is not None
    ):
        entry_point = _ingress_entry_point(leaf, profile)
        if entry_point is None:
            raise ValueError(
                f"initial_ingress action references unresolved entry_point_id "
                f"'{leaf.action.entry_point_id}'. Cannot derive display name "
                f"from prose — the ID must resolve to a canonical entry point."
            )
        return entry_point.name, entry_point.effective_ingress_zone
    return leaf.label, leaf.zone


def _humanize_technique_step_text(step_text: str, leaf: AttackTreeNode) -> str:
    """Replace raw technique-ID or verbatim-name labels with display prose."""
    # When the label is just a raw technique ID, replace with the name.
    _TECHNIQUE_ID_PATTERN = re.compile(r"^AML\.T\d+(\.\d+)?$")
    if _TECHNIQUE_ID_PATTERN.match(step_text):
        return ATLAS_TECHNIQUE_NAMES.get(step_text, step_text)
    # When the label is a verbatim ATLAS technique name, replace with
    # description or generic action label.
    _known_technique_names: dict[str, str] = {
        name.lower(): tid for tid, name in ATLAS_TECHNIQUE_NAMES.items()
    }
    if step_text.lower() in _known_technique_names:
        if leaf.description:
            return leaf.description
        return f"Execute attack step via {step_text}"
    return step_text


def _append_technique_and_zone(
    step_text: str, leaf: AttackTreeNode, step_zone: str | None
) -> str:
    """Append the technique ID suffix and zone annotation, if any."""
    if leaf.technique_id:
        step_text = re.sub(r"\s*\[AML\.T\d+(?:\.\d+)?\]", "", step_text)
        step_text += f" [{leaf.technique_id}]"
    if step_zone is not None:
        step_text += f" ({step_zone})"
    return step_text


def _format_leaf_step_text(
    leaf: AttackTreeNode,
    profile: CapabilityProfile | None = None,
) -> str:
    """Build the display text for a leaf node's Gherkin step.

    Labels are display prose only.  The technique ID is appended if present.
    For typed initial-ingress actions, the display name and zone must come
    from the resolved canonical entry-point ID — never from the leaf label.
    If the ID cannot be resolved and a profile is supplied, this is a fatal
    error (unknown IDs are never silently replaced by prose).
    """
    step_text, step_zone = _resolve_ingress_step_text(leaf, profile)
    step_text = _humanize_technique_step_text(step_text, leaf)
    return _append_technique_and_zone(step_text, leaf, step_zone)


def _build_gherkin_template(
    narrative: NarrativeLayer,
    attack_tree: AttackTree,
    profile: CapabilityProfile,
    seed: ScenarioSeed,
    scenario_tag: str,
) -> str:
    """Build a deterministic Gherkin skeleton from the tree and narrative.

    Action-aware projection (cmps.9):
    - shared ``external_precondition`` leaves → Background Given steps
    - branch-only ``external_precondition`` leaves → Scenario Given steps
    - ``initial_ingress`` and attack actions → Scenario When/And steps
    - ``impact`` leaves → Scenario Then steps (before {ASSERTIONS})
    - Labels are display text only; action discriminator determines step kind.

    When the tree contains OR gates, alternative paths are rendered as
    separate ``Scenario:`` blocks (one per OR-branch combination).  If
    the cross-product of OR branches exceeds :data:`MAX_OR_PATHS`, only
    the first ``MAX_OR_PATHS`` paths are rendered.
    """
    # --- Feature header ---
    lines: list[str] = [
        f"@id:{scenario_tag}",
        f"@{THREAT_VIOLATION_CATEGORY.get(seed.threat_id, 'misaligned-and-deceptive-behavior')}",
        f"Feature: {narrative.title}",
        f"  {narrative.summary}",
        "",
    ]

    # --- Collect leaf nodes for zone scoping ---
    leaf_nodes = _collect_leaf_nodes_dfs(attack_tree.root)
    tree_zones = _tree_zones(leaf_nodes)

    # --- Enumerate attack paths (OR-gate aware) ---
    paths = _enumerate_paths(attack_tree.root)
    # Compute shared preconditions across the complete path set, before any
    # rendering cap is applied.
    background_precondition_ids = _background_precondition_ids(paths)
    paths = _cap_rendered_paths(paths)

    # Only external preconditions common to every attack path belong in the
    # Background. Branch-only preconditions remain in their Scenario blocks.
    background_preconditions = _background_precondition_leaves(
        leaf_nodes, background_precondition_ids
    )

    # --- Background: preconditions ---
    lines.extend(_background_lines(background_preconditions, tree_zones, profile))
    lines.append("")

    multi_path = len(paths) > 1

    for path_idx, path_leaves in enumerate(paths, 1):
        lines.extend(
            _path_block_lines(
                path_idx,
                path_leaves,
                background_precondition_ids,
                multi_path,
                narrative,
                profile,
            )
        )
        # Blank line between scenarios (not after the last one)
        if path_idx < len(paths):
            lines.append("")

    return "\n".join(lines) + "\n"


def _tree_zones(leaf_nodes: list[AttackTreeNode]) -> set[str]:
    """Collect the zones actually present in the tree's leaf nodes."""
    return {leaf.zone for leaf in leaf_nodes if leaf.zone is not None}


def _background_precondition_ids(
    paths: list[list[AttackTreeNode]],
) -> set[str]:
    """Intersect Given-leaf IDs across the complete path set."""
    precondition_ids_by_path = [
        {leaf.id for leaf in path if _leaf_step_kind(leaf) == _STEP_KIND_GIVEN}
        for path in paths
    ]
    if not precondition_ids_by_path:
        return set()
    return set.intersection(*precondition_ids_by_path)


def _cap_rendered_paths(
    paths: list[list[AttackTreeNode]],
) -> list[list[AttackTreeNode]]:
    """Cap the rendered path count at MAX_OR_PATHS with a warning."""
    if len(paths) > MAX_OR_PATHS:
        logger.warning(
            "Attack tree produces %d paths (OR-gate cross-product), capping at %d",
            len(paths),
            MAX_OR_PATHS,
        )
        return paths[:MAX_OR_PATHS]
    return paths


def _background_precondition_leaves(
    leaf_nodes: list[AttackTreeNode],
    background_precondition_ids: set[str],
) -> list[AttackTreeNode]:
    """Return Given leaves common to every attack path."""
    return [
        leaf
        for leaf in leaf_nodes
        if leaf.id in background_precondition_ids
        and _leaf_step_kind(leaf) == _STEP_KIND_GIVEN
    ]


def _precondition_step_lines(
    preconditions: list[AttackTreeNode], profile: CapabilityProfile
) -> tuple[list[str], bool]:
    """Render Background Given/And precondition steps."""
    lines: list[str] = []
    for i, prec_leaf in enumerate(preconditions):
        prec_text = _format_leaf_step_text(prec_leaf, profile)
        keyword = "Given" if i == 0 else "And"
        lines.append(f"    {keyword} {prec_text}")
    return lines, bool(preconditions)


def _zone_capability_lines(
    tree_zones: set[str], profile: CapabilityProfile, step_added: bool
) -> list[str]:
    """Render zone/capability preconditions scoped to tree-present zones."""
    from asago_scenario_generator.models.capability_profile import ZONE_DISPLAY_NAMES

    lines: list[str] = []
    for zone in profile.zones_active:
        if zone not in tree_zones:
            continue  # zone not used in this scenario's tree
        display_name = ZONE_DISPLAY_NAMES.get(zone, zone)
        keyword = "And" if step_added else "Given"
        lines.append(
            f"    {keyword} the system has {display_name} capabilities ({zone})"
        )
        step_added = True
    return lines


def _background_lines(
    background_preconditions: list[AttackTreeNode],
    tree_zones: set[str],
    profile: CapabilityProfile,
) -> list[str]:
    """Render the complete Background block for the Gherkin template."""
    lines: list[str] = ["  Background: Preconditions"]
    prec_lines, step_added = _precondition_step_lines(background_preconditions, profile)
    lines.extend(prec_lines)
    lines.extend(_zone_capability_lines(tree_zones, profile, step_added))
    return lines


def _classify_path_leaf(
    leaf: AttackTreeNode, background_precondition_ids: set[str]
) -> str:
    """Return the partition bucket for one path leaf.

    Buckets: ``scenario_precondition``, ``background``, ``then``, ``when``.
    """
    kind = _leaf_step_kind(leaf)
    if kind == _STEP_KIND_GIVEN:
        if leaf.id not in background_precondition_ids:
            return "scenario_precondition"
        return "background"
    if kind == _STEP_KIND_THEN:
        return "then"
    return "when"


def _partition_path_leaves(
    path_leaves: list[AttackTreeNode],
    background_precondition_ids: set[str],
) -> tuple[list[AttackTreeNode], list[AttackTreeNode], list[AttackTreeNode]]:
    """Separate a path's leaves into scenario/background/when/then buckets."""
    scenario_preconditions: list[AttackTreeNode] = []
    when_leaves: list[AttackTreeNode] = []
    then_leaves: list[AttackTreeNode] = []
    for leaf in path_leaves:
        bucket = _classify_path_leaf(leaf, background_precondition_ids)
        if bucket == "scenario_precondition":
            scenario_preconditions.append(leaf)
        elif bucket == "then":
            then_leaves.append(leaf)
        elif bucket == "when":
            when_leaves.append(leaf)
    return scenario_preconditions, when_leaves, then_leaves


def _sort_when_leaves(when_leaves: list[AttackTreeNode]) -> None:
    """Order initial ingress first, independent of tree traversal order."""
    when_leaves.sort(
        key=lambda leaf: leaf.action is None or leaf.action.kind != "initial_ingress"
    )


def _scenario_precondition_lines(
    narrative: NarrativeLayer,
    multi_path: bool,
    path_idx: int,
    scenario_preconditions: list[AttackTreeNode],
    profile: CapabilityProfile,
) -> list[str]:
    """Render the scenario header, normal-state Given, and branch preconditions."""
    lines: list[str] = []
    if multi_path:
        lines.append(f"  Scenario: {narrative.title} (Path {path_idx})")
    else:
        lines.append(f"  Scenario: {narrative.title}")
    lines.append("    Given the system is in its normal operating state")
    for prec_leaf in scenario_preconditions:
        prec_text = _format_leaf_step_text(prec_leaf, profile)
        lines.append(f"    And {prec_text}")
    lines.append("")
    return lines


def _when_step_lines(
    when_leaves: list[AttackTreeNode], profile: CapabilityProfile
) -> list[str]:
    """Render When/And attack steps for one path."""
    lines: list[str] = []
    for i, leaf in enumerate(when_leaves):
        step_text = _format_leaf_step_text(leaf, profile)
        keyword = "When" if i == 0 else "And"
        lines.append(f"    {keyword} {step_text}")
    return lines


def _then_step_lines(
    then_leaves: list[AttackTreeNode], profile: CapabilityProfile
) -> list[str]:
    """Render Then impact steps for one path."""
    return [f"    Then {_format_leaf_step_text(leaf, profile)}" for leaf in then_leaves]


def _path_block_lines(
    path_idx: int,
    path_leaves: list[AttackTreeNode],
    background_precondition_ids: set[str],
    multi_path: bool,
    narrative: NarrativeLayer,
    profile: CapabilityProfile,
) -> list[str]:
    """Render one Scenario block (header, steps, assertion marker)."""
    scenario_preconditions, when_leaves, then_leaves = _partition_path_leaves(
        path_leaves, background_precondition_ids
    )
    # Initial ingress is always the first attack action, independent of
    # incidental tree traversal order.
    _sort_when_leaves(when_leaves)

    lines = _scenario_precondition_lines(
        narrative, multi_path, path_idx, scenario_preconditions, profile
    )
    lines.extend(_when_step_lines(when_leaves, profile))
    lines.extend(_then_step_lines(then_leaves, profile))
    lines.append("")
    lines.append(f"    {_ASSERTIONS_MARKER}")
    return lines


def _collect_control_points(node: AttackTreeNode) -> list[str]:
    """Collect unique non-None control_point values from tree nodes."""
    points: set[str] = set()
    if node.control_point:
        points.add(node.control_point)
    if node.children:
        for child in node.children:
            points.update(_collect_control_points(child))
    return sorted(points)


def build_call3_context(
    seed: ScenarioSeed,
    narrative: NarrativeLayer,
    attack_tree: AttackTree,
    profile: CapabilityProfile,
    scenario_tag: str,
    projection_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build prompt template variables for Call 3 (Behavior Spec).

    Pure data-preparation function that constructs all template variables
    needed by ``call3_user.j2``.  No LLM calls.

    422o.4: Provides a leaf catalog (leaf_id, projected step IDs, action
    kind, zone, eligible Gherkin keyword) and a postcondition ownership
    table (postcondition ID, owning step ID, semantics) so the LLM can
    emit a structured Call3Response keyed by exact projected IDs.

    Returns:
        Dict mapping template variable names to their values.
    """
    # Collect defensive control points from attack tree nodes
    control_points = _collect_control_points(attack_tree.root)

    # Build leaf catalog from actual tree leaves.
    leaf_catalog: list[dict[str, Any]] = [
        _leaf_catalog_entry(leaf, projection_context)
        for leaf in _collect_leaf_nodes_dfs(attack_tree.root)
    ]

    # Build postcondition ownership table from projection context.
    postcondition_ownership = _postcondition_ownership_rows(projection_context)

    # Humanize projection context for the template (Phase 3)
    from asago_scenario_generator.pipeline.generate.names import (
        humanize_projection_context,
    )

    humanized_projection = (
        humanize_projection_context(projection_context, profile)
        if projection_context is not None
        else projection_context
    )

    return {
        "narrative": narrative,
        "seed": seed,
        "control_points": control_points,
        "projection_context": humanized_projection,
        "leaf_catalog": leaf_catalog,
        "postcondition_ownership": postcondition_ownership,
    }


def _leaf_eligible_keyword(step_kind: str) -> str:
    """Map a leaf step kind to its eligible Gherkin keyword."""
    if step_kind == _STEP_KIND_GIVEN:
        return "Given"
    if step_kind == _STEP_KIND_THEN:
        return "Then"
    return "When"


def _step_semantics_index(projection_context: dict[str, Any]) -> dict[str, Any]:
    """Index selected projection steps by step_id."""
    return {sd["step_id"]: sd for sd in projection_context.get("selected_steps", [])}


def _leaf_step_semantics(
    leaf: AttackTreeNode, step_semantics: dict[str, Any]
) -> list[dict[str, Any]]:
    """Build per-step canonical semantics rows for one leaf."""
    leaf_step_data: list[dict[str, Any]] = []
    for sid in leaf.projected_step_ids:
        sd = step_semantics.get(sid)
        if sd:
            # Use the nested canonical realization record directly.
            realization = sd.get("realization", {})
            leaf_step_data.append(
                {
                    "step_id": sid,
                    "action_kind": realization.get("action_kind", ""),
                    "executor_role": realization.get("executor_role", ""),
                    "boundary_position": realization.get("boundary_position", ""),
                    "consumed_ref_ids": realization.get("consumed_ref_ids", []),
                    "produced_ref_ids": realization.get("produced_ref_ids", []),
                    "produced_effect_ids": realization.get("produced_effect_ids", []),
                    "outcome_link_pc_ids": realization.get("outcome_link_pc_ids", []),
                    "postcondition_ids": realization.get("postcondition_ids", []),
                    "resource_ref_ids": realization.get("resource_ref_ids", []),
                }
            )
    return leaf_step_data


def _leaf_catalog_entry(
    leaf: AttackTreeNode, projection_context: dict[str, Any] | None
) -> dict[str, Any]:
    """Build one leaf catalog entry, optionally enriched with semantics."""
    step_kind = _leaf_step_kind(leaf)
    action_kind = leaf.action.kind if leaf.action else "unknown"
    leaf_entry: dict[str, Any] = {
        "leaf_id": leaf.id,
        "projected_step_ids": list(leaf.projected_step_ids),
        "action_kind": action_kind,
        "zone": leaf.zone,
        "eligible_keyword": _leaf_eligible_keyword(step_kind),
    }
    # Enrich with full per-step canonical semantics from projection
    # context so the LLM can emit complete realization records.
    if projection_context:
        leaf_entry["step_semantics"] = _leaf_step_semantics(
            leaf, _step_semantics_index(projection_context)
        )
    return leaf_entry


def _postcondition_ownership_rows(
    projection_context: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Build the postcondition ownership table from projection context."""
    postcondition_ownership: list[dict[str, Any]] = []
    if projection_context:
        for step_data in projection_context.get("selected_steps", []):
            for pc in step_data.get("observable_postconditions", []):
                postcondition_ownership.append(
                    {
                        "postcondition_id": pc["postcondition_id"],
                        "owning_step_id": step_data["step_id"],
                        "description": pc["description"],
                        "security_relevant": pc["security_relevant"],
                        "terminal": pc["terminal"],
                    }
                )
    return postcondition_ownership


def _call_behavior_spec(
    seed: ScenarioSeed,
    narrative: NarrativeLayer,
    attack_tree: AttackTree,
    profile: CapabilityProfile,
    client: LLMClient,
    use_case: str,
    scenario_tag: str,
    pinned_technique_ids: list[str] | None = None,
    semantic_feedback: str | None = None,
    completion_length_feedback: str | None = None,
    compact_response_schema: bool = False,
    max_completion_tokens: int | None = None,
    projection_context: dict[str, Any] | None = None,
) -> tuple[BehaviorSpec, LLMResult]:
    """Generate a structured behavior spec for a scenario seed (Call 3).

    422o.4: The LLM returns a structured Call3Response keyed by exact
    projected step/postcondition IDs.  The response is validated against
    the projection context and the attack tree, then Gherkin is rendered
    from the accepted structure.  The LLM output is never silently
    replaced — if the structured response does not match the projection,
    a ValueError is raised.

    ``completion_length_feedback`` (the finalization-owned length-retry
    suffix) is appended verbatim to the end of the rendered user prompt.

    Returns:
        Tuple of (BehaviorSpec, LLMResult).
    """
    semantic_context = None
    if projection_context is not None:
        from asago_scenario_generator.pipeline.generate.behavior_semantics import (
            derive_behavior_handles,
        )

        semantic_context = derive_behavior_handles(
            attack_tree, profile, projection_context
        )
        response_model: type[BaseModel] = _semantic_response_model(
            semantic_context, compact_response_schema
        )
        system_prompt, user_prompt = _semantic_prompt_parts(
            use_case, narrative, semantic_context, semantic_feedback
        )
    else:
        system_prompt, user_prompt, response_model = _legacy_prompt_parts(
            seed,
            narrative,
            attack_tree,
            profile,
            scenario_tag,
            projection_context,
            compact_response_schema,
        )
    if completion_length_feedback:
        user_prompt = f"{user_prompt}{completion_length_feedback}"
    result = client.complete(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_format=response_model,
        max_completion_tokens=max_completion_tokens,
    )

    if _uses_draft_compilation(result, semantic_context):
        behavior_spec = _compile_draft_result(result, semantic_context)
    else:
        # Compatibility for recorded/scripted Call3Response fixtures. New
        # provider requests use BehaviorDraftV2 when projection context exists.
        behavior_spec = _compile_compat_result(
            result, attack_tree, profile, projection_context
        )

    return behavior_spec, result


def _semantic_response_model(
    semantic_context: Any, compact_response_schema: bool
) -> type[BaseModel]:
    """Build the structured response model for semantic Call 3 requests."""
    from asago_scenario_generator.pipeline.generate.behavior_semantics import (
        build_behavior_draft_response_model,
    )

    return build_behavior_draft_response_model(
        [
            item.handle
            for item in (
                *semantic_context.action_handles,
                *semantic_context.assertion_handles,
            )
        ],
        compact=compact_response_schema,
        examples_allowed=any(
            item.parameters for item in semantic_context.action_handles
        ),
    )


def _semantic_action_inventory(semantic_context: Any) -> list[dict[str, Any]]:
    """Serialize the action handles for the semantic user prompt."""
    from asago_scenario_generator.pipeline.generate.behavior_semantics import (
        strip_compiler_owned_zone_suffix,
    )

    return [
        {
            "handle": item.handle,
            "interaction": strip_compiler_owned_zone_suffix(
                item.action.text, item.zone
            ),
            "keyword_semantics": item.action.gherkin_keyword,
            "zone": item.zone,
            "parameters": [
                parameter.model_dump(mode="json") for parameter in item.parameters
            ],
        }
        for item in semantic_context.action_handles
    ]


def _semantic_assertion_inventory(semantic_context: Any) -> list[dict[str, Any]]:
    """Serialize the assertion handles for the semantic user prompt."""
    return [
        {
            "handle": item.handle,
            "required_outcome": item.description,
            "after_action_handle": next(
                action.handle
                for action in semantic_context.action_handles
                if item.source_step_id in action.action.projected_step_ids
            ),
        }
        for item in semantic_context.assertion_handles
    ]


def _semantic_prompt_parts(
    use_case: str,
    narrative: NarrativeLayer,
    semantic_context: Any,
    semantic_feedback: str | None,
) -> tuple[str, str]:
    """Build system/user prompts for semantic (handle-based) Call 3."""
    system_prompt = (
        "You author concrete behavioral interactions for one adversarial "
        "scenario. Return only the structured response. Use every action "
        "and assertion handle exactly once and preserve action order. "
        "You control scenario grouping, titles, concrete interaction text, "
        "example values, and assertion wording. The compiler places each "
        "assertion immediately after its canonical owning action. Never emit Gherkin syntax "
        "or canonical IDs; the compiler owns identity and rendering."
    )
    action_inventory = _semantic_action_inventory(semantic_context)
    assertion_inventory = _semantic_assertion_inventory(semantic_context)
    user_prompt = (
        f"Use case:\n{use_case}\n\n"
        f"Narrative title: {narrative.title}\n"
        f"Narrative summary: {narrative.summary}\n\n"
        "Action handles:\n"
        f"{json.dumps(action_inventory, ensure_ascii=False, indent=2)}\n\n"
        "Required assertion handles:\n"
        f"{json.dumps(assertion_inventory, ensure_ascii=False, indent=2)}\n\n"
        "Produce only the structured JSON assertions and interactions "
        "defined by the response schema. When an action's parameters "
        "list is empty, its examples object must be empty.\n"
    )
    if semantic_feedback:
        user_prompt += f"\nCorrection required:\n{semantic_feedback}\n"
    return system_prompt, user_prompt


def _legacy_prompt_parts(
    seed: ScenarioSeed,
    narrative: NarrativeLayer,
    attack_tree: AttackTree,
    profile: CapabilityProfile,
    scenario_tag: str,
    projection_context: dict[str, Any] | None,
    compact_response_schema: bool,
) -> tuple[str, str, type[BaseModel]]:
    """Build system/user prompts for the legacy scripted-response path."""
    ctx = build_call3_context(
        seed=seed,
        narrative=narrative,
        attack_tree=attack_tree,
        profile=profile,
        scenario_tag=scenario_tag,
        projection_context=projection_context,
    )
    response_model = CompactCall3Response if compact_response_schema else Call3Response
    system_prompt = render_prompt("call3_system.j2")
    user_prompt = render_prompt("call3_user.j2", **ctx)
    return system_prompt, user_prompt, response_model


def _uses_draft_compilation(result: LLMResult, semantic_context: Any) -> bool:
    """True when the result carries a semantic draft to compile."""
    if semantic_context is None:
        return False
    if isinstance(result.content, Call3Response):
        return False
    if isinstance(result.content, dict) and "scenarios" not in result.content:
        return False
    return True


def _compile_draft_result(result: LLMResult, semantic_context: Any) -> BehaviorSpec:
    """Compile a semantic BehaviorDraftV2 into the authoritative spec."""
    from asago_scenario_generator.pipeline.generate.behavior_semantics import (
        BehaviorDraftV2,
        compile_behavior_draft,
    )

    draft = (
        result.content
        if isinstance(result.content, BehaviorDraftV2)
        else BehaviorDraftV2.model_validate(result.content)
    )
    return compile_behavior_draft(draft, semantic_context)


def _compile_compat_result(
    result: LLMResult,
    attack_tree: AttackTree,
    profile: CapabilityProfile,
    projection_context: dict[str, Any] | None,
) -> BehaviorSpec:
    """Compile a scripted Call3Response fixture into a BehaviorSpec."""
    call3_response = (
        result.content
        if isinstance(result.content, Call3Response)
        else Call3Response.model_validate(result.content)
    )
    actions = _derive_behavior_actions(attack_tree, profile, projection_context)
    _validate_call3_response(call3_response, attack_tree, projection_context)
    return _call3_response_to_behavior_spec(call3_response, actions)


def _pc_ownership_tables(
    projection_context: dict[str, Any],
) -> tuple[dict[str, str], set[tuple[str, str]]]:
    """Build postcondition ownership (pc_id → owner) and security-relevant pairs."""
    pc_ownership: dict[str, str] = {}
    security_relevant_pairs: set[tuple[str, str]] = set()
    for step_data in projection_context.get("selected_steps", []):
        sid = step_data["step_id"]
        for pc in step_data.get("observable_postconditions", []):
            pc_id = pc["postcondition_id"]
            existing_owner = pc_ownership.get(pc_id)
            if existing_owner is not None and existing_owner != sid:
                raise ValueError(
                    f"Postcondition '{pc_id}' has ambiguous owners "
                    f"'{existing_owner}' and '{sid}'"
                )
            pc_ownership[pc_id] = sid
            if pc.get("security_relevant"):
                security_relevant_pairs.add((sid, pc_id))
    return pc_ownership, security_relevant_pairs


def _require_single_source_step(assertion: Call3Assertion) -> str:
    """Require exactly one source step and return it."""
    if len(assertion.source_step_ids) != 1:
        raise ValueError(
            f"Assertion '{assertion.assertion_id}' has "
            f"{len(assertion.source_step_ids)} source_step_ids — "
            f"exactly one (the owning step) is required"
        )
    return assertion.source_step_ids[0]


def _require_single_postcondition(assertion: Call3Assertion) -> str:
    """Require exactly one projected postcondition and return it."""
    if len(assertion.projected_postcondition_ids) != 1:
        raise ValueError(
            f"Assertion '{assertion.assertion_id}' has "
            f"{len(assertion.projected_postcondition_ids)} "
            f"projected_postcondition_ids — exactly one per assertion "
            f"is required (one assertion per owning-step/postcondition pair)"
        )
    return assertion.projected_postcondition_ids[0]


def _check_assertion_references(
    source_step: str,
    pc_id: str,
    selected_step_ids: set[str],
    pc_ownership: dict[str, str],
) -> str:
    """Validate a source step and postcondition against projection tables.

    Returns the owning step.  Raises for unprojected source steps, unknown
    postconditions, or inexact ownership (the source must BE the owner,
    not merely contain it).
    """
    if source_step not in selected_step_ids:
        raise ValueError(
            f"Assertion references unprojected source step '{source_step}'"
        )
    if pc_id not in pc_ownership:
        raise ValueError(f"Assertion references unknown postcondition '{pc_id}'")
    # Exact ownership: source_step must be THE owner, not just a member.
    owning_step = pc_ownership[pc_id]
    if source_step != owning_step:
        raise ValueError(
            f"Assertion states source step '{source_step}' but postcondition "
            f"'{pc_id}' is owned by step '{owning_step}' — source_step_ids "
            f"must exactly equal the postcondition owner, not merely contain it"
        )
    return owning_step


def _check_assertion_id(assertion_id: str, owning_step: str, pc_id: str) -> None:
    """Require the deterministic assertion ID assert-<owner>-<postcondition>."""
    expected_assertion_id = f"assert-{owning_step}-{pc_id}"
    if assertion_id != expected_assertion_id:
        raise ValueError(
            f"Assertion ID '{assertion_id}' does not match "
            f"deterministic expected ID '{expected_assertion_id}' "
            f"(assert-<owning_step_id>-<postcondition_id>)"
        )


def _track_assertion_pair(
    assertion_id: str,
    pair: tuple[str, str],
    assertion_ids: set[str],
    seen_pairs: set[tuple[str, str]],
) -> None:
    """Track an assertion ID and (step, postcondition) pair, rejecting dupes."""
    if assertion_id in assertion_ids:
        raise ValueError(f"Duplicate assertion ID '{assertion_id}' in Call 3 response")
    assertion_ids.add(assertion_id)
    if pair in seen_pairs:
        raise ValueError(
            f"Assertion '{assertion_id}' duplicates the "
            f"(step, postcondition) pair {pair} "
            f"already covered by another assertion"
        )
    seen_pairs.add(pair)


def _check_security_coverage(
    security_relevant_pairs: set[tuple[str, str]],
    covered_security_pairs: set[tuple[str, str]],
) -> None:
    """Require full coverage of security-relevant postcondition pairs."""
    uncovered_security_pairs = security_relevant_pairs - covered_security_pairs
    if uncovered_security_pairs:
        raise ValueError(
            f"Call 3 response does not cover security-relevant "
            f"postconditions: {sorted(uncovered_security_pairs)}"
        )


def _validate_call3_response(
    response: Call3Response,
    attack_tree: AttackTree,
    projection_context: dict[str, Any] | None,
) -> None:
    """Validate assertions against exact projected postcondition ownership."""
    del attack_tree  # Retained in the compatibility signature for existing callers.
    if projection_context is None:
        raise ValueError("Call 3 requires projection context (422o.4)")

    selected_step_ids = set(projection_context.get("selected_step_ids", []))
    pc_ownership, security_relevant_pairs = _pc_ownership_tables(projection_context)

    # --- Assertion validation ---
    # Contract: one assertion per (owning step, postcondition) pair.
    # - assertion_id == "assert-{source_step_id}-{postcondition_id}"
    # - source_step_ids is a single-element tuple containing the owner
    # - projected_postcondition_ids is a single-element tuple
    # - No unrelated extra source steps (exact ownership, not membership)
    assertion_ids: set[str] = set()
    covered_security_pairs: set[tuple[str, str]] = set()
    seen_assertion_pairs: set[tuple[str, str]] = set()
    for assertion in response.assertions:
        source_step = _require_single_source_step(assertion)
        pc_id = _require_single_postcondition(assertion)
        owning_step = _check_assertion_references(
            source_step, pc_id, selected_step_ids, pc_ownership
        )
        _check_assertion_id(assertion.assertion_id, owning_step, pc_id)

        # No duplicate (step, postcondition) pairs.
        pair = (owning_step, pc_id)
        _track_assertion_pair(
            assertion.assertion_id, pair, assertion_ids, seen_assertion_pairs
        )
        if pair in security_relevant_pairs:
            covered_security_pairs.add(pair)

    # Full security-relevant postcondition coverage
    _check_security_coverage(security_relevant_pairs, covered_security_pairs)


def _leaf_realizations(
    leaf: AttackTreeNode, step_by_id: dict[str, Any]
) -> tuple[ProjectedStepRealization, ...]:
    """Validate and collect canonical realization records for one leaf."""
    realizations: list[ProjectedStepRealization] = []
    for step_id in leaf.projected_step_ids:
        step = step_by_id.get(step_id)
        if step is None:
            raise ValueError(
                f"tree leaf '{leaf.id}' references unknown projected step '{step_id}'"
            )
        realizations.append(
            ProjectedStepRealization.model_validate(step["realization"])
        )
    return tuple(realizations)


def _leaf_behavior_action(
    leaf: AttackTreeNode,
    step_by_id: dict[str, Any],
    profile: CapabilityProfile,
) -> BehaviorAction:
    """Materialize one immutable BehaviorAction from a tree leaf."""
    return BehaviorAction(
        action_id=f"ba-{leaf.id}",
        projected_step_ids=leaf.projected_step_ids,
        source_leaf_id=leaf.id,
        gherkin_keyword=_leaf_eligible_keyword(_leaf_step_kind(leaf)),
        text=_format_leaf_step_text(leaf, profile),
        realizations=_leaf_realizations(leaf, step_by_id),
    )


def _derive_behavior_actions(
    attack_tree: AttackTree,
    profile: CapabilityProfile,
    projection_context: dict[str, Any] | None,
) -> tuple[BehaviorAction, ...]:
    """Materialize immutable actions from the final tree in leaf DFS order."""
    if projection_context is None:
        raise ValueError("Call 3 requires projection context (422o.4)")
    step_by_id = {
        step["step_id"]: step for step in projection_context.get("selected_steps", [])
    }
    actions: list[BehaviorAction] = []
    for leaf in _collect_leaf_nodes_dfs(attack_tree.root):
        if not leaf.projected_step_ids:
            continue
        actions.append(_leaf_behavior_action(leaf, step_by_id, profile))
    return tuple(actions)


def _call3_response_to_behavior_spec(
    response: Call3Response,
    actions: tuple[BehaviorAction, ...],
) -> BehaviorSpec:
    """Convert a validated Call3Response into a BehaviorSpec.

    Gherkin is deterministically rendered from the structured actions and
    assertions — not from an independently authored LLM text output.
    """
    assertions = tuple(
        BehaviorAssertion(
            assertion_id=a.assertion_id,
            source_step_ids=a.source_step_ids,
            projected_postcondition_ids=a.projected_postcondition_ids,
            gherkin_keyword="Then",
            text=a.text,
        )
        for a in response.assertions
    )

    from asago_scenario_generator.pipeline.generate.behavior_compiler import (
        render_gherkin_from_behavior_spec,
    )

    rendered = render_gherkin_from_behavior_spec(
        list(actions), list(assertions), zone_map=None
    )

    return BehaviorSpec(
        actions=actions,
        assertions=assertions,
        gherkin_text=rendered,
    )
