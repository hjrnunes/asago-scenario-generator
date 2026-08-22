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
_STEP_KIND_WHEN = "when"  # initial_ingress, ai_system_action, tool_invocation, integration_interaction
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
    # initial_ingress, ai_system_action, tool_invocation, integration_interaction
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
        # All children required — cross-product of each child's paths.
        result: list[list[AttackTreeNode]] = [[]]
        for child in node.children:
            child_paths = _enumerate_paths(child)
            new_result: list[list[AttackTreeNode]] = []
            for existing in result:
                for cp in child_paths:
                    new_result.append(existing + cp)
            result = new_result
        return result

    # node.gate == GateType.OR
    # Each child is an alternative — collect all children's paths.
    result = []
    for child in node.children:
        result.extend(_enumerate_paths(child))
    return result


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
    step_text = leaf.label
    step_zone = leaf.zone

    if (
        leaf.action is not None
        and leaf.action.kind == "initial_ingress"
        and profile is not None
    ):
        entry_point = next(
            (
                candidate
                for candidate in profile.entry_points
                if candidate.entry_point_id == leaf.action.entry_point_id
            ),
            None,
        )
        if entry_point is None:
            raise ValueError(
                f"initial_ingress action references unresolved entry_point_id "
                f"'{leaf.action.entry_point_id}'. Cannot derive display name "
                f"from prose — the ID must resolve to a canonical entry point."
            )
        step_text = entry_point.name
        step_zone = entry_point.effective_ingress_zone

    # When the label is just a raw technique ID, replace with the name.
    _TECHNIQUE_ID_PATTERN = re.compile(r"^AML\.T\d+(\.\d+)?$")
    if _TECHNIQUE_ID_PATTERN.match(step_text):
        step_text = ATLAS_TECHNIQUE_NAMES.get(step_text, step_text)
    else:
        # When the label is a verbatim ATLAS technique name, replace with
        # description or generic action label.
        _known_technique_names: dict[str, str] = {
            name.lower(): tid for tid, name in ATLAS_TECHNIQUE_NAMES.items()
        }
        if step_text.lower() in _known_technique_names:
            if leaf.description:
                step_text = leaf.description
            else:
                step_text = f"Execute attack step via {step_text}"

    if leaf.technique_id:
        step_text = re.sub(r"\s*\[AML\.T\d+(?:\.\d+)?\]", "", step_text)
        step_text += f" [{leaf.technique_id}]"
    if step_zone is not None:
        step_text += f" ({step_zone})"
    return step_text


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
    # --- Violation category tag ---
    violation_tag = THREAT_VIOLATION_CATEGORY.get(
        seed.threat_id, "misaligned-and-deceptive-behavior"
    )

    # --- Feature header ---
    lines: list[str] = [
        f"@id:{scenario_tag}",
        f"@{violation_tag}",
        f"Feature: {narrative.title}",
        f"  {narrative.summary}",
        "",
    ]

    # --- Collect leaf nodes for zone scoping ---
    leaf_nodes = _collect_leaf_nodes_dfs(attack_tree.root)
    tree_zones = {leaf.zone for leaf in leaf_nodes if leaf.zone is not None}

    # --- Enumerate attack paths (OR-gate aware) ---
    paths = _enumerate_paths(attack_tree.root)

    # Compute shared preconditions across the complete path set, before any
    # rendering cap is applied.
    precondition_ids_by_path = [
        {leaf.id for leaf in path if _leaf_step_kind(leaf) == _STEP_KIND_GIVEN}
        for path in paths
    ]
    background_precondition_ids = (
        set.intersection(*precondition_ids_by_path)
        if precondition_ids_by_path
        else set()
    )

    if len(paths) > MAX_OR_PATHS:
        logger.warning(
            "Attack tree produces %d paths (OR-gate cross-product), capping at %d",
            len(paths),
            MAX_OR_PATHS,
        )
        paths = paths[:MAX_OR_PATHS]

    # Only external preconditions common to every attack path belong in the
    # Background. Branch-only preconditions remain in their Scenario blocks.
    background_preconditions = [
        leaf
        for leaf in leaf_nodes
        if leaf.id in background_precondition_ids
        and _leaf_step_kind(leaf) == _STEP_KIND_GIVEN
    ]

    # --- Background: preconditions ---
    lines.append("  Background: Preconditions")

    for i, prec_leaf in enumerate(background_preconditions):
        prec_text = _format_leaf_step_text(prec_leaf, profile)
        keyword = "Given" if i == 0 else "And"
        lines.append(f"    {keyword} {prec_text}")
    background_step_added = bool(background_preconditions)

    # Additional zone/capability preconditions — scoped to zones
    # actually present in the tree's leaf nodes, not the full profile
    from asago_scenario_generator.models.capability_profile import ZONE_DISPLAY_NAMES

    for zone in profile.zones_active:
        if zone not in tree_zones:
            continue  # zone not used in this scenario's tree

        display_name = ZONE_DISPLAY_NAMES.get(zone, zone)
        keyword = "And" if background_step_added else "Given"
        lines.append(
            f"    {keyword} the system has {display_name} capabilities ({zone})"
        )
        background_step_added = True
    lines.append("")

    multi_path = len(paths) > 1

    for path_idx, path_leaves in enumerate(paths, 1):
        # --- Separate leaves by step kind ---
        scenario_preconditions: list[AttackTreeNode] = []
        when_leaves: list[AttackTreeNode] = []
        then_leaves: list[AttackTreeNode] = []
        for leaf in path_leaves:
            kind = _leaf_step_kind(leaf)
            if kind == _STEP_KIND_GIVEN:
                if leaf.id not in background_precondition_ids:
                    scenario_preconditions.append(leaf)
            elif kind == _STEP_KIND_THEN:
                then_leaves.append(leaf)
            else:
                when_leaves.append(leaf)

        # Initial ingress is always the first attack action, independent of
        # incidental tree traversal order.
        when_leaves.sort(
            key=lambda leaf: (
                leaf.action is None or leaf.action.kind != "initial_ingress"
            )
        )

        # --- Scenario header ---
        if multi_path:
            lines.append(f"  Scenario: {narrative.title} (Path {path_idx})")
        else:
            lines.append(f"  Scenario: {narrative.title}")
        lines.append("    Given the system is in its normal operating state")

        for prec_leaf in scenario_preconditions:
            prec_text = _format_leaf_step_text(prec_leaf, profile)
            lines.append(f"    And {prec_text}")
        lines.append("")

        # --- Attack steps (When/And) from action leaves ---
        for i, leaf in enumerate(when_leaves):
            step_text = _format_leaf_step_text(leaf, profile)
            keyword = "When" if i == 0 else "And"
            lines.append(f"    {keyword} {step_text}")

        # --- Impact steps (Then) from impact leaves ---
        for leaf in then_leaves:
            step_text = _format_leaf_step_text(leaf, profile)
            lines.append(f"    Then {step_text}")

        lines.append("")
        lines.append(f"    {_ASSERTIONS_MARKER}")

        # Blank line between scenarios (not after the last one)
        if path_idx < len(paths):
            lines.append("")

    return "\n".join(lines) + "\n"


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
    leaf_catalog: list[dict[str, Any]] = []
    for leaf in _collect_leaf_nodes_dfs(attack_tree.root):
        step_kind = _leaf_step_kind(leaf)
        eligible = (
            "Given"
            if step_kind == _STEP_KIND_GIVEN
            else "Then"
            if step_kind == _STEP_KIND_THEN
            else "When"
        )
        action_kind = leaf.action.kind if leaf.action else "unknown"
        leaf_entry: dict[str, Any] = {
            "leaf_id": leaf.id,
            "projected_step_ids": list(leaf.projected_step_ids),
            "action_kind": action_kind,
            "zone": leaf.zone,
            "eligible_keyword": eligible,
        }
        # Enrich with full per-step canonical semantics from projection
        # context so the LLM can emit complete realization records.
        if projection_context:
            step_semantics = {}
            for sd in projection_context.get("selected_steps", []):
                step_semantics[sd["step_id"]] = sd
            leaf_step_data = []
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
                            "boundary_position": realization.get(
                                "boundary_position", ""
                            ),
                            "consumed_ref_ids": realization.get("consumed_ref_ids", []),
                            "produced_ref_ids": realization.get("produced_ref_ids", []),
                            "produced_effect_ids": realization.get(
                                "produced_effect_ids", []
                            ),
                            "outcome_link_pc_ids": realization.get(
                                "outcome_link_pc_ids", []
                            ),
                            "postcondition_ids": realization.get(
                                "postcondition_ids", []
                            ),
                            "resource_ref_ids": realization.get("resource_ref_ids", []),
                        }
                    )
            leaf_entry["step_semantics"] = leaf_step_data
        leaf_catalog.append(leaf_entry)

    # Build postcondition ownership table from projection context.
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
            build_behavior_draft_response_model,
            derive_behavior_handles,
            strip_compiler_owned_zone_suffix,
        )

        semantic_context = derive_behavior_handles(
            attack_tree, profile, projection_context
        )
        response_model: type[BaseModel] = build_behavior_draft_response_model(
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
        system_prompt = (
            "You author concrete behavioral interactions for one adversarial "
            "scenario. Return only the structured response. Use every action "
            "and assertion handle exactly once and preserve action order. "
            "You control scenario grouping, titles, concrete interaction text, "
            "example values, and assertion wording. The compiler places each "
            "assertion immediately after its canonical owning action. Never emit Gherkin syntax "
            "or canonical IDs; the compiler owns identity and rendering."
        )
        action_inventory = [
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
        assertion_inventory = [
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
    else:
        ctx = build_call3_context(
            seed=seed,
            narrative=narrative,
            attack_tree=attack_tree,
            profile=profile,
            scenario_tag=scenario_tag,
            projection_context=projection_context,
        )
        response_model = (
            CompactCall3Response if compact_response_schema else Call3Response
        )
        system_prompt = render_prompt("call3_system.j2")
        user_prompt = render_prompt("call3_user.j2", **ctx)
    if completion_length_feedback:
        user_prompt = f"{user_prompt}{completion_length_feedback}"
    result = client.complete(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_format=response_model,
        max_completion_tokens=max_completion_tokens,
    )

    if semantic_context is not None and (
        not isinstance(result.content, Call3Response)
        and (not isinstance(result.content, dict) or "scenarios" in result.content)
    ):
        from asago_scenario_generator.pipeline.generate.behavior_semantics import (
            BehaviorDraftV2,
            compile_behavior_draft,
        )

        draft = (
            result.content
            if isinstance(result.content, BehaviorDraftV2)
            else BehaviorDraftV2.model_validate(result.content)
        )
        behavior_spec = compile_behavior_draft(draft, semantic_context)
    else:
        # Compatibility for recorded/scripted Call3Response fixtures. New
        # provider requests use BehaviorDraftV2 when projection context exists.
        call3_response = (
            result.content
            if isinstance(result.content, Call3Response)
            else Call3Response.model_validate(result.content)
        )
        actions = _derive_behavior_actions(attack_tree, profile, projection_context)
        _validate_call3_response(call3_response, attack_tree, projection_context)
        behavior_spec = _call3_response_to_behavior_spec(call3_response, actions)

    return behavior_spec, result


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

    # Build postcondition ownership: pc_id → owning step_id
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
        if assertion.assertion_id in assertion_ids:
            raise ValueError(
                f"Duplicate assertion ID '{assertion.assertion_id}' in Call 3 response"
            )
        assertion_ids.add(assertion.assertion_id)

        # Exactly one source step and one postcondition per assertion.
        if len(assertion.source_step_ids) != 1:
            raise ValueError(
                f"Assertion '{assertion.assertion_id}' has "
                f"{len(assertion.source_step_ids)} source_step_ids — "
                f"exactly one (the owning step) is required"
            )
        if len(assertion.projected_postcondition_ids) != 1:
            raise ValueError(
                f"Assertion '{assertion.assertion_id}' has "
                f"{len(assertion.projected_postcondition_ids)} "
                f"projected_postcondition_ids — exactly one per assertion "
                f"is required (one assertion per owning-step/postcondition pair)"
            )

        source_step = assertion.source_step_ids[0]
        pc_id = assertion.projected_postcondition_ids[0]

        if source_step not in selected_step_ids:
            raise ValueError(
                f"Assertion '{assertion.assertion_id}' references "
                f"unprojected source step '{source_step}'"
            )

        if pc_id not in pc_ownership:
            raise ValueError(
                f"Assertion '{assertion.assertion_id}' references "
                f"unknown postcondition '{pc_id}'"
            )

        # Exact ownership: source_step must be THE owner, not just a member.
        owning_step = pc_ownership[pc_id]
        if source_step != owning_step:
            raise ValueError(
                f"Assertion '{assertion.assertion_id}' states source step "
                f"'{source_step}' but postcondition '{pc_id}' is owned by "
                f"step '{owning_step}' — source_step_ids must exactly equal "
                f"the postcondition owner, not merely contain it"
            )

        # Deterministic assertion ID: assert-<owner_step>-<postcondition>
        expected_assertion_id = f"assert-{owning_step}-{pc_id}"
        if assertion.assertion_id != expected_assertion_id:
            raise ValueError(
                f"Assertion ID '{assertion.assertion_id}' does not match "
                f"deterministic expected ID '{expected_assertion_id}' "
                f"(assert-<owning_step_id>-<postcondition_id>)"
            )

        # No duplicate (step, postcondition) pairs.
        pair = (owning_step, pc_id)
        if pair in seen_assertion_pairs:
            raise ValueError(
                f"Assertion '{assertion.assertion_id}' duplicates the "
                f"(step, postcondition) pair ({owning_step}, {pc_id}) "
                f"already covered by another assertion"
            )
        seen_assertion_pairs.add(pair)

        if pair in security_relevant_pairs:
            covered_security_pairs.add(pair)

    # Full security-relevant postcondition coverage
    uncovered_security_pairs = security_relevant_pairs - covered_security_pairs
    if uncovered_security_pairs:
        raise ValueError(
            f"Call 3 response does not cover security-relevant "
            f"postconditions: {sorted(uncovered_security_pairs)}"
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
        kind = _leaf_step_kind(leaf)
        keyword = (
            "Given"
            if kind == _STEP_KIND_GIVEN
            else "Then"
            if kind == _STEP_KIND_THEN
            else "When"
        )
        actions.append(
            BehaviorAction(
                action_id=f"ba-{leaf.id}",
                projected_step_ids=leaf.projected_step_ids,
                source_leaf_id=leaf.id,
                gherkin_keyword=keyword,
                text=_format_leaf_step_text(leaf, profile),
                realizations=tuple(realizations),
            )
        )
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

    from asago_scenario_generator.pipeline.generate.assembly import (
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
