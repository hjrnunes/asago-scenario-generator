"""Per-step semantic compatibility between mapped artifacts and projection.

One validator-derived authority (contract §4): typed action-kind and
executor-role compatibility, boundary/zone rules (including the literal
``outside`` narrative zone), exact resource bindings, and observable
postcondition semantics for tree leaves and behavior assertions.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from asago_scenario_generator.models.attack_tree import (
    ImpactAction,
    IntegrationInteractionAction,
    ToolInvocationAction,
)
from asago_scenario_generator.models.projection_envelope import (
    ArtifactStage,
    ProjectionEnvelopeBlock,
    ProjectionTraceabilityStage,
    ProjectionTraceabilityViolation,
    ProjectionTraceabilityViolationCode,
)
from asago_scenario_generator.models.realization import (
    ProjectedStepRealization,
    derive_step_realization,
)
from asago_scenario_generator.pipeline.compatibility import (
    EXECUTOR_ROLE_TO_LEAF_COMPAT as _EXECUTOR_ROLE_TO_LEAF_COMPAT,
    STEP_TO_LEAF_ACTION_COMPAT as _STEP_TO_LEAF_ACTION_COMPAT,
)
from asago_scenario_generator.pipeline.projection_realizations import (
    _check_complete_coverage,
    _check_no_duplicated_steps,
    _check_no_unprojected_steps,
    _iter_leaves,
)

if TYPE_CHECKING:
    from asago_scenario_generator.models.scenario import ScenarioEnvelope


_STEP_ACTION_KIND_TO_GHERKIN: dict[str, set[str]] = {
    "prepare": {"Given"},
    "deliver": {"Given", "When"},
    "invoke": {"When"},
    "transform": {"When"},
    "persist": {"When"},
    "observe": {"When"},
    "impact": {"Then", "When"},
}


def _compare_realization_to_step(
    realization: ProjectedStepRealization,
    step: Any,
    stage: ProjectionTraceabilityStage,
    element_id: str,
    binding_by_slot: dict[str, Any] | None = None,
) -> list[ProjectionTraceabilityViolation]:
    """Compare a ``ProjectedStepRealization`` against a canonical step.

    Uses :func:`derive_step_realization` to build the canonical expected
    record and compares via **direct ``==`` equality** — no sorting, no
    field-by-field checks.  Tuples preserve canonical order, so a
    permutation is a violation.  All fields including expected empty
    tuples are compared unconditionally.

    Returns a list of violations (empty if the realization matches).
    """
    expected = derive_step_realization(step, binding_by_slot or {})
    if realization != expected:
        return [
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.incorrect_resource_binding,
                stage=stage,
                detail=(
                    f"element '{element_id}' realization for step "
                    f"'{step.step_id}' does not exactly match canonical "
                    f"derivation: got={realization}, expected={expected}"
                ),
                element_id=element_id,
                projected_step_id=step.step_id,
            )
        ]
    return []


# Active Schneider zones an inside/crossing element may use (never "outside").
_ACTIVE_SCHNEIDER_ZONES: set[str] = {
    "input",
    "reasoning",
    "tool_execution",
    "memory",
    "inter_agent",
}

# Mapping from canonical boundary_position to valid tree leaf constraints.
_BOUNDARY_COMPAT: dict[str, set[str | None]] = {
    "outside": {None},  # outside steps → external_precondition (no zone)
    "crossing": _ACTIVE_SCHNEIDER_ZONES,
    "inside": _ACTIVE_SCHNEIDER_ZONES,
}

# Mapping from canonical boundary_position to valid NARRATIVE step zones.
# Stage-specific: a narrative step representing activity outside the assessed
# boundary uses the literal zone 'outside' (never an active Schneider zone);
# inside/crossing narrative steps use active Schneider zones.
_NARRATIVE_BOUNDARY_ZONE_COMPAT: dict[str, set[str]] = {
    "outside": {"outside"},
    "crossing": _ACTIVE_SCHNEIDER_ZONES,
    "inside": _ACTIVE_SCHNEIDER_ZONES,
}


def _check_step_semantic_compatibility(
    envelope: ScenarioEnvelope,
    block: ProjectionEnvelopeBlock,
) -> list[ProjectionTraceabilityViolation]:
    """Validate per-step semantic compatibility between mapped leaves and projection.

    For each mapped leaf, validate:
    - typed action kind compatibility with the projected step's action_kind
    - executor/boundary/zone compatibility
    - exact resource slot/binding linked to that projected step
    - relevant consumed/produced/effect semantics
    - observable postconditions

    A resource bound for another step must fail.  An incompatible action
    kind/effect/postcondition mapping must fail.
    """
    violations: list[ProjectionTraceabilityViolation] = []
    tree = envelope.attack_tree
    step_by_id, boundary_by_id = _step_semantic_context(block)
    leaf_by_id = _semantic_leaf_by_id(tree)
    binding_by_slot = _binding_by_slot(block)

    if tree is not None:
        _check_tree_leaf_semantics(
            tree,
            step_by_id,
            boundary_by_id,
            binding_by_slot,
            violations,
        )
    _check_narrative_step_semantics(
        envelope.narrative, step_by_id, binding_by_slot, violations
    )
    _check_behavior_action_semantics(
        envelope, step_by_id, leaf_by_id, binding_by_slot, violations
    )

    return violations


def _step_semantic_context(
    block: ProjectionEnvelopeBlock,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return step_id and boundary_position lookup maps for the chain."""
    chain = block.projection.source_chain
    return (
        {s.step_id: s for s in chain.steps},
        {s.step_id: s.boundary_position for s in chain.steps},
    )


def _semantic_leaf_by_id(tree: Any) -> dict[str, Any]:
    """Return leaf_id to leaf lookups for the tree, if any."""
    if tree is None:
        return {}
    return {leaf.id: leaf for leaf in _iter_leaves(tree.root)}


def _binding_by_slot(block: ProjectionEnvelopeBlock) -> dict[str, Any]:
    """Return slot_id to resource reference lookups for the projection."""
    return {b.slot_id: b.resource_ref for b in block.projection.bindings}


def _check_tree_leaf_semantics(
    tree: Any,
    step_by_id: dict[str, Any],
    boundary_by_id: dict[str, Any],
    binding_by_slot: dict[str, Any],
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Run every tree-leaf semantic compatibility check."""
    for leaf in _iter_leaves(tree.root):
        _check_tree_leaf_external_precondition(leaf, boundary_by_id, violations)
        if not leaf.projected_step_ids:
            continue
        for sid in leaf.projected_step_ids:
            _check_tree_leaf_step_mapping(
                leaf, sid, step_by_id, binding_by_slot, violations
            )


def _external_precondition_mapping_invalid(
    leaf: Any,
    boundary_by_id: dict[str, Any],
) -> bool:
    """True when an external precondition leaf maps non-outside steps or
    carries realizations without step IDs."""
    if any(boundary_by_id.get(sid) != "outside" for sid in leaf.projected_step_ids):
        return True
    return bool(leaf.realizations) and not leaf.projected_step_ids


def _check_tree_leaf_external_precondition(
    leaf: Any,
    boundary_by_id: dict[str, Any],
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Flag external precondition leaves with invalid mappings."""
    action = leaf.action
    if action is None or action.kind != "external_precondition":
        return
    if _external_precondition_mapping_invalid(leaf, boundary_by_id):
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.incorrect_resource_binding,
                stage=ProjectionTraceabilityStage.attack_tree,
                detail=(
                    f"external precondition leaf '{leaf.id}' has "
                    f"{len(leaf.projected_step_ids)} projected_step_ids "
                    f"and {len(leaf.realizations)} realization records "
                    f"— only outside-boundary external preconditions "
                    f"may be mapped"
                ),
                element_id=leaf.id,
                projected_step_id="",
            )
        )


def _check_leaf_action_kind_compat(
    leaf: Any,
    action: Any,
    step: Any,
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Flag leaf action kinds incompatible with the projected action_kind."""
    compatible_kinds = _STEP_TO_LEAF_ACTION_COMPAT.get(step.action_kind, set())
    if action.kind not in compatible_kinds:
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.incorrect_resource_binding,
                stage=ProjectionTraceabilityStage.attack_tree,
                detail=(
                    f"tree leaf '{leaf.id}' action kind '{action.kind}' "
                    f"is incompatible with projected step "
                    f"'{step.step_id}' action_kind '{step.action_kind}' "
                    f"(expected one of {sorted(compatible_kinds)})"
                ),
                element_id=leaf.id,
                projected_step_id=step.step_id,
            )
        )


def _boundary_zone_summary(valid_zones: Any) -> Any:
    """Return the sorted non-null zone list, or the literal 'None' string."""
    return sorted(v for v in valid_zones if v is not None) or "None"


def _check_leaf_boundary_compat(
    leaf: Any,
    action: Any,
    step: Any,
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Flag zone/boundary incompatibilities for one leaf-step mapping."""
    valid_zones = _BOUNDARY_COMPAT.get(step.boundary_position, set())
    external_impact = isinstance(action, ImpactAction) and action.boundary == "external"
    if external_impact:
        # External impacts occur outside the assessed boundary,
        # so the leaf zone is null by model contract and the
        # generic zone check does not apply.  Every mapped
        # projected step must itself be outside-boundary; a
        # non-outside mapping is a boundary semantic violation
        # — the step ID is preserved, never removed or remapped.
        if step.boundary_position != "outside":
            violations.append(
                ProjectionTraceabilityViolation(
                    code=ProjectionTraceabilityViolationCode.incorrect_resource_binding,
                    stage=ProjectionTraceabilityStage.attack_tree,
                    detail=(
                        f"tree leaf '{leaf.id}' external impact "
                        f"maps non-outside projected step "
                        f"'{step.step_id}' (boundary_position "
                        f"'{step.boundary_position}') — boundary "
                        f"semantic violation"
                    ),
                    element_id=leaf.id,
                    projected_step_id=step.step_id,
                )
            )
    elif leaf.zone not in valid_zones:
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.incorrect_resource_binding,
                stage=ProjectionTraceabilityStage.attack_tree,
                detail=(
                    f"tree leaf '{leaf.id}' zone '{leaf.zone}' is "
                    f"incompatible with projected step "
                    f"'{step.step_id}' boundary_position "
                    f"'{step.boundary_position}' (expected one of "
                    f"{_boundary_zone_summary(valid_zones)})"
                ),
                element_id=leaf.id,
                projected_step_id=step.step_id,
            )
        )


def _check_leaf_executor_role_compat(
    leaf: Any,
    action: Any,
    step: Any,
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Flag leaf action kinds incompatible with the projected executor role."""
    compatible_role_kinds = _EXECUTOR_ROLE_TO_LEAF_COMPAT.get(step.executor_role, set())
    if action.kind not in compatible_role_kinds:
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.incorrect_resource_binding,
                stage=ProjectionTraceabilityStage.attack_tree,
                detail=(
                    f"tree leaf '{leaf.id}' action kind '{action.kind}' "
                    f"is incompatible with projected step "
                    f"'{step.step_id}' executor_role "
                    f"'{step.executor_role}' "
                    f"(expected one of {sorted(compatible_role_kinds)})"
                ),
                element_id=leaf.id,
                projected_step_id=step.step_id,
            )
        )


def _check_leaf_produced_effect_compat(
    leaf: Any,
    action: Any,
    step: Any,
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Flag impact actions on steps that produce no effect.

    The original guard only inspected the ai_system_action escalation path
    (a documented no-op pass); the only observable branch is the impact
    branch, so it is evaluated directly.
    """
    if action.kind != "impact":
        return
    if not any(p.kind == "effect" for p in step.produced):
        step_produced_kinds = {p.kind for p in step.produced}
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.incorrect_resource_binding,
                stage=ProjectionTraceabilityStage.attack_tree,
                detail=(
                    f"tree leaf '{leaf.id}' has impact action but "
                    f"projected step '{step.step_id}' produces no "
                    f"effect (produced={sorted(step_produced_kinds)})"
                ),
                element_id=leaf.id,
                projected_step_id=step.step_id,
            )
        )


def _check_leaf_tool_binding(
    leaf: Any,
    action: Any,
    step: Any,
    link: Any,
    ref: Any,
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Flag tool fixture bindings that disagree with the leaf tool_id."""
    if not (
        isinstance(action, ToolInvocationAction)
        and link.role in ("tool_fixture", "tool")
    ):
        return
    from asago_scenario_generator.models.attack_pattern_projection import (
        ToolResourceReference,
    )

    if isinstance(ref, ToolResourceReference) and action.tool_id != ref.tool_id:
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.incorrect_resource_binding,
                stage=ProjectionTraceabilityStage.attack_tree,
                detail=(
                    f"tree leaf '{leaf.id}' tool_id "
                    f"'{action.tool_id}' does not match "
                    f"resource binding for slot "
                    f"'{link.slot_id}' on projected "
                    f"step '{step.step_id}' "
                    f"(expected '{ref.tool_id}')"
                ),
                element_id=leaf.id,
                projected_step_id=step.step_id,
            )
        )


def _resource_ref_integration_mismatch(ref: Any, integration_id: str) -> bool:
    """True when a resource reference binds a different integration."""
    from asago_scenario_generator.models.attack_pattern_projection import (
        IntegrationResourceReference,
    )

    return (
        isinstance(ref, IntegrationResourceReference)
        and integration_id != ref.integration_id
    )


def _check_leaf_integration_binding(
    leaf: Any,
    action: Any,
    step: Any,
    link: Any,
    ref: Any,
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Flag integration bindings that disagree with the leaf integration_id."""
    if not (
        isinstance(action, IntegrationInteractionAction)
        and link.role in ("integration", "downstream")
    ):
        return
    if _resource_ref_integration_mismatch(ref, action.integration_id):
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.incorrect_resource_binding,
                stage=ProjectionTraceabilityStage.attack_tree,
                detail=(
                    f"tree leaf '{leaf.id}' integration_id "
                    f"'{action.integration_id}' does not "
                    f"match resource binding for slot "
                    f"'{link.slot_id}' on projected "
                    f"step '{step.step_id}' "
                    f"(expected '{ref.integration_id}')"
                ),
                element_id=leaf.id,
                projected_step_id=step.step_id,
            )
        )


def _check_leaf_sourced_tool_binding(
    leaf: Any,
    action: Any,
    step: Any,
    link: Any,
    ref: Any,
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Flag tool invocation integrations that disagree with bindings."""
    integration_role = link.role in ("integration", "downstream")
    if not isinstance(action, ToolInvocationAction):
        return
    if not action.integration_id or not integration_role:
        return
    if _resource_ref_integration_mismatch(ref, action.integration_id):
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.incorrect_resource_binding,
                stage=ProjectionTraceabilityStage.attack_tree,
                detail=(
                    f"tree leaf '{leaf.id}' integration_id "
                    f"'{action.integration_id}' does not "
                    f"match resource binding for slot "
                    f"'{link.slot_id}' on projected "
                    f"step '{step.step_id}' "
                    f"(expected '{ref.integration_id}')"
                ),
                element_id=leaf.id,
                projected_step_id=step.step_id,
            )
        )


def _check_leaf_resource_bindings(
    leaf: Any,
    action: Any,
    step: Any,
    binding_by_slot: dict[str, Any],
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Run every per-link resource binding check for a leaf-step mapping."""
    for link in step.resource_links:
        ref = binding_by_slot.get(link.slot_id)
        if ref is None:
            continue
        _check_leaf_tool_binding(leaf, action, step, link, ref, violations)
        _check_leaf_integration_binding(leaf, action, step, link, ref, violations)
        _check_leaf_sourced_tool_binding(leaf, action, step, link, ref, violations)


def _check_leaf_realizations(
    leaf: Any,
    sid: str,
    step: Any,
    binding_by_slot: dict[str, Any],
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Reconcile every tree-leaf realization record with the canonical step."""
    for realization in leaf.realizations:
        if realization.projected_step_id != sid:
            continue
        violations.extend(
            _compare_realization_to_step(
                realization,
                step,
                stage=ProjectionTraceabilityStage.attack_tree,
                element_id=leaf.id,
                binding_by_slot=binding_by_slot,
            )
        )


def _check_tree_leaf_step_mapping(
    leaf: Any,
    sid: str,
    step_by_id: dict[str, Any],
    binding_by_slot: dict[str, Any],
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Run every semantic compatibility check for one leaf-step mapping."""
    step = step_by_id.get(sid)
    if step is None:
        return  # caught by unprojected step check
    action = leaf.action
    if action is None:
        return
    _check_leaf_action_kind_compat(leaf, action, step, violations)
    _check_leaf_boundary_compat(leaf, action, step, violations)
    _check_leaf_executor_role_compat(leaf, action, step, violations)
    _check_leaf_produced_effect_compat(leaf, action, step, violations)
    _check_leaf_resource_bindings(leaf, action, step, binding_by_slot, violations)
    _check_leaf_realizations(leaf, sid, step, binding_by_slot, violations)


def _check_narrative_step_mapping(
    n_step: Any,
    sid: str,
    step_by_id: dict[str, Any],
    binding_by_slot: dict[str, Any],
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Run every semantic compatibility check for one narrative step."""
    step = step_by_id.get(sid)
    if step is None:
        return
    # Narrative stage boundary rules: outside-boundary steps use the
    # literal zone 'outside'; inside/crossing steps use an active
    # Schneider zone (never 'outside').
    valid_zones = _NARRATIVE_BOUNDARY_ZONE_COMPAT.get(step.boundary_position, set())
    if n_step.zone not in valid_zones:
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.incorrect_resource_binding,
                stage=ProjectionTraceabilityStage.narrative,
                detail=(
                    f"narrative step '{n_step.step_number}' zone "
                    f"'{n_step.zone}' is incompatible with projected "
                    f"step '{step.step_id}' boundary_position "
                    f"'{step.boundary_position}'"
                ),
                element_id=str(n_step.step_number),
                projected_step_id=step.step_id,
            )
        )
    # --- Per-step realization record reconciliation (422o.4 blocker #3) ---
    # Compare each realization record against the embedded canonical
    # step.  All non-empty additional fields are checked; the
    # production path always populates them.
    for realization in n_step.realizations:
        if realization.projected_step_id != sid:
            continue
        violations.extend(
            _compare_realization_to_step(
                realization,
                step,
                stage=ProjectionTraceabilityStage.narrative,
                element_id=str(n_step.step_number),
                binding_by_slot=binding_by_slot,
            )
        )


def _check_narrative_step_semantics(
    narrative: Any,
    step_by_id: dict[str, Any],
    binding_by_slot: dict[str, Any],
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Run narrative semantic compatibility for every mapped step."""
    for n_step in narrative.steps:
        if not n_step.projected_step_ids:
            continue
        for sid in n_step.projected_step_ids:
            _check_narrative_step_mapping(
                n_step, sid, step_by_id, binding_by_slot, violations
            )


def _behavior_leaf_kind(leaf_by_id: dict[str, Any], source_leaf_id: str) -> Any:
    """Return the finalized source leaf's action kind, if any."""
    source_leaf = leaf_by_id.get(source_leaf_id)
    if source_leaf is not None and source_leaf.action is not None:
        return source_leaf.action.kind
    return None


def _behavior_leaf_keywords(leaf_kind: Any) -> set[str]:
    """Return the Gherkin keyword set owned by a leaf action kind."""
    if leaf_kind == "external_precondition":
        return {"Given"}
    if leaf_kind == "impact":
        return {"Then"}
    if leaf_kind is not None:
        return {"When"}
    return set()


def _check_behavior_keyword_compat(
    b_action: Any,
    step: Any,
    leaf_by_id: dict[str, Any],
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Flag Gherkin keywords outside the leaf- and step-owned sets."""
    # Phase 3B actions are derived from the finalized leaf.  The
    # leaf's typed action discriminator owns the eligible Gherkin
    # keyword; projected action_kind still owns the canonical
    # realization record checked below.
    leaf_kind = _behavior_leaf_kind(leaf_by_id, b_action.source_leaf_id)
    leaf_keywords = _behavior_leaf_keywords(leaf_kind)
    # Legacy structured envelopes authored actions from projected
    # action_kind.  Keep those readable while Phase 3B admission
    # separately enforces the single deterministic leaf keyword.
    valid_keywords = leaf_keywords | _STEP_ACTION_KIND_TO_GHERKIN.get(
        step.action_kind, set()
    )
    if valid_keywords and b_action.gherkin_keyword not in valid_keywords:
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.postcondition_assertion_mismatch,
                stage=ProjectionTraceabilityStage.behavior_spec,
                detail=(
                    f"behavior action '{b_action.action_id}' "
                    f"gherkin_keyword '{b_action.gherkin_keyword}' "
                    f"is incompatible with finalized leaf "
                    f"'{b_action.source_leaf_id}' action kind "
                    f"'{leaf_kind}' "
                    f"(expected one of {sorted(valid_keywords)})"
                ),
                element_id=b_action.action_id,
                projected_step_id=step.step_id,
            )
        )


def _check_behavior_source_leaf_compat(
    b_action: Any,
    sid: str,
    leaf_by_id: dict[str, Any],
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Flag behavior actions whose source leaf maps a different step."""
    if not b_action.source_leaf_id:
        return
    leaf = leaf_by_id.get(b_action.source_leaf_id)
    if (
        leaf is not None
        and leaf.projected_step_ids
        and sid not in leaf.projected_step_ids
    ):
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.incorrect_resource_binding,
                stage=ProjectionTraceabilityStage.behavior_spec,
                detail=(
                    f"behavior action '{b_action.action_id}' "
                    f"maps to step '{sid}' but its "
                    f"source_leaf_id '{b_action.source_leaf_id}' "
                    f"maps to {leaf.projected_step_ids}"
                ),
                element_id=b_action.action_id,
                projected_step_id=sid,
            )
        )


def _check_behavior_action_step(
    b_action: Any,
    sid: str,
    step: Any,
    leaf_by_id: dict[str, Any],
    binding_by_slot: dict[str, Any],
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Run every behavior action semantic check for one mapped step."""
    _check_behavior_keyword_compat(b_action, step, leaf_by_id, violations)
    _check_behavior_source_leaf_compat(b_action, sid, leaf_by_id, violations)
    # --- Per-step realization record reconciliation (422o.4 blocker #3) ---
    for realization in b_action.realizations:
        if realization.projected_step_id != sid:
            continue
        violations.extend(
            _compare_realization_to_step(
                realization,
                step,
                stage=ProjectionTraceabilityStage.behavior_spec,
                element_id=b_action.action_id,
                binding_by_slot=binding_by_slot,
            )
        )


def _check_behavior_action_semantics(
    envelope: ScenarioEnvelope,
    step_by_id: dict[str, Any],
    leaf_by_id: dict[str, Any],
    binding_by_slot: dict[str, Any],
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Run behavior action semantic compatibility for every mapped step."""
    from asago_scenario_generator.models.scenario import BehaviorSpec

    behavior_spec = envelope.behavior_spec
    if not isinstance(behavior_spec, BehaviorSpec):
        return
    for b_action in behavior_spec.actions:
        for sid in b_action.projected_step_ids:
            step = step_by_id.get(sid)
            if step is None:
                continue  # caught by unprojected step check
            _check_behavior_action_step(
                b_action, sid, step, leaf_by_id, binding_by_slot, violations
            )


_GHERKIN_KEYWORDS: tuple[str, ...] = ("Given", "When", "Then", "And")


def _behavior_element_exists_check(
    realizations: tuple[Any, ...],
    actual_action_ids: set[str],
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Flag block behavior realizations whose element is not an actual action."""
    for r in realizations:
        if r.element_id not in actual_action_ids:
            violations.append(
                ProjectionTraceabilityViolation(
                    code=ProjectionTraceabilityViolationCode.forged_opaque_id,
                    stage=ProjectionTraceabilityStage.behavior_spec,
                    detail=(
                        f"behavior realization element '{r.element_id}' "
                        f"does not exist in actual BehaviorSpec actions"
                    ),
                    element_id=r.element_id,
                )
            )


def _behavior_mapping_mismatches(
    actual_action_map: dict[str, tuple[str, ...]],
    block_behavior_map: dict[str, tuple[str, ...]],
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Flag actual actions absent from or mismapped in the block realizations."""
    for action_id, actual_sids in actual_action_map.items():
        block_sids = block_behavior_map.get(action_id)
        if block_sids is None:
            violations.append(
                ProjectionTraceabilityViolation(
                    code=ProjectionTraceabilityViolationCode.incomplete_coverage,
                    stage=ProjectionTraceabilityStage.behavior_spec,
                    detail=(
                        f"behavior action '{action_id}' exists in "
                        f"BehaviorSpec but is absent from block "
                        f"behavior_realizations"
                    ),
                    element_id=action_id,
                    projected_step_id=actual_sids[0],
                )
            )
        elif set(actual_sids) != set(block_sids):
            violations.append(
                ProjectionTraceabilityViolation(
                    code=ProjectionTraceabilityViolationCode.forged_opaque_id,
                    stage=ProjectionTraceabilityStage.behavior_spec,
                    detail=(
                        f"behavior action '{action_id}' has "
                        f"projected_step_ids {actual_sids} but block "
                        f"maps it to {block_sids}"
                    ),
                    element_id=action_id,
                    projected_step_id=actual_sids[0],
                )
            )


def _behavior_spec_cross_check(
    behavior_spec: Any,
    block: ProjectionEnvelopeBlock,
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Cross-check block behavior realizations against the actual BehaviorSpec."""
    actual_action_ids = {a.action_id for a in behavior_spec.actions}
    actual_action_map: dict[str, tuple[str, ...]] = {
        a.action_id: a.projected_step_ids for a in behavior_spec.actions
    }
    block_behavior_map: dict[str, tuple[str, ...]] = {
        r.element_id: r.projected_step_ids for r in block.behavior_realizations
    }

    # Every block behavior realization element must exist in actual actions.
    _behavior_element_exists_check(
        block.behavior_realizations, actual_action_ids, violations
    )

    # Every actual action must be in block realizations with matching steps.
    _behavior_mapping_mismatches(actual_action_map, block_behavior_map, violations)


def _raw_behavior_stage_shape_check(
    realizations: tuple[Any, ...],
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Flag raw behavior realizations with the wrong artifact stage."""
    # Raw text/dict behavior spec — validate only the realization
    # mappings themselves (no structured cross-check possible).
    for r in realizations:
        if r.artifact_stage != ArtifactStage.behavior:
            violations.append(
                ProjectionTraceabilityViolation(
                    code=ProjectionTraceabilityViolationCode.forged_opaque_id,
                    stage=ProjectionTraceabilityStage.behavior_spec,
                    detail=(
                        f"behavior realization element '{r.element_id}' has "
                        f"wrong artifact_stage '{r.artifact_stage.value}'"
                    ),
                    element_id=r.element_id,
                )
            )


def _is_gherkin_step_line(line: str) -> bool:
    """True when a stripped Gherkin line starts with a step keyword."""
    return any(line.startswith(kw) for kw in _GHERKIN_KEYWORDS)


def _extract_step_text(line: str, zone_pat: Any) -> str | None:
    """Return the text after the step keyword with the zone suffix stripped."""
    for kw in _GHERKIN_KEYWORDS:
        if line.startswith(f"{kw} "):
            raw = line[len(kw) :].strip()
            return zone_pat.sub("", raw).strip()
    return None


def _gherkin_step_texts(gherkin_text: str, zone_pat: Any) -> list[str]:
    """Collect the step-line texts of a Gherkin document, zones stripped."""
    step_texts: list[str] = []
    for line in gherkin_text.splitlines():
        line = line.strip()
        if not line:
            continue
        if not _is_gherkin_step_line(line):
            continue
        raw = _extract_step_text(line, zone_pat)
        if raw is not None:
            step_texts.append(raw)
    return step_texts


def _check_action_texts_present(
    actions: Any,
    step_texts: list[str],
    zone_pat: Any,
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Flag behavior action texts that do not appear as a Gherkin step line."""
    for action in actions:
        base_text = zone_pat.sub("", action.text).strip()
        if base_text not in step_texts and not any(
            base_text in st for st in step_texts
        ):
            violations.append(
                ProjectionTraceabilityViolation(
                    code=ProjectionTraceabilityViolationCode.forged_opaque_id,
                    stage=ProjectionTraceabilityStage.behavior_spec,
                    detail=(
                        f"behavior action '{action.action_id}' text "
                        f"'{action.text}' does not appear as a Gherkin "
                        f"step line"
                    ),
                    element_id=action.action_id,
                )
            )


def _check_assertion_texts_present(
    assertions: Any,
    step_texts: list[str],
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Flag behavior assertion texts that do not appear as a Gherkin step line."""
    for assertion in assertions:
        if assertion.text not in step_texts and not any(
            assertion.text in st for st in step_texts
        ):
            violations.append(
                ProjectionTraceabilityViolation(
                    code=ProjectionTraceabilityViolationCode.forged_opaque_id,
                    stage=ProjectionTraceabilityStage.behavior_spec,
                    detail=(
                        f"behavior assertion '{assertion.assertion_id}' "
                        f"text '{assertion.text}' does not appear as a "
                        f"Gherkin step line"
                    ),
                    element_id=assertion.assertion_id,
                )
            )


def _gherkin_correspondence_check(
    behavior_spec: Any,
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Verify the stored Gherkin matches the deterministic structured rendering."""
    # --- Gherkin correspondence (422o.4 blocker #3) ---
    # Strict deterministic correspondence: re-render the Gherkin from the
    # structured actions/assertions and compare exactly against the stored
    # gherkin_text.  This catches any omission, addition, reordering, or
    # fabrication — no substring matching, no fake IDs.
    # Zone annotations (display metadata) are stripped before comparison.
    import re as _re

    from asago_scenario_generator.pipeline.generate.behavior_compiler import (
        render_gherkin_from_behavior_spec,
    )

    # Re-render without zone map (zones are display-only).
    expected_gherkin = render_gherkin_from_behavior_spec(
        list(behavior_spec.actions),
        list(behavior_spec.assertions),
        zone_map=None,
        scenarios=list(behavior_spec.scenarios),
    )
    # Strip zone annotations from both texts for comparison.
    _zone_pat = _re.compile(r"\s*\([^)]*\)\s*$", _re.MULTILINE)
    actual_stripped = _zone_pat.sub("", behavior_spec.gherkin_text).strip()
    expected_stripped = _zone_pat.sub("", expected_gherkin).strip()
    if actual_stripped != expected_stripped:
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.forged_opaque_id,
                stage=ProjectionTraceabilityStage.behavior_spec,
                detail=(
                    "BehaviorSpec.gherkin_text does not exactly match "
                    "the deterministic rendering from structured "
                    "actions/assertions — content was altered, omitted, "
                    "added, reordered, or fabricated"
                ),
            )
        )

    # Also verify that every action and assertion text appears as a
    # distinct step line in the Gherkin (defense in depth).
    step_texts = _gherkin_step_texts(behavior_spec.gherkin_text, _zone_pat)

    # Every action text must appear as a step text.
    _check_action_texts_present(
        behavior_spec.actions, step_texts, _zone_pat, violations
    )
    # Every assertion text must appear as a step text.
    _check_assertion_texts_present(behavior_spec.assertions, step_texts, violations)


def _check_behavior_realizations(
    envelope: ScenarioEnvelope,
    block: ProjectionEnvelopeBlock,
) -> list[ProjectionTraceabilityViolation]:
    violations: list[ProjectionTraceabilityViolation] = []
    realizations = block.behavior_realizations
    selected = set(block.selected_step_ids)

    # --- Cross-check behavior realizations against actual BehaviorSpec ---
    # When behavior_spec is a structured BehaviorSpec, derive expected
    # realizations from its structured actions and compare against block
    # realizations.  Never accept fake IDs that don't exist in the artifact.
    from asago_scenario_generator.models.scenario import BehaviorSpec

    behavior_spec = envelope.behavior_spec
    if isinstance(behavior_spec, BehaviorSpec):
        _behavior_spec_cross_check(behavior_spec, block, violations)
    else:
        # Raw text/dict behavior spec — validate only the realization
        # mappings themselves (no structured cross-check possible).
        _raw_behavior_stage_shape_check(realizations, violations)

    violations.extend(
        _check_no_unprojected_steps(
            realizations, selected, ProjectionTraceabilityStage.behavior_spec
        )
    )
    violations.extend(
        _check_complete_coverage(
            realizations,
            selected,
            ProjectionTraceabilityStage.behavior_spec,
            "behavior",
        )
    )
    violations.extend(
        _check_no_duplicated_steps(
            realizations,
            block,
            ProjectionTraceabilityStage.behavior_spec,
            "behavior",
        )
    )

    # --- Gherkin correspondence (422o.4 blocker #3) ---
    if isinstance(behavior_spec, BehaviorSpec):
        _gherkin_correspondence_check(behavior_spec, violations)

    return violations


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-26T14:07:25Z","module_hash":"ea455541ea5ddbf21d8a514b47bcbe4c593916f8562a21c6facba0d725180bc7","source_sha256":"be94e0a1a15ac74d9a60e3fc910b680d8f77832d388e59cb76185206f4c8f2ec","functions":[{"id":"func/_compare_realization_to_step","name":"_compare_realization_to_step","line":55,"end_line":87,"hash":"e950062338eb894544c13c3e80f3d7f6602f68ddcf182f6b519c573f13671862"},{"id":"func/_check_step_semantic_compatibility","name":"_check_step_semantic_compatibility","line":117,"end_line":154,"hash":"7fa5608fac950d1b7c88092534639218dea3aeda6fd81f0740541c4e8c188c1f"},{"id":"func/_step_semantic_context","name":"_step_semantic_context","line":157,"end_line":165,"hash":"af640119e03c94646f9d0f9aa72779aa3db9f0baac59300ae9f84b2e4655d8ef"},{"id":"func/_semantic_leaf_by_id","name":"_semantic_leaf_by_id","line":168,"end_line":172,"hash":"086c04f3841803a866783cf494b787be5b64e2a63ce47d0a05afba1200219c8a"},{"id":"func/_binding_by_slot","name":"_binding_by_slot","line":175,"end_line":177,"hash":"d4a1fc9d5f6d02b24eb697b198a7903be38bbe4e0bb12c9352f05153cfbee8e9"},{"id":"func/_check_tree_leaf_semantics","name":"_check_tree_leaf_semantics","line":180,"end_line":195,"hash":"9080bbbc7b94c53d1a8b694e7eece48a2339d32f131df69ff027d43dfeca66c5"},{"id":"func/_external_precondition_mapping_invalid","name":"_external_precondition_mapping_invalid","line":198,"end_line":206,"hash":"baa8c6bdfb9c844702756bae4e5bab94998c9202819633725611f59e9efea963"},{"id":"func/_check_tree_leaf_external_precondition","name":"_check_tree_leaf_external_precondition","line":209,"end_line":233,"hash":"8e85fed9648500097094ffbd0d78ec3f27a5398d2af2415cf837ecdf67947309"},{"id":"func/_check_leaf_action_kind_compat","name":"_check_leaf_action_kind_compat","line":236,"end_line":258,"hash":"db003f41ae672f78adb52f43b7fec5267d0d34fc9805c9eab5a0e5dbcfc0e086"},{"id":"func/_boundary_zone_summary","name":"_boundary_zone_summary","line":261,"end_line":263,"hash":"992142dda4b8ce696ae295941a939fd4ae7abe517c8548b7b0f2a29a0d8302eb"},{"id":"func/_check_leaf_boundary_compat","name":"_check_leaf_boundary_compat","line":266,"end_line":313,"hash":"7b46ddac94fc1d3ddf1ce7e182bd80d3bafe1fb11ae890fa8ded54a04a83c88a"},{"id":"func/_check_leaf_executor_role_compat","name":"_check_leaf_executor_role_compat","line":316,"end_line":339,"hash":"c592e1e33c9868db386fd44d7184aa238e0f8121c1f08d8acbf9ee99a82a5fe0"},{"id":"func/_check_leaf_produced_effect_compat","name":"_check_leaf_produced_effect_compat","line":342,"end_line":370,"hash":"4b266807212bb7284005ee461cca0d12d27f3ecb17ee90389de14b3921e898aa"},{"id":"func/_check_leaf_tool_binding","name":"_check_leaf_tool_binding","line":373,"end_line":407,"hash":"ef92da9c7e5d574a9008d6454ac1daefc10f8666048138aa4a20568d6a5946af"},{"id":"func/_resource_ref_integration_mismatch","name":"_resource_ref_integration_mismatch","line":410,"end_line":419,"hash":"494f0b8cab39c634f1710700410f21fe42cd2e766b4604c3826f5e04c4ba7146"},{"id":"func/_check_leaf_integration_binding","name":"_check_leaf_integration_binding","line":422,"end_line":452,"hash":"f72cc5688b9b9d6c8973dece8d24c6bfddbc4f373828063f69f289878c3f8f68"},{"id":"func/_check_leaf_sourced_tool_binding","name":"_check_leaf_sourced_tool_binding","line":455,"end_line":485,"hash":"8c0b84d79f5fce5b06bec3da68c0383d3a77a5aa58f5efc397455af5af038fa3"},{"id":"func/_check_leaf_resource_bindings","name":"_check_leaf_resource_bindings","line":488,"end_line":502,"hash":"ab4f6a50916bf61c4f603114a1b73030acaae6910534e32e8cc96de648f6abcc"},{"id":"func/_check_leaf_realizations","name":"_check_leaf_realizations","line":505,"end_line":524,"hash":"8382c90357d6c3064ef6fdfac66b57731f42e3bd7b8365465f51009c8792d680"},{"id":"func/_check_tree_leaf_step_mapping","name":"_check_tree_leaf_step_mapping","line":527,"end_line":546,"hash":"2c366a6d14dadb60a2e7fdedd19aa502fa0b79593cf26f2984842f1eeb242253"},{"id":"func/_check_narrative_step_mapping","name":"_check_narrative_step_mapping","line":549,"end_line":594,"hash":"f58421c8cdacf3898f4596803b364fcb090c0ae3f1c1faee04034783d83b6280"},{"id":"func/_check_narrative_step_semantics","name":"_check_narrative_step_semantics","line":597,"end_line":610,"hash":"76c37676e366d6b165670be80055e07833958f6df96e575185279ed4234a5725"},{"id":"func/_behavior_leaf_kind","name":"_behavior_leaf_kind","line":613,"end_line":618,"hash":"5b0bb306ae519a37ab86c29ae1d2a8d4540cb11d8564b08f703ccb0495877513"},{"id":"func/_behavior_leaf_keywords","name":"_behavior_leaf_keywords","line":621,"end_line":629,"hash":"73ec411b7a4be9fbcbc8b3f186a9c3f63f1c4cbae4cd82568722c34b6f865be8"},{"id":"func/_check_behavior_keyword_compat","name":"_check_behavior_keyword_compat","line":632,"end_line":667,"hash":"251c421fdf275a5bb5b5f8f607b7eefd0477aca89a7b517e7baad07da3b0839f"},{"id":"func/_check_behavior_source_leaf_compat","name":"_check_behavior_source_leaf_compat","line":670,"end_line":698,"hash":"bd3df9ce339e1a8d64681a88114041e17dd16aa6ccf3fac967918f794506b573"},{"id":"func/_check_behavior_action_step","name":"_check_behavior_action_step","line":701,"end_line":724,"hash":"a601691f723f84930dc4e6cecf5f79843416a9d12f3e1bab5c7455d87c7def9f"},{"id":"func/_check_behavior_action_semantics","name":"_check_behavior_action_semantics","line":727,"end_line":747,"hash":"29b69005a1355d19a766c7f51225578e5561a29e15e7d3277f3f5a439c98986e"},{"id":"func/_behavior_element_exists_check","name":"_behavior_element_exists_check","line":753,"end_line":771,"hash":"314697f71c9c6f142c1d5c98bf575b84446d9faf9c87862436a702fa0bf54b65"},{"id":"func/_behavior_mapping_mismatches","name":"_behavior_mapping_mismatches","line":774,"end_line":809,"hash":"2a8652a12df9c9bc6e598d8f31f20ad4b7a61a43fe4bc7744183de70395f52fe"},{"id":"func/_behavior_spec_cross_check","name":"_behavior_spec_cross_check","line":812,"end_line":832,"hash":"7c427a4b0606bf3971ae44ce34610c4939f7cd144e822510800c4b41ee2d2dbf"},{"id":"func/_raw_behavior_stage_shape_check","name":"_raw_behavior_stage_shape_check","line":835,"end_line":854,"hash":"3562756f31fd82bca53e49a28460da05aa8f9a84d0c70eba1376afe35b09fbd2"},{"id":"func/_is_gherkin_step_line","name":"_is_gherkin_step_line","line":857,"end_line":859,"hash":"593bf16d2091e7879dd287766a9364e9f295c3c96ab43e3b99cb063d4e000578"},{"id":"func/_extract_step_text","name":"_extract_step_text","line":862,"end_line":868,"hash":"f2c754d942fa1fc59f930cbe53326874a614baa47967af40ea8d7fd0b152cf3b"},{"id":"func/_gherkin_step_texts","name":"_gherkin_step_texts","line":871,"end_line":883,"hash":"fa59e01369d7a895b9399da3d2f8e5e1bc61c08c71011f0a38214c45dfe1d9e3"},{"id":"func/_check_action_texts_present","name":"_check_action_texts_present","line":886,"end_line":909,"hash":"bb92127e2db601fc0305ef524a977be5b9609fae9150852d44b3e0bbc2ab6ea8"},{"id":"func/_check_assertion_texts_present","name":"_check_assertion_texts_present","line":912,"end_line":933,"hash":"b32a02d7e3bd02628292b43d32c688f2f3579c51adffd2caeb2703cbbab8ae5b"},{"id":"func/_gherkin_correspondence_check","name":"_gherkin_correspondence_check","line":936,"end_line":987,"hash":"b2d5c7f5594695b33f00bf02084922f620d9f7a51bd4c6f9fdc2458d7fa5455f"},{"id":"func/_check_behavior_realizations","name":"_check_behavior_realizations","line":990,"end_line":1038,"hash":"8c869ee91257d615821499321a8d6773e7b8c4b2d740853b70807d5e9704a9f0"}]}
# mutate4py-manifest-end
