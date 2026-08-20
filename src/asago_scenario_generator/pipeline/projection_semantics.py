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

    chain = block.projection.source_chain
    step_by_id = {s.step_id: s for s in chain.steps}
    boundary_by_id = {s.step_id: s.boundary_position for s in chain.steps}
    _leaf_by_id: dict[str, Any] = {}
    if tree is not None:
        _leaf_by_id = {leaf.id: leaf for leaf in _iter_leaves(tree.root)}
    binding_by_slot = {b.slot_id: b.resource_ref for b in block.projection.bindings}

    # --- Tree leaf semantic compatibility ---
    if tree is not None:
        for leaf in _iter_leaves(tree.root):
            # External preconditions may map only outside-boundary steps.
            # Internal and crossing external leaves must remain unmapped.
            action = leaf.action
            external_mapping_is_invalid = False
            if action is not None and action.kind == "external_precondition":
                external_mapping_is_invalid = any(
                    boundary_by_id.get(sid) != "outside"
                    for sid in leaf.projected_step_ids
                )
            if (
                action is not None
                and action.kind == "external_precondition"
                and (
                    external_mapping_is_invalid
                    or (leaf.realizations and not leaf.projected_step_ids)
                )
            ):
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
            if not leaf.projected_step_ids:
                continue
            for sid in leaf.projected_step_ids:
                step = step_by_id.get(sid)
                if step is None:
                    continue  # caught by unprojected step check

                action = leaf.action
                if action is None:
                    continue

                # --- Action kind compatibility ---
                compatible_kinds = _STEP_TO_LEAF_ACTION_COMPAT.get(
                    step.action_kind, set()
                )
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

                # --- Boundary/zone compatibility ---
                valid_zones = _BOUNDARY_COMPAT.get(step.boundary_position, set())
                external_impact = (
                    isinstance(action, ImpactAction) and action.boundary == "external"
                )
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
                                f"{sorted(v for v in valid_zones if v is not None) or 'None'})"
                            ),
                            element_id=leaf.id,
                            projected_step_id=step.step_id,
                        )
                    )

                # --- Executor role compatibility (all roles, 422o.4 blocker #4) ---
                compatible_role_kinds = _EXECUTOR_ROLE_TO_LEAF_COMPAT.get(
                    step.executor_role, set()
                )
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

                # --- Produced effect compatibility (422o.4 blocker #4) ---
                # Fix: impact + empty produced must fail, not pass.
                # The previous guard `step_produced_kinds and ...` was falsy
                # when produced was empty, silently accepting impact actions
                # on steps that produce nothing.
                step_produced_kinds = {p.kind for p in step.produced}
                if step_produced_kinds and action.kind == "ai_system_action":
                    if "effect" in step_produced_kinds and not step.attacker_controlled:
                        pass  # already validated by executor role check
                elif action.kind == "impact" and not any(
                    p.kind == "effect" for p in step.produced
                ):
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

                # --- Per-step resource binding validation (422o.4 blocker #4) ---
                # A leaf's tool_id / integration_id must match the
                # resource binding for the leaf's mapped projected step.
                # A resource bound for another step must fail.
                for link in step.resource_links:
                    ref = binding_by_slot.get(link.slot_id)
                    if ref is None:
                        continue
                    if isinstance(action, ToolInvocationAction) and link.role in (
                        "tool_fixture",
                        "tool",
                    ):
                        from asago_scenario_generator.models.attack_pattern import (
                            ToolResourceReference,
                        )

                        if (
                            isinstance(ref, ToolResourceReference)
                            and action.tool_id != ref.tool_id
                        ):
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
                    if isinstance(
                        action, IntegrationInteractionAction
                    ) and link.role in (
                        "integration",
                        "downstream",
                    ):
                        from asago_scenario_generator.models.attack_pattern import (
                            IntegrationResourceReference,
                        )

                        if (
                            isinstance(ref, IntegrationResourceReference)
                            and action.integration_id != ref.integration_id
                        ):
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
                    if (
                        isinstance(action, ToolInvocationAction)
                        and action.integration_id
                        and link.role in ("integration", "downstream")
                    ):
                        from asago_scenario_generator.models.attack_pattern import (
                            IntegrationResourceReference,
                        )

                        if (
                            isinstance(ref, IntegrationResourceReference)
                            and action.integration_id != ref.integration_id
                        ):
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

                # --- Per-step realization record reconciliation (tree boundary) ---
                # Compare each realization record on the tree leaf against the
                # embedded canonical step.  Same check as narrative/behavior.
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

    # --- Narrative semantic compatibility ---
    narrative = envelope.narrative
    for n_step in narrative.steps:
        if not n_step.projected_step_ids:
            continue
        for sid in n_step.projected_step_ids:
            step = step_by_id.get(sid)
            if step is None:
                continue
            # Narrative stage boundary rules: outside-boundary steps use the
            # literal zone 'outside'; inside/crossing steps use an active
            # Schneider zone (never 'outside').
            valid_zones = _NARRATIVE_BOUNDARY_ZONE_COMPAT.get(
                step.boundary_position, set()
            )
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

    # --- Behavior action semantic compatibility (422o.4 blocker #3) ---
    # Validate behavior actions against exact requirements and postconditions,
    # not only projected-step membership.  Check Gherkin keyword matches
    # canonical action semantics, and compare realization records against
    # the embedded canonical step.
    from asago_scenario_generator.models.scenario import BehaviorSpec

    behavior_spec = envelope.behavior_spec
    if isinstance(behavior_spec, BehaviorSpec):
        for b_action in behavior_spec.actions:
            for sid in b_action.projected_step_ids:
                step = step_by_id.get(sid)
                if step is None:
                    continue  # caught by unprojected step check
                # Phase 3B actions are derived from the finalized leaf.  The
                # leaf's typed action discriminator owns the eligible Gherkin
                # keyword; projected action_kind still owns the canonical
                # realization record checked below.
                source_leaf = _leaf_by_id.get(b_action.source_leaf_id)
                leaf_kind = (
                    source_leaf.action.kind
                    if source_leaf is not None and source_leaf.action is not None
                    else None
                )
                leaf_keywords = (
                    {"Given"}
                    if leaf_kind == "external_precondition"
                    else {"Then"}
                    if leaf_kind == "impact"
                    else {"When"}
                    if leaf_kind is not None
                    else set()
                )
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
                # Behavior action must reference a leaf that maps to the same step.
                if b_action.source_leaf_id:
                    leaf = _leaf_by_id.get(b_action.source_leaf_id)
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

    return violations


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
        actual_action_ids = {a.action_id for a in behavior_spec.actions}
        actual_action_map: dict[str, tuple[str, ...]] = {
            a.action_id: a.projected_step_ids for a in behavior_spec.actions
        }
        block_behavior_map: dict[str, tuple[str, ...]] = {
            r.element_id: r.projected_step_ids for r in realizations
        }

        # Every block behavior realization element must exist in actual actions.
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

        # Every actual action must be in block realizations with matching steps.
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
    else:
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
    # Strict deterministic correspondence: re-render the Gherkin from the
    # structured actions/assertions and compare exactly against the stored
    # gherkin_text.  This catches any omission, addition, reordering, or
    # fabrication — no substring matching, no fake IDs.
    # Zone annotations (display metadata) are stripped before comparison.
    if isinstance(behavior_spec, BehaviorSpec):
        import re as _re

        from asago_scenario_generator.pipeline.generate.assembly import (
            render_gherkin_from_behavior_spec,
        )

        # Re-render without zone map (zones are display-only).
        expected_gherkin = render_gherkin_from_behavior_spec(
            list(behavior_spec.actions),
            list(behavior_spec.assertions),
            zone_map=None,
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
        gherkin_lines = [
            line.strip()
            for line in behavior_spec.gherkin_text.splitlines()
            if line.strip()
            and any(
                line.strip().startswith(kw) for kw in ("Given", "When", "Then", "And")
            )
        ]
        # Extract the text content after the keyword, stripping zone suffix.
        step_texts: list[str] = []
        for line in gherkin_lines:
            for kw in ("Given", "When", "Then", "And"):
                if line.startswith(f"{kw} "):
                    raw = line[len(kw) + 1 :].strip()
                    # Strip zone suffix.
                    raw = _zone_pat.sub("", raw).strip()
                    step_texts.append(raw)
                    break

        # Every action text must appear as a step text.
        for action in behavior_spec.actions:
            base_text = _zone_pat.sub("", action.text).strip()
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
        # Every assertion text must appear as a step text.
        for assertion in behavior_spec.assertions:
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

    return violations
