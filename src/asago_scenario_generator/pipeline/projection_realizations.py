"""Per-artifact realization coverage, order, identity, and binding checks.

Narrative, attack-tree, and behavior-assertion artifacts must be completely
and faithfully traced to the canonical projection: every selected projected
step covered, no unprojected claims, no forged element IDs, physical order
preserved, and resource bindings matching the projection.
"""

from __future__ import annotations

from itertools import pairwise
from typing import TYPE_CHECKING, Any

from asago_scenario_generator.models.attack_pattern import (
    EntryPointResourceReference,
    IntegrationResourceReference,
    ToolResourceReference,
)
from asago_scenario_generator.models.attack_tree import (
    AttackTree,
    AttackTreeNode,
    GateType,
    InitialIngressAction,
    IntegrationInteractionAction,
    ToolInvocationAction,
)
from asago_scenario_generator.models.projection_envelope import (
    ArtifactRealizationMapping,
    ArtifactStage,
    ProjectionEnvelopeBlock,
    ProjectionTraceabilityStage,
    ProjectionTraceabilityViolation,
    ProjectionTraceabilityViolationCode,
)

if TYPE_CHECKING:
    from asago_scenario_generator.models.scenario import ScenarioEnvelope


def _step_links_initial_ingress(step: Any, initial_ingress_slot_id: str) -> bool:
    """Whether a projected step owns direct or source-influenced activation."""

    return any(
        (link.role == "ingress" and link.slot_id == initial_ingress_slot_id)
        or (
            link.role == "source_influence"
            and link.target_ingress_slot_id == initial_ingress_slot_id
        )
        for link in step.resource_links
    )


def _check_narrative_realizations(
    envelope: ScenarioEnvelope,
    block: ProjectionEnvelopeBlock,
) -> list[ProjectionTraceabilityViolation]:
    violations: list[ProjectionTraceabilityViolation] = []
    realizations = block.narrative_realizations
    narrative = envelope.narrative
    selected = set(block.selected_step_ids)

    # --- Derive expected realizations from actual narrative.steps fields ---
    # The sidecar table is not proof; projected_step_ids on each step is the
    # canonical reference.  We derive what the realizations SHOULD be from
    # the actual narrative list positions and compare.
    actual_narrative_mapping: dict[str, tuple[str, ...]] = {}
    for step in narrative.steps:
        if step.projected_step_ids:
            actual_narrative_mapping[str(step.step_number)] = step.projected_step_ids

    # Every narrative action element with projected_step_ids must be mapped
    # in the block realizations, and the projected_step_ids must match exactly.
    block_narrative_map: dict[str, tuple[str, ...]] = {
        r.element_id: r.projected_step_ids for r in realizations
    }
    for elem_id, actual_sids in actual_narrative_mapping.items():
        block_sids = block_narrative_map.get(elem_id)
        if block_sids is None:
            violations.append(
                ProjectionTraceabilityViolation(
                    code=ProjectionTraceabilityViolationCode.incomplete_coverage,
                    stage=ProjectionTraceabilityStage.narrative,
                    detail=(
                        f"narrative step '{elem_id}' has projected_step_ids "
                        f"{actual_sids} but is absent from block "
                        f"narrative_realizations"
                    ),
                    element_id=elem_id,
                    projected_step_id=actual_sids[0],
                )
            )
        elif set(actual_sids) != set(block_sids):
            violations.append(
                ProjectionTraceabilityViolation(
                    code=ProjectionTraceabilityViolationCode.forged_opaque_id,
                    stage=ProjectionTraceabilityStage.narrative,
                    detail=(
                        f"narrative step '{elem_id}' has projected_step_ids "
                        f"{actual_sids} but block maps it to {block_sids}"
                    ),
                    element_id=elem_id,
                    projected_step_id=actual_sids[0],
                )
            )

    # Every narrative step element without projected_step_ids must not
    # appear in block realizations (no phantom mappings).
    for r in realizations:
        step_num = r.element_id
        step_obj = next(
            (s for s in narrative.steps if str(s.step_number) == step_num), None
        )
        if step_obj is not None and not step_obj.projected_step_ids:
            violations.append(
                ProjectionTraceabilityViolation(
                    code=ProjectionTraceabilityViolationCode.forged_opaque_id,
                    stage=ProjectionTraceabilityStage.narrative,
                    detail=(
                        f"narrative step '{step_num}' has no projected_step_ids "
                        f"but appears in block narrative_realizations"
                    ),
                    element_id=step_num,
                )
            )

    # --- Every narrative action element must map (422o.4 blocker #3) ---
    # Extra unmapped narrative actions must fail.  A narrative step with
    # an action but no projected_step_ids is an unprojected security action.
    for step in narrative.steps:
        if not step.projected_step_ids:
            violations.append(
                ProjectionTraceabilityViolation(
                    code=ProjectionTraceabilityViolationCode.unprojected_security_action,
                    stage=ProjectionTraceabilityStage.narrative,
                    detail=(
                        f"narrative step '{step.step_number}' has no "
                        f"projected_step_ids — every narrative action "
                        f"element must map to ≥1 projected step"
                    ),
                    element_id=str(step.step_number),
                )
            )

    # Check element IDs reference actual narrative steps.
    valid_step_numbers = {str(s.step_number) for s in narrative.steps}
    for r in realizations:
        if r.artifact_stage != ArtifactStage.narrative:
            violations.append(
                ProjectionTraceabilityViolation(
                    code=ProjectionTraceabilityViolationCode.forged_opaque_id,
                    stage=ProjectionTraceabilityStage.narrative,
                    detail=(
                        f"narrative realization element '{r.element_id}' has "
                        f"wrong artifact_stage '{r.artifact_stage.value}'"
                    ),
                    element_id=r.element_id,
                )
            )
        if r.element_id not in valid_step_numbers:
            violations.append(
                ProjectionTraceabilityViolation(
                    code=ProjectionTraceabilityViolationCode.forged_opaque_id,
                    stage=ProjectionTraceabilityStage.narrative,
                    detail=(
                        f"narrative realization references nonexistent "
                        f"step number '{r.element_id}'"
                    ),
                    element_id=r.element_id,
                )
            )

    # Check no unprojected steps claimed.
    violations.extend(
        _check_no_unprojected_steps(
            realizations, selected, ProjectionTraceabilityStage.narrative
        )
    )

    # Check complete coverage.
    violations.extend(
        _check_complete_coverage(
            realizations,
            selected,
            ProjectionTraceabilityStage.narrative,
            "narrative",
        )
    )

    # --- Validate order from actual narrative.steps list positions ---
    # Not from sidecar tuple position, but from the physical list order.
    violations.extend(_check_narrative_physical_order(narrative, block))

    # Check duplicated steps across mappings.
    violations.extend(
        _check_no_duplicated_steps(
            realizations,
            block,
            ProjectionTraceabilityStage.narrative,
            "narrative",
        )
    )

    return violations


def _check_narrative_physical_order(
    narrative: Any,
    block: ProjectionEnvelopeBlock,
) -> list[ProjectionTraceabilityViolation]:
    """Validate that physical narrative.steps list order preserves projection order.

    Uses actual list positions, not sidecar tuple positions.  A narrative
    physically ordered [2,1,3] must fail even if the sidecar tuple is ordered.
    With many-to-many, IDs inside each element must be strictly increasing and
    adjacent spans may overlap only on IDs they actually share.
    """
    elements = [
        (str(step.step_number), step.projected_step_ids) for step in narrative.steps
    ]
    return _check_artifact_element_order(
        elements,
        block.projected_step_order,
        ProjectionTraceabilityStage.narrative,
        "narrative",
    )


def _check_tree_realizations(
    envelope: ScenarioEnvelope,
    block: ProjectionEnvelopeBlock,
) -> list[ProjectionTraceabilityViolation]:
    violations: list[ProjectionTraceabilityViolation] = []
    realizations = block.tree_realizations
    tree = envelope.attack_tree
    if tree is None:
        # If there are realizations but no tree, that's a forged claim.
        if realizations:
            violations.append(
                ProjectionTraceabilityViolation(
                    code=ProjectionTraceabilityViolationCode.forged_opaque_id,
                    stage=ProjectionTraceabilityStage.attack_tree,
                    detail="tree realizations exist but attack_tree is absent",
                )
            )
        return violations

    selected = set(block.selected_step_ids)

    # --- Derive expected realizations from actual tree leaf fields ---
    # The sidecar table is not proof; projected_step_ids on each leaf is the
    # canonical reference.  We derive what the realizations SHOULD be from
    # the actual tree traversal and compare.
    actual_tree_mapping: dict[str, tuple[str, ...]] = {}
    for leaf in _iter_leaves(tree.root):
        if leaf.projected_step_ids:
            actual_tree_mapping[leaf.id] = leaf.projected_step_ids

    block_tree_map: dict[str, tuple[str, ...]] = {
        r.element_id: r.projected_step_ids for r in realizations
    }
    for leaf_id, actual_sids in actual_tree_mapping.items():
        block_sids = block_tree_map.get(leaf_id)
        if block_sids is None:
            violations.append(
                ProjectionTraceabilityViolation(
                    code=ProjectionTraceabilityViolationCode.incomplete_coverage,
                    stage=ProjectionTraceabilityStage.attack_tree,
                    detail=(
                        f"tree leaf '{leaf_id}' has projected_step_ids "
                        f"{actual_sids} but is absent from block "
                        f"tree_realizations"
                    ),
                    element_id=leaf_id,
                    projected_step_id=actual_sids[0],
                )
            )
        elif set(actual_sids) != set(block_sids):
            violations.append(
                ProjectionTraceabilityViolation(
                    code=ProjectionTraceabilityViolationCode.forged_opaque_id,
                    stage=ProjectionTraceabilityStage.attack_tree,
                    detail=(
                        f"tree leaf '{leaf_id}' has projected_step_ids "
                        f"{actual_sids} but block maps it to {block_sids}"
                    ),
                    element_id=leaf_id,
                    projected_step_id=actual_sids[0],
                )
            )

    # Check element IDs reference actual tree leaves.
    valid_leaf_ids = {leaf.id for leaf in _iter_leaves(tree.root)}
    for r in realizations:
        if r.artifact_stage != ArtifactStage.attack_tree:
            violations.append(
                ProjectionTraceabilityViolation(
                    code=ProjectionTraceabilityViolationCode.forged_opaque_id,
                    stage=ProjectionTraceabilityStage.attack_tree,
                    detail=(
                        f"tree realization element '{r.element_id}' has "
                        f"wrong artifact_stage '{r.artifact_stage.value}'"
                    ),
                    element_id=r.element_id,
                )
            )
        if r.element_id not in valid_leaf_ids:
            violations.append(
                ProjectionTraceabilityViolation(
                    code=ProjectionTraceabilityViolationCode.forged_opaque_id,
                    stage=ProjectionTraceabilityStage.attack_tree,
                    detail=(
                        f"tree realization references nonexistent "
                        f"leaf node '{r.element_id}'"
                    ),
                    element_id=r.element_id,
                )
            )

    violations.extend(
        _check_no_unprojected_steps(
            realizations, selected, ProjectionTraceabilityStage.attack_tree
        )
    )
    violations.extend(
        _check_complete_coverage(
            realizations,
            selected,
            ProjectionTraceabilityStage.attack_tree,
            "attack_tree",
        )
    )

    # --- Validate order from actual tree traversal ---
    violations.extend(_check_tree_physical_order(tree, block))

    violations.extend(
        _check_no_duplicated_steps(
            realizations,
            block,
            ProjectionTraceabilityStage.attack_tree,
            "attack_tree",
        )
    )

    # Check resource binding correctness: tree leaves with typed actions
    # referencing canonical resources must match projection bindings.
    violations.extend(_check_tree_resource_bindings(tree, block))

    # Every security-bearing tree leaf must map to ≥1 projected step.
    violations.extend(_check_security_actions_mapped(tree, realizations, block))

    # Check technique mapping validity: tree leaf technique_ids must be
    # in the projection's projected taxonomy mappings (422o.4 no-repair).
    violations.extend(_check_technique_mapping(tree, block))

    return violations


def _check_technique_mapping(
    tree: AttackTree,
    block: ProjectionEnvelopeBlock,
) -> list[ProjectionTraceabilityViolation]:
    """Check every tree-node technique_id against the projection.

    On candidate-v2 paths (422o.4), technique stripping is semantic repair
    and is prohibited.  Invalid technique IDs become typed violations
    attributed to the attack-tree stage for cmps.5 to route.
    """
    violations: list[ProjectionTraceabilityViolation] = []

    # Collect all valid ATLAS technique IDs from the projection's mappings.
    valid_atlas_ids: set[str] = set()
    for pmapping in block.projected_mappings:
        m = pmapping.mapping
        if hasattr(m, "decision") and m.decision == "exact" and m.taxonomy == "ATLAS":
            valid_atlas_ids.update(m.ids)

    # Connectors are semantic tree elements too; annotations cannot hide there.
    for node in _iter_all_nodes(tree.root):
        if node.technique_id is None:
            continue
        if node.technique_id not in valid_atlas_ids:
            violations.append(
                ProjectionTraceabilityViolation(
                    code=ProjectionTraceabilityViolationCode.invalid_technique_mapping,
                    stage=ProjectionTraceabilityStage.attack_tree,
                    detail=(
                        f"tree node '{node.id}' has technique_id "
                        f"'{node.technique_id}' not in projection's valid "
                        f"ATLAS mappings {sorted(valid_atlas_ids)}"
                    ),
                    element_id=node.id,
                )
            )

    return violations


def _check_tree_physical_order(
    tree: AttackTree,
    block: ProjectionEnvelopeBlock,
) -> list[ProjectionTraceabilityViolation]:
    """Validate that physical tree leaf DFS traversal order preserves projection order.

    Uses actual tree traversal, not sidecar tuple positions.  A tree
    physically reordered must fail even if the sidecar tuple is ordered.
    """
    elements = [(leaf.id, leaf.projected_step_ids) for leaf in _iter_leaves(tree.root)]
    return _check_artifact_element_order(
        elements,
        block.projected_step_order,
        ProjectionTraceabilityStage.attack_tree,
        "attack_tree",
    )


def _check_artifact_element_order(
    elements: list[tuple[str, tuple[str, ...]]],
    order: dict[str, int],
    stage: ProjectionTraceabilityStage,
    artifact_name: str,
) -> list[ProjectionTraceabilityViolation]:
    """Enforce strict within-element order and non-crossing adjacent spans."""
    violations: list[ProjectionTraceabilityViolation] = []
    spans: list[tuple[str, tuple[str, ...], int, int]] = []
    for element_id, step_ids in elements:
        known = tuple(step_id for step_id in step_ids if step_id in order)
        if not known:
            continue
        ordinals = [order[step_id] for step_id in known]
        if ordinals != sorted(set(ordinals)):
            violations.append(
                ProjectionTraceabilityViolation(
                    code=ProjectionTraceabilityViolationCode.reordered_projected_step,
                    stage=stage,
                    detail=(
                        f"{artifact_name} element '{element_id}' projected_step_ids "
                        "are not in strict canonical order"
                    ),
                    element_id=element_id,
                )
            )
        spans.append((element_id, known, min(ordinals), max(ordinals)))

    for previous, current in pairwise(spans):
        _, previous_ids, _, previous_max = previous
        current_id, current_ids, current_min, _ = current
        shared = set(previous_ids) & set(current_ids)
        shared_boundary = any(
            order[step_id] == previous_max == current_min for step_id in shared
        )
        if previous_max > current_min or (
            previous_max == current_min and not shared_boundary
        ):
            violations.append(
                ProjectionTraceabilityViolation(
                    code=ProjectionTraceabilityViolationCode.reordered_projected_step,
                    stage=stage,
                    detail=(
                        f"{artifact_name} element '{current_id}' crosses the "
                        "preceding realization span; equality is allowed only "
                        "for a projected step shared by both elements"
                    ),
                    element_id=current_id,
                )
            )
    return violations


def _check_tree_resource_bindings(
    tree: AttackTree,
    block: ProjectionEnvelopeBlock,
) -> list[ProjectionTraceabilityViolation]:
    """Verify tree leaf resource references match projection bindings for their mapped step.

    A resource bound for another step must fail.  For each mapped leaf,
    the resource it uses must come from a slot linked to the leaf's
    projected step, not just any slot in the projection.
    """
    violations: list[ProjectionTraceabilityViolation] = []
    chain = block.projection.source_chain
    bindings_by_slot = {b.slot_id: b.resource_ref for b in block.projection.bindings}

    # Build a map: step_id → set of slot_ids linked to that step.
    step_by_id = {step.step_id: step for step in chain.steps}
    step_to_slots: dict[str, set[str]] = {}
    step_to_links: dict[str, tuple[Any, ...]] = {}
    for step in chain.steps:
        step_to_slots[step.step_id] = {link.slot_id for link in step.resource_links}
        step_to_links[step.step_id] = step.resource_links

    def integration_requirements(
        mapped_step_ids: tuple[str, ...],
    ) -> dict[str, set[str]]:
        required: dict[str, set[str]] = {}
        for mapped_step_id in mapped_step_ids:
            integration_ids = {
                ref.integration_id
                for link in step_to_links.get(mapped_step_id, ())
                if isinstance(
                    (ref := bindings_by_slot.get(link.slot_id)),
                    IntegrationResourceReference,
                )
            }
            if integration_ids:
                required[mapped_step_id] = integration_ids
        return required

    # Build a map: leaf_id → projected_step_ids from actual tree fields.
    leaf_to_steps: dict[str, tuple[str, ...]] = {}
    for leaf in _iter_leaves(tree.root):
        leaf_to_steps[leaf.id] = leaf.projected_step_ids

    for leaf in _iter_leaves(tree.root):
        action = leaf.action
        if action is None:
            continue
        mapped_step_ids = leaf_to_steps.get(leaf.id, ())
        if not mapped_step_ids:
            # Unmapped leaves are caught by _check_security_actions_mapped.
            continue

        # Collect all valid slots across all mapped steps (many-to-many:
        # a leaf realizing multiple steps may use resources from any of them).
        all_step_slots: set[str] = set()
        for mapped_step_id in mapped_step_ids:
            all_step_slots |= step_to_slots.get(mapped_step_id, set())

        if isinstance(action, InitialIngressAction):
            # Ingress must match the chain's initial ingress slot binding.
            ingress_binding = bindings_by_slot.get(chain.initial_ingress_slot_id)
            if (
                isinstance(ingress_binding, EntryPointResourceReference)
                and action.entry_point_id != ingress_binding.entry_point_id
            ):
                violations.append(
                    ProjectionTraceabilityViolation(
                        code=ProjectionTraceabilityViolationCode.incorrect_ingress_binding,
                        stage=ProjectionTraceabilityStage.attack_tree,
                        detail=(
                            f"tree leaf '{leaf.id}' initial_ingress "
                            f"entry_point_id does not match projection "
                            f"ingress binding"
                        ),
                        element_id=leaf.id,
                    )
                )
            # Also verify that at least one mapped step owns the activation.
            # A source_influence link targeting the initial-ingress slot is
            # the canonical indirect-ingress alternative to a direct ingress
            # resource link.
            owns_activation = any(
                _step_links_initial_ingress(
                    step_by_id[mapped_step_id], chain.initial_ingress_slot_id
                )
                for mapped_step_id in mapped_step_ids
                if mapped_step_id in step_by_id
            )
            if not owns_activation:
                violations.append(
                    ProjectionTraceabilityViolation(
                        code=ProjectionTraceabilityViolationCode.incorrect_resource_binding,
                        stage=ProjectionTraceabilityStage.attack_tree,
                        detail=(
                            f"tree leaf '{leaf.id}' uses initial_ingress but "
                            f"none of mapped steps {list(mapped_step_ids)} "
                            f"own an ingress activation link"
                        ),
                        element_id=leaf.id,
                        projected_step_id=mapped_step_ids[0],
                    )
                )
        elif isinstance(action, ToolInvocationAction):
            # The tool must match a tool slot binding linked to a mapped step.
            found = False
            for slot_id in all_step_slots:
                ref = bindings_by_slot.get(slot_id)
                if (
                    isinstance(ref, ToolResourceReference)
                    and ref.tool_id == action.tool_id
                ):
                    found = True
                    break
            if not found:
                violations.append(
                    ProjectionTraceabilityViolation(
                        code=ProjectionTraceabilityViolationCode.incorrect_resource_binding,
                        stage=ProjectionTraceabilityStage.attack_tree,
                        detail=(
                            f"tree leaf '{leaf.id}' tool_id does not match "
                            f"any tool binding linked to mapped steps "
                            f"{list(mapped_step_ids)}"
                        ),
                        element_id=leaf.id,
                        projected_step_id=mapped_step_ids[0],
                    )
                )

            required_integrations = integration_requirements(mapped_step_ids)
            if action.integration_id is None and required_integrations:
                violations.append(
                    ProjectionTraceabilityViolation(
                        code=ProjectionTraceabilityViolationCode.incorrect_resource_binding,
                        stage=ProjectionTraceabilityStage.attack_tree,
                        detail=(
                            f"tree leaf '{leaf.id}' omits integration_id required "
                            f"by mapped projected steps {list(mapped_step_ids)} "
                            f"(per-step requirements {required_integrations})"
                        ),
                        element_id=leaf.id,
                        projected_step_id=mapped_step_ids[0],
                    )
                )
            elif action.integration_id is not None and (
                not required_integrations
                or any(
                    action.integration_id not in required
                    for required in required_integrations.values()
                )
            ):
                violations.append(
                    ProjectionTraceabilityViolation(
                        code=ProjectionTraceabilityViolationCode.incorrect_resource_binding,
                        stage=ProjectionTraceabilityStage.attack_tree,
                        detail=(
                            f"tree leaf '{leaf.id}' integration_id "
                            f"'{action.integration_id}' is not an integration "
                            "binding linked to every mapped projected step "
                            f"(per-step requirements {required_integrations})"
                        ),
                        element_id=leaf.id,
                        projected_step_id=mapped_step_ids[0],
                    )
                )
        elif isinstance(action, IntegrationInteractionAction):
            required_integrations = integration_requirements(mapped_step_ids)
            if not required_integrations or any(
                action.integration_id not in required
                for required in required_integrations.values()
            ):
                violations.append(
                    ProjectionTraceabilityViolation(
                        code=ProjectionTraceabilityViolationCode.incorrect_resource_binding,
                        stage=ProjectionTraceabilityStage.attack_tree,
                        detail=(
                            f"tree leaf '{leaf.id}' integration_id is not an "
                            "integration binding linked to every mapped "
                            "projected step "
                            f"(per-step requirements {required_integrations})"
                        ),
                        element_id=leaf.id,
                        projected_step_id=mapped_step_ids[0],
                    )
                )

    return violations


def _check_security_actions_mapped(
    tree: AttackTree,
    realizations: tuple[ArtifactRealizationMapping, ...],
    block: ProjectionEnvelopeBlock,
) -> list[ProjectionTraceabilityViolation]:
    """Every security-bearing generated action maps to ≥1 projected step."""
    violations: list[ProjectionTraceabilityViolation] = []
    mapped_leaves = {r.element_id for r in realizations}

    for leaf in _iter_leaves(tree.root):
        # Security-bearing: attacker-controlled action kinds that are not
        # external_precondition.  In the projection, attacker-controlled
        # steps carry the security-relevant semantics.
        if leaf.action is None:
            continue
        kind = leaf.action.kind
        if kind == "external_precondition":
            continue
        # All attack-action leaves (initial_ingress, ai_system_action,
        # tool_invocation, integration_interaction, impact) are
        # security-bearing and must map to ≥1 projected step.
        if leaf.id not in mapped_leaves:
            violations.append(
                ProjectionTraceabilityViolation(
                    code=ProjectionTraceabilityViolationCode.unprojected_security_action,
                    stage=ProjectionTraceabilityStage.attack_tree,
                    detail=(
                        f"security-bearing tree leaf '{leaf.id}' (action "
                        f"kind '{kind}') is not mapped to any projected step"
                    ),
                    element_id=leaf.id,
                )
            )

    return violations


def _check_assertion_realizations(
    envelope: ScenarioEnvelope,
    block: ProjectionEnvelopeBlock,
) -> list[ProjectionTraceabilityViolation]:
    """Assertions map to projected observable postconditions, not setup steps."""
    violations: list[ProjectionTraceabilityViolation] = []
    chain = block.projection.source_chain
    selected = set(block.selected_step_ids)

    # --- Cross-check assertion realizations against actual BehaviorSpec ---
    from asago_scenario_generator.models.scenario import BehaviorSpec

    behavior_spec = envelope.behavior_spec
    if isinstance(behavior_spec, BehaviorSpec):
        actual_assertion_ids = {a.assertion_id for a in behavior_spec.assertions}
        actual_assertion_map = {a.assertion_id: a for a in behavior_spec.assertions}
        # Every block assertion realization must exist in actual assertions.
        for ar in block.assertion_realizations:
            if ar.element_id not in actual_assertion_ids:
                violations.append(
                    ProjectionTraceabilityViolation(
                        code=ProjectionTraceabilityViolationCode.forged_opaque_id,
                        stage=ProjectionTraceabilityStage.behavior_spec,
                        detail=(
                            f"assertion '{ar.element_id}' does not exist in "
                            f"actual BehaviorSpec assertions"
                        ),
                        element_id=ar.element_id,
                    )
                )
            else:
                actual = actual_assertion_map[ar.element_id]
                if actual.source_step_ids != ar.source_step_ids:
                    violations.append(
                        ProjectionTraceabilityViolation(
                            code=ProjectionTraceabilityViolationCode.postcondition_assertion_mismatch,
                            stage=ProjectionTraceabilityStage.behavior_spec,
                            detail=(
                                f"assertion '{ar.element_id}' source_step_ids "
                                f"in block {ar.source_step_ids} do not match "
                                f"actual BehaviorSpec {actual.source_step_ids}"
                            ),
                            element_id=ar.element_id,
                        )
                    )
                if actual.projected_postcondition_ids != ar.projected_postcondition_ids:
                    violations.append(
                        ProjectionTraceabilityViolation(
                            code=ProjectionTraceabilityViolationCode.postcondition_assertion_mismatch,
                            stage=ProjectionTraceabilityStage.behavior_spec,
                            detail=(
                                f"assertion '{ar.element_id}' projected_postcondition_ids "
                                f"in block {ar.projected_postcondition_ids} do not match "
                                f"actual BehaviorSpec {actual.projected_postcondition_ids}"
                            ),
                            element_id=ar.element_id,
                        )
                    )
        # Every actual assertion must be in block realizations.
        block_assertion_ids = {ar.element_id for ar in block.assertion_realizations}
        for actual_id in actual_assertion_ids - block_assertion_ids:
            violations.append(
                ProjectionTraceabilityViolation(
                    code=ProjectionTraceabilityViolationCode.incomplete_coverage,
                    stage=ProjectionTraceabilityStage.behavior_spec,
                    detail=(
                        f"assertion '{actual_id}' exists in BehaviorSpec but "
                        f"is absent from block assertion_realizations"
                    ),
                    element_id=actual_id,
                )
            )

    # Build a lookup of postcondition_id → step_id for all selected steps.
    pc_to_step: dict[str, str] = {}
    for step in chain.steps:
        if step.step_id not in selected:
            continue
        for pc in step.observable_postconditions:
            pc_to_step[pc.postcondition_id] = step.step_id

    security_pcs = block.security_relevant_postconditions()
    all_security_pc_ids: set[str] = set()
    for pc_ids in security_pcs.values():
        all_security_pc_ids.update(pc_ids)

    for ar in block.assertion_realizations:
        # Check source step IDs are selected projected steps.
        for sid in ar.source_step_ids:
            if sid not in selected:
                violations.append(
                    ProjectionTraceabilityViolation(
                        code=ProjectionTraceabilityViolationCode.forged_opaque_id,
                        stage=ProjectionTraceabilityStage.behavior_spec,
                        detail=(
                            f"assertion '{ar.element_id}' references "
                            f"unprojected source step '{sid}'"
                        ),
                        element_id=ar.element_id,
                        projected_step_id=sid,
                    )
                )

        # Check postcondition IDs are resolvable in source steps.
        for pc_id in ar.projected_postcondition_ids:
            owning_step = pc_to_step.get(pc_id)
            if owning_step is None:
                violations.append(
                    ProjectionTraceabilityViolation(
                        code=ProjectionTraceabilityViolationCode.postcondition_assertion_mismatch,
                        stage=ProjectionTraceabilityStage.behavior_spec,
                        detail=(
                            f"assertion '{ar.element_id}' references "
                            f"postcondition '{pc_id}' not found in any "
                            f"selected projected step"
                        ),
                        element_id=ar.element_id,
                        projected_step_id=pc_id,
                    )
                )
            elif owning_step not in ar.source_step_ids:
                violations.append(
                    ProjectionTraceabilityViolation(
                        code=ProjectionTraceabilityViolationCode.postcondition_assertion_mismatch,
                        stage=ProjectionTraceabilityStage.behavior_spec,
                        detail=(
                            f"assertion '{ar.element_id}' claims postcondition "
                            f"'{pc_id}' from step '{owning_step}' but does not "
                            f"list that step in source_step_ids"
                        ),
                        element_id=ar.element_id,
                        projected_step_id=pc_id,
                    )
                )

    # Check that every security-relevant postcondition is asserted.
    asserted_pc_ids: set[str] = set()
    for ar in block.assertion_realizations:
        asserted_pc_ids.update(ar.projected_postcondition_ids)
    missing_security = all_security_pc_ids - asserted_pc_ids
    if missing_security:
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.incomplete_coverage,
                stage=ProjectionTraceabilityStage.behavior_spec,
                detail=(
                    f"security-relevant postconditions not covered by any "
                    f"assertion: {sorted(missing_security)}"
                ),
                projected_step_id=min(missing_security) if missing_security else None,
            )
        )

    return violations


def _check_no_unprojected_steps(
    realizations: tuple[ArtifactRealizationMapping, ...],
    selected: set[str],
    stage: ProjectionTraceabilityStage,
) -> list[ProjectionTraceabilityViolation]:
    violations: list[ProjectionTraceabilityViolation] = []
    for r in realizations:
        for sid in r.projected_step_ids:
            if sid not in selected:
                violations.append(
                    ProjectionTraceabilityViolation(
                        code=ProjectionTraceabilityViolationCode.forged_opaque_id,
                        stage=stage,
                        detail=(
                            f"realization element '{r.element_id}' claims "
                            f"unprojected step '{sid}'"
                        ),
                        element_id=r.element_id,
                        projected_step_id=sid,
                    )
                )
    return violations


def _check_complete_coverage(
    realizations: tuple[ArtifactRealizationMapping, ...],
    selected: set[str],
    stage: ProjectionTraceabilityStage,
    artifact_name: str,
) -> list[ProjectionTraceabilityViolation]:
    violations: list[ProjectionTraceabilityViolation] = []
    covered: set[str] = set()
    for r in realizations:
        covered.update(r.projected_step_ids)
    omitted = selected - covered
    if omitted:
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.incomplete_coverage,
                stage=stage,
                detail=(
                    f"projected steps not covered by {artifact_name} "
                    f"realizations: {sorted(omitted)}"
                ),
                projected_step_id=min(omitted) if omitted else None,
            )
        )
    return violations


def _check_order_preservation(
    realizations: tuple[ArtifactRealizationMapping, ...],
    order: dict[str, int],
    stage: ProjectionTraceabilityStage,
    artifact_name: str,
) -> list[ProjectionTraceabilityViolation]:
    """Verify realization element ordering preserves projected step total order.

    For each pair of mappings (A, B) where A precedes B in the realization
    tuple, the maximum ordinal of A's steps must not exceed the minimum
    ordinal of B's steps — unless they share steps (many-to-many overlap).
    Split/combine is allowed only while preserving total order.
    """
    violations: list[ProjectionTraceabilityViolation] = []
    # Sort realizations by their position in the tuple (artifact element order).
    # For each element, compute the min and max projected step ordinal.
    elements: list[tuple[str, int, int]] = []
    for r in realizations:
        ords = [order[sid] for sid in r.projected_step_ids if sid in order]
        if not ords:
            continue
        elements.append((r.element_id, min(ords), max(ords)))

    # Check that the element sequence is non-decreasing in min-ordinal.
    # A later element may not have a min-ordinal strictly less than an
    # earlier element's min-ordinal unless they share steps (split).
    for i in range(len(elements)):
        for j in range(i + 1, len(elements)):
            _, _, i_max = elements[i]
            j_id, j_min, _ = elements[j]
            # If j's min is before i's max AND they don't share any steps,
            # that's a reorder.  Sharing steps means split/combine, which
            # is allowed.
            r_i = realizations[i]
            r_j = realizations[j]
            shared = set(r_i.projected_step_ids) & set(r_j.projected_step_ids)
            if j_min < i_max and not shared:
                violations.append(
                    ProjectionTraceabilityViolation(
                        code=ProjectionTraceabilityViolationCode.reordered_projected_step,
                        stage=stage,
                        detail=(
                            f"{artifact_name} element '{j_id}' (min ordinal "
                            f"{j_min}) precedes earlier element "
                            f"'{r_i.element_id}' (max ordinal {i_max}) "
                            f"without shared steps — total order violated"
                        ),
                        element_id=j_id,
                    )
                )
                break  # one reorder per element is enough to flag

    return violations


def _check_no_duplicated_steps(
    realizations: tuple[ArtifactRealizationMapping, ...],
    block: ProjectionEnvelopeBlock,
    stage: ProjectionTraceabilityStage,
    artifact_name: str,
) -> list[ProjectionTraceabilityViolation]:
    """Check that no projected step is claimed by more than one element.

    Many-to-many split is allowed: one step MAY be realized by multiple
    elements.  But full **duplication** (same step claimed identically by
    two elements with identical mappings) is suspicious.  We flag only
    when the exact same projected_step_ids tuple appears in two mappings
    — that's a mechanical duplicate, not a semantic split.

    Actually, per contract §5, split/combine is allowed.  The prohibition
    is on *mechanical* duplication (the same element_id appearing twice,
    or identical mappings).  We check for duplicate element_ids.
    """
    violations: list[ProjectionTraceabilityViolation] = []
    seen_elements: set[str] = set()
    for r in realizations:
        if r.element_id in seen_elements:
            violations.append(
                ProjectionTraceabilityViolation(
                    code=ProjectionTraceabilityViolationCode.duplicated_projected_step,
                    stage=stage,
                    detail=(
                        f"{artifact_name} element '{r.element_id}' appears "
                        f"more than once in realizations"
                    ),
                    element_id=r.element_id,
                )
            )
        seen_elements.add(r.element_id)
    return violations


def _iter_leaves(node: AttackTreeNode) -> list[AttackTreeNode]:
    """Collect all leaf nodes from an attack tree (DFS order)."""
    if node.gate == GateType.LEAF:
        return [node]
    if node.children:
        result: list[AttackTreeNode] = []
        for child in node.children:
            result.extend(_iter_leaves(child))
        return result
    return []


def _iter_all_nodes(node: AttackTreeNode) -> list[AttackTreeNode]:
    """Collect all nodes (internal + leaf) from an attack tree (DFS)."""
    result: list[AttackTreeNode] = [node]
    if node.children:
        for child in node.children:
            result.extend(_iter_all_nodes(child))
    return result
