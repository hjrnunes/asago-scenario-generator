"""Per-artifact realization coverage, order, identity, and binding checks.

Narrative, attack-tree, and behavior-assertion artifacts must be completely
and faithfully traced to the canonical projection: every selected projected
step covered, no unprojected claims, no forged element IDs, physical order
preserved, and resource bindings matching the projection.
"""

from __future__ import annotations

from itertools import pairwise
from typing import TYPE_CHECKING, Any

from asago_scenario_generator.models.attack_pattern_projection import (
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


def _actual_narrative_mapping(narrative: Any) -> dict[str, tuple[str, ...]]:
    """Derive expected realizations from actual narrative.steps fields.

    The sidecar table is not proof; projected_step_ids on each step is the
    canonical reference.  We derive what the realizations SHOULD be from
    the actual narrative list positions and compare.
    """
    actual_narrative_mapping: dict[str, tuple[str, ...]] = {}
    for step in narrative.steps:
        if step.projected_step_ids:
            actual_narrative_mapping[str(step.step_number)] = step.projected_step_ids
    return actual_narrative_mapping


def _narrative_mapping_mismatches(
    actual_narrative_mapping: dict[str, tuple[str, ...]],
    block_narrative_map: dict[str, tuple[str, ...]],
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Flag narrative steps absent from or mismapped in the block realizations."""
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


def _phantom_narrative_realizations(
    realizations: tuple[ArtifactRealizationMapping, ...],
    narrative: Any,
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Flag narrative steps mapped in block realizations without projected_step_ids."""
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


def _unprojected_narrative_steps(
    narrative: Any,
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Flag narrative steps whose actions map to no projected step."""
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


def _narrative_stage_shape_check(
    realizations: tuple[ArtifactRealizationMapping, ...],
    valid_step_numbers: set[str],
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Flag narrative realizations with wrong stage or nonexistent step numbers."""
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


def _check_narrative_realizations(
    envelope: ScenarioEnvelope,
    block: ProjectionEnvelopeBlock,
) -> list[ProjectionTraceabilityViolation]:
    violations: list[ProjectionTraceabilityViolation] = []
    realizations = block.narrative_realizations
    narrative = envelope.narrative
    selected = set(block.selected_step_ids)

    # --- Derive expected realizations from actual narrative.steps fields ---
    actual_narrative_mapping = _actual_narrative_mapping(narrative)

    # Every narrative action element with projected_step_ids must be mapped
    # in the block realizations, and the projected_step_ids must match exactly.
    block_narrative_map: dict[str, tuple[str, ...]] = {
        r.element_id: r.projected_step_ids for r in realizations
    }
    _narrative_mapping_mismatches(
        actual_narrative_mapping, block_narrative_map, violations
    )

    # Every narrative step element without projected_step_ids must not
    # appear in block realizations (no phantom mappings).
    _phantom_narrative_realizations(realizations, narrative, violations)

    # --- Every narrative action element must map (422o.4 blocker #3) ---
    # Extra unmapped narrative actions must fail.  A narrative step with
    # an action but no projected_step_ids is an unprojected security action.
    _unprojected_narrative_steps(narrative, violations)

    # Check element IDs reference actual narrative steps.
    valid_step_numbers = {str(s.step_number) for s in narrative.steps}
    _narrative_stage_shape_check(realizations, valid_step_numbers, violations)

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


def _actual_tree_mapping(tree: AttackTree) -> dict[str, tuple[str, ...]]:
    """Derive expected realizations from actual tree leaf fields.

    The sidecar table is not proof; projected_step_ids on each leaf is the
    canonical reference.  We derive what the realizations SHOULD be from
    the actual tree traversal and compare.
    """
    actual_tree_mapping: dict[str, tuple[str, ...]] = {}
    for leaf in _iter_leaves(tree.root):
        if leaf.projected_step_ids:
            actual_tree_mapping[leaf.id] = leaf.projected_step_ids
    return actual_tree_mapping


def _tree_mapping_mismatches(
    actual_tree_mapping: dict[str, tuple[str, ...]],
    block_tree_map: dict[str, tuple[str, ...]],
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Flag tree leaves absent from or mismapped in the block realizations."""
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


def _tree_stage_shape_check(
    realizations: tuple[ArtifactRealizationMapping, ...],
    valid_leaf_ids: set[str],
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Flag tree realizations with wrong stage or nonexistent leaf IDs."""
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
    actual_tree_mapping = _actual_tree_mapping(tree)

    block_tree_map: dict[str, tuple[str, ...]] = {
        r.element_id: r.projected_step_ids for r in realizations
    }
    _tree_mapping_mismatches(actual_tree_mapping, block_tree_map, violations)

    # Check element IDs reference actual tree leaves.
    valid_leaf_ids = {leaf.id for leaf in _iter_leaves(tree.root)}
    _tree_stage_shape_check(realizations, valid_leaf_ids, violations)

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


def _valid_atlas_technique_ids(block: ProjectionEnvelopeBlock) -> set[str]:
    """Collect all valid ATLAS technique IDs from the projection's mappings."""
    valid_atlas_ids: set[str] = set()
    for pmapping in block.projected_mappings:
        m = pmapping.mapping
        if hasattr(m, "decision") and m.decision == "exact" and m.taxonomy == "ATLAS":
            valid_atlas_ids.update(m.ids)
    return valid_atlas_ids


def _invalid_technique_node_violations(
    tree: AttackTree,
    valid_atlas_ids: set[str],
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Flag tree nodes whose technique_id is absent from the projection mappings."""
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
    valid_atlas_ids = _valid_atlas_technique_ids(block)
    _invalid_technique_node_violations(tree, valid_atlas_ids, violations)
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


def _known_ordinals(
    step_ids: tuple[str, ...], order: dict[str, int]
) -> tuple[str, ...] | None:
    """Return the known step ids, or None when none are in the canonical order."""
    known = tuple(step_id for step_id in step_ids if step_id in order)
    if not known:
        return None
    return known


def _strict_order_violation(
    element_id: str,
    ordinals: list[int],
    stage: ProjectionTraceabilityStage,
    artifact_name: str,
) -> ProjectionTraceabilityViolation | None:
    """Return a strict-order violation for non-monotonic ordinals, or None."""
    if ordinals != sorted(set(ordinals)):
        return ProjectionTraceabilityViolation(
            code=ProjectionTraceabilityViolationCode.reordered_projected_step,
            stage=stage,
            detail=(
                f"{artifact_name} element '{element_id}' projected_step_ids "
                "are not in strict canonical order"
            ),
            element_id=element_id,
        )
    return None


def _element_span_violation(
    element_id: str,
    step_ids: tuple[str, ...],
    order: dict[str, int],
    stage: ProjectionTraceabilityStage,
    artifact_name: str,
) -> tuple[
    ProjectionTraceabilityViolation | None, tuple[str, tuple[str, ...], int, int] | None
]:
    """Return (strict-order violation, span) for one element, or (None, None).

    The span is ``(element_id, known, min ordinal, max ordinal)``; elements
    whose projected steps are all unknown to the projection are skipped —
    the projection cannot attest to their order.
    """
    known = _known_ordinals(step_ids, order)
    if known is None:
        return None, None
    ordinals = [order[step_id] for step_id in known]
    violation = _strict_order_violation(element_id, ordinals, stage, artifact_name)
    return violation, (element_id, known, min(ordinals), max(ordinals))


def _span_crossing_violation(
    previous: tuple[str, tuple[str, ...], int, int],
    current: tuple[str, tuple[str, ...], int, int],
    order: dict[str, int],
    stage: ProjectionTraceabilityStage,
    artifact_name: str,
) -> ProjectionTraceabilityViolation | None:
    """Return a crossing violation for an adjacent span pair, or None."""
    _, previous_ids, _, previous_max = previous
    current_id, current_ids, current_min, _ = current
    shared = set(previous_ids) & set(current_ids)
    shared_boundary = any(
        order[step_id] == previous_max == current_min for step_id in shared
    )
    if previous_max > current_min or (
        previous_max == current_min and not shared_boundary
    ):
        return ProjectionTraceabilityViolation(
            code=ProjectionTraceabilityViolationCode.reordered_projected_step,
            stage=stage,
            detail=(
                f"{artifact_name} element '{current_id}' crosses the "
                "preceding realization span; equality is allowed only "
                "for a projected step shared by both elements"
            ),
            element_id=current_id,
        )
    return None


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
        violation, span = _element_span_violation(
            element_id, step_ids, order, stage, artifact_name
        )
        if span is not None:
            spans.append(span)
        if violation is not None:
            violations.append(violation)

    for previous, current in pairwise(spans):
        violation = _span_crossing_violation(
            previous, current, order, stage, artifact_name
        )
        if violation is not None:
            violations.append(violation)
    return violations


def _integration_requirements_for_steps(
    mapped_step_ids: tuple[str, ...],
    step_to_links: dict[str, tuple[Any, ...]],
    bindings_by_slot: dict[str, Any],
) -> dict[str, set[str]]:
    """Return per-step integration IDs required by the mapped steps' links."""
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


def _slots_for_mapped_steps(
    mapped_step_ids: tuple[str, ...],
    step_to_slots: dict[str, set[str]],
) -> set[str]:
    """Collect all valid slots across all mapped steps (many-to-many)."""
    all_step_slots: set[str] = set()
    for mapped_step_id in mapped_step_ids:
        all_step_slots |= step_to_slots.get(mapped_step_id, set())
    return all_step_slots


def _ingress_binding_mismatch(
    action: InitialIngressAction,
    chain: Any,
    bindings_by_slot: dict[str, Any],
) -> bool:
    """True when the leaf's ingress does not match the chain ingress binding."""
    ingress_binding = bindings_by_slot.get(chain.initial_ingress_slot_id)
    if not isinstance(ingress_binding, EntryPointResourceReference):
        return False
    return action.entry_point_id != ingress_binding.entry_point_id


def _owns_ingress_activation(
    mapped_step_ids: tuple[str, ...],
    step_by_id: dict[str, Any],
    initial_ingress_slot_id: str,
) -> bool:
    """True when at least one mapped step owns an ingress activation link.

    A source_influence link targeting the initial-ingress slot is the
    canonical indirect-ingress alternative to a direct ingress resource link.
    """
    return any(
        _step_links_initial_ingress(step_by_id[mapped_step_id], initial_ingress_slot_id)
        for mapped_step_id in mapped_step_ids
        if mapped_step_id in step_by_id
    )


def _check_ingress_leaf_binding(
    leaf: AttackTreeNode,
    chain: Any,
    bindings_by_slot: dict[str, Any],
    step_by_id: dict[str, Any],
    mapped_step_ids: tuple[str, ...],
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Verify an initial_ingress leaf against the chain ingress slot binding."""
    action = leaf.action
    # Ingress must match the chain's initial ingress slot binding.
    if _ingress_binding_mismatch(action, chain, bindings_by_slot):
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
    if not _owns_ingress_activation(
        mapped_step_ids, step_by_id, chain.initial_ingress_slot_id
    ):
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


def _tool_binding_matches(
    action: ToolInvocationAction,
    bindings_by_slot: dict[str, Any],
    all_step_slots: set[str],
) -> bool:
    """True when a tool slot binding linked to a mapped step matches the tool_id."""
    for slot_id in all_step_slots:
        ref = bindings_by_slot.get(slot_id)
        if isinstance(ref, ToolResourceReference) and ref.tool_id == action.tool_id:
            return True
    return False


def _integration_ids_satisfy(
    integration_id: str | None,
    required_integrations: dict[str, set[str]],
) -> bool:
    """True when the action integration_id fails per-step integration requirements."""
    return not required_integrations or any(
        integration_id not in required for required in required_integrations.values()
    )


def _check_tool_integration_requirement(
    leaf: AttackTreeNode,
    action: ToolInvocationAction,
    required_integrations: dict[str, set[str]],
    mapped_step_ids: tuple[str, ...],
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Flag tool leaves that omit or misuse a required integration binding."""
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
    elif action.integration_id is not None and _integration_ids_satisfy(
        action.integration_id, required_integrations
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


def _check_tool_leaf_binding(
    leaf: AttackTreeNode,
    bindings_by_slot: dict[str, Any],
    step_to_slots: dict[str, set[str]],
    step_to_links: dict[str, tuple[Any, ...]],
    mapped_step_ids: tuple[str, ...],
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Verify a tool_invocation leaf's tool_id and integration requirements."""
    action = leaf.action
    all_step_slots = _slots_for_mapped_steps(mapped_step_ids, step_to_slots)
    # The tool must match a tool slot binding linked to a mapped step.
    if not _tool_binding_matches(action, bindings_by_slot, all_step_slots):
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

    required_integrations = _integration_requirements_for_steps(
        mapped_step_ids, step_to_links, bindings_by_slot
    )
    _check_tool_integration_requirement(
        leaf, action, required_integrations, mapped_step_ids, violations
    )


def _check_integration_leaf_binding(
    leaf: AttackTreeNode,
    step_to_links: dict[str, tuple[Any, ...]],
    bindings_by_slot: dict[str, Any],
    mapped_step_ids: tuple[str, ...],
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Verify an integration_interaction leaf's integration requirements."""
    action = leaf.action
    required_integrations = _integration_requirements_for_steps(
        mapped_step_ids, step_to_links, bindings_by_slot
    )
    if _integration_ids_satisfy(action.integration_id, required_integrations):
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


def _check_leaf_resource_binding(
    leaf: AttackTreeNode,
    mapped_step_ids: tuple[str, ...],
    chain: Any,
    bindings_by_slot: dict[str, Any],
    step_by_id: dict[str, Any],
    step_to_slots: dict[str, set[str]],
    step_to_links: dict[str, tuple[Any, ...]],
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Dispatch the resource binding checks for one mapped leaf by action kind."""
    action = leaf.action
    if isinstance(action, InitialIngressAction):
        _check_ingress_leaf_binding(
            leaf, chain, bindings_by_slot, step_by_id, mapped_step_ids, violations
        )
    elif isinstance(action, ToolInvocationAction):
        _check_tool_leaf_binding(
            leaf,
            bindings_by_slot,
            step_to_slots,
            step_to_links,
            mapped_step_ids,
            violations,
        )
    elif isinstance(action, IntegrationInteractionAction):
        _check_integration_leaf_binding(
            leaf, step_to_links, bindings_by_slot, mapped_step_ids, violations
        )


def _resource_binding_context(
    chain: Any,
) -> tuple[dict[str, Any], dict[str, set[str]], dict[str, tuple[Any, ...]]]:
    """Build step_id → (step, slots, links) lookup maps for the chain."""
    step_by_id = {step.step_id: step for step in chain.steps}
    step_to_slots = {
        step.step_id: {link.slot_id for link in step.resource_links}
        for step in chain.steps
    }
    step_to_links = {step.step_id: step.resource_links for step in chain.steps}
    return step_by_id, step_to_slots, step_to_links


def _mapped_binding_leaves(
    tree: AttackTree,
) -> list[tuple[AttackTreeNode, tuple[str, ...]]]:
    """Return (leaf, projected_step_ids) for mapped, action-bearing leaves.

    Unmapped leaves are caught by _check_security_actions_mapped.
    """
    pairs: list[tuple[AttackTreeNode, tuple[str, ...]]] = []
    for leaf in _iter_leaves(tree.root):
        if leaf.action is None:
            continue
        mapped_step_ids = leaf.projected_step_ids
        if not mapped_step_ids:
            continue
        pairs.append((leaf, mapped_step_ids))
    return pairs


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
    step_by_id, step_to_slots, step_to_links = _resource_binding_context(chain)

    for leaf, mapped_step_ids in _mapped_binding_leaves(tree):
        _check_leaf_resource_binding(
            leaf,
            mapped_step_ids,
            chain,
            bindings_by_slot,
            step_by_id,
            step_to_slots,
            step_to_links,
            violations,
        )

    return violations


def _security_bearing_leaf(leaf: AttackTreeNode) -> bool:
    """True when a leaf carries an attacker-controlled security-bearing action."""
    if leaf.action is None:
        return False
    kind = leaf.action.kind
    if kind == "external_precondition":
        return False
    return True


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
        if _security_bearing_leaf(leaf) and leaf.id not in mapped_leaves:
            # All attack-action leaves (initial_ingress, attacker_action,
            # ai_system_action, tool_invocation, integration_interaction,
            # impact) are security-bearing and must map to ≥1 projected step.
            violations.append(
                ProjectionTraceabilityViolation(
                    code=ProjectionTraceabilityViolationCode.unprojected_security_action,
                    stage=ProjectionTraceabilityStage.attack_tree,
                    detail=(
                        f"security-bearing tree leaf '{leaf.id}' (action "
                        f"kind '{leaf.action.kind}') is not mapped to any "
                        f"projected step"
                    ),
                    element_id=leaf.id,
                )
            )

    return violations


def _check_assertion_exists(
    ar: Any,
    actual_assertion_ids: set[str],
    actual_assertion_map: dict[str, Any],
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Flag a block assertion realization absent from or diverging from actual."""
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


def _check_assertion_coverage(
    actual_assertion_ids: set[str],
    realizations: tuple[Any, ...],
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Flag actual assertions absent from the block assertion realizations."""
    block_assertion_ids = {ar.element_id for ar in realizations}
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


def _assertion_spec_cross_check(
    behavior_spec: Any,
    block: ProjectionEnvelopeBlock,
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Cross-check block assertion realizations against the actual BehaviorSpec."""
    actual_assertion_ids = {a.assertion_id for a in behavior_spec.assertions}
    actual_assertion_map = {a.assertion_id: a for a in behavior_spec.assertions}
    # Every block assertion realization must exist in actual assertions.
    for ar in block.assertion_realizations:
        _check_assertion_exists(
            ar, actual_assertion_ids, actual_assertion_map, violations
        )
    # Every actual assertion must be in block realizations.
    _check_assertion_coverage(
        actual_assertion_ids, block.assertion_realizations, violations
    )


def _postcondition_owner_index(
    chain: Any,
    selected: set[str],
) -> dict[str, str]:
    """Build a lookup of postcondition_id → step_id for all selected steps."""
    pc_to_step: dict[str, str] = {}
    for step in chain.steps:
        if step.step_id not in selected:
            continue
        for pc in step.observable_postconditions:
            pc_to_step[pc.postcondition_id] = step.step_id
    return pc_to_step


def _security_postcondition_ids(block: ProjectionEnvelopeBlock) -> set[str]:
    """Collect every security-relevant postcondition id on the block."""
    security_pcs = block.security_relevant_postconditions()
    all_security_pc_ids: set[str] = set()
    for pc_ids in security_pcs.values():
        all_security_pc_ids.update(pc_ids)
    return all_security_pc_ids


def _check_assertion_source_steps(
    ar: Any,
    selected: set[str],
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Flag assertion source step IDs that are not selected projected steps."""
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


def _check_assertion_postcondition_ids(
    ar: Any,
    pc_to_step: dict[str, str],
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Flag assertion postcondition IDs that are unresolvable or unlisted."""
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


def _check_missing_security_postconditions(
    block: ProjectionEnvelopeBlock,
    all_security_pc_ids: set[str],
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Flag security-relevant postconditions not asserted by any realization."""
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
        _assertion_spec_cross_check(behavior_spec, block, violations)

    # Build a lookup of postcondition_id → step_id for all selected steps.
    pc_to_step = _postcondition_owner_index(chain, selected)

    all_security_pc_ids = _security_postcondition_ids(block)

    for ar in block.assertion_realizations:
        # Check source step IDs are selected projected steps.
        _check_assertion_source_steps(ar, selected, violations)

        # Check postcondition IDs are resolvable in source steps.
        _check_assertion_postcondition_ids(ar, pc_to_step, violations)

    # Check that every security-relevant postcondition is asserted.
    _check_missing_security_postconditions(block, all_security_pc_ids, violations)

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


def _order_preservation_elements(
    realizations: tuple[ArtifactRealizationMapping, ...],
    order: dict[str, int],
) -> list[tuple[str, int, int, tuple[str, ...]]]:
    """Map each realization to (element_id, min, max, projected_step_ids).

    Elements whose projected steps are all unknown to the projection are
    skipped — the projection cannot attest to their order.  Each entry
    carries its own realization's step IDs so pair checks never have to
    index back into the unfiltered ``realizations`` tuple.
    """
    elements: list[tuple[str, int, int, tuple[str, ...]]] = []
    for realization in realizations:
        ords = [order[sid] for sid in realization.projected_step_ids if sid in order]
        if not ords:
            continue
        elements.append(
            (
                realization.element_id,
                min(ords),
                max(ords),
                realization.projected_step_ids,
            )
        )
    return elements


def _order_violation_for_pair(
    elements: list[tuple[str, int, int, tuple[str, ...]]],
    i: int,
    j: int,
    stage: ProjectionTraceabilityStage,
    artifact_name: str,
) -> ProjectionTraceabilityViolation | None:
    """Return a reorder violation for the element pair (i, j), or None.

    Splitting/combining is allowed only while preserving total order:
    a later element's minimum ordinal may not precede an earlier
    element's maximum ordinal unless the two elements share a projected
    step.
    """
    i_id, _, i_max, i_step_ids = elements[i]
    j_id, j_min, _, j_step_ids = elements[j]
    shared = set(i_step_ids) & set(j_step_ids)
    if j_min < i_max and not shared:
        return ProjectionTraceabilityViolation(
            code=ProjectionTraceabilityViolationCode.reordered_projected_step,
            stage=stage,
            detail=(
                f"{artifact_name} element '{j_id}' (min ordinal "
                f"{j_min}) precedes earlier element "
                f"'{i_id}' (max ordinal {i_max}) "
                f"without shared steps — total order violated"
            ),
            element_id=j_id,
        )
    return None


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
    elements = _order_preservation_elements(realizations, order)

    # Check that the element sequence is non-decreasing in min-ordinal.
    # A later element may not have a min-ordinal strictly less than an
    # earlier element's min-ordinal unless they share steps (split).
    for i in range(len(elements)):
        for j in range(i, len(elements)):
            if i == j:
                continue
            violation = _order_violation_for_pair(
                elements,
                i,
                j,
                stage,
                artifact_name,
            )
            if violation is not None:
                violations.append(violation)
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
