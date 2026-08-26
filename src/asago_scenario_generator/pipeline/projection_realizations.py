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


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-26T14:02:42Z","module_hash":"e1d0efba9c5323ddcb947b5dbaebe1dc6f242e92a1b1cabbb75376763c9df2fa","source_sha256":"a07cd8dfdfae716b186b6ab638fd60ea91e04bf342b4e87a908d6d98b499f484","functions":[{"id":"func/_step_links_initial_ingress","name":"_step_links_initial_ingress","line":40,"end_line":50,"hash":"3c792e5195c5149d3de1b3eb5fe2efe33abab00016127664c58b30c036bfc4e0"},{"id":"func/_actual_narrative_mapping","name":"_actual_narrative_mapping","line":53,"end_line":64,"hash":"825060af6221fa4a099f93dca26c36e631a79df50f1fc8c48051689d223cb382"},{"id":"func/_narrative_mapping_mismatches","name":"_narrative_mapping_mismatches","line":67,"end_line":101,"hash":"d0a9669b21b5c1712fd36f91f8760bb6ffde09707f3d43669dae35c8593d2ed1"},{"id":"func/_phantom_narrative_realizations","name":"_phantom_narrative_realizations","line":104,"end_line":126,"hash":"480e0946edeb6c018af37fae5c8b1f2ecb51fee36ad7f57b93b9fa2783ce923d"},{"id":"func/_unprojected_narrative_steps","name":"_unprojected_narrative_steps","line":129,"end_line":147,"hash":"69e05a42a670ecb2a82d060915a67a6db004273a4d6b8621644cccaaa50c6129"},{"id":"func/_narrative_stage_shape_check","name":"_narrative_stage_shape_check","line":150,"end_line":180,"hash":"13b3addead75a15fdfb11e88213b0723135fdf14b5d8b10d437587ce5b4bc5bb"},{"id":"func/_check_narrative_realizations","name":"_check_narrative_realizations","line":183,"end_line":248,"hash":"37157abe207bbab54ae62398335dc4b09e508fc015f062b1a866cb7e7a3b1be7"},{"id":"func/_check_narrative_physical_order","name":"_check_narrative_physical_order","line":251,"end_line":270,"hash":"94acddf20d55b3f0e3508379a8c6ecaa18a311e3962b255b86d1578dfa6c55c4"},{"id":"func/_actual_tree_mapping","name":"_actual_tree_mapping","line":273,"end_line":284,"hash":"a764123ed09576cdb4950f5715d6127b7610ab3073cbd73235b59df2329ba553"},{"id":"func/_tree_mapping_mismatches","name":"_tree_mapping_mismatches","line":287,"end_line":321,"hash":"b68863dd9c37e2cfe2ea6289f6869d5b0a64af374fb9755e02b6223b26a0690d"},{"id":"func/_tree_stage_shape_check","name":"_tree_stage_shape_check","line":324,"end_line":354,"hash":"e66b8f054970aba532ea11317d3424337589d2d95e0e90c4702cbf50c6360161"},{"id":"func/_check_tree_realizations","name":"_check_tree_realizations","line":357,"end_line":427,"hash":"3f4b00b710761ac1b968335f14ee4775167a7b958db57b6e59dc5f4f6e657502"},{"id":"func/_valid_atlas_technique_ids","name":"_valid_atlas_technique_ids","line":430,"end_line":437,"hash":"849cb452fda2e4d95e4ba0e8b45f10e8004321d0cdd25643da460bbb2e970f0d"},{"id":"func/_invalid_technique_node_violations","name":"_invalid_technique_node_violations","line":440,"end_line":462,"hash":"aaeb7e5d8ec61d53489f0f44605a8e676267669c8f9395fc77589b349f40f89f"},{"id":"func/_check_technique_mapping","name":"_check_technique_mapping","line":465,"end_line":478,"hash":"5a39b4a740208be249fda113a54aeaed06046e4ab3966eb3e3eaaf643a2325ca"},{"id":"func/_check_tree_physical_order","name":"_check_tree_physical_order","line":481,"end_line":496,"hash":"96c1dc7d322610202e6963bf23febd00933eb67213c7423a33d3959af37ba283"},{"id":"func/_known_ordinals","name":"_known_ordinals","line":499,"end_line":506,"hash":"454282427c70fe67232ade0ceb0384798d01ff3704104d137ce82ffc1dd847d7"},{"id":"func/_strict_order_violation","name":"_strict_order_violation","line":509,"end_line":526,"hash":"b52412740592b61ba12426ed47ad5af2695ee3d5b6e36003366d917bcae2baf8"},{"id":"func/_element_span_violation","name":"_element_span_violation","line":529,"end_line":549,"hash":"008dfd4b0093314caa4777e4da2ac710b7d537d61c32beef0a37522c14109a87"},{"id":"func/_span_crossing_violation","name":"_span_crossing_violation","line":552,"end_line":579,"hash":"3cb0ef7f8cc62d1e432f0cde99f7e53c88b7fe28beb86e789472854333d6261a"},{"id":"func/_check_artifact_element_order","name":"_check_artifact_element_order","line":582,"end_line":606,"hash":"3a1b640482c945bb8a9b8c9ced120bf46854900f23df65520796c1ecb2ba57ff"},{"id":"func/_integration_requirements_for_steps","name":"_integration_requirements_for_steps","line":609,"end_line":627,"hash":"0f8d29154e3cc754a3838e1fba5dd37ffa476962417b4b330260b520dcea6bbc"},{"id":"func/_slots_for_mapped_steps","name":"_slots_for_mapped_steps","line":630,"end_line":638,"hash":"2c041141bf1eb34dfd0763f1deed2c7ad25dfaed86deb21fd87a9d7db1963f55"},{"id":"func/_ingress_binding_mismatch","name":"_ingress_binding_mismatch","line":641,"end_line":650,"hash":"c695df66aeb84766afac2df485dd1d4dfae9b3a1b12f73667827e2c4825fdbee"},{"id":"func/_owns_ingress_activation","name":"_owns_ingress_activation","line":653,"end_line":667,"hash":"82037a618fed0761a4b7546625a33aef0b8ba3f61875d5a18705790be5d1c623"},{"id":"func/_check_ingress_leaf_binding","name":"_check_ingress_leaf_binding","line":670,"end_line":710,"hash":"aab8286beb6d0e7221478f6acbb5a8a111d8fe0cf65c2c0f9672dd37eb750024"},{"id":"func/_tool_binding_matches","name":"_tool_binding_matches","line":713,"end_line":723,"hash":"627e177ef6aec01db3a11adc7a71aebdcb85999f24883c7f29333ced114d6bd6"},{"id":"func/_integration_ids_satisfy","name":"_integration_ids_satisfy","line":726,"end_line":733,"hash":"54a4e1da44e3d4bb59f67623d5b6bfabb7ad518e26218aea77c082a957608d3b"},{"id":"func/_check_tool_integration_requirement","name":"_check_tool_integration_requirement","line":736,"end_line":774,"hash":"569637c7de7e9d12ac5ccd4b9c1eba9d9decf79fa8c5a5e2c07b0ca3392dc965"},{"id":"func/_check_tool_leaf_binding","name":"_check_tool_leaf_binding","line":777,"end_line":809,"hash":"daea559e6dff14756aa0207b2ab7265b4d752e9b499f0b9e113ba97819cede7b"},{"id":"func/_check_integration_leaf_binding","name":"_check_integration_leaf_binding","line":812,"end_line":838,"hash":"e67b22001cf939dce71cb9bb7a2a53fa6b4f571d16c097911bef130625d5f0c5"},{"id":"func/_check_leaf_resource_binding","name":"_check_leaf_resource_binding","line":841,"end_line":869,"hash":"01b655dabbac3ae7aef600e40c98db150be7b7b3c63058b01f51d679c0425c9d"},{"id":"func/_resource_binding_context","name":"_resource_binding_context","line":872,"end_line":882,"hash":"6cd9f419d7f439ebe9e79c5e80873e58abce336e730e788d14763133c3502a88"},{"id":"func/_mapped_binding_leaves","name":"_mapped_binding_leaves","line":885,"end_line":900,"hash":"24cc2ebddf4d1c59b0b54033284b12adab3a0e571bd7e417a55e24c2bd12e26e"},{"id":"func/_check_tree_resource_bindings","name":"_check_tree_resource_bindings","line":903,"end_line":932,"hash":"a9270ec125cef3a26f46a3c50a0caa6ae0be46d432b4d12d27b82c4d81b3b8fd"},{"id":"func/_security_bearing_leaf","name":"_security_bearing_leaf","line":935,"end_line":942,"hash":"e1eb120c19440b9a50e9dea969f903c16d026c7a5f87b96ccd61eb5ebe29a299"},{"id":"func/_check_security_actions_mapped","name":"_check_security_actions_mapped","line":945,"end_line":975,"hash":"bec54c06a82aaf7c18f6ff1ebeda4f6317f465c955c8dc8f14db4219560266d4"},{"id":"func/_check_assertion_exists","name":"_check_assertion_exists","line":978,"end_line":1024,"hash":"f661b6c4607667d39e3820639e2604a5e9e86316da1fda631360a1e81e771db3"},{"id":"func/_check_assertion_coverage","name":"_check_assertion_coverage","line":1027,"end_line":1045,"hash":"ccf148d2fda425b818d13c3db546e0b30429353970502b924308eb12aa1c0467"},{"id":"func/_assertion_spec_cross_check","name":"_assertion_spec_cross_check","line":1048,"end_line":1064,"hash":"4665bf90b07c71b0dc5486afabacd463f7606d2e500813178d2cd5f7efa92db1"},{"id":"func/_postcondition_owner_index","name":"_postcondition_owner_index","line":1067,"end_line":1078,"hash":"907141c7af5b974784011940be4488288475cd03ae46d4d05f13f2e104082beb"},{"id":"func/_security_postcondition_ids","name":"_security_postcondition_ids","line":1081,"end_line":1087,"hash":"72fee2bdf6c5613afb935937383ac72094c94f62f16d99f22beb6baf559b993e"},{"id":"func/_check_assertion_source_steps","name":"_check_assertion_source_steps","line":1090,"end_line":1109,"hash":"e510d770aee1e1b3250ec0addeec1692b4440a111adf7e70f61a2472428b5382"},{"id":"func/_check_assertion_postcondition_ids","name":"_check_assertion_postcondition_ids","line":1112,"end_line":1147,"hash":"b8ece7f73bab86aa7c82b8fd098a0d53ce2bf1c28dcaa399ee6fc7ed355cf6f8"},{"id":"func/_check_missing_security_postconditions","name":"_check_missing_security_postconditions","line":1150,"end_line":1171,"hash":"49268d24a016fa2a7f2c9a29b39fa84575e038b6fa85a19c955df28e67d01211"},{"id":"func/_check_assertion_realizations","name":"_check_assertion_realizations","line":1174,"end_line":1205,"hash":"6d1eaaa1bb0a0591e4346530608e864ccb21f9b7a7a8891549b5a2ac59ff2512"},{"id":"func/_check_no_unprojected_steps","name":"_check_no_unprojected_steps","line":1208,"end_line":1229,"hash":"8a6b17c21f5ae0ec565fb1dd7b4f2610438f18520b76cc63bb602e0281973331"},{"id":"func/_check_complete_coverage","name":"_check_complete_coverage","line":1232,"end_line":1255,"hash":"e00a3926c5dbd77cdf0d911a19e7e24e1379fa8bad91a16a55008af0f942a95d"},{"id":"func/_order_preservation_elements","name":"_order_preservation_elements","line":1258,"end_line":1282,"hash":"621599263ad9ec31664fa3c160fdb5ab8fce564e779db5d03f1b00b6865b8a0f"},{"id":"func/_order_violation_for_pair","name":"_order_violation_for_pair","line":1285,"end_line":1314,"hash":"231210203ee0af8908fdd6b43cd61a2a0303e6bffe37af0666b080af4c508bed"},{"id":"func/_check_order_preservation","name":"_check_order_preservation","line":1317,"end_line":1351,"hash":"8209fc038222fdba2ae20f889c0f30217348e7b9e78f52d7bc94423a49206688"},{"id":"func/_check_no_duplicated_steps","name":"_check_no_duplicated_steps","line":1354,"end_line":1388,"hash":"b07d77d407b6e52a868e3f30a2a3af808978cedf1dae88ab8163cf6d041e35d3"},{"id":"func/_iter_leaves","name":"_iter_leaves","line":1391,"end_line":1400,"hash":"9d97cfe3d05861888a6a5e54c2f2e1a98b28cb21a3df7ab4e3dd00c0149d3948"},{"id":"func/_iter_all_nodes","name":"_iter_all_nodes","line":1403,"end_line":1409,"hash":"746a557b768690e45262e89bbd216cbb4747726e08a2e8518586a731b0aac421"}]}
# mutate4py-manifest-end
