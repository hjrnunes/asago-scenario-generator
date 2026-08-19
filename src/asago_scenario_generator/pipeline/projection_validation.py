"""Standalone projection traceability validation for ScenarioEnvelope.

Validates that every generated artifact (narrative, attack tree, behavior
spec) is completely and faithfully traced to the deeply immutable canonical
projection persisted on the envelope (bead ``asago-scenario-generator-422o.4``).

This module defines the **violations and validation**, not the final
retry/quarantine state machine (deferred to cmps.5).  It exposes typed
validation inputs and results that cmps.5 will consume.

Checks performed:

1. **Projection integrity** — the embedded :class:`ProjectionSnapshot` is
   self-validating (digest-verified).  When authoritative source inputs
   are supplied, the projection and execution requirements are recomputed
   and compared to detect drift or nested mutation.

2. **Coverage** — every selected projected step is covered by narrative
   actions, attack-tree leaves, and behavior actions.

3. **Order preservation** — realization mappings preserve the total order
   of projected steps within each artifact stage.

4. **No unprojected steps** — no realization mapping or generated action
   claims a step ID absent from the projection.

5. **Resource binding correctness** — generated actions referencing
   canonical resources match the projection's resource bindings.

6. **Ingress identity** — the canonical initial ingress ID is consistent
   across the projection, envelope, actor, narrative, and attack tree.

7. **OR-tree prohibition** — authoritative scenario trees prohibit OR
   nodes in v1; AND decomposition represents one concrete execution only.

8. **Assertion mapping** — behavior assertions map to projected observable
   postconditions, not to setup steps.

9. **Forged opaque IDs** — generated content must not reference opaque IDs
   absent from the projection.
"""

from __future__ import annotations

from itertools import pairwise
from typing import TYPE_CHECKING, Any

from asago_scenario_generator.models.attack_pattern import (
    AttackPattern,
    EntryPointResourceReference,
    IntegrationResourceReference,
    TaxonomyResolver,
    ToolResourceReference,
    validate_attack_pattern,
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
    ProjectionTraceabilityResult,
    ProjectionTraceabilityStage,
    ProjectionTraceabilityViolation,
    ProjectionTraceabilityViolationCode,
)
from asago_scenario_generator.models.realization import (
    ProjectedStepRealization,
    derive_step_realization,
)
from asago_scenario_generator.pipeline.projection import (
    CapabilityFactSnapshot,
    _candidate_v2_id,
    _derive_execution_requirements_core,
    _fail_closed_if_no_requirements,
    _normalize_semantic_order,
    _pattern_pin,
    _projected_mappings,
    compute_derivation_context_digest,
    compute_execution_requirements_digest,
)

if TYPE_CHECKING:
    from asago_scenario_generator.models.scenario import ScenarioEnvelope


# ---------------------------------------------------------------------------#
# Public API
# ---------------------------------------------------------------------------#


def validate_projection_traceability(
    envelope: ScenarioEnvelope,
    *,
    authoritative_pattern: dict[str, Any] | None = None,
    taxonomy_resolver: TaxonomyResolver | None = None,
    capability_snapshot: CapabilityFactSnapshot | None = None,
    expected_catalog_pin: str | None = None,
) -> ProjectionTraceabilityResult:
    """Validate projection traceability on a scenario envelope.

    Standalone: does not require a taxonomy checkout when only the
    envelope's embedded projection is available.  When authoritative
    source inputs (``authoritative_pattern``, ``taxonomy_resolver``,
    ``capability_snapshot``, ``expected_catalog_pin``) are supplied, the
    projection and execution requirements are recomputed and compared to
    detect drift or nested mutation.

    Returns a :class:`ProjectionTraceabilityResult` with typed violations
    attributed to the earliest responsible generated stage.
    """
    violations: list[ProjectionTraceabilityViolation] = []

    block = envelope.projection
    if block is None:
        # Missing projection is a typed invalid state (422o.4).
        # Pre-alpha: no optional legacy loophole.
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.nested_mutation,
                stage=ProjectionTraceabilityStage.actor_profile,
                detail=(
                    "projection block is absent; every generated scenario "
                    "must embed exactly one immutable projection block"
                ),
            )
        )
        return ProjectionTraceabilityResult(valid=False, violations=violations)

    # --- Check 1: projection integrity & drift (contract §2) ---
    violations.extend(
        _check_projection_drift(
            block,
            authoritative_pattern=authoritative_pattern,
            taxonomy_resolver=taxonomy_resolver,
            capability_snapshot=capability_snapshot,
            expected_catalog_pin=expected_catalog_pin,
        )
    )

    # --- Check 6: ingress identity (contract §7) ---
    violations.extend(_check_ingress_identity(envelope, block))

    # --- Check 6b: candidate ID recompute (422o.4 blocker #1) ---
    # Recompute the projected candidate ID from the embedded
    # ProjectionSnapshot and compare to envelope.candidate_id.
    recomputed_cid = _candidate_v2_id(
        block.projection.source_chain.pattern_id, block.projection
    )
    if envelope.candidate_id != recomputed_cid:
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.forged_opaque_id,
                stage=ProjectionTraceabilityStage.actor_profile,
                detail=(
                    f"envelope candidate_id '{envelope.candidate_id}' does not "
                    f"match recomputed projected candidate ID "
                    f"'{recomputed_cid}' from embedded ProjectionSnapshot"
                ),
                element_id=envelope.candidate_id,
            )
        )

    # --- Check 7: OR-tree prohibition (contract §6) ---
    violations.extend(_check_or_tree_prohibition(envelope, block))

    # --- Checks 2-5, 8-9: artifact realization coverage ---
    violations.extend(_check_narrative_realizations(envelope, block))
    violations.extend(_check_tree_realizations(envelope, block))
    violations.extend(_check_step_semantic_compatibility(envelope, block))
    violations.extend(_check_behavior_realizations(envelope, block))
    violations.extend(_check_assertion_realizations(envelope, block))

    # Deduplicate violations by (code, stage, element_id, projected_step_id).
    seen: set[tuple[str, str, str | None, str | None]] = set()
    unique: list[ProjectionTraceabilityViolation] = []
    for v in violations:
        key = (v.code.value, v.stage.value, v.element_id, v.projected_step_id)
        if key not in seen:
            seen.add(key)
            unique.append(v)

    return ProjectionTraceabilityResult(
        valid=len(unique) == 0,
        violations=unique,
    )


# ---------------------------------------------------------------------------#
# Check 1: projection drift and nested mutation (contract §2)
# ---------------------------------------------------------------------------#


def _check_projection_drift(
    block: ProjectionEnvelopeBlock,
    *,
    authoritative_pattern: dict[str, Any] | None,
    taxonomy_resolver: TaxonomyResolver | None,
    capability_snapshot: CapabilityFactSnapshot | None,
    expected_catalog_pin: str | None,
) -> list[ProjectionTraceabilityViolation]:
    violations: list[ProjectionTraceabilityViolation] = []

    # The ProjectionSnapshot is self-validating on construction.  But we
    # must detect nested mutation of the *already-persisted* block.  We
    # re-validate the snapshot's digest by re-serializing and checking
    # against the stored projection_digest.
    try:
        from asago_scenario_generator.models.attack_pattern import (
            compute_projection_digest,
        )

        recomputed = compute_projection_digest(block.projection)
        if recomputed != block.projection.projection_digest:
            violations.append(
                ProjectionTraceabilityViolation(
                    code=ProjectionTraceabilityViolationCode.nested_mutation,
                    stage=ProjectionTraceabilityStage.actor_profile,
                    detail=(
                        "persisted projection_digest does not match recomputed "
                        "digest; the projection snapshot was mutated after capture"
                    ),
                )
            )
    except (TypeError, ValueError, AttributeError):
        # If recompute fails, the snapshot is structurally corrupt.
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.nested_mutation,
                stage=ProjectionTraceabilityStage.actor_profile,
                detail="projection snapshot re-serialization failed; "
                "structurally corrupt",
            )
        )

    # Recompute execution requirements digest.  Handle both model instances
    # and plain dicts (model_construct bypass may produce dicts for
    # discriminated-union fields).
    expected_req_digest = compute_execution_requirements_digest(
        block.execution_requirements
    )
    if expected_req_digest != block.execution_requirements_digest:
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.requirement_drift,
                stage=ProjectionTraceabilityStage.actor_profile,
                detail=(
                    "execution_requirements_digest does not match recomputed "
                    "digest; requirements were mutated after derivation"
                ),
            )
        )

    # --- Standalone recomputation from embedded evidence (422o.4 blocker #2-#3) ---
    # Derive controllability from the embedded CapabilityFactSnapshot, NOT
    # from the persisted ingress_controllability field (which is self-signed).
    # This prevents a caller from flipping controllability and re-signing
    # arbitrary requirements.
    chain = block.projection.source_chain
    pattern_id = chain.pattern_id

    # Step 1: Verify snapshot integrity (detect nested mutation of evidence).
    snapshot = block.capability_snapshot
    try:
        snapshot.assert_integrity()
    except (ValueError, TypeError, AttributeError) as exc:
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.nested_mutation,
                stage=ProjectionTraceabilityStage.actor_profile,
                detail=(f"embedded capability snapshot integrity check failed: {exc}"),
            )
        )
        return violations  # Cannot proceed with corrupted evidence.

    # Step 2: Verify snapshot digest matches the projection pin.
    if snapshot.snapshot_digest != block.projection.capability_fact_snapshot_digest:
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.nested_mutation,
                stage=ProjectionTraceabilityStage.actor_profile,
                detail=(
                    "embedded capability_snapshot.snapshot_digest does not "
                    "match projection.capability_fact_snapshot_digest; "
                    "evidence was substituted after projection"
                ),
            )
        )
        return violations

    # Step 3: Derive controllability from evidence.
    try:
        ep = snapshot.profile.resolve_entry_point(
            block.canonical_ingress.entry_point_id
        )
        if ep is None:
            violations.append(
                ProjectionTraceabilityViolation(
                    code=ProjectionTraceabilityViolationCode.requirement_drift,
                    stage=ProjectionTraceabilityStage.actor_profile,
                    detail=(
                        "canonical_ingress entry_point_id is absent from "
                        "the embedded capability snapshot profile"
                    ),
                )
            )
            return violations
        derived_controllability = ep.effective_controllability
    except (ValueError, TypeError, AttributeError) as exc:
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.requirement_drift,
                stage=ProjectionTraceabilityStage.actor_profile,
                detail=f"failed to derive controllability from evidence: {exc}",
            )
        )
        return violations

    # Step 4: Verify persisted controllability matches derived.
    if derived_controllability != block.ingress_controllability:
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.requirement_drift,
                stage=ProjectionTraceabilityStage.actor_profile,
                detail=(
                    f"persisted ingress_controllability "
                    f"'{block.ingress_controllability}' does not match "
                    f"controllability '{derived_controllability}' derived "
                    f"from embedded capability evidence"
                ),
            )
        )

    # Step 5: Recompute execution requirements from embedded projection +
    # derived controllability (NOT persisted controllability).
    recomputed_reqs, req_issue = _derive_execution_requirements_core(
        pattern_id, chain, block.projection, derived_controllability
    )
    recomputed_reqs, req_issue = _fail_closed_if_no_requirements(
        pattern_id, recomputed_reqs, req_issue
    )
    if req_issue is not None:
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.requirement_drift,
                stage=ProjectionTraceabilityStage.actor_profile,
                detail=(
                    f"standalone requirement recomputation failed: {req_issue.detail}"
                ),
            )
        )
    elif recomputed_reqs != block.execution_requirements:
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.requirement_drift,
                stage=ProjectionTraceabilityStage.actor_profile,
                detail=(
                    "standalone recomputed execution requirements do not "
                    "match persisted; requirements may be forged"
                ),
            )
        )

    # Step 6: Verify derivation context digest using derived controllability.
    expected_ctx_digest = compute_derivation_context_digest(
        block.projection.projection_digest,
        pattern_id,
        derived_controllability,
    )
    if expected_ctx_digest != block.derivation_context_digest:
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.requirement_drift,
                stage=ProjectionTraceabilityStage.actor_profile,
                detail=(
                    "derivation_context_digest does not match when computed "
                    "with controllability derived from evidence; controllability "
                    "may have been flipped"
                ),
            )
        )

    # Recompute projected_mappings from embedded source chain + selected IDs.
    expected_mappings = _projected_mappings(chain, block.projection.selected_step_ids)
    if expected_mappings != block.projected_mappings:
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.projection_drift,
                stage=ProjectionTraceabilityStage.actor_profile,
                detail=(
                    "standalone recomputed projected mappings do not match "
                    "persisted; mappings may be forged"
                ),
            )
        )

    # When authoritative source inputs are available, recompute and compare
    # as additional qualification (not the only semantic check).
    if (
        authoritative_pattern is not None
        and taxonomy_resolver is not None
        and capability_snapshot is not None
        and expected_catalog_pin is not None
    ):
        violations.extend(
            _recompute_and_compare(
                block,
                authoritative_pattern,
                taxonomy_resolver,
                capability_snapshot,
                expected_catalog_pin,
            )
        )

    return violations


def _recompute_and_compare(
    block: ProjectionEnvelopeBlock,
    authoritative_pattern: dict[str, Any],
    taxonomy_resolver: TaxonomyResolver,
    capability_snapshot: CapabilityFactSnapshot,
    expected_catalog_pin: str,
) -> list[ProjectionTraceabilityViolation]:
    violations: list[ProjectionTraceabilityViolation] = []

    try:
        pattern = validate_attack_pattern(authoritative_pattern, taxonomy_resolver)
        pattern = AttackPattern.model_validate(
            _normalize_semantic_order(pattern.model_dump(mode="json"))
        )
    except (TypeError, ValueError) as exc:
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.projection_drift,
                stage=ProjectionTraceabilityStage.actor_profile,
                detail=f"authoritative pattern qualification failed: {exc}",
            )
        )
        return violations

    chain = pattern.canonical_chain
    projection = block.projection

    # Compare source chain.
    if projection.source_chain != chain:
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.projection_drift,
                stage=ProjectionTraceabilityStage.actor_profile,
                detail="persisted source chain does not match authoritative pattern",
            )
        )
        return violations

    # Compare pins.
    pattern_pin = _pattern_pin(pattern)
    if projection.pattern_pin != pattern_pin:
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.authoritative_pattern_pin_mismatch,
                stage=ProjectionTraceabilityStage.actor_profile,
                detail="persisted pattern_pin does not match authoritative pattern",
            )
        )
    if projection.catalog_pin != expected_catalog_pin:
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.authoritative_catalog_pin_mismatch,
                stage=ProjectionTraceabilityStage.actor_profile,
                detail="persisted catalog_pin does not match trusted catalog",
            )
        )
    if (
        projection.capability_fact_snapshot_digest
        != capability_snapshot.snapshot_digest
    ):
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.projection_drift,
                stage=ProjectionTraceabilityStage.actor_profile,
                detail="persisted capability_fact_snapshot_digest does not match",
            )
        )

    # Recompute execution requirements from the projection.
    reqs, issue = _derive_execution_requirements_core(
        pattern.id, chain, projection, block.ingress_controllability
    )
    reqs, issue = _fail_closed_if_no_requirements(pattern.id, reqs, issue)
    if issue is not None:
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.requirement_drift,
                stage=ProjectionTraceabilityStage.actor_profile,
                detail=f"recomputation failed: {issue.detail}",
            )
        )
    elif reqs != block.execution_requirements:
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.requirement_drift,
                stage=ProjectionTraceabilityStage.actor_profile,
                detail="recomputed execution requirements do not match persisted",
            )
        )

    # Recompute projected mappings.
    expected_mappings = _projected_mappings(chain, projection.selected_step_ids)
    if expected_mappings != block.projected_mappings:
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.projection_drift,
                stage=ProjectionTraceabilityStage.actor_profile,
                detail="recomputed projected mappings do not match persisted",
            )
        )

    return violations


# ---------------------------------------------------------------------------#
# Check 6: ingress identity (contract §7)
# ---------------------------------------------------------------------------#


def _check_ingress_identity(
    envelope: ScenarioEnvelope,
    block: ProjectionEnvelopeBlock,
) -> list[ProjectionTraceabilityViolation]:
    violations: list[ProjectionTraceabilityViolation] = []
    expected = block.canonical_ingress.entry_point_id

    # Envelope-level initial_entry_point_id.
    if envelope.initial_entry_point_id != expected:
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.ingress_identity_mismatch,
                stage=ProjectionTraceabilityStage.actor_profile,
                detail=(
                    f"envelope initial_entry_point_id "
                    f"'{envelope.initial_entry_point_id}' does not match "
                    f"projection canonical_ingress '{expected}'"
                ),
                element_id="envelope.initial_entry_point_id",
            )
        )

    # Actor access provenance.
    actor = envelope.actor_profile
    if (
        actor is not None
        and actor.access is not None
        and actor.access.initial_entry_point_id != expected
    ):
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.ingress_identity_mismatch,
                stage=ProjectionTraceabilityStage.actor_profile,
                detail=(
                    f"actor access initial_entry_point_id "
                    f"'{actor.access.initial_entry_point_id}' does not "
                    f"match projection canonical_ingress '{expected}'"
                ),
                element_id="actor_profile.access.initial_entry_point_id",
            )
        )

    # Narrative access realization.
    narrative = envelope.narrative
    if (
        narrative.access_realization is not None
        and narrative.access_realization.initial_entry_point_id != expected
    ):
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.ingress_identity_mismatch,
                stage=ProjectionTraceabilityStage.narrative,
                detail=(
                    f"narrative access_realization initial_entry_point_id "
                    f"'{narrative.access_realization.initial_entry_point_id}' "
                    f"does not match projection canonical_ingress '{expected}'"
                ),
                element_id=str(narrative.access_realization.responsible_step_number),
            )
        )

    # Attack tree initial_ingress leaves.
    tree = envelope.attack_tree
    if tree is not None:
        for leaf in _iter_leaves(tree.root):
            if (
                leaf.action is not None
                and isinstance(leaf.action, InitialIngressAction)
                and leaf.action.entry_point_id != expected
            ):
                violations.append(
                    ProjectionTraceabilityViolation(
                        code=ProjectionTraceabilityViolationCode.ingress_identity_mismatch,
                        stage=ProjectionTraceabilityStage.attack_tree,
                        detail=(
                            f"tree leaf '{leaf.id}' initial_ingress "
                            f"entry_point_id '{leaf.action.entry_point_id}' "
                            f"does not match projection canonical_ingress "
                            f"'{expected}'"
                        ),
                        element_id=leaf.id,
                    )
                )

    return violations


# ---------------------------------------------------------------------------#
# Check 7: OR-tree prohibition (contract §6)
# ---------------------------------------------------------------------------#


def _check_or_tree_prohibition(
    envelope: ScenarioEnvelope,
    block: ProjectionEnvelopeBlock,
) -> list[ProjectionTraceabilityViolation]:
    violations: list[ProjectionTraceabilityViolation] = []
    tree = envelope.attack_tree
    if tree is None:
        return violations

    for node in _iter_all_nodes(tree.root):
        if node.gate == GateType.OR:
            violations.append(
                ProjectionTraceabilityViolation(
                    code=ProjectionTraceabilityViolationCode.or_tree_prohibited,
                    stage=ProjectionTraceabilityStage.attack_tree,
                    detail=(
                        f"OR node '{node.id}' is prohibited in v1 "
                        "authoritative scenario trees; AND decomposition/"
                        "hierarchy represents one concrete execution only"
                    ),
                    element_id=node.id,
                )
            )

    return violations


# ---------------------------------------------------------------------------#
# Check 2-5: narrative realizations (contract §4, §5)
# ---------------------------------------------------------------------------#


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


# ---------------------------------------------------------------------------#
# Check 2-5: attack tree realizations (contract §4, §5)
# ---------------------------------------------------------------------------#


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
            # Also verify the ingress slot is linked to at least one mapped step.
            if chain.initial_ingress_slot_id not in all_step_slots:
                violations.append(
                    ProjectionTraceabilityViolation(
                        code=ProjectionTraceabilityViolationCode.incorrect_resource_binding,
                        stage=ProjectionTraceabilityStage.attack_tree,
                        detail=(
                            f"tree leaf '{leaf.id}' uses initial_ingress but "
                            f"none of mapped steps {list(mapped_step_ids)} "
                            f"have an ingress resource_link"
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


# ---------------------------------------------------------------------------#
# Check 4b: per-step semantic compatibility (contract §4)
# ---------------------------------------------------------------------------#

# Mapping from canonical chain step action_kind to valid tree leaf action kinds.
# Canonical action_kinds: prepare, deliver, invoke, transform, persist, observe, impact
# Tree leaf action kinds: initial_ingress, external_precondition, ai_system_action,
#   tool_invocation, integration_interaction, impact
_STEP_TO_LEAF_ACTION_COMPAT: dict[str, set[str]] = {
    "prepare": {"external_precondition", "initial_ingress"},
    "deliver": {"initial_ingress"},
    "invoke": {"initial_ingress", "tool_invocation", "integration_interaction"},
    "transform": {"ai_system_action"},
    "persist": {"ai_system_action", "tool_invocation"},
    "observe": {
        "ai_system_action",
        "integration_interaction",
        "external_precondition",
    },
    "impact": {"impact"},
}

# Mapping from canonical executor_role to compatible leaf action kinds.
# 422o.4: all executor roles checked, not just attacker.
_EXECUTOR_ROLE_TO_LEAF_COMPAT: dict[str, set[str]] = {
    "attacker": {
        "initial_ingress",
        "external_precondition",
        "impact",
        "tool_invocation",
    },
    "system": {
        "ai_system_action",
        "tool_invocation",
        "integration_interaction",
        "impact",
    },
    "operator": {"external_precondition", "integration_interaction", "impact"},
}

# Mapping from canonical action_kind to valid Gherkin keyword for behavior.
# 422o.4: behavior keyword must match canonical action semantics.
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


# Mapping from canonical boundary_position to valid tree leaf constraints.
_BOUNDARY_COMPAT: dict[str, set[str | None]] = {
    "outside": {None},  # outside steps → external_precondition (no zone)
    "crossing": {"input", "reasoning", "tool_execution", "memory", "inter_agent"},
    "inside": {"input", "reasoning", "tool_execution", "memory", "inter_agent"},
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
                if leaf.zone not in valid_zones:
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
            # Narrative step zone must be compatible with projected step boundary.
            valid_zones = _BOUNDARY_COMPAT.get(step.boundary_position, set())
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


# ---------------------------------------------------------------------------#
# Check 8: assertion realizations (contract §4)
# ---------------------------------------------------------------------------#


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


# ---------------------------------------------------------------------------#
# Shared realization checks
# ---------------------------------------------------------------------------#


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


# ---------------------------------------------------------------------------#
# Tree traversal helpers
# ---------------------------------------------------------------------------#


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
