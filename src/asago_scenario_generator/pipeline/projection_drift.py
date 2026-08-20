"""Projection drift and nested-mutation detection (contract §2).

Recomputes the projection digest and execution-requirements digest from the
embedded evidence and compares them to the persisted digests on the
projection block, so nested mutation after capture is detected.
"""

from __future__ import annotations

from typing import Any

from asago_scenario_generator.models.attack_pattern import (
    AttackPattern,
    TaxonomyResolver,
    validate_attack_pattern,
)
from asago_scenario_generator.models.projection_envelope import (
    ProjectionEnvelopeBlock,
    ProjectionTraceabilityStage,
    ProjectionTraceabilityViolation,
    ProjectionTraceabilityViolationCode,
)
from asago_scenario_generator.pipeline.projection import (
    CapabilityFactSnapshot,
    _derive_execution_requirements_core,
    _fail_closed_if_no_requirements,
    _normalize_semantic_order,
    _pattern_pin,
    _projected_mappings,
    compute_derivation_context_digest,
    compute_execution_requirements_digest,
)


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
