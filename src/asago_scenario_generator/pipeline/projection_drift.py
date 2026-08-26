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
from asago_scenario_generator.pipeline.projection_contracts import (
    _normalize_semantic_order,
    _pattern_pin,
    _projected_mappings,
    compute_derivation_context_digest,
    compute_execution_requirements_digest,
)
from asago_scenario_generator.pipeline.projection_requirements import (
    _derive_execution_requirements_core,
    _fail_closed_if_no_requirements,
)
from asago_scenario_generator.pipeline.projection_snapshot import (
    CapabilityFactSnapshot,
)


def _authoritative_inputs_available(
    authoritative_pattern: dict[str, Any] | None,
    taxonomy_resolver: TaxonomyResolver | None,
    capability_snapshot: CapabilityFactSnapshot | None,
    expected_catalog_pin: str | None,
) -> bool:
    """Whether all authoritative source inputs were supplied for qualification."""
    return (
        authoritative_pattern is not None
        and taxonomy_resolver is not None
        and capability_snapshot is not None
        and expected_catalog_pin is not None
    )


def _verify_projection_digest(
    block: ProjectionEnvelopeBlock,
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Re-validate the snapshot digest by re-serializing (nested mutation)."""
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


def _verify_requirements_digest(
    block: ProjectionEnvelopeBlock,
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Recompute the execution-requirements digest and compare to the stored one."""
    # Handle both model instances and plain dicts (model_construct bypass may
    # produce dicts for discriminated-union fields).
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


def _verify_snapshot_integrity(
    block: ProjectionEnvelopeBlock,
    violations: list[ProjectionTraceabilityViolation],
) -> bool:
    """Verify embedded capability snapshot integrity; False if corrupted."""
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
        return False  # Cannot proceed with corrupted evidence.
    return True


def _verify_snapshot_digest_match(
    block: ProjectionEnvelopeBlock,
    violations: list[ProjectionTraceabilityViolation],
) -> bool:
    """Verify the snapshot digest matches the projection pin; False if not."""
    snapshot = block.capability_snapshot
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
        return False
    return True


def _derive_controllability_from_evidence(
    block: ProjectionEnvelopeBlock,
    violations: list[ProjectionTraceabilityViolation],
) -> str | None:
    """Derive ingress controllability from the embedded evidence, or None."""
    snapshot = block.capability_snapshot
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
            return None
        return ep.effective_controllability
    except (ValueError, TypeError, AttributeError) as exc:
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.requirement_drift,
                stage=ProjectionTraceabilityStage.actor_profile,
                detail=f"failed to derive controllability from evidence: {exc}",
            )
        )
        return None


def _check_controllability_match(
    derived_controllability: str,
    block: ProjectionEnvelopeBlock,
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Flag persisted controllability that disagrees with the derived value."""
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


def _recompute_requirements_from_evidence(
    block: ProjectionEnvelopeBlock,
    pattern_id: str,
    chain: Any,
    derived_controllability: str,
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Recompute execution requirements from embedded projection + derived control."""
    # Recompute from embedded projection + derived controllability
    # (NOT persisted controllability).
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


def _verify_derivation_context_digest(
    block: ProjectionEnvelopeBlock,
    pattern_id: str,
    derived_controllability: str,
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Verify the derivation context digest with evidence-derived controllability."""
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


def _verify_projected_mappings(
    block: ProjectionEnvelopeBlock,
    chain: Any,
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Recompute projected_mappings from the embedded source chain + selected IDs."""
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


def _check_projection_drift(
    block: ProjectionEnvelopeBlock,
    *,
    authoritative_pattern: dict[str, Any] | None,
    taxonomy_resolver: TaxonomyResolver | None,
    capability_snapshot: CapabilityFactSnapshot | None,
    expected_catalog_pin: str | None,
) -> list[ProjectionTraceabilityViolation]:
    violations: list[ProjectionTraceabilityViolation] = []

    _verify_projection_digest(block, violations)
    _verify_requirements_digest(block, violations)

    # --- Standalone recomputation from embedded evidence (422o.4 blocker #2-#3) ---
    # Derive controllability from the embedded CapabilityFactSnapshot, NOT
    # from the persisted ingress_controllability field (which is self-signed).
    # This prevents a caller from flipping controllability and re-signing
    # arbitrary requirements.
    chain = block.projection.source_chain
    pattern_id = chain.pattern_id

    # Step 1: Verify snapshot integrity (detect nested mutation of evidence).
    if not _verify_snapshot_integrity(block, violations):
        return violations

    # Step 2: Verify snapshot digest matches the projection pin.
    if not _verify_snapshot_digest_match(block, violations):
        return violations

    # Step 3: Derive controllability from evidence.
    derived_controllability = _derive_controllability_from_evidence(block, violations)
    if derived_controllability is None:
        return violations

    # Step 4: Verify persisted controllability matches derived.
    _check_controllability_match(derived_controllability, block, violations)

    # Step 5: Recompute execution requirements from embedded projection +
    # derived controllability (NOT persisted controllability).
    _recompute_requirements_from_evidence(
        block, pattern_id, chain, derived_controllability, violations
    )

    # Step 6: Verify derivation context digest using derived controllability.
    _verify_derivation_context_digest(
        block, pattern_id, derived_controllability, violations
    )

    # Recompute projected_mappings from embedded source chain + selected IDs.
    _verify_projected_mappings(block, chain, violations)

    # When authoritative source inputs are available, recompute and compare
    # as additional qualification (not the only semantic check).
    if _authoritative_inputs_available(
        authoritative_pattern,
        taxonomy_resolver,
        capability_snapshot,
        expected_catalog_pin,
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


def _validate_authoritative_pattern(
    authoritative_pattern: dict[str, Any],
    taxonomy_resolver: TaxonomyResolver,
    violations: list[ProjectionTraceabilityViolation],
) -> AttackPattern | None:
    """Validate and normalize the authoritative pattern, or None on failure."""
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
        return None
    return pattern


def _compare_source_chain(
    projection: Any,
    chain: Any,
    violations: list[ProjectionTraceabilityViolation],
) -> bool:
    """Compare the persisted source chain to the authoritative chain; True if equal."""
    if projection.source_chain != chain:
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.projection_drift,
                stage=ProjectionTraceabilityStage.actor_profile,
                detail="persisted source chain does not match authoritative pattern",
            )
        )
        return False
    return True


def _compare_projection_pins(
    projection: Any,
    pattern: AttackPattern,
    expected_catalog_pin: str,
    capability_snapshot: CapabilityFactSnapshot,
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Compare the pattern pin, catalog pin, and snapshot digest pins."""
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


def _compare_recomputed_requirements(
    projection: Any,
    pattern: AttackPattern,
    block: ProjectionEnvelopeBlock,
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Recompute execution requirements from the projection and compare."""
    chain = pattern.canonical_chain
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


def _compare_recomputed_mappings(
    projection: Any,
    chain: Any,
    block: ProjectionEnvelopeBlock,
    violations: list[ProjectionTraceabilityViolation],
) -> None:
    """Recompute projected mappings and compare to the persisted ones."""
    expected_mappings = _projected_mappings(chain, projection.selected_step_ids)
    if expected_mappings != block.projected_mappings:
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.projection_drift,
                stage=ProjectionTraceabilityStage.actor_profile,
                detail="recomputed projected mappings do not match persisted",
            )
        )


def _recompute_and_compare(
    block: ProjectionEnvelopeBlock,
    authoritative_pattern: dict[str, Any],
    taxonomy_resolver: TaxonomyResolver,
    capability_snapshot: CapabilityFactSnapshot,
    expected_catalog_pin: str,
) -> list[ProjectionTraceabilityViolation]:
    violations: list[ProjectionTraceabilityViolation] = []

    pattern = _validate_authoritative_pattern(
        authoritative_pattern, taxonomy_resolver, violations
    )
    if pattern is None:
        return violations

    chain = pattern.canonical_chain
    projection = block.projection

    # Compare source chain.
    if not _compare_source_chain(projection, chain, violations):
        return violations

    # Compare pins.
    _compare_projection_pins(
        projection, pattern, expected_catalog_pin, capability_snapshot, violations
    )

    # Recompute execution requirements from the projection.
    _compare_recomputed_requirements(projection, pattern, block, violations)

    # Recompute projected mappings.
    _compare_recomputed_mappings(projection, chain, block, violations)

    return violations
