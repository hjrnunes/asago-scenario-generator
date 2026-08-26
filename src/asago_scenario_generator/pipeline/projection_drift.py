"""Projection drift and nested-mutation detection (contract §2).

Recomputes the projection digest and execution-requirements digest from the
embedded evidence and compares them to the persisted digests on the
projection block, so nested mutation after capture is detected.
"""

from __future__ import annotations

from typing import Any

from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
from asago_scenario_generator.models.attack_pattern_contracts import TaxonomyResolver
from asago_scenario_generator.models.attack_pattern_validation import (
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
        from asago_scenario_generator.models.attack_pattern_digests import (
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


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-26T11:30:52Z","module_hash":"076680e7d5dd6b651dae39bc078a4f8fa8188ee5b2491e4b25f2a69b3bd8c2ec","source_sha256":"abaa11a4c03c523eaa36ea8f42757c7485a9333d3e58b7aadd3165a95160f5db","functions":[{"id":"func/_authoritative_inputs_available","name":"_authoritative_inputs_available","line":39,"end_line":51,"hash":"e58c9be813b4f609afacb9f0801f483257e2d00772614d5ac8d4834856ca1cbb"},{"id":"func/_verify_projection_digest","name":"_verify_projection_digest","line":54,"end_line":89,"hash":"d99140488ed602b3661d694348b02e936450d7c2edd74509a7197083199dd41d"},{"id":"func/_verify_requirements_digest","name":"_verify_requirements_digest","line":92,"end_line":112,"hash":"9e5e36a4f546c4e11d41ec2b8c8a4751a4e603c951060c4c51c03895c265df12"},{"id":"func/_verify_snapshot_integrity","name":"_verify_snapshot_integrity","line":115,"end_line":132,"hash":"3967d2b75babb9e82ddf0472ca2e7c8c6ae43e1bde96cbb6453017cfb7e19420"},{"id":"func/_verify_snapshot_digest_match","name":"_verify_snapshot_digest_match","line":135,"end_line":154,"hash":"dda8af3b6809bfc16cd1d356ae0909c54539100a1f9babd7ebcc380dd4f96193"},{"id":"func/_derive_controllability_from_evidence","name":"_derive_controllability_from_evidence","line":157,"end_line":188,"hash":"7e032f3cc242f05f320813d67450f0f872a96fc372bd9b9b43240b260689fb56"},{"id":"func/_check_controllability_match","name":"_check_controllability_match","line":191,"end_line":209,"hash":"6fd914018c2f7e64c45270e7ad0e94a48514084c729eedc6d0e9bac851550341"},{"id":"func/_recompute_requirements_from_evidence","name":"_recompute_requirements_from_evidence","line":212,"end_line":248,"hash":"e2e591608f8bf16a4ad774fc5072545c7e3f8d301ba35a6b136b0c73278d0f98"},{"id":"func/_verify_derivation_context_digest","name":"_verify_derivation_context_digest","line":251,"end_line":274,"hash":"97ce91bec3f842fe323b8110bb2d210d4399ebe20e8640ce5cee91e80713ac39"},{"id":"func/_verify_projected_mappings","name":"_verify_projected_mappings","line":277,"end_line":294,"hash":"bd21bebc2156add278dcce1f906d1532104be87cf4a3406f2bfea2764bc1a7dd"},{"id":"func/_check_projection_drift","name":"_check_projection_drift","line":297,"end_line":366,"hash":"5f2e7448a1565286a537733fa9c6e43774f5c52fd51f14d1a422e162cc2a59c6"},{"id":"func/_validate_authoritative_pattern","name":"_validate_authoritative_pattern","line":369,"end_line":389,"hash":"b1884a4a74ebb7d139dfaa41a7ce32d53074220d4debf7a02130e5738f9bed9b"},{"id":"func/_compare_source_chain","name":"_compare_source_chain","line":392,"end_line":407,"hash":"6cdedbb398871ea1cf66d86ebfe57e85cbb8a2d966e27ca5d52aa7c5f2f88365"},{"id":"func/_compare_projection_pins","name":"_compare_projection_pins","line":410,"end_line":445,"hash":"c6d48280602f1ad802205708af0bfb43c9ad10f7cedb64f966ea233a8bfc6ab3"},{"id":"func/_compare_recomputed_requirements","name":"_compare_recomputed_requirements","line":448,"end_line":475,"hash":"9b66f6fcfa2448a2d942ee7338660ceb786ad8ec4d66b6526b6e30d6c57ccd51"},{"id":"func/_compare_recomputed_mappings","name":"_compare_recomputed_mappings","line":478,"end_line":493,"hash":"e1e2250f112044a79d4ed1f8c3bc80f94c86b7ba461bb6c4de8a887dab6cc75a"},{"id":"func/_recompute_and_compare","name":"_recompute_and_compare","line":496,"end_line":529,"hash":"60899db7611bbe53c6e716ebe894630012f3e2e4ec4ad21afcbe07b83a198a4d"}]}
# mutate4py-manifest-end
