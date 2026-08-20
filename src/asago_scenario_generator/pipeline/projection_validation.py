"""Standalone projection traceability validation for ScenarioEnvelope.

Validates that every generated artifact (narrative, attack tree, behavior
spec) is completely and faithfully traced to the deeply immutable canonical
projection persisted on the envelope (bead ``asago-scenario-generator-422o.4``).

This module owns the **entry point** and the ingress/OR-tree checks; the
per-artifact realization checks live in ``projection_realizations``,
per-step semantic compatibility in ``projection_semantics``, and drift
detection in ``projection_drift``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from asago_scenario_generator.models.attack_pattern import TaxonomyResolver
from asago_scenario_generator.models.attack_tree import (
    GateType,
    InitialIngressAction,
)
from asago_scenario_generator.models.projection_envelope import (
    ProjectionEnvelopeBlock,
    ProjectionTraceabilityResult,
    ProjectionTraceabilityStage,
    ProjectionTraceabilityViolation,
    ProjectionTraceabilityViolationCode,
)
from asago_scenario_generator.pipeline.compatibility import (
    EXECUTOR_ROLE_TO_LEAF_COMPAT,
    STEP_TO_LEAF_ACTION_COMPAT,
)
from asago_scenario_generator.pipeline.projection import (
    CapabilityFactSnapshot,
    _candidate_v2_id,
)
from asago_scenario_generator.pipeline.projection_drift import (
    _check_projection_drift,
)
from asago_scenario_generator.pipeline.projection_realizations import (
    _check_assertion_realizations,
    _check_narrative_physical_order,
    _check_narrative_realizations,
    _check_technique_mapping,
    _check_tree_physical_order,
    _check_tree_realizations,
    _check_tree_resource_bindings,
    _iter_all_nodes,
    _iter_leaves,
)
from asago_scenario_generator.pipeline.projection_semantics import (
    _check_behavior_realizations,
    _check_step_semantic_compatibility,
)

if TYPE_CHECKING:
    from asago_scenario_generator.models.scenario import ScenarioEnvelope

_EXECUTOR_ROLE_TO_LEAF_COMPAT = EXECUTOR_ROLE_TO_LEAF_COMPAT
_STEP_TO_LEAF_ACTION_COMPAT = STEP_TO_LEAF_ACTION_COMPAT

__all__ = [
    "EXECUTOR_ROLE_TO_LEAF_COMPAT",
    "STEP_TO_LEAF_ACTION_COMPAT",
    "_EXECUTOR_ROLE_TO_LEAF_COMPAT",
    "_STEP_TO_LEAF_ACTION_COMPAT",
    "_check_narrative_physical_order",
    "_check_step_semantic_compatibility",
    "_check_technique_mapping",
    "_check_tree_physical_order",
    "_check_tree_resource_bindings",
    "validate_projection_traceability",
]


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


# ---------------------------------------------------------------------------#
# Check 2-5: attack tree realizations (contract §4, §5)
# ---------------------------------------------------------------------------#


# ---------------------------------------------------------------------------#
# Check 4b: per-step semantic compatibility (contract §4)
# ---------------------------------------------------------------------------#
# The action-kind and executor-role compatibility mappings live in
# ``pipeline.compatibility`` (single source of truth shared with the prompt
# alignment table).  They are re-imported above as the ``_``-prefixed names
# so existing call sites keep working.

# Mapping from canonical action_kind to valid Gherkin keyword for behavior.
# 422o.4: behavior keyword must match canonical action semantics.


# ---------------------------------------------------------------------------#
# Check 8: assertion realizations (contract §4)
# ---------------------------------------------------------------------------#


# ---------------------------------------------------------------------------#
# Shared realization checks
# ---------------------------------------------------------------------------#


# ---------------------------------------------------------------------------#
# Tree traversal helpers
# ---------------------------------------------------------------------------#
