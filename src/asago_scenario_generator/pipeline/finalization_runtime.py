"""Snapshot and lifecycle plumbing for the finalization port."""

from __future__ import annotations

from typing import Any

from asago_scenario_generator.pipeline.finalization_contracts import (
    CandidateFinalizationContext,
    GeneratedArtifacts,
    GeneratedStage,
    PrebehaviorFinalizationResult,
)
from asago_scenario_generator.pipeline.finalization_gate_contracts import (
    GateCode,
    GateResult,
    GateViolation,
)
from asago_scenario_generator.pipeline.finalization_snapshots import (
    ActorSemanticSnapshot,
    FinalTreeSemanticSnapshot,
    NarrativeSemanticSnapshot,
    ProjectionSemanticSnapshot,
)
from asago_scenario_generator.pipeline.projection_contracts import (
    ProjectedCandidate,
    canonical_json_bytes,
)


def _context_guard_failure(
    context: CandidateFinalizationContext,
) -> PrebehaviorFinalizationResult | None:
    """Failure when the context is not a verified candidate context."""
    if not isinstance(context, CandidateFinalizationContext) or not isinstance(
        context.verified_snapshot, ProjectionSemanticSnapshot
    ):
        return PrebehaviorFinalizationResult(
            None,
            (
                GateViolation(
                    GateCode.candidate_identity,
                    "verified candidate context is required",
                    None,
                ).lifecycle(),
            ),
        )
    return None


def _revalidated_projection(
    context: CandidateFinalizationContext,
) -> ProjectedCandidate | PrebehaviorFinalizationResult:
    """Revalidate the candidate against its authoritative snapshot."""
    try:
        projection = context.verified_snapshot
        projection.verify_digest()
        current = ProjectedCandidate.model_validate(
            context.candidate.model_dump(mode="json")
        )
        if canonical_json_bytes(current) != projection.canonical_bytes:
            raise ValueError(
                "candidate changed after authoritative revalidation snapshot"
            )
    except (TypeError, ValueError, AttributeError) as exc:
        return PrebehaviorFinalizationResult(
            None,
            (GateViolation(GateCode.candidate_identity, str(exc), None).lifecycle(),),
        )
    return projection


def _capture_one_snapshot(
    snapshot_type: type, artifact: Any, owner: GeneratedStage
) -> Any | PrebehaviorFinalizationResult:
    """Capture one semantic snapshot, or a snapshot-integrity failure."""
    try:
        snapshot = snapshot_type.capture(artifact)
        snapshot.verify_digest()
    except (TypeError, ValueError, AttributeError) as exc:
        return PrebehaviorFinalizationResult(
            None,
            (GateViolation(GateCode.snapshot_integrity, str(exc), owner).lifecycle(),),
        )
    return snapshot


def _captured_artifacts(
    artifacts: GeneratedArtifacts,
) -> tuple[Any, Any, Any] | PrebehaviorFinalizationResult:
    """Capture and verify actor, narrative, and tree semantic snapshots."""
    captured: list[Any] = []
    for snapshot_type, artifact, owner in (
        (ActorSemanticSnapshot, artifacts.actor, GeneratedStage.actor),
        (NarrativeSemanticSnapshot, artifacts.narrative, GeneratedStage.narrative),
        (FinalTreeSemanticSnapshot, artifacts.tree, GeneratedStage.tree),
    ):
        snapshot = _capture_one_snapshot(snapshot_type, artifact, owner)
        if isinstance(snapshot, PrebehaviorFinalizationResult):
            return snapshot
        captured.append(snapshot)
    actor, narrative, tree = captured
    return actor, narrative, tree


def _preflight(
    context: CandidateFinalizationContext, artifacts: GeneratedArtifacts
) -> tuple[Any, Any, Any, Any] | PrebehaviorFinalizationResult:
    """Verified (projection, actor, narrative, tree), or a failure result."""
    failure = _context_guard_failure(context)
    if failure is not None:
        return failure
    projection = _revalidated_projection(context)
    if isinstance(projection, PrebehaviorFinalizationResult):
        return projection
    captured = _captured_artifacts(artifacts)
    if isinstance(captured, PrebehaviorFinalizationResult):
        return captured
    actor, narrative, tree = captured
    return projection, actor, narrative, tree


def _gate_failure_result(gates: GateResult) -> PrebehaviorFinalizationResult | None:
    """Lifecycle-violation failure when a gate result has violations."""
    if gates.violations:
        return PrebehaviorFinalizationResult(
            None, tuple(v.lifecycle() for v in gates.violations)
        )
    return None
