"""Compatibility façade for pre-behavior finalization gates.

Gate contracts, snapshots, repair, and pure pre-behavior checks live in
responsibility-specific modules.  This façade retains the established import
surface and the finalizer's monkeypatch seams.
"""

from __future__ import annotations

from typing import Any

from asago_scenario_generator.models.complexity import capability_level_rank
from asago_scenario_generator.pipeline.complexity import (
    assess_candidate_complexity,
    assess_final_complexity,
)
from asago_scenario_generator.pipeline.finalization_contracts import (
    CandidateFinalizationContext,
    GeneratedArtifacts,
    GeneratedStage,
    PrebehaviorFinalizationResult,
)
from . import (
    finalization_gate_contracts,
    finalization_parsimony,
    finalization_prebehavior,
    finalization_runtime,
    finalization_snapshots,
)
from .finalization_gate_contracts import (
    CONDITIONALLY_APPLICABLE_EVIDENCE_IDS,
    DIAGNOSTIC_BACKED_EVIDENCE_IDS,
    EXCEPTIONAL_ADMISSION_EVIDENCE_IDS,
    NORMAL_POSTBEHAVIOR_EVIDENCE_IDS,
    AdmissionEvidenceId,
    GateCode,
    GateResult,
    GateViolation,
)
from .finalization_parsimony import (
    RepairRecord,
    TreeParsimonyResult,
    check_tree_parsimony,
    finalize_tree_parsimony,
)
from .finalization_prebehavior import run_prebehavior_gates
from .finalization_runtime import (
    _gate_failure_result,
    _preflight,
)
from .finalization_snapshots import (
    ActorSemanticSnapshot,
    FinalTreeSemanticSnapshot,
    NarrativeSemanticSnapshot,
    ProjectionSemanticSnapshot,
)


def _complexity_floor_violation(
    candidate: Any,
    before_tree: Any,
    after_tree: Any,
    actor: Any,
) -> PrebehaviorFinalizationResult | None:
    """Violation when parsimony repair lowers required attack complexity."""
    before = assess_final_complexity(
        assess_candidate_complexity(candidate),
        [leaf for leaf in _leaves(before_tree.root)],
        actor.access,
    )
    after = assess_final_complexity(
        assess_candidate_complexity(candidate),
        [leaf for leaf in _leaves(after_tree.root)],
        actor.access,
    )
    if (
        before.final is not None
        and after.final is not None
        and capability_level_rank(after.final.required_level)
        < capability_level_rank(before.final.required_level)
    ):
        return PrebehaviorFinalizationResult(
            None,
            (
                GateViolation(
                    GateCode.parsimony,
                    "parsimony repair lowered required attack complexity",
                    GeneratedStage.tree,
                ).lifecycle(),
            ),
        )
    return None


def _parsimony_repair(
    tree: Any, candidate: Any, actor: Any
) -> tuple[Any | None, PrebehaviorFinalizationResult | None]:
    """Apply parsimony repair, then verify the complexity floor holds."""
    repair = finalize_tree_parsimony(tree)
    if repair.violations:
        return None, PrebehaviorFinalizationResult(
            None, tuple(v.lifecycle() for v in repair.violations)
        )
    failure = _complexity_floor_violation(candidate, tree, repair.tree, actor)
    if failure is not None:
        return None, failure
    return repair, None


def _final_tree_snapshot(
    repair: Any,
) -> tuple[Any | None, PrebehaviorFinalizationResult | None]:
    """Final repaired-tree snapshot, or a snapshot-integrity failure."""
    try:
        snapshot = FinalTreeSemanticSnapshot.capture(repair.tree)
        snapshot.verify_digest()
    except (TypeError, ValueError, AttributeError) as exc:
        return None, PrebehaviorFinalizationResult(
            None,
            (
                GateViolation(
                    GateCode.snapshot_integrity, str(exc), GeneratedStage.tree
                ).lifecycle(),
            ),
        )
    return snapshot, None


class PrebehaviorFinalizerPort:
    """Concrete, callable finalization port; deliberately not production-wired."""

    def __init__(self, capability_snapshot: Any, profile: Any | None = None) -> None:
        self.capability_snapshot = capability_snapshot
        self.profile = profile or capability_snapshot.profile

    def _rerun_and_snapshot(
        self,
        projection: ProjectionSemanticSnapshot,
        actor: Any,
        narrative: Any,
        repair: Any,
    ) -> tuple[Any | None, PrebehaviorFinalizationResult | None]:
        """Rerun gates on the repaired tree, then capture the final snapshot."""
        failure = _gate_failure_result(
            run_prebehavior_gates(
                projection.candidate,
                actor.actor,
                narrative.narrative,
                repair.tree,
                self.capability_snapshot,
                self.profile,
            )
        )
        if failure is not None:
            return None, failure
        return _final_tree_snapshot(repair)

    def _finalize_verified(
        self,
        projection: ProjectionSemanticSnapshot,
        actor: Any,
        narrative: Any,
        tree: Any,
    ) -> PrebehaviorFinalizationResult:
        """Run the gate, parsimony, and revalidation sequence."""
        try:
            failure = _gate_failure_result(
                run_prebehavior_gates(
                    projection.candidate,
                    actor.actor,
                    narrative.narrative,
                    tree.tree,
                    self.capability_snapshot,
                    self.profile,
                )
            )
            if failure is not None:
                return failure
            repair, failure = _parsimony_repair(
                tree.tree, projection.candidate, actor.actor
            )
            if failure is not None:
                return failure
            snapshot, failure = self._rerun_and_snapshot(
                projection, actor, narrative, repair
            )
            if failure is not None:
                return failure
            return PrebehaviorFinalizationResult(
                snapshot,
                candidate_snapshot=projection,
                actor_snapshot=actor,
                narrative_snapshot=narrative,
                repair_record=repair.record,
            )
        except (TypeError, ValueError, AttributeError) as exc:
            return PrebehaviorFinalizationResult(
                None,
                (
                    GateViolation(
                        GateCode.snapshot_integrity, str(exc), GeneratedStage.tree
                    ).lifecycle(),
                ),
            )

    def __call__(
        self, context: CandidateFinalizationContext, artifacts: GeneratedArtifacts
    ) -> PrebehaviorFinalizationResult:
        preflight = _preflight(context, artifacts)
        if isinstance(preflight, PrebehaviorFinalizationResult):
            return preflight
        projection, actor, narrative, tree = preflight
        return self._finalize_verified(projection, actor, narrative, tree)


def make_prebehavior_finalizer(
    capability_snapshot: Any, profile: Any | None = None
) -> PrebehaviorFinalizerPort:
    """Build the concrete callback without wiring it into the runner."""
    return PrebehaviorFinalizerPort(capability_snapshot, profile)


def _leaves(node: Any) -> list[Any]:
    """Compatibility traversal used by the façade's complexity check."""
    return finalization_parsimony._leaves(node)


_COMPATIBILITY_MODULES = (
    finalization_gate_contracts,
    finalization_snapshots,
    finalization_parsimony,
    finalization_prebehavior,
    finalization_runtime,
)


def __getattr__(name: str) -> Any:
    """Resolve historical private helpers from implementation modules."""
    for module in _COMPATIBILITY_MODULES:
        try:
            return getattr(module, name)
        except AttributeError:
            continue
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = (
    "CONDITIONALLY_APPLICABLE_EVIDENCE_IDS",
    "DIAGNOSTIC_BACKED_EVIDENCE_IDS",
    "EXCEPTIONAL_ADMISSION_EVIDENCE_IDS",
    "NORMAL_POSTBEHAVIOR_EVIDENCE_IDS",
    "AdmissionEvidenceId",
    "ActorSemanticSnapshot",
    "FinalTreeSemanticSnapshot",
    "GateCode",
    "GateResult",
    "GateViolation",
    "NarrativeSemanticSnapshot",
    "PrebehaviorFinalizerPort",
    "ProjectionSemanticSnapshot",
    "RepairRecord",
    "TreeParsimonyResult",
    "check_tree_parsimony",
    "finalize_tree_parsimony",
    "make_prebehavior_finalizer",
    "run_prebehavior_gates",
)
