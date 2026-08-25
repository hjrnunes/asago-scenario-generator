"""Terminal transition and artifact assembly helpers."""

from __future__ import annotations

from typing import Any

from asago_scenario_generator.manifest import ManifestIntegrityError
from asago_scenario_generator.pipeline.finalization_contracts import (
    CandidateTerminalStatus,
    GeneratedStage,
    LifecycleState,
)
from .persistence_common import canonical_sha256
from .persistence_journal import (
    AdmittedArtifactPublication,
    AdmittedTerminalPayload,
    FinalizationInventoryV1,
    QuarantineBundleV1,
)
from .persistence_plan import CoveragePlanV2
from .persistence_journal import _publication_receipts, _quarantine_receipt
from .persistence_artifacts import (
    ArtifactReceipt,
    _terminal_receipt_projection,
)
from .persistence_models import (
    CandidateAttemptRecord,
    GateResultRecord,
    StageAttemptRecord,
    TransitionRecord,
    ViolationRecord,
)


def _causal_stage_artifacts(*args: Any, **kwargs: Any) -> dict[GeneratedStage, Any]:
    from asago_scenario_generator.pipeline import persistence_validation as validation

    return validation._causal_stage_artifacts(*args, **kwargs)


def _admitting_report_required(
    latest_transition: object, report: object | None
) -> None:
    if latest_transition.current is LifecycleState.admitting and report is None:
        raise TypeError(
            "admitting terminal result requires PostbehaviorAdmissionReport"
        )


def _terminal_state_for(expected_admitted: bool) -> LifecycleState:
    return LifecycleState.admitted if expected_admitted else LifecycleState.rejected


def _candidate_stages(
    next_inventory: FinalizationInventoryV1, candidate_id: str
) -> list[StageAttemptRecord]:
    return [
        item
        for item in next_inventory.stage_attempts
        if item.candidate_id == candidate_id
    ]


def _planned_choice_for(coverage_plan: CoveragePlanV2, candidate_id: str) -> object:
    return next(
        choice
        for target in coverage_plan.targets
        for choice in target.ordered_choices
        if choice.candidate_id == candidate_id
    )


def _terminal_trace(
    inventory: FinalizationInventoryV1, candidate_attempt: CandidateAttemptRecord
) -> tuple[list[TransitionRecord], TransitionRecord]:
    transitions = [
        item
        for item in inventory.transitions
        if item.target_entry_point_id == candidate_attempt.target_entry_point_id
    ]
    if not transitions:
        raise ManifestIntegrityError(
            "Terminal result requires a preceding target transition"
        )
    return transitions, max(transitions, key=lambda item: item.sequence)


def _terminal_transition_payload(
    candidate_id: str,
    status: object,
    latest_transition: TransitionRecord,
    target_entry_point_id: str,
    transition_index: int,
) -> dict[str, Any]:
    return {
        "previous": latest_transition.current.value,
        "current": (
            LifecycleState.admitted.value
            if status is CandidateTerminalStatus.admitted
            else LifecycleState.rejected.value
        ),
        "candidate_id": candidate_id,
        "reason": f"candidate terminal status: {status.value}",
        "transition_index": transition_index,
        "target_entry_point_id": target_entry_point_id,
    }


def _candidate_snapshots(
    stages: list[StageAttemptRecord], causal_artifacts: dict[GeneratedStage, Any]
) -> dict[str, str | None]:
    return {
        "candidate_snapshot_sha256": (
            stages[-1].candidate_snapshot_sha256 if stages else None
        ),
        "actor_snapshot_sha256": (
            canonical_sha256(causal_artifacts[GeneratedStage.actor])
            if GeneratedStage.actor in causal_artifacts
            else None
        ),
        "narrative_snapshot_sha256": (
            canonical_sha256(causal_artifacts[GeneratedStage.narrative])
            if GeneratedStage.narrative in causal_artifacts
            else None
        ),
        "final_tree_snapshot_sha256": (
            canonical_sha256(causal_artifacts[GeneratedStage.tree])
            if GeneratedStage.behavior in causal_artifacts
            else None
        ),
    }


def _quarantine_bundle_for(
    next_inventory: FinalizationInventoryV1,
    candidate_attempt: CandidateAttemptRecord,
    candidate_id: str,
    causal_artifacts: dict[GeneratedStage, Any],
    serialized_violations: list[ViolationRecord],
) -> tuple[QuarantineBundleV1, list[ArtifactReceipt]]:
    target_id = candidate_attempt.target_entry_point_id
    artifacts = {stage: causal_artifacts.get(stage) for stage in GeneratedStage}
    digests = {
        stage: canonical_sha256(artifact)
        for stage, artifact in artifacts.items()
        if artifact is not None
    }
    bundle = QuarantineBundleV1(
        schema_version="1",
        run_id=next_inventory.run_id,
        attempt_id=candidate_attempt.attempt_id,
        candidate_id=candidate_id,
        target_entry_point_id=target_id,
        actor=artifacts[GeneratedStage.actor],
        narrative=artifacts[GeneratedStage.narrative],
        tree=artifacts[GeneratedStage.tree],
        behavior=artifacts[GeneratedStage.behavior],
        artifact_sha256=digests,
        violations=serialized_violations,
    )
    return bundle, [_quarantine_receipt(bundle)]


def _publish_or_quarantine(
    candidate_id: str,
    terminal_payload: AdmittedTerminalPayload | None,
    next_inventory: FinalizationInventoryV1,
    candidate_attempt: CandidateAttemptRecord,
    causal_artifacts: dict[GeneratedStage, Any],
    serialized_violations: list[ViolationRecord],
) -> tuple[
    AdmittedArtifactPublication | None, QuarantineBundleV1 | None, list[ArtifactReceipt]
]:
    """Extend the terminal inventory with the admitted or quarantine receipts."""
    publication = terminal_payload.publication if terminal_payload is not None else None
    if publication is not None:
        if publication.candidate_id != candidate_id:
            raise ManifestIntegrityError(
                "Admitted publication candidate identity mismatch"
            )
        receipts = _publication_receipts(publication)
        next_inventory.admitted_inventory.extend(receipts)
        return publication, None, receipts
    bundle, receipts = _quarantine_bundle_for(
        next_inventory,
        candidate_attempt,
        candidate_id,
        causal_artifacts,
        serialized_violations,
    )
    next_inventory.quarantine_inventory.extend(receipts)
    return None, bundle, receipts


def _candidate_terminal_payload(
    candidate_id: str,
    status: object,
    serialized_violations: list[ViolationRecord],
    gate_results: list[GateResultRecord],
    terminal_receipts: list[ArtifactReceipt],
    snapshots: dict[str, str | None],
) -> dict[str, Any]:
    return {
        "candidate_id": candidate_id,
        "status": status.value,
        "violations": [item.model_dump(mode="json") for item in serialized_violations],
        "gate_results": [item.model_dump(mode="json") for item in gate_results],
        "snapshots": snapshots,
        "terminal_receipts": _terminal_receipt_projection(terminal_receipts),
    }
