"""Terminal candidate-result methods for persistence."""

from __future__ import annotations

from typing import Any

from asago_scenario_generator.manifest import ManifestIntegrityError
from asago_scenario_generator.pipeline.finalization_contracts import (
    CandidateTerminalResult,
    GeneratedStage,
    LifecycleState,
)
from .persistence_common import _event_key, canonical_sha256
from .persistence_adapter_admission import (
    _admission_payload,
)
from .persistence_adapter_state import _next_transition_index
from .persistence_adapter_terminal import (
    _admitting_report_required,
    _candidate_stages,
    _candidate_snapshots,
    _candidate_terminal_payload,
    _planned_choice_for,
    _publish_or_quarantine,
    _terminal_state_for,
    _terminal_trace,
    _terminal_transition_payload,
)
from .persistence_journal import FinalizationInventoryV1
from .persistence_decisions import AdmissionDecisionRecord
from .persistence_artifacts import ArtifactReceipt
from .persistence_models import (
    CandidateAttemptRecord,
    GateResultRecord,
    ParsimonyRepairRecord,
    StageAttemptRecord,
    TransitionRecord,
    ViolationRecord,
)


class _PersistenceAdapterTerminalMethods:
    def _candidate_evidence(
        self,
        next_inventory: FinalizationInventoryV1,
        candidate_id: str,
        candidate_attempt: CandidateAttemptRecord,
    ) -> tuple[list[StageAttemptRecord], dict[GeneratedStage, Any]]:
        stages = _candidate_stages(next_inventory, candidate_id)
        planned_choice = _planned_choice_for(self.coverage_plan, candidate_id)
        from .persistence_adapter_terminal import _causal_stage_artifacts

        causal_artifacts = _causal_stage_artifacts(
            stages,
            candidate_attempt_id=candidate_attempt.attempt_id,
            durable_candidate=planned_choice.projected_candidate,
            repairs=[
                item
                for item in next_inventory.repairs
                if item.candidate_id == candidate_id
            ],
        )
        return stages, causal_artifacts

    def _terminal_records(
        self,
        next_inventory: FinalizationInventoryV1,
        candidate_id: str,
        candidate_attempt: CandidateAttemptRecord,
        transition_event_id: str,
        transition_payload_sha256: str,
        transition_payload: dict[str, Any],
        transition_index: int,
        latest_transition: TransitionRecord,
        terminal_state: LifecycleState,
        payload: dict[str, Any],
        payload_sha256: str,
        event_id: str,
        result: CandidateTerminalResult,
        gate_results: list[GateResultRecord],
        serialized_violations: list[ViolationRecord],
        terminal_receipts: list[ArtifactReceipt],
        snapshots: dict[str, str | None],
        expected_admitted: bool,
    ) -> bool:
        """Append the terminal transition and decision records; False on replay."""
        if self._replayed(event_id, payload_sha256):
            return False
        if latest_transition.candidate_id != candidate_id:
            raise ManifestIntegrityError(
                "Terminal result does not match active candidate trace"
            )
        next_inventory.transitions.append(
            TransitionRecord(
                event_id=transition_event_id,
                payload_sha256=transition_payload_sha256,
                sequence=self._sequence(next_inventory),
                target_entry_point_id=candidate_attempt.target_entry_point_id,
                index=transition_index,
                previous=latest_transition.current,
                current=terminal_state,
                candidate_id=candidate_id,
                reason=transition_payload["reason"],
            )
        )
        next_inventory.admission_decisions.append(
            AdmissionDecisionRecord(
                event_id=event_id,
                payload_sha256=payload_sha256,
                sequence=self._sequence(next_inventory),
                candidate_id=candidate_id,
                status=result.status,
                admitted=expected_admitted,
                gate_results=gate_results,
                violations=serialized_violations,
                terminal_receipts=terminal_receipts,
                **snapshots,
            )
        )
        return True

    def record_candidate_result(
        self, candidate_id: str, result: CandidateTerminalResult
    ) -> None:
        with self._lock:
            (
                terminal_payload,
                report,
                gate_results,
                serialized_violations,
                expected_admitted,
            ) = _admission_payload(result, candidate_id)
            next_inventory = self.inventory.model_copy(deep=True)
            candidate_attempt = self._candidate_attempt(next_inventory, candidate_id)
            target_transitions, latest_transition = _terminal_trace(
                next_inventory, candidate_attempt
            )
            _admitting_report_required(latest_transition, report)
            terminal_state = _terminal_state_for(expected_admitted)
            transition_index = _next_transition_index(target_transitions)
            transition_payload = _terminal_transition_payload(
                candidate_id,
                result.status,
                latest_transition,
                candidate_attempt.target_entry_point_id,
                transition_index,
            )
            transition_event_id = _event_key(
                "transition",
                [candidate_attempt.target_entry_point_id, transition_index],
            )
            transition_payload_sha256 = canonical_sha256(transition_payload)
            stages, causal_artifacts = self._candidate_evidence(
                next_inventory, candidate_id, candidate_attempt
            )
            snapshots = _candidate_snapshots(stages, causal_artifacts)
            publication, bundle, terminal_receipts = _publish_or_quarantine(
                candidate_id,
                terminal_payload,
                next_inventory,
                candidate_attempt,
                causal_artifacts,
                serialized_violations,
            )
            payload = _candidate_terminal_payload(
                candidate_id,
                result.status,
                serialized_violations,
                gate_results,
                terminal_receipts,
                snapshots,
            )
            payload_sha256 = canonical_sha256(payload)
            event_id = _event_key("candidate_result", candidate_id)
            appended = self._terminal_records(
                next_inventory,
                candidate_id,
                candidate_attempt,
                transition_event_id,
                transition_payload_sha256,
                transition_payload,
                transition_index,
                latest_transition,
                terminal_state,
                payload,
                payload_sha256,
                event_id,
                result,
                gate_results,
                serialized_violations,
                terminal_receipts,
                snapshots,
                expected_admitted,
            )
            if appended:
                self._commit(
                    next_inventory,
                    quarantine_bundle=bundle,
                    admitted_publication=publication,
                )

    def record_repair(self, candidate_id: str, record: Any) -> None:
        with self._lock:
            next_inventory = self.inventory.model_copy(deep=True)
            attempt = self._candidate_attempt(next_inventory, candidate_id)
            payload = {
                "candidate_id": candidate_id,
                "before_digest": record.before_digest,
                "after_digest": record.after_digest,
                "removed_ids": list(record.removed_ids),
                "preserved_projected_ids": list(record.preserved_projected_ids),
                "accepted": record.accepted,
                "detail": record.detail,
            }
            payload_sha256 = canonical_sha256(payload)
            event_id = _event_key(
                "parsimony_repair", [candidate_id, record.before_digest]
            )
            if self._replayed(event_id, payload_sha256):
                return
            next_inventory.repairs.append(
                ParsimonyRepairRecord(
                    event_id=event_id,
                    payload_sha256=payload_sha256,
                    sequence=self._sequence(next_inventory),
                    candidate_attempt_id=attempt.attempt_id,
                    candidate_id=candidate_id,
                    target_entry_point_id=attempt.target_entry_point_id,
                    before_digest=record.before_digest,
                    after_digest=record.after_digest,
                    removed_ids=list(record.removed_ids),
                    preserved_projected_ids=list(record.preserved_projected_ids),
                    accepted=record.accepted,
                    detail=record.detail,
                )
            )
            self._commit(next_inventory)
