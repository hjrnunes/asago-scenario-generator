"""Candidate-attempt and stage-result methods for persistence."""

from __future__ import annotations

from typing import Any

from asago_scenario_generator.manifest import ManifestIntegrityError
from asago_scenario_generator.pipeline.finalization_contracts import (
    GeneratedStageResult,
    LifecycleState,
    LifecycleTransition,
    StageInvocation,
)
from .persistence_common import _event_key, _json_value, canonical_sha256
from .persistence_adapter_evidence import (
    _call_log_entry,
    _call_log_entry_for,
    _stage_attempt_payload,
    _stage_evidence_parts,
    _stage_input_record,
    _visible_artifact_map,
    _violations,
)
from .persistence_journal import FinalizationInventoryV1
from .persistence_models import (
    CandidateAttemptRecord,
    StageAttemptRecord,
    StageInputRecord,
    TransitionRecord,
)


class _PersistenceAdapterEventMethods:
    def _resolved_transition_target(self, transition: LifecycleTransition) -> str:
        """Resolve the durable target identity for one transition."""
        target_id = transition.target_entry_point_id
        if target_id is None and transition.candidate_id in self._candidate_plan:
            target_id = self._candidate_plan[transition.candidate_id][0]
        if target_id is None:
            raise ManifestIntegrityError(
                "Lifecycle transition requires target identity"
            )
        return target_id

    def _record_candidate_attempt_if_missing(
        self, next_inventory: FinalizationInventoryV1, candidate_id: str
    ) -> None:
        """Persist the reserved candidate attempt event exactly once."""
        if candidate_id not in self._candidate_plan:
            raise ManifestIntegrityError(
                f"Unknown coverage-plan candidate {candidate_id!r}"
            )
        if any(
            item.candidate_id == candidate_id
            for item in next_inventory.candidate_attempts
        ):
            return
        target_id, queue_rank = self._candidate_plan[candidate_id]
        candidate_payload = {
            "candidate_id": candidate_id,
            "target_entry_point_id": target_id,
            "queue_rank": queue_rank,
        }
        candidate_event = _event_key("candidate_attempt", candidate_id)
        candidate_digest = canonical_sha256(candidate_payload)
        if not self._replayed(candidate_event, candidate_digest):
            next_inventory.candidate_attempts.append(
                CandidateAttemptRecord(
                    event_id=candidate_event,
                    payload_sha256=candidate_digest,
                    sequence=self._sequence(next_inventory),
                    attempt_id=f"{candidate_id}:candidate",
                    candidate_id=candidate_id,
                    target_entry_point_id=target_id,
                    queue_rank=queue_rank,
                    is_primary=queue_rank == 0,
                    stage_attempt_ids=[],
                )
            )

    def _candidate_attempt(
        self, inventory: FinalizationInventoryV1, candidate_id: str
    ) -> CandidateAttemptRecord:
        attempt = next(
            (
                item
                for item in inventory.candidate_attempts
                if item.candidate_id == candidate_id
            ),
            None,
        )
        if attempt is None:
            raise ManifestIntegrityError(
                f"Persistence callback has no CandidateAttemptRecord for {candidate_id}"
            )
        return attempt

    def record_transition(self, transition: LifecycleTransition) -> None:
        with self._lock:
            target_id = self._resolved_transition_target(transition)
            payload = {
                "previous": transition.previous.value,
                "current": transition.current.value,
                "candidate_id": transition.candidate_id,
                "reason": transition.reason,
                "transition_index": transition.transition_index,
                "target_entry_point_id": target_id,
            }
            payload_sha256 = canonical_sha256(payload)
            event_id = _event_key(
                "transition", [target_id, transition.transition_index]
            )
            if self._replayed(event_id, payload_sha256):
                return
            next_inventory = self.inventory.model_copy(deep=True)
            if transition.current is LifecycleState.revalidating_candidate:
                self._record_candidate_attempt_if_missing(
                    next_inventory, transition.candidate_id
                )
            elif transition.candidate_id is not None:
                self._candidate_attempt(next_inventory, transition.candidate_id)
            next_inventory.transitions.append(
                TransitionRecord(
                    event_id=event_id,
                    payload_sha256=payload_sha256,
                    sequence=self._sequence(next_inventory),
                    target_entry_point_id=target_id,
                    index=transition.transition_index,
                    previous=transition.previous,
                    current=transition.current,
                    candidate_id=transition.candidate_id,
                    reason=transition.reason,
                )
            )
            self._commit(next_inventory)

    def _stage_attempt_record(
        self,
        next_inventory: FinalizationInventoryV1,
        event_id: str,
        payload_sha256: str,
        attempt_id: str,
        invocation: StageInvocation,
        input_record: StageInputRecord,
        input_payload: dict[str, Any],
        prompt: object,
        call: object,
        result: GeneratedStageResult,
        output: Any,
        failure: object,
        candidate: Any,
    ) -> StageAttemptRecord:
        return StageAttemptRecord(
            event_id=event_id,
            payload_sha256=payload_sha256,
            sequence=self._sequence(next_inventory),
            attempt_id=attempt_id,
            candidate_id=invocation.candidate_id,
            stage=invocation.stage,
            invocation_index=invocation.invocation_index,
            owner_retry_index=invocation.owner_retry_index,
            prompt=prompt,
            call=call,
            result=output,
            failure=failure,
            input=input_record,
            input_sha256=canonical_sha256(input_payload),
            candidate_snapshot_sha256=canonical_sha256(candidate),
            final_tree_snapshot_sha256=invocation.final_tree_digest,
            output_sha256=(
                canonical_sha256(result.artifact)
                if result.artifact is not None
                else None
            ),
            violations=_violations(result.violations),
        )

    def record_stage_result(
        self, invocation: StageInvocation, result: GeneratedStageResult
    ) -> None:
        with self._lock:
            attempt_id = (
                f"{invocation.candidate_id}:{invocation.stage.value}:"
                f"{invocation.invocation_index}"
            )
            next_inventory = self.inventory.model_copy(deep=True)
            candidate_attempt = self._candidate_attempt(
                next_inventory, invocation.candidate_id
            )
            call, failure, prompt = _stage_evidence_parts(result.evidence)
            visible_artifacts = _visible_artifact_map(invocation)
            if invocation.candidate_snapshot is None:
                raise TypeError("stage persistence requires a candidate snapshot")
            candidate = _json_value(invocation.candidate_snapshot)
            output = (
                _json_value(result.artifact) if result.artifact is not None else None
            )
            input_record = _stage_input_record(
                invocation, candidate, prompt, visible_artifacts
            )
            input_payload = input_record.model_dump(mode="json")
            payload = _stage_attempt_payload(
                attempt_id, input_payload, call, failure, output, result.violations
            )
            payload_sha256 = canonical_sha256(payload)
            event_id = _event_key("stage_attempt", attempt_id)
            if self._replayed(event_id, payload_sha256):
                return
            record = self._stage_attempt_record(
                next_inventory,
                event_id,
                payload_sha256,
                attempt_id,
                invocation,
                input_record,
                input_payload,
                prompt,
                call,
                result,
                output,
                failure,
                candidate,
            )
            next_inventory.stage_attempts.append(record)
            candidate_attempt.stage_attempt_ids.append(attempt_id)

            entry = _call_log_entry(invocation, attempt_id, result.evidence)
            _call_log_entry_for(result.evidence, entry)

            from asago_scenario_generator.pipeline.io import write_pipeline_call_log

            write_pipeline_call_log([entry], self.run_dir)

            self._commit(next_inventory)
