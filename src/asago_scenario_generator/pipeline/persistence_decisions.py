"""Terminal admission decisions and durable event hash checks."""

from __future__ import annotations


from pydantic import Field, model_validator

from asago_scenario_generator.pipeline.finalization_contracts import (
    CandidateTerminalStatus,
)
from .persistence_artifacts import (
    ArtifactReceipt,
    _admitted_canonical_evidence,
    _admitted_flag_matches,
    _admitted_gate_applicability,
    _admitted_snapshot_digests,
    _diagnostics_copy_authoritative,
    _exceptional_evidence_singleton,
    _gate_evidence_unique,
    _terminal_receipt_violation,
    _terminal_receipt_projection,
)
from .persistence_common import SHA256_PATTERN, _verify_event
from .persistence_models import (
    GateResultRecord,
    ViolationRecord,
)
from .persistence_plan import StrictModel


class AdmissionDecisionRecord(StrictModel):
    event_id: str = Field(pattern=SHA256_PATTERN)
    payload_sha256: str = Field(pattern=SHA256_PATTERN)
    sequence: int = Field(ge=0)
    candidate_id: str = Field(min_length=1)
    status: CandidateTerminalStatus
    admitted: bool
    gate_results: list[GateResultRecord]
    candidate_snapshot_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    actor_snapshot_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    narrative_snapshot_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    final_tree_snapshot_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    violations: list[ViolationRecord]
    terminal_receipts: list[ArtifactReceipt]

    @model_validator(mode="after")
    def _status_matches_admission(self) -> AdmissionDecisionRecord:
        _admitted_flag_matches(self.status, self.admitted)
        _gate_evidence_unique(self.gate_results)
        evidence_ids = [gate.gate for gate in self.gate_results]
        _exceptional_evidence_singleton(evidence_ids)
        _admitted_canonical_evidence(self.admitted, evidence_ids)
        _admitted_gate_applicability(self.admitted, self.gate_results)
        _diagnostics_copy_authoritative(self.gate_results)
        _admitted_snapshot_digests(
            self.admitted,
            (
                self.candidate_snapshot_sha256,
                self.actor_snapshot_sha256,
                self.narrative_snapshot_sha256,
                self.final_tree_snapshot_sha256,
            ),
        )
        violation = _terminal_receipt_violation(
            self.terminal_receipts, self.admitted, self.candidate_id
        )
        if violation is not None:
            raise ValueError(violation)
        return self


def _verify_candidate_attempt_hashes(items: list[object]) -> None:
    for item in items:
        payload = {
            "candidate_id": item.candidate_id,
            "target_entry_point_id": item.target_entry_point_id,
            "queue_rank": item.queue_rank,
        }
        _verify_event(item, "candidate_attempt", item.candidate_id, payload)


def _verify_transition_hashes(items: list[object]) -> None:
    for item in items:
        payload = {
            "previous": item.previous.value,
            "current": item.current.value,
            "candidate_id": item.candidate_id,
            "reason": item.reason,
            "transition_index": item.index,
            "target_entry_point_id": item.target_entry_point_id,
        }
        _verify_event(
            item,
            "transition",
            [item.target_entry_point_id, item.index],
            payload,
        )


def _verify_stage_attempt_hashes(items: list[object]) -> None:
    for item in items:
        payload = {
            "attempt_id": item.attempt_id,
            "input": item.input.model_dump(mode="json"),
            "call": item.call.model_dump(mode="json") if item.call else None,
            "failure": (item.failure.model_dump(mode="json") if item.failure else None),
            "result": item.result,
            "violations": [
                violation.model_dump(mode="json") for violation in item.violations
            ],
        }
        _verify_event(item, "stage_attempt", item.attempt_id, payload)


def _verify_repair_hashes(items: list[object]) -> None:
    for item in items:
        payload = {
            "candidate_id": item.candidate_id,
            "before_digest": item.before_digest,
            "after_digest": item.after_digest,
            "removed_ids": item.removed_ids,
            "preserved_projected_ids": item.preserved_projected_ids,
            "accepted": item.accepted,
            "detail": item.detail,
        }
        _verify_event(
            item,
            "parsimony_repair",
            [item.candidate_id, item.before_digest],
            payload,
        )


def _verify_admission_decision_hashes(items: list[object]) -> None:
    for item in items:
        snapshots = {
            "candidate_snapshot_sha256": item.candidate_snapshot_sha256,
            "actor_snapshot_sha256": item.actor_snapshot_sha256,
            "narrative_snapshot_sha256": item.narrative_snapshot_sha256,
            "final_tree_snapshot_sha256": item.final_tree_snapshot_sha256,
        }
        payload = {
            "candidate_id": item.candidate_id,
            "status": item.status.value,
            "violations": [
                violation.model_dump(mode="json") for violation in item.violations
            ],
            "gate_results": [
                gate.model_dump(mode="json") for gate in item.gate_results
            ],
            "snapshots": snapshots,
            "terminal_receipts": _terminal_receipt_projection(item.terminal_receipts),
        }
        _verify_event(item, "candidate_result", item.candidate_id, payload)
