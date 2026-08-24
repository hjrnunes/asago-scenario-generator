"""Unwired cmps.5 Phase 4 persistence contracts and manifest-v3 validation.

These contracts deliberately do not activate manifest v3 or invoke the
finalization machine from the production runner.  They are adapters for the
Phase 5 dependency-injection boundary.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
import threading
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, JsonValue, field_validator, model_validator

from asago_scenario_generator.manifest import (
    ArtifactEntry,
    ArtifactRole,
    ManifestIntegrityError,
    RunStatus,
    atomic_write_text,
    build_artifact_entry,
)
from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    InventoryCompleteness,
)
from asago_scenario_generator.pipeline.coverage_planning import (
    QualifiedCandidate,
    deserialize_qualified_candidate,
)
from asago_scenario_generator.pipeline.finalization import (
    MAX_COMPLETION_LENGTH_RETRIES,
    MAX_OWNER_RETRIES,
    CandidateTerminalResult,
    CandidateTerminalStatus,
    FinalizationPersistenceError,
    GeneratedStage,
    GeneratedStageResult,
    LifecycleState,
    LifecycleTransition,
    StageInvocation,
)
from asago_scenario_generator.pipeline.finalization_admission import (
    PostbehaviorAdmissionReport,
)
from asago_scenario_generator.pipeline.finalization_gates import (
    CONDITIONALLY_APPLICABLE_EVIDENCE_IDS,
    DIAGNOSTIC_BACKED_EVIDENCE_IDS,
    EXCEPTIONAL_ADMISSION_EVIDENCE_IDS,
    NORMAL_POSTBEHAVIOR_EVIDENCE_IDS,
    AdmissionEvidenceId,
)
from asago_scenario_generator.pipeline.generation_contracts import (
    CausalRetryControl,
    StageAttemptFailure,
    StageCallEvidence,
)
from asago_scenario_generator.pipeline.projection import canonical_json_bytes

COVERAGE_PLAN_VERSION = "2"
FINALIZATION_INVENTORY_VERSION = "1"
QUARANTINE_BUNDLE_VERSION = "1"
PLANNING_CHECKPOINT_VERSION = "1"
SHA256_PATTERN = r"^[0-9a-f]{64}$"
MAX_TARGET_CHOICES = 3


class StrictModel(BaseModel):
    """Persistence base: unknown fields are never silently accepted."""

    model_config = {"extra": "forbid", "use_enum_values": False}


class PlanningStageEventV1(StrictModel):
    # Global projection evidence and target-level budget evidence legitimately
    # have no candidate identity (and global issues have no target identity).
    entry_point_id: str
    candidate_id: str
    stage: str = Field(min_length=1)
    reason: str = Field(min_length=1)
    detail: str = ""
    payload: JsonValue | None = None


class PlanningCheckpointV1(StrictModel):
    """Immutable pre-finalization evidence needed by the completion tail."""

    schema_version: Literal["1"] = "1"
    qualification_facts_source: str | None = None
    qualification_facts_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    stage_events: list[PlanningStageEventV1]
    projection_limitation_target_ids: list[str]
    selected_candidate_ids: list[str]
    capped_count: int = Field(ge=0)
    uncovered_target_ids: list[str]
    per_pattern_counts: dict[str, int]
    primary_candidate_ids: dict[str, str]
    attempted_candidate_ids: list[str]
    selection_limitation_target_ids: list[str]
    fallback_candidate_ids: dict[str, list[str]]

    @model_validator(mode="after")
    def canonical_collections(self) -> PlanningCheckpointV1:
        if (self.qualification_facts_source is None) != (
            self.qualification_facts_sha256 is None
        ):
            raise ValueError(
                "qualification facts source and SHA-256 must be present together"
            )
        if self.qualification_facts_source is not None:
            source_sha256 = hashlib.sha256(
                self.qualification_facts_source.encode("utf-8")
            ).hexdigest()
            if source_sha256 != self.qualification_facts_sha256:
                raise ValueError("qualification facts source SHA-256 mismatch")
        ordered_lists = (
            self.projection_limitation_target_ids,
            self.uncovered_target_ids,
            self.attempted_candidate_ids,
            self.selection_limitation_target_ids,
        )
        if any(values != sorted(set(values)) for values in ordered_lists):
            raise ValueError("planning checkpoint ID lists must be sorted and unique")
        if self.selected_candidate_ids != list(
            dict.fromkeys(self.selected_candidate_ids)
        ):
            raise ValueError("selected candidate IDs must be ordered and unique")
        if any(
            ids != list(dict.fromkeys(ids))
            for ids in self.fallback_candidate_ids.values()
        ):
            raise ValueError("fallback candidate IDs must be ordered and unique")
        return self


class TargetState(str, Enum):
    selected = "selected"
    admitted = "admitted"
    exhausted = "exhausted"


class QualifiedCandidateRef(StrictModel):
    """Complete candidate-v2 materialization plus merged filter provenance."""

    candidate_id: str = Field(min_length=1)
    filter_candidate_id: str
    pattern_id: str = Field(min_length=1)
    entry_point_id: str = Field(min_length=1)
    rank: int = Field(ge=0)
    projected_candidate: dict[str, Any]
    accepted_filters: list[dict[str, Any]]
    accepted_rationale: str
    origins: list[dict[str, Any]]
    rejection_rationales: list[dict[str, Any]]
    pinned_entry_point: str
    pinned_technique_ids: list[str]
    pinned_technique_names: list[str]

    @model_validator(mode="after")
    def _identity_matches_materialization(self) -> QualifiedCandidateRef:
        raw = self.model_dump(mode="json")
        deserialized = deserialize_qualified_candidate(raw)
        expected = QualifiedCandidate(
            projected=deserialized.projected,
            accepted_filters=deserialized.accepted_filters,
            rank=deserialized.rank,
        ).to_plan_ref()
        if canonical_json_bytes(raw) != canonical_json_bytes(expected):
            raise ValueError("qualified candidate provenance mirrors are not canonical")
        return self


class CoverageTargetEntry(StrictModel):
    entry_point_id: str = Field(min_length=1)
    entry_point_name: str = Field(min_length=1)
    ordered_choices: list[QualifiedCandidateRef] = Field(max_length=MAX_TARGET_CHOICES)
    primary_candidate_id: str | None
    attempted_candidate_ids: list[str]
    admitted_candidate_id: str | None
    target_state: TargetState
    fallback_available: list[QualifiedCandidateRef] = Field(
        max_length=MAX_TARGET_CHOICES
    )
    target_id: str | None = Field(default=None, min_length=1)

    @property
    def effective_target_id(self) -> str:
        """Durable target identity, falling back for pre-field plan artifacts."""
        return self.target_id or self.entry_point_id

    @model_validator(mode="after")
    def _validate_queue(self) -> CoverageTargetEntry:
        ids = [choice.candidate_id for choice in self.ordered_choices]
        if len(ids) != len(set(ids)):
            raise ValueError("ordered choices contain duplicate candidate IDs")
        if len(self.attempted_candidate_ids) != len(set(self.attempted_candidate_ids)):
            raise ValueError("attempted_candidate_ids contains duplicates")
        if self.primary_candidate_id is not None:
            if not ids or ids[0] != self.primary_candidate_id:
                raise ValueError("primary candidate must be the first ordered choice")
        attempted = set(self.attempted_candidate_ids)
        if self.attempted_candidate_ids != ids[: len(self.attempted_candidate_ids)]:
            raise ValueError("attempted_candidate_ids must be the exact ordered prefix")
        if ids and self.primary_candidate_id is None:
            raise ValueError("nonempty ordered choices require a primary candidate")
        if not ids and self.target_state is not TargetState.exhausted:
            raise ValueError("empty target queues must already be exhausted")
        fallbacks = [choice.candidate_id for choice in self.fallback_available]
        if attempted.intersection(fallbacks):
            raise ValueError("fallback_available must exclude attempted candidates")
        expected_fallbacks = (
            []
            if self.target_state is TargetState.admitted
            else [candidate_id for candidate_id in ids if candidate_id not in attempted]
        )
        if fallbacks != expected_fallbacks:
            raise ValueError(
                "fallback_available must preserve unattempted ordered-choice order"
            )
        ordered_by_id = {choice.candidate_id: choice for choice in self.ordered_choices}
        if any(
            choice != ordered_by_id[choice.candidate_id]
            for choice in self.fallback_available
        ):
            raise ValueError(
                "fallback_available entries must exactly equal their ordered choices"
            )
        ranks = [choice.rank for choice in self.ordered_choices]
        if ranks != list(range(len(ranks))):
            raise ValueError("ordered choice queue ranks must be contiguous from zero")
        if any(
            choice.entry_point_id != self.entry_point_id
            for choice in self.ordered_choices
        ):
            raise ValueError("every ordered choice must match its coverage target")
        if self.admitted_candidate_id is not None:
            if self.admitted_candidate_id not in attempted:
                raise ValueError("admitted candidate must have been attempted")
            if self.target_state is not TargetState.admitted:
                raise ValueError("admitted candidate requires target_state=admitted")
            admitted_index = ids.index(self.admitted_candidate_id)
            if len(self.attempted_candidate_ids) != admitted_index + 1:
                raise ValueError("admitted target cannot contain later attempts")
        elif self.target_state is TargetState.admitted:
            raise ValueError("target_state=admitted requires admitted_candidate_id")
        if self.target_state is TargetState.selected:
            if self.admitted_candidate_id is not None:
                raise ValueError("selected target must be nonterminal and not admitted")
        if self.target_state is TargetState.exhausted:
            if (
                self.admitted_candidate_id is not None
                or self.attempted_candidate_ids != ids
            ):
                raise ValueError(
                    "exhausted target requires all choices attempted and none admitted"
                )
        return self


class CoveragePlanV2(StrictModel):
    schema_version: Literal["2"]
    completeness: Literal["not_applicable", "confirmed_complete"]
    evidence_refs: list[str]
    targets: list[CoverageTargetEntry]
    selection_limitation_target_ids: list[str]

    @model_validator(mode="after")
    def _unique_targets_and_candidates(self) -> CoveragePlanV2:
        target_ids = [target.effective_target_id for target in self.targets]
        if len(target_ids) != len(set(target_ids)):
            raise ValueError("coverage plan contains duplicate target IDs")
        candidates = [
            choice.candidate_id
            for target in self.targets
            for choice in target.ordered_choices
        ]
        if len(candidates) != len(set(candidates)):
            raise ValueError("candidate IDs must be unique across coverage targets")
        limitations = self.selection_limitation_target_ids
        if len(limitations) != len(set(limitations)) or not set(limitations).issubset(
            target_ids
        ):
            raise ValueError(
                "selection limitations must uniquely reference coverage targets"
            )
        if self.completeness == "confirmed_complete" and not self.evidence_refs:
            raise ValueError("confirmed completeness requires evidence references")
        if self.completeness == "not_applicable" and self.evidence_refs:
            raise ValueError("not-applicable completeness forbids evidence references")
        return self


class ViolationRecord(StrictModel):
    code: str = Field(min_length=1)
    detail: str = Field(min_length=1)
    owner: GeneratedStage | None
    retryable: bool


class PromptRecord(StrictModel):
    system_prompt: str | None
    user_prompt: str | None


class StageInputRecord(StrictModel):
    candidate: JsonValue
    candidate_id: str = Field(min_length=1)
    stage: GeneratedStage
    invocation_index: int = Field(ge=0)
    owner_retry_index: int = Field(ge=0, le=MAX_OWNER_RETRIES)
    visible_artifacts: dict[str, JsonValue]
    prompt: PromptRecord | None
    final_tree_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    retry_reason: str | None = None
    retry_control: JsonValue | None = None
    total_request_budget: int = Field(default=MAX_COMPLETION_LENGTH_RETRIES + 1, ge=1)


class LLMResultRecord(StrictModel):
    content: JsonValue
    prompt_tokens: int = Field(ge=0)
    completion_tokens: int = Field(ge=0)
    duration_ms: int = Field(ge=0)
    system_prompt: str
    user_prompt: str
    request_controls: dict[str, JsonValue] = Field(default_factory=dict)


class CallMetadataRecord(StrictModel):
    call: str
    prompt_tokens: int = Field(ge=0)
    completion_tokens: int = Field(ge=0)
    duration_ms: int = Field(ge=0)


class StageCallEvidenceRecord(StrictModel):
    call_name: str
    result: LLMResultRecord
    metadata: CallMetadataRecord
    semantic_evidence: dict[str, JsonValue] | None = None


class StageAttemptFailureRecord(StrictModel):
    call_name: str
    exception_type: str = Field(min_length=1)
    detail: str
    phase: Literal["before_invocation", "invocation", "post_response"]
    invoked: bool
    # Stable typed routing evidence: "completion_length" for length
    # exhaustion (with finish reason and usage) or the generic
    # "stage_attempt_failed" code.  Never derived from exception text.
    code: str = Field(min_length=1)
    retryable: bool = True
    semantic_evidence: dict[str, JsonValue] | None = None
    finish_reason: str | None = None
    prompt_tokens: int | None = Field(default=None, ge=0)
    completion_tokens: int | None = Field(default=None, ge=0)
    total_tokens: int | None = Field(default=None, ge=0)
    usage_details: dict[str, JsonValue] = Field(default_factory=dict)
    response_id: str | None = None
    model: str | None = None
    partial_character_count: int | None = Field(default=None, ge=0)
    partial_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    partial_preview_prefix: str | None = Field(default=None, max_length=128)
    partial_preview_suffix: str | None = Field(default=None, max_length=128)
    elapsed_ms: int | None = Field(default=None, ge=0)
    request_controls: dict[str, JsonValue] = Field(default_factory=dict)
    prompt: PromptRecord | None
    result: LLMResultRecord | None
    raw_response: JsonValue | None


class StageAttemptRecord(StrictModel):
    event_id: str = Field(pattern=SHA256_PATTERN)
    payload_sha256: str = Field(pattern=SHA256_PATTERN)
    sequence: int = Field(ge=0)
    attempt_id: str = Field(min_length=1)
    candidate_id: str = Field(min_length=1)
    stage: GeneratedStage
    invocation_index: int = Field(ge=0)
    owner_retry_index: int = Field(ge=0, le=MAX_OWNER_RETRIES)
    prompt: PromptRecord | None
    call: StageCallEvidenceRecord | None
    result: JsonValue | None
    failure: StageAttemptFailureRecord | None
    input: StageInputRecord
    input_sha256: str = Field(pattern=SHA256_PATTERN)
    candidate_snapshot_sha256: str = Field(pattern=SHA256_PATTERN)
    final_tree_snapshot_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    output_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    violations: list[ViolationRecord]

    @model_validator(mode="after")
    def _one_result_shape(self) -> StageAttemptRecord:
        if self.result is not None and self.failure is not None:
            raise ValueError("stage attempt cannot contain both result and failure")
        if self.input_sha256 != canonical_sha256(self.input):
            raise ValueError("stage input digest mismatch")
        if self.candidate_snapshot_sha256 != canonical_sha256(self.input.candidate):
            raise ValueError("candidate snapshot digest mismatch")
        if self.final_tree_snapshot_sha256 != self.input.final_tree_digest:
            raise ValueError("final-tree snapshot digest mismatch")
        expected_output = (
            canonical_sha256(self.result) if self.result is not None else None
        )
        if self.output_sha256 != expected_output:
            raise ValueError("stage output digest mismatch")
        if (
            self.input.candidate_id != self.candidate_id
            or self.input.stage is not self.stage
            or self.input.invocation_index != self.invocation_index
            or self.input.owner_retry_index != self.owner_retry_index
        ):
            raise ValueError("stage input identity/index mismatch")
        return self


class CandidateAttemptRecord(StrictModel):
    event_id: str = Field(pattern=SHA256_PATTERN)
    payload_sha256: str = Field(pattern=SHA256_PATTERN)
    sequence: int = Field(ge=0)
    attempt_id: str = Field(min_length=1)
    candidate_id: str = Field(min_length=1)
    target_entry_point_id: str = Field(min_length=1)
    queue_rank: int = Field(ge=0)
    is_primary: bool
    stage_attempt_ids: list[str]


class TransitionRecord(StrictModel):
    event_id: str = Field(pattern=SHA256_PATTERN)
    payload_sha256: str = Field(pattern=SHA256_PATTERN)
    sequence: int = Field(ge=0)
    target_entry_point_id: str = Field(min_length=1)
    index: int = Field(ge=0)
    previous: LifecycleState
    current: LifecycleState
    candidate_id: str | None
    reason: str = Field(min_length=1)


class ParsimonyRepairRecord(StrictModel):
    event_id: str = Field(pattern=SHA256_PATTERN)
    payload_sha256: str = Field(pattern=SHA256_PATTERN)
    sequence: int = Field(ge=0)
    candidate_attempt_id: str = Field(min_length=1)
    candidate_id: str = Field(min_length=1)
    target_entry_point_id: str = Field(min_length=1)
    before_digest: str = Field(pattern=SHA256_PATTERN)
    after_digest: str = Field(pattern=SHA256_PATTERN)
    removed_ids: list[str]
    preserved_projected_ids: list[str]
    accepted: bool
    detail: str


class GateResultRecord(StrictModel):
    gate: AdmissionEvidenceId
    passed: bool
    violations: list[ViolationRecord]
    diagnostics: list[ViolationRecord]
    applicable: bool

    @model_validator(mode="after")
    def _passed_matches_violations(self) -> GateResultRecord:
        if self.gate in DIAGNOSTIC_BACKED_EVIDENCE_IDS:
            if self.violations or self.passed != (not self.diagnostics):
                raise ValueError("diagnostic-backed outcome must match diagnostics")
        elif self.passed != (not self.violations):
            raise ValueError("ordinary gate outcome must match hard violations")
        return self


class ArtifactReceipt(StrictModel):
    candidate_id: str = Field(min_length=1)
    role: ArtifactRole
    path: str = Field(min_length=1)
    sha256: str = Field(pattern=SHA256_PATTERN)
    scenario_id: str | None

    @field_validator("path")
    @classmethod
    def _canonical_path(cls, value: str) -> str:
        path = PurePosixPath(value)
        if (
            not value
            or path.is_absolute()
            or path.as_posix() != value
            or ".." in path.parts
            or "." in path.parts
            or "\\" in value
        ):
            raise ValueError("artifact receipt path must be canonical and relative")
        return value

    @model_validator(mode="after")
    def _role_identity(self) -> ArtifactReceipt:
        if self.role in {ArtifactRole.SCENARIO_YAML, ArtifactRole.SCENARIO_FEATURE}:
            if not self.scenario_id:
                raise ValueError("normal scenario receipts require scenario_id")
        elif self.role is ArtifactRole.QUARANTINE_BUNDLE:
            if self.scenario_id is not None:
                raise ValueError("quarantine receipts forbid scenario_id")
        else:
            raise ValueError("unsupported finalization artifact receipt role")
        return self


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
        if self.admitted != (self.status is CandidateTerminalStatus.admitted):
            raise ValueError("admitted flag must match terminal candidate status")
        evidence_ids = [gate.gate for gate in self.gate_results]
        if len(evidence_ids) != len(set(evidence_ids)):
            raise ValueError("admission evidence IDs must be unique")
        exceptional = set(evidence_ids) & EXCEPTIONAL_ADMISSION_EVIDENCE_IDS
        if exceptional and len(evidence_ids) != 1:
            raise ValueError("exceptional admission evidence must be a singleton")
        if self.admitted and set(evidence_ids) != set(NORMAL_POSTBEHAVIOR_EVIDENCE_IDS):
            raise ValueError("admitted decision requires canonical gate evidence")
        if self.admitted and any(
            not gate.applicable
            for gate in self.gate_results
            if gate.gate not in CONDITIONALLY_APPLICABLE_EVIDENCE_IDS
        ):
            raise ValueError("intrinsic admitted evidence must be applicable")
        authoritative = [
            violation for gate in self.gate_results for violation in gate.violations
        ]
        if any(
            diagnostic not in authoritative
            for gate in self.gate_results
            if gate.gate in DIAGNOSTIC_BACKED_EVIDENCE_IDS
            for diagnostic in gate.diagnostics
        ):
            raise ValueError("category diagnostic must copy an authoritative violation")
        snapshots = (
            self.candidate_snapshot_sha256,
            self.actor_snapshot_sha256,
            self.narrative_snapshot_sha256,
            self.final_tree_snapshot_sha256,
        )
        if self.admitted and any(digest is None for digest in snapshots):
            raise ValueError("admitted decision requires all four snapshot digests")
        expected_roles = (
            {ArtifactRole.SCENARIO_YAML, ArtifactRole.SCENARIO_FEATURE}
            if self.admitted
            else {ArtifactRole.QUARANTINE_BUNDLE}
        )
        if (
            {receipt.role for receipt in self.terminal_receipts} != expected_roles
            or len(self.terminal_receipts) != len(expected_roles)
            or any(
                receipt.candidate_id != self.candidate_id
                for receipt in self.terminal_receipts
            )
        ):
            raise ValueError("terminal receipts do not match candidate terminal status")
        if (
            self.admitted
            and len({receipt.scenario_id for receipt in self.terminal_receipts}) != 1
        ):
            raise ValueError("admitted terminal receipts require one scenario_id")
        return self


class FinalizationInventoryV1(StrictModel):
    schema_version: Literal["1"]
    run_id: str = Field(min_length=1)
    coverage_plan_sha256: str = Field(pattern=SHA256_PATTERN)
    candidate_attempts: list[CandidateAttemptRecord]
    stage_attempts: list[StageAttemptRecord]
    transitions: list[TransitionRecord]
    repairs: list[ParsimonyRepairRecord]
    admission_decisions: list[AdmissionDecisionRecord]
    admitted_inventory: list[ArtifactReceipt]
    quarantine_inventory: list[ArtifactReceipt]

    @model_validator(mode="after")
    def _local_integrity(self) -> FinalizationInventoryV1:
        events = [
            *self.candidate_attempts,
            *self.stage_attempts,
            *self.transitions,
            *self.repairs,
            *self.admission_decisions,
        ]
        _check_durable_event_ids(events)
        _check_durable_event_sequences(events)
        _check_unique_attempt_and_candidate_ids(
            self.candidate_attempts, self.stage_attempts
        )
        transitions_by_target, attempts_by_target = _index_target_trace_events(
            self.transitions, self.candidate_attempts
        )
        terminal_edges = _target_trace_terminal_edges(
            transitions_by_target, attempts_by_target
        )
        _check_lifecycle_edges(self.transitions)
        _check_stage_references(self.candidate_attempts, self.stage_attempts)
        _check_repair_records(
            self.repairs, self.candidate_attempts, self.stage_attempts
        )
        _check_stage_invocation_indexes(self.stage_attempts)
        _check_generating_transition_traces(
            self.candidate_attempts,
            self.transitions,
            self.stage_attempts,
            self.repairs,
            self.admission_decisions,
            terminal_edges,
        )
        _check_terminal_decisions(
            self.candidate_attempts,
            transitions_by_target,
            self.stage_attempts,
            self.repairs,
            self.admission_decisions,
            terminal_edges,
        )
        _check_receipt_inventories(
            self.admission_decisions,
            self.admitted_inventory,
            self.quarantine_inventory,
        )
        self._verify_event_hashes()
        return self

    def _verify_event_hashes(self) -> None:
        for item in self.candidate_attempts:
            payload = {
                "candidate_id": item.candidate_id,
                "target_entry_point_id": item.target_entry_point_id,
                "queue_rank": item.queue_rank,
            }
            _verify_event(item, "candidate_attempt", item.candidate_id, payload)
        for item in self.transitions:
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
        for item in self.stage_attempts:
            payload = {
                "attempt_id": item.attempt_id,
                "input": item.input.model_dump(mode="json"),
                "call": item.call.model_dump(mode="json") if item.call else None,
                "failure": (
                    item.failure.model_dump(mode="json") if item.failure else None
                ),
                "result": item.result,
                "violations": [
                    violation.model_dump(mode="json") for violation in item.violations
                ],
            }
            _verify_event(item, "stage_attempt", item.attempt_id, payload)
        for item in self.repairs:
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
        for item in self.admission_decisions:
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
                "terminal_receipts": _terminal_receipt_projection(
                    item.terminal_receipts
                ),
            }
            _verify_event(item, "candidate_result", item.candidate_id, payload)


def _check_durable_event_ids(events: Sequence[StrictModel]) -> None:
    """Reject duplicate durable event IDs across all inventory event kinds."""
    event_ids = [item.event_id for item in events]
    if len(event_ids) != len(set(event_ids)):
        raise ValueError("duplicate durable event IDs")


def _check_durable_event_sequences(events: Sequence[StrictModel]) -> None:
    """Reject durable event sequences that are not contiguous from zero."""
    if sorted(item.sequence for item in events) != list(range(len(events))):
        raise ValueError("durable event sequences must be contiguous from zero")


def _attempt_ids(records: Sequence[StrictModel]) -> list[str]:
    """Return the attempt IDs of durable event records."""
    return [item.attempt_id for item in records]


def _candidate_ids(records: Sequence[StrictModel]) -> list[str]:
    """Return the candidate IDs of durable event records."""
    return [item.candidate_id for item in records]


def _check_unique_attempt_and_candidate_ids(
    candidate_attempts: Sequence[CandidateAttemptRecord],
    stage_attempts: Sequence[StageAttemptRecord],
) -> None:
    """Reject duplicate attempt or candidate IDs across the inventory."""
    for label, values in (
        ("candidate attempt", _attempt_ids(candidate_attempts)),
        ("stage attempt", _attempt_ids(stage_attempts)),
        ("candidate", _candidate_ids(candidate_attempts)),
    ):
        if len(values) != len(set(values)):
            raise ValueError(f"duplicate {label} IDs")


def _index_target_trace_events(
    transitions: Sequence[TransitionRecord],
    candidate_attempts: Sequence[CandidateAttemptRecord],
) -> tuple[dict[str, list[TransitionRecord]], dict[str, list[CandidateAttemptRecord]]]:
    """Index lifecycle transitions and attempts by effective target, and require
    every candidate attempt to carry a target trace."""
    transitions_by_target: dict[str, list[TransitionRecord]] = {}
    for transition in transitions:
        transitions_by_target.setdefault(transition.target_entry_point_id, []).append(
            transition
        )
    attempts_by_target: dict[str, list[CandidateAttemptRecord]] = {}
    for attempt in candidate_attempts:
        attempts_by_target.setdefault(attempt.target_entry_point_id, []).append(attempt)
    if set(attempts_by_target) - set(transitions_by_target):
        raise ValueError("each candidate attempt requires a target trace")
    return transitions_by_target, attempts_by_target


def _target_trace_terminal_edges(
    transitions_by_target: dict[str, list[TransitionRecord]],
    attempts_by_target: dict[str, list[CandidateAttemptRecord]],
) -> dict[str, TransitionRecord]:
    """Validate every target transition chain and candidate trace, returning
    the terminal transition edge keyed by admitted/rejected candidate."""
    terminal_edges: dict[str, TransitionRecord] = {}
    for target_id, target_transitions in transitions_by_target.items():
        target_transitions.sort(key=lambda item: item.sequence)
        _check_target_transition_indexes(target_transitions)
        target_attempts = sorted(
            attempts_by_target.get(target_id, []), key=lambda item: item.sequence
        )
        _check_target_candidate_trace(
            target_transitions, target_attempts, terminal_edges
        )
    return terminal_edges


def _transition_indexes_contiguous(
    target_transitions: list[TransitionRecord],
) -> bool:
    """True when per-target transition indexes are contiguous from zero."""
    return [item.index for item in target_transitions] == list(
        range(len(target_transitions))
    )


def _check_target_transition_indexes(
    target_transitions: list[TransitionRecord],
) -> None:
    """Reject non-contiguous per-target transition indexes and chains that do
    not start from pending."""
    if not _transition_indexes_contiguous(target_transitions):
        raise ValueError("transition indexes must be contiguous per target")
    if target_transitions[0].previous is not LifecycleState.pending:
        raise ValueError("first target transition must start from pending")
    for previous, current in zip(target_transitions, target_transitions[1:]):
        if previous.current is not current.previous:
            raise ValueError("transition state chain is noncontiguous per target")


@dataclass
class _CandidateTraceState:
    """Replay state for one target's candidate trace segments."""

    next_attempt: int = 0
    active_candidate: str | None = None
    seen_candidates: set[str] = field(default_factory=set)


def _check_target_candidate_trace(
    target_transitions: list[TransitionRecord],
    target_attempts: list[CandidateAttemptRecord],
    terminal_edges: dict[str, TransitionRecord],
) -> None:
    """Replay one target's revalidating/exhausted/active trace segments."""
    state = _CandidateTraceState()
    for position, transition in enumerate(target_transitions):
        if transition.current is LifecycleState.revalidating_candidate:
            _check_revalidating_segment(transition, target_attempts, state)
        elif transition.current is LifecycleState.exhausted:
            _check_exhausted_segment(
                transition, position, target_transitions, state.active_candidate
            )
        else:
            _check_active_segment(transition, state, terminal_edges)
    if state.next_attempt != len(target_attempts):
        raise ValueError(
            "each candidate attempt requires one revalidating trace segment"
        )


def _revalidating_segment_invalid(
    transition: TransitionRecord,
    state: _CandidateTraceState,
    attempt_count: int,
) -> bool:
    """True when a revalidating transition does not exactly match the next
    durable attempt."""
    return (
        state.active_candidate is not None
        or transition.candidate_id is None
        or transition.candidate_id in state.seen_candidates
        or state.next_attempt >= attempt_count
    )


def _check_revalidating_segment(
    transition: TransitionRecord,
    target_attempts: list[CandidateAttemptRecord],
    state: _CandidateTraceState,
) -> None:
    """Validate and advance a revalidating-candidate trace segment."""
    if _revalidating_segment_invalid(transition, state, len(target_attempts)):
        raise ValueError("invalid or duplicate candidate trace segment")
    attempt = target_attempts[state.next_attempt]
    if (
        transition.candidate_id != attempt.candidate_id
        or attempt.sequence >= transition.sequence
    ):
        raise ValueError("candidate trace does not match next durable attempt")
    state.active_candidate = transition.candidate_id
    state.seen_candidates.add(state.active_candidate)
    state.next_attempt += 1


def _check_exhausted_segment(
    transition: TransitionRecord,
    position: int,
    target_transitions: list[TransitionRecord],
    active_candidate: str | None,
) -> None:
    """Reject exhaustive transitions that are not the final candidate-free edge."""
    if (
        transition.candidate_id is not None
        or position != len(target_transitions) - 1
        or active_candidate is not None
    ):
        raise ValueError("target exhaustion must be candidate-free and final")


def _check_active_segment(
    transition: TransitionRecord,
    state: _CandidateTraceState,
    terminal_edges: dict[str, TransitionRecord],
) -> None:
    """Validate active-trace continuity and record admitted/rejected terminals."""
    if (
        state.active_candidate is None
        or transition.candidate_id != state.active_candidate
    ):
        raise ValueError("lifecycle candidate changed inside an active trace")
    if transition.current in {
        LifecycleState.admitted,
        LifecycleState.rejected,
    }:
        terminal_edges[state.active_candidate] = transition
        state.active_candidate = None


def _legal_lifecycle_edges() -> set[tuple[LifecycleState, LifecycleState]]:
    """Return every legal lifecycle edge pair for durable transitions."""
    generating_state = _generating_state_by_stage()
    active = {
        LifecycleState.generating_actor,
        LifecycleState.generating_narrative,
        LifecycleState.generating_tree,
        LifecycleState.finalizing_prebehavior,
        LifecycleState.generating_behavior,
        LifecycleState.admitting,
    }
    legal_edges = {
        (LifecycleState.pending, LifecycleState.revalidating_candidate),
        (LifecycleState.pending, LifecycleState.exhausted),
        (LifecycleState.rejected, LifecycleState.revalidating_candidate),
        (LifecycleState.rejected, LifecycleState.exhausted),
        (LifecycleState.revalidating_candidate, LifecycleState.generating_actor),
        (LifecycleState.revalidating_candidate, LifecycleState.rejected),
        (LifecycleState.generating_actor, LifecycleState.generating_narrative),
        (LifecycleState.generating_narrative, LifecycleState.generating_tree),
        (LifecycleState.generating_tree, LifecycleState.finalizing_prebehavior),
        (LifecycleState.finalizing_prebehavior, LifecycleState.generating_behavior),
        (LifecycleState.generating_behavior, LifecycleState.admitting),
        (LifecycleState.admitting, LifecycleState.admitted),
        (LifecycleState.admitting, LifecycleState.rejected),
    }
    legal_edges.update(
        (source, destination)
        for source in active
        for destination in generating_state.values()
    )
    legal_edges.update((source, LifecycleState.rejected) for source in active)
    return legal_edges


def _generating_state_by_stage() -> dict[GeneratedStage, LifecycleState]:
    """Map each generated stage to its durable generating lifecycle state."""
    return {
        GeneratedStage.actor: LifecycleState.generating_actor,
        GeneratedStage.narrative: LifecycleState.generating_narrative,
        GeneratedStage.tree: LifecycleState.generating_tree,
        GeneratedStage.behavior: LifecycleState.generating_behavior,
    }


def _check_lifecycle_edges(transitions: Sequence[TransitionRecord]) -> None:
    """Reject durable transitions whose edge is not in the legal edge set."""
    legal_edges = _legal_lifecycle_edges()
    for transition in sorted(transitions, key=lambda item: item.sequence):
        if (transition.previous, transition.current) not in legal_edges:
            raise ValueError(
                f"illegal lifecycle edge {transition.previous.value}->{transition.current.value}"
            )


def _stage_reference_invalid(
    stage: StageAttemptRecord | None,
    attempt: CandidateAttemptRecord,
) -> bool:
    """True when a referenced stage attempt is missing or owned by another
    candidate."""
    return stage is None or stage.candidate_id != attempt.candidate_id


def _stage_attempts_by_id(
    stage_attempts: Sequence[StageAttemptRecord],
) -> dict[str, StageAttemptRecord]:
    """Index stage attempts by durable attempt ID."""
    return {item.attempt_id: item for item in stage_attempts}


def _attempts_by_id(
    candidate_attempts: Sequence[CandidateAttemptRecord],
) -> dict[str, CandidateAttemptRecord]:
    """Index candidate attempts by durable attempt ID."""
    return {item.attempt_id: item for item in candidate_attempts}


def _check_stage_references(
    candidate_attempts: Sequence[CandidateAttemptRecord],
    stage_attempts: Sequence[StageAttemptRecord],
) -> None:
    """Require candidate stage references to match stage attempts exactly."""
    stage_by_id = _stage_attempts_by_id(stage_attempts)
    referenced_stage_ids: set[str] = set()
    for attempt in candidate_attempts:
        for stage_id in attempt.stage_attempt_ids:
            if _stage_reference_invalid(stage_by_id.get(stage_id), attempt):
                raise ValueError(
                    "candidate attempt references an invalid stage attempt"
                )
            referenced_stage_ids.add(stage_id)
    if referenced_stage_ids != set(stage_by_id):
        raise ValueError("stage attempts and candidate references must match exactly")


def _repair_mismatches_attempt(
    repair: ParsimonyRepairRecord,
    attempt: CandidateAttemptRecord | None,
) -> bool:
    """True when a repair record does not match its candidate attempt."""
    return (
        attempt is None
        or repair.candidate_id != attempt.candidate_id
        or repair.target_entry_point_id != attempt.target_entry_point_id
    )


def _subsequent_behavior_inputs(
    stage_attempts: Sequence[StageAttemptRecord],
    repair: ParsimonyRepairRecord,
) -> list[str]:
    """Return behavior final-tree inputs recorded after the repair."""
    return [
        item.final_tree_snapshot_sha256
        for item in stage_attempts
        if item.candidate_id == repair.candidate_id
        and item.stage is GeneratedStage.behavior
        and item.sequence > repair.sequence
    ]


def _check_repair_records(
    repairs: Sequence[ParsimonyRepairRecord],
    candidate_attempts: Sequence[CandidateAttemptRecord],
    stage_attempts: Sequence[StageAttemptRecord],
) -> None:
    """Require every repair record to match its candidate attempt and bind
    behavior final-tree input."""
    attempts_by_id = _attempts_by_id(candidate_attempts)
    for repair in repairs:
        attempt = attempts_by_id.get(repair.candidate_attempt_id)
        if _repair_mismatches_attempt(repair, attempt):
            raise ValueError("repair record does not match its candidate attempt")
        subsequent_behavior_inputs = _subsequent_behavior_inputs(stage_attempts, repair)
        if (
            subsequent_behavior_inputs
            and repair.after_digest not in subsequent_behavior_inputs
        ):
            raise ValueError("repair output is not bound to behavior final-tree input")


def _stage_invocation_indexes_contiguous(
    records: list[StageAttemptRecord],
) -> bool:
    """True when per-candidate-stage invocation indexes are contiguous."""
    return [item.invocation_index for item in records] == list(range(len(records)))


def _stage_retry_indexes_not_monotonic(records: list[StageAttemptRecord]) -> bool:
    """True when owner retry indexes decrease between adjacent records."""
    return any(
        right.owner_retry_index < left.owner_retry_index
        for left, right in zip(records, records[1:])
    )


def _check_stage_invocation_indexes(
    stage_attempts: Sequence[StageAttemptRecord],
) -> None:
    """Require contiguous per-candidate-stage invocation indexes and monotonic
    owner retry indexes."""
    by_candidate_stage: dict[tuple[str, GeneratedStage], list[StageAttemptRecord]] = {}
    for item in stage_attempts:
        by_candidate_stage.setdefault((item.candidate_id, item.stage), []).append(item)
    for records in by_candidate_stage.values():
        records.sort(key=lambda item: item.invocation_index)
        if not _stage_invocation_indexes_contiguous(records):
            raise ValueError("stage invocation indexes must be contiguous")
        if _stage_retry_indexes_not_monotonic(records):
            raise ValueError("stage owner retry indexes must be monotonic")


def _generating_transitions_for(
    attempt: CandidateAttemptRecord,
    transitions: Sequence[TransitionRecord],
    generating_states: set[LifecycleState],
) -> list[TransitionRecord]:
    """Return the candidate's generating transitions in durable order."""
    return sorted(
        (
            item
            for item in transitions
            if item.candidate_id == attempt.candidate_id
            and item.current in generating_states
        ),
        key=lambda item: item.sequence,
    )


def _stage_attempts_for(
    attempt: CandidateAttemptRecord,
    stage_attempts: Sequence[StageAttemptRecord],
) -> list[StageAttemptRecord]:
    """Return the candidate's stage attempts in durable order."""
    return sorted(
        (item for item in stage_attempts if item.candidate_id == attempt.candidate_id),
        key=lambda item: item.sequence,
    )


def _generating_transition_count_mismatch(
    generating_transitions: list[TransitionRecord],
    ordered_stage_attempts: list[StageAttemptRecord],
) -> bool:
    """True when generating transitions do not map 1:1 (or 1:1 plus one
    unmatched terminal generation edge) to stage attempts."""
    return len(generating_transitions) not in {
        len(ordered_stage_attempts),
        len(ordered_stage_attempts) + 1,
    }


def _decision_for_candidate(
    admission_decisions: Sequence[AdmissionDecisionRecord],
    candidate_id: str,
) -> AdmissionDecisionRecord | None:
    """Return the terminal admission decision for a candidate, if any."""
    return next(
        (item for item in admission_decisions if item.candidate_id == candidate_id),
        None,
    )


def _later_candidate_events(
    attempt: CandidateAttemptRecord,
    unmatched: TransitionRecord,
    transitions: Sequence[TransitionRecord],
    stage_attempts: Sequence[StageAttemptRecord],
    repairs: Sequence[ParsimonyRepairRecord],
    admission_decisions: Sequence[AdmissionDecisionRecord],
) -> list[Any]:
    """Return every durable candidate event recorded after the unmatched
    generating transition."""
    return [
        item
        for item in [
            *transitions,
            *stage_attempts,
            *repairs,
            *admission_decisions,
        ]
        if item.candidate_id == attempt.candidate_id
        and item.sequence > unmatched.sequence
    ]


def _unknown_terminal_adjacency(
    terminal: TransitionRecord | None,
    decision: AdmissionDecisionRecord | None,
    ordered_later: list[Any],
) -> bool:
    """True when the terminal edge and decision are exactly the next two
    events after the unmatched generating transition."""
    return (
        terminal is not None
        and decision is not None
        and ordered_later == [terminal, decision]
    )


def _unknown_terminal_edge_order(
    terminal: TransitionRecord,
    decision: AdmissionDecisionRecord,
    unmatched: TransitionRecord,
) -> bool:
    """True when terminal and decision follow the unmatched edge in exact
    adjacent sequence order."""
    return (
        terminal.previous is unmatched.current
        and terminal.sequence == unmatched.sequence + 1
        and decision.sequence == terminal.sequence + 1
    )


def _unknown_outcome_decision(decision: AdmissionDecisionRecord) -> bool:
    """True when the decision is a bare generation/finalization failure."""
    return (
        decision.status is CandidateTerminalStatus.generation_or_finalization_failed
        and not decision.admitted
        and not decision.gate_results
    )


def _single_unknown_invocation_violation(
    decision: AdmissionDecisionRecord,
) -> bool:
    """True when the decision carries exactly the unknown-invocation-outcome
    violation."""
    return (
        len(decision.violations) == 1
        and decision.violations[0].code == "unknown_invocation_outcome"
        and decision.violations[0].owner is None
        and not decision.violations[0].retryable
    )


def _single_quarantine_bundle_receipt(
    decision: AdmissionDecisionRecord,
) -> bool:
    """True when the decision carries exactly one quarantine-bundle receipt."""
    return (
        len(decision.terminal_receipts) == 1
        and decision.terminal_receipts[0].role is ArtifactRole.QUARANTINE_BUNDLE
    )


def _no_later_stage_or_repair_events(
    attempt: CandidateAttemptRecord,
    unmatched: TransitionRecord,
    stage_attempts: Sequence[StageAttemptRecord],
    repairs: Sequence[ParsimonyRepairRecord],
) -> bool:
    """True when no stage attempt or repair follows the unmatched edge."""
    return not any(
        item.sequence > unmatched.sequence
        for item in [*stage_attempts, *repairs]
        if item.candidate_id == attempt.candidate_id
    )


def _unknown_terminal_trace_matches(
    terminal: TransitionRecord | None,
    decision: AdmissionDecisionRecord | None,
    ordered_later: list[Any],
    unmatched: TransitionRecord,
) -> bool:
    """True when adjacency and edge ordering of the unknown terminal match."""
    return _unknown_terminal_adjacency(
        terminal, decision, ordered_later
    ) and _unknown_terminal_edge_order(terminal, decision, unmatched)


def _unknown_terminal_decision_matches(
    decision: AdmissionDecisionRecord,
    attempt: CandidateAttemptRecord,
    unmatched: TransitionRecord,
    stage_attempts: Sequence[StageAttemptRecord],
    repairs: Sequence[ParsimonyRepairRecord],
) -> bool:
    """True when the terminal decision is exactly the unknown-outcome
    quarantine terminalization."""
    return (
        _unknown_outcome_decision(decision)
        and _single_unknown_invocation_violation(decision)
        and _single_quarantine_bundle_receipt(decision)
        and _no_later_stage_or_repair_events(
            attempt, unmatched, stage_attempts, repairs
        )
    )


def _is_exact_unknown_terminal(
    attempt: CandidateAttemptRecord,
    unmatched: TransitionRecord,
    later_candidate_events: Sequence[Any],
    admission_decisions: Sequence[AdmissionDecisionRecord],
    terminal_edges: dict[str, TransitionRecord],
    stage_attempts: Sequence[StageAttemptRecord],
    repairs: Sequence[ParsimonyRepairRecord],
) -> bool:
    """True when an unmatched generating transition is followed by exactly
    the unknown-outcome terminalization sequence."""
    decision = _decision_for_candidate(admission_decisions, attempt.candidate_id)
    terminal = terminal_edges.get(attempt.candidate_id)
    ordered_later = sorted(later_candidate_events, key=lambda item: item.sequence)
    return _unknown_terminal_trace_matches(
        terminal, decision, ordered_later, unmatched
    ) and _unknown_terminal_decision_matches(
        decision, attempt, unmatched, stage_attempts, repairs
    )


def _check_unmatched_generating_transition(
    attempt: CandidateAttemptRecord,
    unmatched: TransitionRecord,
    candidate_attempts: Sequence[CandidateAttemptRecord],
    transitions: Sequence[TransitionRecord],
    stage_attempts: Sequence[StageAttemptRecord],
    repairs: Sequence[ParsimonyRepairRecord],
    admission_decisions: Sequence[AdmissionDecisionRecord],
    terminal_edges: dict[str, TransitionRecord],
) -> None:
    """Reject later candidate events after an unmatched generating transition
    unless they are exactly the unknown-outcome terminalization."""
    later_candidate_events = _later_candidate_events(
        attempt,
        unmatched,
        transitions,
        stage_attempts,
        repairs,
        admission_decisions,
    )
    if later_candidate_events and not _is_exact_unknown_terminal(
        attempt,
        unmatched,
        later_candidate_events,
        admission_decisions,
        terminal_edges,
        stage_attempts,
        repairs,
    ):
        raise ValueError(
            "unmatched generating transition permits only exact "
            "unknown-outcome terminalization"
        )


def _generating_stage_pairing_mismatch(
    transition: TransitionRecord,
    stage: StageAttemptRecord,
    generating_state: dict[GeneratedStage, LifecycleState],
) -> bool:
    """True when a generating transition does not pair with its stage
    attempt."""
    return (
        transition.current is not generating_state[stage.stage]
        or transition.candidate_id != stage.candidate_id
        or transition.sequence >= stage.sequence
    )


def _check_generating_stage_pairing(
    generating_transitions: list[TransitionRecord],
    ordered_stage_attempts: list[StageAttemptRecord],
    generating_state: dict[GeneratedStage, LifecycleState],
) -> None:
    """Require each generating transition to pair with its stage attempt."""
    for transition, stage in zip(generating_transitions, ordered_stage_attempts):
        if _generating_stage_pairing_mismatch(transition, stage, generating_state):
            raise ValueError("generating transition/stage attempt trace mismatch")


def _check_generating_transition_traces(
    candidate_attempts: Sequence[CandidateAttemptRecord],
    transitions: Sequence[TransitionRecord],
    stage_attempts: Sequence[StageAttemptRecord],
    repairs: Sequence[ParsimonyRepairRecord],
    admission_decisions: Sequence[AdmissionDecisionRecord],
    terminal_edges: dict[str, TransitionRecord],
) -> None:
    """Require generating transitions to correspond 1:1 to stage attempts per
    candidate."""
    generating_state = _generating_state_by_stage()
    generating_states = set(generating_state.values())
    for attempt in candidate_attempts:
        generating_transitions = _generating_transitions_for(
            attempt, transitions, generating_states
        )
        ordered_stage_attempts = _stage_attempts_for(attempt, stage_attempts)
        if _generating_transition_count_mismatch(
            generating_transitions, ordered_stage_attempts
        ):
            raise ValueError(
                "generating transitions must correspond 1:1 to stage attempts"
            )
        if len(generating_transitions) == len(ordered_stage_attempts) + 1:
            _check_unmatched_generating_transition(
                attempt,
                generating_transitions[-1],
                candidate_attempts,
                transitions,
                stage_attempts,
                repairs,
                admission_decisions,
                terminal_edges,
            )
        _check_generating_stage_pairing(
            generating_transitions, ordered_stage_attempts, generating_state
        )


def _candidate_stages_for(
    candidate_id: str,
    stage_attempts: Sequence[StageAttemptRecord],
) -> list[StageAttemptRecord]:
    """Return the candidate's stage attempts."""
    return [item for item in stage_attempts if item.candidate_id == candidate_id]


def _check_stage_evidence_precedes_terminal(
    candidate_stages: list[StageAttemptRecord],
    terminal_edge: TransitionRecord,
) -> None:
    """Require stage evidence to precede the candidate terminal edge."""
    if any(item.sequence >= terminal_edge.sequence for item in candidate_stages):
        raise ValueError("stage evidence must precede candidate terminal edge")


def _check_terminal_precedes_decision(
    terminal_edge: TransitionRecord,
    decision: AdmissionDecisionRecord,
) -> None:
    """Require the candidate terminal edge to precede its decision."""
    if terminal_edge.sequence >= decision.sequence:
        raise ValueError("candidate terminal edge must precede its decision")


def _next_target_transition_after(
    decision: AdmissionDecisionRecord,
    terminal_edge: TransitionRecord,
    transitions_by_target: dict[str, list[TransitionRecord]],
    candidate_attempts: Sequence[CandidateAttemptRecord],
) -> TransitionRecord | None:
    """Return the next target transition after the candidate terminal edge."""
    target_entry_point_id = next(
        attempt.target_entry_point_id
        for attempt in candidate_attempts
        if attempt.candidate_id == decision.candidate_id
    )
    return next(
        (
            item
            for item in transitions_by_target[target_entry_point_id]
            if item.sequence > terminal_edge.sequence
        ),
        None,
    )


def _check_decision_precedes_next_target_transition(
    next_target_transition: TransitionRecord | None,
    decision: AdmissionDecisionRecord,
) -> None:
    """Require the candidate decision to precede the next target transition."""
    if (
        next_target_transition is not None
        and decision.sequence >= next_target_transition.sequence
    ):
        raise ValueError("candidate decision must precede the next target transition")


def _check_postbehavior_admission_edge(
    terminal_edge: TransitionRecord,
    decision: AdmissionDecisionRecord,
) -> None:
    """Require admitted/gated decisions to terminate from admitting."""
    if (decision.admitted or decision.gate_results) and (
        terminal_edge.previous is not LifecycleState.admitting
    ):
        raise ValueError("postbehavior admission requires admitting terminal edge")


def _check_admitting_edge_requires_gate_evidence(
    terminal_edge: TransitionRecord,
    decision: AdmissionDecisionRecord,
) -> None:
    """Require typed admission gate evidence on admitting terminal edges."""
    if terminal_edge.previous is LifecycleState.admitting and not decision.gate_results:
        raise ValueError(
            "admitting terminal edge requires typed admission gate evidence"
        )


def _check_gate_violations_match_terminal(
    decision: AdmissionDecisionRecord,
) -> None:
    """Require admission gate violations to match terminal violations."""
    flattened_gate_violations = [
        violation for gate in decision.gate_results for violation in gate.violations
    ]
    if decision.gate_results and (flattened_gate_violations != decision.violations):
        raise ValueError("admission gate violations must match terminal violations")


def _admitted_missing_passing_gate_evidence(
    decision: AdmissionDecisionRecord,
) -> bool:
    """True when an admitted decision lacks nonempty passing gate evidence."""
    return decision.admitted and (
        not decision.gate_results
        or any(not gate.passed for gate in decision.gate_results)
        or decision.violations
    )


def _check_admitted_requires_passing_gates(
    decision: AdmissionDecisionRecord,
) -> None:
    """Require admitted decisions to carry nonempty passing gate evidence."""
    if _admitted_missing_passing_gate_evidence(decision):
        raise ValueError("admitted decision requires nonempty passing gate evidence")


def _causal_artifacts_for_decision(
    decision: AdmissionDecisionRecord,
    candidate_stages: list[StageAttemptRecord],
    candidate_attempts: Sequence[CandidateAttemptRecord],
    repairs: Sequence[ParsimonyRepairRecord],
) -> dict[GeneratedStage, JsonValue]:
    """Reduce the candidate's durable stage evidence to one artifact
    frontier."""
    return _causal_stage_artifacts(
        candidate_stages,
        candidate_attempt_id=next(
            item.attempt_id
            for item in candidate_attempts
            if item.candidate_id == decision.candidate_id
        ),
        repairs=[
            item for item in repairs if item.candidate_id == decision.candidate_id
        ],
    )


def _expected_admission_snapshots(
    causal: dict[GeneratedStage, JsonValue],
    candidate_stages: list[StageAttemptRecord],
) -> tuple[str | None, str | None, str | None, str | None]:
    """Return the snapshot digests required by the durable stage evidence."""
    return (
        candidate_stages[-1].candidate_snapshot_sha256 if candidate_stages else None,
        canonical_sha256(causal[GeneratedStage.actor])
        if GeneratedStage.actor in causal
        else None,
        canonical_sha256(causal[GeneratedStage.narrative])
        if GeneratedStage.narrative in causal
        else None,
        canonical_sha256(causal[GeneratedStage.tree])
        if GeneratedStage.behavior in causal
        else None,
    )


def _check_admission_snapshot_digests(
    decision: AdmissionDecisionRecord,
    candidate_stages: list[StageAttemptRecord],
    candidate_attempts: Sequence[CandidateAttemptRecord],
    repairs: Sequence[ParsimonyRepairRecord],
) -> None:
    """Require admitted decision snapshot digests to match stage evidence."""
    candidate_stages.sort(key=lambda item: item.sequence)
    causal = _causal_artifacts_for_decision(
        decision, candidate_stages, candidate_attempts, repairs
    )
    actual_snapshots = (
        decision.candidate_snapshot_sha256,
        decision.actor_snapshot_sha256,
        decision.narrative_snapshot_sha256,
        decision.final_tree_snapshot_sha256,
    )
    if actual_snapshots != _expected_admission_snapshots(causal, candidate_stages):
        raise ValueError("admission snapshot digests do not match stage evidence")


def _check_admission_decision(
    decision: AdmissionDecisionRecord,
    terminal_edges: dict[str, TransitionRecord],
    transitions_by_target: dict[str, list[TransitionRecord]],
    candidate_attempts: Sequence[CandidateAttemptRecord],
    stage_attempts: Sequence[StageAttemptRecord],
    repairs: Sequence[ParsimonyRepairRecord],
) -> None:
    """Require one terminal admission decision to match its candidate
    trace, gate evidence, and snapshot digests."""
    expected = LifecycleState.admitted if decision.admitted else LifecycleState.rejected
    terminal_edge = terminal_edges.get(decision.candidate_id)
    if terminal_edge is None or terminal_edge.current is not expected:
        raise ValueError(
            "admission decision requires matching admitting terminal transition"
        )
    candidate_stages = _candidate_stages_for(decision.candidate_id, stage_attempts)
    _check_stage_evidence_precedes_terminal(candidate_stages, terminal_edge)
    _check_terminal_precedes_decision(terminal_edge, decision)
    _check_decision_precedes_next_target_transition(
        _next_target_transition_after(
            decision, terminal_edge, transitions_by_target, candidate_attempts
        ),
        decision,
    )
    _check_postbehavior_admission_edge(terminal_edge, decision)
    _check_admitting_edge_requires_gate_evidence(terminal_edge, decision)
    _check_gate_violations_match_terminal(decision)
    _check_admitted_requires_passing_gates(decision)
    if decision.admitted:
        _check_admission_snapshot_digests(
            decision, candidate_stages, candidate_attempts, repairs
        )


def _check_terminal_decisions(
    candidate_attempts: Sequence[CandidateAttemptRecord],
    transitions_by_target: dict[str, list[TransitionRecord]],
    stage_attempts: Sequence[StageAttemptRecord],
    repairs: Sequence[ParsimonyRepairRecord],
    admission_decisions: Sequence[AdmissionDecisionRecord],
    terminal_edges: dict[str, TransitionRecord],
) -> None:
    """Reconcile terminal admission decisions against terminal trace edges."""
    decisions = [item.candidate_id for item in admission_decisions]
    if len(decisions) != len(set(decisions)):
        raise ValueError("duplicate terminal admission decisions")
    if set(terminal_edges) != set(decisions):
        raise ValueError("terminal edges and admission decisions must match exactly")
    for decision in admission_decisions:
        _check_admission_decision(
            decision,
            terminal_edges,
            transitions_by_target,
            candidate_attempts,
            stage_attempts,
            repairs,
        )


def _receipt_keys(receipts: Sequence[ArtifactReceipt]) -> list[bytes]:
    """Return canonical JSON keys for receipts."""
    return [canonical_json_bytes(item) for item in receipts]


def _decision_receipt_keys(
    admission_decisions: Sequence[AdmissionDecisionRecord],
) -> list[bytes]:
    """Return canonical JSON keys for every decision terminal receipt."""
    return [
        canonical_json_bytes(receipt)
        for decision in admission_decisions
        for receipt in decision.terminal_receipts
    ]


def _receipt_inventories_mismatched(
    decision_receipt_keys: list[bytes],
    inventory_receipt_keys: list[bytes],
) -> bool:
    """True when terminal decision receipts and finalization inventories do
    not match exactly."""
    return (
        len(decision_receipt_keys) != len(set(decision_receipt_keys))
        or len(inventory_receipt_keys) != len(set(inventory_receipt_keys))
        or set(decision_receipt_keys) != set(inventory_receipt_keys)
    )


def _check_receipt_inventories(
    admission_decisions: Sequence[AdmissionDecisionRecord],
    admitted_inventory: Sequence[ArtifactReceipt],
    quarantine_inventory: Sequence[ArtifactReceipt],
) -> None:
    """Require terminal decision receipts and finalization inventories to
    match exactly."""
    inventory_receipts = [
        *admitted_inventory,
        *quarantine_inventory,
    ]
    if _receipt_inventories_mismatched(
        _decision_receipt_keys(admission_decisions),
        _receipt_keys(inventory_receipts),
    ):
        raise ValueError(
            "terminal decision receipts and finalization inventories must match exactly"
        )


def _causal_stage_artifacts(
    records: list[StageAttemptRecord],
    *,
    candidate_attempt_id: str,
    durable_candidate: JsonValue | None = None,
    repairs: Sequence[ParsimonyRepairRecord] = (),
) -> dict[GeneratedStage, JsonValue]:
    """Reduce stage evidence to one causally contiguous artifact frontier."""
    frontier: dict[GeneratedStage, JsonValue] = {}
    order = tuple(GeneratedStage)
    for record in sorted(records, key=lambda item: item.sequence):
        if (
            durable_candidate is not None
            and record.input.candidate != durable_candidate
        ):
            raise ValueError("stage candidate snapshot differs from durable plan")
        for invalidated in order[order.index(record.stage) :]:
            frontier.pop(invalidated, None)
        visible = dict(record.input.visible_artifacts)
        if record.stage is GeneratedStage.behavior:
            visible_tree = visible.get(GeneratedStage.tree.value)
            if (
                visible_tree is None
                or record.final_tree_snapshot_sha256 != canonical_sha256(visible_tree)
            ):
                raise ValueError(
                    "behavior evidence is not bound to its final-tree input"
                )
            generated_tree = frontier.get(GeneratedStage.tree)
            if generated_tree is None:
                raise ValueError("behavior evidence has no causal generated tree")
            before_digest = canonical_sha256(generated_tree)
            after_digest = canonical_sha256(visible_tree)
            if before_digest != after_digest and not any(
                repair.accepted
                and repair.candidate_attempt_id == candidate_attempt_id
                and repair.sequence < record.sequence
                and repair.before_digest == before_digest
                and repair.after_digest == after_digest
                for repair in repairs
            ):
                raise ValueError(
                    "behavior tree is neither generated nor linked by accepted repair"
                )
            frontier[GeneratedStage.tree] = visible_tree
        expected_visible = {
            stage.value: artifact for stage, artifact in frontier.items()
        }
        if visible != expected_visible:
            raise ValueError("stage evidence is not one contiguous causal frontier")
        if (
            record.result is not None
            and not record.violations
            and record.call is not None
        ):
            frontier[record.stage] = record.result
    return frontier


class PersistenceJournalV1(StrictModel):
    """Recoverable two-document state update; never part of a final manifest."""

    schema_version: Literal["1"]
    coverage_plan: CoveragePlanV2
    finalization_inventory: FinalizationInventoryV1
    quarantine_bundle: QuarantineBundleV1 | None = None
    admitted_publication: AdmittedArtifactPublication | None = None

    @model_validator(mode="after")
    def _hash_link(self) -> PersistenceJournalV1:
        expected = hashlib.sha256(canonical_json_bytes(self.coverage_plan)).hexdigest()
        if self.finalization_inventory.coverage_plan_sha256 != expected:
            raise ValueError(
                "journal inventory does not reference journal coverage plan"
            )
        events = [
            *self.finalization_inventory.candidate_attempts,
            *self.finalization_inventory.stage_attempts,
            *self.finalization_inventory.transitions,
            *self.finalization_inventory.repairs,
            *self.finalization_inventory.admission_decisions,
        ]
        latest = max(events, key=lambda item: item.sequence, default=None)
        terminal = latest if isinstance(latest, AdmissionDecisionRecord) else None
        if terminal is None:
            if (
                self.admitted_publication is not None
                or self.quarantine_bundle is not None
            ):
                raise ValueError(
                    "journal terminal evidence requires the latest terminal decision"
                )
            return self
        if terminal.admitted:
            if self.admitted_publication is None or self.quarantine_bundle is not None:
                raise ValueError(
                    "admitted journal decision requires exactly one publication"
                )
            if terminal.terminal_receipts != _publication_receipts(
                self.admitted_publication
            ):
                raise ValueError(
                    "journal publication does not match terminal decision receipts"
                )
        else:
            if self.quarantine_bundle is None or self.admitted_publication is not None:
                raise ValueError(
                    "non-admitted journal decision requires exactly one quarantine bundle"
                )
            attempt = next(
                (
                    item
                    for item in self.finalization_inventory.candidate_attempts
                    if item.candidate_id == terminal.candidate_id
                ),
                None,
            )
            bundle = self.quarantine_bundle
            if (
                attempt is None
                or bundle.run_id != self.finalization_inventory.run_id
                or bundle.attempt_id != attempt.attempt_id
                or bundle.candidate_id != terminal.candidate_id
                or bundle.target_entry_point_id != attempt.target_entry_point_id
                or bundle.violations != terminal.violations
                or terminal.terminal_receipts != [_quarantine_receipt(bundle)]
            ):
                raise ValueError(
                    "journal quarantine bundle does not match terminal decision"
                )
        return self


class QuarantineBundleV1(StrictModel):
    """Forensic generated layers; deliberately not a ScenarioEnvelope."""

    schema_version: Literal["1"]
    run_id: str = Field(min_length=1)
    attempt_id: str = Field(min_length=1)
    candidate_id: str = Field(min_length=1)
    target_entry_point_id: str = Field(min_length=1)
    actor: JsonValue | None
    narrative: JsonValue | None
    tree: JsonValue | None
    behavior: JsonValue | None
    artifact_sha256: dict[GeneratedStage, str]
    violations: list[ViolationRecord] = Field(min_length=1)

    @field_validator("attempt_id")
    @classmethod
    def _safe_attempt_id(cls, value: str) -> str:
        if (
            not value
            or any(char in value for char in ("/", "\\"))
            or value in {".", ".."}
        ):
            raise ValueError("attempt_id must be a safe filename component")
        return value

    @field_validator("artifact_sha256")
    @classmethod
    def _valid_digests(
        cls, value: dict[GeneratedStage, str]
    ) -> dict[GeneratedStage, str]:
        for digest in value.values():
            if len(digest) != 64 or any(
                char not in "0123456789abcdef" for char in digest
            ):
                raise ValueError("quarantine artifact digest must be canonical SHA-256")
        return value

    @model_validator(mode="after")
    def _digests_match_artifacts(self) -> QuarantineBundleV1:
        for stage in GeneratedStage:
            artifact = getattr(self, stage.value)
            digest = self.artifact_sha256.get(stage)
            if (artifact is None) != (digest is None):
                raise ValueError(
                    "each serialized quarantine artifact requires one digest"
                )
            if artifact is not None and digest != canonical_sha256(artifact):
                raise ValueError(f"quarantine {stage.value} digest mismatch")
        return self


class AdmittedArtifactPublication(StrictModel):
    """Exact admitted file bytes carried through the recovery journal."""

    candidate_id: str = Field(min_length=1)
    scenario_id: str = Field(min_length=1)
    yaml_text: str
    feature_text: str

    @field_validator("scenario_id")
    @classmethod
    def _safe_scenario_id(cls, value: str) -> str:
        if value in {".", ".."} or any(char in value for char in ("/", "\\")):
            raise ValueError("scenario_id must be a safe filename component")
        return value

    @model_validator(mode="after")
    def _serialized_identity(self) -> AdmittedArtifactPublication:
        try:
            document = yaml.safe_load(self.yaml_text)
        except yaml.YAMLError as exc:
            raise ValueError(f"admitted YAML is invalid: {exc}") from exc
        if not isinstance(document, dict):
            raise ValueError("admitted YAML must serialize an object")
        if document.get("scenario_id") != self.scenario_id:
            raise ValueError("admitted YAML scenario_id mismatch")
        if document.get("candidate_id") != self.candidate_id:
            raise ValueError("admitted YAML candidate_id mismatch")
        return self


@dataclass(frozen=True, slots=True)
class AdmittedTerminalPayload:
    """Successful gate evidence and exact publication bytes as one value."""

    report: PostbehaviorAdmissionReport
    publication: AdmittedArtifactPublication


PersistenceJournalV1.model_rebuild()


def _json_value(value: Any) -> JsonValue:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    elif isinstance(value, tuple):
        value = list(value)
    # Round-trip only through the one public canonical encoder.  This both
    # normalizes NFC and rejects unsupported/non-finite values.
    return json.loads(canonical_json_bytes(value))


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _write_model(run_dir: Path, rel_path: str, model: BaseModel) -> Path:
    # Revalidate after any adapter-side list mutation so an invalid in-memory
    # object can never replace the last valid on-disk document.
    model = type(model).model_validate(model.model_dump(mode="python"))
    content = canonical_json_bytes(model)
    return atomic_write_text(run_dir / rel_path, content.decode("utf-8"))


def _canonical_parts(rel_path: str) -> tuple[str, ...]:
    path = PurePosixPath(rel_path)
    if (
        not rel_path
        or path.is_absolute()
        or path.as_posix() != rel_path
        or any(part in {"", ".", ".."} for part in path.parts)
        or "\\" in rel_path
    ):
        raise ManifestIntegrityError(f"Persistence path is not canonical: {rel_path}")
    return path.parts


def _open_parent(
    run_dir: Path, rel_path: str, *, create: bool = False
) -> tuple[int, str]:
    parts = _canonical_parts(rel_path)
    fd = os.open(run_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            try:
                next_fd = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=fd,
                )
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(part, dir_fd=fd)
                os.fsync(fd)
                next_fd = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=fd,
                )
            os.close(fd)
            fd = next_fd
        return fd, parts[-1]
    except Exception:
        os.close(fd)
        raise


def _safe_read(run_dir: Path, rel_path: str) -> bytes:
    data = b""
    try:
        parent_fd, name = _open_parent(run_dir, rel_path)
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise ManifestIntegrityError(
                        f"Persistence artifact is not a file: {rel_path}"
                    )
                while chunk := os.read(fd, 65536):
                    data += chunk
            finally:
                os.close(fd)
        finally:
            os.close(parent_fd)
    except OSError as exc:
        raise ManifestIntegrityError(
            f"Cannot safely read {run_dir / rel_path}: {exc}"
        ) from exc
    return data


def _exclusive_create(run_dir: Path, rel_path: str, content: bytes) -> None:
    parent_fd, name = _open_parent(run_dir, rel_path, create=True)
    temporary = f".{name}.{secrets.token_hex(8)}.tmp"
    try:
        fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent_fd,
        )
        try:
            view = memoryview(content)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.link(
                temporary,
                name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
                follow_symlinks=False,
            )
        except FileExistsError:
            if _safe_read(run_dir, rel_path) != content:
                raise ManifestIntegrityError(
                    f"Immutable evidence collision at {name}"
                ) from None
        os.fsync(parent_fd)
    finally:
        try:
            os.unlink(temporary, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        os.close(parent_fd)


def write_coverage_plan(run_dir: Path, plan: CoveragePlanV2) -> ArtifactEntry:
    _write_model(run_dir, "coverage-plan.json", plan)
    return build_artifact_entry(
        ArtifactRole.COVERAGE_PLAN,
        run_dir,
        "coverage-plan.json",
        schema_version=COVERAGE_PLAN_VERSION,
    )


def read_coverage_plan(
    run_dir: Path, entry: ArtifactEntry | None = None
) -> CoveragePlanV2:
    return _read_model(
        run_dir, entry, ArtifactRole.COVERAGE_PLAN, "coverage-plan.json", CoveragePlanV2
    )


def write_finalization_inventory(
    run_dir: Path, inventory: FinalizationInventoryV1
) -> ArtifactEntry:
    _write_model(run_dir, "finalization-inventory.json", inventory)
    return build_artifact_entry(
        ArtifactRole.FINALIZATION_INVENTORY,
        run_dir,
        "finalization-inventory.json",
        schema_version=FINALIZATION_INVENTORY_VERSION,
    )


def read_finalization_inventory(
    run_dir: Path, entry: ArtifactEntry | None = None
) -> FinalizationInventoryV1:
    return _read_model(
        run_dir,
        entry,
        ArtifactRole.FINALIZATION_INVENTORY,
        "finalization-inventory.json",
        FinalizationInventoryV1,
    )


def build_semantic_generation_summary(
    inventory: FinalizationInventoryV1,
) -> dict[str, Any]:
    """Derive the bounded manifest view from finalization authority."""
    required_stages = ("actor", "narrative", "tree", "behavior")
    decisions = {item.candidate_id: item for item in inventory.admission_decisions}
    records: list[dict[str, Any]] = []
    candidates: dict[str, dict[str, Any]] = {}
    for item in sorted(inventory.stage_attempts, key=lambda value: value.sequence):
        carrier = item.call if item.call is not None else item.failure
        semantic = carrier.semantic_evidence if carrier is not None else None
        stage_name = item.stage.value
        outcome = "missing_semantic_evidence"
        warnings: list[str] = []
        if semantic is not None:
            attempts = semantic.get("attempts", [])
            latest = attempts[-1] if attempts else {}
            outcome = str(latest.get("result") or "missing_attempt_result")
            warnings = [str(value) for value in semantic.get("warnings", [])]
        records.append(
            {
                "candidate_id": item.candidate_id,
                "stage": stage_name,
                "invocation_index": item.invocation_index,
                "outcome": outcome,
                "semantic_evidence": semantic,
            }
        )
        candidate = candidates.setdefault(
            item.candidate_id,
            {
                "admitted": bool(
                    decisions.get(item.candidate_id)
                    and decisions[item.candidate_id].admitted
                ),
                "complete_provider_semantics": False,
                "presentation_fallbacks": [],
                "stages": {},
            },
        )
        candidate["stages"][stage_name] = outcome
        candidate["presentation_fallbacks"].extend(
            warning
            for warning in warnings
            if warning.startswith("presentation_fallback:")
            and warning not in candidate["presentation_fallbacks"]
        )

    for candidate in candidates.values():
        candidate["complete_provider_semantics"] = all(
            candidate["stages"].get(stage) == "accepted" for stage in required_stages
        )
    return {
        "schema_version": "1",
        "required_stages": list(required_stages),
        "candidates": candidates,
        "stage_records": records,
    }


def write_quarantine_bundle(run_dir: Path, bundle: QuarantineBundleV1) -> ArtifactEntry:
    rel_path = f"quarantine/{bundle.attempt_id}.json"
    bundle = QuarantineBundleV1.model_validate(bundle.model_dump(mode="python"))
    _exclusive_create(run_dir, rel_path, canonical_json_bytes(bundle))
    return build_artifact_entry(
        ArtifactRole.QUARANTINE_BUNDLE,
        run_dir,
        rel_path,
        schema_version=QUARANTINE_BUNDLE_VERSION,
        candidate_id=bundle.candidate_id,
    )


def write_planning_checkpoint(run_dir: Path, checkpoint: PlanningCheckpointV1) -> Path:
    checkpoint = PlanningCheckpointV1.model_validate(
        checkpoint.model_dump(mode="python")
    )
    _exclusive_create(
        run_dir,
        "planning-checkpoint.json",
        canonical_json_bytes(checkpoint.model_dump(mode="json", exclude_none=True)),
    )
    return run_dir / "planning-checkpoint.json"


def read_planning_checkpoint_bytes(content: bytes) -> PlanningCheckpointV1:
    try:
        return PlanningCheckpointV1.model_validate_json(content)
    except Exception as exc:
        raise ManifestIntegrityError(f"Invalid planning checkpoint: {exc}") from exc


def validate_planning_checkpoint(
    checkpoint: PlanningCheckpointV1, plan: CoveragePlanV2
) -> None:
    """Bind immutable completion-tail evidence to the durable target plan."""
    expected_fallbacks = {
        target.effective_target_id: [
            choice.candidate_id for choice in target.ordered_choices
        ]
        for target in plan.targets
    }
    expected_primaries = {
        target.effective_target_id: target.primary_candidate_id
        for target in plan.targets
        if target.primary_candidate_id is not None
    }
    if checkpoint.fallback_candidate_ids != expected_fallbacks:
        raise ManifestIntegrityError(
            "planning checkpoint fallback queues mismatch plan"
        )
    if checkpoint.primary_candidate_ids != expected_primaries:
        raise ManifestIntegrityError("planning checkpoint primaries mismatch plan")
    if sorted(checkpoint.selected_candidate_ids) != sorted(expected_primaries.values()):
        raise ManifestIntegrityError("planning checkpoint selection mismatch plan")
    if checkpoint.attempted_candidate_ids != sorted(checkpoint.selected_candidate_ids):
        raise ManifestIntegrityError("planning checkpoint attempted selection mismatch")
    if checkpoint.uncovered_target_ids != sorted(
        target.effective_target_id
        for target in plan.targets
        if not target.ordered_choices
    ):
        raise ManifestIntegrityError(
            "planning checkpoint uncovered targets mismatch plan"
        )
    plan_target_ids = {target.effective_target_id for target in plan.targets}
    if not set(checkpoint.projection_limitation_target_ids) <= plan_target_ids:
        raise ManifestIntegrityError(
            "planning checkpoint projection limitations are absent from plan"
        )
    if checkpoint.selection_limitation_target_ids != sorted(
        plan.selection_limitation_target_ids
    ):
        raise ManifestIntegrityError(
            "planning checkpoint selection limitations mismatch plan"
        )


def read_quarantine_bundle(run_dir: Path, entry: ArtifactEntry) -> QuarantineBundleV1:
    expected = PurePosixPath(entry.path)
    if (
        expected.as_posix() != entry.path
        or ".." in expected.parts
        or len(expected.parts) != 2
        or expected.parts[0] != "quarantine"
    ):
        raise ManifestIntegrityError(f"Invalid quarantine bundle path: {entry.path}")
    return _read_model(
        run_dir, entry, ArtifactRole.QUARANTINE_BUNDLE, entry.path, QuarantineBundleV1
    )


def _read_journal(run_dir: Path) -> PersistenceJournalV1 | None:
    journal_path = run_dir / ".finalization-state.json"
    if not journal_path.exists():
        return None
    try:
        journal = PersistenceJournalV1.model_validate_json(
            _safe_read(run_dir, journal_path.name)
        )
    except Exception as exc:
        raise ManifestIntegrityError(
            f"Invalid finalization state journal: {exc}"
        ) from exc

    return journal


def _publish_journal(run_dir: Path, journal: PersistenceJournalV1) -> CoveragePlanV2:
    """Complete one already-validated synchronized state replacement."""

    journal_path = run_dir / ".finalization-state.json"
    if journal.quarantine_bundle is not None:
        write_quarantine_bundle(run_dir, journal.quarantine_bundle)
    if journal.admitted_publication is not None:
        _write_admitted_publication(run_dir, journal.admitted_publication)
    write_finalization_inventory(run_dir, journal.finalization_inventory)
    write_coverage_plan(run_dir, journal.coverage_plan)
    journal_path.unlink()
    dir_fd = os.open(run_dir, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)
    return journal.coverage_plan


def recover_finalization_journal(
    run_dir: Path, *, expected_run_id: str
) -> CoveragePlanV2 | None:
    """Complete an interrupted v3 state publication before forensic loading."""
    run_dir = Path(run_dir)
    journal = _read_journal(run_dir)
    if journal is None:
        return None
    if journal.finalization_inventory.run_id != expected_run_id:
        raise ManifestIntegrityError(
            "finalization state journal run_id does not match resumed run"
        )
    return _publish_journal(run_dir, journal)


def _read_model(
    run_dir: Path,
    entry: ArtifactEntry | None,
    role: ArtifactRole,
    expected_path: str,
    model_type: type[StrictModel],
) -> Any:
    if entry is not None:
        if entry.role is not role or entry.path != expected_path:
            raise ManifestIntegrityError(
                f"{role.value} role/path mismatch: {entry.role.value} {entry.path}"
            )
        content = _safe_read(run_dir, expected_path)
        actual = hashlib.sha256(content).hexdigest()
        if actual != entry.sha256:
            raise ManifestIntegrityError(f"Hash mismatch for {entry.path}")
    try:
        return model_type.model_validate_json(
            content if entry is not None else _safe_read(run_dir, expected_path)
        )
    except Exception as exc:
        raise ManifestIntegrityError(f"Invalid {role.value}: {exc}") from exc


def validate_v3_inventories(resolver: Any) -> None:
    """Reconcile manifest v3, coverage, finalization, and quarantine receipts."""
    _check_v3_journal_unresolved(resolver)
    (
        coverage_entry,
        final_entry,
        planning_entry,
    ) = _v3_persistence_entries(resolver)
    coverage, final, checkpoint = _v3_load_persistence_models(
        resolver, coverage_entry, final_entry, planning_entry
    )
    validate_planning_checkpoint(checkpoint, coverage)
    _check_v3_run_identity(final, resolver.manifest.run_id, coverage_entry.sha256)
    admitted_decisions = _v3_admitted_decisions(final)
    _check_v3_gate_applicability(resolver, final, admitted_decisions)
    plan_by_candidate = _v3_plan_by_candidate(coverage)
    _check_v3_transitions_in_plan(final, plan_by_candidate, coverage)
    admitted, quarantined = _v3_receipt_candidate_sets(final)
    _check_v3_inventory_disjoint(admitted, quarantined)
    _check_v3_attempts_match_plan(final, plan_by_candidate)
    attempts_by_target = _v3_attempts_by_target(final)
    _check_v3_attempted_candidates_per_target(final, coverage, attempts_by_target)
    admitted_decision_ids = _v3_admitted_decision_ids(final)
    _check_v3_terminal_decision_sets(
        _v3_attempted_and_terminal_ids(final),
        admitted,
        quarantined,
        admitted_decision_ids,
    )
    _check_v3_fallback_order(attempts_by_target, admitted_decision_ids)
    _check_v3_target_terminal_states(final, coverage, admitted_decision_ids)
    _check_v3_manifest_receipts(resolver, final)
    _check_v3_admitted_receipt_pairs(final, admitted)
    _check_v3_quarantined_receipts(final, quarantined)
    _check_v3_eval_and_role_scopes(resolver, quarantined, admitted)
    _check_v3_admitted_causal_evidence(final, plan_by_candidate, admitted)
    _check_v3_quarantine_bundles(resolver, final, plan_by_candidate)
    _check_v3_completed_status(resolver, quarantined)


def _check_v3_journal_unresolved(resolver: Any) -> None:
    """Reject finalization while an interrupted journal is still present."""
    if (resolver.run_dir / ".finalization-state.json").exists():
        raise ManifestIntegrityError(
            "Manifest v3 cannot finalize with an unresolved journal"
        )


def _v3_persistence_entries(resolver: Any) -> tuple[Any, Any, Any]:
    """Return the v3 persistence singleton entries, rejecting missing ones."""
    coverage_entry = resolver.entry_by_role(ArtifactRole.COVERAGE_PLAN)
    final_entry = resolver.entry_by_role(ArtifactRole.FINALIZATION_INVENTORY)
    planning_entry = resolver.entry_by_role(ArtifactRole.PLANNING_CHECKPOINT)
    if planning_entry is None or coverage_entry is None or final_entry is None:
        raise ManifestIntegrityError("Manifest v3 persistence singletons are missing")
    return coverage_entry, final_entry, planning_entry


def _v3_load_persistence_models(
    resolver: Any,
    coverage_entry: Any,
    final_entry: Any,
    planning_entry: Any,
) -> tuple[CoveragePlanV2, FinalizationInventoryV1, Any]:
    """Load and validate the durable v3 persistence models."""
    try:
        coverage = CoveragePlanV2.model_validate(resolver.read_json(coverage_entry))
        final = FinalizationInventoryV1.model_validate(resolver.read_json(final_entry))
    except Exception as exc:
        raise ManifestIntegrityError(
            f"Invalid manifest v3 persistence model: {exc}"
        ) from exc
    checkpoint = read_planning_checkpoint_bytes(resolver.read_bytes(planning_entry))
    return coverage, final, checkpoint


def _check_v3_run_identity(
    final: FinalizationInventoryV1,
    run_id: str,
    coverage_plan_sha256: str,
) -> None:
    """Require the finalization inventory run identity to match the manifest."""
    if final.run_id != run_id:
        raise ManifestIntegrityError("Finalization inventory run_id mismatch")
    if final.coverage_plan_sha256 != coverage_plan_sha256:
        raise ManifestIntegrityError("Finalization coverage plan hash mismatch")


def _v3_admitted_decisions(
    final: FinalizationInventoryV1,
) -> list[AdmissionDecisionRecord]:
    """Return admitted terminal decisions."""
    return [decision for decision in final.admission_decisions if decision.admitted]


def _v3_profile_applicability(resolver: Any) -> dict[AdmissionEvidenceId, bool]:
    """Load the capability profile and its conditional evidence applicability."""
    profile_entry = resolver.entry_by_role(ArtifactRole.CAPABILITY_PROFILE)
    if profile_entry is None:
        raise ManifestIntegrityError("Admitted inventory requires capability profile")
    try:
        profile = CapabilityProfile.model_validate(resolver.read_yaml(profile_entry))
    except Exception as exc:
        raise ManifestIntegrityError(f"Invalid capability profile: {exc}") from exc
    return {
        AdmissionEvidenceId.tool_integration_grounding: (
            profile.tool_inventory_completeness
            is InventoryCompleteness.operator_confirmed_complete
        ),
        AdmissionEvidenceId.data_access_grounding: (
            profile.entry_point_completeness
            is InventoryCompleteness.operator_confirmed_complete
        ),
    }


def _v3_decision_gate_applicability_mismatch(
    decision: AdmissionDecisionRecord,
    expected_applicability: dict[AdmissionEvidenceId, bool],
) -> bool:
    """True when any gated applicability diverges from the profile."""
    gates = {gate.gate: gate for gate in decision.gate_results}
    return any(
        gates[evidence_id].applicable is not expected
        for evidence_id, expected in expected_applicability.items()
    )


def _check_v3_gate_applicability(
    resolver: Any,
    final: FinalizationInventoryV1,
    admitted_decisions: list[AdmissionDecisionRecord],
) -> None:
    """Require admitted conditional evidence to match the capability profile."""
    if not admitted_decisions:
        return
    expected_applicability = _v3_profile_applicability(resolver)
    for decision in admitted_decisions:
        if _v3_decision_gate_applicability_mismatch(decision, expected_applicability):
            raise ManifestIntegrityError(
                "Admitted conditional evidence applicability does not match "
                "the capability profile"
            )


def _v3_plan_by_candidate(
    coverage: CoveragePlanV2,
) -> dict[str, tuple[Any, Any]]:
    """Index coverage choices by candidate_id with their owning target."""
    return {
        choice.candidate_id: (target, choice)
        for target in coverage.targets
        for choice in target.ordered_choices
    }


def _v3_transition_plan_mismatch(
    planned: tuple[Any, Any] | None,
    transition: TransitionRecord,
) -> bool:
    """True when a candidate transition is absent from or foreign to the plan."""
    return (
        planned is None
        or planned[0].effective_target_id != transition.target_entry_point_id
    )


def _check_v3_transition_in_plan(
    transition: TransitionRecord,
    plan_by_candidate: dict[str, tuple[Any, Any]],
    plan_target_ids: set[str],
) -> None:
    """Require one lifecycle transition to reference a planned target and
    candidate."""
    if transition.target_entry_point_id not in plan_target_ids:
        raise ManifestIntegrityError("Lifecycle transition target is absent from plan")
    if transition.candidate_id is not None:
        planned = plan_by_candidate.get(transition.candidate_id)
        if _v3_transition_plan_mismatch(planned, transition):
            raise ManifestIntegrityError(
                "Lifecycle transition candidate/target is absent from plan"
            )


def _check_v3_transitions_in_plan(
    final: FinalizationInventoryV1,
    plan_by_candidate: dict[str, tuple[Any, Any]],
    coverage: CoveragePlanV2,
) -> None:
    """Require every lifecycle transition to reference a planned target and
    candidate."""
    plan_target_ids = {target.effective_target_id for target in coverage.targets}
    for transition in final.transitions:
        _check_v3_transition_in_plan(transition, plan_by_candidate, plan_target_ids)


def _v3_receipt_candidate_sets(
    final: FinalizationInventoryV1,
) -> tuple[set[str], set[str]]:
    """Return admitted and quarantined receipt candidate sets."""
    admitted = {receipt.candidate_id for receipt in final.admitted_inventory}
    quarantined = {receipt.candidate_id for receipt in final.quarantine_inventory}
    return admitted, quarantined


def _check_v3_inventory_disjoint(
    admitted: set[str],
    quarantined: set[str],
) -> None:
    """Reject candidate overlap between admitted and quarantine inventory."""
    if admitted & quarantined:
        raise ManifestIntegrityError("Admitted and quarantine inventories overlap")


def _v3_attempt_plan_mismatch(
    attempt: CandidateAttemptRecord,
    planned: tuple[Any, Any],
) -> bool:
    """True when an attempt target/rank diverges from the coverage plan."""
    target, choice = planned
    return (
        attempt.target_entry_point_id != target.effective_target_id
        or attempt.queue_rank != choice.rank
    )


def _check_v3_attempts_match_plan(
    final: FinalizationInventoryV1,
    plan_by_candidate: dict[str, tuple[Any, Any]],
) -> None:
    """Require every finalization attempt to match its coverage-plan entry."""
    for attempt in final.candidate_attempts:
        planned = plan_by_candidate.get(attempt.candidate_id)
        if planned is None:
            raise ManifestIntegrityError(
                "Finalization attempt is absent from coverage plan"
            )
        if _v3_attempt_plan_mismatch(attempt, planned):
            raise ManifestIntegrityError(
                "Finalization attempt does not match coverage plan"
            )


def _v3_attempts_by_target(
    final: FinalizationInventoryV1,
) -> dict[str, list[CandidateAttemptRecord]]:
    """Index candidate attempts by effective target ID."""
    attempts_by_target: dict[str, list[CandidateAttemptRecord]] = {}
    for attempt in final.candidate_attempts:
        attempts_by_target.setdefault(attempt.target_entry_point_id, []).append(attempt)
    return attempts_by_target


def _v3_candidate_ids(attempts: Sequence[CandidateAttemptRecord]) -> list[str]:
    """Return candidate IDs of attempts in order."""
    return [item.candidate_id for item in attempts]


def _v3_attempted_ids_by_target(
    attempts_by_target: dict[str, list[CandidateAttemptRecord]],
) -> dict[str, list[str]]:
    """Map each target to its attempted candidate IDs in durable order."""
    return {
        target_id: _v3_candidate_ids(attempts)
        for target_id, attempts in attempts_by_target.items()
    }


def _check_v3_attempted_candidates_per_target(
    final: FinalizationInventoryV1,
    coverage: CoveragePlanV2,
    attempts_by_target: dict[str, list[CandidateAttemptRecord]],
) -> None:
    """Require coverage-plan attempted candidates to match the inventory."""
    attempts_by_target_id = _v3_attempted_ids_by_target(attempts_by_target)
    for target in coverage.targets:
        if target.attempted_candidate_ids != attempts_by_target_id.get(
            target.effective_target_id, []
        ):
            raise ManifestIntegrityError(
                "Coverage plan attempted candidates do not match finalization inventory"
            )


def _v3_admitted_decision_ids(
    final: FinalizationInventoryV1,
) -> set[str]:
    """Return candidate IDs of admitted terminal decisions."""
    return {
        decision.candidate_id
        for decision in final.admission_decisions
        if decision.admitted
    }


def _v3_attempted_and_terminal_ids(
    final: FinalizationInventoryV1,
) -> tuple[set[str], set[str]]:
    """Return attempted and terminal candidate ID sets."""
    attempted = {item.candidate_id for item in final.candidate_attempts}
    terminal = {item.candidate_id for item in final.admission_decisions}
    return attempted, terminal


def _check_v3_terminal_decision_sets(
    attempted_and_terminal: tuple[set[str], set[str]],
    admitted: set[str],
    quarantined: set[str],
    admitted_decisions: set[str],
) -> None:
    """Require receipt and decision candidate sets to reconcile exactly."""
    attempted_candidates, terminal_candidates = attempted_and_terminal
    if attempted_candidates != terminal_candidates:
        raise ManifestIntegrityError(
            "Every attempted candidate requires exactly one terminal decision"
        )
    nonadmitted_decisions = terminal_candidates - admitted_decisions
    if admitted != admitted_decisions:
        raise ManifestIntegrityError(
            "Admitted receipts must exactly match admitted terminal decisions"
        )
    if quarantined != nonadmitted_decisions:
        raise ManifestIntegrityError(
            "Quarantine receipts must exactly match non-admitted terminal decisions"
        )


def _v3_fallback_ranks_not_increasing(
    attempts: Sequence[CandidateAttemptRecord],
) -> bool:
    """True when fallback queue ranks do not strictly increase."""
    ranks = [item.queue_rank for item in attempts]
    return any(right <= left for left, right in zip(ranks, ranks[1:]))


def _check_v3_no_fallback_after_admission(
    attempts: Sequence[CandidateAttemptRecord],
    admitted_decisions: set[str],
) -> None:
    """Reject fallback attempts issued after target admission."""
    for index, attempt in enumerate(attempts[:-1]):
        if attempt.candidate_id in admitted_decisions:
            raise ManifestIntegrityError("Fallback attempted after target admission")


def _v3_primary_candidate_not_first(
    attempts: Sequence[CandidateAttemptRecord],
) -> bool:
    """True when the first attempt is not the primary candidate."""
    return bool(attempts) and not attempts[0].is_primary


def _check_v3_fallback_attempts(
    attempts: Sequence[CandidateAttemptRecord],
    admitted_decisions: set[str],
) -> None:
    """Require fallback ordering: increasing ranks, primary first, then no
    fallback after admission."""
    if _v3_fallback_ranks_not_increasing(attempts):
        raise ManifestIntegrityError(
            "Fallback attempts must have increasing queue rank"
        )
    if _v3_primary_candidate_not_first(attempts):
        raise ManifestIntegrityError(
            "Primary candidate must be attempted before fallback"
        )
    if any(item.is_primary for item in attempts[1:]):
        raise ManifestIntegrityError("Only the first target attempt may be primary")
    _check_v3_no_fallback_after_admission(attempts, admitted_decisions)


def _check_v3_fallback_order(
    attempts_by_target: dict[str, list[CandidateAttemptRecord]],
    admitted_decisions: set[str],
) -> None:
    """Require fallback ordering invariants per target."""
    for attempts in attempts_by_target.values():
        _check_v3_fallback_attempts(attempts, admitted_decisions)


def _v3_target_admitted_ids(
    target: Any,
    admitted_decisions: set[str],
) -> list[str]:
    """Return the target's attempted candidates that were admitted."""
    return [
        candidate_id
        for candidate_id in target.attempted_candidate_ids
        if candidate_id in admitted_decisions
    ]


def _check_v3_target_terminal_state(
    target: Any,
    final: FinalizationInventoryV1,
    admitted_decisions: set[str],
) -> None:
    """Require an admitted/exhausted target to match terminal decisions."""
    target_admitted = _v3_target_admitted_ids(target, admitted_decisions)
    if target.target_state is TargetState.admitted:
        if target_admitted != [target.admitted_candidate_id]:
            raise ManifestIntegrityError(
                "Coverage target admission does not match terminal decision"
            )
    elif target.target_state is not TargetState.exhausted:
        raise ManifestIntegrityError(
            "Completed manifest v3 targets must be admitted or exhausted"
        )
    _check_v3_target_terminal_transition(target, final)


def _v3_target_transitions(
    final: FinalizationInventoryV1,
    target_id: str,
) -> list[TransitionRecord]:
    """Return the durable transitions for one effective target."""
    return [
        item for item in final.transitions if item.target_entry_point_id == target_id
    ]


def _check_v3_target_terminal_transition(
    target: Any,
    final: FinalizationInventoryV1,
) -> None:
    """Require the target's final transition to match its target state."""
    target_transitions = _v3_target_transitions(final, target.effective_target_id)
    expected_terminal = (
        LifecycleState.admitted
        if target.target_state is TargetState.admitted
        else LifecycleState.exhausted
    )
    if (
        not target_transitions
        or target_transitions[-1].current is not expected_terminal
    ):
        raise ManifestIntegrityError(
            "Coverage target state does not match its terminal transition"
        )


def _check_v3_target_terminal_states(
    final: FinalizationInventoryV1,
    coverage: CoveragePlanV2,
    admitted_decisions: set[str],
) -> None:
    """Require every coverage target terminal state to reconcile."""
    for target in coverage.targets:
        _check_v3_target_terminal_state(target, final, admitted_decisions)


def _v3_manifest_scenario_entries(manifest: Any) -> set[tuple[Any, ...]]:
    """Return scenario/quarantine manifest entry keys."""
    return {
        (entry.role, entry.path, entry.candidate_id, entry.scenario_id, entry.sha256)
        for entry in manifest.inventory
        if entry.role
        in {
            ArtifactRole.SCENARIO_YAML,
            ArtifactRole.SCENARIO_FEATURE,
            ArtifactRole.QUARANTINE_BUNDLE,
        }
    }


def _v3_receipt_entries(final: FinalizationInventoryV1) -> set[tuple[Any, ...]]:
    """Return finalization receipt entry keys."""
    return {
        (item.role, item.path, item.candidate_id, item.scenario_id, item.sha256)
        for item in [*final.admitted_inventory, *final.quarantine_inventory]
    }


def _check_v3_manifest_receipts(
    resolver: Any,
    final: FinalizationInventoryV1,
) -> None:
    """Require finalization receipts and manifest entries to match exactly."""
    manifest_entries = _v3_manifest_scenario_entries(resolver.manifest)
    receipt_entries = _v3_receipt_entries(final)
    if manifest_entries != receipt_entries:
        raise ManifestIntegrityError(
            "Finalization receipts and manifest entries must match exactly"
        )


def _v3_receipts_for(
    receipts: Sequence[ArtifactReceipt],
    candidate_id: str,
) -> list[ArtifactReceipt]:
    """Return receipts for one candidate."""
    return [item for item in receipts if item.candidate_id == candidate_id]


def _admitted_receipt_roles_mismatch(receipts: Sequence[ArtifactReceipt]) -> bool:
    """True when admitted receipts are not exactly one YAML/feature pair."""
    return sorted(
        (item.role for item in receipts), key=lambda role: role.value
    ) != sorted(
        [ArtifactRole.SCENARIO_YAML, ArtifactRole.SCENARIO_FEATURE],
        key=lambda role: role.value,
    )


def _check_v3_admitted_receipt_pairs(
    final: FinalizationInventoryV1,
    admitted: set[str],
) -> None:
    """Require every admitted candidate to carry one YAML/feature pair."""
    for candidate_id in admitted:
        receipts = _v3_receipts_for(final.admitted_inventory, candidate_id)
        if _admitted_receipt_roles_mismatch(receipts):
            raise ManifestIntegrityError(
                "Every admitted candidate requires one YAML/feature pair"
            )
        if len({item.scenario_id for item in receipts}) != 1:
            raise ManifestIntegrityError(
                "Admitted YAML/feature receipts require the same scenario_id"
            )


def _check_v3_quarantined_receipts(
    final: FinalizationInventoryV1,
    quarantined: set[str],
) -> None:
    """Require every quarantined candidate to carry one bundle only."""
    for candidate_id in quarantined:
        receipts = _v3_receipts_for(final.quarantine_inventory, candidate_id)
        if len(receipts) != 1 or receipts[0].role is not ArtifactRole.QUARANTINE_BUNDLE:
            raise ManifestIntegrityError(
                "Every quarantined candidate requires one bundle only"
            )


def _v3_eval_scorecard_candidates(manifest: Any) -> set[Any]:
    """Return candidate IDs carrying an eval scorecard entry."""
    return {
        entry.candidate_id
        for entry in manifest.inventory
        if entry.role is ArtifactRole.EVAL_SCORECARD and entry.candidate_id
    }


def _v3_bundle_candidates(manifest: Any) -> set[Any]:
    """Return candidate IDs carrying a quarantine bundle entry."""
    return {
        entry.candidate_id
        for entry in manifest.inventory
        if entry.role is ArtifactRole.QUARANTINE_BUNDLE
    }


def _v3_normal_scenario_candidates(manifest: Any) -> set[Any]:
    """Return candidate IDs carrying normal scenario roles."""
    return {
        entry.candidate_id
        for entry in manifest.inventory
        if entry.role in {ArtifactRole.SCENARIO_YAML, ArtifactRole.SCENARIO_FEATURE}
    }


def _check_v3_eval_and_role_scopes(
    resolver: Any,
    quarantined: set[str],
    admitted: set[str],
) -> None:
    """Reject normal/eval roles on quarantined candidates and require normal
    scenario inventory to contain admitted candidates only."""
    eval_candidates = _v3_eval_scorecard_candidates(resolver.manifest)
    if eval_candidates & quarantined:
        raise ManifestIntegrityError(
            "Evaluation inventory contains quarantined candidate"
        )
    bundle_candidates = _v3_bundle_candidates(resolver.manifest)
    normal_candidates = _v3_normal_scenario_candidates(resolver.manifest)
    if bundle_candidates & normal_candidates:
        raise ManifestIntegrityError(
            "Quarantine candidate carries a normal scenario role"
        )
    if normal_candidates != admitted:
        raise ManifestIntegrityError(
            "Normal scenario inventory must contain admitted candidates only"
        )


def _v3_attempt_for(
    final: FinalizationInventoryV1,
    candidate_id: str,
) -> CandidateAttemptRecord:
    """Return the candidate's durable attempt."""
    return next(
        item for item in final.candidate_attempts if item.candidate_id == candidate_id
    )


def _v3_stage_attempts_for(
    final: FinalizationInventoryV1,
    candidate_id: str,
) -> list[StageAttemptRecord]:
    """Return the candidate's stage attempts."""
    return [item for item in final.stage_attempts if item.candidate_id == candidate_id]


def _v3_repairs_for(
    final: FinalizationInventoryV1,
    candidate_id: str,
) -> list[ParsimonyRepairRecord]:
    """Return the candidate's parsimony repair records."""
    return [item for item in final.repairs if item.candidate_id == candidate_id]


def _check_v3_admitted_causal_evidence(
    final: FinalizationInventoryV1,
    plan_by_candidate: dict[str, tuple[Any, Any]],
    admitted: set[str],
) -> None:
    """Require each admitted candidate's durable stage evidence to reduce to a
    causal artifact frontier."""
    for candidate_id in admitted:
        attempt = _v3_attempt_for(final, candidate_id)
        _causal_stage_artifacts(
            _v3_stage_attempts_for(final, candidate_id),
            candidate_attempt_id=attempt.attempt_id,
            durable_candidate=plan_by_candidate[candidate_id][1].projected_candidate,
            repairs=_v3_repairs_for(final, candidate_id),
        )


def _v3_read_bundle(resolver: Any, entry: Any) -> QuarantineBundleV1:
    """Load and validate one quarantine bundle."""
    try:
        return QuarantineBundleV1.model_validate(resolver.read_json(entry))
    except Exception as exc:
        raise ManifestIntegrityError(
            f"Invalid quarantine bundle {entry.path}: {exc}"
        ) from exc


def _v3_bundle_identity_mismatch(
    bundle: QuarantineBundleV1,
    resolver: Any,
    entry: Any,
) -> bool:
    """True when a bundle's run/candidate identity or path diverges."""
    return (
        bundle.run_id != resolver.manifest.run_id
        or bundle.candidate_id != entry.candidate_id
        or entry.path != f"quarantine/{bundle.attempt_id}.json"
    )


def _v3_bundle_attempt_mismatch(
    attempt: CandidateAttemptRecord | None,
    bundle: QuarantineBundleV1,
) -> bool:
    """True when a bundle does not match its candidate attempt."""
    return (
        attempt is None
        or attempt.attempt_id != bundle.attempt_id
        or attempt.target_entry_point_id != bundle.target_entry_point_id
    )


def _v3_attempt_or_none(
    final: FinalizationInventoryV1,
    candidate_id: str,
) -> CandidateAttemptRecord | None:
    """Return the candidate's durable attempt, if any."""
    return next(
        (
            item
            for item in final.candidate_attempts
            if item.candidate_id == candidate_id
        ),
        None,
    )


def _v3_decision_for(
    final: FinalizationInventoryV1,
    candidate_id: str,
) -> AdmissionDecisionRecord:
    """Return the candidate's terminal admission decision."""
    return next(
        item for item in final.admission_decisions if item.candidate_id == candidate_id
    )


def _check_v3_bundle_identity(
    bundle: QuarantineBundleV1,
    resolver: Any,
    entry: Any,
) -> None:
    """Reject a quarantine bundle whose identity or path diverges."""
    if _v3_bundle_identity_mismatch(bundle, resolver, entry):
        raise ManifestIntegrityError(
            f"Quarantine bundle identity/path mismatch: {entry.path}"
        )


def _check_v3_bundle_attempt(
    bundle: QuarantineBundleV1,
    attempt: CandidateAttemptRecord | None,
    entry: Any,
) -> None:
    """Reject a quarantine bundle that does not match its candidate attempt."""
    if _v3_bundle_attempt_mismatch(attempt, bundle):
        raise ManifestIntegrityError(
            f"Quarantine bundle does not match candidate attempt: {entry.path}"
        )


def _check_v3_bundle_violations(
    bundle: QuarantineBundleV1,
    decision: AdmissionDecisionRecord,
    entry: Any,
) -> None:
    """Reject bundle violations that diverge from the terminal decision."""
    if bundle.violations != decision.violations:
        raise ManifestIntegrityError(
            f"Quarantine bundle violations mismatch terminal decision: {entry.path}"
        )


def _check_v3_bundle_stage_evidence(
    bundle: QuarantineBundleV1,
    causal_artifacts: dict[GeneratedStage, JsonValue],
    entry: Any,
) -> None:
    """Require each bundle stage artifact to match causal stage evidence."""
    for stage in GeneratedStage:
        if getattr(bundle, stage.value) != causal_artifacts.get(stage):
            raise ManifestIntegrityError(
                f"Quarantine bundle {stage.value} evidence mismatch: {entry.path}"
            )


def _check_v3_quarantine_bundles(
    resolver: Any,
    final: FinalizationInventoryV1,
    plan_by_candidate: dict[str, tuple[Any, Any]],
) -> None:
    """Require every quarantine bundle to reconcile with the finalization
    inventory."""
    for entry in resolver.entries_by_role(ArtifactRole.QUARANTINE_BUNDLE):
        bundle = _v3_read_bundle(resolver, entry)
        _check_v3_bundle_identity(bundle, resolver, entry)
        attempt = _v3_attempt_or_none(final, bundle.candidate_id)
        _check_v3_bundle_attempt(bundle, attempt, entry)
        decision = _v3_decision_for(final, bundle.candidate_id)
        _check_v3_bundle_violations(bundle, decision, entry)
        causal_artifacts = _causal_stage_artifacts(
            _v3_stage_attempts_for(final, bundle.candidate_id),
            candidate_attempt_id=attempt.attempt_id,
            durable_candidate=plan_by_candidate[bundle.candidate_id][
                1
            ].projected_candidate,
            repairs=_v3_repairs_for(final, bundle.candidate_id),
        )
        _check_v3_bundle_stage_evidence(bundle, causal_artifacts, entry)


def _check_v3_completed_status(
    resolver: Any,
    quarantined: set[str],
) -> None:
    """Require the manifest status to match the presence of quarantine."""
    if quarantined and resolver.manifest.status is not RunStatus.COMPLETED_WITH_ERRORS:
        raise ManifestIntegrityError(
            "Manifest v3 quarantine inventory requires completed_with_errors"
        )
    if not quarantined and resolver.manifest.status not in {
        RunStatus.COMPLETED,
        RunStatus.COMPLETED_WITH_ERRORS,
    }:
        raise ManifestIntegrityError(
            "Manifest v3 inventory requires a completed status"
        )


def _violations(values: Any) -> list[ViolationRecord]:
    records: list[ViolationRecord] = []
    for value in values:
        owner = getattr(value, "owner", None)
        code = getattr(value, "code", "invalid")
        if isinstance(code, Enum):
            serialized_code = code.value
        elif isinstance(code, str):
            serialized_code = code
        else:
            raise TypeError("violation code must be a string or enum")
        records.append(
            ViolationRecord(
                code=serialized_code,
                detail=value.detail,
                owner=owner,
                retryable=getattr(value, "retryable", owner is not None),
            )
        )
    return records


def make_admitted_terminal_payload(
    report: PostbehaviorAdmissionReport,
    publication: AdmittedArtifactPublication,
) -> AdmittedTerminalPayload:
    """Phase 5 seam joining concrete admission gates to publication bytes."""

    if type(report) is not PostbehaviorAdmissionReport:
        raise TypeError("admission persistence requires PostbehaviorAdmissionReport")
    return AdmittedTerminalPayload(report=report, publication=publication)


def _llm_result(value: Any) -> LLMResultRecord:
    return LLMResultRecord(
        content=_json_value(value.content),
        prompt_tokens=value.prompt_tokens,
        completion_tokens=value.completion_tokens,
        duration_ms=value.duration_ms,
        system_prompt=value.system_prompt,
        user_prompt=value.user_prompt,
        request_controls=_json_value(getattr(value, "request_controls", {})),
    )


def _pipeline_log_response(value: Any) -> Any:
    """Convert one LLM result content to the historical log representation."""
    content = value.content
    if content is None:
        return None
    if hasattr(content, "model_dump"):
        return content.model_dump(mode="json")
    return content if isinstance(content, str) else str(content)


def _call_evidence(value: StageCallEvidence) -> StageCallEvidenceRecord:
    return StageCallEvidenceRecord(
        call_name=value.call_name.value,
        result=_llm_result(value.result),
        metadata=CallMetadataRecord(
            call=value.metadata.call.value,
            prompt_tokens=value.metadata.prompt_tokens,
            completion_tokens=value.metadata.completion_tokens,
            duration_ms=value.metadata.duration_ms,
        ),
        semantic_evidence=(
            _json_value(value.semantic_evidence.as_dict())
            if value.semantic_evidence is not None
            else None
        ),
    )


def _attempt_failure(value: StageAttemptFailure) -> StageAttemptFailureRecord:
    prompt = (
        PromptRecord(
            system_prompt=value.system_prompt,
            user_prompt=value.user_prompt,
        )
        if value.system_prompt is not None or value.user_prompt is not None
        else None
    )
    return StageAttemptFailureRecord(
        call_name=value.call_name.value,
        exception_type=value.exception_type,
        detail=value.detail,
        phase=value.phase,
        invoked=value.invoked,
        code=value.code,
        retryable=value.retryable,
        semantic_evidence=(
            _json_value(value.semantic_evidence.as_dict())
            if value.semantic_evidence is not None
            else None
        ),
        finish_reason=value.finish_reason,
        prompt_tokens=value.prompt_tokens,
        completion_tokens=value.completion_tokens,
        total_tokens=value.total_tokens,
        usage_details=_json_value(value.usage_details or {}),
        response_id=value.response_id,
        model=value.model,
        partial_character_count=value.partial_character_count,
        partial_sha256=value.partial_sha256,
        partial_preview_prefix=value.partial_preview_prefix,
        partial_preview_suffix=value.partial_preview_suffix,
        elapsed_ms=value.elapsed_ms,
        request_controls=_json_value(value.request_controls),
        prompt=prompt,
        result=_llm_result(value.result) if value.result is not None else None,
        raw_response=(
            _json_value(value.raw_response) if value.raw_response is not None else None
        ),
    )


def _retry_control(value: CausalRetryControl | None) -> JsonValue | None:
    if value is None:
        return None
    return {
        "control_id": value.control_id,
        "field": value.field,
        "initial_value": value.initial_value,
        "retry_value": value.retry_value,
    }


def _event_key(kind: str, identity: Any) -> str:
    return canonical_sha256({"kind": kind, "identity": identity})


def _verify_event(item: Any, kind: str, identity: Any, payload: Any) -> None:
    if item.event_id != _event_key(kind, identity):
        raise ValueError(f"{kind} event ID mismatch")
    if item.payload_sha256 != canonical_sha256(payload):
        raise ValueError(f"{kind} payload digest mismatch")


def _publication_receipts(
    publication: AdmittedArtifactPublication,
) -> list[ArtifactReceipt]:
    return [
        ArtifactReceipt(
            candidate_id=publication.candidate_id,
            role=role,
            path=f"scenarios/{publication.scenario_id}{suffix}",
            sha256=hashlib.sha256(content.encode("utf-8")).hexdigest(),
            scenario_id=publication.scenario_id,
        )
        for role, suffix, content in (
            (ArtifactRole.SCENARIO_YAML, ".yaml", publication.yaml_text),
            (ArtifactRole.SCENARIO_FEATURE, ".feature", publication.feature_text),
        )
    ]


def _quarantine_receipt(bundle: QuarantineBundleV1) -> ArtifactReceipt:
    return ArtifactReceipt(
        candidate_id=bundle.candidate_id,
        role=ArtifactRole.QUARANTINE_BUNDLE,
        path=f"quarantine/{bundle.attempt_id}.json",
        sha256=hashlib.sha256(canonical_json_bytes(bundle)).hexdigest(),
        scenario_id=None,
    )


def _terminal_receipt_projection(
    receipts: list[ArtifactReceipt],
) -> list[dict[str, str | None]]:
    return [
        {
            "role": receipt.role.value,
            "path": receipt.path,
            "candidate_id": receipt.candidate_id,
            "scenario_id": receipt.scenario_id,
            "sha256": receipt.sha256,
        }
        for receipt in sorted(receipts, key=lambda item: (item.role.value, item.path))
    ]


def _gate_report_records(
    report: PostbehaviorAdmissionReport,
) -> list[GateResultRecord]:
    if type(report) is not PostbehaviorAdmissionReport:
        raise TypeError("admission persistence requires PostbehaviorAdmissionReport")
    return [
        GateResultRecord(
            gate=gate.evidence_id,
            passed=gate.passed,
            applicable=gate.applicable,
            violations=[
                ViolationRecord(
                    code=violation.code.value,
                    detail=violation.detail,
                    owner=violation.owner,
                    retryable=violation.owner is not None,
                )
                for violation in gate.violations
            ],
            diagnostics=[
                ViolationRecord(
                    code=diagnostic.code.value,
                    detail=diagnostic.detail,
                    owner=diagnostic.owner,
                    retryable=diagnostic.owner is not None,
                )
                for diagnostic in gate.diagnostics
            ],
        )
        for gate in report.gate_results
    ]


def _write_admitted_publication(
    run_dir: Path, publication: AdmittedArtifactPublication
) -> None:
    for receipt, content in zip(
        _publication_receipts(publication),
        (publication.yaml_text, publication.feature_text),
        strict=True,
    ):
        _exclusive_create(run_dir, receipt.path, content.encode("utf-8"))


class FinalizationPersistenceAdapter:
    """Journaled, durable implementation of ``FinalizationPersistencePort``."""

    def __init__(
        self,
        run_dir: Path,
        inventory: FinalizationInventoryV1,
        coverage_plan: CoveragePlanV2,
    ) -> None:
        self.run_dir = Path(run_dir)
        self.inventory = inventory
        self.coverage_plan = coverage_plan
        self._lock = threading.Lock()
        self._candidate_plan = {
            choice.candidate_id: (target.effective_target_id, choice.rank)
            for target in coverage_plan.targets
            for choice in target.ordered_choices
        }
        self._events = {
            item.event_id: item.payload_sha256
            for item in [
                *inventory.candidate_attempts,
                *inventory.stage_attempts,
                *inventory.transitions,
                *inventory.repairs,
                *inventory.admission_decisions,
            ]
        }
        self._failed = False

    def _sequence(self, inventory: FinalizationInventoryV1) -> int:
        return sum(
            len(items)
            for items in (
                inventory.candidate_attempts,
                inventory.stage_attempts,
                inventory.transitions,
                inventory.repairs,
                inventory.admission_decisions,
            )
        )

    def _replayed(self, event_id: str, payload_sha256: str) -> bool:
        existing = self._events.get(event_id)
        if existing is None:
            return False
        if existing != payload_sha256:
            raise ManifestIntegrityError(
                f"Conflicting duplicate persistence event {event_id}"
            )
        return True

    def _derive_plan(self, inventory: FinalizationInventoryV1) -> CoveragePlanV2:
        decisions = {item.candidate_id: item for item in inventory.admission_decisions}
        next_targets: list[CoverageTargetEntry] = []
        for target in self.coverage_plan.targets:
            attempted = [
                item.candidate_id
                for item in sorted(
                    inventory.candidate_attempts, key=lambda item: item.sequence
                )
                if item.target_entry_point_id == target.effective_target_id
            ]
            admitted = next(
                (
                    candidate_id
                    for candidate_id in attempted
                    if candidate_id in decisions and decisions[candidate_id].admitted
                ),
                None,
            )
            choice_ids = [item.candidate_id for item in target.ordered_choices]
            terminal = bool(attempted) and all(
                candidate_id in decisions for candidate_id in attempted
            )
            if admitted is not None:
                state = TargetState.admitted
                fallback: list[QualifiedCandidateRef] = []
            elif attempted == choice_ids and terminal or not choice_ids:
                state = TargetState.exhausted
                fallback = []
            else:
                state = TargetState.selected
                fallback = target.ordered_choices[len(attempted) :]
            next_targets.append(
                target.model_copy(
                    update={
                        "attempted_candidate_ids": attempted,
                        "admitted_candidate_id": admitted,
                        "target_state": state,
                        "fallback_available": fallback,
                    }
                )
            )
        return CoveragePlanV2.model_validate(
            self.coverage_plan.model_copy(update={"targets": next_targets}).model_dump(
                mode="python"
            )
        )

    def _commit(
        self,
        next_inventory: FinalizationInventoryV1,
        *,
        quarantine_bundle: QuarantineBundleV1 | None = None,
        admitted_publication: AdmittedArtifactPublication | None = None,
    ) -> None:
        if self._failed:
            raise FinalizationPersistenceError(
                "Persistence adapter requires journal recovery before reuse"
            )
        if (self.run_dir / ".finalization-state.json").exists():
            self._failed = True
            raise FinalizationPersistenceError(
                "Unresolved finalization journal must be recovered before another event"
            )
        next_plan = self._derive_plan(next_inventory)
        plan_sha256 = hashlib.sha256(canonical_json_bytes(next_plan)).hexdigest()
        next_inventory = FinalizationInventoryV1.model_validate(
            next_inventory.model_copy(
                update={"coverage_plan_sha256": plan_sha256}
            ).model_dump(mode="python")
        )
        journal = PersistenceJournalV1(
            schema_version="1",
            coverage_plan=next_plan,
            finalization_inventory=next_inventory,
            quarantine_bundle=quarantine_bundle,
            admitted_publication=admitted_publication,
        )
        try:
            _write_model(self.run_dir, ".finalization-state.json", journal)
            if quarantine_bundle is not None:
                write_quarantine_bundle(self.run_dir, quarantine_bundle)
            if admitted_publication is not None:
                _write_admitted_publication(self.run_dir, admitted_publication)
            write_finalization_inventory(self.run_dir, next_inventory)
            write_coverage_plan(self.run_dir, next_plan)
            journal_path = self.run_dir / ".finalization-state.json"
            journal_path.unlink()
            dir_fd = os.open(self.run_dir, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except Exception as exc:
            self._failed = True
            raise FinalizationPersistenceError(
                f"Finalization state commit failed: {exc}"
            ) from exc
        self.inventory = next_inventory
        self.coverage_plan = next_plan
        self._events = {
            item.event_id: item.payload_sha256
            for item in [
                *next_inventory.candidate_attempts,
                *next_inventory.stage_attempts,
                *next_inventory.transitions,
                *next_inventory.repairs,
                *next_inventory.admission_decisions,
            ]
        }

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
            payload = {
                "previous": transition.previous.value,
                "current": transition.current.value,
                "candidate_id": transition.candidate_id,
                "reason": transition.reason,
                "transition_index": transition.transition_index,
            }
            target_id = transition.target_entry_point_id
            if target_id is None and transition.candidate_id in self._candidate_plan:
                target_id = self._candidate_plan[transition.candidate_id][0]
            if target_id is None:
                raise ManifestIntegrityError(
                    "Lifecycle transition requires target identity"
                )
            payload["target_entry_point_id"] = target_id
            payload_sha256 = canonical_sha256(payload)
            event_id = _event_key(
                "transition", [target_id, transition.transition_index]
            )
            if self._replayed(event_id, payload_sha256):
                return
            next_inventory = self.inventory.model_copy(deep=True)
            if transition.current is LifecycleState.revalidating_candidate:
                candidate_id = transition.candidate_id
                if candidate_id not in self._candidate_plan:
                    raise ManifestIntegrityError(
                        f"Unknown coverage-plan candidate {candidate_id!r}"
                    )
                if not any(
                    item.candidate_id == candidate_id
                    for item in next_inventory.candidate_attempts
                ):
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
            if isinstance(result.evidence, StageCallEvidence):
                call = _call_evidence(result.evidence)
                failure = None
                prompt = PromptRecord(
                    system_prompt=call.result.system_prompt,
                    user_prompt=call.result.user_prompt,
                )
            elif isinstance(result.evidence, StageAttemptFailure):
                call = None
                failure = _attempt_failure(result.evidence)
                prompt = failure.prompt
            else:
                raise TypeError(
                    "stage persistence requires StageCallEvidence or StageAttemptFailure"
                )
            visible_artifacts = {
                stage.value: _json_value(invocation.artifacts.get(stage))
                for stage in GeneratedStage
                if invocation.artifacts.get(stage) is not None
            }
            if invocation.candidate_snapshot is None:
                raise TypeError("stage persistence requires a candidate snapshot")
            candidate = _json_value(invocation.candidate_snapshot)
            output = (
                _json_value(result.artifact) if result.artifact is not None else None
            )
            input_record = StageInputRecord(
                candidate=candidate,
                candidate_id=invocation.candidate_id,
                stage=invocation.stage,
                invocation_index=invocation.invocation_index,
                owner_retry_index=invocation.owner_retry_index,
                visible_artifacts=visible_artifacts,
                prompt=prompt,
                final_tree_digest=invocation.final_tree_digest,
                retry_reason=invocation.retry_reason,
                retry_control=_retry_control(invocation.retry_control),
                total_request_budget=invocation.total_request_budget,
            )
            input_payload = input_record.model_dump(mode="json")
            payload = {
                "attempt_id": attempt_id,
                "input": input_payload,
                "call": call.model_dump(mode="json") if call else None,
                "failure": failure.model_dump(mode="json") if failure else None,
                "result": output,
                "violations": [
                    item.model_dump(mode="json")
                    for item in _violations(result.violations)
                ],
            }
            payload_sha256 = canonical_sha256(payload)
            event_id = _event_key("stage_attempt", attempt_id)
            if self._replayed(event_id, payload_sha256):
                return
            record = StageAttemptRecord(
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
            next_inventory.stage_attempts.append(record)
            candidate_attempt.stage_attempt_ids.append(attempt_id)

            # Build a simple dict entry from the available data for calls.jsonl
            entry: dict[str, Any] = {
                "call": result.evidence.call_name.value,
                "candidate_id": invocation.candidate_id,
                "stage": invocation.stage.value,
                "attempt_id": attempt_id,
                "retry_reason": invocation.retry_reason,
                "retry_control": _retry_control(invocation.retry_control),
                "total_request_budget": invocation.total_request_budget,
            }

            if isinstance(result.evidence, StageCallEvidence):
                evidence = result.evidence
                llm_result = evidence.result
                response = _pipeline_log_response(llm_result)

                entry.update(
                    {
                        "system_prompt": llm_result.system_prompt,
                        "user_prompt": llm_result.user_prompt,
                        "response": response,
                        "prompt_tokens": llm_result.prompt_tokens,
                        "completion_tokens": llm_result.completion_tokens,
                        "duration_ms": llm_result.duration_ms,
                        "request_controls": llm_result.request_controls,
                        "semantic_evidence": (
                            evidence.semantic_evidence.as_dict()
                            if evidence.semantic_evidence is not None
                            else None
                        ),
                    }
                )
            elif isinstance(result.evidence, StageAttemptFailure):
                evidence = result.evidence
                if evidence.result is not None:
                    llm_result = evidence.result
                    response = _pipeline_log_response(llm_result)

                    entry.update(
                        {
                            "system_prompt": llm_result.system_prompt,
                            "user_prompt": llm_result.user_prompt,
                            "response": response,
                            "prompt_tokens": llm_result.prompt_tokens,
                            "completion_tokens": llm_result.completion_tokens,
                            "duration_ms": llm_result.duration_ms,
                            "request_controls": (
                                evidence.request_controls or llm_result.request_controls
                            ),
                        }
                    )
                else:
                    entry.update(
                        {
                            "system_prompt": evidence.system_prompt,
                            "user_prompt": evidence.user_prompt,
                            "response": None,
                            "prompt_tokens": evidence.prompt_tokens,
                            "completion_tokens": evidence.completion_tokens,
                            "duration_ms": evidence.elapsed_ms,
                            "request_controls": evidence.request_controls,
                        }
                    )
                entry["error"] = f"{evidence.exception_type}: {evidence.detail}"
                # Stable typed routing evidence for every failed attempt row.
                entry["code"] = evidence.code
                entry["retryable"] = evidence.retryable
                entry["semantic_evidence"] = (
                    evidence.semantic_evidence.as_dict()
                    if evidence.semantic_evidence is not None
                    else None
                )
                if evidence.finish_reason is not None:
                    entry["finish_reason"] = evidence.finish_reason
                entry.update(
                    {
                        "total_tokens": evidence.total_tokens,
                        "usage_details": evidence.usage_details,
                        "response_id": evidence.response_id,
                        "model": evidence.model,
                        "partial_character_count": evidence.partial_character_count,
                        "partial_sha256": evidence.partial_sha256,
                        "partial_preview_prefix": evidence.partial_preview_prefix,
                        "partial_preview_suffix": evidence.partial_preview_suffix,
                        "elapsed_ms": evidence.elapsed_ms,
                    }
                )

            from asago_scenario_generator.pipeline.io import write_pipeline_call_log

            write_pipeline_call_log([entry], self.run_dir)

            self._commit(next_inventory)

    def record_candidate_result(
        self, candidate_id: str, result: CandidateTerminalResult
    ) -> None:
        with self._lock:
            if result.candidate_id != candidate_id:
                raise ValueError("candidate terminal result identity mismatch")
            next_inventory = self.inventory.model_copy(deep=True)
            candidate_attempt = self._candidate_attempt(next_inventory, candidate_id)
            admission_value = (
                result.admission.value if result.admission is not None else None
            )
            expected_admitted = result.status is CandidateTerminalStatus.admitted
            if result.admission is not None and (
                result.admission.admitted != expected_admitted
            ):
                raise TypeError(
                    "terminal status and AdmissionDecision.admitted must agree"
                )
            terminal_payload: AdmittedTerminalPayload | None = None
            report: PostbehaviorAdmissionReport | None = None
            if result.status is CandidateTerminalStatus.admitted:
                if type(admission_value) is not AdmittedTerminalPayload:
                    raise TypeError(
                        "admitted result requires typed report and publication payload"
                    )
                terminal_payload = admission_value
                report = terminal_payload.report
            elif result.admission is not None:
                if type(admission_value) is not PostbehaviorAdmissionReport:
                    raise TypeError(
                        "postbehavior rejection requires PostbehaviorAdmissionReport"
                    )
                report = admission_value
            gate_results = _gate_report_records(report) if report is not None else []
            serialized_violations = _violations(result.violations)
            if (
                report is not None
                and [
                    violation for gate in gate_results for violation in gate.violations
                ]
                != serialized_violations
            ):
                raise TypeError(
                    "typed admission report and terminal violations must agree"
                )
            if expected_admitted and (
                not gate_results
                or any(not gate.passed for gate in gate_results)
                or serialized_violations
            ):
                raise TypeError("admitted result requires nonempty passing gate report")
            target_transitions = [
                item
                for item in next_inventory.transitions
                if item.target_entry_point_id == candidate_attempt.target_entry_point_id
            ]
            if not target_transitions:
                raise ManifestIntegrityError(
                    "Terminal result requires a preceding target transition"
                )
            latest_transition = max(target_transitions, key=lambda item: item.sequence)
            if latest_transition.current is LifecycleState.admitting and report is None:
                raise TypeError(
                    "admitting terminal result requires PostbehaviorAdmissionReport"
                )
            terminal_state = (
                LifecycleState.admitted
                if result.status is CandidateTerminalStatus.admitted
                else LifecycleState.rejected
            )
            transition_index = max(item.index for item in target_transitions) + 1
            transition_payload = {
                "previous": latest_transition.current.value,
                "current": terminal_state.value,
                "candidate_id": candidate_id,
                "reason": f"candidate terminal status: {result.status.value}",
                "transition_index": transition_index,
                "target_entry_point_id": candidate_attempt.target_entry_point_id,
            }
            transition_event_id = _event_key(
                "transition",
                [candidate_attempt.target_entry_point_id, transition_index],
            )
            transition_payload_sha256 = canonical_sha256(transition_payload)
            stages = [
                item
                for item in next_inventory.stage_attempts
                if item.candidate_id == candidate_id
            ]
            planned_choice = next(
                choice
                for target in self.coverage_plan.targets
                for choice in target.ordered_choices
                if choice.candidate_id == candidate_id
            )
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
            snapshots = {
                "candidate_snapshot_sha256": stages[-1].candidate_snapshot_sha256
                if stages
                else None,
                "actor_snapshot_sha256": canonical_sha256(
                    causal_artifacts[GeneratedStage.actor]
                )
                if GeneratedStage.actor in causal_artifacts
                else None,
                "narrative_snapshot_sha256": canonical_sha256(
                    causal_artifacts[GeneratedStage.narrative]
                )
                if GeneratedStage.narrative in causal_artifacts
                else None,
                "final_tree_snapshot_sha256": canonical_sha256(
                    causal_artifacts[GeneratedStage.tree]
                )
                if GeneratedStage.behavior in causal_artifacts
                else None,
            }
            publication = (
                terminal_payload.publication if terminal_payload is not None else None
            )
            bundle = None
            if publication is not None:
                if publication.candidate_id != candidate_id:
                    raise ManifestIntegrityError(
                        "Admitted publication candidate identity mismatch"
                    )
                terminal_receipts = _publication_receipts(publication)
                next_inventory.admitted_inventory.extend(terminal_receipts)
            else:
                target_id = candidate_attempt.target_entry_point_id
                artifacts = {
                    stage: causal_artifacts.get(stage) for stage in GeneratedStage
                }
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
                terminal_receipts = [_quarantine_receipt(bundle)]
                next_inventory.quarantine_inventory.extend(terminal_receipts)
            payload = {
                "candidate_id": candidate_id,
                "status": result.status.value,
                "violations": [
                    item.model_dump(mode="json") for item in serialized_violations
                ],
                "gate_results": [item.model_dump(mode="json") for item in gate_results],
                "snapshots": snapshots,
                "terminal_receipts": _terminal_receipt_projection(terminal_receipts),
            }
            payload_sha256 = canonical_sha256(payload)
            event_id = _event_key("candidate_result", candidate_id)
            if self._replayed(event_id, payload_sha256):
                return
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
            decision = AdmissionDecisionRecord(
                event_id=event_id,
                payload_sha256=payload_sha256,
                sequence=self._sequence(next_inventory),
                candidate_id=candidate_id,
                status=result.status,
                admitted=result.status is CandidateTerminalStatus.admitted,
                gate_results=gate_results,
                violations=serialized_violations,
                terminal_receipts=terminal_receipts,
                **snapshots,
            )
            next_inventory.admission_decisions.append(decision)
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


def make_finalization_persistence_adapter(
    run_dir: Path,
    *,
    run_id: str,
    coverage_plan: CoveragePlanV2,
) -> FinalizationPersistenceAdapter:
    """Phase 5 factory; creates no runner coupling and activates no manifest version."""

    run_dir = Path(run_dir)
    recovered_plan = recover_finalization_journal(run_dir, expected_run_id=run_id)
    if recovered_plan is not None:
        coverage_plan = recovered_plan
    coverage_plan = CoveragePlanV2.model_validate(
        coverage_plan.model_dump(mode="python")
    )
    coverage_plan_sha256 = hashlib.sha256(
        canonical_json_bytes(coverage_plan)
    ).hexdigest()
    plan_path = run_dir / "coverage-plan.json"
    inventory_path = run_dir / "finalization-inventory.json"
    if not plan_path.exists() and not inventory_path.exists():
        inventory = FinalizationInventoryV1(
            schema_version="1",
            run_id=run_id,
            coverage_plan_sha256=coverage_plan_sha256,
            candidate_attempts=[],
            stage_attempts=[],
            transitions=[],
            repairs=[],
            admission_decisions=[],
            admitted_inventory=[],
            quarantine_inventory=[],
        )
        journal = PersistenceJournalV1(
            schema_version="1",
            coverage_plan=coverage_plan,
            finalization_inventory=inventory,
        )
        _write_model(run_dir, ".finalization-state.json", journal)
        write_finalization_inventory(run_dir, inventory)
        write_coverage_plan(run_dir, coverage_plan)
        (run_dir / ".finalization-state.json").unlink()
        dir_fd = os.open(run_dir, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)

    if plan_path.exists():
        persisted_plan = read_coverage_plan(run_dir)
        if persisted_plan != coverage_plan:
            raise ManifestIntegrityError(
                "Supplied coverage plan differs from persisted plan"
            )
    else:
        write_coverage_plan(run_dir, coverage_plan)
    if inventory_path.exists():
        inventory = read_finalization_inventory(Path(run_dir))
        if (
            inventory.run_id != run_id
            or inventory.coverage_plan_sha256 != coverage_plan_sha256
        ):
            raise ManifestIntegrityError(
                "Existing finalization inventory identity mismatch"
            )
    else:
        inventory = FinalizationInventoryV1(
            schema_version="1",
            run_id=run_id,
            coverage_plan_sha256=coverage_plan_sha256,
            candidate_attempts=[],
            stage_attempts=[],
            transitions=[],
            repairs=[],
            admission_decisions=[],
            admitted_inventory=[],
            quarantine_inventory=[],
        )
        write_finalization_inventory(run_dir, inventory)
    return FinalizationPersistenceAdapter(run_dir, inventory, coverage_plan)
