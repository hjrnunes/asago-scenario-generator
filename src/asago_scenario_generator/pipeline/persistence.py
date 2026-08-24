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
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, JsonValue, field_validator, model_validator

from asago_scenario_generator.manifest import (
    ArtifactEntry,
    ArtifactRole,
    ManifestIntegrityError,
    atomic_write_text,
    build_artifact_entry,
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


# The inventory-validation predicates live in the private sibling module
# pipeline.persistence_validation; re-export them here so all existing
# import paths (including private helpers used by tests) keep working.
from asago_scenario_generator.pipeline.persistence_validation import (  # noqa: E402
    _check_durable_event_ids as _check_durable_event_ids,
    _check_durable_event_sequences as _check_durable_event_sequences,
    _attempt_ids as _attempt_ids,
    _candidate_ids as _candidate_ids,
    _check_unique_attempt_and_candidate_ids as _check_unique_attempt_and_candidate_ids,
    _index_target_trace_events as _index_target_trace_events,
    _target_trace_terminal_edges as _target_trace_terminal_edges,
    _transition_indexes_contiguous as _transition_indexes_contiguous,
    _check_target_transition_indexes as _check_target_transition_indexes,
    _CandidateTraceState as _CandidateTraceState,
    _check_target_candidate_trace as _check_target_candidate_trace,
    _revalidating_segment_invalid as _revalidating_segment_invalid,
    _check_revalidating_segment as _check_revalidating_segment,
    _check_exhausted_segment as _check_exhausted_segment,
    _check_active_segment as _check_active_segment,
    _legal_lifecycle_edges as _legal_lifecycle_edges,
    _generating_state_by_stage as _generating_state_by_stage,
    _check_lifecycle_edges as _check_lifecycle_edges,
    _stage_reference_invalid as _stage_reference_invalid,
    _stage_attempts_by_id as _stage_attempts_by_id,
    _attempts_by_id as _attempts_by_id,
    _check_stage_references as _check_stage_references,
    _repair_mismatches_attempt as _repair_mismatches_attempt,
    _subsequent_behavior_inputs as _subsequent_behavior_inputs,
    _check_repair_records as _check_repair_records,
    _stage_invocation_indexes_contiguous as _stage_invocation_indexes_contiguous,
    _stage_retry_indexes_not_monotonic as _stage_retry_indexes_not_monotonic,
    _check_stage_invocation_indexes as _check_stage_invocation_indexes,
    _generating_transitions_for as _generating_transitions_for,
    _stage_attempts_for as _stage_attempts_for,
    _generating_transition_count_mismatch as _generating_transition_count_mismatch,
    _decision_for_candidate as _decision_for_candidate,
    _later_candidate_events as _later_candidate_events,
    _unknown_terminal_adjacency as _unknown_terminal_adjacency,
    _unknown_terminal_edge_order as _unknown_terminal_edge_order,
    _unknown_outcome_decision as _unknown_outcome_decision,
    _single_unknown_invocation_violation as _single_unknown_invocation_violation,
    _single_quarantine_bundle_receipt as _single_quarantine_bundle_receipt,
    _no_later_stage_or_repair_events as _no_later_stage_or_repair_events,
    _unknown_terminal_trace_matches as _unknown_terminal_trace_matches,
    _unknown_terminal_decision_matches as _unknown_terminal_decision_matches,
    _is_exact_unknown_terminal as _is_exact_unknown_terminal,
    _check_unmatched_generating_transition as _check_unmatched_generating_transition,
    _generating_stage_pairing_mismatch as _generating_stage_pairing_mismatch,
    _check_generating_stage_pairing as _check_generating_stage_pairing,
    _check_generating_transition_traces as _check_generating_transition_traces,
    _candidate_stages_for as _candidate_stages_for,
    _check_stage_evidence_precedes_terminal as _check_stage_evidence_precedes_terminal,
    _check_terminal_precedes_decision as _check_terminal_precedes_decision,
    _next_target_transition_after as _next_target_transition_after,
    _check_decision_precedes_next_target_transition as _check_decision_precedes_next_target_transition,
    _check_postbehavior_admission_edge as _check_postbehavior_admission_edge,
    _check_admitting_edge_requires_gate_evidence as _check_admitting_edge_requires_gate_evidence,
    _check_gate_violations_match_terminal as _check_gate_violations_match_terminal,
    _admitted_missing_passing_gate_evidence as _admitted_missing_passing_gate_evidence,
    _check_admitted_requires_passing_gates as _check_admitted_requires_passing_gates,
    _causal_artifacts_for_decision as _causal_artifacts_for_decision,
    _expected_admission_snapshots as _expected_admission_snapshots,
    _check_admission_snapshot_digests as _check_admission_snapshot_digests,
    _check_admission_decision as _check_admission_decision,
    _check_terminal_decisions as _check_terminal_decisions,
    _receipt_keys as _receipt_keys,
    _decision_receipt_keys as _decision_receipt_keys,
    _receipt_inventories_mismatched as _receipt_inventories_mismatched,
    _check_receipt_inventories as _check_receipt_inventories,
    _causal_stage_artifacts as _causal_stage_artifacts,
    validate_v3_inventories as validate_v3_inventories,
    _check_v3_journal_unresolved as _check_v3_journal_unresolved,
    _v3_persistence_entries as _v3_persistence_entries,
    _v3_load_persistence_models as _v3_load_persistence_models,
    _check_v3_run_identity as _check_v3_run_identity,
    _v3_admitted_decisions as _v3_admitted_decisions,
    _v3_profile_applicability as _v3_profile_applicability,
    _v3_decision_gate_applicability_mismatch as _v3_decision_gate_applicability_mismatch,
    _check_v3_gate_applicability as _check_v3_gate_applicability,
    _v3_plan_by_candidate as _v3_plan_by_candidate,
    _v3_transition_plan_mismatch as _v3_transition_plan_mismatch,
    _check_v3_transition_in_plan as _check_v3_transition_in_plan,
    _check_v3_transitions_in_plan as _check_v3_transitions_in_plan,
    _v3_receipt_candidate_sets as _v3_receipt_candidate_sets,
    _check_v3_inventory_disjoint as _check_v3_inventory_disjoint,
    _v3_attempt_plan_mismatch as _v3_attempt_plan_mismatch,
    _check_v3_attempts_match_plan as _check_v3_attempts_match_plan,
    _v3_attempts_by_target as _v3_attempts_by_target,
    _v3_candidate_ids as _v3_candidate_ids,
    _v3_attempted_ids_by_target as _v3_attempted_ids_by_target,
    _check_v3_attempted_candidates_per_target as _check_v3_attempted_candidates_per_target,
    _v3_admitted_decision_ids as _v3_admitted_decision_ids,
    _v3_attempted_and_terminal_ids as _v3_attempted_and_terminal_ids,
    _check_v3_terminal_decision_sets as _check_v3_terminal_decision_sets,
    _v3_fallback_ranks_not_increasing as _v3_fallback_ranks_not_increasing,
    _check_v3_no_fallback_after_admission as _check_v3_no_fallback_after_admission,
    _v3_primary_candidate_not_first as _v3_primary_candidate_not_first,
    _check_v3_fallback_attempts as _check_v3_fallback_attempts,
    _check_v3_fallback_order as _check_v3_fallback_order,
    _v3_target_admitted_ids as _v3_target_admitted_ids,
    _check_v3_target_terminal_state as _check_v3_target_terminal_state,
    _v3_target_transitions as _v3_target_transitions,
    _check_v3_target_terminal_transition as _check_v3_target_terminal_transition,
    _check_v3_target_terminal_states as _check_v3_target_terminal_states,
    _v3_manifest_scenario_entries as _v3_manifest_scenario_entries,
    _v3_receipt_entries as _v3_receipt_entries,
    _check_v3_manifest_receipts as _check_v3_manifest_receipts,
    _v3_receipts_for as _v3_receipts_for,
    _admitted_receipt_roles_mismatch as _admitted_receipt_roles_mismatch,
    _check_v3_admitted_receipt_pairs as _check_v3_admitted_receipt_pairs,
    _check_v3_quarantined_receipts as _check_v3_quarantined_receipts,
    _v3_eval_scorecard_candidates as _v3_eval_scorecard_candidates,
    _v3_bundle_candidates as _v3_bundle_candidates,
    _v3_normal_scenario_candidates as _v3_normal_scenario_candidates,
    _check_v3_eval_and_role_scopes as _check_v3_eval_and_role_scopes,
    _v3_attempt_for as _v3_attempt_for,
    _v3_stage_attempts_for as _v3_stage_attempts_for,
    _v3_repairs_for as _v3_repairs_for,
    _check_v3_admitted_causal_evidence as _check_v3_admitted_causal_evidence,
    _v3_read_bundle as _v3_read_bundle,
    _v3_bundle_identity_mismatch as _v3_bundle_identity_mismatch,
    _v3_bundle_attempt_mismatch as _v3_bundle_attempt_mismatch,
    _v3_attempt_or_none as _v3_attempt_or_none,
    _v3_decision_for as _v3_decision_for,
    _check_v3_bundle_identity as _check_v3_bundle_identity,
    _check_v3_bundle_attempt as _check_v3_bundle_attempt,
    _check_v3_bundle_violations as _check_v3_bundle_violations,
    _check_v3_bundle_stage_evidence as _check_v3_bundle_stage_evidence,
    _check_v3_quarantine_bundles as _check_v3_quarantine_bundles,
    _check_v3_completed_status as _check_v3_completed_status,
    _violations as _violations,
)
