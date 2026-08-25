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


def _qualification_facts_valid(source: str | None, sha256: str | None) -> None:
    if (source is None) != (sha256 is None):
        raise ValueError(
            "qualification facts source and SHA-256 must be present together"
        )
    if source is not None:
        source_sha256 = hashlib.sha256(source.encode("utf-8")).hexdigest()
        if source_sha256 != sha256:
            raise ValueError("qualification facts source SHA-256 mismatch")


def _id_lists_sorted_unique(lists: tuple[list[str], ...]) -> None:
    if any(values != sorted(set(values)) for values in lists):
        raise ValueError("planning checkpoint ID lists must be sorted and unique")


def _ordered_unique_list(values: list[str]) -> None:
    if values != list(dict.fromkeys(values)):
        raise ValueError("planning checkpoint IDs must be ordered and unique")


def _fallback_lists_ordered_unique(
    fallback_candidate_ids: dict[str, list[str]],
) -> None:
    if any(ids != list(dict.fromkeys(ids)) for ids in fallback_candidate_ids.values()):
        raise ValueError("fallback candidate IDs must be ordered and unique")


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
        _qualification_facts_valid(
            self.qualification_facts_source, self.qualification_facts_sha256
        )
        _id_lists_sorted_unique(
            (
                self.projection_limitation_target_ids,
                self.uncovered_target_ids,
                self.attempted_candidate_ids,
                self.selection_limitation_target_ids,
            )
        )
        _ordered_unique_list(self.selected_candidate_ids)
        _fallback_lists_ordered_unique(self.fallback_candidate_ids)
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


def _queue_ids_unique(entry: object) -> None:
    ids = [choice.candidate_id for choice in entry.ordered_choices]
    if len(ids) != len(set(ids)):
        raise ValueError("ordered choices contain duplicate candidate IDs")
    if len(entry.attempted_candidate_ids) != len(set(entry.attempted_candidate_ids)):
        raise ValueError("attempted_candidate_ids contains duplicates")


def _queue_primary_identity_valid(entry: object) -> None:
    ids = [choice.candidate_id for choice in entry.ordered_choices]
    if entry.primary_candidate_id is not None and (
        not ids or ids[0] != entry.primary_candidate_id
    ):
        raise ValueError("primary candidate must be the first ordered choice")


def _queue_primary_required_valid(entry: object) -> None:
    ids = [choice.candidate_id for choice in entry.ordered_choices]
    if ids and entry.primary_candidate_id is None:
        raise ValueError("nonempty ordered choices require a primary candidate")


def _queue_primary_valid(entry: object) -> None:
    _queue_primary_identity_valid(entry)
    _queue_primary_required_valid(entry)


def _queue_attempted_prefix_valid(entry: object) -> None:
    ids = [choice.candidate_id for choice in entry.ordered_choices]
    if entry.attempted_candidate_ids != ids[: len(entry.attempted_candidate_ids)]:
        raise ValueError("attempted_candidate_ids must be the exact ordered prefix")


def _queue_empty_exhausted_valid(entry: object) -> None:
    if not entry.ordered_choices and entry.target_state is not TargetState.exhausted:
        raise ValueError("empty target queues must already be exhausted")


def _queue_admitted_attempted_valid(entry: object) -> None:
    if entry.admitted_candidate_id is not None and (
        entry.admitted_candidate_id not in entry.attempted_candidate_ids
    ):
        raise ValueError("admitted candidate must have been attempted")


def _queue_admitted_state_valid(entry: object) -> None:
    if entry.admitted_candidate_id is not None:
        if entry.target_state is not TargetState.admitted:
            raise ValueError("admitted candidate requires target_state=admitted")
        admitted_index = [
            choice.candidate_id for choice in entry.ordered_choices
        ].index(entry.admitted_candidate_id)
        if len(entry.attempted_candidate_ids) != admitted_index + 1:
            raise ValueError("admitted target cannot contain later attempts")
    elif entry.target_state is TargetState.admitted:
        raise ValueError("target_state=admitted requires admitted_candidate_id")


def _queue_selected_valid(entry: object) -> None:
    if (
        entry.target_state is TargetState.selected
        and entry.admitted_candidate_id is not None
    ):
        raise ValueError("selected target must be nonterminal and not admitted")


def _queue_exhausted_valid(entry: object) -> None:
    ids = [choice.candidate_id for choice in entry.ordered_choices]
    if entry.target_state is TargetState.exhausted:
        if (
            entry.admitted_candidate_id is not None
            or entry.attempted_candidate_ids != ids
        ):
            raise ValueError(
                "exhausted target requires all choices attempted and none admitted"
            )


def _expected_fallback_ids(entry: object, ids: list[str]) -> list[str]:
    if entry.target_state is TargetState.admitted:
        return []
    attempted = set(entry.attempted_candidate_ids)
    return [candidate_id for candidate_id in ids if candidate_id not in attempted]


def _fallbacks_exclude_attempted(entry: object) -> None:
    fallbacks = [choice.candidate_id for choice in entry.fallback_available]
    attempted = set(entry.attempted_candidate_ids)
    if attempted.intersection(fallbacks):
        raise ValueError("fallback_available must exclude attempted candidates")


def _fallbacks_preserve_order(entry: object) -> None:
    ids = [choice.candidate_id for choice in entry.ordered_choices]
    fallbacks = [choice.candidate_id for choice in entry.fallback_available]
    expected = _expected_fallback_ids(entry, ids)
    if fallbacks != expected:
        raise ValueError(
            "fallback_available must preserve unattempted ordered-choice order"
        )


def _fallbacks_match_choices(entry: object) -> None:
    ordered_by_id = {choice.candidate_id: choice for choice in entry.ordered_choices}
    if any(
        choice != ordered_by_id[choice.candidate_id]
        for choice in entry.fallback_available
    ):
        raise ValueError(
            "fallback_available entries must exactly equal their ordered choices"
        )


def _queue_fallbacks_valid(entry: object) -> None:
    _fallbacks_exclude_attempted(entry)
    _fallbacks_preserve_order(entry)
    _fallbacks_match_choices(entry)


def _queue_ranks_valid(entry: object) -> None:
    ranks = [choice.rank for choice in entry.ordered_choices]
    if ranks != list(range(len(ranks))):
        raise ValueError("ordered choice queue ranks must be contiguous from zero")


def _queue_target_match_valid(entry: object) -> None:
    if any(
        choice.entry_point_id != entry.entry_point_id
        for choice in entry.ordered_choices
    ):
        raise ValueError("every ordered choice must match its coverage target")


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
        _queue_ids_unique(self)
        _queue_primary_valid(self)
        _queue_attempted_prefix_valid(self)
        _queue_empty_exhausted_valid(self)
        _queue_admitted_attempted_valid(self)
        _queue_admitted_state_valid(self)
        _queue_selected_valid(self)
        _queue_exhausted_valid(self)
        _queue_fallbacks_valid(self)
        _queue_ranks_valid(self)
        _queue_target_match_valid(self)
        return self


def _target_ids_unique(targets: list[object]) -> None:
    target_ids = [target.effective_target_id for target in targets]
    if len(target_ids) != len(set(target_ids)):
        raise ValueError("coverage plan contains duplicate target IDs")


def _candidate_ids_unique(targets: list[object]) -> None:
    candidates = [
        choice.candidate_id for target in targets for choice in target.ordered_choices
    ]
    if len(candidates) != len(set(candidates)):
        raise ValueError("candidate IDs must be unique across coverage targets")


def _selection_limitations_valid(limitations: list[str], target_ids: list[str]) -> None:
    if len(limitations) != len(set(limitations)) or not set(limitations).issubset(
        target_ids
    ):
        raise ValueError(
            "selection limitations must uniquely reference coverage targets"
        )


def _completeness_evidence_valid(completeness: str, evidence_refs: list[str]) -> None:
    if completeness == "confirmed_complete" and not evidence_refs:
        raise ValueError("confirmed completeness requires evidence references")
    if completeness == "not_applicable" and evidence_refs:
        raise ValueError("not-applicable completeness forbids evidence references")


class CoveragePlanV2(StrictModel):
    schema_version: Literal["2"]
    completeness: Literal["not_applicable", "confirmed_complete"]
    evidence_refs: list[str]
    targets: list[CoverageTargetEntry]
    selection_limitation_target_ids: list[str]

    @model_validator(mode="after")
    def _unique_targets_and_candidates(self) -> CoveragePlanV2:
        _target_ids_unique(self.targets)
        _candidate_ids_unique(self.targets)
        target_ids = [target.effective_target_id for target in self.targets]
        _selection_limitations_valid(self.selection_limitation_target_ids, target_ids)
        _completeness_evidence_valid(self.completeness, self.evidence_refs)
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


def _result_failure_mutually_exclusive(result: Any, failure: Any) -> None:
    if result is not None and failure is not None:
        raise ValueError("stage attempt cannot contain both result and failure")


def _input_digests_valid(record: object) -> None:
    if record.input_sha256 != canonical_sha256(record.input):
        raise ValueError("stage input digest mismatch")
    if record.candidate_snapshot_sha256 != canonical_sha256(record.input.candidate):
        raise ValueError("candidate snapshot digest mismatch")
    if record.final_tree_snapshot_sha256 != record.input.final_tree_digest:
        raise ValueError("final-tree snapshot digest mismatch")


def _output_digest_valid(result: Any, output_sha256: str | None) -> None:
    expected_output = canonical_sha256(result) if result is not None else None
    if output_sha256 != expected_output:
        raise ValueError("stage output digest mismatch")


def _input_identity_valid(record: object) -> None:
    if (
        record.input.candidate_id != record.candidate_id
        or record.input.stage is not record.stage
        or record.input.invocation_index != record.invocation_index
        or record.input.owner_retry_index != record.owner_retry_index
    ):
        raise ValueError("stage input identity/index mismatch")


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
        _result_failure_mutually_exclusive(self.result, self.failure)
        _input_digests_valid(self)
        _output_digest_valid(self.result, self.output_sha256)
        _input_identity_valid(self)
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


def _path_component_safe(value: str) -> bool:
    path = PurePosixPath(value)
    return ".." in path.parts or "." in path.parts or "\\" in value


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
            or _path_component_safe(value)
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


def _admitted_flag_matches(status: object, admitted: bool) -> None:
    if admitted != (status is CandidateTerminalStatus.admitted):
        raise ValueError("admitted flag must match terminal candidate status")


def _gate_evidence_unique(gate_results: list[object]) -> None:
    evidence_ids = [gate.gate for gate in gate_results]
    if len(evidence_ids) != len(set(evidence_ids)):
        raise ValueError("admission evidence IDs must be unique")


def _exceptional_evidence_singleton(evidence_ids: list[object]) -> None:
    exceptional = set(evidence_ids) & EXCEPTIONAL_ADMISSION_EVIDENCE_IDS
    if exceptional and len(evidence_ids) != 1:
        raise ValueError("exceptional admission evidence must be a singleton")


def _admitted_canonical_evidence(admitted: bool, evidence_ids: list[object]) -> None:
    if admitted and set(evidence_ids) != set(NORMAL_POSTBEHAVIOR_EVIDENCE_IDS):
        raise ValueError("admitted decision requires canonical gate evidence")


def _admitted_gate_applicability(admitted: bool, gate_results: list[object]) -> None:
    if admitted and any(
        not gate.applicable
        for gate in gate_results
        if gate.gate not in CONDITIONALLY_APPLICABLE_EVIDENCE_IDS
    ):
        raise ValueError("intrinsic admitted evidence must be applicable")


def _authoritative_violations(gate_results: list[object]) -> list[object]:
    return [violation for gate in gate_results for violation in gate.violations]


def _category_diagnostics(gate_results: list[object]) -> list[object]:
    return [
        diagnostic
        for gate in gate_results
        if gate.gate in DIAGNOSTIC_BACKED_EVIDENCE_IDS
        for diagnostic in gate.diagnostics
    ]


def _diagnostics_copy_authoritative(gate_results: list[object]) -> None:
    authoritative = _authoritative_violations(gate_results)
    diagnostics = _category_diagnostics(gate_results)
    if any(diagnostic not in authoritative for diagnostic in diagnostics):
        raise ValueError("category diagnostic must copy an authoritative violation")


def _admitted_snapshot_digests(
    admitted: bool, snapshots: tuple[str | None, ...]
) -> None:
    if admitted and any(digest is None for digest in snapshots):
        raise ValueError("admitted decision requires all four snapshot digests")


def _receipt_roles_mismatched(
    receipts: list[object], expected_roles: set[object]
) -> bool:
    roles = {receipt.role for receipt in receipts}
    return roles != expected_roles or len(receipts) != len(expected_roles)


def _receipt_identity_mismatched(receipts: list[object], candidate_id: str) -> bool:
    return any(receipt.candidate_id != candidate_id for receipt in receipts)


def _admitted_scenario_ids(receipts: list[object]) -> set[str | None]:
    return {receipt.scenario_id for receipt in receipts}


def _terminal_receipt_violation(
    receipts: list[object], admitted: bool, candidate_id: str
) -> str | None:
    expected_roles = (
        {ArtifactRole.SCENARIO_YAML, ArtifactRole.SCENARIO_FEATURE}
        if admitted
        else {ArtifactRole.QUARANTINE_BUNDLE}
    )
    if _receipt_roles_mismatched(receipts, expected_roles):
        return "terminal receipts do not match candidate terminal status"
    if _receipt_identity_mismatched(receipts, candidate_id):
        return "terminal receipts do not match candidate terminal status"
    if admitted and len(_admitted_scenario_ids(receipts)) != 1:
        return "admitted terminal receipts require one scenario_id"
    return None


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
        _verify_candidate_attempt_hashes(self.candidate_attempts)
        _verify_transition_hashes(self.transitions)
        _verify_stage_attempt_hashes(self.stage_attempts)
        _verify_repair_hashes(self.repairs)
        _verify_admission_decision_hashes(self.admission_decisions)


def _plan_link_valid(journal: object) -> None:
    expected = hashlib.sha256(canonical_json_bytes(journal.coverage_plan)).hexdigest()
    if journal.finalization_inventory.coverage_plan_sha256 != expected:
        raise ValueError("journal inventory does not reference journal coverage plan")


def _latest_terminal_event(inventory: FinalizationInventoryV1) -> object | None:
    events = [
        *inventory.candidate_attempts,
        *inventory.stage_attempts,
        *inventory.transitions,
        *inventory.repairs,
        *inventory.admission_decisions,
    ]
    latest = max(events, key=lambda item: item.sequence, default=None)
    if isinstance(latest, AdmissionDecisionRecord):
        return latest
    return None


def _no_terminal_evidence_valid(journal: object) -> None:
    if (
        journal.admitted_publication is not None
        or journal.quarantine_bundle is not None
    ):
        raise ValueError(
            "journal terminal evidence requires the latest terminal decision"
        )


def _admitted_journal_valid(journal: object, terminal: object) -> None:
    if journal.admitted_publication is None or journal.quarantine_bundle is not None:
        raise ValueError("admitted journal decision requires exactly one publication")
    if terminal.terminal_receipts != _publication_receipts(
        journal.admitted_publication
    ):
        raise ValueError(
            "journal publication does not match terminal decision receipts"
        )


def _journal_attempt_for(journal: object, candidate_id: str) -> object | None:
    return next(
        (
            item
            for item in journal.finalization_inventory.candidate_attempts
            if item.candidate_id == candidate_id
        ),
        None,
    )


def _quarantine_bundle_fields_mismatched(
    bundle: object, attempt: object, terminal: object, run_id: str
) -> bool:
    return (
        bundle.run_id != run_id
        or bundle.attempt_id != attempt.attempt_id
        or bundle.candidate_id != terminal.candidate_id
        or bundle.target_entry_point_id != attempt.target_entry_point_id
        or bundle.violations != terminal.violations
    )


def _quarantine_journal_valid(journal: object, terminal: object) -> None:
    if journal.quarantine_bundle is None or journal.admitted_publication is not None:
        raise ValueError(
            "non-admitted journal decision requires exactly one quarantine bundle"
        )
    attempt = _journal_attempt_for(journal, terminal.candidate_id)
    if attempt is None:
        raise ValueError("journal quarantine bundle does not match terminal decision")
    if _quarantine_bundle_fields_mismatched(
        journal.quarantine_bundle,
        attempt,
        terminal,
        journal.finalization_inventory.run_id,
    ):
        raise ValueError("journal quarantine bundle does not match terminal decision")
    if terminal.terminal_receipts != [_quarantine_receipt(journal.quarantine_bundle)]:
        raise ValueError("journal quarantine bundle does not match terminal decision")


class PersistenceJournalV1(StrictModel):
    """Recoverable two-document state update; never part of a final manifest."""

    schema_version: Literal["1"]
    coverage_plan: CoveragePlanV2
    finalization_inventory: FinalizationInventoryV1
    quarantine_bundle: QuarantineBundleV1 | None = None
    admitted_publication: AdmittedArtifactPublication | None = None

    @model_validator(mode="after")
    def _hash_link(self) -> PersistenceJournalV1:
        _plan_link_valid(self)
        terminal = _latest_terminal_event(self.finalization_inventory)
        if terminal is None:
            _no_terminal_evidence_valid(self)
            return self
        if terminal.admitted:
            _admitted_journal_valid(self, terminal)
        else:
            _quarantine_journal_valid(self, terminal)
        return self


def _unsafe_filename_characters(value: str) -> bool:
    return any(char in value for char in ("/", "\\"))


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
        if not value or _unsafe_filename_characters(value) or value in {".", ".."}:
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


def _parse_admitted_yaml(yaml_text: str) -> Any:
    try:
        return yaml.safe_load(yaml_text)
    except yaml.YAMLError as exc:
        raise ValueError(f"admitted YAML is invalid: {exc}") from exc


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
        document = _parse_admitted_yaml(self.yaml_text)
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


def _canonical_path_mismatch(rel_path: str, path: PurePosixPath) -> bool:
    return path.is_absolute() or path.as_posix() != rel_path or "\\" in rel_path


def _unsafe_path_parts(parts: tuple[str, ...]) -> bool:
    return any(part in {"", ".", ".."} for part in parts)


def _canonical_parts(rel_path: str) -> tuple[str, ...]:
    path = PurePosixPath(rel_path)
    if (
        not rel_path
        or _canonical_path_mismatch(rel_path, path)
        or _unsafe_path_parts(path.parts)
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


def _semantic_outcome(semantic: Any) -> tuple[str, list[str]]:
    if semantic is None:
        return "missing_semantic_evidence", []
    attempts = semantic.get("attempts", [])
    latest = attempts[-1] if attempts else {}
    outcome = str(latest.get("result") or "missing_attempt_result")
    warnings = [str(value) for value in semantic.get("warnings", [])]
    return outcome, warnings


def _stage_record(item: object) -> tuple[dict[str, Any], str, str, list[str]]:
    carrier = item.call if item.call is not None else item.failure
    semantic = carrier.semantic_evidence if carrier is not None else None
    outcome, warnings = _semantic_outcome(semantic)
    record = {
        "candidate_id": item.candidate_id,
        "stage": item.stage.value,
        "invocation_index": item.invocation_index,
        "outcome": outcome,
        "semantic_evidence": semantic,
    }
    return record, item.candidate_id, item.stage.value, warnings


def _candidate_stage_entry(
    candidate_id: str, decisions: dict[str, object]
) -> dict[str, Any]:
    decision = decisions.get(candidate_id)
    return {
        "admitted": bool(decision and decision.admitted),
        "complete_provider_semantics": False,
        "presentation_fallbacks": [],
        "stages": {},
    }


def _fallback_warnings(warnings: list[str], existing: list[str]) -> list[str]:
    return [
        warning
        for warning in warnings
        if warning.startswith("presentation_fallback:") and warning not in existing
    ]


def _complete_provider_semantics(
    candidate: dict[str, Any], required_stages: tuple[str, ...]
) -> bool:
    return all(
        candidate["stages"].get(stage) == "accepted" for stage in required_stages
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
        record, candidate_id, stage_name, warnings = _stage_record(item)
        records.append(record)
        candidate = candidates.setdefault(
            candidate_id, _candidate_stage_entry(candidate_id, decisions)
        )
        candidate["stages"][stage_name] = record["outcome"]
        candidate["presentation_fallbacks"].extend(
            _fallback_warnings(warnings, candidate["presentation_fallbacks"])
        )
    for candidate in candidates.values():
        candidate["complete_provider_semantics"] = _complete_provider_semantics(
            candidate, required_stages
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


def _expected_fallback_queues(plan: CoveragePlanV2) -> dict[str, list[str]]:
    return {
        target.effective_target_id: [
            choice.candidate_id for choice in target.ordered_choices
        ]
        for target in plan.targets
    }


def _expected_primaries(plan: CoveragePlanV2) -> dict[str, str]:
    return {
        target.effective_target_id: target.primary_candidate_id
        for target in plan.targets
        if target.primary_candidate_id is not None
    }


def _checkpoint_fallbacks_match(
    checkpoint: PlanningCheckpointV1, expected: dict[str, list[str]]
) -> None:
    if checkpoint.fallback_candidate_ids != expected:
        raise ManifestIntegrityError(
            "planning checkpoint fallback queues mismatch plan"
        )


def _checkpoint_primaries_match(
    checkpoint: PlanningCheckpointV1, expected: dict[str, str]
) -> None:
    if checkpoint.primary_candidate_ids != expected:
        raise ManifestIntegrityError("planning checkpoint primaries mismatch plan")


def _checkpoint_selection_matches(
    checkpoint: PlanningCheckpointV1, primaries: dict[str, str]
) -> None:
    if sorted(checkpoint.selected_candidate_ids) != sorted(primaries.values()):
        raise ManifestIntegrityError("planning checkpoint selection mismatch plan")


def _checkpoint_attempted_matches(checkpoint: PlanningCheckpointV1) -> None:
    if checkpoint.attempted_candidate_ids != sorted(checkpoint.selected_candidate_ids):
        raise ManifestIntegrityError("planning checkpoint attempted selection mismatch")


def _checkpoint_uncovered_matches(
    checkpoint: PlanningCheckpointV1, plan: CoveragePlanV2
) -> None:
    if checkpoint.uncovered_target_ids != sorted(
        target.effective_target_id
        for target in plan.targets
        if not target.ordered_choices
    ):
        raise ManifestIntegrityError(
            "planning checkpoint uncovered targets mismatch plan"
        )


def _checkpoint_limitations_match(
    checkpoint: PlanningCheckpointV1, plan: CoveragePlanV2
) -> None:
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


def validate_planning_checkpoint(
    checkpoint: PlanningCheckpointV1, plan: CoveragePlanV2
) -> None:
    """Bind immutable completion-tail evidence to the durable target plan."""
    _checkpoint_fallbacks_match(checkpoint, _expected_fallback_queues(plan))
    expected_primaries = _expected_primaries(plan)
    _checkpoint_primaries_match(checkpoint, expected_primaries)
    _checkpoint_selection_matches(checkpoint, expected_primaries)
    _checkpoint_attempted_matches(checkpoint)
    _checkpoint_uncovered_matches(checkpoint, plan)
    _checkpoint_limitations_match(checkpoint, plan)


def _quarantine_path_valid(entry: ArtifactEntry) -> bool:
    expected = PurePosixPath(entry.path)
    return not (
        expected.as_posix() != entry.path
        or ".." in expected.parts
        or len(expected.parts) != 2
        or expected.parts[0] != "quarantine"
    )


def read_quarantine_bundle(run_dir: Path, entry: ArtifactEntry) -> QuarantineBundleV1:
    if not _quarantine_path_valid(entry):
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


def _verified_expected_entry(
    entry: ArtifactEntry | None,
    role: ArtifactRole,
    expected_path: str,
) -> None:
    if entry is not None:
        if entry.role is not role or entry.path != expected_path:
            raise ManifestIntegrityError(
                f"{role.value} role/path mismatch: {entry.role.value} {entry.path}"
            )


def _read_verified_content(
    run_dir: Path, entry: ArtifactEntry | None, expected_path: str
) -> bytes:
    if entry is None:
        return _safe_read(run_dir, expected_path)
    content = _safe_read(run_dir, expected_path)
    if hashlib.sha256(content).hexdigest() != entry.sha256:
        raise ManifestIntegrityError(f"Hash mismatch for {entry.path}")
    return content


def _read_model(
    run_dir: Path,
    entry: ArtifactEntry | None,
    role: ArtifactRole,
    expected_path: str,
    model_type: type[StrictModel],
) -> Any:
    _verified_expected_entry(entry, role, expected_path)
    try:
        return model_type.model_validate_json(
            _read_verified_content(run_dir, entry, expected_path)
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


def _prompt_record(value: Any) -> PromptRecord | None:
    if value.system_prompt is None and value.user_prompt is None:
        return None
    return PromptRecord(
        system_prompt=value.system_prompt,
        user_prompt=value.user_prompt,
    )


def _semantic_json(value: Any) -> JsonValue | None:
    return _json_value(value.as_dict()) if value is not None else None


def _attempt_failure(value: StageAttemptFailure) -> StageAttemptFailureRecord:
    prompt = _prompt_record(value)
    return StageAttemptFailureRecord(
        call_name=value.call_name.value,
        exception_type=value.exception_type,
        detail=value.detail,
        phase=value.phase,
        invoked=value.invoked,
        code=value.code,
        retryable=value.retryable,
        semantic_evidence=_semantic_json(value.semantic_evidence),
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


def _violation_record(value: Any) -> ViolationRecord:
    owner = getattr(value, "owner", None)
    code = getattr(value, "code", "invalid")
    if isinstance(code, Enum):
        serialized_code = code.value
    elif isinstance(code, str):
        serialized_code = code
    else:
        raise TypeError("violation code must be a string or enum")
    return ViolationRecord(
        code=serialized_code,
        detail=value.detail,
        owner=owner,
        retryable=getattr(value, "retryable", owner is not None),
    )


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
            violations=[_violation_record(v) for v in gate.violations],
            diagnostics=[_violation_record(d) for d in gate.diagnostics],
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


def _attempted_ids_for(target_id: str, attempts: list[object]) -> list[str]:
    return [
        item.candidate_id
        for item in sorted(attempts, key=lambda item: item.sequence)
        if item.target_entry_point_id == target_id
    ]


def _admitted_id_for(attempted: list[str], decisions: dict[str, object]) -> str | None:
    return next(
        (
            candidate_id
            for candidate_id in attempted
            if candidate_id in decisions and decisions[candidate_id].admitted
        ),
        None,
    )


def _target_terminal(attempted: list[str], decisions: dict[str, object]) -> bool:
    return bool(attempted) and all(
        candidate_id in decisions for candidate_id in attempted
    )


def _target_state_and_fallback(
    attempted: list[str],
    choice_ids: list[str],
    target: CoverageTargetEntry,
    terminal: bool,
    admitted: str | None,
) -> tuple[TargetState, list[QualifiedCandidateRef]]:
    if admitted is not None:
        return TargetState.admitted, []
    if (attempted == choice_ids and terminal) or not choice_ids:
        return TargetState.exhausted, []
    return TargetState.selected, target.ordered_choices[len(attempted) :]


def _fsync_dir(run_dir: Path) -> None:
    dir_fd = os.open(run_dir, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def _next_transition_index(transitions: list[object]) -> int:
    return max(item.index for item in transitions) + 1


def _refresh_state(
    adapter: object, next_inventory: FinalizationInventoryV1, next_plan: CoveragePlanV2
) -> None:
    adapter.inventory = next_inventory
    adapter.coverage_plan = next_plan
    adapter._events = {
        item.event_id: item.payload_sha256
        for item in [
            *next_inventory.candidate_attempts,
            *next_inventory.stage_attempts,
            *next_inventory.transitions,
            *next_inventory.repairs,
            *next_inventory.admission_decisions,
        ]
    }


def _stage_evidence_parts(
    evidence: object,
) -> tuple[
    StageCallEvidenceRecord | None,
    StageAttemptFailureRecord | None,
    PromptRecord | None,
]:
    if isinstance(evidence, StageCallEvidence):
        call = _call_evidence(evidence)
        prompt = PromptRecord(
            system_prompt=call.result.system_prompt,
            user_prompt=call.result.user_prompt,
        )
        return call, None, prompt
    if isinstance(evidence, StageAttemptFailure):
        failure = _attempt_failure(evidence)
        return None, failure, failure.prompt
    raise TypeError(
        "stage persistence requires StageCallEvidence or StageAttemptFailure"
    )


def _stage_input_record(
    invocation: object,
    candidate: JsonValue,
    prompt: PromptRecord | None,
    visible_artifacts: dict[str, Any],
) -> StageInputRecord:
    return StageInputRecord(
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


def _stage_attempt_payload(
    attempt_id: str,
    input_payload: dict[str, Any],
    call: StageCallEvidenceRecord | None,
    failure: StageAttemptFailureRecord | None,
    output: JsonValue | None,
    violations: list[object],
) -> dict[str, Any]:
    return {
        "attempt_id": attempt_id,
        "input": input_payload,
        "call": call.model_dump(mode="json") if call else None,
        "failure": failure.model_dump(mode="json") if failure else None,
        "result": output,
        "violations": [
            item.model_dump(mode="json") for item in _violations(violations)
        ],
    }


def _call_log_entry(
    invocation: object, attempt_id: str, evidence: object
) -> dict[str, Any]:
    """Build a simple dict entry from the available data for calls.jsonl."""
    return {
        "call": evidence.call_name.value,
        "candidate_id": invocation.candidate_id,
        "stage": invocation.stage.value,
        "attempt_id": attempt_id,
        "retry_reason": invocation.retry_reason,
        "retry_control": _retry_control(invocation.retry_control),
        "total_request_budget": invocation.total_request_budget,
    }


def _llm_log_fields(llm_result: object, request_controls: Any) -> dict[str, Any]:
    return {
        "system_prompt": llm_result.system_prompt,
        "user_prompt": llm_result.user_prompt,
        "response": _pipeline_log_response(llm_result),
        "prompt_tokens": llm_result.prompt_tokens,
        "completion_tokens": llm_result.completion_tokens,
        "duration_ms": llm_result.duration_ms,
        "request_controls": request_controls,
    }


def _failure_evidence_log_entry(evidence: object, entry: dict[str, Any]) -> None:
    if evidence.result is not None:
        llm_result = evidence.result
        entry.update(
            _llm_log_fields(
                llm_result,
                evidence.request_controls or llm_result.request_controls,
            )
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
    entry["semantic_evidence"] = _semantic_json(evidence.semantic_evidence)
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


def _call_log_entry_for(evidence: object, entry: dict[str, Any]) -> None:
    if isinstance(evidence, StageCallEvidence):
        llm_result = evidence.result
        entry.update(_llm_log_fields(llm_result, llm_result.request_controls))
        entry["semantic_evidence"] = (
            evidence.semantic_evidence.as_dict()
            if evidence.semantic_evidence is not None
            else None
        )
        return
    _failure_evidence_log_entry(evidence, entry)


def _expected_admitted(status: object) -> bool:
    return status is CandidateTerminalStatus.admitted


def _admission_agreement_valid(result: object, expected_admitted: bool) -> None:
    if result.admission is not None and result.admission.admitted != expected_admitted:
        raise TypeError("terminal status and AdmissionDecision.admitted must agree")


def _admitted_payload(
    result: object, admission_value: Any
) -> tuple[AdmittedTerminalPayload, PostbehaviorAdmissionReport]:
    if type(admission_value) is not AdmittedTerminalPayload:
        raise TypeError("admitted result requires typed report and publication payload")
    terminal_payload = admission_value
    return terminal_payload, terminal_payload.report


def _rejection_report(
    result: object, admission_value: Any
) -> PostbehaviorAdmissionReport | None:
    if result.admission is None:
        return None
    if type(admission_value) is not PostbehaviorAdmissionReport:
        raise TypeError("postbehavior rejection requires PostbehaviorAdmissionReport")
    return admission_value


def _report_violations_agree(
    gate_results: list[GateResultRecord], serialized_violations: list[ViolationRecord]
) -> None:
    if [
        violation for gate in gate_results for violation in gate.violations
    ] != serialized_violations:
        raise TypeError("typed admission report and terminal violations must agree")


def _admitted_gate_report_valid(
    gate_results: list[GateResultRecord],
    serialized_violations: list[ViolationRecord],
) -> None:
    if (
        not gate_results
        or any(not gate.passed for gate in gate_results)
        or serialized_violations
    ):
        raise TypeError("admitted result requires nonempty passing gate report")


def _terminal_report_for(
    result: object, admission_value: Any
) -> tuple[AdmittedTerminalPayload | None, PostbehaviorAdmissionReport | None]:
    if result.status is CandidateTerminalStatus.admitted:
        return _admitted_payload(result, admission_value)
    return None, _rejection_report(result, admission_value)


def _gate_records_and_agreement(
    report: PostbehaviorAdmissionReport | None,
    serialized_violations: list[ViolationRecord],
) -> list[GateResultRecord]:
    if report is None:
        return []
    gate_results = _gate_report_records(report)
    _report_violations_agree(gate_results, serialized_violations)
    return gate_results


def _admission_payload(
    result: object, candidate_id: str
) -> tuple[
    AdmittedTerminalPayload | None,
    PostbehaviorAdmissionReport | None,
    list[GateResultRecord],
    list[ViolationRecord],
    bool,
]:
    """Extract and validate the typed terminal evidence for one decision."""
    if result.candidate_id != candidate_id:
        raise ValueError("candidate terminal result identity mismatch")
    admission_value = result.admission.value if result.admission is not None else None
    expected_admitted = _expected_admitted(result.status)
    _admission_agreement_valid(result, expected_admitted)
    terminal_payload, report = _terminal_report_for(result, admission_value)
    serialized_violations = _violations(result.violations)
    gate_results = _gate_records_and_agreement(report, serialized_violations)
    if expected_admitted:
        _admitted_gate_report_valid(gate_results, serialized_violations)
    return (
        terminal_payload,
        report,
        gate_results,
        serialized_violations,
        expected_admitted,
    )


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


def _visible_artifact_map(invocation: object) -> dict[str, Any]:
    return {
        stage.value: _json_value(invocation.artifacts.get(stage))
        for stage in GeneratedStage
        if invocation.artifacts.get(stage) is not None
    }


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
        attempts = sorted(inventory.candidate_attempts, key=lambda item: item.sequence)
        next_targets: list[CoverageTargetEntry] = []
        for target in self.coverage_plan.targets:
            attempted = _attempted_ids_for(target.effective_target_id, attempts)
            admitted = _admitted_id_for(attempted, decisions)
            choice_ids = [item.candidate_id for item in target.ordered_choices]
            terminal = _target_terminal(attempted, decisions)
            state, fallback = _target_state_and_fallback(
                attempted, choice_ids, target, terminal, admitted
            )
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
        _refresh_state(self, next_inventory, next_plan)

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

    def _candidate_evidence(
        self,
        next_inventory: FinalizationInventoryV1,
        candidate_id: str,
        candidate_attempt: CandidateAttemptRecord,
    ) -> tuple[list[StageAttemptRecord], dict[GeneratedStage, Any]]:
        stages = _candidate_stages(next_inventory, candidate_id)
        planned_choice = _planned_choice_for(self.coverage_plan, candidate_id)
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


def _empty_inventory(run_id: str, coverage_plan_sha256: str) -> FinalizationInventoryV1:
    return FinalizationInventoryV1(
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


def _bootstrap_fresh(run_dir: Path, run_id: str, coverage_plan: CoveragePlanV2) -> None:
    coverage_plan_sha256 = hashlib.sha256(
        canonical_json_bytes(coverage_plan)
    ).hexdigest()
    inventory = _empty_inventory(run_id, coverage_plan_sha256)
    journal = PersistenceJournalV1(
        schema_version="1",
        coverage_plan=coverage_plan,
        finalization_inventory=inventory,
    )
    _write_model(run_dir, ".finalization-state.json", journal)
    write_finalization_inventory(run_dir, inventory)
    write_coverage_plan(run_dir, coverage_plan)
    (run_dir / ".finalization-state.json").unlink()
    _fsync_dir(run_dir)


def _recovered_or_validated_plan(
    run_dir: Path, run_id: str, coverage_plan: CoveragePlanV2
) -> CoveragePlanV2:
    recovered_plan = recover_finalization_journal(run_dir, expected_run_id=run_id)
    if recovered_plan is not None:
        coverage_plan = recovered_plan
    return CoveragePlanV2.model_validate(coverage_plan.model_dump(mode="python"))


def _persisted_plan_check(run_dir: Path, coverage_plan: CoveragePlanV2) -> None:
    persisted_plan = read_coverage_plan(run_dir)
    if persisted_plan != coverage_plan:
        raise ManifestIntegrityError(
            "Supplied coverage plan differs from persisted plan"
        )


def _persisted_inventory_check(
    run_dir: Path, run_id: str, coverage_plan_sha256: str
) -> FinalizationInventoryV1:
    inventory = read_finalization_inventory(Path(run_dir))
    if (
        inventory.run_id != run_id
        or inventory.coverage_plan_sha256 != coverage_plan_sha256
    ):
        raise ManifestIntegrityError(
            "Existing finalization inventory identity mismatch"
        )
    return inventory


def make_finalization_persistence_adapter(
    run_dir: Path,
    *,
    run_id: str,
    coverage_plan: CoveragePlanV2,
) -> FinalizationPersistenceAdapter:
    """Phase 5 factory; creates no runner coupling and activates no manifest version."""

    run_dir = Path(run_dir)
    coverage_plan = _recovered_or_validated_plan(run_dir, run_id, coverage_plan)
    coverage_plan_sha256 = hashlib.sha256(
        canonical_json_bytes(coverage_plan)
    ).hexdigest()
    plan_path = run_dir / "coverage-plan.json"
    inventory_path = run_dir / "finalization-inventory.json"
    if not plan_path.exists() and not inventory_path.exists():
        _bootstrap_fresh(run_dir, run_id, coverage_plan)
    if plan_path.exists():
        _persisted_plan_check(run_dir, coverage_plan)
    else:
        write_coverage_plan(run_dir, coverage_plan)
    if inventory_path.exists():
        inventory = _persisted_inventory_check(run_dir, run_id, coverage_plan_sha256)
    else:
        inventory = _empty_inventory(run_id, coverage_plan_sha256)
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
