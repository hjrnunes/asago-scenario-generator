"""Durable stage evidence and admission-gate record contracts."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field, JsonValue, model_validator

from asago_scenario_generator.pipeline.finalization_contracts import (
    MAX_COMPLETION_LENGTH_RETRIES,
    MAX_OWNER_RETRIES,
    GeneratedStage,
    LifecycleState,
)
from asago_scenario_generator.pipeline.finalization_gates import (
    DIAGNOSTIC_BACKED_EVIDENCE_IDS,
    AdmissionEvidenceId,
)
from .persistence_common import SHA256_PATTERN, canonical_sha256
from .persistence_plan import StrictModel


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
