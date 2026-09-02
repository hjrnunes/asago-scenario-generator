"""Read-only manifest-v3 finalization inventory records.

The recoverable publication journal and terminal publication payload belonged
to the retired finalization writer.  Historical manifest validation needs only
the immutable inventory and quarantine-bundle records retained here.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field, JsonValue, field_validator, model_validator

from asago_scenario_generator.pipeline.finalization_contracts import (
    GeneratedStage,
)
from .persistence_artifacts import ArtifactReceipt
from .persistence_common import SHA256_PATTERN, canonical_sha256
from .persistence_decisions import (
    AdmissionDecisionRecord,
    _verify_admission_decision_hashes,
    _verify_candidate_attempt_hashes,
    _verify_repair_hashes,
    _verify_stage_attempt_hashes,
    _verify_transition_hashes,
)
from .persistence_models import (
    CandidateAttemptRecord,
    ParsimonyRepairRecord,
    StageAttemptRecord,
    TransitionRecord,
    ViolationRecord,
)
from .persistence_plan import StrictModel


def _validate_inventory(inventory: object) -> None:
    """Run the pure inventory validator lazily to keep model imports acyclic."""
    from asago_scenario_generator.pipeline import persistence_validation as validation

    events = [
        *inventory.candidate_attempts,
        *inventory.stage_attempts,
        *inventory.transitions,
        *inventory.repairs,
        *inventory.admission_decisions,
    ]
    validation._check_durable_event_ids(events)
    validation._check_durable_event_sequences(events)
    validation._check_unique_attempt_and_candidate_ids(
        inventory.candidate_attempts, inventory.stage_attempts
    )
    transitions_by_target, attempts_by_target = validation._index_target_trace_events(
        inventory.transitions, inventory.candidate_attempts
    )
    terminal_edges = validation._target_trace_terminal_edges(
        transitions_by_target, attempts_by_target
    )
    validation._check_lifecycle_edges(inventory.transitions)
    validation._check_stage_references(
        inventory.candidate_attempts, inventory.stage_attempts
    )
    validation._check_repair_records(
        inventory.repairs, inventory.candidate_attempts, inventory.stage_attempts
    )
    validation._check_stage_invocation_indexes(inventory.stage_attempts)
    validation._check_generating_transition_traces(
        inventory.candidate_attempts,
        inventory.transitions,
        inventory.stage_attempts,
        inventory.repairs,
        inventory.admission_decisions,
        terminal_edges,
    )
    validation._check_terminal_decisions(
        inventory.candidate_attempts,
        transitions_by_target,
        inventory.stage_attempts,
        inventory.repairs,
        inventory.admission_decisions,
        terminal_edges,
    )
    validation._check_receipt_inventories(
        inventory.admission_decisions,
        inventory.admitted_inventory,
        inventory.quarantine_inventory,
    )


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
        _validate_inventory(self)
        self._verify_event_hashes()
        return self

    def _verify_event_hashes(self) -> None:
        _verify_candidate_attempt_hashes(self.candidate_attempts)
        _verify_transition_hashes(self.transitions)
        _verify_stage_attempt_hashes(self.stage_attempts)
        _verify_repair_hashes(self.repairs)
        _verify_admission_decision_hashes(self.admission_decisions)


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


FinalizationInventoryV1.model_rebuild(_types_namespace=globals())
QuarantineBundleV1.model_rebuild(_types_namespace=globals())
