"""Finalization inventory and recoverable publication-journal contracts."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Literal

import yaml
from pydantic import Field, JsonValue, field_validator, model_validator

from asago_scenario_generator.manifest import ArtifactRole
from asago_scenario_generator.pipeline.finalization_contracts import (
    GeneratedStage,
)
from asago_scenario_generator.pipeline.finalization_admission import (
    PostbehaviorAdmissionReport,
)
from .persistence_artifacts import ArtifactReceipt
from .persistence_common import SHA256_PATTERN, canonical_json_bytes, canonical_sha256
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
from .persistence_plan import CoveragePlanV2, StrictModel


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


FinalizationInventoryV1.model_rebuild(_types_namespace=globals())
QuarantineBundleV1.model_rebuild(_types_namespace=globals())
AdmittedArtifactPublication.model_rebuild(_types_namespace=globals())
PersistenceJournalV1.model_rebuild(_types_namespace=globals())
