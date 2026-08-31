"""Closed contracts for the offline Phase 3 STPA challenge ledger."""

from __future__ import annotations

import json
from typing import Annotated, Any, Literal

import yaml
from pydantic import Field, model_validator

from asago_scenario_generator.models.canonical import (
    ClosedCanonicalModel,
    canonical_json_bytes,
    canonical_json_text,
    compute_framed_digest,
    unique_sorted_strings,
)
from asago_scenario_generator.models.hybrid_coverage import (
    ArtifactPin,
    Digest,
    HYBRID_COVERAGE_ASSESSMENT_SCHEMA_VERSION,
    ObligationId,
    StructuralDisposition,
    TraceReference,
    UcaType,
    compute_matrix_row_id,
)

STPA_CHALLENGE_LEDGER_SCHEMA_VERSION = "stpa-obligation-challenge-ledger-v1"
STPA_CHALLENGE_LEDGER_DIGEST_DOMAIN = (
    "asago-scenario-generator:stpa-obligation-challenge-ledger:v1"
)
STPA_CHALLENGE_ID_DOMAIN = "asago-scenario-generator:stpa-obligation-challenge:v1"
EXPLICIT_PRIORITY_POLICY_VERSION = "explicit-priority-v1"

ChallengeId = Annotated[str, Field(pattern=r"^challenge:v1:[0-9a-f]{64}$")]
SelectionStatus = Literal["selected", "not_selected_budget"]


class _ChallengeModel(ClosedCanonicalModel):
    """Common closed and immutable challenge-ledger model configuration."""


class ChallengeEligibility(_ChallengeModel):
    """One explicitly approved obligation/STPA-slot challenge target."""

    obligation_id: ObligationId
    slot_id: str = Field(min_length=1)
    priority: int = Field(ge=0, strict=True)
    rationale: str = Field(min_length=1)
    evidence_refs: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def canonicalize_evidence(self) -> "ChallengeEligibility":
        object.__setattr__(
            self,
            "evidence_refs",
            unique_sorted_strings(self.evidence_refs, "evidence_refs"),
        )
        return self


class OriginalStpaDecision(_ChallengeModel):
    """Immutable snapshot of the STPA decision before reconsideration."""

    row_id: str = Field(pattern=r"^hca-struct:v1:[0-9a-f]{64}$")
    slot_id: str = Field(min_length=1)
    controller_id: str = Field(min_length=1)
    control_action_id: str = Field(min_length=1)
    uca_type: UcaType
    disposition: StructuralDisposition
    ica_ids: tuple[str, ...] = ()
    evidence: tuple[str, ...] = Field(min_length=1)
    trace_refs: tuple[TraceReference, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_decision(self) -> "OriginalStpaDecision":
        object.__setattr__(
            self, "ica_ids", unique_sorted_strings(self.ica_ids, "ica_ids")
        )
        object.__setattr__(
            self, "evidence", unique_sorted_strings(self.evidence, "evidence")
        )
        traces = tuple(
            sorted(
                self.trace_refs,
                key=lambda trace: canonical_json_bytes(trace.model_dump(mode="json")),
            )
        )
        trace_identities = tuple(
            (
                trace.artifact_id,
                trace.schema_version,
                trace.semantic_digest,
                trace.record_id,
            )
            for trace in traces
        )
        if len(trace_identities) != len(set(trace_identities)):
            raise ValueError("original STPA decision traces must be unique")
        object.__setattr__(self, "trace_refs", traces)
        if self.row_id != compute_matrix_row_id("struct", self.slot_id):
            raise ValueError("original structural row identity does not match slot")
        if (self.disposition == "ica") != bool(self.ica_ids):
            raise ValueError("original STPA disposition contradicts ICA identities")
        return self


class ChallengeOutcome(_ChallengeModel):
    """One completed STPA reconsideration result with typed evidence."""

    disposition: Literal["ica", "justified_na", "unresolved"]
    ica_ids: tuple[str, ...] = ()
    rationale: str = Field(min_length=1)
    evidence_refs: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_outcome(self) -> "ChallengeOutcome":
        object.__setattr__(
            self, "ica_ids", unique_sorted_strings(self.ica_ids, "ica_ids")
        )
        object.__setattr__(
            self,
            "evidence_refs",
            unique_sorted_strings(self.evidence_refs, "evidence_refs"),
        )
        if self.disposition == "ica" and not self.ica_ids:
            raise ValueError("ICA outcome requires at least one ICA identity")
        if self.disposition != "ica" and self.ica_ids:
            raise ValueError("only ICA outcomes may retain ICA identities")
        return self


class ChallengeRecord(_ChallengeModel):
    """Selection and baseline evidence for one exact challenge target."""

    challenge_id: ChallengeId
    obligation_id: ObligationId
    slot_id: str
    priority: int = Field(ge=0, strict=True)
    eligibility_rationale: str = Field(min_length=1)
    eligibility_evidence_refs: tuple[str, ...] = Field(min_length=1)
    selection_status: SelectionStatus
    original_decision: OriginalStpaDecision
    outcome: ChallengeOutcome | None = None

    @model_validator(mode="after")
    def validate_record(self) -> "ChallengeRecord":
        object.__setattr__(
            self,
            "eligibility_evidence_refs",
            unique_sorted_strings(
                self.eligibility_evidence_refs, "eligibility_evidence_refs"
            ),
        )
        if self.slot_id != self.original_decision.slot_id:
            raise ValueError("challenge slot does not match original STPA decision")
        if self.selection_status == "not_selected_budget" and self.outcome is not None:
            raise ValueError("a budget-excluded target cannot have an outcome")
        return self


class ChallengeLedgerDiagnostics(_ChallengeModel):
    """Counts derived from the retained selection records."""

    eligible_targets: int = Field(ge=0)
    selected_targets: int = Field(ge=0)
    not_selected_budget: int = Field(ge=0)


def compute_challenge_id(
    assessment_digest: str, obligation_id: str, slot_id: str
) -> str:
    """Return the content-addressed identity for one assessment-bound target."""
    digest = compute_framed_digest(
        STPA_CHALLENGE_ID_DOMAIN,
        {
            "assessment_digest": assessment_digest,
            "obligation_id": obligation_id,
            "slot_id": slot_id,
        },
    )
    return f"challenge:v1:{digest}"


def _ledger_payload(ledger: "StpaChallengeLedger") -> dict[str, Any]:
    return {
        "schema_version": ledger.schema_version,
        "assessment_pin": ledger.assessment_pin.model_dump(mode="json"),
        "source_pins": [pin.model_dump(mode="json") for pin in ledger.source_pins],
        "selection_policy_version": ledger.selection_policy_version,
        "challenge_budget": ledger.challenge_budget,
        "records": [record.model_dump(mode="json") for record in ledger.records],
        "diagnostics": ledger.diagnostics.model_dump(mode="json"),
        "network_calls": ledger.network_calls,
        "model_calls": ledger.model_calls,
    }


def _canonical_pins(values: tuple[ArtifactPin, ...]) -> tuple[ArtifactPin, ...]:
    pins = tuple(
        sorted(
            values,
            key=lambda pin: canonical_json_bytes(pin.model_dump(mode="json")),
        )
    )
    if len({pin.artifact_id for pin in pins}) != len(pins):
        raise ValueError("source pins must contain unique artifact IDs")
    return pins


def _canonical_records(
    values: tuple[ChallengeRecord, ...],
) -> tuple[ChallengeRecord, ...]:
    records = tuple(
        sorted(
            values,
            key=lambda record: (
                record.priority,
                record.obligation_id,
                record.slot_id,
            ),
        )
    )
    identities = tuple((record.obligation_id, record.slot_id) for record in records)
    if len(identities) != len(set(identities)):
        raise ValueError("challenge records must contain unique target pairs")
    return records


def _pin_identities(pins: tuple[ArtifactPin, ...]) -> set[tuple[str, str, str]]:
    return {(pin.artifact_id, pin.schema_version, pin.semantic_digest) for pin in pins}


def _validate_record_trace(
    record: ChallengeRecord, pin_identities: set[tuple[str, str, str]]
) -> None:
    traces = record.original_decision.trace_refs
    if any(
        (trace.artifact_id, trace.schema_version, trace.semantic_digest)
        not in pin_identities
        for trace in traces
    ):
        raise ValueError("original-decision trace does not resolve to source pins")


def _validate_record_selection(
    record: ChallengeRecord, index: int, selected: int
) -> None:
    expected_status = "selected" if index < selected else "not_selected_budget"
    if record.selection_status != expected_status:
        raise ValueError("challenge selection status contradicts policy")


def _validate_record_identity(record: ChallengeRecord, assessment_digest: str) -> None:
    expected_id = compute_challenge_id(
        assessment_digest,
        record.obligation_id,
        record.slot_id,
    )
    if record.challenge_id != expected_id:
        raise ValueError("challenge identity does not match exact target")


def _validate_records(
    records: tuple[ChallengeRecord, ...],
    pins: tuple[ArtifactPin, ...],
    assessment_digest: str,
    challenge_budget: int,
) -> int:
    selected = min(challenge_budget, len(records))
    pin_ids = _pin_identities(pins)
    for index, record in enumerate(records):
        _validate_record_trace(record, pin_ids)
        _validate_record_selection(record, index, selected)
        _validate_record_identity(record, assessment_digest)
    return selected


def _derived_diagnostics(
    records: tuple[ChallengeRecord, ...], selected: int
) -> ChallengeLedgerDiagnostics:
    return ChallengeLedgerDiagnostics(
        eligible_targets=len(records),
        selected_targets=selected,
        not_selected_budget=len(records) - selected,
    )


class StpaChallengeLedger(_ChallengeModel):
    """Canonical offline ledger for bounded Phase 3 reconsideration."""

    schema_version: Literal[STPA_CHALLENGE_LEDGER_SCHEMA_VERSION] = (
        STPA_CHALLENGE_LEDGER_SCHEMA_VERSION
    )
    semantic_digest: Digest | None = None
    assessment_pin: ArtifactPin
    source_pins: tuple[ArtifactPin, ...] = Field(min_length=3)
    selection_policy_version: Literal[EXPLICIT_PRIORITY_POLICY_VERSION] = (
        EXPLICIT_PRIORITY_POLICY_VERSION
    )
    challenge_budget: int = Field(ge=0, strict=True)
    records: tuple[ChallengeRecord, ...]
    diagnostics: ChallengeLedgerDiagnostics
    network_calls: Literal[0] = 0
    model_calls: Literal[0] = 0

    @model_validator(mode="after")
    def canonicalize_and_verify(self) -> "StpaChallengeLedger":
        if (
            self.assessment_pin.schema_version
            != HYBRID_COVERAGE_ASSESSMENT_SCHEMA_VERSION
        ):
            raise ValueError("assessment pin must name a Phase 2 assessment")
        pins = _canonical_pins(self.source_pins)
        object.__setattr__(self, "source_pins", pins)
        ordered = _canonical_records(self.records)
        object.__setattr__(self, "records", ordered)
        selected = _validate_records(
            ordered,
            pins,
            self.assessment_pin.semantic_digest,
            self.challenge_budget,
        )
        expected_diagnostics = _derived_diagnostics(ordered, selected)
        if self.diagnostics != expected_diagnostics:
            raise ValueError("challenge ledger diagnostics do not reconcile")
        expected = self.compute_semantic_digest()
        if self.semantic_digest is not None and self.semantic_digest != expected:
            raise ValueError("STPA challenge ledger semantic_digest does not match")
        object.__setattr__(self, "semantic_digest", expected)
        return self

    def compute_semantic_digest(self) -> str:
        """Compute the framed digest over the complete offline ledger."""
        return compute_framed_digest(
            STPA_CHALLENGE_LEDGER_DIGEST_DOMAIN, _ledger_payload(self)
        )

    def assert_integrity(self) -> None:
        """Raise when persisted ledger content has been modified."""
        if self.semantic_digest != self.compute_semantic_digest():
            raise ValueError("STPA challenge ledger digest mismatch")

    def to_yaml(self) -> str:
        """Serialize the integrity-checked ledger as deterministic YAML."""
        self.assert_integrity()
        return yaml.dump(
            self.model_dump(mode="json"),
            default_flow_style=False,
            sort_keys=True,
            allow_unicode=True,
        )

    def to_json(self) -> str:
        """Serialize stable diagnostic JSON."""
        self.assert_integrity()
        return canonical_json_text(self.model_dump(mode="json"))

    @classmethod
    def from_yaml(cls, text: str | bytes) -> "StpaChallengeLedger":
        """Load and integrity-check one closed YAML ledger."""
        return cls._load(yaml.safe_load(text))

    @classmethod
    def from_json(cls, text: str | bytes) -> "StpaChallengeLedger":
        """Load and integrity-check one closed JSON ledger."""
        return cls._load(json.loads(text))

    @classmethod
    def _load(cls, data: Any) -> "StpaChallengeLedger":
        if not isinstance(data, dict):
            raise ValueError("STPA challenge ledger must be a mapping")
        if data.get("schema_version") != STPA_CHALLENGE_LEDGER_SCHEMA_VERSION:
            raise ValueError("unsupported STPA challenge ledger schema version")
        if not data.get("semantic_digest"):
            raise ValueError("STPA challenge ledger semantic_digest is required")
        result = cls.model_validate(data)
        result.assert_integrity()
        return result


__all__ = [
    "EXPLICIT_PRIORITY_POLICY_VERSION",
    "STPA_CHALLENGE_LEDGER_SCHEMA_VERSION",
    "ChallengeEligibility",
    "ChallengeLedgerDiagnostics",
    "ChallengeOutcome",
    "ChallengeRecord",
    "OriginalStpaDecision",
    "StpaChallengeLedger",
    "compute_challenge_id",
]
