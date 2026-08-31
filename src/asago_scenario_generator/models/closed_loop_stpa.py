"""Closed aggregate for one bounded Phase 3 STPA run."""

from __future__ import annotations

import json
from typing import Any, Literal

import yaml
from pydantic import Field, StrictBool, model_validator

from asago_scenario_generator.models.canonical import (
    ClosedCanonicalModel,
    canonical_json_text,
    compute_framed_digest,
)
from asago_scenario_generator.models.challenge_analysis import ChallengeAnalysisResult
from asago_scenario_generator.models.challenge_ledger import (
    ChallengeRecord,
    StpaChallengeLedger,
)
from asago_scenario_generator.models.hybrid_coverage import Digest


STPA_CLOSED_LOOP_RUN_SCHEMA_VERSION = "stpa-obligation-closed-loop-run-v1"
STPA_CLOSED_LOOP_RUN_DIGEST_DOMAIN = (
    "asago-scenario-generator:stpa-obligation-closed-loop-run:v1"
)


class ClosedLoopRunDiagnostics(ClosedCanonicalModel):
    """Exact selection, attempt, and outcome counts without a blended status."""

    eligible_targets: int = Field(ge=0, strict=True)
    selected_targets: int = Field(ge=0, strict=True)
    not_selected_budget: int = Field(ge=0, strict=True)
    attempted_targets: int = Field(ge=0, strict=True)
    pending_selected_targets: int = Field(ge=0, strict=True)
    completed_outcomes: int = Field(ge=0, strict=True)
    technical_failures: int = Field(ge=0, strict=True)
    ica_outcomes: int = Field(ge=0, strict=True)
    justified_na_outcomes: int = Field(ge=0, strict=True)
    unresolved_outcomes: int = Field(ge=0, strict=True)
    adapter_attempts: int = Field(ge=0, strict=True)
    provider_calls: int = Field(ge=0, strict=True)
    network_calls: int = Field(ge=0, strict=True)


def _run_payload(run: "ClosedLoopStpaRun") -> dict[str, Any]:
    return run.model_dump(mode="json", exclude={"semantic_digest"})


def _selected_records(ledger: StpaChallengeLedger) -> dict[str, ChallengeRecord]:
    return {
        record.challenge_id: record
        for record in ledger.records
        if record.selection_status == "selected"
    }


def _validate_analysis_lineage(
    result: ChallengeAnalysisResult,
    record: ChallengeRecord,
    ledger: StpaChallengeLedger,
) -> None:
    if result.request.assessment_pin != ledger.assessment_pin:
        raise ValueError("closed-loop analysis substituted the assessment pin")
    if result.request.source_pins != ledger.source_pins:
        raise ValueError("closed-loop analysis substituted upstream source pins")
    if result.original_decision != record.original_decision:
        raise ValueError("closed-loop analysis replaced the original STPA decision")


def _canonical_analyses(
    analyses: tuple[ChallengeAnalysisResult, ...], ledger: StpaChallengeLedger
) -> tuple[ChallengeAnalysisResult, ...]:
    ordered = tuple(sorted(analyses, key=lambda item: item.request.challenge_id))
    identifiers = tuple(item.request.challenge_id for item in ordered)
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("closed-loop run contains duplicate challenge attempts")
    selected = _selected_records(ledger)
    for result in ordered:
        record = selected.get(result.request.challenge_id)
        if record is None:
            raise ValueError("closed-loop analysis does not name a selected target")
        _validate_analysis_lineage(result, record, ledger)
    return ordered


def _derive_diagnostics(
    ledger: StpaChallengeLedger,
    analyses: tuple[ChallengeAnalysisResult, ...],
) -> ClosedLoopRunDiagnostics:
    outcomes = tuple(item.outcome for item in analyses if item.outcome is not None)
    selected = ledger.diagnostics.selected_targets
    return ClosedLoopRunDiagnostics(
        eligible_targets=ledger.diagnostics.eligible_targets,
        selected_targets=selected,
        not_selected_budget=ledger.diagnostics.not_selected_budget,
        attempted_targets=len(analyses),
        pending_selected_targets=selected - len(analyses),
        completed_outcomes=len(outcomes),
        technical_failures=_count_status(analyses, "technical_failure"),
        ica_outcomes=_count_disposition(outcomes, "ica"),
        justified_na_outcomes=_count_disposition(outcomes, "justified_na"),
        unresolved_outcomes=_count_disposition(outcomes, "unresolved"),
        adapter_attempts=sum(item.call_evidence.adapter_attempts for item in analyses),
        provider_calls=sum(item.call_evidence.provider_calls for item in analyses),
        network_calls=sum(item.call_evidence.network_calls for item in analyses),
    )


def _count_status(analyses: tuple[ChallengeAnalysisResult, ...], status: str) -> int:
    return sum(item.status == status for item in analyses)


def _count_disposition(outcomes: tuple[Any, ...], disposition: str) -> int:
    return sum(item.disposition == disposition for item in outcomes)


def _validate_attempt_accounting(
    opted_in: bool,
    analyses: tuple[ChallengeAnalysisResult, ...],
    selected: int,
) -> None:
    validator = (
        _validate_opted_in_attempts if opted_in else _validate_opted_out_attempts
    )
    validator(analyses, selected)


def _validate_opted_out_attempts(
    analyses: tuple[ChallengeAnalysisResult, ...], selected: int
) -> None:
    del selected
    if analyses:
        raise ValueError("opted-out closed-loop run cannot contain attempts")


def _validate_opted_in_attempts(
    analyses: tuple[ChallengeAnalysisResult, ...], selected: int
) -> None:
    if len(analyses) != selected:
        raise ValueError(
            "opted-in closed-loop run must account for every selected target"
        )


def _reconcile_diagnostics(
    supplied: ClosedLoopRunDiagnostics | None,
    expected: ClosedLoopRunDiagnostics,
) -> None:
    if supplied is not None and supplied != expected:
        raise ValueError("closed-loop run diagnostics do not reconcile")


def _verify_digest(supplied: str | None, expected: str) -> None:
    if supplied is not None and supplied != expected:
        raise ValueError("closed-loop run semantic_digest does not match")


class ClosedLoopStpaRun(ClosedCanonicalModel):
    """Selection and adjacent analysis history for one exact assessment."""

    schema_version: Literal["stpa-obligation-closed-loop-run-v1"] = (
        STPA_CLOSED_LOOP_RUN_SCHEMA_VERSION
    )
    ledger: StpaChallengeLedger
    analysis_opt_in: StrictBool
    analyses: tuple[ChallengeAnalysisResult, ...] = ()
    diagnostics: ClosedLoopRunDiagnostics | None = None
    correspondence_changes: Literal[0] = 0
    coverage_changes: Literal[0] = 0
    hybrid_generation_status: Literal["not_attempted"] = "not_attempted"
    hybrid_admission_status: Literal["not_assessed"] = "not_assessed"
    semantic_digest: Digest | None = None

    @model_validator(mode="after")
    def canonicalize_and_verify(self) -> "ClosedLoopStpaRun":
        self.ledger.assert_integrity()
        analyses = _canonical_analyses(self.analyses, self.ledger)
        selected = self.ledger.diagnostics.selected_targets
        _validate_attempt_accounting(self.analysis_opt_in, analyses, selected)
        object.__setattr__(self, "analyses", analyses)
        expected_diagnostics = _derive_diagnostics(self.ledger, analyses)
        _reconcile_diagnostics(self.diagnostics, expected_diagnostics)
        object.__setattr__(self, "diagnostics", expected_diagnostics)
        expected_digest = self.compute_semantic_digest()
        _verify_digest(self.semantic_digest, expected_digest)
        object.__setattr__(self, "semantic_digest", expected_digest)
        return self

    def compute_semantic_digest(self) -> str:
        return compute_framed_digest(
            STPA_CLOSED_LOOP_RUN_DIGEST_DOMAIN, _run_payload(self)
        )

    def assert_integrity(self) -> None:
        self.ledger.assert_integrity()
        for analysis in self.analyses:
            analysis.assert_integrity()
        if self.semantic_digest != self.compute_semantic_digest():
            raise ValueError("closed-loop run digest mismatch")

    def to_yaml(self) -> str:
        self.assert_integrity()
        options = {
            "default_flow_style": False,
            "allow_unicode": True,
            "sort_keys": True,
        }
        return yaml.dump(self.model_dump(mode="json"), **options)

    def to_json(self) -> str:
        self.assert_integrity()
        return canonical_json_text(self.model_dump(mode="json"))

    @classmethod
    def from_yaml(cls, value: str | bytes) -> "ClosedLoopStpaRun":
        return cls._load(yaml.safe_load(value))

    @classmethod
    def from_json(cls, value: str | bytes) -> "ClosedLoopStpaRun":
        return cls._load(json.loads(value))

    @classmethod
    def _load(cls, value: Any) -> "ClosedLoopStpaRun":
        if not isinstance(value, dict):
            raise ValueError("closed-loop run payload must be a mapping")
        if value.get("schema_version") != STPA_CLOSED_LOOP_RUN_SCHEMA_VERSION:
            raise ValueError("unsupported closed-loop run schema_version")
        if not value.get("semantic_digest"):
            raise ValueError("closed-loop run semantic_digest is required")
        result = cls.model_validate(value)
        result.assert_integrity()
        return result


__all__ = [
    "ClosedLoopRunDiagnostics",
    "ClosedLoopStpaRun",
    "STPA_CLOSED_LOOP_RUN_DIGEST_DOMAIN",
    "STPA_CLOSED_LOOP_RUN_SCHEMA_VERSION",
]
