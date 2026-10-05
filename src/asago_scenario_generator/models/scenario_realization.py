"""Closed evidence that an ICA finding survived scenario production."""

from __future__ import annotations

from collections import Counter
from typing import Any, ClassVar, Literal

from pydantic import Field, model_validator

from asago_scenario_generator.models.canonical import (
    CanonicalYamlMixin,
    ClosedCanonicalModel,
    SemanticDigestMixin,
    compute_framed_digest,
    unique_sorted_strings,
)
from asago_scenario_generator.models.artifact_pin import (
    ArtifactPin,
    Digest,
    ObligationId,
)
from asago_scenario_generator.models.obligation_funnel import ObligationStopReason


SCENARIO_REALIZATION_SCHEMA_VERSION = "stpa-scenario-realization-v1"
SCENARIO_REALIZATION_DIGEST_DOMAIN = (
    "asago-scenario-generator:stpa-scenario-realization:v1"
)
SCENARIO_REALIZATION_RECORD_DOMAIN = (
    "asago-scenario-generator:stpa-scenario-realization-record:v1"
)
SCENARIO_REALIZATION_SOURCE_PIN_SPECS: tuple[tuple[str, str], ...] = (
    ("obligation-accounting", "stpa-obligation-accounting-v1"),
    ("ica-enumeration", "ica-enumeration-v1"),
    ("stpa-scenario-collection", "stpa-scenario-collection-v1"),
)

ScenarioRealizationStatus = Literal["realized", "unresolved", "not_requested"]


class _RealizationModel(ClosedCanonicalModel):
    """Common closed and immutable realization record configuration."""


class ScenarioRealizationRecord(_RealizationModel):
    """One exact obligation/ICA finding after scenario production."""

    record_id: str | None = None
    obligation_id: ObligationId
    consideration_pair_id: str = Field(min_length=1)
    route_id: str = Field(min_length=1)
    slot_id: str = Field(min_length=1)
    ica_id: str = Field(min_length=1)
    status: ScenarioRealizationStatus
    stop_reason: ObligationStopReason
    scenario_ids: tuple[str, ...] = ()
    context_digests: tuple[Digest, ...] = ()
    evidence: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def canonicalize_and_validate(self) -> "ScenarioRealizationRecord":
        pairs = _canonical_scenario_pairs(self.scenario_ids, self.context_digests)
        object.__setattr__(self, "scenario_ids", tuple(item[0] for item in pairs))
        object.__setattr__(self, "context_digests", tuple(item[1] for item in pairs))
        object.__setattr__(
            self, "evidence", unique_sorted_strings(self.evidence, "evidence")
        )
        _validate_realization_status(self.status, self.stop_reason, bool(pairs))
        expected = self.compute_record_id()
        if self.record_id is not None and self.record_id != expected:
            raise ValueError("scenario realization record_id does not match content")
        object.__setattr__(self, "record_id", expected)
        return self

    def compute_record_id(self) -> str:
        """Compute the stable record identity from the complete result."""
        digest = compute_framed_digest(
            SCENARIO_REALIZATION_RECORD_DOMAIN,
            self.model_dump(mode="json", exclude={"record_id"}),
        )
        return f"realization:v1:{digest}"


_REQUIRED_STOP_REASONS = {
    "realized": ("scenario_realized", "realized records require scenario_realized"),
    "unresolved": (
        "scenario_generation_failure",
        "unresolved records require scenario_generation_failure",
    ),
    "not_requested": (
        "scenario_not_requested",
        "not-requested records require scenario_not_requested",
    ),
}


def _canonical_scenario_pairs(
    scenario_ids: tuple[str, ...], context_digests: tuple[str, ...]
) -> tuple[tuple[str, str], ...]:
    """Pair scenario IDs with context digests in sorted order, rejecting repeats."""
    if len(scenario_ids) != len(context_digests):
        raise ValueError(
            "scenario realization IDs and context digests must stay paired"
        )
    pairs = tuple(sorted(zip(scenario_ids, context_digests)))
    if len(pairs) != len(set(pairs)):
        raise ValueError("scenario realization references must be unique")
    return pairs


def _validate_realization_status(
    status: str, stop_reason: str, has_scenarios: bool
) -> None:
    """Allow scenarios only on realized records and require the status stop reason."""
    if status == "realized" and not has_scenarios:
        raise ValueError("realized records require scenario IDs and context digests")
    if status != "realized" and has_scenarios:
        raise ValueError(
            "unresolved and not-requested records cannot claim realized scenarios"
        )
    required, message = _REQUIRED_STOP_REASONS[status]
    if stop_reason != required:
        raise ValueError(message)


class ScenarioRealizationSummary(_RealizationModel):
    """Exact independently derived counts for realization records."""

    total: int = Field(ge=0, strict=True)
    realized: int = Field(ge=0, strict=True)
    unresolved: int = Field(ge=0, strict=True)
    not_requested: int = Field(ge=0, strict=True)


def derive_scenario_realization_summary(
    records: tuple[ScenarioRealizationRecord, ...] | list[ScenarioRealizationRecord],
) -> ScenarioRealizationSummary:
    """Derive all counts from the exact record collection."""
    values = tuple(records)
    counts = Counter(item.status for item in values)
    return ScenarioRealizationSummary(
        total=len(values),
        realized=counts["realized"],
        unresolved=counts["unresolved"],
        not_requested=counts["not_requested"],
    )


def validate_scenario_realization_source_pins(
    values: tuple[ArtifactPin, ...] | list[ArtifactPin],
) -> tuple[ArtifactPin, ...]:
    """Require one exact pin for each authority used by realization."""
    if any(not isinstance(item, ArtifactPin) for item in values):
        raise TypeError("scenario realization source_pins require ArtifactPin values")
    ordered = tuple(sorted(values, key=lambda item: item.artifact_id))
    if len({item.artifact_id for item in ordered}) != len(ordered):
        raise ValueError("scenario realization source_pins contain duplicate IDs")
    expected = dict(SCENARIO_REALIZATION_SOURCE_PIN_SPECS)
    actual = {item.artifact_id: item.schema_version for item in ordered}
    if actual != expected:
        raise ValueError(
            "scenario realization source_pins must contain the exact accounting, "
            "ICA-enumeration, and scenario-collection authorities"
        )
    return ordered


class ScenarioRealizationAssessment(
    SemanticDigestMixin, CanonicalYamlMixin, _RealizationModel
):
    """Content-addressed scenario realization for all ICA findings."""

    _digest_domain: ClassVar[str] = SCENARIO_REALIZATION_DIGEST_DOMAIN

    schema_version: Literal[SCENARIO_REALIZATION_SCHEMA_VERSION] = (
        SCENARIO_REALIZATION_SCHEMA_VERSION
    )
    semantic_digest: Digest | None = None
    source_pins: tuple[ArtifactPin, ...] = Field(min_length=3, max_length=3)
    records: tuple[ScenarioRealizationRecord, ...]
    summary: ScenarioRealizationSummary

    @model_validator(mode="after")
    def canonicalize_validate_and_digest(self) -> "ScenarioRealizationAssessment":
        object.__setattr__(
            self,
            "source_pins",
            validate_scenario_realization_source_pins(self.source_pins),
        )
        records = tuple(
            sorted(
                self.records,
                key=lambda item: (
                    item.obligation_id,
                    item.slot_id,
                    item.ica_id,
                    item.consideration_pair_id,
                ),
            )
        )
        keys = tuple(
            (item.obligation_id, item.consideration_pair_id, item.ica_id)
            for item in records
        )
        if len(keys) != len(set(keys)):
            raise ValueError("scenario realization records contain duplicate findings")
        object.__setattr__(self, "records", records)
        expected_summary = derive_scenario_realization_summary(records)
        if self.summary != expected_summary:
            raise ValueError("scenario realization summary does not reconcile")
        self._attest_semantic_digest(
            "scenario realization semantic_digest does not match"
        )
        return self

    def assert_integrity(self) -> None:
        """Verify source pins, records, summary, and digest."""
        validate_scenario_realization_source_pins(self.source_pins)
        if self.summary != derive_scenario_realization_summary(self.records):
            raise ValueError("scenario realization summary does not reconcile")
        if self.semantic_digest != self.compute_semantic_digest():
            raise ValueError("scenario realization digest mismatch")

    @classmethod
    def _load_checked(cls, data: dict[str, Any]) -> "ScenarioRealizationAssessment":
        if data.get("schema_version") != SCENARIO_REALIZATION_SCHEMA_VERSION:
            raise ValueError(
                f"Unsupported schema version: {data.get('schema_version')!r}"
            )
        artifact = cls.model_validate(data)
        artifact.assert_integrity()
        return artifact


__all__ = [
    "SCENARIO_REALIZATION_DIGEST_DOMAIN",
    "SCENARIO_REALIZATION_SCHEMA_VERSION",
    "SCENARIO_REALIZATION_SOURCE_PIN_SPECS",
    "ScenarioRealizationAssessment",
    "ScenarioRealizationRecord",
    "ScenarioRealizationStatus",
    "ScenarioRealizationSummary",
    "derive_scenario_realization_summary",
    "validate_scenario_realization_source_pins",
]
