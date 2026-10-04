"""Closed provisional accounting contracts for obligation-aware STPA.

Accounting is intentionally separate from scenario realization.  An
``addressed`` row proves only that STPA emitted an
exact structural finding for the obligation; it never asserts taxonomy
coverage.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable
from typing import Any, Literal

import yaml
from pydantic import Field, model_validator

from asago_scenario_generator.models.canonical import (
    ClosedCanonicalModel,
    canonical_json_text,
    compute_framed_digest,
    unique_sorted_strings,
)
from asago_scenario_generator.models.artifact_pin import (
    ArtifactPin,
    Digest,
    ObligationId,
)
from asago_scenario_generator.models.obligation_funnel import ObligationStopReason
from asago_scenario_generator.models.obligation_consideration import (
    ConsiderationDiagnostic,
)


OBLIGATION_ACCOUNTING_SCHEMA_VERSION = "stpa-obligation-accounting-v1"
OBLIGATION_ACCOUNTING_DIGEST_DOMAIN = (
    "asago-scenario-generator:stpa-obligation-accounting:v1"
)
OBLIGATION_ACCOUNTING_SOURCE_PIN_SPECS: tuple[tuple[str, str], ...] = (
    ("taxonomy-obligation-plan", "taxonomy-obligation-plan-v1"),
    ("stpa-loss-analysis", "stpa-loss-analysis-v1"),
    ("stpa-control-structure", "stpa-control-structure-v1"),
    ("ica-enumeration", "ica-enumeration-v1"),
)

AccountingDisposition = Literal[
    "addressed",
    "proposed_not_applicable",
    "unresolved",
    "upstream_gap",
    "capability_excluded",
    "governance_only",
]


class _AccountingModel(ClosedCanonicalModel):
    """Common closed and immutable configuration for accounting records."""


def _canonical_strings(values: tuple[str, ...], label: str) -> tuple[str, ...]:
    """Return unique set-like values in stable order."""
    return unique_sorted_strings(values, label)


def _canonical_pins(values: tuple[ArtifactPin, ...]) -> tuple[ArtifactPin, ...]:
    """Sort pins and reject duplicate artifact identities."""
    ordered = tuple(
        sorted(
            values,
            key=lambda item: item.model_dump_json(),
        )
    )
    if len({item.artifact_id for item in ordered}) != len(ordered):
        raise ValueError("accounting source pins must contain unique artifact IDs")
    return ordered


def validate_obligation_accounting_source_pins(
    values: Iterable[ArtifactPin],
) -> tuple[ArtifactPin, ...]:
    """Require the exact four upstream authorities used by accounting."""
    pins = tuple(values)
    if any(not isinstance(item, ArtifactPin) for item in pins):
        raise TypeError("accounting source_pins must contain only ArtifactPin values")
    ordered = _canonical_pins(pins)
    actual = {item.artifact_id: item for item in ordered}
    _require_exact_pin_authorities(ordered, actual)
    _require_pin_schema_labels(actual)
    return ordered


def _require_exact_pin_authorities(
    ordered: tuple[ArtifactPin, ...], actual: dict[str, ArtifactPin]
) -> None:
    """Require one pin for each accounting authority and no other pins."""
    expected = dict(OBLIGATION_ACCOUNTING_SOURCE_PIN_SPECS)
    gaps = (
        ("missing", tuple(sorted(set(expected) - set(actual)))),
        ("unknown", tuple(sorted(set(actual) - set(expected)))),
    )
    details = [f"{label}={','.join(ids)}" for label, ids in gaps if ids]
    if details or len(ordered) != len(expected):
        raise ValueError(
            "accounting source_pins must contain exactly one pin for each "
            f"required authority ({'; '.join(details) or 'duplicate identities'})"
        )


def _require_pin_schema_labels(actual: dict[str, ArtifactPin]) -> None:
    """Require the stable schema label on each accounting authority pin."""
    wrong_schema = tuple(
        f"{artifact_id}={actual[artifact_id].schema_version!r}"
        for artifact_id, schema_version in OBLIGATION_ACCOUNTING_SOURCE_PIN_SPECS
        if actual[artifact_id].schema_version != schema_version
    )
    if wrong_schema:
        raise ValueError(
            "accounting source_pins use the wrong schema labels: "
            + ", ".join(wrong_schema)
        )


class ObligationAccountingRow(_AccountingModel):
    """One provisional disposition for exactly one Phase 1 obligation."""

    obligation_id: ObligationId
    disposition: AccountingDisposition
    stop_reason: ObligationStopReason | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    slot_ids: tuple[str, ...] = ()
    ica_ids: tuple[str, ...] = ()
    exec_candidate_ids: tuple[str, ...] = ()
    hazard_ids: tuple[str, ...] = ()
    constraint_ids: tuple[str, ...] = ()
    route_refs: tuple[str, ...] = ()
    evidence: tuple[str, ...] = Field(min_length=1)
    diagnostics: tuple[ConsiderationDiagnostic, ...] = ()

    @model_validator(mode="after")
    def canonicalize_and_validate(self) -> "ObligationAccountingRow":
        for field_name in (*_FINDING_FIELDS, "evidence"):
            object.__setattr__(
                self,
                field_name,
                _canonical_strings(getattr(self, field_name), field_name),
            )
        if any(not item.startswith("EXEC:") for item in self.exec_candidate_ids):
            raise ValueError(
                "execution candidate IDs must use canonical EXEC:* identity"
            )
        validate_disposition = _DISPOSITION_VALIDATORS.get(self.disposition)
        if validate_disposition is not None:
            validate_disposition(self)
        return self


_FINDING_FIELDS = (
    "slot_ids",
    "ica_ids",
    "exec_candidate_ids",
    "hazard_ids",
    "constraint_ids",
    "route_refs",
)
_ADDRESSED_REQUIREMENTS = (
    ("slot_ids", "addressed accounting rows require exact slot IDs"),
    ("ica_ids", "addressed accounting rows require exact ICA IDs"),
    ("exec_candidate_ids", "addressed accounting rows require exact EXEC IDs"),
    ("hazard_ids", "addressed accounting rows require exact hazard IDs"),
    ("constraint_ids", "addressed accounting rows require exact constraint IDs"),
    ("route_refs", "addressed accounting rows require route references"),
)


def _require_nonempty(values: tuple[str, ...], message: str) -> None:
    """Raise a stable error for a required nonempty identity collection."""
    if not values:
        raise ValueError(message)


def _validate_addressed_row(row: ObligationAccountingRow) -> None:
    """Require every exact structural identity on an addressed row."""
    for field_name, message in _ADDRESSED_REQUIREMENTS:
        _require_nonempty(getattr(row, field_name), message)


def _validate_not_applicable_row(row: ObligationAccountingRow) -> None:
    """Require routed slots and route references without retained findings."""
    _require_nonempty(
        row.slot_ids, "proposed non-applicable rows require routed slot IDs"
    )
    if row.ica_ids or row.exec_candidate_ids:
        raise ValueError("proposed non-applicable rows cannot retain findings")
    _require_nonempty(
        row.route_refs, "proposed non-applicable rows require route references"
    )


def _validate_row_without_findings(row: ObligationAccountingRow) -> None:
    """Reject STPA findings on excluded and governance-only rows."""
    if any(getattr(row, field_name) for field_name in _FINDING_FIELDS):
        raise ValueError(
            "excluded and governance-only rows cannot contain STPA findings"
        )


_DISPOSITION_VALIDATORS = {
    "addressed": _validate_addressed_row,
    "proposed_not_applicable": _validate_not_applicable_row,
    "capability_excluded": _validate_row_without_findings,
    "governance_only": _validate_row_without_findings,
}


class ObligationAccountingSummary(_AccountingModel):
    """Exact counts for all six provisional accounting dispositions."""

    total: int = Field(ge=0, strict=True)
    addressed: int = Field(ge=0, strict=True)
    proposed_not_applicable: int = Field(ge=0, strict=True)
    unresolved: int = Field(ge=0, strict=True)
    upstream_gap: int = Field(ge=0, strict=True)
    capability_excluded: int = Field(ge=0, strict=True)
    governance_only: int = Field(ge=0, strict=True)


def derive_obligation_accounting_summary(
    rows: tuple[ObligationAccountingRow, ...] | list[ObligationAccountingRow],
) -> ObligationAccountingSummary:
    """Derive all summary counts directly from authoritative rows."""
    values = tuple(rows)
    counts = Counter(row.disposition for row in values)
    return ObligationAccountingSummary(
        total=len(values),
        addressed=counts["addressed"],
        proposed_not_applicable=counts["proposed_not_applicable"],
        unresolved=counts["unresolved"],
        upstream_gap=counts["upstream_gap"],
        capability_excluded=counts["capability_excluded"],
        governance_only=counts["governance_only"],
    )


class ObligationAccounting(_AccountingModel):
    """Content-addressed provisional accounting for the complete plan."""

    schema_version: Literal[OBLIGATION_ACCOUNTING_SCHEMA_VERSION] = (
        OBLIGATION_ACCOUNTING_SCHEMA_VERSION
    )
    semantic_digest: Digest | None = None
    source_pins: tuple[ArtifactPin, ...] = Field(min_length=1)
    rows: tuple[ObligationAccountingRow, ...]
    summary: ObligationAccountingSummary

    @model_validator(mode="after")
    def canonicalize_validate_and_digest(self) -> "ObligationAccounting":
        object.__setattr__(
            self,
            "source_pins",
            validate_obligation_accounting_source_pins(self.source_pins),
        )
        rows = tuple(sorted(self.rows, key=lambda item: item.obligation_id))
        ids = tuple(row.obligation_id for row in rows)
        if len(ids) != len(set(ids)):
            raise ValueError("accounting rows must contain unique obligation IDs")
        object.__setattr__(self, "rows", rows)
        expected_summary = derive_obligation_accounting_summary(rows)
        if self.summary != expected_summary:
            raise ValueError("obligation accounting summary does not reconcile")
        expected = self.compute_semantic_digest()
        if self.semantic_digest is not None and self.semantic_digest != expected:
            raise ValueError("obligation accounting semantic_digest does not match")
        object.__setattr__(self, "semantic_digest", expected)
        return self

    def _digest_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"semantic_digest"})

    def compute_semantic_digest(self) -> str:
        """Compute the version-framed accounting digest."""
        return compute_framed_digest(
            OBLIGATION_ACCOUNTING_DIGEST_DOMAIN, self._digest_payload()
        )

    def assert_integrity(self) -> None:
        """Verify row summary, source pins, and semantic digest."""
        validate_obligation_accounting_source_pins(self.source_pins)
        if self.summary != derive_obligation_accounting_summary(self.rows):
            raise ValueError("obligation accounting summary does not reconcile")
        if self.semantic_digest != self.compute_semantic_digest():
            raise ValueError("obligation accounting digest mismatch")

    def to_yaml(self) -> str:
        """Serialize the closed artifact as canonical YAML."""
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
    def from_yaml(cls, value: str | bytes) -> "ObligationAccounting":
        """Load and integrity-check one YAML artifact."""
        data = yaml.safe_load(value)
        if not isinstance(data, dict):
            raise ValueError("YAML data must be a dictionary")
        return cls._load_checked(data)

    @classmethod
    def from_json(cls, value: str | bytes) -> "ObligationAccounting":
        """Load and integrity-check one JSON artifact."""
        try:
            data = json.loads(value)
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError(f"Invalid JSON obligation accounting: {exc}") from exc
        if not isinstance(data, dict):
            raise ValueError("JSON data must be a dictionary")
        return cls._load_checked(data)

    @classmethod
    def _load_checked(cls, data: dict[str, Any]) -> "ObligationAccounting":
        if data.get("schema_version") != OBLIGATION_ACCOUNTING_SCHEMA_VERSION:
            raise ValueError(
                f"Unsupported schema version: '{data.get('schema_version')}' is unsupported"
            )
        artifact = cls.model_validate(data)
        artifact.assert_integrity()
        return artifact


__all__ = [
    "AccountingDisposition",
    "OBLIGATION_ACCOUNTING_DIGEST_DOMAIN",
    "OBLIGATION_ACCOUNTING_SCHEMA_VERSION",
    "ObligationAccounting",
    "ObligationAccountingRow",
    "ObligationAccountingSummary",
    "OBLIGATION_ACCOUNTING_SOURCE_PIN_SPECS",
    "derive_obligation_accounting_summary",
    "validate_obligation_accounting_source_pins",
]
