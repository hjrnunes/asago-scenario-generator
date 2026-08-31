"""Closed taxonomy-candidate materialization contracts for Phase 4.

The Phase 1 plan deliberately stores candidate identity and disposition, not a
complete mechanism.  These immutable values carry the complete canonical
projection copied from the current projection boundary and bind it back to
the exact Phase 1 candidate-record digest.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field, model_validator

from asago_scenario_generator.models.hybrid_coverage import ArtifactPin
from asago_scenario_generator.models.hybrid_scenario_projection import (
    ArtifactProjectionSourcePin,
    CandidateId,
    Digest,
    MechanismProjection,
    ObligationId,
    ProjectionSourcePin,
    _ProjectionModel,
    _derive_id,
    _semantic_digest,
    _source_pin_key,
)


CANDIDATE_MATERIALIZATION_SCHEMA_VERSION = "taxonomy-candidate-materialization-v1"
CANDIDATE_MATERIALIZATION_SET_SCHEMA_VERSION = (
    "taxonomy-candidate-materialization-set-v1"
)
CANDIDATE_MATERIALIZATION_DIGEST_DOMAIN = "asago.taxonomy-candidate-materialization.v1"
CANDIDATE_MATERIALIZATION_SET_DIGEST_DOMAIN = (
    "asago.taxonomy-candidate-materialization-set.v1"
)
PHASE1_CANDIDATE_RECORD_DIGEST_DOMAIN = "asago.phase1-candidate-record.v1"


class CandidateMaterialization(_ProjectionModel):
    """One complete, candidate-v2 mechanism materialization."""

    schema_version: Literal[CANDIDATE_MATERIALIZATION_SCHEMA_VERSION] = (
        CANDIDATE_MATERIALIZATION_SCHEMA_VERSION
    )
    materialization_id: str = ""
    obligation_id: ObligationId
    risk_id: str = Field(min_length=1)
    attack_pattern_id: str = Field(min_length=1)
    selected_candidate_id: CandidateId
    phase1_candidate_record_digest: Digest
    mechanism_projection: MechanismProjection
    source_pins: tuple[ProjectionSourcePin, ...] = Field(min_length=1)
    semantic_digest: Digest | None = None

    @model_validator(mode="after")
    def verify_and_identify(self) -> "CandidateMaterialization":
        _validate_materialization_identity(self)
        object.__setattr__(
            self,
            "source_pins",
            tuple(sorted(self.source_pins, key=_source_pin_key)),
        )
        _set_materialization_id(self)
        _set_materialization_digest(self)
        return self

    def assert_integrity(self) -> None:
        """Verify the complete materialization and its nested mechanism."""
        self.mechanism_projection.assert_integrity()
        if self.semantic_digest != _semantic_digest(
            self, CANDIDATE_MATERIALIZATION_DIGEST_DOMAIN
        ):
            raise ValueError("materialization semantic digest mismatch")


class CandidateMaterializationSet(_ProjectionModel):
    """Content-addressed set of candidate materializations for one plan."""

    schema_version: Literal[CANDIDATE_MATERIALIZATION_SET_SCHEMA_VERSION] = (
        CANDIDATE_MATERIALIZATION_SET_SCHEMA_VERSION
    )
    obligation_plan_pin: ArtifactPin
    entries: tuple[CandidateMaterialization, ...] = ()
    source_pins: tuple[ProjectionSourcePin, ...] = Field(min_length=1)
    semantic_digest: Digest | None = None

    @model_validator(mode="after")
    def canonicalize_and_verify(self) -> "CandidateMaterializationSet":
        entries = _canonical_materialization_entries(self.entries)
        pins = _canonical_materialization_set_pins(self)
        object.__setattr__(self, "entries", entries)
        object.__setattr__(self, "source_pins", pins)
        _set_materialization_set_digest(self)
        return self

    def assert_integrity(self) -> None:
        """Verify all entries and the enclosing set digest."""
        for entry in self.entries:
            entry.assert_integrity()
        if self.semantic_digest != _semantic_digest(
            self, CANDIDATE_MATERIALIZATION_SET_DIGEST_DOMAIN
        ):
            raise ValueError("materialization-set semantic digest mismatch")


def _require_unique(values: Any, message: str) -> None:
    """Reject duplicate semantic identities in one immutable collection."""
    values = tuple(values)
    if len(values) != len(set(values)):
        raise ValueError(message)


def _validate_materialization_identity(value: CandidateMaterialization) -> None:
    """Require one materialization and its mechanism to share all identities."""
    mechanism = value.mechanism_projection
    if any(
        expected != actual
        for expected, actual in (
            (value.obligation_id, mechanism.obligation_id),
            (value.attack_pattern_id, mechanism.attack_pattern_id),
            (value.selected_candidate_id, mechanism.selected_candidate_id),
        )
    ):
        raise ValueError("materialization identity does not match mechanism")


def _set_materialization_id(value: CandidateMaterialization) -> None:
    """Derive and validate one content-addressed materialization ID."""
    expected = _derive_id(
        value,
        "materialization:v1:",
        CANDIDATE_MATERIALIZATION_DIGEST_DOMAIN,
        "materialization_id",
    )
    if value.materialization_id and value.materialization_id != expected:
        raise ValueError("materialization_id does not match content")
    object.__setattr__(value, "materialization_id", expected)


def _set_materialization_digest(value: CandidateMaterialization) -> None:
    """Derive and validate one complete materialization digest."""
    expected = _semantic_digest(value, CANDIDATE_MATERIALIZATION_DIGEST_DOMAIN)
    if value.semantic_digest is not None and value.semantic_digest != expected:
        raise ValueError("materialization semantic_digest does not match content")
    object.__setattr__(value, "semantic_digest", expected)


def _canonical_materialization_entries(
    entries: tuple[CandidateMaterialization, ...],
) -> tuple[CandidateMaterialization, ...]:
    """Sort entries and reject duplicate materialization identities."""
    ordered = tuple(
        sorted(
            entries, key=lambda item: (item.obligation_id, item.selected_candidate_id)
        )
    )
    _require_unique(
        (item.materialization_id for item in ordered),
        "materialization IDs must be unique",
    )
    _require_unique(
        ((item.obligation_id, item.selected_candidate_id) for item in ordered),
        "materialization obligation/candidate identities must be unique",
    )
    return ordered


def _canonical_materialization_set_pins(
    value: CandidateMaterializationSet,
) -> tuple[ProjectionSourcePin, ...]:
    """Sort set pins and add the exact obligation-plan pin when omitted."""
    pins = tuple(sorted(value.source_pins, key=_source_pin_key))
    plan_pin = ArtifactProjectionSourcePin.from_artifact_pin(
        value.obligation_plan_pin, role="obligation-plan"
    )
    if plan_pin not in pins:
        return tuple(sorted((*pins, plan_pin), key=_source_pin_key))
    return pins


def _set_materialization_set_digest(value: CandidateMaterializationSet) -> None:
    """Derive and validate one complete materialization-set digest."""
    expected = _semantic_digest(value, CANDIDATE_MATERIALIZATION_SET_DIGEST_DOMAIN)
    if value.semantic_digest is not None and value.semantic_digest != expected:
        raise ValueError("materialization-set semantic_digest does not match content")
    object.__setattr__(value, "semantic_digest", expected)


__all__ = [
    "CANDIDATE_MATERIALIZATION_DIGEST_DOMAIN",
    "CANDIDATE_MATERIALIZATION_SCHEMA_VERSION",
    "CANDIDATE_MATERIALIZATION_SET_DIGEST_DOMAIN",
    "CANDIDATE_MATERIALIZATION_SET_SCHEMA_VERSION",
    "CandidateMaterialization",
    "CandidateMaterializationSet",
    "PHASE1_CANDIDATE_RECORD_DIGEST_DOMAIN",
]
