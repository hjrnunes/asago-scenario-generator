"""Typed source-influence provenance models for taxonomy scenario envelopes.

Persisted source-influence provenance links projected attack-tree leaves
and narrative steps to the threat sources, mitigations, and capability
constraints declared for a taxonomy scenario envelope.  Qualification is
deterministic and fails closed: missing, unknown, mismatched, orphaned,
and unreferenced provenance all produce typed violations with coverage
metrics (see ``pipeline.source_influence`` for the engine).

Design invariants:

- **Typed references**: every provenance reference carries an explicit
  ``source_type`` and stable ``source_id`` (e.g. ``threat:T12``,
  ``mitigation:M12``, ``constraint:KCX-MAGENT``), so serialized metadata
  is independently inspectable without project imports.
- **Shared records**: declared source records are a scenario-level
  universe stored exactly once; artifact links resolve to those records.
- **Self-describing links**: each artifact link records its artifact kind
  and ID plus the projected step it claims to realize, so persisted
  metadata can be re-validated against the envelope.
"""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

# ---------------------------------------------------------------------------#
# Typed source records
# ---------------------------------------------------------------------------#


class SourceInfluenceSourceType(str, Enum):
    """Typed source categories referenced by source-influence provenance."""

    threat_source = "threat_source"
    mitigation = "mitigation"
    capability_constraint = "capability_constraint"


_SOURCE_PREFIX_TO_TYPE: dict[str, SourceInfluenceSourceType] = {
    "threat": SourceInfluenceSourceType.threat_source,
    "mitigation": SourceInfluenceSourceType.mitigation,
    "constraint": SourceInfluenceSourceType.capability_constraint,
}


class SourceInfluenceSourceRef(BaseModel):
    """One declared source record in the scenario's provenance universe."""

    model_config = ConfigDict(extra="forbid")

    source_type: SourceInfluenceSourceType = Field(
        description=(
            "Typed source category: threat_source, mitigation, or "
            "capability_constraint."
        ),
    )
    source_id: str = Field(
        min_length=1,
        description=(
            "Stable source identifier from the taxonomy scenario envelope "
            "vocabulary, e.g. 'threat:T12', 'mitigation:M12', or "
            "'constraint:KCX-MAGENT'."
        ),
    )

    @model_validator(mode="after")
    def _source_id_matches_type(self) -> SourceInfluenceSourceRef:
        """Reject IDs whose serialized prefix contradicts their type."""
        expected_prefix = {
            SourceInfluenceSourceType.threat_source: "threat:",
            SourceInfluenceSourceType.mitigation: "mitigation:",
            SourceInfluenceSourceType.capability_constraint: "constraint:",
        }[self.source_type]
        if not self.source_id.startswith(expected_prefix):
            raise ValueError(
                f"source_id {self.source_id!r} must use the "
                f"{expected_prefix!r} prefix for source_type "
                f"{self.source_type.value!r}"
            )
        identifier = self.source_id[len(expected_prefix) :]
        if not identifier or identifier != identifier.strip():
            raise ValueError("source_id must contain a non-blank identifier")
        return self

    def __hash__(self) -> int:
        return hash((self.source_type, self.source_id))


def parse_source_ref(value: str) -> SourceInfluenceSourceRef:
    """Parse a compact ``type:id`` reference into a typed source record.

    Accepts the taxonomy envelope vocabulary prefixes ``threat:``,
    ``mitigation:``, and ``constraint:``.
    """
    value = value.strip()
    prefix, separator, source_id = value.partition(":")
    if not separator or prefix not in _SOURCE_PREFIX_TO_TYPE or not source_id:
        raise ValueError(
            f"invalid source reference {value!r}: expected a 'type:source_id' "
            f"value with one of the prefixes {sorted(_SOURCE_PREFIX_TO_TYPE)}"
        )
    return SourceInfluenceSourceRef(
        source_type=_SOURCE_PREFIX_TO_TYPE[prefix],
        source_id=value,
    )


# ---------------------------------------------------------------------------#
# Artifact elements and links
# ---------------------------------------------------------------------------#


class SourceInfluenceArtifactKind(str, Enum):
    """Generated artifact element kind covered by source-influence provenance."""

    projected_leaf = "projected_leaf"
    narrative_step = "narrative_step"


class SourceInfluenceArtifactElement(BaseModel):
    """One generated artifact element that realizes projected steps."""

    model_config = ConfigDict(extra="forbid")

    artifact_id: str = Field(
        min_length=1,
        description=(
            "Generated artifact element identifier: attack-tree leaf node id "
            "(e.g. 'n1.1') or narrative step number as a string."
        ),
    )
    projected_step_ids: tuple[str, ...] = Field(
        min_length=1,
        description="Projected step IDs this artifact element realizes.",
    )


class SourceInfluenceArtifactLink(BaseModel):
    """A provenance link from one artifact element to typed source records.

    The recorded ``projected_step_id`` is the step the link claims the
    artifact realizes; qualification verifies it against the artifact's
    actual realized projected steps.
    """

    model_config = ConfigDict(extra="forbid")

    artifact_kind: SourceInfluenceArtifactKind = Field(
        description="Generated artifact stage the linked element belongs to.",
    )
    artifact_id: str = Field(
        min_length=1,
        description=(
            "Generated artifact element identifier this link attaches to "
            "(leaf id or narrative step number as a string)."
        ),
    )
    projected_step_id: str = Field(
        min_length=1,
        description=(
            "Projected step ID this link claims the artifact realizes.  "
            "Must match one of the artifact's realized projected steps."
        ),
    )
    source_refs: tuple[SourceInfluenceSourceRef, ...] = Field(
        default=(),
        description=(
            "Typed source records this artifact is linked to.  Must "
            "resolve against the declared source universe and include "
            "every source type."
        ),
    )


# ---------------------------------------------------------------------------#
# Violations, metrics, qualification, and persisted block
# ---------------------------------------------------------------------------#


class SourceInfluenceViolationCode(str, Enum):
    """Typed violation codes for source-influence provenance failures."""

    missing_source_provenance = "missing_source_provenance"
    unknown_source_reference = "unknown_source_reference"
    provenance_projected_step_mismatch = "provenance_projected_step_mismatch"
    orphaned_source_provenance = "orphaned_source_provenance"
    unreferenced_source_influence_artifact = "unreferenced_source_influence_artifact"


class SourceInfluenceViolation(BaseModel):
    """A single typed source-influence provenance violation."""

    model_config = ConfigDict(extra="forbid")

    code: SourceInfluenceViolationCode = Field(
        description="Typed violation code from the closed violation set.",
    )
    detail: str = Field(min_length=1)
    source_type: SourceInfluenceSourceType | None = Field(
        default=None,
        description="Source type involved, when the violation names a source.",
    )
    source_id: str | None = Field(
        default=None,
        description="Stable source ID involved, when the violation names a source.",
    )
    artifact_id: str | None = Field(
        default=None,
        description="Artifact element ID involved, when the violation names one.",
    )
    projected_step_id: str | None = Field(
        default=None,
        description="Projected step ID involved, when the violation names one.",
    )


class CoverageFraction(BaseModel):
    """Deterministic coverage fraction (numerator over denominator)."""

    model_config = ConfigDict(extra="forbid")

    numerator: int = Field(default=0, ge=0)
    denominator: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def _numerator_within_denominator(self) -> CoverageFraction:
        if self.numerator > self.denominator:
            raise ValueError(
                f"coverage numerator {self.numerator} exceeds denominator "
                f"{self.denominator}"
            )
        return self


class SourceInfluenceMetrics(BaseModel):
    """Deterministic source-influence qualification metrics."""

    model_config = ConfigDict(extra="forbid")

    projected_leaf_coverage: CoverageFraction = Field(
        description="Covered projected leaves over all provenance-carrying leaves.",
    )
    narrative_step_coverage: CoverageFraction = Field(
        description="Covered narrative steps over all narrative steps.",
    )
    source_reference_coverage: CoverageFraction = Field(
        description="Declared source records referenced at least once over all declared records.",
    )
    orphaned_source_count: int = Field(
        default=0,
        ge=0,
        description="Declared source records never referenced by any artifact link.",
    )
    unreferenced_artifact_count: int = Field(
        default=0,
        ge=0,
        description="Artifact elements carrying no provenance link at all.",
    )


class SourceInfluenceQualification(BaseModel):
    """Aggregated deterministic source-influence qualification result."""

    model_config = ConfigDict(extra="forbid")

    valid: bool = Field(
        default=True,
        description="False when any typed provenance violation is present.",
    )
    status: Literal["pass", "fail"] = Field(
        default="pass",
        description="Serialized qualification status; 'pass' iff valid.",
    )
    violations: tuple[SourceInfluenceViolation, ...] = Field(default_factory=tuple)
    metrics: SourceInfluenceMetrics

    @model_validator(mode="after")
    def _sync_status(self) -> SourceInfluenceQualification:
        expected_valid = not self.violations
        if self.valid != expected_valid:
            raise ValueError(
                "valid must be False when violations exist and True otherwise"
            )
        expected_status = "pass" if expected_valid else "fail"
        if self.status != expected_status:
            raise ValueError(
                f"status must be {expected_status!r} for the recorded violations"
            )
        return self


class SourceInfluenceProvenanceBlock(BaseModel):
    """Typed source-influence provenance block persisted on the envelope.

    Carries the scenario-level declared source universe (stored once),
    the per-artifact links for projected leaves and narrative steps, and
    the deterministic qualification metrics plus status.  Envelope-level
    validation recomputes the qualification from the envelope's actual
    artifacts and rejects stale or tampered persisted metadata.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1"] = "1"
    declared_sources: tuple[SourceInfluenceSourceRef, ...] = Field(
        description=(
            "Scenario-level declared source universe: each typed source "
            "record is stored exactly once."
        ),
    )
    leaf_links: tuple[SourceInfluenceArtifactLink, ...] = Field(
        default=(),
        description="Provenance links for projected attack-tree leaves.",
    )
    narrative_links: tuple[SourceInfluenceArtifactLink, ...] = Field(
        default=(),
        description="Provenance links for narrative steps.",
    )
    metrics: SourceInfluenceMetrics = Field(
        description="Deterministic qualification metrics for this block.",
    )
    status: Literal["pass", "fail"] = Field(
        description="Persisted qualification status for this block.",
    )


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-20T11:16:30Z","module_hash":"fd4973d6ba3c6cb42261b8f0c39599140444b008a9f0c3b34d71d9b22ad85e93","functions":[{"id":"func/SourceInfluenceSourceRef._source_id_matches_type","name":"_source_id_matches_type","line":71,"end_line":87,"hash":"dfd00b2cdf38b8828659a010ee350d156cf59fb52cf116017f5b37e485d7b245"},{"id":"func/SourceInfluenceSourceRef.__hash__","name":"__hash__","line":89,"end_line":90,"hash":"8811d518fa96d2634be1b9b22c04b156fb7324efc92bca15e7eead46f5771cf5"},{"id":"func/parse_source_ref","name":"parse_source_ref","line":93,"end_line":109,"hash":"cb61eee4750e1b2c92dca8c822e0ff4e19ece72f158a6bd9f5ea75636ae6f167"},{"id":"func/CoverageFraction._numerator_within_denominator","name":"_numerator_within_denominator","line":230,"end_line":236,"hash":"1fc62a4539751de8f4130ae6dde34e1eabb7456f3d24347e8087bb7b61fddf0d"},{"id":"func/SourceInfluenceQualification._sync_status","name":"_sync_status","line":282,"end_line":293,"hash":"3869022fe206ca5aa3b05ce10d82d27d0efc8ebf3c5b4e6f833cc805006c90f8"}]}
# mutate4py-manifest-end
