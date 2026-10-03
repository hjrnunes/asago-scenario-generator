"""Content-addressed pins that published synthesis artifacts use to cite sources."""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import Field

from asago_scenario_generator.models.canonical import (
    ClosedCanonicalModel,
    compute_framed_digest,
)

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
ObligationId = Annotated[str, Field(pattern=r"^ob:v1:[0-9a-f]{64}$")]


class ArtifactPin(ClosedCanonicalModel):
    """Content-addressed identity of one upstream artifact."""

    artifact_id: str = Field(min_length=1)
    schema_version: str = Field(min_length=1)
    semantic_digest: Digest


class TraceReference(ClosedCanonicalModel):
    """Reference to one exact record in a pinned artifact."""

    artifact_id: str = Field(min_length=1)
    schema_version: str = Field(min_length=1)
    semantic_digest: Digest
    record_id: str = Field(min_length=1)


def _canonical_ica_enumeration_payload(ica_enumeration: Any) -> dict[str, Any]:
    """Canonicalize set-like ICA collections before computing their pin."""
    payload = ica_enumeration.model_dump(mode="json")
    slots = []
    for slot in payload["slots"]:
        slot = dict(slot)
        # ``unresolved_reason`` was added as an explicit third structural
        # disposition.  Preserve the v1 digest for historical resolved/N/A
        # slots by omitting its null default; a non-null reason remains
        # semantic content and is therefore retained in the pin.
        if slot.get("unresolved_reason") is None:
            slot.pop("unresolved_reason", None)
        icas = []
        for ica in slot["icas"]:
            ica = dict(ica)
            # Human-facing style diagnostics are deliberately non-semantic.
            # They must not repin the artifacts that cite this enumeration.
            ica.pop("quality_warnings", None)
            ica["related_hazards"] = sorted(ica["related_hazards"])
            ica["related_constraints"] = sorted(ica["related_constraints"])
            icas.append(ica)
        slot["icas"] = sorted(icas, key=lambda item: item["ica_id"])
        slots.append(slot)
    payload["slots"] = sorted(slots, key=lambda item: item["slot_id"])
    return payload


def compute_ica_enumeration_digest(ica_enumeration: Any) -> str:
    """Compute the canonical source pin for one typed ICA enumeration."""
    from asago_scenario_generator.stpa.models.ica_enumeration import ICAEnumeration

    if not isinstance(ica_enumeration, ICAEnumeration):
        raise TypeError("ica_enumeration must be an ICAEnumeration")
    return compute_framed_digest(
        "asago-scenario-generator:ica-enumeration:v1",
        _canonical_ica_enumeration_payload(ica_enumeration),
    )


__all__ = [
    "ArtifactPin",
    "Digest",
    "ObligationId",
    "TraceReference",
    "compute_ica_enumeration_digest",
]
