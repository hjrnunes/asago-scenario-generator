"""Correspondence proposal and reconciliation domain models and serialization contracts."""

from __future__ import annotations

import json
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

RelationType = Literal["supports", "addresses", "overlaps", "contradicts"]
EvidenceSource = Literal[
    "exact-id", "curated-map", "resource-overlap", "heuristic", "model-assisted"
]
EvidenceStrength = Literal["high", "weak"]
AdjudicationStatus = Literal["confirmed", "rejected", "unresolved"]


def _deterministic_yaml(data: dict[str, Any]) -> str:
    """Serialize mapping data to a deterministic YAML string.

    Double-quoted style is required for losslessness: PyYAML's plain,
    single-quoted, and literal styles silently corrupt U+0085 (NEL)
    values, which its reader treats as a line break.
    """
    # Kwarg values are bound to locals so each constant sits on an executed
    # line: coverage attributes a call to its first line only, leaving
    # constants on continuation lines invisible to mutation selection.
    block_style = False
    sort_keys = True
    allow_unicode = True
    default_style = '"'
    return yaml.dump(
        data,
        default_flow_style=block_style,
        sort_keys=sort_keys,
        allow_unicode=allow_unicode,
        default_style=default_style,
    )


def _deterministic_json(data: dict[str, Any]) -> str:
    """Serialize mapping data to a deterministic JSON string."""
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


class ProposalProvenance(BaseModel):
    """Provenance tracking for a correspondence proposal."""

    model_config = ConfigDict(extra="ignore")

    proposer_id: str
    proposer_version: str = "1"
    evidence_refs: list[str] = Field(default_factory=list)
    stpa_version: str = ""
    taxonomy_version: str = ""
    rationale: str = ""
    adapter_kind: str | None = None


class CorrespondenceProposal(BaseModel):
    """Individual correspondence proposal linking STPA and taxonomy references."""

    model_config = ConfigDict(extra="ignore")

    proposal_id: str
    left_ref: str
    right_ref: str
    relation_type: str = "supports"
    evidence_source: str = "exact-id"
    strength: str = "high"
    proposer_id: str = ""
    proposer_version: str = "1"
    evidence_refs: list[str] = Field(default_factory=list)
    stpa_version: str = ""
    taxonomy_version: str = ""
    rationale: str = ""
    provenance: ProposalProvenance | None = None
    is_confirmed: bool = False

    def model_post_init(self, __context: Any) -> None:
        """Ensure provenance sub-model is populated if top-level fields are present."""
        if self.provenance is None and self.proposer_id:
            self.provenance = ProposalProvenance(
                proposer_id=self.proposer_id,
                proposer_version=self.proposer_version,
                evidence_refs=list(self.evidence_refs),
                stpa_version=self.stpa_version,
                taxonomy_version=self.taxonomy_version,
                rationale=self.rationale,
            )


class ProposalSet(BaseModel):
    """Collection of correspondence proposals."""

    model_config = ConfigDict(extra="ignore")

    schema_version: str | int = "1"
    stpa_version: str = ""
    taxonomy_version: str = ""
    proposals: list[CorrespondenceProposal] = Field(default_factory=list)

    def to_yaml(self) -> str:
        """Serialize proposal set to deterministic YAML string."""
        return _deterministic_yaml(self.model_dump(mode="json"))

    @classmethod
    def from_yaml(cls, text: str | bytes) -> ProposalSet:
        """Deserialize proposal set from YAML text or bytes."""
        data = yaml.safe_load(text)
        return cls.model_validate(data)

    def to_json(self) -> str:
        """Serialize proposal set to deterministic JSON string."""
        return _deterministic_json(self.model_dump(mode="json"))

    @classmethod
    def from_json(cls, text: str | bytes) -> ProposalSet:
        """Deserialize proposal set from JSON text or bytes."""
        data = json.loads(text)
        return cls.model_validate(data)


class AdjudicationHistoryItem(BaseModel):
    """Audit entry for an adjudication decision."""

    model_config = ConfigDict(extra="ignore")

    adjudication: str
    timestamp: str | None = None
    reason: str | None = None
    adjudicated_by: str | None = None


class ReconciledProposal(BaseModel):
    """A reconciled correspondence proposal with adjudication status."""

    model_config = ConfigDict(extra="ignore")

    proposal_id: str
    left_ref: str
    right_ref: str
    relation_type: str
    evidence_source: str
    strength: str
    adjudication: str = "unresolved"
    conflict_reason: str | None = None
    proposer_id: str = ""
    proposer_version: str = "1"
    evidence_refs: list[str] = Field(default_factory=list)
    stpa_version: str = ""
    taxonomy_version: str = ""
    rationale: str = ""
    provenance: ProposalProvenance | None = None
    adjudication_history: list[AdjudicationHistoryItem] = Field(default_factory=list)


class ReconciliationError(BaseModel):
    """An error recorded during correspondence reconciliation."""

    model_config = ConfigDict(extra="ignore")

    proposal_id: str
    error_code: str
    message: str = ""

    @property
    def code(self) -> str:
        return self.error_code


class ReconciliationResult(BaseModel):
    """Artifact capturing the complete reconciliation outcome."""

    model_config = ConfigDict(extra="ignore")

    schema_version: str | int = "1"
    stpa_version: str = ""
    taxonomy_version: str = ""
    is_valid: bool = True
    proposals: list[ReconciledProposal] = Field(default_factory=list)
    errors: list[ReconciliationError] = Field(default_factory=list)
    network_calls: int = 0
    model_calls: int = 0

    def to_yaml(self) -> str:
        """Serialize reconciliation result to deterministic YAML string."""
        return _deterministic_yaml(self.model_dump(mode="json"))

    @classmethod
    def from_yaml(cls, text: str | bytes) -> ReconciliationResult:
        """Deserialize reconciliation result from YAML text or bytes."""
        data = yaml.safe_load(text)
        return cls.model_validate(data)

    def to_json(self) -> str:
        """Serialize reconciliation result to deterministic JSON string."""
        return _deterministic_json(self.model_dump(mode="json"))

    @classmethod
    def from_json(cls, text: str | bytes) -> ReconciliationResult:
        """Deserialize reconciliation result from JSON text or bytes."""
        data = json.loads(text)
        return cls.model_validate(data)
