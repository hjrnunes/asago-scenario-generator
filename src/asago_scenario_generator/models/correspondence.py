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


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-28T01:11:02Z","module_hash":"faf487268a7650392f33f5040dbe79b4ac35fec88aabbcfe972f87fc76b79211","source_sha256":"5ef7cac6d9c379a647808f9ed6d874d718dcedf6ca76eafd9c53e98839cdfbc0","functions":[{"id":"func/_deterministic_yaml","name":"_deterministic_yaml","line":19,"end_line":39,"hash":"37357942bcba482235659f86ca2eb49bd27ebb5a7c3dd627a9e86698e83c7c26"},{"id":"func/_deterministic_json","name":"_deterministic_json","line":42,"end_line":44,"hash":"16202821fbd81b9882d05bd394dd4b6688304dc1fd4382c3e048decdfd459ebb"},{"id":"func/CorrespondenceProposal.model_post_init","name":"model_post_init","line":81,"end_line":91,"hash":"9a8a150c6231b002e8f022a0002adb798fcb77529f5cdece510cb00c105cc0d3"},{"id":"func/ProposalSet.to_yaml","name":"to_yaml","line":104,"end_line":106,"hash":"e14fa1dfc58e7893271c322d126c2eee5e2ad5db759cc668ae0d5e03fe84aaa0"},{"id":"func/ProposalSet.from_yaml","name":"from_yaml","line":109,"end_line":112,"hash":"5009e103bcc837c6bf5415799760ec35c5d661c0ec0f988c1a23e85797470320"},{"id":"func/ProposalSet.to_json","name":"to_json","line":114,"end_line":116,"hash":"60067e27ced8f949d5dbe73830b266fc28e51e3c64006ba6c17084baaa915958"},{"id":"func/ProposalSet.from_json","name":"from_json","line":119,"end_line":122,"hash":"358547622f5e95662a8d0c1141a761aca3ec4e211e6fd506674ee68d7bd7a7ac"},{"id":"func/ReconciliationError.code","name":"code","line":169,"end_line":170,"hash":"28fa3e0acce77e8a146dc7748f9ee6902f48d4621a4e0fbfd62a4cd1de865ac4"},{"id":"func/ReconciliationResult.to_yaml","name":"to_yaml","line":187,"end_line":189,"hash":"7e2aaf4852f8d6f8594988098f435d19c4249b088c42b0c8acb9c7801ccb213c"},{"id":"func/ReconciliationResult.from_yaml","name":"from_yaml","line":192,"end_line":195,"hash":"bc1b4fe2d0f235c9e1d4fe35fe64a322a714aa27c56e3d1462b60641904ef477"},{"id":"func/ReconciliationResult.to_json","name":"to_json","line":197,"end_line":199,"hash":"b65017db653d09bff16c77ebe8e90e53c53f8c4eda66aaab7a1714747b81fe3e"},{"id":"func/ReconciliationResult.from_json","name":"from_json","line":202,"end_line":205,"hash":"edaa5a66e45eaf56577e8be64bc106cafebc5ebde9874a4ef762e64bed518477"}]}
# mutate4py-manifest-end
