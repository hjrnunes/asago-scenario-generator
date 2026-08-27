"""Taxonomy obligation plan data contracts."""

from __future__ import annotations

import json
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

ObligationScope = Literal["in-scope", "out-of-scope"]
ObligationDisposition = Literal[
    "gated",
    "missing-template",
    "infeasible",
    "unsupported",
    "generated",
    "governance-only",
]


class QualificationTraceItem(BaseModel):
    """Trace evidence for one evaluated qualification predicate."""

    model_config = ConfigDict(extra="ignore")

    predicate: str
    facts: str | dict[str, Any]
    result: str | bool
    reason: str


class RejectedCandidateEvidence(BaseModel):
    """Evidence record for a rejected candidate during expansion."""

    model_config = ConfigDict(extra="ignore")

    candidate_id: str
    reason: str


class TaxonomyObligation(BaseModel):
    """One risk-to-attack-pattern obligation in the ledger."""

    model_config = ConfigDict(extra="ignore")

    obligation_id: str
    risk_id: str
    pattern_id: str | None = None
    scope: ObligationScope
    terminal_disposition: ObligationDisposition
    qualification_trace: list[QualificationTraceItem] = Field(default_factory=list)
    accepted_candidates: list[str] = Field(default_factory=list)
    rejected_candidates: list[RejectedCandidateEvidence] = Field(default_factory=list)


class TaxonomyObligationPlan(BaseModel):
    """Authoritative ledger of taxonomy obligations and terminal outcomes."""

    model_config = ConfigDict(extra="ignore")

    taxonomy_version: str
    mapping_version: str
    qualification_ruleset_version: str
    template_version: str
    digest: str
    obligations: list[TaxonomyObligation] = Field(default_factory=list)
    network_calls: int = 0
    model_calls: int = 0

    def to_yaml(self) -> str:
        """Serialize this obligation plan to a deterministic YAML string."""
        data = self.model_dump(mode="json")
        return yaml.dump(
            data,
            default_flow_style=False,
            sort_keys=True,
            allow_unicode=True,
        )

    @classmethod
    def from_yaml(cls, text: str | bytes) -> TaxonomyObligationPlan:
        """Deserialize an obligation plan from YAML text or bytes."""
        data = yaml.safe_load(text)
        return cls.model_validate(data)

    def to_json(self) -> str:
        """Serialize this obligation plan to a deterministic JSON string."""
        data = self.model_dump(mode="json")
        return json.dumps(data, indent=2, sort_keys=True) + "\n"

    @classmethod
    def from_json(cls, text: str | bytes) -> TaxonomyObligationPlan:
        """Deserialize an obligation plan from JSON text or bytes."""
        data = json.loads(text)
        return cls.model_validate(data)


class TaxonomyObligationSnapshot(BaseModel):
    """Pinned taxonomy obligation snapshot input fixture."""

    model_config = ConfigDict(extra="ignore")

    taxonomy_version: str
    mapping_version: str
    qualification_ruleset_version: str
    template_version: str
    digest: str
    relationships: list[dict[str, Any]] = Field(default_factory=list)
    risk_cards: list[dict[str, Any]] = Field(default_factory=list)
    config: dict[str, Any] = Field(default_factory=dict)
    qualification_evaluations: list[dict[str, Any]] = Field(default_factory=list)
    candidate_expansions: list[dict[str, Any]] = Field(default_factory=list)
