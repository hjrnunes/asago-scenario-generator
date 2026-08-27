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
        block_style = False
        sort_keys = True
        allow_unicode = True
        return yaml.dump(
            data,
            default_flow_style=block_style,
            sort_keys=sort_keys,
            allow_unicode=allow_unicode,
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


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-27T17:25:35Z","module_hash":"d38a96134997dcc74fe51873c0634b1f42f84abc8331a9dcd19e09cb576b85de","source_sha256":"979060079ecd283c1b0dda3830df765546bc5ca9f1c5d8b3af1419e23cd3d2af","functions":[{"id":"func/TaxonomyObligationPlan.to_yaml","name":"to_yaml","line":71,"end_line":82,"hash":"73217524bf13313902c32d35d43d5e49a2f1735614a31ad45e5832d74f64d209"},{"id":"func/TaxonomyObligationPlan.from_yaml","name":"from_yaml","line":85,"end_line":88,"hash":"a43c0ed0ec41ad4a493f9d10c181c7c32dc184828a3ae779f82753dbab664dfb"},{"id":"func/TaxonomyObligationPlan.to_json","name":"to_json","line":90,"end_line":93,"hash":"1e0e70433e57ad4a80551c4baa6c639eff1af94d13e9bee27bc04777706aa33e"},{"id":"func/TaxonomyObligationPlan.from_json","name":"from_json","line":96,"end_line":99,"hash":"b60d8d93a3982890d86407390ecbd6419103e0e6ad53f54162dff14f52d7b4fd"}]}
# mutate4py-manifest-end
