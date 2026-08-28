"""Taxonomy obligation plan data contracts."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

ObligationScopeDisposition = Literal[
    "applicable", "capability_excluded", "governance_only"
]
ObligationQualificationDisposition = Literal[
    "ready",
    "missing_evidence",
    "contradictory_evidence",
    "structurally_infeasible",
    "not_attempted",
]
ObligationCorrespondenceDisposition = Literal["not_assessed"]
ObligationProjectionDisposition = Literal[
    "projectable",
    "projection_infeasible",
    "budget_deferred",
    "not_attempted",
]


def _deterministic_yaml(data: dict[str, Any]) -> str:
    """Serialize mapping data to a deterministic YAML string."""
    return yaml.dump(
        data,
        default_flow_style=False,
        sort_keys=True,
        allow_unicode=True,
    )


def _deterministic_json(data: dict[str, Any]) -> str:
    """Serialize mapping data to a deterministic JSON string."""
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def _synced_pin_pair(
    modern: str | None, legacy: str | None
) -> tuple[str | None, str | None]:
    """Keep a modern pin and its legacy alias consistent with each other."""
    if legacy and not modern:
        return legacy, legacy
    if modern and not legacy:
        return modern, modern
    return modern, legacy


def _reject_unsupported_schema_version(data: dict[str, Any]) -> None:
    """Reject persisted plans declaring an unsupported schema version."""
    schema_ver = data.get("schema_version")
    if schema_ver != "taxonomy-obligation-plan-v1":
        raise ValueError(f"Unsupported schema version: '{schema_ver}' is unsupported")


def _reject_phase_one_correspondence_claims(data: dict[str, Any]) -> None:
    """Reject persisted Phase 1 plans claiming a correspondence disposition."""
    for ob in data.get("obligations", []):
        if isinstance(ob, dict):
            disp = ob.get("correspondence_disposition")
            if disp is not None and disp != "not_assessed":
                raise ValueError(
                    f"Invalid correspondence disposition: '{disp}' is invalid"
                )


def compute_sha256(data: Any) -> str:
    """Compute deterministic SHA-256 hex digest for arbitrary data."""
    if isinstance(data, str):
        content = data.encode("utf-8")
    elif isinstance(data, (dict, list)):
        content = json.dumps(data, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    elif isinstance(data, bytes):
        content = data
    else:
        content = str(data).encode("utf-8")
    return hashlib.sha256(content).hexdigest()


class QualificationTraceItem(BaseModel):
    """Trace evidence for one evaluated qualification predicate."""

    model_config = ConfigDict(extra="forbid")

    predicate: str
    facts: str | dict[str, Any]
    result: str | bool
    reason: str


class CandidateRecord(BaseModel):
    """Evidence record for a candidate during projection."""

    model_config = ConfigDict(extra="forbid")

    candidate_id: str
    projection_disposition: ObligationProjectionDisposition = "projectable"
    reason: str = ""


class TaxonomyObligation(BaseModel):
    """One risk-to-attack-pattern obligation in the ledger."""

    model_config = ConfigDict(extra="forbid")

    obligation_id: str
    risk_id: str
    pattern_id: str | None = None
    scope_disposition: ObligationScopeDisposition
    qualification_disposition: ObligationQualificationDisposition
    correspondence_disposition: ObligationCorrespondenceDisposition = "not_assessed"
    projection_disposition: ObligationProjectionDisposition = "not_attempted"
    qualification_trace: list[QualificationTraceItem] = Field(default_factory=list)
    candidate_records: list[CandidateRecord] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)


class ObligationPlanSummary(BaseModel):
    """Summary counts derived from obligation rows."""

    model_config = ConfigDict(extra="forbid")

    total: int = 0
    applicable: int = 0
    governance_only: int = 0
    capability_excluded: int = 0
    ready: int = 0
    missing_or_contradictory: int = 0
    structurally_infeasible: int = 0
    projectable: int = 0
    projection_infeasible: int = 0
    budget_deferred: int = 0


class TaxonomyObligationPlan(BaseModel):
    """Authoritative ledger of taxonomy obligations and terminal outcomes."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["taxonomy-obligation-plan-v1"] = (
        "taxonomy-obligation-plan-v1"
    )
    catalog_pins: dict[str, str] = Field(default_factory=dict)
    mapping_pins: dict[str, str] = Field(default_factory=dict)
    capability_snapshot_digest: str
    qualification_facts_digest: str
    generation_inputs_digest: str
    semantic_digest: str
    obligations: list[TaxonomyObligation] = Field(default_factory=list)
    summary: ObligationPlanSummary = Field(default_factory=ObligationPlanSummary)
    network_calls: int = 0
    model_calls: int = 0

    def compute_semantic_digest(self) -> str:
        """Compute the semantic digest from canonical content."""
        canonical_payload = {
            "schema_version": self.schema_version,
            "catalog_pins": self.catalog_pins,
            "mapping_pins": self.mapping_pins,
            "capability_snapshot_digest": self.capability_snapshot_digest,
            "qualification_facts_digest": self.qualification_facts_digest,
            "generation_inputs_digest": self.generation_inputs_digest,
            "obligations": [ob.model_dump(mode="json") for ob in self.obligations],
            "summary": self.summary.model_dump(mode="json"),
        }
        return compute_sha256(canonical_payload)

    def to_yaml(self) -> str:
        """Serialize this obligation plan to a deterministic YAML string."""
        data = self.model_dump(mode="json")
        return _deterministic_yaml(data)

    @classmethod
    def from_yaml(cls, text: str | bytes) -> TaxonomyObligationPlan:
        """Deserialize an obligation plan from YAML text or bytes, verifying closed schema and semantic digest."""
        data = yaml.safe_load(text)
        if not isinstance(data, dict):
            raise ValueError("YAML data must be a dictionary")
        return cls._validate_and_check_digest(data)

    def to_json(self) -> str:
        """Serialize this obligation plan to a deterministic JSON string."""
        data = self.model_dump(mode="json")
        return _deterministic_json(data)

    @classmethod
    def from_json(cls, text: str | bytes) -> TaxonomyObligationPlan:
        """Deserialize an obligation plan from JSON text or bytes, verifying closed schema and semantic digest."""
        data = json.loads(text)
        if not isinstance(data, dict):
            raise ValueError("JSON data must be a dictionary")
        return cls._validate_and_check_digest(data)

    @classmethod
    def _validate_and_check_digest(cls, data: dict[str, Any]) -> TaxonomyObligationPlan:
        """Validate model schema and ensure semantic digest matches computed value."""
        _reject_unsupported_schema_version(data)
        _reject_phase_one_correspondence_claims(data)
        try:
            plan = cls.model_validate(data)
        except ValidationError as exc:
            raise ValueError(str(exc)) from exc

        expected_digest = plan.compute_semantic_digest()
        if plan.semantic_digest != expected_digest:
            raise ValueError(
                f"Digest mismatch: recorded '{plan.semantic_digest}' != computed '{expected_digest}'"
            )

        return plan


class TaxonomyObligationSnapshot(BaseModel):
    """Pinned taxonomy obligation snapshot input fixture."""

    model_config = ConfigDict(extra="ignore")

    catalog_pin: str = "atlas-2026.05"
    mapping_pin: str = "sssom-v1"
    capability_content: Any = "profile-v1"
    qualification_facts: Any = "facts-v1"
    generation_inputs: Any = None
    capability_snapshot_digest: str | None = None
    qualification_facts_digest: str | None = None
    generation_inputs_digest: str | None = None
    semantic_digest: str | None = None
    relationships: list[dict[str, Any]] = Field(default_factory=list)
    risk_cards: list[dict[str, Any]] = Field(default_factory=list)
    config: dict[str, Any] = Field(default_factory=dict)
    qualification_evaluations: list[dict[str, Any]] = Field(default_factory=list)
    candidate_expansions: list[dict[str, Any]] = Field(default_factory=list)
    ica_prose: str = ""

    # Legacy field aliases
    taxonomy_version: str | None = None
    mapping_version: str | None = None
    qualification_ruleset_version: str | None = None
    template_version: str | None = None
    digest: str | None = None

    def model_post_init(self, __context: Any) -> None:
        self.catalog_pin, self.taxonomy_version = _synced_pin_pair(
            self.catalog_pin, self.taxonomy_version
        )
        self.mapping_pin, self.mapping_version = _synced_pin_pair(
            self.mapping_pin, self.mapping_version
        )


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-27T17:25:35Z","module_hash":"d38a96134997dcc74fe51873c0634b1f42f84abc8331a9dcd19e09cb576b85de","source_sha256":"979060079ecd283c1b0dda3830df765546bc5ca9f1c5d8b3af1419e23cd3d2af","functions":[{"id":"func/TaxonomyObligationPlan.to_yaml","name":"to_yaml","line":71,"end_line":82,"hash":"73217524bf13313902c32d35d43d5e49a2f1735614a31ad45e5832d74f64d209"},{"id":"func/TaxonomyObligationPlan.from_yaml","name":"from_yaml","line":85,"end_line":88,"hash":"a43c0ed0ec41ad4a493f9d10c181c7c32dc184828a3ae779f82753dbab664dfb"},{"id":"func/TaxonomyObligationPlan.to_json","name":"to_json","line":90,"end_line":93,"hash":"1e0e70433e57ad4a80551c4baa6c639eff1af94d13e9bee27bc04777706aa33e"},{"id":"func/TaxonomyObligationPlan.from_json","name":"from_json","line":96,"end_line":99,"hash":"b60d8d93a3982890d86407390ecbd6419103e0e6ad53f54162dff14f52d7b4fd"}]}
# mutate4py-manifest-end
