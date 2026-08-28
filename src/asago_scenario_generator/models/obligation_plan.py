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
# {"version":1,"tested_at":"2026-08-28T10:30:09Z","module_hash":"3e74c43b53c6ebdc09e41c969863d2f10a3a8a7002e848ff95d578ef33d995e7","source_sha256":"d38d79417a70d44b30fb1f4167a4302e5a0515d1aa1db5d55bd5700e4f68ef71","functions":[{"id":"func/_deterministic_yaml","name":"_deterministic_yaml","line":31,"end_line":38,"hash":"d674bc30b830451cc3349022a06650c558a8ba825e9a12628386dc837529a376"},{"id":"func/_deterministic_json","name":"_deterministic_json","line":41,"end_line":43,"hash":"16202821fbd81b9882d05bd394dd4b6688304dc1fd4382c3e048decdfd459ebb"},{"id":"func/_synced_pin_pair","name":"_synced_pin_pair","line":46,"end_line":54,"hash":"5f40bba85b95b185e95a28d498baa5ae0654ee078c6c2b10e9ad12c1da5c05e3"},{"id":"func/_reject_unsupported_schema_version","name":"_reject_unsupported_schema_version","line":57,"end_line":61,"hash":"70bb8c8d4ef9ad44335c3c56033ac8324066337465bd7821d2981a73e7ae14b2"},{"id":"func/_reject_phase_one_correspondence_claims","name":"_reject_phase_one_correspondence_claims","line":64,"end_line":72,"hash":"3d775cf6474e0d860267bf24882a4a92e13123b2d41846cb13f6dc6936bbc113"},{"id":"func/compute_sha256","name":"compute_sha256","line":75,"end_line":87,"hash":"4707125efd8af9d86b2af97a6af3647302357a071aee7bf5a69e3b24194cdeb3"},{"id":"func/TaxonomyObligationPlan.compute_semantic_digest","name":"compute_semantic_digest","line":164,"end_line":176,"hash":"c332b0f224d6d3c9c5e1379f7123c2ced3fd92fe6fc05e14715e55db28d78311"},{"id":"func/TaxonomyObligationPlan.to_yaml","name":"to_yaml","line":178,"end_line":181,"hash":"8b1bef9d6c264c21c00c3fa67ecb0bd8d6afa5df9d406955e8620aea78edcf13"},{"id":"func/TaxonomyObligationPlan.from_yaml","name":"from_yaml","line":184,"end_line":189,"hash":"effeb40b17ae70ec0495c039c84c29e6091b9b7d19bce45ec75a179162e2c806"},{"id":"func/TaxonomyObligationPlan.to_json","name":"to_json","line":191,"end_line":194,"hash":"70497caeeb7929c0b91709e8f5442a6254e8a3b5f355ca26544470c5272ffd72"},{"id":"func/TaxonomyObligationPlan.from_json","name":"from_json","line":197,"end_line":202,"hash":"0c0f2a5b27f9b68ee782fc5d14472f63cfb1546998263dbc8f2db3d14cc1e6d1"},{"id":"func/TaxonomyObligationPlan._validate_and_check_digest","name":"_validate_and_check_digest","line":205,"end_line":220,"hash":"ae74548a249671dae1ee2f58ea38cb8d25017a5532c99b0f0b54a95dfafbff9d"},{"id":"func/TaxonomyObligationSnapshot.model_post_init","name":"model_post_init","line":251,"end_line":257,"hash":"4b0d8ad2475a9439c176abcbd3e6c20fec92d835b12c2b37f2c61a3e0eee060f"}]}
# mutate4py-manifest-end
