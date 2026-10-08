"""Closed, immutable contracts for the taxonomy obligation ledger."""

from __future__ import annotations

from collections import Counter
from itertools import chain
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    model_serializer,
    model_validator,
)

from asago_scenario_generator.models.attack_pattern_contracts import (
    AuthoritativeFactReference,
    EvaluatedFactEvidence,
    Scalar,
    TaxonomyPin,
    validate_fact_scalar,
)
from asago_scenario_generator.models.attack_pattern_projection import (
    EntryPointResourceReference,
    ResourceBinding,
)
from asago_scenario_generator.models.canonical import (
    FrozenDict,
    canonical_yaml,
    compute_framed_digest as _compute_framed_digest,
    load_yaml_mapping,
    normalize_unicode,
)

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
ObligationProjectionDisposition = Literal[
    "projectable", "projection_infeasible", "budget_deferred", "not_attempted"
]

_PLAN_SCHEMA_VERSION = "taxonomy-obligation-plan-v1"
_PLAN_DIGEST_DOMAIN = "asago-scenario-generator:taxonomy-obligation-plan:v1"
_SHA256_RE = r"^[0-9a-f]{64}$"


class _ContractModel(BaseModel):
    """Common closed and immutable configuration for authoritative records."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    @model_validator(mode="before")
    @classmethod
    def normalize_input_strings(cls, value: Any) -> Any:
        """Apply the repository NFC rule before any field is interpreted."""
        return normalize_unicode(value)


class RiskEvidence(_ContractModel):
    """One typed evidence span copied from a reviewed risk card."""

    text: str = ""
    source: str | None = None
    relevance: float | None = Field(default=None, ge=0.0, le=1.0)


class MitigationReference(_ContractModel):
    """One typed mitigation reference copied from a reviewed risk card."""

    mitigation_id: str | None = None
    description: str = ""
    source: str | None = None


class RiskReference(_ContractModel):
    """Immutable provenance for the reviewed risk that created an obligation."""

    risk_id: str = Field(min_length=1)
    risk_name: str = ""
    risk_description: str = ""
    taxonomy: str = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    grounding_confidence: Literal["high", "medium", "low"] = "low"
    evidence: tuple[RiskEvidence, ...] = ()
    scores: dict[str, float] | None = None
    mitigations: tuple[MitigationReference, ...] = ()
    threat: str | None = None
    threat_source: str | None = None
    vulnerability: str | None = None
    consequence: str | None = None
    impact: str | None = None

    @model_validator(mode="after")
    def freeze_nested_mappings(self) -> RiskReference:
        """Prevent mutation of optional score metadata after validation."""
        if self.scores is not None:
            object.__setattr__(self, "scores", FrozenDict(self.scores))
        return self


class TaxonomyChainEntry(_ContractModel):
    """One ordered taxonomy identifier in an authoritative pattern chain."""

    taxonomy: str = Field(min_length=1)
    id: str = Field(min_length=1)


class ConflictingFactReadingEvidence(_ContractModel):
    """One retained conflicting reading and its source."""

    value: Scalar
    source: str = Field(min_length=1)


class QualificationFactEvidence(_ContractModel):
    """One typed qualification reading retained by the obligation ledger."""

    fact: AuthoritativeFactReference
    status: Literal["present", "absent", "unknown", "contradictory"]
    value: Scalar | None = None
    readings: tuple[ConflictingFactReadingEvidence, ...] = ()

    @model_serializer(mode="wrap")
    def _serialize(self, handler: Any) -> dict[str, Any]:
        """Omit empty readings so existing plan digests stay stable."""
        payload = handler(self)
        if not self.readings:
            payload.pop("readings", None)
        return payload

    @model_validator(mode="after")
    def coherent(self) -> QualificationFactEvidence:
        """Require values only for unambiguous present readings."""
        if self.status == "present":
            if self.value is None:
                raise ValueError("present fact evidence requires a value")
            validate_fact_scalar(self.fact, self.value)
        elif self.value is not None:
            raise ValueError(
                "absent, unknown, and contradictory fact evidence require a null value"
            )
        return self

    @model_validator(mode="after")
    def readings_document_a_contradiction(self) -> QualificationFactEvidence:
        """Retain conflicting readings only as two or more contradicting sources."""
        if not self.readings:
            return self
        if self.status != "contradictory":
            raise ValueError(
                "conflicting readings are retained only beside a "
                "contradictory qualification fact"
            )
        if len(self.readings) < 2:
            raise ValueError("a conflicting fact retains at least two readings")
        return self


class FactEvaluationEvidence(_ContractModel):
    """Typed condition or precondition result retained by Phase 1."""

    evaluation_type: Literal["condition", "precondition", "qualification_fact"]
    step_id: str = Field(min_length=1)
    condition_id: str | None = None
    result: Literal["true", "false", "unknown"]
    facts: tuple[EvaluatedFactEvidence | QualificationFactEvidence, ...] = Field(
        min_length=1
    )
    rationale: str = Field(min_length=1)


class EvidenceRecord(_ContractModel):
    """Typed, non-assertive evidence explaining a planning disposition."""

    kind: Literal[
        "mapping",
        "scope",
        "qualification",
        "projection",
        "governance",
        "advisory",
    ]
    detail: str = Field(min_length=1)
    source: str | None = None
    fact_evaluations: tuple[FactEvaluationEvidence, ...] = ()


def _require_obligation_condition(condition: bool, message: str) -> None:
    """Raise a stable validation error when an obligation condition is false."""
    if not condition:
        raise ValueError(message)


def _validate_governance_obligation(row: TaxonomyObligation) -> None:
    """Validate the closed shape of a pattern-less governance row."""
    _require_obligation_condition(
        row.scope_disposition == "governance_only",
        "pattern-less obligations must be governance_only",
    )
    _require_obligation_condition(
        row.qualification_disposition == "not_attempted",
        "governance-only obligations must be not_attempted",
    )
    _require_obligation_condition(
        not row.taxonomy_chain and row.attack_pattern_semantic_digest is None,
        "pattern-less obligations cannot carry pattern provenance",
    )


def _validate_pattern_obligation(row: TaxonomyObligation) -> None:
    """Validate pattern identity and the scope/qualification matrix."""
    _require_obligation_condition(
        row.attack_pattern_semantic_digest is not None,
        "pattern obligations require attack_pattern_semantic_digest",
    )
    _require_obligation_condition(
        not (
            row.scope_disposition == "applicable"
            and row.qualification_disposition == "not_attempted"
        ),
        "applicable obligations require qualification disposition",
    )
    _require_obligation_condition(
        not (
            row.scope_disposition != "applicable"
            and row.qualification_disposition != "not_attempted"
        ),
        "non-applicable obligations require not_attempted qualification",
    )


def _validate_candidate_scope(row: TaxonomyObligation) -> None:
    """Reject candidate records under a non-applicable scope disposition."""
    if row.scope_disposition != "applicable" and any(
        item.projection_disposition != "not_attempted" for item in row.candidate_records
    ):
        raise ValueError("non-applicable obligations cannot carry projected candidates")


def _validate_candidate_qualification(row: TaxonomyObligation) -> None:
    """Reject projectable candidates when the obligation is not ready."""
    _reject_projectable_when_unready(row)
    _reject_infeasible_when_unqualified(row)


def _has_candidate_disposition(
    row: TaxonomyObligation,
    disposition: ObligationProjectionDisposition,
) -> bool:
    """Return whether a row carries one candidate projection disposition."""
    return any(
        item.projection_disposition == disposition for item in row.candidate_records
    )


def _reject_projectable_when_unready(row: TaxonomyObligation) -> None:
    """Reject projectable candidates unless qualification is ready."""
    if row.qualification_disposition != "ready" and _has_candidate_disposition(
        row, "projectable"
    ):
        raise ValueError("non-ready obligations cannot carry projectable candidates")


def _reject_infeasible_when_unqualified(row: TaxonomyObligation) -> None:
    """Reject projection rejects when qualification cannot reach projection."""
    if row.qualification_disposition not in {
        "ready",
        "structurally_infeasible",
    } and _has_candidate_disposition(row, "projection_infeasible"):
        raise ValueError(
            "missing or contradictory obligations cannot carry projection rejects"
        )


def _sort_obligation_collections(row: TaxonomyObligation) -> None:
    """Canonicalize the row's set-like child collections in place."""
    object.__setattr__(
        row,
        "candidate_records",
        tuple(sorted(row.candidate_records, key=lambda item: item.candidate_id)),
    )
    object.__setattr__(
        row,
        "evidence",
        tuple(sorted(row.evidence, key=lambda item: item.model_dump_json())),
    )


def _validate_unique_candidate_ids(row: TaxonomyObligation) -> None:
    """Reject duplicate candidate identities within one obligation row."""
    ids = [item.candidate_id for item in row.candidate_records]
    _require_obligation_condition(
        len(ids) == len(set(ids)),
        "candidate IDs must be unique within an obligation",
    )


class CandidateRecord(_ContractModel):
    """One concrete candidate-v2 projection detail under an obligation."""

    candidate_id: str = Field(pattern=r"^cand:v2:[0-9a-f]{32}$")
    canonical_ingress: EntryPointResourceReference | None = None
    resource_bindings: tuple[ResourceBinding, ...] = ()
    projection_disposition: ObligationProjectionDisposition = "projectable"
    reason: str = ""
    evidence: tuple[EvidenceRecord, ...] = ()

    @model_validator(mode="after")
    def canonical_candidate_has_bindings(self) -> CandidateRecord:
        """Require complete bindings for candidates and evidence for rejects."""
        if self.projection_disposition == "projection_infeasible":
            _validate_infeasible_candidate(self)
        else:
            _validate_projected_candidate(self)
        return self


def _validate_infeasible_candidate(candidate: CandidateRecord) -> None:
    """Validate evidence and optional bindings for a rejected candidate."""
    if not candidate.reason:
        raise ValueError("projection-infeasible candidates require a reason")
    if not candidate.evidence:
        raise ValueError("projection-infeasible candidates require typed evidence")
    if candidate.canonical_ingress is None:
        if candidate.resource_bindings:
            raise ValueError("candidate resource bindings require canonical_ingress")
        return
    _validate_ingress_binding(candidate)


def _validate_projected_candidate(candidate: CandidateRecord) -> None:
    """Require a complete ingress and binding for a projected candidate."""
    if candidate.canonical_ingress is None:
        raise ValueError("projected candidates require canonical_ingress")
    _validate_ingress_binding(candidate)


def _validate_ingress_binding(candidate: CandidateRecord) -> None:
    """Ensure the canonical ingress is represented in candidate bindings."""
    if not any(
        binding.resource_ref == candidate.canonical_ingress
        for binding in candidate.resource_bindings
    ):
        raise ValueError("candidate canonical_ingress must be a resource binding")


class TaxonomyObligation(_ContractModel):
    """One risk-pattern planning obligation in the authoritative ledger."""

    obligation_id: str = Field(pattern=r"^ob:v1:[0-9a-f]{64}$")
    risk_ref: RiskReference
    taxonomy_chain: tuple[TaxonomyChainEntry, ...]
    attack_pattern_id: str | None = None
    attack_pattern_semantic_digest: str | None = Field(default=None, pattern=_SHA256_RE)
    scope_disposition: ObligationScopeDisposition
    qualification_disposition: ObligationQualificationDisposition
    candidate_records: tuple[CandidateRecord, ...]
    evidence: tuple[EvidenceRecord, ...]

    @model_validator(mode="after")
    def coherent_dispositions(self) -> TaxonomyObligation:
        """Enforce the closed Phase 1 disposition matrix."""
        if self.attack_pattern_id is None:
            _validate_governance_obligation(self)
        else:
            _validate_pattern_obligation(self)
        _validate_candidate_scope(self)
        _validate_candidate_qualification(self)
        _validate_unique_candidate_ids(self)
        _sort_obligation_collections(self)
        return self


class ObligationPlanSummary(_ContractModel):
    """Exact roll-up of authoritative obligation and candidate rows."""

    total: int = Field(ge=0)
    applicable: int = Field(ge=0)
    governance_only: int = Field(ge=0)
    capability_excluded: int = Field(ge=0)
    ready: int = Field(ge=0)
    missing_or_contradictory: int = Field(ge=0)
    structurally_infeasible: int = Field(ge=0)
    projectable: int = Field(ge=0)
    projection_infeasible: int = Field(ge=0)
    budget_deferred: int = Field(ge=0)


def derive_obligation_summary(
    obligations: tuple[TaxonomyObligation, ...] | list[TaxonomyObligation],
) -> ObligationPlanSummary:
    """Derive every summary count directly from authoritative rows."""
    rows = tuple(obligations)
    scopes = Counter(map(lambda row: row.scope_disposition, rows))
    qualifications = Counter(map(lambda row: row.qualification_disposition, rows))
    candidates = chain.from_iterable(map(lambda row: row.candidate_records, rows))
    projections = Counter(
        map(lambda candidate: candidate.projection_disposition, candidates)
    )
    return ObligationPlanSummary(
        total=len(rows),
        applicable=scopes["applicable"],
        governance_only=scopes["governance_only"],
        capability_excluded=scopes["capability_excluded"],
        ready=qualifications["ready"],
        missing_or_contradictory=qualifications["missing_evidence"]
        + qualifications["contradictory_evidence"],
        structurally_infeasible=qualifications["structurally_infeasible"],
        projectable=projections["projectable"],
        projection_infeasible=projections["projection_infeasible"],
        budget_deferred=projections["budget_deferred"],
    )


def _canonical_plan_payload(plan: TaxonomyObligationPlan) -> dict[str, Any]:
    """Return digest payload with set-like row collections canonically ordered."""
    rows = []
    for row in sorted(plan.obligations, key=lambda item: item.obligation_id):
        payload = row.model_dump(mode="json")
        payload["candidate_records"] = sorted(
            payload["candidate_records"], key=lambda item: item["candidate_id"]
        )
        rows.append(payload)
    return {
        "schema_version": plan.schema_version,
        "capability_snapshot_digest": plan.capability_snapshot_digest,
        "catalog_pins": {
            key: value.model_dump(mode="json")
            for key, value in sorted(plan.catalog_pins.items())
        },
        "mapping_pins": {
            key: value.model_dump(mode="json")
            for key, value in sorted(plan.mapping_pins.items())
        },
        "qualification_facts_digest": plan.qualification_facts_digest,
        "obligations": rows,
        "summary": plan.summary.model_dump(mode="json"),
    }


class TaxonomyObligationPlan(_ContractModel):
    """Authoritative ``taxonomy-obligation-plan-v1`` persisted artifact."""

    schema_version: Literal[_PLAN_SCHEMA_VERSION]
    semantic_digest: str = Field(pattern=_SHA256_RE)
    capability_snapshot_digest: str = Field(pattern=_SHA256_RE)
    catalog_pins: dict[str, "TaxonomyPin"] = Field(min_length=1)
    mapping_pins: dict[str, "TaxonomyPin"]
    qualification_facts_digest: str = Field(pattern=_SHA256_RE)
    obligations: tuple[TaxonomyObligation, ...]
    summary: ObligationPlanSummary

    @model_validator(mode="after")
    def exact_summary_and_unique_ids(self) -> TaxonomyObligationPlan:
        """Reject any summary that was not derived from these rows."""
        if set(self.mapping_pins) != {"sssom", "obligation_edges"}:
            raise ValueError(
                "mapping_pins must contain exactly 'sssom' and 'obligation_edges'"
            )
        object.__setattr__(self, "catalog_pins", FrozenDict(self.catalog_pins))
        object.__setattr__(self, "mapping_pins", FrozenDict(self.mapping_pins))
        ids = [row.obligation_id for row in self.obligations]
        if len(ids) != len(set(ids)):
            raise ValueError("obligation IDs must be unique")
        object.__setattr__(
            self,
            "obligations",
            tuple(sorted(self.obligations, key=lambda item: item.obligation_id)),
        )
        expected = derive_obligation_summary(self.obligations)
        if self.summary != expected:
            raise ValueError(
                "obligation plan summary does not reconcile with obligation rows"
            )
        return self

    def compute_semantic_digest(self) -> str:
        """Compute the version-framed digest over all semantic plan content."""
        return _compute_framed_digest(
            _PLAN_DIGEST_DOMAIN, _canonical_plan_payload(self)
        )

    def assert_integrity(self) -> None:
        """Verify summary and semantic digest without changing this plan."""
        expected_summary = derive_obligation_summary(self.obligations)
        if self.summary != expected_summary:
            raise ValueError(
                "obligation plan summary does not reconcile with obligation rows"
            )
        expected_digest = self.compute_semantic_digest()
        if self.semantic_digest != expected_digest:
            raise ValueError(
                f"Digest mismatch: recorded '{self.semantic_digest}' != computed '{expected_digest}'"
            )

    def to_yaml(self) -> str:
        """Serialize the closed plan as canonical YAML."""
        return canonical_yaml(self)

    @classmethod
    def from_yaml(cls, text: str | bytes) -> TaxonomyObligationPlan:
        """Load and integrity-check one closed YAML plan."""
        return cls._load_checked(load_yaml_mapping(text))

    @classmethod
    def _load_checked(cls, data: dict[str, Any]) -> TaxonomyObligationPlan:
        """Apply closed-schema, summary, and digest validation in that order."""
        if data.get("schema_version") != _PLAN_SCHEMA_VERSION:
            raise ValueError(
                f"Unsupported schema version: '{data.get('schema_version')}' is unsupported"
            )
        try:
            plan = cls.model_validate(data)
        except ValidationError as exc:
            raise ValueError(str(exc)) from exc
        plan.assert_integrity()
        return plan


TaxonomyObligationPlan.model_rebuild(_types_namespace={"TaxonomyPin": TaxonomyPin})
