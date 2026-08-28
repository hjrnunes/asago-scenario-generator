"""Closed, immutable contracts for the taxonomy obligation ledger."""

from __future__ import annotations

import json
from collections import Counter
from itertools import chain
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

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
    compute_framed_digest as _compute_framed_digest,
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
ObligationCorrespondenceDisposition = Literal["not_assessed"]
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


class QualificationFactEvidence(_ContractModel):
    """One typed qualification reading retained by the obligation ledger."""

    fact: AuthoritativeFactReference
    status: Literal["present", "absent", "unknown", "contradictory"]
    value: Scalar | None = None

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
    correspondence_disposition: ObligationCorrespondenceDisposition
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
        return yaml.dump(
            self.model_dump(mode="json"),
            default_flow_style=False,
            sort_keys=True,
            allow_unicode=True,
        )

    def to_json(self) -> str:
        """Serialize canonical JSON for diagnostics."""
        return (
            json.dumps(
                self.model_dump(mode="json"),
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
            )
            + "\n"
        )

    @classmethod
    def from_yaml(cls, text: str | bytes) -> TaxonomyObligationPlan:
        """Load and integrity-check one closed YAML plan."""
        data = yaml.safe_load(text)
        if not isinstance(data, dict):
            raise ValueError("YAML data must be a dictionary")
        return cls._load_checked(data)

    @classmethod
    def from_json(cls, text: str | bytes) -> TaxonomyObligationPlan:
        """Load and integrity-check one closed JSON plan."""
        try:
            data = json.loads(text)
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError(f"Invalid JSON obligation plan: {exc}") from exc
        if not isinstance(data, dict):
            raise ValueError("JSON data must be a dictionary")
        return cls._load_checked(data)

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


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-28T17:41:16Z","module_hash":"58133bdeb4d1fb0cd7af9117da47d85094a950ed8b1bb03b4f36dc15f2c8c423","source_sha256":"71831981f6f23430efb986d9cc1972288a6ef68f7dda17a09f6bed406d12e0b2","functions":[{"id":"func/_ContractModel.normalize_input_strings","name":"normalize_input_strings","line":57,"end_line":59,"hash":"c7e207d09362389216d6784572b2ecc23ebc0574903e961b694c97540aab18c3"},{"id":"func/RiskReference.freeze_nested_mappings","name":"freeze_nested_mappings","line":97,"end_line":101,"hash":"019ccb37934770a989ed183ac5a905ae6b6a4e77af96639c3e427b107d72dd75"},{"id":"func/QualificationFactEvidence.coherent","name":"coherent","line":119,"end_line":129,"hash":"e958321fec9c4724c4cb20e133a78c68ce1354de4df1dca4b46ada0c291392c2"},{"id":"func/_require_obligation_condition","name":"_require_obligation_condition","line":161,"end_line":164,"hash":"76c4c33c6413eef08544c6597b8873772063b4745e94400b28d24d097fdfe776"},{"id":"func/_validate_governance_obligation","name":"_validate_governance_obligation","line":167,"end_line":180,"hash":"9da3f2e253ad0786b3bdcb03650ddacc20f8d7c943668bf35d79024fef525820"},{"id":"func/_validate_pattern_obligation","name":"_validate_pattern_obligation","line":183,"end_line":202,"hash":"8d918811554af8f7201047aece4176cd11502327bd44f8364070beffcb4b79f9"},{"id":"func/_validate_candidate_scope","name":"_validate_candidate_scope","line":205,"end_line":210,"hash":"88062749987dae466db27c01fa4e3650c61f62872f0670cb6f0be0d440faf1df"},{"id":"func/_validate_candidate_qualification","name":"_validate_candidate_qualification","line":213,"end_line":216,"hash":"60e7b87d71ca8020f306b9df6b269ccec2faa9b9750931a5492c002930588ff6"},{"id":"func/_has_candidate_disposition","name":"_has_candidate_disposition","line":219,"end_line":226,"hash":"d5ea0ba9ed1d04c1aba4bc499abf5f297f5bff66cd27848c68f556dc5124d5f9"},{"id":"func/_reject_projectable_when_unready","name":"_reject_projectable_when_unready","line":229,"end_line":234,"hash":"0354d6390bb07c2487fa6405c3eb8a07dd9b8be8fa3b9570923b31f6c13df2a9"},{"id":"func/_reject_infeasible_when_unqualified","name":"_reject_infeasible_when_unqualified","line":237,"end_line":245,"hash":"4edb3446db01115854888f9f3320b6ae51a11e9db656ff2472a54ee98776516f"},{"id":"func/_sort_obligation_collections","name":"_sort_obligation_collections","line":248,"end_line":259,"hash":"707d8b2d1b7be5fb97fc4ff77ccab1b011c257ce48e37b04b7543d8e6ca0601f"},{"id":"func/_validate_unique_candidate_ids","name":"_validate_unique_candidate_ids","line":262,"end_line":268,"hash":"39e4c13bc38c41480cb2edb672832e5822568002e67e0936c9f871900540797a"},{"id":"func/CandidateRecord.canonical_candidate_has_bindings","name":"canonical_candidate_has_bindings","line":282,"end_line":288,"hash":"1368cd5c01a6928ed87a025031a0472acdf75b28ce6c6ca1a68645ec1d2f7644"},{"id":"func/_validate_infeasible_candidate","name":"_validate_infeasible_candidate","line":291,"end_line":301,"hash":"f53fb78f624c64891888153e86c96960a30e0f1ebb2feb5ee0eaa8c7e3fa05eb"},{"id":"func/_validate_projected_candidate","name":"_validate_projected_candidate","line":304,"end_line":308,"hash":"f7c7d5318b4f0bb3a1ea07f5f29ba60e75bd7b9bd1d645942516512e3df9f2f1"},{"id":"func/_validate_ingress_binding","name":"_validate_ingress_binding","line":311,"end_line":317,"hash":"a0786c683e332e706d970cfbbf1c6d144cd876845014fc5a9c9fefa383f8dca9"},{"id":"func/TaxonomyObligation.coherent_dispositions","name":"coherent_dispositions","line":335,"end_line":345,"hash":"65ddc51021f75a38ef7f14c3dc24c13efa00c989864d1004342f925580a30590"},{"id":"func/derive_obligation_summary","name":"derive_obligation_summary","line":363,"end_line":386,"hash":"3c5200663afce484e8fbd9da689f72d81d6e42c477e4df20b9256ed42b0d0ac6"},{"id":"func/_canonical_plan_payload","name":"_canonical_plan_payload","line":389,"end_line":412,"hash":"ec0cde8b88a0fd94a5c782acbc68cc38c111059e158e91d05dc29bd217d0d9d4"},{"id":"func/TaxonomyObligationPlan.exact_summary_and_unique_ids","name":"exact_summary_and_unique_ids","line":428,"end_line":449,"hash":"c91e6da02116146cdb6ae28cc800d72a8779c6a2e1217f400ff91e883805ed1e"},{"id":"func/TaxonomyObligationPlan.compute_semantic_digest","name":"compute_semantic_digest","line":451,"end_line":455,"hash":"72f68a2d3dd5abbf7ce9f869904849b647194a9304934d2aa97de823d81bcafc"},{"id":"func/TaxonomyObligationPlan.assert_integrity","name":"assert_integrity","line":457,"end_line":468,"hash":"62de83c4ed39e5787f634760b2e2df2368718a4d601b1ca18f8789340c2819b1"},{"id":"func/TaxonomyObligationPlan.to_yaml","name":"to_yaml","line":470,"end_line":477,"hash":"fc8b05d1e1f133e07a5a51056fa7d00fc195216a1e50c2f88ceea955da570dce"},{"id":"func/TaxonomyObligationPlan.to_json","name":"to_json","line":479,"end_line":489,"hash":"e3c4d9920e1605a27dffa1ed01f451b49afd5c3238e3fbe0f74889a90689a317"},{"id":"func/TaxonomyObligationPlan.from_yaml","name":"from_yaml","line":492,"end_line":497,"hash":"230f7c4c38b3be54898c310a1f1906b2b923331c716538e8eda1f3c943e12318"},{"id":"func/TaxonomyObligationPlan.from_json","name":"from_json","line":500,"end_line":508,"hash":"2c31ab370a3f4c2bf13b6b334c82d73779888b7c2ca903b4d0ec9355f4e4ff67"},{"id":"func/TaxonomyObligationPlan._load_checked","name":"_load_checked","line":511,"end_line":522,"hash":"9e278e219aafa10f99c7fa8d2d41ebabc1646003b0076a4650da3774efceeab6"}]}
# mutate4py-manifest-end
