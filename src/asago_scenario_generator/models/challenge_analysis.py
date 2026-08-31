"""Closed contracts for one opted-in Phase 3 STPA reconsideration."""

from __future__ import annotations

import json
from typing import Annotated, Any, ClassVar, Literal

import yaml
from pydantic import Field, model_validator

from asago_scenario_generator.models.canonical import (
    ClosedCanonicalModel,
    canonical_json_text,
    compute_framed_digest,
    unique_sorted_strings,
)
from asago_scenario_generator.models.challenge_ledger import (
    ChallengeId,
    ChallengeOutcome,
    OriginalStpaDecision,
    compute_challenge_id,
)
from asago_scenario_generator.models.hybrid_coverage import (
    ArtifactPin,
    Digest,
    GapReason,
    ObligationId,
    TraceReference,
)

STPA_CHALLENGE_ANALYSIS_SCHEMA_VERSION = "stpa-obligation-challenge-analysis-v1"
STPA_CHALLENGE_REQUEST_SCHEMA_VERSION = "stpa-obligation-challenge-request-v1"
STPA_CHALLENGE_REQUEST_DIGEST_DOMAIN = (
    "asago-scenario-generator:stpa-obligation-challenge-request:v1"
)
STPA_CHALLENGE_RESPONSE_DIGEST_DOMAIN = (
    "asago-scenario-generator:stpa-obligation-challenge-response:v1"
)
STPA_CHALLENGE_ANALYSIS_DIGEST_DOMAIN = (
    "asago-scenario-generator:stpa-obligation-challenge-analysis:v1"
)


class _ChallengeAnalysisModel(ClosedCanonicalModel):
    """Common closed and immutable analysis-model configuration."""


class _ChallengeDigestModel(_ChallengeAnalysisModel):
    """Challenge model with one version-framed semantic digest contract."""

    _digest_domain: ClassVar[str]

    def _semantic_payload(self) -> dict[str, Any]:
        raise NotImplementedError

    def compute_semantic_digest(self) -> str:
        return compute_framed_digest(self._digest_domain, self._semantic_payload())


class ChallengeAnalysisControls(_ChallengeAnalysisModel):
    """Explicit effective controls for one no-retry adapter attempt."""

    model_profile: str = Field(min_length=1)
    model_name: str = Field(min_length=1)
    deadline_seconds: float = Field(gt=0, strict=True)
    temperature: float = Field(ge=0, le=2, strict=True)
    attempt_limit: Literal[1] = 1
    automatic_retries: Literal[0] = 0


class ChallengeLossContext(_ChallengeAnalysisModel):
    """One authoritative loss available to reconsideration."""

    loss_id: str = Field(min_length=1)
    description: str = Field(min_length=1)


class ChallengeHazardContext(_ChallengeAnalysisModel):
    """One authoritative hazard and its exact loss references."""

    hazard_id: str = Field(min_length=1)
    description: str = Field(min_length=1)
    related_losses: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def canonicalize(self) -> "ChallengeHazardContext":
        object.__setattr__(
            self,
            "related_losses",
            unique_sorted_strings(self.related_losses, "related_losses"),
        )
        return self


class ChallengeConstraintContext(_ChallengeAnalysisModel):
    """One authoritative system or responsibility constraint."""

    constraint_id: str = Field(min_length=1)
    description: str = Field(min_length=1)
    related_hazards: tuple[str, ...] = ()

    @model_validator(mode="after")
    def canonicalize(self) -> "ChallengeConstraintContext":
        object.__setattr__(
            self,
            "related_hazards",
            unique_sorted_strings(self.related_hazards, "related_hazards"),
        )
        return self


class ChallengeControllerContext(_ChallengeAnalysisModel):
    """Exact controller and control-action context for the selected slot."""

    controller_id: str = Field(min_length=1)
    controller_description: str = Field(min_length=1)
    control_action_id: str = Field(min_length=1)
    control_action_description: str = Field(min_length=1)
    responsibility_constraint_ids: tuple[str, ...] = ()

    @model_validator(mode="after")
    def canonicalize(self) -> "ChallengeControllerContext":
        object.__setattr__(
            self,
            "responsibility_constraint_ids",
            unique_sorted_strings(
                self.responsibility_constraint_ids,
                "responsibility_constraint_ids",
            ),
        )
        return self


class ChallengeTaxonomyContext(_ChallengeAnalysisModel):
    """Exact Phase 2 taxonomy row supplied as analysis context only."""

    obligation_id: ObligationId
    risk_id: str = Field(min_length=1)
    attack_pattern_id: str | None = None
    attack_pattern_semantic_digest: Digest | None = None
    scope_disposition: str = Field(min_length=1)
    qualification_disposition: str = Field(min_length=1)
    correspondence_disposition: str = Field(min_length=1)
    gap_reason: GapReason | None = None
    accepted_relation_ids: tuple[str, ...] = ()
    trace_refs: tuple[TraceReference, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def canonicalize(self) -> "ChallengeTaxonomyContext":
        object.__setattr__(
            self,
            "accepted_relation_ids",
            unique_sorted_strings(self.accepted_relation_ids, "accepted_relation_ids"),
        )
        return self


class ChallengeAnalysisContext(_ChallengeAnalysisModel):
    """Typed Phase 2 and STPA authority presented to the adapter."""

    taxonomy: ChallengeTaxonomyContext
    controller: ChallengeControllerContext
    losses: tuple[ChallengeLossContext, ...] = Field(min_length=1)
    hazards: tuple[ChallengeHazardContext, ...] = Field(min_length=1)
    constraints: tuple[ChallengeConstraintContext, ...] = Field(min_length=1)
    loss_analysis_pin: ArtifactPin
    control_structure_pin: ArtifactPin
    exec_candidate_id: str = Field(pattern=r"^EXEC:[^:]+:[^:]+:[A-Z_]+$")

    @model_validator(mode="after")
    def canonicalize(self) -> "ChallengeAnalysisContext":
        for field_name, identity in (
            ("losses", "loss_id"),
            ("hazards", "hazard_id"),
            ("constraints", "constraint_id"),
        ):
            values = tuple(
                sorted(
                    getattr(self, field_name), key=lambda item: getattr(item, identity)
                )
            )
            identifiers = tuple(getattr(item, identity) for item in values)
            if len(identifiers) != len(set(identifiers)):
                raise ValueError(f"{field_name} identities must be unique")
            object.__setattr__(self, field_name, values)
        return self


def _request_payload(request: "ChallengeAnalysisRequest") -> dict[str, Any]:
    return request.model_dump(mode="json", exclude={"semantic_digest"})


def _validate_request_target(request: "ChallengeAnalysisRequest") -> None:
    original = request.original_decision
    taxonomy = request.context.taxonomy
    expected = compute_challenge_id(
        request.assessment_pin.semantic_digest,
        taxonomy.obligation_id,
        original.slot_id,
    )
    if request.challenge_id != expected:
        raise ValueError("challenge request does not name its exact target")
    controller = request.context.controller
    if (
        controller.controller_id != original.controller_id
        or controller.control_action_id != original.control_action_id
    ):
        raise ValueError("challenge request substituted structural target identities")
    expected_exec = f"EXEC:{original.controller_id}:{original.control_action_id}:{original.uca_type}"
    if request.context.exec_candidate_id != expected_exec:
        raise ValueError("challenge request substituted the canonical EXEC identity")


def _validate_request_traces(request: "ChallengeAnalysisRequest") -> None:
    pins = {
        (pin.artifact_id, pin.schema_version, pin.semantic_digest)
        for pin in request.source_pins
    }
    traces = (
        *request.original_decision.trace_refs,
        *request.context.taxonomy.trace_refs,
    )
    if any(
        (trace.artifact_id, trace.schema_version, trace.semantic_digest) not in pins
        for trace in traces
    ):
        raise ValueError("challenge request trace does not resolve to source pins")


def _verify_request_digest(request: "ChallengeAnalysisRequest") -> None:
    expected = request.compute_semantic_digest()
    _validate_optional_digest(
        request.semantic_digest,
        expected,
        "challenge request semantic_digest does not match",
    )
    object.__setattr__(request, "semantic_digest", expected)


class ChallengeAnalysisRequest(_ChallengeDigestModel):
    """Content-addressed request for one exact selected challenge target."""

    schema_version: Literal[STPA_CHALLENGE_REQUEST_SCHEMA_VERSION] = (
        STPA_CHALLENGE_REQUEST_SCHEMA_VERSION
    )
    semantic_digest: Digest | None = None
    challenge_id: ChallengeId
    assessment_pin: ArtifactPin
    source_pins: tuple[ArtifactPin, ...] = Field(min_length=3)
    original_decision: OriginalStpaDecision
    context: ChallengeAnalysisContext
    controls: ChallengeAnalysisControls
    attempt_number: Literal[1] = 1
    _digest_domain = STPA_CHALLENGE_REQUEST_DIGEST_DOMAIN

    @model_validator(mode="after")
    def canonicalize_and_verify(self) -> "ChallengeAnalysisRequest":
        pins = tuple(sorted(self.source_pins, key=lambda item: item.artifact_id))
        if len({pin.artifact_id for pin in pins}) != len(pins):
            raise ValueError("challenge request source pin IDs must be unique")
        object.__setattr__(self, "source_pins", pins)
        _validate_request_target(self)
        _validate_request_traces(self)
        _verify_request_digest(self)
        return self

    def _semantic_payload(self) -> dict[str, Any]:
        return _request_payload(self)


class ProposedIca(_ChallengeAnalysisModel):
    """One additive ICA proposed by the bounded reconsideration."""

    ica_id: str = Field(min_length=1)
    exec_candidate_id: str = Field(pattern=r"^EXEC:[^:]+:[^:]+:[A-Z_]+$")
    ica_text: str = Field(min_length=1)
    hazardous_context: str = Field(min_length=1)
    loss_scenario: str = Field(min_length=1)
    related_hazards: tuple[str, ...] = Field(min_length=1)
    related_constraints: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def canonicalize(self) -> "ProposedIca":
        object.__setattr__(
            self,
            "related_hazards",
            unique_sorted_strings(self.related_hazards, "related_hazards"),
        )
        object.__setattr__(
            self,
            "related_constraints",
            unique_sorted_strings(self.related_constraints, "related_constraints"),
        )
        return self


class IcaChallengeDraft(_ChallengeAnalysisModel):
    """Adapter draft proposing one additive ICA."""

    disposition: Literal["ica"] = "ica"
    proposed_ica: ProposedIca
    rationale: str = Field(min_length=1)
    evidence_refs: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def canonicalize(self) -> "IcaChallengeDraft":
        object.__setattr__(
            self,
            "evidence_refs",
            unique_sorted_strings(self.evidence_refs, "evidence_refs"),
        )
        return self


class JustifiedNaChallengeDraft(_ChallengeAnalysisModel):
    """Adapter draft retaining explicit structural inapplicability evidence."""

    disposition: Literal["justified_na"] = "justified_na"
    rationale: str = Field(min_length=1)
    evidence_refs: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def canonicalize(self) -> "JustifiedNaChallengeDraft":
        object.__setattr__(
            self,
            "evidence_refs",
            unique_sorted_strings(self.evidence_refs, "evidence_refs"),
        )
        return self


class UnresolvedChallengeDraft(_ChallengeAnalysisModel):
    """Adapter draft retaining why the bounded reconsideration did not resolve."""

    disposition: Literal["unresolved"] = "unresolved"
    reason: Literal[
        "missing_evidence",
        "contradictory_evidence",
        "insufficient_causal_support",
        "adapter_indeterminate",
    ]
    rationale: str = Field(min_length=1)
    evidence_refs: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def canonicalize(self) -> "UnresolvedChallengeDraft":
        object.__setattr__(
            self,
            "evidence_refs",
            unique_sorted_strings(self.evidence_refs, "evidence_refs"),
        )
        return self


ChallengeOutcomeDraft = Annotated[
    IcaChallengeDraft | JustifiedNaChallengeDraft | UnresolvedChallengeDraft,
    Field(discriminator="disposition"),
]


def _response_payload(response: "ChallengeAdapterResponse") -> dict[str, Any]:
    return response.model_dump(mode="json", exclude={"response_digest"})


def _validate_adapter_counts(
    adapter_kind: str,
    provider_calls: int,
    network_calls: int,
    provider_message: str,
) -> None:
    if adapter_kind == "fake":
        if provider_calls or network_calls:
            raise ValueError(
                "fake challenge adapter cannot report provider/network calls"
            )
        return
    if provider_calls != 1:
        raise ValueError(provider_message)


def _validate_optional_digest(actual: str | None, expected: str, message: str) -> None:
    if actual is not None and actual != expected:
        raise ValueError(message)


def _validate_response_pair(
    response_digest: str | None, response_ref: str | None
) -> None:
    if (response_digest is None) != (response_ref is None):
        raise ValueError("failure response digest and reference must appear together")


class ChallengeAdapterResponse(_ChallengeAnalysisModel):
    """Typed adapter response and request/response evidence for one call."""

    status: Literal["completed"] = "completed"
    request_digest: Digest
    response_digest: Digest | None = None
    draft: ChallengeOutcomeDraft
    effective_controls: ChallengeAnalysisControls
    adapter_kind: Literal["fake", "provider"]
    request_ref: str = Field(min_length=1)
    response_ref: str = Field(min_length=1)
    provider_calls: Literal[0, 1]
    network_calls: Literal[0, 1]

    @model_validator(mode="after")
    def verify_response(self) -> "ChallengeAdapterResponse":
        _validate_adapter_counts(
            self.adapter_kind,
            self.provider_calls,
            self.network_calls,
            "provider challenge adapter must report one provider call",
        )
        expected = compute_framed_digest(
            STPA_CHALLENGE_RESPONSE_DIGEST_DOMAIN, _response_payload(self)
        )
        _validate_optional_digest(
            self.response_digest,
            expected,
            "challenge adapter response_digest does not match",
        )
        object.__setattr__(self, "response_digest", expected)
        return self


class ChallengeTechnicalFailure(_ChallengeAnalysisModel):
    """A failed adapter attempt that made no structural STPA conclusion."""

    kind: Literal[
        "provider_initialization",
        "provider_timeout",
        "provider_error",
        "invalid_response",
        "identity_validation_failed",
    ]
    message: str = Field(min_length=1)
    evidence_refs: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def canonicalize(self) -> "ChallengeTechnicalFailure":
        object.__setattr__(
            self,
            "evidence_refs",
            unique_sorted_strings(self.evidence_refs, "evidence_refs"),
        )
        return self


class ChallengeAdapterFailureResponse(_ChallengeAnalysisModel):
    """Typed technical failure returned by the sole adapter attempt."""

    status: Literal["technical_failure"] = "technical_failure"
    request_digest: Digest
    response_digest: Digest | None = None
    failure: ChallengeTechnicalFailure
    effective_controls: ChallengeAnalysisControls
    adapter_kind: Literal["fake", "provider"]
    request_ref: str = Field(min_length=1)
    response_ref: str | None = None
    provider_calls: Literal[0, 1]
    network_calls: Literal[0, 1]

    @model_validator(mode="after")
    def validate_failure_evidence(self) -> "ChallengeAdapterFailureResponse":
        _validate_adapter_counts(
            self.adapter_kind,
            self.provider_calls,
            self.network_calls,
            "provider failure must report one provider call",
        )
        _validate_response_pair(self.response_digest, self.response_ref)
        return self


class ChallengeCallEvidence(_ChallengeAnalysisModel):
    """Validated evidence for exactly one adapter attempt."""

    adapter_kind: Literal["fake", "provider"]
    adapter_attempts: Literal[0, 1] = 1
    provider_calls: Literal[0, 1]
    network_calls: Literal[0, 1]
    request_digest: Digest
    response_digest: Digest | None = None
    request_ref: str = Field(min_length=1)
    response_ref: str | None = None
    effective_controls: ChallengeAnalysisControls
    validation_status: Literal["accepted", "technical_failure"] = "accepted"

    @model_validator(mode="after")
    def validate_call(self) -> "ChallengeCallEvidence":
        _validate_adapter_counts(
            self.adapter_kind,
            self.provider_calls,
            self.network_calls,
            "provider call evidence must report one provider call",
        )
        _validate_response_pair(self.response_digest, self.response_ref)
        if self.validation_status == "accepted" and self.response_digest is None:
            raise ValueError("accepted challenge call requires response evidence")
        return self


def _analysis_payload(result: "ChallengeAnalysisResult") -> dict[str, Any]:
    return result.model_dump(mode="json", exclude={"semantic_digest"})


def _validate_analysis_result_kind(result: "ChallengeAnalysisResult") -> None:
    completed = result.status == "completed"
    if completed != (result.outcome is not None):
        raise ValueError("challenge analysis status contradicts structural outcome")
    if completed == (result.technical_failure is not None):
        raise ValueError("challenge analysis must contain exactly one result kind")


def _validate_analysis_result_outcome(result: "ChallengeAnalysisResult") -> None:
    disposition = result.outcome.disposition if result.outcome is not None else None
    if (disposition == "ica") != (result.proposed_ica is not None):
        raise ValueError("challenge result ICA payload contradicts outcome")
    if (disposition == "unresolved") != (result.unresolved_reason is not None):
        raise ValueError("challenge unresolved reason contradicts outcome")


def _validate_analysis_result_evidence(result: "ChallengeAnalysisResult") -> None:
    request = result.request
    evidence = result.call_evidence
    _require_equal(
        evidence.request_digest,
        request.semantic_digest,
        "challenge call evidence is bound to another request",
    )
    _require_equal(
        evidence.effective_controls,
        request.controls,
        "challenge call evidence substituted effective controls",
    )
    expected = "accepted" if result.status == "completed" else "technical_failure"
    _require_equal(
        evidence.validation_status,
        expected,
        "challenge call validation status contradicts result",
    )


def _require_equal(actual: Any, expected: Any, message: str) -> None:
    if actual != expected:
        raise ValueError(message)


class ChallengeAnalysisResult(_ChallengeDigestModel):
    """Canonical additive result for one completed reconsideration."""

    schema_version: Literal[STPA_CHALLENGE_ANALYSIS_SCHEMA_VERSION] = (
        STPA_CHALLENGE_ANALYSIS_SCHEMA_VERSION
    )
    semantic_digest: Digest | None = None
    status: Literal["completed", "technical_failure"] = "completed"
    request: ChallengeAnalysisRequest
    original_decision: OriginalStpaDecision
    outcome: ChallengeOutcome | None = None
    proposed_ica: ProposedIca | None = None
    unresolved_reason: (
        Literal[
            "missing_evidence",
            "contradictory_evidence",
            "insufficient_causal_support",
            "adapter_indeterminate",
        ]
        | None
    ) = None
    technical_failure: ChallengeTechnicalFailure | None = None
    call_evidence: ChallengeCallEvidence
    correspondence_changes: Literal[0] = 0
    coverage_changes: Literal[0] = 0
    hybrid_generation_status: Literal["not_attempted"] = "not_attempted"
    hybrid_admission_status: Literal["not_assessed"] = "not_assessed"
    _digest_domain = STPA_CHALLENGE_ANALYSIS_DIGEST_DOMAIN

    @model_validator(mode="after")
    def verify_result(self) -> "ChallengeAnalysisResult":
        if self.original_decision != self.request.original_decision:
            raise ValueError("challenge result replaced the original STPA decision")
        _validate_analysis_result_kind(self)
        _validate_analysis_result_outcome(self)
        _validate_analysis_result_evidence(self)
        expected = self.compute_semantic_digest()
        if self.semantic_digest is not None and self.semantic_digest != expected:
            raise ValueError("challenge analysis semantic_digest does not match")
        object.__setattr__(self, "semantic_digest", expected)
        return self

    def _semantic_payload(self) -> dict[str, Any]:
        return _analysis_payload(self)

    def assert_integrity(self) -> None:
        if self.semantic_digest != self.compute_semantic_digest():
            raise ValueError("challenge analysis digest mismatch")

    def to_yaml(self) -> str:
        self.assert_integrity()
        return yaml.dump(
            self.model_dump(mode="json"),
            default_flow_style=False,
            sort_keys=True,
            allow_unicode=True,
        )

    def to_json(self) -> str:
        self.assert_integrity()
        return canonical_json_text(self.model_dump(mode="json"))

    @classmethod
    def from_yaml(cls, text: str | bytes) -> "ChallengeAnalysisResult":
        return cls._load(yaml.safe_load(text))

    @classmethod
    def from_json(cls, text: str | bytes) -> "ChallengeAnalysisResult":
        return cls._load(json.loads(text))

    @classmethod
    def _load(cls, value: Any) -> "ChallengeAnalysisResult":
        if not isinstance(value, dict):
            raise ValueError("challenge analysis must be a mapping")
        if value.get("schema_version") != STPA_CHALLENGE_ANALYSIS_SCHEMA_VERSION:
            raise ValueError("unsupported challenge analysis schema version")
        if not value.get("semantic_digest"):
            raise ValueError("challenge analysis semantic_digest is required")
        result = cls.model_validate(value)
        result.assert_integrity()
        return result


__all__ = [
    "STPA_CHALLENGE_ANALYSIS_SCHEMA_VERSION",
    "ChallengeAdapterFailureResponse",
    "ChallengeAdapterResponse",
    "ChallengeAnalysisContext",
    "ChallengeAnalysisControls",
    "ChallengeAnalysisRequest",
    "ChallengeAnalysisResult",
    "ChallengeCallEvidence",
    "ChallengeConstraintContext",
    "ChallengeControllerContext",
    "ChallengeHazardContext",
    "ChallengeLossContext",
    "ChallengeOutcomeDraft",
    "ChallengeTaxonomyContext",
    "ChallengeTechnicalFailure",
    "IcaChallengeDraft",
    "JustifiedNaChallengeDraft",
    "ProposedIca",
    "UnresolvedChallengeDraft",
]
