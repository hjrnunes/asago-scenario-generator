"""Provider-facing contracts for the obligation-aware STPA seams.

The durable obligation records are owned by
``models.obligation_consideration``.  This module deliberately does not
redefine those records: the STPA package only owns request envelopes and
provider-local draft/response shapes.  That separation lets a provider be
replaced without creating a second, incompatible obligation vocabulary.
"""

from __future__ import annotations

from typing import Any, ClassVar, Literal, Protocol

from pydantic import Field, model_validator

from asago_scenario_generator.models.canonical import (
    ClosedCanonicalModel,
    canonical_json_text,
    compute_framed_digest,
)
from asago_scenario_generator.models.hybrid_coverage import ArtifactPin, Digest
from asago_scenario_generator.models.obligation_consideration import (
    BoundedStructuralRevision,
    ConsiderationCallEvidence,
    ConsiderationDiagnostic,
    IcaConsideration,
    MissingStructuralConcept,
    MappingStrength,
    NeutralObligationBrief,
    ObligationIcaConsideration,
    ObligationRoute,
    RevisionAddition,
    RevisionDelta,
    StructuralRevisionDelta,
    StructuralConceptKind,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlActionTemporality,
    ControlStructure,
)
from asago_scenario_generator.stpa.models.ica_enumeration import (
    ICAEnumeration,
    ICASlot,
    UCAType,
)
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.threat_enum.slot_creation import SlotPlaceholder
from asago_scenario_generator.stpa.obligation_aware.ica_verification import (
    IcaConstraintContext,
    IcaHazardContext,
    IcaHazardVerificationAttempt,
    IcaHazardVerificationBatch,
    IcaHazardVerificationCorrection,
    IcaHazardVerificationRecord,
    IcaHazardVerificationRequest,
    IcaHazardVerificationVerdict,
    IcaHazardVerdict,
    IcaLossContext,
)


ROUTING_REQUEST_SCHEMA_VERSION = "stpa-obligation-routing-request-v1"
REVISION_REQUEST_SCHEMA_VERSION = "stpa-obligation-revision-request-v1"
SLOT_REQUEST_SCHEMA_VERSION = "stpa-obligation-slot-request-v1"

ROUTING_REQUEST_DIGEST_DOMAIN = (
    "asago-scenario-generator:stpa-obligation-routing-request:v1"
)
REVISION_REQUEST_DIGEST_DOMAIN = (
    "asago-scenario-generator:stpa-obligation-revision-request:v1"
)
SLOT_REQUEST_DIGEST_DOMAIN = "asago-scenario-generator:stpa-obligation-slot-request:v1"


class _Model(ClosedCanonicalModel):
    """Closed immutable provider boundary model."""


class _DigestModel(_Model):
    """Provider request with a content-addressed semantic digest."""

    _digest_domain: ClassVar[str]
    semantic_digest: Digest | None = None

    def _semantic_payload(self) -> dict[str, Any]:
        raise NotImplementedError

    def compute_semantic_digest(self) -> str:
        """Compute the request digest without its digest field."""
        return compute_framed_digest(self._digest_domain, self._semantic_payload())

    def assert_integrity(self) -> None:
        """Raise when request content and its digest disagree."""
        if self.semantic_digest != self.compute_semantic_digest():
            raise ValueError("semantic digest does not match request content")

    def to_json(self) -> str:
        """Return canonical diagnostic JSON after integrity validation."""
        self.assert_integrity()
        return canonical_json_text(self.model_dump(mode="json"))


class AnalysisControls(_Model):
    """Explicit controls for one provider-capable named analysis stage."""

    model_profile: str = Field(min_length=1)
    model_name: str = Field(min_length=1)
    deadline_seconds: float = Field(gt=0, strict=True)
    temperature: float = Field(ge=0, le=2, strict=True)
    validation_retries: int = Field(ge=0, le=1, strict=True, default=1)
    max_batch_size: int = Field(gt=0, strict=True, default=8)
    # Optional model-context settings are kept on the stage controls rather
    # than inferred from prompt text.  Older deterministic callers omit them;
    # provider adapters resolve them from the client/profile when available.
    context_window: int | None = Field(gt=0, strict=True, default=None)
    maximum_completion_tokens: int | None = Field(gt=0, strict=True, default=None)
    safety_margin: int | None = Field(ge=0, strict=True, default=None)


class StructuralRoutingRequest(_DigestModel):
    """One canonical batch sent to the structural routing stage."""

    schema_version: Literal[ROUTING_REQUEST_SCHEMA_VERSION] = (
        ROUTING_REQUEST_SCHEMA_VERSION
    )
    batch_id: str = Field(min_length=1)
    purpose: Literal["initial", "recheck"] = "initial"
    briefs: tuple[NeutralObligationBrief, ...] = Field(min_length=1)
    loss_analysis: LossAnalysis
    control_structure: ControlStructure
    slots: tuple[SlotPlaceholder, ...] = ()
    controls: AnalysisControls
    _digest_domain = ROUTING_REQUEST_DIGEST_DOMAIN

    @model_validator(mode="after")
    def canonicalize_and_verify(self) -> "StructuralRoutingRequest":
        briefs = tuple(sorted(self.briefs, key=lambda item: item.obligation_id))
        if len({item.obligation_id for item in briefs}) != len(briefs):
            raise ValueError("routing request briefs must have unique obligation IDs")
        object.__setattr__(self, "briefs", briefs)
        slots = tuple(sorted(self.slots, key=lambda item: item.slot_id))
        if len({item.slot_id for item in slots}) != len(slots):
            raise ValueError("routing request slots must have unique slot IDs")
        object.__setattr__(self, "slots", slots)
        expected = self.compute_semantic_digest()
        if self.semantic_digest is not None and self.semantic_digest != expected:
            raise ValueError("routing request semantic_digest does not match")
        object.__setattr__(self, "semantic_digest", expected)
        return self

    def _semantic_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"semantic_digest"})


class StructuralRoutingResponse(_Model):
    """Provider-local response envelope containing authoritative routes."""

    status: Literal["completed"] = "completed"
    request_digest: Digest
    routes: tuple[ObligationRoute, ...] = ()
    adapter_kind: Literal["fake", "provider"] = "fake"
    request_ref: str = "memory://stpa-obligation-routing/request"
    response_ref: str = "memory://stpa-obligation-routing/response"
    provider_calls: Literal[0, 1] = 0
    network_calls: Literal[0, 1] = 0
    response_digest: Digest | None = None

    @model_validator(mode="after")
    def canonicalize_and_validate(self) -> "StructuralRoutingResponse":
        if self.adapter_kind == "fake" and (self.provider_calls or self.network_calls):
            raise ValueError("fake adapter cannot report provider/network calls")
        if self.adapter_kind == "provider" and self.provider_calls != 1:
            raise ValueError("provider adapter must report one provider call")
        routes = tuple(sorted(self.routes, key=lambda item: item.obligation_id))
        if len({item.obligation_id for item in routes}) != len(routes):
            raise ValueError("routing response must contain unique obligation IDs")
        object.__setattr__(self, "routes", routes)
        return self


# Request-local draft types are intentionally separate from the durable
# RevisionAddition/StructuralRevisionDelta models. Their handles are never
# published as STPA IDs; revision.py resolves them in one deterministic pass.
class DraftLoss(_Model):
    handle: str = Field(min_length=1)
    description: str = Field(min_length=1)
    provenance: Literal["risk_card", "use_case", "critic_derived"] = "critic_derived"
    source_risk_cards: tuple[str, ...] = ()


class DraftHazard(_Model):
    handle: str = Field(min_length=1)
    description: str = Field(min_length=1)
    related_loss_ids: tuple[str, ...] = ()
    related_loss_handles: tuple[str, ...] = ()


class DraftSecurityConstraint(_Model):
    handle: str = Field(min_length=1)
    description: str = Field(min_length=1)
    related_hazard_ids: tuple[str, ...] = ()
    related_hazard_handles: tuple[str, ...] = ()
    responsibility_ids: tuple[str, ...] = ()
    responsibility_handles: tuple[str, ...] = ()


class DraftResponsibilityConstraint(_Model):
    handle: str = Field(min_length=1)
    description: str = Field(min_length=1)


class DraftResponsibility(_Model):
    handle: str = Field(min_length=1)
    description: str = Field(min_length=1)
    existing_resp_id: str | None = None
    security_constraint_ids: tuple[str, ...] = ()
    security_constraint_handles: tuple[str, ...] = ()
    responsibility_constraints: tuple[DraftResponsibilityConstraint, ...] = ()


class DraftControlledProcess(_Model):
    handle: str = Field(min_length=1)
    description: str = Field(min_length=1)


class DraftProcessModelPart(_Model):
    handle: str = Field(min_length=1)
    responsibility_id: str | None = None
    responsibility_handle: str | None = None
    description: str = Field(min_length=1)
    feedback_source_type: Literal["responsibility", "controlled_process"] | None = None
    feedback_source_id: str | None = None
    feedback_source_handle: str | None = None


class DraftControlAction(_Model):
    handle: str = Field(min_length=1)
    responsibility_id: str | None = None
    responsibility_handle: str | None = None
    description: str = Field(min_length=1)
    target_type: Literal["responsibility", "controlled_process"] | None = None
    target_id: str | None = None
    target_handle: str | None = None


class DraftFeedbackChannel(_Model):
    handle: str = Field(min_length=1)
    responsibility_id: str | None = None
    responsibility_handle: str | None = None
    description: str = Field(min_length=1)
    updates_id: str | None = None
    updates_handle: str | None = None
    source_type: Literal["responsibility", "controlled_process"] | None = None
    source_id: str | None = None
    source_handle: str | None = None


class DraftCoordinationMechanism(_Model):
    handle: str = Field(min_length=1)
    description: str = Field(min_length=1)
    payload: str = Field(min_length=1)


class DraftCoordinationLink(_Model):
    handle: str = Field(min_length=1)
    description: str = Field(min_length=1)
    source_id: str | None = None
    source_handle: str | None = None
    target_id: str | None = None
    target_handle: str | None = None
    shared_pm_id: str | None = None
    shared_pm_handle: str | None = None
    mechanism: DraftCoordinationMechanism


class RevisionGapDecision(_Model):
    """One request-local disposition for a structural revision gap.

    The provider sees an opaque ``gap_handle`` and chooses whether the gap is
    supported by the supplied evidence.  Final STPA identities are allocated
    by the deterministic revision compiler, never by this draft.
    """

    gap_handle: str = Field(min_length=1)
    disposition: Literal["propose_addition", "dismiss_unsupported", "unresolved"]
    rationale: str = Field(min_length=1)


class IcaDeviationDraft(_Model):
    """Type-specific unsafe-control deviation supplied by a provider."""

    not_provided_context: str | None = None
    incorrect_value_or_effect: str | None = None
    timing_deviation: str | None = None
    duration_deviation: str | None = None

    @model_validator(mode="after")
    def exactly_one_deviation(self) -> "IcaDeviationDraft":
        values = (
            self.not_provided_context,
            self.incorrect_value_or_effect,
            self.timing_deviation,
            self.duration_deviation,
        )
        if sum(value is not None and bool(value.strip()) for value in values) != 1:
            raise ValueError("ICA draft must contain exactly one non-empty deviation")
        if any(value is not None and not value.strip() for value in values):
            raise ValueError("ICA deviation fields must not be blank")
        return self

    @property
    def field_name(self) -> str:
        """Return the one populated type-specific field name."""
        for name in (
            "not_provided_context",
            "incorrect_value_or_effect",
            "timing_deviation",
            "duration_deviation",
        ):
            if getattr(self, name) is not None:
                return name
        raise ValueError("ICA draft has no deviation")

    @property
    def text(self) -> str:
        """Return the populated deviation text."""
        return getattr(self, self.field_name)


class IcaFindingDraft(_Model):
    """Structured provider draft for one unsafe-control finding."""

    deviation: IcaDeviationDraft
    hazardous_context: str = Field(min_length=1)
    loss_consequence: str = Field(min_length=1)
    related_hazard_ids: tuple[str, ...] = Field(min_length=1)
    related_constraint_ids: tuple[str, ...] = Field(min_length=1)
    process_model_refs: tuple[str, ...] = ()
    feedback_refs: tuple[str, ...] = ()
    context_row: str | None = Field(
        default=None, exclude_if=lambda value: value is None
    )

    @model_validator(mode="after")
    def unique_references(self) -> "IcaFindingDraft":
        for name in (
            "related_hazard_ids",
            "related_constraint_ids",
            "process_model_refs",
            "feedback_refs",
        ):
            values = getattr(self, name)
            if len(values) != len(set(values)):
                raise ValueError(f"{name} must contain unique references")
        return self


class ObligationIcaDraft(_Model):
    """Provider-local obligation result for one target slot."""

    obligation_handle: str = Field(min_length=1)
    disposition: Literal["finding", "proposed_not_applicable", "unresolved"]
    finding_indexes: tuple[int, ...] = ()
    rationale: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_indexes(self) -> "ObligationIcaDraft":
        if any(index < 0 for index in self.finding_indexes):
            raise ValueError("finding_indexes must be non-negative")
        if len(self.finding_indexes) != len(set(self.finding_indexes)):
            raise ValueError("finding_indexes must be unique")
        if self.disposition == "finding" and not self.finding_indexes:
            raise ValueError("finding consideration requires finding_indexes")
        if self.disposition != "finding" and self.finding_indexes:
            raise ValueError("only a finding consideration may retain finding_indexes")
        return self


class SlotIcaDraft(_Model):
    """Structured target-scoped ICA draft before canonical compilation."""

    slot_id: str = Field(min_length=1)
    is_na: bool
    na_rationale: str | None = None
    findings: tuple[IcaFindingDraft, ...] = ()
    consideration_results: tuple[ObligationIcaDraft, ...] = ()

    @model_validator(mode="after")
    def validate_na_and_findings(self) -> "SlotIcaDraft":
        if self.is_na:
            if self.findings:
                raise ValueError("N/A ICA draft cannot contain findings")
            if not self.na_rationale or not self.na_rationale.strip():
                raise ValueError("N/A ICA draft requires a non-empty na_rationale")
        elif not self.findings:
            raise ValueError("non-N/A ICA draft requires at least one finding")
        return self


# Provider response entries may use the historical final ``ICASlot`` shape or
# the strict structured draft.  The latter is compiled into the former at the
# obligation-aware seam, preserving compatibility with older fakes.
# Put the normative provider-local draft first so generated JSON Schema leads
# model clients toward the request-local shape.  The historical final-slot
# shape remains accepted by the outer compatibility adapter.
SlotProviderEntry = SlotIcaDraft | ICASlot


class PromptReference(_Model):
    """One selectable provider reference with its plain-language meaning."""

    id: str = Field(min_length=1)
    description: str = Field(min_length=1)


class ProviderKnownConcern(_Model):
    """The concise attack-pattern concern a provider is asked to examine."""

    attack_pattern_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    description: str = Field(min_length=1)


class ProviderReviewedRisk(_Model):
    """Only risk meaning useful to routing; audit metadata stays out of band."""

    risk_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    threat: str | None = None
    consequence: str | None = None
    impact: str | None = None


class ProviderApplicabilityFact(_Model):
    """A qualification fact rendered with status and a human-readable role."""

    fact_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    value: str | int | bool | None = None
    status: Literal["present", "absent", "unknown", "contradictory"]
    meaning: str = Field(min_length=1)


class ProviderApplicability(_Model):
    """Qualification context relevant to the provider's routing decision."""

    conclusion: str = Field(min_length=1)
    relevant_facts: tuple[ProviderApplicabilityFact, ...] = ()
    missing_or_conflicting_facts: tuple[ProviderApplicabilityFact, ...] = ()


class ProviderSystemResource(_Model):
    """A known resource shown only with an explanatory type and role."""

    resource_id: str = Field(min_length=1)
    resource_type: str = Field(min_length=1)
    description: str = Field(min_length=1)
    relevance: str = Field(min_length=1)


class ProviderMappingStrength(_Model):
    """Plain-language provenance for how a risk/pattern pair was discovered."""

    label: MappingStrength
    meaning: str = Field(min_length=1)


class ProviderObligationQuestion(_Model):
    """Compact provider-facing projection of a durable neutral brief."""

    obligation_handle: str = Field(min_length=1)
    known_concern: ProviderKnownConcern
    reviewed_risk: ProviderReviewedRisk
    applicability: ProviderApplicability
    mapping_strength: ProviderMappingStrength
    known_system_resources: tuple[ProviderSystemResource, ...] = ()
    analyst_instruction: str = Field(min_length=1)


class ProviderControlAction(PromptReference):
    """A control action with explicit owner and controlled-process target."""

    owner: PromptReference
    target_process: PromptReference | None = None
    action_temporality: ControlActionTemporality | None = None
    operation: str | None = Field(default=None, exclude_if=lambda value: value is None)
    process_model_refs: tuple[str, ...] = Field(
        default=(), exclude_if=lambda value: not value
    )


class ProviderSlot(PromptReference):
    """One deterministic slot paired with its authoritative action and owner."""

    uca_type: UCAType
    action_temporality: ControlActionTemporality | None = None
    owner: PromptReference | None = None
    control_action: PromptReference
    target_process: PromptReference | None = None
    coordination_path: PromptReference | None = None


class ProviderResponsibility(PromptReference):
    """One target responsibility and its assigned structural context."""

    assigned_constraints: tuple[PromptReference, ...] = ()
    controlled_process: PromptReference | None = None


class ProviderProcessModelPart(PromptReference):
    """A target-scoped process-model part."""

    owner: PromptReference
    values: tuple[str, ...] = Field(default=(), exclude_if=lambda value: not value)
    evidence_refs: tuple[str, ...] = Field(
        default=(), exclude_if=lambda value: not value
    )


class ProviderFeedbackChannel(PromptReference):
    """A target-scoped feedback channel."""

    owner: PromptReference
    updates: PromptReference | None = None
    source: PromptReference | None = None
    source_kind: str | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    untrusted: bool | None = Field(default=None, exclude_if=lambda value: value is None)


class ProviderContextValue(_Model):
    """One process-model variable value within a context row."""

    process_model_id: str = Field(min_length=1)
    value: str = Field(min_length=1)


class ProviderContextRow(_Model):
    """One row of a control action's context table."""

    id: str = Field(min_length=1)
    control_action_id: str = Field(min_length=1)
    values: tuple[ProviderContextValue, ...] = Field(min_length=1)


class ProviderHazard(PromptReference):
    """A hazard retaining its exact loss relationships."""

    related_losses: tuple[PromptReference, ...] = ()


class ProviderConstraint(PromptReference):
    """A constraint retaining the hazards it governs."""

    related_hazards: tuple[PromptReference, ...] = ()


class ProviderCoordinationPath(PromptReference):
    """A coordination path with source, target, and shared process model."""

    source: PromptReference
    target: PromptReference
    mechanism: PromptReference
    shared_process_model: PromptReference


class ProviderTargetIndex(_Model):
    """Compact STPA graph index for one target or an entire routing pass."""

    target_id: str | None = None
    target_kind: Literal["all", "responsibility", "coordination_link"] = "all"
    responsibilities: tuple[ProviderResponsibility, ...] = ()
    coordination_paths: tuple[ProviderCoordinationPath, ...] = ()
    controlled_processes: tuple[PromptReference, ...] = ()
    control_actions: tuple[ProviderControlAction, ...] = ()
    process_model_parts: tuple[ProviderProcessModelPart, ...] = ()
    feedback_channels: tuple[ProviderFeedbackChannel, ...] = ()
    slots: tuple[ProviderSlot, ...] = ()
    losses: tuple[PromptReference, ...] = ()
    hazards: tuple[ProviderHazard, ...] = ()
    constraints: tuple[ProviderConstraint, ...] = ()
    context_rows: tuple[ProviderContextRow, ...] = Field(
        default=(), exclude_if=lambda value: not value
    )
    # References mentioned in selected prose but not represented by an edge
    # in this target's graph.  They are explained, selectable context only;
    # keeping them separate prevents a textual mention from becoming a false
    # ownership or causal relationship.
    referenced_records: tuple[PromptReference, ...] = ()


class ProviderRoutedRoute(_Model):
    """Compact route evidence for a target-scoped ICA prompt."""

    route_handle: str = Field(min_length=1)
    obligation_handle: str = Field(min_length=1)
    slot_ids: tuple[str, ...] = ()
    hazard_ids: tuple[str, ...] = ()
    constraint_ids: tuple[str, ...] = ()
    instruction: str = Field(min_length=1)


class ProviderRoutingContext(_Model):
    """Closed provider view for structural obligation routing."""

    obligation_questions: tuple[ProviderObligationQuestion, ...] = Field(min_length=1)
    target_index: ProviderTargetIndex
    instructions: str = Field(min_length=1)


class ProviderRevisionGap(_Model):
    """Request-local revision gap with no final STPA identity."""

    gap_handle: str = Field(min_length=1)
    trigger_obligation_handle: str = Field(min_length=1)
    plain_description: str = Field(min_length=1)
    why_the_concept_is_needed: str = Field(min_length=1)
    expected_concept_kind: StructuralConceptKind
    related_existing_context: tuple[PromptReference, ...] = ()


class ProviderRevisionContext(_Model):
    """Closed provider view for the one atomic structural-revision round."""

    gaps: tuple[ProviderRevisionGap, ...] = Field(min_length=1)
    target_index: ProviderTargetIndex
    instructions: str = Field(min_length=1)


ProviderRevisionGap.model_rebuild(
    _types_namespace={"StructuralConceptKind": StructuralConceptKind}
)


class PromptContractAudit(_Model):
    """Deterministic pre-dispatch audit for one rendered provider prompt."""

    stage: str = Field(min_length=1)
    view_type: str = Field(min_length=1)
    valid: bool
    issues: tuple[str, ...] = ()
    prompt_digest: str | None = None

    def assert_valid(self) -> None:
        """Raise a technical error when the prompt contract is defective."""
        if not self.valid:
            raise ValueError(
                f"{self.stage} prompt contract audit failed: " + "; ".join(self.issues)
            )


class RevisionDraft(_Model):
    """Request-local additive draft returned by a revision adapter."""

    trigger_gap_ids: tuple[str, ...] = ()
    trigger_obligation_ids: tuple[str, ...] = ()
    losses: tuple[DraftLoss, ...] = ()
    hazards: tuple[DraftHazard, ...] = ()
    security_constraints: tuple[DraftSecurityConstraint, ...] = ()
    responsibilities: tuple[DraftResponsibility, ...] = ()
    controlled_processes: tuple[DraftControlledProcess, ...] = ()
    process_model_parts: tuple[DraftProcessModelPart, ...] = ()
    control_actions: tuple[DraftControlAction, ...] = ()
    feedback_channels: tuple[DraftFeedbackChannel, ...] = ()
    coordination_links: tuple[DraftCoordinationLink, ...] = ()
    dismissed_gap_ids: tuple[str, ...] = ()
    gap_decisions: tuple[RevisionGapDecision, ...] = ()
    rationale: str = ""

    @model_validator(mode="after")
    def unique_gap_decisions(self) -> "RevisionDraft":
        handles = tuple(item.gap_handle for item in self.gap_decisions)
        if len(handles) != len(set(handles)):
            raise ValueError("revision gap decisions must have unique gap handles")
        return self


class StructuralRevisionRequest(_DigestModel):
    """Complete gap set and immutable baseline for one revision attempt."""

    schema_version: Literal[REVISION_REQUEST_SCHEMA_VERSION] = (
        REVISION_REQUEST_SCHEMA_VERSION
    )
    gaps: tuple[MissingStructuralConcept, ...] = Field(min_length=1)
    baseline_loss_analysis: LossAnalysis
    baseline_control_structure: ControlStructure
    controls: AnalysisControls
    plan_digest: Digest | None = None
    _digest_domain = REVISION_REQUEST_DIGEST_DOMAIN

    @model_validator(mode="after")
    def canonicalize_and_verify(self) -> "StructuralRevisionRequest":
        gaps = tuple(sorted(self.gaps, key=lambda item: item.gap_id or ""))
        if len({item.gap_id for item in gaps}) != len(gaps):
            raise ValueError("revision gaps must have unique gap IDs")
        object.__setattr__(self, "gaps", gaps)
        expected = self.compute_semantic_digest()
        if self.semantic_digest is not None and self.semantic_digest != expected:
            raise ValueError("revision request semantic_digest does not match")
        object.__setattr__(self, "semantic_digest", expected)
        return self

    def _semantic_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"semantic_digest"})


class StructuralRevisionResponse(_Model):
    """Provider-local response for the one permitted revision attempt."""

    # ``rejected`` is an explicit, valid domain outcome: the adapter completed
    # its one proposal attempt but declined to apply the resulting draft.  It
    # is distinct from protocol/provider/compiler failures, which the caller
    # records as ``technical_failure`` without treating them as a conclusion.
    status: Literal["completed", "rejected"] = "completed"
    request_digest: Digest
    draft: RevisionDraft
    adapter_kind: Literal["fake", "provider"] = "fake"
    request_ref: str = "memory://stpa-obligation-revision/request"
    response_ref: str = "memory://stpa-obligation-revision/response"
    provider_calls: Literal[0, 1] = 0
    network_calls: Literal[0, 1] = 0
    response_digest: Digest | None = None

    @model_validator(mode="after")
    def validate_response(self) -> "StructuralRevisionResponse":
        if self.adapter_kind == "fake" and (self.provider_calls or self.network_calls):
            raise ValueError("fake adapter cannot report provider/network calls")
        if self.adapter_kind == "provider" and self.provider_calls != 1:
            raise ValueError("provider adapter must report one provider call")
        return self


class SynthesisSlotRequest(_DigestModel):
    """Target-scoped ICA request containing only routed obligation briefs."""

    schema_version: Literal[SLOT_REQUEST_SCHEMA_VERSION] = SLOT_REQUEST_SCHEMA_VERSION
    target_id: str = Field(min_length=1)
    target_kind: Literal["responsibility", "coordination_link"]
    slots: tuple[SlotPlaceholder, ...] = Field(min_length=1)
    routed_briefs: tuple[NeutralObligationBrief, ...] = ()
    routed_routes: tuple[ObligationRoute, ...] = ()
    loss_analysis: LossAnalysis
    control_structure: ControlStructure
    controls: AnalysisControls
    _digest_domain = SLOT_REQUEST_DIGEST_DOMAIN

    @model_validator(mode="after")
    def canonicalize_and_verify(self) -> "SynthesisSlotRequest":
        object.__setattr__(
            self, "slots", tuple(sorted(self.slots, key=lambda item: item.slot_id))
        )
        object.__setattr__(
            self,
            "routed_briefs",
            tuple(sorted(self.routed_briefs, key=lambda item: item.obligation_id)),
        )
        object.__setattr__(
            self,
            "routed_routes",
            tuple(sorted(self.routed_routes, key=lambda item: item.obligation_id)),
        )
        expected = self.compute_semantic_digest()
        if self.semantic_digest is not None and self.semantic_digest != expected:
            raise ValueError("slot request semantic_digest does not match")
        object.__setattr__(self, "semantic_digest", expected)
        return self

    def _semantic_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"semantic_digest"})


class SynthesisSlotResponse(_Model):
    """Provider-local slot response with authoritative pair evidence."""

    status: Literal["completed"] = "completed"
    request_digest: Digest
    filled_slots: tuple[SlotProviderEntry, ...] = ()
    considerations: tuple[ObligationIcaConsideration, ...] = ()
    adapter_kind: Literal["fake", "provider"] = "fake"
    request_ref: str = "memory://stpa-obligation-slots/request"
    response_ref: str = "memory://stpa-obligation-slots/response"
    provider_calls: Literal[0, 1] = 0
    network_calls: Literal[0, 1] = 0
    response_digest: Digest | None = None

    @model_validator(mode="after")
    def validate_response(self) -> "SynthesisSlotResponse":
        if self.adapter_kind == "fake" and (self.provider_calls or self.network_calls):
            raise ValueError("fake adapter cannot report provider/network calls")
        if self.adapter_kind == "provider" and self.provider_calls != 1:
            raise ValueError("provider adapter must report one provider call")
        object.__setattr__(
            self,
            "filled_slots",
            tuple(sorted(self.filled_slots, key=lambda item: item.slot_id)),
        )
        pairs = tuple(
            (item.obligation_id, item.slot_id) for item in self.considerations
        )
        if len(pairs) != len(set(pairs)):
            raise ValueError("slot response must contain unique obligation/slot pairs")
        object.__setattr__(
            self,
            "considerations",
            tuple(
                sorted(
                    self.considerations,
                    key=lambda item: (item.obligation_id, item.slot_id),
                )
            ),
        )
        return self


class SynthesisSlotFillResult(_Model):
    """Final deterministic slot universe and separate obligation evidence."""

    ica_enumeration: ICAEnumeration
    considerations: tuple[ObligationIcaConsideration, ...] = ()
    requests: tuple[SynthesisSlotRequest, ...] = ()
    call_evidence: tuple[ConsiderationCallEvidence, ...] = ()
    diagnostics: tuple[ConsiderationDiagnostic, ...] = ()
    ica_hazard_verification: IcaHazardVerificationBatch | None = None

    @model_validator(mode="after")
    def canonicalize(self) -> "SynthesisSlotFillResult":
        pairs = tuple(
            (item.obligation_id, item.slot_id) for item in self.considerations
        )
        if len(pairs) != len(set(pairs)):
            raise ValueError("slot fill result has duplicate obligation/slot evidence")
        object.__setattr__(
            self,
            "considerations",
            tuple(
                sorted(
                    self.considerations,
                    key=lambda item: (item.obligation_id, item.slot_id),
                )
            ),
        )
        object.__setattr__(
            self,
            "requests",
            tuple(sorted(self.requests, key=lambda item: item.target_id)),
        )
        object.__setattr__(
            self,
            "call_evidence",
            tuple(sorted(self.call_evidence, key=lambda item: item.call_id)),
        )
        object.__setattr__(
            self,
            "diagnostics",
            tuple(sorted(self.diagnostics, key=lambda item: (item.code, item.detail))),
        )
        return self


class StructuralAnalysisAdapter(Protocol):
    """Adapter contract for the named routing and bounded revision stages."""

    def route(self, request: StructuralRoutingRequest) -> StructuralRoutingResponse: ...

    def revise(
        self, request: StructuralRevisionRequest
    ) -> StructuralRevisionResponse: ...


class SlotAnalysisAdapter(Protocol):
    """Adapter contract for the named synthesis-specific ICA stage."""

    def fill(self, request: SynthesisSlotRequest) -> SynthesisSlotResponse: ...


class ObligationAwareAnalysisAdapter(
    StructuralAnalysisAdapter, SlotAnalysisAdapter, Protocol
):
    """Combined adapter contract for callers that own all named stages."""


# Compatibility aliases are provider-envelope aliases, not duplicate domain
# records. The inward types remain imported directly from the models package.
StructuralGap = MissingStructuralConcept
ObligationSlotEvidence = ObligationIcaConsideration
CallEvidence = ConsiderationCallEvidence
SourcePin = ArtifactPin
StructuralRouteRequest = StructuralRoutingRequest
StructuralRouteResponse = StructuralRoutingResponse
RevisionRequest = StructuralRevisionRequest
RevisionResponse = StructuralRevisionResponse
SlotFillRequest = SynthesisSlotRequest
SlotFillResponse = SynthesisSlotResponse


__all__ = [
    "AnalysisControls",
    "ArtifactPin",
    "BoundedStructuralRevision",
    "CallEvidence",
    "ConsiderationCallEvidence",
    "ConsiderationDiagnostic",
    "Digest",
    "DraftControlAction",
    "DraftControlledProcess",
    "DraftCoordinationLink",
    "DraftCoordinationMechanism",
    "DraftFeedbackChannel",
    "DraftHazard",
    "DraftLoss",
    "DraftProcessModelPart",
    "DraftResponsibility",
    "DraftResponsibilityConstraint",
    "DraftSecurityConstraint",
    "IcaDeviationDraft",
    "IcaFindingDraft",
    "IcaConstraintContext",
    "IcaHazardContext",
    "IcaHazardVerificationAttempt",
    "IcaHazardVerificationBatch",
    "IcaHazardVerificationCorrection",
    "IcaHazardVerificationRecord",
    "IcaHazardVerificationRequest",
    "IcaHazardVerificationVerdict",
    "IcaHazardVerdict",
    "IcaLossContext",
    "IcaConsideration",
    "MissingStructuralConcept",
    "NeutralObligationBrief",
    "ObligationIcaDraft",
    "ObligationAwareAnalysisAdapter",
    "ObligationIcaConsideration",
    "ObligationRoute",
    "ObligationSlotEvidence",
    "PromptReference",
    "ProviderApplicability",
    "ProviderApplicabilityFact",
    "ProviderControlAction",
    "ProviderConstraint",
    "ProviderCoordinationPath",
    "ProviderFeedbackChannel",
    "ProviderHazard",
    "ProviderKnownConcern",
    "ProviderMappingStrength",
    "ProviderObligationQuestion",
    "ProviderProcessModelPart",
    "ProviderResponsibility",
    "ProviderRevisionContext",
    "ProviderRevisionGap",
    "ProviderReviewedRisk",
    "ProviderRoutedRoute",
    "ProviderSlot",
    "ProviderSystemResource",
    "ProviderTargetIndex",
    "ProviderRoutingContext",
    "PromptContractAudit",
    "RevisionGapDecision",
    "RevisionAddition",
    "RevisionDelta",
    "RevisionDraft",
    "RevisionRequest",
    "RevisionResponse",
    "SLOT_REQUEST_SCHEMA_VERSION",
    "SlotAnalysisAdapter",
    "SlotIcaDraft",
    "SlotProviderEntry",
    "SlotFillRequest",
    "SlotFillResponse",
    "SourcePin",
    "StructuralAnalysisAdapter",
    "StructuralGap",
    "StructuralRevisionDelta",
    "StructuralRevisionRequest",
    "StructuralRevisionResponse",
    "StructuralRouteRequest",
    "StructuralRouteResponse",
    "StructuralRoutingRequest",
    "StructuralRoutingResponse",
    "SynthesisSlotFillResult",
    "SynthesisSlotRequest",
    "SynthesisSlotResponse",
]
