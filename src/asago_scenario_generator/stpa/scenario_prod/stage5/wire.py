"""Stage 5 provider wire models, the declared causal factor, and source choices."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, Any, Literal, Union
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    StrictBool,
    StrictStr,
    StringConstraints,
    model_validator,
)
from asago_scenario_generator.stpa.models.causal_factor import (
    CausalEvidenceStatus,
    CausalFactorKind,
    validate_causal_evidence_shape,
)
from asago_scenario_generator.stpa.models.semantic_conditions import (
    SemanticCondition,
    SemanticValue,
)
from asago_scenario_generator.stpa.observation_contract import (
    SafeObservableOutcome,
)
from asago_scenario_generator.stpa.models.scenario_spec import (
    AdversaryKind,
)


class CausalFactorDeclaration(BaseModel):
    """One Stage 5 declaration of an evidence-backed causal factor.

    ``kind`` and ``source_id`` name the structural finding, ``evidence``
    carries the declared evidence description, and ``temporal_condition``
    carries the typed temporal condition the provider declared.  The evidence
    status distinguishes an existing structural failure from an explicitly
    reachable capability or a bounded assumption.  Capability and access
    references are resolved against the exact scenario context during
    deterministic assembly.
    """

    model_config = ConfigDict(extra="forbid")

    kind: CausalFactorKind
    source_id: str = Field(min_length=1)
    evidence: str = Field(min_length=1)
    temporal_condition: SemanticCondition | None = None
    evidence_status: CausalEvidenceStatus = CausalEvidenceStatus.structural_failure
    capability_refs: tuple[str, ...] = ()
    access_refs: tuple[str, ...] = ()
    bounded_assumption: str | None = None

    @model_validator(mode="after")
    def validate_evidence_shape(self) -> "CausalFactorDeclaration":
        """Require supporting material for capability and assumption claims."""
        validate_causal_evidence_shape(
            self.evidence_status,
            self.capability_refs,
            self.access_refs,
            self.bounded_assumption,
        )
        return self


class _ObservationCriterionDraft(BaseModel):
    """Provider declaration of one observable or analytical outcome."""

    model_config = ConfigDict(extra="forbid")

    criterion_id: StrictStr = Field(min_length=1)
    outcome: StrictStr = Field(min_length=1, max_length=600)
    observable: StrictBool
    claim_level: StrictStr | None = None
    evidence: StrictStr | None = None
    operation_name: StrictStr | None = Field(default=None, min_length=1)
    reason: StrictStr = Field(min_length=1, max_length=600)

    @model_validator(mode="after")
    def validate_observation_shape(self) -> "_ObservationCriterionDraft":
        """Require a complete evidence boundary for observable claims."""

        if self.observable and (self.claim_level is None or self.evidence is None):
            raise ValueError(
                "observable observation criteria require claim_level and evidence"
            )
        if not self.observable and (
            self.claim_level is not None or self.operation_name is not None
        ):
            raise ValueError(
                "non-observable observation criteria must not declare claim_level "
                "or operation_name"
            )
        return self


class _ContextTemporalConditionWire(BaseModel):
    """Marker base for strict, request-local temporal factor branches."""

    model_config = ConfigDict(extra="forbid")


class _ContextOrderingTemporalWire(_ContextTemporalConditionWire):
    """Provider ordering condition using request-local step handles."""

    type: Literal["ordering"]
    reference_handle: StrictStr = Field(min_length=1)
    relation: Literal["before", "after"]


class _ContextDelayTemporalWire(_ContextTemporalConditionWire):
    """Provider delay condition using a request-local reference handle."""

    type: Literal["delay"]
    reference_handle: StrictStr = Field(min_length=1)
    delay_ms: SemanticValue


class _ContextDurationTemporalWire(_ContextTemporalConditionWire):
    """Provider duration condition using a request-local reference handle."""

    type: Literal["duration"]
    reference_handle: StrictStr = Field(min_length=1)
    duration_ms: SemanticValue


class _ContextWindowTemporalWire(_ContextTemporalConditionWire):
    """Provider window condition using a request-local reference handle."""

    type: Literal["window"]
    reference_handle: StrictStr = Field(min_length=1)
    window_from_ms: SemanticValue
    window_to_ms: SemanticValue


class _ContextAbsenceTemporalWire(_ContextTemporalConditionWire):
    """Provider absence condition using local reference and step handles."""

    type: Literal["absence"]
    reference_handle: StrictStr = Field(min_length=1)
    until_step_handle: StrictStr = Field(min_length=1)


def _reject_evidence_status_label(value: str) -> None:
    """Reject an evidence field that is only a known status label."""
    if value in {status.value for status in CausalEvidenceStatus}:
        raise ValueError(
            "causal factor evidence must explain the causal condition, not repeat "
            "the evidence_status label"
        )


_ContextNonBlankText = Annotated[
    StrictStr,
    StringConstraints(strip_whitespace=True, min_length=1),
]


class _ContextAttackerIntentionDraft(BaseModel):
    """Provider prose with compiler-owned structural references."""

    model_config = ConfigDict(extra="forbid")

    description: _ContextNonBlankText
    source_handles: tuple[str, ...] = Field(min_length=1)


class _ContextAttackerBDIDraft(BaseModel):
    """Provider-only attacker BDI using local causal-source handles.

    Cardinality depends on the adversary record: functional candidates use an
    explicitly empty BDI, while adversarial candidates retain the historical
    non-empty desires and intentions requirements.  The request-local dynamic
    schema supplies the concrete intention subtype.
    """

    model_config = ConfigDict(extra="forbid")

    beliefs: list[str]
    desires: list[_ContextNonBlankText]
    intentions: list[_ContextAttackerIntentionDraft]


class _ContextAdversarialDraft(BaseModel):
    """Provider-authored adversary who and why, never the delivery channel.

    ``reaches_target_via`` is compiler-owned, so the provider wire does not
    carry it.  The historical wire derives the reach from the stimulus
    category; the normal wire carries no stimulus, so
    the reach derives from the adversary kind alone and stays null unless
    the kind is ``third_party_via_content``.
    """

    model_config = ConfigDict(extra="forbid")

    kind: Literal[
        AdversaryKind.external_attacker,
        AdversaryKind.malicious_customer,
        AdversaryKind.third_party_via_content,
    ]
    gain: _ContextNonBlankText


class _ContextFunctionalAdversaryDraft(BaseModel):
    """Functional provider branch with no invented actor benefit."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal[AdversaryKind.none]
    # Accepted for frozen historical provider fixtures, but ignored by the
    # compiler and never requested by the functional prompt.
    gain: _ContextNonBlankText | None = None


_ContextAdversaryValue = Annotated[
    Union[_ContextAdversarialDraft, _ContextFunctionalAdversaryDraft],
    Field(discriminator="kind"),
]


class _ContextSemanticOutcomeDraft(BaseModel):
    """Normal-path unsafe outcome: one bounded semantic proposition.

    The normal product run publishes the scenario handoff, which derives its
    failure meaning from the immutable context.  Execution design (typed
    conditions, comparison evidence) belongs to the artifact generator, so
    this draft carries the scenario semantics only.
    """

    model_config = ConfigDict(extra="forbid")

    semantic_proposition: StrictStr = Field(min_length=1, max_length=600)
    observation_criteria: list[_ObservationCriterionDraft] = Field(default_factory=list)
    safe_observable_outcome: SafeObservableOutcome | None = None
    # The condition the parse removed from a reply-only reply because it did
    # not fit the condition schema; validation records it, it never publishes.
    _unparsed_condition: Any = PrivateAttr(default=None)


class _ContextSemanticFactorWireBase(BaseModel):
    """Provider factor fields before evidence-status branching.

    The evidence-prose rule is causal discipline. The wire binds no factor to
    a delivery route; delivery is artifact design that the consumer owns.
    """

    model_config = ConfigDict(extra="forbid")

    source_handle: StrictStr = Field(pattern=r"^cause_\d+$")
    evidence: StrictStr = Field(min_length=1)

    @model_validator(mode="after")
    def validate_evidence_explanation(self) -> "_ContextSemanticFactorWireBase":
        """Require prose evidence rather than copying its status label."""
        _reject_evidence_status_label(self.evidence)
        return self


class _ContextScenarioSemanticsPayload(BaseModel):
    """Normal-path response body: scenario semantics and causal evidence only.

    The wire requests no stimulus category, no execution route, no
    factor-route binding and no executable unsafe-outcome conditions.
    Artifact-feasibility machinery therefore never runs in normal acceptance.
    """

    model_config = ConfigDict(extra="forbid")

    adversary: _ContextAdversaryValue
    attacker_bdi: _ContextAttackerBDIDraft
    causal_factors: list[_ContextSemanticFactorWireBase]
    unsafe_outcome: _ContextSemanticOutcomeDraft


@dataclass(frozen=True)
class _CausalSourceChoice:
    """One request-local handle bound to an exact structural factor source."""

    handle: str
    kind: CausalFactorKind
    source_id: str
    description: str
    source_kind: str | None = None
