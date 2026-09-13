"""Closed producer-side contracts for STPA execution projection v3.

This module is the immutable, content-addressed v3 wire contract paired with
bundle v2.  It reuses the v2 value objects so the shared structural rules
cannot drift, and adds exactly two deltas: the structured omission-evidence
carrier on the unsafe outcome and the exact prepared direct-prompt text on the
stimulus requirement.

A bundle v2 index is homogeneous: every entry references a v3 projection,
including entries whose outcome is not an omission.  Legacy proposition-only
runs keep publishing bundle v1 with v2 projections unchanged.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictStr,
    model_validator,
)

from asago_scenario_generator.models.canonical import (
    canonical_json_bytes,
    compute_framed_digest,
)
from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionClassification,
    ExecutionDeliveryClass,
    SemanticExecutionContract,
)
from asago_scenario_generator.stpa.models.execution_projection_v2 import (
    BundleScenarioReference,
    ExecutionCausalFactor,
    ExecutionRequirements,
    ExecutionStep,
    ExecutionTraceRefs,
    ProducerIdentity,
    UCAType,
    _condition_is_compatible,
    _set_projection_digest,
    _validate_action_reference,
    _validate_execution_classification,
    _validate_factor_sequence,
    _validate_projection_bindings,
    _validate_projection_conditions,
    _validate_projection_identity,
    _validate_projection_lineage,
    _validate_projection_outcome,
    _validate_step_sequence,
    _validate_stimulus_requirements,
    _validate_unique_outcome_refs,
    SHA256_PATTERN,
)
from asago_scenario_generator.stpa.models.omission_evidence import (
    OmissionEvidence,
)
from asago_scenario_generator.stpa.models.semantic_conditions import (
    ActionPresenceCondition,
    SemanticCondition,
    StimulusTurn,
    contains_binding_placeholder,
    normalize_semantic_proposition,
)

PROJECTION_V3_SCHEMA_VERSION = "stpa-execution-projection-v3"
BUNDLE_V2_SCHEMA_VERSION = "stpa-execution-bundle-v2"
PROJECTION_V3_DIGEST_FRAME = PROJECTION_V3_SCHEMA_VERSION
BUNDLE_V2_DIGEST_FRAME = BUNDLE_V2_SCHEMA_VERSION

# Hard bound from the approved structured-evidence proposal
# (build/qualification/current-interface-followup-20260913/
# structured-evidence-proposal.md): one prepared_user_text at most 4,096
# characters, copied before projection and delivered verbatim.
MAX_PREPARED_USER_TEXT_LENGTH = 4096


class _ClosedFrozenModel(BaseModel):
    """Base for immutable closed wire records."""

    # Enum discriminators are canonical JSON strings.  Scalar fields below
    # use Strict* annotations so wire values are never coerced.
    model_config = ConfigDict(extra="forbid", frozen=True)


class UnsafeOutcomeV3(_ClosedFrozenModel):
    """The semantic condition that makes the selected action unsafe.

    Carries the v2 field set plus the optional structured omission-evidence
    carrier.  The carrier rides only on the authored action-absence route; the
    legacy temporal ``absence`` condition never carries one.
    """

    outcome_id: StrictStr = Field(pattern=r"^OUTCOME-[A-Za-z0-9._-]+$")
    control_action_id: StrictStr = Field(min_length=1)
    uca_type: UCAType
    condition: SemanticCondition
    semantic_proposition: StrictStr | None
    semantic_binding_required: StrictBool
    hazard_refs: tuple[StrictStr, ...] = ()
    constraint_refs: tuple[StrictStr, ...] = ()
    # The carrier and its derived digest travel together or not at all; the
    # digest is recomputed here and never trusted from the wire.
    omission_evidence: OmissionEvidence | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    omission_evidence_digest: StrictStr | None = Field(
        default=None,
        pattern=SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )

    @model_validator(mode="after")
    def validate_outcome(self) -> "UnsafeOutcomeV3":
        _validate_action_reference(self.control_action_id)
        if not _condition_is_compatible(self.uca_type, self.condition):
            raise ValueError(
                f"condition type '{self.condition.type}' is incompatible with "
                f"UCA type '{self.uca_type.value}'"
            )
        actual_binding = contains_binding_placeholder(self.condition)
        if self.semantic_binding_required is not actual_binding:
            raise ValueError(
                "semantic_binding_required must exactly match placeholder presence"
            )
        if self.semantic_proposition is not None:
            normalize_semantic_proposition(self.semantic_proposition, required=True)
        _validate_unique_outcome_refs(self.hazard_refs, "hazard_refs")
        _validate_unique_outcome_refs(self.constraint_refs, "constraint_refs")
        object.__setattr__(self, "hazard_refs", tuple(sorted(self.hazard_refs)))
        object.__setattr__(self, "constraint_refs", tuple(sorted(self.constraint_refs)))
        self._validate_omission_carrier()
        return self

    def _validate_omission_carrier(self) -> None:
        """Bind the carrier to the authored action-absence route only."""
        is_action_absence = (
            isinstance(self.condition, ActionPresenceCondition)
            and self.condition.expected == "not_provided"
        )
        if is_action_absence and self.omission_evidence is None:
            raise ValueError("action-presence outcomes require omission_evidence")
        if not is_action_absence and self.omission_evidence is not None:
            raise ValueError(
                "omission_evidence is allowed only on action-presence outcomes"
            )
        if self.omission_evidence is None:
            if self.omission_evidence_digest is not None:
                raise ValueError("omission_evidence_digest requires omission_evidence")
            return
        expected = self.omission_evidence.compute_carrier_digest()
        if self.omission_evidence_digest != expected:
            raise ValueError(
                "omission_evidence_digest does not match the carrier content"
            )


class AdversarialStimulusRequirementV3(_ClosedFrozenModel):
    """Platform-neutral content that must drive one causal path.

    Carries the v2 field set plus the exact prepared direct-prompt text copied
    before projection.  The two text forms are mutually exclusive: a direct
    prompt delivers the prepared text verbatim, a conversation delivers the
    published turns, and indirect content owns neither field.
    """

    stimulus_id: StrictStr = Field(pattern=r"^STIM-\d+$")
    intent: StrictStr = Field(min_length=1)
    desired_effect: StrictStr = Field(min_length=1)
    delivery_class: ExecutionDeliveryClass
    factor_id: StrictStr = Field(pattern=r"^CF-\d+$")
    source_role: StrictStr = Field(
        min_length=1,
        pattern=r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$",
    )
    carrier_requirement_id: StrictStr | None = Field(
        default=None, pattern=r"^REQ-[A-Za-z0-9._-]+$"
    )
    turns: tuple[StimulusTurn, ...] | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    prepared_user_text: StrictStr | None = Field(
        default=None,
        min_length=1,
        max_length=MAX_PREPARED_USER_TEXT_LENGTH,
        exclude_if=lambda value: value is None,
    )

    @model_validator(mode="after")
    def validate_delivery(self) -> "AdversarialStimulusRequirementV3":
        if self.delivery_class is ExecutionDeliveryClass.indirect_content:
            if self.carrier_requirement_id is None:
                raise ValueError(
                    "indirect_content stimuli require carrier_requirement_id"
                )
        elif self.carrier_requirement_id is not None:
            raise ValueError(
                "only indirect_content stimuli may name a carrier requirement"
            )
        self._validate_prepared_delivery()
        return self

    def _validate_prepared_delivery(self) -> None:
        """Enforce the mutually exclusive v3 stimulus text forms."""
        if self.delivery_class is ExecutionDeliveryClass.direct_prompt:
            if self.prepared_user_text is None:
                raise ValueError("direct_prompt stimuli require prepared_user_text")
            if self.turns is not None:
                raise ValueError("direct_prompt stimuli must not carry turns")
            return
        if self.delivery_class is ExecutionDeliveryClass.conversation_context:
            if self.prepared_user_text is not None:
                raise ValueError(
                    "conversation_context stimuli must not carry prepared_user_text"
                )
            if self.turns is None:
                raise ValueError("conversation_context stimuli require turns")
            if not 2 <= len(self.turns) <= 3:
                raise ValueError("stimulus turns require two to three entries")
            turn_ids = [turn.turn_id for turn in self.turns]
            if len(turn_ids) != len(set(turn_ids)):
                raise ValueError("stimulus turns must carry unique turn_id values")
            return
        if self.prepared_user_text is not None or self.turns is not None:
            raise ValueError(
                "indirect_content stimuli must not carry prepared_user_text or turns"
            )


class ExecutionProjectionV3(_ClosedFrozenModel):
    """Complete immutable ``stpa-execution-projection-v3`` document."""

    schema_version: Literal[PROJECTION_V3_SCHEMA_VERSION] = PROJECTION_V3_SCHEMA_VERSION
    run_id: StrictStr = Field(min_length=1)
    scenario_id: StrictStr = Field(min_length=1)
    candidate_id: StrictStr = Field(min_length=1)
    ica_slot_id: StrictStr = Field(min_length=1)
    ica_id: StrictStr = Field(min_length=1)
    controller_id: StrictStr = Field(min_length=1)
    control_action_id: StrictStr = Field(min_length=1)
    uca_type: UCAType
    causal_factors: tuple[ExecutionCausalFactor, ...]
    steps: tuple[ExecutionStep, ...]
    unsafe_outcome: UnsafeOutcomeV3
    stimulus_requirements: tuple[AdversarialStimulusRequirementV3, ...] = ()
    execution_requirements: ExecutionRequirements
    execution_contract: SemanticExecutionContract
    execution_classification: ExecutionClassification
    trace_refs: ExecutionTraceRefs
    # In-process construction may omit this so the model can derive it.  The
    # persisted standalone parser rejects omission before model validation.
    semantic_digest: StrictStr | None = Field(default=None, pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_projection(self) -> "ExecutionProjectionV3":
        # The v2 seam helpers are attribute-based and version-neutral; reuse
        # them so the shared structural rules cannot drift between wires.
        _validate_projection_identity(self)
        _validate_projection_outcome(self)
        _validate_projection_lineage(self)
        _validate_factor_sequence(self.causal_factors)
        _validate_step_sequence(self.steps, self.causal_factors, self.control_action_id)
        _validate_projection_conditions(self)
        _validate_projection_bindings(self)
        _validate_stimulus_requirements(self)
        _validate_execution_classification(self)
        _set_projection_digest(self)
        return self

    def semantic_payload(self) -> dict[str, Any]:
        """Return canonical projection data excluding ``semantic_digest``."""
        return self.model_dump(mode="json", exclude={"semantic_digest"})

    def compute_semantic_digest(self) -> str:
        """Compute the framed semantic SHA-256 digest."""
        return compute_framed_digest(
            PROJECTION_V3_DIGEST_FRAME, self.semantic_payload()
        )

    def canonical_json_bytes(self) -> bytes:
        """Return canonical JSON bytes including the recorded digest."""
        return canonical_json_bytes(self.model_dump(mode="json"))

    def canonical_json_text(self) -> str:
        """Return compact canonical JSON text with no trailing whitespace."""
        return self.canonical_json_bytes().decode("utf-8")


# Bundle-v2 entries reference v3 projections.  The v2 bundle entry is not
# version-neutral: its nested projection and validation references pin the
# projection-v2 schema literal, so bundle v2 re-declares the same entry shape
# with the v3 literals instead of importing the v2 entry records.
class BundleProjectionReferenceV3(_ClosedFrozenModel):
    """Exact persisted canonical v3 projection JSON reference."""

    path: StrictStr = Field(min_length=1)
    schema_version: Literal[PROJECTION_V3_SCHEMA_VERSION] = PROJECTION_V3_SCHEMA_VERSION
    content_sha256: StrictStr = Field(pattern=SHA256_PATTERN)
    semantic_digest: StrictStr = Field(pattern=SHA256_PATTERN)


class BundleValidationReferenceV3(_ClosedFrozenModel):
    """Validation attestation recorded in a bundle-v2 index entry."""

    status: Literal["valid"] = "valid"
    validator_version: Literal[PROJECTION_V3_SCHEMA_VERSION] = (
        PROJECTION_V3_SCHEMA_VERSION
    )


class ExecutionBundleEntryV3(_ClosedFrozenModel):
    """One scenario/projection pair in a bundle-v2 run-level index."""

    scenario_id: StrictStr = Field(min_length=1)
    candidate_id: StrictStr = Field(min_length=1)
    ica_slot_id: StrictStr = Field(min_length=1)
    ica_id: StrictStr = Field(min_length=1)
    scenario: BundleScenarioReference
    projection: BundleProjectionReferenceV3
    validation: BundleValidationReferenceV3 = BundleValidationReferenceV3()

    @model_validator(mode="after")
    def validate_pair_identity(self) -> "ExecutionBundleEntryV3":
        if not self.ica_id.startswith(self.ica_slot_id + ":"):
            raise ValueError("bundle entry ICA does not belong to its slot")
        return self


class ExecutionBundleIndexV2(_ClosedFrozenModel):
    """Closed content-addressed ``stpa-execution-bundle-v2`` index."""

    schema_version: Literal[BUNDLE_V2_SCHEMA_VERSION] = BUNDLE_V2_SCHEMA_VERSION
    run_id: StrictStr = Field(min_length=1)
    producer: ProducerIdentity
    entries: tuple[ExecutionBundleEntryV3, ...] = ()
    bundle_digest: StrictStr | None = Field(default=None, pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_entries_and_digest(self) -> "ExecutionBundleIndexV2":
        ordered = tuple(
            sorted(
                self.entries,
                key=lambda entry: (
                    entry.scenario_id,
                    entry.candidate_id,
                    entry.ica_slot_id,
                    entry.ica_id,
                ),
            )
        )
        identities = [
            (entry.scenario_id, entry.candidate_id, entry.ica_slot_id, entry.ica_id)
            for entry in ordered
        ]
        if len(identities) != len(set(identities)):
            raise ValueError("bundle entries must have unique identity tuples")
        if ordered != self.entries:
            object.__setattr__(self, "entries", ordered)
        expected = self.compute_bundle_digest()
        if self.bundle_digest is not None and self.bundle_digest != expected:
            raise ValueError("bundle_digest does not match index content")
        object.__setattr__(self, "bundle_digest", expected)
        return self

    def semantic_payload(self) -> dict[str, Any]:
        """Return canonical index data excluding ``bundle_digest``."""
        return self.model_dump(mode="json", exclude={"bundle_digest"})

    def compute_bundle_digest(self) -> str:
        """Compute the framed bundle index digest."""
        return compute_framed_digest(BUNDLE_V2_DIGEST_FRAME, self.semantic_payload())

    def canonical_json_bytes(self) -> bytes:
        """Return canonical index JSON bytes including ``bundle_digest``."""
        return canonical_json_bytes(self.model_dump(mode="json"))


__all__ = [
    "BUNDLE_V2_DIGEST_FRAME",
    "BUNDLE_V2_SCHEMA_VERSION",
    "BundleProjectionReferenceV3",
    "BundleValidationReferenceV3",
    "ExecutionBundleEntryV3",
    "ExecutionBundleIndexV2",
    "ExecutionProjectionV3",
    "MAX_PREPARED_USER_TEXT_LENGTH",
    "PROJECTION_V3_DIGEST_FRAME",
    "PROJECTION_V3_SCHEMA_VERSION",
    "AdversarialStimulusRequirementV3",
    "UnsafeOutcomeV3",
]
