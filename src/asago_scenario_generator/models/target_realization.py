"""Closed contracts for the target-realization lens.

Target realization is deliberately kept out of both the STPA runner and the
target-discovery package.  These models form the immutable bridge between an
attested, target-blind STPA baseline and an observed execution target.  An
operation reference is an identity only: ``resource_id`` and ``operation_id``
are copied from the target profile without semantic matching or rewriting.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, ClassVar, Literal, Mapping, Sequence

import yaml
from pydantic import Field, PrivateAttr, field_validator, model_validator

from asago_scenario_generator.models.canonical import (
    ClosedCanonicalModel,
    FrozenDict,
    FrozenList,
    SemanticDigestMixin,
    canonical_yaml,
    compute_framed_digest,
    unique_sorted_strings,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
)
from asago_scenario_generator.stpa.models.ica_enumeration import ICAEnumeration
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis


TARGET_REALIZATION_SCHEMA_VERSION = "target-realization-v1"
TARGET_REALIZATION_DIGEST_DOMAIN = "asago-scenario-generator:target-realization:v1"
TARGET_REALIZATION_BASELINE_DIGEST_DOMAIN = (
    "asago-scenario-generator:target-realization-baseline:v1"
)
TARGET_REALIZATION_EFFECTIVE_SCHEMA_VERSION = "target-realization-effective-v1"
TARGET_REALIZATION_EFFECTIVE_DIGEST_DOMAIN = (
    "asago-scenario-generator:target-realization-effective:v1"
)


def _canonicalize_string_fields(model: object, field_names: Sequence[str]) -> None:
    """Canonicalize repeated string collections on a closed model."""
    for field_name in field_names:
        object.__setattr__(
            model,
            field_name,
            unique_sorted_strings(getattr(model, field_name), field_name),
        )


class TargetRealizationDisposition(str, Enum):
    """Deterministic outcome for one baseline-action mapping attempt."""

    supported = "supported"
    ambiguous = "ambiguous"
    unmapped = "unmapped"
    contradictory = "contradictory"


class CapabilityExposureDisposition(str, Enum):
    """Disposition in the declared-versus-observed capability matrix."""

    confirmed_exposure = "confirmed_exposure"
    declared_not_observed = "declared_not_observed"
    undocumented_exposure = "undocumented_exposure"
    capability_conflict = "capability_conflict"
    not_comparable = "not_comparable"


class TargetRealizationProvenance(str, Enum):
    """Origin of a realization record."""

    systemic_baseline = "systemic_baseline"
    target_derived = "target_derived"


class TargetRealizationExtensionDisposition(str, Enum):
    """Outcome for one bounded additive target-extension proposal."""

    accepted = "accepted"
    rejected = "rejected"


class TargetRealizationVerification(ClosedCanonicalModel):
    """Independent, local verification evidence for one mapping response."""

    status: Literal["verified", "rejected", "unverified"] = "unverified"
    detail: str = ""
    evidence_refs: tuple[str, ...] = ()

    @model_validator(mode="after")
    def canonicalize(self) -> "TargetRealizationVerification":
        _canonicalize_string_fields(self, ("evidence_refs",))
        return self


class TargetOperationReference(ClosedCanonicalModel):
    """Exact resource/operation identity copied from an observed profile."""

    resource_id: str = Field(min_length=1)
    operation_id: str = Field(min_length=1)

    @property
    def identity(self) -> tuple[str, str]:
        """Return the exact lookup identity used by deterministic code."""
        return self.resource_id, self.operation_id


class TargetOperationObservation(ClosedCanonicalModel):
    """Observed operation facts used in realization prompt views."""

    reference: TargetOperationReference
    description: str = ""
    # Keep the exact public interface contract alongside the compact argument
    # name list.  ``argument_names`` alone loses the type, requiredness,
    # default, enum, and nested-object meaning needed by target-specific ICA
    # analysis.  The scanner/profile boundary owns removal of runtime secrets;
    # realization must not redact or invent schema values here.
    input_schema: Mapping[str, Any] = Field(default_factory=dict)
    argument_names: tuple[str, ...] = ()
    effect: str | None = None
    state_effect: str | None = None
    state_changing: bool = False
    # These fields make the observed-versus-inferred boundary explicit in
    # compact provider views.  Interface description/schema are observed;
    # effect/state labels come from the separately reviewed interpretation.
    semantic_authority: str | None = None
    interpretation_disposition: str | None = None
    interpreter_verifier_agreement: str | None = None
    evidence_refs: tuple[str, ...] = ()

    @field_validator("input_schema", mode="before")
    @classmethod
    def freeze_input_schema(cls, value: Any) -> Any:
        """Retain exact schema semantics while closing nested JSON values."""
        return _freeze_interface_json(value)

    @model_validator(mode="after")
    def canonicalize(self) -> "TargetOperationObservation":
        object.__setattr__(
            self, "input_schema", _freeze_interface_json(self.input_schema)
        )
        properties = self.input_schema.get("properties", {})
        if properties is None:
            properties = {}
        if not isinstance(properties, Mapping):
            raise ValueError(
                "target operation input_schema.properties must be a mapping"
            )
        schema_argument_names = tuple(sorted(str(name) for name in properties))
        if (
            self.argument_names
            and schema_argument_names
            and tuple(sorted(self.argument_names)) != schema_argument_names
        ):
            raise ValueError(
                "target operation argument_names must match input_schema properties"
            )
        object.__setattr__(
            self,
            "argument_names",
            unique_sorted_strings(
                schema_argument_names or self.argument_names, "argument_names"
            ),
        )
        _canonicalize_string_fields(self, ("evidence_refs",))
        return self

    @property
    def resource_id(self) -> str:
        return self.reference.resource_id

    @property
    def operation_id(self) -> str:
        return self.reference.operation_id


def target_operation_action_description(operation: TargetOperationObservation) -> str:
    """Render one exact observed operation as a compiler-owned action meaning."""
    if not isinstance(operation, TargetOperationObservation):
        raise TypeError("operation must be a TargetOperationObservation")
    description = operation.description.strip() or (
        f"Invoke observed target operation {operation.operation_id}"
    )
    if operation.argument_names:
        return f"{description} (arguments: {', '.join(operation.argument_names)})"
    return description


class SystemicElementReference(ClosedCanonicalModel):
    """Closed reference retained in the systemic control-structure snapshot."""

    type: Literal["responsibility", "controlled_process"]
    id: str = Field(min_length=1)


class SystemicControlAction(ClosedCanonicalModel):
    """One baseline or target-derived control action."""

    control_action_id: str = Field(min_length=1)
    controller_id: str = Field(min_length=1)
    description: str = Field(min_length=1)
    target: SystemicElementReference | None = None
    effect_kind: str | None = None
    temporality: str | None = None
    provenance: TargetRealizationProvenance = (
        TargetRealizationProvenance.systemic_baseline
    )


class SystemicLoss(ClosedCanonicalModel):
    """Closed snapshot of one typed STPA loss."""

    loss_id: str = Field(min_length=1)
    description: str = Field(min_length=1)
    provenance: str = Field(min_length=1)
    source_risk_cards: tuple[str, ...] = ()

    @model_validator(mode="after")
    def canonicalize(self) -> "SystemicLoss":
        _canonicalize_string_fields(self, ("source_risk_cards",))
        return self


class SystemicHazard(ClosedCanonicalModel):
    """Closed snapshot of one typed STPA hazard."""

    hazard_id: str = Field(min_length=1)
    description: str = Field(min_length=1)
    related_losses: tuple[str, ...] = ()

    @model_validator(mode="after")
    def canonicalize(self) -> "SystemicHazard":
        _canonicalize_string_fields(self, ("related_losses",))
        return self


class SystemicSecurityConstraint(ClosedCanonicalModel):
    """Closed snapshot of one typed security constraint."""

    constraint_id: str = Field(min_length=1)
    description: str = Field(min_length=1)
    related_hazards: tuple[str, ...] = ()

    @model_validator(mode="after")
    def canonicalize(self) -> "SystemicSecurityConstraint":
        _canonicalize_string_fields(self, ("related_hazards",))
        return self


class SystemicLossAnalysisSnapshot(ClosedCanonicalModel):
    """Explicit JSON-compatible snapshot of typed loss-analysis authority."""

    risk_card_losses: tuple[SystemicLoss, ...] = ()
    use_case_losses: tuple[SystemicLoss, ...] = ()
    hazards: tuple[SystemicHazard, ...] = ()
    security_constraints: tuple[SystemicSecurityConstraint, ...] = ()


class SystemicResponsibilityConstraint(ClosedCanonicalModel):
    """Closed responsibility-constraint snapshot."""

    rc_id: str = Field(min_length=1)
    description: str = Field(min_length=1)


class SystemicProcessModelPart(ClosedCanonicalModel):
    """Closed process-model-part snapshot."""

    pm_id: str = Field(min_length=1)
    description: str = Field(min_length=1)
    feedback_source: SystemicElementReference | None = None


class SystemicFeedbackChannel(ClosedCanonicalModel):
    """Closed feedback-channel snapshot."""

    fb_id: str = Field(min_length=1)
    description: str = Field(min_length=1)
    updates: str = Field(min_length=1)
    source: SystemicElementReference | None = None


class SystemicResponsibility(ClosedCanonicalModel):
    """Closed responsibility snapshot containing its exact action list."""

    resp_id: str = Field(min_length=1)
    description: str = Field(min_length=1)
    responsibility_constraints: tuple[SystemicResponsibilityConstraint, ...] = ()
    security_constraint_refs: tuple[str, ...] = ()
    process_model_parts: tuple[SystemicProcessModelPart, ...] = ()
    control_actions: tuple[SystemicControlAction, ...] = ()
    feedback_channels: tuple[SystemicFeedbackChannel, ...] = ()

    @model_validator(mode="after")
    def canonicalize(self) -> "SystemicResponsibility":
        _canonicalize_string_fields(self, ("security_constraint_refs",))
        return self


class SystemicControlledProcess(ClosedCanonicalModel):
    """Closed controlled-process snapshot."""

    cp_id: str = Field(min_length=1)
    description: str = Field(min_length=1)
    provenance: TargetRealizationProvenance = (
        TargetRealizationProvenance.systemic_baseline
    )


class SystemicCoordinationMechanism(ClosedCanonicalModel):
    """Closed coordination-mechanism snapshot."""

    cm_id: str = Field(min_length=1)
    description: str = Field(min_length=1)
    payload: str = ""


class SystemicCoordinationLink(ClosedCanonicalModel):
    """Closed coordination-link snapshot."""

    link_id: str = Field(min_length=1)
    source: str = Field(min_length=1)
    target: str = Field(min_length=1)
    shared_pm: str = Field(min_length=1)
    coordination_mechanism: SystemicCoordinationMechanism
    description: str = Field(min_length=1)


class SystemicControlStructureSnapshot(ClosedCanonicalModel):
    """Explicit JSON-compatible snapshot of typed control-structure authority."""

    responsibilities: tuple[SystemicResponsibility, ...]
    controlled_processes: tuple[SystemicControlledProcess, ...] = ()
    coordination_links: tuple[SystemicCoordinationLink, ...] = ()

    def element_description(
        self,
        element_type: Literal["responsibility", "controlled_process"],
        element_id: str,
    ) -> str | None:
        """Resolve exact namespace/identity meaning without inferring a function."""
        descriptions = {
            "responsibility": {
                item.resp_id: item.description for item in self.responsibilities
            },
            "controlled_process": {
                item.cp_id: item.description for item in self.controlled_processes
            },
        }
        return descriptions[element_type].get(element_id)


class SystemicICA(ClosedCanonicalModel):
    """Closed snapshot of one ordinary ICA."""

    ica_id: str = Field(min_length=1)
    ica_text: str = Field(min_length=1)
    # Preserve the original slot-filling deviation separately from the
    # rendered controller/action sentence.  Target-derived findings may be
    # copied into this snapshot without recovering the clause by parsing
    # provider prose.
    deviation: str | None = Field(default=None, min_length=1)
    hazardous_context: str = Field(min_length=1)
    loss_scenario: str = Field(min_length=1)
    related_hazards: tuple[str, ...] = ()
    related_constraints: tuple[str, ...] = ()
    quality_warnings: tuple[str, ...] = ()

    @model_validator(mode="after")
    def canonicalize(self) -> "SystemicICA":
        _canonicalize_string_fields(
            self, ("related_hazards", "related_constraints", "quality_warnings")
        )
        return self


class SystemicICASlot(ClosedCanonicalModel):
    """Closed snapshot of one ordinary ICA slot."""

    slot_id: str = Field(min_length=1)
    responsibility: str | None = None
    coordination_link: str | None = None
    control_action: str = Field(min_length=1)
    action_temporality: str | None = None
    uca_type: str = Field(min_length=1)
    is_na: bool
    icas: tuple[SystemicICA, ...] = ()
    na_justification: str | None = None
    unresolved_reason: str | None = None

    @model_validator(mode="after")
    def validate_resolution_state(self) -> "SystemicICASlot":
        """Retain unresolved provider failures without relabelling them N/A."""
        if self.unresolved_reason is not None:
            if not self.unresolved_reason.strip():
                raise ValueError(
                    f"ICA slot {self.slot_id} unresolved_reason must be non-empty"
                )
            if self.is_na:
                raise ValueError(
                    f"ICA slot {self.slot_id} cannot be unresolved and is_na"
                )
            if self.icas:
                raise ValueError(
                    f"ICA slot {self.slot_id} cannot be unresolved with findings"
                )
            if self.na_justification is not None:
                raise ValueError(
                    f"ICA slot {self.slot_id} cannot be unresolved with na_justification"
                )
        return self


class TargetDerivedICASlot(ClosedCanonicalModel):
    """One closed ICA slot proposed by the bounded target-extension lens.

    A target extension supplies the minimum identity and authority needed for
    ordinary ICA enumeration to run later.  It does not copy or replace the
    systemic ICA findings already present in the baseline.
    """

    slot_id: str = Field(min_length=1)
    responsibility: str = Field(min_length=1)
    control_action: str = Field(min_length=1)
    action_temporality: str | None = None
    uca_type: str = Field(min_length=1)
    provenance: Literal[TargetRealizationProvenance.target_derived.value] = (
        TargetRealizationProvenance.target_derived.value
    )

    @property
    def control_action_id(self) -> str:
        """Expose the action identity using the control-action vocabulary."""
        return self.control_action


class TargetDerivedICAFinding(ClosedCanonicalModel):
    """One independently verified ICA finding for a target-derived slot.

    The target-extension provider owns only the prose and exact references in
    this value.  The target-realization compiler owns slot membership,
    baseline-reference validation, provenance, and the decision to include a
    finding in the effective candidate universe.
    """

    slot_id: str = Field(min_length=1)
    ica_id: str = Field(min_length=1)
    ica_text: str = Field(min_length=1)
    deviation: str | None = Field(default=None, min_length=1)
    hazardous_context: str = Field(min_length=1)
    loss_scenario: str = Field(min_length=1)
    related_hazards: tuple[str, ...] = ()
    related_constraints: tuple[str, ...] = ()
    quality_warnings: tuple[str, ...] = ()
    verification: TargetRealizationVerification
    provenance: Literal[TargetRealizationProvenance.target_derived.value] = (
        TargetRealizationProvenance.target_derived.value
    )

    @model_validator(mode="after")
    def canonicalize(self) -> "TargetDerivedICAFinding":
        _canonicalize_string_fields(
            self,
            ("related_hazards", "related_constraints", "quality_warnings"),
        )
        _validate_slot_relative_ica_identity(self.slot_id, self.ica_id)
        return self


class SystemicICAEnumerationSnapshot(ClosedCanonicalModel):
    """Explicit JSON-compatible snapshot of typed ICA enumeration authority."""

    slots: tuple[SystemicICASlot, ...]


class SystemicStpaBaseline(ClosedCanonicalModel):
    """Frozen, target-blind STPA facts consumed by target realization.

    The only construction path from live STPA objects is :meth:`from_stpa`,
    which requires the exact typed ``LossAnalysis``, ``ControlStructure`` and
    ``ICAEnumeration`` authorities.  Persisted values are accepted only in
    this model's explicit closed snapshot shape; embedded arbitrary objects
    cannot be used to infer actions or ICA identities.
    """

    baseline_id: str = Field(min_length=1)
    baseline_digest: str | None = None
    loss_analysis: SystemicLossAnalysisSnapshot
    control_structure: SystemicControlStructureSnapshot
    ica_enumeration: SystemicICAEnumerationSnapshot
    control_actions: tuple[SystemicControlAction, ...]
    declared_capabilities: tuple[str, ...] = ()
    prompt_hashes: tuple[str, ...] = ()
    reference_inventory: tuple[str, ...] = ()
    source_pins: tuple[str, ...] = ()

    @classmethod
    def from_stpa(
        cls,
        *,
        loss_analysis: LossAnalysis,
        control_structure: ControlStructure,
        ica_enumeration: ICAEnumeration,
        baseline_id: str = "baseline:systemic",
        prompt_hashes: Sequence[str] = (),
        reference_inventory: Sequence[str] = (),
        source_pins: Sequence[str] = (),
        declared_capabilities: Sequence[str] = (),
    ) -> "SystemicStpaBaseline":
        """Build an attested target-blind snapshot from exact STPA types."""
        _require_stpa_authorities(loss_analysis, control_structure, ica_enumeration)
        return cls(
            baseline_id=baseline_id,
            loss_analysis=_loss_analysis_snapshot(loss_analysis),
            control_structure=_control_structure_snapshot(control_structure),
            ica_enumeration=_ica_snapshot(ica_enumeration),
            control_actions=tuple(
                _control_action_snapshot(responsibility.resp_id, action)
                for responsibility in control_structure.responsibilities
                for action in responsibility.control_actions
            ),
            declared_capabilities=tuple(declared_capabilities),
            prompt_hashes=tuple(prompt_hashes),
            reference_inventory=tuple(reference_inventory),
            source_pins=tuple(source_pins),
        )

    @model_validator(mode="after")
    def canonicalize_and_attest(self) -> "SystemicStpaBaseline":
        _canonicalize_baseline_metadata(self)
        actions = _sorted_baseline_actions(self.control_actions)
        expected_actions = _sorted_structure_actions(self.control_structure)
        _validate_baseline_actions(actions, expected_actions)
        object.__setattr__(self, "control_actions", actions)
        _attest_baseline_digest(self)
        return self

    @property
    def ica_slots(self) -> tuple[str, ...]:
        """Return exact baseline ICA slot identities."""
        return tuple(slot.slot_id for slot in self.ica_enumeration.slots)

    @property
    def ica_ids(self) -> tuple[str, ...]:
        """Return exact baseline ICA identities."""
        return tuple(
            ica.ica_id for slot in self.ica_enumeration.slots for ica in slot.icas
        )

    def baseline_payload(self) -> dict[str, object]:
        """Return baseline content excluding its derived digest."""
        return self.model_dump(mode="json", exclude={"baseline_digest"})

    def compute_baseline_digest(self) -> str:
        """Compute the version-framed identity of the systemic baseline."""
        return compute_framed_digest(
            TARGET_REALIZATION_BASELINE_DIGEST_DOMAIN, self.baseline_payload()
        )

    def assert_integrity(self) -> None:
        """Raise when a frozen baseline has changed after construction."""
        if self.baseline_digest != self.compute_baseline_digest():
            raise ValueError("target-blind baseline digest mismatch")


class CapabilityClaim(ClosedCanonicalModel):
    """Typed capability fact accepted by the matrix helper."""

    capability: str = Field(min_length=1)
    conflicting: bool = False


class CapabilityExposureRow(ClosedCanonicalModel):
    """One declared/observed capability comparison."""

    capability: str = Field(min_length=1)
    declared: bool
    observed: bool
    disposition: CapabilityExposureDisposition
    conflicting: bool = False
    evidence_refs: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_disposition(self) -> "CapabilityExposureRow":
        expected = (
            CapabilityExposureDisposition.capability_conflict
            if self.conflicting
            else _capability_disposition(self.declared, self.observed)
        )
        if (
            self.disposition is not CapabilityExposureDisposition.not_comparable
            and self.disposition is not expected
        ):
            raise ValueError("capability exposure disposition does not reconcile")
        _canonicalize_string_fields(self, ("evidence_refs",))
        return self


class TargetRealizationRow(ClosedCanonicalModel):
    """One immutable realization row for one baseline control action."""

    control_action_id: str = Field(min_length=1)
    controller_id: str = Field(min_length=1)
    disposition: TargetRealizationDisposition
    candidate_operations: tuple[TargetOperationReference, ...] = ()
    selected_operation: TargetOperationReference | None = None
    evidence_refs: tuple[str, ...] = ()
    rationale: str = ""
    verifier: TargetRealizationVerification = TargetRealizationVerification()
    provenance: TargetRealizationProvenance = (
        TargetRealizationProvenance.systemic_baseline
    )

    @model_validator(mode="after")
    def validate_row(self) -> "TargetRealizationRow":
        candidates = _sorted_operation_references(self.candidate_operations)
        object.__setattr__(self, "candidate_operations", candidates)
        _canonicalize_string_fields(self, ("evidence_refs",))
        _validate_row_selection(self.disposition, self.selected_operation, candidates)
        return self


class TargetRealizationProviderResponse(ClosedCanonicalModel):
    """The one exact structured response accepted at the provider boundary."""

    control_action_id: str = Field(min_length=1)
    disposition: TargetRealizationDisposition
    candidate_operations: tuple[TargetOperationReference, ...] = ()
    selected_operation: TargetOperationReference | None = None
    evidence_refs: tuple[str, ...] = ()
    rationale: str = ""
    verifier: TargetRealizationVerification | None = None

    @model_validator(mode="after")
    def validate_response(self) -> "TargetRealizationProviderResponse":
        candidates = _sorted_operation_references(self.candidate_operations)
        object.__setattr__(self, "candidate_operations", candidates)
        _canonicalize_string_fields(self, ("evidence_refs",))
        _validate_response_selection(
            self.disposition, self.selected_operation, candidates
        )
        return self


class TargetDerivedControlActionProposal(ClosedCanonicalModel):
    """Provider choices for one action; observed operation facts stay fixed.

    The provider may choose the existing controller/target relationship used
    to analyse an uncovered operation.  It does not copy the operation's
    description, name, argument schema, effect kind, or temporality: those
    values are immutable observations and the compiler owns their projection
    into the additive action.
    """

    controller_id: str = Field(min_length=1)
    target: SystemicElementReference | None = None
    target_new_controlled_process: bool = False

    @model_validator(mode="after")
    def validate_target_choice(self) -> "TargetDerivedControlActionProposal":
        if self.target is not None and self.target_new_controlled_process:
            raise ValueError(
                "target-derived action cannot choose an existing and new target"
            )
        return self


class TargetDerivedICASlotProposal(ClosedCanonicalModel):
    """Provider UCA meaning for one slot; code assigns action/slot identity."""

    action_temporality: str | None = None
    uca_type: Literal[
        "NOT_PROVIDED",
        "INCORRECT",
        "WRONG_TIMING",
        "WRONG_DURATION",
    ]


class TargetDerivedControlledProcessProposal(ClosedCanonicalModel):
    """Optional provider description for one newly required controlled process."""

    description: str = Field(min_length=1)


class TargetRealizationExtensionOutcome(ClosedCanonicalModel):
    """One provider outcome for an uncovered observed target operation."""

    operation: TargetOperationReference
    disposition: TargetRealizationExtensionDisposition
    control_action: TargetDerivedControlActionProposal | None = None
    ica_slots: tuple[TargetDerivedICASlotProposal, ...] = ()
    controlled_process: TargetDerivedControlledProcessProposal | None = None
    evidence_refs: tuple[str, ...] = Field(min_length=1)
    rationale: str = ""
    # This is populated by the extension adapter's independent
    # action-to-operation verifier.  It is deliberately separate from the
    # provider rationale; an accepted extension without a verified exact
    # operation must remain uncovered in the compiled result.
    verification: TargetRealizationVerification | None = None

    @property
    def operation_ref(self) -> TargetOperationReference:
        """Expose the exact observed operation reference."""
        return self.operation

    @model_validator(mode="after")
    def validate_outcome(self) -> "TargetRealizationExtensionOutcome":
        slots = _sorted_extension_slots(self.ica_slots)
        _validate_extension_slot_meanings(slots)
        object.__setattr__(self, "ica_slots", slots)
        _canonicalize_string_fields(self, ("evidence_refs",))
        _validate_extension_payload(self, slots)
        return self


class TargetRealizationExtensionProviderResponse(ClosedCanonicalModel):
    """The one exact structured response accepted for bounded extension."""

    outcomes: tuple[TargetRealizationExtensionOutcome, ...] = ()
    _provider_diagnostics: tuple[str, ...] = PrivateAttr(default=())

    @model_validator(mode="after")
    def validate_outcomes(self) -> "TargetRealizationExtensionProviderResponse":
        outcomes = tuple(
            sorted(self.outcomes, key=lambda item: item.operation.identity)
        )
        if len({item.operation.identity for item in outcomes}) != len(outcomes):
            raise ValueError("target extension operation identities must be unique")
        object.__setattr__(self, "outcomes", outcomes)
        return self

    @property
    def provider_diagnostics(self) -> tuple[str, ...]:
        """Return response-boundary diagnostics without changing the wire."""
        return self._provider_diagnostics

    def with_provider_diagnostics(
        self,
        diagnostics: Sequence[str],
    ) -> "TargetRealizationExtensionProviderResponse":
        """Return a response carrying non-wire provider diagnostics."""
        response = self.model_copy()
        object.__setattr__(response, "_provider_diagnostics", tuple(diagnostics))
        return response


class TargetRealizationExtensionRequest(ClosedCanonicalModel):
    """Frozen provider input for one bounded additive extension attempt."""

    baseline: SystemicStpaBaseline
    operations: tuple[TargetOperationObservation, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_request(self) -> "TargetRealizationExtensionRequest":
        _require_unique_operation_observations(self.operations)
        return self


class TargetDerivedICAOperationContext(ClosedCanonicalModel):
    """Exact target operation context linked to one derived control action.

    Target-derived ICA prose is only useful when it can name the operation it
    analyses.  Keeping the action identity and the observed operation in one
    closed value prevents a provider from silently borrowing a different tool
    description or argument schema.
    """

    control_action_id: str = Field(min_length=1)
    operation: TargetOperationObservation


class TargetDerivedICARequest(ClosedCanonicalModel):
    """Frozen input for the one target-derived ICA compilation batch.

    The request contains the attested systemic authority plus only accepted
    target-derived actions and slots.  It is intentionally separate from the
    ordinary target-realization request so the provider cannot reinterpret
    baseline ICA findings or turn an uncovered operation into an implicit
    baseline action.
    """

    baseline: SystemicStpaBaseline
    target_derived_control_actions: tuple[SystemicControlAction, ...] = Field(
        min_length=1
    )
    target_derived_ica_slots: tuple[TargetDerivedICASlot, ...] = Field(min_length=1)
    # Populated by the composition seam from supported target-realization
    # records.  The default keeps hand-built historical requests readable;
    # production requests always carry the selected operation context.
    target_operation_context: tuple[TargetDerivedICAOperationContext, ...] = ()

    @model_validator(mode="after")
    def validate_request(self) -> "TargetDerivedICARequest":
        action_ids = _validate_target_derived_actions(
            self.target_derived_control_actions
        )
        _validate_target_derived_slots(self.target_derived_ica_slots, action_ids)
        if self.target_operation_context:
            _validate_target_operation_context(
                self.target_operation_context, action_ids
            )
        return self


class TargetDerivedICAProviderResponse(ClosedCanonicalModel):
    """The one exact response accepted for target-derived ICA findings."""

    findings: tuple[TargetDerivedICAFinding, ...] = ()

    @model_validator(mode="after")
    def canonicalize(self) -> "TargetDerivedICAProviderResponse":
        findings = _sorted_target_derived_findings(self.findings)
        object.__setattr__(self, "findings", findings)
        return self


class TargetOperationRecord(ClosedCanonicalModel):
    """One account row for every observed operation in the target profile."""

    operation: TargetOperationObservation
    disposition: TargetRealizationDisposition
    baseline_control_action_ids: tuple[str, ...] = ()
    target_derived_control_action_id: str | None = Field(default=None, min_length=1)
    evidence_refs: tuple[str, ...] = ()
    provenance: TargetRealizationProvenance = (
        TargetRealizationProvenance.systemic_baseline
    )

    @model_validator(mode="after")
    def canonicalize(self) -> "TargetOperationRecord":
        _canonicalize_string_fields(
            self, ("baseline_control_action_ids", "evidence_refs")
        )
        _validate_operation_record_provenance(self)
        return self

    @property
    def operation_ref(self) -> TargetOperationReference:
        """Return the exact operation identity."""
        return self.operation.reference


class TargetRealizationSummary(ClosedCanonicalModel):
    """Exact non-blended counts for the target-realization artifact."""

    baseline_control_actions: int = Field(ge=0)
    observed_operations: int = Field(ge=0)
    supported: int = Field(ge=0)
    ambiguous: int = Field(ge=0)
    unmapped: int = Field(ge=0)
    contradictory: int = Field(ge=0)
    target_derived: int = Field(ge=0, default=0)
    capability_confirmed_exposure: int = Field(ge=0, default=0)
    capability_declared_not_observed: int = Field(ge=0, default=0)
    capability_undocumented_exposure: int = Field(ge=0, default=0)
    capability_conflict: int = Field(ge=0, default=0)
    capability_not_comparable: int = Field(ge=0, default=0)

    @model_validator(mode="after")
    def reconcile_counts(self) -> "TargetRealizationSummary":
        if self.observed_operations != (
            self.supported
            + self.ambiguous
            + self.unmapped
            + self.contradictory
            + self.target_derived
        ):
            raise ValueError("target realization operation counts do not reconcile")
        return self


class TargetRealizationDenominators(ClosedCanonicalModel):
    """Separate baseline and target-derived candidate-universe counts."""

    baseline_control_actions: int = Field(ge=0)
    target_derived_control_actions: int = Field(ge=0)
    baseline_ica_slots: int = Field(ge=0)
    target_derived_ica_slots: int = Field(ge=0)
    baseline_ica_findings: int = Field(ge=0)
    target_derived_ica_findings: int = Field(ge=0)


class TargetRealizationEffectiveView(SemanticDigestMixin, ClosedCanonicalModel):
    """Additive control-structure/ICA view consumed after realization.

    ``effective_control_structure`` and ``effective_ica_enumeration`` are
    freshly assembled closed snapshots.  They contain every baseline record
    plus accepted target-derived records; the source baseline is never edited.
    Target-derived finding provenance and verification remain explicit beside
    the combined view, and the six denominator fields prevent a blended
    baseline/target score from being mistaken for coverage.
    """

    _digest_domain: ClassVar[str] = TARGET_REALIZATION_EFFECTIVE_DIGEST_DOMAIN
    schema_version: Literal[TARGET_REALIZATION_EFFECTIVE_SCHEMA_VERSION] = (
        TARGET_REALIZATION_EFFECTIVE_SCHEMA_VERSION
    )
    semantic_digest: str | None = None
    baseline_id: str = Field(min_length=1)
    baseline_digest: str = Field(min_length=1)
    profile_id: str = Field(min_length=1)
    profile_digest: str = Field(min_length=1)
    baseline_control_action_ids: tuple[str, ...] = ()
    baseline_controlled_process_ids: tuple[str, ...] = ()
    baseline_ica_slot_ids: tuple[str, ...] = ()
    baseline_ica_ids: tuple[str, ...] = ()
    effective_control_structure: SystemicControlStructureSnapshot
    effective_ica_enumeration: SystemicICAEnumerationSnapshot
    target_derived_control_actions: tuple[SystemicControlAction, ...] = ()
    target_derived_controlled_processes: tuple[SystemicControlledProcess, ...] = ()
    target_derived_ica_slots: tuple[TargetDerivedICASlot, ...] = ()
    target_derived_ica_findings: tuple[TargetDerivedICAFinding, ...] = ()
    denominators: TargetRealizationDenominators
    diagnostics: tuple[str, ...] = ()

    @property
    def control_structure(self) -> SystemicControlStructureSnapshot:
        """Alias used by downstream consumers for the effective snapshot."""
        return self.effective_control_structure

    @property
    def ica_enumeration(self) -> SystemicICAEnumerationSnapshot:
        """Alias used by downstream consumers for the effective snapshot."""
        return self.effective_ica_enumeration

    @model_validator(mode="after")
    def canonicalize_and_attest(self) -> "TargetRealizationEffectiveView":
        baseline_ids = _canonical_effective_baseline_ids(self)
        actions, processes, slots, findings = _canonical_effective_additions(self)
        _validate_effective_additions(actions, processes, slots, findings)
        _validate_effective_unions(
            self, baseline_ids, actions, processes, slots, findings
        )
        expected_denominators = _effective_denominators(
            baseline_ids, actions, processes, slots, findings
        )
        if self.denominators != expected_denominators:
            raise ValueError(
                "effective target-realization denominators do not reconcile"
            )
        object.__setattr__(self, "baseline_control_action_ids", baseline_ids[0])
        object.__setattr__(self, "baseline_controlled_process_ids", baseline_ids[1])
        object.__setattr__(self, "baseline_ica_slot_ids", baseline_ids[2])
        object.__setattr__(self, "baseline_ica_ids", baseline_ids[3])
        object.__setattr__(self, "target_derived_control_actions", actions)
        object.__setattr__(self, "target_derived_controlled_processes", processes)
        object.__setattr__(self, "target_derived_ica_slots", slots)
        object.__setattr__(self, "target_derived_ica_findings", findings)
        object.__setattr__(
            self, "diagnostics", _canonical_diagnostics(self.diagnostics)
        )
        self._attest_semantic_digest(
            "effective target-realization semantic_digest does not match"
        )
        return self

    def assert_integrity(self) -> None:
        """Raise when effective-view content has been modified."""
        if self.semantic_digest != self.compute_semantic_digest():
            raise ValueError("effective target-realization semantic_digest mismatch")


class TargetRealizationResult(SemanticDigestMixin, ClosedCanonicalModel):
    """Closed, content-addressed output of the target-realization lens."""

    _digest_domain: ClassVar[str] = TARGET_REALIZATION_DIGEST_DOMAIN
    schema_version: Literal[TARGET_REALIZATION_SCHEMA_VERSION] = (
        TARGET_REALIZATION_SCHEMA_VERSION
    )
    semantic_digest: str | None = None
    baseline_id: str = Field(min_length=1)
    baseline_digest: str = Field(min_length=1)
    profile_id: str = Field(min_length=1)
    profile_digest: str = Field(min_length=1)
    rows: tuple[TargetRealizationRow, ...] = ()
    operation_records: tuple[TargetOperationRecord, ...] = ()
    capability_reconciliation: tuple[CapabilityExposureRow, ...] = ()
    target_derived_control_actions: tuple[SystemicControlAction, ...] = ()
    target_derived_controlled_processes: tuple[SystemicControlledProcess, ...] = ()
    target_derived_ica_slots: tuple[TargetDerivedICASlot, ...] = ()
    target_derived_ica_findings: tuple[TargetDerivedICAFinding, ...] = ()
    effective_view: TargetRealizationEffectiveView | None = None
    uncovered_operations: tuple[TargetOperationReference, ...] = ()
    diagnostics: tuple[str, ...] = ()
    summary: TargetRealizationSummary

    @model_validator(mode="after")
    def canonicalize_and_digest(self) -> "TargetRealizationResult":
        (
            rows,
            operations,
            derived,
            derived_processes,
            derived_slots,
            findings,
        ) = _canonical_result_collections(self)
        _validate_result_rows(rows)
        _validate_result_operations(operations)
        _validate_result_actions(rows, operations, derived)
        _validate_result_processes(derived_processes)
        _validate_result_slots(derived_slots, derived)
        _validate_result_findings(findings, self.effective_view)
        _validate_result_effective_view(
            self,
            derived,
            derived_processes,
            derived_slots,
            findings,
        )
        object.__setattr__(self, "rows", rows)
        object.__setattr__(self, "operation_records", operations)
        object.__setattr__(self, "target_derived_control_actions", derived)
        object.__setattr__(
            self, "target_derived_controlled_processes", derived_processes
        )
        object.__setattr__(self, "target_derived_ica_slots", derived_slots)
        object.__setattr__(self, "target_derived_ica_findings", findings)
        uncovered = _validate_result_uncovered(self.uncovered_operations, operations)
        object.__setattr__(self, "uncovered_operations", uncovered)
        object.__setattr__(
            self, "diagnostics", _canonical_diagnostics(self.diagnostics)
        )
        _validate_result_summary(
            self.summary, rows, operations, self.capability_reconciliation, derived
        )
        self._attest_semantic_digest(
            "target realization semantic_digest does not match"
        )
        return self

    def assert_integrity(self) -> None:
        """Raise when persisted realization content has been modified."""
        if self.semantic_digest != self.compute_semantic_digest():
            raise ValueError("target realization semantic_digest mismatch")

    def to_yaml(self) -> str:
        """Serialize the closed artifact as deterministic YAML."""
        self.assert_integrity()
        return canonical_yaml(self)

    @classmethod
    def from_yaml(cls, text: str | bytes) -> "TargetRealizationResult":
        """Load and verify one YAML artifact."""
        data = yaml.safe_load(text)
        return cls._load(data)

    @classmethod
    def _load(cls, data: Any) -> "TargetRealizationResult":
        if not isinstance(data, Mapping):
            raise ValueError("target realization must be a mapping")
        if data.get("schema_version") != TARGET_REALIZATION_SCHEMA_VERSION:
            raise ValueError("unsupported target realization schema version")
        if not data.get("semantic_digest"):
            raise ValueError("target realization semantic_digest is required")
        result = cls.model_validate(data)
        result.assert_integrity()
        return result


def _freeze_interface_json(value: Any) -> Any:
    """Recursively close one JSON-compatible observed interface value."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return _interface_scalar(value)
    if isinstance(value, FrozenDict | FrozenList):
        return value
    if isinstance(value, Mapping):
        return _freeze_interface_mapping(value)
    if isinstance(value, (list, tuple)):
        return FrozenList(_freeze_interface_json(item) for item in value)
    raise TypeError("target operation input_schema must contain only JSON values")


def _interface_scalar(value: Any) -> Any:
    """Return one JSON scalar, rejecting NaN."""
    if isinstance(value, float) and value != value:
        raise ValueError("target operation input_schema cannot contain NaN")
    return value


def _freeze_interface_mapping(value: Mapping[Any, Any]) -> FrozenDict:
    """Close one JSON object whose keys must all be strings."""
    if any(not isinstance(key, str) for key in value):
        raise TypeError("target operation input_schema keys must be strings")
    return FrozenDict(
        {key: _freeze_interface_json(item) for key, item in value.items()}
    )


def _validate_slot_relative_ica_identity(slot_id: str, ica_id: str) -> None:
    """Require a positive, slot-relative target-derived ICA identity."""
    _require_slot_relative_prefix(slot_id, ica_id)
    suffix = ica_id[len(slot_id) + 1 :]
    if not _is_positive_slot_index(suffix):
        raise ValueError(
            "target-derived ICA identity must end in a positive slot index"
        )


def _require_slot_relative_prefix(slot_id: str, ica_id: str) -> None:
    if not ica_id.startswith(f"{slot_id}:"):
        raise ValueError(
            f"target-derived ICA identity must be slot-relative: {slot_id}/{ica_id}"
        )


def _is_positive_slot_index(suffix: str) -> bool:
    return suffix.isdigit() and int(suffix) >= 1


def _require_exact_type(value: object, expected: type, name: str) -> None:
    """Reject duck-typed authorities at the live STPA factory boundary."""
    if not isinstance(value, expected):
        raise TypeError(f"{name} must be a typed {expected.__name__}")


def _require_stpa_authorities(
    loss_analysis: object,
    control_structure: object,
    ica_enumeration: object,
) -> None:
    """Validate all three exact typed authorities used by ``from_stpa``."""
    _require_exact_type(loss_analysis, LossAnalysis, "loss_analysis")
    _require_exact_type(control_structure, ControlStructure, "control_structure")
    _require_exact_type(ica_enumeration, ICAEnumeration, "ica_enumeration")


def _canonicalize_baseline_metadata(baseline: SystemicStpaBaseline) -> None:
    _canonicalize_string_fields(
        baseline,
        (
            "declared_capabilities",
            "prompt_hashes",
            "reference_inventory",
            "source_pins",
        ),
    )


def _sorted_baseline_actions(
    actions: Sequence[SystemicControlAction],
) -> tuple[SystemicControlAction, ...]:
    return tuple(
        sorted(actions, key=lambda item: (item.controller_id, item.control_action_id))
    )


def _sorted_structure_actions(
    structure: SystemicControlStructureSnapshot,
) -> tuple[SystemicControlAction, ...]:
    return _sorted_baseline_actions(
        action
        for responsibility in structure.responsibilities
        for action in responsibility.control_actions
    )


def _validate_baseline_actions(
    actions: Sequence[SystemicControlAction],
    expected_actions: Sequence[SystemicControlAction],
) -> None:
    _require_unique_values(
        (item.control_action_id for item in actions),
        "baseline control_actions must have unique identities",
    )
    _require_equal_values(
        tuple(actions),
        tuple(expected_actions),
        "baseline control_actions must match the control-structure snapshot",
    )


def _attest_baseline_digest(baseline: SystemicStpaBaseline) -> None:
    expected = baseline.compute_baseline_digest()
    if baseline.baseline_digest is not None and baseline.baseline_digest != expected:
        raise ValueError("baseline_digest does not match target-blind baseline")
    object.__setattr__(baseline, "baseline_digest", expected)


def _sorted_operation_references(
    references: Sequence[TargetOperationReference],
) -> tuple[TargetOperationReference, ...]:
    sorted_references = tuple(
        sorted(references, key=lambda ref: (ref.resource_id, ref.operation_id))
    )
    _require_unique_values(
        (item.identity for item in sorted_references),
        "operation references must be unique",
    )
    return sorted_references


def _validate_row_selection(
    disposition: TargetRealizationDisposition,
    selected: TargetOperationReference | None,
    candidates: Sequence[TargetOperationReference],
) -> None:
    if disposition is TargetRealizationDisposition.supported:
        _require_selected_operation(selected, candidates, "realization")
        return
    _require_no_selected_operation(
        selected,
        "ambiguous, unmapped, and contradictory rows cannot select an operation",
    )


def _validate_response_selection(
    disposition: TargetRealizationDisposition,
    selected: TargetOperationReference | None,
    candidates: Sequence[TargetOperationReference],
) -> None:
    if disposition is TargetRealizationDisposition.supported:
        _require_selected_operation(selected, candidates, "response")
        return
    _require_no_selected_operation(
        selected,
        "non-supported response cannot select an exact operation",
    )


def _require_selected_operation(
    selected: TargetOperationReference | None,
    candidates: Sequence[TargetOperationReference],
    context: str,
) -> None:
    if selected is None:
        raise ValueError(f"supported {context} requires selected_operation")
    _require_membership(
        selected.identity,
        (item.identity for item in candidates),
        "selected operation must be one of the candidates",
    )


def _require_no_selected_operation(
    selected: TargetOperationReference | None,
    message: str,
) -> None:
    if selected is not None:
        raise ValueError(message)


def _sorted_extension_slots(
    slots: Sequence[TargetDerivedICASlotProposal],
) -> tuple[TargetDerivedICASlotProposal, ...]:
    return tuple(
        sorted(slots, key=lambda item: (item.uca_type, item.action_temporality or ""))
    )


def _validate_extension_slot_meanings(
    slots: Sequence[TargetDerivedICASlotProposal],
) -> None:
    _require_unique_values(
        ((item.uca_type, item.action_temporality) for item in slots),
        "target-extension ICA slot meanings must be unique",
    )


def _validate_extension_payload(
    outcome: TargetRealizationExtensionOutcome,
    slots: Sequence[TargetDerivedICASlotProposal],
) -> None:
    if outcome.disposition is TargetRealizationExtensionDisposition.accepted:
        _validate_accepted_extension(outcome)
        return
    if (
        outcome.control_action is not None
        or slots
        or outcome.controlled_process is not None
    ):
        raise ValueError("rejected target extensions cannot carry actions or ICA slots")


def _validate_accepted_extension(
    outcome: TargetRealizationExtensionOutcome,
) -> None:
    if outcome.control_action is None:
        raise ValueError("accepted target extension requires control_action")
    if not outcome.evidence_refs:
        raise ValueError("accepted target extension requires evidence_refs")
    _validate_extension_process_choice(outcome)


def _validate_extension_process_choice(
    outcome: TargetRealizationExtensionOutcome,
) -> None:
    action = outcome.control_action
    _validate_new_process_choice(action, outcome.controlled_process)
    _validate_existing_process_choice(action, outcome.controlled_process)


def _validate_new_process_choice(
    action: TargetDerivedControlActionProposal | None,
    process: TargetDerivedControlledProcessProposal | None,
) -> None:
    if action is not None and action.target_new_controlled_process and process is None:
        raise ValueError(
            "new target control-process target requires a process proposal"
        )


def _validate_existing_process_choice(
    action: TargetDerivedControlActionProposal | None,
    process: TargetDerivedControlledProcessProposal | None,
) -> None:
    if (
        action is not None
        and not action.target_new_controlled_process
        and process is not None
    ):
        raise ValueError(
            "target control-process proposal requires a new process target"
        )


def _require_unique_operation_observations(
    operations: Sequence[TargetOperationObservation],
) -> None:
    _require_unique_values(
        (item.reference.identity for item in operations),
        "target extension request operations must be unique",
    )


def _validate_target_operation_context(
    contexts: Sequence[TargetDerivedICAOperationContext], action_ids: set[str]
) -> None:
    """Require one exact observed identity per target-derived context row."""
    identities = tuple(item.operation.reference.identity for item in contexts)
    _require_unique_values(
        identities,
        "target-derived ICA operation context identities must be unique",
        expected_len=len(contexts),
    )
    _require_all_members(
        (item.control_action_id for item in contexts),
        action_ids,
        "target-derived ICA operation context action is unknown",
    )


def _validate_target_derived_actions(
    actions: Sequence[SystemicControlAction],
) -> set[str]:
    action_ids = {item.control_action_id for item in actions}
    _require_unique_values(
        action_ids,
        "target-derived ICA request actions must be unique",
        expected_len=len(actions),
    )
    _require_all_provenance(
        actions,
        TargetRealizationProvenance.target_derived,
        "target-derived ICA request actions need target provenance",
    )
    return action_ids


def _validate_target_derived_slots(
    slots: Sequence[TargetDerivedICASlot],
    action_ids: set[str],
) -> None:
    slot_ids = {item.slot_id for item in slots}
    _require_unique_values(
        slot_ids,
        "target-derived ICA request slots must be unique",
        expected_len=len(slots),
    )
    _require_all_members(
        (item.control_action for item in slots),
        action_ids,
        "target-derived ICA request slot action is unknown",
    )


def _sorted_target_derived_findings(
    findings: Sequence[TargetDerivedICAFinding],
) -> tuple[TargetDerivedICAFinding, ...]:
    sorted_findings = tuple(
        sorted(findings, key=lambda item: (item.slot_id, item.ica_id))
    )
    _require_unique_values(
        (item.ica_id for item in sorted_findings),
        "target-derived ICA identities must be unique",
    )
    return sorted_findings


def _validate_operation_record_provenance(record: TargetOperationRecord) -> None:
    if record.provenance is TargetRealizationProvenance.target_derived:
        _validate_target_derived_record(record)
        return
    _validate_systemic_record(record)


def _validate_target_derived_record(record: TargetOperationRecord) -> None:
    if record.target_derived_control_action_id is None:
        raise ValueError(
            "target-derived operation requires its control-action identity"
        )
    if record.baseline_control_action_ids:
        raise ValueError(
            "target-derived operation cannot claim baseline control actions"
        )


def _validate_systemic_record(record: TargetOperationRecord) -> None:
    if record.target_derived_control_action_id is not None:
        raise ValueError(
            "systemic operation record cannot claim a target-derived action"
        )


def _require_unique_values(
    values: Sequence[object] | set[object] | Any,
    message: str,
    *,
    expected_len: int | None = None,
) -> None:
    values_tuple = tuple(values)
    if len(set(values_tuple)) != (
        len(values_tuple) if expected_len is None else expected_len
    ):
        raise ValueError(message)


def _require_equal_values(actual: object, expected: object, message: str) -> None:
    if actual != expected:
        raise ValueError(message)


def _require_membership(
    value: object, candidates: Sequence[object] | Any, message: str
) -> None:
    if value not in candidates:
        raise ValueError(message)


def _require_all_members(
    values: Sequence[object], candidates: set[object], message: str
) -> None:
    if any(value not in candidates for value in values):
        raise ValueError(message)


def _require_all_provenance(
    values: Sequence[object], expected: object, message: str
) -> None:
    if any(getattr(value, "provenance") is not expected for value in values):
        raise ValueError(message)


def _canonical_effective_baseline_ids(
    view: TargetRealizationEffectiveView,
) -> tuple[tuple[str, ...], ...]:
    result = []
    for field_name, message in (
        (
            "baseline_control_action_ids",
            "baseline control-action identities must be unique",
        ),
        (
            "baseline_controlled_process_ids",
            "baseline controlled-process identities must be unique",
        ),
        ("baseline_ica_slot_ids", "baseline ICA-slot identities must be unique"),
        ("baseline_ica_ids", "baseline ICA identities must be unique"),
    ):
        values = tuple(sorted(set(getattr(view, field_name))))
        _require_equal_values(
            len(values),
            len(getattr(view, field_name)),
            message,
        )
        result.append(values)
    return tuple(result)


def _canonical_effective_additions(
    view: TargetRealizationEffectiveView,
) -> tuple[
    tuple[SystemicControlAction, ...],
    tuple[SystemicControlledProcess, ...],
    tuple[TargetDerivedICASlot, ...],
    tuple[TargetDerivedICAFinding, ...],
]:
    return (
        tuple(
            sorted(
                view.target_derived_control_actions,
                key=lambda item: (item.controller_id, item.control_action_id),
            )
        ),
        tuple(
            sorted(
                view.target_derived_controlled_processes, key=lambda item: item.cp_id
            )
        ),
        tuple(sorted(view.target_derived_ica_slots, key=lambda item: item.slot_id)),
        tuple(
            sorted(
                view.target_derived_ica_findings,
                key=lambda item: (item.slot_id, item.ica_id),
            )
        ),
    )


def _validate_effective_additions(
    actions: Sequence[SystemicControlAction],
    processes: Sequence[SystemicControlledProcess],
    slots: Sequence[TargetDerivedICASlot],
    findings: Sequence[TargetDerivedICAFinding],
) -> None:
    action_ids = _unique_id_set(
        actions,
        "control_action_id",
        "effective target-derived control-action identities must be unique",
    )
    _require_all_provenance(
        actions,
        TargetRealizationProvenance.target_derived,
        "effective target-derived actions need target provenance",
    )
    _unique_id_set(
        processes,
        "cp_id",
        "effective target-derived controlled processes must be unique",
    )
    _require_all_provenance(
        processes,
        TargetRealizationProvenance.target_derived,
        "effective target-derived controlled processes need target provenance",
    )
    slot_ids = _unique_id_set(
        slots, "slot_id", "effective target-derived ICA-slot identities must be unique"
    )
    _require_all_members(
        (item.control_action for item in slots),
        action_ids,
        "effective target-derived ICA slot action is unknown",
    )
    _unique_id_set(
        findings, "ica_id", "effective target-derived ICA identities must be unique"
    )
    _require_all_literal_provenance(
        findings, "effective target-derived findings need target provenance"
    )
    _require_all_verified(findings)
    _require_all_members(
        (item.slot_id for item in findings),
        slot_ids,
        "effective target-derived finding slot is unknown",
    )


def _unique_id_set(values: Sequence[object], field_name: str, message: str) -> set[str]:
    identifiers = {str(getattr(item, field_name)) for item in values}
    _require_unique_values(identifiers, message, expected_len=len(values))
    return identifiers


def _require_all_literal_provenance(
    findings: Sequence[TargetDerivedICAFinding], message: str
) -> None:
    if any(
        item.provenance != TargetRealizationProvenance.target_derived.value
        for item in findings
    ):
        raise ValueError(message)


def _require_all_verified(findings: Sequence[TargetDerivedICAFinding]) -> None:
    if any(item.verification.status != "verified" for item in findings):
        raise ValueError("effective target-derived findings must be verified")


def _validate_effective_unions(
    view: TargetRealizationEffectiveView,
    baseline_ids: tuple[tuple[str, ...], ...],
    actions: Sequence[SystemicControlAction],
    processes: Sequence[SystemicControlledProcess],
    slots: Sequence[TargetDerivedICASlot],
    findings: Sequence[TargetDerivedICAFinding],
) -> None:
    expected = _expected_effective_unions(baseline_ids, actions, processes, slots)
    actual = _actual_effective_unions(view)
    _require_equal_values(
        actual[0],
        expected[0],
        "effective control structure does not preserve the action union",
    )
    _require_equal_values(
        actual[1],
        expected[1],
        "effective control structure does not preserve the process union",
    )
    _require_equal_values(
        actual[2],
        expected[2],
        "effective ICA enumeration does not preserve the slot union",
    )
    effective_ica_ids = actual[3]
    _require_subset(
        baseline_ids[3],
        effective_ica_ids,
        "effective ICA enumeration removed a baseline finding",
    )
    _require_subset(
        (item.ica_id for item in findings),
        effective_ica_ids,
        "effective ICA enumeration omitted a target-derived finding",
    )


def _expected_effective_unions(
    baseline_ids: tuple[tuple[str, ...], ...],
    actions: Sequence[SystemicControlAction],
    processes: Sequence[SystemicControlledProcess],
    slots: Sequence[TargetDerivedICASlot],
) -> tuple[set[str], set[str], set[str]]:
    return (
        set(baseline_ids[0]) | {item.control_action_id for item in actions},
        set(baseline_ids[1]) | {item.cp_id for item in processes},
        set(baseline_ids[2]) | {item.slot_id for item in slots},
    )


def _actual_effective_unions(
    view: TargetRealizationEffectiveView,
) -> tuple[set[str], set[str], set[str], set[str]]:
    return (
        _effective_action_ids(view),
        _effective_process_ids(view),
        _effective_slot_ids(view),
        _effective_ica_ids(view),
    )


def _effective_action_ids(view: TargetRealizationEffectiveView) -> set[str]:
    return {
        item.control_action_id
        for responsibility in view.effective_control_structure.responsibilities
        for item in responsibility.control_actions
    }


def _effective_process_ids(view: TargetRealizationEffectiveView) -> set[str]:
    return {
        item.cp_id for item in view.effective_control_structure.controlled_processes
    }


def _effective_slot_ids(view: TargetRealizationEffectiveView) -> set[str]:
    return {item.slot_id for item in view.effective_ica_enumeration.slots}


def _effective_ica_ids(view: TargetRealizationEffectiveView) -> set[str]:
    return {
        item.ica_id
        for slot in view.effective_ica_enumeration.slots
        for item in slot.icas
    }


def _require_subset(
    values: Sequence[str] | set[str], universe: set[str], message: str
) -> None:
    if not set(values).issubset(universe):
        raise ValueError(message)


def _effective_denominators(
    baseline_ids: tuple[tuple[str, ...], ...],
    actions: Sequence[SystemicControlAction],
    processes: Sequence[SystemicControlledProcess],
    slots: Sequence[TargetDerivedICASlot],
    findings: Sequence[TargetDerivedICAFinding],
) -> TargetRealizationDenominators:
    del processes
    return TargetRealizationDenominators(
        baseline_control_actions=len(baseline_ids[0]),
        target_derived_control_actions=len(actions),
        baseline_ica_slots=len(baseline_ids[2]),
        target_derived_ica_slots=len(slots),
        baseline_ica_findings=len(baseline_ids[3]),
        target_derived_ica_findings=len(findings),
    )


def _canonical_diagnostics(values: Sequence[str]) -> tuple[str, ...]:
    return tuple(sorted(set(values)))


def _canonical_result_collections(
    result: TargetRealizationResult,
) -> tuple[
    tuple[TargetRealizationRow, ...],
    tuple[TargetOperationRecord, ...],
    tuple[SystemicControlAction, ...],
    tuple[SystemicControlledProcess, ...],
    tuple[TargetDerivedICASlot, ...],
    tuple[TargetDerivedICAFinding, ...],
]:
    return (
        tuple(
            sorted(
                result.rows, key=lambda row: (row.controller_id, row.control_action_id)
            )
        ),
        tuple(
            sorted(
                result.operation_records, key=lambda item: item.operation_ref.identity
            )
        ),
        tuple(
            sorted(
                result.target_derived_control_actions,
                key=lambda item: (item.controller_id, item.control_action_id),
            )
        ),
        tuple(
            sorted(
                result.target_derived_controlled_processes, key=lambda item: item.cp_id
            )
        ),
        tuple(sorted(result.target_derived_ica_slots, key=lambda item: item.slot_id)),
        tuple(
            sorted(
                result.target_derived_ica_findings,
                key=lambda item: (item.slot_id, item.ica_id),
            )
        ),
    )


def _validate_result_rows(rows: Sequence[TargetRealizationRow]) -> None:
    _require_unique_values(
        (row.control_action_id for row in rows),
        "target realization rows must have unique actions",
    )


def _validate_result_operations(operations: Sequence[TargetOperationRecord]) -> None:
    _require_unique_values(
        (item.operation_ref.identity for item in operations),
        "target operation records must have unique identities",
    )


def _validate_result_actions(
    rows: Sequence[TargetRealizationRow],
    operations: Sequence[TargetOperationRecord],
    derived: Sequence[SystemicControlAction],
) -> None:
    derived_ids = _unique_id_set(
        derived,
        "control_action_id",
        "target-derived control-action identities must be unique",
    )
    baseline_ids = {row.control_action_id for row in rows}
    _require_disjoint_action_ids(baseline_ids, derived_ids)
    _require_all_provenance(
        derived,
        TargetRealizationProvenance.target_derived,
        "target-derived actions must carry target_derived provenance",
    )
    _require_derived_action_records(operations, derived_ids)


def _require_disjoint_action_ids(baseline_ids: set[str], derived_ids: set[str]) -> None:
    if baseline_ids & derived_ids:
        raise ValueError(
            "target-derived control-action identity collides with baseline"
        )


def _require_derived_action_records(
    operations: Sequence[TargetOperationRecord], derived_ids: set[str]
) -> None:
    record_ids = {
        item.target_derived_control_action_id
        for item in operations
        if item.provenance is TargetRealizationProvenance.target_derived
    }
    _require_equal_values(
        record_ids,
        derived_ids,
        "target-derived operation records must bind every derived action",
    )


def _validate_result_processes(
    processes: Sequence[SystemicControlledProcess],
) -> None:
    _unique_id_set(
        processes,
        "cp_id",
        "target-derived controlled-process identities must be unique",
    )
    _require_all_provenance(
        processes,
        TargetRealizationProvenance.target_derived,
        "target-derived controlled processes must carry target_derived provenance",
    )


def _validate_result_slots(
    slots: Sequence[TargetDerivedICASlot],
    derived: Sequence[SystemicControlAction],
) -> None:
    _unique_id_set(
        slots, "slot_id", "target-derived ICA slot identities must be unique"
    )
    _require_all_members(
        (item.control_action for item in slots),
        {item.control_action_id for item in derived},
        "target-derived ICA slots must reference target-derived actions",
    )


def _validate_result_findings(
    findings: Sequence[TargetDerivedICAFinding],
    effective_view: TargetRealizationEffectiveView | None,
) -> None:
    _unique_id_set(findings, "ica_id", "target-derived ICA identities must be unique")
    _require_all_literal_provenance(
        findings, "target-derived ICA findings need target provenance"
    )
    if findings and effective_view is None:
        raise ValueError("target-derived ICA findings require an effective target view")


def _validate_result_effective_view(
    result: TargetRealizationResult,
    derived: Sequence[SystemicControlAction],
    processes: Sequence[SystemicControlledProcess],
    slots: Sequence[TargetDerivedICASlot],
    findings: Sequence[TargetDerivedICAFinding],
) -> None:
    if result.effective_view is None:
        return
    view = result.effective_view
    pairs = (
        (
            view.baseline_id,
            result.baseline_id,
            "effective view baseline_id does not match realization",
        ),
        (
            view.baseline_digest,
            result.baseline_digest,
            "effective view baseline_digest does not match realization",
        ),
        (
            view.profile_id,
            result.profile_id,
            "effective view profile_id does not match realization",
        ),
        (
            view.profile_digest,
            result.profile_digest,
            "effective view profile_digest does not match realization",
        ),
        (
            view.target_derived_control_actions,
            tuple(derived),
            "effective view target actions do not match realization",
        ),
        (
            view.target_derived_controlled_processes,
            tuple(processes),
            "effective view target processes do not match realization",
        ),
        (
            view.target_derived_ica_slots,
            tuple(slots),
            "effective view target slots do not match realization",
        ),
        (
            view.target_derived_ica_findings,
            tuple(findings),
            "effective view target findings do not match realization",
        ),
    )
    for actual, expected, message in pairs:
        _require_equal_values(actual, expected, message)
    view.assert_integrity()


def _validate_result_uncovered(
    uncovered: Sequence[TargetOperationReference],
    operations: Sequence[TargetOperationRecord],
) -> tuple[TargetOperationReference, ...]:
    expected = tuple(
        item.operation_ref
        for item in operations
        if item.disposition is not TargetRealizationDisposition.supported
    )
    canonical = tuple(sorted(uncovered, key=lambda item: item.identity))
    _require_equal_values(
        canonical,
        expected,
        "uncovered_operations must match non-supported operation records",
    )
    return canonical


def _validate_result_summary(
    summary: TargetRealizationSummary,
    rows: Sequence[TargetRealizationRow],
    operations: Sequence[TargetOperationRecord],
    capabilities: Sequence[CapabilityExposureRow],
    derived: Sequence[SystemicControlAction],
) -> None:
    _require_equal_values(
        summary,
        _derive_summary(rows, operations, capabilities, derived),
        "target realization summary does not reconcile",
    )


def _derive_summary(
    rows: Sequence[TargetRealizationRow],
    operations: Sequence[TargetOperationRecord],
    capabilities: Sequence[CapabilityExposureRow],
    derived: Sequence[SystemicControlAction],
) -> TargetRealizationSummary:
    counts, target_derived_operations = _operation_summary_counts(operations)
    capability_counts = _capability_summary_counts(capabilities)
    _require_equal_values(
        target_derived_operations,
        len(derived),
        "target-derived operation records must match target-derived actions",
    )
    return TargetRealizationSummary(
        baseline_control_actions=len(rows),
        observed_operations=len(operations),
        supported=counts[TargetRealizationDisposition.supported.value],
        ambiguous=counts[TargetRealizationDisposition.ambiguous.value],
        unmapped=counts[TargetRealizationDisposition.unmapped.value],
        contradictory=counts[TargetRealizationDisposition.contradictory.value],
        target_derived=target_derived_operations,
        capability_confirmed_exposure=capability_counts[
            CapabilityExposureDisposition.confirmed_exposure.value
        ],
        capability_declared_not_observed=capability_counts[
            CapabilityExposureDisposition.declared_not_observed.value
        ],
        capability_undocumented_exposure=capability_counts[
            CapabilityExposureDisposition.undocumented_exposure.value
        ],
        capability_conflict=capability_counts[
            CapabilityExposureDisposition.capability_conflict.value
        ],
        capability_not_comparable=capability_counts[
            CapabilityExposureDisposition.not_comparable.value
        ],
    )


def _operation_summary_counts(
    operations: Sequence[TargetOperationRecord],
) -> tuple[dict[str, int], int]:
    counts = {item.value: 0 for item in TargetRealizationDisposition}
    target_derived = 0
    for record in operations:
        if record.provenance is TargetRealizationProvenance.target_derived:
            target_derived += 1
        else:
            counts[record.disposition.value] += 1
    return counts, target_derived


def _capability_summary_counts(
    capabilities: Sequence[CapabilityExposureRow],
) -> dict[str, int]:
    counts = {item.value: 0 for item in CapabilityExposureDisposition}
    for record in capabilities:
        counts[record.disposition.value] += 1
    return counts


def _capability_disposition(
    declared: bool, observed: bool
) -> CapabilityExposureDisposition:
    if declared and observed:
        return CapabilityExposureDisposition.confirmed_exposure
    if declared:
        return CapabilityExposureDisposition.declared_not_observed
    return CapabilityExposureDisposition.undocumented_exposure


def verified_pair_evidence_ref(
    action_id: str, resource_id: str, operation_id: str
) -> str:
    """Return the deterministic evidence ref for one exact verified pair."""
    return f"target-realization:verified-pair:{action_id}:{resource_id}/{operation_id}"


def verified_operations(realization: Any | None) -> dict[str, str]:
    """Map actions to the exact operation target realization verified for them.

    A systemic baseline row contributes when its provenance, supported
    disposition, verifier status, and verified-pair evidence agree.  A
    target-derived operation record contributes only when its verified-pair
    evidence matches the record's action/resource/operation identity.
    Unverified, ambiguous, missing, mismatched, or duplicate records
    contribute nothing, and baseline action IDs win over derived ones.  The
    reads are duck-typed so plain test doubles and enum-backed values agree.
    """
    verified = _verified_baseline_operations(realization)
    for action_id, operation_id in _verified_derived_operations(realization).items():
        verified.setdefault(action_id, operation_id)
    return verified


def _verified_baseline_operations(realization: Any | None) -> dict[str, str]:
    if realization is None:
        return {}
    # A duplicate baseline row cannot establish one exact mapping.
    rows = _single_item_by_action(
        tuple(getattr(realization, "rows", ()) or ()), "control_action_id"
    )
    verified = {
        action_id: _verified_baseline_operation(action_id, row)
        for action_id, row in rows.items()
    }
    return {key: value for key, value in verified.items() if value is not None}


def _verified_derived_operations(realization: Any | None) -> dict[str, str]:
    if realization is None:
        return {}
    supported = (
        record
        for record in tuple(getattr(realization, "operation_records", ()) or ())
        if _raw_value(getattr(record, "provenance", None)) == "target_derived"
        and _raw_value(getattr(record, "disposition", None)) == "supported"
    )
    # More than one target operation for one derived action is ambiguous,
    # even when the operation IDs happen to repeat.
    records = _single_item_by_action(supported, "target_derived_control_action_id")
    verified = {
        action_id: _verified_pair_operation(
            action_id,
            getattr(record, "operation", None),
            getattr(record, "evidence_refs", ()),
        )
        for action_id, record in records.items()
    }
    return {key: value for key, value in verified.items() if value is not None}


def _single_item_by_action(items: Any, action_attr: str) -> dict[str, Any]:
    """Group items by a truthy action ID; keep actions with exactly one item."""
    grouped: dict[str, list[Any]] = {}
    for item in items:
        action_id = getattr(item, action_attr, None)
        if action_id:
            grouped.setdefault(action_id, []).append(item)
    return {key: group[0] for key, group in grouped.items() if len(group) == 1}


def _verified_baseline_operation(action_id: str, row: Any) -> str | None:
    verifier = getattr(row, "verifier", None)
    if (
        _raw_value(getattr(row, "provenance", None)) != "systemic_baseline"
        or _raw_value(getattr(row, "disposition", None)) != "supported"
        or _raw_value(getattr(verifier, "status", None)) != "verified"
    ):
        return None
    return _verified_pair_operation(
        action_id,
        getattr(row, "selected_operation", None),
        getattr(verifier, "evidence_refs", ()),
    )


def _verified_pair_operation(
    action_id: str, operation: Any, evidence_refs: Any
) -> str | None:
    resource_id = getattr(operation, "resource_id", None)
    operation_id = getattr(operation, "operation_id", None)
    if not isinstance(resource_id, str) or not isinstance(operation_id, str):
        return None
    expected = verified_pair_evidence_ref(action_id, resource_id, operation_id)
    if expected not in tuple(evidence_refs or ()):
        return None
    return operation_id


def _raw_value(value: Any) -> Any:
    return getattr(value, "value", value)


def _enum_value(value: object) -> str | None:
    if value is None:
        return None
    return str(value.value) if isinstance(value, Enum) else str(value)


def _loss_analysis_snapshot(value: LossAnalysis) -> SystemicLossAnalysisSnapshot:
    return SystemicLossAnalysisSnapshot(
        risk_card_losses=_loss_snapshots(value.risk_card_losses),
        use_case_losses=_loss_snapshots(value.use_case_losses),
        hazards=_hazard_snapshots(value.hazards),
        security_constraints=_constraint_snapshots(value.security_constraints),
    )


def _loss_snapshots(values: Sequence[Any]) -> tuple[SystemicLoss, ...]:
    return tuple(
        SystemicLoss(
            loss_id=item.loss_id,
            description=item.description,
            provenance=_enum_value(item.provenance) or "",
            source_risk_cards=tuple(item.source_risk_cards),
        )
        for item in values
    )


def _hazard_snapshots(values: Sequence[Any]) -> tuple[SystemicHazard, ...]:
    return tuple(
        SystemicHazard(
            hazard_id=item.hazard_id,
            description=item.description,
            related_losses=tuple(item.related_losses),
        )
        for item in values
    )


def _constraint_snapshots(
    values: Sequence[Any],
) -> tuple[SystemicSecurityConstraint, ...]:
    return tuple(
        SystemicSecurityConstraint(
            constraint_id=item.constraint_id,
            description=item.description,
            related_hazards=tuple(item.related_hazards),
        )
        for item in values
    )


def _element_reference(value: object) -> SystemicElementReference | None:
    if value is None:
        return None
    return SystemicElementReference(type=_enum_value(value.type) or "", id=value.id)


def _control_action_snapshot(
    controller_id: str, value: ControlAction
) -> SystemicControlAction:
    return SystemicControlAction(
        control_action_id=value.ca_id,
        controller_id=controller_id,
        description=value.description,
        target=_element_reference(value.target),
        effect_kind=_enum_value(value.effect_kind),
        temporality=_enum_value(value.temporality),
    )


def _control_structure_snapshot(
    value: ControlStructure,
) -> SystemicControlStructureSnapshot:
    return SystemicControlStructureSnapshot(
        responsibilities=_responsibility_snapshots(value.responsibilities),
        controlled_processes=_process_snapshots(value.controlled_processes),
        coordination_links=_coordination_snapshots(value.coordination_links),
    )


def _responsibility_snapshots(
    values: Sequence[Any],
) -> tuple[SystemicResponsibility, ...]:
    return tuple(_responsibility_snapshot(item) for item in values)


def _responsibility_snapshot(value: Any) -> SystemicResponsibility:
    return SystemicResponsibility(
        resp_id=value.resp_id,
        description=value.description,
        responsibility_constraints=_responsibility_constraints(value),
        security_constraint_refs=tuple(value.security_constraint_refs),
        process_model_parts=_process_model_part_snapshots(value.process_model_parts),
        control_actions=tuple(
            _control_action_snapshot(value.resp_id, item)
            for item in value.control_actions
        ),
        feedback_channels=_feedback_channel_snapshots(value.feedback_channels),
    )


def _responsibility_constraints(
    value: Any,
) -> tuple[SystemicResponsibilityConstraint, ...]:
    return tuple(
        SystemicResponsibilityConstraint(rc_id=item.rc_id, description=item.description)
        for item in value.responsibility_constraints
    )


def _process_model_part_snapshots(
    values: Sequence[Any],
) -> tuple[SystemicProcessModelPart, ...]:
    return tuple(
        SystemicProcessModelPart(
            pm_id=item.pm_id,
            description=item.description,
            feedback_source=_element_reference(item.feedback_source),
        )
        for item in values
    )


def _feedback_channel_snapshots(
    values: Sequence[Any],
) -> tuple[SystemicFeedbackChannel, ...]:
    return tuple(
        SystemicFeedbackChannel(
            fb_id=item.fb_id,
            description=item.description,
            updates=item.updates,
            source=_element_reference(item.source),
        )
        for item in values
    )


def _process_snapshots(
    values: Sequence[Any],
) -> tuple[SystemicControlledProcess, ...]:
    return tuple(
        SystemicControlledProcess(cp_id=item.cp_id, description=item.description)
        for item in values
    )


def _coordination_snapshots(
    values: Sequence[Any],
) -> tuple[SystemicCoordinationLink, ...]:
    return tuple(_coordination_snapshot(item) for item in values)


def _coordination_snapshot(value: Any) -> SystemicCoordinationLink:
    return SystemicCoordinationLink(
        link_id=value.link_id,
        source=value.source,
        target=value.target,
        shared_pm=value.shared_pm,
        coordination_mechanism=SystemicCoordinationMechanism(
            cm_id=value.coordination_mechanism.cm_id,
            description=value.coordination_mechanism.description,
            payload=value.coordination_mechanism.payload,
        ),
        description=value.description,
    )


def _ica_snapshot(value: ICAEnumeration) -> SystemicICAEnumerationSnapshot:
    return SystemicICAEnumerationSnapshot(
        slots=tuple(
            SystemicICASlot(
                slot_id=slot.slot_id,
                responsibility=slot.responsibility,
                coordination_link=slot.coordination_link,
                control_action=slot.control_action,
                action_temporality=_enum_value(slot.action_temporality),
                uca_type=_enum_value(slot.uca_type) or "",
                is_na=slot.is_na,
                icas=tuple(
                    SystemicICA(
                        ica_id=ica.ica_id,
                        ica_text=ica.ica_text,
                        deviation=getattr(ica, "deviation", None),
                        hazardous_context=ica.hazardous_context,
                        loss_scenario=ica.loss_scenario,
                        related_hazards=tuple(ica.related_hazards),
                        related_constraints=tuple(ica.related_constraints),
                        quality_warnings=tuple(ica.quality_warnings),
                    )
                    for ica in slot.icas
                ),
                na_justification=slot.na_justification,
                unresolved_reason=slot.unresolved_reason,
            )
            for slot in value.slots
        )
    )


__all__ = [
    "CapabilityClaim",
    "CapabilityExposureDisposition",
    "CapabilityExposureRow",
    "SystemicControlAction",
    "SystemicControlStructureSnapshot",
    "SystemicControlledProcess",
    "SystemicCoordinationLink",
    "SystemicCoordinationMechanism",
    "SystemicElementReference",
    "SystemicFeedbackChannel",
    "SystemicHazard",
    "SystemicICA",
    "SystemicICAEnumerationSnapshot",
    "SystemicICASlot",
    "SystemicLoss",
    "SystemicLossAnalysisSnapshot",
    "SystemicProcessModelPart",
    "SystemicResponsibility",
    "SystemicResponsibilityConstraint",
    "SystemicSecurityConstraint",
    "SystemicStpaBaseline",
    "TargetDerivedICASlot",
    "TARGET_REALIZATION_BASELINE_DIGEST_DOMAIN",
    "TARGET_REALIZATION_DIGEST_DOMAIN",
    "TARGET_REALIZATION_EFFECTIVE_DIGEST_DOMAIN",
    "TARGET_REALIZATION_EFFECTIVE_SCHEMA_VERSION",
    "TARGET_REALIZATION_SCHEMA_VERSION",
    "TargetDerivedICAFinding",
    "TargetDerivedICAOperationContext",
    "TargetDerivedICAProviderResponse",
    "TargetDerivedICARequest",
    "TargetDerivedControlActionProposal",
    "TargetDerivedControlledProcessProposal",
    "TargetDerivedICASlotProposal",
    "TargetOperationObservation",
    "target_operation_action_description",
    "TargetOperationRecord",
    "TargetOperationReference",
    "TargetRealizationDisposition",
    "TargetRealizationExtensionDisposition",
    "TargetRealizationExtensionOutcome",
    "TargetRealizationExtensionProviderResponse",
    "TargetRealizationExtensionRequest",
    "TargetRealizationDenominators",
    "TargetRealizationEffectiveView",
    "TargetRealizationProviderResponse",
    "TargetRealizationProvenance",
    "TargetRealizationResult",
    "TargetRealizationRow",
    "TargetRealizationSummary",
    "TargetRealizationVerification",
]
