"""Closed producer-side contracts for STPA execution projection v2.

The models in this module describe semantic execution intent only.  They do
not contain provider prompts, runtime tools, endpoints, observers, clocks or
observations.  The neutral semantic-condition leaf is shared with the Stage 5
provider response model so the inward and published contracts cannot drift.

The historical v1 models remain available for read/validation compatibility;
this module is the immutable, content-addressed v2 wire contract.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from enum import Enum
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    model_validator,
)

from asago_scenario_generator.models.canonical import (
    canonical_json_bytes,
    compute_framed_digest,
)
from asago_scenario_generator.stpa.models.causal_factor import (
    CausalEvidenceStatus,
    CausalFactorKind,
    namespace_for,
)
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.models.execution_classification import (
    BindingCompleteness,
    ExecutionActionKind,
    ExecutionClassification,
    ExecutionContractDisposition,
    ExecutionDeliveryClass,
    SemanticExecutionContract,
    SemanticExecutionDelivery,
)
from asago_scenario_generator.stpa.models.semantic_conditions import (
    AbsenceCondition,
    ActionPresenceCondition,
    ActionValueCondition,
    DelayCondition,
    DurationCondition,
    OrderingCondition,
    SemanticBindingPlaceholder,
    SemanticBindingValueType,
    SemanticCondition,
    SemanticValue,
    StateValueCondition,
    StimulusTurn,
    WindowCondition,
    collect_binding_refs,
    contains_binding_placeholder,
    normalize_semantic_proposition,
)


PROJECTION_SCHEMA_VERSION = "stpa-execution-projection-v2"
BUNDLE_SCHEMA_VERSION = "stpa-execution-bundle-v1"
PRODUCER_NAME = "asago-scenario-generator"
PRODUCER_VERSION = "0.1.0"
PROJECTION_DIGEST_FRAME = PROJECTION_SCHEMA_VERSION
BUNDLE_DIGEST_FRAME = BUNDLE_SCHEMA_VERSION
SHA256_PATTERN = r"^[0-9a-f]{64}$"

_STRUCTURAL_REFERENCE = re.compile(r"^(?:PM|FB|CA|CM)-\d+(?:-\d+)?$|^S-\d+$")
_FACTOR_REFERENCE = re.compile(r"^(?:PM|FB|CA)-\d+(?:-\d+)?$")
_ICA_REFERENCE_SUFFIX = re.compile(r"^.+:[^:]+$")


class _ClosedFrozenModel(BaseModel):
    """Base for immutable closed wire records."""

    # Enum discriminators are canonical JSON strings.  Scalar fields below
    # use Strict* annotations so wire values are never coerced.
    model_config = ConfigDict(extra="forbid", frozen=True)


class ExecutionCausalFactor(_ClosedFrozenModel):
    """One immutable, evidence-backed causal factor in a v2 projection."""

    factor_id: StrictStr = Field(pattern=r"^CF-\d+$")
    order: StrictInt = Field(ge=1)
    kind: CausalFactorKind
    structural_source_id: StrictStr = Field(min_length=1)
    description: StrictStr = Field(min_length=1)
    evidence_status: CausalEvidenceStatus = CausalEvidenceStatus.structural_failure
    capability_refs: tuple[StrictStr, ...] = ()
    access_refs: tuple[StrictStr, ...] = ()
    bounded_assumption: StrictStr | None = None
    temporal_condition: SemanticCondition | None = None

    @model_validator(mode="after")
    def validate_factor(self) -> "ExecutionCausalFactor":
        _validate_factor_namespace(self.kind, self.structural_source_id)
        _validate_factor_evidence(
            self.evidence_status,
            self.capability_refs,
            self.access_refs,
            self.bounded_assumption,
        )
        return self


class ExecutionStepKind(str, Enum):
    """The only two step roles admitted by the projection wire contract."""

    causal_factor = "CAUSAL_FACTOR"
    unsafe_control_action = "UNSAFE_CONTROL_ACTION"


class ExecutionStep(_ClosedFrozenModel):
    """One canonical ordered execution-intent step."""

    step_id: StrictStr = Field(pattern=r"^S-\d+$")
    order: StrictInt = Field(ge=1)
    kind: ExecutionStepKind
    factor_id: StrictStr | None = Field(default=None, pattern=r"^CF-\d+$")
    structural_source_id: StrictStr = Field(min_length=1)

    @model_validator(mode="after")
    def validate_step_shape(self) -> "ExecutionStep":
        if self.kind is ExecutionStepKind.causal_factor:
            _validate_causal_factor_step(self.factor_id, self.structural_source_id)
        else:
            _validate_unsafe_action_step(self.factor_id, self.structural_source_id)
        return self


def _validate_causal_factor_step(
    factor_id: str | None,
    structural_source_id: str,
) -> None:
    if factor_id is None:
        raise ValueError("causal-factor step requires factor_id")
    if not _FACTOR_REFERENCE.fullmatch(structural_source_id):
        raise ValueError("causal-factor step has an invalid structural source")


def _validate_unsafe_action_step(
    factor_id: str | None,
    structural_source_id: str,
) -> None:
    if factor_id is not None:
        raise ValueError("unsafe-control-action step must not have factor_id")
    _validate_action_reference(structural_source_id)


class UnsafeOutcome(_ClosedFrozenModel):
    """The semantic condition that makes the selected action unsafe."""

    outcome_id: StrictStr = Field(pattern=r"^OUTCOME-[A-Za-z0-9._-]+$")
    control_action_id: StrictStr = Field(min_length=1)
    uca_type: UCAType
    condition: SemanticCondition
    semantic_proposition: StrictStr | None
    semantic_binding_required: StrictBool
    hazard_refs: tuple[StrictStr, ...] = ()
    constraint_refs: tuple[StrictStr, ...] = ()

    @model_validator(mode="after")
    def validate_outcome(self) -> "UnsafeOutcome":
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
        return self


class ExecutionRequirements(_ClosedFrozenModel):
    """Neutral capabilities required to realize or observe a projection."""

    requires_multi_turn: StrictBool
    requires_tool_execution: StrictBool
    requires_persistent_state: StrictBool
    requires_multi_agent: StrictBool
    requires_real_clock: StrictBool
    requires_state_observation: StrictBool
    required_surface_categories: tuple[
        Literal[
            "external_input",
            "system_instruction",
            "tool_result",
            "tool_definition",
            "persistent_data",
            "agent_message",
            "environment_event",
        ],
        ...,
    ]

    @model_validator(mode="after")
    def validate_categories(self) -> "ExecutionRequirements":
        if len(self.required_surface_categories) != len(
            set(self.required_surface_categories)
        ):
            raise ValueError("required_surface_categories must be unique")
        return self


class AdversarialStimulusRequirement(_ClosedFrozenModel):
    """Platform-neutral content that must drive one causal path.

    The producer owns the adversarial intent, selected causal factor and exact
    delivery route.  A consumer may bind that route to platform surfaces, but
    cannot choose another factor or delivery class.
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

    @model_validator(mode="after")
    def validate_delivery(self) -> "AdversarialStimulusRequirement":
        if self.delivery_class is ExecutionDeliveryClass.indirect_content:
            if self.carrier_requirement_id is None:
                raise ValueError(
                    "indirect_content stimuli require carrier_requirement_id"
                )
        elif self.carrier_requirement_id is not None:
            raise ValueError(
                "only indirect_content stimuli may name a carrier requirement"
            )
        self._validate_turns()
        return self

    def _validate_turns(self) -> None:
        if self.turns is None:
            return
        if self.delivery_class is not ExecutionDeliveryClass.conversation_context:
            raise ValueError("only conversation_context stimuli may carry turns")
        if not 2 <= len(self.turns) <= 3:
            raise ValueError("stimulus turns require two to three entries")
        turn_ids = [turn.turn_id for turn in self.turns]
        if len(turn_ids) != len(set(turn_ids)):
            raise ValueError("stimulus turns must carry unique turn_id values")


class ExecutionSourcePins(_ClosedFrozenModel):
    """Digest pins for the structural authority used to build a projection."""

    control_structure: StrictStr = Field(pattern=SHA256_PATTERN)
    loss_analysis: StrictStr = Field(pattern=SHA256_PATTERN)
    ica_enumeration: StrictStr = Field(pattern=SHA256_PATTERN)
    scenario_context: StrictStr = Field(pattern=SHA256_PATTERN)
    execution_target_profile: StrictStr | None = Field(
        default=None, pattern=SHA256_PATTERN, exclude_if=lambda value: value is None
    )
    target_realization: StrictStr | None = Field(
        default=None, pattern=SHA256_PATTERN, exclude_if=lambda value: value is None
    )

    @model_validator(mode="after")
    def validate_target_lineage_pair(self) -> "ExecutionSourcePins":
        if (self.execution_target_profile is None) is not (
            self.target_realization is None
        ):
            raise ValueError(
                "execution_target_profile and target_realization pins must be paired"
            )
        return self


class ExecutionTraceRefs(_ClosedFrozenModel):
    """Typed provenance references that cannot alter execution semantics."""

    obligation_ids: tuple[StrictStr, ...] = ()
    risk_ids: tuple[StrictStr, ...] = ()
    attack_pattern_ids: tuple[StrictStr, ...] = ()
    technique_ids: tuple[StrictStr, ...] = ()
    loss_ids: tuple[StrictStr, ...] = ()
    hazard_ids: tuple[StrictStr, ...] = ()
    constraint_ids: tuple[StrictStr, ...] = ()
    source_pins: ExecutionSourcePins

    @model_validator(mode="after")
    def canonicalize_sets(self) -> "ExecutionTraceRefs":
        for field_name in (
            "obligation_ids",
            "risk_ids",
            "attack_pattern_ids",
            "technique_ids",
            "loss_ids",
            "hazard_ids",
            "constraint_ids",
        ):
            values = getattr(self, field_name)
            if len(values) != len(set(values)):
                raise ValueError(f"{field_name} must contain unique IDs")
            object.__setattr__(self, field_name, tuple(sorted(values)))
        return self


class ExecutionProjectionV2(_ClosedFrozenModel):
    """Complete immutable ``stpa-execution-projection-v2`` document."""

    schema_version: Literal[PROJECTION_SCHEMA_VERSION] = PROJECTION_SCHEMA_VERSION
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
    unsafe_outcome: UnsafeOutcome
    stimulus_requirements: tuple[AdversarialStimulusRequirement, ...] = ()
    execution_requirements: ExecutionRequirements
    execution_contract: SemanticExecutionContract
    execution_classification: ExecutionClassification
    trace_refs: ExecutionTraceRefs
    # In-process construction may omit this so the model can derive it.  The
    # persisted standalone parser rejects omission before model validation.
    semantic_digest: StrictStr | None = Field(default=None, pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_projection(self) -> "ExecutionProjectionV2":
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
        return compute_framed_digest(PROJECTION_DIGEST_FRAME, self.semantic_payload())

    def canonical_json_bytes(self) -> bytes:
        """Return canonical JSON bytes including the recorded digest."""
        return canonical_json_bytes(self.model_dump(mode="json"))

    def canonical_json_text(self) -> str:
        """Return compact canonical JSON text with no trailing whitespace."""
        return self.canonical_json_bytes().decode("utf-8")


class ExecutionRunIdentity(_ClosedFrozenModel):
    """Run identity and producer metadata supplied to the producer seam."""

    run_id: StrictStr = Field(min_length=1)
    producer_name: StrictStr = PRODUCER_NAME
    producer_version: StrictStr = PRODUCER_VERSION


class ProducerIdentity(_ClosedFrozenModel):
    """Bundle producer metadata."""

    name: StrictStr = Field(min_length=1)
    version: StrictStr = Field(min_length=1)


class BundleScenarioReference(_ClosedFrozenModel):
    """Exact persisted canonical scenario JSON reference."""

    path: StrictStr = Field(min_length=1)
    content_sha256: StrictStr = Field(pattern=SHA256_PATTERN)


class BundleProjectionReference(_ClosedFrozenModel):
    """Exact persisted canonical projection JSON reference."""

    path: StrictStr = Field(min_length=1)
    schema_version: Literal[PROJECTION_SCHEMA_VERSION] = PROJECTION_SCHEMA_VERSION
    content_sha256: StrictStr = Field(pattern=SHA256_PATTERN)
    semantic_digest: StrictStr = Field(pattern=SHA256_PATTERN)


class BundleValidationReference(_ClosedFrozenModel):
    """Validation attestation recorded in a bundle index entry."""

    status: Literal["valid"] = "valid"
    validator_version: Literal[PROJECTION_SCHEMA_VERSION] = PROJECTION_SCHEMA_VERSION


class ExecutionBundleEntry(_ClosedFrozenModel):
    """One scenario/projection pair in the run-level index."""

    scenario_id: StrictStr = Field(min_length=1)
    candidate_id: StrictStr = Field(min_length=1)
    ica_slot_id: StrictStr = Field(min_length=1)
    ica_id: StrictStr = Field(min_length=1)
    scenario: BundleScenarioReference
    projection: BundleProjectionReference
    validation: BundleValidationReference = BundleValidationReference()

    @model_validator(mode="after")
    def validate_pair_identity(self) -> "ExecutionBundleEntry":
        if not self.ica_id.startswith(self.ica_slot_id + ":"):
            raise ValueError("bundle entry ICA does not belong to its slot")
        return self


class ExecutionBundleIndex(_ClosedFrozenModel):
    """Closed content-addressed ``stpa-execution-bundle-v1`` index."""

    schema_version: Literal[BUNDLE_SCHEMA_VERSION] = BUNDLE_SCHEMA_VERSION
    run_id: StrictStr = Field(min_length=1)
    producer: ProducerIdentity
    entries: tuple[ExecutionBundleEntry, ...] = ()
    bundle_digest: StrictStr | None = Field(default=None, pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_entries_and_digest(self) -> "ExecutionBundleIndex":
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
        return compute_framed_digest(BUNDLE_DIGEST_FRAME, self.semantic_payload())

    def canonical_json_bytes(self) -> bytes:
        """Return canonical index JSON bytes including ``bundle_digest``."""
        return canonical_json_bytes(self.model_dump(mode="json"))


class ProjectionValidationCode(str, Enum):
    """Stable standalone projection and bundle violation codes."""

    schema_version_mismatch = "schema_version_mismatch"
    required_field_missing = "required_field_missing"
    unexpected_field = "unexpected_field"
    container_type_mismatch = "container_type_mismatch"
    identity_mismatch = "identity_mismatch"
    source_pin_mismatch = "source_pin_mismatch"
    factor_reference_mismatch = "factor_reference_mismatch"
    factor_order_mismatch = "factor_order_mismatch"
    condition_type_mismatch = "condition_type_mismatch"
    condition_field_mismatch = "condition_field_mismatch"
    condition_reference_mismatch = "condition_reference_mismatch"
    condition_value_invalid = "condition_value_invalid"
    stimulus_field_mismatch = "stimulus_field_mismatch"
    semantic_binding_state_mismatch = "semantic_binding_state_mismatch"
    step_mapping_mismatch = "step_mapping_mismatch"
    uca_condition_incompatible = "uca_condition_incompatible"
    runtime_observation_forbidden = "runtime_observation_forbidden"
    execution_classification_mismatch = "execution_classification_mismatch"
    semantic_digest_mismatch = "semantic_digest_mismatch"
    bundle_path_invalid = "bundle_path_invalid"
    content_digest_mismatch = "content_digest_mismatch"
    pair_identity_mismatch = "pair_identity_mismatch"


class ProjectionValidationViolation(_ClosedFrozenModel):
    """One deterministic standalone validation diagnostic."""

    code: ProjectionValidationCode
    path: StrictStr = Field(min_length=1)
    detail: StrictStr = Field(min_length=1)


class ExecutionProjectionValidationResult(_ClosedFrozenModel):
    """Result of parsing and completely validating a v2 projection."""

    valid: StrictBool
    projection: ExecutionProjectionV2 | None = None
    violations: tuple[ProjectionValidationViolation, ...] = ()

    @model_validator(mode="after")
    def synchronize_validity(self) -> "ExecutionProjectionValidationResult":
        expected = self.projection is not None and not self.violations
        if self.valid is not expected:
            object.__setattr__(self, "valid", expected)
        return self


class BundleValidationResult(_ClosedFrozenModel):
    """Result of verifying one persisted execution bundle."""

    valid: StrictBool
    index: ExecutionBundleIndex | None = None
    violations: tuple[ProjectionValidationViolation, ...] = ()

    @model_validator(mode="after")
    def synchronize_validity(self) -> "BundleValidationResult":
        expected = self.index is not None and not self.violations
        if self.valid is not expected:
            object.__setattr__(self, "valid", expected)
        return self


def _validate_factor_namespace(kind: CausalFactorKind, source_id: str) -> None:
    expected_prefix = f"{namespace_for(kind)}-"
    if not source_id.startswith(expected_prefix):
        raise ValueError(
            f"structural_source_id '{source_id}' does not use "
            f"the {namespace_for(kind)} namespace"
        )
    if not _FACTOR_REFERENCE.fullmatch(source_id):
        raise ValueError("structural_source_id is not a canonical structural reference")


def _validate_factor_evidence(
    status: CausalEvidenceStatus,
    capability_refs: Sequence[str],
    access_refs: Sequence[str],
    bounded_assumption: str | None,
) -> None:
    if status is CausalEvidenceStatus.reachable_capability:
        _require_reachable_evidence(capability_refs, access_refs)
    else:
        _reject_unexpected_capability_evidence(capability_refs, access_refs)
    if status is CausalEvidenceStatus.bounded_assumption:
        _require_bounded_assumption(bounded_assumption)
    else:
        _reject_unexpected_assumption(bounded_assumption)


def _require_reachable_evidence(
    capability_refs: Sequence[str], access_refs: Sequence[str]
) -> None:
    if not capability_refs or not access_refs:
        raise ValueError(
            "reachable_capability factor requires capability_refs and access_refs"
        )


def _reject_unexpected_capability_evidence(
    capability_refs: Sequence[str], access_refs: Sequence[str]
) -> None:
    if capability_refs or access_refs:
        raise ValueError(
            "capability_refs and access_refs require reachable_capability evidence"
        )


def _require_bounded_assumption(value: str | None) -> None:
    if not value or not value.strip():
        raise ValueError("bounded_assumption factor requires bounded_assumption text")


def _reject_unexpected_assumption(value: str | None) -> None:
    if value is not None:
        raise ValueError("bounded_assumption text requires bounded_assumption evidence")


def _validate_projection_identity(projection: ExecutionProjectionV2) -> None:
    expected_candidate = (
        f"EXEC:{projection.controller_id}:{projection.control_action_id}:"
        f"{projection.uca_type.value}"
    )
    if projection.candidate_id != expected_candidate:
        raise ValueError("candidate_id does not match controller/action/UCA identity")
    expected_slot = (
        f"{projection.controller_id}:{projection.control_action_id}:"
        f"{projection.uca_type.value}"
    )
    if projection.ica_slot_id != expected_slot:
        raise ValueError("ica_slot_id does not match controller/action/UCA identity")
    if not _ica_belongs_to_slot(projection.ica_id, projection.ica_slot_id):
        raise ValueError("ica_id does not belong to ica_slot_id")


def _ica_belongs_to_slot(ica_id: str, slot_id: str) -> bool:
    return bool(_ICA_REFERENCE_SUFFIX.fullmatch(ica_id)) and ica_id.startswith(
        slot_id + ":"
    )


def _validate_projection_outcome(projection: ExecutionProjectionV2) -> None:
    outcome = projection.unsafe_outcome
    if outcome.control_action_id != projection.control_action_id:
        raise ValueError("unsafe_outcome control_action_id does not match projection")
    if outcome.uca_type is not projection.uca_type:
        raise ValueError("unsafe_outcome uca_type does not match projection")


def _validate_projection_lineage(projection: ExecutionProjectionV2) -> None:
    """Close outcome meaning and source lineage before publication."""
    outcome = projection.unsafe_outcome
    contract = projection.execution_contract
    if contract.action_kind is ExecutionActionKind.model_output:
        normalize_semantic_proposition(outcome.semantic_proposition, required=True)
        if projection.uca_type is UCAType.incorrect:
            condition = outcome.condition
            if not (
                isinstance(condition, ActionValueCondition)
                and condition.property == "semantic_proposition"
                and condition.operator == "equals"
                and type(condition.expected) is bool
                and condition.expected is True
            ):
                raise ValueError(
                    "model_output INCORRECT outcomes require the fixed "
                    "semantic-proposition action_value condition"
                )
    elif outcome.semantic_proposition is not None:
        normalize_semantic_proposition(outcome.semantic_proposition, required=True)

    if contract.disposition is not ExecutionContractDisposition.executable_route:
        return
    trace = projection.trace_refs
    if not outcome.hazard_refs:
        raise ValueError("executable unsafe outcome requires at least one hazard_ref")
    if not outcome.constraint_refs:
        raise ValueError(
            "executable unsafe outcome requires at least one constraint_ref"
        )
    if not trace.loss_ids:
        raise ValueError("executable projection requires at least one loss trace ref")
    if tuple(outcome.hazard_refs) != tuple(trace.hazard_ids):
        raise ValueError(
            "unsafe outcome hazard_refs must exactly match trace_refs.hazard_ids"
        )
    if tuple(outcome.constraint_refs) != tuple(trace.constraint_ids):
        raise ValueError(
            "unsafe outcome constraint_refs must exactly match trace_refs.constraint_ids"
        )


def _validate_unique_outcome_refs(values: Sequence[str], field_name: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{field_name} must contain unique IDs")


def _validate_projection_conditions(projection: ExecutionProjectionV2) -> None:
    exported_refs = _exported_projection_refs(projection)
    outcome_condition = projection.unsafe_outcome.condition
    if (
        isinstance(outcome_condition, OrderingCondition)
        and outcome_condition.reference_step_id == projection.steps[-1].step_id
    ):
        raise ValueError(
            "unsafe outcome ordering cannot compare the action with itself"
        )
    _validate_condition_references(
        outcome_condition,
        projection.steps,
        exported_refs,
    )
    for factor in projection.causal_factors:
        _validate_optional_condition(
            factor.temporal_condition, projection.steps, exported_refs
        )


def _exported_projection_refs(projection: ExecutionProjectionV2) -> set[str]:
    return {factor.structural_source_id for factor in projection.causal_factors} | {
        projection.control_action_id
    }


def _validate_optional_condition(
    condition: SemanticCondition | None,
    steps: Sequence[ExecutionStep],
    exported_refs: set[str],
) -> None:
    if condition is not None:
        _validate_condition_references(condition, steps, exported_refs)


def _validate_projection_bindings(projection: ExecutionProjectionV2) -> None:
    refs = [
        ref
        for factor in projection.causal_factors
        for ref in collect_binding_refs(factor.temporal_condition)
    ]
    refs.extend(collect_binding_refs(projection.unsafe_outcome.condition))
    if len(refs) != len(set(refs)):
        raise ValueError(
            "semantic binding references must be unique within a projection"
        )


def _validate_stimulus_requirements(projection: ExecutionProjectionV2) -> None:
    if (
        projection.execution_contract.disposition
        is ExecutionContractDisposition.analytical_only
    ):
        _validate_analytical_stimulus_requirements(projection)
        return
    _validate_executable_stimulus_requirements(projection)


def _validate_analytical_stimulus_requirements(
    projection: ExecutionProjectionV2,
) -> None:
    """Ensure analytical findings carry no executable stimulus route."""
    if projection.stimulus_requirements:
        raise ValueError(
            "analytical_only projections cannot publish an execution stimulus route"
        )


def _validate_executable_stimulus_requirements(
    projection: ExecutionProjectionV2,
) -> None:
    """Ensure one executable stimulus matches its selected delivery exactly."""
    if len(projection.stimulus_requirements) != 1:
        raise ValueError("executable projections require exactly one stimulus route")
    factor_ids = {factor.factor_id for factor in projection.causal_factors}
    for item in projection.stimulus_requirements:
        _validate_stimulus_factor(item, factor_ids)
        _validate_stimulus_delivery(item, projection.execution_contract.delivery)


def _validate_stimulus_factor(
    item: AdversarialStimulusRequirement,
    factor_ids: set[str],
) -> None:
    """Require a stimulus route to name one projected causal factor."""
    if item.factor_id not in factor_ids:
        raise ValueError(
            "stimulus requirement factor_id must resolve to a causal factor"
        )


def _validate_stimulus_delivery(
    item: AdversarialStimulusRequirement,
    delivery: SemanticExecutionDelivery | None,
) -> None:
    """Require stimulus fields to equal the contract's selected delivery."""
    if delivery is None:
        raise ValueError("stimulus route requires an execution delivery")
    if _stimulus_delivery_matches(item, delivery):
        return
    raise ValueError("stimulus route must match the execution contract delivery")


def _stimulus_delivery_matches(
    item: AdversarialStimulusRequirement,
    delivery: SemanticExecutionDelivery,
) -> bool:
    """Compare every identity field in a published delivery route."""
    return (
        item.delivery_class is delivery.delivery_class
        and item.factor_id == delivery.factor_id
        and item.source_role == delivery.source_role
        and item.carrier_requirement_id == delivery.carrier_requirement_id
    )


def _validate_execution_classification(projection: ExecutionProjectionV2) -> None:
    """Keep the semantic contract and derived classification consistent."""
    contract = projection.execution_contract
    classification = projection.execution_classification
    _validate_classification_delivery_factor(projection)
    _require_classification_digest(classification)
    if contract.disposition is ExecutionContractDisposition.analytical_only:
        _validate_analytical_classification(classification)
    elif not contract.resource_requirements:
        _validate_target_agnostic_classification(classification)


def _validate_classification_delivery_factor(
    projection: ExecutionProjectionV2,
) -> None:
    """Require a selected delivery factor to be present in the projection."""
    delivery = projection.execution_contract.delivery
    if delivery is None:
        return
    factor_ids = {factor.factor_id for factor in projection.causal_factors}
    if delivery.factor_id not in factor_ids:
        raise ValueError("execution delivery factor_id must resolve to a causal factor")


def _require_classification_digest(classification: ExecutionClassification) -> None:
    """Require the classification to carry its derived content digest."""
    if classification.classification_digest is None:
        raise ValueError("execution classification requires classification_digest")


def _validate_analytical_classification(
    classification: ExecutionClassification,
) -> None:
    """Require an analytical contract to make no execution claim."""
    expected = (
        BindingCompleteness.analytical_only,
        "none",
        "invalid",
        "no_execution_claim",
    )
    actual = (
        classification.binding_completeness,
        classification.environment_basis.value,
        classification.profile_fit.value,
        classification.claim_scope.value,
    )
    if actual != expected:
        raise ValueError(
            "analytical_only execution contracts require the analytical classification tuple"
        )
    _reject_classification_bindings(
        classification,
        "analytical_only",
        allow_profile_lineage=True,
    )


def _validate_target_agnostic_classification(
    classification: ExecutionClassification,
) -> None:
    """Require a resource-free route to remain target agnostic."""
    expected = (
        BindingCompleteness.concrete,
        "target_agnostic",
        "not_required",
        "model_behavior_only",
    )
    actual = (
        classification.binding_completeness,
        classification.environment_basis.value,
        classification.profile_fit.value,
        classification.claim_scope.value,
    )
    if actual != expected:
        raise ValueError(
            "resource-free executable contracts require the target-agnostic classification tuple"
        )
    _reject_classification_bindings(
        classification,
        "resource-free",
        allow_profile_lineage=True,
    )


def _reject_classification_bindings(
    classification: ExecutionClassification,
    label: str,
    *,
    allow_profile_lineage: bool = False,
) -> None:
    """Reject runtime bindings, while optionally retaining source lineage."""
    if (
        classification.resolved_bindings
        or classification.unresolved_requirement_ids
        or classification.ambiguous_matches
        or classification.unsupported_requirement_ids
        or (
            classification.target_profile_digest is not None
            and not allow_profile_lineage
        )
    ):
        raise ValueError(
            f"{label} classifications cannot contain bindings or profile pins"
        )


def _set_projection_digest(projection: ExecutionProjectionV2) -> None:
    expected_digest = projection.compute_semantic_digest()
    if (
        projection.semantic_digest is not None
        and projection.semantic_digest != expected_digest
    ):
        raise ValueError("semantic_digest does not match projection content")
    object.__setattr__(projection, "semantic_digest", expected_digest)


def _validate_action_reference(reference: str) -> None:
    if not re.fullmatch(r"^(?:CA|CM)-\d+(?:-\d+)?$", reference):
        raise ValueError("control_action_id must be a canonical CA-* or CM-* ID")


def _condition_is_compatible(uca_type: UCAType, condition: SemanticCondition) -> bool:
    accepted = {
        UCAType.not_provided: {"action_presence"},
        UCAType.incorrect: {"action_value", "state_value"},
        UCAType.wrong_timing: {"ordering", "delay", "window", "absence"},
        UCAType.wrong_duration: {"duration"},
    }
    return condition.type in accepted[uca_type]


def _validate_factor_sequence(factors: Sequence[ExecutionCausalFactor]) -> None:
    if not factors:
        raise ValueError("v2 execution projection requires at least one causal factor")
    _validate_factor_ids(factors)
    _validate_factor_orders(factors)


def _validate_factor_ids(factors: Sequence[ExecutionCausalFactor]) -> None:
    expected_ids = tuple(f"CF-{index}" for index in range(1, len(factors) + 1))
    if tuple(item.factor_id for item in factors) != expected_ids:
        raise ValueError("causal factor IDs must be deterministic positional CF-* IDs")


def _validate_factor_orders(factors: Sequence[ExecutionCausalFactor]) -> None:
    expected_orders = tuple(range(1, len(factors) + 1))
    if tuple(item.order for item in factors) != expected_orders:
        raise ValueError("causal factor order must be contiguous and one-based")


def _validate_step_sequence(
    steps: Sequence[ExecutionStep],
    factors: Sequence[ExecutionCausalFactor],
    control_action_id: str,
) -> None:
    _validate_step_count(steps, factors)
    _validate_step_ids_and_orders(steps)
    _validate_factor_step_mapping(steps, factors)
    _validate_final_step(steps[-1], control_action_id)


def _validate_step_count(
    steps: Sequence[ExecutionStep], factors: Sequence[ExecutionCausalFactor]
) -> None:
    if len(steps) != len(factors) + 1:
        raise ValueError("steps must contain one factor step and one final UCA step")


def _validate_step_ids_and_orders(steps: Sequence[ExecutionStep]) -> None:
    expected_steps = tuple(f"S-{index}" for index in range(1, len(steps) + 1))
    if tuple(item.step_id for item in steps) != expected_steps:
        raise ValueError("step IDs must be deterministic positional S-* IDs")
    if tuple(item.order for item in steps) != tuple(range(1, len(steps) + 1)):
        raise ValueError("step order must be contiguous and one-based")


def _validate_factor_step_mapping(
    steps: Sequence[ExecutionStep], factors: Sequence[ExecutionCausalFactor]
) -> None:
    for factor, step in zip(factors, steps[:-1], strict=True):
        if _factor_step_mismatch(step, factor):
            raise ValueError("causal factor and execution step mapping is not exact")


def _factor_step_mismatch(step: ExecutionStep, factor: ExecutionCausalFactor) -> bool:
    return (
        step.kind is not ExecutionStepKind.causal_factor
        or step.factor_id != factor.factor_id
        or step.structural_source_id != factor.structural_source_id
    )


def _validate_final_step(step: ExecutionStep, control_action_id: str) -> None:
    if (
        step.kind is not ExecutionStepKind.unsafe_control_action
        or step.factor_id is not None
        or step.structural_source_id != control_action_id
    ):
        raise ValueError("final and only final step must be the unsafe control action")


def _validate_condition_references(
    condition: SemanticCondition,
    steps: Sequence[ExecutionStep],
    exported_refs: set[str],
) -> None:
    """Resolve condition references to this projection's exported universe."""
    reference_validators = (
        (OrderingCondition, _validate_ordering_reference),
        (AbsenceCondition, _validate_absence_reference),
        (DelayCondition, _validate_structural_condition_reference),
        (DurationCondition, _validate_structural_condition_reference),
        (WindowCondition, _validate_structural_condition_reference),
        (ActionPresenceCondition, _validate_action_condition_reference),
        (ActionValueCondition, _validate_action_condition_reference),
        (StateValueCondition, _validate_state_condition_reference),
    )
    for condition_type, validator in reference_validators:
        if isinstance(condition, condition_type):
            validator(condition, steps, exported_refs)
            return


def _validate_ordering_reference(
    condition: OrderingCondition,
    steps: Sequence[ExecutionStep],
    exported_refs: set[str],
) -> None:
    del exported_refs
    if condition.reference_step_id not in {step.step_id for step in steps}:
        raise ValueError("ordering condition references an unknown step")


def _validate_absence_reference(
    condition: AbsenceCondition,
    steps: Sequence[ExecutionStep],
    exported_refs: set[str],
) -> None:
    if condition.until_step_id not in {step.step_id for step in steps}:
        raise ValueError("absence condition references an unknown step")
    _require_exported_ref(condition.reference_ref, exported_refs)


def _validate_structural_condition_reference(
    condition: DelayCondition | DurationCondition | WindowCondition,
    steps: Sequence[ExecutionStep],
    exported_refs: set[str],
) -> None:
    del steps
    _require_exported_ref(condition.reference_ref, exported_refs)


def _validate_action_condition_reference(
    condition: ActionPresenceCondition | ActionValueCondition,
    steps: Sequence[ExecutionStep],
    exported_refs: set[str],
) -> None:
    del steps
    _require_exported_ref(condition.control_action_id, exported_refs)


def _validate_state_condition_reference(
    condition: StateValueCondition,
    steps: Sequence[ExecutionStep],
    exported_refs: set[str],
) -> None:
    del steps
    _require_exported_ref(condition.subject_ref, exported_refs)


def _require_exported_ref(reference: str, exported_refs: set[str]) -> None:
    if not _STRUCTURAL_REFERENCE.fullmatch(reference) or reference not in exported_refs:
        raise ValueError(
            f"condition reference '{reference}' is not an exported structural ID"
        )


__all__ = [
    "AbsenceCondition",
    "ActionPresenceCondition",
    "ActionValueCondition",
    "BUNDLE_DIGEST_FRAME",
    "BUNDLE_SCHEMA_VERSION",
    "BundleProjectionReference",
    "BundleScenarioReference",
    "BundleValidationReference",
    "BundleValidationResult",
    "DelayCondition",
    "DurationCondition",
    "ExecutionBundleEntry",
    "ExecutionBundleIndex",
    "ExecutionCausalFactor",
    "ExecutionProjectionV2",
    "ExecutionProjectionValidationResult",
    "ExecutionRequirements",
    "ExecutionRunIdentity",
    "ExecutionSourcePins",
    "ExecutionStep",
    "ExecutionStepKind",
    "ExecutionTraceRefs",
    "OrderingCondition",
    "PROJECTION_DIGEST_FRAME",
    "PROJECTION_SCHEMA_VERSION",
    "ProducerIdentity",
    "ProjectionValidationCode",
    "ProjectionValidationViolation",
    "SemanticBindingPlaceholder",
    "SemanticBindingValueType",
    "SemanticCondition",
    "SemanticValue",
    "StateValueCondition",
    "StimulusTurn",
    "UnsafeOutcome",
    "WindowCondition",
    "canonical_json_bytes",
    "collect_binding_refs",
    "contains_binding_placeholder",
]
