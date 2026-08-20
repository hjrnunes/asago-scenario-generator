"""Post-SP3 STPA execution projection boundary schema.

Maps STPA structural findings (causal factors, control actions, and
UCAs) into canonical platform-neutral candidate execution envelopes.
Controller flaws, feedback timing, and sensor or actuator anomalies are
retained as deterministic temporal assertions and executable scenario
steps in a temporal action vector.

All identifiers are stable control-structure identifiers (PM-X-Y,
FB-X-Y, CA-X-Y); the contract contains no adapter payloads and no
parsed prose.  Empty causal factors produce an empty temporal vector
without invented behavior.

Causal-factor kinds and their per-kind behavior (namespace, predicate,
step kind, step text) live in the neutral ``causal_factor`` registry;
typed temporal constraints live in ``temporal_constraints``.  Both are
re-exported from this module for backward compatibility.
"""

from __future__ import annotations

from typing import Literal
from typing import Sequence

from pydantic import BaseModel, Field, model_validator

from asago_scenario_generator.stpa.models.causal_factor import (
    CausalFactor,
    CausalFactorKind,
    ScenarioStepKind,
    TemporalPredicate,
    predicate_for,
    step_kind_for,
)
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.models.temporal_constraints import (
    AbsenceConstraint,
    DelayConstraint,
    DurationConstraint,
    OrderingConstraint,
    TemporalConstraint,
    UcaOutcomeConstraint,
    WindowConstraint,
    is_structural_reference,
    parse_declared_timing,
)


class TemporalAssertion(BaseModel):
    """One executable temporal assertion derived from a causal factor.

    ``constraint`` is the typed temporal constraint derived only from
    declared Stage 5 evidence; unknown timing leaves it ``None`` and sets
    ``requires_binding`` so no guessed timing enters the projection.
    """

    assertion_id: str  # canonical "TA-<n>"
    order_index: int = Field(ge=0)
    kind: CausalFactorKind
    source_id: str = Field(min_length=1)
    predicate: TemporalPredicate
    constraint: TemporalConstraint | None = None
    requires_binding: bool = True

    @model_validator(mode="after")
    def validate_predicate_consistency(self) -> TemporalAssertion:
        expected = predicate_for(self.kind)
        if self.predicate != expected:
            raise ValueError(
                f"TemporalAssertion {self.assertion_id} predicate "
                f"'{self.predicate.value}' is inconsistent with kind "
                f"'{self.kind.value}' (expected '{expected.value}')."
            )
        return self

    @model_validator(mode="after")
    def sync_requires_binding(self) -> TemporalAssertion:
        self.requires_binding = self.constraint is None
        return self


class ScenarioStep(BaseModel):
    """One deterministic ordered scenario step in the temporal vector."""

    step_id: str  # canonical "S-<n>"
    order_index: int = Field(ge=0)
    kind: ScenarioStepKind
    source_id: str = Field(min_length=1)
    text: str = Field(min_length=1)


def _validate_sequence(
    items: Sequence[BaseModel],
    id_field: str,
    label: str,
    id_prefix: str,
) -> None:
    """Validate that one sequence is canonical: unique ids and dense order."""
    seen: set[str] = set()
    for index, item in enumerate(items):
        identifier = getattr(item, id_field)
        if identifier in seen:
            raise ValueError(
                f"TemporalActionVector contains duplicate {label} id '{identifier}'."
            )
        seen.add(identifier)
        if item.order_index != index:
            raise ValueError(
                f"TemporalActionVector {label} '{identifier}' order_index "
                f"{item.order_index} is not its deterministic position "
                f"{index}."
            )
        expected_identifier = f"{id_prefix}-{index + 1}"
        if identifier != expected_identifier:
            raise ValueError(
                f"TemporalActionVector {label} id '{identifier}' is not "
                f"the canonical identifier '{expected_identifier}'."
            )


def _validate_uca_step_is_last(
    steps: Sequence[ScenarioStep],
    control_action_id: str,
) -> None:
    """Validate that a non-empty step list ends with the UCA step."""
    if not steps:
        return
    last = steps[-1]
    if last.kind != ScenarioStepKind.unsafe_control_action:
        raise ValueError(
            "TemporalActionVector scenario steps must end with the "
            "unsafe control action step."
        )
    if last.source_id != control_action_id:
        raise ValueError(
            f"TemporalActionVector unsafe control action step references "
            f"'{last.source_id}' but the vector targets "
            f"'{control_action_id}'."
        )


class TemporalActionVector(BaseModel):
    """Deterministic temporal projection of causal factors for one candidate.

    Empty causal factors produce an empty vector: no assertions and no
    steps are invented.  With causal factors, the vector ends with the
    unsafe control action step for the targeted control action and maps
    that final outcome explicitly through ``uca_constraint``.
    """

    candidate_id: str
    control_action_id: str
    assertions: list[TemporalAssertion] = Field(default_factory=list)
    steps: list[ScenarioStep] = Field(default_factory=list)
    uca_constraint: UcaOutcomeConstraint | None = None

    @model_validator(mode="after")
    def validate_deterministic_sequences(self) -> TemporalActionVector:
        parts = self.candidate_id.split(":")
        if len(parts) != 4 or parts[0] != "EXEC" or not parts[1]:
            raise ValueError(
                "TemporalActionVector candidate_id must be the canonical "
                "EXEC:<controller>:<control_action>:<uca_type> identifier "
                f"for control action '{self.control_action_id}'."
            )
        try:
            candidate_uca_type = UCAType(parts[3])
        except ValueError as exc:
            raise ValueError(
                f"TemporalActionVector candidate_id has unknown UCA type '{parts[3]}'."
            ) from exc
        expected_candidate_id = candidate_id_for(
            parts[1], self.control_action_id, candidate_uca_type
        )
        if self.candidate_id != expected_candidate_id:
            raise ValueError(
                "TemporalActionVector candidate_id is not canonical for "
                "its controller, control action, and UCA type."
            )
        _validate_sequence(self.assertions, "assertion_id", "assertion", "TA")
        _validate_sequence(self.steps, "step_id", "scenario step", "S")
        _validate_uca_step_is_last(self.steps, self.control_action_id)
        return self


def candidate_id_for(
    controller_id: str,
    control_action_id: str,
    uca_type: UCAType,
) -> str:
    """Return the canonical candidate identifier for an unsafe control action."""
    return f"EXEC:{controller_id}:{control_action_id}:{uca_type.value}"


def uca_ref_for(
    controller_id: str,
    control_action_id: str,
    uca_type: UCAType,
) -> str:
    """Return the canonical UCA reference linked by a candidate envelope."""
    return f"{controller_id}:{control_action_id}:{uca_type.value}"


class CandidateExecutionEnvelope(BaseModel):
    """Platform-neutral candidate execution envelope for one UCA.

    The envelope carries only canonical structural identifiers and
    deterministic projections; ``platform_neutral`` is structurally
    pinned so adapters can trust the payload contains no vendor shape.

    The structural candidate identity (``candidate_id``) is preserved;
    the ICA ID and scenario ID are carried as separate optional fields
    so standalone exports identify them independently.
    """

    candidate_id: str
    controller_id: str
    control_action_id: str
    control_action_description: str = Field(min_length=1)
    uca_type: UCAType
    uca_ref: str
    causal_factors: list[CausalFactor] = Field(default_factory=list)
    temporal_vector: TemporalActionVector | None = None
    ica_id: str | None = None
    scenario_id: str | None = None
    platform_neutral: Literal[True] = True

    @model_validator(mode="after")
    def validate_canonical_references(self) -> CandidateExecutionEnvelope:
        expected_candidate_id = candidate_id_for(
            self.controller_id, self.control_action_id, self.uca_type
        )
        if self.candidate_id != expected_candidate_id:
            raise ValueError(
                f"CandidateExecutionEnvelope candidate_id '{self.candidate_id}' "
                f"does not match the canonical candidate identifier "
                f"'{expected_candidate_id}'."
            )
        expected_uca_ref = uca_ref_for(
            self.controller_id, self.control_action_id, self.uca_type
        )
        if self.uca_ref != expected_uca_ref:
            raise ValueError(
                f"CandidateExecutionEnvelope uca_ref '{self.uca_ref}' does not "
                f"match the canonical UCA reference '{expected_uca_ref}'."
            )
        if (
            self.temporal_vector is not None
            and self.temporal_vector.candidate_id != self.candidate_id
        ):
            raise ValueError(
                f"CandidateExecutionEnvelope temporal vector is linked to "
                f"candidate '{self.temporal_vector.candidate_id}' but the "
                f"envelope candidate is '{self.candidate_id}'."
            )
        return self


__all__ = [
    "AbsenceConstraint",
    "CandidateExecutionEnvelope",
    "CausalFactor",
    "CausalFactorKind",
    "DelayConstraint",
    "DurationConstraint",
    "OrderingConstraint",
    "ScenarioStep",
    "ScenarioStepKind",
    "TemporalActionVector",
    "TemporalAssertion",
    "TemporalConstraint",
    "TemporalPredicate",
    "UcaOutcomeConstraint",
    "WindowConstraint",
    "candidate_id_for",
    "is_structural_reference",
    "parse_declared_timing",
    "predicate_for",
    "step_kind_for",
    "uca_ref_for",
]


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-20T10:33:14Z","module_hash":"f6325c495575c75a4b27250459a952ce0d04058170895856ac7327d4155fd72b","functions":[{"id":"func/TemporalAssertion.validate_predicate_consistency","name":"validate_predicate_consistency","line":95,"end_line":103,"hash":"8b33c3f26027dab43072b2fcb0cbb96551ec72db21a6fefd1eba04ed2c32bf65"},{"id":"func/_validate_sequence","name":"_validate_sequence","line":139,"end_line":165,"hash":"774a92e224a06eb5ea8a393404d4565c95c40a6e28219a3c021eca6c2f310b98"},{"id":"func/_validate_uca_step_is_last","name":"_validate_uca_step_is_last","line":168,"end_line":186,"hash":"0f6abc85faeaf8eead3964465977cab636ff81b3c039ff4c014a92a62143a531"},{"id":"func/TemporalActionVector.validate_deterministic_sequences","name":"validate_deterministic_sequences","line":203,"end_line":229,"hash":"81f5192adcd8ff29e88d34cd7c665bbc0f4ba232c53e0f3376ebcd243739b2c1"},{"id":"func/CandidateExecutionEnvelope.validate_canonical_references","name":"validate_canonical_references","line":269,"end_line":296,"hash":"9c80a1b145db2dcba35b19c0f62034dd2fe3767236e93e6719bdacdcd9977bca"}]}
# mutate4py-manifest-end
