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
"""

from __future__ import annotations

from enum import Enum
from typing import Literal, Sequence

from pydantic import BaseModel, Field, model_validator

from asago_scenario_generator.stpa.models.ica_enumeration import UCAType


class CausalFactorKind(str, Enum):
    """Kind of STPA causal factor mapped into an execution envelope."""

    process_model_flaw = "PROCESS_MODEL_FLAW"
    feedback_delay = "FEEDBACK_DELAY"
    sensor_anomaly = "SENSOR_ANOMALY"
    actuator_anomaly = "ACTUATOR_ANOMALY"


class CausalFactor(BaseModel):
    """A structural causal factor explaining an unsafe control action.

    ``source_id`` is a stable control-structure identifier (PM-X-Y for
    process-model flaws, FB-X-Y for feedback delays and sensor
    anomalies, CA-X-Y for actuator anomalies).
    """

    kind: CausalFactorKind
    source_id: str = Field(min_length=1)
    description: str = Field(min_length=1)


class TemporalPredicate(str, Enum):
    """Executable predicate encoded by a temporal assertion."""

    model_flawed = "MODEL_FLAWED"
    feedback_delayed = "FEEDBACK_DELAYED"
    sensor_anomalous = "SENSOR_ANOMALOUS"
    actuator_anomalous = "ACTUATOR_ANOMALOUS"


_PREDICATE_BY_KIND: dict[CausalFactorKind, TemporalPredicate] = {
    CausalFactorKind.process_model_flaw: TemporalPredicate.model_flawed,
    CausalFactorKind.feedback_delay: TemporalPredicate.feedback_delayed,
    CausalFactorKind.sensor_anomaly: TemporalPredicate.sensor_anomalous,
    CausalFactorKind.actuator_anomaly: TemporalPredicate.actuator_anomalous,
}


def predicate_for(kind: CausalFactorKind) -> TemporalPredicate:
    """Return the executable predicate canonically paired with a factor kind."""
    return _PREDICATE_BY_KIND[kind]


class TemporalAssertion(BaseModel):
    """One executable temporal assertion derived from a causal factor."""

    assertion_id: str  # canonical "TA-<n>"
    order_index: int = Field(ge=0)
    kind: CausalFactorKind
    source_id: str = Field(min_length=1)
    predicate: TemporalPredicate

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


class ScenarioStepKind(str, Enum):
    """Kind of a deterministic scenario step in the temporal vector."""

    process_model_flaw = "PROCESS_MODEL_FLAW"
    feedback_delay = "FEEDBACK_DELAY"
    sensor_anomaly = "SENSOR_ANOMALY"
    actuator_anomaly = "ACTUATOR_ANOMALY"
    unsafe_control_action = "UNSAFE_CONTROL_ACTION"


_STEP_KIND_BY_FACTOR_KIND: dict[CausalFactorKind, ScenarioStepKind] = {
    CausalFactorKind.process_model_flaw: ScenarioStepKind.process_model_flaw,
    CausalFactorKind.feedback_delay: ScenarioStepKind.feedback_delay,
    CausalFactorKind.sensor_anomaly: ScenarioStepKind.sensor_anomaly,
    CausalFactorKind.actuator_anomaly: ScenarioStepKind.actuator_anomaly,
}


def step_kind_for(kind: CausalFactorKind) -> ScenarioStepKind:
    """Return the scenario-step kind canonically paired with a factor kind."""
    return _STEP_KIND_BY_FACTOR_KIND[kind]


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
    unsafe control action step for the targeted control action.
    """

    candidate_id: str
    control_action_id: str
    assertions: list[TemporalAssertion] = Field(default_factory=list)
    steps: list[ScenarioStep] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_deterministic_sequences(self) -> TemporalActionVector:
        parts = self.candidate_id.split(":")
        if len(parts) != 4 or parts[0] != "EXEC" or parts[2] != self.control_action_id:
            raise ValueError(
                "TemporalActionVector candidate_id must be the canonical "
                "EXEC:<controller>:<control_action>:<uca_type> identifier "
                f"for control action '{self.control_action_id}'."
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
    """

    candidate_id: str
    controller_id: str
    control_action_id: str
    control_action_description: str = Field(min_length=1)
    uca_type: UCAType
    uca_ref: str
    causal_factors: list[CausalFactor] = Field(default_factory=list)
    temporal_vector: TemporalActionVector | None = None
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
    "CandidateExecutionEnvelope",
    "CausalFactor",
    "CausalFactorKind",
    "ScenarioStep",
    "ScenarioStepKind",
    "TemporalActionVector",
    "TemporalAssertion",
    "TemporalPredicate",
    "candidate_id_for",
    "predicate_for",
    "step_kind_for",
    "uca_ref_for",
]
