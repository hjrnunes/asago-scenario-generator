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

    @model_validator(mode="after")
    def validate_source_namespace(self) -> CausalFactor:
        expected_prefix = {
            CausalFactorKind.process_model_flaw: "PM-",
            CausalFactorKind.feedback_delay: "FB-",
            CausalFactorKind.sensor_anomaly: "FB-",
            CausalFactorKind.actuator_anomaly: "CA-",
        }[self.kind]
        if not self.source_id.startswith(expected_prefix):
            raise ValueError(
                f"CausalFactor {self.kind.value} source_id "
                f"'{self.source_id}' must use the {expected_prefix[:-1]} namespace; "
                f"it is not a known {expected_prefix[:-1]} identifier."
            )
        return self


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


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-20T10:33:14Z","module_hash":"f6325c495575c75a4b27250459a952ce0d04058170895856ac7327d4155fd72b","functions":[{"id":"func/CausalFactor.validate_source_namespace","name":"validate_source_namespace","line":47,"end_line":60,"hash":"783b5839832fdb6a208b0f65b237de8b01d567823be0f63687afb73e88e71b72"},{"id":"func/predicate_for","name":"predicate_for","line":80,"end_line":82,"hash":"fec70a4f2b011858b357f48027d014bf1fda3b6a79c5a708a9cf5dcd149de345"},{"id":"func/TemporalAssertion.validate_predicate_consistency","name":"validate_predicate_consistency","line":95,"end_line":103,"hash":"8b33c3f26027dab43072b2fcb0cbb96551ec72db21a6fefd1eba04ed2c32bf65"},{"id":"func/step_kind_for","name":"step_kind_for","line":124,"end_line":126,"hash":"4d201c78392b502ab2f624e5831c5894808ab1fb23059ed23ebd6553be34915d"},{"id":"func/_validate_sequence","name":"_validate_sequence","line":139,"end_line":165,"hash":"774a92e224a06eb5ea8a393404d4565c95c40a6e28219a3c021eca6c2f310b98"},{"id":"func/_validate_uca_step_is_last","name":"_validate_uca_step_is_last","line":168,"end_line":186,"hash":"0f6abc85faeaf8eead3964465977cab636ff81b3c039ff4c014a92a62143a531"},{"id":"func/TemporalActionVector.validate_deterministic_sequences","name":"validate_deterministic_sequences","line":203,"end_line":229,"hash":"81f5192adcd8ff29e88d34cd7c665bbc0f4ba232c53e0f3376ebcd243739b2c1"},{"id":"func/candidate_id_for","name":"candidate_id_for","line":232,"end_line":238,"hash":"12635952b58522185d9844a217358e5533cd2ecc320def88c8d90fa8355706fe"},{"id":"func/uca_ref_for","name":"uca_ref_for","line":241,"end_line":247,"hash":"baaaad7e4ffc18436b09afe2d6475872adf188f0690ac05f8d5a1e2f6a80e405"},{"id":"func/CandidateExecutionEnvelope.validate_canonical_references","name":"validate_canonical_references","line":269,"end_line":296,"hash":"9c80a1b145db2dcba35b19c0f62034dd2fe3767236e93e6719bdacdcd9977bca"}]}
# mutate4py-manifest-end
