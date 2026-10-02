"""Post-SP3 STPA execution projection boundary schema.

Defines the temporal action vector: controller flaws, feedback timing,
and sensor or actuator anomalies expressed as temporal assertions and
ordered scenario steps for one candidate.

All identifiers are stable control-structure identifiers (PM-X-Y,
FB-X-Y, CA-X-Y); the contract contains no adapter payloads and no
parsed prose.

Causal-factor kinds and their per-kind behavior (namespace, predicate,
step kind, step text) live in the neutral ``causal_factor`` registry;
typed temporal constraints live in ``temporal_constraints``.  Both are
re-exported from this module for backward compatibility.
"""

from __future__ import annotations

from typing import Sequence

from pydantic import BaseModel, Field, model_validator

from asago_scenario_generator.stpa.models.causal_factor import (
    CausalFactor,
    CausalFactorKind,
    ScenarioStepKind,
    TemporalPredicate,
    predicate_for,
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


__all__ = [
    "AbsenceConstraint",
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
    "predicate_for",
]
