"""Typed temporal execution constraints for STPA projections.

Discriminated constraint variants.  Numeric values use canonical units —
milliseconds for delays and windows, seconds for durations — with only
the variant's relevant fields present.  Constraint references resolve
to structural PM-/FB-/CA- or projected S-* IDs; anything else is
rejected by :func:`is_structural_reference`.

An assertion without a constraint (``None``) sets ``requires_binding``
instead of carrying a guessed value or a runtime observation.
"""

from __future__ import annotations

import re
from typing import Annotated, Literal, Union

from pydantic import BaseModel, Field, model_validator

from asago_scenario_generator.stpa.models.ica_enumeration import UCAType

_STRUCTURAL_REFERENCE = re.compile(r"^(?:PM|FB|CA)-\d+(?:-\d+)?$|^S-\d+$")


def is_structural_reference(reference: str) -> bool:
    """True when a reference resolves to a PM-, FB-, CA-, or S-* ID."""
    return bool(_STRUCTURAL_REFERENCE.fullmatch(reference))


class TemporalConstraintBase(BaseModel):
    """Shared shape of every typed temporal constraint.

    ``reference`` resolves to a PM-, FB-, CA-, or S-* structural ID;
    construction fails closed for any other namespace so forged
    constraints are rejected at model boundary.
    """

    reference: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_reference_namespace(self) -> TemporalConstraintBase:
        if not is_structural_reference(self.reference):
            raise ValueError(
                f"temporal constraint reference '{self.reference}' does not "
                "resolve to a PM-, FB-, CA-, or S-* structural ID"
            )
        return self


class OrderingConstraint(TemporalConstraintBase):
    """Declared order of the source relative to a projected step."""

    type: Literal["ordering"] = "ordering"
    ordering: Literal["before", "after"]


class DelayConstraint(TemporalConstraintBase):
    """Declared feedback delay, normalized to canonical milliseconds."""

    type: Literal["delay"] = "delay"
    delay_ms: int = Field(ge=0)


class DurationConstraint(TemporalConstraintBase):
    """Declared control-action duration, normalized to canonical seconds."""

    type: Literal["duration"] = "duration"
    duration_s: int = Field(ge=0)


class WindowConstraint(TemporalConstraintBase):
    """Declared timing window, normalized to canonical milliseconds."""

    type: Literal["window"] = "window"
    window_from_ms: int = Field(ge=0)
    window_to_ms: int = Field(ge=0)


class AbsenceConstraint(TemporalConstraintBase):
    """Declared absence of the source until a projected step."""

    type: Literal["absence"] = "absence"


TemporalConstraint = Annotated[
    Union[
        OrderingConstraint,
        DelayConstraint,
        DurationConstraint,
        WindowConstraint,
        AbsenceConstraint,
    ],
    Field(discriminator="type"),
]


class UcaOutcomeConstraint(BaseModel):
    """Explicit mapping of the final unsafe-control-action outcome.

    The vector-level ``uca_constraint`` mirrors the final UCA step and
    is derived only when the projection has causal factors; runtime
    observations are never projection input and live only in evaluation
    output.
    """

    type: Literal["uca_outcome"] = "uca_outcome"
    control_action_id: str = Field(min_length=1)
    uca_type: UCAType


__all__ = [
    "AbsenceConstraint",
    "DelayConstraint",
    "DurationConstraint",
    "OrderingConstraint",
    "TemporalConstraint",
    "TemporalConstraintBase",
    "UcaOutcomeConstraint",
    "WindowConstraint",
    "is_structural_reference",
]
