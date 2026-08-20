"""Typed temporal execution constraints for STPA projections.

Deterministic, discriminated constraint variants derived only from
declared Stage 5 evidence.  Numeric values use canonical units —
milliseconds for delays and windows, seconds for durations — with only
the variant's relevant fields present.  Constraint references resolve
to structural PM-/FB-/CA- or projected S-* IDs; anything else is
rejected by :func:`is_structural_reference`.

Unknown or undeclared timing produces no constraint (``None``) with
``requires_binding`` on the owning assertion — never a guessed value and
never a runtime observation.  Runtime observations stay in evaluation
output; the projection never imports them.
"""

from __future__ import annotations

import re
from typing import Annotated, Literal, Union

from pydantic import BaseModel, Field, model_validator

from asago_scenario_generator.stpa.models.ica_enumeration import UCAType

_STRUCTURAL_REFERENCE = re.compile(r"^(?:PM|FB|CA)-\d+(?:-\d+)?$|^S-\d+$")

_NUMERIC_UNITS_MS = frozenset({"milliseconds", "ms"})
_NUMERIC_UNITS_S = frozenset({"seconds", "s"})


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


# ---------------------------------------------------------------------------#
# Deterministic parsing of declared timing text
# ---------------------------------------------------------------------------#


def _normalize_ms(value_text: str, unit: str) -> int | None:
    """Normalize a numeric timing value to canonical milliseconds."""
    value = int(value_text)
    if unit in _NUMERIC_UNITS_MS:
        return value
    if unit in _NUMERIC_UNITS_S:
        return value * 1000
    return None


def _normalize_s(value_text: str, unit: str) -> int | None:
    """Normalize a numeric timing value to canonical seconds."""
    value = int(value_text)
    if unit in _NUMERIC_UNITS_S:
        return value
    if unit in _NUMERIC_UNITS_MS and value % 1000 == 0:
        return value // 1000
    return None


def parse_declared_timing(
    declared_timing: str | None,
    source_id: str,
) -> TemporalConstraint | None:
    """Derive the typed temporal constraint from declared timing evidence.

    Matches only canonical declarative phrasing; any unknown or
    malformed timing (including foreign references) yields ``None`` so
    the owning assertion requires binding instead of receiving a guessed
    constraint.

    Args:
        declared_timing: The Stage 5 declared timing text, or ``None``.
        source_id: The causal factor's source ID, used as the reference
            for delay, duration, and window constraints.

    Returns:
        The typed constraint variant, or ``None`` when timing is unknown.
    """
    if not declared_timing:
        return None
    text = declared_timing.strip()
    if not text:
        return None

    ordering = re.fullmatch(r"ordering (before|after) (.+)", text)
    if ordering and is_structural_reference(ordering.group(2)):
        return OrderingConstraint(
            ordering=ordering.group(1), reference=ordering.group(2)
        )

    delay = re.fullmatch(r"delay (\d+) (milliseconds|ms|seconds|s)", text)
    if delay:
        value_ms = _normalize_ms(delay.group(1), delay.group(2))
        if value_ms is not None:
            return DelayConstraint(delay_ms=value_ms, reference=source_id)

    duration = re.fullmatch(r"duration (\d+) (milliseconds|ms|seconds|s)", text)
    if duration:
        value_s = _normalize_s(duration.group(1), duration.group(2))
        if value_s is not None:
            return DurationConstraint(duration_s=value_s, reference=source_id)

    window = re.fullmatch(
        r"window from (\d+) to (\d+) (milliseconds|ms|seconds|s)", text
    )
    if window:
        from_ms = _normalize_ms(window.group(1), window.group(3))
        to_ms = _normalize_ms(window.group(2), window.group(3))
        if from_ms is not None and to_ms is not None:
            return WindowConstraint(
                window_from_ms=from_ms, window_to_ms=to_ms, reference=source_id
            )

    absence = re.fullmatch(r"absence until (.+)", text)
    if absence and is_structural_reference(absence.group(1)):
        return AbsenceConstraint(reference=absence.group(1))

    return None


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
    "parse_declared_timing",
]
