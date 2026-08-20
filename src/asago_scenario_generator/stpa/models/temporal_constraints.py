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
from collections.abc import Callable
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


def _parse_ordering(text: str, source_id: str) -> TemporalConstraint | None:
    """Parse declared "ordering before|after <ref>" timing."""
    match = re.fullmatch(r"ordering (before|after) (.+)", text)
    if match and is_structural_reference(match.group(2)):
        return OrderingConstraint(ordering=match.group(1), reference=match.group(2))
    return None


def _parse_delay(text: str, source_id: str) -> TemporalConstraint | None:
    """Parse declared "delay <n> <unit>" timing into canonical milliseconds."""
    match = re.fullmatch(r"delay (\d+) (milliseconds|ms|seconds|s)", text)
    if not match:
        return None
    value_ms = _normalize_ms(match.group(1), match.group(2))
    if value_ms is None:
        return None
    return DelayConstraint(delay_ms=value_ms, reference=source_id)


def _parse_duration(text: str, source_id: str) -> TemporalConstraint | None:
    """Parse declared "duration <n> <unit>" timing into canonical seconds."""
    match = re.fullmatch(r"duration (\d+) (milliseconds|ms|seconds|s)", text)
    if not match:
        return None
    value_s = _normalize_s(match.group(1), match.group(2))
    if value_s is None:
        return None
    return DurationConstraint(duration_s=value_s, reference=source_id)


def _parse_window(text: str, source_id: str) -> TemporalConstraint | None:
    """Parse declared "window from <a> to <b> <unit>" timing into ms bounds."""
    match = re.fullmatch(
        r"window from (\d+) to (\d+) (milliseconds|ms|seconds|s)", text
    )
    if not match:
        return None
    from_ms = _normalize_ms(match.group(1), match.group(3))
    to_ms = _normalize_ms(match.group(2), match.group(3))
    if from_ms is None or to_ms is None:
        return None
    return WindowConstraint(
        window_from_ms=from_ms, window_to_ms=to_ms, reference=source_id
    )


def _parse_absence(text: str, source_id: str) -> TemporalConstraint | None:
    """Parse declared "absence until <ref>" timing."""
    match = re.fullmatch(r"absence until (.+)", text)
    if match and is_structural_reference(match.group(1)):
        return AbsenceConstraint(reference=match.group(1))
    return None


# Variant parsers in canonical precedence order; each returns ``None`` for
# any text it does not fully own, so the loop derives at most one constraint.
_TIMING_PARSERS: tuple[Callable[[str, str], TemporalConstraint | None], ...] = (
    _parse_ordering,
    _parse_delay,
    _parse_duration,
    _parse_window,
    _parse_absence,
)


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
    text = (declared_timing or "").strip()
    if not text:
        return None
    for parser in _TIMING_PARSERS:
        constraint = parser(text, source_id)
        if constraint is not None:
            return constraint
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
