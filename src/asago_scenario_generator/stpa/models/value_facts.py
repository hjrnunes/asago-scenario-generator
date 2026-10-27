"""Declared value facts: the record kind and the format of a target's values.

A target declares what kind of record an operation argument or a state value
holds (an order id, a customer id, a patient id, free text) and whether it
holds a date or a date-time. The declarations travel on the execution target
profile as ``value_facts``. A tool's input schema declares a format too: a
``string`` argument with ``format: date`` or ``format: date-time``
(:func:`with_argument_formats`). Nothing here is inferred from a name, a
value, or a description: a value without a declaration has no fact.

- A record kind is a lower_snake label. Two different record kinds are
  disjoint: declaring them states that a value of one is never a value of the
  other.
- A format states that every value is text of that RFC 3339 form: ``date``
  (``2026-09-15``) or ``date-time`` (``2026-09-15T10:00:00Z``).
- A state path is dotted and relative to ``TARGET-STATE``; a ``*`` segment
  stands for any one key. ``state_fields`` declares the value at a path, and
  ``state_keys`` the keys of the mapping at a path.

A lookup returns no fact when two declarations match the same value and
disagree.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from enum import Enum

from pydantic import ConfigDict, Field, StrictStr, model_validator

from asago_scenario_generator.models.canonical import ClosedCanonicalModel

RECORD_KIND_PATTERN = r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$"
STATE_PATH_PATTERN = r"^[^.]+(?:\.[^.]+)*$"
WILDCARD = "*"


class ValueFormat(str, Enum):
    """A declared text form of every value: an RFC 3339 date or date-time."""

    date = "date"
    date_time = "date-time"


class DeclaredValue(ClosedCanonicalModel):
    """A record kind, a format, or both, declared for one set of values."""

    # The JSON Schema states the same rule as ``_declares_a_fact``: at least
    # one of the two is present and not null.
    model_config = ConfigDict(
        json_schema_extra={
            "anyOf": [
                {
                    "required": ["record_kind"],
                    "properties": {"record_kind": {"type": "string"}},
                },
                {
                    "required": ["format"],
                    "properties": {"format": {"type": "string"}},
                },
            ]
        }
    )

    record_kind: StrictStr | None = Field(default=None, pattern=RECORD_KIND_PATTERN)
    format: ValueFormat | None = None

    @model_validator(mode="after")
    def _declares_a_fact(self) -> DeclaredValue:
        if self.record_kind is None and self.format is None:
            raise ValueError("a value fact declares a record_kind, a format, or both")
        return self

    def declared(self) -> DeclaredValue:
        """Return only the declaration, without what it is declared for."""

        return DeclaredValue(record_kind=self.record_kind, format=self.format)


class ArgumentValueFact(DeclaredValue):
    """The values one argument of one operation takes."""

    operation_id: StrictStr = Field(min_length=1)
    argument: StrictStr = Field(min_length=1)


class StateValueFact(DeclaredValue):
    """The values at a state path, or the keys of the mapping at it."""

    path: StrictStr = Field(pattern=STATE_PATH_PATTERN)


class TargetValueFacts(ClosedCanonicalModel):
    """Every value fact one target declares, each target value at most once."""

    arguments: tuple[ArgumentValueFact, ...] = ()
    state_fields: tuple[StateValueFact, ...] = ()
    state_keys: tuple[StateValueFact, ...] = ()

    @model_validator(mode="after")
    def _canonical(self) -> TargetValueFacts:
        arguments = tuple(
            sorted(self.arguments, key=lambda item: (item.operation_id, item.argument))
        )
        _require_unique(
            [(item.operation_id, item.argument) for item in arguments],
            "argument value facts",
        )
        object.__setattr__(self, "arguments", arguments)
        for name in ("state_fields", "state_keys"):
            items = tuple(sorted(getattr(self, name), key=lambda item: item.path))
            _require_unique([item.path for item in items], f"{name} value facts")
            object.__setattr__(self, name, items)
        return self

    def argument(self, operation_id: str, argument: str) -> DeclaredValue | None:
        """Return the declaration of one operation argument."""

        for item in self.arguments:
            if item.operation_id == operation_id and item.argument == argument:
                return item.declared()
        return None

    def state_field(self, segments: Sequence[str]) -> DeclaredValue | None:
        """Return the declaration of the value at a state path."""

        return _match(self.state_fields, segments)

    def state_key(self, segments: Sequence[str]) -> DeclaredValue | None:
        """Return the declaration of the keys of the mapping at a state path."""

        return _match(self.state_keys, segments)


def _match(
    facts: Sequence[StateValueFact], segments: Sequence[str]
) -> DeclaredValue | None:
    found = {
        item.declared() for item in facts if _matches(item.path.split("."), segments)
    }
    return found.pop() if len(found) == 1 else None


def with_argument_formats(
    facts: TargetValueFacts | None,
    formats: Mapping[tuple[str, str], ValueFormat],
) -> TargetValueFacts | None:
    """Add the format an input schema declares for each argument to ``facts``.

    ``formats`` maps an ``(operation_id, argument)`` pair to the format its
    input schema declares. An argument ``facts`` does not declare gains a
    format fact. An argument ``facts`` declares keeps one fact when that
    declaration states the same format or none, the latter gaining the
    format; it has no fact when the two formats differ. Without formats,
    ``facts`` returns unchanged.
    """

    if not formats:
        return facts
    base = facts if facts is not None else TargetValueFacts()
    arguments = {(item.operation_id, item.argument): item for item in base.arguments}
    for (operation_id, argument), value_format in formats.items():
        declared = arguments.get((operation_id, argument))
        if declared is None or declared.format is None:
            arguments[(operation_id, argument)] = ArgumentValueFact(
                operation_id=operation_id,
                argument=argument,
                record_kind=declared.record_kind if declared else None,
                format=value_format,
            )
        elif declared.format is not value_format:
            del arguments[(operation_id, argument)]
    return TargetValueFacts(
        arguments=tuple(arguments.values()),
        state_fields=base.state_fields,
        state_keys=base.state_keys,
    )


def _matches(pattern: Sequence[str], segments: Sequence[str]) -> bool:
    return len(pattern) == len(segments) and all(
        part in (WILDCARD, segment)
        for part, segment in zip(pattern, segments, strict=True)
    )


def _require_unique(keys: Sequence[object], label: str) -> None:
    if len(keys) != len(set(keys)):
        raise ValueError(f"{label} must declare each target value once")


__all__ = [
    "RECORD_KIND_PATTERN",
    "ArgumentValueFact",
    "DeclaredValue",
    "StateValueFact",
    "TargetValueFacts",
    "ValueFormat",
    "with_argument_formats",
]
