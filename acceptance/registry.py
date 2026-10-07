"""Registration and resolution for acceptance step handlers.

The registry is intentionally independent from feature-module loading and
scenario execution.  A feature manifest records into a private stage and the
runtime publishes that stage only after every module has registered
successfully.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from functools import partialmethod
from typing import Any

PatternEntry = tuple[re.Pattern[str], Any, str | None]
PatternKey = tuple[str, str, str | None]


def _handler_name(handler: Any) -> str:
    return getattr(handler, "__name__", repr(handler))


def _duplicate_error(pattern: str, handler: Any, feature: str | None) -> RuntimeError:
    scope = f"feature {feature!r}" if feature else "global scope"
    return RuntimeError(
        f"Duplicate step pattern registration in {scope}: "
        f"{pattern!r} (handler {_handler_name(handler)}) — "
        "second registration is redundant"
    )


def track_registration(
    keys: set[PatternKey],
    pattern: str,
    handler: Any,
    feature: str | None,
) -> None:
    """Record a registration and reject an exact duplicate."""
    key = (pattern, _handler_name(handler), feature)
    if key in keys:
        raise _duplicate_error(pattern, handler, feature)
    keys.add(key)


def find_pattern_conflicts(
    patterns: Iterable[PatternEntry],
    step_texts: list[str],
) -> list[tuple[str, str, str]]:
    """Find duplicate raw patterns with distinct handlers in one scope."""
    conflicts: list[tuple[str, str, str]] = []
    for patterns_by_raw_pattern in _scoped_patterns(patterns).values():
        for raw_pattern, registrations in patterns_by_raw_pattern.items():
            distinct_handlers = _distinct_handlers(registrations)
            if len(distinct_handlers) < 2:
                continue
            witness = _conflict_witness(distinct_handlers, step_texts)
            conflicts.append((witness, raw_pattern, raw_pattern))
    return conflicts


def _scoped_patterns(
    patterns: Iterable[PatternEntry],
) -> dict[str | None, dict[str, list[PatternEntry]]]:
    scoped: dict[str | None, dict[str, list[PatternEntry]]] = {}
    for pattern, handler, tag in patterns:
        scoped.setdefault(tag, {}).setdefault(pattern.pattern, []).append(
            (pattern, handler, tag)
        )
    return scoped


def _distinct_handlers(registrations: Iterable[PatternEntry]) -> list[PatternEntry]:
    distinct: list[PatternEntry] = []
    for registration in registrations:
        if not any(existing[1] is registration[1] for existing in distinct):
            distinct.append(registration)
    return distinct


def _conflict_witness(
    registrations: list[PatternEntry],
    step_texts: Iterable[str],
) -> str:
    return next(
        (text for text in step_texts if registrations[0][0].search(text)),
        "<no supplied witness>",
    )


def resolve_handler(
    patterns: Iterable[PatternEntry],
    text: str,
    feature: str | None = None,
) -> Any | None:
    """Return the first handler eligible for *text* and *feature*."""
    for pattern, handler, tag in patterns:
        if tag is not None and tag != feature:
            continue
        if pattern.search(text):
            return handler
    return None


class RegistrationStage:
    """Private transaction buffer for one registry publication."""

    def __init__(self) -> None:
        self.entries: list[tuple[int, int, bool, str, Any, str | None]] = []
        self.keys: set[PatternKey] = set()
        self.feature: str | None = None
        self._sequence = 0

    def set_feature(self, feature: str | None) -> None:
        self.feature = feature

    def add(
        self,
        pattern: str,
        handler: Any,
        first: bool,
        source_order: int | None,
    ) -> None:
        tag = self.feature if first else None
        track_registration(self.keys, pattern, handler, tag)
        order = source_order if source_order is not None else self._sequence
        self.entries.append((order, self._sequence, first, pattern, handler, tag))
        self._sequence += 1


class RegistrationAPI:
    """Small registration API passed to feature modules."""

    def __init__(self, stage: RegistrationStage) -> None:
        self._stage = stage

    def set_feature(self, tag: str | None) -> None:
        self._stage.set_feature(tag)

    def _register(
        self,
        pattern: str,
        handler: Any,
        *,
        first: bool,
        source_order: int | None = None,
    ) -> None:
        self._stage.add(pattern, handler, first, source_order)

    register = partialmethod(_register, first=False)
    register_first = partialmethod(_register, first=True)

    def install_handlers(self, namespaces: list[dict[str, Any]]) -> None:
        """Retain the old hook without mutating feature-module namespaces.

        Feature modules now import their handlers explicitly.  The argument
        remains accepted for callers that used the old private hook, but
        namespace mutation is deliberately no longer part of registration.
        """
        del namespaces


def publish(
    stage: RegistrationStage,
    patterns: list[PatternEntry],
    keys: set[PatternKey],
) -> None:
    """Atomically replace the published registry with a completed stage."""
    published: list[PatternEntry] = []
    for _, _, first, raw_pattern, handler, tag in sorted(
        stage.entries,
        key=lambda entry: (entry[0], entry[1]),
    ):
        entry = (re.compile(raw_pattern, re.IGNORECASE), handler, tag)
        if first:
            published.insert(0, entry)
        else:
            published.append(entry)
    patterns[:] = published
    keys.clear()
    keys.update(stage.keys)


StepEntry = tuple[str, Any, bool, str | None]


class StepTable:
    """Step registrations of one feature module, kept in definition order.

    ``@table(pattern)`` appends a global step; ``@table.first(pattern)``
    registers it ahead of the global steps, scoped to ``feature`` when given.
    ``table.register(api)`` replays the entries through a registration API, so
    definition order replaces hand-numbered ``source_order`` values.
    """

    def __init__(self) -> None:
        self.entries: list[StepEntry] = []
        self._run_handler: Any = None
        self._run_start = 0

    def add(
        self,
        pattern: str,
        handler: Any,
        *,
        first: bool = False,
        feature: str | None = None,
    ) -> None:
        if feature is not None and not first:
            raise ValueError(f"feature scope requires first=True: {pattern!r}")
        self._run_handler = None
        self.entries.append((pattern, handler, first, feature))

    def _decorator(self, pattern: str, first: bool, feature: str | None) -> Any:
        def decorate(handler: Any) -> Any:
            # Stacked decorators run bottom-up; inserting each one ahead of the
            # same handler's earlier entries keeps the table in reading order.
            if handler is not self._run_handler:
                self._run_handler = handler
                self._run_start = len(self.entries)
            self.entries.insert(self._run_start, (pattern, handler, first, feature))
            return handler

        return decorate

    def __call__(self, pattern: str) -> Any:
        return self._decorator(pattern, False, None)

    def first(self, pattern: str, *, feature: str | None = None) -> Any:
        return self._decorator(pattern, True, feature)

    def register(self, api: Any) -> None:
        for pattern, handler, first, feature in self.entries:
            api.set_feature(feature)
            if first:
                api.register_first(pattern, handler)
            else:
                api.register(pattern, handler)
        api.set_feature(None)


class PatternRegistry:
    """Mutable published registry with isolated staging operations."""

    def __init__(self) -> None:
        self.patterns: list[PatternEntry] = []
        self.keys: set[PatternKey] = set()

    def register(
        self,
        pattern: str,
        handler: Any,
        *,
        feature: str | None = None,
    ) -> None:
        track_registration(self.keys, pattern, handler, feature)
        self.patterns.append((re.compile(pattern, re.IGNORECASE), handler, feature))

    def register_first(
        self,
        pattern: str,
        handler: Any,
        *,
        feature: str | None = None,
    ) -> None:
        track_registration(self.keys, pattern, handler, feature)
        self.patterns.insert(
            0,
            (re.compile(pattern, re.IGNORECASE), handler, feature),
        )

    def publish(self, stage: RegistrationStage) -> None:
        publish(stage, self.patterns, self.keys)

    def resolve(self, text: str, feature: str | None = None) -> Any | None:
        """Return the first handler eligible for *text* and *feature*."""
        return resolve_handler(self.patterns, text, feature)

    def conflicts(self, step_texts: list[str]) -> list[tuple[str, str, str]]:
        return find_pattern_conflicts(self.patterns, step_texts)


__all__ = [
    "PatternEntry",
    "PatternKey",
    "PatternRegistry",
    "RegistrationAPI",
    "RegistrationStage",
    "StepEntry",
    "StepTable",
    "find_pattern_conflicts",
    "publish",
    "resolve_handler",
    "track_registration",
]
