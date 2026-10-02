"""Check-local identity rules over observed TARGET-STATE.

Two objects stay separate:

- the **session subject**: an observed string in TARGET-STATE plus the path
  it was read from; never a principal, role, or permission;
- the **record index**: which JSON objects can be named, under strict
  container rules; never an authorization claim.

This module is deliberately free of ``scenario_prod`` imports so any layer
can apply the same rules.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal


@dataclass(frozen=True)
class SessionSubject:
    """An observed TARGET-STATE string and the path it was read from.

    ``observed`` carries the exact path and value; ``unobserved`` and
    ``ambiguous`` carry neither (discovery never picks one of several
    candidate keys; the matched keys are retained in ``candidates`` as
    diagnostic evidence).
    """

    status: Literal["observed", "unobserved", "ambiguous"]
    path: tuple[str, ...] | None
    value: str | None
    candidates: tuple[str, ...] = ()

    @property
    def observed(self) -> bool:
        """Whether a unique session-subject string was observed."""
        return self.status == "observed"


_SESSION_KEY_RE = re.compile(r"^authenticated_.+_id$")


def resolve_session_subject(state: Any) -> SessionSubject:
    """Discover the session subject in parsed TARGET-STATE.

    Top-level keys matching ``^authenticated_.+_id$`` with non-empty string
    values are discovered: one key is ``observed``, none is ``unobserved``,
    and two or more are ``ambiguous``.  Non-mapping state is ``unobserved``.
    """
    if not isinstance(state, dict):
        return SessionSubject(status="unobserved", path=None, value=None)
    matches = sorted(
        key
        for key, value in state.items()
        if _SESSION_KEY_RE.match(key) and isinstance(value, str) and value
    )
    if len(matches) == 1:
        key = matches[0]
        return SessionSubject(status="observed", path=(key,), value=state[key])
    if not matches:
        return SessionSubject(status="unobserved", path=None, value=None)
    return SessionSubject(
        status="ambiguous",
        path=None,
        value=None,
        candidates=tuple(matches),
    )


class RecordIndex:
    """Which TARGET-STATE objects can be named as records.

    A mapping whose values are all mappings yields one record per child,
    addressed by the map key only (never by an embedded id field).
    Sequences, dicts of lists, and scalars are not record collections.  No
    identifier is ever guessed.
    """

    def __init__(self, state: Any) -> None:
        self._records: dict[str, dict[str, dict[str, Any]]] = {}
        if not isinstance(state, dict):
            return
        for name, container in state.items():
            if (
                isinstance(container, dict)
                and container
                and all(isinstance(value, dict) for value in container.values())
            ):
                self._records[name] = {
                    str(key): value for key, value in container.items()
                }

    @property
    def collections(self) -> tuple[str, ...]:
        """The addressable collection names, in canonical order."""
        return tuple(sorted(self._records))


__all__ = [
    "RecordIndex",
    "SessionSubject",
    "resolve_session_subject",
]
