"""One rule a scenario handoff breaks."""

from __future__ import annotations

from typing import NamedTuple


class Violation(NamedTuple):
    """A rule's code, the dotted path of the break, and a reason.

    A violation is a plain three-item tuple, so a reader that unpacked the old
    ``(code, path, reason)`` triples keeps working. Codes keep the producer's
    vocabulary: ``artifact_design_field:<leaf>`` and ``prose_hiding:<slug>`` from
    the ownership walker, ``schema_violation:<field>`` from the schema and the
    rules it cannot state.
    """

    code: str
    path: str
    reason: str


__all__ = ["Violation"]
