"""The canonical ID each request-local handle of one Stage 1a reply compiles to.

A failed Stage 1a reply reaches repair in its own handles.  Salvage reads it
in that form, then one compile renames every handle to the canonical ID the
allocation gave it; the repair records, warnings, and merges work on
canonical IDs from there.  A value outside the map (an earlier call's
canonical ID, or an unknown reference) names itself, so an unknown reference
survives the compile for the reference repair to select.

Handles are unique per kind, not across kinds, so each kind has its own map.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TypeVar

from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysisDraft

LOSS = "loss"
HAZARD = "hazard"
CONSTRAINT = "constraint"

_EMPTY: Mapping[str, str] = MappingProxyType({})

Draft = TypeVar("Draft", bound=LossAnalysisDraft)


@dataclass(frozen=True)
class IdSpace:
    """Per-kind maps from a reply's handles to their canonical IDs."""

    losses: Mapping[str, str] = field(default=_EMPTY)
    hazards: Mapping[str, str] = field(default=_EMPTY)
    constraints: Mapping[str, str] = field(default=_EMPTY)

    def _map(self, kind: str) -> Mapping[str, str]:
        return {LOSS: self.losses, HAZARD: self.hazards, CONSTRAINT: self.constraints}[
            kind
        ]

    def name(self, kind: str, value: str) -> str:
        """The canonical ID of one handle; any other value names itself."""
        return self._map(kind).get(value, value)

    def handle(self, kind: str, value: str) -> str:
        """The handle a canonical ID names; any other value names itself."""
        for handle, canonical in self._map(kind).items():
            if canonical == value:
                return handle
        return value

    def compile(self, draft: Draft) -> Draft:
        """Rename every handle of ``draft`` to its canonical ID."""
        return _renamed(draft, self.name)

    def to_handles(self, draft: Draft) -> Draft:
        """Rename every canonical ID of this reply back to its handle."""
        return _renamed(draft, self.handle)


def _renamed(draft: Draft, rename: Callable[[str, str], str]) -> Draft:
    payload = draft.model_dump(mode="json")
    for collection in ("risk_card_losses", "use_case_losses"):
        for row in payload[collection]:
            row["loss_id"] = rename(LOSS, row["loss_id"])
    for row in payload["hazards"]:
        row["hazard_id"] = rename(HAZARD, row["hazard_id"])
        row["related_losses"] = [rename(LOSS, ref) for ref in row["related_losses"]]
    for row in payload["security_constraints"]:
        row["constraint_id"] = rename(CONSTRAINT, row["constraint_id"])
        row["related_hazards"] = [rename(HAZARD, ref) for ref in row["related_hazards"]]
    for row in payload["risk_dispositions"]:
        row["loss_ids"] = [rename(LOSS, ref) for ref in row["loss_ids"]]
    return type(draft).model_validate(payload)
