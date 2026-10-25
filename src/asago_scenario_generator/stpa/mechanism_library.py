"""The mechanism library: reviewed control-loop mechanisms with code-owned IDs.

A mechanism is a way adversary influence becomes a wrong controller belief or
decision on a typed control-structure path.  Its entry is data, in
``data/taxonomies/mechanisms/mechanism-library.yaml``; :class:`MechanismId`
owns the identities, and loading fails on an unknown, missing or repeated ID
and on a missing or unknown field.

An entry records:

- ``question``: what the mechanism asks of a system, in one sentence;
- ``signature``: the typed structure that makes the mechanism worth
  considering on a path (:class:`MechanismSignature`);
- ``required_evidence``: what a supplied structural description must govern
  before a path carries the mechanism;
- ``counterexamples``: structures that resemble the mechanism but do not
  carry it;
- ``safe_behavior``: what a controller does so that the path does not carry
  it.

A judgement of a path against an entry reads the signature to decide whether
the path's structure fits, then the evidence and counterexamples to decide
whether its descriptions do.
"""

from __future__ import annotations

from enum import StrEnum
from functools import cache
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator, model_validator
import yaml

from asago_scenario_generator.data.paths import DATA_ROOT
from asago_scenario_generator.models.canonical import ClosedCanonicalModel
from asago_scenario_generator.stpa.models.control_structure import (
    FeedbackAuthorityStatus,
    FeedbackSourceKind,
)

MECHANISM_LIBRARY_PATH = (
    DATA_ROOT / "taxonomies" / "mechanisms" / "mechanism-library.yaml"
)


class MechanismId(StrEnum):
    """The identity of every mechanism the library holds.

    - ``user_claim``: a claim in the current user message stands in for a
      value the controller should establish from a source entitled to set it;
    - ``retrieved_instructions``: retrieved content or tool output changes
      what the controller takes as its instructions, goal or authority;
    - ``stale_history``: an earlier turn justifies an action after the state
      it described has changed;
    - ``delegated_authority``: one controller's adversary-influenced belief or
      message counts as permission for another;
    - ``stale_feedback``: feedback about an earlier state justifies an action
      after that state has changed;
    - ``forged_completion``: a report that an operation succeeded is taken as
      evidence that its effect happened.
    """

    user_claim = "user_claim"
    retrieved_instructions = "retrieved_instructions"
    stale_history = "stale_history"
    delegated_authority = "delegated_authority"
    stale_feedback = "stale_feedback"
    forged_completion = "forged_completion"


class ProcessModelUse(StrEnum):
    """How a path uses the process-model variable its feedback channel updates.

    - ``read_by_path``: the channel ``updates`` the variable, and the path's
      control action lists it in ``process_model_refs`` or the path's
      coordination link shares it as ``shared_pm``.
    """

    read_by_path = "read_by_path"


class ControllerCrossing(StrEnum):
    """Whether a path carrying the mechanism reaches another controller.

    - ``within_controller``: the path ends at a control action of the
      controller that holds the variable; a coordination link joins no path;
    - ``may_cross``: the path ends at that controller's action, or reaches
      another controller;
    - ``must_cross``: the path reaches another controller, through a
      coordination link whose ``source`` owns the variable or an action whose
      effect is ``agent_message``.
    """

    within_controller = "within_controller"
    may_cross = "may_cross"
    must_cross = "must_cross"


class MechanismSignature(ClosedCanonicalModel):
    """The typed structure on which a mechanism is worth considering.

    ``source_kinds`` are the feedback source kinds a path may start from.
    ``authority`` are the statuses of that channel's authority over its
    variable under which the mechanism applies; a channel without
    ``authority_for_update`` is ``unknown``.  ``process_model_refs`` says how
    the path uses the updated variable, and ``crossing`` whether it reaches
    another controller.
    """

    source_kinds: tuple[FeedbackSourceKind, ...] = Field(min_length=1)
    authority: tuple[FeedbackAuthorityStatus, ...] = Field(min_length=1)
    process_model_refs: ProcessModelUse
    crossing: ControllerCrossing

    @field_validator("source_kinds", "authority")
    @classmethod
    def _distinct(cls, value: tuple[StrEnum, ...]) -> tuple[StrEnum, ...]:
        if len(set(value)) != len(value):
            raise ValueError("must not repeat a value")
        return value


class MechanismEntry(ClosedCanonicalModel):
    """One reviewed mechanism; see the module docstring for its fields."""

    id: MechanismId
    name: str = Field(min_length=1)
    question: str = Field(min_length=1)
    signature: MechanismSignature
    required_evidence: tuple[str, ...] = Field(min_length=1)
    counterexamples: tuple[str, ...] = Field(min_length=1)
    safe_behavior: str = Field(min_length=1)

    @field_validator("required_evidence", "counterexamples")
    @classmethod
    def _non_empty_items(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not item.strip() for item in value):
            raise ValueError("must not hold an empty item")
        if len(set(value)) != len(value):
            raise ValueError("must not repeat an item")
        return value


class MechanismLibrary(ClosedCanonicalModel):
    """Every mechanism entry, exactly one per :class:`MechanismId`."""

    version: Literal[1]
    mechanisms: tuple[MechanismEntry, ...]

    @model_validator(mode="after")
    def _one_entry_per_id(self) -> MechanismLibrary:
        ids = [entry.id.value for entry in self.mechanisms]
        repeated = sorted({item for item in ids if ids.count(item) > 1})
        if repeated:
            raise ValueError(f"mechanism library repeats IDs: {repeated}")
        missing = sorted({item.value for item in MechanismId} - set(ids))
        if missing:
            raise ValueError(f"mechanism library lacks entries for: {missing}")
        return self

    def entry(self, mechanism_id: MechanismId | str) -> MechanismEntry:
        """Return the entry of *mechanism_id*; an unknown ID raises."""
        wanted = MechanismId(mechanism_id)
        return next(entry for entry in self.mechanisms if entry.id is wanted)


def load_mechanism_library(path: str | Path | None = None) -> MechanismLibrary:
    """Load and validate the library file, the bundled one by default."""
    source = Path(path) if path is not None else MECHANISM_LIBRARY_PATH
    return MechanismLibrary.model_validate(yaml.safe_load(source.read_text()))


@cache
def bundled_mechanism_library() -> MechanismLibrary:
    """The validated bundled library, loaded once."""
    return load_mechanism_library()


__all__ = [
    "MECHANISM_LIBRARY_PATH",
    "ControllerCrossing",
    "MechanismEntry",
    "MechanismId",
    "MechanismLibrary",
    "MechanismSignature",
    "ProcessModelUse",
    "bundled_mechanism_library",
    "load_mechanism_library",
]
