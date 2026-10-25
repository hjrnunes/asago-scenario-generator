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

:class:`PatternMechanismRelation` links attack patterns to the mechanisms they
realize, in ``data/taxonomies/mappings/attack-pattern-to-mechanism.yaml``.
The relation is many to many.  Each link pins the pattern's chain semantic
digest, so a revised pattern needs its link reviewed again, and the file
carries the semantic digest of its own content, which loading checks.
"""

from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum
from functools import cache
from pathlib import Path
from typing import Any, ClassVar, Literal

from pydantic import Field, field_validator, model_validator
import yaml

from asago_scenario_generator.data.paths import DATA_ROOT
from asago_scenario_generator.models.canonical import (
    ClosedCanonicalModel,
    SemanticDigestMixin,
)
from asago_scenario_generator.stpa.models.control_structure import (
    FeedbackAuthorityStatus,
    FeedbackSourceKind,
)

MECHANISM_LIBRARY_PATH = (
    DATA_ROOT / "taxonomies" / "mechanisms" / "mechanism-library.yaml"
)
PATTERN_MECHANISM_RELATION_PATH = (
    DATA_ROOT / "taxonomies" / "mappings" / "attack-pattern-to-mechanism.yaml"
)
PATTERN_MECHANISM_DIGEST_DOMAIN = (
    "asago-scenario-generator:pattern-mechanism-relation:v1"
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


class PatternMechanismLink(ClosedCanonicalModel):
    """The mechanisms one attack pattern realizes, pinned to its revision.

    ``pattern_semantic_digest`` is the pattern's ``canonical_chain``
    semantic digest when the link was reviewed.
    """

    pattern_id: str = Field(pattern=r"^AP-T\d+-\d+$")
    pattern_semantic_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    mechanisms: tuple[MechanismId, ...] = Field(min_length=1)
    rationale: str = Field(min_length=1)

    @field_validator("mechanisms")
    @classmethod
    def _distinct(cls, value: tuple[MechanismId, ...]) -> tuple[MechanismId, ...]:
        if len(set(value)) != len(value):
            raise ValueError("must not repeat a mechanism")
        return value


class PatternMechanismRelation(SemanticDigestMixin, ClosedCanonicalModel):
    """Attack pattern to mechanism links, one per pattern, with a checked digest.

    A pattern without a link realizes no known mechanism; that is not a
    claim that it realizes none.
    """

    _digest_domain: ClassVar[str] = PATTERN_MECHANISM_DIGEST_DOMAIN

    version: Literal[1]
    predicate: Literal["realizes"]
    links: tuple[PatternMechanismLink, ...] = Field(min_length=1)
    semantic_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def _one_link_per_pattern_and_digest(self) -> PatternMechanismRelation:
        ids = [link.pattern_id for link in self.links]
        repeated = sorted({item for item in ids if ids.count(item) > 1})
        if repeated:
            raise ValueError(f"pattern-mechanism relation repeats patterns: {repeated}")
        expected = self.compute_semantic_digest()
        if self.semantic_digest != expected:
            raise ValueError(
                "pattern-mechanism relation semantic_digest does not match its "
                f"content; expected {expected}"
            )
        return self

    def mechanisms_for(self, pattern_id: str) -> tuple[MechanismId, ...]:
        """The mechanisms *pattern_id* realizes; empty for an unlinked pattern."""
        return next(
            (link.mechanisms for link in self.links if link.pattern_id == pattern_id),
            (),
        )

    def pattern_reference_errors(self, catalog: Iterable[Any]) -> list[str]:
        """Name every link whose pattern is missing from *catalog* or revised.

        *catalog* holds typed attack patterns; a link resolves when a pattern
        has its ID and its chain's semantic digest equals the pinned one.
        """
        digests = {
            pattern.id: pattern.canonical_chain.semantic_digest for pattern in catalog
        }
        errors = []
        for link in self.links:
            digest = digests.get(link.pattern_id)
            if digest is None:
                errors.append(f"{link.pattern_id}: not in the attack-pattern catalog")
            elif digest != link.pattern_semantic_digest:
                errors.append(
                    f"{link.pattern_id}: pinned digest "
                    f"{link.pattern_semantic_digest} != catalog digest {digest}"
                )
        return errors


def load_pattern_mechanism_relation(
    path: str | Path | None = None,
) -> PatternMechanismRelation:
    """Load the relation file and check its digest, the bundled one by default."""
    source = Path(path) if path is not None else PATTERN_MECHANISM_RELATION_PATH
    return PatternMechanismRelation.model_validate(yaml.safe_load(source.read_text()))


@cache
def bundled_pattern_mechanism_relation() -> PatternMechanismRelation:
    """The digest-checked bundled relation, loaded once."""
    return load_pattern_mechanism_relation()


def pattern_mechanisms(pattern_id: str) -> tuple[MechanismEntry, ...]:
    """The bundled entries of the mechanisms *pattern_id* realizes, in link order."""
    library = bundled_mechanism_library()
    return tuple(
        library.entry(mechanism_id)
        for mechanism_id in bundled_pattern_mechanism_relation().mechanisms_for(
            pattern_id
        )
    )


__all__ = [
    "MECHANISM_LIBRARY_PATH",
    "PATTERN_MECHANISM_DIGEST_DOMAIN",
    "PATTERN_MECHANISM_RELATION_PATH",
    "ControllerCrossing",
    "MechanismEntry",
    "MechanismId",
    "MechanismLibrary",
    "MechanismSignature",
    "PatternMechanismLink",
    "PatternMechanismRelation",
    "ProcessModelUse",
    "bundled_mechanism_library",
    "bundled_pattern_mechanism_relation",
    "load_mechanism_library",
    "load_pattern_mechanism_relation",
    "pattern_mechanisms",
]
