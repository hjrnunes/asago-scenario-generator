"""Content-addressed semantic snapshots for finalization artifacts."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Generic, TypeVar

from pydantic import BaseModel

from asago_scenario_generator.models.attack_tree import AttackTree
from asago_scenario_generator.models.scenario import ActorProfile, NarrativeLayer
from asago_scenario_generator.pipeline.projection_contracts import (
    ProjectedCandidate,
    canonical_json_bytes,
)


M = TypeVar("M", bound=BaseModel)


def _canonical(model: BaseModel) -> bytes:
    return canonical_json_bytes(model)


@dataclass(frozen=True, slots=True)
class _SemanticSnapshot(Generic[M]):
    """Content-addressed model copy; both stored bytes and model are verified."""

    model: M
    canonical_bytes: bytes
    digest: str

    @classmethod
    def capture(cls, model: M):
        fresh = type(model).model_validate(model.model_dump(mode="json"))
        canonical = _canonical(fresh)
        return cls(fresh, canonical, hashlib.sha256(canonical).hexdigest())

    def verify_digest(self) -> None:
        if hashlib.sha256(self.canonical_bytes).hexdigest() != self.digest:
            raise ValueError("snapshot canonical bytes were changed")
        if _canonical(self.model) != self.canonical_bytes:
            raise ValueError("snapshot model drifted after capture")
        # Also prove the held bytes remain independently materializable.
        type(self.model).model_validate_json(self.canonical_bytes)

    def materialize(self) -> M:
        self.verify_digest()
        return type(self.model).model_validate_json(self.canonical_bytes)


class ProjectionSemanticSnapshot(_SemanticSnapshot[ProjectedCandidate]):
    @property
    def candidate(self) -> ProjectedCandidate:
        return self.materialize()

    @property
    def projection(self) -> ProjectedCandidate:
        return self.candidate


class ActorSemanticSnapshot(_SemanticSnapshot[ActorProfile]):
    @property
    def actor(self) -> ActorProfile:
        return self.materialize()


class NarrativeSemanticSnapshot(_SemanticSnapshot[NarrativeLayer]):
    @property
    def narrative(self) -> NarrativeLayer:
        return self.materialize()


class FinalTreeSemanticSnapshot(_SemanticSnapshot[AttackTree]):
    @property
    def tree(self) -> AttackTree:
        return self.materialize()
