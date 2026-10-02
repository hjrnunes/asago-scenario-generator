"""Contracts and value objects for target-scoped finalization."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


MAX_OWNER_RETRIES = 1
MAX_COMPLETION_LENGTH_RETRIES = 1


class GeneratedStage(str, Enum):
    """Only stages that own generated artifacts and retry budgets."""

    actor = "actor"
    narrative = "narrative"
    tree = "tree"
    behavior = "behavior"


class LifecycleState(str, Enum):
    pending = "pending"
    revalidating_candidate = "revalidating_candidate"
    generating_actor = "generating_actor"
    generating_narrative = "generating_narrative"
    generating_tree = "generating_tree"
    finalizing_prebehavior = "finalizing_prebehavior"
    generating_behavior = "generating_behavior"
    admitting = "admitting"
    admitted = "admitted"
    rejected = "rejected"
    exhausted = "exhausted"


class CandidateTerminalStatus(str, Enum):
    admitted = "admitted"
    rejected = "rejected"
    generation_or_finalization_failed = "generation_or_finalization_failed"


@dataclass(frozen=True, slots=True)
class LifecycleViolation:
    """Typed lifecycle failure; ``owner=None`` is candidate/projection-owned."""

    detail: str
    owner: GeneratedStage | None = None
    code: str = "invalid"
    retryable: bool = True

    @property
    def can_retry_generation(self) -> bool:
        return self.retryable and self.owner is not None
