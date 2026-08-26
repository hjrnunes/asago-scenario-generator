"""Contracts and value objects for target-scoped finalization."""

from __future__ import annotations

import copy
import hashlib
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any, Literal, Protocol, runtime_checkable

from asago_scenario_generator.pipeline.generation_contracts import (
    CausalRetryControl,
)

MAX_OWNER_RETRIES = 1
MAX_TARGETED_RETRIES = MAX_OWNER_RETRIES  # Compatibility name.
MAX_TARGET_CHOICES = 3
MAX_COMPLETION_LENGTH_RETRIES = 1


class GeneratedStage(str, Enum):
    """Only stages that own generated artifacts and retry budgets."""

    actor = "actor"
    narrative = "narrative"
    tree = "tree"
    behavior = "behavior"


GENERATION_ORDER: tuple[GeneratedStage, ...] = (
    GeneratedStage.actor,
    GeneratedStage.narrative,
    GeneratedStage.tree,
    GeneratedStage.behavior,
)


# Approved stage-specific completion-length retry suffixes.  The retry
# user prompt is exactly the original prompt followed by this suffix.
COMPLETION_LENGTH_RETRY_SUFFIXES: dict[GeneratedStage, str] = {
    GeneratedStage.actor: (
        "Return only a schema-matching object with bounded lists and concise prose."
    ),
    GeneratedStage.narrative: (
        "Return only a schema-matching object with bounded lists and concise prose."
    ),
    GeneratedStage.tree: "Return only a complete schema-matching YAML document.",
    GeneratedStage.behavior: (
        "Return only the complete required Gherkin/assertion payload."
    ),
}

_COMPACT_RESPONSE_SCHEMA_RETRY = CausalRetryControl(
    control_id="candidate-specific-compact-response-schema",
    field="response_schema",
    initial_value="standard",
    retry_value="compact-v1",
)

COMPLETION_LENGTH_RETRY_CONTROLS: dict[GeneratedStage, CausalRetryControl] = {
    GeneratedStage.actor: _COMPACT_RESPONSE_SCHEMA_RETRY,
    GeneratedStage.narrative: CausalRetryControl(
        control_id="stage-specific-completion-cap",
        field="max_completion_tokens",
        initial_value=8192,
        retry_value=4096,
    ),
    GeneratedStage.tree: CausalRetryControl(
        control_id="lower-retry-temperature",
        field="temperature",
        initial_value=0.4,
        retry_value=0.1,
    ),
    GeneratedStage.behavior: _COMPACT_RESPONSE_SCHEMA_RETRY,
}


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


class FinalizationPersistenceError(RuntimeError):
    """Durable lifecycle state could not be committed and must be recovered."""

    failure_code = "persistence_failed"


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


@dataclass(slots=True)
class GeneratedArtifacts:
    actor: Any | None = None
    narrative: Any | None = None
    tree: Any | None = None
    behavior: Any | None = None

    def get(self, stage: GeneratedStage) -> Any | None:
        return getattr(self, stage.value)

    def set(self, stage: GeneratedStage, value: Any) -> None:
        setattr(self, stage.value, value)

    def invalidate_from(self, owner: GeneratedStage) -> None:
        start = GENERATION_ORDER.index(owner)
        for stage in GENERATION_ORDER[start:]:
            self.set(stage, None)


@runtime_checkable
class FinalTreeSnapshot(Protocol):
    """Immutable finalized-tree authority consumed by behavior/admission."""

    @property
    def tree(self) -> Any: ...

    @property
    def digest(self) -> str: ...

    def verify_digest(self) -> None: ...


@runtime_checkable
class VerifiedCandidateSnapshot(Protocol):
    """Candidate baseline captured immediately after authoritative revalidation."""

    @property
    def candidate(self) -> Any: ...

    @property
    def digest(self) -> str: ...

    def verify_digest(self) -> None: ...


@runtime_checkable
class TargetChoiceEntry(Protocol):
    """Coverage-plan choice queue consumed by target finalization."""

    ordered_choices: Sequence[dict[str, Any]]
    fallback_available: Sequence[dict[str, Any]]
    primary_candidate_id: str | None


@dataclass(frozen=True, slots=True)
class CandidateFinalizationContext:
    """Verified baseline plus the live candidate visible to generation stages."""

    candidate: Any
    verified_snapshot: VerifiedCandidateSnapshot

    @property
    def candidate_id(self) -> str | None:
        return getattr(self.candidate, "candidate_id", None)


@dataclass(frozen=True, slots=True)
class _OpaqueCandidateSnapshot:
    """Test/compatibility snapshot for non-Pydantic Phase 2 candidate doubles."""

    _candidate: Any
    digest: str

    @classmethod
    def capture(cls, candidate: Any) -> _OpaqueCandidateSnapshot:
        copied = copy.deepcopy(candidate)
        return cls(copied, hashlib.sha256(repr(copied).encode()).hexdigest())

    @property
    def candidate(self) -> Any:
        return copy.deepcopy(self._candidate)

    def verify_digest(self) -> None:
        if hashlib.sha256(repr(self._candidate).encode()).hexdigest() != self.digest:
            raise ValueError("verified candidate snapshot drifted")


@dataclass(frozen=True, slots=True)
class CandidateValidation:
    candidate: Any | None
    violations: tuple[LifecycleViolation, ...] = ()

    @property
    def valid(self) -> bool:
        return self.candidate is not None and not self.violations


@dataclass(frozen=True, slots=True)
class StageInvocation:
    candidate_id: str
    stage: GeneratedStage
    invocation_index: int
    owner_retry_index: int
    artifacts: GeneratedArtifacts
    final_tree_digest: str | None = None
    candidate_snapshot: Any | None = None
    retry_feedback: str | None = None
    retry_reason: str | None = None
    retry_control: CausalRetryControl | None = None
    total_request_budget: int = MAX_COMPLETION_LENGTH_RETRIES + 1


@dataclass(frozen=True, slots=True)
class GeneratedStageResult:
    artifact: Any | None
    evidence: Any = None
    violations: tuple[LifecycleViolation, ...] = ()


@dataclass(frozen=True, slots=True)
class PrebehaviorFinalizationResult:
    snapshot: FinalTreeSnapshot | None
    violations: tuple[LifecycleViolation, ...] = ()
    candidate_snapshot: VerifiedCandidateSnapshot | None = None
    actor_snapshot: Any | None = None
    narrative_snapshot: Any | None = None
    repair_record: Any | None = None


@dataclass(frozen=True, slots=True)
class AdmissionDecision:
    admitted: bool
    violations: tuple[LifecycleViolation, ...] = ()
    value: Any = None


@dataclass(frozen=True, slots=True)
class CandidateTerminalResult:
    """Exactly one terminal lifecycle outcome for one reserved plan choice."""

    candidate_id: str
    status: CandidateTerminalStatus
    violations: tuple[LifecycleViolation, ...] = ()
    admission: AdmissionDecision | None = None


@dataclass(frozen=True, slots=True)
class LifecycleTransition:
    previous: LifecycleState
    current: LifecycleState
    candidate_id: str | None
    reason: str
    transition_index: int = 0
    target_entry_point_id: str | None = None


@dataclass(frozen=True, slots=True)
class TargetFinalizationResult:
    state: LifecycleState
    candidate_id: str | None
    admission: AdmissionDecision | None
    attempted_candidate_ids: tuple[str, ...]
    violations: tuple[LifecycleViolation, ...]
    transitions: tuple[LifecycleTransition, ...]


StageCallback = Callable[[Any, StageInvocation], GeneratedStageResult]
CandidateRevalidator = Callable[[dict[str, Any]], CandidateValidation]
PrebehaviorFinalizer = Callable[
    [CandidateFinalizationContext, GeneratedArtifacts], PrebehaviorFinalizationResult
]
AdmissionCallback = Callable[
    [Any, GeneratedArtifacts, FinalTreeSnapshot], AdmissionDecision
]


class FinalizationPersistencePort(Protocol):
    """Effect boundary; manifest-v3/quarantine implementations are deferred."""

    def record_transition(self, transition: LifecycleTransition) -> None: ...

    def record_stage_result(
        self, invocation: StageInvocation, result: GeneratedStageResult
    ) -> None: ...

    def record_candidate_result(
        self, candidate_id: str, result: CandidateTerminalResult
    ) -> None: ...

    def record_repair(self, candidate_id: str, record: Any) -> None: ...


def earliest_generated_owner(
    violations: Sequence[LifecycleViolation],
) -> GeneratedStage | None:
    """Choose the earliest retryable generated owner across all violations.

    Any candidate/projection-owned violation is nonretryable regardless of
    generated-stage failures present in the same aggregate.
    """
    if any(not violation.can_retry_generation for violation in violations):
        return None
    owners = {violation.owner for violation in violations}
    return next((stage for stage in GENERATION_ORDER if stage in owners), None)


def ordered_target_choice_refs(entry: TargetChoiceEntry) -> tuple[dict[str, Any], ...]:
    """Primary first, then persisted fallback availability, bounded and unique."""
    all_refs = [*entry.ordered_choices, *entry.fallback_available]
    primary = _primary_choice_ref(all_refs, entry.primary_candidate_id)
    ordered = ([primary] if primary is not None else []) + list(
        entry.fallback_available
    )
    return tuple(_unique_choice_refs(ordered))


def _primary_choice_ref(
    all_refs: list[dict[str, Any]], primary_candidate_id: str | None
) -> dict[str, Any] | None:
    """Locate the primary choice reference across the combined queue."""
    return next(
        (ref for ref in all_refs if ref.get("candidate_id") == primary_candidate_id),
        None,
    )


def _unique_choice_refs(ordered: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate candidate refs by id, bounded to the target choice cap."""
    seen: set[str] = set()
    result: list[dict[str, Any]] = []
    for ref in ordered:
        candidate_id = ref.get("candidate_id")
        if not isinstance(candidate_id, str) or candidate_id in seen:
            continue
        seen.add(candidate_id)
        result.append(ref)
        if len(result) == MAX_TARGET_CHOICES:
            break
    return result


@dataclass
class _CandidateCursor:
    """Mutable per-candidate advancement state for the finalization loop."""

    next_stage: GeneratedStage = GeneratedStage.actor
    snapshot: FinalTreeSnapshot | None = None
    finalized_authority: PrebehaviorFinalizationResult | None = None
    suppress_durable_boundary: bool = False
    terminal: CandidateTerminalResult | None = None


@dataclass(frozen=True)
class _PreparedStage:
    """Outcome of one prebehavior finalization attempt."""

    action: Literal["proceed", "retry", "terminal"]
    owner: GeneratedStage | None = None
    result: CandidateTerminalResult | None = None
    snapshot: FinalTreeSnapshot | None = None
    authority: PrebehaviorFinalizationResult | None = None


def _canonical_candidate_id(validation: Any) -> str | None:
    """The candidate identity carried by a revalidation result, if any."""
    if validation.candidate is not None:
        return getattr(validation.candidate, "candidate_id", None)
    return None


def _validation_rejected(
    validation: CandidateValidation, identity_violation: LifecycleViolation | None
) -> bool:
    return validation.violations or not validation.valid or identity_violation


def _candidate_identity_violation(
    ref_id: str, canonical_id: str | None
) -> LifecycleViolation | None:
    """Require the revalidated candidate to keep the persisted identity."""
    if canonical_id is not None and canonical_id != ref_id:
        return LifecycleViolation(
            code="candidate_identity_mismatch",
            detail=(
                f"revalidated candidate_id {canonical_id!r} does not match "
                f"persisted candidate_id {ref_id!r}"
            ),
            retryable=False,
        )
    return None
