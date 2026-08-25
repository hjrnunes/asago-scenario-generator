"""Production target-scoped finalization and admission lifecycle.

The controller owns candidate choice, targeted retry routing, and admission
sequencing while generation, validation, finalization, admission, and
persistence effects remain dependency-injected ports.
"""

from __future__ import annotations

import copy
import hashlib
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal, Protocol, runtime_checkable

from asago_scenario_generator.models.scenario import CallName
from asago_scenario_generator.pipeline.coverage_planning import (
    CoveragePlan,
    CoveragePlanEntry,
    deserialize_qualified_candidate,
    revalidate_qualified_candidate,
)
from asago_scenario_generator.pipeline.generation_contracts import (
    CausalRetryControl,
    RetryDirective,
    StageAttemptFailure,
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


def _capture_verified_candidate(candidate: Any) -> VerifiedCandidateSnapshot:
    """Capture semantic Pydantic candidates; retain Phase 2 test compatibility."""
    from pydantic import BaseModel

    if isinstance(candidate, BaseModel):
        # Late import avoids the finalization-gates -> finalization import cycle.
        from asago_scenario_generator.pipeline.finalization_gates import (
            ProjectionSemanticSnapshot,
        )

        return ProjectionSemanticSnapshot.capture(candidate)
    return _OpaqueCandidateSnapshot.capture(candidate)


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


def ordered_target_choice_refs(entry: CoveragePlanEntry) -> tuple[dict[str, Any], ...]:
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


@dataclass
class TargetFinalizationMachine:
    """Lifecycle controller for one coverage target and up to three choices."""

    entry: CoveragePlanEntry
    stage_callbacks: Mapping[GeneratedStage, StageCallback]
    candidate_revalidator: CandidateRevalidator
    prebehavior_finalizer: PrebehaviorFinalizer
    admission_callback: AdmissionCallback
    persistence: FinalizationPersistencePort
    attempted_candidate_ids: set[str]
    state: LifecycleState = LifecycleState.pending
    artifacts: GeneratedArtifacts = field(default_factory=GeneratedArtifacts)
    invocation_counts: dict[GeneratedStage, int] = field(default_factory=dict)
    owner_retry_counts: dict[GeneratedStage, int] = field(default_factory=dict)
    length_retry_counts: dict[GeneratedStage, int] = field(default_factory=dict)
    retry_feedback: dict[GeneratedStage, str] = field(default_factory=dict)
    retry_reasons: dict[GeneratedStage, str] = field(default_factory=dict)
    retry_controls: dict[GeneratedStage, CausalRetryControl] = field(
        default_factory=dict
    )
    transition_index_offset: int = 0
    resume_candidate_id: str | None = None
    resume_next_stage: GeneratedStage | None = None
    resume_artifacts: GeneratedArtifacts | None = None
    resume_invocation_counts: dict[GeneratedStage, int] = field(default_factory=dict)
    resume_owner_retry_counts: dict[GeneratedStage, int] = field(default_factory=dict)
    resume_length_retry_counts: dict[GeneratedStage, int] = field(default_factory=dict)
    resume_retry_feedback: dict[GeneratedStage, str] = field(default_factory=dict)
    resume_retry_reasons: dict[GeneratedStage, str] = field(default_factory=dict)
    resume_retry_controls: dict[GeneratedStage, CausalRetryControl] = field(
        default_factory=dict
    )
    transitions: list[LifecycleTransition] = field(default_factory=list)
    violations: list[LifecycleViolation] = field(default_factory=list)

    def _transition(
        self, state: LifecycleState, candidate_id: str | None, reason: str
    ) -> None:
        transition = LifecycleTransition(
            previous=self.state,
            current=state,
            candidate_id=candidate_id,
            reason=reason,
            transition_index=self.transition_index_offset + len(self.transitions),
            target_entry_point_id=self.entry.effective_target_id,
        )
        self.persistence.record_transition(transition)
        self.state = state
        self.transitions.append(transition)

    def _invoke_stage(
        self,
        candidate: Any,
        candidate_id: str,
        stage: GeneratedStage,
        final_tree_snapshot: FinalTreeSnapshot | None = None,
    ) -> tuple[LifecycleViolation, ...]:
        self._transition(
            LifecycleState(f"generating_{stage.value}"), candidate_id, "invoke stage"
        )
        invocation_index = self.invocation_counts.get(stage, 0)
        self.invocation_counts[stage] = invocation_index + 1
        visible_artifacts, visible_tree = self._stage_visible_artifacts(
            stage, final_tree_snapshot
        )
        invocation = StageInvocation(
            candidate_id=candidate_id,
            stage=stage,
            invocation_index=invocation_index,
            owner_retry_index=self.owner_retry_counts.get(stage, 0),
            artifacts=visible_artifacts,
            final_tree_digest=(
                final_tree_snapshot.digest if final_tree_snapshot is not None else None
            ),
            candidate_snapshot=candidate,
            retry_feedback=self.retry_feedback.get(stage),
            retry_reason=self.retry_reasons.get(stage),
            retry_control=self.retry_controls.get(stage),
        )
        try:
            result = self.stage_callbacks[stage](candidate, invocation)
        except StageAttemptFailure as exc:
            # Every stage helper performs exactly one provider request per
            # invocation. Finalization alone interprets retryability: provider-
            # correctable draft/protocol failures use the owner budget, while
            # projection infeasibility and compiler defects terminate.
            result = self._stage_attempt_failure_result(stage, exc)
        except Exception as exc:  # noqa: BLE001 - callback failure is lifecycle data
            result = self._unexpected_stage_failure(stage, exc)
        self.persistence.record_stage_result(invocation, result)
        if not result.violations:
            self.artifacts.set(stage, result.artifact)
        return result.violations

    def _stage_visible_artifacts(
        self,
        stage: GeneratedStage,
        final_tree_snapshot: FinalTreeSnapshot | None,
    ) -> tuple[GeneratedArtifacts, Any | None]:
        """Expose the invocation view of artifacts, injecting the final tree."""
        visible_artifacts = self.artifacts
        visible_tree = None
        if stage is GeneratedStage.behavior and final_tree_snapshot is not None:
            visible_tree = final_tree_snapshot.tree
            visible_artifacts = copy.copy(self.artifacts)
            visible_artifacts.tree = visible_tree
        return visible_artifacts, visible_tree

    def _stage_attempt_failure_result(
        self, stage: GeneratedStage, exc: StageAttemptFailure
    ) -> GeneratedStageResult:
        """Convert a typed stage failure into lifecycle evidence, budgeting lengths."""
        if (
            exc.code == StageAttemptFailure.COMPLETION_LENGTH_CODE
            and self.length_retry_counts.get(stage, 0) >= MAX_COMPLETION_LENGTH_RETRIES
        ):
            exc.code = StageAttemptFailure.SEMANTIC_DRAFT_LENGTH_CODE
            exc.retryable = False
        return GeneratedStageResult(
            artifact=None,
            evidence=exc,
            violations=(
                LifecycleViolation(
                    owner=stage,
                    code=exc.code,
                    detail=f"{exc.exception_type}: {exc.detail}",
                    retryable=exc.retryable,
                ),
            ),
        )

    def _unexpected_stage_failure(
        self, stage: GeneratedStage, exc: Exception
    ) -> GeneratedStageResult:
        """Convert an unexpected callback exception into lifecycle evidence."""
        call_name = {
            GeneratedStage.actor: CallName.actor_profile,
            GeneratedStage.narrative: CallName.narrative,
            GeneratedStage.tree: CallName.attack_tree,
            GeneratedStage.behavior: CallName.behavior_spec,
        }[stage]
        failure = StageAttemptFailure(
            call_name=call_name,
            exception=exc,
            phase="before_invocation",
            invoked=False,
        )
        return GeneratedStageResult(
            artifact=None,
            evidence=failure,
            violations=(
                LifecycleViolation(
                    owner=stage,
                    code="stage_exception",
                    detail=f"{failure.exception_type}: {failure.detail}",
                ),
            ),
        )

    def _route_violations(
        self, violations: Sequence[LifecycleViolation]
    ) -> GeneratedStage | None:
        self.violations.extend(violations)
        owner = earliest_generated_owner(violations)
        if owner is None:
            return None
        if any(
            item.owner is owner
            and item.code == StageAttemptFailure.COMPLETION_LENGTH_CODE
            for item in violations
        ):
            return self._route_completion_length_retry(owner)
        return self._route_semantic_retry(owner, violations)

    def _route_semantic_retry(
        self, owner: GeneratedStage, violations: Sequence[LifecycleViolation]
    ) -> GeneratedStage | None:
        """Route a non-length violation through the semantic owner-retry budget.

        Returns the owner to re-invoke, or ``None`` when the semantic
        owner-retry budget is exhausted (terminal for this candidate).
        """
        self.retry_reasons.pop(owner, None)
        self.retry_controls.pop(owner, None)
        used = self.owner_retry_counts.get(owner, 0)
        if used >= MAX_OWNER_RETRIES:
            return None
        self.owner_retry_counts[owner] = used + 1
        self.retry_feedback[owner] = (
            "; ".join(
                f"{item.code}: {item.detail}"
                for item in violations
                if item.owner is owner
            )
            or f"Retry {owner.value} to correct validation failure"
        )
        self.artifacts.invalidate_from(owner)
        return owner

    def _route_completion_length_retry(
        self, owner: GeneratedStage
    ) -> GeneratedStage | None:
        """Authorize the one completion-length retry for ``owner``.

        Returns the owner to re-invoke, or ``None`` when the one allowed
        length retry is already spent: a second length failure is terminal
        for this candidate and never consumes semantic owner-retry budget.
        """
        used = self.length_retry_counts.get(owner, 0)
        if used >= MAX_COMPLETION_LENGTH_RETRIES:
            return None
        self.length_retry_counts[owner] = used + 1
        self.retry_feedback[owner] = COMPLETION_LENGTH_RETRY_SUFFIXES[owner]
        self.retry_reasons[owner] = StageAttemptFailure.COMPLETION_LENGTH_CODE
        self.retry_controls[owner] = COMPLETION_LENGTH_RETRY_CONTROLS[owner]
        self.artifacts.invalidate_from(owner)
        return owner

    def _run_candidate(
        self,
        candidate: Any,
        candidate_id: str,
        verified_candidate: VerifiedCandidateSnapshot,
        next_stage: GeneratedStage = GeneratedStage.actor,
    ) -> CandidateTerminalResult:
        cursor = _CandidateCursor(
            next_stage=next_stage,
            suppress_durable_boundary=self._suppress_durable_boundary(candidate_id),
        )
        while True:
            outcome = self._run_candidate_stages(
                candidate, candidate_id, verified_candidate, cursor
            )
            if outcome == "terminal":
                return cursor.terminal
            if outcome == "retry":
                continue
            if self._admit_candidate(candidate, candidate_id, cursor) == "terminal":
                return cursor.terminal

    def _run_candidate_stages(
        self,
        candidate: Any,
        candidate_id: str,
        verified_candidate: VerifiedCandidateSnapshot,
        cursor: _CandidateCursor,
    ) -> str:
        """Advance every remaining generated stage; returns an outcome."""
        for stage in GENERATION_ORDER[GENERATION_ORDER.index(cursor.next_stage) :]:
            outcome = self._advance_stage(
                stage, candidate, candidate_id, verified_candidate, cursor
            )
            if outcome == "retry":
                return "retry"
            if outcome == "terminal":
                return "terminal"
        return "ok"

    def _advance_stage(
        self,
        stage: GeneratedStage,
        candidate: Any,
        candidate_id: str,
        verified_candidate: VerifiedCandidateSnapshot,
        cursor: _CandidateCursor,
    ) -> str:
        """Advance one generated stage, updating the cursor; returns outcome."""
        if stage is GeneratedStage.behavior:
            if cursor.snapshot is None:
                prepared = self._finalize_prebehavior(
                    candidate,
                    candidate_id,
                    verified_candidate,
                    cursor.suppress_durable_boundary,
                )
                cursor.suppress_durable_boundary = False
                if prepared.action == "retry":
                    cursor.next_stage = prepared.owner
                    return "retry"
                if prepared.action == "terminal":
                    cursor.terminal = prepared.result
                    return "terminal"
                cursor.snapshot = prepared.snapshot
                cursor.finalized_authority = prepared.authority
            # A successful behavior result may already be durable when a
            # process exits before deterministic admission. Reuse it; never
            # repeat the external behavior invocation.
            if self.artifacts.behavior is not None:
                return "ok"
        return self._invoke_stage_outcome(stage, candidate, candidate_id, cursor)

    def _invoke_stage_outcome(
        self,
        stage: GeneratedStage,
        candidate: Any,
        candidate_id: str,
        cursor: _CandidateCursor,
    ) -> str:
        """Invoke one stage and route its violations; returns an outcome."""
        stage_violations = self._invoke_stage(
            candidate, candidate_id, stage, cursor.snapshot
        )
        if not stage_violations:
            return "ok"
        owner = self._route_violations(stage_violations)
        if owner is None:
            cursor.terminal = CandidateTerminalResult(
                candidate_id,
                CandidateTerminalStatus.generation_or_finalization_failed,
                tuple(stage_violations),
            )
            return "terminal"
        if owner is not GeneratedStage.behavior:
            cursor.snapshot = None
            cursor.finalized_authority = None
        cursor.next_stage = owner
        return "retry"

    def _finalize_prebehavior(
        self,
        candidate: Any,
        candidate_id: str,
        verified_candidate: VerifiedCandidateSnapshot,
        suppress_durable_boundary: bool,
    ) -> _PreparedStage:
        """Run the prebehavior finalizer once; returns a prepared outcome."""
        if not suppress_durable_boundary:
            self._transition(
                LifecycleState.finalizing_prebehavior,
                candidate_id,
                "tree complete",
            )
        finalized = self.prebehavior_finalizer(
            CandidateFinalizationContext(candidate, verified_candidate),
            self.artifacts,
        )
        if finalized.violations:
            owner = self._route_violations(finalized.violations)
            if owner is None:
                return _PreparedStage(
                    "terminal",
                    result=CandidateTerminalResult(
                        candidate_id,
                        CandidateTerminalStatus.generation_or_finalization_failed,
                        tuple(finalized.violations),
                    ),
                )
            return _PreparedStage("retry", owner=owner)
        if finalized.snapshot is None:
            violation = LifecycleViolation(
                code="missing_final_tree_snapshot",
                detail="prebehavior finalizer returned no snapshot",
                retryable=False,
            )
            self.violations.append(violation)
            return _PreparedStage(
                "terminal",
                result=CandidateTerminalResult(
                    candidate_id,
                    CandidateTerminalStatus.generation_or_finalization_failed,
                    (violation,),
                ),
            )
        if finalized.repair_record is not None:
            self.persistence.record_repair(candidate_id, finalized.repair_record)
        return _PreparedStage(
            "proceed", snapshot=finalized.snapshot, authority=finalized
        )

    def _admit_candidate(
        self,
        candidate: Any,
        candidate_id: str,
        cursor: _CandidateCursor,
    ) -> str:
        """Run deterministic admission; returns a terminal or retry outcome."""
        admission_candidate, admission_artifacts = self._admission_views(
            candidate, candidate_id, cursor
        )
        decision = self.admission_callback(
            admission_candidate, admission_artifacts, cursor.snapshot
        )
        if decision.admitted:
            cursor.terminal = CandidateTerminalResult(
                candidate_id,
                CandidateTerminalStatus.admitted,
                admission=decision,
            )
            return "terminal"
        return self._route_admission_violations(candidate_id, cursor, decision)

    def _admission_views(
        self,
        candidate: Any,
        candidate_id: str,
        cursor: _CandidateCursor,
    ) -> tuple[Any, GeneratedArtifacts]:
        """Build the admission candidate and artifact views with digest checks."""
        if cursor.snapshot is None:
            raise RuntimeError("behavior completed without finalized tree snapshot")
        if self.state is not LifecycleState.admitting:
            self._transition(LifecycleState.admitting, candidate_id, "stages complete")
        admission_candidate = candidate
        admission_artifacts = copy.deepcopy(self.artifacts)
        verify_tree = getattr(cursor.snapshot, "verify_digest", None)
        if callable(verify_tree):
            verify_tree()
        admission_artifacts.tree = cursor.snapshot.tree
        if cursor.finalized_authority is not None:
            admission_candidate, admission_artifacts = self._authority_admission_views(
                cursor.finalized_authority,
                admission_candidate,
                admission_artifacts,
            )
        return admission_candidate, admission_artifacts

    def _authority_admission_views(
        self,
        finalized_authority: PrebehaviorFinalizationResult,
        admission_candidate: Any,
        admission_artifacts: GeneratedArtifacts,
    ) -> tuple[Any, GeneratedArtifacts]:
        """Swap in verified authority snapshots for the admission views."""
        if finalized_authority.candidate_snapshot is not None:
            finalized_authority.candidate_snapshot.verify_digest()
            admission_candidate = finalized_authority.candidate_snapshot.candidate
        for name in ("actor", "narrative"):
            authority = getattr(finalized_authority, f"{name}_snapshot")
            if authority is not None:
                authority.verify_digest()
                setattr(admission_artifacts, name, getattr(authority, name))
        return admission_candidate, admission_artifacts

    def _route_admission_violations(
        self,
        candidate_id: str,
        cursor: _CandidateCursor,
        decision: AdmissionDecision,
    ) -> str:
        """Route admission violations; returns a terminal or retry outcome."""
        owner = self._route_violations(decision.violations)
        if owner is None:
            cursor.terminal = CandidateTerminalResult(
                candidate_id,
                CandidateTerminalStatus.rejected,
                tuple(decision.violations),
                decision,
            )
            return "terminal"
        if owner is not GeneratedStage.behavior:
            cursor.snapshot = None
            cursor.finalized_authority = None
        cursor.next_stage = owner
        return "retry"

    def _suppress_durable_boundary(self, candidate_id: str) -> bool:
        """True when a resumed candidate already crossed the prebehavior edge."""
        return candidate_id == self.resume_candidate_id and self.state in {
            LifecycleState.finalizing_prebehavior,
            LifecycleState.generating_behavior,
            LifecycleState.admitting,
        }

    def run(self) -> TargetFinalizationResult:
        for ref in ordered_target_choice_refs(self.entry):
            ref_id = ref["candidate_id"]
            resuming = ref_id == self.resume_candidate_id
            if ref_id in self.attempted_candidate_ids and not resuming:
                continue
            # Invocation, owner-retry, and length-retry counters are
            # candidate-local traces.
            self._prepare_candidate_attempt(ref_id, resuming)
            terminal = self._attempt_candidate(ref, ref_id, resuming)
            terminal_state = (
                LifecycleState.admitted
                if terminal.status is CandidateTerminalStatus.admitted
                else LifecycleState.rejected
            )
            # The adapter atomically persists the terminal edge, decision, and
            # publication/quarantine evidence before local state advances.
            self._record_terminal(ref_id, terminal, terminal_state)
            if terminal.status is CandidateTerminalStatus.admitted:
                return self._result(ref_id, terminal.admission)
        self._transition(LifecycleState.exhausted, None, "candidate choices exhausted")
        return self._result(None, None)

    def _prepare_candidate_attempt(self, ref_id: str, resuming: bool) -> None:
        """Reset candidate-local counters and durable boundary for one attempt."""
        if not resuming:
            self._fresh_candidate_state(ref_id)
            return
        self._resume_candidate_state()

    def _resume_candidate_state(self) -> None:
        """Restore the durable per-attempt state persisted at interruption."""
        self.invocation_counts = dict(self.resume_invocation_counts)
        self.owner_retry_counts = dict(self.resume_owner_retry_counts)
        self.length_retry_counts = dict(self.resume_length_retry_counts)
        self.retry_feedback = dict(self.resume_retry_feedback)
        self.retry_reasons = dict(self.resume_retry_reasons)
        self.retry_controls = dict(self.resume_retry_controls)
        self.artifacts = self.resume_artifacts or GeneratedArtifacts()

    def _fresh_candidate_state(self, ref_id: str) -> None:
        """Start a brand-new attempt: counters, transition, and reservation."""
        self.invocation_counts = {}
        self.owner_retry_counts = {}
        self.length_retry_counts = {}
        self.retry_feedback = {}
        self.retry_reasons = {}
        self.retry_controls = {}
        self._transition(
            LifecycleState.revalidating_candidate,
            ref_id,
            "authoritative revalidation",
        )
        # Reserve only after the durable transition succeeds, but before
        # authoritative validation or any generation callback.
        self.attempted_candidate_ids.add(ref_id)

    def _attempt_candidate(
        self, ref: dict[str, Any], ref_id: str, resuming: bool
    ) -> CandidateTerminalResult:
        """Revalidate and run one reserved candidate choice."""
        try:
            validation = self.candidate_revalidator(ref)
        except Exception as exc:  # noqa: BLE001 - terminal lifecycle evidence
            return self._revalidation_exception_result(ref_id, exc)
        return self._validate_candidate_attempt(validation, ref_id, resuming)

    def _revalidation_exception_result(
        self, ref_id: str, exc: Exception
    ) -> CandidateTerminalResult:
        """Convert a revalidation crash into terminal rejected evidence."""
        violation = LifecycleViolation(
            code="candidate_revalidation_exception",
            detail=f"{type(exc).__name__}: {exc}",
            retryable=False,
        )
        self.violations.append(violation)
        return CandidateTerminalResult(
            ref_id, CandidateTerminalStatus.rejected, (violation,)
        )

    def _validate_candidate_attempt(
        self,
        validation: CandidateValidation,
        ref_id: str,
        resuming: bool,
    ) -> CandidateTerminalResult:
        """Qualify the revalidated candidate and run it, or reject it."""
        identity_violation = _candidate_identity_violation(
            ref_id, _canonical_candidate_id(validation)
        )
        if _validation_rejected(validation, identity_violation):
            return self._revalidation_failure_result(
                ref_id, validation, identity_violation
            )
        if not resuming:
            self._reset_candidate_local_state()
        return self._run_validated_attempt(validation, ref_id, resuming)

    def _run_validated_attempt(
        self,
        validation: CandidateValidation,
        ref_id: str,
        resuming: bool,
    ) -> CandidateTerminalResult:
        """Capture the verified snapshot and run the candidate attempt."""
        try:
            verified_candidate = self._capture_verified(validation)
        except Exception as exc:  # noqa: BLE001 - candidate evidence
            return self._snapshot_failure_result(ref_id, exc)
        try:
            return self._run_candidate(
                validation.candidate,
                ref_id,
                verified_candidate,
                self._resume_next_stage(resuming),
            )
        except FinalizationPersistenceError:
            raise
        except Exception as exc:  # noqa: BLE001 - lifecycle evidence
            return self._run_candidate_exception_result(ref_id, exc)

    def _revalidation_failure_result(
        self,
        ref_id: str,
        validation: CandidateValidation,
        identity_violation: LifecycleViolation | None,
    ) -> CandidateTerminalResult:
        """Aggregate revalidation violations into terminal rejected evidence."""
        violations = list(validation.violations)
        if identity_violation is not None:
            violations.append(identity_violation)
        if not violations:
            violations.append(
                LifecycleViolation(
                    code="candidate_revalidation_failed",
                    detail="authoritative candidate revalidation failed",
                    retryable=False,
                )
            )
        self.violations.extend(violations)
        return CandidateTerminalResult(
            ref_id, CandidateTerminalStatus.rejected, tuple(violations)
        )

    def _capture_verified(
        self, validation: CandidateValidation
    ) -> VerifiedCandidateSnapshot:
        """Capture and verify the candidate evidence snapshot."""
        verified_candidate = _capture_verified_candidate(validation.candidate)
        verified_candidate.verify_digest()
        return verified_candidate

    def _snapshot_failure_result(
        self, ref_id: str, exc: Exception
    ) -> CandidateTerminalResult:
        """Convert a candidate snapshot failure into terminal rejected evidence."""
        violation = LifecycleViolation(
            code="candidate_snapshot_failed",
            detail=f"{type(exc).__name__}: {exc}",
            retryable=False,
        )
        self.violations.append(violation)
        return CandidateTerminalResult(
            ref_id, CandidateTerminalStatus.rejected, (violation,)
        )

    def _reset_candidate_local_state(self) -> None:
        """Clear candidate-local retry traces before a fresh attempt."""
        self.artifacts = GeneratedArtifacts()
        self.owner_retry_counts = {}
        self.length_retry_counts = {}
        self.retry_reasons = {}

    def _resume_next_stage(self, resuming: bool) -> GeneratedStage:
        """Pick the resumed stage or the canonical first stage."""
        if resuming and self.resume_next_stage is not None:
            return self.resume_next_stage
        return GeneratedStage.actor

    def _run_candidate_exception_result(
        self, ref_id: str, exc: Exception
    ) -> CandidateTerminalResult:
        """Convert an unexpected candidate callback crash into lifecycle evidence."""
        if self.state is LifecycleState.admitting:
            from asago_scenario_generator.pipeline.finalization_admission import (
                PostbehaviorAdmissionReport,
            )
            from asago_scenario_generator.pipeline.finalization_gates import (
                AdmissionEvidenceId,
                GateCode,
                GateResult,
                GateViolation,
            )

            gate_violation = GateViolation(
                GateCode.admission_exception,
                f"{type(exc).__name__}: {exc}",
                None,
            )
            violation = gate_violation.lifecycle()
            admission = AdmissionDecision(
                False,
                (violation,),
                value=PostbehaviorAdmissionReport(
                    envelope=None,
                    gate_results=(
                        GateResult(
                            AdmissionEvidenceId.admission_exception,
                            (gate_violation,),
                        ),
                    ),
                ),
            )
            terminal_status = CandidateTerminalStatus.rejected
        else:
            violation = LifecycleViolation(
                code="lifecycle_callback_exception",
                detail=f"{type(exc).__name__}: {exc}",
                retryable=False,
            )
            admission = None
            terminal_status = CandidateTerminalStatus.generation_or_finalization_failed
        self.violations.append(violation)
        return CandidateTerminalResult(ref_id, terminal_status, (violation,), admission)

    def _record_terminal(
        self,
        ref_id: str,
        terminal: CandidateTerminalResult,
        terminal_state: LifecycleState,
    ) -> None:
        """Persist the terminal edge, decision, and local state advance."""
        self.persistence.record_candidate_result(ref_id, terminal)
        terminal_transition = LifecycleTransition(
            previous=self.state,
            current=terminal_state,
            candidate_id=ref_id,
            reason=f"candidate terminal status: {terminal.status.value}",
            transition_index=self.transition_index_offset + len(self.transitions),
            target_entry_point_id=self.entry.effective_target_id,
        )
        self.state = terminal_state
        self.transitions.append(terminal_transition)

    def _result(
        self,
        candidate_id: str | None,
        admission: AdmissionDecision | None,
    ) -> TargetFinalizationResult:
        """Build the machine's finalization result from local state."""
        return TargetFinalizationResult(
            state=self.state,
            candidate_id=candidate_id,
            admission=admission,
            attempted_candidate_ids=tuple(sorted(self.attempted_candidate_ids)),
            violations=tuple(self.violations),
            transitions=tuple(self.transitions),
        )


def fallback_candidates_for_target(
    plan: CoveragePlan,
    entry_point_id: str,
    *,
    taxonomy_resolver: Any,
    snapshot: Any,
    trusted_catalog: Sequence[dict[str, Any]],
    attempted_candidate_ids: set[str],
) -> list[Any]:
    """Compatibility loader with primary-first authoritative revalidation."""
    entry = next(
        (item for item in plan.targets if item.entry_point_id == entry_point_id), None
    )
    if entry is None:
        return []
    candidates: list[Any] = []
    for ref in ordered_target_choice_refs(entry):
        candidate = deserialize_qualified_candidate(ref)
        if candidate.candidate_id in attempted_candidate_ids:
            continue
        attempted_candidate_ids.add(candidate.candidate_id)
        revalidate_qualified_candidate(
            ref, taxonomy_resolver, snapshot, trusted_catalog
        )
        candidates.append(candidate)
    return candidates


def retry_directive_for(invocation: StageInvocation) -> RetryDirective | None:
    """Rebuild the typed retry directive for one explicit re-invocation.

    Returns ``None`` for a first attempt; a ``RetryDirective`` carrying the
    feedback and (for completion-length retries) the ``completion_length``
    reason otherwise.
    """
    if not (invocation.owner_retry_index or invocation.retry_reason):
        return None
    return RetryDirective(
        feedback=invocation.retry_feedback,
        reason=invocation.retry_reason,
        causal_control=invocation.retry_control,
        attempt_index=invocation.invocation_index,
    )


class AssertionsOnlyBehaviorPort:
    """Unwired adapter from finalization callbacks to one Call 3 attempt."""

    def __init__(self, prepared: Any) -> None:
        self.prepared = prepared

    def __call__(
        self, candidate: Any, invocation: StageInvocation
    ) -> GeneratedStageResult:
        if invocation.stage is not GeneratedStage.behavior:
            raise ValueError("assertions-only behavior port requires behavior stage")
        candidate_id = getattr(candidate, "candidate_id", None)
        if candidate_id != self.prepared.candidate_id:
            raise ValueError("behavior candidate differs from prepared projection")
        if invocation.final_tree_digest is None or invocation.artifacts.tree is None:
            raise ValueError("verified final-tree materialization is required")

        from asago_scenario_generator.pipeline.generate.stages import (
            generate_behavior_stage,
        )

        result = generate_behavior_stage(
            self.prepared,
            invocation.artifacts.narrative,
            invocation.artifacts.tree,
            retry_directive_for(invocation),
        )
        return GeneratedStageResult(result.artifact, result.evidence)


def make_assertions_only_behavior_callback(prepared: Any) -> AssertionsOnlyBehaviorPort:
    """Build the concrete single-attempt behavior callback without runner wiring."""
    return AssertionsOnlyBehaviorPort(prepared)


# Compatibility alias for callers that used the checkpoint's stage name.
LifecycleStage = GeneratedStage
