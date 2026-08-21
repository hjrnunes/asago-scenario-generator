"""Target finalization lifecycle invariants for cmps.5 phase 2."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from asago_scenario_generator.models.scenario import CallName
from asago_scenario_generator.pipeline.coverage_planning import CoveragePlanEntry
from asago_scenario_generator.pipeline.generate.stages import StageAttemptFailure
from asago_scenario_generator.pipeline.finalization import (
    COMPLETION_LENGTH_RETRY_SUFFIXES,
    GENERATION_ORDER,
    MAX_COMPLETION_LENGTH_RETRIES,
    MAX_OWNER_RETRIES,
    AdmissionDecision,
    CandidateTerminalStatus,
    CandidateValidation,
    GeneratedStage,
    GeneratedStageResult,
    LifecycleState,
    LifecycleViolation,
    PrebehaviorFinalizationResult,
    StageInvocation,
    TargetFinalizationMachine,
    earliest_generated_owner,
    ordered_target_choice_refs,
)


@dataclass(frozen=True)
class Candidate:
    candidate_id: str


@dataclass(frozen=True)
class Snapshot:
    tree: object
    digest: str = "digest"


class PersistenceFake:
    def __init__(self) -> None:
        self.transitions = []
        self.stage_results = []
        self.candidate_results = []

    def record_transition(self, transition) -> None:
        self.transitions.append(transition)

    def record_stage_result(self, invocation, result) -> None:
        self.stage_results.append((invocation, result))

    def record_candidate_result(self, candidate_id, decision) -> None:
        self.candidate_results.append((candidate_id, decision))


def _ref(candidate_id: str) -> dict:
    return {"candidate_id": candidate_id}


def _entry(
    *, primary: str = "primary", fallbacks: tuple[str, ...] = ("fallback",)
) -> CoveragePlanEntry:
    # Deliberately put primary second to prove selected-primary ordering wins.
    ordered = [_ref(candidate_id) for candidate_id in (*fallbacks, primary)]
    return CoveragePlanEntry(
        entry_point_id="ep:v1:test",
        entry_point_name="test",
        ordered_choices=ordered,
        primary_candidate_id=primary,
        primary_state="selected",
        fallback_available=[_ref(candidate_id) for candidate_id in fallbacks],
    )


def _machine(
    *,
    entry: CoveragePlanEntry | None = None,
    callbacks=None,
    revalidate=None,
    finalize=None,
    admit=None,
    attempted=None,
):
    calls: list[GeneratedStage] = []

    def default_stage(candidate, invocation):
        calls.append(invocation.stage)
        return GeneratedStageResult(
            artifact=f"{candidate.candidate_id}:{invocation.stage.value}:{invocation.invocation_index}"
        )

    persistence = PersistenceFake()
    machine = TargetFinalizationMachine(
        entry=entry or _entry(fallbacks=()),
        stage_callbacks=callbacks
        or {stage: default_stage for stage in GENERATION_ORDER},
        candidate_revalidator=revalidate
        or (lambda ref: CandidateValidation(Candidate(ref["candidate_id"]))),
        prebehavior_finalizer=finalize
        or (
            lambda candidate, artifacts: PrebehaviorFinalizationResult(
                Snapshot(artifacts.tree)
            )
        ),
        admission_callback=admit
        or (lambda candidate, artifacts, snapshot: AdmissionDecision(True)),
        persistence=persistence,
        attempted_candidate_ids=attempted if attempted is not None else set(),
    )
    return machine, calls, persistence


@pytest.mark.parametrize("owner", GENERATION_ORDER)
def test_retry_matrix_regenerates_exact_owner_and_downstream(owner) -> None:
    admission_calls = 0

    def admit(candidate, artifacts, snapshot):
        nonlocal admission_calls
        admission_calls += 1
        if admission_calls == 1:
            return AdmissionDecision(False, (LifecycleViolation("retry", owner=owner),))
        return AdmissionDecision(True)

    machine, calls, _ = _machine(admit=admit)
    result = machine.run()

    assert result.state is LifecycleState.admitted
    owner_offset = GENERATION_ORDER.index(owner)
    for index, stage in enumerate(GENERATION_ORDER):
        assert calls.count(stage) == (1 if index < owner_offset else 2)
    assert machine.owner_retry_counts == {owner: 1}


def test_upstream_retry_increments_downstream_invocation_not_retry_budget() -> None:
    admission_calls = 0

    def admit(candidate, artifacts, snapshot):
        nonlocal admission_calls
        admission_calls += 1
        if admission_calls == 1:
            return AdmissionDecision(
                False, (LifecycleViolation("actor owns", owner=GeneratedStage.actor),)
            )
        return AdmissionDecision(True)

    machine, _, persistence = _machine(admit=admit)
    machine.run()

    behavior_invocations = [
        invocation
        for invocation, _ in persistence.stage_results
        if invocation.stage is GeneratedStage.behavior
    ]
    assert [item.invocation_index for item in behavior_invocations] == [0, 1]
    assert [item.owner_retry_index for item in behavior_invocations] == [0, 0]
    assert machine.owner_retry_counts == {GeneratedStage.actor: 1}


def test_owner_retry_budgets_are_separate() -> None:
    owners = iter(
        (
            GeneratedStage.tree,
            GeneratedStage.narrative,
            GeneratedStage.narrative,
        )
    )

    def admit(candidate, artifacts, snapshot):
        try:
            owner = next(owners)
        except StopIteration:
            return AdmissionDecision(True)
        return AdmissionDecision(False, (LifecycleViolation("retry", owner=owner),))

    machine, _, _ = _machine(admit=admit)
    result = machine.run()

    assert result.state is LifecycleState.admitted
    assert machine.owner_retry_counts == {
        GeneratedStage.tree: 1,
        GeneratedStage.narrative: MAX_OWNER_RETRIES,
    }


def test_aggregate_violations_choose_earliest_generated_owner() -> None:
    violations = (
        LifecycleViolation("behavior", owner=GeneratedStage.behavior),
        LifecycleViolation("tree", owner=GeneratedStage.tree),
        LifecycleViolation("narrative", owner=GeneratedStage.narrative),
    )
    assert earliest_generated_owner(violations) is GeneratedStage.narrative


def test_projection_owned_violation_is_nonretryable_and_advances_choice() -> None:
    generated_candidates: list[str] = []

    def revalidate(ref):
        if ref["candidate_id"] == "primary":
            return CandidateValidation(
                None,
                (
                    LifecycleViolation(
                        "projection mismatch", code="projection", retryable=False
                    ),
                ),
            )
        return CandidateValidation(Candidate(ref["candidate_id"]))

    def stage(candidate, invocation):
        generated_candidates.append(candidate.candidate_id)
        return GeneratedStageResult(invocation.stage.value)

    machine, _, _ = _machine(
        entry=_entry(),
        revalidate=revalidate,
        callbacks={stage_name: stage for stage_name in GENERATION_ORDER},
    )
    result = machine.run()

    assert result.candidate_id == "fallback"
    assert generated_candidates == ["fallback"] * len(GENERATION_ORDER)


def test_revalidation_identity_substitution_rejects_reserved_ref_and_cannot_reuse() -> (
    None
):
    generated_candidates: list[str] = []
    attempted: set[str] = set()

    def revalidate(ref):
        # Persisted A attempts to substitute canonical B.  The real B fallback
        # remains independently eligible and may only be generated as B.
        return CandidateValidation(Candidate("B"))

    def stage(candidate, invocation):
        generated_candidates.append(candidate.candidate_id)
        return GeneratedStageResult(invocation.stage.value)

    machine, _, persistence = _machine(
        entry=_entry(primary="A", fallbacks=("B",)),
        revalidate=revalidate,
        callbacks={stage_name: stage for stage_name in GENERATION_ORDER},
        attempted=attempted,
    )
    result = machine.run()

    assert result.candidate_id == "B"
    assert generated_candidates == ["B"] * len(GENERATION_ORDER)
    assert attempted == {"A", "B"}
    assert [candidate_id for candidate_id, _ in persistence.candidate_results] == [
        "A",
        "B",
    ]
    mismatch = persistence.candidate_results[0][1]
    assert mismatch.status is CandidateTerminalStatus.rejected
    assert mismatch.violations[0].code == "candidate_identity_mismatch"

    second, second_calls, _ = _machine(
        entry=_entry(primary="A", fallbacks=("B",)), attempted=attempted
    )
    assert second.run().state is LifecycleState.exhausted
    assert second_calls == []


def test_primary_is_first_then_fallbacks_bounded_to_three() -> None:
    entry = _entry(primary="p", fallbacks=("f1", "f2", "f3", "f4"))
    assert [ref["candidate_id"] for ref in ordered_target_choice_refs(entry)] == [
        "p",
        "f1",
        "f2",
    ]


def test_fallback_progression_exhaustion_and_global_no_reuse() -> None:
    attempted = {"primary"}
    revalidated: list[str] = []

    def reject(ref):
        revalidated.append(ref["candidate_id"])
        return CandidateValidation(
            None,
            (LifecycleViolation("invalid", retryable=False),),
        )

    machine, calls, _ = _machine(
        entry=_entry(fallbacks=("f1", "f2", "f3")),
        revalidate=reject,
        attempted=attempted,
    )
    result = machine.run()

    assert result.state is LifecycleState.exhausted
    assert revalidated == ["f1", "f2"]  # max three includes skipped primary
    assert calls == []
    assert attempted == {"primary", "f1", "f2"}


def test_no_fallback_or_revalidation_after_admission() -> None:
    revalidated: list[str] = []

    def revalidate(ref):
        revalidated.append(ref["candidate_id"])
        return CandidateValidation(Candidate(ref["candidate_id"]))

    machine, _, _ = _machine(entry=_entry(), revalidate=revalidate)
    result = machine.run()

    assert result.state is LifecycleState.admitted
    assert revalidated == ["primary"]


def test_prebehavior_finalization_is_reachable_and_precedes_behavior() -> None:
    events: list[str] = []

    def stage(candidate, invocation):
        events.append(invocation.stage.value)
        return GeneratedStageResult(invocation.stage.value)

    def finalize(candidate, artifacts):
        events.append("finalize")
        assert artifacts.tree is not None
        assert artifacts.behavior is None
        return PrebehaviorFinalizationResult(Snapshot(artifacts.tree))

    machine, _, _ = _machine(
        callbacks={stage_name: stage for stage_name in GENERATION_ORDER},
        finalize=finalize,
    )
    machine.run()

    assert events == ["actor", "narrative", "tree", "finalize", "behavior"]


def test_stage_retry_exhaustion_records_terminal_before_fallback() -> None:
    calls: list[tuple[str, GeneratedStage]] = []

    def stage(candidate, invocation):
        calls.append((candidate.candidate_id, invocation.stage))
        if (
            candidate.candidate_id == "primary"
            and invocation.stage is GeneratedStage.tree
        ):
            return GeneratedStageResult(
                None,
                violations=(
                    LifecycleViolation("tree failed", owner=GeneratedStage.tree),
                ),
            )
        return GeneratedStageResult(invocation.stage.value)

    machine, _, persistence = _machine(
        entry=_entry(),
        callbacks={stage_name: stage for stage_name in GENERATION_ORDER},
    )
    result = machine.run()

    assert result.candidate_id == "fallback"
    assert calls.count(("primary", GeneratedStage.tree)) == MAX_OWNER_RETRIES + 1
    assert [item[0] for item in persistence.candidate_results] == [
        "primary",
        "fallback",
    ]
    assert persistence.candidate_results[0][1].status is (
        CandidateTerminalStatus.generation_or_finalization_failed
    )
    assert (
        persistence.candidate_results[1][1].status is CandidateTerminalStatus.admitted
    )


def test_missing_final_tree_snapshot_records_one_terminal_result() -> None:
    def finalize(candidate, artifacts):
        if candidate.candidate_id == "primary":
            return PrebehaviorFinalizationResult(None)
        return PrebehaviorFinalizationResult(Snapshot(artifacts.tree))

    machine, _, persistence = _machine(entry=_entry(), finalize=finalize)
    assert machine.run().candidate_id == "fallback"

    assert [item[0] for item in persistence.candidate_results] == [
        "primary",
        "fallback",
    ]
    failed = persistence.candidate_results[0][1]
    assert failed.status is CandidateTerminalStatus.generation_or_finalization_failed
    assert failed.violations[0].code == "missing_final_tree_snapshot"


def test_nonretryable_prebehavior_violation_records_one_terminal_result() -> None:
    def finalize(candidate, artifacts):
        if candidate.candidate_id == "primary":
            return PrebehaviorFinalizationResult(
                None,
                (
                    LifecycleViolation(
                        "projection-owned finalization failure",
                        code="projection",
                        retryable=False,
                    ),
                ),
            )
        return PrebehaviorFinalizationResult(Snapshot(artifacts.tree))

    machine, _, persistence = _machine(entry=_entry(), finalize=finalize)
    assert machine.run().candidate_id == "fallback"

    assert len(persistence.candidate_results) == 2
    assert len({item[0] for item in persistence.candidate_results}) == 2
    assert persistence.candidate_results[0][1].status is (
        CandidateTerminalStatus.generation_or_finalization_failed
    )


def test_stage_attempt_failure_evidence_is_persisted_on_every_failed_invocation() -> (
    None
):
    failure = StageAttemptFailure(
        call_name=CallName.attack_tree,
        exception=ValueError("parse rejected"),
        phase="post_response",
        invoked=True,
        system_prompt="system",
        user_prompt="user",
    )

    def stage(candidate, invocation):
        if invocation.stage is GeneratedStage.tree:
            raise failure
        return GeneratedStageResult(invocation.stage.value)

    machine, _, persistence = _machine(
        callbacks={stage_name: stage for stage_name in GENERATION_ORDER}
    )
    machine.run()

    failed_results = [
        result
        for invocation, result in persistence.stage_results
        if invocation.stage is GeneratedStage.tree
    ]
    assert len(failed_results) == MAX_OWNER_RETRIES + 1
    assert all(result.evidence is failure for result in failed_results)
    assert all(
        result.violations[0].code == "stage_attempt_failed" for result in failed_results
    )


def test_actor_attempt_failure_consumes_the_semantic_owner_budget() -> None:
    """Actor stage attempts are exactly one request and retried by the lifecycle.

    The hidden in-helper length retry is gone: every generated stage,
    including actor, participates in the semantic owner-retry budget.
    """
    failure = StageAttemptFailure(
        call_name=CallName.actor_profile,
        exception=RuntimeError("actor endpoint failed"),
        phase="invocation",
        invoked=True,
        system_prompt="system",
        user_prompt="user",
    )

    def stage(candidate, invocation):
        if invocation.stage is GeneratedStage.actor:
            raise failure
        return GeneratedStageResult(invocation.stage.value)

    machine, _, persistence = _machine(
        callbacks={stage_name: stage for stage_name in GENERATION_ORDER}
    )
    result = machine.run()

    assert result.state is LifecycleState.exhausted
    failed_results = [
        result
        for invocation, result in persistence.stage_results
        if invocation.stage is GeneratedStage.actor
    ]
    assert len(failed_results) == MAX_OWNER_RETRIES + 1
    assert all(result.evidence is failure for result in failed_results)
    assert all(result.violations[0].retryable is True for result in failed_results)
    assert all(
        result.violations[0].code == "stage_attempt_failed" for result in failed_results
    )
    assert machine.owner_retry_counts == {GeneratedStage.actor: MAX_OWNER_RETRIES}


def _completion_length_failure() -> StageAttemptFailure:
    return StageAttemptFailure(
        call_name=CallName.actor_profile,
        exception=RuntimeError("completion truncated"),
        phase="invocation",
        invoked=True,
        code=StageAttemptFailure.COMPLETION_LENGTH_CODE,
        finish_reason="length",
        prompt_tokens=30,
        completion_tokens=15,
    )


def test_second_completion_length_failure_is_terminal_without_semantic_budget() -> None:
    """One length retry per stage; a second length failure ends the candidate.

    The retried invocation carries the approved suffix and the
    ``completion_length`` reason, and the semantic owner-retry budget is
    never consumed.
    """
    failure = _completion_length_failure()

    def stage(candidate, invocation):
        raise failure

    machine, _, persistence = _machine(
        callbacks={stage_name: stage for stage_name in GENERATION_ORDER}
    )
    result = machine.run()

    assert result.state is LifecycleState.exhausted
    terminal = persistence.candidate_results[0][1]
    assert terminal.status is CandidateTerminalStatus.generation_or_finalization_failed
    actor_results = [
        (invocation, outcome)
        for invocation, outcome in persistence.stage_results
        if invocation.stage is GeneratedStage.actor
    ]
    assert len(actor_results) == MAX_COMPLETION_LENGTH_RETRIES + 1
    retry_invocation = actor_results[1][0]
    assert retry_invocation.retry_reason == "completion_length"
    assert (
        retry_invocation.retry_feedback
        == COMPLETION_LENGTH_RETRY_SUFFIXES[GeneratedStage.actor]
    )
    assert machine.length_retry_counts == {GeneratedStage.actor: 1}
    assert machine.owner_retry_counts == {}


def test_completion_length_retry_then_success_admits_without_semantic_budget() -> None:
    """A successful length retry admits; the length retry is not an owner retry."""
    failure = _completion_length_failure()
    attempts = 0

    def stage(candidate, invocation):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise failure
        return GeneratedStageResult(invocation.stage.value)

    machine, _, persistence = _machine(
        callbacks={stage_name: stage for stage_name in GENERATION_ORDER}
    )
    result = machine.run()

    assert result.state is LifecycleState.admitted
    actor_invocations = [
        invocation
        for invocation, _ in persistence.stage_results
        if invocation.stage is GeneratedStage.actor
    ]
    assert [item.invocation_index for item in actor_invocations] == [0, 1]
    assert [item.owner_retry_index for item in actor_invocations] == [0, 0]
    assert actor_invocations[1].retry_reason == "completion_length"
    assert machine.length_retry_counts == {GeneratedStage.actor: 1}
    assert machine.owner_retry_counts == {}


@pytest.mark.parametrize(
    ("stage", "field", "initial", "retry"),
    (
        (GeneratedStage.actor, "response_schema", "standard", "compact-v1"),
        (GeneratedStage.narrative, "max_completion_tokens", 16384, 8192),
        (GeneratedStage.tree, "temperature", 0.4, 0.1),
        (GeneratedStage.behavior, "response_schema", "standard", "compact-v1"),
    ),
)
def test_completion_length_retry_selects_one_approved_causal_control(
    stage, field, initial, retry
) -> None:
    failure = _completion_length_failure()
    invocations: list[StageInvocation] = []

    def callback(candidate, invocation):
        invocations.append(invocation)
        if invocation.stage is stage and invocation.invocation_index == 0:
            raise failure
        return GeneratedStageResult(invocation.stage.value)

    machine, _, _ = _machine(
        callbacks={stage_name: callback for stage_name in GENERATION_ORDER}
    )
    assert machine.run().state is LifecycleState.admitted

    retry_invocation = next(
        item
        for item in invocations
        if item.stage is stage and item.invocation_index == 1
    )
    control = retry_invocation.retry_control
    assert control is not None
    assert control.field == field
    assert control.initial_value == initial
    assert control.retry_value == retry
    assert retry_invocation.total_request_budget == 2


def test_semantic_failure_after_length_retry_clears_the_length_reason() -> None:
    """Semantic routing drops a stale length reason before re-invoking."""
    failure = _completion_length_failure()
    invocations: list[StageInvocation] = []
    admission_calls = 0

    def stage(candidate, invocation):
        invocations.append(invocation)
        if len(invocations) == 1:
            raise failure
        return GeneratedStageResult(invocation.stage.value)

    def admit(candidate, artifacts, snapshot):
        nonlocal admission_calls
        admission_calls += 1
        if admission_calls == 1:
            return AdmissionDecision(
                False, (LifecycleViolation("semantic", owner=GeneratedStage.actor),)
            )
        return AdmissionDecision(True)

    machine, _, _ = _machine(
        callbacks={stage_name: stage for stage_name in GENERATION_ORDER},
        admit=admit,
    )
    result = machine.run()

    assert result.state is LifecycleState.admitted
    actor_invocations = [
        item for item in invocations if item.stage is GeneratedStage.actor
    ]
    assert [item.retry_reason for item in actor_invocations] == [
        None,
        "completion_length",
        None,
    ]
    assert machine.length_retry_counts == {GeneratedStage.actor: 1}
    assert machine.owner_retry_counts == {GeneratedStage.actor: 1}
