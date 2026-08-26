"""Target finalization lifecycle invariants for cmps.5 phase 2."""

from __future__ import annotations

from dataclasses import dataclass, replace

import pytest

from asago_scenario_generator.models.scenario import CallName
from asago_scenario_generator.pipeline.coverage_planning import (
    CoveragePlan,
    CoveragePlanEntry,
)
from asago_scenario_generator.pipeline.generate.stages import StageAttemptFailure
from asago_scenario_generator.pipeline.finalization import (
    COMPLETION_LENGTH_RETRY_SUFFIXES,
    GENERATION_ORDER,
    MAX_COMPLETION_LENGTH_RETRIES,
    MAX_OWNER_RETRIES,
    AdmissionDecision,
    CandidateTerminalStatus,
    CandidateValidation,
    GeneratedArtifacts,
    GeneratedStage,
    GeneratedStageResult,
    LifecycleState,
    LifecycleViolation,
    PrebehaviorFinalizationResult,
    StageInvocation,
    TargetFinalizationMachine,
    _CandidateCursor,
    earliest_generated_owner,
    fallback_candidates_for_target,
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
        self.repairs = []

    def record_transition(self, transition) -> None:
        self.transitions.append(transition)

    def record_stage_result(self, invocation, result) -> None:
        self.stage_results.append((invocation, result))

    def record_candidate_result(self, candidate_id, decision) -> None:
        self.candidate_results.append((candidate_id, decision))

    def record_repair(self, candidate_id, record) -> None:
        self.repairs.append((candidate_id, record))


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


def test_prebehavior_retry_restarts_at_the_declared_owner() -> None:
    finalization_count = 0

    def finalize(candidate, artifacts):
        nonlocal finalization_count
        finalization_count += 1
        if finalization_count == 1:
            return PrebehaviorFinalizationResult(
                None,
                (LifecycleViolation("tree needs retry", owner=GeneratedStage.tree),),
            )
        return PrebehaviorFinalizationResult(Snapshot(artifacts.tree))

    machine, calls, _ = _machine(finalize=finalize)

    result = machine.run()

    assert result.state is LifecycleState.admitted
    assert finalization_count == 2
    assert calls.count(GeneratedStage.tree) == 2


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


@pytest.mark.parametrize(
    "code", ["projection_infeasible", "canonical_compilation_failed"]
)
def test_nonretryable_stage_classifications_terminate_without_owner_retry(
    code: str,
) -> None:
    failure = StageAttemptFailure(
        call_name=CallName.attack_tree,
        exception=RuntimeError(code),
        phase="post_response",
        invoked=True,
        code=code,
        retryable=False,
    )

    def stage(candidate, invocation):
        if invocation.stage is GeneratedStage.tree:
            raise failure
        return GeneratedStageResult(invocation.stage.value)

    machine, _, persistence = _machine(
        callbacks={stage_name: stage for stage_name in GENERATION_ORDER}
    )
    result = machine.run()

    failed_results = [
        item
        for invocation, item in persistence.stage_results
        if invocation.stage is GeneratedStage.tree
    ]
    assert result.state is LifecycleState.exhausted
    assert len(failed_results) == 1
    assert failed_results[0].violations[0].code == code
    assert failed_results[0].violations[0].retryable is False
    assert machine.owner_retry_counts == {}


@pytest.mark.parametrize(
    "code", ["semantic_draft_protocol_failed", "semantic_draft_invalid"]
)
def test_provider_correctable_stage_classifications_use_owner_retry_budget(
    code: str,
) -> None:
    failure = StageAttemptFailure(
        call_name=CallName.attack_tree,
        exception=RuntimeError(code),
        phase="post_response",
        invoked=True,
        code=code,
        retryable=True,
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
        item
        for invocation, item in persistence.stage_results
        if invocation.stage is GeneratedStage.tree
    ]
    assert len(failed_results) == MAX_OWNER_RETRIES + 1
    assert all(item.violations[0].code == code for item in failed_results)
    assert all(item.violations[0].retryable is True for item in failed_results)
    assert machine.owner_retry_counts == {GeneratedStage.tree: MAX_OWNER_RETRIES}


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


def test_canonical_compilation_failure_is_not_retried_by_finalization() -> None:
    failure = StageAttemptFailure(
        call_name=CallName.narrative,
        exception=RuntimeError("canonical compiler defect"),
        phase="post_response",
        invoked=True,
        code="canonical_compilation_failed",
        retryable=False,
    )

    def stage(candidate, invocation):
        if invocation.stage is GeneratedStage.narrative:
            raise failure
        return GeneratedStageResult(invocation.stage.value)

    machine, _, persistence = _machine(
        callbacks={stage_name: stage for stage_name in GENERATION_ORDER}
    )
    result = machine.run()

    assert result.state is LifecycleState.exhausted
    failed = [
        item
        for invocation, item in persistence.stage_results
        if invocation.stage is GeneratedStage.narrative
    ]
    assert len(failed) == 1
    assert failed[0].violations[0].code == "canonical_compilation_failed"
    assert failed[0].violations[0].retryable is False
    assert machine.owner_retry_counts == {}


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
    assert terminal.violations[0].code == "semantic_draft_length_failed"
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
        (GeneratedStage.narrative, "max_completion_tokens", 8192, 4096),
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


# ---------------------------------------------------------------------------#
# Zero-coverage internals: fallback_candidates_for_target (CRAP slice 4)
# ---------------------------------------------------------------------------#


class TestFallbackCandidatesForTarget:
    """fallback_candidates_for_target: primary-first authoritative revalidation."""

    def _plan(self, entry: CoveragePlanEntry | None = None) -> CoveragePlan:
        return CoveragePlan(
            schema_version="1",
            completeness="complete",
            evidence_refs=[],
            targets=[entry or _entry()],
        )

    def _patch_loaders(self, monkeypatch) -> None:
        self.deserialized: list[dict] = []
        self.revalidated: list[dict] = []
        monkeypatch.setattr(
            "asago_scenario_generator.pipeline.finalization."
            "deserialize_qualified_candidate",
            lambda ref: self.deserialized.append(ref) or Candidate(ref["candidate_id"]),
        )
        monkeypatch.setattr(
            "asago_scenario_generator.pipeline.finalization."
            "revalidate_qualified_candidate",
            lambda ref, taxonomy_resolver, snapshot, trusted_catalog: (
                self.revalidated.append(ref)
            ),
        )

    def test_unknown_target_returns_empty(self, monkeypatch) -> None:
        self._patch_loaders(monkeypatch)

        candidates = fallback_candidates_for_target(
            self._plan(),
            "ep:v1:unknown",
            taxonomy_resolver=object(),
            snapshot=object(),
            trusted_catalog=[],
            attempted_candidate_ids=set(),
        )

        assert candidates == []
        assert self.deserialized == []

    def test_primary_first_then_fallbacks_with_revalidation(self, monkeypatch) -> None:
        self._patch_loaders(monkeypatch)
        attempted: set[str] = set()

        candidates = fallback_candidates_for_target(
            self._plan(_entry(primary="primary", fallbacks=("f1", "f2"))),
            "ep:v1:test",
            taxonomy_resolver=object(),
            snapshot=object(),
            trusted_catalog=[object()],
            attempted_candidate_ids=attempted,
        )

        assert [c.candidate_id for c in candidates] == ["primary", "f1", "f2"]
        # ordered_choices were reordered: primary first, then fallbacks.
        assert [ref["candidate_id"] for ref in self.revalidated] == [
            "primary",
            "f1",
            "f2",
        ]
        assert attempted == {"primary", "f1", "f2"}

    def test_attempted_candidates_are_skipped(self, monkeypatch) -> None:
        self._patch_loaders(monkeypatch)
        attempted = {"primary"}

        candidates = fallback_candidates_for_target(
            self._plan(_entry(primary="primary", fallbacks=("f1", "f2"))),
            "ep:v1:test",
            taxonomy_resolver=object(),
            snapshot=object(),
            trusted_catalog=[],
            attempted_candidate_ids=attempted,
        )

        assert [c.candidate_id for c in candidates] == ["f1", "f2"]
        assert attempted == {"primary", "f1", "f2"}

    def test_unlisted_primary_falls_back_to_available_choices(
        self, monkeypatch
    ) -> None:
        self._patch_loaders(monkeypatch)
        entry = CoveragePlanEntry(
            entry_point_id="ep:v1:test",
            entry_point_name="test",
            ordered_choices=[_ref("f1"), _ref("f2")],
            primary_candidate_id="ghost",
            primary_state="selected",
            fallback_available=[_ref("f1"), _ref("f2")],
        )

        candidates = fallback_candidates_for_target(
            self._plan(entry),
            "ep:v1:test",
            taxonomy_resolver=object(),
            snapshot=object(),
            trusted_catalog=[],
            attempted_candidate_ids=set(),
        )

        assert [c.candidate_id for c in candidates] == ["f1", "f2"]

    def test_duplicate_refs_are_deduplicated_across_sections(self, monkeypatch) -> None:
        self._patch_loaders(monkeypatch)
        entry = replace(
            _entry(primary="primary", fallbacks=("f1",)),
            fallback_available=[_ref("f1"), _ref("f1")],
        )

        candidates = fallback_candidates_for_target(
            self._plan(entry),
            "ep:v1:test",
            taxonomy_resolver=object(),
            snapshot=object(),
            trusted_catalog=[],
            attempted_candidate_ids=set(),
        )

        assert [c.candidate_id for c in candidates] == ["primary", "f1"]


class TestFinalizationMachineHelpers:
    """Direct coverage for the decomposed finalization machine helpers."""

    def test_default_transition_and_invocation_indexes_start_at_zero(self):
        machine, _calls, persistence = _machine()
        machine._transition(LifecycleState.revalidating_candidate, "c", "test")

        observed = []

        def callback(candidate, invocation):
            observed.append(invocation)
            return GeneratedStageResult("actor")

        machine.stage_callbacks[GeneratedStage.actor] = callback
        machine._invoke_stage(Candidate("c"), "c", GeneratedStage.actor)

        assert persistence.transitions[0].transition_index == 0
        assert observed[0].invocation_index == 0

    def test_primary_choice_ref_and_unique_choice_refs(self):
        from asago_scenario_generator.pipeline.finalization import (
            MAX_TARGET_CHOICES,
            _primary_choice_ref,
            _unique_choice_refs,
        )

        refs = [{"candidate_id": "a"}, {"candidate_id": "b"}]
        assert _primary_choice_ref(refs, "b") == {"candidate_id": "b"}
        assert _primary_choice_ref(refs, "missing") is None
        assert _unique_choice_refs(refs) == refs
        dupes = [
            {"candidate_id": "a"},
            {"candidate_id": "a"},
            {"candidate_id": "b"},
        ]
        assert _unique_choice_refs(dupes) == [
            {"candidate_id": "a"},
            {"candidate_id": "b"},
        ]
        many = [{"candidate_id": f"c{i}"} for i in range(5)]
        assert len(_unique_choice_refs(many)) == MAX_TARGET_CHOICES

    def test_stage_visible_artifacts_behavior_tree_injection(self):
        machine, _calls, _persistence = _machine()

        visible, tree = machine._stage_visible_artifacts(GeneratedStage.actor, None)
        assert tree is None
        assert visible is machine.artifacts

        snapshot = Snapshot("tree-value")
        visible, tree = machine._stage_visible_artifacts(
            GeneratedStage.behavior, snapshot
        )
        assert tree == "tree-value"
        assert visible is not machine.artifacts
        assert visible.tree == "tree-value"

        visible, tree = machine._stage_visible_artifacts(
            GeneratedStage.actor, snapshot
        )
        assert tree is None
        assert visible is machine.artifacts

    def test_invoke_stage_exposes_verified_tree_and_default_index(self):
        machine, _calls, persistence = _machine()
        observed = []

        def callback(candidate, invocation):
            observed.append(invocation)
            return GeneratedStageResult("behavior")

        machine.stage_callbacks[GeneratedStage.behavior] = callback
        machine._invoke_stage(
            Candidate("c"), "c", GeneratedStage.behavior, Snapshot("tree-value")
        )

        invocation = observed[0]
        assert invocation.invocation_index == 0
        assert invocation.final_tree_digest == "digest"
        assert invocation.artifacts.tree == "tree-value"
        assert persistence.stage_results[0][1].artifact == "behavior"

    def test_unexpected_stage_failure_is_not_marked_invoked(self):
        machine, _calls, persistence = _machine()

        def callback(candidate, invocation):
            raise RuntimeError("unexpected")

        machine.stage_callbacks[GeneratedStage.actor] = callback
        machine._invoke_stage(Candidate("c"), "c", GeneratedStage.actor)

        result = persistence.stage_results[0][1]
        assert result.evidence.invoked is False

    def test_stage_attempt_failure_result_length_and_budget(self):
        machine, _calls, _persistence = _machine()

        exc = StageAttemptFailure(
            call_name=CallName.narrative,
            exception=RuntimeError("len"),
            phase="post_response",
            invoked=True,
            code=StageAttemptFailure.COMPLETION_LENGTH_CODE,
        )
        result = machine._stage_attempt_failure_result(GeneratedStage.narrative, exc)
        assert result.evidence is exc
        assert result.violations[0].code == StageAttemptFailure.COMPLETION_LENGTH_CODE
        assert result.violations[0].retryable is True

        machine.length_retry_counts[GeneratedStage.narrative] = (
            MAX_COMPLETION_LENGTH_RETRIES
        )
        exhausted = StageAttemptFailure(
            call_name=CallName.narrative,
            exception=RuntimeError("len"),
            phase="post_response",
            invoked=True,
            code=StageAttemptFailure.COMPLETION_LENGTH_CODE,
        )
        result = machine._stage_attempt_failure_result(
            GeneratedStage.narrative, exhausted
        )
        assert (
            result.violations[0].code == StageAttemptFailure.SEMANTIC_DRAFT_LENGTH_CODE
        )
        assert result.violations[0].retryable is False

    def test_completion_length_retry_route_stops_at_budget(self):
        machine, _calls, _persistence = _machine()
        machine.length_retry_counts[GeneratedStage.actor] = (
            MAX_COMPLETION_LENGTH_RETRIES
        )

        assert machine._route_completion_length_retry(GeneratedStage.actor) is None
        assert machine.length_retry_counts[GeneratedStage.actor] == (
            MAX_COMPLETION_LENGTH_RETRIES
        )

    def test_finalize_prebehavior_proceed_and_repair(self):
        machine, _calls, persistence = _machine()
        repair = {"repair": 1}
        machine.prebehavior_finalizer = lambda candidate, artifacts: (
            PrebehaviorFinalizationResult(
                Snapshot(artifacts.tree), repair_record=repair
            )
        )

        prepared = machine._finalize_prebehavior(
            Candidate("c"), "c", Snapshot("v"), False
        )

        assert prepared.action == "proceed"
        assert prepared.snapshot.tree == machine.artifacts.tree
        assert prepared.authority.repair_record is repair
        assert persistence.repairs == [("c", repair)]
        assert (
            persistence.transitions[-1].current is LifecycleState.finalizing_prebehavior
        )

    def test_finalize_prebehavior_retry_and_terminal(self):
        machine, _calls, _persistence = _machine()

        machine.prebehavior_finalizer = lambda candidate, artifacts: (
            PrebehaviorFinalizationResult(
                None,
                violations=(LifecycleViolation("retry", owner=GeneratedStage.tree),),
            )
        )
        prepared = machine._finalize_prebehavior(
            Candidate("c"), "c", Snapshot("v"), False
        )
        assert prepared.action == "retry"
        assert prepared.owner is GeneratedStage.tree

        machine.prebehavior_finalizer = lambda candidate, artifacts: (
            PrebehaviorFinalizationResult(
                None, violations=(LifecycleViolation("hard", retryable=False),)
            )
        )
        prepared = machine._finalize_prebehavior(
            Candidate("c"), "c", Snapshot("v"), True
        )
        assert prepared.action == "terminal"
        assert (
            prepared.result.status
            is CandidateTerminalStatus.generation_or_finalization_failed
        )

        machine.prebehavior_finalizer = lambda candidate, artifacts: (
            PrebehaviorFinalizationResult(None)
        )
        prepared = machine._finalize_prebehavior(
            Candidate("c"), "c", Snapshot("v"), True
        )
        assert prepared.action == "terminal"
        assert prepared.result.violations[0].code == "missing_final_tree_snapshot"
        assert prepared.result.violations[0].retryable is False

    def test_admit_candidate_admitted_and_rejected_retry(self):
        machine, _calls, _persistence = _machine()
        machine.artifacts.set(GeneratedStage.actor, "actor-artifact")

        cursor = _CandidateCursor(
            next_stage=GeneratedStage.behavior, snapshot=Snapshot("t")
        )
        outcome = machine._admit_candidate(Candidate("c"), "c", cursor)
        assert outcome == "terminal"
        assert cursor.terminal.status is CandidateTerminalStatus.admitted
        assert cursor.terminal.admission.admitted is True

        def reject(candidate, artifacts, snapshot):
            return AdmissionDecision(
                False,
                (LifecycleViolation("retry", owner=GeneratedStage.tree),),
            )

        machine.admission_callback = reject
        cursor = _CandidateCursor(
            next_stage=GeneratedStage.behavior, snapshot=Snapshot("t")
        )
        outcome = machine._admit_candidate(Candidate("c"), "c", cursor)
        assert outcome == "retry"
        assert cursor.next_stage is GeneratedStage.tree

    def test_admission_views_transition_and_preserve_behavior_owner_state(self):
        machine, _calls, persistence = _machine()
        cursor = _CandidateCursor(snapshot=Snapshot("tree"))

        _candidate, artifacts = machine._admission_views(Candidate("c"), "c", cursor)

        assert persistence.transitions[-1].current is LifecycleState.admitting
        assert artifacts.tree == "tree"

        cursor.finalized_authority = object()
        outcome = machine._route_admission_violations(
            "c",
            cursor,
            AdmissionDecision(
                False,
                (LifecycleViolation("behavior retry", owner=GeneratedStage.behavior),),
            ),
        )
        assert outcome == "retry"
        assert cursor.snapshot is not None
        assert cursor.finalized_authority is not None

    def test_invoke_stage_outcome_ok_retry_terminal(self):
        machine, calls, persistence = _machine()
        cursor = _CandidateCursor()

        outcome = machine._invoke_stage_outcome(
            GeneratedStage.actor, Candidate("c"), "c", cursor
        )
        assert outcome == "ok"
        assert calls == [GeneratedStage.actor]

        def flaky(candidate, invocation):
            raise StageAttemptFailure(
                call_name=CallName.actor_profile,
                exception=RuntimeError("x"),
                phase="invocation",
                invoked=True,
                retryable=True,
            )

        machine.stage_callbacks[GeneratedStage.actor] = flaky
        outcome = machine._invoke_stage_outcome(
            GeneratedStage.actor, Candidate("c"), "c", cursor
        )
        assert outcome == "retry"
        assert cursor.next_stage is GeneratedStage.actor

        def hard(candidate, invocation):
            raise StageAttemptFailure(
                call_name=CallName.actor_profile,
                exception=RuntimeError("x"),
                phase="invocation",
                invoked=True,
                retryable=False,
            )

        machine.stage_callbacks[GeneratedStage.actor] = hard
        outcome = machine._invoke_stage_outcome(
            GeneratedStage.actor, Candidate("c"), "c", cursor
        )
        assert outcome == "terminal"
        assert (
            cursor.terminal.status
            is CandidateTerminalStatus.generation_or_finalization_failed
        )

        machine, _calls, _persistence = _machine()
        cursor = _CandidateCursor(snapshot=Snapshot("tree"))
        machine.stage_callbacks[GeneratedStage.actor] = lambda candidate, invocation: (
            GeneratedStageResult(
                None,
                violations=(
                    LifecycleViolation(
                        "behavior retry", owner=GeneratedStage.behavior
                    ),
                ),
            )
        )
        outcome = machine._invoke_stage_outcome(
            GeneratedStage.actor, Candidate("c"), "c", cursor
        )
        assert outcome == "retry"
        assert cursor.snapshot is not None

    def test_advance_stage_reuses_durable_behavior(self):
        machine, calls, _persistence = _machine()
        machine.artifacts.set(GeneratedStage.behavior, "durable-behavior")
        cursor = _CandidateCursor(snapshot=Snapshot("t"))

        outcome = machine._advance_stage(
            GeneratedStage.behavior, Candidate("c"), "c", Snapshot("v"), cursor
        )

        assert outcome == "ok"
        assert calls == []

        machine, _calls, _persistence = _machine()
        cursor = _CandidateCursor(suppress_durable_boundary=True)
        outcome = machine._advance_stage(
            GeneratedStage.behavior, Candidate("c"), "c", Snapshot("v"), cursor
        )
        assert outcome == "ok"
        assert cursor.suppress_durable_boundary is False

    def test_prepare_candidate_attempt_and_reset_local_state(self):
        machine, _calls, _persistence = _machine()
        machine.resume_invocation_counts = {GeneratedStage.actor: 3}

        machine._prepare_candidate_attempt("c", resuming=True)
        assert machine.invocation_counts == {GeneratedStage.actor: 3}

        machine._prepare_candidate_attempt("c", resuming=False)
        assert machine.invocation_counts == {}
        assert machine.state is LifecycleState.revalidating_candidate
        assert "c" in machine.attempted_candidate_ids

        machine._reset_candidate_local_state()
        assert machine.artifacts.get(GeneratedStage.actor) is None
        assert machine.owner_retry_counts == {}
        assert machine.length_retry_counts == {}
        assert machine.retry_reasons == {}

    def test_validate_candidate_attempt_paths(self):
        machine, _calls, _persistence = _machine()

        terminal = machine._validate_candidate_attempt(
            CandidateValidation(
                None, (LifecycleViolation("invalid", retryable=False),)
            ),
            "c",
            False,
        )
        assert terminal.status is CandidateTerminalStatus.rejected
        assert terminal.violations[0].code == "invalid"

        terminal = machine._validate_candidate_attempt(
            CandidateValidation(Candidate("other")), "c", False
        )
        assert terminal.status is CandidateTerminalStatus.rejected
        assert terminal.violations[0].code == "candidate_identity_mismatch"

        terminal = machine._validate_candidate_attempt(
            CandidateValidation(Candidate("c")), "c", False
        )
        assert terminal.status is CandidateTerminalStatus.admitted

    def test_failure_helpers_mark_terminal_violations_nonretryable(self):
        machine, _calls, _persistence = _machine()

        terminal = machine._revalidation_exception_result("c", RuntimeError("boom"))
        assert terminal.violations[0].retryable is False

        terminal = machine._revalidation_failure_result(
            "c", CandidateValidation(None), None
        )
        assert terminal.violations[0].retryable is False

        terminal = machine._snapshot_failure_result("c", RuntimeError("boom"))
        assert terminal.violations[0].retryable is False

    def test_run_candidate_exception_result_admitting_and_other(self):
        machine, _calls, _persistence = _machine()

        machine.state = LifecycleState.admitting
        terminal = machine._run_candidate_exception_result("c", RuntimeError("boom"))
        assert terminal.status is CandidateTerminalStatus.rejected
        assert terminal.admission is not None
        assert terminal.admission.value is not None
        assert terminal.admission.admitted is False

        machine.state = LifecycleState.generating_actor
        terminal = machine._run_candidate_exception_result("c", RuntimeError("boom"))
        assert (
            terminal.status is CandidateTerminalStatus.generation_or_finalization_failed
        )
        assert terminal.admission is None
        assert terminal.violations[0].code == "lifecycle_callback_exception"
        assert terminal.violations[0].retryable is False

    def test_candidate_identity_violation_helper(self):
        from asago_scenario_generator.pipeline.finalization import (
            _candidate_identity_violation,
        )

        assert _candidate_identity_violation("c", "c") is None
        assert _candidate_identity_violation("c", None) is None
        violation = _candidate_identity_violation("c", "other")
        assert violation is not None
        assert violation.code == "candidate_identity_mismatch"

    def test_record_terminal_and_result(self):
        from asago_scenario_generator.pipeline.finalization import (
            CandidateTerminalResult,
        )

        machine, _calls, persistence = _machine()
        terminal = CandidateTerminalResult("c", CandidateTerminalStatus.admitted)

        machine._record_terminal("c", terminal, LifecycleState.admitted)

        assert machine.state is LifecycleState.admitted
        assert len(persistence.candidate_results) == 1
        result = machine._result("c", None)
        assert result.candidate_id == "c"
        assert result.transitions
        exhausted = machine._result(None, None)
        assert exhausted.candidate_id is None

    def test_resume_state_defaults_and_stage_selection(self):
        machine, _calls, _persistence = _machine()
        machine._resume_candidate_state()
        assert isinstance(machine.artifacts, GeneratedArtifacts)

        restored = GeneratedArtifacts(actor="restored")
        machine.resume_artifacts = restored
        machine._resume_candidate_state()
        assert machine.artifacts is restored

        machine.resume_next_stage = GeneratedStage.tree
        assert machine._resume_next_stage(True) is GeneratedStage.tree
        assert machine._resume_next_stage(False) is GeneratedStage.actor
        machine.resume_next_stage = None
        assert machine._resume_next_stage(True) is GeneratedStage.actor

    def test_suppress_durable_boundary_requires_matching_resumed_active_state(self):
        machine, _calls, _persistence = _machine()
        machine.resume_candidate_id = "c"
        machine.state = LifecycleState.generating_behavior
        assert machine._suppress_durable_boundary("c") is True

        machine.resume_candidate_id = "other"
        assert machine._suppress_durable_boundary("c") is False
        machine.resume_candidate_id = "c"
        machine.state = LifecycleState.pending
        assert machine._suppress_durable_boundary("c") is False

    def test_run_stops_after_first_admitted_candidate(self):
        machine, calls, persistence = _machine()

        result = machine.run()

        assert result.state is LifecycleState.admitted
        assert calls == list(GENERATION_ORDER)
        assert len(persistence.candidate_results) == 1
