"""Deterministic inventory-validation predicates for manifest-v3 persistence.

Pure validation for finalization-inventory integrity and manifest-v3
reconciliation.  Extracted from ``pipeline.persistence`` so the durable
models, IO, and finalization adapter stay independently mutation-scoped:
everything here raises ``ValueError`` or ``ManifestIntegrityError`` and
never touches the filesystem directly.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from pydantic import JsonValue

from asago_scenario_generator.manifest import (
    ArtifactRole,
    ManifestIntegrityError,
    RunStatus,
)
from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    InventoryCompleteness,
)
from asago_scenario_generator.pipeline.finalization import (
    CandidateTerminalStatus,
    GeneratedStage,
    LifecycleState,
)
from asago_scenario_generator.pipeline.finalization_gates import AdmissionEvidenceId
from asago_scenario_generator.pipeline.projection import canonical_json_bytes
from asago_scenario_generator.pipeline.persistence import (
    AdmissionDecisionRecord,
    ArtifactReceipt,
    CandidateAttemptRecord,
    CoveragePlanV2,
    FinalizationInventoryV1,
    ParsimonyRepairRecord,
    QuarantineBundleV1,
    StageAttemptRecord,
    StrictModel,
    TargetState,
    TransitionRecord,
    ViolationRecord,
    canonical_sha256,
    read_planning_checkpoint_bytes,
    validate_planning_checkpoint,
)


def _check_durable_event_ids(events: Sequence[StrictModel]) -> None:
    """Reject duplicate durable event IDs across all inventory event kinds."""
    event_ids = [item.event_id for item in events]
    if len(event_ids) != len(set(event_ids)):
        raise ValueError("duplicate durable event IDs")


def _check_durable_event_sequences(events: Sequence[StrictModel]) -> None:
    """Reject durable event sequences that are not contiguous from zero."""
    if sorted(item.sequence for item in events) != list(range(len(events))):
        raise ValueError("durable event sequences must be contiguous from zero")


def _attempt_ids(records: Sequence[StrictModel]) -> list[str]:
    """Return the attempt IDs of durable event records."""
    return [item.attempt_id for item in records]


def _candidate_ids(records: Sequence[StrictModel]) -> list[str]:
    """Return the candidate IDs of durable event records."""
    return [item.candidate_id for item in records]


def _check_unique_attempt_and_candidate_ids(
    candidate_attempts: Sequence[CandidateAttemptRecord],
    stage_attempts: Sequence[StageAttemptRecord],
) -> None:
    """Reject duplicate attempt or candidate IDs across the inventory."""
    for label, values in (
        ("candidate attempt", _attempt_ids(candidate_attempts)),
        ("stage attempt", _attempt_ids(stage_attempts)),
        ("candidate", _candidate_ids(candidate_attempts)),
    ):
        if len(values) != len(set(values)):
            raise ValueError(f"duplicate {label} IDs")


def _index_target_trace_events(
    transitions: Sequence[TransitionRecord],
    candidate_attempts: Sequence[CandidateAttemptRecord],
) -> tuple[dict[str, list[TransitionRecord]], dict[str, list[CandidateAttemptRecord]]]:
    """Index lifecycle transitions and attempts by effective target, and require
    every candidate attempt to carry a target trace."""
    transitions_by_target: dict[str, list[TransitionRecord]] = {}
    for transition in transitions:
        transitions_by_target.setdefault(transition.target_entry_point_id, []).append(
            transition
        )
    attempts_by_target: dict[str, list[CandidateAttemptRecord]] = {}
    for attempt in candidate_attempts:
        attempts_by_target.setdefault(attempt.target_entry_point_id, []).append(attempt)
    if set(attempts_by_target) - set(transitions_by_target):
        raise ValueError("each candidate attempt requires a target trace")
    return transitions_by_target, attempts_by_target


def _target_trace_terminal_edges(
    transitions_by_target: dict[str, list[TransitionRecord]],
    attempts_by_target: dict[str, list[CandidateAttemptRecord]],
) -> dict[str, TransitionRecord]:
    """Validate every target transition chain and candidate trace, returning
    the terminal transition edge keyed by admitted/rejected candidate."""
    terminal_edges: dict[str, TransitionRecord] = {}
    for target_id, target_transitions in transitions_by_target.items():
        target_transitions.sort(key=lambda item: item.sequence)
        _check_target_transition_indexes(target_transitions)
        target_attempts = sorted(
            attempts_by_target.get(target_id, []), key=lambda item: item.sequence
        )
        _check_target_candidate_trace(
            target_transitions, target_attempts, terminal_edges
        )
    return terminal_edges


def _transition_indexes_contiguous(
    target_transitions: list[TransitionRecord],
) -> bool:
    """True when per-target transition indexes are contiguous from zero."""
    return [item.index for item in target_transitions] == list(
        range(len(target_transitions))
    )


def _check_target_transition_indexes(
    target_transitions: list[TransitionRecord],
) -> None:
    """Reject non-contiguous per-target transition indexes and chains that do
    not start from pending."""
    if not _transition_indexes_contiguous(target_transitions):
        raise ValueError("transition indexes must be contiguous per target")
    if target_transitions[0].previous is not LifecycleState.pending:
        raise ValueError("first target transition must start from pending")
    for previous, current in zip(target_transitions, target_transitions[1:]):
        if previous.current is not current.previous:
            raise ValueError("transition state chain is noncontiguous per target")


@dataclass
class _CandidateTraceState:
    """Replay state for one target's candidate trace segments."""

    next_attempt: int = 0
    active_candidate: str | None = None
    seen_candidates: set[str] = field(default_factory=set)


def _check_target_candidate_trace(
    target_transitions: list[TransitionRecord],
    target_attempts: list[CandidateAttemptRecord],
    terminal_edges: dict[str, TransitionRecord],
) -> None:
    """Replay one target's revalidating/exhausted/active trace segments."""
    state = _CandidateTraceState()
    for position, transition in enumerate(target_transitions):
        if transition.current is LifecycleState.revalidating_candidate:
            _check_revalidating_segment(transition, target_attempts, state)
        elif transition.current is LifecycleState.exhausted:
            _check_exhausted_segment(
                transition, position, target_transitions, state.active_candidate
            )
        else:
            _check_active_segment(transition, state, terminal_edges)
    if state.next_attempt != len(target_attempts):
        raise ValueError(
            "each candidate attempt requires one revalidating trace segment"
        )


def _revalidating_segment_invalid(
    transition: TransitionRecord,
    state: _CandidateTraceState,
    attempt_count: int,
) -> bool:
    """True when a revalidating transition does not exactly match the next
    durable attempt."""
    return (
        state.active_candidate is not None
        or transition.candidate_id is None
        or transition.candidate_id in state.seen_candidates
        or state.next_attempt >= attempt_count
    )


def _check_revalidating_segment(
    transition: TransitionRecord,
    target_attempts: list[CandidateAttemptRecord],
    state: _CandidateTraceState,
) -> None:
    """Validate and advance a revalidating-candidate trace segment."""
    if _revalidating_segment_invalid(transition, state, len(target_attempts)):
        raise ValueError("invalid or duplicate candidate trace segment")
    attempt = target_attempts[state.next_attempt]
    if (
        transition.candidate_id != attempt.candidate_id
        or attempt.sequence >= transition.sequence
    ):
        raise ValueError("candidate trace does not match next durable attempt")
    state.active_candidate = transition.candidate_id
    state.seen_candidates.add(state.active_candidate)
    state.next_attempt += 1


def _check_exhausted_segment(
    transition: TransitionRecord,
    position: int,
    target_transitions: list[TransitionRecord],
    active_candidate: str | None,
) -> None:
    """Reject exhaustive transitions that are not the final candidate-free edge."""
    if (
        transition.candidate_id is not None
        or position != len(target_transitions) - 1
        or active_candidate is not None
    ):
        raise ValueError("target exhaustion must be candidate-free and final")


def _check_active_segment(
    transition: TransitionRecord,
    state: _CandidateTraceState,
    terminal_edges: dict[str, TransitionRecord],
) -> None:
    """Validate active-trace continuity and record admitted/rejected terminals."""
    if (
        state.active_candidate is None
        or transition.candidate_id != state.active_candidate
    ):
        raise ValueError("lifecycle candidate changed inside an active trace")
    if transition.current in {
        LifecycleState.admitted,
        LifecycleState.rejected,
    }:
        terminal_edges[state.active_candidate] = transition
        state.active_candidate = None


def _legal_lifecycle_edges() -> set[tuple[LifecycleState, LifecycleState]]:
    """Return every legal lifecycle edge pair for durable transitions."""
    generating_state = _generating_state_by_stage()
    active = {
        LifecycleState.generating_actor,
        LifecycleState.generating_narrative,
        LifecycleState.generating_tree,
        LifecycleState.finalizing_prebehavior,
        LifecycleState.generating_behavior,
        LifecycleState.admitting,
    }
    legal_edges = {
        (LifecycleState.pending, LifecycleState.revalidating_candidate),
        (LifecycleState.pending, LifecycleState.exhausted),
        (LifecycleState.rejected, LifecycleState.revalidating_candidate),
        (LifecycleState.rejected, LifecycleState.exhausted),
        (LifecycleState.revalidating_candidate, LifecycleState.generating_actor),
        (LifecycleState.revalidating_candidate, LifecycleState.rejected),
        (LifecycleState.generating_actor, LifecycleState.generating_narrative),
        (LifecycleState.generating_narrative, LifecycleState.generating_tree),
        (LifecycleState.generating_tree, LifecycleState.finalizing_prebehavior),
        (LifecycleState.finalizing_prebehavior, LifecycleState.generating_behavior),
        (LifecycleState.generating_behavior, LifecycleState.admitting),
        (LifecycleState.admitting, LifecycleState.admitted),
        (LifecycleState.admitting, LifecycleState.rejected),
    }
    legal_edges.update(
        (source, destination)
        for source in active
        for destination in generating_state.values()
    )
    legal_edges.update((source, LifecycleState.rejected) for source in active)
    return legal_edges


def _generating_state_by_stage() -> dict[GeneratedStage, LifecycleState]:
    """Map each generated stage to its durable generating lifecycle state."""
    return {
        GeneratedStage.actor: LifecycleState.generating_actor,
        GeneratedStage.narrative: LifecycleState.generating_narrative,
        GeneratedStage.tree: LifecycleState.generating_tree,
        GeneratedStage.behavior: LifecycleState.generating_behavior,
    }


def _check_lifecycle_edges(transitions: Sequence[TransitionRecord]) -> None:
    """Reject durable transitions whose edge is not in the legal edge set."""
    legal_edges = _legal_lifecycle_edges()
    for transition in sorted(transitions, key=lambda item: item.sequence):
        if (transition.previous, transition.current) not in legal_edges:
            raise ValueError(
                f"illegal lifecycle edge {transition.previous.value}->{transition.current.value}"
            )


def _stage_reference_invalid(
    stage: StageAttemptRecord | None,
    attempt: CandidateAttemptRecord,
) -> bool:
    """True when a referenced stage attempt is missing or owned by another
    candidate."""
    return stage is None or stage.candidate_id != attempt.candidate_id


def _stage_attempts_by_id(
    stage_attempts: Sequence[StageAttemptRecord],
) -> dict[str, StageAttemptRecord]:
    """Index stage attempts by durable attempt ID."""
    return {item.attempt_id: item for item in stage_attempts}


def _attempts_by_id(
    candidate_attempts: Sequence[CandidateAttemptRecord],
) -> dict[str, CandidateAttemptRecord]:
    """Index candidate attempts by durable attempt ID."""
    return {item.attempt_id: item for item in candidate_attempts}


def _check_stage_references(
    candidate_attempts: Sequence[CandidateAttemptRecord],
    stage_attempts: Sequence[StageAttemptRecord],
) -> None:
    """Require candidate stage references to match stage attempts exactly."""
    stage_by_id = _stage_attempts_by_id(stage_attempts)
    referenced_stage_ids: set[str] = set()
    for attempt in candidate_attempts:
        for stage_id in attempt.stage_attempt_ids:
            if _stage_reference_invalid(stage_by_id.get(stage_id), attempt):
                raise ValueError(
                    "candidate attempt references an invalid stage attempt"
                )
            referenced_stage_ids.add(stage_id)
    if referenced_stage_ids != set(stage_by_id):
        raise ValueError("stage attempts and candidate references must match exactly")


def _repair_mismatches_attempt(
    repair: ParsimonyRepairRecord,
    attempt: CandidateAttemptRecord | None,
) -> bool:
    """True when a repair record does not match its candidate attempt."""
    return (
        attempt is None
        or repair.candidate_id != attempt.candidate_id
        or repair.target_entry_point_id != attempt.target_entry_point_id
    )


def _subsequent_behavior_inputs(
    stage_attempts: Sequence[StageAttemptRecord],
    repair: ParsimonyRepairRecord,
) -> list[str]:
    """Return behavior final-tree inputs recorded after the repair."""
    return [
        item.final_tree_snapshot_sha256
        for item in stage_attempts
        if item.candidate_id == repair.candidate_id
        and item.stage is GeneratedStage.behavior
        and item.sequence > repair.sequence
    ]


def _check_repair_records(
    repairs: Sequence[ParsimonyRepairRecord],
    candidate_attempts: Sequence[CandidateAttemptRecord],
    stage_attempts: Sequence[StageAttemptRecord],
) -> None:
    """Require every repair record to match its candidate attempt and bind
    behavior final-tree input."""
    attempts_by_id = _attempts_by_id(candidate_attempts)
    for repair in repairs:
        attempt = attempts_by_id.get(repair.candidate_attempt_id)
        if _repair_mismatches_attempt(repair, attempt):
            raise ValueError("repair record does not match its candidate attempt")
        subsequent_behavior_inputs = _subsequent_behavior_inputs(stage_attempts, repair)
        if (
            subsequent_behavior_inputs
            and repair.after_digest not in subsequent_behavior_inputs
        ):
            raise ValueError("repair output is not bound to behavior final-tree input")


def _stage_invocation_indexes_contiguous(
    records: list[StageAttemptRecord],
) -> bool:
    """True when per-candidate-stage invocation indexes are contiguous."""
    return [item.invocation_index for item in records] == list(range(len(records)))


def _stage_retry_indexes_not_monotonic(records: list[StageAttemptRecord]) -> bool:
    """True when owner retry indexes decrease between adjacent records."""
    return any(
        right.owner_retry_index < left.owner_retry_index
        for left, right in zip(records, records[1:])
    )


def _check_stage_invocation_indexes(
    stage_attempts: Sequence[StageAttemptRecord],
) -> None:
    """Require contiguous per-candidate-stage invocation indexes and monotonic
    owner retry indexes."""
    by_candidate_stage: dict[tuple[str, GeneratedStage], list[StageAttemptRecord]] = {}
    for item in stage_attempts:
        by_candidate_stage.setdefault((item.candidate_id, item.stage), []).append(item)
    for records in by_candidate_stage.values():
        records.sort(key=lambda item: item.invocation_index)
        if not _stage_invocation_indexes_contiguous(records):
            raise ValueError("stage invocation indexes must be contiguous")
        if _stage_retry_indexes_not_monotonic(records):
            raise ValueError("stage owner retry indexes must be monotonic")


def _generating_transitions_for(
    attempt: CandidateAttemptRecord,
    transitions: Sequence[TransitionRecord],
    generating_states: set[LifecycleState],
) -> list[TransitionRecord]:
    """Return the candidate's generating transitions in durable order."""
    return sorted(
        (
            item
            for item in transitions
            if item.candidate_id == attempt.candidate_id
            and item.current in generating_states
        ),
        key=lambda item: item.sequence,
    )


def _stage_attempts_for(
    attempt: CandidateAttemptRecord,
    stage_attempts: Sequence[StageAttemptRecord],
) -> list[StageAttemptRecord]:
    """Return the candidate's stage attempts in durable order."""
    return sorted(
        (item for item in stage_attempts if item.candidate_id == attempt.candidate_id),
        key=lambda item: item.sequence,
    )


def _generating_transition_count_mismatch(
    generating_transitions: list[TransitionRecord],
    ordered_stage_attempts: list[StageAttemptRecord],
) -> bool:
    """True when generating transitions do not map 1:1 (or 1:1 plus one
    unmatched terminal generation edge) to stage attempts."""
    return len(generating_transitions) not in {
        len(ordered_stage_attempts),
        len(ordered_stage_attempts) + 1,
    }


def _decision_for_candidate(
    admission_decisions: Sequence[AdmissionDecisionRecord],
    candidate_id: str,
) -> AdmissionDecisionRecord | None:
    """Return the terminal admission decision for a candidate, if any."""
    return next(
        (item for item in admission_decisions if item.candidate_id == candidate_id),
        None,
    )


def _later_candidate_events(
    attempt: CandidateAttemptRecord,
    unmatched: TransitionRecord,
    transitions: Sequence[TransitionRecord],
    stage_attempts: Sequence[StageAttemptRecord],
    repairs: Sequence[ParsimonyRepairRecord],
    admission_decisions: Sequence[AdmissionDecisionRecord],
) -> list[Any]:
    """Return every durable candidate event recorded after the unmatched
    generating transition."""
    return [
        item
        for item in [
            *transitions,
            *stage_attempts,
            *repairs,
            *admission_decisions,
        ]
        if item.candidate_id == attempt.candidate_id
        and item.sequence > unmatched.sequence
    ]


def _unknown_terminal_adjacency(
    terminal: TransitionRecord | None,
    decision: AdmissionDecisionRecord | None,
    ordered_later: list[Any],
) -> bool:
    """True when the terminal edge and decision are exactly the next two
    events after the unmatched generating transition."""
    return (
        terminal is not None
        and decision is not None
        and ordered_later == [terminal, decision]
    )


def _unknown_terminal_edge_order(
    terminal: TransitionRecord,
    decision: AdmissionDecisionRecord,
    unmatched: TransitionRecord,
) -> bool:
    """True when terminal and decision follow the unmatched edge in exact
    adjacent sequence order."""
    return (
        terminal.previous is unmatched.current
        and terminal.sequence == unmatched.sequence + 1
        and decision.sequence == terminal.sequence + 1
    )


def _unknown_outcome_decision(decision: AdmissionDecisionRecord) -> bool:
    """True when the decision is a bare generation/finalization failure."""
    return (
        decision.status is CandidateTerminalStatus.generation_or_finalization_failed
        and not decision.admitted
        and not decision.gate_results
    )


def _single_unknown_invocation_violation(
    decision: AdmissionDecisionRecord,
) -> bool:
    """True when the decision carries exactly the unknown-invocation-outcome
    violation."""
    return (
        len(decision.violations) == 1
        and decision.violations[0].code == "unknown_invocation_outcome"
        and decision.violations[0].owner is None
        and not decision.violations[0].retryable
    )


def _single_quarantine_bundle_receipt(
    decision: AdmissionDecisionRecord,
) -> bool:
    """True when the decision carries exactly one quarantine-bundle receipt."""
    return (
        len(decision.terminal_receipts) == 1
        and decision.terminal_receipts[0].role is ArtifactRole.QUARANTINE_BUNDLE
    )


def _no_later_stage_or_repair_events(
    attempt: CandidateAttemptRecord,
    unmatched: TransitionRecord,
    stage_attempts: Sequence[StageAttemptRecord],
    repairs: Sequence[ParsimonyRepairRecord],
) -> bool:
    """True when no stage attempt or repair follows the unmatched edge."""
    return not any(
        item.sequence > unmatched.sequence
        for item in [*stage_attempts, *repairs]
        if item.candidate_id == attempt.candidate_id
    )


def _unknown_terminal_trace_matches(
    terminal: TransitionRecord | None,
    decision: AdmissionDecisionRecord | None,
    ordered_later: list[Any],
    unmatched: TransitionRecord,
) -> bool:
    """True when adjacency and edge ordering of the unknown terminal match."""
    return _unknown_terminal_adjacency(
        terminal, decision, ordered_later
    ) and _unknown_terminal_edge_order(terminal, decision, unmatched)


def _unknown_terminal_decision_matches(
    decision: AdmissionDecisionRecord,
    attempt: CandidateAttemptRecord,
    unmatched: TransitionRecord,
    stage_attempts: Sequence[StageAttemptRecord],
    repairs: Sequence[ParsimonyRepairRecord],
) -> bool:
    """True when the terminal decision is exactly the unknown-outcome
    quarantine terminalization."""
    return (
        _unknown_outcome_decision(decision)
        and _single_unknown_invocation_violation(decision)
        and _single_quarantine_bundle_receipt(decision)
        and _no_later_stage_or_repair_events(
            attempt, unmatched, stage_attempts, repairs
        )
    )


def _is_exact_unknown_terminal(
    attempt: CandidateAttemptRecord,
    unmatched: TransitionRecord,
    later_candidate_events: Sequence[Any],
    admission_decisions: Sequence[AdmissionDecisionRecord],
    terminal_edges: dict[str, TransitionRecord],
    stage_attempts: Sequence[StageAttemptRecord],
    repairs: Sequence[ParsimonyRepairRecord],
) -> bool:
    """True when an unmatched generating transition is followed by exactly
    the unknown-outcome terminalization sequence."""
    decision = _decision_for_candidate(admission_decisions, attempt.candidate_id)
    terminal = terminal_edges.get(attempt.candidate_id)
    ordered_later = sorted(later_candidate_events, key=lambda item: item.sequence)
    return _unknown_terminal_trace_matches(
        terminal, decision, ordered_later, unmatched
    ) and _unknown_terminal_decision_matches(
        decision, attempt, unmatched, stage_attempts, repairs
    )


def _check_unmatched_generating_transition(
    attempt: CandidateAttemptRecord,
    unmatched: TransitionRecord,
    candidate_attempts: Sequence[CandidateAttemptRecord],
    transitions: Sequence[TransitionRecord],
    stage_attempts: Sequence[StageAttemptRecord],
    repairs: Sequence[ParsimonyRepairRecord],
    admission_decisions: Sequence[AdmissionDecisionRecord],
    terminal_edges: dict[str, TransitionRecord],
) -> None:
    """Reject later candidate events after an unmatched generating transition
    unless they are exactly the unknown-outcome terminalization."""
    later_candidate_events = _later_candidate_events(
        attempt,
        unmatched,
        transitions,
        stage_attempts,
        repairs,
        admission_decisions,
    )
    if later_candidate_events and not _is_exact_unknown_terminal(
        attempt,
        unmatched,
        later_candidate_events,
        admission_decisions,
        terminal_edges,
        stage_attempts,
        repairs,
    ):
        raise ValueError(
            "unmatched generating transition permits only exact "
            "unknown-outcome terminalization"
        )


def _generating_stage_pairing_mismatch(
    transition: TransitionRecord,
    stage: StageAttemptRecord,
    generating_state: dict[GeneratedStage, LifecycleState],
) -> bool:
    """True when a generating transition does not pair with its stage
    attempt."""
    return (
        transition.current is not generating_state[stage.stage]
        or transition.candidate_id != stage.candidate_id
        or transition.sequence >= stage.sequence
    )


def _check_generating_stage_pairing(
    generating_transitions: list[TransitionRecord],
    ordered_stage_attempts: list[StageAttemptRecord],
    generating_state: dict[GeneratedStage, LifecycleState],
) -> None:
    """Require each generating transition to pair with its stage attempt."""
    for transition, stage in zip(generating_transitions, ordered_stage_attempts):
        if _generating_stage_pairing_mismatch(transition, stage, generating_state):
            raise ValueError("generating transition/stage attempt trace mismatch")


def _check_generating_transition_traces(
    candidate_attempts: Sequence[CandidateAttemptRecord],
    transitions: Sequence[TransitionRecord],
    stage_attempts: Sequence[StageAttemptRecord],
    repairs: Sequence[ParsimonyRepairRecord],
    admission_decisions: Sequence[AdmissionDecisionRecord],
    terminal_edges: dict[str, TransitionRecord],
) -> None:
    """Require generating transitions to correspond 1:1 to stage attempts per
    candidate."""
    generating_state = _generating_state_by_stage()
    generating_states = set(generating_state.values())
    for attempt in candidate_attempts:
        generating_transitions = _generating_transitions_for(
            attempt, transitions, generating_states
        )
        ordered_stage_attempts = _stage_attempts_for(attempt, stage_attempts)
        if _generating_transition_count_mismatch(
            generating_transitions, ordered_stage_attempts
        ):
            raise ValueError(
                "generating transitions must correspond 1:1 to stage attempts"
            )
        if len(generating_transitions) == len(ordered_stage_attempts) + 1:
            _check_unmatched_generating_transition(
                attempt,
                generating_transitions[-1],
                candidate_attempts,
                transitions,
                stage_attempts,
                repairs,
                admission_decisions,
                terminal_edges,
            )
        _check_generating_stage_pairing(
            generating_transitions, ordered_stage_attempts, generating_state
        )


def _candidate_stages_for(
    candidate_id: str,
    stage_attempts: Sequence[StageAttemptRecord],
) -> list[StageAttemptRecord]:
    """Return the candidate's stage attempts."""
    return [item for item in stage_attempts if item.candidate_id == candidate_id]


def _check_stage_evidence_precedes_terminal(
    candidate_stages: list[StageAttemptRecord],
    terminal_edge: TransitionRecord,
) -> None:
    """Require stage evidence to precede the candidate terminal edge."""
    if any(item.sequence >= terminal_edge.sequence for item in candidate_stages):
        raise ValueError("stage evidence must precede candidate terminal edge")


def _check_terminal_precedes_decision(
    terminal_edge: TransitionRecord,
    decision: AdmissionDecisionRecord,
) -> None:
    """Require the candidate terminal edge to precede its decision."""
    if terminal_edge.sequence >= decision.sequence:
        raise ValueError("candidate terminal edge must precede its decision")


def _next_target_transition_after(
    decision: AdmissionDecisionRecord,
    terminal_edge: TransitionRecord,
    transitions_by_target: dict[str, list[TransitionRecord]],
    candidate_attempts: Sequence[CandidateAttemptRecord],
) -> TransitionRecord | None:
    """Return the next target transition after the candidate terminal edge."""
    target_entry_point_id = next(
        attempt.target_entry_point_id
        for attempt in candidate_attempts
        if attempt.candidate_id == decision.candidate_id
    )
    return next(
        (
            item
            for item in transitions_by_target[target_entry_point_id]
            if item.sequence > terminal_edge.sequence
        ),
        None,
    )


def _check_decision_precedes_next_target_transition(
    next_target_transition: TransitionRecord | None,
    decision: AdmissionDecisionRecord,
) -> None:
    """Require the candidate decision to precede the next target transition."""
    if (
        next_target_transition is not None
        and decision.sequence >= next_target_transition.sequence
    ):
        raise ValueError("candidate decision must precede the next target transition")


def _check_postbehavior_admission_edge(
    terminal_edge: TransitionRecord,
    decision: AdmissionDecisionRecord,
) -> None:
    """Require admitted/gated decisions to terminate from admitting."""
    if (decision.admitted or decision.gate_results) and (
        terminal_edge.previous is not LifecycleState.admitting
    ):
        raise ValueError("postbehavior admission requires admitting terminal edge")


def _check_admitting_edge_requires_gate_evidence(
    terminal_edge: TransitionRecord,
    decision: AdmissionDecisionRecord,
) -> None:
    """Require typed admission gate evidence on admitting terminal edges."""
    if terminal_edge.previous is LifecycleState.admitting and not decision.gate_results:
        raise ValueError(
            "admitting terminal edge requires typed admission gate evidence"
        )


def _check_gate_violations_match_terminal(
    decision: AdmissionDecisionRecord,
) -> None:
    """Require admission gate violations to match terminal violations."""
    flattened_gate_violations = [
        violation for gate in decision.gate_results for violation in gate.violations
    ]
    if decision.gate_results and (flattened_gate_violations != decision.violations):
        raise ValueError("admission gate violations must match terminal violations")


def _admitted_missing_passing_gate_evidence(
    decision: AdmissionDecisionRecord,
) -> bool:
    """True when an admitted decision lacks nonempty passing gate evidence."""
    return decision.admitted and (
        not decision.gate_results
        or any(not gate.passed for gate in decision.gate_results)
        or decision.violations
    )


def _check_admitted_requires_passing_gates(
    decision: AdmissionDecisionRecord,
) -> None:
    """Require admitted decisions to carry nonempty passing gate evidence."""
    if _admitted_missing_passing_gate_evidence(decision):
        raise ValueError("admitted decision requires nonempty passing gate evidence")


def _causal_artifacts_for_decision(
    decision: AdmissionDecisionRecord,
    candidate_stages: list[StageAttemptRecord],
    candidate_attempts: Sequence[CandidateAttemptRecord],
    repairs: Sequence[ParsimonyRepairRecord],
) -> dict[GeneratedStage, JsonValue]:
    """Reduce the candidate's durable stage evidence to one artifact
    frontier."""
    return _causal_stage_artifacts(
        candidate_stages,
        candidate_attempt_id=next(
            item.attempt_id
            for item in candidate_attempts
            if item.candidate_id == decision.candidate_id
        ),
        repairs=[
            item for item in repairs if item.candidate_id == decision.candidate_id
        ],
    )


def _expected_admission_snapshots(
    causal: dict[GeneratedStage, JsonValue],
    candidate_stages: list[StageAttemptRecord],
) -> tuple[str | None, str | None, str | None, str | None]:
    """Return the snapshot digests required by the durable stage evidence."""
    return (
        candidate_stages[-1].candidate_snapshot_sha256 if candidate_stages else None,
        canonical_sha256(causal[GeneratedStage.actor])
        if GeneratedStage.actor in causal
        else None,
        canonical_sha256(causal[GeneratedStage.narrative])
        if GeneratedStage.narrative in causal
        else None,
        canonical_sha256(causal[GeneratedStage.tree])
        if GeneratedStage.behavior in causal
        else None,
    )


def _check_admission_snapshot_digests(
    decision: AdmissionDecisionRecord,
    candidate_stages: list[StageAttemptRecord],
    candidate_attempts: Sequence[CandidateAttemptRecord],
    repairs: Sequence[ParsimonyRepairRecord],
) -> None:
    """Require admitted decision snapshot digests to match stage evidence."""
    candidate_stages.sort(key=lambda item: item.sequence)
    causal = _causal_artifacts_for_decision(
        decision, candidate_stages, candidate_attempts, repairs
    )
    actual_snapshots = (
        decision.candidate_snapshot_sha256,
        decision.actor_snapshot_sha256,
        decision.narrative_snapshot_sha256,
        decision.final_tree_snapshot_sha256,
    )
    if actual_snapshots != _expected_admission_snapshots(causal, candidate_stages):
        raise ValueError("admission snapshot digests do not match stage evidence")


def _check_admission_decision(
    decision: AdmissionDecisionRecord,
    terminal_edges: dict[str, TransitionRecord],
    transitions_by_target: dict[str, list[TransitionRecord]],
    candidate_attempts: Sequence[CandidateAttemptRecord],
    stage_attempts: Sequence[StageAttemptRecord],
    repairs: Sequence[ParsimonyRepairRecord],
) -> None:
    """Require one terminal admission decision to match its candidate
    trace, gate evidence, and snapshot digests."""
    expected = LifecycleState.admitted if decision.admitted else LifecycleState.rejected
    terminal_edge = terminal_edges.get(decision.candidate_id)
    if terminal_edge is None or terminal_edge.current is not expected:
        raise ValueError(
            "admission decision requires matching admitting terminal transition"
        )
    candidate_stages = _candidate_stages_for(decision.candidate_id, stage_attempts)
    _check_stage_evidence_precedes_terminal(candidate_stages, terminal_edge)
    _check_terminal_precedes_decision(terminal_edge, decision)
    _check_decision_precedes_next_target_transition(
        _next_target_transition_after(
            decision, terminal_edge, transitions_by_target, candidate_attempts
        ),
        decision,
    )
    _check_postbehavior_admission_edge(terminal_edge, decision)
    _check_admitting_edge_requires_gate_evidence(terminal_edge, decision)
    _check_gate_violations_match_terminal(decision)
    _check_admitted_requires_passing_gates(decision)
    if decision.admitted:
        _check_admission_snapshot_digests(
            decision, candidate_stages, candidate_attempts, repairs
        )


def _check_terminal_decisions(
    candidate_attempts: Sequence[CandidateAttemptRecord],
    transitions_by_target: dict[str, list[TransitionRecord]],
    stage_attempts: Sequence[StageAttemptRecord],
    repairs: Sequence[ParsimonyRepairRecord],
    admission_decisions: Sequence[AdmissionDecisionRecord],
    terminal_edges: dict[str, TransitionRecord],
) -> None:
    """Reconcile terminal admission decisions against terminal trace edges."""
    decisions = [item.candidate_id for item in admission_decisions]
    if len(decisions) != len(set(decisions)):
        raise ValueError("duplicate terminal admission decisions")
    if set(terminal_edges) != set(decisions):
        raise ValueError("terminal edges and admission decisions must match exactly")
    for decision in admission_decisions:
        _check_admission_decision(
            decision,
            terminal_edges,
            transitions_by_target,
            candidate_attempts,
            stage_attempts,
            repairs,
        )


def _receipt_keys(receipts: Sequence[ArtifactReceipt]) -> list[bytes]:
    """Return canonical JSON keys for receipts."""
    return [canonical_json_bytes(item) for item in receipts]


def _decision_receipt_keys(
    admission_decisions: Sequence[AdmissionDecisionRecord],
) -> list[bytes]:
    """Return canonical JSON keys for every decision terminal receipt."""
    return [
        canonical_json_bytes(receipt)
        for decision in admission_decisions
        for receipt in decision.terminal_receipts
    ]


def _receipt_inventories_mismatched(
    decision_receipt_keys: list[bytes],
    inventory_receipt_keys: list[bytes],
) -> bool:
    """True when terminal decision receipts and finalization inventories do
    not match exactly."""
    return (
        len(decision_receipt_keys) != len(set(decision_receipt_keys))
        or len(inventory_receipt_keys) != len(set(inventory_receipt_keys))
        or set(decision_receipt_keys) != set(inventory_receipt_keys)
    )


def _check_receipt_inventories(
    admission_decisions: Sequence[AdmissionDecisionRecord],
    admitted_inventory: Sequence[ArtifactReceipt],
    quarantine_inventory: Sequence[ArtifactReceipt],
) -> None:
    """Require terminal decision receipts and finalization inventories to
    match exactly."""
    inventory_receipts = [
        *admitted_inventory,
        *quarantine_inventory,
    ]
    if _receipt_inventories_mismatched(
        _decision_receipt_keys(admission_decisions),
        _receipt_keys(inventory_receipts),
    ):
        raise ValueError(
            "terminal decision receipts and finalization inventories must match exactly"
        )


def _causal_stage_artifacts(
    records: list[StageAttemptRecord],
    *,
    candidate_attempt_id: str,
    durable_candidate: JsonValue | None = None,
    repairs: Sequence[ParsimonyRepairRecord] = (),
) -> dict[GeneratedStage, JsonValue]:
    """Reduce stage evidence to one causally contiguous artifact frontier."""
    frontier: dict[GeneratedStage, JsonValue] = {}
    order = tuple(GeneratedStage)
    for record in sorted(records, key=lambda item: item.sequence):
        if (
            durable_candidate is not None
            and record.input.candidate != durable_candidate
        ):
            raise ValueError("stage candidate snapshot differs from durable plan")
        for invalidated in order[order.index(record.stage) :]:
            frontier.pop(invalidated, None)
        visible = dict(record.input.visible_artifacts)
        if record.stage is GeneratedStage.behavior:
            visible_tree = visible.get(GeneratedStage.tree.value)
            if (
                visible_tree is None
                or record.final_tree_snapshot_sha256 != canonical_sha256(visible_tree)
            ):
                raise ValueError(
                    "behavior evidence is not bound to its final-tree input"
                )
            generated_tree = frontier.get(GeneratedStage.tree)
            if generated_tree is None:
                raise ValueError("behavior evidence has no causal generated tree")
            before_digest = canonical_sha256(generated_tree)
            after_digest = canonical_sha256(visible_tree)
            if before_digest != after_digest and not any(
                repair.accepted
                and repair.candidate_attempt_id == candidate_attempt_id
                and repair.sequence < record.sequence
                and repair.before_digest == before_digest
                and repair.after_digest == after_digest
                for repair in repairs
            ):
                raise ValueError(
                    "behavior tree is neither generated nor linked by accepted repair"
                )
            frontier[GeneratedStage.tree] = visible_tree
        expected_visible = {
            stage.value: artifact for stage, artifact in frontier.items()
        }
        if visible != expected_visible:
            raise ValueError("stage evidence is not one contiguous causal frontier")
        if (
            record.result is not None
            and not record.violations
            and record.call is not None
        ):
            frontier[record.stage] = record.result
    return frontier


def validate_v3_inventories(resolver: Any) -> None:
    """Reconcile manifest v3, coverage, finalization, and quarantine receipts."""
    _check_v3_journal_unresolved(resolver)
    (
        coverage_entry,
        final_entry,
        planning_entry,
    ) = _v3_persistence_entries(resolver)
    coverage, final, checkpoint = _v3_load_persistence_models(
        resolver, coverage_entry, final_entry, planning_entry
    )
    validate_planning_checkpoint(checkpoint, coverage)
    _check_v3_run_identity(final, resolver.manifest.run_id, coverage_entry.sha256)
    admitted_decisions = _v3_admitted_decisions(final)
    _check_v3_gate_applicability(resolver, final, admitted_decisions)
    plan_by_candidate = _v3_plan_by_candidate(coverage)
    _check_v3_transitions_in_plan(final, plan_by_candidate, coverage)
    admitted, quarantined = _v3_receipt_candidate_sets(final)
    _check_v3_inventory_disjoint(admitted, quarantined)
    _check_v3_attempts_match_plan(final, plan_by_candidate)
    attempts_by_target = _v3_attempts_by_target(final)
    _check_v3_attempted_candidates_per_target(final, coverage, attempts_by_target)
    admitted_decision_ids = _v3_admitted_decision_ids(final)
    _check_v3_terminal_decision_sets(
        _v3_attempted_and_terminal_ids(final),
        admitted,
        quarantined,
        admitted_decision_ids,
    )
    _check_v3_fallback_order(attempts_by_target, admitted_decision_ids)
    _check_v3_target_terminal_states(final, coverage, admitted_decision_ids)
    _check_v3_manifest_receipts(resolver, final)
    _check_v3_admitted_receipt_pairs(final, admitted)
    _check_v3_quarantined_receipts(final, quarantined)
    _check_v3_eval_and_role_scopes(resolver, quarantined, admitted)
    _check_v3_admitted_causal_evidence(final, plan_by_candidate, admitted)
    _check_v3_quarantine_bundles(resolver, final, plan_by_candidate)
    _check_v3_completed_status(resolver, quarantined)


def _check_v3_journal_unresolved(resolver: Any) -> None:
    """Reject finalization while an interrupted journal is still present."""
    if (resolver.run_dir / ".finalization-state.json").exists():
        raise ManifestIntegrityError(
            "Manifest v3 cannot finalize with an unresolved journal"
        )


def _v3_persistence_entries(resolver: Any) -> tuple[Any, Any, Any]:
    """Return the v3 persistence singleton entries, rejecting missing ones."""
    coverage_entry = resolver.entry_by_role(ArtifactRole.COVERAGE_PLAN)
    final_entry = resolver.entry_by_role(ArtifactRole.FINALIZATION_INVENTORY)
    planning_entry = resolver.entry_by_role(ArtifactRole.PLANNING_CHECKPOINT)
    if planning_entry is None or coverage_entry is None or final_entry is None:
        raise ManifestIntegrityError("Manifest v3 persistence singletons are missing")
    return coverage_entry, final_entry, planning_entry


def _v3_load_persistence_models(
    resolver: Any,
    coverage_entry: Any,
    final_entry: Any,
    planning_entry: Any,
) -> tuple[CoveragePlanV2, FinalizationInventoryV1, Any]:
    """Load and validate the durable v3 persistence models."""
    try:
        coverage = CoveragePlanV2.model_validate(resolver.read_json(coverage_entry))
        final = FinalizationInventoryV1.model_validate(resolver.read_json(final_entry))
    except Exception as exc:
        raise ManifestIntegrityError(
            f"Invalid manifest v3 persistence model: {exc}"
        ) from exc
    checkpoint = read_planning_checkpoint_bytes(resolver.read_bytes(planning_entry))
    return coverage, final, checkpoint


def _check_v3_run_identity(
    final: FinalizationInventoryV1,
    run_id: str,
    coverage_plan_sha256: str,
) -> None:
    """Require the finalization inventory run identity to match the manifest."""
    if final.run_id != run_id:
        raise ManifestIntegrityError("Finalization inventory run_id mismatch")
    if final.coverage_plan_sha256 != coverage_plan_sha256:
        raise ManifestIntegrityError("Finalization coverage plan hash mismatch")


def _v3_admitted_decisions(
    final: FinalizationInventoryV1,
) -> list[AdmissionDecisionRecord]:
    """Return admitted terminal decisions."""
    return [decision for decision in final.admission_decisions if decision.admitted]


def _v3_profile_applicability(resolver: Any) -> dict[AdmissionEvidenceId, bool]:
    """Load the capability profile and its conditional evidence applicability."""
    profile_entry = resolver.entry_by_role(ArtifactRole.CAPABILITY_PROFILE)
    if profile_entry is None:
        raise ManifestIntegrityError("Admitted inventory requires capability profile")
    try:
        profile = CapabilityProfile.model_validate(resolver.read_yaml(profile_entry))
    except Exception as exc:
        raise ManifestIntegrityError(f"Invalid capability profile: {exc}") from exc
    return {
        AdmissionEvidenceId.tool_integration_grounding: (
            profile.tool_inventory_completeness
            is InventoryCompleteness.operator_confirmed_complete
        ),
        AdmissionEvidenceId.data_access_grounding: (
            profile.entry_point_completeness
            is InventoryCompleteness.operator_confirmed_complete
        ),
    }


def _v3_decision_gate_applicability_mismatch(
    decision: AdmissionDecisionRecord,
    expected_applicability: dict[AdmissionEvidenceId, bool],
) -> bool:
    """True when any gated applicability diverges from the profile."""
    gates = {gate.gate: gate for gate in decision.gate_results}
    return any(
        gates[evidence_id].applicable is not expected
        for evidence_id, expected in expected_applicability.items()
    )


def _check_v3_gate_applicability(
    resolver: Any,
    final: FinalizationInventoryV1,
    admitted_decisions: list[AdmissionDecisionRecord],
) -> None:
    """Require admitted conditional evidence to match the capability profile."""
    if not admitted_decisions:
        return
    expected_applicability = _v3_profile_applicability(resolver)
    for decision in admitted_decisions:
        if _v3_decision_gate_applicability_mismatch(decision, expected_applicability):
            raise ManifestIntegrityError(
                "Admitted conditional evidence applicability does not match "
                "the capability profile"
            )


def _v3_plan_by_candidate(
    coverage: CoveragePlanV2,
) -> dict[str, tuple[Any, Any]]:
    """Index coverage choices by candidate_id with their owning target."""
    return {
        choice.candidate_id: (target, choice)
        for target in coverage.targets
        for choice in target.ordered_choices
    }


def _v3_transition_plan_mismatch(
    planned: tuple[Any, Any] | None,
    transition: TransitionRecord,
) -> bool:
    """True when a candidate transition is absent from or foreign to the plan."""
    return (
        planned is None
        or planned[0].effective_target_id != transition.target_entry_point_id
    )


def _check_v3_transition_in_plan(
    transition: TransitionRecord,
    plan_by_candidate: dict[str, tuple[Any, Any]],
    plan_target_ids: set[str],
) -> None:
    """Require one lifecycle transition to reference a planned target and
    candidate."""
    if transition.target_entry_point_id not in plan_target_ids:
        raise ManifestIntegrityError("Lifecycle transition target is absent from plan")
    if transition.candidate_id is not None:
        planned = plan_by_candidate.get(transition.candidate_id)
        if _v3_transition_plan_mismatch(planned, transition):
            raise ManifestIntegrityError(
                "Lifecycle transition candidate/target is absent from plan"
            )


def _check_v3_transitions_in_plan(
    final: FinalizationInventoryV1,
    plan_by_candidate: dict[str, tuple[Any, Any]],
    coverage: CoveragePlanV2,
) -> None:
    """Require every lifecycle transition to reference a planned target and
    candidate."""
    plan_target_ids = {target.effective_target_id for target in coverage.targets}
    for transition in final.transitions:
        _check_v3_transition_in_plan(transition, plan_by_candidate, plan_target_ids)


def _v3_receipt_candidate_sets(
    final: FinalizationInventoryV1,
) -> tuple[set[str], set[str]]:
    """Return admitted and quarantined receipt candidate sets."""
    admitted = {receipt.candidate_id for receipt in final.admitted_inventory}
    quarantined = {receipt.candidate_id for receipt in final.quarantine_inventory}
    return admitted, quarantined


def _check_v3_inventory_disjoint(
    admitted: set[str],
    quarantined: set[str],
) -> None:
    """Reject candidate overlap between admitted and quarantine inventory."""
    if admitted & quarantined:
        raise ManifestIntegrityError("Admitted and quarantine inventories overlap")


def _v3_attempt_plan_mismatch(
    attempt: CandidateAttemptRecord,
    planned: tuple[Any, Any],
) -> bool:
    """True when an attempt target/rank diverges from the coverage plan."""
    target, choice = planned
    return (
        attempt.target_entry_point_id != target.effective_target_id
        or attempt.queue_rank != choice.rank
    )


def _check_v3_attempts_match_plan(
    final: FinalizationInventoryV1,
    plan_by_candidate: dict[str, tuple[Any, Any]],
) -> None:
    """Require every finalization attempt to match its coverage-plan entry."""
    for attempt in final.candidate_attempts:
        planned = plan_by_candidate.get(attempt.candidate_id)
        if planned is None:
            raise ManifestIntegrityError(
                "Finalization attempt is absent from coverage plan"
            )
        if _v3_attempt_plan_mismatch(attempt, planned):
            raise ManifestIntegrityError(
                "Finalization attempt does not match coverage plan"
            )


def _v3_attempts_by_target(
    final: FinalizationInventoryV1,
) -> dict[str, list[CandidateAttemptRecord]]:
    """Index candidate attempts by effective target ID."""
    attempts_by_target: dict[str, list[CandidateAttemptRecord]] = {}
    for attempt in final.candidate_attempts:
        attempts_by_target.setdefault(attempt.target_entry_point_id, []).append(attempt)
    return attempts_by_target


def _v3_candidate_ids(attempts: Sequence[CandidateAttemptRecord]) -> list[str]:
    """Return candidate IDs of attempts in order."""
    return [item.candidate_id for item in attempts]


def _v3_attempted_ids_by_target(
    attempts_by_target: dict[str, list[CandidateAttemptRecord]],
) -> dict[str, list[str]]:
    """Map each target to its attempted candidate IDs in durable order."""
    return {
        target_id: _v3_candidate_ids(attempts)
        for target_id, attempts in attempts_by_target.items()
    }


def _check_v3_attempted_candidates_per_target(
    final: FinalizationInventoryV1,
    coverage: CoveragePlanV2,
    attempts_by_target: dict[str, list[CandidateAttemptRecord]],
) -> None:
    """Require coverage-plan attempted candidates to match the inventory."""
    attempts_by_target_id = _v3_attempted_ids_by_target(attempts_by_target)
    for target in coverage.targets:
        if target.attempted_candidate_ids != attempts_by_target_id.get(
            target.effective_target_id, []
        ):
            raise ManifestIntegrityError(
                "Coverage plan attempted candidates do not match finalization inventory"
            )


def _v3_admitted_decision_ids(
    final: FinalizationInventoryV1,
) -> set[str]:
    """Return candidate IDs of admitted terminal decisions."""
    return {
        decision.candidate_id
        for decision in final.admission_decisions
        if decision.admitted
    }


def _v3_attempted_and_terminal_ids(
    final: FinalizationInventoryV1,
) -> tuple[set[str], set[str]]:
    """Return attempted and terminal candidate ID sets."""
    attempted = {item.candidate_id for item in final.candidate_attempts}
    terminal = {item.candidate_id for item in final.admission_decisions}
    return attempted, terminal


def _check_v3_terminal_decision_sets(
    attempted_and_terminal: tuple[set[str], set[str]],
    admitted: set[str],
    quarantined: set[str],
    admitted_decisions: set[str],
) -> None:
    """Require receipt and decision candidate sets to reconcile exactly."""
    attempted_candidates, terminal_candidates = attempted_and_terminal
    if attempted_candidates != terminal_candidates:
        raise ManifestIntegrityError(
            "Every attempted candidate requires exactly one terminal decision"
        )
    nonadmitted_decisions = terminal_candidates - admitted_decisions
    if admitted != admitted_decisions:
        raise ManifestIntegrityError(
            "Admitted receipts must exactly match admitted terminal decisions"
        )
    if quarantined != nonadmitted_decisions:
        raise ManifestIntegrityError(
            "Quarantine receipts must exactly match non-admitted terminal decisions"
        )


def _v3_fallback_ranks_not_increasing(
    attempts: Sequence[CandidateAttemptRecord],
) -> bool:
    """True when fallback queue ranks do not strictly increase."""
    ranks = [item.queue_rank for item in attempts]
    return any(right <= left for left, right in zip(ranks, ranks[1:]))


def _check_v3_no_fallback_after_admission(
    attempts: Sequence[CandidateAttemptRecord],
    admitted_decisions: set[str],
) -> None:
    """Reject fallback attempts issued after target admission."""
    for index, attempt in enumerate(attempts[:-1]):
        if attempt.candidate_id in admitted_decisions:
            raise ManifestIntegrityError("Fallback attempted after target admission")


def _v3_primary_candidate_not_first(
    attempts: Sequence[CandidateAttemptRecord],
) -> bool:
    """True when the first attempt is not the primary candidate."""
    return bool(attempts) and not attempts[0].is_primary


def _check_v3_fallback_attempts(
    attempts: Sequence[CandidateAttemptRecord],
    admitted_decisions: set[str],
) -> None:
    """Require fallback ordering: increasing ranks, primary first, then no
    fallback after admission."""
    if _v3_fallback_ranks_not_increasing(attempts):
        raise ManifestIntegrityError(
            "Fallback attempts must have increasing queue rank"
        )
    if _v3_primary_candidate_not_first(attempts):
        raise ManifestIntegrityError(
            "Primary candidate must be attempted before fallback"
        )
    if any(item.is_primary for item in attempts[1:]):
        raise ManifestIntegrityError("Only the first target attempt may be primary")
    _check_v3_no_fallback_after_admission(attempts, admitted_decisions)


def _check_v3_fallback_order(
    attempts_by_target: dict[str, list[CandidateAttemptRecord]],
    admitted_decisions: set[str],
) -> None:
    """Require fallback ordering invariants per target."""
    for attempts in attempts_by_target.values():
        _check_v3_fallback_attempts(attempts, admitted_decisions)


def _v3_target_admitted_ids(
    target: Any,
    admitted_decisions: set[str],
) -> list[str]:
    """Return the target's attempted candidates that were admitted."""
    return [
        candidate_id
        for candidate_id in target.attempted_candidate_ids
        if candidate_id in admitted_decisions
    ]


def _check_v3_target_terminal_state(
    target: Any,
    final: FinalizationInventoryV1,
    admitted_decisions: set[str],
) -> None:
    """Require an admitted/exhausted target to match terminal decisions."""
    target_admitted = _v3_target_admitted_ids(target, admitted_decisions)
    if target.target_state is TargetState.admitted:
        if target_admitted != [target.admitted_candidate_id]:
            raise ManifestIntegrityError(
                "Coverage target admission does not match terminal decision"
            )
    elif target.target_state is not TargetState.exhausted:
        raise ManifestIntegrityError(
            "Completed manifest v3 targets must be admitted or exhausted"
        )
    _check_v3_target_terminal_transition(target, final)


def _v3_target_transitions(
    final: FinalizationInventoryV1,
    target_id: str,
) -> list[TransitionRecord]:
    """Return the durable transitions for one effective target."""
    return [
        item for item in final.transitions if item.target_entry_point_id == target_id
    ]


def _check_v3_target_terminal_transition(
    target: Any,
    final: FinalizationInventoryV1,
) -> None:
    """Require the target's final transition to match its target state."""
    target_transitions = _v3_target_transitions(final, target.effective_target_id)
    expected_terminal = (
        LifecycleState.admitted
        if target.target_state is TargetState.admitted
        else LifecycleState.exhausted
    )
    if (
        not target_transitions
        or target_transitions[-1].current is not expected_terminal
    ):
        raise ManifestIntegrityError(
            "Coverage target state does not match its terminal transition"
        )


def _check_v3_target_terminal_states(
    final: FinalizationInventoryV1,
    coverage: CoveragePlanV2,
    admitted_decisions: set[str],
) -> None:
    """Require every coverage target terminal state to reconcile."""
    for target in coverage.targets:
        _check_v3_target_terminal_state(target, final, admitted_decisions)


def _v3_manifest_scenario_entries(manifest: Any) -> set[tuple[Any, ...]]:
    """Return scenario/quarantine manifest entry keys."""
    return {
        (entry.role, entry.path, entry.candidate_id, entry.scenario_id, entry.sha256)
        for entry in manifest.inventory
        if entry.role
        in {
            ArtifactRole.SCENARIO_YAML,
            ArtifactRole.SCENARIO_FEATURE,
            ArtifactRole.QUARANTINE_BUNDLE,
        }
    }


def _v3_receipt_entries(final: FinalizationInventoryV1) -> set[tuple[Any, ...]]:
    """Return finalization receipt entry keys."""
    return {
        (item.role, item.path, item.candidate_id, item.scenario_id, item.sha256)
        for item in [*final.admitted_inventory, *final.quarantine_inventory]
    }


def _check_v3_manifest_receipts(
    resolver: Any,
    final: FinalizationInventoryV1,
) -> None:
    """Require finalization receipts and manifest entries to match exactly."""
    manifest_entries = _v3_manifest_scenario_entries(resolver.manifest)
    receipt_entries = _v3_receipt_entries(final)
    if manifest_entries != receipt_entries:
        raise ManifestIntegrityError(
            "Finalization receipts and manifest entries must match exactly"
        )


def _v3_receipts_for(
    receipts: Sequence[ArtifactReceipt],
    candidate_id: str,
) -> list[ArtifactReceipt]:
    """Return receipts for one candidate."""
    return [item for item in receipts if item.candidate_id == candidate_id]


def _admitted_receipt_roles_mismatch(receipts: Sequence[ArtifactReceipt]) -> bool:
    """True when admitted receipts are not exactly one YAML/feature pair."""
    return sorted(
        (item.role for item in receipts), key=lambda role: role.value
    ) != sorted(
        [ArtifactRole.SCENARIO_YAML, ArtifactRole.SCENARIO_FEATURE],
        key=lambda role: role.value,
    )


def _check_v3_admitted_receipt_pairs(
    final: FinalizationInventoryV1,
    admitted: set[str],
) -> None:
    """Require every admitted candidate to carry one YAML/feature pair."""
    for candidate_id in admitted:
        receipts = _v3_receipts_for(final.admitted_inventory, candidate_id)
        if _admitted_receipt_roles_mismatch(receipts):
            raise ManifestIntegrityError(
                "Every admitted candidate requires one YAML/feature pair"
            )
        if len({item.scenario_id for item in receipts}) != 1:
            raise ManifestIntegrityError(
                "Admitted YAML/feature receipts require the same scenario_id"
            )


def _check_v3_quarantined_receipts(
    final: FinalizationInventoryV1,
    quarantined: set[str],
) -> None:
    """Require every quarantined candidate to carry one bundle only."""
    for candidate_id in quarantined:
        receipts = _v3_receipts_for(final.quarantine_inventory, candidate_id)
        if len(receipts) != 1 or receipts[0].role is not ArtifactRole.QUARANTINE_BUNDLE:
            raise ManifestIntegrityError(
                "Every quarantined candidate requires one bundle only"
            )


def _v3_eval_scorecard_candidates(manifest: Any) -> set[Any]:
    """Return candidate IDs carrying an eval scorecard entry."""
    return {
        entry.candidate_id
        for entry in manifest.inventory
        if entry.role is ArtifactRole.EVAL_SCORECARD and entry.candidate_id
    }


def _v3_bundle_candidates(manifest: Any) -> set[Any]:
    """Return candidate IDs carrying a quarantine bundle entry."""
    return {
        entry.candidate_id
        for entry in manifest.inventory
        if entry.role is ArtifactRole.QUARANTINE_BUNDLE
    }


def _v3_normal_scenario_candidates(manifest: Any) -> set[Any]:
    """Return candidate IDs carrying normal scenario roles."""
    return {
        entry.candidate_id
        for entry in manifest.inventory
        if entry.role in {ArtifactRole.SCENARIO_YAML, ArtifactRole.SCENARIO_FEATURE}
    }


def _check_v3_eval_and_role_scopes(
    resolver: Any,
    quarantined: set[str],
    admitted: set[str],
) -> None:
    """Reject normal/eval roles on quarantined candidates and require normal
    scenario inventory to contain admitted candidates only."""
    eval_candidates = _v3_eval_scorecard_candidates(resolver.manifest)
    if eval_candidates & quarantined:
        raise ManifestIntegrityError(
            "Evaluation inventory contains quarantined candidate"
        )
    bundle_candidates = _v3_bundle_candidates(resolver.manifest)
    normal_candidates = _v3_normal_scenario_candidates(resolver.manifest)
    if bundle_candidates & normal_candidates:
        raise ManifestIntegrityError(
            "Quarantine candidate carries a normal scenario role"
        )
    if normal_candidates != admitted:
        raise ManifestIntegrityError(
            "Normal scenario inventory must contain admitted candidates only"
        )


def _v3_attempt_for(
    final: FinalizationInventoryV1,
    candidate_id: str,
) -> CandidateAttemptRecord:
    """Return the candidate's durable attempt."""
    return next(
        item for item in final.candidate_attempts if item.candidate_id == candidate_id
    )


def _v3_stage_attempts_for(
    final: FinalizationInventoryV1,
    candidate_id: str,
) -> list[StageAttemptRecord]:
    """Return the candidate's stage attempts."""
    return [item for item in final.stage_attempts if item.candidate_id == candidate_id]


def _v3_repairs_for(
    final: FinalizationInventoryV1,
    candidate_id: str,
) -> list[ParsimonyRepairRecord]:
    """Return the candidate's parsimony repair records."""
    return [item for item in final.repairs if item.candidate_id == candidate_id]


def _check_v3_admitted_causal_evidence(
    final: FinalizationInventoryV1,
    plan_by_candidate: dict[str, tuple[Any, Any]],
    admitted: set[str],
) -> None:
    """Require each admitted candidate's durable stage evidence to reduce to a
    causal artifact frontier."""
    for candidate_id in admitted:
        attempt = _v3_attempt_for(final, candidate_id)
        _causal_stage_artifacts(
            _v3_stage_attempts_for(final, candidate_id),
            candidate_attempt_id=attempt.attempt_id,
            durable_candidate=plan_by_candidate[candidate_id][1].projected_candidate,
            repairs=_v3_repairs_for(final, candidate_id),
        )


def _v3_read_bundle(resolver: Any, entry: Any) -> QuarantineBundleV1:
    """Load and validate one quarantine bundle."""
    try:
        return QuarantineBundleV1.model_validate(resolver.read_json(entry))
    except Exception as exc:
        raise ManifestIntegrityError(
            f"Invalid quarantine bundle {entry.path}: {exc}"
        ) from exc


def _v3_bundle_identity_mismatch(
    bundle: QuarantineBundleV1,
    resolver: Any,
    entry: Any,
) -> bool:
    """True when a bundle's run/candidate identity or path diverges."""
    return (
        bundle.run_id != resolver.manifest.run_id
        or bundle.candidate_id != entry.candidate_id
        or entry.path != f"quarantine/{bundle.attempt_id}.json"
    )


def _v3_bundle_attempt_mismatch(
    attempt: CandidateAttemptRecord | None,
    bundle: QuarantineBundleV1,
) -> bool:
    """True when a bundle does not match its candidate attempt."""
    return (
        attempt is None
        or attempt.attempt_id != bundle.attempt_id
        or attempt.target_entry_point_id != bundle.target_entry_point_id
    )


def _v3_attempt_or_none(
    final: FinalizationInventoryV1,
    candidate_id: str,
) -> CandidateAttemptRecord | None:
    """Return the candidate's durable attempt, if any."""
    return next(
        (
            item
            for item in final.candidate_attempts
            if item.candidate_id == candidate_id
        ),
        None,
    )


def _v3_decision_for(
    final: FinalizationInventoryV1,
    candidate_id: str,
) -> AdmissionDecisionRecord:
    """Return the candidate's terminal admission decision."""
    return next(
        item for item in final.admission_decisions if item.candidate_id == candidate_id
    )


def _check_v3_bundle_identity(
    bundle: QuarantineBundleV1,
    resolver: Any,
    entry: Any,
) -> None:
    """Reject a quarantine bundle whose identity or path diverges."""
    if _v3_bundle_identity_mismatch(bundle, resolver, entry):
        raise ManifestIntegrityError(
            f"Quarantine bundle identity/path mismatch: {entry.path}"
        )


def _check_v3_bundle_attempt(
    bundle: QuarantineBundleV1,
    attempt: CandidateAttemptRecord | None,
    entry: Any,
) -> None:
    """Reject a quarantine bundle that does not match its candidate attempt."""
    if _v3_bundle_attempt_mismatch(attempt, bundle):
        raise ManifestIntegrityError(
            f"Quarantine bundle does not match candidate attempt: {entry.path}"
        )


def _check_v3_bundle_violations(
    bundle: QuarantineBundleV1,
    decision: AdmissionDecisionRecord,
    entry: Any,
) -> None:
    """Reject bundle violations that diverge from the terminal decision."""
    if bundle.violations != decision.violations:
        raise ManifestIntegrityError(
            f"Quarantine bundle violations mismatch terminal decision: {entry.path}"
        )


def _check_v3_bundle_stage_evidence(
    bundle: QuarantineBundleV1,
    causal_artifacts: dict[GeneratedStage, JsonValue],
    entry: Any,
) -> None:
    """Require each bundle stage artifact to match causal stage evidence."""
    for stage in GeneratedStage:
        if getattr(bundle, stage.value) != causal_artifacts.get(stage):
            raise ManifestIntegrityError(
                f"Quarantine bundle {stage.value} evidence mismatch: {entry.path}"
            )


def _check_v3_quarantine_bundles(
    resolver: Any,
    final: FinalizationInventoryV1,
    plan_by_candidate: dict[str, tuple[Any, Any]],
) -> None:
    """Require every quarantine bundle to reconcile with the finalization
    inventory."""
    for entry in resolver.entries_by_role(ArtifactRole.QUARANTINE_BUNDLE):
        bundle = _v3_read_bundle(resolver, entry)
        _check_v3_bundle_identity(bundle, resolver, entry)
        attempt = _v3_attempt_or_none(final, bundle.candidate_id)
        _check_v3_bundle_attempt(bundle, attempt, entry)
        decision = _v3_decision_for(final, bundle.candidate_id)
        _check_v3_bundle_violations(bundle, decision, entry)
        causal_artifacts = _causal_stage_artifacts(
            _v3_stage_attempts_for(final, bundle.candidate_id),
            candidate_attempt_id=attempt.attempt_id,
            durable_candidate=plan_by_candidate[bundle.candidate_id][
                1
            ].projected_candidate,
            repairs=_v3_repairs_for(final, bundle.candidate_id),
        )
        _check_v3_bundle_stage_evidence(bundle, causal_artifacts, entry)


def _check_v3_completed_status(
    resolver: Any,
    quarantined: set[str],
) -> None:
    """Require the manifest status to match the presence of quarantine."""
    if quarantined and resolver.manifest.status is not RunStatus.COMPLETED_WITH_ERRORS:
        raise ManifestIntegrityError(
            "Manifest v3 quarantine inventory requires completed_with_errors"
        )
    if not quarantined and resolver.manifest.status not in {
        RunStatus.COMPLETED,
        RunStatus.COMPLETED_WITH_ERRORS,
    }:
        raise ManifestIntegrityError(
            "Manifest v3 inventory requires a completed status"
        )


def _violations(values: Any) -> list[ViolationRecord]:
    records: list[ViolationRecord] = []
    for value in values:
        owner = getattr(value, "owner", None)
        code = getattr(value, "code", "invalid")
        if isinstance(code, Enum):
            serialized_code = code.value
        elif isinstance(code, str):
            serialized_code = code
        else:
            raise TypeError("violation code must be a string or enum")
        records.append(
            ViolationRecord(
                code=serialized_code,
                detail=value.detail,
                owner=owner,
                retryable=getattr(value, "retryable", owner is not None),
            )
        )
    return records
