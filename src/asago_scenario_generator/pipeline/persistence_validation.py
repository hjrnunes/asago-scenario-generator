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
from asago_scenario_generator.pipeline.finalization_contracts import (
    CandidateTerminalStatus,
    GeneratedStage,
    LifecycleState,
)
from asago_scenario_generator.pipeline.finalization_gates import AdmissionEvidenceId
from asago_scenario_generator.pipeline.projection_contracts import canonical_json_bytes
from asago_scenario_generator.pipeline.persistence_artifacts import ArtifactReceipt
from asago_scenario_generator.pipeline.persistence_checkpoint import (
    read_planning_checkpoint_bytes,
    validate_planning_checkpoint,
)
from asago_scenario_generator.pipeline.persistence_common import canonical_sha256
from asago_scenario_generator.pipeline.persistence_decisions import (
    AdmissionDecisionRecord,
)
from asago_scenario_generator.pipeline.persistence_journal import (
    FinalizationInventoryV1,
    QuarantineBundleV1,
)
from asago_scenario_generator.pipeline.persistence_models import (
    CandidateAttemptRecord,
    ParsimonyRepairRecord,
    StageAttemptRecord,
    TransitionRecord,
    ViolationRecord,
)
from asago_scenario_generator.pipeline.persistence_plan import (
    CoveragePlanV2,
    StrictModel,
    TargetState,
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


def _require_bound_stage_snapshot(
    record: StageAttemptRecord,
    durable_candidate: JsonValue | None,
) -> None:
    """Reject a stage snapshot that diverges from the pinned durable plan."""
    if durable_candidate is not None and record.input.candidate != durable_candidate:
        raise ValueError("stage candidate snapshot differs from durable plan")


def _require_input_bound_tree(
    record: StageAttemptRecord,
    visible_tree: JsonValue | None,
) -> None:
    """Reject behavior evidence unbound to its final-tree input."""
    if visible_tree is None or record.final_tree_snapshot_sha256 != canonical_sha256(
        visible_tree
    ):
        raise ValueError("behavior evidence is not bound to its final-tree input")


def _require_generated_tree(generated_tree: JsonValue | None) -> None:
    """Reject behavior evidence without a causally generated tree."""
    if generated_tree is None:
        raise ValueError("behavior evidence has no causal generated tree")


def _repair_links_attempt(
    repair: ParsimonyRepairRecord,
    candidate_attempt_id: str,
    sequence: int,
) -> bool:
    """True when the repair is accepted, on-attempt, and strictly prior."""
    return (
        repair.accepted
        and repair.candidate_attempt_id == candidate_attempt_id
        and repair.sequence < sequence
    )


def _repair_covers_digests(
    repair: ParsimonyRepairRecord,
    before_digest: str,
    after_digest: str,
) -> bool:
    """True when the repair links exactly this digest transition."""
    return repair.before_digest == before_digest and repair.after_digest == after_digest


def _has_accepted_tree_repair(
    repairs: Sequence[ParsimonyRepairRecord],
    candidate_attempt_id: str,
    sequence: int,
    before_digest: str,
    after_digest: str,
) -> bool:
    """True when an accepted prior repair links the digest transition."""
    for repair in repairs:
        if _repair_links_attempt(
            repair, candidate_attempt_id, sequence
        ) and _repair_covers_digests(repair, before_digest, after_digest):
            return True
    return False


def _require_tree_linkage(
    record: StageAttemptRecord,
    visible_tree: JsonValue,
    generated_tree: JsonValue,
    candidate_attempt_id: str,
    repairs: Sequence[ParsimonyRepairRecord],
) -> None:
    """Reject a tree transition that is neither generated nor repair-linked."""
    before_digest = canonical_sha256(generated_tree)
    after_digest = canonical_sha256(visible_tree)
    if before_digest != after_digest and not _has_accepted_tree_repair(
        repairs,
        candidate_attempt_id,
        record.sequence,
        before_digest,
        after_digest,
    ):
        raise ValueError(
            "behavior tree is neither generated nor linked by accepted repair"
        )


def _bound_behavior_tree(
    record: StageAttemptRecord,
    visible: dict[str, JsonValue],
    frontier: dict[GeneratedStage, JsonValue],
    candidate_attempt_id: str,
    repairs: Sequence[ParsimonyRepairRecord],
) -> JsonValue:
    """Validate and return the behavior stage's bound tree artifact."""
    visible_tree = visible.get(GeneratedStage.tree.value)
    _require_input_bound_tree(record, visible_tree)
    generated_tree = frontier.get(GeneratedStage.tree)
    _require_generated_tree(generated_tree)
    _require_tree_linkage(
        record, visible_tree, generated_tree, candidate_attempt_id, repairs
    )
    return visible_tree


def _require_frontier_contiguous(
    visible: dict[str, JsonValue],
    frontier: dict[GeneratedStage, JsonValue],
) -> None:
    """Reject stage evidence that is not one contiguous causal frontier."""
    expected_visible = {stage.value: artifact for stage, artifact in frontier.items()}
    if visible != expected_visible:
        raise ValueError("stage evidence is not one contiguous causal frontier")


def _has_frontier_result(record: StageAttemptRecord) -> bool:
    """True when the record contributes a result to the artifact frontier."""
    return (
        record.result is not None and not record.violations and record.call is not None
    )


def _fold_record_into_frontier(
    record: StageAttemptRecord,
    frontier: dict[GeneratedStage, JsonValue],
    order: tuple[GeneratedStage, ...],
    candidate_attempt_id: str,
    durable_candidate: JsonValue | None,
    repairs: Sequence[ParsimonyRepairRecord],
) -> None:
    """Fold one stage record into the causally contiguous artifact frontier."""
    _require_bound_stage_snapshot(record, durable_candidate)
    for invalidated in order[order.index(record.stage) :]:
        frontier.pop(invalidated, None)
    visible = dict(record.input.visible_artifacts)
    if record.stage is GeneratedStage.behavior:
        frontier[GeneratedStage.tree] = _bound_behavior_tree(
            record, visible, frontier, candidate_attempt_id, repairs
        )
    _require_frontier_contiguous(visible, frontier)
    if _has_frontier_result(record):
        frontier[record.stage] = record.result


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
        _fold_record_into_frontier(
            record,
            frontier,
            order,
            candidate_attempt_id,
            durable_candidate,
            repairs,
        )
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
        RunStatus.COMPLETED_WITH_WARNINGS,
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


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-24T10:04:08Z","module_hash":"290bbe03657cae6fd5589c158aaf8192fabdbba42e5a366c0e1e5c152f6171be","source_sha256":"1f54ac3c109ecedc18908a92b92c8bf8db2898d13d3245450d5af3a8e4938462","functions":[{"id":"func/_check_durable_event_ids","name":"_check_durable_event_ids","line":54,"end_line":58,"hash":"f91e95aab743433225916c42e79e29df259831ea63b3dd4d7a469a40c2c6eb0e"},{"id":"func/_check_durable_event_sequences","name":"_check_durable_event_sequences","line":61,"end_line":64,"hash":"4a31f6f238b60786fec17834c7537898b80876b0972977b6fcc303a6ad6385df"},{"id":"func/_attempt_ids","name":"_attempt_ids","line":67,"end_line":69,"hash":"2b01bcfdb43b3392bcae04c36b4554814d79c402e7f2fc4f7944a2583e0b9ae5"},{"id":"func/_candidate_ids","name":"_candidate_ids","line":72,"end_line":74,"hash":"995ae15f4cef29ca0d5f8a245e7a9be72679d73ee377cface35208324de49496"},{"id":"func/_check_unique_attempt_and_candidate_ids","name":"_check_unique_attempt_and_candidate_ids","line":77,"end_line":88,"hash":"8d8ad73208f415f507c1a587ab34bddd3b05dc42cc7ce6fb26395b7fd762f14c"},{"id":"func/_index_target_trace_events","name":"_index_target_trace_events","line":91,"end_line":107,"hash":"96dbcc9833cdcace681c4da5e79fa10b458e402d20f7a6a3706c8b906d1b3fbd"},{"id":"func/_target_trace_terminal_edges","name":"_target_trace_terminal_edges","line":110,"end_line":126,"hash":"040dff782318fbbc91e6171647ef009e7b37bff7a8512e8c2f90bd0226e09835"},{"id":"func/_transition_indexes_contiguous","name":"_transition_indexes_contiguous","line":129,"end_line":135,"hash":"99dffe4b928c3fd385a610563d019eb91b643564b535086655c8ee732fb21481"},{"id":"func/_check_target_transition_indexes","name":"_check_target_transition_indexes","line":138,"end_line":149,"hash":"9650fda71fdfe5321b00a499dc2afc7ebe95b8481582c0be61f2d25bdb23e457"},{"id":"func/_check_target_candidate_trace","name":"_check_target_candidate_trace","line":161,"end_line":180,"hash":"e21082ab0c7c4e8df2fbc7ab14e3c61db4dbc93c617d5ae160651f17698dcd88"},{"id":"func/_revalidating_segment_invalid","name":"_revalidating_segment_invalid","line":183,"end_line":195,"hash":"4106c58bbd55a632cc02bc69f988dac5197fb742bf78bc16338365738debcd8b"},{"id":"func/_check_revalidating_segment","name":"_check_revalidating_segment","line":198,"end_line":214,"hash":"3c1b4e85e92c3008fbd332edd0440dd4d0b17fd9bb4e07b861df21c4a072af19"},{"id":"func/_check_exhausted_segment","name":"_check_exhausted_segment","line":217,"end_line":229,"hash":"d8f19ec8559a2da450e2e54509f2041ae4c6cb960c024de0268b8656252dd9c6"},{"id":"func/_check_active_segment","name":"_check_active_segment","line":232,"end_line":248,"hash":"03920df78e84868ef2f5e28b74432b57a32773898a863e4714e657626d428935"},{"id":"func/_legal_lifecycle_edges","name":"_legal_lifecycle_edges","line":251,"end_line":283,"hash":"6c253504a40cd54814fb6e50e72239b3b5f38e8bf556ec97ef29c661e18f56b5"},{"id":"func/_generating_state_by_stage","name":"_generating_state_by_stage","line":286,"end_line":293,"hash":"c73b026e9f14effd9480abd6935557638991d128aa84be0bd87fdafe46899f03"},{"id":"func/_check_lifecycle_edges","name":"_check_lifecycle_edges","line":296,"end_line":303,"hash":"081d83467173f3aaf3ae1ea829bfc2ced92dddc9976093998d98a0a28882be64"},{"id":"func/_stage_reference_invalid","name":"_stage_reference_invalid","line":306,"end_line":312,"hash":"eb5b57ee62b886821c63181c468b5a6032d76fa2bc7aea784f048d3a9dcb4931"},{"id":"func/_stage_attempts_by_id","name":"_stage_attempts_by_id","line":315,"end_line":319,"hash":"50a15d886e7eb36f87833e58ec87d9872c78fff172475dc233fef97c5a9396ee"},{"id":"func/_attempts_by_id","name":"_attempts_by_id","line":322,"end_line":326,"hash":"28bf3db92b16d4e92b2da76ae336c0f5085bf8dac12def7856899c57d23b5537"},{"id":"func/_check_stage_references","name":"_check_stage_references","line":329,"end_line":344,"hash":"8dd346c1b0488c0e1a62d565eb02ad9b8a91dab351c9bedfc2ce24bf655fc2ee"},{"id":"func/_repair_mismatches_attempt","name":"_repair_mismatches_attempt","line":347,"end_line":356,"hash":"73ad4c758861423eb14899d02b80944e57e38f1df7b4433d41b3385785252d2c"},{"id":"func/_subsequent_behavior_inputs","name":"_subsequent_behavior_inputs","line":359,"end_line":370,"hash":"4c36313d45f39ffc70b7df62c2f2ba8043ae0c4a00f4dec15883e849a77913ff"},{"id":"func/_check_repair_records","name":"_check_repair_records","line":373,"end_line":390,"hash":"57bd4da629e6f501e90db3461ee06a20e484a987e62bc759c000141d2cb8d538"},{"id":"func/_stage_invocation_indexes_contiguous","name":"_stage_invocation_indexes_contiguous","line":393,"end_line":397,"hash":"bda68da18bddeee784e70be22a9779572ad9df9c17ecdbfc95381ffacf6dc868"},{"id":"func/_stage_retry_indexes_not_monotonic","name":"_stage_retry_indexes_not_monotonic","line":400,"end_line":405,"hash":"7528abf995b6de6eb09ebecd93c02b7c7e61adf2476105734dea76edfc050fcc"},{"id":"func/_check_stage_invocation_indexes","name":"_check_stage_invocation_indexes","line":408,"end_line":421,"hash":"762d402d42d644147c711378fdd5578a3c6f429c5524d204e6286761fd3f1bc8"},{"id":"func/_generating_transitions_for","name":"_generating_transitions_for","line":424,"end_line":438,"hash":"659927a7c993967b35263a972ea47efe928d57133de9eb72b2417ec7e4c747f5"},{"id":"func/_stage_attempts_for","name":"_stage_attempts_for","line":441,"end_line":449,"hash":"e9f3435bebf735542bb09c983e12111fb606ea53bf34e80117c18e7ac7320609"},{"id":"func/_generating_transition_count_mismatch","name":"_generating_transition_count_mismatch","line":452,"end_line":461,"hash":"ec707deb8f50bf9455ff8eaa0ab66a2fd150b079ee9295c975874d51e34127e2"},{"id":"func/_decision_for_candidate","name":"_decision_for_candidate","line":464,"end_line":472,"hash":"f3d1ec54c785ecd41850f462e86f2c0231c114cf23a4fb281cdb723a297e4008"},{"id":"func/_later_candidate_events","name":"_later_candidate_events","line":475,"end_line":495,"hash":"5d224d443c78874e7ceb46d1e9fe48b65f8006f865a2d2f4b74773ce2935878f"},{"id":"func/_unknown_terminal_adjacency","name":"_unknown_terminal_adjacency","line":498,"end_line":509,"hash":"07446a49b2bd2d4a6c6c836e6c1cfb1f0c1ad7af8243d18e771642578684b823"},{"id":"func/_unknown_terminal_edge_order","name":"_unknown_terminal_edge_order","line":512,"end_line":523,"hash":"10f9381ccbde6fef5958bdeb5a9c28d2a5159b9b04f846d61185d585675c5474"},{"id":"func/_unknown_outcome_decision","name":"_unknown_outcome_decision","line":526,"end_line":532,"hash":"5c92ca0b468cf6884a40fc53d261a0d691d643010ec8225a5167a8cd8d0bbf70"},{"id":"func/_single_unknown_invocation_violation","name":"_single_unknown_invocation_violation","line":535,"end_line":545,"hash":"333de51bd0df75ed22b9c484aff4817f94ac0ad94228f83d4d8bd9936c805a18"},{"id":"func/_single_quarantine_bundle_receipt","name":"_single_quarantine_bundle_receipt","line":548,"end_line":555,"hash":"5c946fdb266d1125a6b95d494d25b9bd1d80a730a24bb849ac39fb15a42cb017"},{"id":"func/_no_later_stage_or_repair_events","name":"_no_later_stage_or_repair_events","line":558,"end_line":569,"hash":"bc935a37fdc0345cbcc74dffc8154ca24fbe9281ba085b38ff1e7c1bc88a0ceb"},{"id":"func/_unknown_terminal_trace_matches","name":"_unknown_terminal_trace_matches","line":572,"end_line":581,"hash":"9d9af383310cdf43d1c993f4df023e2de8214d55745d5baa252e21753fde30ac"},{"id":"func/_unknown_terminal_decision_matches","name":"_unknown_terminal_decision_matches","line":584,"end_line":600,"hash":"2177159bcbdab48de246b342ba23b1bdab1cb71ea3ade30675a17e7c798372c9"},{"id":"func/_is_exact_unknown_terminal","name":"_is_exact_unknown_terminal","line":603,"end_line":621,"hash":"34481f9af934f803efcf456068cf0b990df55151673ccff164026148b59c9ce0"},{"id":"func/_check_unmatched_generating_transition","name":"_check_unmatched_generating_transition","line":624,"end_line":656,"hash":"f359117b6bd7b36186478575fbd0a9ed34a30f62340c09e757058b43db60d50a"},{"id":"func/_generating_stage_pairing_mismatch","name":"_generating_stage_pairing_mismatch","line":659,"end_line":670,"hash":"792c42882de1c2796156ee45546306b9d71dd7c26fec932f9f8f1800cb46c3c7"},{"id":"func/_check_generating_stage_pairing","name":"_check_generating_stage_pairing","line":673,"end_line":681,"hash":"823362b823a326194a68b7c7156ed564b042d6d90aa8abb28e0e6bf0276bb95e"},{"id":"func/_check_generating_transition_traces","name":"_check_generating_transition_traces","line":684,"end_line":720,"hash":"cd5a10e2aaf61fb29cbe4b2b4d9dcbdee27e07a859e0f76ec8f9bbb47296ffe4"},{"id":"func/_candidate_stages_for","name":"_candidate_stages_for","line":723,"end_line":728,"hash":"9f5d7cac4ac1e02a53a6aa9bd3a8cabbd8238a7a1e4d277a0f9c7081603821f8"},{"id":"func/_check_stage_evidence_precedes_terminal","name":"_check_stage_evidence_precedes_terminal","line":731,"end_line":737,"hash":"925487d328700a367c58178cd4715e49056c93bc3a98a1ae045064832fa3234b"},{"id":"func/_check_terminal_precedes_decision","name":"_check_terminal_precedes_decision","line":740,"end_line":746,"hash":"eab95b85f27191f687b2791dca26c91fb9bc1a40c4e1d94cad00f96119c9c69f"},{"id":"func/_next_target_transition_after","name":"_next_target_transition_after","line":749,"end_line":768,"hash":"4aaa9b48f0699d5136d6b03c04433eaffe8b68818c85e97bfb4adffe1b5ed318"},{"id":"func/_check_decision_precedes_next_target_transition","name":"_check_decision_precedes_next_target_transition","line":771,"end_line":780,"hash":"891085723d37fec5395e92c48e9128552b2e4d5e0b37cceaf9d5ddf2f840a4c9"},{"id":"func/_check_postbehavior_admission_edge","name":"_check_postbehavior_admission_edge","line":783,"end_line":791,"hash":"7f96d81639528473c3dd83e33d36ed63259a7b635a5f644181a2dad88f8a0853"},{"id":"func/_check_admitting_edge_requires_gate_evidence","name":"_check_admitting_edge_requires_gate_evidence","line":794,"end_line":802,"hash":"e88afa02c52f769dd200d206532d9c41d3f10828df9cdf4f6406f5c6ced6198f"},{"id":"func/_check_gate_violations_match_terminal","name":"_check_gate_violations_match_terminal","line":805,"end_line":813,"hash":"42da7b45152514cc84844bddfc777369d8fdb1babae8b7a602e4f6b5bac2a94c"},{"id":"func/_admitted_missing_passing_gate_evidence","name":"_admitted_missing_passing_gate_evidence","line":816,"end_line":824,"hash":"6530420f6702ca0aa275aa6cafe963c20b10309ba468144fa18cc02b70e5552e"},{"id":"func/_check_admitted_requires_passing_gates","name":"_check_admitted_requires_passing_gates","line":827,"end_line":832,"hash":"cbb11c6ad12b6a353cd4a2911ffeb26390dff6408d072a8c9d3f362347086c7b"},{"id":"func/_causal_artifacts_for_decision","name":"_causal_artifacts_for_decision","line":835,"end_line":853,"hash":"1c2e0e22c03991515318584d8fea0cb02263000a45553978d1ba7b872339d6a1"},{"id":"func/_expected_admission_snapshots","name":"_expected_admission_snapshots","line":856,"end_line":872,"hash":"b55e69a76ba45aff9e751a47a57af644d9ac567a7755cf8b9a11dd97a9bca066"},{"id":"func/_check_admission_snapshot_digests","name":"_check_admission_snapshot_digests","line":875,"end_line":893,"hash":"a8bc3ad78c6a1e58673e81ef9807ff3e8a922989dee4592a7fcc20169fcda462"},{"id":"func/_check_admission_decision","name":"_check_admission_decision","line":896,"end_line":928,"hash":"a287bd58682411ce16a8a4083746853e4c28133e043745846a4ba4c65793125d"},{"id":"func/_check_terminal_decisions","name":"_check_terminal_decisions","line":931,"end_line":953,"hash":"809e3ea41cc70d24635e7d8bbf079e22b8b4af21b8f9c1bf380212184a048c0f"},{"id":"func/_receipt_keys","name":"_receipt_keys","line":956,"end_line":958,"hash":"878b19b162e2609272ab32cdda85d4143e5879a008b9b68cb1b46d1e414cf3b1"},{"id":"func/_decision_receipt_keys","name":"_decision_receipt_keys","line":961,"end_line":969,"hash":"dd014049dea95ceaaf62bac88569072ac68fe8839e709aa4bf3c65c7f6f6e20c"},{"id":"func/_receipt_inventories_mismatched","name":"_receipt_inventories_mismatched","line":972,"end_line":982,"hash":"e4f4043fe164581fd9b29bcdfc425b82a690c09ca468ac65c78803a7b8888ed0"},{"id":"func/_check_receipt_inventories","name":"_check_receipt_inventories","line":985,"end_line":1002,"hash":"d6818ac1b182dd8f423fd98ef54281c08e591c953bdcd86bdfed5d6745216c43"},{"id":"func/_require_bound_stage_snapshot","name":"_require_bound_stage_snapshot","line":1005,"end_line":1011,"hash":"68502b8c5672865f137923a0dc853d80f22a3454d7c4669c27c1e2fbf9107287"},{"id":"func/_require_input_bound_tree","name":"_require_input_bound_tree","line":1014,"end_line":1022,"hash":"cd04572a95f0181b9dbf57887fb88474f022ec161c45b7e089752f5ba18962c0"},{"id":"func/_require_generated_tree","name":"_require_generated_tree","line":1025,"end_line":1028,"hash":"eb5aa2a458f83dbc7b1351e867fb9d3b47e79f1dbf703c51db3443c64f259f77"},{"id":"func/_repair_links_attempt","name":"_repair_links_attempt","line":1031,"end_line":1041,"hash":"ecfb556a24d5065bf74ba9e22af03cc2541fea075f3ea7f219835c7e6e1f9804"},{"id":"func/_repair_covers_digests","name":"_repair_covers_digests","line":1044,"end_line":1050,"hash":"846ec040a95334b4aa58438644fa518bf3b4122b4bf2258b30c42ebafadee0d1"},{"id":"func/_has_accepted_tree_repair","name":"_has_accepted_tree_repair","line":1053,"end_line":1066,"hash":"6473c0559ee2067398a094266e23070dbfc8e84309c58a0a77d01c9412c5cbca"},{"id":"func/_require_tree_linkage","name":"_require_tree_linkage","line":1069,"end_line":1088,"hash":"46f44502ad87435ed80906452427766c51943aef1ce1fc8478c8e68536905f56"},{"id":"func/_bound_behavior_tree","name":"_bound_behavior_tree","line":1091,"end_line":1106,"hash":"6bc1945a328b3b571714d56e6606886ad664304062a5b00ae3f6f13ca4986251"},{"id":"func/_require_frontier_contiguous","name":"_require_frontier_contiguous","line":1109,"end_line":1116,"hash":"a830ae4beaca49b4bf5c108d98d0bfac2bba11dd5ddc52ffb24720daca8485ed"},{"id":"func/_has_frontier_result","name":"_has_frontier_result","line":1119,"end_line":1123,"hash":"b6b614e5e3ed52b2dc57ba94534872b8fe54965ee24c08061a325c8277fb3213"},{"id":"func/_fold_record_into_frontier","name":"_fold_record_into_frontier","line":1126,"end_line":1145,"hash":"5056df53d07013fee327139a2cddd23cb01b0cc86d07bd0092738ad3dc74b215"},{"id":"func/_causal_stage_artifacts","name":"_causal_stage_artifacts","line":1148,"end_line":1167,"hash":"6c7d0506a8fa21ff01f9ac6604e43d500ffa8d4c9004823ee0cd4777410c63a6"},{"id":"func/validate_v3_inventories","name":"validate_v3_inventories","line":1170,"end_line":1207,"hash":"d7a07b8e4590cf353c82ac3bad92e0740fafbfa37c6fe5640d879cb219b65024"},{"id":"func/_check_v3_journal_unresolved","name":"_check_v3_journal_unresolved","line":1210,"end_line":1215,"hash":"ae3e1454170acb1c60f127f2239a84e776b2112c7de4f5346151d07627b7db4d"},{"id":"func/_v3_persistence_entries","name":"_v3_persistence_entries","line":1218,"end_line":1225,"hash":"7d620c381731a24b4d2ca7ff32c79de331f38f9cecfed554dfc8a4196111cf20"},{"id":"func/_v3_load_persistence_models","name":"_v3_load_persistence_models","line":1228,"end_line":1243,"hash":"1c299856238accf33a57501f15a8662069ee3e657ba563876322c3f2fb1005bc"},{"id":"func/_check_v3_run_identity","name":"_check_v3_run_identity","line":1246,"end_line":1255,"hash":"bcd9bb2edfbf80eb74a4cb1be60e7e9926001d35e574b1ef7734e03519083809"},{"id":"func/_v3_admitted_decisions","name":"_v3_admitted_decisions","line":1258,"end_line":1262,"hash":"a7d5712b658d98f9b1c7379a0270c96907cef36291b26516216fdd80b245112a"},{"id":"func/_v3_profile_applicability","name":"_v3_profile_applicability","line":1265,"end_line":1283,"hash":"a6c3d96879f6b3ef67baf14b9053ac67d2195102c37d6b806f05c502b68b0288"},{"id":"func/_v3_decision_gate_applicability_mismatch","name":"_v3_decision_gate_applicability_mismatch","line":1286,"end_line":1295,"hash":"269f3e40a19f8f566c81c82e28411c0259f0da7245e7cfe9ebbd435d98821b25"},{"id":"func/_check_v3_gate_applicability","name":"_check_v3_gate_applicability","line":1298,"end_line":1312,"hash":"0bc3dcdea6ee992b0ef20d5189ab56a3277ce4f44298368eb0ca254a41091afa"},{"id":"func/_v3_plan_by_candidate","name":"_v3_plan_by_candidate","line":1315,"end_line":1323,"hash":"0144581e5beae22365a5dda22e1bf63142a5f0d4282178dcdaaae7ad19db67af"},{"id":"func/_v3_transition_plan_mismatch","name":"_v3_transition_plan_mismatch","line":1326,"end_line":1334,"hash":"2576b0e3a3712ef008b48ea2beb956704141da2e3451d8a7b6c3bacd68e11e02"},{"id":"func/_check_v3_transition_in_plan","name":"_check_v3_transition_in_plan","line":1337,"end_line":1351,"hash":"c9361b39eee79b5995a03431a4ea7dcda00c307ce0e251d6e8f1cd607aaa3a3b"},{"id":"func/_check_v3_transitions_in_plan","name":"_check_v3_transitions_in_plan","line":1354,"end_line":1363,"hash":"d22bb99601d5f0bc205d68eb7a8af96282b2335c98b33825331aaccf0999af1d"},{"id":"func/_v3_receipt_candidate_sets","name":"_v3_receipt_candidate_sets","line":1366,"end_line":1372,"hash":"9875a242ed2d450469d69393c6db6644c43000aaf5cf48626a1c242ce1211dc4"},{"id":"func/_check_v3_inventory_disjoint","name":"_check_v3_inventory_disjoint","line":1375,"end_line":1381,"hash":"9b9ff5ba818f732acf84aa4cced79e0c8ec4b5437a68c01bdc8d8fbb890b073c"},{"id":"func/_v3_attempt_plan_mismatch","name":"_v3_attempt_plan_mismatch","line":1384,"end_line":1393,"hash":"dc2d249421f55ff4284e2e60001e721e1c43635929b68edfb9c11fc70bf262a6"},{"id":"func/_check_v3_attempts_match_plan","name":"_check_v3_attempts_match_plan","line":1396,"end_line":1410,"hash":"d5efb76a17c4aaee4079f738c7305e63d7ee08787071e814e166c1a68fc13514"},{"id":"func/_v3_attempts_by_target","name":"_v3_attempts_by_target","line":1413,"end_line":1420,"hash":"b0ffb7775ec9948bf2882a668af1db31983f69c15b4416a54536a924819b86c7"},{"id":"func/_v3_candidate_ids","name":"_v3_candidate_ids","line":1423,"end_line":1425,"hash":"a9107059307585eea0a4fbaf3223017b7b03cfb28963fe5852e997f9c9faad3b"},{"id":"func/_v3_attempted_ids_by_target","name":"_v3_attempted_ids_by_target","line":1428,"end_line":1435,"hash":"43aeafa0b7cdab174ba64dfb41cad99ae354f42e6f7a97276388c35a3bf7c4b5"},{"id":"func/_check_v3_attempted_candidates_per_target","name":"_check_v3_attempted_candidates_per_target","line":1438,"end_line":1451,"hash":"4fbee4827044c0bcf8584b462bd6f4a52acf51796cb5a1dd62901d5050adb453"},{"id":"func/_v3_admitted_decision_ids","name":"_v3_admitted_decision_ids","line":1454,"end_line":1462,"hash":"3ccb43b65f70594fe77e3cf56e8b812a54f7afb791ead7862c966185ed0ddbbe"},{"id":"func/_v3_attempted_and_terminal_ids","name":"_v3_attempted_and_terminal_ids","line":1465,"end_line":1471,"hash":"1f628f81c86b465977cdefd40d46eff7e7cdfa432392aa27177f84e0e4475b9a"},{"id":"func/_check_v3_terminal_decision_sets","name":"_check_v3_terminal_decision_sets","line":1474,"end_line":1494,"hash":"c0def55487dde81006e43e967cacffaff65077213d4010de6df067e66da2fa0d"},{"id":"func/_v3_fallback_ranks_not_increasing","name":"_v3_fallback_ranks_not_increasing","line":1497,"end_line":1502,"hash":"a695edbe8099cf4367466326cf02a40f5e830b3fa60c30e0d02f9798ce0ae52c"},{"id":"func/_check_v3_no_fallback_after_admission","name":"_check_v3_no_fallback_after_admission","line":1505,"end_line":1512,"hash":"16d75fdf42acb15d0ac99367bc5721f302031892c9d95dc770b6a192598fef59"},{"id":"func/_v3_primary_candidate_not_first","name":"_v3_primary_candidate_not_first","line":1515,"end_line":1519,"hash":"e23ae771f9e7c9521ed63734fe12ec2a387bee90e138705790f85a16e113918c"},{"id":"func/_check_v3_fallback_attempts","name":"_check_v3_fallback_attempts","line":1522,"end_line":1538,"hash":"873c58cce6071f3061b655198564bc527c5af1020eed42095a0f2446e2519a86"},{"id":"func/_check_v3_fallback_order","name":"_check_v3_fallback_order","line":1541,"end_line":1547,"hash":"25a06926237e44a8245d9c33a89af4bf41f3924097f3de6b70488ead10723c43"},{"id":"func/_v3_target_admitted_ids","name":"_v3_target_admitted_ids","line":1550,"end_line":1559,"hash":"b6e476170e7d517457c4dc250c6a146a92dbd3399487b165e843bc30ce2c687c"},{"id":"func/_check_v3_target_terminal_state","name":"_check_v3_target_terminal_state","line":1562,"end_line":1578,"hash":"0c41205566d56b17a917dca20afe41983bf4b502c56e2fcd5f87eade007747bf"},{"id":"func/_v3_target_transitions","name":"_v3_target_transitions","line":1581,"end_line":1588,"hash":"948387a1871eb4aa85a0590e45d27bce7b43d0451554f05e26482c29b3fca2d5"},{"id":"func/_check_v3_target_terminal_transition","name":"_check_v3_target_terminal_transition","line":1591,"end_line":1608,"hash":"d3a030b9d0214faa3fad4224f39a86ee26421ab744d8093702867b318f5b5198"},{"id":"func/_check_v3_target_terminal_states","name":"_check_v3_target_terminal_states","line":1611,"end_line":1618,"hash":"ebd2cd5a5846ba2e7312319b8490c880e52b6a94040a82f4fefaa2efda7493fb"},{"id":"func/_v3_manifest_scenario_entries","name":"_v3_manifest_scenario_entries","line":1621,"end_line":1632,"hash":"4d0f2419515bcecffbcf5ca8ebdb18d364965b296555527ea811175b830ae4fe"},{"id":"func/_v3_receipt_entries","name":"_v3_receipt_entries","line":1635,"end_line":1640,"hash":"da9c745bf0810dd7328d4ab222166f02d5f892f0d81f6cc5833560ea0e36e738"},{"id":"func/_check_v3_manifest_receipts","name":"_check_v3_manifest_receipts","line":1643,"end_line":1653,"hash":"ba9453b2febc4dfe7fc1a3202cd2d7b96f8968dad26226f68ea1526812b8614d"},{"id":"func/_v3_receipts_for","name":"_v3_receipts_for","line":1656,"end_line":1661,"hash":"710d2972bdd9cabb7729af905841d2898c18aaf4bb4733ace01ffce7774af90f"},{"id":"func/_admitted_receipt_roles_mismatch","name":"_admitted_receipt_roles_mismatch","line":1664,"end_line":1671,"hash":"f320f78c383fd99d441ab6b64412f8a4c2bfb1db1002297a8aa06a9d860a7315"},{"id":"func/_check_v3_admitted_receipt_pairs","name":"_check_v3_admitted_receipt_pairs","line":1674,"end_line":1688,"hash":"e3c58760ed1d712b7a36211698d10276531cbd4a0423e55e3a1cb5d23ceb2a49"},{"id":"func/_check_v3_quarantined_receipts","name":"_check_v3_quarantined_receipts","line":1691,"end_line":1701,"hash":"fe12284b97eacf86fc5648fac1b045eea0ebcf519ff01fa5656dc8e7c8c28dcf"},{"id":"func/_v3_eval_scorecard_candidates","name":"_v3_eval_scorecard_candidates","line":1704,"end_line":1710,"hash":"d5a7c342b1b267b8fa0910d93c5e31136f23c52028b052d39a22d01ab3c698a5"},{"id":"func/_v3_bundle_candidates","name":"_v3_bundle_candidates","line":1713,"end_line":1719,"hash":"e18bddab41dd4f300f90241f4615b741afb0810ae67b53331938b5be33e6a913"},{"id":"func/_v3_normal_scenario_candidates","name":"_v3_normal_scenario_candidates","line":1722,"end_line":1728,"hash":"a79b25457349698de4fa9a48bb9ff9ed4cca2340d57f1c03a893b6ac76233441"},{"id":"func/_check_v3_eval_and_role_scopes","name":"_check_v3_eval_and_role_scopes","line":1731,"end_line":1752,"hash":"b78489f88ffbbd5b8ebb23af9ea56bee18cc113f090ba2c34835244273e2804a"},{"id":"func/_v3_attempt_for","name":"_v3_attempt_for","line":1755,"end_line":1762,"hash":"702031769cbb59f86072a00eef5b5c408c215371b082b17e01acde63ba3a46ee"},{"id":"func/_v3_stage_attempts_for","name":"_v3_stage_attempts_for","line":1765,"end_line":1770,"hash":"01fd00f977e60095578e453f4f4fc7cc404ca7232d5fb34b8c5d0155df518334"},{"id":"func/_v3_repairs_for","name":"_v3_repairs_for","line":1773,"end_line":1778,"hash":"d1a1d3c200b552274454eac2538e40702b06aedaff171292de66d3f45b592ffc"},{"id":"func/_check_v3_admitted_causal_evidence","name":"_check_v3_admitted_causal_evidence","line":1781,"end_line":1795,"hash":"d524f747b80cfe600c3ca1c2411d6c572421db303934569e0bc7100cfe39c238"},{"id":"func/_v3_read_bundle","name":"_v3_read_bundle","line":1798,"end_line":1805,"hash":"fc265fc7a75aed0ae908e2fa5e7633da65ab399926a90314142f08729f9d52dd"},{"id":"func/_v3_bundle_identity_mismatch","name":"_v3_bundle_identity_mismatch","line":1808,"end_line":1818,"hash":"f6f7f3e8778a08ca75542fca523a09a4700d29b8dd1d52adf18b8c78a835d78f"},{"id":"func/_v3_bundle_attempt_mismatch","name":"_v3_bundle_attempt_mismatch","line":1821,"end_line":1830,"hash":"d567117ab1be4300085b37901b529f5718b5ba5c1993c63f9c6c3dfa3aac43d6"},{"id":"func/_v3_attempt_or_none","name":"_v3_attempt_or_none","line":1833,"end_line":1845,"hash":"84bd975e9a7f2d86f5c57de53563a51f474e719ef3c5c0583aeba07b80c991af"},{"id":"func/_v3_decision_for","name":"_v3_decision_for","line":1848,"end_line":1855,"hash":"e3010aeb8eca2115ca2d85b8f12b546042a5087f2e02109250731513b6947f6e"},{"id":"func/_check_v3_bundle_identity","name":"_check_v3_bundle_identity","line":1858,"end_line":1867,"hash":"f1570fafac41be86777a5f9ba0e690d37ff60dbfaf4969177087c7df3479f9d0"},{"id":"func/_check_v3_bundle_attempt","name":"_check_v3_bundle_attempt","line":1870,"end_line":1879,"hash":"4a703840cdd3318b6ae25d94b73c905fcd85f1a1d51751a01710231df3ac9ab8"},{"id":"func/_check_v3_bundle_violations","name":"_check_v3_bundle_violations","line":1882,"end_line":1891,"hash":"6615fb3faf3f6c8efb81bd8c920a65141c954a3e89a1d7c610eb0639e3ec2397"},{"id":"func/_check_v3_bundle_stage_evidence","name":"_check_v3_bundle_stage_evidence","line":1894,"end_line":1904,"hash":"10aef5a87015e15933f818400d3cfe73af0b8e2ef8687be308b60fe871538a5d"},{"id":"func/_check_v3_quarantine_bundles","name":"_check_v3_quarantine_bundles","line":1907,"end_line":1929,"hash":"d6eef868bf4d544640a25b9cd1356fdd539ae6f01b9c2d540402d1d00a3aa1e1"},{"id":"func/_check_v3_completed_status","name":"_check_v3_completed_status","line":1932,"end_line":1947,"hash":"53ac8a6969f74bcee52e9e6be1b5fa023e9d453e4ec57459ca4c6f3af82be235"},{"id":"func/_violations","name":"_violations","line":1950,"end_line":1969,"hash":"afab43297773ebbb567503fc210a19e1ba873866178e1423eccdd9a463075429"}]}
# mutate4py-manifest-end
