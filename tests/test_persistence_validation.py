"""Behavior of the manifest-v3 inventory validation predicates."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from asago_scenario_generator.manifest import (
    ArtifactRole,
    ManifestIntegrityError,
    RunStatus,
)
from asago_scenario_generator.pipeline.finalization_contracts import (
    GeneratedStage,
    LifecycleState,
)
from asago_scenario_generator.pipeline.persistence_common import canonical_sha256
from asago_scenario_generator.pipeline.persistence_validation import (
    _CandidateTraceState,
    _check_admission_decision,
    _check_gate_violations_match_terminal,
    _check_revalidating_segment,
    _check_target_candidate_trace,
    _check_target_transition_indexes,
    _check_v3_admitted_receipt_pairs,
    _check_v3_completed_status,
    _check_v3_eval_and_role_scopes,
    _check_v3_fallback_attempts,
    _check_v3_terminal_decision_sets,
    _fold_record_into_frontier,
)

L = LifecycleState


def _transition(
    sequence: int,
    previous: LifecycleState,
    current: LifecycleState,
    candidate_id: str | None = None,
    index: int | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        sequence=sequence,
        index=sequence if index is None else index,
        previous=previous,
        current=current,
        candidate_id=candidate_id,
    )


def _candidate(candidate_id: str, sequence: int) -> SimpleNamespace:
    return SimpleNamespace(candidate_id=candidate_id, sequence=sequence)


# --- _check_target_transition_indexes ---------------------------------------


def test_transition_indexes_accept_a_contiguous_chain_from_pending() -> None:
    _check_target_transition_indexes(
        [
            _transition(0, L.pending, L.revalidating_candidate, "c"),
            _transition(1, L.revalidating_candidate, L.generating_actor, "c"),
        ]
    )


def test_transition_indexes_reject_gaps() -> None:
    chain = [
        _transition(0, L.pending, L.revalidating_candidate, "c", index=0),
        _transition(1, L.revalidating_candidate, L.rejected, "c", index=2),
    ]
    with pytest.raises(ValueError, match="contiguous per target"):
        _check_target_transition_indexes(chain)


def test_transition_indexes_reject_a_chain_that_does_not_start_from_pending() -> None:
    chain = [_transition(0, L.rejected, L.exhausted)]
    with pytest.raises(ValueError, match="must start from pending"):
        _check_target_transition_indexes(chain)


def test_transition_indexes_reject_a_broken_state_chain() -> None:
    chain = [
        _transition(0, L.pending, L.revalidating_candidate, "c"),
        _transition(1, L.generating_actor, L.rejected, "c"),
    ]
    with pytest.raises(ValueError, match="state chain is noncontiguous"):
        _check_target_transition_indexes(chain)


# --- _check_target_candidate_trace and its segments --------------------------


def _full_trace() -> list[SimpleNamespace]:
    return [
        _transition(1, L.pending, L.revalidating_candidate, "c1"),
        _transition(2, L.revalidating_candidate, L.generating_actor, "c1"),
        _transition(3, L.generating_actor, L.rejected, "c1"),
        _transition(4, L.rejected, L.revalidating_candidate, "c2"),
        _transition(5, L.revalidating_candidate, L.rejected, "c2"),
        _transition(6, L.rejected, L.exhausted),
    ]


def test_candidate_trace_replays_segments_and_records_terminal_edges() -> None:
    transitions = _full_trace()
    terminal_edges: dict[str, Any] = {}
    _check_target_candidate_trace(
        transitions, [_candidate("c1", 0), _candidate("c2", 0)], terminal_edges
    )
    assert terminal_edges == {"c1": transitions[2], "c2": transitions[4]}


def test_candidate_trace_requires_a_segment_for_each_attempt() -> None:
    attempts = [_candidate("c1", 0), _candidate("c2", 0), _candidate("c3", 0)]
    with pytest.raises(ValueError, match="one revalidating trace segment"):
        _check_target_candidate_trace(_full_trace(), attempts, {})


def test_candidate_trace_rejects_a_candidate_change_inside_an_active_trace() -> None:
    transitions = [
        _transition(1, L.pending, L.revalidating_candidate, "c1"),
        _transition(2, L.revalidating_candidate, L.generating_actor, "other"),
    ]
    with pytest.raises(ValueError, match="candidate changed inside an active trace"):
        _check_target_candidate_trace(transitions, [_candidate("c1", 0)], {})


def test_candidate_trace_rejects_active_edges_without_a_revalidating_segment() -> None:
    transitions = [_transition(1, L.pending, L.generating_actor, "c1")]
    with pytest.raises(ValueError, match="candidate changed inside an active trace"):
        _check_target_candidate_trace(transitions, [], {})


def test_candidate_trace_rejects_exhaustion_that_is_not_final() -> None:
    transitions = [
        _transition(1, L.pending, L.exhausted),
        _transition(2, L.exhausted, L.revalidating_candidate, "c1"),
    ]
    with pytest.raises(ValueError, match="exhaustion must be candidate-free and final"):
        _check_target_candidate_trace(transitions, [_candidate("c1", 0)], {})


def test_candidate_trace_rejects_exhaustion_that_carries_a_candidate() -> None:
    transitions = [_transition(1, L.pending, L.exhausted, "c1")]
    with pytest.raises(ValueError, match="exhaustion must be candidate-free and final"):
        _check_target_candidate_trace(transitions, [], {})


def test_candidate_trace_rejects_exhaustion_inside_an_active_trace() -> None:
    transitions = [
        _transition(1, L.pending, L.revalidating_candidate, "c1"),
        _transition(2, L.revalidating_candidate, L.exhausted),
    ]
    with pytest.raises(ValueError, match="exhaustion must be candidate-free and final"):
        _check_target_candidate_trace(transitions, [_candidate("c1", 0)], {})


def test_revalidating_segment_activates_the_next_durable_attempt() -> None:
    state = _CandidateTraceState()
    transition = _transition(5, L.pending, L.revalidating_candidate, "c1")
    _check_revalidating_segment(transition, [_candidate("c1", 4)], state)
    assert state.active_candidate == "c1"
    assert state.seen_candidates == {"c1"}
    assert state.next_attempt == 1


@pytest.mark.parametrize(
    ("state", "candidate_id"),
    [
        (_CandidateTraceState(active_candidate="busy"), "c1"),
        (_CandidateTraceState(), None),
        (_CandidateTraceState(seen_candidates={"c1"}), "c1"),
        (_CandidateTraceState(next_attempt=1), "c1"),
    ],
    ids=["active", "no-candidate", "duplicate", "no-attempt-left"],
)
def test_revalidating_segment_rejects_invalid_or_duplicate_segments(
    state: _CandidateTraceState, candidate_id: str | None
) -> None:
    transition = _transition(5, L.pending, L.revalidating_candidate, candidate_id)
    with pytest.raises(ValueError, match="invalid or duplicate candidate trace"):
        _check_revalidating_segment(transition, [_candidate("c1", 0)], state)


@pytest.mark.parametrize(
    ("attempt", "transition_sequence"),
    [(_candidate("other", 0), 5), (_candidate("c1", 5), 5)],
    ids=["other-candidate", "attempt-not-before-transition"],
)
def test_revalidating_segment_rejects_a_mismatched_durable_attempt(
    attempt: SimpleNamespace, transition_sequence: int
) -> None:
    transition = _transition(
        transition_sequence, L.pending, L.revalidating_candidate, "c1"
    )
    with pytest.raises(ValueError, match="does not match next durable attempt"):
        _check_revalidating_segment(transition, [attempt], _CandidateTraceState())


# --- _check_gate_violations_match_terminal ------------------------------------


def _gate(*violations: str) -> SimpleNamespace:
    return SimpleNamespace(violations=list(violations))


def test_gate_violations_accept_decisions_without_gate_results() -> None:
    _check_gate_violations_match_terminal(
        SimpleNamespace(gate_results=[], violations=["ignored"])
    )


def test_gate_violations_accept_a_flattened_match() -> None:
    _check_gate_violations_match_terminal(
        SimpleNamespace(
            gate_results=[_gate("a"), _gate(), _gate("b")], violations=["a", "b"]
        )
    )


def test_gate_violations_reject_a_terminal_mismatch() -> None:
    decision = SimpleNamespace(gate_results=[_gate("a")], violations=["b"])
    with pytest.raises(ValueError, match="gate violations must match terminal"):
        _check_gate_violations_match_terminal(decision)


# --- _check_admission_decision ------------------------------------------------


def _decision(**overrides: Any) -> SimpleNamespace:
    values: dict[str, Any] = {
        "candidate_id": "c1",
        "admitted": False,
        "sequence": 10,
        "gate_results": [],
        "violations": [],
        "candidate_snapshot_sha256": None,
        "actor_snapshot_sha256": None,
        "narrative_snapshot_sha256": None,
        "final_tree_snapshot_sha256": None,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _passing_gate() -> SimpleNamespace:
    return SimpleNamespace(passed=True, violations=[])


class _AdmissionFixture:
    def __init__(self, *, current: LifecycleState, previous: LifecycleState) -> None:
        self.terminal = _transition(5, previous, current, "c1")
        self.attempts = [
            SimpleNamespace(
                candidate_id="c1", attempt_id="a1", target_entry_point_id="t1"
            )
        ]
        self.transitions_by_target = {"t1": [self.terminal]}

    def check(
        self,
        decision: SimpleNamespace,
        *,
        stages: list[Any] | None = None,
        terminal_edges: dict[str, Any] | None = None,
    ) -> None:
        edges = {"c1": self.terminal} if terminal_edges is None else terminal_edges
        _check_admission_decision(
            decision,
            edges,
            self.transitions_by_target,
            self.attempts,
            stages or [],
            [],
        )


def test_admission_decision_accepts_a_rejected_decision_after_its_terminal_edge() -> (
    None
):
    _AdmissionFixture(current=L.rejected, previous=L.generating_actor).check(
        _decision()
    )


def test_admission_decision_requires_a_matching_terminal_transition() -> None:
    fixture = _AdmissionFixture(current=L.rejected, previous=L.generating_actor)
    with pytest.raises(ValueError, match="matching admitting terminal transition"):
        fixture.check(_decision(), terminal_edges={})
    with pytest.raises(ValueError, match="matching admitting terminal transition"):
        fixture.check(_decision(admitted=True))


def test_admission_decision_requires_stage_evidence_before_the_terminal_edge() -> None:
    fixture = _AdmissionFixture(current=L.rejected, previous=L.generating_actor)
    with pytest.raises(ValueError, match="stage evidence must precede"):
        fixture.check(
            _decision(), stages=[SimpleNamespace(candidate_id="c1", sequence=5)]
        )


def test_admission_decision_ignores_stage_evidence_of_other_candidates() -> None:
    fixture = _AdmissionFixture(current=L.rejected, previous=L.generating_actor)
    fixture.check(_decision(), stages=[SimpleNamespace(candidate_id="x", sequence=9)])


def test_admission_decision_requires_the_decision_after_the_terminal_edge() -> None:
    fixture = _AdmissionFixture(current=L.rejected, previous=L.generating_actor)
    with pytest.raises(ValueError, match="terminal edge must precede its decision"):
        fixture.check(_decision(sequence=5))


def test_admission_decision_requires_the_decision_before_the_next_target_transition() -> (
    None
):
    fixture = _AdmissionFixture(current=L.rejected, previous=L.generating_actor)
    fixture.transitions_by_target["t1"].append(_transition(8, L.rejected, L.exhausted))
    with pytest.raises(ValueError, match="decision must precede the next target"):
        fixture.check(_decision(sequence=9))
    fixture.check(_decision(sequence=7))


def test_admission_decision_requires_admitting_edge_for_gated_decisions() -> None:
    fixture = _AdmissionFixture(current=L.rejected, previous=L.generating_actor)
    with pytest.raises(ValueError, match="requires admitting terminal edge"):
        fixture.check(_decision(gate_results=[_gate()]))


def test_admission_decision_requires_gate_evidence_on_admitting_edges() -> None:
    fixture = _AdmissionFixture(current=L.rejected, previous=L.admitting)
    with pytest.raises(ValueError, match="requires typed admission gate evidence"):
        fixture.check(_decision())


def test_admission_decision_requires_gate_violations_to_match() -> None:
    fixture = _AdmissionFixture(current=L.rejected, previous=L.admitting)
    with pytest.raises(ValueError, match="gate violations must match terminal"):
        fixture.check(_decision(gate_results=[_gate("a")], violations=[]))


def test_admission_decision_requires_admitted_decisions_to_pass_every_gate() -> None:
    fixture = _AdmissionFixture(current=L.admitted, previous=L.admitting)
    failed = SimpleNamespace(passed=False, violations=[])
    with pytest.raises(ValueError, match="nonempty passing gate evidence"):
        fixture.check(_decision(admitted=True, gate_results=[failed]))


def test_admission_decision_accepts_admission_with_matching_snapshots() -> None:
    fixture = _AdmissionFixture(current=L.admitted, previous=L.admitting)
    fixture.check(_decision(admitted=True, gate_results=[_passing_gate()]))


def test_admission_decision_rejects_snapshot_digests_without_stage_evidence() -> None:
    fixture = _AdmissionFixture(current=L.admitted, previous=L.admitting)
    decision = _decision(
        admitted=True,
        gate_results=[_passing_gate()],
        candidate_snapshot_sha256="a" * 64,
    )
    with pytest.raises(
        ValueError, match="snapshot digests do not match stage evidence"
    ):
        fixture.check(decision)


# --- _fold_record_into_frontier -----------------------------------------------

_ORDER = tuple(GeneratedStage)
_ACTOR = {"actor": 1}
_NARRATIVE = {"narrative": 1}
_TREE = {"tree": 1}


def _record(
    stage: GeneratedStage,
    *,
    visible: dict[str, Any] | None = None,
    result: Any = None,
    candidate: Any = None,
    call: bool = True,
    violations: tuple[str, ...] = (),
    tree_digest: str | None = None,
    sequence: int = 1,
) -> SimpleNamespace:
    return SimpleNamespace(
        stage=stage,
        sequence=sequence,
        result=result,
        call=object() if call else None,
        violations=list(violations),
        final_tree_snapshot_sha256=tree_digest,
        input=SimpleNamespace(candidate=candidate, visible_artifacts=visible or {}),
    )


def _fold(
    record: SimpleNamespace,
    frontier: dict[GeneratedStage, Any],
    *,
    durable: Any = None,
    repairs: tuple[Any, ...] = (),
) -> None:
    _fold_record_into_frontier(record, frontier, _ORDER, "a1", durable, repairs)


def test_fold_adds_a_result_to_the_frontier() -> None:
    frontier: dict[GeneratedStage, Any] = {}
    _fold(_record(GeneratedStage.actor, result=_ACTOR), frontier)
    assert frontier == {GeneratedStage.actor: _ACTOR}


@pytest.mark.parametrize(
    "overrides",
    [{"result": None}, {"violations": ("bad",)}, {"call": False}],
    ids=["no-result", "violations", "no-call"],
)
def test_fold_skips_records_that_contribute_no_result(
    overrides: dict[str, Any],
) -> None:
    frontier: dict[GeneratedStage, Any] = {}
    overrides = {"result": _ACTOR, **overrides}
    _fold(_record(GeneratedStage.actor, **overrides), frontier)
    assert frontier == {}


def test_fold_invalidates_the_stage_and_every_later_stage() -> None:
    frontier = {
        GeneratedStage.actor: _ACTOR,
        GeneratedStage.narrative: _NARRATIVE,
        GeneratedStage.tree: _TREE,
    }
    _fold(
        _record(GeneratedStage.narrative, visible={"actor": _ACTOR}),
        frontier,
    )
    assert frontier == {GeneratedStage.actor: _ACTOR}


def test_fold_rejects_a_candidate_snapshot_that_differs_from_the_durable_plan() -> None:
    record = _record(GeneratedStage.actor, candidate={"a": 1})
    with pytest.raises(ValueError, match="differs from durable plan"):
        _fold(record, {}, durable={"a": 2})
    _fold(record, {}, durable={"a": 1})


def test_fold_rejects_visible_artifacts_that_are_not_the_frontier() -> None:
    record = _record(GeneratedStage.narrative, visible={"actor": {"other": 1}})
    with pytest.raises(ValueError, match="one contiguous causal frontier"):
        _fold(record, {GeneratedStage.actor: _ACTOR})


def _behavior_frontier() -> dict[GeneratedStage, Any]:
    return {
        GeneratedStage.actor: _ACTOR,
        GeneratedStage.narrative: _NARRATIVE,
        GeneratedStage.tree: _TREE,
    }


def _behavior_visible(tree: Any = _TREE) -> dict[str, Any]:
    return {"actor": _ACTOR, "narrative": _NARRATIVE, "tree": tree}


def test_fold_binds_the_behavior_stage_to_its_generated_tree() -> None:
    frontier = _behavior_frontier()
    record = _record(
        GeneratedStage.behavior,
        visible=_behavior_visible(),
        tree_digest=canonical_sha256(_TREE),
        result={"behavior": 1},
    )
    _fold(record, frontier)
    assert frontier[GeneratedStage.tree] == _TREE
    assert frontier[GeneratedStage.behavior] == {"behavior": 1}


def test_fold_rejects_behavior_without_an_input_bound_tree() -> None:
    record = _record(
        GeneratedStage.behavior,
        visible=_behavior_visible(),
        tree_digest="0" * 64,
    )
    with pytest.raises(ValueError, match="not bound to its final-tree input"):
        _fold(record, _behavior_frontier())


def test_fold_rejects_behavior_without_a_generated_tree() -> None:
    record = _record(
        GeneratedStage.behavior,
        visible={"tree": _TREE},
        tree_digest=canonical_sha256(_TREE),
    )
    with pytest.raises(ValueError, match="no causal generated tree"):
        _fold(record, {})


def _repair(**overrides: Any) -> SimpleNamespace:
    values: dict[str, Any] = {
        "accepted": True,
        "candidate_attempt_id": "a1",
        "sequence": 0,
        "before_digest": canonical_sha256(_TREE),
        "after_digest": canonical_sha256({"tree": 2}),
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_fold_accepts_a_repaired_tree_linked_by_an_accepted_repair() -> None:
    repaired = {"tree": 2}
    record = _record(
        GeneratedStage.behavior,
        visible=_behavior_visible(repaired),
        tree_digest=canonical_sha256(repaired),
    )
    frontier = _behavior_frontier()
    _fold(record, frontier, repairs=(_repair(),))
    assert frontier[GeneratedStage.tree] == repaired


@pytest.mark.parametrize(
    "repair",
    [
        _repair(accepted=False),
        _repair(candidate_attempt_id="other"),
        _repair(sequence=1),
        _repair(before_digest="0" * 64),
    ],
    ids=["unaccepted", "other-attempt", "not-prior", "other-digests"],
)
def test_fold_rejects_a_repaired_tree_without_a_matching_repair(
    repair: SimpleNamespace,
) -> None:
    repaired = {"tree": 2}
    record = _record(
        GeneratedStage.behavior,
        visible=_behavior_visible(repaired),
        tree_digest=canonical_sha256(repaired),
    )
    with pytest.raises(ValueError, match="neither generated nor linked"):
        _fold(record, _behavior_frontier(), repairs=(repair,))


# --- _check_v3_terminal_decision_sets -----------------------------------------


def test_terminal_decision_sets_accept_exactly_reconciled_candidates() -> None:
    _check_v3_terminal_decision_sets(
        ({"a", "b", "c"}, {"a", "b", "c"}), {"a"}, {"b", "c"}, {"a"}
    )


def test_terminal_decision_sets_require_a_decision_for_every_attempt() -> None:
    with pytest.raises(ManifestIntegrityError, match="exactly one terminal decision"):
        _check_v3_terminal_decision_sets(({"a", "b"}, {"a"}), {"a"}, set(), {"a"})


def test_terminal_decision_sets_require_admitted_receipts_to_match_decisions() -> None:
    with pytest.raises(ManifestIntegrityError, match="Admitted receipts must exactly"):
        _check_v3_terminal_decision_sets(({"a", "b"}, {"a", "b"}), set(), {"b"}, {"a"})


def test_terminal_decision_sets_require_quarantine_to_match_nonadmitted() -> None:
    with pytest.raises(
        ManifestIntegrityError, match="Quarantine receipts must exactly"
    ):
        _check_v3_terminal_decision_sets(({"a", "b"}, {"a", "b"}), {"a"}, set(), {"a"})


# --- _check_v3_fallback_attempts ----------------------------------------------


def _fallback(candidate_id: str, rank: int, *, primary: bool) -> SimpleNamespace:
    return SimpleNamespace(
        candidate_id=candidate_id, queue_rank=rank, is_primary=primary
    )


def test_fallback_attempts_accept_empty_and_ordered_attempts() -> None:
    _check_v3_fallback_attempts([], set())
    _check_v3_fallback_attempts(
        [_fallback("a", 0, primary=True), _fallback("b", 1, primary=False)], {"b"}
    )


def test_fallback_attempts_require_increasing_ranks() -> None:
    attempts = [_fallback("a", 1, primary=True), _fallback("b", 1, primary=False)]
    with pytest.raises(ManifestIntegrityError, match="increasing queue rank"):
        _check_v3_fallback_attempts(attempts, set())


def test_fallback_attempts_require_the_primary_candidate_first() -> None:
    attempts = [_fallback("a", 0, primary=False), _fallback("b", 1, primary=False)]
    with pytest.raises(ManifestIntegrityError, match="Primary candidate must be"):
        _check_v3_fallback_attempts(attempts, set())


def test_fallback_attempts_allow_only_the_first_attempt_to_be_primary() -> None:
    attempts = [_fallback("a", 0, primary=True), _fallback("b", 1, primary=True)]
    with pytest.raises(ManifestIntegrityError, match="Only the first target attempt"):
        _check_v3_fallback_attempts(attempts, set())


def test_fallback_attempts_reject_fallback_after_admission() -> None:
    attempts = [_fallback("a", 0, primary=True), _fallback("b", 1, primary=False)]
    with pytest.raises(ManifestIntegrityError, match="after target admission"):
        _check_v3_fallback_attempts(attempts, {"a"})


# --- _check_v3_admitted_receipt_pairs -----------------------------------------


def _receipt(
    candidate_id: str, role: ArtifactRole, scenario_id: str | None
) -> SimpleNamespace:
    return SimpleNamespace(
        candidate_id=candidate_id, role=role, scenario_id=scenario_id
    )


def _pair(candidate_id: str, scenario_id: str = "s1") -> list[SimpleNamespace]:
    return [
        _receipt(candidate_id, ArtifactRole.SCENARIO_FEATURE, scenario_id),
        _receipt(candidate_id, ArtifactRole.SCENARIO_YAML, scenario_id),
    ]


def test_admitted_receipt_pairs_accept_one_yaml_and_feature_pair() -> None:
    final = SimpleNamespace(admitted_inventory=_pair("c1") + _pair("c2", "s2"))
    _check_v3_admitted_receipt_pairs(final, {"c1", "c2"})


@pytest.mark.parametrize(
    "receipts",
    [
        [],
        [_receipt("c1", ArtifactRole.SCENARIO_YAML, "s1")],
        [
            _receipt("c1", ArtifactRole.SCENARIO_YAML, "s1"),
            _receipt("c1", ArtifactRole.SCENARIO_YAML, "s1"),
        ],
    ],
    ids=["none", "yaml-only", "two-yaml"],
)
def test_admitted_receipt_pairs_reject_incomplete_pairs(
    receipts: list[SimpleNamespace],
) -> None:
    final = SimpleNamespace(admitted_inventory=receipts)
    with pytest.raises(ManifestIntegrityError, match="one YAML/feature pair"):
        _check_v3_admitted_receipt_pairs(final, {"c1"})


def test_admitted_receipt_pairs_require_one_scenario_id() -> None:
    receipts = [
        _receipt("c1", ArtifactRole.SCENARIO_YAML, "s1"),
        _receipt("c1", ArtifactRole.SCENARIO_FEATURE, "s2"),
    ]
    with pytest.raises(ManifestIntegrityError, match="same scenario_id"):
        _check_v3_admitted_receipt_pairs(
            SimpleNamespace(admitted_inventory=receipts), {"c1"}
        )


# --- _check_v3_eval_and_role_scopes -------------------------------------------


def _resolver_with(*entries: tuple[ArtifactRole, str | None]) -> SimpleNamespace:
    inventory = [
        SimpleNamespace(role=role, candidate_id=candidate_id)
        for role, candidate_id in entries
    ]
    return SimpleNamespace(manifest=SimpleNamespace(inventory=inventory))


def test_eval_and_role_scopes_accept_normal_roles_for_admitted_candidates() -> None:
    resolver = _resolver_with(
        (ArtifactRole.SCENARIO_YAML, "c1"),
        (ArtifactRole.SCENARIO_FEATURE, "c1"),
        (ArtifactRole.EVAL_SCORECARD, None),
        (ArtifactRole.QUARANTINE_BUNDLE, "q1"),
    )
    _check_v3_eval_and_role_scopes(resolver, {"q1"}, {"c1"})


def test_eval_and_role_scopes_reject_a_scorecard_for_a_quarantined_candidate() -> None:
    resolver = _resolver_with((ArtifactRole.EVAL_SCORECARD, "q1"))
    with pytest.raises(ManifestIntegrityError, match="Evaluation inventory contains"):
        _check_v3_eval_and_role_scopes(resolver, {"q1"}, set())


def test_eval_and_role_scopes_reject_a_bundle_with_a_normal_role() -> None:
    resolver = _resolver_with(
        (ArtifactRole.SCENARIO_YAML, "c1"), (ArtifactRole.QUARANTINE_BUNDLE, "c1")
    )
    with pytest.raises(ManifestIntegrityError, match="carries a normal scenario role"):
        _check_v3_eval_and_role_scopes(resolver, set(), {"c1"})


def test_eval_and_role_scopes_require_normal_inventory_to_equal_admitted() -> None:
    resolver = _resolver_with((ArtifactRole.SCENARIO_YAML, "c1"))
    with pytest.raises(ManifestIntegrityError, match="admitted candidates only"):
        _check_v3_eval_and_role_scopes(resolver, set(), {"c1", "c2"})


# --- _check_v3_completed_status -----------------------------------------------


def _status(status: RunStatus) -> SimpleNamespace:
    return SimpleNamespace(manifest=SimpleNamespace(status=status))


def test_completed_status_requires_errors_when_anything_is_quarantined() -> None:
    _check_v3_completed_status(_status(RunStatus.COMPLETED_WITH_ERRORS), {"q1"})
    for status in (RunStatus.COMPLETED, RunStatus.COMPLETED_WITH_WARNINGS):
        with pytest.raises(
            ManifestIntegrityError, match="requires completed_with_errors"
        ):
            _check_v3_completed_status(_status(status), {"q1"})


@pytest.mark.parametrize(
    "status",
    [
        RunStatus.COMPLETED,
        RunStatus.COMPLETED_WITH_WARNINGS,
        RunStatus.COMPLETED_WITH_ERRORS,
    ],
)
def test_completed_status_accepts_completed_statuses_without_quarantine(
    status: RunStatus,
) -> None:
    _check_v3_completed_status(_status(status), set())


@pytest.mark.parametrize("status", [RunStatus.STARTED, RunStatus.FAILED])
def test_completed_status_rejects_unfinished_statuses_without_quarantine(
    status: RunStatus,
) -> None:
    with pytest.raises(ManifestIntegrityError, match="requires a completed status"):
        _check_v3_completed_status(_status(status), set())
