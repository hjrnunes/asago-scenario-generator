"""Candidate-terminal accounting (correction spec 2026-09-12, sections 3
and 6.4).

The seven-valued candidate terminals, the post-publication assignment
seam (``resolve_authoring_terminals``), the once-only record write, and
the ST-1 through ST-13 status table.  ST-1 and ST-5 read the frozen
MiniOcciAI record and live in
``tests/stpa/test_occiai_subject_overlay.py``; every other case is
synthetic and offline.
"""

from __future__ import annotations

from types import SimpleNamespace

import yaml

from asago_scenario_generator.stpa.models.scenario_spec import AdversaryKind
from asago_scenario_generator.stpa.scenario_prod.authoring import (
    AUTHORING_TERMINAL_NO_YIELD,
    AUTHORING_TERMINAL_PUBLISHED,
    AUTHORING_TERMINAL_UNPROCESSABLE,
    CandidateAuthoringOutcome,
    resolve_authoring_terminals,
)
from asago_scenario_generator.pipeline.synthesis import (
    SynthesisRunStatus,
    _authored_generation_status,
    _authored_scenario_counts,
    _finalize_authoring_record,
    _scenario_generation_status,
)


def _accepted(*, kind: AdversaryKind = AdversaryKind.external_attacker):
    """A minimal accepted-scenario stand-in carrying its adversary kind."""
    return SimpleNamespace(draft=SimpleNamespace(adversary=SimpleNamespace(kind=kind)))


def _outcome(
    *,
    accepted=(),
    error: str | None = None,
    call_issued: bool = False,
    resolution: str | None = None,
) -> CandidateAuthoringOutcome:
    return CandidateAuthoringOutcome(
        candidate=SimpleNamespace(
            step_label="SC-1:tool",
            constraint_id="SC-1",
            action_name="tool",
            failure_direction="forbidden",
            direction_authority="proposed",
        ),
        accepted=accepted,
        error=error,
        call_issued=call_issued,
        resolution=resolution,
    )


def _resolve(outcomes, bundle_statuses):
    """Bundle each accepted draft under an ICA id with its SP3 status."""
    bundles = {}
    ica_statuses = {}
    index = 0
    for outcome in outcomes:
        for accepted in outcome.accepted:
            index += 1
            ica_id = f"RESP-1:CA-1-1:INCORRECT:{index}"
            bundles[ica_id] = SimpleNamespace(accepted=accepted)
            status = bundle_statuses.get(id(accepted))
            if status is not None:
                ica_statuses[ica_id] = status
    return resolve_authoring_terminals(tuple(outcomes), bundles, ica_statuses)


def _counts(resolutions, sp3_statuses=(), drafts=(0, 0, 0)):
    terminals = [
        SimpleNamespace(
            resolution=resolution,
            accepted=([None] * drafts[0]),
            rejected=([None] * drafts[1]),
            held=([None] * drafts[2]),
        )
        for resolution in resolutions
    ]
    result = SimpleNamespace(
        candidate_outcomes=[
            SimpleNamespace(status=SimpleNamespace(value=status), ica_id=f"i{i}")
            for i, status in enumerate(sp3_statuses)
        ],
        stage_errors=(),
    )
    return _authored_scenario_counts(terminals, result)


# resolve_authoring_terminals: the four post-call terminals (spec 3.2)


def test_pre_call_resolutions_stand_unchanged():
    outcomes = (
        _outcome(resolution="specification_only"),
        _outcome(resolution="no_expressible_oracle"),
    )
    resolved = _resolve(outcomes, {})
    assert [outcome.resolution for outcome in resolved] == [
        "specification_only",
        "no_expressible_oracle",
    ]


def test_a_candidate_wide_error_is_unprocessable():
    (resolved,) = _resolve((_outcome(error="prompt render failure"),), {})
    assert resolved.resolution == AUTHORING_TERMINAL_UNPROCESSABLE
    assert resolved.resolution_detail == "prompt render failure"


def test_a_post_issue_error_is_attempted_not_unprocessable():
    """A provider or decode failure after the call was issued yields no
    artifacts and never reaches publication: attempted_no_yield (spec
    3.2), so an all-fail run reports failed, not 'not attempted'."""
    (resolved,) = _resolve((_outcome(error="provider timeout", call_issued=True),), {})
    assert resolved.resolution == AUTHORING_TERMINAL_NO_YIELD
    assert resolved.resolution_detail == "provider timeout"
    counts = _counts([resolved.resolution])
    assert counts["attempted"] == 1
    assert _authored_generation_status(counts) == (
        SynthesisRunStatus.FAILED,
        "zero_yield_after_attempts",
    )


def test_published_when_one_adversarial_artifact_publishes():
    published, failed = _accepted(), _accepted()
    (resolved,) = _resolve(
        (_outcome(accepted=(published, failed)),),
        {id(published): "published", id(failed): "publication_failed"},
    )
    assert resolved.resolution == AUTHORING_TERMINAL_PUBLISHED


def test_functional_specification_when_only_functional_drafts_persist():
    functional = _accepted(kind=AdversaryKind.none)
    (resolved,) = _resolve(
        (_outcome(accepted=(functional,)),), {id(functional): "functional_test"}
    )
    assert resolved.resolution == "functional_specification"


def test_st13_mixed_candidate_is_functional_specification():
    """A persisted functional specification plus a failed adversarial
    publication on the same candidate resolves functional_specification;
    the adversarial failure stays on the artifact."""
    functional = _accepted(kind=AdversaryKind.none)
    adversarial = _accepted()
    (resolved,) = _resolve(
        (_outcome(accepted=(functional, adversarial)),),
        {id(functional): "functional_test", id(adversarial): "publication_failed"},
    )
    assert resolved.resolution == "functional_specification"


def test_publication_failed_when_every_artifact_fails_publication():
    first, second = _accepted(), _accepted()
    (resolved,) = _resolve(
        (_outcome(accepted=(first, second)),),
        {id(first): "publication_failed", id(second): "publication_failed"},
    )
    assert resolved.resolution == "publication_failed"


def test_attempted_no_yield_when_nothing_reached_publication():
    accepted = _accepted()
    # The ICA never received an SP3 outcome: it never reached publication.
    (resolved,) = _resolve((_outcome(accepted=(accepted,)),), {})
    assert resolved.resolution == AUTHORING_TERMINAL_NO_YIELD


def test_attempted_no_yield_when_the_call_yielded_no_drafts():
    (resolved,) = _resolve((_outcome(),), {})
    assert resolved.resolution == AUTHORING_TERMINAL_NO_YIELD


def test_adversarial_publication_does_not_publish_a_functional_candidate():
    """An adversarial artifact's success never re-labels a functional-only
    candidate, and a functional draft's persistence never publishes an
    adversarial one."""
    functional = _accepted(kind=AdversaryKind.none)
    (resolved,) = _resolve(
        (_outcome(accepted=(functional,)),), {id(functional): "published"}
    )
    # A nonsensical status combination (functional draft marked published)
    # still cannot manufacture an adversarial publication.
    assert resolved.resolution != AUTHORING_TERMINAL_PUBLISHED


# The record is written once, after publication (spec 3.4)


def test_finalize_writes_the_record_once_with_final_resolutions(tmp_path):
    from tests.stpa.test_authored_assembly import _accepted as _real_accepted

    accepted = _real_accepted()
    outcome = CandidateAuthoringOutcome(
        candidate=accepted.candidate, accepted=(accepted,)
    )
    bundles = {"RESP-1:CA-1-2:INCORRECT:1": SimpleNamespace(accepted=accepted)}
    scenario_result = SimpleNamespace(
        candidate_outcomes=(
            SimpleNamespace(
                ica_id="RESP-1:CA-1-2:INCORRECT:1",
                status=SimpleNamespace(value="published"),
            ),
        )
    )
    terminals = _finalize_authoring_record(
        (outcome,), bundles, scenario_result, tmp_path
    )
    assert [outcome.resolution for outcome in terminals] == ["published"]
    record = yaml.safe_load((tmp_path / "authored-scenarios.yaml").read_text())
    (row,) = record["candidates"]
    assert row["resolution"] == AUTHORING_TERMINAL_PUBLISHED
    assert row["constraint_id"] == "SC-1"
    assert row["action"] == "process_refund"
    assert len(row["accepted"]) == 1


# The run_status table (spec 3.3 and 6.4)


def test_st2_attempted_with_zero_yield_is_failed():
    counts = _counts(["attempted_no_yield"] * 7)
    assert _authored_generation_status(counts) == (
        SynthesisRunStatus.FAILED,
        "zero_yield_after_attempts",
    )
    assert counts["requested"] == 7
    assert counts["attempted"] == 7


def test_st3_only_ineligible_candidates_is_no_candidates():
    counts = _counts(["no_expressible_oracle"] * 8 + ["specification_only"] * 8)
    assert _authored_generation_status(counts) == (
        SynthesisRunStatus.NO_CANDIDATES,
        "no_eligible_candidates",
    )
    assert counts["requested"] == 0
    assert counts["ineligible"] == 16


def test_st4_the_target_blind_status_path_is_unchanged():
    assert _scenario_generation_status(
        {"requested": 0, "attempted": 0, "generated": 0, "functional_test": 0}
    ) == (SynthesisRunStatus.NO_CANDIDATES, "no_eligible_candidates")
    # The pre-existing completed reason string on the target-blind path.
    assert _scenario_generation_status(
        {"requested": 3, "attempted": 3, "generated": 3, "functional_test": 0}
    ) == (SynthesisRunStatus.COMPLETED, "all_requested_candidates_resolved")


def test_st6_artifact_parity_is_not_completion():
    counts = _counts(["published", "attempted_no_yield"], ["published", "published"])
    assert counts["generated"] == 2
    assert counts["requested"] == 2
    assert _authored_generation_status(counts) == (
        SynthesisRunStatus.DEGRADED,
        "partial_candidate_yield",
    )


def test_st7_artifact_overcount_still_completes_per_candidate():
    counts = _counts(["published", "published"], ["published"] * 4)
    assert counts["generated"] == 4
    assert counts["requested"] == 2
    assert _authored_generation_status(counts) == (
        SynthesisRunStatus.COMPLETED,
        "all_requested_candidates_resolved",
    )


def test_st8_only_functional_specifications_survive():
    counts = _counts(
        ["functional_specification", "functional_specification"],
        ["functional_test"] * 3,
    )
    assert counts["generated"] == 0
    assert counts["functional_specifications"] == 3
    assert counts["functional_test"] == 2
    assert _authored_generation_status(counts) == (
        SynthesisRunStatus.COMPLETED,
        "all_requested_candidates_resolved",
    )


def test_st9_mixed_artifact_kinds_complete_when_all_candidates_resolve():
    counts = _counts(
        ["published", "functional_specification"],
        ["published", "functional_test"],
    )
    assert counts["generated"] == 1
    assert counts["functional_specifications"] == 1
    assert _authored_generation_status(counts) == (
        SynthesisRunStatus.COMPLETED,
        "all_requested_candidates_resolved",
    )


def test_st10_compile_then_publication_failure_is_failed():
    counts = _counts(["publication_failed"], ["publication_failed"])
    assert counts["generated"] == 0
    assert counts["publication_failed"] == 1
    assert _authored_generation_status(counts) == (
        SynthesisRunStatus.FAILED,
        "zero_yield_after_attempts",
    )


def test_st11_a_published_sibling_makes_publication_failure_degraded():
    counts = _counts(
        ["published", "publication_failed"],
        ["published", "publication_failed"],
    )
    assert counts["generated"] == 1
    assert counts["publication_failed"] == 1
    assert _authored_generation_status(counts) == (
        SynthesisRunStatus.DEGRADED,
        "partial_candidate_yield",
    )


def test_st12_two_publication_failures_are_failed():
    counts = _counts(
        ["publication_failed", "publication_failed"],
        ["publication_failed"] * 2,
    )
    assert _authored_generation_status(counts) == (
        SynthesisRunStatus.FAILED,
        "zero_yield_after_attempts",
    )


def test_st13_status_counts_the_functional_terminal_not_the_artifact_failure():
    counts = _counts(
        ["functional_specification"],
        ["functional_test", "publication_failed"],
    )
    assert counts["generated"] == 0
    assert counts["functional_specifications"] == 1
    assert counts["functional_test"] == 1
    # publication_failed is an artifact outcome here, not a candidate one.
    assert counts["publication_failed"] == 0
    assert counts["failed"] == 1
    assert _authored_generation_status(counts) == (
        SynthesisRunStatus.COMPLETED,
        "all_requested_candidates_resolved",
    )


def test_draft_counts_never_enter_run_status():
    counts = _counts(
        ["published"],
        ["published"],
        drafts=(1, 2, 1),
    )
    assert counts["drafts_returned"] == 4
    assert counts["drafts_accepted"] == 1
    assert counts["drafts_rejected"] == 2
    assert counts["drafts_held"] == 1
    assert _authored_generation_status(counts)[0] is SynthesisRunStatus.COMPLETED


def test_adapter_failure_counts_as_returned_and_rejected_without_hiding_sibling():
    from dataclasses import replace

    from asago_scenario_generator.stpa.scenario_prod.authoring_adapter import (
        CurrentDraftAdapterFailure,
    )

    failure = CurrentDraftAdapterFailure(
        draft_index=2,
        reason="source_handle_unknown",
        detail="A selected handle was not supplied in this request.",
        raw_draft={"unsafe_observation": {"choice_handle": "unknown"}},
    )
    outcome = replace(
        _outcome(accepted=(_accepted(),), resolution="published", call_issued=True),
        adapter_rejections=(failure,),
    )
    result = SimpleNamespace(
        candidate_outcomes=[SimpleNamespace(status="published")], stage_errors=[]
    )
    counts = _authored_scenario_counts((outcome,), result)
    assert counts["drafts_returned"] == 2
    assert counts["drafts_accepted"] == 1
    assert counts["drafts_rejected"] == counts["drafts_adapter_rejected"] == 1
    assert counts["published"] == 1
    assert _authored_generation_status(counts)[0] is SynthesisRunStatus.COMPLETED


def test_unprocessable_candidates_are_requested_but_not_attempted():
    counts = _counts(["unprocessable", "published"], ["published"])
    assert counts["requested"] == 2
    assert counts["attempted"] == 1
    assert counts["unprocessable"] == 1
    assert _authored_generation_status(counts) == (
        SynthesisRunStatus.DEGRADED,
        "partial_candidate_yield",
    )
