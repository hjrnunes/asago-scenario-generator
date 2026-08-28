"""Property tests for the taxonomy obligation plan and planner.

These properties pin lossless serialization round trips, byte-stable
formatting, canonical-order invariance under relationship presentation
order, digest self-consistency, summary conservation, candidate-record
uniqueness, relationship conservation, and configuration-secret
redaction. They are offline and deterministic; they never contact an
LLM endpoint.
"""

from __future__ import annotations

from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st

from asago_scenario_generator.models.obligation_plan import (
    TaxonomyObligationPlan,
    TaxonomyObligationSnapshot,
)
from asago_scenario_generator.pipeline.obligation_planner import plan_obligations

_MAX_EXAMPLES = 60

_IDS = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_",
    min_size=1,
    max_size=12,
)
_SCOPES = ("applicable", "governance_only", "capability_excluded")
_APPLICABLE_QUALIFICATIONS = (
    "ready",
    "missing_evidence",
    "contradictory_evidence",
    "structurally_infeasible",
)
_PROJECTION_DISPOSITIONS = (
    "projectable",
    "projection_infeasible",
    "budget_deferred",
    "not_attempted",
)
_SETTLED_PROJECTIONS = ("not_attempted", "projection_infeasible")


def _planner_snapshot(
    relationships: list[dict[str, Any]],
    *,
    candidate_expansions: list[dict[str, Any]] | None = None,
    qualification_evaluations: list[dict[str, Any]] | None = None,
) -> TaxonomyObligationSnapshot:
    """Build a pinned planner snapshot from raw fixture rows."""
    return TaxonomyObligationSnapshot(
        catalog_pin="atlas-2026.05",
        mapping_pin="sssom-v1",
        capability_content={"content": "profile-v1"},
        qualification_facts={"facts": "facts-v1"},
        relationships=relationships,
        risk_cards=[],
        config={},
        qualification_evaluations=qualification_evaluations or [],
        candidate_expansions=candidate_expansions or [],
    )


@st.composite
def _relationship_row(draw: st.DrawFn) -> dict[str, Any]:
    """Draw one relationship row inside the closed Phase 1 disposition contract."""
    risk_id = draw(_IDS)
    pattern_id = draw(st.one_of(st.none(), _IDS))
    scope = draw(st.sampled_from(_SCOPES))
    if scope in ("governance_only", "capability_excluded"):
        qualification = "not_attempted"
        projection = "not_attempted"
    else:
        qualification = draw(st.sampled_from(_APPLICABLE_QUALIFICATIONS))
        if qualification == "ready":
            projection = draw(st.sampled_from(_PROJECTION_DISPOSITIONS))
        else:
            projection = draw(st.sampled_from(_SETTLED_PROJECTIONS))
    return {
        "risk_id": risk_id,
        "pattern_id": pattern_id,
        "scope_disposition": scope,
        "qualification_disposition": qualification,
        "projection_disposition": projection,
    }


def _relationships() -> st.SearchStrategy:
    """Draw relationship rows inside the closed Phase 1 disposition contract."""
    return st.lists(_relationship_row(), max_size=6)


@st.composite
def _snapshots_with_candidates(
    draw: st.DrawFn,
) -> tuple[TaxonomyObligationSnapshot, list[dict[str, Any]]]:
    """Draw a snapshot whose first relationship carries candidate expansions."""
    relationships = draw(_relationships())
    expansions: list[dict[str, Any]] = []
    if relationships:
        target = relationships[0]
        candidates = draw(
            st.lists(
                st.fixed_dictionaries(
                    {
                        "candidate_id": _IDS,
                        "projection_disposition": st.sampled_from(
                            _PROJECTION_DISPOSITIONS
                        ),
                        "reason": st.one_of(st.none(), _IDS),
                    }
                ),
                max_size=5,
            )
        )
        expansions.append(
            {
                "risk_id": target["risk_id"],
                "pattern_id": target["pattern_id"],
                "candidates": candidates,
            }
        )
    return _planner_snapshot(
        relationships, candidate_expansions=expansions
    ), relationships


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(data=_snapshots_with_candidates())
def test_plan_round_trips_are_lossless(
    data: tuple[TaxonomyObligationSnapshot, list[dict[str, Any]]],
) -> None:
    """YAML and JSON persistence preserve the full planner artifact."""
    snapshot, _ = data
    plan = plan_obligations(snapshot)

    assert TaxonomyObligationPlan.from_yaml(plan.to_yaml()) == plan
    assert TaxonomyObligationPlan.from_json(plan.to_json()) == plan


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(data=_snapshots_with_candidates())
def test_plan_serialization_is_byte_stable(
    data: tuple[TaxonomyObligationSnapshot, list[dict[str, Any]]],
) -> None:
    """Repeated serialization of one plan is byte-identical."""
    snapshot, _ = data
    plan = plan_obligations(snapshot)

    assert plan.to_yaml() == plan.to_yaml()
    assert plan.to_json() == plan.to_json()


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(relationships=_relationships())
def test_plan_is_invariant_under_relationship_presentation_order(
    relationships: list[dict[str, Any]],
) -> None:
    """Shuffled relationship order cannot change the produced plan."""
    plan_a = plan_obligations(_planner_snapshot(list(relationships)))
    plan_b = plan_obligations(_planner_snapshot(list(reversed(relationships))))

    assert plan_a.to_yaml() == plan_b.to_yaml()
    assert plan_a.to_json() == plan_b.to_json()


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(data=_snapshots_with_candidates())
def test_planner_plans_are_self_consistent(
    data: tuple[TaxonomyObligationSnapshot, list[dict[str, Any]]],
) -> None:
    """Digests, summaries, ledgers, and candidate records conserve their inputs."""
    snapshot, relationships = data
    plan = plan_obligations(snapshot)

    assert plan.semantic_digest == plan.compute_semantic_digest()
    assert len(plan.obligations) == len(relationships)

    summary = plan.summary
    assert summary.total == len(plan.obligations)
    assert summary.total == (
        summary.applicable + summary.governance_only + summary.capability_excluded
    )
    assert summary.applicable == (
        summary.ready + summary.missing_or_contradictory + summary.structurally_infeasible
    )

    for obligation in plan.obligations:
        candidate_ids = [
            record.candidate_id for record in obligation.candidate_records
        ]
        assert len(candidate_ids) == len(set(candidate_ids))


@st.composite
def _snapshots_with_secrets(draw: st.DrawFn) -> tuple[TaxonomyObligationSnapshot, str]:
    """Draw a snapshot whose configuration secret leaks into trace inputs."""
    secret = draw(
        st.text(
            alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
            min_size=4,
            max_size=16,
        )
    )
    relationships = draw(st.lists(_relationship_row(), min_size=1, max_size=3))
    target = relationships[0]
    evaluation = {
        "risk_id": target["risk_id"],
        "pattern_id": target["pattern_id"],
        "predicate": f"pred.{secret}",
        "facts": f"facts contain {secret}",
        "result": "false",
        "reason": f"because {secret}",
    }
    snapshot = _planner_snapshot(
        relationships, qualification_evaluations=[evaluation]
    )
    snapshot.config = {"api_secret": secret}
    return snapshot, secret


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(data=_snapshots_with_secrets())
def test_configuration_secrets_never_reach_qualification_traces(
    data: tuple[TaxonomyObligationSnapshot, str],
) -> None:
    """Trace fields are redacted and never carry the raw configuration secret."""
    snapshot, secret = data
    plan = plan_obligations(snapshot)

    traces = [
        item for obligation in plan.obligations for item in obligation.qualification_trace
    ]
    assert traces, "the matching evaluation must be retained as a trace"
    for item in traces:
        assert secret not in item.predicate
        assert secret not in str(item.facts)
        assert secret not in str(item.result)
        assert secret not in item.reason
        assert "[REDACTED]" in item.predicate
