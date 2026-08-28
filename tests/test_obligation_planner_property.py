"""Property tests for the taxonomy obligation planner and plan artifact.

These properties pin canonical ordering, serialization round trips,
domain closure, and secret redaction for ``pipeline.obligation_planner``
and ``models.obligation_plan``.  They are offline and deterministic; they
never contact an LLM endpoint.
"""

from __future__ import annotations

import json
from typing import get_args

import yaml
from hypothesis import given, settings
from hypothesis import strategies as st

from asago_scenario_generator.models.obligation_plan import (
    ObligationCorrespondenceDisposition,
    ObligationProjectionDisposition,
    ObligationQualificationDisposition,
    ObligationScopeDisposition,
    TaxonomyObligationPlan,
    TaxonomyObligationSnapshot,
)
from asago_scenario_generator.pipeline.obligation_planner import plan_obligations

_MAX_EXAMPLES = 60
_IDS = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz0123456789-_",
    min_size=1,
    max_size=16,
)

_VALID_COMBINATIONS = [
    ("applicable", "ready", "projectable", True),
    ("applicable", "missing_evidence", "not_attempted", True),
    ("applicable", "contradictory_evidence", "not_attempted", True),
    ("applicable", "structurally_infeasible", "not_attempted", True),
    ("capability_excluded", "not_attempted", "not_attempted", True),
    ("governance_only", "not_attempted", "not_attempted", False),
]

_VALID_KINDS = [
    "gated threat",
    "missing generation template",
    "projection infeasibility",
    "unsupported requirement",
    "qualified generable pattern",
    "governance review",
    "unclassified note",
]


def _snapshot(
    relationships: list[dict[str, object]],
    config: dict[str, str] | None = None,
) -> TaxonomyObligationSnapshot:
    return TaxonomyObligationSnapshot(
        taxonomy_version="atlas-2026.05",
        mapping_version="sssom-v1",
        qualification_ruleset_version="catalog-qualification-v1",
        template_version="scenario-envelope-v1",
        digest="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        relationships=relationships,
        risk_cards=[],
        config=config or {},
        qualification_evaluations=[],
        candidate_expansions=[],
    )


@st.composite
def _relationship_lists(draw: st.DrawFn) -> list[dict[str, object]]:
    """Draw relationship dicts with valid combinations and kinds."""
    num_items = draw(st.integers(min_value=0, max_value=8))
    relationships: list[dict[str, object]] = []
    for _ in range(num_items):
        risk_id = draw(_IDS)
        combo = draw(st.sampled_from(_VALID_COMBINATIONS))
        scope, qual, proj, pattern_allowed = combo
        pattern_id = draw(_IDS) if pattern_allowed else None

        use_kind = draw(st.booleans())
        if use_kind:
            kind = draw(st.sampled_from(_VALID_KINDS))
            rel: dict[str, object] = {
                "risk_id": risk_id,
                "pattern_id": draw(_IDS),
                "relationship_kind": kind,
            }
        else:
            rel = {
                "risk_id": risk_id,
                "pattern_id": pattern_id,
                "scope_disposition": scope,
                "qualification_disposition": qual,
                "projection_disposition": proj,
            }
        relationships.append(rel)
    return relationships


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(relationships=_relationship_lists())
def test_plan_is_invariant_under_relationship_presentation_order(
    relationships: list[dict[str, object]],
) -> None:
    """Canonical ledger order does not depend on snapshot presentation."""
    plan_a = plan_obligations(_snapshot(relationships))
    plan_b = plan_obligations(_snapshot(list(reversed(relationships))))

    assert plan_a == plan_b
    assert plan_a.to_yaml() == plan_b.to_yaml()
    assert plan_a.to_json() == plan_b.to_json()
    assert len(plan_a.obligations) == len(relationships)


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(relationships=_relationship_lists())
def test_every_obligation_has_closed_scope_and_disposition(
    relationships: list[dict[str, object]],
) -> None:
    """Scope and terminal disposition stay inside their declared domains."""
    plan = plan_obligations(_snapshot(relationships))

    for obligation in plan.obligations:
        assert obligation.scope_disposition in get_args(ObligationScopeDisposition)
        assert obligation.qualification_disposition in get_args(
            ObligationQualificationDisposition
        )
        assert obligation.correspondence_disposition in get_args(
            ObligationCorrespondenceDisposition
        )
        assert obligation.projection_disposition in get_args(
            ObligationProjectionDisposition
        )
        assert obligation.risk_id in obligation.obligation_id


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(
    risk_a=_IDS,
    risk_b=_IDS,
    pattern_a=_IDS,
    pattern_b=_IDS,
)
def test_obligation_identity_is_injective_in_risk_and_pattern(
    risk_a: str, risk_b: str, pattern_a: str, pattern_b: str
) -> None:
    """Distinct (risk, pattern) pairs produce distinct obligation ids."""
    id_a = f"ob:{risk_a}:{pattern_a}"
    id_b = f"ob:{risk_b}:{pattern_b}"
    if (risk_a, pattern_a) == (risk_b, pattern_b):
        assert id_a == id_b
        return
    assert id_a != id_b


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(relationships=_relationship_lists())
def test_yaml_and_json_round_trips_are_lossless(
    relationships: list[dict[str, object]],
) -> None:
    """YAML and JSON persistence preserve the authoritative plan model."""
    plan = plan_obligations(_snapshot(relationships))

    assert TaxonomyObligationPlan.from_yaml(plan.to_yaml()) == plan
    assert TaxonomyObligationPlan.from_json(plan.to_json()) == plan


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(relationships=_relationship_lists())
def test_serialization_is_byte_stable(relationships: list[dict[str, object]]) -> None:
    """Serializing the same plan twice yields byte-identical artifacts."""
    plan = plan_obligations(_snapshot(relationships))

    assert plan.to_yaml() == plan.to_yaml()
    assert plan.to_json() == plan.to_json()


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(
    secret=st.text(
        alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        min_size=8,
        max_size=24,
    ),
    predicate=_IDS,
)
def test_config_values_never_leak_into_qualification_traces(
    secret: str, predicate: str
) -> None:
    """Known configuration strings are redacted from persisted traces."""
    snapshot = _snapshot(
        [{"risk_id": "risk-1", "pattern_id": "AP-T1-01"}],
        config={"api_secret": secret},
    )
    snapshot.qualification_evaluations = [
        {
            "risk_id": "risk-1",
            "pattern_id": "AP-T1-01",
            "predicate": f"{predicate} {secret}",
            "facts": f"{predicate}=true {secret}",
            "result": "true",
            "reason": f"evaluated {secret}",
        }
    ]

    plan = plan_obligations(snapshot)
    serialized = plan.to_yaml() + plan.to_json()

    assert secret not in serialized
    trace = plan.obligations[0].qualification_trace[0]
    assert secret not in trace.predicate
    assert secret not in str(trace.facts)
    assert secret not in trace.reason


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(relationships=_relationship_lists())
def test_json_artifact_is_sorted_and_parseable(
    relationships: list[dict[str, object]],
) -> None:
    """The JSON artifact is deterministic, key-sorted, and reparseable."""
    text = plan_obligations(_snapshot(relationships)).to_json()

    parsed = json.loads(text)
    keys = [key for key in parsed]
    assert keys == sorted(keys)
    assert yaml.safe_load(text) == parsed

