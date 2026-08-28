"""Property tests for the typed taxonomy-obligation planner seam."""

from __future__ import annotations

import re

from hypothesis import given, settings
from hypothesis import strategies as st

from asago_scenario_generator.pipeline.obligation_planner import (
    plan_taxonomy_obligations,
)
from tests.helpers.obligation_factory import make_inputs

_MAX_EXAMPLES = 24
_IDS = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz0123456789-_",
    min_size=1,
    max_size=16,
)
_RISK_ID_LISTS = st.lists(_IDS, min_size=1, max_size=5, unique=True)


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(risk_ids=_RISK_ID_LISTS)
def test_planner_retains_each_mapped_risk_with_distinct_identity(
    risk_ids: list[str],
) -> None:
    """Many risks reaching one pattern remain distinct, versioned obligations."""
    plan = plan_taxonomy_obligations(make_inputs(risk_ids=tuple(risk_ids)))

    assert len(plan.obligations) == len(risk_ids)
    assert {row.risk_ref.risk_id for row in plan.obligations} == set(risk_ids)
    assert len({row.obligation_id for row in plan.obligations}) == len(risk_ids)
    assert all(
        re.fullmatch(r"ob:v1:[0-9a-f]{64}", row.obligation_id)
        for row in plan.obligations
    )


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(risk_ids=_RISK_ID_LISTS)
def test_planner_retains_unmapped_risks_as_governance_rows(
    risk_ids: list[str],
) -> None:
    """An advisory mapping filter cannot remove reviewed risks from the ledger."""
    plan = plan_taxonomy_obligations(
        make_inputs(risk_ids=tuple(risk_ids), include_mapping=False)
    )

    assert len(plan.obligations) == len(risk_ids)
    assert {row.risk_ref.risk_id for row in plan.obligations} == set(risk_ids)
    assert all(row.attack_pattern_id is None for row in plan.obligations)
    assert all(row.scope_disposition == "governance_only" for row in plan.obligations)
    assert all(
        row.qualification_disposition == "not_attempted" for row in plan.obligations
    )


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(risk_ids=_RISK_ID_LISTS)
def test_planner_orders_rows_by_canonical_identity(risk_ids: list[str]) -> None:
    """Returned row order is canonical, independent of input order."""
    plan = plan_taxonomy_obligations(make_inputs(risk_ids=tuple(reversed(risk_ids))))

    assert [row.obligation_id for row in plan.obligations] == sorted(
        row.obligation_id for row in plan.obligations
    )
