"""A reviewed risk with no attack-pattern catalog stays a governance-only row."""

from __future__ import annotations

from asago_scenario_generator.pipeline.obligation_contracts import (
    TaxonomyObligationInputs,
)
from asago_scenario_generator.pipeline.obligation_planner import (
    plan_taxonomy_obligations,
)
from tests.helpers.obligation_factory import make_inputs


def test_empty_catalog_plans_a_governance_only_row_for_the_risk() -> None:
    payload = make_inputs(
        risk_ids=("risk-governance-only",), include_mapping=False
    ).model_dump(mode="json")
    # The catalog pin still names the release; with no pattern record the
    # planner must not verify it against an empty catalog.
    payload["attack_pattern_catalog"] = []

    plan = plan_taxonomy_obligations(TaxonomyObligationInputs.model_validate(payload))

    rows = [(row.risk_ref.risk_id, row.scope_disposition) for row in plan.obligations]
    assert rows == [("risk-governance-only", "governance_only")]
