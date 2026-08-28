"""Property tests for the typed taxonomy-obligation output contract."""

from __future__ import annotations

import json

import pytest
import yaml
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from asago_scenario_generator.pipeline.obligation_contracts import (
    TaxonomyObligationInputs,
)
from asago_scenario_generator.pipeline.obligation_planner import (
    plan_taxonomy_obligations,
)
from tests.helpers.obligation_factory import make_inputs, make_plan

_MAX_EXAMPLES = 24
_IDS = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz0123456789-_",
    min_size=1,
    max_size=16,
)
_RISK_ID_LISTS = st.lists(_IDS, min_size=1, max_size=5, unique=True)


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(risk_ids=_RISK_ID_LISTS)
def test_typed_plan_is_invariant_under_risk_presentation_order(
    risk_ids: list[str],
) -> None:
    """Canonical ledger ordering does not depend on input collection order."""
    plan_a = plan_taxonomy_obligations(make_inputs(risk_ids=tuple(risk_ids)))
    plan_b = plan_taxonomy_obligations(make_inputs(risk_ids=tuple(reversed(risk_ids))))

    assert plan_a == plan_b
    assert plan_a.to_yaml() == plan_b.to_yaml()
    assert plan_a.to_json() == plan_b.to_json()
    assert len(plan_a.obligations) == len(risk_ids)


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(risk_ids=_RISK_ID_LISTS)
def test_typed_plan_summary_conserves_rows_and_candidates(
    risk_ids: list[str],
) -> None:
    """Summary equations are derived from the returned authoritative rows."""
    plan = plan_taxonomy_obligations(make_inputs(risk_ids=tuple(risk_ids)))
    summary = plan.summary
    candidates = [
        candidate
        for obligation in plan.obligations
        for candidate in obligation.candidate_records
    ]

    assert summary.total == len(plan.obligations)
    assert summary.total == (
        summary.applicable + summary.governance_only + summary.capability_excluded
    )
    assert summary.applicable == (
        summary.ready
        + summary.missing_or_contradictory
        + summary.structurally_infeasible
    )
    assert summary.projectable == sum(
        candidate.projection_disposition == "projectable" for candidate in candidates
    )
    assert summary.projection_infeasible == sum(
        candidate.projection_disposition == "projection_infeasible"
        for candidate in candidates
    )
    assert summary.budget_deferred == sum(
        candidate.projection_disposition == "budget_deferred"
        for candidate in candidates
    )


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(risk_ids=_RISK_ID_LISTS)
def test_typed_plan_yaml_and_json_round_trips_are_lossless(
    risk_ids: list[str],
) -> None:
    """Canonical YAML and JSON preserve each typed planner result."""
    plan = plan_taxonomy_obligations(make_inputs(risk_ids=tuple(risk_ids)))

    assert type(plan).from_yaml(plan.to_yaml()) == plan
    assert type(plan).from_json(plan.to_json()) == plan


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(risk_ids=_RISK_ID_LISTS)
def test_typed_plan_serialization_is_byte_stable(risk_ids: list[str]) -> None:
    """Repeated serialization of one result is byte-identical."""
    plan = plan_taxonomy_obligations(make_inputs(risk_ids=tuple(risk_ids)))

    assert plan.to_yaml() == plan.to_yaml()
    assert plan.to_json() == plan.to_json()
    parsed = json.loads(plan.to_json())
    assert yaml.safe_load(plan.to_json()) == parsed
    assert list(parsed) == sorted(parsed)


def test_nfc_normalization_preserves_typed_plan_identity() -> None:
    """Equivalent composed/decomposed input strings have the same identity."""
    decomposed = "risco-e\u0301"
    composed = "risco-é"

    decomposed_plan = make_plan(risk_ids=(decomposed,))
    composed_plan = make_plan(risk_ids=(composed,))

    assert decomposed_plan == composed_plan
    assert decomposed_plan.obligations[0].risk_ref.risk_id == composed


def test_legacy_ingress_fields_are_rejected_by_typed_input_contract() -> None:
    """Provider-era config, traces, and candidate overrides cannot enter Phase 1."""
    payload = make_inputs().model_dump(mode="json")
    for field, value in (
        ("config", {"api_secret": "SECRET_SENTINEL"}),
        ("qualification_trace", [{"predicate": "legacy"}]),
        ("candidate_expansions", [{"candidate_id": "caller-authored"}]),
    ):
        candidate_payload = {**payload, field: value}
        with pytest.raises(ValidationError):
            TaxonomyObligationInputs.model_validate(candidate_payload)
