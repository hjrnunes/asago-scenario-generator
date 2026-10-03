"""Contract tests for obligation-aware STPA consideration bookkeeping."""

from __future__ import annotations


import pytest

from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
from asago_scenario_generator.models.artifact_pin import ArtifactPin
from asago_scenario_generator.models.obligation_consideration import (
    BoundedStructuralRevision,
    ConsiderationDiagnostic,
    NeutralObligationBrief,
    ObligationConsideration,
    ObligationRoute,
)
from asago_scenario_generator.pipeline.obligation_consideration import (
    batch_neutral_obligation_briefs,
    build_consideration_artifact,
    build_neutral_obligation_briefs,
    validate_obligation_routes,
)

from tests.helpers.obligation_factory import make_plan
from tests.helpers.projection_factory import get_test_raw_pattern


def _briefs():
    plan = make_plan()
    patterns = (AttackPattern.model_validate(get_test_raw_pattern()),)
    return plan, build_neutral_obligation_briefs(plan, patterns)


def _pin(artifact_id: str, schema_version: str = "fixture-v1") -> ArtifactPin:
    return ArtifactPin(
        artifact_id=artifact_id,
        schema_version=schema_version,
        semantic_digest="0" * 64,
    )


def _targeted_route(obligation_id: str) -> ObligationRoute:
    return ObligationRoute(
        route_id=None,
        obligation_id=obligation_id,
        disposition="targeted",
        slot_ids=("RESP-1:CA-1:TYPE-NOT_PROVIDED",),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        evidence=("route evidence",),
        model_call_refs=("call:consideration:1",),
    )


def test_neutral_brief_is_hypothesis_and_does_not_render_ordered_chain() -> None:
    plan, briefs = _briefs()

    assert len(briefs) == 1
    brief = briefs[0]
    assert isinstance(brief, NeutralObligationBrief)
    assert brief.plan_digest == plan.semantic_digest
    assert "hypothesis" in brief.instruction.lower()
    assert "mandatory" in brief.instruction.lower()
    assert all(
        step.step_id not in brief.instruction for step in brief.attack_pattern_steps
    )
    assert brief.semantic_digest == brief.compute_semantic_digest()


def test_brief_factory_retains_applicable_rows_even_when_projection_is_not_ready() -> (
    None
):
    plan, briefs = _briefs()
    row = plan.obligations[0]
    retained = build_neutral_obligation_briefs(
        plan, (AttackPattern.model_validate(get_test_raw_pattern()),)
    )

    assert [brief.obligation_id for brief in retained] == [row.obligation_id]
    assert retained[0].qualification_disposition == row.qualification_disposition


def test_brief_factory_rejects_loose_plan_or_pattern_values() -> None:
    plan, briefs = _briefs()
    with pytest.raises(TypeError, match="TaxonomyObligationPlan"):
        build_neutral_obligation_briefs(  # type: ignore[arg-type]
            plan.model_dump(mode="json"),
            (AttackPattern.model_validate(get_test_raw_pattern()),),
        )
    with pytest.raises(TypeError, match="AttackPattern"):
        build_neutral_obligation_briefs(  # type: ignore[arg-type]
            plan,
            (
                AttackPattern.model_validate(get_test_raw_pattern()).model_dump(
                    mode="json"
                ),
            ),
        )


def test_batching_is_canonical_and_rejects_invalid_size() -> None:
    plan = make_plan(risk_ids=("risk-a", "risk-b"))
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    briefs = build_neutral_obligation_briefs(plan, (pattern,))

    forward = batch_neutral_obligation_briefs(briefs, 1)
    reverse = batch_neutral_obligation_briefs(tuple(reversed(briefs)), 1)
    assert forward == reverse
    assert all(len(batch) == 1 for batch in forward)
    with pytest.raises(ValueError, match="positive"):
        batch_neutral_obligation_briefs(briefs, 0)
    with pytest.raises(TypeError, match="integer"):
        batch_neutral_obligation_briefs(briefs, True)  # type: ignore[arg-type]


def test_route_validation_requires_exactly_one_result_per_brief() -> None:
    _plan, briefs = _briefs()
    route = _targeted_route(briefs[0].obligation_id)
    assert validate_obligation_routes(briefs, (route,)) == (route,)
    with pytest.raises(ValueError, match="exactly once"):
        validate_obligation_routes(briefs, ())
    with pytest.raises(ValueError, match="duplicate"):
        validate_obligation_routes(briefs, (route, route))
    with pytest.raises(ValueError, match="additional"):
        validate_obligation_routes(
            briefs,
            (route, _targeted_route("ob:v1:" + "1" * 64)),
        )


def test_consideration_artifact_carries_its_semantic_digest() -> None:
    plan, briefs = _briefs()
    route = _targeted_route(briefs[0].obligation_id)
    artifact = build_consideration_artifact(
        plan=plan,
        briefs=briefs,
        initial_routes=(route,),
        revision=BoundedStructuralRevision(status="not_required"),
        final_routes=(route,),
        source_pins=(
            ArtifactPin(
                artifact_id="taxonomy-obligation-plan",
                schema_version="taxonomy-obligation-plan-v1",
                semantic_digest=plan.semantic_digest,
            ),
        ),
        diagnostics=(ConsiderationDiagnostic(code="fixture", detail="bookkeeping"),),
    )
    assert isinstance(artifact, ObligationConsideration)
    assert artifact.semantic_digest == artifact.compute_semantic_digest()
