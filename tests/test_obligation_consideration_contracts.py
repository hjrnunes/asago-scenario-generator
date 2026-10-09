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
    ObligationIcaConsideration,
    ObligationRoute,
    StructuralRevisionDelta,
)
from asago_scenario_generator.pipeline.obligation_consideration import (
    batch_neutral_obligation_briefs,
    build_consideration_artifact,
    build_neutral_briefs,
    validate_obligation_routes,
)

from tests.helpers.obligation_factory import make_pin, make_plan
from tests.helpers.projection_factory import get_test_raw_pattern


def _briefs():
    plan = make_plan()
    patterns = (AttackPattern.model_validate(get_test_raw_pattern()),)
    return plan, build_neutral_briefs(plan, patterns)


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
    retained = build_neutral_briefs(
        plan, (AttackPattern.model_validate(get_test_raw_pattern()),)
    )

    assert [brief.obligation_id for brief in retained] == [row.obligation_id]
    assert retained[0].qualification_disposition == row.qualification_disposition


def test_brief_factory_rejects_loose_plan_or_pattern_values() -> None:
    plan, briefs = _briefs()
    with pytest.raises(TypeError, match="TaxonomyObligationPlan"):
        build_neutral_briefs(  # type: ignore[arg-type]
            plan.model_dump(mode="json"),
            (AttackPattern.model_validate(get_test_raw_pattern()),),
        )
    with pytest.raises(TypeError, match="AttackPattern"):
        build_neutral_briefs(  # type: ignore[arg-type]
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
    briefs = build_neutral_briefs(plan, (pattern,))

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


def _delta() -> StructuralRevisionDelta:
    return StructuralRevisionDelta(trigger_gap_ids=("gap:v1:a",), evidence=("e",))


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        ({"status": "not_required", "trigger_gap_ids": ("gap",)}, "revision activity"),
        ({"status": "rejected", "trigger_gap_ids": ()}, "trigger obligations and gaps"),
        (
            {"status": "applied", "proposed_delta": None},
            "proposed and accepted deltas",
        ),
        ({"status": "applied", "accepted_delta": "delta"}, "revised artifact pins"),
        ({"status": "rejected", "accepted_delta": "delta"}, "only an applied"),
    ],
)
def test_bounded_revision_rejects_inconsistent_status(
    fields: dict, message: str
) -> None:
    values = {
        "trigger_obligation_ids": ("ob:v1:" + "1" * 64,),
        "trigger_gap_ids": ("gap:v1:a",),
        "proposed_delta": _delta(),
    }
    if fields.get("status") == "not_required":
        values = {}
    values.update(fields)
    if values.get("accepted_delta") == "delta":
        values["accepted_delta"] = _delta()
    with pytest.raises(ValueError, match=message):
        BoundedStructuralRevision(**values)


def test_bounded_revision_accepts_applied_outcome_with_canonical_triggers() -> None:
    revision = BoundedStructuralRevision(
        status="applied",
        trigger_obligation_ids=("ob:v1:" + "b" * 64, "ob:v1:" + "a" * 64),
        trigger_gap_ids=("gap:v1:a",),
        proposed_delta=_delta(),
        accepted_delta=_delta(),
        revised_pins=(make_pin("revised"),),
    )
    assert revision.trigger_obligation_ids == ("ob:v1:" + "a" * 64, "ob:v1:" + "b" * 64)
    assert revision.accepted_delta == _delta()


def _ica(**fields) -> ObligationIcaConsideration:
    values = {
        "route_id": "route:v1:x",
        "obligation_id": "ob:v1:" + "1" * 64,
        "slot_id": "RESP-1:CA-1:TYPE-NOT_PROVIDED",
        "disposition": "finding",
        "ica_ids": ("ICA-1",),
        "exec_candidate_ids": ("EXEC:1",),
        "hazard_ids": ("H-1",),
        "constraint_ids": ("SC-1",),
        "evidence": ("evidence",),
    }
    values.update(fields)
    return ObligationIcaConsideration(**values)


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        ({"exec_candidate_ids": ("CAND-1",)}, "canonical EXEC"),
        ({"ica_ids": ()}, "ICA and EXEC identities"),
        ({"hazard_ids": ()}, "hazard and constraint identities"),
        ({"disposition": "proposed_not_applicable"}, "cannot retain findings"),
        (
            {
                "disposition": "proposed_not_applicable",
                "ica_ids": (),
                "exec_candidate_ids": (),
            },
            "complete structural inventory",
        ),
        (
            {
                "disposition": "proposed_not_applicable",
                "ica_ids": (),
                "exec_candidate_ids": (),
                "structural_inventory_complete": True,
            },
            "requires a rationale",
        ),
        ({"disposition": "unresolved"}, "unresolved ICA considerations"),
        ({"pair_id": "pair:v1:wrong"}, "pair_id does not match"),
    ],
)
def test_ica_consideration_rejects_inconsistent_disposition(
    fields: dict, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        _ica(**fields)


def test_ica_consideration_accepts_each_disposition_and_assigns_pair_id() -> None:
    finding = _ica()
    assert finding.pair_id is not None and finding.pair_id.startswith("pair:v1:")
    assert _ica(pair_id=finding.pair_id) == finding
    not_applicable = _ica(
        disposition="proposed_not_applicable",
        ica_ids=(),
        exec_candidate_ids=(),
        structural_inventory_complete=True,
        rationale="no such path",
    )
    assert not_applicable.disposition == "proposed_not_applicable"
    unresolved = _ica(disposition="unresolved", ica_ids=(), exec_candidate_ids=())
    assert unresolved.disposition == "unresolved"


def test_consideration_rejects_route_sets_that_do_not_match_the_revision() -> None:
    plan, briefs = _briefs()
    route = _targeted_route(briefs[0].obligation_id)
    other = ObligationRoute(
        obligation_id=briefs[0].obligation_id,
        disposition="unresolved",
        rationale="not yet placed",
        evidence=("route evidence",),
    )
    plan_pin = ArtifactPin(
        artifact_id="taxonomy-obligation-plan",
        schema_version="taxonomy-obligation-plan-v1",
        semantic_digest=plan.semantic_digest,
    )
    base = {"source_pins": (plan_pin,), "briefs": briefs, "initial_routes": (route,)}
    with pytest.raises(ValueError, match="final routes equal initial routes"):
        ObligationConsideration(**base, final_routes=(other,))
    with pytest.raises(ValueError, match="require an applied structural revision"):
        ObligationConsideration(
            **base, final_routes=(route,), rechecked_routes=(route,)
        )
    with pytest.raises(ValueError, match="exact Phase 1 plan pin"):
        ObligationConsideration(
            **{**base, "source_pins": (make_pin("other"),)}, final_routes=(route,)
        )


def test_brief_factory_rejects_unknown_or_substituted_patterns() -> None:
    plan, _ = _briefs()
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    substituted = pattern.model_copy(
        update={
            "canonical_chain": pattern.canonical_chain.model_copy(
                update={"semantic_digest": "f" * 64}
            )
        }
    )
    with pytest.raises(ValueError, match="references an unknown attack pattern"):
        build_neutral_briefs(plan, ())
    with pytest.raises(ValueError, match="substituted its attack-pattern digest"):
        build_neutral_briefs(plan, (substituted,))


@pytest.mark.parametrize(
    ("routes", "match"),
    [
        ("routes", "must be an iterable of ObligationRoute"),
        (5, "must be an iterable of ObligationRoute"),
        ((object(),), "must contain only ObligationRoute"),
    ],
)
def test_route_validation_rejects_loose_route_values(routes, match) -> None:
    _plan, briefs = _briefs()
    with pytest.raises(TypeError, match=match):
        validate_obligation_routes(briefs, routes)


@pytest.mark.parametrize(
    ("overrides", "error", "match"),
    [
        ({"revision": object()}, TypeError, "BoundedStructuralRevision"),
        ({"diagnostics": (object(),)}, TypeError, "ConsiderationDiagnostic"),
        ({"source_pins": (object(),)}, TypeError, "only ArtifactPin"),
        (
            {"source_pins": (make_pin("taxonomy-obligation-plan"),)},
            ValueError,
            "substituted Phase 1 plan pin",
        ),
    ],
)
def test_consideration_artifact_rejects_loose_or_substituted_inputs(
    overrides, error, match
) -> None:
    plan, briefs = _briefs()
    route = _targeted_route(briefs[0].obligation_id)
    with pytest.raises(error, match=match):
        build_consideration_artifact(
            plan=plan,
            briefs=briefs,
            initial_routes=(route,),
            final_routes=(route,),
            **overrides,
        )
