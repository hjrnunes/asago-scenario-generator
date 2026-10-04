"""Contract tests for provisional obligation accounting."""

from __future__ import annotations


import pytest

from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
from asago_scenario_generator.models.artifact_pin import ArtifactPin
from asago_scenario_generator.models.obligation_accounting import (
    ObligationAccounting,
    ObligationAccountingRow,
)
from asago_scenario_generator.models.obligation_consideration import (
    ConsiderationDiagnostic,
    ObligationIcaConsideration,
    ObligationRoute,
)
from asago_scenario_generator.models.obligation_plan import (
    TaxonomyObligation,
    TaxonomyObligationPlan,
    derive_obligation_summary,
)
from asago_scenario_generator.pipeline.obligation_consideration import (
    build_consideration_artifact,
    build_neutral_obligation_briefs,
    build_obligation_accounting,
)
from tests.helpers.obligation_factory import make_plan
from tests.helpers.projection_factory import get_test_raw_pattern


def _fixture():
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    plan = make_plan()
    briefs = build_neutral_obligation_briefs(plan, (pattern,))
    route = ObligationRoute(
        obligation_id=briefs[0].obligation_id,
        disposition="targeted",
        slot_ids=("RESP-1:CA-1-1:NOT_PROVIDED",),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        rationale="The validation path is structurally relevant.",
        evidence=("RESP-1", "H-1", "SC-1"),
    )
    consideration = build_consideration_artifact(
        plan=plan,
        briefs=briefs,
        initial_routes=(route,),
        final_routes=(route,),
    )
    pair = ObligationIcaConsideration(
        route_id=route.route_id,
        obligation_id=route.obligation_id,
        slot_id=route.slot_ids[0],
        disposition="finding",
        ica_ids=(f"{route.slot_ids[0]}:1",),
        exec_candidate_ids=("EXEC:RESP-1:CA-1-1:NOT_PROVIDED",),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        evidence=("call:ica:1",),
    )
    return plan, consideration, pair


def _plan_with_non_stpa_rows():
    """Build one exact Phase 1 plan containing all accounting scopes."""
    plan = make_plan()
    source_row = plan.obligations[0]
    excluded_payload = source_row.model_dump(mode="json")
    excluded_payload.update(
        obligation_id="ob:v1:" + "c" * 64,
        scope_disposition="capability_excluded",
        qualification_disposition="not_attempted",
        candidate_records=[],
        evidence=[
            {
                "kind": "scope",
                "detail": "required capability was explicitly excluded",
            }
        ],
    )
    excluded = TaxonomyObligation.model_validate(excluded_payload)
    governance = TaxonomyObligation.model_validate(
        {
            "obligation_id": "ob:v1:" + "b" * 64,
            "risk_ref": {
                "risk_id": "governance-risk",
                "risk_name": "Governance risk",
            },
            "taxonomy_chain": [],
            "attack_pattern_id": None,
            "attack_pattern_semantic_digest": None,
            "scope_disposition": "governance_only",
            "qualification_disposition": "not_attempted",
            "candidate_records": [],
            "evidence": [
                {
                    "kind": "governance",
                    "detail": "reviewed governance-only obligation",
                }
            ],
        }
    )
    rows = (source_row, excluded, governance)
    unchecked = TaxonomyObligationPlan.model_validate(
        {
            "schema_version": plan.schema_version,
            "semantic_digest": "0" * 64,
            "capability_snapshot_digest": plan.capability_snapshot_digest,
            "catalog_pins": plan.catalog_pins,
            "mapping_pins": plan.mapping_pins,
            "qualification_facts_digest": plan.qualification_facts_digest,
            "obligations": rows,
            "summary": derive_obligation_summary(rows),
        }
    )
    return TaxonomyObligationPlan.model_validate(
        {
            **unchecked.model_dump(mode="json"),
            "semantic_digest": unchecked.compute_semantic_digest(),
        }
    )


def _pin(artifact_id: str, schema_version: str = "fixture-v1") -> ArtifactPin:
    return ArtifactPin(
        artifact_id=artifact_id,
        schema_version=schema_version,
        semantic_digest="1" * 64,
    )


def _accounting_pins(plan: TaxonomyObligationPlan) -> tuple[ArtifactPin, ...]:
    """Return the four stable authorities required by accounting."""
    return (
        ArtifactPin(
            artifact_id="taxonomy-obligation-plan",
            schema_version="taxonomy-obligation-plan-v1",
            semantic_digest=plan.semantic_digest,
        ),
        ArtifactPin(
            artifact_id="stpa-loss-analysis",
            schema_version="stpa-loss-analysis-v1",
            semantic_digest="2" * 64,
        ),
        ArtifactPin(
            artifact_id="stpa-control-structure",
            schema_version="stpa-control-structure-v1",
            semantic_digest="3" * 64,
        ),
        ArtifactPin(
            artifact_id="ica-enumeration",
            schema_version="ica-enumeration-v1",
            semantic_digest="4" * 64,
        ),
    )


def test_accounting_derives_addressed_row_and_separate_summary() -> None:
    plan, consideration, pair = _fixture()
    accounting = build_obligation_accounting(
        plan=plan,
        consideration=consideration,
        ica_considerations=(pair,),
        source_pins=_accounting_pins(plan),
    )

    assert isinstance(accounting, ObligationAccounting)
    assert len(accounting.rows) == len(plan.obligations)
    assert accounting.rows[0].disposition == "addressed"
    assert accounting.rows[0].ica_ids == pair.ica_ids
    assert accounting.summary.total == 1
    assert accounting.summary.addressed == 1


def test_finding_and_unresolved_slot_remains_unresolved() -> None:
    """One finding cannot hide uncertainty on another routed slot."""
    plan, original, finding = _fixture()
    second_slot = "RESP-1:CA-1-1:PROVIDED_TOO_LATE"
    route_payload = original.final_routes[0].model_dump(mode="json")
    route_payload["route_id"] = None
    route_payload["slot_ids"] = (*original.final_routes[0].slot_ids, second_slot)
    route = ObligationRoute.model_validate(route_payload)
    consideration = build_consideration_artifact(
        plan=plan,
        briefs=original.briefs,
        initial_routes=(route,),
        final_routes=(route,),
    )
    unresolved = ObligationIcaConsideration(
        route_id=route.route_id,
        obligation_id=route.obligation_id,
        slot_id=second_slot,
        disposition="unresolved",
        rationale="The available evidence cannot distinguish the unsafe timing.",
        evidence=("call:ica:2",),
    )
    rebound_finding = finding.model_copy(update={"route_id": route.route_id})

    accounting = build_obligation_accounting(
        plan=plan,
        consideration=consideration,
        ica_considerations=(rebound_finding, unresolved),
        source_pins=_accounting_pins(plan),
    )

    assert accounting.rows[0].disposition == "unresolved"
    assert accounting.rows[0].ica_ids == ()
    assert accounting.summary.unresolved == 1
    assert {
        (pin.artifact_id, pin.schema_version) for pin in accounting.source_pins
    } == {
        ("taxonomy-obligation-plan", "taxonomy-obligation-plan-v1"),
        ("stpa-loss-analysis", "stpa-loss-analysis-v1"),
        ("stpa-control-structure", "stpa-control-structure-v1"),
        ("ica-enumeration", "ica-enumeration-v1"),
    }
    assert accounting.semantic_digest == accounting.compute_semantic_digest()


def test_accounting_requires_all_four_authority_pins_exactly_once() -> None:
    plan, consideration, pair = _fixture()

    with pytest.raises(ValueError, match="exactly one.*ica-enumeration"):
        build_obligation_accounting(
            plan=plan,
            consideration=consideration,
            ica_considerations=(pair,),
            source_pins=_accounting_pins(plan)[:-1],
        )

    with pytest.raises(ValueError, match="unknown"):
        build_obligation_accounting(
            plan=plan,
            consideration=consideration,
            ica_considerations=(pair,),
            source_pins=(*_accounting_pins(plan), _pin("unrelated-authority")),
        )


def test_accounting_model_requires_all_four_authority_pins() -> None:
    plan, consideration, pair = _fixture()
    accounting = build_obligation_accounting(
        plan=plan,
        consideration=consideration,
        ica_considerations=(pair,),
        source_pins=_accounting_pins(plan),
    )
    payload = accounting.model_dump(mode="python")
    payload["source_pins"] = _accounting_pins(plan)[:-1]

    with pytest.raises(ValueError, match="exactly one.*ica-enumeration"):
        ObligationAccounting.model_validate(payload)


@pytest.mark.parametrize(
    ("artifact_id", "schema_version"),
    (
        ("taxonomy-obligation-plan", "taxonomy-obligation-plan-v2"),
        ("stpa-loss-analysis", "loss-analysis-v1"),
        ("stpa-control-structure", "control-structure-v1"),
        ("ica-enumeration", "ica-enumeration-v2"),
    ),
)
def test_accounting_requires_stable_authority_schema_labels(
    artifact_id: str, schema_version: str
) -> None:
    plan, consideration, pair = _fixture()
    pins = list(_accounting_pins(plan))
    index = next(
        index for index, pin in enumerate(pins) if pin.artifact_id == artifact_id
    )
    pins[index] = ArtifactPin(
        artifact_id=artifact_id,
        schema_version=schema_version,
        semantic_digest=pins[index].semantic_digest,
    )

    with pytest.raises(ValueError, match="schema"):
        build_obligation_accounting(
            plan=plan,
            consideration=consideration,
            ica_considerations=(pair,),
            source_pins=tuple(pins),
        )


def test_accounting_never_accepts_coverage_as_a_provisional_disposition() -> None:
    with pytest.raises(ValueError):
        ObligationAccountingRow(
            obligation_id="ob:v1:" + "a" * 64,
            disposition="covered",  # type: ignore[arg-type]
            evidence=("invalid",),
        )


@pytest.mark.parametrize(
    "field",
    ("slot_ids", "ica_ids", "exec_candidate_ids", "hazard_ids", "constraint_ids"),
)
def test_addressed_rows_require_every_exact_structural_identity(field: str) -> None:
    values = {
        "obligation_id": "ob:v1:" + "a" * 64,
        "disposition": "addressed",
        "slot_ids": ("RESP-1:CA-1-1:NOT_PROVIDED",),
        "ica_ids": ("ica-1",),
        "exec_candidate_ids": ("EXEC:RESP-1:CA-1-1:NOT_PROVIDED",),
        "hazard_ids": ("H-1",),
        "constraint_ids": ("SC-1",),
        "route_refs": ("route:v1:" + "c" * 64,),
        "evidence": ("route evidence",),
    }
    values[field] = ()
    with pytest.raises(ValueError, match="exact"):
        ObligationAccountingRow(**values)


def test_accounting_retains_capability_excluded_and_governance_rows_exactly_once() -> (
    None
):
    plan = _plan_with_non_stpa_rows()
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    briefs = build_neutral_obligation_briefs(plan, (pattern,))
    route = ObligationRoute(
        obligation_id=briefs[0].obligation_id,
        disposition="targeted",
        slot_ids=("RESP-1:CA-1-1:NOT_PROVIDED",),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        evidence=("route evidence",),
    )
    consideration = build_consideration_artifact(
        plan=plan,
        briefs=briefs,
        initial_routes=(route,),
        final_routes=(route,),
    )
    pair = ObligationIcaConsideration(
        route_id=route.route_id,
        obligation_id=route.obligation_id,
        slot_id=route.slot_ids[0],
        disposition="finding",
        ica_ids=("ica-1",),
        exec_candidate_ids=("EXEC:RESP-1:CA-1-1:NOT_PROVIDED",),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        evidence=("ica evidence",),
    )

    accounting = build_obligation_accounting(
        plan=plan,
        consideration=consideration,
        ica_considerations=(pair,),
        source_pins=_accounting_pins(plan),
    )

    assert {row.obligation_id for row in accounting.rows} == {
        row.obligation_id for row in plan.obligations
    }
    dispositions = {row.obligation_id: row.disposition for row in accounting.rows}
    by_scope = {row.scope_disposition: row for row in plan.obligations}
    assert dispositions[by_scope["applicable"].obligation_id] == "addressed"
    assert dispositions[by_scope["capability_excluded"].obligation_id] == (
        "capability_excluded"
    )
    assert dispositions[by_scope["governance_only"].obligation_id] == "governance_only"
    assert accounting.summary.model_dump(mode="python") == {
        "total": 3,
        "addressed": 1,
        "proposed_not_applicable": 0,
        "unresolved": 0,
        "upstream_gap": 0,
        "capability_excluded": 1,
        "governance_only": 1,
    }


def test_missing_exact_ica_pair_remains_unresolved() -> None:
    plan, consideration, _pair = _fixture()
    accounting = build_obligation_accounting(
        plan=plan,
        consideration=consideration,
        source_pins=_accounting_pins(plan),
    )

    row = accounting.rows[0]
    assert row.disposition == "unresolved"
    assert {diagnostic.code for diagnostic in row.diagnostics} == {
        "missing_ica_consideration"
    }


def test_structural_non_applicability_requires_complete_slot_evidence() -> None:
    plan, consideration, _pair = _fixture()
    briefs = consideration.briefs
    route = ObligationRoute(
        obligation_id=briefs[0].obligation_id,
        disposition="proposed_not_applicable",
        slot_ids=("RESP-1:CA-1-1:NOT_PROVIDED",),
        rationale="No control path can carry this action in the reviewed structure.",
        evidence=("inventory:complete",),
    )
    consideration = build_consideration_artifact(
        plan=plan,
        briefs=briefs,
        initial_routes=(route,),
        final_routes=(route,),
    )
    pair = ObligationIcaConsideration(
        route_id=route.route_id,
        obligation_id=route.obligation_id,
        slot_id=route.slot_ids[0],
        disposition="proposed_not_applicable",
        structural_inventory_complete=True,
        rationale="The complete structure has no applicable control action.",
        evidence=("inventory:complete",),
    )
    accounting = build_obligation_accounting(
        plan=plan,
        consideration=consideration,
        ica_considerations=(pair,),
        source_pins=_accounting_pins(plan),
    )

    assert accounting.rows[0].disposition == "proposed_not_applicable"
    assert accounting.summary.proposed_not_applicable == 1


@pytest.mark.parametrize(
    ("pairs", "error", "match"),
    [
        (lambda pair: (object(),), TypeError, "only ObligationIcaConsideration"),
        (lambda pair: (pair, pair), ValueError, "unique obligation/slot pairs"),
        (
            lambda pair: (
                pair.model_copy(update={"route_id": "route:v1:" + "f" * 64}),
            ),
            ValueError,
            "does not resolve to its final route",
        ),
        (
            lambda pair: (
                pair.model_copy(update={"slot_id": "RESP-9:CA-9:NOT_PROVIDED"}),
            ),
            ValueError,
            "names a slot outside its final route",
        ),
    ],
)
def test_accounting_rejects_pairs_outside_the_final_routes(pairs, error, match) -> None:
    plan, consideration, pair = _fixture()
    with pytest.raises(error, match=match):
        build_obligation_accounting(
            plan=plan,
            consideration=consideration,
            ica_considerations=pairs(pair),
            source_pins=_accounting_pins(plan),
        )


@pytest.mark.parametrize(
    ("code", "stop_reason"),
    [
        ("prompt_budget_exceeded", "prompt_budget_exceeded"),
        ("routing_validation_failed", "provider_contract_failure"),
        ("routing_record_validation_failed", "no_structural_route"),
    ],
)
def test_unresolved_route_stop_reason_follows_its_diagnostic(
    code: str, stop_reason: str
) -> None:
    plan, original, _pair = _fixture()
    route = ObligationRoute(
        obligation_id=original.briefs[0].obligation_id,
        disposition="unresolved",
        rationale="Structural routing response could not be validated.",
        evidence=("routing-validation",),
        diagnostics=(ConsiderationDiagnostic(code=code, detail="fixture"),),
    )
    consideration = build_consideration_artifact(
        plan=plan,
        briefs=original.briefs,
        initial_routes=(route,),
        final_routes=(route,),
    )
    row = build_obligation_accounting(
        plan=plan, consideration=consideration, source_pins=_accounting_pins(plan)
    ).rows[0]
    assert (row.disposition, row.stop_reason) == ("unresolved", stop_reason)
    assert row.route_refs == (route.route_id,)
