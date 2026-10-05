"""Focused tests for the typed taxonomy-obligation planner seam."""

from __future__ import annotations

import unicodedata
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from pydantic import ValidationError

from asago_scenario_generator.models.obligation_plan import TaxonomyObligationPlan
from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
from asago_scenario_generator.models.attack_pattern_digests import (
    compute_chain_semantic_digest,
)
from asago_scenario_generator.models.attack_pattern_contracts import (
    AuthoritativeFactReference,
    EvaluatedFactEvidence,
)
from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.pipeline.obligation_contracts import (
    TaxonomyObligationInputs,
)
from asago_scenario_generator.pipeline import obligation_planner as planner_module
from asago_scenario_generator.pipeline.obligation_planner import (
    plan_taxonomy_obligations,
)
from asago_scenario_generator.pipeline.projection_contracts import (
    capture_capability_snapshot,
)
from asago_scenario_generator.pipeline.projection_authoritative import (
    _derived_candidates,
)
from asago_scenario_generator.pipeline.projection_contracts import (
    AuthoritativeProjectionObservation,
    ProjectionBatch,
    ProjectionBudget,
    ProjectionLimitation,
    canonical_json_bytes,
)
from asago_scenario_generator.pipeline.projection_qualification import (
    compute_authoritative_catalog_pin,
)
from tests.helpers.obligation_factory import make_inputs, make_plan
from tests.helpers.projection_factory import (
    get_projected_candidate,
    get_test_raw_pattern,
    get_test_profile,
    get_test_resolver,
    get_test_snapshot,
)


def _pattern_requiring_code_interpreter() -> tuple[
    AttackPattern, str, AuthoritativeFactReference
]:
    code_interpreter = AuthoritativeFactReference(
        namespace="profile",
        fact_id="capabilities.code_interpreter",
        value_type="boolean",
        property_path=(),
    )
    raw_pattern = deepcopy(get_test_raw_pattern())
    raw_pattern["canonical_chain"]["steps"][-1]["preconditions"] = [
        {
            "condition_id": "pre.code_interpreter",
            "condition": {
                "op": "existence",
                "schema_version": "1",
                "fact": code_interpreter.model_dump(mode="json"),
                "exists": True,
            },
        }
    ]
    raw_pattern["canonical_chain"]["semantic_digest"] = compute_chain_semantic_digest(
        raw_pattern["canonical_chain"]
    )
    pattern = AttackPattern.model_validate(raw_pattern)
    return (
        pattern,
        compute_authoritative_catalog_pin(
            [pattern.model_dump(mode="json")], get_test_resolver()
        ),
        code_interpreter,
    )


def test_shared_pattern_keeps_distinct_risk_scoped_obligations() -> None:
    """Two reviewed risks reaching one pattern remain separate ledger rows."""
    plan = make_plan(risk_ids=("risk-a", "risk-b"))

    assert len(plan.obligations) == 2
    assert {row.risk_ref.risk_id for row in plan.obligations} == {"risk-a", "risk-b"}
    assert len({row.obligation_id for row in plan.obligations}) == 2
    assert all(row.attack_pattern_id == "AP-T1-01" for row in plan.obligations)


def test_reviewed_risk_without_mapping_is_retained_for_governance() -> None:
    """A risk with no resolved pattern is visible rather than silently dropped."""
    plan = make_plan(risk_ids=("risk-governance",), include_mapping=False)

    assert len(plan.obligations) == 1
    row = plan.obligations[0]
    assert row.risk_ref.risk_id == "risk-governance"
    assert row.attack_pattern_id is None
    assert row.scope_disposition == "governance_only"
    assert row.qualification_disposition == "not_attempted"
    assert row.candidate_records == ()
    assert any(item.kind == "governance" for item in row.evidence)


def test_every_mapping_path_is_retained_as_evidence() -> None:
    """The planner preserves direct and transitive mapping paths."""
    mappings = [
        {
            "source_id": "risk-path",
            "target_id": "taxonomy-intermediate",
            "relation": "risk_to_taxonomy",
            "evidence": ["reviewed direct mapping"],
        },
        {
            "source_id": "taxonomy-intermediate",
            "target_id": "AP-T1-01",
            "relation": "taxonomy_to_pattern",
            "evidence": ["reviewed transitive mapping"],
        },
        {
            "source_id": "risk-path",
            "target_id": "AP-T1-01",
            "relation": "direct_pattern_match",
            "evidence": ["reviewed direct pattern mapping"],
        },
    ]
    plan = make_plan(risk_ids=("risk-path",), mappings=mappings)

    mapping_evidence = [
        item for item in plan.obligations[0].evidence if item.kind == "mapping"
    ]
    assert len(mapping_evidence) == 2
    assert any("taxonomy-intermediate" in item.detail for item in mapping_evidence)
    assert any("direct_pattern_match" in item.detail for item in mapping_evidence)


def test_candidates_are_derived_with_authoritative_ingress_and_bindings() -> None:
    """Projected candidates carry the exact ingress and resource bindings."""
    candidate = get_projected_candidate()
    row = make_plan().obligations[0]

    records = {record.candidate_id: record for record in row.candidate_records}
    record = records[candidate.candidate_id]
    assert record.projection_disposition == "projectable"
    assert record.canonical_ingress == candidate.canonical_ingress
    assert record.resource_bindings == candidate.projection.bindings


def test_deferred_observation_rejects_candidate_identity_collisions() -> None:
    """A reused candidate digest cannot hide different derived content."""
    candidate = get_projected_candidate()
    collision = candidate.model_copy(update={"pattern_id": "AP-COLLISION"})
    allocator = SimpleNamespace(
        candidate_groups=(
            SimpleNamespace(generated=(candidate,)),
            SimpleNamespace(generated=(collision,)),
        )
    )

    with pytest.raises(ValueError, match="candidate-v2 identity collision"):
        _derived_candidates(allocator)


def test_budget_deferred_candidates_retain_authoritative_identity_and_bindings() -> (
    None
):
    """A candidate output cap changes disposition, not candidate truth."""
    profile_payload = get_test_profile().model_dump(mode="json")
    profile_payload["entry_points"][1]["controllability"] = "direct"
    snapshot = capture_capability_snapshot(
        CapabilityProfile.model_validate(profile_payload),
        get_test_snapshot().facts,
    )
    complete_inputs = make_inputs(capability_snapshot=snapshot)
    complete = plan_taxonomy_obligations(complete_inputs)
    bounded = plan_taxonomy_obligations(
        complete_inputs.model_copy(
            update={
                "projection_budget": ProjectionBudget(
                    max_candidates=1,
                    max_derivation_work=4096,
                )
            }
        )
    )

    complete_records = {
        record.candidate_id: (record.canonical_ingress, record.resource_bindings)
        for record in complete.obligations[0].candidate_records
    }
    bounded_records = {
        record.candidate_id: (record.canonical_ingress, record.resource_bindings)
        for record in bounded.obligations[0].candidate_records
    }
    dispositions = [
        record.projection_disposition
        for record in bounded.obligations[0].candidate_records
    ]

    assert len(complete_records) == 2
    assert bounded_records == complete_records
    assert dispositions.count("projectable") == 1
    assert dispositions.count("budget_deferred") == 1
    assert bounded.summary.projectable == 1
    assert bounded.summary.budget_deferred == 1


def test_derivation_work_limit_does_not_synthesize_deferred_candidates() -> None:
    """Unknown overflow remains a limitation, never a fabricated candidate."""
    profile_payload = get_test_profile().model_dump(mode="json")
    profile_payload["entry_points"][1]["controllability"] = "direct"
    snapshot = capture_capability_snapshot(
        CapabilityProfile.model_validate(profile_payload),
        get_test_snapshot().facts,
    )
    complete_inputs = make_inputs(capability_snapshot=snapshot)
    complete = plan_taxonomy_obligations(complete_inputs)
    work_limited = plan_taxonomy_obligations(
        complete_inputs.model_copy(
            update={
                "projection_budget": ProjectionBudget(
                    max_candidates=1,
                    max_derivation_work=1,
                )
            }
        )
    )
    complete_ids = {
        record.candidate_id for record in complete.obligations[0].candidate_records
    }
    limited_records = work_limited.obligations[0].candidate_records

    assert len(complete_ids) == 2
    assert len(limited_records) == 1
    assert limited_records[0].candidate_id in complete_ids
    assert limited_records[0].projection_disposition == "projectable"
    assert work_limited.summary.budget_deferred == 0
    assert any(
        evidence.source == "derivation_work_exhausted"
        for evidence in work_limited.obligations[0].evidence
    )


def test_pattern_local_limitation_keeps_empty_projection_qualified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A bounded result applies only its own pattern limitation fallback."""
    inputs = make_inputs()
    observation = AuthoritativeProjectionObservation(
        batch=ProjectionBatch(
            capability_fact_snapshot_digest=inputs.capability_snapshot.snapshot_digest,
            candidates=(),
            infeasibilities=(),
            limitations=(
                ProjectionLimitation(
                    code="derivation_work_exhausted",
                    pattern_id="AP-T1-01",
                    total_compatible_bindings=1,
                    emitted_bindings=0,
                ),
            ),
        )
    )
    monkeypatch.setattr(
        planner_module,
        "project_authoritative_candidate_observations",
        lambda *_args, **_kwargs: observation,
    )

    row = plan_taxonomy_obligations(inputs).obligations[0]

    assert row.qualification_disposition == "ready"
    assert row.candidate_records == ()
    assert any(
        evidence.source == "derivation_work_exhausted" for evidence in row.evidence
    )


def test_projection_rejections_are_retained_as_typed_candidate_records() -> None:
    """A structural projection rejection remains countable and explainable."""
    profile_payload = get_test_profile().model_dump(mode="json")
    profile_payload["entry_points"] = [
        {**entry_point, "direction": "output"}
        for entry_point in profile_payload["entry_points"]
    ]
    snapshot = capture_capability_snapshot(
        CapabilityProfile.model_validate(profile_payload),
        get_test_snapshot().facts,
    )

    plan = plan_taxonomy_obligations(make_inputs(capability_snapshot=snapshot))
    row = plan.obligations[0]

    assert row.qualification_disposition == "structurally_infeasible"
    assert len(row.candidate_records) == 1
    record = row.candidate_records[0]
    assert record.projection_disposition == "projection_infeasible"
    assert record.canonical_ingress is None
    assert record.resource_bindings == ()
    assert record.reason == "no compatible canonical entry_point resource for slot"
    assert len(record.evidence) == 1
    assert record.evidence[0].source == "missing_compatible_resource"
    assert plan.summary.projection_infeasible == 1


def test_unknown_resource_operation_is_retained_as_missing_evidence() -> None:
    """Unreviewed operation support is an evidence gap, not impossibility."""
    raw_pattern = deepcopy(get_test_raw_pattern())
    raw_pattern["canonical_chain"]["resource_slots"][1]["required_operations"] = [
        "retrieve_data"
    ]
    raw_pattern["canonical_chain"]["semantic_digest"] = compute_chain_semantic_digest(
        raw_pattern["canonical_chain"]
    )
    pattern = AttackPattern.model_validate(raw_pattern)
    catalog_digest = compute_authoritative_catalog_pin(
        [pattern.model_dump(mode="json")], get_test_resolver()
    )

    row = plan_taxonomy_obligations(
        make_inputs(
            pattern=pattern,
            catalog_pins={"atlas": {"release": "v1", "digest": catalog_digest}},
        )
    ).obligations[0]

    assert row.qualification_disposition == "missing_evidence"
    assert row.candidate_records == ()
    assert any(
        evidence.source == "unknown_resource_operation" for evidence in row.evidence
    )


def test_unsupported_resource_operation_is_structurally_infeasible() -> None:
    """A reviewed operation mismatch is a concrete feasibility rejection."""
    raw_pattern = deepcopy(get_test_raw_pattern())
    raw_pattern["canonical_chain"]["resource_slots"][1]["required_operations"] = [
        "retrieve_data"
    ]
    raw_pattern["canonical_chain"]["semantic_digest"] = compute_chain_semantic_digest(
        raw_pattern["canonical_chain"]
    )
    pattern = AttackPattern.model_validate(raw_pattern)
    catalog_digest = compute_authoritative_catalog_pin(
        [pattern.model_dump(mode="json")], get_test_resolver()
    )
    profile_payload = get_test_profile().model_dump(mode="json")
    profile_payload["tool_inventory"][0]["supported_operations"] = ["transmit_data"]
    snapshot = capture_capability_snapshot(
        CapabilityProfile.model_validate(profile_payload), get_test_snapshot().facts
    )

    row = plan_taxonomy_obligations(
        make_inputs(
            pattern=pattern,
            capability_snapshot=snapshot,
            catalog_pins={"atlas": {"release": "v1", "digest": catalog_digest}},
        )
    ).obligations[0]

    assert row.qualification_disposition == "structurally_infeasible"
    assert len(row.candidate_records) == 1
    assert row.candidate_records[0].evidence[0].source == (
        "unsupported_resource_operation"
    )


def test_unsupported_projection_is_retained_with_concrete_rejection_evidence() -> None:
    """Unsupported derivation produces a deterministic rejected candidate row."""
    raw_pattern = deepcopy(get_test_raw_pattern())
    raw_pattern["canonical_chain"]["steps"][0]["resource_links"] = []
    raw_pattern["canonical_chain"]["semantic_digest"] = compute_chain_semantic_digest(
        raw_pattern["canonical_chain"]
    )
    pattern = AttackPattern.model_validate(raw_pattern)
    catalog_digest = compute_authoritative_catalog_pin(
        [pattern.model_dump(mode="json")],
        get_test_resolver(),
    )

    plan = plan_taxonomy_obligations(
        make_inputs(
            pattern=pattern,
            catalog_pins={
                "atlas": {
                    "release": "v1",
                    "digest": catalog_digest,
                }
            },
        )
    )
    row = plan.obligations[0]

    assert row.qualification_disposition == "structurally_infeasible"
    assert len(row.candidate_records) == 1
    record = row.candidate_records[0]
    assert record.projection_disposition == "projection_infeasible"
    assert record.reason == (
        "no activation mechanism (ingress or source_influence) among selected steps"
    )
    assert record.evidence[0].source == "unsupported_requirement_derivation"
    assert plan.summary.projection_infeasible == 1


def test_capability_exclusion_precedes_absent_separate_qualification_facts() -> None:
    """An incompatible profile is excluded without attempting qualification."""
    raw_pattern = deepcopy(get_test_raw_pattern())
    raw_pattern["prerequisite_capabilities"]["kc_requires"] = {
        "all": ["KC2.1"],
        "any": [],
    }
    pattern = AttackPattern.model_validate(raw_pattern)
    catalog_digest = compute_authoritative_catalog_pin(
        [pattern.model_dump(mode="json")],
        get_test_resolver(),
    )
    payload = make_inputs(
        pattern=pattern,
        catalog_pins={
            "atlas": {
                "release": "v1",
                "digest": catalog_digest,
            }
        },
    ).model_dump(mode="json")
    payload["qualification_facts"] = {"facts": {}}

    plan = plan_taxonomy_obligations(TaxonomyObligationInputs.model_validate(payload))
    row = plan.obligations[0]

    assert row.scope_disposition == "capability_excluded"
    assert row.qualification_disposition == "not_attempted"
    assert row.candidate_records == ()
    assert any(
        evidence.kind == "projection" and evidence.source == "incompatible_profile"
        for evidence in row.evidence
    )


def test_contradictory_qualification_fact_is_retained_as_contradictory_evidence() -> (
    None
):
    """Contradictory required facts block readiness without becoming unknown."""
    payload = make_inputs().model_dump(mode="json")
    qualification = payload["qualification_facts"]
    fact_key = next(iter(qualification["facts"]))
    qualification["facts"][fact_key]["status"] = "contradictory"
    qualification["facts"][fact_key]["value"] = None
    qualification["semantic_digest"] = None

    plan = plan_taxonomy_obligations(TaxonomyObligationInputs.model_validate(payload))
    row = plan.obligations[0]

    assert row.qualification_disposition == "contradictory_evidence"
    assert row.candidate_records == ()
    evaluation = next(
        evaluation
        for evidence in row.evidence
        for evaluation in evidence.fact_evaluations
        if evaluation.evaluation_type == "qualification_fact"
    )
    assert evaluation.result == "unknown"
    assert evaluation.rationale == "authoritative qualification fact is contradictory"
    assert [(fact.status, fact.value) for fact in evaluation.facts] == [
        ("contradictory", None)
    ]
    assert TaxonomyObligationPlan.from_yaml(plan.to_yaml()) == plan


def test_contradictory_qualification_precedes_mixed_missing_readings() -> None:
    """Contradiction wins deterministically when required readings are mixed."""
    raw_pattern = deepcopy(get_test_raw_pattern())
    second_fact = {
        "namespace": "profile",
        "fact_id": "region",
        "value_type": "string",
        "property_path": [],
    }
    raw_pattern["canonical_chain"]["steps"][2]["preconditions"] = [
        {
            "condition_id": "pre.region",
            "condition": {
                "op": "equality",
                "schema_version": "1",
                "fact": second_fact,
                "value": "eu",
            },
        }
    ]
    raw_pattern["canonical_chain"]["semantic_digest"] = compute_chain_semantic_digest(
        raw_pattern["canonical_chain"]
    )
    pattern = AttackPattern.model_validate(raw_pattern)
    catalog_digest = compute_authoritative_catalog_pin(
        [pattern.model_dump(mode="json")],
        get_test_resolver(),
    )
    payload = make_inputs(
        pattern=pattern,
        catalog_pins={
            "atlas": {
                "release": "v1",
                "digest": catalog_digest,
            }
        },
    ).model_dump(mode="json")
    qualification = payload["qualification_facts"]
    mode_key = next(
        key
        for key, value in qualification["facts"].items()
        if value["fact"]["fact_id"] == "mode"
    )
    region_key = canonical_json_bytes(second_fact).decode("utf-8")
    qualification["facts"][mode_key]["status"] = "contradictory"
    qualification["facts"][mode_key]["value"] = None
    qualification["facts"][region_key] = {
        "fact": second_fact,
        "status": "absent",
        "value": None,
    }
    qualification["semantic_digest"] = None

    plan = plan_taxonomy_obligations(TaxonomyObligationInputs.model_validate(payload))
    row = plan.obligations[0]
    evaluation = next(
        evaluation
        for evidence in row.evidence
        for evaluation in evidence.fact_evaluations
        if evaluation.evaluation_type == "qualification_fact"
    )

    assert row.qualification_disposition == "contradictory_evidence"
    assert row.candidate_records == ()
    assert {fact.status for fact in evaluation.facts} == {"absent", "contradictory"}
    assert evaluation.rationale == "authoritative qualification fact is contradictory"


def test_ready_obligation_persists_typed_condition_fact_evidence() -> None:
    """Ready rows retain evaluated facts, result, status, and rationale."""
    plan = make_plan()
    evaluations = tuple(
        evaluation
        for evidence in plan.obligations[0].evidence
        for evaluation in evidence.fact_evaluations
    )

    condition = next(
        item for item in evaluations if item.evaluation_type == "condition"
    )
    assert condition.step_id == "step.2"
    assert condition.result == "true"
    assert condition.rationale == "authoritative condition evaluation"
    assert [(fact.status, fact.value) for fact in condition.facts] == [
        ("present", "active")
    ]
    assert TaxonomyObligationPlan.from_yaml(plan.to_yaml()) == plan


def test_ready_obligation_persists_typed_precondition_fact_evidence() -> None:
    """Selected-step preconditions survive as typed qualification evidence."""
    raw_pattern = deepcopy(get_test_raw_pattern())
    raw_pattern["canonical_chain"]["steps"][-1]["preconditions"] = [
        {
            "condition_id": "pre.active",
            "condition": {
                "op": "equality",
                "schema_version": "1",
                "fact": {
                    "namespace": "profile",
                    "fact_id": "mode",
                    "value_type": "string",
                    "property_path": [],
                },
                "value": "active",
            },
        }
    ]
    raw_pattern["canonical_chain"]["semantic_digest"] = compute_chain_semantic_digest(
        raw_pattern["canonical_chain"]
    )
    pattern = AttackPattern.model_validate(raw_pattern)
    catalog_digest = compute_authoritative_catalog_pin(
        [pattern.model_dump(mode="json")],
        get_test_resolver(),
    )
    plan = plan_taxonomy_obligations(
        make_inputs(
            pattern=pattern,
            catalog_pins={
                "atlas": {
                    "release": "v1",
                    "digest": catalog_digest,
                }
            },
        )
    )
    evaluations = tuple(
        evaluation
        for evidence in plan.obligations[0].evidence
        for evaluation in evidence.fact_evaluations
    )

    precondition = next(
        item for item in evaluations if item.evaluation_type == "precondition"
    )
    assert precondition.step_id == "step.3"
    assert precondition.condition_id == "pre.active"
    assert precondition.result == "true"
    assert precondition.rationale == "authoritative precondition evaluation"
    assert [fact.status for fact in precondition.facts] == ["present"]


def test_failed_precondition_persists_typed_projection_fact_evidence() -> None:
    """Projection rejection retains the evaluated facts and rejection rationale."""
    raw_pattern = deepcopy(get_test_raw_pattern())
    raw_pattern["canonical_chain"]["steps"][-1]["preconditions"] = [
        {
            "condition_id": "pre.inactive",
            "condition": {
                "op": "equality",
                "schema_version": "1",
                "fact": {
                    "namespace": "profile",
                    "fact_id": "mode",
                    "value_type": "string",
                    "property_path": [],
                },
                "value": "inactive",
            },
        }
    ]
    raw_pattern["canonical_chain"]["semantic_digest"] = compute_chain_semantic_digest(
        raw_pattern["canonical_chain"]
    )
    pattern = AttackPattern.model_validate(raw_pattern)
    catalog_digest = compute_authoritative_catalog_pin(
        [pattern.model_dump(mode="json")],
        get_test_resolver(),
    )
    row = plan_taxonomy_obligations(
        make_inputs(
            pattern=pattern,
            catalog_pins={
                "atlas": {
                    "release": "v1",
                    "digest": catalog_digest,
                }
            },
        )
    ).obligations[0]
    rejection = next(
        evidence
        for evidence in row.evidence
        if evidence.source == "precondition_not_satisfied"
    )
    precondition = next(
        item
        for item in rejection.fact_evaluations
        if item.evaluation_type == "precondition"
        and item.condition_id == "pre.inactive"
    )

    assert row.qualification_disposition == "contradictory_evidence"
    assert precondition.result == "false"
    assert [(fact.status, fact.value) for fact in precondition.facts] == [
        ("present", "active")
    ]
    assert precondition.rationale == (
        "one or more selected-step preconditions are false"
    )


def test_explicitly_absent_precondition_precedes_generic_fact_gap() -> None:
    """A concrete false precondition is contradiction, not missing evidence."""
    pattern, catalog_digest, code_interpreter = _pattern_requiring_code_interpreter()
    snapshot = capture_capability_snapshot(
        get_test_profile(),
        (
            *get_test_snapshot().facts,
            EvaluatedFactEvidence(fact=code_interpreter, status="absent"),
        ),
    )

    row = plan_taxonomy_obligations(
        make_inputs(
            pattern=pattern,
            capability_snapshot=snapshot,
            catalog_pins={"atlas": {"release": "v1", "digest": catalog_digest}},
        )
    ).obligations[0]

    assert row.qualification_disposition == "contradictory_evidence"
    assert row.candidate_records == ()
    rejection = next(
        evidence
        for evidence in row.evidence
        if evidence.source == "precondition_not_satisfied"
    )
    precondition = next(
        evaluation
        for evaluation in rejection.fact_evaluations
        if evaluation.evaluation_type == "precondition"
        and evaluation.condition_id == "pre.code_interpreter"
    )
    assert precondition.result == "false"
    assert precondition.facts[0].status == "absent"


def test_unknown_precondition_fact_remains_missing_evidence() -> None:
    """No authoritative reading remains an evidence gap, not contradiction."""
    pattern, catalog_digest, _ = _pattern_requiring_code_interpreter()

    row = plan_taxonomy_obligations(
        make_inputs(
            pattern=pattern,
            catalog_pins={"atlas": {"release": "v1", "digest": catalog_digest}},
        )
    ).obligations[0]

    assert row.qualification_disposition == "missing_evidence"
    assert row.candidate_records == ()
    qualification = next(
        evidence
        for evidence in row.evidence
        if evidence.source == "qualification-facts"
    )
    assert qualification.fact_evaluations[0].facts[0].status == "absent"


def test_planner_accepts_only_complete_typed_inputs() -> None:
    """The public planner fails closed for mappings, paths, and legacy records."""
    with pytest.raises(TypeError):
        plan_taxonomy_obligations({})  # type: ignore[arg-type]

    payload = make_inputs().model_dump(mode="json")
    for field, value in (
        ("config", {"api_secret": "SECRET_SENTINEL"}),
        ("qualification_trace", [{"predicate": "legacy"}]),
        ("candidate_expansions", [{"candidate_id": "caller-authored"}]),
    ):
        with pytest.raises(ValidationError):
            TaxonomyObligationInputs.model_validate({**payload, field: value})


@pytest.mark.parametrize(
    ("field", "other_name"),
    [
        ("capability_snapshot", "capability_fact_snapshot"),
        ("attack_pattern_catalog", "attack_patterns"),
        ("attack_pattern_catalog", "catalog"),
        ("cross_taxonomy_mappings", "risk_pattern_mappings"),
        ("cross_taxonomy_mappings", "mappings"),
        ("sssom_mappings", "sssom"),
        ("catalog_pins", "taxonomy_pins"),
        ("mapping_pins", "mapping_set_pins"),
        ("qualification_facts", "qualification_evidence"),
        ("projection_budget", "budget"),
        ("compatibility_policy", "compatibility"),
    ],
)
def test_planner_inputs_accept_only_field_names(field: str, other_name: str) -> None:
    payload = make_inputs().model_dump(mode="json")
    payload[other_name] = payload.pop(field)

    with pytest.raises(ValidationError):
        TaxonomyObligationInputs.model_validate(payload)


def test_invalid_snapshot_and_budget_are_rejected_before_planning() -> None:
    """Contradictory global inputs do not produce a partial plan."""
    payload = make_inputs().model_dump(mode="json")

    snapshot = dict(payload["capability_snapshot"])
    snapshot["snapshot_digest"] = snapshot["snapshot_digest"][::-1]
    with pytest.raises((ValidationError, ValueError)):
        TaxonomyObligationInputs.model_validate(
            {**payload, "capability_snapshot": snapshot}
        )

    with pytest.raises((ValidationError, ValueError)):
        TaxonomyObligationInputs.model_validate(
            {
                **payload,
                "projection_budget": {
                    "max_candidates": 0,
                    "max_derivation_work": 4096,
                },
            }
        )


def test_unicode_risk_ids_are_normalized_before_identity_is_computed() -> None:
    """NFC-equivalent risk identifiers produce one canonical obligation identity."""
    decomposed = "risco-e\u0301"
    plan = make_plan(risk_ids=(decomposed,))

    assert plan.obligations[0].risk_ref.risk_id == unicodedata.normalize(
        "NFC", decomposed
    )
    assert plan.obligations[0].risk_ref.risk_id == "risco-é"
    assert plan.obligations[0].obligation_id.startswith("ob:v1:")


def test_planner_is_offline_and_deterministic(offline_llm: None) -> None:
    """Planning uses the typed local inputs and never needs an LLM provider."""
    first = make_plan()
    second = make_plan()

    assert first == second
    assert first.to_yaml() == second.to_yaml()
    assert first.to_json() == second.to_json()


def test_yaml_persistence_is_atomic_and_round_trip_verified(tmp_path: Path) -> None:
    """The persistence adapter publishes one validated YAML artifact atomically."""
    from asago_scenario_generator.pipeline.obligation_persistence import (
        write_taxonomy_obligation_plan,
    )

    inputs = TaxonomyObligationInputs.model_validate(
        yaml.safe_load(
            yaml.safe_dump(make_inputs().model_dump(mode="json"), sort_keys=True)
        )
    )
    output_dir = tmp_path / "published"

    expected = make_plan()
    plan = plan_taxonomy_obligations(inputs)
    written = [write_taxonomy_obligation_plan(output_dir, plan)]

    assert plan == expected
    assert written == [output_dir / "taxonomy-obligation-plan.yaml"]
    assert TaxonomyObligationPlan.from_yaml(written[0].read_text()) == plan
    assert not list(output_dir.glob("*.tmp"))
