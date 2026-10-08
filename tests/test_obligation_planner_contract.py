"""Red tests for the normative Phase 1 obligation-planner contract.

The legacy ``plan_obligations(snapshot)`` fixture API is covered by the
compatibility tests in :mod:`test_obligation_planner`.  These tests exercise
the reviewed typed planner seam and intentionally use the authoritative
projection fixture instead of supplying candidate records as input.
"""

from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from importlib import import_module
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest
from pydantic import ValidationError
from tests.cli_helpers import PlainCliRunner

from asago_scenario_generator.models.attack_pattern import (
    AttackPattern,
    compute_chain_semantic_digest,
)
from asago_scenario_generator.models.canonical import (
    FrozenDict,
    FrozenList,
    canonical_json_bytes,
)
from asago_scenario_generator.models.risk_card import RiskCard
from asago_scenario_generator.pipeline.obligation_contracts import (
    CompatibilityPolicyInput,
    CrossTaxonomyMappingInput,
    QualificationFactsInput,
    RiskCardInput,
    SSSOMMappingInput,
    _freeze_nested_collections,
    compute_mapping_bundle_digest,
)
from asago_scenario_generator.pipeline.projection_authoritative import (
    project_authoritative_candidate_observations,
)
from asago_scenario_generator.pipeline.projection_contracts import (
    ProjectionBudget,
    capture_capability_snapshot,
    CapabilityFactSnapshot,
    ProjectionBatch,
    ProjectionIssue,
    RejectedProjectionCandidate,
)
from asago_scenario_generator.pipeline.projection_authoritative import (
    _deduplicate_rejected_candidates,
    _deferred_projection_candidates,
)
from tests.helpers.projection_factory import (
    get_projected_candidate,
    get_test_profile,
    get_test_raw_pattern,
    get_test_resolver,
    get_test_snapshot,
)
from asago_scenario_generator.models.obligation_plan import (
    RiskEvidence,
    TaxonomyObligationPlan,
)
from asago_scenario_generator.pipeline.obligation_persistence import (
    write_taxonomy_obligation_plan,
)
from asago_scenario_generator.cli import app
from asago_scenario_generator.pipeline.taxonomy_inputs import (
    OBLIGATION_EDGES_RELEASE,
)


def _input_type() -> type[Any]:
    """Resolve the typed input from the pipeline contract boundary only."""
    for module_name in (
        "asago_scenario_generator.pipeline.obligation_contracts",
        "asago_scenario_generator.pipeline.obligation_planner",
    ):
        try:
            module = import_module(module_name)
            input_type = getattr(module, "TaxonomyObligationInputs")
        except (ImportError, AttributeError):
            continue
        if input_type.__module__ == "asago_scenario_generator.models.obligation_plan":
            pytest.fail(
                "TaxonomyObligationInputs must be a pipeline input contract, "
                "not a persisted output model"
            )
        return input_type
    pytest.fail(
        "Corrective contract is missing TaxonomyObligationInputs from "
        "pipeline.obligation_contracts or pipeline.obligation_planner"
    )


def _projection_fixture() -> tuple[Any, AttackPattern, CapabilityFactSnapshot]:
    """Return a real candidate, its authoritative pattern, and its snapshot."""
    candidate = get_projected_candidate()
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    snapshot = get_test_snapshot()
    assert isinstance(snapshot, CapabilityFactSnapshot)
    return candidate, pattern, snapshot


def _qualification_fact_type() -> type[Any]:
    """Resolve the current shared qualification-fact value contract."""
    module = import_module("asago_scenario_generator.pipeline.obligation_contracts")
    for name in ("QualificationFactSet", "QualificationFactsInput"):
        fact_type = getattr(module, name, None)
        if fact_type is not None:
            return fact_type
    pytest.fail(
        "The pipeline contract must expose QualificationFactSet or "
        "QualificationFactsInput"
    )


def _qualification_fact_set(snapshot: CapabilityFactSnapshot) -> Any:
    """Construct a fact set so its shared validator computes the real digest."""
    fact_type = _qualification_fact_type()
    for value in (list(snapshot.facts), {"facts": list(snapshot.facts)}):
        try:
            fact_set = fact_type.model_validate(value)
        except (TypeError, ValidationError, ValueError):
            continue
        digest = getattr(fact_set, "semantic_digest", None)
        if digest:
            return fact_set
    pytest.fail("The shared qualification-fact contract could not build a valid set")


def test_rejected_candidate_identity_collisions_fail_closed() -> None:
    """Two different rejects cannot share one candidate-v2 identity."""
    issue = ProjectionIssue(
        code="missing_compatible_resource",
        pattern_id="AP-T1-01",
        detail="no compatible resource",
    )
    candidate = RejectedProjectionCandidate(
        candidate_id="cand:v2:" + "a" * 32,
        pattern_id=issue.pattern_id,
        reason=issue.detail,
        issue=issue,
    )
    conflicting = candidate.model_copy(update={"reason": "different reason"})

    with pytest.raises(ValueError, match="rejected candidate-v2 identity collision"):
        _deduplicate_rejected_candidates([candidate, conflicting])


def test_deferred_tail_does_not_continue_after_work_exhaustion() -> None:
    """An exhausted allocator must not be advanced by observation."""
    fill_round_robin = Mock()
    allocator = SimpleNamespace(
        work_exhausted=True,
        retain_deferred=False,
        candidate_groups=(),
        fill_round_robin=fill_round_robin,
    )
    batch = ProjectionBatch(
        capability_fact_snapshot_digest="0" * 64,
        candidates=(),
        infeasibilities=(),
        limitations=(),
    )

    assert _deferred_projection_candidates(allocator, batch, True) == ()
    fill_round_robin.assert_not_called()


def test_deferred_tail_sets_allocator_retention_before_continuing() -> None:
    """A live observation tail enables deferred retention before filling."""
    fill_round_robin = Mock()
    allocator = SimpleNamespace(
        work_exhausted=False,
        retain_deferred=False,
        candidate_groups=(),
        fill_round_robin=fill_round_robin,
    )
    batch = ProjectionBatch(
        capability_fact_snapshot_digest="0" * 64,
        candidates=(),
        infeasibilities=(),
        limitations=(),
    )

    assert _deferred_projection_candidates(allocator, batch, True) == ()
    assert allocator.retain_deferred is True
    fill_round_robin.assert_called_once_with()


def test_nested_freezing_dispatch_handles_every_supported_shape() -> None:
    """Nested input copies preserve models and freeze every collection kind."""
    evidence = RiskEvidence(text="reviewed")
    already_frozen_mapping = FrozenDict({"value": "stable"})
    already_frozen_list = FrozenList(["stable"])

    assert _freeze_nested_collections(already_frozen_mapping) is already_frozen_mapping
    assert _freeze_nested_collections(already_frozen_list) is already_frozen_list
    assert _freeze_nested_collections(evidence) is evidence
    assert _freeze_nested_collections(7) == 7

    mapping = _freeze_nested_collections(
        {"model": evidence, "tuple": ("item",), "set": {"item"}}
    )
    assert isinstance(mapping, FrozenDict)
    assert mapping["model"] is evidence
    assert mapping["tuple"] == ("item",)
    assert isinstance(mapping["set"], frozenset)

    sequence = _freeze_nested_collections([{"item": "value"}])
    assert isinstance(sequence, FrozenList)
    assert isinstance(sequence[0], FrozenDict)


def _risk_card(risk_id: str) -> RiskCard:
    """Build a typed reviewed risk card for the planner input."""
    return RiskCard(
        risk_id=risk_id,
        risk_name=f"Risk {risk_id}",
        risk_description="A reviewed risk used by the planner contract tests.",
        taxonomy="ibm-risk-atlas",
        confidence=1.0,
        grounding_confidence="high",
    )


def _pattern(*, pattern_id: str | None = None, mutate: bool = False) -> AttackPattern:
    """Return an authoritative pattern, optionally with repinned semantics."""
    raw = deepcopy(get_test_raw_pattern())
    if pattern_id is not None:
        raw["id"] = pattern_id
        raw["canonical_chain"]["pattern_id"] = pattern_id
    if mutate:
        raw["canonical_chain"]["steps"][0]["provenance"]["adaptation_rationale"] = (
            "semantic content changed under test"
        )
    raw["canonical_chain"]["semantic_digest"] = compute_chain_semantic_digest(
        raw["canonical_chain"]
    )
    return AttackPattern.model_validate(raw)


def _real_catalog_pin(
    pattern: AttackPattern, snapshot: CapabilityFactSnapshot
) -> dict[str, str]:
    """Capture a catalog pin from the real authoritative projection path."""
    batch = project_authoritative_candidate_observations(
        [pattern.model_dump(mode="json")],
        get_test_resolver(),
        snapshot,
        budget=ProjectionBudget(max_candidates=100),
    ).batch
    assert batch.candidates, batch.infeasibilities
    candidate = batch.candidates[0]
    release = pattern.canonical_chain.taxonomy_context.atlas.release
    return {"release": release, "digest": candidate.projection.catalog_pin}


def _real_mapping_pin(
    pattern: AttackPattern,
) -> dict[str, str]:
    """Capture the mapping-set pin carried by the taxonomy context."""
    context = pattern.canonical_chain.taxonomy_context
    return {
        "release": context.atlas.release,
        "digest": context.mapping_set_digest,
    }


def _real_mapping_bundle_pin(
    mappings: list[dict[str, Any]],
) -> dict[str, str]:
    """Capture the separately framed supplied-edge bundle pin."""
    return {
        "release": OBLIGATION_EDGES_RELEASE,
        "digest": compute_mapping_bundle_digest(mappings, []),
    }


def _input_payload(
    *,
    risk_ids: tuple[str, ...] = ("risk-a",),
    pattern: AttackPattern | None = None,
    capability_snapshot: CapabilityFactSnapshot | None = None,
    include_mapping: bool = True,
    catalog_pins: dict[str, Any] | None = None,
    mapping_pins: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Construct typed planner input from authoritative domain fixtures.

    In particular, this function deliberately has no candidate-record input.
    Candidate records are planner output derived from the pattern and snapshot.
    """
    candidate, default_pattern, default_snapshot = _projection_fixture()
    pattern = pattern or default_pattern
    capability_snapshot = capability_snapshot or default_snapshot
    mappings = (
        [
            {
                "source_id": risk_id,
                "target_id": pattern.id,
                "relation": "exact_match",
                "confidence": 1.0,
            }
            for risk_id in risk_ids
        ]
        if include_mapping
        else []
    )
    default_catalog_pins = {"atlas": _real_catalog_pin(pattern, capability_snapshot)}
    default_mapping_pins = {
        "sssom": _real_mapping_pin(pattern),
        "obligation_edges": _real_mapping_bundle_pin(mappings),
    }
    qualification_facts = _qualification_fact_set(capability_snapshot)
    values: dict[str, Any] = {
        "risk_cards": [_risk_card(risk_id) for risk_id in risk_ids],
        "capability_snapshot": capability_snapshot,
        "attack_pattern_catalog": [pattern],
        "cross_taxonomy_mappings": mappings,
        "sssom_mappings": [],
        "catalog_pins": catalog_pins or default_catalog_pins,
        "mapping_pins": mapping_pins or default_mapping_pins,
        "qualification_facts": qualification_facts,
        "projection_budget": ProjectionBudget(
            max_candidates=100,
            max_derivation_work=4096,
        ),
        "compatibility_policy": {"allow_legacy_keyword_matches": False},
    }
    assert "candidate_expansions" not in values
    return values


def _make_inputs(**kwargs: Any) -> Any:
    """Construct the public typed input value."""
    input_type = _input_type()
    return input_type.model_validate(_input_payload(**kwargs))


def _plan(inputs: Any) -> Any:
    """Call only the agreed typed planner seam."""
    try:
        from asago_scenario_generator.pipeline.obligation_planner import (
            plan_taxonomy_obligations,
        )
    except ImportError as exc:  # pragma: no cover - expected before implementation
        pytest.fail(
            "Corrective contract is missing plan_taxonomy_obligations: " + str(exc)
        )
    return plan_taxonomy_obligations(inputs)


def _plan_row(plan: Any, *, count: int = 1) -> dict[str, Any]:
    rows = plan.model_dump(mode="json")["obligations"]
    assert len(rows) == count
    return rows[0]


def _jsonable(value: Any) -> Any:
    """Encode typed input models for the file adapter without losing semantics."""
    if hasattr(value, "model_dump"):
        return _jsonable(value.model_dump(mode="json"))
    if isinstance(value, dict):
        return {key: _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def test_typed_inputs_live_in_the_pipeline_and_have_no_candidate_escape_hatch() -> None:
    """Input contracts are not persisted output models or candidate overrides."""
    input_type = _input_type()

    assert input_type.__module__ in {
        "asago_scenario_generator.pipeline.obligation_contracts",
        "asago_scenario_generator.pipeline.obligation_planner",
    }
    assert "candidate_expansions" not in input_type.model_fields


def test_risk_card_without_pattern_is_retained_as_governance_visibility() -> None:
    """A reviewed risk remains visible when no mapping reaches a pattern."""
    plan = _plan(
        _make_inputs(
            risk_ids=("risk-governance-only",),
            include_mapping=False,
        )
    )

    row = _plan_row(plan)
    assert row["risk_ref"]["risk_id"] == "risk-governance-only"
    assert row["scope_disposition"] == "governance_only"
    assert row["qualification_disposition"] == "not_attempted"


def test_two_risks_reaching_one_pattern_keep_distinct_risk_obligations() -> None:
    """Risk provenance is not collapsed when the attack pattern is shared."""
    plan = _plan(_make_inputs(risk_ids=("risk-a", "risk-b")))
    rows = plan.model_dump(mode="json")["obligations"]

    assert len(rows) == 2
    assert {row["risk_ref"]["risk_id"] for row in rows} == {"risk-a", "risk-b"}
    assert len({row["obligation_id"] for row in rows}) == 2


def test_persisted_obligation_row_has_the_normative_closed_shape() -> None:
    """Rows retain risk/taxonomy provenance and evidence without legacy aliases."""
    candidate, pattern, _snapshot = _projection_fixture()
    row = _plan_row(_plan(_make_inputs()))

    assert set(row) == {
        "obligation_id",
        "risk_ref",
        "taxonomy_chain",
        "attack_pattern_id",
        "attack_pattern_semantic_digest",
        "scope_disposition",
        "qualification_disposition",
        "candidate_records",
        "evidence",
    }
    assert row["risk_ref"]["risk_id"] == "risk-a"
    assert row["taxonomy_chain"] == [{"taxonomy": "ATLAS", "id": "AML.T0001"}]
    assert row["attack_pattern_id"] == pattern.id
    assert (
        row["attack_pattern_semantic_digest"] == pattern.canonical_chain.semantic_digest
    )
    assert isinstance(row["candidate_records"], list)
    assert isinstance(row["evidence"], list)
    assert (
        candidate.projection.capability_fact_snapshot_digest
        == get_test_snapshot().snapshot_digest
    )


def test_candidate_records_are_derived_with_ingress_and_resource_bindings() -> None:
    """The planner derives candidate-v2 details from the authoritative projection."""
    candidate, _pattern_value, _snapshot = _projection_fixture()
    row = _plan_row(_plan(_make_inputs()))
    records = row["candidate_records"]

    assert len(records) >= 1
    record = next(
        item for item in records if item["candidate_id"] == candidate.candidate_id
    )
    assert record["canonical_ingress"] == candidate.canonical_ingress.model_dump(
        mode="json"
    )
    assert record["resource_bindings"] == [
        binding.model_dump(mode="json") for binding in candidate.projection.bindings
    ]
    assert record["projection_disposition"] == "projectable"


def test_summary_is_reconciled_and_zero_candidate_records_have_zero_projection_counts() -> (
    None
):
    """Summary counts derive from rows, not obligation-level readiness."""
    plan = _plan(
        _make_inputs(
            risk_ids=("risk-governance-only",),
            include_mapping=False,
        )
    )

    assert plan.summary.total == 1
    assert plan.summary.projectable == 0
    assert plan.summary.projection_infeasible == 0
    assert plan.summary.budget_deferred == 0

    raw = plan.model_dump(mode="json")
    raw["summary"]["total"] = 999
    try:
        repaired = type(plan).model_validate(raw)
    except (ValidationError, ValueError):
        return
    assert repaired.summary.total == 1


@pytest.mark.parametrize("mutation", ["unknown", "budget", "snapshot"])
def test_typed_inputs_reject_unknown_malformed_and_contradictory_fields(
    mutation: str,
) -> None:
    """Global input errors fail before planning can return a partial ledger."""
    payload = _input_payload()
    if mutation == "unknown":
        payload["unsupported_field"] = True
    elif mutation == "budget":
        payload["projection_budget"] = {
            "max_candidates": 0,
            "max_derivation_work": 4096,
        }
    else:
        snapshot = get_test_snapshot().model_dump(mode="json")
        snapshot["snapshot_digest"] = snapshot["snapshot_digest"][::-1]
        payload["capability_snapshot"] = snapshot

    with pytest.raises((ValidationError, ValueError)):
        _input_type().model_validate(payload)


def test_qualification_fact_set_uses_framed_digest_and_rejects_mismatch() -> None:
    """Qualification facts use the shared domain digest, never a placeholder."""
    fact_set = _qualification_fact_set(get_test_snapshot())
    semantic_digest = fact_set.semantic_digest

    assert re.fullmatch(r"[0-9a-f]{64}", semantic_digest)
    assert (
        semantic_digest
        != hashlib.sha256(
            canonical_json_bytes(fact_set.model_dump(mode="json")["facts"])
        ).hexdigest()
    )

    declared = fact_set.model_dump(mode="json")
    declared["semantic_digest"] = semantic_digest[::-1]
    with pytest.raises((ValidationError, ValueError)):
        type(fact_set).model_validate(declared)


def test_qualification_facts_are_closed_typed_and_deeply_immutable() -> None:
    """Qualification facts cannot carry arbitrary values or mutable maps."""
    snapshot = get_test_snapshot()
    fact_set = QualificationFactsInput.model_validate(list(snapshot.facts))
    fact_key = next(iter(fact_set.facts))

    assert fact_set.facts[fact_key].status == "present"
    with pytest.raises((TypeError, ValueError)):
        fact_set.facts[fact_key] = "caller-authored"  # type: ignore[assignment]

    raw = fact_set.model_dump(mode="json")
    raw["facts"][fact_key] = "caller-authored"
    with pytest.raises(ValidationError):
        QualificationFactsInput.model_validate(raw)

    raw = fact_set.model_dump(mode="json")
    raw["facts"][fact_key]["value"] = {"arbitrary": "payload"}
    with pytest.raises(ValidationError):
        QualificationFactsInput.model_validate(raw)


@pytest.mark.parametrize(
    ("status", "expected_disposition"),
    [
        ("absent", "missing_evidence"),
        ("unknown", "missing_evidence"),
        ("contradictory", "contradictory_evidence"),
    ],
)
def test_unusable_qualification_fact_status_cannot_make_an_obligation_ready(
    status: str,
    expected_disposition: str,
) -> None:
    """Only an unambiguous present reading satisfies readiness coverage."""
    payload = _input_payload()
    qualification = payload["qualification_facts"]
    raw = qualification.model_dump(mode="json")
    fact_key = next(iter(raw["facts"]))
    raw["facts"][fact_key]["status"] = status
    raw["facts"][fact_key]["value"] = None
    raw["semantic_digest"] = None
    payload["qualification_facts"] = QualificationFactsInput.model_validate(raw)

    row = _plan(_input_type().model_validate(payload)).obligations[0]

    assert row.qualification_disposition == expected_disposition
    assert row.candidate_records == ()

    if status == "contradictory":
        evaluation = next(
            evaluation
            for evidence in row.evidence
            for evaluation in evidence.fact_evaluations
            if evaluation.evaluation_type == "qualification_fact"
        )
        assert evaluation.rationale == (
            "authoritative qualification fact is contradictory"
        )
        assert [fact.status for fact in evaluation.facts] == ["contradictory"]


def test_input_mapping_pin_inventory_is_exact() -> None:
    """Inputs require exactly the two documented mapping authorities."""
    payload = _input_payload()
    pins = payload["mapping_pins"]
    pins["bundle"] = pins.pop("obligation_edges")

    with pytest.raises((ValidationError, ValueError), match="mapping_pins"):
        _input_type().model_validate(payload)


def test_persisted_mapping_pin_inventory_is_exact() -> None:
    """Persisted plans reject arbitrary mapping-pin aliases even with valid digests."""
    raw = _plan(_make_inputs()).model_dump(mode="json")
    raw["mapping_pins"]["bundle"] = raw["mapping_pins"].pop("obligation_edges")

    with pytest.raises(ValidationError, match="mapping_pins"):
        type(_plan(_make_inputs())).model_validate(raw)


def test_typed_input_maps_are_copied_from_the_callers() -> None:
    """Post-validation changes to payload dictionaries cannot drift the input."""
    payload = _input_payload()
    pins = payload["mapping_pins"]
    qualification = payload["qualification_facts"]
    inputs = _input_type().model_validate(payload)

    original_pin = inputs.mapping_pins["sssom"].digest
    pins["sssom"] = {"release": "caller-mutated", "digest": "0" * 64}
    assert inputs.mapping_pins["sssom"].digest == original_pin
    with pytest.raises(TypeError, match="immutable"):
        inputs.mapping_pins["sssom"] = inputs.mapping_pins["sssom"]  # type: ignore[index]
    with pytest.raises(TypeError, match="immutable"):
        inputs.catalog_pins["new"] = inputs.catalog_pins["atlas"]  # type: ignore[index]

    original_facts = inputs.qualification_facts.facts
    if isinstance(qualification, QualificationFactsInput):
        qualification_payload = qualification.model_dump(mode="json")
        qualification_payload["facts"].clear()
    assert inputs.qualification_facts.facts == original_facts


def test_typed_inputs_copy_the_mutable_capability_snapshot() -> None:
    """A caller cannot mutate the snapshot captured by the typed input."""
    snapshot = get_test_snapshot().model_copy(deep=True)
    inputs = _input_type().model_validate(_input_payload(capability_snapshot=snapshot))
    original_zones = tuple(inputs.capability_snapshot.profile.zones_active)
    original_kc = tuple(inputs.capability_snapshot.profile.kc_subcodes)

    snapshot.profile.zones_active.append("memory")
    snapshot.profile.kc_subcodes.append("KC2.1")

    assert tuple(inputs.capability_snapshot.profile.zones_active) == original_zones
    assert tuple(inputs.capability_snapshot.profile.kc_subcodes) == original_kc
    inputs.capability_snapshot.assert_integrity()
    with pytest.raises(TypeError, match="immutable"):
        inputs.capability_snapshot.profile.zones_active.append("memory")


def _assert_identity_changes(**changed_kwargs: Any) -> None:
    """Assert a domain identity change produces a version-framed obligation ID."""
    base = _plan(_make_inputs())
    changed = _plan(_make_inputs(**changed_kwargs))

    base_id = base.obligations[0].obligation_id
    changed_id = changed.obligations[0].obligation_id
    assert base_id != changed_id
    assert re.fullmatch(r"ob:v1:[0-9a-f]{64}", base_id)
    assert re.fullmatch(r"ob:v1:[0-9a-f]{64}", changed_id)


def test_obligation_id_changes_when_risk_identity_changes() -> None:
    _assert_identity_changes(risk_ids=("risk-b",))


def test_obligation_id_changes_when_pattern_identity_changes_after_repin() -> None:
    mutated = _pattern(mutate=True)
    repinned_catalog = {"atlas": _real_catalog_pin(mutated, get_test_snapshot())}
    _assert_identity_changes(pattern=mutated, catalog_pins=repinned_catalog)


def test_obligation_id_changes_when_capability_snapshot_changes() -> None:
    snapshot = get_test_snapshot()
    fact = snapshot.facts[0].model_copy(update={"value": "inactive"})
    changed_snapshot = capture_capability_snapshot(get_test_profile(), (fact,))
    assert changed_snapshot.snapshot_digest != snapshot.snapshot_digest
    _assert_identity_changes(capability_snapshot=changed_snapshot)


def test_obligation_id_changes_when_catalog_pin_changes() -> None:
    pattern = _pattern()
    catalog_pin = _real_catalog_pin(pattern, get_test_snapshot())
    changed_pin = {**catalog_pin, "release": catalog_pin["release"] + "-repinned"}
    _assert_identity_changes(catalog_pins={"atlas": changed_pin})


def test_obligation_id_changes_when_mapping_pin_changes() -> None:
    mapping_pin = _real_mapping_pin(_pattern())
    changed_pin = {**mapping_pin, "release": mapping_pin["release"] + "-repinned"}
    mappings = _input_payload()["cross_taxonomy_mappings"]
    _assert_identity_changes(
        mapping_pins={
            "sssom": changed_pin,
            "obligation_edges": _real_mapping_bundle_pin(mappings),
        }
    )


def test_pattern_content_mutation_under_an_unchanged_pin_is_rejected() -> None:
    """Changed catalog content cannot reuse the original catalog pin."""
    mutated = _pattern(mutate=True)
    payload = _input_payload()
    payload["attack_pattern_catalog"] = [mutated]

    with pytest.raises((ValidationError, ValueError)):
        inputs = _input_type().model_validate(payload)
        _plan(inputs)


def test_mapping_edge_content_cannot_drift_under_an_unchanged_mapping_pin() -> None:
    """The declared mapping bundle pin binds reviewed edge evidence as content."""
    contracts = import_module("asago_scenario_generator.pipeline.obligation_contracts")
    payload = _input_payload()
    edge_digest = contracts.compute_mapping_bundle_digest(
        payload["cross_taxonomy_mappings"],
        payload["sssom_mappings"],
    )
    payload["mapping_pins"] = {
        "sssom": _real_mapping_pin(payload["attack_pattern_catalog"][0]),
        "obligation_edges": {
            "release": OBLIGATION_EDGES_RELEASE,
            "digest": edge_digest,
        },
    }
    _input_type().model_validate(payload)

    drifted = deepcopy(payload)
    drifted["cross_taxonomy_mappings"][0]["evidence"] = ["changed reviewed evidence"]
    with pytest.raises((ValidationError, ValueError), match="mapping bundle"):
        _input_type().model_validate(drifted)


def test_sssom_edge_content_cannot_drift_under_an_unchanged_mapping_pin() -> None:
    """SSSOM provenance is part of the separately declared edge-bundle pin."""
    payload = _input_payload()
    pattern = payload["attack_pattern_catalog"][0]
    payload["cross_taxonomy_mappings"] = [
        {
            "source_id": "risk-a",
            "target_id": "taxonomy-intermediate",
            "relation": "risk_to_taxonomy",
        }
    ]
    payload["sssom_mappings"] = [
        {
            "subject_id": "taxonomy-intermediate",
            "object_id": pattern.id,
            "predicate_id": "exact_match",
            "subject_source": "risk-taxonomy-v1",
            "object_source": "atlas-v1",
            "mapping_justification": "reviewed SSSOM edge",
        }
    ]
    payload["mapping_pins"] = {
        "sssom": _real_mapping_pin(pattern),
        "obligation_edges": {
            "release": OBLIGATION_EDGES_RELEASE,
            "digest": compute_mapping_bundle_digest(
                payload["cross_taxonomy_mappings"], payload["sssom_mappings"]
            ),
        },
    }
    _input_type().model_validate(payload)

    drifted = deepcopy(payload)
    drifted["sssom_mappings"][0]["mapping_justification"] = "unreviewed replacement"
    with pytest.raises((ValidationError, ValueError), match="mapping bundle"):
        _input_type().model_validate(drifted)


@pytest.mark.parametrize(
    ("missing_pin", "message"),
    [
        ("sssom", "taxonomy-context mapping set"),
        ("obligation_edges", "mapping bundle"),
    ],
)
def test_context_and_supplied_edge_pins_are_distinct_required_authorities(
    missing_pin: str,
    message: str,
) -> None:
    """Neither the catalog context pin nor supplied-edge pin substitutes for the other."""
    payload = _input_payload()
    pins = payload["mapping_pins"]
    del pins[missing_pin]

    with pytest.raises((ValidationError, ValueError), match=message):
        _input_type().model_validate(payload)


def test_mapping_bundle_digest_is_invariant_to_edge_presentation_order() -> None:
    """Canonical edge ordering and evidence ordering do not repin the bundle."""
    forward = [
        {
            "source_id": "risk-a",
            "target_id": "taxonomy-intermediate",
            "relation": "risk_to_taxonomy",
            "evidence": ["second", "first"],
        },
        {
            "source_id": "taxonomy-intermediate",
            "target_id": "AP-T1-01",
            "relation": "taxonomy_to_pattern",
        },
    ]
    reverse = deepcopy(list(reversed(forward)))
    reverse[-1]["evidence"] = list(reversed(reverse[-1]["evidence"]))

    assert compute_mapping_bundle_digest(forward, []) == (
        compute_mapping_bundle_digest(reverse, [])
    )


def test_repinned_pattern_content_is_accepted_with_a_new_identity() -> None:
    """Re-signing changed content and capturing its new catalog pin changes identity."""
    original = _pattern()
    mutated = _pattern(mutate=True)
    original_pin = _real_catalog_pin(original, get_test_snapshot())
    mutated_pin = _real_catalog_pin(mutated, get_test_snapshot())
    assert (
        mutated.canonical_chain.semantic_digest
        != original.canonical_chain.semantic_digest
    )
    assert mutated_pin["digest"] != original_pin["digest"]

    original_plan = _plan(_make_inputs(catalog_pins={"atlas": original_pin}))
    mutated_plan = _plan(
        _make_inputs(pattern=mutated, catalog_pins={"atlas": mutated_pin})
    )
    assert (
        original_plan.obligations[0].obligation_id
        != mutated_plan.obligations[0].obligation_id
    )


def test_run_plan_obligations_publishes_a_round_trip_validated_artifact(
    tmp_path: Path,
) -> None:
    """The persistence adapter returns exactly what its written artifact reloads."""

    inputs = _input_type().model_validate(
        json.loads(json.dumps(_jsonable(_input_payload())))
    )
    output_dir = tmp_path / "published"

    plan = _plan(inputs)
    written = [write_taxonomy_obligation_plan(output_dir, plan)]

    assert written == [output_dir / "taxonomy-obligation-plan.yaml"]
    assert len(plan.obligations) == 1
    published = TaxonomyObligationPlan.from_yaml(written[0].read_text(encoding="utf-8"))
    assert published == plan
    assert not list(output_dir.glob("*.tmp"))


def test_missing_qualification_facts_preserve_an_unready_obligation() -> None:
    """The planner consumes qualification facts instead of digesting them only."""
    payload = _input_payload()
    payload["qualification_facts"] = {"facts": {}}

    plan = _plan(_input_type().model_validate(payload))
    row = _plan_row(plan)

    assert row["scope_disposition"] == "applicable"
    assert row["qualification_disposition"] == "missing_evidence"
    assert row["candidate_records"] == []
    missing = next(
        evaluation
        for evidence in row["evidence"]
        for evaluation in evidence["fact_evaluations"]
        if evaluation["evaluation_type"] == "qualification_fact"
    )
    assert missing["step_id"] == "AP-T1-01"
    assert missing["result"] == "unknown"
    assert missing["rationale"] == "authoritative qualification fact is absent"
    assert [fact["status"] for fact in missing["facts"]] == ["absent"]


def test_unknown_mapping_source_is_rejected_before_planning() -> None:
    """A mapping component cannot introduce an unrooted source node."""
    payload = _input_payload()
    pattern = _projection_fixture()[1]
    payload["cross_taxonomy_mappings"] = [
        {
            "source_id": "unrooted-source",
            "target_id": pattern.id,
            "relation": "exact_match",
        }
    ]

    with pytest.raises((ValidationError, ValueError), match="sources"):
        _input_type().model_validate(payload)


def test_mapping_graph_rejects_cycles_before_planning() -> None:
    """The combined reviewed mapping graph must remain acyclic."""
    payload = _input_payload()
    payload["cross_taxonomy_mappings"] = [
        {"source_id": "risk-a", "target_id": "mapping-cycle"},
        {"source_id": "mapping-cycle", "target_id": "risk-a"},
    ]

    with pytest.raises((ValidationError, ValueError), match="acyclic"):
        _input_type().model_validate(payload)


def test_validate_obligation_plan_is_not_a_public_cli_command() -> None:
    """Phase 1 exposes planning/persistence, not a second validation command."""
    result = PlainCliRunner().invoke(app, ["--help"])

    assert result.exit_code == 0, result.stderr
    assert "validate-obligation-plan" not in result.stdout


def test_input_risk_identity_is_nonempty() -> None:
    """A typed reviewed risk cannot enter the graph without an identity."""
    with pytest.raises(ValidationError):
        RiskCardInput(risk_id="")


@pytest.mark.parametrize("field", ["source_id", "target_id", "relation"])
def test_cross_taxonomy_mapping_fields_are_nonempty(field: str) -> None:
    """Every cross-taxonomy edge component has a meaningful value."""
    values: dict[str, Any] = {
        "source_id": "risk-a",
        "target_id": "AP-T1-01",
        "relation": "exact_match",
    }
    values[field] = ""

    with pytest.raises(ValidationError):
        CrossTaxonomyMappingInput.model_validate(values)


@pytest.mark.parametrize(
    ("field", "other_name"),
    [
        ("source_id", "risk_id"),
        ("source_id", "subject_id"),
        ("target_id", "pattern_id"),
        ("target_id", "attack_pattern_id"),
        ("target_id", "object_id"),
        ("relation", "predicate"),
        ("relation", "predicate_id"),
    ],
)
def test_cross_taxonomy_mapping_accepts_only_field_names(
    field: str, other_name: str
) -> None:
    values: dict[str, Any] = {
        "source_id": "risk-a",
        "target_id": "AP-T1-01",
        "relation": "exact_match",
    }
    values[other_name] = values.pop(field)

    with pytest.raises(ValidationError):
        CrossTaxonomyMappingInput.model_validate(values)


@pytest.mark.parametrize(
    "field",
    [
        "subject_id",
        "object_id",
        "predicate_id",
        "subject_source",
        "object_source",
        "mapping_justification",
    ],
)
def test_sssom_mapping_fields_are_nonempty(field: str) -> None:
    """SSSOM rows reject empty identity, vocabulary, and provenance fields."""
    values: dict[str, Any] = {
        "subject_id": "risk-a",
        "object_id": "AP-T1-01",
        "predicate_id": "exact_match",
        "subject_source": "risk-source",
        "object_source": "atlas-source",
        "mapping_justification": "reviewed mapping",
    }
    values[field] = ""

    with pytest.raises(ValidationError):
        SSSOMMappingInput.model_validate(values)


def test_compatibility_policy_defaults_to_closed_legacy_behavior() -> None:
    """Legacy keyword matching stays opt-in at the typed input boundary."""
    assert CompatibilityPolicyInput().allow_legacy_keyword_matches is False


def _contradictory_fact_raw() -> dict[str, Any]:
    """Return one contradictory fact carrying two conflicting readings."""
    reading = get_test_snapshot().facts[0]
    payload = reading.model_dump(mode="json")
    payload["status"] = "contradictory"
    payload["value"] = None
    payload["readings"] = [
        {"value": True, "source": "narrative use-case statement"},
        {"value": False, "source": "reviewed policy document"},
    ]
    return payload


def test_contradictory_fact_retains_both_conflicting_readings() -> None:
    """A contradictory fact keeps every supplied reading with its source."""
    fact_set = QualificationFactsInput.model_validate(
        {"facts": [_contradictory_fact_raw()]}
    )

    (fact,) = fact_set.facts.values()
    assert fact.status == "contradictory"
    assert [(reading.value, reading.source) for reading in fact.readings] == [
        (True, "narrative use-case statement"),
        (False, "reviewed policy document"),
    ]


def test_conflicting_readings_change_the_framed_digest() -> None:
    """The digest covers the retained readings, so edits cannot hide a conflict."""
    raw = _contradictory_fact_raw()
    first = QualificationFactsInput.model_validate({"facts": [raw]})
    raw["readings"][1]["value"] = True
    second = QualificationFactsInput.model_validate({"facts": [raw]})

    assert first.semantic_digest != second.semantic_digest


def test_conflicting_readings_require_the_contradictory_status() -> None:
    """An unambiguous reading cannot carry conflicting readings."""
    raw = _contradictory_fact_raw()
    raw["status"] = "present"
    raw["value"] = True

    with pytest.raises((ValidationError, ValueError)):
        QualificationFactsInput.model_validate({"facts": [raw]})


def test_a_conflict_requires_two_or_more_readings() -> None:
    """One reading alone is not a conflict."""
    raw = _contradictory_fact_raw()
    raw["readings"] = raw["readings"][:1]

    with pytest.raises((ValidationError, ValueError)):
        QualificationFactsInput.model_validate({"facts": [raw]})


def test_contradictory_readings_reach_the_published_evidence() -> None:
    """Published qualification evidence shows both values and their sources."""
    payload = _input_payload()
    qualification = payload["qualification_facts"]
    raw = qualification.model_dump(mode="json")
    fact_key = next(iter(raw["facts"]))
    raw["facts"][fact_key]["status"] = "contradictory"
    raw["facts"][fact_key]["value"] = None
    raw["facts"][fact_key]["readings"] = [
        {"value": True, "source": "narrative use-case statement"},
        {"value": False, "source": "reviewed policy document"},
    ]
    raw["semantic_digest"] = None
    payload["qualification_facts"] = QualificationFactsInput.model_validate(raw)

    row = _plan(_input_type().model_validate(payload)).obligations[0]

    assert row.qualification_disposition == "contradictory_evidence"
    evaluation = next(
        evaluation
        for evidence in row.evidence
        for evaluation in evidence.fact_evaluations
        if evaluation.evaluation_type == "qualification_fact"
    )
    (fact,) = evaluation.facts
    assert fact.status == "contradictory"
    assert fact.value is None
    assert [(reading.value, reading.source) for reading in fact.readings] == [
        (True, "narrative use-case statement"),
        (False, "reviewed policy document"),
    ]
