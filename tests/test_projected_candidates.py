"""Focused tests for deterministic authoritative candidate projection (422o.3)."""

from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import ValidationError

from asago_scenario_generator.models.attack_pattern import (
    AttackPattern,
    AuthoritativeFactReference,
    EvaluatedFactEvidence,
    compute_chain_semantic_digest,
    IntegrationResourceReference,
    ResourceSlot,
    ProjectionSnapshot,
    compute_projection_digest,
    validate_projection_snapshot,
    OutputSurfaceResourceReference,
    AgentInternalResourceReference,
    ToolResourceReference,
    TrustBoundaryResourceReference,
    AllCondition,
    AnyCondition,
    EqualityCondition,
    NotCondition,
)
from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    ConfidenceLevel,
)
from asago_scenario_generator.pipeline.projection_contracts import (
    ProjectionBudget,
    capture_capability_snapshot,
    CandidateComplexityInputs,
    PreconditionEvaluationResult,
    ProjectionLimitation,
    ProjectedCandidate,
    _candidate_v2_id,
    _require_unique_requirement_ids,
    _verify_chain_identity,
    _verify_canonical_ingress,
    _verify_execution_requirements_digest,
    _verify_candidate_identity,
    _expected_precondition_key_map,
    _verify_precondition_results,
    _verify_precondition_true,
    _verify_projected_mappings,
    _expected_complexity_inputs,
    _selected_steps_for_projection,
    _verify_complexity_inputs,
    _entry_point_eligible_for_slot,
    CapabilityFactSnapshot,
    _restriction_blocks,
    _resource_id_allowed,
    _slot_reference_compatible,
    _normalize_unicode,
    _normalized_mapping,
    _resource_id,
    _resource_contained,
    _assert_snapshot_facts_uniquely_sorted,
    _canonical_json,
    _snapshot_resource_payload,
    _sorted_by,
    _sorted_canonical,
    _condition_fact_items,
    _condition_facts,
    _resource_key,
    ProjectedMapping,
    _chain_atlas_mappings,
    _projected_mappings,
    _step_atlas_mappings,
)
from asago_scenario_generator.models.attack_pattern_projection import (
    EntryPointResourceReference,
)
from asago_scenario_generator.pipeline.projection_allocation import (
    _source_influence_target_id,
)
from asago_scenario_generator.pipeline.projection_authoritative import (
    project_authoritative_candidate_observations,
)
from asago_scenario_generator.pipeline.projection_relations import (
    _source_entry_point_detail,
)
import re
import asago_scenario_generator.pipeline.projection_requirements as req_mod
from asago_scenario_generator.pipeline.projection_requirements import (
    _requirement_id,
    _link_role_requirement,
    _source_identity_kind_for_link,
    _linked_postcondition_ids,
    _observation_requirements,
    _security_outcome_requirements,
    _require_unique_requirement_ids_or_issue,
    _derive_execution_requirements_core,
    _selected_ingress_links,
    _ingress_controllability_for_link,
    _derive_execution_requirements,
    _resolve_ingress_controllability,
)
from asago_scenario_generator.data.loaders import load_attack_patterns
from asago_scenario_generator.data.taxonomy_pins import load_taxonomy_resolver
from asago_scenario_generator.pipeline.projection_resources import (
    _combination_satisfies_distinctness,
    _count_compatible_combinations,
    _references_for_kind,
    _entry_point_reference_allowed,
    _references_for_slot,
    _assignment_conflicts,
    _constrained_components,
    _constrained_indexes,
    _count_component_assignments,
    _distinctness_edges,
    _unconstrained_product,
    _cartesian_fill,
    _combination_baseline,
    _combination_key,
    _iter_coverage_first_combinations,
    _max_option_length,
    _offset_variants,
    _variant_combinations,
)
from tests.helpers.projection_factory import _fact, _evidence

ZERO = "0" * 64


def _project_batch(
    records: list[dict[str, Any]],
    resolver: Any,
    snapshot: Any,
    *,
    budget: ProjectionBudget | None = None,
) -> Any:
    """Project through the live planner seam and return its capped batch."""
    return project_authoritative_candidate_observations(
        records, resolver, snapshot, budget=budget
    ).batch


class TaxonomyResolver:
    def __init__(self, context: Any) -> None:
        self.taxonomy_context = context

    def contains(self, taxonomy: str, identifier: str) -> bool:
        return (taxonomy, identifier) in {
            ("ATLAS", "AML.T0001"),
            ("LAAF", "LAAF.1"),
        }


def _step(step_id: str, order: int, *, conditional: bool = False) -> dict[str, Any]:
    final = order == 3
    attacker = order == 1
    return {
        "step_id": step_id,
        "requirement": "conditional" if conditional else "required",
        "condition": {
            "op": "equality",
            "schema_version": "1",
            "fact": _fact(),
            "value": "active",
        }
        if conditional
        else None,
        "executor_role": "attacker" if attacker else "system",
        "boundary_position": "crossing" if attacker else "inside",
        "action_kind": "prepare" if attacker else "impact" if final else "observe",
        "consumed": [],
        "produced": [
            {"kind": "effect", "ref_id": f"effect.{order}", "value_type": "boolean"}
        ],
        "preconditions": [],
        "observable_postconditions": [
            {
                "postcondition_id": f"post.{order}",
                "description": "observable",
                "security_relevant": final,
                "terminal": final,
            }
        ],
        "resource_links": (
            [
                {
                    "slot_id": "ingress",
                    "role": "ingress",
                    "trust_boundary_slot_id": None,
                }
            ]
            if attacker
            else []
        ),
        "observable_outcome_links": (
            # The terminal step is security-relevant; it must carry an
            # explicit outcome link so the security assertion is derived
            # from the link, not from the security_relevant flag alone.
            [
                {
                    "postcondition_id": f"post.{order}",
                    "observation": "model_context",
                    "binding_slot_id": "ingress",
                }
            ]
            if final
            else []
        ),
        "order": order,
        "attacker_controlled": attacker,
        "provenance": {
            "tier": "observed",
            "references": [
                {"reference_type": "catalog", "reference_id": f"case-{order}"}
            ],
            "confidence": 90,
            "adaptation_rationale": "represented",
        },
        "mappings": (
            [{"decision": "exact", "taxonomy": "ATLAS", "ids": ["AML.T0001"]}]
            if attacker
            else [{"decision": "not_applicable", "taxonomy": "ATLAS"}]
        ),
    }


def _pattern(*, conditional: bool = True) -> dict[str, Any]:
    chain = {
        "schema_version": "v1",
        "pattern_id": "AP-T1-01",
        "chain_id": "chain.1",
        "semantic_revision": 1,
        "semantic_digest": ZERO,
        "taxonomy_context": {
            "atlas": {"release": "v1", "digest": ZERO},
            # ATLAS-only: no LAAF pin exists; the canonical framing of an
            # absent pin is JSON null, so digests cover ``"laaf": None``.
            "laaf": None,
            "mapping_set_digest": ZERO,
        },
        "mappings": [{"decision": "exact", "taxonomy": "ATLAS", "ids": ["AML.T0001"]}],
        "steps": [
            _step("step.1", 1),
            _step("step.2", 2, conditional=conditional),
            _step("step.3", 3),
        ],
        "earliest_attacker_controlled_step_id": "step.1",
        "resource_slots": [
            {"slot_id": "ingress", "kind": "entry_point", "purpose": "initial_ingress"},
            {"slot_id": "tool", "kind": "tool", "purpose": "supporting"},
            {"slot_id": "source", "kind": "integration", "purpose": "supporting"},
            {
                "slot_id": "boundary",
                "kind": "trust_boundary",
                "purpose": "intermediate",
            },
        ],
        "initial_ingress_slot_id": "ingress",
    }
    chain["semantic_digest"] = compute_chain_semantic_digest(chain)
    return {
        "id": "AP-T1-01",
        "threat_id": "T1",
        "name": "Pattern",
        "description": "Canonical",
        "prerequisite_capabilities": {"min_zones": ["input"]},
        "canonical_chain": chain,
    }


def _profile(*, duplicate_resources: bool = False) -> CapabilityProfile:
    tools = [{"name": "writer", "description": "changes state"}]
    integrations = [
        {
            "name": "CRM",
            "integration_type": "api",
            "auth_method": "oauth",
            "data_sensitivity": "high",
        }
    ]
    boundaries = [
        {
            "name": "user-to-agent",
            "from_zone": "input",
            "to_zone": "reasoning",
            "confidence": "explicit",
        }
    ]
    if duplicate_resources:
        tools.append({"name": "sender", "description": "changes state"})
        integrations.append(
            {
                "name": "Queue",
                "integration_type": "message_queue",
                "auth_method": "service_account",
                "data_sensitivity": "medium",
            }
        )
    return CapabilityProfile(
        zones_active=["input", "reasoning", "tool_execution"],
        entry_points=[
            {"name": "chat", "direction": "input", "controllability": "direct"},
            {
                "name": "RAG documents",
                "direction": "input",
                "controllability": "indirect",
            },
        ],
        confidence=ConfidenceLevel.high,
        kc_subcodes=["KC1.1", "KC5.1"],
        tool_inventory=tools,
        tool_types=[
            {
                "name": item["name"],
                "zone": "tool_execution",
                "can_modify_state": True,
                "data_sensitivity": "medium",
                "code_execution": False,
            }
            for item in tools
        ],
        external_integrations=integrations,
        trust_boundaries=boundaries,
    )


def _project(
    *,
    profile: CapabilityProfile | None = None,
    evidence: tuple[EvaluatedFactEvidence, ...] = (_evidence(),),
    budget: int = 100,
    pattern: dict[str, Any] | None = None,
):
    raw = pattern or _pattern()
    resolver_pattern = raw if "canonical_chain" in raw else _pattern()
    resolver = TaxonomyResolver(
        __import__(
            "asago_scenario_generator.models.attack_pattern", fromlist=["AttackPattern"]
        )
        .AttackPattern.model_validate(resolver_pattern)
        .canonical_chain.taxonomy_context
    )
    snapshot = capture_capability_snapshot(profile or _profile(), evidence)
    return _project_batch(
        [raw],
        resolver,
        snapshot,
        budget=ProjectionBudget(max_candidates=budget),
    )


def test_snapshot_is_content_addressed_order_independent_and_qualifies_resources() -> (
    None
):
    profile = _profile()
    first = capture_capability_snapshot(profile, (_evidence(),))
    second = capture_capability_snapshot(
        profile.model_copy(deep=True), tuple(reversed((_evidence(),)))
    )
    assert first.snapshot_digest == second.snapshot_digest
    assert first.capability_fact_snapshot_digest == first.snapshot_digest
    assert first.fact(_evidence().fact) == _evidence()
    for candidate in _project().candidates:
        for binding in candidate.projection.bindings:
            assert first.contains_resource(binding.resource_ref)

    first.profile.kc_subcodes.append("KC2.1")
    with pytest.raises(ValueError, match="changed after capture"):
        first.fact(_evidence().fact)


def test_snapshot_capture_rejects_conflicts_and_copies_profile() -> None:
    profile = _profile()
    snapshot = capture_capability_snapshot(profile, (_evidence(),))

    snapshot.profile.kc_subcodes.append("KC2.1")
    assert "KC2.1" not in profile.kc_subcodes

    with pytest.raises(
        ValueError, match="conflicting authoritative readings for one fact"
    ):
        capture_capability_snapshot(
            profile, (_evidence("active"), _evidence("inactive"))
        )


def test_projection_contract_boundary_values_are_explicit() -> None:
    assert ProjectionBudget(max_candidates=1, max_derivation_work=1)
    with pytest.raises(ValidationError):
        ProjectionBudget(max_candidates=0)
    with pytest.raises(ValidationError):
        ProjectionBudget(max_derivation_work=0)
    with pytest.raises(ValidationError):
        PreconditionEvaluationResult(
            step_id="step",
            condition_id="condition",
            result="true",
            evidence=(),
        )
    assert PreconditionEvaluationResult(
        step_id="step",
        condition_id="condition",
        result="true",
        evidence=(_evidence(),),
    )

    assert ProjectionLimitation(
        code="candidate_budget_exhausted",
        pattern_id="pattern",
        total_compatible_bindings=0,
        emitted_bindings=0,
    )
    with pytest.raises(ValidationError):
        ProjectionLimitation(
            code="candidate_budget_exhausted",
            pattern_id="pattern",
            total_compatible_bindings=-1,
        )
    with pytest.raises(ValidationError):
        ProjectionLimitation(
            code="candidate_budget_exhausted",
            pattern_id="pattern",
            emitted_bindings=-1,
        )

    base = {
        "selected_step_count": 1,
        "attacker_controlled_step_count": 1,
        "boundary_crossing_step_count": 0,
        "selected_conditional_step_count": 0,
        "concrete_binding_count": 1,
        "execution_requirement_count": 1,
    }
    assert CandidateComplexityInputs(**base)
    for field in (
        "selected_step_count",
        "attacker_controlled_step_count",
        "concrete_binding_count",
        "execution_requirement_count",
    ):
        with pytest.raises(ValidationError):
            CandidateComplexityInputs(**{**base, field: 0})


def test_content_identity_normalizes_canonically_equivalent_unicode() -> None:
    composed = _pattern()
    decomposed = _pattern()
    composed["name"] = "Caf\N{LATIN SMALL LETTER E WITH ACUTE}"
    decomposed["name"] = "Cafe\N{COMBINING ACUTE ACCENT}"
    assert _project(pattern=composed) == _project(pattern=decomposed)


def test_true_and_false_conditions_persist_complete_evidence_and_projection() -> None:
    selected = _project(evidence=(_evidence("active"),)).candidates
    omitted = _project(evidence=(_evidence("inactive"),)).candidates
    assert {r.result for r in selected[0].projection.condition_results} == {"true"}
    assert selected[0].projection.selected_step_ids == ("step.1", "step.2", "step.3")
    assert {r.result for r in omitted[0].projection.condition_results} == {"false"}
    assert omitted[0].projection.selected_step_ids == ("step.1", "step.3")
    assert omitted[0].projection.omissions[0].step_id == "step.2"


def test_unknown_is_typed_unresolved_and_never_becomes_a_candidate() -> None:
    result = _project(evidence=())
    assert result.candidates == ()
    assert result.infeasibilities[0].code == "unresolved_condition"
    assert result.infeasibilities[0].condition_results[0].result == "unknown"


def test_selected_step_preconditions_persist_true_false_and_unknown_evidence() -> None:
    raw = _pattern(conditional=False)
    raw["canonical_chain"]["steps"][0]["preconditions"] = [
        {
            "condition_id": "pre.mode",
            "condition": {
                "op": "equality",
                "schema_version": "1",
                "fact": _fact(),
                "value": "active",
            },
        }
    ]
    raw["canonical_chain"]["semantic_digest"] = compute_chain_semantic_digest(
        raw["canonical_chain"]
    )

    satisfied = _project(pattern=raw, evidence=(_evidence("active"),))
    assert satisfied.candidates[0].precondition_results[0].result == "true"
    duplicate = satisfied.candidates[0].model_dump(mode="json")
    duplicate["precondition_results"].append(
        deepcopy(duplicate["precondition_results"][0])
    )
    with pytest.raises(ValidationError, match="keys must be unique"):
        type(satisfied.candidates[0]).model_validate(duplicate)

    false = _project(pattern=raw, evidence=(_evidence("inactive"),))
    assert false.candidates == ()
    assert false.infeasibilities[0].code == "precondition_not_satisfied"
    assert false.infeasibilities[0].precondition_results[0].result == "false"

    unknown = _project(pattern=raw, evidence=())
    assert unknown.candidates == ()
    assert unknown.infeasibilities[0].code == "unresolved_condition"
    assert unknown.infeasibilities[0].precondition_results[0].result == "unknown"


def test_bindings_exactly_cover_slots_and_indirect_ingress_fails_closed() -> None:
    result = _project()
    assert {c.ingress_controllability for c in result.candidates} == {"direct"}
    assert {issue.code for issue in result.infeasibilities} == {
        "unsupported_requirement_derivation"
    }
    for candidate in result.candidates:
        assert {b.slot_id for b in candidate.projection.bindings} == {
            "ingress",
            "tool",
            "source",
            "boundary",
        }
        assert {
            requirement.kind for requirement in candidate.execution_requirements
        } == {
            "direct_input_control",
            "observation",
            "security_outcome_assertion",
        }


def test_unsupported_binding_is_typed_infeasibility() -> None:
    raw = _pattern()
    raw["canonical_chain"]["resource_slots"].append(
        {"slot_id": "missing", "kind": "entry_point", "purpose": "target"}
    )
    raw["canonical_chain"]["semantic_digest"] = compute_chain_semantic_digest(
        raw["canonical_chain"]
    )
    profile = _profile().model_copy(update={"entry_points": []})
    result = _project(profile=profile, pattern=raw)
    assert result.candidates == ()
    assert {issue.code for issue in result.infeasibilities} == {
        "missing_compatible_resource"
    }


def test_expansion_is_bounded_coverage_aware_stable_and_deduplicated() -> None:
    first = _project(profile=_profile(duplicate_resources=True), budget=3)
    second = _project(profile=_profile(duplicate_resources=True), budget=3)
    assert first.candidates == second.candidates
    assert len(first.candidates) == len({c.candidate_id for c in first.candidates}) == 3
    assert any(
        limitation.code == "candidate_budget_exhausted"
        for limitation in first.limitations
    )
    assert {c.ingress_controllability for c in first.candidates} == {"direct"}
    assert (
        len(
            {
                binding.resource_ref.tool_id
                for candidate in first.candidates
                for binding in candidate.projection.bindings
                if binding.resource_ref.kind == "tool"
            }
        )
        == 2
    )


def test_observation_keeps_batch_truncation_and_defers_the_tail() -> None:
    """Planning observation reports deferred candidates outside the capped batch."""
    raw = _pattern()
    resolver = TaxonomyResolver(
        AttackPattern.model_validate(raw).canonical_chain.taxonomy_context
    )
    snapshot = capture_capability_snapshot(
        _profile(duplicate_resources=True), (_evidence(),)
    )
    budget = ProjectionBudget(max_candidates=3, max_derivation_work=4096)

    observed = project_authoritative_candidate_observations(
        [raw], resolver, snapshot, budget=budget
    )
    established = observed.batch

    assert len(established.candidates) == 3
    assert {item.code for item in established.limitations} == {
        "candidate_budget_exhausted"
    }
    assert observed.deferred_candidates
    assert not (
        {item.candidate_id for item in observed.deferred_candidates}
        & {item.candidate_id for item in established.candidates}
    )


def test_observation_keeps_batch_limitations_before_tail_collection() -> None:
    """Observing deferred candidates does not add work-exhaustion limits."""
    raw = _pattern()
    resolver = TaxonomyResolver(
        AttackPattern.model_validate(raw).canonical_chain.taxonomy_context
    )
    snapshot = capture_capability_snapshot(
        _profile(duplicate_resources=True), (_evidence(),)
    )
    budget = ProjectionBudget(max_candidates=1, max_derivation_work=2)

    observed = project_authoritative_candidate_observations(
        [raw], resolver, snapshot, budget=budget
    )

    assert {item.code for item in observed.batch.limitations} == {
        "candidate_budget_exhausted"
    }
    assert observed.deferred_candidates


def test_explicit_execution_requirements_are_versioned_and_digest_verified() -> None:
    direct = _project().candidates[0]
    assert {r.kind for r in direct.execution_requirements} == {
        "direct_input_control",
        "observation",
        "security_outcome_assertion",
    }
    assert direct.requirement_derivation_version == "1"
    assert len(direct.execution_requirements_digest) == 64
    forged = direct.model_dump(mode="json")
    forged["execution_requirements_digest"] = ZERO
    with pytest.raises(ValidationError, match="requirements_digest"):
        type(direct).model_validate(forged)


@pytest.mark.parametrize("action_kind", ["deliver", "transform", "invoke", "persist"])
def test_unlinked_action_resources_and_observations_are_never_inferred(
    action_kind: str,
) -> None:
    """Action kind alone never produces requirements; only explicit links do."""
    raw = _pattern(conditional=False)
    raw["canonical_chain"]["steps"][1]["action_kind"] = action_kind
    raw["canonical_chain"]["semantic_digest"] = compute_chain_semantic_digest(
        raw["canonical_chain"]
    )
    result = _project(pattern=raw)
    # The candidate succeeds because the first step has an explicit ingress
    # link and the terminal step has an explicit outcome link on its
    # security-relevant postcondition.  Action kind is irrelevant to
    # requirement derivation.
    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    assert {requirement.kind for requirement in candidate.execution_requirements} == {
        "direct_input_control",
        "observation",
        "security_outcome_assertion",
    }
    # No tool-fixture requirements are inferred from action kind.
    assert not any(
        requirement.kind == "state_changing_tool_fixture"
        for requirement in candidate.execution_requirements
    )


def test_candidate_v2_identity_is_stable_and_sensitive_to_every_identity_axis() -> None:
    baseline = _project().candidates
    repeated = _project().candidates
    assert [c.candidate_id for c in baseline] == [c.candidate_id for c in repeated]
    assert all(c.candidate_id.startswith("cand:v2:") for c in baseline)

    changed = _pattern()
    changed["canonical_chain"]["semantic_revision"] = 2
    changed["canonical_chain"]["semantic_digest"] = compute_chain_semantic_digest(
        changed["canonical_chain"]
    )
    assert {c.candidate_id for c in _project(pattern=changed).candidates}.isdisjoint(
        {c.candidate_id for c in baseline}
    )

    changed_projection = _project(evidence=(_evidence("inactive"),)).candidates
    assert {c.candidate_id for c in changed_projection}.isdisjoint(
        {c.candidate_id for c in baseline}
    )
    assert len({c.candidate_id for c in baseline}) == 1

    forged = baseline[0].model_dump(mode="json")
    forged["candidate_id"] = "cand:v2:" + "0" * 32
    with pytest.raises(ValidationError, match="candidate_id"):
        type(baseline[0]).model_validate(forged)


def test_projected_mappings_are_cumulative_not_a_technique_subset_axis() -> None:
    candidates = _project().candidates
    assert all(candidate.projected_mappings for candidate in candidates)
    assert all(
        mapping.mapping.taxonomy == "ATLAS"
        for candidate in candidates
        for mapping in candidate.projected_mappings
    )
    assert all(not hasattr(candidate, "technique_ids") for candidate in candidates)
    assert all(not hasattr(candidate, "prompt_emphasis") for candidate in candidates)


def test_legacy_catalog_record_cannot_masquerade_as_projected_candidate() -> None:
    legacy = {
        "id": "AP-T1-01",
        "threat_id": "T1",
        "name": "Legacy",
        "description": "No authoritative chain",
        "prerequisite_capabilities": {"min_zones": ["input"]},
        "kill_chain": [],
    }
    with pytest.raises(ValueError, match="authoritative"):
        _project(pattern=deepcopy(legacy))


def test_kc_all_and_any_prerequisites_are_authoritative_profile_gates() -> None:
    raw = _pattern()
    raw["prerequisite_capabilities"]["kc_requires"] = {
        "all": ["KC5.1"],
        "any": ["KC1.1", "KC2.1"],
    }
    assert _project(pattern=raw).candidates

    raw["prerequisite_capabilities"]["kc_requires"]["all"] = ["KC2.1"]
    result = _project(pattern=raw)
    assert result.candidates == ()
    assert result.infeasibilities[0].code == "incompatible_profile"
    assert "KC2.1" in result.infeasibilities[0].detail

    raw["prerequisite_capabilities"]["kc_requires"] = {
        "all": [],
        "any": ["KC2.1", "KC3.1"],
    }
    result = _project(pattern=raw)
    assert result.candidates == ()
    assert "requires any KC code" in result.infeasibilities[0].detail


@pytest.mark.parametrize("decision", ["exact", "unmapped", "not_applicable"])
def test_laaf_decisions_fail_closed_without_an_explicit_laaf_pin(
    decision: str,
) -> None:
    raw = _pattern()
    mapping = {"decision": decision, "taxonomy": "LAAF"}
    if decision == "exact":
        mapping["ids"] = ["LAAF.1"]
    elif decision == "unmapped":
        mapping["rationale"] = "No authoritative taxonomy is available."
    if decision == "not_applicable":
        raw["canonical_chain"]["steps"][-1]["mappings"] = [mapping]
    else:
        raw["canonical_chain"]["mappings"].append(mapping)
    raw["canonical_chain"]["semantic_digest"] = compute_chain_semantic_digest(
        raw["canonical_chain"]
    )
    with pytest.raises(ValueError, match="LAAF taxonomy pin"):
        _project(pattern=raw)

    # Normal qualification rejects the same record through the projection
    # boundary even when the resolver itself is valid and ATLAS-only.
    snapshot = capture_capability_snapshot(_profile(), (_evidence(),))
    with pytest.raises(ValueError, match="qualification failed"):
        _project_batch([raw], _atlas_only_resolver(), snapshot)


def _atlas_only_resolver() -> TaxonomyResolver:
    """Resolver pinned to the default fixture's ATLAS-only taxonomy context."""
    context = AttackPattern.model_validate(_pattern()).canonical_chain.taxonomy_context
    assert context.laaf is None
    return TaxonomyResolver(context)


def test_catalog_pin_and_candidate_identity_ignore_record_order_and_duplicates() -> (
    None
):
    first = _pattern()
    second = deepcopy(first)
    second["id"] = "AP-T1-02"
    second["canonical_chain"]["pattern_id"] = "AP-T1-02"
    second["canonical_chain"]["chain_id"] = "chain.2"
    second["canonical_chain"]["semantic_digest"] = compute_chain_semantic_digest(
        second["canonical_chain"]
    )
    resolver = TaxonomyResolver(
        __import__(
            "asago_scenario_generator.models.attack_pattern", fromlist=["AttackPattern"]
        )
        .AttackPattern.model_validate(first)
        .canonical_chain.taxonomy_context
    )
    snapshot = capture_capability_snapshot(_profile(), (_evidence(),))
    forward = _project_batch([first, second], resolver, snapshot)
    reverse = _project_batch([second, first, deepcopy(first)], resolver, snapshot)
    assert [candidate.candidate_id for candidate in forward.candidates] == [
        candidate.candidate_id for candidate in reverse.candidates
    ]
    bounded = _project_batch(
        [second, first], resolver, snapshot, budget=ProjectionBudget(max_candidates=2)
    )
    assert {candidate.pattern_id for candidate in bounded.candidates} == {
        "AP-T1-01",
        "AP-T1-02",
    }
    assert bounded.limitations == ()

    reordered = deepcopy(first)
    reordered["canonical_chain"]["resource_slots"].reverse()
    assert _project(pattern=first) == _project(pattern=reordered)

    divergent = deepcopy(first)
    divergent["canonical_chain"]["semantic_revision"] = 2
    divergent["canonical_chain"]["semantic_digest"] = compute_chain_semantic_digest(
        divergent["canonical_chain"]
    )
    with pytest.raises(ValueError, match="share one pattern id"):
        _project_batch([first, divergent], resolver, snapshot)


# ---------------------------------------------------------------------------
# Adversarial projection tests for explicit canonical linkage (422o.3.1)
# ---------------------------------------------------------------------------


def test_absent_linkage_fails_closed() -> None:
    """Indirect ingress without source_influence linkage fails closed.

    The projection must not produce a candidate when the ingress entry point
    is indirect and no explicit source_influence link provides an alternative
    requirement derivation path.  This is the typed fail-closed behavior for
    unsupported linkage.
    """
    raw = _pattern(conditional=False)
    # The fixture has a direct-ingress entry point.  Replace it with an
    # indirect one to trigger the fail-closed path.
    profile = CapabilityProfile(
        zones_active=["input", "reasoning", "tool_execution"],
        entry_points=[
            {"name": "chat", "direction": "input", "controllability": "indirect"},
        ],
        confidence=ConfidenceLevel.high,
        kc_subcodes=["KC1.1", "KC5.1"],
        tool_inventory=[{"name": "writer", "description": "changes state"}],
        tool_types=[
            {
                "name": "writer",
                "zone": "tool_execution",
                "can_modify_state": True,
                "data_sensitivity": "medium",
                "code_execution": False,
            }
        ],
        external_integrations=[
            {
                "name": "CRM",
                "integration_type": "api",
                "auth_method": "oauth",
                "data_sensitivity": "high",
            }
        ],
        trust_boundaries=[
            {
                "name": "user-to-agent",
                "from_zone": "input",
                "to_zone": "reasoning",
                "confidence": "explicit",
            }
        ],
    )
    result = _project(profile=profile, pattern=raw)
    assert result.candidates == ()
    assert {issue.code for issue in result.infeasibilities} == {
        "unsupported_requirement_derivation"
    }


def test_no_explicit_links_produces_no_observations() -> None:
    """With explicit linkage, only linked postconditions produce observations
    and security assertions.  A security-relevant postcondition without an
    explicit outcome link fails closed at model validation — the security
    assertion cannot be derived from the ``security_relevant`` flag alone.
    """
    raw = _pattern(conditional=False)
    # Remove the terminal step's outcome link while keeping
    # security_relevant=True.  Model validation must reject this: the
    # security-relevant postcondition lacks an observable outcome link.
    raw["canonical_chain"]["steps"][2]["observable_outcome_links"] = []
    raw["canonical_chain"]["semantic_digest"] = compute_chain_semantic_digest(
        raw["canonical_chain"]
    )
    with pytest.raises(ValidationError, match="lacks an observable outcome link"):
        __import__(
            "asago_scenario_generator.models.attack_pattern", fromlist=["AttackPattern"]
        ).AttackPattern.model_validate(raw)


def test_explicit_observable_outcome_link_produces_observation() -> None:
    """An explicit observable_outcome_link produces an ObservationRequirement."""
    raw = _pattern(conditional=False)
    # Add an observable_outcome_link to step 2 (inside, system step).
    raw["canonical_chain"]["steps"][1]["observable_outcome_links"] = [
        {
            "postcondition_id": "post.2",
            "observation": "model_context",
            "binding_slot_id": "ingress",
        }
    ]
    raw["canonical_chain"]["semantic_digest"] = compute_chain_semantic_digest(
        raw["canonical_chain"]
    )
    result = _project(pattern=raw)
    candidate = result.candidates[0]
    kinds = {requirement.kind for requirement in candidate.execution_requirements}
    assert "observation" in kinds
    assert "direct_input_control" in kinds
    assert "security_outcome_assertion" in kinds


def test_tool_fixture_link_produces_tool_fixture_requirement() -> None:
    """A tool_fixture resource link produces a StateChangingToolFixtureRequirement."""
    raw = _pattern(conditional=False)
    # Add a tool_fixture link to step 2 (inside, system step).
    raw["canonical_chain"]["steps"][1]["resource_links"] = [
        {
            "slot_id": "tool",
            "role": "tool_fixture",
            "trust_boundary_slot_id": None,
        }
    ]
    raw["canonical_chain"]["semantic_digest"] = compute_chain_semantic_digest(
        raw["canonical_chain"]
    )
    result = _project(pattern=raw)
    candidate = result.candidates[0]
    kinds = {requirement.kind for requirement in candidate.execution_requirements}
    assert "state_changing_tool_fixture" in kinds
    assert "direct_input_control" in kinds
    assert "security_outcome_assertion" in kinds


def test_source_influence_link_produces_upstream_requirement() -> None:
    """A source_influence resource link produces an UpstreamSourceInfluenceRequirement."""
    raw = _pattern(conditional=False)
    # Add a source_influence link to step 2 (inside, system step).
    raw["canonical_chain"]["steps"][1]["resource_links"] = [
        {
            "slot_id": "source",
            "role": "source_influence",
            "trust_boundary_slot_id": "boundary",
            "target_ingress_slot_id": "ingress",
        }
    ]
    # A source_influence chain must not also carry a direct ingress link.
    raw["canonical_chain"]["steps"][0]["resource_links"] = []
    raw["canonical_chain"]["semantic_digest"] = compute_chain_semantic_digest(
        raw["canonical_chain"]
    )
    result = _project(pattern=raw)
    candidate = result.candidates[0]
    kinds = {requirement.kind for requirement in candidate.execution_requirements}
    assert "upstream_source_influence" in kinds
    assert "direct_input_control" not in kinds
    assert "security_outcome_assertion" in kinds


def test_source_influence_activates_indirect_ingress() -> None:
    """A source_influence link activates a candidate even when the bound
    ingress entry point is indirect.  This is the explicit source-boundary
    to canonical-ingress activation path: no inference from ingress
    controllability, and no direct-input requirement is derived.
    """
    raw = _pattern(conditional=False)
    raw["canonical_chain"]["steps"][1]["resource_links"] = [
        {
            "slot_id": "source",
            "role": "source_influence",
            "trust_boundary_slot_id": "boundary",
            "target_ingress_slot_id": "ingress",
        }
    ]
    raw["canonical_chain"]["steps"][0]["resource_links"] = []
    raw["canonical_chain"]["semantic_digest"] = compute_chain_semantic_digest(
        raw["canonical_chain"]
    )
    profile = CapabilityProfile(
        zones_active=["input", "reasoning", "tool_execution"],
        entry_points=[
            {
                "name": "chat",
                "direction": "input",
                "controllability": "indirect",
                "ingress_zone": "reasoning",
            },
        ],
        confidence=ConfidenceLevel.high,
        kc_subcodes=["KC1.1", "KC5.1"],
        tool_inventory=[{"name": "writer", "description": "changes state"}],
        tool_types=[
            {
                "name": "writer",
                "zone": "tool_execution",
                "can_modify_state": True,
                "data_sensitivity": "medium",
                "code_execution": False,
            }
        ],
        external_integrations=[
            {
                "name": "CRM",
                "integration_type": "api",
                "auth_method": "oauth",
                "data_sensitivity": "high",
            }
        ],
        trust_boundaries=[
            {
                "name": "user-to-agent",
                "from_zone": "input",
                "to_zone": "reasoning",
                "confidence": "explicit",
            }
        ],
    )
    result = _project(profile=profile, pattern=raw)
    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    kinds = {requirement.kind for requirement in candidate.execution_requirements}
    assert "upstream_source_influence" in kinds
    assert "direct_input_control" not in kinds
    assert not any(
        issue.code == "unsupported_requirement_derivation"
        for issue in result.infeasibilities
    )


# ---------------------------------------------------------------------------
# Adversarial tests: activation over selected steps, typed infeasibility
# ---------------------------------------------------------------------------


def test_conditional_activation_omitted_fails_closed() -> None:
    """When the only activation link is on a conditional step that is omitted
    by condition evaluation, the projection must fail closed with a typed
    unsupported-activation issue — not admit indirect ingress."""
    raw = _pattern(conditional=True)
    # The model forbids activation links on conditional steps (no branch
    # semantics), so we test the adjacent failure: remove the ingress link
    # from the required step.1, leaving no activation among selected steps.
    raw["canonical_chain"]["steps"][0]["resource_links"] = []
    raw["canonical_chain"]["semantic_digest"] = compute_chain_semantic_digest(
        raw["canonical_chain"]
    )
    # step.1 has no ingress link and step.2 has no activation link.
    # No activation among selected steps → typed infeasibility.
    result = _project(pattern=raw)
    assert len(result.candidates) == 0
    assert any(
        issue.code == "unsupported_requirement_derivation"
        and "no activation mechanism" in issue.detail
        for issue in result.infeasibilities
    )


def test_no_selected_activation_produces_typed_infeasibility() -> None:
    """A chain with no activation mechanism among selected steps produces a
    typed unsupported_requirement_derivation issue, not a candidate."""
    raw = _pattern(conditional=False)
    raw["canonical_chain"]["steps"][0]["resource_links"] = []
    raw["canonical_chain"]["semantic_digest"] = compute_chain_semantic_digest(
        raw["canonical_chain"]
    )
    result = _project(pattern=raw)
    assert len(result.candidates) == 0
    assert any(
        issue.code == "unsupported_requirement_derivation"
        and "no activation mechanism" in issue.detail
        for issue in result.infeasibilities
    )


def test_security_assertion_only_from_explicit_outcome_link() -> None:
    """A security-relevant postcondition with an explicit outcome link
    produces a SecurityOutcomeAssertionRequirement.  The assertion is
    traced to the link, not to the security_relevant flag alone."""
    raw = _pattern(conditional=False)
    # The terminal step already has an outcome link from the fixture.
    result = _project(pattern=raw)
    candidate = result.candidates[0]
    sec_reqs = [
        r
        for r in candidate.execution_requirements
        if r.kind == "security_outcome_assertion"
    ]
    assert len(sec_reqs) == 1
    # The observation requirement for the same link should also exist.
    obs_reqs = [r for r in candidate.execution_requirements if r.kind == "observation"]
    assert len(obs_reqs) == 1


# ---------------------------------------------------------------------------
# Requirement ID injectivity and uniqueness (second independent review)
# ---------------------------------------------------------------------------


def test_requirement_id_injective_for_dotted_components() -> None:
    """Requirement IDs must be injective: step 'a' + slot 'b.c' must produce
    a different ID than step 'a.b' + slot 'c'."""
    id1 = _requirement_id("req.test", "a", "b.c")
    id2 = _requirement_id("req.test", "a.b", "c")
    assert id1 != id2, f"requirement IDs collide: {id1} == {id2} for dotted components"


def test_requirement_id_stable_and_reversible() -> None:
    """Same components must always produce the same requirement ID, and
    the encoding must be reversible (proving injectivity)."""
    id1 = _requirement_id("req.observation", "step1", "post.result")
    id2 = _requirement_id("req.observation", "step1", "post.result")
    assert id1 == id2
    # Verify the encoding is reversible: the suffix is the last dot-segment
    # and contains only hex + colons; split on ':' and hex-decode each part.
    suffix = id1.rsplit(".", 1)[1]
    parts = suffix.split(":")
    decoded = [bytes.fromhex(p).decode("utf-8") for p in parts]
    assert decoded == ["step1", "post.result"]


def test_requirement_id_valid_identifier_syntax() -> None:
    """Generated requirement IDs must match the Identifier regex."""
    pattern = r"^[A-Za-z0-9][A-Za-z0-9._:-]*$"
    rid = _requirement_id("req.direct-input", "ingress")
    assert re.match(pattern, rid), f"{rid} does not match Identifier regex"
    rid2 = _requirement_id(
        "req.source-influence", "step.a.b", "slot.c.d", "None", "None"
    )
    assert re.match(pattern, rid2), f"{rid2} does not match Identifier regex"


def test_derived_id_collision_fails_closed_typed() -> None:
    """If derived requirement IDs somehow collide (e.g. an encoding edge
    case), the projection must fail closed with a typed
    unsupported_requirement_derivation issue, not an uncaught ValueError."""
    raw = _pattern(conditional=False)
    # Monkeypatch _requirement_id to force a collision: make it return
    # the same ID for every call regardless of prefix or components.

    original = req_mod._requirement_id
    req_mod._requirement_id = lambda prefix, *components: "req.collision.forced"
    try:
        result = _project(pattern=raw)
    finally:
        req_mod._requirement_id = original
    assert len(result.candidates) == 0
    assert any(
        issue.code == "unsupported_requirement_derivation" and "collide" in issue.detail
        for issue in result.infeasibilities
    )


def test_observation_retains_concrete_rejected_combinations() -> None:
    """A failed requirement derivation keeps its concrete binding identity."""
    raw = _pattern(conditional=False)
    resolver = TaxonomyResolver(
        __import__(
            "asago_scenario_generator.models.attack_pattern",
            fromlist=["AttackPattern"],
        )
        .AttackPattern.model_validate(raw)
        .canonical_chain.taxonomy_context
    )
    snapshot = capture_capability_snapshot(_profile(), (_evidence(),))

    import asago_scenario_generator.pipeline.projection_requirements as req_mod

    original = req_mod._requirement_id
    req_mod._requirement_id = lambda prefix, *components: "req.collision.forced"
    try:
        observed = project_authoritative_candidate_observations(
            [raw],
            resolver,
            snapshot,
            budget=ProjectionBudget(max_candidates=100),
        )
    finally:
        req_mod._requirement_id = original

    assert observed.batch.candidates == ()
    rejected = next(
        item
        for item in observed.rejected_candidates
        if item.reason.startswith("derived requirement IDs collide")
    )
    assert rejected.projection_disposition == "projection_infeasible"
    assert rejected.reason.startswith("derived requirement IDs collide")
    assert rejected.canonical_ingress is not None
    assert rejected.resource_bindings
    assert rejected.issue.code == "unsupported_requirement_derivation"


def test_observation_rejected_identity_is_deterministic() -> None:
    """Equivalent rejected combinations receive the same observation identity."""
    raw = _pattern(conditional=False)
    pattern = AttackPattern.model_validate(raw)
    resolver = TaxonomyResolver(pattern.canonical_chain.taxonomy_context)
    snapshot = capture_capability_snapshot(_profile(), (_evidence(),))

    original = req_mod._requirement_id
    req_mod._requirement_id = lambda prefix, *components: "req.collision.forced"
    try:
        first = project_authoritative_candidate_observations(
            [raw], resolver, snapshot, budget=ProjectionBudget(max_candidates=100)
        )
        second = project_authoritative_candidate_observations(
            [raw], resolver, snapshot, budget=ProjectionBudget(max_candidates=100)
        )
    finally:
        req_mod._requirement_id = original

    assert [item.candidate_id for item in first.rejected_candidates] == [
        item.candidate_id for item in second.rejected_candidates
    ]


def test_dotted_component_partition_collision_fails_closed() -> None:
    """If two requirement IDs would collide due to dotted component
    ambiguity, the projection must fail closed with a typed issue.

    We simulate this by having two steps whose step_id/slot_id
    combinations would produce the same dot-concatenated ID under the
    old scheme but distinct IDs under the injective encoding.
    """
    raw = _pattern(conditional=False)
    # Add a second tool slot and give step 2 a tool_fixture link to it,
    # using a slot_id that would collide with step 1's under dot concat.
    raw["canonical_chain"]["resource_slots"].append(
        {"slot_id": "tool.b", "kind": "tool", "purpose": "supporting"}
    )
    raw["canonical_chain"]["steps"][1]["resource_links"] = [
        {"slot_id": "tool.b", "role": "tool_fixture", "trust_boundary_slot_id": None}
    ]
    raw["canonical_chain"]["semantic_digest"] = compute_chain_semantic_digest(
        raw["canonical_chain"]
    )
    result = _project(pattern=raw)
    # With injective encoding, the IDs should NOT collide, so we should
    # get a candidate.  This proves the encoding prevents the collision.
    assert len(result.candidates) > 0
    candidate = result.candidates[0]
    req_ids = [r.requirement_id for r in candidate.execution_requirements]
    assert len(req_ids) == len(set(req_ids)), "requirement IDs must be unique"


def test_projected_candidate_validator_rejects_duplicate_requirement_ids() -> None:
    """ProjectedCandidate model validator must reject execution_requirements
    with duplicate requirement_ids."""
    # Build a minimal candidate with duplicate requirement IDs by
    # constructing two identical requirements and injecting them.
    raw = _pattern(conditional=False)
    result = _project(pattern=raw)
    assert len(result.candidates) > 0
    candidate = result.candidates[0]
    # Duplicate the first requirement to create a collision.
    reqs = list(candidate.execution_requirements)
    reqs.append(reqs[0])
    bad_data = candidate.model_dump(mode="json")
    bad_data["execution_requirements"] = [r.model_dump(mode="json") for r in reqs]
    with pytest.raises(ValidationError, match="unique"):
        ProjectedCandidate.model_validate(bad_data)


def test_all_live_projected_candidate_requirement_ids_unique() -> None:
    """Every requirement ID across all live projected candidates must be
    unique within each candidate."""

    patterns = load_attack_patterns()
    resolver = load_taxonomy_resolver()
    profile = CapabilityProfile(
        zones_active=["input", "reasoning", "tool_execution", "memory", "inter_agent"],
        entry_points=[
            {"name": "chat", "direction": "input", "controllability": "direct"},
            {
                "name": "RAG documents",
                "direction": "input",
                "controllability": "indirect",
            },
        ],
        confidence=ConfidenceLevel.high,
        kc_subcodes=[
            "KC1.1",
            "KC5.1",
            "KCX-PMEM",
            "KC6.1.1",
            "KC6.1.2",
            "KC6.4",
            "KC6.5",
        ],
        tool_inventory=[{"name": "writer", "description": "changes state"}],
        tool_types=[
            {
                "name": "writer",
                "zone": "tool_execution",
                "can_modify_state": True,
                "data_sensitivity": "medium",
                "code_execution": False,
            }
        ],
        external_integrations=[
            {
                "name": "CRM",
                "integration_type": "api",
                "auth_method": "oauth",
                "data_sensitivity": "high",
            },
            {
                "name": "Queue",
                "integration_type": "message_queue",
                "auth_method": "service_account",
                "data_sensitivity": "medium",
            },
        ],
        trust_boundaries=[
            {
                "name": "user-to-agent",
                "from_zone": "input",
                "to_zone": "reasoning",
                "confidence": "explicit",
            }
        ],
    )
    snapshot = capture_capability_snapshot(profile, [_evidence()])
    batch = _project_batch(
        list(patterns.values()),
        resolver,
        snapshot,
        budget=ProjectionBudget(max_candidates=512),
    )
    for candidate in batch.candidates:
        req_ids = [r.requirement_id for r in candidate.execution_requirements]
        assert len(req_ids) == len(set(req_ids)), (
            f"{candidate.pattern_id}: duplicate requirement IDs {req_ids}"
        )


# ---------------------------------------------------------------------------
# End-to-end AP-T6-07 infeasibility projection (second independent review)
# ---------------------------------------------------------------------------


def test_slot_distinctness_is_explicit_not_globally_injective() -> None:
    """Only slot pairs named by the authoritative contract must differ."""

    slots = (
        ResourceSlot(
            slot_id="config",
            kind="integration",
            purpose="intermediate",
            distinct_from_slot_ids=("endpoint",),
        ),
        ResourceSlot(slot_id="endpoint", kind="integration", purpose="target"),
        ResourceSlot(slot_id="audit", kind="integration", purpose="supporting"),
    )
    first = IntegrationResourceReference(
        kind="integration", integration_id="int:v1:" + "1" * 32
    )
    second = IntegrationResourceReference(
        kind="integration", integration_id="int:v1:" + "2" * 32
    )
    assert _combination_satisfies_distinctness(slots, (first, second, first))
    assert not _combination_satisfies_distinctness(slots, (first, first, second))
    options = ((first, second), (first, second), (first, second))
    assert _count_compatible_combinations(slots, options) == 4


def test_ap_t6_07_catalog_projection_derives_source_influence_activation() -> None:
    """The catalog's configuration-poisoning edge deterministically derives
    source influence through the declared boundary into canonical ingress."""

    patterns = load_attack_patterns()
    raw = patterns["AP-T6-07"]
    resolver = load_taxonomy_resolver()

    # Build a profile that satisfies all of AP-T6-07's prerequisites:
    # zones, KC codes, and compatible resources for every declared slot.
    # AP-T6-07 has: ingress (entry_point), agent_config + c2_channel
    # (integrations), boundary (trust_boundary).
    profile = CapabilityProfile(
        zones_active=["input", "reasoning", "tool_execution", "memory"],
        entry_points=[
            {
                "name": "configuration loader",
                "entry_point_type": "configuration_load",
                "direction": "input",
                "controllability": "indirect",
                "ingress_zone": "reasoning",
            },
        ],
        confidence=ConfidenceLevel.high,
        kc_subcodes=["KCX-PMEM", "KC6.1.1", "KC4.3"],
        tool_inventory=[{"name": "writer", "description": "changes state"}],
        tool_types=[
            {
                "name": "writer",
                "zone": "tool_execution",
                "can_modify_state": True,
                "data_sensitivity": "medium",
                "code_execution": False,
            }
        ],
        external_integrations=[
            {
                "name": "agent_config",
                "integration_type": "file_system",
                "auth_method": "oauth",
                "data_sensitivity": "high",
            },
            {
                "name": "c2_channel",
                "integration_type": "api",
                "auth_method": "oauth",
                "data_sensitivity": "high",
            },
        ],
        trust_boundaries=[
            {
                "name": "boundary",
                "from_zone": "memory",
                "to_zone": "reasoning",
                "confidence": "explicit",
            }
        ],
    )
    # AP-T6-07 has a precondition requiring attacker_code_execution_on_agent_host
    # to be True; provide that evidence so the projection reaches the activation
    # check rather than failing on an unresolved condition.
    runtime_evidence = EvaluatedFactEvidence(
        fact=AuthoritativeFactReference.model_validate(
            {
                "namespace": "runtime_state",
                "fact_id": "attacker_code_execution_on_agent_host",
                "value_type": "boolean",
                "property_path": [],
            }
        ),
        status="present",
        value=True,
    )
    snapshot = capture_capability_snapshot(profile, [_evidence(), runtime_evidence])
    batch = _project_batch(
        [raw],
        resolver,
        snapshot,
        budget=ProjectionBudget(max_candidates=10),
    )

    candidates = [c for c in batch.candidates if c.pattern_id == "AP-T6-07"]
    assert len(candidates) == 1
    candidate = candidates[0]
    bindings = {
        binding.slot_id: binding.resource_ref
        for binding in candidate.projection.bindings
    }
    config = profile.resolve_integration(bindings["agent_config"].integration_id)
    c2 = profile.resolve_integration(bindings["c2_channel"].integration_id)
    assert config is not None and config.integration_type.value == "file_system"
    assert c2 is not None and c2.integration_type.value == "api"
    assert bindings["agent_config"] != bindings["c2_channel"]

    # A serialized candidate cannot swap the two same-kind references after
    # projection: re-signing the projection and candidate identity still fails
    # authoritative typed-slot validation.

    swapped = candidate.model_dump(mode="json")
    swapped_bindings = {
        binding["slot_id"]: binding for binding in swapped["projection"]["bindings"]
    }
    (
        swapped_bindings["agent_config"]["resource_ref"],
        swapped_bindings["c2_channel"]["resource_ref"],
    ) = (
        swapped_bindings["c2_channel"]["resource_ref"],
        swapped_bindings["agent_config"]["resource_ref"],
    )
    swapped["projection"]["projection_digest"] = compute_projection_digest(
        swapped["projection"]
    )
    swapped_projection = ProjectionSnapshot.model_validate(swapped["projection"])
    swapped["candidate_id"] = _candidate_v2_id("AP-T6-07", swapped_projection)
    with pytest.raises(ValueError, match="resource is incompatible with slot"):
        validate_projection_snapshot(swapped["projection"], snapshot)
    requirements = [
        item
        for item in candidate.execution_requirements
        if item.kind == "upstream_source_influence"
    ]
    assert len(requirements) == 1
    requirement = requirements[0]
    assert requirement.source_slot_id == "agent_config"
    assert requirement.source_identity_kind == "integration"
    assert requirement.trust_boundary_slot_id == "boundary"
    assert requirement.target_ingress_slot_id == "ingress"
    assert not [i for i in batch.infeasibilities if i.pattern_id == "AP-T6-07"]

    # The catalog support remains fail-closed when its authoritative runtime
    # fact is absent, even though every resource is otherwise compatible.
    unresolved = _project_batch(
        [raw], resolver, capture_capability_snapshot(profile, [_evidence()])
    )
    assert not unresolved.candidates
    assert unresolved.infeasibilities[0].code == "unresolved_condition"

    # A missing trust-boundary resource cannot be laundered through the
    # source integration or canonical ingress.
    no_boundary_profile = profile.model_copy(update={"trust_boundaries": None})
    no_boundary = _project_batch(
        [raw],
        resolver,
        capture_capability_snapshot(
            no_boundary_profile, [_evidence(), runtime_evidence]
        ),
    )
    assert not no_boundary.candidates
    assert any(
        issue.code == "missing_compatible_resource" and issue.slot_id == "boundary"
        for issue in no_boundary.infeasibilities
    )

    # Every typed dimension fails closed independently. One integration cannot
    # alias both roles; missing either typed role, a mismatched ingress, or a
    # reversed boundary produces no nearest-fit candidate.
    base = profile.model_dump(mode="python", exclude_computed_fields=True)
    negative_updates = [
        (
            {"external_integrations": [base["external_integrations"][0]]},
            "c2_channel",
        ),
        (
            {"external_integrations": [base["external_integrations"][1]]},
            "agent_config",
        ),
        (
            {
                "external_integrations": [
                    base["external_integrations"][0],
                    base["external_integrations"][0],
                ]
            },
            "c2_channel",
        ),
        (
            {
                "entry_points": [
                    {
                        **base["entry_points"][0],
                        "entry_point_type": "user_input",
                    }
                ]
            },
            "ingress",
        ),
        (
            {
                "entry_points": [
                    {
                        **base["entry_points"][0],
                        "controllability": "direct",
                    }
                ]
            },
            "ingress",
        ),
        (
            {
                "entry_points": [
                    {
                        **base["entry_points"][0],
                        "name": "configuration document",
                        "controllability": None,
                    }
                ]
            },
            "ingress",
        ),
        (
            {
                "trust_boundaries": [
                    {
                        **base["trust_boundaries"][0],
                        "from_zone": "reasoning",
                        "to_zone": "memory",
                    }
                ]
            },
            "boundary",
        ),
    ]
    for update, expected_missing_slot in negative_updates:
        incompatible_profile = CapabilityProfile.model_validate({**base, **update})
        incompatible = _project_batch(
            [raw],
            resolver,
            capture_capability_snapshot(
                incompatible_profile, [_evidence(), runtime_evidence]
            ),
        )
        assert not incompatible.candidates
        assert any(
            issue.code == "missing_compatible_resource"
            and issue.slot_id == expected_missing_slot
            for issue in incompatible.infeasibilities
        )

    # Removing activation from the otherwise valid authoritative record
    # remains a typed projection infeasibility rather than an admitted empty
    # requirement set.
    no_activation_raw = deepcopy(raw)
    activation_step = next(
        step
        for step in no_activation_raw["canonical_chain"]["steps"]
        if step["step_id"] == "poisoned_prompt_activation"
    )
    activation_step["resource_links"] = []
    no_activation_raw["canonical_chain"]["semantic_digest"] = (
        compute_chain_semantic_digest(no_activation_raw["canonical_chain"])
    )
    no_activation = _project_batch([no_activation_raw], resolver, snapshot)
    assert not no_activation.candidates
    assert any(
        issue.code == "unsupported_requirement_derivation"
        and "no activation mechanism" in issue.detail
        for issue in no_activation.infeasibilities
    )

    # Typed linkage cannot target the source integration in place of the
    # canonical initial-ingress slot.
    mismatched_raw = deepcopy(raw)
    mismatched_step = next(
        step
        for step in mismatched_raw["canonical_chain"]["steps"]
        if step["step_id"] == "poisoned_prompt_activation"
    )
    mismatched_step["resource_links"][0]["target_ingress_slot_id"] = "agent_config"
    mismatched_raw["canonical_chain"]["semantic_digest"] = (
        compute_chain_semantic_digest(mismatched_raw["canonical_chain"])
    )
    with pytest.raises(ValueError, match="target_ingress_slot_id"):
        _project_batch([mismatched_raw], resolver, snapshot)


# ---------------------------------------------------------------------------
# New vocabulary projection tests: output_surface, agent_internal
# ---------------------------------------------------------------------------


def test_output_surface_slot_enumerates_output_and_bidirectional_entry_points() -> None:
    """An output_surface slot kind must enumerate entry points whose
    direction is 'output' or 'bidirectional', but not 'input'.
    A bidirectional entry point supports both input and output, so it
    qualifies as an output surface."""

    profile = CapabilityProfile(
        zones_active=["input", "reasoning"],
        entry_points=[
            {"name": "chat-in", "direction": "input", "controllability": "direct"},
            {"name": "chat-out", "direction": "output", "controllability": "direct"},
            {
                "name": "chat-bi",
                "direction": "bidirectional",
                "controllability": "direct",
            },
        ],
        confidence=ConfidenceLevel.high,
        kc_subcodes=["KC1.1"],
    )
    snapshot = capture_capability_snapshot(profile, [_evidence()])
    refs = _references_for_kind(
        "output_surface",
        snapshot,
        initial_ingress=False,
        attacker_influence_required=False,
    )
    # Both output and bidirectional entry points should be enumerated.
    assert len(refs) == 2
    assert all(isinstance(r, OutputSurfaceResourceReference) for r in refs)
    for r in refs:
        ep = profile.resolve_output_surface(r.entry_point_id)
        assert ep is not None
        assert ep.direction in ("output", "bidirectional")


def test_output_surface_slot_with_no_output_entry_points_yields_no_options() -> None:
    """If the profile has no output or bidirectional entry points, an
    output_surface slot yields zero options — the pattern should fail
    closed."""

    profile = CapabilityProfile(
        zones_active=["input"],
        entry_points=[
            {"name": "chat-in", "direction": "input", "controllability": "direct"},
        ],
        confidence=ConfidenceLevel.high,
        kc_subcodes=["KC1.1"],
    )
    snapshot = capture_capability_snapshot(profile, [_evidence()])
    refs = _references_for_kind(
        "output_surface",
        snapshot,
        initial_ingress=False,
        attacker_influence_required=False,
    )
    assert refs == ()


def test_agent_internal_slot_yields_only_intrinsic_typed_resource() -> None:
    """Agent working state resolves to one intrinsic typed singleton, never
    to an unrelated profile inventory resource."""

    profile = CapabilityProfile(
        zones_active=["input", "reasoning"],
        entry_points=[
            {"name": "chat", "direction": "input", "controllability": "direct"},
        ],
        confidence=ConfidenceLevel.high,
        kc_subcodes=["KC1.1"],
    )
    snapshot = capture_capability_snapshot(profile, [_evidence()])
    refs = _references_for_kind(
        "agent_internal",
        snapshot,
        initial_ingress=False,
        attacker_influence_required=False,
    )
    assert refs == (AgentInternalResourceReference(kind="agent_internal"),)
    assert snapshot.contains_resource(refs[0])


def test_ap_t1_06_catalog_projection_binds_intrinsic_agent_state() -> None:
    """AP-T1-06 binds agent state to the typed intrinsic singleton while
    retaining concrete catalog-backed bindings for every external resource."""

    patterns = load_attack_patterns()
    raw = patterns["AP-T1-06"]
    resolver = load_taxonomy_resolver()

    # Build a profile that satisfies AP-T1-06's prerequisites and all
    # catalog-backed resource slots.
    # A single bidirectional chat entry point serves as both the ingress
    # and the output surface (rendered_output slot).
    profile = CapabilityProfile(
        zones_active=["input", "reasoning", "memory"],
        entry_points=[
            {"name": "chat", "direction": "bidirectional", "controllability": "direct"},
        ],
        confidence=ConfidenceLevel.high,
        kc_subcodes=["KCX-VSTORE", "KC4.3"],
        tool_inventory=[],
        tool_types=[],
        external_integrations=[
            {
                "name": "rag_corpus",
                "integration_type": "api",
                "auth_method": "oauth",
                "data_sensitivity": "high",
            },
            {
                "name": "exfil_endpoint",
                "integration_type": "api",
                "auth_method": "oauth",
                "data_sensitivity": "high",
            },
        ],
        trust_boundaries=[
            {
                "name": "boundary",
                "from_zone": "input",
                "to_zone": "reasoning",
                "confidence": "explicit",
            }
        ],
    )
    snapshot = capture_capability_snapshot(profile, [_evidence()])
    batch = _project_batch(
        [raw],
        resolver,
        snapshot,
        budget=ProjectionBudget(max_candidates=10),
    )

    candidates = [c for c in batch.candidates if c.pattern_id == "AP-T1-06"]
    assert len(candidates) == 4
    bindings = {
        binding.slot_id: binding.resource_ref
        for binding in candidates[0].projection.bindings
    }
    assert bindings["agent_internal_state"].kind == "agent_internal"
    assert snapshot.contains_resource(bindings["agent_internal_state"])
    assert not [i for i in batch.infeasibilities if i.pattern_id == "AP-T1-06"]


class TestCandidateIdentityHelpers:
    """Branch-level coverage for verifiable_identity_and_derivation helpers."""

    @staticmethod
    def _candidate():
        result = _project()
        assert result.candidates
        return result.candidates[0]

    def test_require_unique_requirement_ids_ok_and_duplicate(self):
        _require_unique_requirement_ids(
            (
                SimpleNamespace(requirement_id="r1"),
                SimpleNamespace(requirement_id="r2"),
            )
        )
        with pytest.raises(ValueError, match="must be unique"):
            _require_unique_requirement_ids(
                (
                    SimpleNamespace(requirement_id="r1"),
                    SimpleNamespace(requirement_id="r1"),
                )
            )

    @staticmethod
    def _verifier_pair(name: str, candidate):
        """A call that must pass for the derived value and one that must not."""
        chain = candidate.projection.source_chain
        selected = candidate.projection.selected_step_ids
        other_ingress = next(
            (
                binding.resource_ref
                for binding in candidate.projection.bindings
                if binding.resource_ref != candidate.canonical_ingress
            ),
            None,
        )
        pairs = {
            "chain_identity": lambda bad: _verify_chain_identity(
                "other-pattern" if bad else candidate.pattern_id,
                candidate.chain_id,
                candidate.chain_semantic_revision,
                candidate.chain_semantic_digest,
                chain,
            ),
            "canonical_ingress": lambda bad: _verify_canonical_ingress(
                candidate.projection,
                chain,
                other_ingress if bad else candidate.canonical_ingress,
            ),
            "execution_requirements_digest": (
                lambda bad: _verify_execution_requirements_digest(
                    candidate.execution_requirements,
                    "0" * 64 if bad else candidate.execution_requirements_digest,
                )
            ),
            "candidate_identity": lambda bad: _verify_candidate_identity(
                "cand:v2:" + "0" * 32 if bad else candidate.candidate_id,
                candidate.pattern_id,
                candidate.projection,
            ),
            "projected_mappings": lambda bad: _verify_projected_mappings(
                () if bad else candidate.projected_mappings, chain, selected
            ),
        }
        verify = pairs[name]
        return (lambda: verify(False)), (lambda: verify(True))

    @pytest.mark.parametrize(
        ("name", "message"),
        [
            ("chain_identity", "chain identity"),
            ("canonical_ingress", "canonical_ingress"),
            ("execution_requirements_digest", "does not match requirements"),
            ("candidate_identity", "candidate_id"),
            ("projected_mappings", "mappings"),
        ],
        ids=lambda value: value.replace(" ", "_"),
    )
    def test_verifier_accepts_the_derived_value_and_rejects_a_changed_one(
        self, name: str, message: str
    ):
        accepted, rejected = self._verifier_pair(name, self._candidate())

        accepted()
        with pytest.raises(ValueError, match=message):
            rejected()

    def test_expected_precondition_key_map(self):
        candidate = self._candidate()
        chain = candidate.projection.source_chain
        key_map = _expected_precondition_key_map(
            chain, candidate.projection.selected_step_ids
        )
        assert isinstance(key_map, dict)

    def test_verify_precondition_results_uniqueness(self):
        duplicate = [
            SimpleNamespace(step_id="s1", condition_id="c1"),
            SimpleNamespace(step_id="s1", condition_id="c1"),
        ]
        with pytest.raises(ValueError, match="keys must be unique"):
            _verify_precondition_results({}, duplicate)

    def test_verify_precondition_results_coverage(self):
        with pytest.raises(ValueError, match="exactly cover"):
            _verify_precondition_results(
                {("s2", "c2"): None},
                [SimpleNamespace(step_id="s1", condition_id="c1")],
            )

    def test_verify_precondition_results_ok(self):

        raw = _pattern(conditional=True)
        chain = AttackPattern.model_validate(raw).canonical_chain
        condition = chain.steps[1].condition
        expected = {("step.2", "c1"): condition}
        supplied = [
            PreconditionEvaluationResult(
                step_id="step.2",
                condition_id="c1",
                result="true",
                evidence=(_evidence("active"),),
            )
        ]
        _verify_precondition_results(expected, supplied)

    def test_verify_precondition_true_rejects_false_result(self):

        chain = AttackPattern.model_validate(_pattern(conditional=True)).canonical_chain
        condition = chain.steps[1].condition
        supplied = PreconditionEvaluationResult(
            step_id="step.2",
            condition_id="c1",
            result="false",
            evidence=(_evidence("active"),),
        )
        with pytest.raises(ValueError, match="must evaluate true"):
            _verify_precondition_true(condition, supplied)

    def test_verify_precondition_true_rejects_evidence_mismatch(self):

        chain = AttackPattern.model_validate(_pattern(conditional=True)).canonical_chain
        condition = chain.steps[1].condition
        supplied = PreconditionEvaluationResult(
            step_id="step.2",
            condition_id="c1",
            result="true",
            evidence=(_evidence("inactive"),),
        )
        with pytest.raises(ValueError, match="must evaluate true"):
            _verify_precondition_true(condition, supplied)

    def test_expected_complexity_inputs_and_verify(self):
        candidate = self._candidate()
        chain = candidate.projection.source_chain
        selected_steps = _selected_steps_for_projection(
            chain, candidate.projection.selected_step_ids
        )
        expected = _expected_complexity_inputs(
            selected_steps, candidate.projection, candidate.execution_requirements
        )
        assert expected == candidate.complexity_inputs
        _verify_complexity_inputs(
            candidate.complexity_inputs,
            chain,
            candidate.projection,
            candidate.execution_requirements,
        )
        wrong = expected.model_copy(update={"selected_step_count": 99})
        with pytest.raises(ValueError, match="complexity inputs"):
            _verify_complexity_inputs(
                wrong,
                chain,
                candidate.projection,
                candidate.execution_requirements,
            )


class TestReferenceResolutionHelpers:
    """Branch-level coverage for reference-kind and slot resolution helpers."""

    @staticmethod
    def _snapshot(profile: CapabilityProfile | None = None):
        return capture_capability_snapshot(profile or _profile())

    def test_entry_point_reference_allowed_unconstrained(self):
        snapshot = self._snapshot()
        active_zones = set(snapshot.profile.zones_active)
        for entry_point in snapshot.profile.entry_points:
            assert _entry_point_reference_allowed(
                entry_point,
                active_zones,
                initial_ingress=False,
                attacker_influence_required=False,
            )

    def test_entry_point_reference_allowed_requires_accessibility(self):
        base = _profile()
        output = base.entry_points[0].model_copy(update={"direction": "output"})
        profile = base.model_copy(
            update={"entry_points": [output, base.entry_points[1]]}
        )
        snapshot = self._snapshot(profile)
        active_zones = set(snapshot.profile.zones_active)
        assert not _entry_point_reference_allowed(
            output,
            active_zones,
            initial_ingress=True,
            attacker_influence_required=False,
        )
        assert _entry_point_reference_allowed(
            base.entry_points[1],
            active_zones,
            initial_ingress=True,
            attacker_influence_required=False,
        )

    def test_entry_point_eligibility_only_requires_accessibility_for_ingress(self):
        from asago_scenario_generator.models.attack_pattern import (
            EntryPointResourceReference,
            ResourceSlot,
        )

        base = _profile()
        output = base.entry_points[0].model_copy(update={"direction": "output"})
        profile = base.model_copy(update={"entry_points": [output]})
        snapshot = self._snapshot(profile)
        reference = EntryPointResourceReference(
            kind="entry_point", entry_point_id=output.entry_point_id
        )

        for purpose in ("initial_ingress", "supporting"):
            slot = ResourceSlot.model_validate(
                {"slot_id": purpose, "kind": "entry_point", "purpose": purpose}
            )
            assert not _entry_point_eligible_for_slot(reference, slot, snapshot)

        target = ResourceSlot.model_validate(
            {"slot_id": "target", "kind": "entry_point", "purpose": "target"}
        )
        assert _entry_point_eligible_for_slot(reference, target, snapshot)

    def test_references_for_kind_entry_point(self):
        snapshot = self._snapshot()
        refs = _references_for_kind(
            "entry_point",
            snapshot,
            initial_ingress=True,
            attacker_influence_required=False,
        )
        assert len(refs) == 2
        assert all(ref.kind == "entry_point" for ref in refs)
        refs_all = _references_for_kind(
            "entry_point",
            snapshot,
            initial_ingress=False,
            attacker_influence_required=False,
        )
        assert len(refs_all) == 2

    def test_references_for_kind_output_surface(self):
        base = _profile()
        bidirectional = base.entry_points[0].model_copy(
            update={"direction": "bidirectional"}
        )
        profile = base.model_copy(
            update={"entry_points": [bidirectional, base.entry_points[1]]}
        )
        snapshot = self._snapshot(profile)
        refs = _references_for_kind(
            "output_surface",
            snapshot,
            initial_ingress=False,
            attacker_influence_required=False,
        )
        assert len(refs) == 1
        assert refs[0].entry_point_id == bidirectional.entry_point_id

    def test_references_for_kind_output_surface_none(self):
        snapshot = self._snapshot()
        refs = _references_for_kind(
            "output_surface",
            snapshot,
            initial_ingress=False,
            attacker_influence_required=False,
        )
        assert refs == ()

    @pytest.mark.parametrize(
        ("kind", "expected_id_field", "expected_id"),
        [
            ("tool", "tool_id", lambda profile: profile.tool_inventory[0].tool_id),
            (
                "integration",
                "integration_id",
                lambda profile: profile.external_integrations[0].integration_id,
            ),
            ("agent_internal", None, None),
            ("trust_boundary", None, None),
        ],
        ids=["tool", "integration", "agent_internal", "trust_boundary"],
    )
    def test_references_for_kind_yields_one_reference_of_the_kind(
        self, kind, expected_id_field, expected_id
    ):
        snapshot = self._snapshot()
        refs = _references_for_kind(
            kind, snapshot, initial_ingress=False, attacker_influence_required=False
        )
        assert len(refs) == 1
        assert refs[0].kind == kind
        if expected_id is not None:
            assert getattr(refs[0], expected_id_field) == expected_id(snapshot.profile)

    def test_agent_internal_has_no_references_without_the_reasoning_zone(self):
        snapshot_no_reasoning = CapabilityFactSnapshot.model_construct(
            profile=CapabilityProfile.model_construct(zones_active=["input"]),
            facts=(),
            snapshot_digest="0" * 64,
        )
        assert (
            _references_for_kind(
                "agent_internal",
                snapshot_no_reasoning,
                initial_ingress=False,
                attacker_influence_required=False,
            )
            == ()
        )

    def test_unknown_kind_falls_back_to_the_trust_boundary_references(self):
        snapshot = self._snapshot()
        refs = _references_for_kind(
            "trust_boundary",
            snapshot,
            initial_ingress=False,
            attacker_influence_required=False,
        )
        fallback = _references_for_kind(
            "unknown_kind",
            snapshot,
            initial_ingress=False,
            attacker_influence_required=False,
        )
        assert fallback == refs

    @pytest.mark.parametrize(
        ("restriction", "blocks"),
        [((), False), (("api",), False), (("message_queue",), True)],
        ids=["unrestricted", "listed", "unlisted"],
    )
    def test_restriction_blocks(self, restriction, blocks):
        assert _restriction_blocks("api", restriction) is blocks

    @pytest.mark.parametrize(
        ("allowed", "accepted"),
        [("none", True), ("own", True), ("other", False)],
    )
    def test_resource_id_allowed(self, allowed, accepted):
        snapshot = self._snapshot()
        reference = _references_for_kind(
            "integration",
            snapshot,
            initial_ingress=False,
            attacker_influence_required=False,
        )[0]
        allowed_ids = {
            "none": set(),
            "own": {reference.integration_id},
            "other": {"other-id"},
        }[allowed]
        assert _resource_id_allowed(reference, allowed_ids) is accepted

    @pytest.mark.parametrize(
        ("kind", "index", "slot", "compatible"),
        [
            (
                "integration",
                0,
                {"kind": "integration", "allowed_integration_types": ["api"]},
                True,
            ),
            (
                "integration",
                0,
                {"kind": "integration", "allowed_integration_types": ["message_queue"]},
                False,
            ),
            (
                "entry_point",
                1,
                {
                    "kind": "entry_point",
                    "allowed_entry_point_types": [
                        "user_input",
                        "external_content",
                        "other",
                    ],
                    "allowed_entry_point_directions": ["input"],
                    "allowed_entry_point_controllability": ["direct", "indirect"],
                    "allowed_entry_point_ingress_zones": ["input"],
                },
                True,
            ),
            (
                "entry_point",
                1,
                {"kind": "entry_point", "allowed_entry_point_directions": ["output"]},
                False,
            ),
            (
                "trust_boundary",
                0,
                {
                    "kind": "trust_boundary",
                    "purpose": "intermediate",
                    "allowed_trust_boundary_from_zones": ["input"],
                    "allowed_trust_boundary_to_zones": ["reasoning"],
                },
                True,
            ),
            (
                "trust_boundary",
                0,
                {
                    "kind": "trust_boundary",
                    "purpose": "intermediate",
                    "allowed_trust_boundary_to_zones": ["tool_execution"],
                },
                False,
            ),
            # Non-constrained kinds always match the slot constraints.
            ("tool", 0, {"kind": "tool"}, True),
        ],
        ids=[
            "integration_type_allowed",
            "integration_type_blocked",
            "entry_point_allowed",
            "entry_point_direction_blocked",
            "trust_boundary_allowed",
            "trust_boundary_zone_blocked",
            "unconstrained_tool",
        ],
    )
    def test_slot_reference_compatible_kinds(self, kind, index, slot, compatible):
        snapshot = self._snapshot()
        reference = _references_for_kind(
            kind, snapshot, initial_ingress=False, attacker_influence_required=False
        )[index]
        resource_slot = ResourceSlot.model_validate(
            {"slot_id": "s", "purpose": "supporting", **slot}
        )
        assert (
            _slot_reference_compatible(reference, resource_slot, snapshot) is compatible
        )

    def test_snapshot_resource_matching_fails_closed_at_each_filter(self):
        from asago_scenario_generator.models.attack_pattern import (
            EntryPointResourceReference,
            ResourceSlot,
            ToolResourceReference,
        )

        snapshot = self._snapshot()
        entry_point = snapshot.profile.entry_points[0]
        reference = EntryPointResourceReference(
            kind="entry_point", entry_point_id=entry_point.entry_point_id
        )
        target_slot = ResourceSlot.model_validate(
            {"slot_id": "target", "kind": "entry_point", "purpose": "target"}
        )

        assert not snapshot.resource_matches_slot(
            ToolResourceReference(kind="tool", tool_id="tool:v1:" + "0" * 32),
            target_slot,
        )
        assert not snapshot.resource_matches_slot(
            EntryPointResourceReference(
                kind="entry_point", entry_point_id="ep:v1:" + "f" * 32
            ),
            target_slot,
        )
        assert not snapshot.resource_matches_slot(
            reference,
            target_slot.model_copy(
                update={"allowed_resource_ids": ["ep:v1:" + "f" * 32]}
            ),
        )
        assert not snapshot.resource_matches_slot(
            reference,
            target_slot.model_copy(
                update={"allowed_entry_point_directions": ["output"]}
            ),
        )
        assert snapshot.resource_matches_slot(reference, target_slot)

    def test_references_for_slot_applies_all_filters(self):

        snapshot = self._snapshot()
        slot = ResourceSlot.model_validate(
            {
                "slot_id": "s1",
                "kind": "integration",
                "purpose": "supporting",
                "allowed_integration_types": ["api"],
                "allowed_resource_ids": [
                    snapshot.profile.external_integrations[0].integration_id
                ],
            }
        )
        refs = _references_for_slot(slot, snapshot, initial_ingress=False)
        assert len(refs) == 1
        assert refs[0].integration_id == (
            snapshot.profile.external_integrations[0].integration_id
        )
        id_blocked = ResourceSlot.model_validate(
            {
                "slot_id": "s2",
                "kind": "integration",
                "purpose": "supporting",
                "allowed_resource_ids": ["int:v1:" + "1" * 32],
            }
        )
        assert _references_for_slot(id_blocked, snapshot, initial_ingress=False) == ()


class TestRequirementDerivationHelpers:
    """Branch-level coverage for execution-requirement derivation helpers."""

    @staticmethod
    def _chain():
        return _project().candidates[0].projection.source_chain

    def test_link_role_requirement_ingress_direct(self):
        chain = self._chain()
        step = next(s for s in chain.steps if s.step_id == "step.1")
        link = next(link for link in step.resource_links if link.role == "ingress")
        slot = next(s for s in chain.resource_slots if s.slot_id == link.slot_id)
        derived, issue = _link_role_requirement("AP-T1-01", step, link, slot, "direct")
        assert issue is None
        assert len(derived) == 1
        assert derived[0].kind == "direct_input_control"

    def test_link_role_requirement_ingress_indirect(self):
        chain = self._chain()
        step = next(s for s in chain.steps if s.step_id == "step.1")
        link = next(link for link in step.resource_links if link.role == "ingress")
        slot = next(s for s in chain.resource_slots if s.slot_id == link.slot_id)
        derived, issue = _link_role_requirement(
            "AP-T1-01", step, link, slot, "indirect"
        )
        assert derived is None
        assert issue is not None
        assert issue.code == "unsupported_requirement_derivation"

    @pytest.mark.parametrize(
        ("link", "slot_kind", "controllability", "expected"),
        [
            (
                {"role": "tool_fixture", "slot_id": "slot"},
                "tool",
                "indirect",
                [{"kind": "state_changing_tool_fixture"}],
            ),
            (
                {
                    "role": "source_influence",
                    "slot_id": "slot",
                    "source_identity_kind": None,
                    "trust_boundary_slot_id": "boundary",
                    "target_ingress_slot_id": "ingress",
                },
                "integration",
                "indirect",
                [
                    {
                        "kind": "upstream_source_influence",
                        "source_identity_kind": "integration",
                    }
                ],
            ),
            ({"role": "unknown", "slot_id": "slot"}, "tool", "direct", []),
        ],
        ids=["tool_fixture", "source_influence", "unknown_role"],
    )
    def test_link_role_requirement_for_a_stand_in_link(
        self, link, slot_kind, controllability, expected
    ):
        derived, issue = _link_role_requirement(
            "AP-T1-01",
            SimpleNamespace(step_id="step.2"),
            SimpleNamespace(**link),
            SimpleNamespace(slot_id="slot", kind=slot_kind),
            controllability,
        )
        assert issue is None
        assert [
            {name: getattr(item, name) for name in want}
            for item, want in zip(derived, expected, strict=True)
        ] == expected

    @pytest.mark.parametrize(
        ("link_kind", "slot_kind", "expected"),
        [
            ("entry_point", "integration", "entry_point"),
            (None, "entry_point", "entry_point"),
            (None, "integration", "integration"),
        ],
        ids=["link_names_the_kind", "slot_entry_point", "slot_integration"],
    )
    def test_source_identity_kind_for_link(self, link_kind, slot_kind, expected):
        link = SimpleNamespace(source_identity_kind=link_kind)
        assert (
            _source_identity_kind_for_link(link, SimpleNamespace(kind=slot_kind))
            == expected
        )

    def test_linked_postcondition_ids_and_observation_requirements(self):
        chain = self._chain()
        final_step = next(s for s in chain.steps if s.step_id == "step.3")
        assert _linked_postcondition_ids(final_step) == {"post.3"}
        observations = _observation_requirements(final_step)
        assert len(observations) == 1
        assert observations[0].kind == "observation"

    def test_security_outcome_requirements(self):
        chain = self._chain()
        final_step = next(s for s in chain.steps if s.step_id == "step.3")
        assert len(_security_outcome_requirements(final_step, {"post.3"})) == 1
        assert _security_outcome_requirements(final_step, set()) == []

    def test_require_unique_requirement_ids_or_issue(self):
        unique = (
            SimpleNamespace(requirement_id="r1"),
            SimpleNamespace(requirement_id="r2"),
        )
        derived, issue = _require_unique_requirement_ids_or_issue(unique, "AP-T1-01")
        assert issue is None
        assert derived == unique
        duplicate = (
            SimpleNamespace(requirement_id="r1"),
            SimpleNamespace(requirement_id="r1"),
        )
        derived, issue = _require_unique_requirement_ids_or_issue(duplicate, "AP-T1-01")
        assert derived is None
        assert issue is not None
        assert "collide" in issue.detail

    def test_derive_execution_requirements_core_ok_and_indirect(self):
        candidate = _project().candidates[0]
        chain = candidate.projection.source_chain
        derived, issue = _derive_execution_requirements_core(
            candidate.pattern_id,
            chain,
            candidate.projection,
            "direct",
        )
        assert issue is None
        assert derived == candidate.execution_requirements
        derived, issue = _derive_execution_requirements_core(
            candidate.pattern_id,
            chain,
            candidate.projection,
            "indirect",
        )
        assert derived is None
        assert issue is not None

    def test_selected_ingress_links(self):
        candidate = _project().candidates[0]
        chain = candidate.projection.source_chain
        links = _selected_ingress_links(chain, candidate.projection)
        assert len(links) == 1
        assert links[0].role == "ingress"

    def test_ingress_controllability_for_link(self):
        candidate = _project().candidates[0]
        chain = candidate.projection.source_chain
        link = _selected_ingress_links(chain, candidate.projection)[0]
        bindings = {
            item.slot_id: item.resource_ref for item in candidate.projection.bindings
        }
        snapshot = capture_capability_snapshot(_profile())
        assert _ingress_controllability_for_link(bindings, link, snapshot) == "direct"

    def test_ingress_controllability_for_link_wrong_binding_type(self):

        candidate = _project().candidates[0]
        chain = candidate.projection.source_chain
        link = _selected_ingress_links(chain, candidate.projection)[0]
        snapshot = capture_capability_snapshot(_profile())
        with pytest.raises(TypeError, match="not an entry point"):
            _ingress_controllability_for_link(
                {
                    link.slot_id: ToolResourceReference(
                        kind="tool", tool_id="tool:v1:" + "0" * 32
                    )
                },
                link,
                snapshot,
            )

    def test_resolve_ingress_controllability_direct_and_derive(self):
        candidate = _project().candidates[0]
        chain = candidate.projection.source_chain
        snapshot = capture_capability_snapshot(_profile())
        assert (
            _resolve_ingress_controllability(chain, candidate.projection, snapshot)
            == "direct"
        )
        derived, issue = _derive_execution_requirements(
            candidate.pattern_id, chain, candidate.projection, snapshot
        )
        assert issue is None
        assert derived == candidate.execution_requirements


class TestRemainingProjectionHelpers:
    """Direct coverage for the small projection helpers decomposed for CRAP."""

    @staticmethod
    def _snapshot():
        return capture_capability_snapshot(_profile(), (_evidence(),))

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("cafe\u0301", "café"),
            (7, 7),
            (None, None),
            (["e\u0301", 1], ["é", 1]),
            (("e\u0301", 2), ("é", 2)),
            ({"ca\u0301fe": {"o\u0301": "x"}}, {"cáfe": {"ó": "x"}}),
        ],
        ids=["string", "integer", "none", "list", "tuple", "nested_mapping"],
    )
    def test_normalize_unicode_nfc_and_container_recursion(self, value, expected):
        assert _normalize_unicode(value) == expected

    @pytest.mark.parametrize(
        ("mapping", "error", "message"),
        [
            ({1: "a"}, TypeError, "must be strings"),
            ({"café": 1, "cafe\u0301": 2}, ValueError, "collide"),
        ],
        ids=["non_string_key", "nfc_collision"],
    )
    def test_normalized_mapping_rejects(self, mapping, error, message):
        with pytest.raises(error, match=message):
            _normalized_mapping(mapping)

    def test_normalized_mapping_recurses_into_values(self):
        assert _normalized_mapping({"a": ["e\u0301", {"c": "o\u0301"}]}) == {
            "a": ["é", {"c": "ó"}]
        }

    @pytest.mark.parametrize(
        ("reference", "expected"),
        [
            (
                EntryPointResourceReference(
                    kind="entry_point", entry_point_id="ep:v1:" + "0" * 32
                ),
                "ep:v1:" + "0" * 32,
            ),
            (
                ToolResourceReference(kind="tool", tool_id="tool:v1:" + "1" * 32),
                "tool:v1:" + "1" * 32,
            ),
            (
                IntegrationResourceReference(
                    kind="integration", integration_id="int:v1:" + "2" * 32
                ),
                "int:v1:" + "2" * 32,
            ),
            (
                TrustBoundaryResourceReference(
                    kind="trust_boundary", trust_boundary_id="tb:v1:" + "3" * 32
                ),
                "tb:v1:" + "3" * 32,
            ),
            (
                OutputSurfaceResourceReference(
                    kind="output_surface", entry_point_id="ep:v1:" + "4" * 32
                ),
                "ep:v1:" + "4" * 32,
            ),
            (
                AgentInternalResourceReference(kind="agent_internal"),
                "agent_internal:reasoning",
            ),
        ],
        ids=[
            "entry_point",
            "tool",
            "integration",
            "trust_boundary",
            "output_surface",
            "agent_internal",
        ],
    )
    def test_resource_id_extracts_each_typed_kind(self, reference, expected):
        assert _resource_id(reference) == expected

    def test_resource_id_rejects_unknown_reference(self):
        with pytest.raises(TypeError, match="unsupported"):
            _resource_id(object())

    def test_contains_resource_matches_profile_inventory(self):
        from asago_scenario_generator.models.attack_pattern import (
            AgentInternalResourceReference,
            EntryPointResourceReference,
            OutputSurfaceResourceReference,
            ToolResourceReference,
        )

        snapshot = self._snapshot()
        entry = _references_for_kind(
            "entry_point",
            snapshot,
            initial_ingress=True,
            attacker_influence_required=False,
        )[0]
        tool = _references_for_kind(
            "tool", snapshot, initial_ingress=False, attacker_influence_required=False
        )[0]
        integration = _references_for_kind(
            "integration",
            snapshot,
            initial_ingress=False,
            attacker_influence_required=False,
        )[0]
        boundary = _references_for_kind(
            "trust_boundary",
            snapshot,
            initial_ingress=False,
            attacker_influence_required=False,
        )[0]
        assert snapshot.contains_resource(entry)
        assert snapshot.contains_resource(tool)
        assert snapshot.contains_resource(integration)
        assert snapshot.contains_resource(boundary)
        assert snapshot.contains_resource(
            AgentInternalResourceReference(kind="agent_internal")
        )
        # The fixture profile exposes no output-direction entry points.
        assert not snapshot.contains_resource(
            OutputSurfaceResourceReference(
                kind="output_surface", entry_point_id="ep:v1:" + "f" * 32
            )
        )
        assert not snapshot.contains_resource(
            EntryPointResourceReference(
                kind="entry_point", entry_point_id="ep:v1:" + "e" * 32
            )
        )
        assert not snapshot.contains_resource(
            ToolResourceReference(kind="tool", tool_id="tool:v1:" + "d" * 32)
        )
        assert not _resource_contained(object(), snapshot.profile)

    def test_coherent_digest_accepts_captured_snapshot(self):
        snapshot = self._snapshot()
        assert snapshot.coherent_digest() is snapshot

    def test_coherent_digest_rejects_stale_digest(self):
        snapshot = self._snapshot()
        forged = CapabilityFactSnapshot.model_construct(
            profile=snapshot.profile,
            facts=snapshot.facts,
            snapshot_digest="0" * 64,
        )
        with pytest.raises(ValueError, match="snapshot_digest does not match"):
            forged.coherent_digest()

    def test_assert_snapshot_facts_uniquely_sorted(self):
        with pytest.raises(ValueError, match="uniquely sorted"):
            _assert_snapshot_facts_uniquely_sorted([_evidence(), _evidence()])
        fact_a = AuthoritativeFactReference.model_validate(
            {
                "namespace": "profile",
                "fact_id": "a",
                "value_type": "string",
                "property_path": [],
            }
        )
        fact_b = AuthoritativeFactReference.model_validate(
            {
                "namespace": "profile",
                "fact_id": "b",
                "value_type": "string",
                "property_path": [],
            }
        )
        evidence_a = EvaluatedFactEvidence(fact=fact_a, status="present", value="x")
        evidence_b = EvaluatedFactEvidence(fact=fact_b, status="present", value="y")
        with pytest.raises(ValueError, match="uniquely sorted"):
            _assert_snapshot_facts_uniquely_sorted((evidence_b, evidence_a))
        _assert_snapshot_facts_uniquely_sorted((evidence_a, evidence_b))

    def test_snapshot_resource_payload_is_sorted_and_complete(self):
        snapshot = self._snapshot()
        profile = snapshot.profile
        payload = _snapshot_resource_payload(profile)
        assert payload["zones_active"] == ["input", "reasoning", "tool_execution"]
        assert payload["kc_subcodes"] == ["KC1.1", "KC5.1"]
        assert len(payload["entry_points"]) == 2
        assert [item["entry_point_id"] for item in payload["entry_points"]] == sorted(
            item["entry_point_id"] for item in payload["entry_points"]
        )
        assert len(payload["tools"]) == 1
        assert payload["tools"][0]["name"] == "writer"
        assert payload["tool_types"][0]["name"] == "writer"
        assert len(payload["integrations"]) == 1
        assert payload["integrations"][0]["name"] == "CRM"
        assert len(payload["trust_boundaries"]) == 1
        assert payload["trust_boundaries"][0]["name"] == "user-to-agent"
        assert _sorted_by(profile.entry_points, "entry_point_id") == sorted(
            (item.model_dump(mode="json") for item in profile.entry_points),
            key=lambda item: item["entry_point_id"],
        )
        assert _sorted_canonical(profile.tool_types) == sorted(
            (item.model_dump(mode="json") for item in profile.tool_types),
            key=lambda item: _canonical_json(item),
        )

    def test_condition_facts_collects_deduplicates_and_sorts(self):

        fact_a = AuthoritativeFactReference.model_validate(
            {
                "namespace": "profile",
                "fact_id": "a",
                "value_type": "string",
                "property_path": [],
            }
        )
        fact_b = AuthoritativeFactReference.model_validate(
            {
                "namespace": "profile",
                "fact_id": "b",
                "value_type": "string",
                "property_path": [],
            }
        )
        eq_a = EqualityCondition(
            op="equality", schema_version="1", fact=fact_a, value="x"
        )
        eq_b = EqualityCondition(
            op="equality", schema_version="1", fact=fact_b, value="y"
        )
        inner = AllCondition(op="all", schema_version="1", operands=(eq_b, eq_a))
        all_cond = AllCondition(op="all", schema_version="1", operands=(eq_a, inner))
        any_cond = AnyCondition(op="any", schema_version="1", operands=(eq_b, eq_a))
        not_cond = NotCondition(op="not", schema_version="1", operand=eq_b)
        assert _condition_facts(all_cond) == (fact_a, fact_b)
        assert _condition_facts(any_cond) == (fact_a, fact_b)
        assert _condition_facts(not_cond) == (fact_b,)
        assert _condition_facts(eq_a) == (fact_a,)
        assert _condition_fact_items(eq_a) == [fact_a]

    def test_count_compatible_combinations_helpers(self):
        slots = (
            SimpleNamespace(slot_id="a", distinct_from_slot_ids=("b",)),
            SimpleNamespace(slot_id="b", distinct_from_slot_ids=("a",)),
            SimpleNamespace(slot_id="c", distinct_from_slot_ids=()),
        )
        edges = _distinctness_edges(slots)
        assert edges == {frozenset((0, 1))}
        assert _constrained_indexes(edges) == {0, 1}
        assert _unconstrained_product(((1, 2), (1, 2), (1, 2, 3)), {0, 1}) == 3
        options = (("r0a", "r0b"), ("r1a", "r1b"), ("r2a",))
        assert _count_component_assignments({0, 1}, edges, options) == 4
        assert _assignment_conflicts(0, "r0a", {1: "r0a"}, edges) is True
        assert _assignment_conflicts(0, "r0a", {1: "r1a"}, edges) is False
        assert _assignment_conflicts(0, "r0a", {2: "r2a"}, edges) is False
        assert _constrained_components({0, 1}, edges) == [{0, 1}]
        assert _constrained_components(set(), set()) == []

    def test_iter_coverage_first_combinations_order_and_dedup(self):

        snapshot = capture_capability_snapshot(
            _profile(duplicate_resources=True), (_evidence(),)
        )
        tools = _references_for_kind(
            "tool", snapshot, initial_ingress=False, attacker_influence_required=False
        )
        ints = _references_for_kind(
            "integration",
            snapshot,
            initial_ingress=False,
            attacker_influence_required=False,
        )
        options = (tools[:2], ints[:2])
        result = list(_iter_coverage_first_combinations(options))
        assert result == [
            (tools[0], ints[0]),
            (tools[1], ints[0]),
            (tools[0], ints[1]),
            (tools[1], ints[1]),
        ]
        assert _combination_baseline(options) == (tools[0], ints[0])
        assert _combination_key((tools[0],)) == (_resource_key(tools[0]),)
        assert _max_option_length(options) == 2
        assert list(_offset_variants((tools[0], ints[0]), options, 1, set())) == [
            (tools[1], ints[0]),
            (tools[0], ints[1]),
        ]
        assert list(_variant_combinations((tools[0], ints[0]), options, set())) == [
            (tools[1], ints[0]),
            (tools[0], ints[1]),
        ]
        seen = {
            _combination_key((tools[0], ints[0])),
            _combination_key((tools[0], ints[1])),
            _combination_key((tools[1], ints[0])),
        }
        assert list(_cartesian_fill(options, seen)) == [(tools[1], ints[1])]

    def test_projected_mappings_helpers(self):

        chain = AttackPattern.model_validate(_pattern()).canonical_chain
        chain_only = tuple(_chain_atlas_mappings(chain))
        assert _projected_mappings(chain, ()) == chain_only
        step = chain.steps[0]
        assert tuple(_step_atlas_mappings(step)) == tuple(
            ProjectedMapping(scope="step", step_id=step.step_id, mapping=mapping)
            for mapping in step.mappings
            if mapping.taxonomy == "ATLAS"
        )
        combined = _projected_mappings(chain, (step.step_id,))
        assert combined[: len(chain_only)] == chain_only
        assert any(item.scope == "step" for item in combined)

    def test_build_candidate_from_combination_helpers_round_trip(self):
        from asago_scenario_generator.pipeline.projection_candidates import (
            _bindings_for_combination,
            _build_candidate_from_combination,
            _candidate_complexity_inputs,
            _ingress_for_combination,
            _projection_data_for_combination,
            _selected_steps_from_chain,
        )

        raw = _pattern()
        resolver = TaxonomyResolver(
            __import__(
                "asago_scenario_generator.models.attack_pattern",
                fromlist=["AttackPattern"],
            )
            .AttackPattern.model_validate(raw)
            .canonical_chain.taxonomy_context
        )
        snapshot = capture_capability_snapshot(_profile(), (_evidence(),))
        batch = _project_batch(
            [raw], resolver, snapshot, budget=ProjectionBudget(max_candidates=100)
        )
        candidate = batch.candidates[0]
        chain = candidate.projection.source_chain
        bindings = candidate.projection.bindings
        resources = tuple(item.resource_ref for item in bindings)
        assert _bindings_for_combination(chain, resources) == bindings
        ingress_ref, controllability = _ingress_for_combination(
            bindings, chain, snapshot
        )
        assert ingress_ref == candidate.canonical_ingress
        assert controllability == candidate.ingress_controllability
        selected = candidate.projection.selected_step_ids
        selected_steps = _selected_steps_from_chain(chain, selected)
        assert selected_steps == [
            step for step in chain.steps if step.step_id in set(selected)
        ]
        complexity = _candidate_complexity_inputs(
            selected_steps, bindings, candidate.execution_requirements
        )
        assert complexity == candidate.complexity_inputs
        data = _projection_data_for_combination(
            chain,
            selected,
            candidate.projection.condition_results,
            candidate.projection.omissions,
            bindings,
            candidate.projection.catalog_pin,
            candidate.projection.pattern_pin,
            snapshot,
            candidate.projection.source_influence_paths,
        )
        assert data["projection_digest"] == candidate.projection.projection_digest
        rebuilt, issue = _build_candidate_from_combination(
            candidate.pattern_id,
            chain,
            selected,
            candidate.projection.condition_results,
            candidate.projection.omissions,
            resources,
            candidate.projection.catalog_pin,
            candidate.projection.pattern_pin,
            candidate.precondition_results,
            snapshot,
        )
        assert issue is None
        assert rebuilt == candidate


class TestSourceInfluenceTargetId:
    """The relation target ingress comes from options, else explicit ids."""

    INGRESS_SLOT = "slot-ingress"

    def _link(self) -> SimpleNamespace:
        return SimpleNamespace(target_ingress_slot_id=self.INGRESS_SLOT)

    def _chain(self, *slots: tuple[str, tuple[str, ...]]) -> SimpleNamespace:
        return SimpleNamespace(
            resource_slots=[
                SimpleNamespace(slot_id=slot_id, allowed_resource_ids=allowed)
                for slot_id, allowed in slots
            ]
        )

    def test_prefers_the_first_option_of_the_selected_ingress(self) -> None:
        first = EntryPointResourceReference(
            kind="entry_point", entry_point_id="ep:v1:" + "a" * 32
        )
        second = EntryPointResourceReference(
            kind="entry_point", entry_point_id="ep:v1:" + "b" * 32
        )
        chain = self._chain((self.INGRESS_SLOT, ("ep:v1:" + "c" * 32,)))
        option_sets = [(), (first, second)]
        assert (
            _source_influence_target_id(self._link(), chain, option_sets, 1)
            == first.entry_point_id
        )

    def test_falls_back_to_the_first_explicit_allowed_id_without_options(self) -> None:
        chain = self._chain(
            ("other", ("ep:other",)), (self.INGRESS_SLOT, ("ep:one", "ep:two"))
        )
        assert _source_influence_target_id(self._link(), chain, [()], 0) == "ep:one"
        assert _source_influence_target_id(self._link(), chain, [], 0) == "ep:one"

    def test_returns_none_when_the_ingress_slot_allows_no_ids(self) -> None:
        chain = self._chain((self.INGRESS_SLOT, ()))
        assert _source_influence_target_id(self._link(), chain, [()], 0) is None

    def test_returns_none_when_the_chain_has_no_ingress_slot(self) -> None:
        chain = self._chain(("other", ("ep:other",)))
        assert _source_influence_target_id(self._link(), chain, [()], 0) is None


def _entry_point_ref(entry_point_id: str) -> EntryPointResourceReference:
    return EntryPointResourceReference(
        kind="entry_point", entry_point_id=entry_point_id
    )


def test_source_entry_point_detail_requires_an_influenceable_distinct_source() -> None:
    snapshot = capture_capability_snapshot(_profile(), (_evidence(),))
    chat, rag = (
        _entry_point_ref(ep.entry_point_id) for ep in snapshot.profile.entry_points
    )
    unknown = _entry_point_ref("ep:v1:" + "f" * 32)
    assert _source_entry_point_detail(SimpleNamespace(), chat, snapshot) is None
    assert (
        _source_entry_point_detail(unknown, chat, snapshot)
        == "entry-point source is not attacker-influenceable"
    )
    assert (
        _source_entry_point_detail(chat, chat, snapshot)
        == "source entry point must be distinct from target ingress"
    )
    assert _source_entry_point_detail(rag, chat, snapshot) is None


def test_unavailable_explicit_relation_boundary_is_a_relation_infeasibility() -> None:
    raw = _pattern(conditional=False)
    chain = raw["canonical_chain"]
    chain["steps"][0]["resource_links"] = []
    chain["steps"][1]["resource_links"] = [
        {
            "slot_id": "source",
            "role": "source_influence",
            "trust_boundary_slot_id": "boundary",
            "target_ingress_slot_id": "ingress",
        }
    ]
    chain["resource_slots"][3]["allowed_resource_ids"] = ["tb:v1:" + "f" * 32]
    chain["semantic_digest"] = compute_chain_semantic_digest(chain)
    snapshot = capture_capability_snapshot(_profile(), (_evidence(),))
    observation = project_authoritative_candidate_observations(
        [raw], _atlas_only_resolver(), snapshot
    )
    (issue,) = [
        issue
        for issue in observation.batch.infeasibilities
        if issue.code == "source_influence_relation_infeasible"
    ]
    chat = snapshot.profile.entry_points[0]
    assert issue.model_dump(exclude_defaults=True) == {
        "code": "source_influence_relation_infeasible",
        "pattern_id": "AP-T1-01",
        "slot_id": "boundary",
        "detail": "source-influence relation resource is not reviewed",
        "boundary_id": "tb:v1:" + "f" * 32,
        "target_ingress_id": chat.entry_point_id,
        "canonical_ingress_id": chat.entry_point_id,
        "expected_target_zone": chat.effective_ingress_zone,
        "actual_boundary_zones": "unreviewed",
        "expected_source_kind": "integration",
        "actual_binding_kind": "integration",
        "guidance": "Review the explicit ingress_zone or trust-boundary declaration.",
    }
