"""Focused tests for the authoritative attack-pattern contract."""

import unicodedata
from copy import deepcopy
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from pydantic import TypeAdapter, ValidationError

from asago_scenario_generator.data.loaders import load_attack_patterns
from asago_scenario_generator.models.attack_pattern import (
    AttackPattern,
    AuthoritativeFactReference,
    CanonicalAttackChain,
    Condition,
    ConditionEvaluationResult,
    EvaluatedFactEvidence,
    ExecutionRequirement,
    LegacyAttackPatternRecord,
    ProjectionSnapshot,
    _canonical_json,
    compute_chain_semantic_digest,
    compute_projection_digest,
    evaluate_condition,
    validate_attack_pattern,
    validate_projection_snapshot,
)

ZERO = "0" * 64
ONE = "1" * 64
CHAIN_GOLDEN = "c7d23d8a6aaf6e4c39e71fcf71257f586ee77c758e3e1097c462433d163f4bde"
PROJECTION_GOLDEN = "4148dfe2b5f4f7cf30f152c79b8fafce3e5ddc056775a27ae0f53f37f1994960"
REFS = {
    "entry_point": {"kind": "entry_point", "entry_point_id": "ep:v1:" + "1" * 32},
    "tool": {"kind": "tool", "tool_id": "tool:v1:" + "2" * 32},
    "integration": {"kind": "integration", "integration_id": "int:v1:" + "3" * 32},
    "trust_boundary": {
        "kind": "trust_boundary",
        "trust_boundary_id": "tb:v1:" + "4" * 32,
    },
}


def fact(value_type: str = "string") -> dict[str, Any]:
    return {
        "namespace": "profile",
        "fact_id": "mode",
        "value_type": value_type,
        "property_path": [],
    }


def equality() -> dict[str, Any]:
    return {"op": "equality", "schema_version": "1", "fact": fact(), "value": "active"}


def step(step_id: str, order: int, attacker: bool) -> dict[str, Any]:
    final = order == 3
    return {
        "step_id": step_id,
        "requirement": "conditional" if order == 2 else "required",
        "condition": equality() if order == 2 else None,
        "executor_role": "attacker" if attacker else "system",
        "boundary_position": "crossing" if attacker else "inside",
        "action_kind": "deliver" if attacker else "impact",
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
                    "target_ingress_slot_id": None,
                }
            ]
            if attacker
            else []
        ),
        "observable_outcome_links": [
            {
                "postcondition_id": f"post.{order}",
                "observation": "model_context",
                "binding_slot_id": "ingress",
            }
        ],
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
            else [{"decision": "not_applicable", "taxonomy": "LAAF"}]
        ),
    }


def resign_chain(raw: dict[str, Any]) -> dict[str, Any]:
    raw["semantic_digest"] = compute_chain_semantic_digest(raw)
    return raw


def chain_data() -> dict[str, Any]:
    return resign_chain(
        {
            "schema_version": "v1",
            "pattern_id": "AP-T1-01",
            "chain_id": "chain.1",
            "semantic_revision": 1,
            "semantic_digest": ZERO,
            "taxonomy_context": {
                "atlas": {"release": "v1", "digest": ZERO},
                "laaf": {"release": "v1", "digest": ONE},
                "mapping_set_digest": ZERO,
            },
            "mappings": [
                {"decision": "exact", "taxonomy": "ATLAS", "ids": ["AML.T0001"]}
            ],
            "steps": [
                step("step.1", 1, True),
                step("step.2", 2, False),
                step("step.3", 3, False),
            ],
            "earliest_attacker_controlled_step_id": "step.1",
            "resource_slots": [
                {
                    "slot_id": "ingress",
                    "kind": "entry_point",
                    "purpose": "initial_ingress",
                },
                {"slot_id": "tool", "kind": "tool", "purpose": "supporting"},
                {"slot_id": "source", "kind": "integration", "purpose": "supporting"},
                {"slot_id": "boundary", "kind": "trust_boundary", "purpose": "target"},
            ],
            "initial_ingress_slot_id": "ingress",
        }
    )


def pattern_data() -> dict[str, Any]:
    return {
        "id": "AP-T1-01",
        "threat_id": "T1",
        "name": "Pattern",
        "description": "Canonical",
        "prerequisite_capabilities": {"min_zones": ["input"]},
        "canonical_chain": chain_data(),
    }


def condition_result(result: str = "true") -> dict[str, Any]:
    return {
        "condition_step_id": "step.2",
        "result": result,
        "evidence": [
            {
                "fact": fact(),
                "status": "present",
                "value": "inactive" if result == "false" else "active",
            }
        ],
    }


def resign_projection(raw: dict[str, Any]) -> dict[str, Any]:
    raw["projection_digest"] = compute_projection_digest(raw)
    return raw


def projection_data(result: str = "true") -> dict[str, Any]:
    selected = (
        ["step.1", "step.3"] if result == "false" else ["step.1", "step.2", "step.3"]
    )
    return resign_projection(
        {
            "schema_version": "1",
            "source_chain": chain_data(),
            "selected_step_ids": selected,
            "condition_results": [condition_result(result)],
            "omissions": [{"step_id": "step.2", "reason": "condition_false"}]
            if result == "false"
            else [],
            "bindings": [
                {"slot_id": key, "resource_ref": deepcopy(REFS[kind])}
                for key, kind in (
                    ("ingress", "entry_point"),
                    ("tool", "tool"),
                    ("source", "integration"),
                    ("boundary", "trust_boundary"),
                )
            ],
            "catalog_pin": ONE,
            "pattern_pin": ZERO,
            "capability_fact_snapshot_digest": ONE,
            "projection_digest": ZERO,
        }
    )


def invalid_chain(mutation: Any) -> None:
    raw = chain_data()
    mutation(raw)
    resign_chain(raw)
    with pytest.raises(ValidationError):
        CanonicalAttackChain.model_validate(raw)


def test_roundtrip_digest_stability_and_structural_schema() -> None:
    pattern = AttackPattern.model_validate(pattern_data())
    assert pattern.canonical_chain.semantic_digest == CHAIN_GOLDEN
    assert AttackPattern.model_validate(pattern.model_dump(mode="json")) == pattern
    assert (
        compute_chain_semantic_digest(pattern.canonical_chain)
        == chain_data()["semantic_digest"]
    )
    reordered = {key: chain_data()[key] for key in reversed(chain_data())}
    assert compute_chain_semantic_digest(reordered) == chain_data()["semantic_digest"]
    schema = AttackPattern.model_json_schema()
    Draft202012Validator.check_schema(schema)
    assert Draft202012Validator(schema).is_valid(pattern.model_dump(mode="json"))


def test_chain_digest_normalization_and_semantic_sensitivity() -> None:
    raw = chain_data()
    reordered = deepcopy(raw)
    reordered["mappings"].reverse()
    reordered["resource_slots"].reverse()
    assert compute_chain_semantic_digest(reordered) == raw["semantic_digest"]

    nfc = deepcopy(raw)
    nfd = deepcopy(raw)
    nfc["steps"][0]["provenance"]["adaptation_rationale"] = "caf\u00e9"
    nfd["steps"][0]["provenance"]["adaptation_rationale"] = unicodedata.normalize(
        "NFD", "caf\u00e9"
    )
    assert compute_chain_semantic_digest(nfc) == compute_chain_semantic_digest(nfd)

    for mutation in (
        lambda c: c.update(semantic_revision=2),
        lambda c: c["steps"].reverse(),
        lambda c: c["taxonomy_context"]["atlas"].update(release="v2"),
    ):
        changed = deepcopy(raw)
        mutation(changed)
        assert compute_chain_semantic_digest(changed) != raw["semantic_digest"]


def test_legacy_catalog_stays_isolated() -> None:
    """The live catalog is now canonical (49 records with canonical_chain).

    Legacy kill_chain fields are gone from every live record; each record
    validates as the canonical AttackPattern model and does NOT validate as
    a LegacyAttackPatternRecord (which requires kill_chain/evidence).
    """
    records = load_attack_patterns()
    assert len(records) == 49
    assert all("kill_chain" not in r for r in records.values())
    assert all("canonical_chain" in r for r in records.values())
    assert all(
        isinstance(AttackPattern.model_validate(r), AttackPattern)
        for r in records.values()
    )
    with pytest.raises(ValidationError):
        LegacyAttackPatternRecord.model_validate(next(iter(records.values())))


@pytest.mark.parametrize(
    "mutation",
    [
        lambda c: c["steps"][0].update(executor_role="system"),
        lambda c: c["steps"][1].update(executor_role="attacker"),
        lambda c: c["steps"][1].update(
            mappings=[{"decision": "exact", "taxonomy": "ATLAS", "ids": ["AML.T0001"]}]
        ),
        lambda c: c["steps"][1].update(
            mappings=[
                {"decision": "unmapped", "taxonomy": "ATLAS", "rationale": "none"}
            ]
        ),
        lambda c: c["steps"][0].update(
            attacker_controlled=False,
            executor_role="system",
            mappings=[{"decision": "not_applicable", "taxonomy": "ATLAS"}],
        ),
        lambda c: c["steps"][0].update(execution_requirements=[]),
        lambda c: c["resource_slots"][0].update(kind="tool"),
    ],
)
def test_chain_role_start_mapping_and_authored_requirement_negatives(
    mutation: Any,
) -> None:
    invalid_chain(mutation)


def test_condition_evidence_present_absent_unknown_contract() -> None:
    assert ConditionEvaluationResult.model_validate(condition_result()).result == "true"
    unknown = condition_result("unknown")
    unknown["evidence"][0].update(status="unknown", value=None)
    assert ConditionEvaluationResult.model_validate(unknown).result == "unknown"
    for status, value in (
        ("present", None),
        ("absent", "active"),
        ("unknown", "active"),
        ("present", True),
    ):
        raw = condition_result()
        raw["evidence"][0].update(status=status, value=value)
        with pytest.raises(ValidationError):
            ConditionEvaluationResult.model_validate(raw)
    duplicate = condition_result()
    duplicate["evidence"].append(deepcopy(duplicate["evidence"][0]))
    with pytest.raises(ValidationError, match="unique"):
        ConditionEvaluationResult.model_validate(duplicate)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda p: p.update(selected_step_ids=[]),
        lambda p: p.update(
            selected_step_ids=["step.2", "step.3"],
            omissions=[{"step_id": "step.1", "reason": "condition_false"}],
        ),
        lambda p: p.update(
            selected_step_ids=["step.1", "step.2"],
            omissions=[{"step_id": "step.3", "reason": "condition_false"}],
        ),
        lambda p: p["condition_results"][0].update(result="unknown"),
        lambda p: p["condition_results"][0]["evidence"][0]["fact"].update(
            fact_id="unrelated"
        ),
        lambda p: p.update(
            omissions=[{"step_id": "step.2", "reason": "condition_false"}]
        ),
        lambda p: p["omissions"].append(
            {"step_id": "step.1", "reason": "condition_false"}
        ),
        lambda p: p["bindings"].pop(),
        lambda p: p["bindings"].append(deepcopy(p["bindings"][0])),
        lambda p: p["bindings"][0].update(resource_ref=deepcopy(REFS["tool"])),
        lambda p: p["source_chain"]["steps"][0].update(action_kind="prepare"),
    ],
)
def test_projection_source_semantics_negatives(mutation: Any) -> None:
    raw = projection_data()
    mutation(raw)
    resign_projection(raw)
    with pytest.raises(ValidationError):
        ProjectionSnapshot.model_validate(raw)


def test_projection_roundtrip_false_omission_and_digest() -> None:
    assert projection_data()["projection_digest"] == PROJECTION_GOLDEN
    projection = ProjectionSnapshot.model_validate(projection_data("false"))
    assert projection.selected_step_ids == ("step.1", "step.3")
    assert (
        ProjectionSnapshot.model_validate(projection.model_dump(mode="json"))
        == projection
    )
    changed = projection_data()
    changed["source_chain"]["steps"][0]["action_kind"] = "prepare"
    assert compute_projection_digest(changed) != projection_data()["projection_digest"]


@pytest.mark.parametrize(
    "kind,field",
    [
        ("entry_point", "entry_point_id"),
        ("tool", "tool_id"),
        ("integration", "integration_id"),
        ("trust_boundary", "trust_boundary_id"),
    ],
)
def test_resource_reference_domain_patterns(kind: str, field: str) -> None:
    raw = projection_data()
    binding = next(b for b in raw["bindings"] if b["resource_ref"]["kind"] == kind)
    binding["resource_ref"][field] = "arbitrary"
    resign_projection(raw)
    with pytest.raises(ValidationError):
        ProjectionSnapshot.model_validate(raw)


def requirements() -> list[dict[str, Any]]:
    return [
        {
            "schema_version": "1",
            "requirement_id": "r1",
            "kind": "direct_input_control",
            "entry_point_slot_id": "ingress",
        },
        {
            "schema_version": "1",
            "requirement_id": "r2",
            "kind": "upstream_source_influence",
            "source_slot_id": "source",
            "source_identity_kind": "integration",
            "trust_boundary_slot_id": "boundary",
            "target_ingress_slot_id": "ingress",
        },
        {
            "schema_version": "1",
            "requirement_id": "r3",
            "kind": "state_changing_tool_fixture",
            "tool_slot_id": "tool",
        },
        {
            "schema_version": "1",
            "requirement_id": "r4",
            "kind": "observation",
            "observation": "tool_invocation",
            "binding_slot_id": "tool",
        },
        {
            "schema_version": "1",
            "requirement_id": "r5",
            "kind": "security_outcome_assertion",
            "source_step_id": "step.3",
            "postcondition_id": "post.3",
        },
    ]


def test_every_execution_requirement_union_shape_and_upstream_source_kinds() -> None:
    adapter = TypeAdapter(ExecutionRequirement)
    assert [adapter.validate_python(r).kind for r in requirements()] == [
        r["kind"] for r in requirements()
    ]
    upstream = requirements()[1]
    upstream["source_identity_kind"] = "entry_point"
    assert adapter.validate_python(upstream).source_identity_kind == "entry_point"
    for invalid in ("tool", "trust_boundary"):
        upstream["source_identity_kind"] = invalid
        with pytest.raises(ValidationError):
            adapter.validate_python(upstream)


def parsed_condition(raw: dict[str, Any]) -> Condition:
    return TypeAdapter(Condition).validate_python(raw)


def evidence(
    fact_raw: dict[str, Any], status: str, value: Any = None
) -> EvaluatedFactEvidence:
    return EvaluatedFactEvidence.model_validate(
        {"fact": fact_raw, "status": status, "value": value}
    )


def test_pure_condition_evaluator_complete_evidence_and_kleene_semantics() -> None:
    fact_a = fact()
    fact_b = {**fact(), "fact_id": "enabled", "value_type": "boolean"}
    a = equality()
    b = {"op": "equality", "schema_version": "1", "fact": fact_b, "value": True}
    present_a = evidence(fact_a, "present", "active")
    absent_a = evidence(fact_a, "absent")
    unknown_a = evidence(fact_a, "unknown")
    present_b = evidence(fact_b, "present", True)
    unknown_b = evidence(fact_b, "unknown")
    extra = evidence({**fact(), "fact_id": "extra"}, "absent")

    exists_false = parsed_condition(
        {"op": "existence", "schema_version": "1", "fact": fact_a, "exists": False}
    )
    assert evaluate_condition(exists_false, (absent_a,)) == "true"
    assert evaluate_condition(exists_false, (unknown_a,)) == "unknown"

    all_condition = parsed_condition(
        {"op": "all", "schema_version": "1", "operands": [a, b]}
    )
    any_condition = parsed_condition(
        {"op": "any", "schema_version": "1", "operands": [a, b]}
    )
    not_condition = parsed_condition({"op": "not", "schema_version": "1", "operand": a})
    assert evaluate_condition(all_condition, (absent_a, unknown_b)) == "false"
    assert evaluate_condition(all_condition, (present_a, unknown_b)) == "unknown"
    assert evaluate_condition(any_condition, (present_a, unknown_b)) == "true"
    assert evaluate_condition(any_condition, (absent_a, unknown_b)) == "unknown"
    assert evaluate_condition(not_condition, (present_a,)) == "false"
    assert evaluate_condition(not_condition, (unknown_a,)) == "unknown"
    for invalid in (
        (present_a,),
        (present_a, present_b, present_b),
        (present_a, present_b, extra),
    ):
        with pytest.raises(ValueError):
            evaluate_condition(all_condition, invalid)


def test_projection_rejects_evidence_result_mismatches_and_partial_evidence() -> None:
    for status, value, result in (
        ("present", "inactive", "true"),
        ("unknown", None, "true"),
        ("present", "active", "false"),
    ):
        raw = projection_data(result)
        raw["condition_results"][0]["evidence"][0].update(status=status, value=value)
        resign_projection(raw)
        with pytest.raises(ValidationError, match="recorded condition result"):
            ProjectionSnapshot.model_validate(raw)

    raw = projection_data()
    second = {**fact(), "fact_id": "other"}
    raw["source_chain"]["steps"][1]["condition"] = {
        "op": "all",
        "schema_version": "1",
        "operands": [
            equality(),
            {"op": "equality", "schema_version": "1", "fact": second, "value": "yes"},
        ],
    }
    resign_chain(raw["source_chain"])
    resign_projection(raw)
    with pytest.raises(ValidationError, match="exactly cover"):
        ProjectionSnapshot.model_validate(raw)


class SnapshotResolver:
    capability_fact_snapshot_digest = ONE

    def __init__(self) -> None:
        self.reading = evidence(fact(), "present", "active")
        self.missing_kind: str | None = None

    def fact(
        self, reference: AuthoritativeFactReference
    ) -> EvaluatedFactEvidence | None:
        return self.reading if reference == self.reading.fact else None

    def contains_resource(self, reference: Any) -> bool:
        return reference.kind != self.missing_kind

    def resource_matches_slot(self, reference: Any, slot: Any) -> bool:
        return self.contains_resource(reference) and reference.kind == slot.kind


def test_projection_snapshot_requires_external_qualification() -> None:
    with pytest.raises(TypeError):
        validate_projection_snapshot(projection_data())  # type: ignore[call-arg]
    assert validate_projection_snapshot(projection_data(), SnapshotResolver())

    resolver = SnapshotResolver()
    resolver.capability_fact_snapshot_digest = ZERO
    with pytest.raises(ValueError, match="digest pin"):
        validate_projection_snapshot(projection_data(), resolver)

    resolver = SnapshotResolver()
    resolver.reading = resolver.reading.model_copy(
        update={"fact": resolver.reading.fact.model_copy(update={"fact_id": "missing"})}
    )
    with pytest.raises(ValueError, match="fact is missing"):
        validate_projection_snapshot(projection_data(), resolver)

    for status, value in (("absent", None), ("present", "inactive")):
        resolver = SnapshotResolver()
        resolver.reading = evidence(fact(), status, value)
        with pytest.raises(ValueError, match="does not match"):
            validate_projection_snapshot(projection_data(), resolver)

    for kind in REFS:
        resolver = SnapshotResolver()
        resolver.missing_kind = kind
        with pytest.raises(ValueError, match=kind):
            validate_projection_snapshot(projection_data(), resolver)


class Resolver:
    taxonomy_context = CanonicalAttackChain.model_validate(
        chain_data()
    ).taxonomy_context

    def contains(self, taxonomy: str, identifier: str) -> bool:
        return taxonomy == "ATLAS" and identifier == "AML.T0001"


def test_required_qualification_resolver_ids_and_pins() -> None:
    assert validate_attack_pattern(pattern_data(), Resolver()).id == "AP-T1-01"
    with pytest.raises(TypeError):
        validate_attack_pattern(pattern_data())  # type: ignore[call-arg]
    raw = pattern_data()
    raw["canonical_chain"]["steps"][0]["mappings"][0]["ids"] = ["AML.UNKNOWN"]
    resign_chain(raw["canonical_chain"])
    with pytest.raises(ValueError, match="unknown ATLAS id"):
        validate_attack_pattern(raw, Resolver())
    resolver = Resolver()
    resolver.taxonomy_context = resolver.taxonomy_context.model_copy(
        update={"mapping_set_digest": ONE}
    )
    with pytest.raises(ValueError, match="pins"):
        validate_attack_pattern(pattern_data(), resolver)


def atlas_only_chain_data() -> dict[str, Any]:
    """Chain variant with no LAAF pin and exclusively ATLAS decisions."""
    raw = chain_data()
    raw["taxonomy_context"]["laaf"] = None
    for step_raw in raw["steps"]:
        for mapping in step_raw["mappings"]:
            if mapping["taxonomy"] == "LAAF":
                mapping["taxonomy"] = "ATLAS"
    return resign_chain(raw)


def atlas_only_pattern_data() -> dict[str, Any]:
    return {**pattern_data(), "canonical_chain": atlas_only_chain_data()}


class MembershipResolver:
    def __init__(self, context: Any, members: set[tuple[str, str]]) -> None:
        self.taxonomy_context = context
        self.members = members

    def contains(self, taxonomy: str, identifier: str) -> bool:
        return (taxonomy, identifier) in self.members


def atlas_only_resolver() -> MembershipResolver:
    context = CanonicalAttackChain.model_validate(
        atlas_only_chain_data()
    ).taxonomy_context
    assert context.laaf is None
    return MembershipResolver(context, {("ATLAS", "AML.T0001")})


def test_atlas_only_chain_parses_and_qualifies_without_laaf_pin() -> None:
    pattern = validate_attack_pattern(atlas_only_pattern_data(), atlas_only_resolver())
    assert pattern.canonical_chain.taxonomy_context.laaf is None
    assert AttackPattern.model_validate(pattern.model_dump(mode="json")) == pattern
    schema = AttackPattern.model_json_schema()
    assert Draft202012Validator(schema).is_valid(pattern.model_dump(mode="json"))
    # The optional axis is content: adding a pin changes the chain digest.
    pinned = atlas_only_chain_data()
    pinned["taxonomy_context"]["laaf"] = {"release": "v1", "digest": ONE}
    assert (
        compute_chain_semantic_digest(pinned)
        != atlas_only_chain_data()["semantic_digest"]
    )


def test_omitted_laaf_key_signs_and_qualifies_like_explicit_null() -> None:
    explicit = atlas_only_chain_data()
    omitted = deepcopy(explicit)
    del omitted["taxonomy_context"]["laaf"]
    # Signing the omitted-key raw dict through the public helper frames the
    # optional axis exactly like the explicit null that model validation
    # materializes, and never mutates the caller's dict.
    omitted["semantic_digest"] = compute_chain_semantic_digest(omitted)
    assert "laaf" not in omitted["taxonomy_context"]
    assert omitted["semantic_digest"] == explicit["semantic_digest"]
    pattern = validate_attack_pattern(
        {**pattern_data(), "canonical_chain": omitted}, atlas_only_resolver()
    )
    assert pattern.canonical_chain.taxonomy_context.laaf is None


@pytest.mark.parametrize(
    "scope,decision",
    [
        ("chain", "exact"),
        ("chain", "unmapped"),
        ("step_attacker", "exact"),
        ("step_attacker", "unmapped"),
        ("step_system", "not_applicable"),
    ],
)
def test_laaf_decisions_fail_closed_without_a_pin(scope: str, decision: str) -> None:
    raw = atlas_only_chain_data()
    mapping: dict[str, Any] = {"decision": decision, "taxonomy": "LAAF"}
    if decision == "exact":
        mapping["ids"] = ["L1"]
    elif decision == "unmapped":
        mapping["rationale"] = "Legacy migration hint only."
    if scope == "chain":
        raw["mappings"].append(mapping)
    elif scope == "step_attacker":
        raw["steps"][0]["mappings"] = [mapping]
    else:
        raw["steps"][1]["mappings"] = [mapping]
    resign_chain(raw)
    with pytest.raises(ValidationError, match="LAAF taxonomy pin"):
        CanonicalAttackChain.model_validate(raw)
    pattern_raw = {**pattern_data(), "canonical_chain": raw}
    with pytest.raises(ValueError, match="LAAF taxonomy pin"):
        validate_attack_pattern(pattern_raw, atlas_only_resolver())


def laaf_pinned_chain_data(laaf_ids: list[str]) -> dict[str, Any]:
    """Chain variant with an explicit LAAF pin and an exact LAAF mapping."""
    raw = chain_data()
    raw["mappings"].append({"decision": "exact", "taxonomy": "LAAF", "ids": laaf_ids})
    return resign_chain(raw)


def laaf_pinned_pattern_data(laaf_ids: list[str]) -> dict[str, Any]:
    return {**pattern_data(), "canonical_chain": laaf_pinned_chain_data(laaf_ids)}


def laaf_pinned_context() -> Any:
    return CanonicalAttackChain.model_validate(
        laaf_pinned_chain_data(["L1"])
    ).taxonomy_context


def test_explicit_laaf_pin_and_membership_qualifies() -> None:
    context = laaf_pinned_context()
    resolver = MembershipResolver(context, {("ATLAS", "AML.T0001"), ("LAAF", "L1")})
    assert validate_attack_pattern(laaf_pinned_pattern_data(["L1"]), resolver)


def test_exact_laaf_id_outside_explicit_membership_fails() -> None:
    context = laaf_pinned_context()
    resolver = MembershipResolver(context, {("ATLAS", "AML.T0001"), ("LAAF", "L2")})
    with pytest.raises(ValueError, match="unknown LAAF id"):
        validate_attack_pattern(laaf_pinned_pattern_data(["L1"]), resolver)


def test_mismatched_laaf_pin_fails_and_atlas_only_resolver_rejects_pin() -> None:
    context = laaf_pinned_context()
    assert context.laaf is not None
    mismatched = context.model_copy(
        update={"laaf": context.laaf.model_copy(update={"digest": ZERO})}
    )
    resolver = MembershipResolver(mismatched, {("ATLAS", "AML.T0001"), ("LAAF", "L1")})
    with pytest.raises(ValueError, match="pins"):
        validate_attack_pattern(laaf_pinned_pattern_data(["L1"]), resolver)
    # An ATLAS-only resolver can never accept an explicit chain LAAF pin:
    # taxonomy_context equality stays meaningful across the optional axis.
    atlas_only = MembershipResolver(
        context.model_copy(update={"laaf": None}),
        {("ATLAS", "AML.T0001"), ("LAAF", "L1")},
    )
    with pytest.raises(ValueError, match="pins"):
        validate_attack_pattern(laaf_pinned_pattern_data(["L1"]), atlas_only)


def test_condition_ast_stays_discriminated_and_bounded() -> None:
    adapter = TypeAdapter(Condition)
    assert adapter.validate_python(equality()).op == "equality"
    with pytest.raises(ValidationError):
        adapter.validate_python(
            {"op": "all", "schema_version": "1", "operands": [equality()]}
        )
    nested = equality()
    for _ in range(4):
        nested = {"op": "not", "schema_version": "1", "operand": nested}
    with pytest.raises(ValidationError, match="structural limits"):
        adapter.validate_python(nested)


def test_duplicate_condition_operands_rejected() -> None:
    """Composite operands must be pairwise distinct."""
    adapter = TypeAdapter(Condition)
    with pytest.raises(ValidationError, match="duplicate condition operands"):
        adapter.validate_python(
            {
                "op": "all",
                "schema_version": "1",
                "operands": [equality(), equality()],
            }
        )
    adapter.validate_python(
        {
            "op": "all",
            "schema_version": "1",
            "operands": [equality(), equality_variant()],
        }
    )


def equality_variant() -> dict[str, Any]:
    return {
        "op": "equality",
        "schema_version": "1",
        "fact": {**fact(), "fact_id": "enabled", "value_type": "boolean"},
        "value": True,
    }


def test_membership_condition_value_branches() -> None:
    """Membership values match the fact type and stay unique."""
    adapter = TypeAdapter(Condition)
    valid = adapter.validate_python(
        {
            "op": "membership",
            "schema_version": "1",
            "fact": fact(),
            "values": ["active", "draining"],
        }
    )
    assert valid.op == "membership"
    with pytest.raises(ValidationError, match="membership values must be unique"):
        adapter.validate_python(
            {
                "op": "membership",
                "schema_version": "1",
                "fact": fact(),
                "values": ["active", "active"],
            }
        )
    with pytest.raises(ValidationError, match="exactly match"):
        adapter.validate_python(
            {
                "op": "membership",
                "schema_version": "1",
                "fact": fact(),
                "values": [1, 2],
            }
        )


def test_normalize_accepts_model_instances() -> None:
    """Canonicalization handles model instances and their python dumps alike."""
    chain = CanonicalAttackChain.model_validate(chain_data())
    assert _canonical_json(chain) == _canonical_json(chain.model_dump(mode="python"))


@pytest.mark.parametrize(
    "mutation",
    [
        lambda p: p.update(extra=True),
        lambda p: p.pop("canonical_chain"),
        lambda p: p["canonical_chain"]["steps"][0].pop("executor_role"),
        lambda p: p["canonical_chain"]["steps"][0]["produced"][0].update(
            kind="invented"
        ),
        lambda p: p["canonical_chain"].update(semantic_revision="1"),
    ],
)
def test_generated_schema_structural_negative_parity(mutation: Any) -> None:
    raw = pattern_data()
    mutation(raw)
    if "canonical_chain" in raw:
        resign_chain(raw["canonical_chain"])
    with pytest.raises(ValidationError):
        AttackPattern.model_validate(raw)
    assert not Draft202012Validator(AttackPattern.model_json_schema()).is_valid(raw)


# ---------------------------------------------------------------------------
# Adversarial canonical-linkage tests (422o.3.1)
# ---------------------------------------------------------------------------


def _link_chain() -> dict[str, Any]:
    """Chain with explicit linkage for adversarial mutation tests."""
    raw = chain_data()
    # chain_data already has resource_links and observable_outcome_links
    # from the updated step() helper.
    return raw


def test_dangling_resource_link_fails_closed() -> None:
    """A resource link referencing an absent slot must fail validation."""
    raw = _link_chain()
    raw["steps"][0]["resource_links"] = [
        {"slot_id": "nonexistent", "role": "ingress", "trust_boundary_slot_id": None}
    ]
    resign_chain(raw)
    with pytest.raises(ValidationError, match="absent slot nonexistent"):
        AttackPattern.model_validate({**pattern_data(), "canonical_chain": raw})


def test_dangling_observable_outcome_link_fails_closed() -> None:
    """An observable outcome link referencing an absent binding slot fails."""
    raw = _link_chain()
    raw["steps"][0]["observable_outcome_links"] = [
        {
            "postcondition_id": "post.1",
            "observation": "model_context",
            "binding_slot_id": "nonexistent",
        }
    ]
    resign_chain(raw)
    with pytest.raises(ValidationError, match="absent slot nonexistent"):
        AttackPattern.model_validate({**pattern_data(), "canonical_chain": raw})


def test_dangling_outcome_postcondition_fails_closed() -> None:
    """An outcome link referencing an absent postcondition fails at step scope."""
    raw = _link_chain()
    raw["steps"][0]["observable_outcome_links"] = [
        {
            "postcondition_id": "post.nonexistent",
            "observation": "model_context",
            "binding_slot_id": "ingress",
        }
    ]
    resign_chain(raw)
    with pytest.raises(ValidationError, match="absent postcondition"):
        AttackPattern.model_validate({**pattern_data(), "canonical_chain": raw})


def test_duplicate_resource_links_fail_closed() -> None:
    """Duplicate resource link slot_ids within a step fail validation."""
    raw = _link_chain()
    raw["steps"][0]["resource_links"] = [
        {"slot_id": "ingress", "role": "ingress", "trust_boundary_slot_id": None},
        {"slot_id": "ingress", "role": "ingress", "trust_boundary_slot_id": None},
    ]
    resign_chain(raw)
    with pytest.raises(ValidationError, match="duplicate ids in resource links"):
        AttackPattern.model_validate({**pattern_data(), "canonical_chain": raw})


def test_duplicate_observable_outcome_links_fail_closed() -> None:
    """Duplicate observable outcome links within a step fail validation."""
    raw = _link_chain()
    raw["steps"][0]["observable_outcome_links"] = [
        {
            "postcondition_id": "post.1",
            "observation": "model_context",
            "binding_slot_id": "ingress",
        },
        {
            "postcondition_id": "post.1",
            "observation": "model_context",
            "binding_slot_id": "ingress",
        },
    ]
    resign_chain(raw)
    with pytest.raises(ValidationError, match="duplicate observable outcome links"):
        AttackPattern.model_validate({**pattern_data(), "canonical_chain": raw})


def test_backward_ingress_link_on_outside_step_fails_closed() -> None:
    """An ingress link on a step at 'outside' boundary fails validation."""
    raw = _link_chain()
    # Step 1 is attacker=True → boundary_position='crossing'.
    # Change it to 'outside' to make the ingress link backward.  Clear
    # outcome links first so the chain-level ingress-on-outside check fires
    # rather than the step-level outside-step outcome link prohibition.
    raw["steps"][0]["boundary_position"] = "outside"
    raw["steps"][0]["observable_outcome_links"] = []
    resign_chain(raw)
    with pytest.raises(ValidationError, match="crossing or inside boundary"):
        AttackPattern.model_validate({**pattern_data(), "canonical_chain": raw})


def test_contradictory_tool_fixture_link_to_non_tool_slot_fails_closed() -> None:
    """A tool_fixture link referencing a non-tool slot fails validation."""
    raw = _link_chain()
    raw["steps"][0]["resource_links"] = [
        {"slot_id": "ingress", "role": "tool_fixture", "trust_boundary_slot_id": None}
    ]
    resign_chain(raw)
    with pytest.raises(
        ValidationError, match="tool_fixture link must reference a tool"
    ):
        AttackPattern.model_validate({**pattern_data(), "canonical_chain": raw})


def test_contradictory_ingress_link_to_non_ingress_slot_fails_closed() -> None:
    """An ingress link to a slot that is not the initial ingress fails."""
    raw = _link_chain()
    raw["steps"][0]["resource_links"] = [
        {"slot_id": "tool", "role": "ingress", "trust_boundary_slot_id": None}
    ]
    resign_chain(raw)
    with pytest.raises(
        ValidationError, match="ingress link must reference the initial"
    ):
        AttackPattern.model_validate({**pattern_data(), "canonical_chain": raw})


def test_source_influence_without_trust_boundary_fails_closed() -> None:
    """A source_influence link without a trust_boundary_slot_id fails."""
    raw = _link_chain()
    raw["steps"][1]["resource_links"] = [
        {
            "slot_id": "source",
            "role": "source_influence",
            "trust_boundary_slot_id": None,
        }
    ]
    resign_chain(raw)
    with pytest.raises(
        ValidationError, match="source_influence.*requires a trust_boundary_slot_id"
    ):
        AttackPattern.model_validate({**pattern_data(), "canonical_chain": raw})


def test_source_influence_with_trust_boundary_on_wrong_role_fails_closed() -> None:
    """A trust_boundary_slot_id on a non-source_influence link fails."""
    raw = _link_chain()
    raw["steps"][0]["resource_links"] = [
        {
            "slot_id": "ingress",
            "role": "ingress",
            "trust_boundary_slot_id": "boundary",
        }
    ]
    resign_chain(raw)
    with pytest.raises(
        ValidationError,
        match="trust_boundary_slot_id is only valid for source_influence",
    ):
        AttackPattern.model_validate({**pattern_data(), "canonical_chain": raw})


def test_observable_outcome_wrong_slot_kind_fails_closed() -> None:
    """An observable outcome link with wrong binding slot kind fails."""
    raw = _link_chain()
    # model_context requires an entry_point slot; 'tool' is not entry_point.
    raw["steps"][0]["observable_outcome_links"] = [
        {
            "postcondition_id": "post.1",
            "observation": "model_context",
            "binding_slot_id": "tool",
        }
    ]
    resign_chain(raw)
    with pytest.raises(ValidationError, match="requires a entry_point slot"):
        AttackPattern.model_validate({**pattern_data(), "canonical_chain": raw})


def test_absent_ingress_link_validates_but_unsupported() -> None:
    """A chain with no ingress link validates at model level (structurally
    valid) but is candidate-v2-infeasible: the projection fails closed with
    a typed unsupported-activation issue rather than a model ValidationError.
    """
    raw = _link_chain()
    raw["steps"][0]["resource_links"] = []
    resign_chain(raw)
    # Model validation succeeds: absence of activation is not a structural
    # defect, only a candidate-v2 feasibility defect.
    pattern = AttackPattern.model_validate({**pattern_data(), "canonical_chain": raw})
    assert pattern.canonical_chain.steps[0].resource_links == ()


def test_unsupported_observation_kind_fails_closed() -> None:
    """An unsupported observation kind literal fails schema validation."""
    raw = _link_chain()
    raw["steps"][0]["observable_outcome_links"] = [
        {
            "postcondition_id": "post.1",
            "observation": "unsupported_kind",
            "binding_slot_id": "ingress",
        }
    ]
    resign_chain(raw)
    with pytest.raises(ValidationError):
        AttackPattern.model_validate({**pattern_data(), "canonical_chain": raw})


def test_source_influence_without_target_ingress_fails_closed() -> None:
    """A source_influence link without a target_ingress_slot_id fails."""
    raw = _link_chain()
    raw["steps"][0]["resource_links"] = []
    raw["steps"][1]["resource_links"] = [
        {
            "slot_id": "source",
            "role": "source_influence",
            "trust_boundary_slot_id": "boundary",
            "target_ingress_slot_id": None,
        }
    ]
    resign_chain(raw)
    with pytest.raises(
        ValidationError, match="source_influence.*requires a target_ingress_slot_id"
    ):
        AttackPattern.model_validate({**pattern_data(), "canonical_chain": raw})


def test_source_influence_target_ingress_not_initial_ingress_fails_closed() -> None:
    """A source_influence link whose target is not the initial ingress fails."""
    raw = _link_chain()
    raw["steps"][0]["resource_links"] = []
    # Step 2 is conditional in the fixture; activation links require a
    # required step, so make it required before adding the link.
    raw["steps"][1]["requirement"] = "required"
    raw["steps"][1]["condition"] = None
    # 'tool' is a declared slot but not the initial ingress entry point.
    raw["steps"][1]["resource_links"] = [
        {
            "slot_id": "source",
            "role": "source_influence",
            "trust_boundary_slot_id": "boundary",
            "target_ingress_slot_id": "tool",
        }
    ]
    resign_chain(raw)
    with pytest.raises(
        ValidationError, match="target_ingress_slot_id must reference the initial"
    ):
        AttackPattern.model_validate({**pattern_data(), "canonical_chain": raw})


def test_source_influence_on_outside_step_fails_closed() -> None:
    """A source_influence link on an outside (no-crossing) step fails."""
    raw = _link_chain()
    raw["steps"][0]["resource_links"] = []
    # Step 2 is conditional in the fixture; activation links require a
    # required step, so make it required before adding the link.
    raw["steps"][1]["requirement"] = "required"
    raw["steps"][1]["condition"] = None
    # Force it to 'outside' to break the boundary compatibility of the
    # source-influence crossing.  Clear outcome links so the outside-step
    # outcome link prohibition doesn't fire first.
    raw["steps"][1]["boundary_position"] = "outside"
    raw["steps"][1]["observable_outcome_links"] = []
    raw["steps"][1]["resource_links"] = [
        {
            "slot_id": "source",
            "role": "source_influence",
            "trust_boundary_slot_id": "boundary",
            "target_ingress_slot_id": "ingress",
        }
    ]
    resign_chain(raw)
    with pytest.raises(
        ValidationError, match="source_influence link requires a crossing or inside"
    ):
        AttackPattern.model_validate({**pattern_data(), "canonical_chain": raw})


def test_both_ingress_and_source_influence_fails_closed() -> None:
    """A chain carrying both a direct ingress link and a source_influence
    link to the initial ingress violates the one-mechanism rule."""
    raw = _link_chain()
    # Step 2 is conditional in the fixture; activation links require a
    # required step, so make it required before adding the link.
    raw["steps"][1]["requirement"] = "required"
    raw["steps"][1]["condition"] = None
    raw["steps"][1]["resource_links"] = [
        {
            "slot_id": "source",
            "role": "source_influence",
            "trust_boundary_slot_id": "boundary",
            "target_ingress_slot_id": "ingress",
        }
    ]
    resign_chain(raw)
    with pytest.raises(
        ValidationError, match="exactly one activation mechanism is permitted"
    ):
        AttackPattern.model_validate({**pattern_data(), "canonical_chain": raw})


def test_no_activation_link_fails_closed() -> None:
    """A chain with neither an ingress nor a source_influence link to the
    initial ingress is structurally valid but candidate-v2-infeasible:
    the projection fails closed with a typed unsupported-activation issue."""
    raw = _link_chain()
    raw["steps"][0]["resource_links"] = []
    resign_chain(raw)
    # Model validation succeeds: absence of activation is not a structural
    # defect, only a candidate-v2 feasibility defect.
    pattern = AttackPattern.model_validate({**pattern_data(), "canonical_chain": raw})
    assert pattern.canonical_chain.steps[0].resource_links == ()


# ---------------------------------------------------------------------------
# Adversarial tests: omitted vs explicit-empty link arrays and immutability
# ---------------------------------------------------------------------------


def test_omitted_link_arrays_sign_like_explicit_empty() -> None:
    """A raw dict that omits ``resource_links`` and ``observable_outcome_links``
    must produce the same digest as one with explicit empty lists.  The digest
    helper canonicalizes omitted arrays to ``[]`` without mutating the caller's
    dict.  Both forms must validate when the chain is otherwise valid."""
    base = _link_chain()
    # Test on step 1 (which has links) and step 2 (no links): omit the arrays
    # on step 2 and compare against explicit empty.
    explicit_empty = deepcopy(base)
    explicit_empty["steps"][1]["resource_links"] = []
    explicit_empty["steps"][1]["observable_outcome_links"] = []
    explicit_empty["semantic_digest"] = compute_chain_semantic_digest(explicit_empty)

    omitted = deepcopy(base)
    omitted["steps"][1].pop("resource_links", None)
    omitted["steps"][1].pop("observable_outcome_links", None)
    omitted["semantic_digest"] = compute_chain_semantic_digest(omitted)

    # Both must produce the same digest.
    assert omitted["semantic_digest"] == explicit_empty["semantic_digest"]

    # The omitted-arrays dict must not have been mutated.
    assert "resource_links" not in omitted["steps"][1]
    assert "observable_outcome_links" not in omitted["steps"][1]

    # Both must validate (step 1 retains its links, terminal step retains its
    # outcome link; only step 2's omitted/empty arrays differ).
    pattern_omitted = AttackPattern.model_validate(
        {**pattern_data(), "canonical_chain": omitted}
    )
    pattern_explicit = AttackPattern.model_validate(
        {**pattern_data(), "canonical_chain": explicit_empty}
    )
    assert (
        pattern_omitted.canonical_chain.semantic_digest
        == pattern_explicit.canonical_chain.semantic_digest
    )


def test_digest_helper_does_not_mutate_input() -> None:
    """compute_chain_semantic_digest must never mutate the caller's dict,
    even when it canonicalizes omitted link arrays."""
    raw = _link_chain()
    # Remove link arrays from step 2 only (step 1 and 3 retain theirs).
    raw["steps"][1].pop("resource_links", None)
    raw["steps"][1].pop("observable_outcome_links", None)
    snapshot = deepcopy(raw)
    _ = compute_chain_semantic_digest(raw)
    # The input must be unchanged.
    assert raw == snapshot
    assert "resource_links" not in raw["steps"][1]
    assert "observable_outcome_links" not in raw["steps"][1]


def test_conditional_step_with_activation_link_fails_closed() -> None:
    """An activation link (ingress or source_influence) on a conditional step
    fails validation: activation must be deterministic, and conditional steps
    may be omitted by condition evaluation."""
    raw = _link_chain()
    # Step 2 is conditional; add an ingress link to it.
    raw["steps"][1]["resource_links"] = [
        {"slot_id": "ingress", "role": "ingress", "trust_boundary_slot_id": None}
    ]
    resign_chain(raw)
    with pytest.raises(ValidationError, match="conditional and must not"):
        AttackPattern.model_validate({**pattern_data(), "canonical_chain": raw})


def test_same_postcondition_two_outcome_links_fails_closed() -> None:
    """Two outcome links for the same postcondition on a step fail validation,
    even if the observation or binding differs — the requirement IDs would
    collide."""
    raw = _link_chain()
    raw["steps"][0]["observable_outcome_links"] = [
        {
            "postcondition_id": "post.1",
            "observation": "model_context",
            "binding_slot_id": "ingress",
        },
        {
            "postcondition_id": "post.1",
            "observation": "persistent_state",
            "binding_slot_id": "source",
        },
    ]
    resign_chain(raw)
    with pytest.raises(
        ValidationError, match="duplicate observable outcome links for the same"
    ):
        AttackPattern.model_validate({**pattern_data(), "canonical_chain": raw})


# ---------------------------------------------------------------------------
# Chain-wide activation uniqueness (second independent review)
# ---------------------------------------------------------------------------


def test_two_direct_ingress_links_fail_closed() -> None:
    """Two required steps each carrying an ingress link to the initial
    ingress slot must fail validation: at most one chain-wide activation
    link is permitted."""
    raw = _link_chain()
    # Step 2 is conditional in the fixture; make it required and add
    # a second ingress link.
    raw["steps"][1]["requirement"] = "required"
    raw["steps"][1]["condition"] = None
    raw["steps"][1]["resource_links"] = [
        {
            "slot_id": "ingress",
            "role": "ingress",
            "trust_boundary_slot_id": None,
            "target_ingress_slot_id": None,
        }
    ]
    resign_chain(raw)
    with pytest.raises(ValidationError, match="at most one"):
        AttackPattern.model_validate({**pattern_data(), "canonical_chain": raw})


def test_two_source_influence_links_fail_closed() -> None:
    """Two required steps each carrying a source_influence link to the
    initial ingress slot must fail validation: at most one chain-wide
    activation link is permitted."""
    raw = _link_chain()
    # Remove the ingress link from step 1; add source_influence to step 1 and step 2.
    raw["steps"][0]["resource_links"] = [
        {
            "slot_id": "source",
            "role": "source_influence",
            "trust_boundary_slot_id": "boundary",
            "target_ingress_slot_id": "ingress",
        }
    ]
    raw["steps"][1]["requirement"] = "required"
    raw["steps"][1]["condition"] = None
    raw["steps"][1]["resource_links"] = [
        {
            "slot_id": "source",
            "role": "source_influence",
            "trust_boundary_slot_id": "boundary",
            "target_ingress_slot_id": "ingress",
        }
    ]
    resign_chain(raw)
    with pytest.raises(ValidationError, match="at most one"):
        AttackPattern.model_validate({**pattern_data(), "canonical_chain": raw})


def test_direct_plus_source_influence_fail_closed() -> None:
    """A chain with both a direct ingress link and a source_influence link
    must fail validation: exactly one activation mechanism is permitted."""
    raw = _link_chain()
    # Step 1 already has the ingress link; add source_influence to step 2.
    raw["steps"][1]["requirement"] = "required"
    raw["steps"][1]["condition"] = None
    raw["steps"][1]["resource_links"] = [
        {
            "slot_id": "source",
            "role": "source_influence",
            "trust_boundary_slot_id": "boundary",
            "target_ingress_slot_id": "ingress",
        }
    ]
    resign_chain(raw)
    with pytest.raises(
        ValidationError, match="exactly one activation mechanism is permitted"
    ):
        AttackPattern.model_validate({**pattern_data(), "canonical_chain": raw})


# ---------------------------------------------------------------------------
# New observation/slot vocabulary: rendered_output, endpoint_receipt,
# agent_state / agent_internal — positive and negative compatibility tests.
# ---------------------------------------------------------------------------


def test_rendered_output_observation_requires_output_surface_slot() -> None:
    """rendered_output observation kind requires an output_surface slot."""
    raw = _link_chain()
    # Add an output_surface slot.
    raw["resource_slots"].append(
        {"slot_id": "output", "kind": "output_surface", "purpose": "intermediate"}
    )
    raw["steps"][0]["observable_outcome_links"] = [
        {
            "postcondition_id": "post.1",
            "observation": "rendered_output",
            "binding_slot_id": "output",
        }
    ]
    resign_chain(raw)
    AttackPattern.model_validate({**pattern_data(), "canonical_chain": raw})


def test_rendered_output_observation_rejects_entry_point_slot() -> None:
    """rendered_output observation kind must not bind to an entry_point slot."""
    raw = _link_chain()
    raw["steps"][0]["observable_outcome_links"] = [
        {
            "postcondition_id": "post.1",
            "observation": "rendered_output",
            "binding_slot_id": "ingress",
        }
    ]
    resign_chain(raw)
    with pytest.raises(
        ValidationError, match="rendered_output requires a output_surface slot"
    ):
        AttackPattern.model_validate({**pattern_data(), "canonical_chain": raw})


def test_endpoint_receipt_observation_requires_integration_slot() -> None:
    """endpoint_receipt observation kind requires an integration slot."""
    raw = _link_chain()
    raw["steps"][0]["observable_outcome_links"] = [
        {
            "postcondition_id": "post.1",
            "observation": "endpoint_receipt",
            "binding_slot_id": "source",
        }
    ]
    resign_chain(raw)
    AttackPattern.model_validate({**pattern_data(), "canonical_chain": raw})


def test_endpoint_receipt_observation_rejects_entry_point_slot() -> None:
    """endpoint_receipt observation kind must not bind to an entry_point slot."""
    raw = _link_chain()
    raw["steps"][0]["observable_outcome_links"] = [
        {
            "postcondition_id": "post.1",
            "observation": "endpoint_receipt",
            "binding_slot_id": "ingress",
        }
    ]
    resign_chain(raw)
    with pytest.raises(
        ValidationError, match="endpoint_receipt requires a integration slot"
    ):
        AttackPattern.model_validate({**pattern_data(), "canonical_chain": raw})


def test_agent_state_observation_requires_agent_internal_slot() -> None:
    """agent_state observation kind requires an agent_internal slot."""
    raw = _link_chain()
    raw["resource_slots"].append(
        {"slot_id": "internal", "kind": "agent_internal", "purpose": "intermediate"}
    )
    raw["steps"][0]["observable_outcome_links"] = [
        {
            "postcondition_id": "post.1",
            "observation": "agent_state",
            "binding_slot_id": "internal",
        }
    ]
    resign_chain(raw)
    AttackPattern.model_validate({**pattern_data(), "canonical_chain": raw})


def test_agent_state_observation_rejects_entry_point_slot() -> None:
    """agent_state observation kind must not bind to an entry_point slot.

    This prevents the nearest-fit error of binding agent-internal state
    to an input ingress.
    """
    raw = _link_chain()
    raw["steps"][0]["observable_outcome_links"] = [
        {
            "postcondition_id": "post.1",
            "observation": "agent_state",
            "binding_slot_id": "ingress",
        }
    ]
    resign_chain(raw)
    with pytest.raises(
        ValidationError, match="agent_state requires a agent_internal slot"
    ):
        AttackPattern.model_validate({**pattern_data(), "canonical_chain": raw})


def test_agent_state_observation_rejects_integration_slot() -> None:
    """agent_state observation kind must not bind to an integration slot."""
    raw = _link_chain()
    raw["steps"][0]["observable_outcome_links"] = [
        {
            "postcondition_id": "post.1",
            "observation": "agent_state",
            "binding_slot_id": "source",
        }
    ]
    resign_chain(raw)
    with pytest.raises(
        ValidationError, match="agent_state requires a agent_internal slot"
    ):
        AttackPattern.model_validate({**pattern_data(), "canonical_chain": raw})
