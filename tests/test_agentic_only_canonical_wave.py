"""Wave test for the agentic-only canonical-chain migration (asago-scenario-generator-422o.2.6).

Covers only data/taxonomies/attack-patterns/attack-patterns-agentic-only.yaml:
the T8/T9/T10/T14/T16 records migrated per catalog-lineage.yaml. Mapping and
resource-slot expectations are derived from the lineage artifact where it
remains authoritative; records corrected during exact-head semantic review
(AP-T9-07, AP-T16-03) carry explicit, tested lineage deltas instead.
Shared catalog-wide contracts (merged loader shape, legacy isolation) are
owned by other tests and are intentionally not re-asserted here.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml
from pydantic import TypeAdapter

from asago_scenario_generator.data.loaders import load_attack_patterns
from asago_scenario_generator.data.taxonomy_pins import load_taxonomy_resolver
from asago_scenario_generator.models.attack_pattern import (
    AttackPattern,
    Condition,
    EvaluatedFactEvidence,
    compute_chain_semantic_digest,
    evaluate_condition,
    validate_attack_pattern,
)

AP_DIR = Path(__file__).resolve().parents[1] / "data" / "taxonomies" / "attack-patterns"
AGENTIC_ONLY_PATH = AP_DIR / "attack-patterns-agentic-only.yaml"

RESULTING_IDS = {
    "AP-T10-01",
    "AP-T16-02",
    "AP-T16-03",
    "AP-T8-01",
    "AP-T9-01",
    "AP-T9-02",
    "AP-T9-07",
    "AP-T9-05",
    "AP-T9-06",
}

DEFERRED_SOURCE_IDS = {
    "AP-T8-02",
    "AP-T8-03",
    "AP-T9-03",
    "AP-T9-04",
    "AP-T10-02",
    "AP-T10-03",
    "AP-T14-01",
    "AP-T14-02",
    "AP-T14-03",
    "AP-T14-04",
    "AP-T16-01",
}

EXPECTED_TERMINAL_TIERS = {
    "AP-T8-01": ("record_divergence_outcome", "inferred"),
    "AP-T9-05": ("false_attribution_recorded", "variant"),
    "AP-T9-06": ("sustained_takeover_observed", "inferred"),
    "AP-T9-07": ("destroy_agent_data", "inferred"),
    "AP-T10-01": ("approve_malicious_actions", "variant"),
    "AP-T16-02": ("context_hijacking_impact", "variant"),
    "AP-T16-03": ("false_scope_impact", "variant"),
}

S_CITATION = re.compile(r"\bS\d{2}\b")


@pytest.fixture(scope="module")
def raw_records() -> dict[str, dict]:
    return load_attack_patterns(AGENTIC_ONLY_PATH)


@pytest.fixture(scope="module")
def resolver():
    return load_taxonomy_resolver()


@pytest.fixture(scope="module")
def validated(raw_records, resolver) -> dict[str, AttackPattern]:
    return {
        pid: validate_attack_pattern(record, resolver)
        for pid, record in raw_records.items()
    }


def _step_exact(pattern: AttackPattern) -> dict[str, str]:
    out = {}
    for step in pattern.canonical_chain.steps:
        for mapping in step.mappings:
            if mapping.decision == "exact":
                assert len(mapping.ids) == 1
                out[step.step_id] = mapping.ids[0]
    return out


def test_exact_resulting_id_set_and_no_deferred_live(raw_records) -> None:
    assert set(raw_records) == RESULTING_IDS
    assert DEFERRED_SOURCE_IDS.isdisjoint(raw_records)
    # T14 has no resulting records and no T8/T14 construct was forced beyond
    # the lineage outcomes.
    assert not any(pid.startswith("AP-T14-") for pid in raw_records)


def test_records_are_canonical_not_legacy(raw_records) -> None:
    for pid, record in raw_records.items():
        assert record["id"] == pid
        assert "kill_chain" not in record
        chain = record["canonical_chain"]
        assert chain["schema_version"] == "v1"
        assert chain["pattern_id"] == pid


def test_all_records_validate_against_pinned_resolver(validated) -> None:
    assert set(validated) == RESULTING_IDS


def test_chains_are_branch_free_total_order(validated) -> None:
    for pattern in validated.values():
        steps = pattern.canonical_chain.steps
        assert [s.order for s in steps] == list(range(1, len(steps) + 1))
        assert len({s.step_id for s in steps}) == len(steps)
        assert (
            pattern.canonical_chain.earliest_attacker_controlled_step_id
            == steps[0].step_id
        )
        assert steps[0].attacker_controlled


def test_semantic_digests_match_chain_semantics(validated) -> None:
    for pattern in validated.values():
        chain = pattern.canonical_chain
        assert chain.semantic_digest == compute_chain_semantic_digest(chain)


def test_taxonomy_context_pins_match_production(validated, resolver) -> None:
    pin = resolver.taxonomy_context
    for pattern in validated.values():
        ctx = pattern.canonical_chain.taxonomy_context
        assert ctx.atlas.release == pin.atlas.release
        assert ctx.atlas.digest == pin.atlas.digest
        assert ctx.laaf is None
        assert ctx.mapping_set_digest == pin.mapping_set_digest


def test_role_sensitive_mapping_rule(validated) -> None:
    for pattern in validated.values():
        for step in pattern.canonical_chain.steps:
            decisions = [m.decision for m in step.mappings]
            if step.attacker_controlled:
                assert step.executor_role == "attacker"
                assert all(d in ("exact", "unmapped") for d in decisions)
            else:
                assert step.executor_role in ("system", "operator")
                assert all(d == "not_applicable" for d in decisions)


def test_unmapped_decisions_carry_rationale(validated) -> None:
    found_unmapped = False
    for pid, pattern in validated.items():
        scopes = [pattern.canonical_chain.mappings] + [
            s.mappings for s in pattern.canonical_chain.steps
        ]
        for mappings in scopes:
            for mapping in mappings:
                if mapping.decision == "unmapped":
                    found_unmapped = True
                    assert mapping.rationale.strip(), pid
    assert found_unmapped


def test_causal_graph_backward_and_forward_reachable(validated) -> None:
    for pid, pattern in validated.items():
        steps = pattern.canonical_chain.steps
        produced_by: dict[str, int] = {}
        for step in steps:
            for out in step.produced:
                assert out.ref_id not in produced_by, (pid, out.ref_id)
                produced_by[out.ref_id] = step.order
        consumed: dict[str, list[int]] = {}
        for step in steps:
            for ref in step.consumed:
                # Backward reachability: every input is produced earlier.
                assert ref.ref_id in produced_by, (pid, step.step_id, ref.ref_id)
                assert produced_by[ref.ref_id] < step.order
                consumed.setdefault(ref.ref_id, []).append(step.order)
        final_order = steps[-1].order
        for step in steps:
            for out in step.produced:
                if out.kind == "effect":
                    # Effects are observable outcomes, never consumed.
                    assert out.ref_id not in consumed, (pid, out.ref_id)
                elif step.order != final_order:
                    # Forward reachability: no dangling artifact/state.
                    assert out.ref_id in consumed, (pid, out.ref_id)
        # The terminal step produces only observable effects.
        assert all(out.kind == "effect" for out in steps[-1].produced), pid


def test_conditions_actions_resources_are_typed(validated) -> None:
    for pattern in validated.values():
        chain = pattern.canonical_chain
        for step in chain.steps:
            assert step.action_kind in (
                "prepare",
                "deliver",
                "invoke",
                "transform",
                "persist",
                "observe",
                "impact",
            )
            assert (step.requirement == "conditional") == (step.condition is not None)
            for ref in step.consumed:
                assert ref.kind in ("artifact", "state")
            for ref in step.produced:
                assert ref.kind in ("artifact", "state", "effect")
            assert step.observable_postconditions
        ingress = [s for s in chain.resource_slots if s.purpose == "initial_ingress"]
        assert len(ingress) == 1
        assert ingress[0].slot_id == chain.initial_ingress_slot_id
        assert ingress[0].kind == "entry_point"


def test_provenance_honesty_rules(validated) -> None:
    for pid, pattern in validated.items():
        for step in pattern.canonical_chain.steps:
            prov = step.provenance
            assert prov.tier in ("observed", "variant", "inferred", "designed")
            assert 0 <= prov.confidence <= 100
            assert prov.references
            assert prov.adaptation_rationale.strip()
            if prov.tier == "observed":
                # Observed claims must cite case-study evidence and pin the
                # evidencing case step(s) in the rationale.
                case_refs = [
                    r.reference_id
                    for r in prov.references
                    if r.reference_type == "catalog"
                    and r.reference_id.startswith("AML.CS")
                ]
                assert case_refs, (pid, step.step_id)
                assert S_CITATION.search(prov.adaptation_rationale), (
                    pid,
                    step.step_id,
                )


def test_terminal_tiers_are_honest(validated) -> None:
    for pid, (step_id, tier) in EXPECTED_TERMINAL_TIERS.items():
        chain = validated[pid].canonical_chain
        terminal = chain.steps[-1]
        assert terminal.step_id == step_id
        assert any(
            pc.security_relevant and pc.terminal
            for pc in terminal.observable_postconditions
        )
        assert terminal.provenance.tier == tier, pid
        # Exactly one terminal step per chain: single mechanism per record.
        terminal_steps = [
            s.step_id
            for s in chain.steps
            if any(pc.terminal for pc in s.observable_postconditions)
        ]
        assert terminal_steps == [step_id], pid


def test_t907_single_data_destruction_mechanism(validated) -> None:
    pattern = validated["AP-T9-07"]
    chain = pattern.canonical_chain
    assert [s.step_id for s in chain.steps] == [
        "authenticate_as_agent",
        "destroy_agent_data",
    ]
    # The request-flood branch is fully removed: AML.T0029 appears in no
    # mapping decision (its remaining mentions are explanatory provenance
    # for the S11 definition-level retag, not mapping authority).
    all_mapping_ids = {
        technique_id
        for scope in (chain.mappings, *(s.mappings for s in chain.steps))
        for mapping in scope
        if mapping.decision == "exact"
        for technique_id in mapping.ids
    }
    assert "AML.T0029" not in all_mapping_ids
    destroy = chain.steps[-1]
    assert destroy.attacker_controlled
    assert destroy.observable_postconditions[0].terminal


def test_t1603_pure_deceptive_metadata_mechanism(validated) -> None:
    pattern = validated["AP-T16-03"]
    chain = pattern.canonical_chain
    assert [s.step_id for s in chain.steps] == [
        "craft_deceptive_descriptions",
        "alter_registry_metadata",
        "select_tool_under_false_scope",
        "invoke_tool_under_false_scope",
        "false_scope_impact",
    ]
    # No hidden-code supply-chain identities remain in any mapping decision
    # (remaining textual mentions are explicit non-claims in provenance
    # rationales, not mapping authority).
    all_mapping_ids = {
        technique_id
        for scope in (chain.mappings, *(s.mappings for s in chain.steps))
        for mapping in scope
        if mapping.decision == "exact"
        for technique_id in mapping.ids
    }
    for forbidden in ("AML.T0104", "AML.T0111", "AML.T0011.002"):
        assert forbidden not in all_mapping_ids
    for step in chain.steps:
        for marker in ("poisoned_tool", "install", "injection", "reputation"):
            assert marker not in step.step_id
    # The victim-side selection/invocation is honestly system-roled.
    for step_id in ("select_tool_under_false_scope", "invoke_tool_under_false_scope"):
        step = next(s for s in chain.steps if s.step_id == step_id)
        assert step.executor_role == "system"
        assert not step.attacker_controlled
        assert all(m.decision == "not_applicable" for m in step.mappings)
    # The alteration step carries the defensible exact identity.
    alter = chain.steps[1]
    assert alter.attacker_controlled
    assert [m.ids for m in alter.mappings if m.decision == "exact"] == [("AML.T0110",)]


def test_t1001_craft_obfuscate_before_delivery_no_conditional_persistence(
    validated,
) -> None:
    chain = validated["AP-T10-01"].canonical_chain
    ids = [s.step_id for s in chain.steps]
    assert "persist_in_content_store" not in ids
    assert all(s.condition is None for s in chain.steps)
    assert (
        ids.index("craft_misleading_context")
        < ids.index("obfuscate_malicious_content")
        < ids.index("deliver_crafted_content")
        < ids.index("activate_injection")
    )
    by_id = {s.step_id: s for s in chain.steps}
    assert [r.ref_id for r in by_id["obfuscate_malicious_content"].consumed] == [
        "payload.misleading_context"
    ]
    assert [r.ref_id for r in by_id["deliver_crafted_content"].consumed] == [
        "payload.obfuscated_context"
    ]
    # The conditional S13 payoff is downgraded from observed.
    terminal = chain.steps[-1]
    assert terminal.step_id == "approve_malicious_actions"
    assert terminal.provenance.tier == "variant"


def test_t905_sensitive_action_precedes_attribution_terminal(validated) -> None:
    chain = validated["AP-T9-05"].canonical_chain
    by_id = {s.step_id: s for s in chain.steps}
    action = by_id["perform_sensitive_action"]
    terminal = by_id["false_attribution_recorded"]
    assert action.order == terminal.order - 1
    assert action.attacker_controlled
    assert [r.ref_id for r in action.consumed] == ["auth.identity_granted"]
    assert [r.ref_id for r in action.produced] == ["action.sensitive_action_record"]
    assert [r.ref_id for r in terminal.consumed] == ["action.sensitive_action_record"]


def test_t906_future_session_activation_precedes_sustained_terminal(validated) -> None:
    chain = validated["AP-T9-06"].canonical_chain
    by_id = {s.step_id: s for s in chain.steps}
    activation = by_id["operate_in_future_session"]
    terminal = by_id["sustained_takeover_observed"]
    assert activation.order == terminal.order - 1
    assert activation.attacker_controlled
    assert [r.ref_id for r in terminal.consumed] == [
        "ops.future_session_operations",
        "activity.concealed",
    ]
    # Unsupported long-lived-token claims are downgraded from observed.
    extract = by_id["extract_long_lived_tokens"]
    post = extract.observable_postconditions[0].description
    assert "long-lived" not in post and "surviving" not in post
    assert [r.ref_id for r in extract.produced] == ["credential.stolen_token"]
    assert by_id["establish_persistent_access"].provenance.tier == "variant"


def test_t906_observed_steps_do_not_claim_token_lifetime(validated) -> None:
    """Observed S00-S01 establish host/process access, not token lifetime."""
    chain = validated["AP-T9-06"].canonical_chain
    by_id = {s.step_id: s for s in chain.steps}
    initial = by_id["initial_access"]
    assert initial.provenance.tier == "observed"
    initial_post = initial.observable_postconditions[0].description
    assert "long-lived" not in initial_post
    assert "agent credentials" in initial_post
    enum = by_id["enumerate_credential_stores"]
    assert enum.provenance.tier == "observed"
    enum_post = enum.observable_postconditions[0].description
    assert "long-lived" not in enum_post
    assert "authentication-token sources" in enum_post


def test_t906_cross_session_concealment_is_variant(validated) -> None:
    """Cross-session concealment is inferred, not observed: honestly variant."""
    chain = validated["AP-T9-06"].canonical_chain
    step = {s.step_id: s for s in chain.steps}["conceal_cross_session_activity"]
    assert step.provenance.tier == "variant"
    assert step.provenance.confidence is not None
    assert step.provenance.confidence < 90
    assert any(r.reference_id == "AML.CS0036" for r in step.provenance.references)
    rationale = step.provenance.adaptation_rationale
    assert "inferred" in rationale
    assert "across sessions" in rationale
    assert "S08" in rationale


def test_t801_start_is_credential_acquisition_only(validated) -> None:
    chain = validated["AP-T8-01"].canonical_chain
    start = chain.steps[0]
    assert start.step_id == "obtain_record_access"
    assert [m.ids for m in start.mappings if m.decision == "exact"] == [("AML.T0055",)]
    text = (
        start.observable_postconditions[0].description
        + start.provenance.adaptation_rationale
    )
    assert "interface access" not in text
    assert "credential" in text or "tokens" in text


def test_t1602_crafted_response_only_no_interception(validated) -> None:
    pattern = validated["AP-T16-02"]
    assert "crafts a server-side response" in pattern.description
    assert "or intercept" not in pattern.description
    assert "intercepts" not in pattern.description


def test_split_boundary_is_clean(validated) -> None:
    t902 = validated["AP-T9-02"].canonical_chain
    t907 = validated["AP-T9-07"].canonical_chain
    assert t902.steps[-1].step_id == "impersonated_operation_attributed"
    # AP-T9-02 owns immediate stolen-credential impersonation (theft and
    # thread-poisoning identities); AP-T9-07 owns the independent
    # data-destruction disruption and carries neither theft identity.
    assert _step_exact(validated["AP-T9-02"]) == {
        "extract_tokens": "AML.T0090",
        "poison_session_context": "AML.T0080.001",
    }
    t907_exact = {
        technique_id
        for scope in (t907.mappings, *(s.mappings for s in t907.steps))
        for mapping in scope
        if mapping.decision == "exact"
        for technique_id in mapping.ids
    }
    assert t907_exact == {"AML.T0101", "AML.T0091.000"}
    assert "AML.T0101" not in {
        technique_id
        for scope in (t902.mappings, *(s.mappings for s in t902.steps))
        for mapping in scope
        if mapping.decision == "exact"
        for technique_id in mapping.ids
    }


def test_t901_execution_precedes_attribution(validated) -> None:
    chain = validated["AP-T9-01"].canonical_chain
    ids = [s.step_id for s in chain.steps]
    assert ids.index("execute_delegated_actions") < ids.index(
        "attribution_recorded_for_user"
    )
    terminal = chain.steps[-1]
    assert [r.ref_id for r in terminal.consumed] == ["action.execution_record"]


def test_condition_evaluation_true_and_false_semantics() -> None:
    # The typed-condition contract: a profile-fact equality gate (the shape
    # the removed AP-T10-01 persistence condition used) evaluates to true on
    # matching evidence and false on contradicting/absent evidence.
    fact_raw = {
        "namespace": "profile",
        "fact_id": "has_persistent_memory",
        "value_type": "boolean",
        "property_path": [],
    }
    condition = TypeAdapter(Condition).validate_python(
        {"op": "equality", "schema_version": "1", "fact": fact_raw, "value": True}
    )

    def evidence(status: str, value=None) -> EvaluatedFactEvidence:
        return EvaluatedFactEvidence.model_validate(
            {"fact": fact_raw, "status": status, "value": value}
        )

    assert evaluate_condition(condition, (evidence("present", True),)) == "true"
    assert evaluate_condition(condition, (evidence("present", False),)) == "false"
    assert evaluate_condition(condition, (evidence("absent"),)) == "false"
    assert evaluate_condition(condition, (evidence("unknown"),)) == "unknown"
    negated = TypeAdapter(Condition).validate_python(
        {
            "op": "not",
            "schema_version": "1",
            "operand": condition.model_dump(mode="json"),
        }
    )
    assert evaluate_condition(negated, (evidence("present", True),)) == "false"
    assert evaluate_condition(negated, (evidence("present", False),)) == "true"


def test_file_header_metadata_is_canonical() -> None:
    data = yaml.safe_load(AGENTIC_ONLY_PATH.read_text())
    assert data["source"]["lineage"] == "catalog-lineage.yaml v1.0.0"
    assert (
        "MITRE ATLAS 2026.05 (sole v1 mapping authority)"
        in data["source"]["derived_from"]
    )
