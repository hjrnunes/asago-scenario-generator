"""Dedicated acceptance tests for the halluc-intent canonical-chain migration (422o.2.5).

Scope: ``data/taxonomies/attack-patterns/attack-patterns-halluc-intent.yaml`` only.

The file is migrated under the authoritative catalog-lineage dispositions for
its sixteen historical source records (AP-T5-01..04, AP-T6-01..05,
AP-T11-01..03, AP-T13-01..04): 5 retain, 7 narrow, 4 defer.  Deferred records
produce no live catalog record.  Each live record carries exactly one
branch-free, total-order canonical chain with typed artifact/state/effect
linkage, resource slots, per-step provenance tiers, and resolver-backed
ATLAS-only mapping decisions (LAAF absent; SSSOM ``skos:relatedMatch`` rows
are candidate provenance only).

Where the semantically honest chain diverges from the current lineage
artifact's mapping tables (AP-T11-01, AP-T11-02, AP-T6-02 after exact-head
semantic review), these tests pin the live authoritative sets.  They do not
read ``catalog-lineage.yaml``, so a change to the lineage record alone does
not fail them.

These tests are additive: they never mutate shared fixtures and never edit
other taxonomy files.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from asago_scenario_generator.data.loaders import load_attack_patterns
from asago_scenario_generator.data.taxonomy_pins import load_taxonomy_resolver
from asago_scenario_generator.models.attack_pattern import (
    compute_chain_semantic_digest,
    validate_attack_pattern,
    validate_legacy_attack_pattern,
)

AP_DIR = Path(__file__).resolve().parents[1] / "data" / "taxonomies" / "attack-patterns"
HALLUC_INTENT_PATH = AP_DIR / "attack-patterns-halluc-intent.yaml"
SSSOM_PATH = AP_DIR / "attack-patterns-halluc-intent.sssom.tsv"

# The authoritative resulting IDs, exactly.
EXPECTED_IDS = frozenset(
    {
        "AP-T11-01",
        "AP-T11-02",
        "AP-T11-03",
        "AP-T13-04",
        "AP-T5-01",
        "AP-T5-02",
        "AP-T5-04",
        "AP-T6-01",
        "AP-T6-02",
        "AP-T6-03",
        "AP-T6-04",
        "AP-T6-05",
    }
)

DEFERRED_SOURCES = frozenset({"AP-T5-03", "AP-T13-01", "AP-T13-02", "AP-T13-03"})

# Golden semantic digests: recompute-stable pins for the authored chains.
EXPECTED_DIGESTS = {
    "AP-T5-01": "3eeeed3fbe273c264078f0747c87f4e86bb8db5f2ac659bba28758844d8a1c7d",
    "AP-T5-02": "89be3fa9b853ab1b6d6da300d6543325063159e4f9eb4543ee7b5b2a237f9e2c",
    "AP-T5-04": "873c5b56a18eb516c27df9f565e00550f6986f8efe3e961c1c8f655a72383ad7",
    "AP-T6-01": "791bd845bdddca3d6b4adad4d172ff752d89c87c03ad7221109ec93b464911b9",
    "AP-T6-02": "e67e81b309d7a224fdbdb0da4d9c9c89c02d1b155369f8c2d3c37b899e2bffb7",
    "AP-T6-03": "baeee6c2a308348ce9dbb86ec3b11baab51d3d5dffb317116fb1384db1c4b966",
    "AP-T6-04": "a5f298c855489cb16133483758a39d57baa6445574b31c01d130c4c3a3d1ba1d",
    "AP-T6-05": "88920bcadbf881e00e81fc534e18ca7bbe8255ed33363e8207497b213f4751cf",
    "AP-T11-01": "6706b17a624aec0b22d63f9a06d210cf0f6767d51b5ff4842c5c9ecb69844878",
    "AP-T11-02": "91d10276df05e6211ac8cc71920e2282c613fbbe5a95bb0cd63390171cac45be",
    "AP-T11-03": "d039172e7c51927c4e66765ca0f6d5055b779320cdb834f4a236a65f1fe21077",
    "AP-T13-04": "5067d1cdf0f1ee6e3385a6ac5e30b4248ca2a13d052298e40756212f86c144c3",
}

# Live authoritative exact-mapping sets (ATLAS only).  Exact mapping requires
# operational identity against the pinned technique definitions.
EXPECTED_CHAIN_MAPPINGS = {
    "AP-T5-01": {"AML.T0080.000"},
    "AP-T5-02": {"AML.T0070"},
    "AP-T5-04": {"AML.T0070"},
    "AP-T6-01": {"AML.T0051.000"},
    "AP-T6-02": {"AML.T0051.000"},
    "AP-T6-03": {"AML.T0051.001"},
    "AP-T6-04": {"AML.T0029"},
    "AP-T6-05": {"AML.T0020"},
    "AP-T11-01": {"AML.T0051.000", "AML.T0053"},
    "AP-T11-02": {"AML.T0051.000"},
    "AP-T11-03": {"AML.T0051.000"},
    "AP-T13-04": {"AML.T0061"},
}

EXPECTED_STEP_MAPPINGS = {
    "AP-T5-01": {
        ("conceal_payload", "AML.T0068"),
        ("deliver_via_trusted_channel", "AML.T0051.001"),
    },
    "AP-T5-02": {
        ("develop_endpoint_injection", "AML.T0066"),
        ("activate_injection", "AML.T0051.002"),
    },
    "AP-T5-04": {
        ("craft_false_reference_data", "AML.T0066"),
        ("manipulate_tool_invocations", "AML.T0053"),
    },
    "AP-T6-01": {("setup", "AML.T0065")},
    "AP-T6-02": {("execute_code_via_interpreter", "AML.T0050")},
    "AP-T6-03": {
        ("craft_poisoned_content", "AML.T0066"),
        ("conceal_injection", "AML.T0068"),
    },
    "AP-T6-04": {("delivery", "AML.T0051.000")},
    "AP-T6-05": {
        ("access_learning_interface", "AML.T0040"),
        ("deliver_adversarial_feedback", "AML.T0051.000"),
    },
    "AP-T11-01": {("execute_embedded_payload", "AML.T0050")},
    "AP-T11-02": {
        ("deliver_backdoor_prompt", "AML.T0051.000"),
        ("generate_backdoored_workflow", "AML.T0053"),
        ("execute_hidden_logic", "AML.T0050"),
    },
    "AP-T11-03": {
        ("craft_ambiguous_input", "AML.T0065"),
        ("execute_unintended_command", "AML.T0050"),
    },
    "AP-T13-04": {
        ("inject_initial_payload", "AML.T0051.001"),
        ("replicate_in_agent_outputs", "AML.T0061"),
    },
}

# Per-record terminal expectations: final step id and required keywords in the
# terminal postcondition (first-observable-outcome semantics).
TERMINAL_EXPECTATIONS = {
    "AP-T5-01": ("compound_distortion", ("compounding",)),
    "AP-T5-02": ("exfiltrate_via_endpoints", ("endpoint", "exfiltration")),
    "AP-T5-04": ("value_biased_decisions", ("fabricated values",)),
    "AP-T6-01": ("impact", ("drift",)),
    "AP-T6-02": ("execute_code_via_interpreter", ("unauthorized command execution",)),
    "AP-T6-03": ("execute_unintended_actions", ("goal-redirected",)),
    "AP-T6-04": ("impact", ("denial",)),
    "AP-T6-05": ("degrade_decision_integrity", ("corruption",)),
    "AP-T11-01": ("execute_embedded_payload", ("deployment", "compromise")),
    "AP-T11-02": ("execute_hidden_logic", ("hidden logic", "unauthorized action")),
    "AP-T11-03": ("execute_unintended_command", ("command-injection",)),
    "AP-T13-04": ("propagate_to_peer_agents", ("peer", "replicat")),
}

EXPECTED_STEP_SEQUENCES = {
    "AP-T5-01": [
        "craft_false_information",
        "conceal_payload",
        "deliver_via_trusted_channel",
        "execute_injection",
        "establish_memory_persistence",
        "reuse_stored_fabrication",
        "feedback_reinforces_memory",
        "compound_distortion",
    ],
    "AP-T5-02": [
        "develop_endpoint_injection",
        "stage_injection_content",
        "trigger_retrieval",
        "activate_injection",
        "exfiltrate_via_endpoints",
    ],
    "AP-T5-04": [
        "identify_data_corpus",
        "probe_retrieval_mechanisms",
        "discover_value_handling",
        "craft_false_reference_data",
        "obfuscate_injection",
        "deliver_fabricated_values",
        "persist_in_rag",
        "activate_via_retrieval",
        "manipulate_tool_invocations",
        "value_biased_decisions",
    ],
    "AP-T6-02": [
        "research_injection_patterns",
        "access_agent_interface",
        "test_prompt_injections",
        "validate_exploit_reliability",
        "deliver_refined_injection",
        "execute_code_via_interpreter",
    ],
    "AP-T11-01": [
        "analyze_framework_apis",
        "scan_deployment_targets",
        "extract_call_chains",
        "develop_exploit_prompts",
        "access_public_application",
        "submit_crafted_prompt",
        "bypass_guardrails",
        "invoke_tools_with_attacker_args",
        "generate_backdoored_configuration",
        "deploy_configuration",
        "execute_embedded_payload",
    ],
    "AP-T11-02": [
        "develop_backdoor_prompt",
        "deliver_backdoor_prompt",
        "generate_backdoored_workflow",
        "persist_backdoored_workflow",
        "execute_hidden_logic",
    ],
    "AP-T13-04": [
        "craft_self_propagating_payload",
        "inject_initial_payload",
        "replicate_in_agent_outputs",
        "propagate_to_peer_agents",
    ],
}

LEGACY_KEYS = {"kill_chain", "evidence"}


@pytest.fixture(scope="module")
def raw() -> dict:
    return yaml.safe_load(HALLUC_INTENT_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def patterns(raw: dict) -> dict:
    return raw["patterns"]


@pytest.fixture(scope="module")
def resolver():
    return load_taxonomy_resolver()


@pytest.fixture(scope="module")
def qualified(patterns: dict, resolver) -> dict:
    """Every live record qualified against the production pinned resolver."""
    return {
        pid: validate_attack_pattern(record, resolver)
        for pid, record in patterns.items()
    }


def _walk_keys(value):
    if isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _walk_keys(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_keys(item)


def _walk_strings(value):
    if isinstance(value, dict):
        for item in value.values():
            yield from _walk_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_strings(item)
    elif isinstance(value, str):
        yield value


def _chain_exact_ids(chain: dict) -> set[str]:
    return {
        identifier
        for mapping in chain["mappings"]
        if mapping["decision"] == "exact"
        for identifier in mapping["ids"]
    }


def _step_exact_ids(chain: dict) -> set[tuple[str, str]]:
    """Flatten every id of every exact mapping as (step_id, id) pairs.

    Never inspect only ``ids[0]`` and never key by step alone (which would
    silently overwrite a step carrying multiple exact ids).
    """
    return {
        (step["step_id"], identifier)
        for step in chain["steps"]
        for mapping in step["mappings"]
        if mapping["decision"] == "exact"
        for identifier in mapping["ids"]
    }


def _terminal_postconditions(step: dict) -> list[dict]:
    return [
        out
        for out in step["observable_postconditions"]
        if out["security_relevant"] and out["terminal"]
    ]


# ---------------------------------------------------------------------------
# Resulting ID set and legacy removal
# ---------------------------------------------------------------------------


def test_resulting_id_set_is_exact(patterns: dict) -> None:
    assert set(patterns) == EXPECTED_IDS
    assert DEFERRED_SOURCES.isdisjoint(patterns)


def test_no_yaml_aliases_in_committed_data() -> None:
    """Anchors/aliases would silently couple records under hand edits."""
    text = HALLUC_INTENT_PATH.read_text(encoding="utf-8")
    data_lines = (
        line for line in text.splitlines() if line and not line.startswith("#")
    )
    assert not any("&id" in line or "*id" in line for line in data_lines)


def test_legacy_kill_chain_and_evidence_removed(patterns: dict) -> None:
    for pid, record in patterns.items():
        found = set(_walk_keys(record)) & LEGACY_KEYS
        assert not found, f"{pid}: legacy keys remain: {found}"
        with pytest.raises(ValidationError):
            validate_legacy_attack_pattern(record)


# ---------------------------------------------------------------------------
# Production qualification, pins, and digests
# ---------------------------------------------------------------------------


def test_all_records_qualify_against_production_resolver(qualified: dict) -> None:
    assert set(qualified) == EXPECTED_IDS


def test_taxonomy_context_matches_production_pins(patterns: dict, resolver) -> None:
    pinned = resolver.taxonomy_context
    assert pinned.atlas.release == "2026.05"
    assert pinned.laaf is None
    for record in patterns.values():
        context = record["canonical_chain"]["taxonomy_context"]
        assert context["atlas"]["release"] == pinned.atlas.release
        assert context["atlas"]["digest"] == pinned.atlas.digest
        assert context["laaf"] is None
        assert context["mapping_set_digest"] == pinned.mapping_set_digest


def test_semantic_digests_are_golden_and_recompute(patterns: dict) -> None:
    assert set(EXPECTED_DIGESTS) == set(patterns)
    for pid, record in patterns.items():
        chain = record["canonical_chain"]
        assert chain["semantic_digest"] == EXPECTED_DIGESTS[pid]
        assert compute_chain_semantic_digest(chain) == EXPECTED_DIGESTS[pid]


# ---------------------------------------------------------------------------
# Exact mappings: operational identity, strict set equality, lineage deltas
# ---------------------------------------------------------------------------


def test_exact_mappings_are_atlas_only_and_resolver_backed(
    patterns: dict, resolver
) -> None:
    for pid, record in patterns.items():
        chain = record["canonical_chain"]
        scopes = [chain["mappings"], *(step["mappings"] for step in chain["steps"])]
        assert any(m["decision"] == "exact" for m in chain["mappings"]), pid
        for scope in scopes:
            for mapping in scope:
                assert mapping["taxonomy"] == "ATLAS", (
                    f"{pid}: LAAF decision under an absent LAAF pin"
                )
                if mapping["decision"] == "exact":
                    for identifier in mapping["ids"]:
                        assert resolver.contains("ATLAS", identifier), (
                            f"{pid}: unbacked exact id {identifier}"
                        )


def test_exact_mapping_sets_equal_expected(patterns: dict) -> None:
    """Strict both-direction equality against the live authoritative sets."""
    assert set(EXPECTED_CHAIN_MAPPINGS) == EXPECTED_IDS
    assert set(EXPECTED_STEP_MAPPINGS) == EXPECTED_IDS
    for pid, record in patterns.items():
        chain = record["canonical_chain"]
        assert _chain_exact_ids(chain) == EXPECTED_CHAIN_MAPPINGS[pid], pid
        assert _step_exact_ids(chain) == EXPECTED_STEP_MAPPINGS[pid], pid


# ---------------------------------------------------------------------------
# Chain shape: branch-free total order, typed linkage, reachability
# ---------------------------------------------------------------------------


def test_chains_are_branch_free_and_total_order(qualified: dict) -> None:
    for pid, pattern in qualified.items():
        chain = pattern.canonical_chain
        steps = chain.steps
        assert [step.order for step in steps] == list(range(1, len(steps) + 1)), pid
        for step in steps:
            assert step.requirement == "required", f"{pid}.{step.step_id}"
            assert step.condition is None, f"{pid}.{step.step_id}"
        for step in steps[:-1]:
            assert not any(
                out.security_relevant and out.terminal
                for out in step.observable_postconditions
            ), f"{pid}.{step.step_id}"
        terminal = [
            out
            for out in steps[-1].observable_postconditions
            if out.security_relevant and out.terminal
        ]
        assert len(terminal) == 1, pid


def test_consumed_references_are_produced_upstream(qualified: dict) -> None:
    """Every consumed typed reference is produced by an earlier step."""
    for pid, pattern in qualified.items():
        available: set[tuple[str, str]] = set()
        for step in pattern.canonical_chain.steps:
            for ref in step.consumed:
                key = (ref.kind, ref.ref_id)
                assert key in available, (
                    f"{pid}.{step.step_id} consumes unproduced {key}"
                )
            for ref in step.produced:
                available.add((ref.kind, ref.ref_id))


def test_chain_graph_is_fully_reachable(patterns: dict) -> None:
    """Forward reachability from step 1 and backward reachability from the
    terminal step cover every step; no produced reference is left dead outside
    the terminal step (no orphan causality)."""
    for pid, record in patterns.items():
        steps = record["canonical_chain"]["steps"]
        producer: dict[tuple[str, str], int] = {}
        for step in steps:
            for ref in step["produced"]:
                producer[(ref["kind"], ref["ref_id"])] = step["order"]
        forward: dict[int, set[int]] = {step["order"]: set() for step in steps}
        for step in steps:
            for ref in step["consumed"]:
                forward[producer[(ref["kind"], ref["ref_id"])]].add(step["order"])

        def reachable(start: int, edges: dict[int, set[int]]) -> set[int]:
            seen: set[int] = set()
            stack = [start]
            while stack:
                node = stack.pop()
                if node not in seen:
                    seen.add(node)
                    stack.extend(edges[node] - seen)
            return seen

        all_orders = set(forward)
        assert reachable(1, forward) == all_orders, f"{pid}: unreachable from step 1"
        backward: dict[int, set[int]] = {order: set() for order in forward}
        for src, targets in forward.items():
            for target in targets:
                backward[target].add(src)
        assert reachable(steps[-1]["order"], backward) == all_orders, (
            f"{pid}: terminal does not reach every step backward"
        )

        consumed = {
            (ref["kind"], ref["ref_id"]) for step in steps for ref in step["consumed"]
        }
        for step in steps[:-1]:
            for ref in step["produced"]:
                assert (ref["kind"], ref["ref_id"]) in consumed, (
                    f"{pid}.{step['step_id']}: dead produced ref {ref['ref_id']}"
                )


def test_resource_slots_and_ingress(qualified: dict) -> None:
    for pid, pattern in qualified.items():
        chain = pattern.canonical_chain
        ingress = [
            slot for slot in chain.resource_slots if slot.purpose == "initial_ingress"
        ]
        assert len(ingress) == 1, pid
        assert ingress[0].slot_id == chain.initial_ingress_slot_id, pid
        assert ingress[0].kind == "entry_point", pid
        assert any(
            slot.purpose in {"target", "supporting"} for slot in chain.resource_slots
        ), pid


# ---------------------------------------------------------------------------
# Per-record terminal/causal expectations and step sequences
# ---------------------------------------------------------------------------


def test_per_record_terminal_semantics(patterns: dict) -> None:
    assert set(TERMINAL_EXPECTATIONS) == EXPECTED_IDS
    for pid, (final_step_id, keywords) in TERMINAL_EXPECTATIONS.items():
        steps = patterns[pid]["canonical_chain"]["steps"]
        assert steps[-1]["step_id"] == final_step_id, pid
        terminal = _terminal_postconditions(steps[-1])
        assert len(terminal) == 1, pid
        description = terminal[0]["description"].lower()
        for keyword in keywords:
            assert keyword in description, f"{pid}: terminal missing {keyword!r}"


def test_corrected_step_sequences(patterns: dict) -> None:
    for pid, sequence in EXPECTED_STEP_SEQUENCES.items():
        steps = patterns[pid]["canonical_chain"]["steps"]
        assert [step["step_id"] for step in steps] == sequence, pid


# ---------------------------------------------------------------------------
# Lineage fidelity: dispositions, resulting sets, slot plans
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Key semantic decisions (exact-head review corrections)
# ---------------------------------------------------------------------------


def test_t5_01_owns_factual_misinformation_not_operational_rules(
    patterns: dict,
) -> None:
    """OG-01 boundary: AP-T5-01 keeps recursive factual-misinformation
    compounding; injected operational-rule override belongs to AP-T1-01."""
    description = patterns["AP-T5-01"]["description"].lower()
    assert "compound" in description
    assert "false factual information" in description
    assert "operational-rule override belongs to ap-t1-01" in description


def test_t5_01_structurally_realizes_recursive_compounding(patterns: dict) -> None:
    """The recursion is unrolled: persist -> reuse -> feedback write-back ->
    compounded terminal, never prose-only one-shot poisoning."""
    steps = patterns["AP-T5-01"]["canonical_chain"]["steps"]
    by_id = {step["step_id"]: step for step in steps}

    reuse = by_id["reuse_stored_fabrication"]
    assert [ref["ref_id"] for ref in reuse["consumed"]] == ["poisoned_memory"]
    assert reuse["provenance"]["tier"] == "variant"

    feedback = by_id["feedback_reinforces_memory"]
    assert {ref["ref_id"] for ref in feedback["consumed"]} == {
        "poisoned_memory",
        "distorted_response",
    }
    assert [ref["ref_id"] for ref in feedback["produced"]] == ["reinforced_memory"]
    assert feedback["provenance"]["tier"] == "variant"

    terminal_step = steps[-1]
    assert terminal_step["step_id"] == "compound_distortion"
    assert [ref["ref_id"] for ref in terminal_step["consumed"]] == ["reinforced_memory"]
    # The one-shot path (poisoned_memory straight to terminal) must not exist.
    assert "poisoned_memory" not in {ref["ref_id"] for ref in terminal_step["consumed"]}


def test_t5_02_terminates_at_actual_endpoint_exfiltration(patterns: dict) -> None:
    steps = patterns["AP-T5-02"]["canonical_chain"]["steps"]
    assert len(steps) == 5
    final = steps[-1]
    assert final["step_id"] == "exfiltrate_via_endpoints"
    assert final["action_kind"] == "impact"
    terminal = _terminal_postconditions(final)
    assert len(terminal) == 1
    description = terminal[0]["description"].lower()
    assert "attacker-controlled endpoint" in description
    assert "first observable exfiltration" in description
    assert [ref["ref_id"] for ref in final["produced"]] == ["context_data_exfiltrated"]
    # No duplicate downstream impact restatement remains.
    assert "data_exfiltration_impact" not in {step["step_id"] for step in steps}
    assert "endpoint_request_emitted" not in set(_walk_strings(steps))


def test_t5_04_obfuscates_before_delivery(patterns: dict) -> None:
    steps = patterns["AP-T5-04"]["canonical_chain"]["steps"]
    by_id = {step["step_id"]: step for step in steps}
    obfuscate = by_id["obfuscate_injection"]
    deliver = by_id["deliver_fabricated_values"]
    persist = by_id["persist_in_rag"]
    assert obfuscate["order"] < deliver["order"] < persist["order"]
    assert obfuscate["boundary_position"] == "outside"
    assert obfuscate["action_kind"] == "prepare"
    # Obfuscation transforms the crafted values before any delivery; nothing is
    # transformed from outside after crossing the boundary.
    assert [ref["ref_id"] for ref in obfuscate["consumed"]] == [
        "fabricated_reference_values"
    ]
    assert [ref["ref_id"] for ref in deliver["consumed"]] == ["prioritized_injection"]
    assert [ref["ref_id"] for ref in persist["consumed"]] == ["delivered_values"]


def test_t6_02_terminates_at_first_unauthorized_execution(patterns: dict) -> None:
    record = patterns["AP-T6-02"]
    steps = record["canonical_chain"]["steps"]
    assert len(steps) == 6
    final = steps[-1]
    assert final["step_id"] == "execute_code_via_interpreter"
    assert final["action_kind"] == "impact"
    terminal = _terminal_postconditions(final)
    assert len(terminal) == 1
    assert (
        "first observable unauthorized command execution"
        in terminal[0]["description"].lower()
    )
    # Later credential access / broader compromise is removed entirely.
    step_ids = {step["step_id"] for step in steps}
    assert "exfiltrate_credentials" not in step_ids
    assert "system_compromise" not in step_ids
    strings = set(_walk_strings(record))
    assert "revealed_credentials" not in strings
    assert "AML.T0055" not in strings
    assert "code_execution_result" not in strings
    # First-terminal boundary is stated in the record description.
    assert "first unauthorized command execution" in record["description"].lower()


def test_t11_01_iac_sequence_and_honest_tiers(patterns: dict) -> None:
    """The chain realizes actual backdoored-config generation and deployment;
    IaC-specific steps are tiered variant and never claim observed IaC timing
    from CS0052. Generic prompt-to-RCE machinery (sandbox escape, reverse
    shell) is gone."""
    record = patterns["AP-T11-01"]
    steps = record["canonical_chain"]["steps"]
    by_id = {step["step_id"]: step for step in steps}

    for removed in (
        "execute_code_in_interpreter",
        "escape_sandbox",
        "establish_reverse_shell",
        "achieve_system_control",
    ):
        assert removed not in by_id
    assert "AML.T0105" not in set(_walk_strings(record))

    iac_steps = ["generate_backdoored_configuration", "deploy_configuration"]
    for step_id in iac_steps + ["execute_embedded_payload"]:
        step = by_id[step_id]
        assert step["provenance"]["tier"] == "variant", step_id
        assert (
            "not observed from cs0052"
            in step["provenance"]["adaptation_rationale"].lower()
        ), step_id

    generate = by_id["generate_backdoored_configuration"]
    assert generate["executor_role"] == "system"
    assert [ref["ref_id"] for ref in generate["produced"]] == ["backdoored_config"]

    deploy = by_id["deploy_configuration"]
    assert deploy["executor_role"] == "system"
    assert [ref["ref_id"] for ref in deploy["consumed"]] == ["backdoored_config"]
    assert [ref["ref_id"] for ref in deploy["produced"]] == ["deployed_configuration"]

    execute = steps[-1]
    assert execute["step_id"] == "execute_embedded_payload"
    assert execute["action_kind"] == "impact"
    assert [ref["ref_id"] for ref in execute["consumed"]] == ["deployed_configuration"]
    assert _step_exact_ids(record["canonical_chain"]) == {
        ("execute_embedded_payload", "AML.T0050")
    }
    terminal = _terminal_postconditions(execute)
    assert len(terminal) == 1
    description = terminal[0]["description"].lower()
    assert "on deployment" in description
    assert "first observable compromise" in description


def test_t11_02_direct_delivery_and_strict_variant_provenance(patterns: dict) -> None:
    """Direct AML.T0051.000 prompt delivery to the workflow agent; no
    credential/repository configuration poisoning and no AML.T0081 anywhere;
    every step stays variant-tier CS0047 adaptation with the agent-as-payload
    mismatch stated. Ordinary interface access is folded into the delivery
    ingress, so the crafted prompt is consumed exactly once."""
    record = patterns["AP-T11-02"]
    chain = record["canonical_chain"]
    steps = chain["steps"]
    assert len(steps) == 5

    strings = set(_walk_strings(record))
    for removed in (
        "obtain_credentials",
        "access_workflow_agent_interface",
        "workflow_agent_session",
        "inject_malicious_configuration",
        "initialize_poisoned_agent",
        "publishing_credentials",
        "poisoned_configuration",
        "steered_agent_state",
        "AML.T0081",
    ):
        assert removed not in strings, removed

    # The crafted prompt has exactly one consumer: the delivery step.
    prompt_consumers = [
        step["step_id"]
        for step in steps
        if any(ref["ref_id"] == "backdoor_prompt" for ref in step["consumed"])
    ]
    assert prompt_consumers == ["deliver_backdoor_prompt"]

    for step in steps:
        provenance = step["provenance"]
        assert provenance["tier"] == "variant", (
            f"AP-T11-02.{step['step_id']}: tier {provenance['tier']} "
            "would overclaim direct demonstration"
        )
        reference_ids = {ref["reference_id"] for ref in provenance["references"]}
        assert "AML.CS0047" in reference_ids, step["step_id"]
        rationale = provenance["adaptation_rationale"].lower()
        assert "adapt" in rationale or "analog" in rationale, step["step_id"]
        # The agent-as-payload mismatch must be stated on every step: in
        # CS0047 the agent is the destructive payload, not the target.
        assert "agent-as-payload" in rationale or (
            "destructive payload" in rationale and "manipulation target" in rationale
        ), f"AP-T11-02.{step['step_id']}: agent-as-payload mismatch not stated"

    deliver = steps[1]
    assert deliver["step_id"] == "deliver_backdoor_prompt"
    assert deliver["action_kind"] == "deliver"
    assert deliver["boundary_position"] == "crossing"
    assert "ordinary user interface" in (
        deliver["observable_postconditions"][0]["description"].lower()
    )
    exact = _step_exact_ids(chain)
    assert ("deliver_backdoor_prompt", "AML.T0051.000") in exact
    assert ("generate_backdoored_workflow", "AML.T0053") in exact
    assert ("execute_hidden_logic", "AML.T0050") in exact
    assert _chain_exact_ids(chain) == {"AML.T0051.000"}
    assert record["nist_classification"]["attack_class"] == (
        "genai.direct_prompt_injection.abuse_violations"
    )


def test_t13_04_terminates_at_first_peer_replication(patterns: dict) -> None:
    record = patterns["AP-T13-04"]
    steps = record["canonical_chain"]["steps"]
    assert len(steps) == 4
    final = steps[-1]
    assert final["step_id"] == "propagate_to_peer_agents"
    assert final["action_kind"] == "impact"
    terminal = _terminal_postconditions(final)
    assert len(terminal) == 1
    description = terminal[0]["description"].lower()
    assert "peer agent" in description
    assert "first observable propagation" in description
    # Network-wide persistence is out of scope for this record.
    assert "achieve_system_wide_compromise" not in {step["step_id"] for step in steps}
    strings = set(_walk_strings(record))
    assert "network_compromise_outcome" not in strings
    assert "peer_adoption_state" not in strings


def test_sssom_rows_remain_candidate_relatedmatch_only() -> None:
    """The owned SSSOM provenance confers no mapping authority: all predicates
    stay skos:relatedMatch."""
    lines = [
        line
        for line in SSSOM_PATH.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    ]
    header = lines[0].split("\t")
    predicate_column = header.index("predicate_id")
    predicates = {line.split("\t")[predicate_column] for line in lines[1:]}
    assert predicates == {"skos:relatedMatch"}


# ---------------------------------------------------------------------------
# Catalog load integration (read-only)
# ---------------------------------------------------------------------------


def test_merged_catalog_contains_resulting_ids_only() -> None:
    catalog = load_attack_patterns()
    assert EXPECTED_IDS.issubset(catalog)
    assert DEFERRED_SOURCES.isdisjoint(catalog)
