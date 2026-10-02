"""Wave test for the memory-tool canonical-chain migration (bead 422o.2.4).

Validates data/taxonomies/attack-patterns/attack-patterns-memory-tool.yaml
against expected tables taken from the catalog-lineage.yaml dispositions for
the 17 historical memory-tool sources (T1-T4); the tests do not read the
lineage record itself:

- exactly the 14 authoritative resulting records exist, in catalog order;
  deferred sources (AP-T3-01, AP-T4-02, AP-T4-04) produce no live record;
- legacy ``kill_chain``/``evidence`` fields are removed;
- every record parses and qualifies against the production taxonomy resolver
  (ATLAS is the sole v1 authority; LAAF is absent);
- each canonical chain is one branch-free total-order chain whose step mapping
  decisions, chain mapping, resource slots, and description match the
  expected tables exactly, with a recomputed semantic digest.
"""

from __future__ import annotations

import pytest
import yaml

from asago_scenario_generator.data.loaders import (
    _DEFAULT_ATTACK_PATTERNS_DIR,
    load_attack_patterns,
)
from asago_scenario_generator.data.taxonomy_pins import load_taxonomy_resolver
from asago_scenario_generator.models.attack_pattern import (
    compute_chain_semantic_digest,
    validate_attack_pattern,
)

MEMORY_TOOL_FILE = _DEFAULT_ATTACK_PATTERNS_DIR / "attack-patterns-memory-tool.yaml"

EXPECTED_IDS = [
    "AP-T1-01",
    "AP-T1-02",
    "AP-T1-03",
    "AP-T1-04",
    "AP-T2-01",
    "AP-T2-02",
    "AP-T2-03",
    "AP-T2-04",
    "AP-T2-05",
    "AP-T2-06",
    "AP-T3-02",
    "AP-T3-03",
    "AP-T4-01",
    "AP-T4-03",
]

DEFERRED_IDS = ["AP-T3-01", "AP-T4-02", "AP-T4-04"]

# Record-specific expected causal spines (exact step_id sequences), pinned by
# the independent exact-head semantic review: no side branches, and the chain ends
# at the first observable terminal of the lineage terminal semantics.
EXPECTED_STEPS = {
    "AP-T1-01": [
        "craft_payload",
        "conceal_injection",
        "deliver_payload",
        "execute_injection",
        "persist_in_memory",
        "impact",
    ],
    "AP-T1-02": [
        "craft_fragments",
        "deliver_fragments",
        "execute_fragments",
        "escalate_privileges",
    ],
    "AP-T1-03": ["gain_access", "deliver_inputs", "corrupt_memory", "impact"],
    "AP-T1-04": [
        "gain_access",
        "craft_payload",
        "inject_payload",
        "poison_shared_memory",
        "impact",
    ],
    "AP-T2-01": [
        "reconnaissance",
        "craft_payload",
        "deliver_payload",
        "execute_injection",
        "invoke_tool",
        "impact",
    ],
    "AP-T2-02": [
        "reconnaissance",
        "craft_payload",
        "deliver_payload",
        "execute_injection",
        "discover_data",
        "collect_data",
        "exfiltrate_data",
    ],
    "AP-T2-03": ["discover_tools", "setup", "execution", "amplification"],
    "AP-T2-04": [
        "craft_payload",
        "conceal_injection",
        "deliver_payload",
        "execute_injection",
        "persist_in_memory",
        "invoke_tool_from_memory",
    ],
    "AP-T2-05": [
        "gain_access",
        "craft_adversarial_content",
        "inject_content",
        "persist_in_retrieval",
        "trigger_tool_invocation",
    ],
    "AP-T2-06": [
        "reconnaissance",
        "gain_access",
        "craft_payload",
        "verify_attack",
        "deliver_injection",
        "execute_injection",
        "invoke_tool",
    ],
    "AP-T3-02": [
        "reconnaissance",
        "probe_trust_boundaries",
        "discover_connected_services",
        "craft_cross_boundary_request",
        "obfuscate_request",
        "deliver_request",
        "execute_request",
        "escalate_privileges",
    ],
    "AP-T3-03": [
        "identify_provisioning_weakness",
        "instantiate_shadow_agent",
        "inherit_credentials",
        "operate_shadow_agent",
    ],
    "AP-T4-01": [
        "analyze_processing_behavior",
        "craft_expensive_input",
        "submit_expensive_input",
        "impact",
    ],
    "AP-T4-03": [
        "identify_quota_bound_integrations",
        "craft_quota_exhausting_request",
        "deliver_request",
        "amplify_api_calls",
        "impact",
    ],
}

# Reported envelope deltas: the record mechanism boundary itself is narrowed
# so chain-level exact identities rest on pinned operations.
# Note: the memory-tool live descriptions happen to equal the lineage
# mechanism_boundary text for all 14 records; this is a domain-specific
# property, not a universal contract.

# Record-specific provenance tier pins for the review-mandated downgrades.
EXPECTED_STEP_TIERS = {
    ("AP-T3-02", "deliver_request"): "variant",
    ("AP-T3-02", "execute_request"): "variant",
    ("AP-T3-02", "escalate_privileges"): "variant",
    ("AP-T2-03", "amplification"): "designed",
    ("AP-T3-03", "operate_shadow_agent"): "designed",
    ("AP-T1-02", "escalate_privileges"): "inferred",
    ("AP-T1-01", "impact"): "inferred",
}

# Record-specific exact-mapping pins for the review-mandated narrowing.
# Note: the withdrawn AML.T0080.000 (AP-T1-04) and AML.T0012 (AP-T3-02)
# mappings are intentionally NOT pinned here; their absence is asserted
# separately in test_review_mandated_narrowing_rationales.
EXPECTED_EXACT_STEP_MAPPINGS = {
    ("AP-T2-06", "invoke_tool"): ["AML.T0050"],
    ("AP-T1-04", "inject_payload"): ["AML.T0051.001"],
    ("AP-T3-02", "escalate_privileges"): ["AML.T0053"],
    ("AP-T1-01", "persist_in_memory"): ["AML.T0080.000"],
    ("AP-T2-04", "invoke_tool_from_memory"): ["AML.T0051.002"],
    ("AP-T2-02", "exfiltrate_data"): ["AML.T0086"],
}


@pytest.fixture(scope="module")
def document() -> dict:
    return yaml.safe_load(MEMORY_TOOL_FILE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def patterns(document) -> dict:
    return document["patterns"]


@pytest.fixture(scope="module")
def resolver():
    return load_taxonomy_resolver()


def test_exact_resulting_id_set_and_order(patterns) -> None:
    assert list(patterns) == EXPECTED_IDS


def test_deferred_sources_produce_no_live_record(patterns) -> None:
    for pid in DEFERRED_IDS:
        assert pid not in patterns


def test_legacy_fields_removed(patterns) -> None:
    for pid, record in patterns.items():
        assert "kill_chain" not in record, pid
        assert "evidence" not in record, pid


def test_records_validate_against_production_resolver(patterns, resolver) -> None:
    for record in patterns.values():
        validate_attack_pattern(record, resolver)


def test_chain_is_branch_free_total_order(patterns) -> None:
    for pid, record in patterns.items():
        steps = record["canonical_chain"]["steps"]
        assert [s["order"] for s in steps] == list(range(1, len(steps) + 1)), pid
        assert all(s["requirement"] == "required" for s in steps), pid
        assert all(s["condition"] is None for s in steps), pid
        assert len({s["step_id"] for s in steps}) == len(steps), pid


def test_start_semantics(patterns) -> None:
    """The earliest attacker-controlled action is the first chain step."""
    for pid, record in patterns.items():
        chain = record["canonical_chain"]
        first = chain["steps"][0]
        assert first["attacker_controlled"], pid
        assert first["executor_role"] == "attacker", pid
        assert chain["earliest_attacker_controlled_step_id"] == first["step_id"], pid


def test_terminal_semantics(patterns) -> None:
    """Exactly the final step carries the security-relevant terminal outcome."""
    for pid, record in patterns.items():
        steps = record["canonical_chain"]["steps"]
        for step in steps[:-1]:
            assert not any(
                p["security_relevant"] and p["terminal"]
                for p in step["observable_postconditions"]
            ), (pid, step["step_id"])
        assert any(
            p["security_relevant"] and p["terminal"]
            for p in steps[-1]["observable_postconditions"]
        ), pid


def test_consumed_references_are_produced_in_order(patterns) -> None:
    """Every consumed reference is produced by an earlier step (causal order)."""
    for pid, record in patterns.items():
        produced: set[str] = set()
        for step in record["canonical_chain"]["steps"]:
            for ref in step["consumed"]:
                assert ref["ref_id"] in produced, (pid, step["step_id"], ref["ref_id"])
            produced |= {ref["ref_id"] for ref in step["produced"]}


def test_provenance_is_tiered_and_cited(patterns) -> None:
    for pid, record in patterns.items():
        for step in record["canonical_chain"]["steps"]:
            provenance = step["provenance"]
            assert provenance["tier"] in {"observed", "variant", "inferred", "designed"}
            assert 0 <= provenance["confidence"] <= 100
            assert provenance["references"], (pid, step["step_id"])
            assert provenance["adaptation_rationale"].strip(), (pid, step["step_id"])


def test_semantic_digest_recomputes(patterns) -> None:
    for pid, record in patterns.items():
        chain = record["canonical_chain"]
        assert chain["semantic_digest"] == compute_chain_semantic_digest(chain), pid


def test_taxonomy_context_pins_resolver_and_laaf_absent(patterns, resolver) -> None:
    expected = resolver.taxonomy_context.model_dump(mode="json")
    for pid, record in patterns.items():
        chain = record["canonical_chain"]
        assert chain["taxonomy_context"] == expected, pid
        assert chain["taxonomy_context"]["laaf"] is None, pid
        decisions = list(chain["mappings"]) + [
            m for s in chain["steps"] for m in s["mappings"]
        ]
        assert all(m["taxonomy"] == "ATLAS" for m in decisions), pid


def test_catalog_loader_integrates_migrated_records(resolver) -> None:
    loaded = load_attack_patterns()
    for pid in EXPECTED_IDS:
        assert pid in loaded
        validate_attack_pattern(loaded[pid], resolver)
    for pid in DEFERRED_IDS:
        assert pid not in loaded


def test_record_specific_causal_spines(patterns) -> None:
    """Each record's step sequence is exactly the pinned causal spine."""
    assert set(EXPECTED_STEPS) == set(patterns)
    for pid, record in patterns.items():
        actual = [s["step_id"] for s in record["canonical_chain"]["steps"]]
        assert actual == EXPECTED_STEPS[pid], pid


def test_backward_reachability_to_terminal(patterns) -> None:
    """Every required nonterminal step contributes to the terminal: at least
    one of its produced references is consumed by a later step, and the
    reference graph reaches the terminal step."""
    for pid, record in patterns.items():
        steps = record["canonical_chain"]["steps"]
        consumers: dict[int, set[int]] = {i: set() for i in range(len(steps))}
        for j, step in enumerate(steps):
            consumed_ids = {r["ref_id"] for r in step["consumed"]}
            for i in range(j):
                produced_ids = {r["ref_id"] for r in steps[i]["produced"]}
                if produced_ids & consumed_ids:
                    consumers[i].add(j)
        terminal = len(steps) - 1
        for i in range(terminal):
            assert consumers[i], (pid, steps[i]["step_id"], "dangling side branch")
            # transitive reachability to the terminal step
            reached = set()
            frontier = list(consumers[i])
            while frontier:
                node = frontier.pop()
                if node in reached:
                    continue
                reached.add(node)
                frontier.extend(consumers[node])
            assert terminal in reached, (pid, steps[i]["step_id"])


def test_record_specific_provenance_tiers(patterns) -> None:
    for (pid, step_id), tier in EXPECTED_STEP_TIERS.items():
        step = next(
            s
            for s in patterns[pid]["canonical_chain"]["steps"]
            if s["step_id"] == step_id
        )
        assert step["provenance"]["tier"] == tier, (pid, step_id)


def test_record_specific_exact_step_mappings(patterns) -> None:
    for (pid, step_id), ids in EXPECTED_EXACT_STEP_MAPPINGS.items():
        step = next(
            s
            for s in patterns[pid]["canonical_chain"]["steps"]
            if s["step_id"] == step_id
        )
        (decision,) = step["mappings"]
        assert decision["decision"] == "exact", (pid, step_id)
        assert decision["taxonomy"] == "ATLAS"
        assert list(decision["ids"]) == ids, (pid, step_id)


def test_review_mandated_narrowing_rationales(patterns) -> None:
    """The exact-identity narrowing and lineage deltas are documented in the
    affected steps' rationales (fail closed, not silent qualification)."""

    def step_of(pid, step_id):
        return next(
            s
            for s in patterns[pid]["canonical_chain"]["steps"]
            if s["step_id"] == step_id
        )

    t006 = step_of("AP-T2-06", "invoke_tool")
    assert "interpreter" in t006["provenance"]["adaptation_rationale"].lower()
    assert "reported as a delta" in t006["provenance"]["adaptation_rationale"]

    # Final re-review: AP-T2-06 boundary narrowed to the interpreter tool and
    # the withdrawn AML.T0080.000 (AP-T1-04) / AML.T0012 (AP-T3-02) exact
    # mappings are absent from the records.
    t206_record = patterns["AP-T2-06"]
    assert "command/scripting interpreter tool" in t206_record["description"]
    assert "API client" not in t206_record["description"]
    assert "API-client mode is out of scope" in t206_record["description"]

    t104_record = patterns["AP-T1-04"]
    assert "RAG-indexed retrieval store" in t104_record["description"]
    t104_exact_ids = {
        atlas_id
        for scope in (
            t104_record["canonical_chain"]["mappings"],
            *(s["mappings"] for s in t104_record["canonical_chain"]["steps"]),
        )
        for decision in scope
        if decision["decision"] == "exact"
        for atlas_id in decision["ids"]
    }
    assert "AML.T0080.000" not in t104_exact_ids
    assert t104_exact_ids == {"AML.T0070", "AML.T0051.001"}
    t104_steps = [s["step_id"] for s in t104_record["canonical_chain"]["steps"]]
    assert "propagate_corruption" not in t104_steps
    # The terminal consumes store.corrupted directly.
    assert any(
        r["ref_id"] == "store.corrupted"
        for r in t104_record["canonical_chain"]["steps"][-1]["consumed"]
    )

    t302_record = patterns["AP-T3-02"]
    t302_exact_ids = {
        atlas_id
        for scope in (
            t302_record["canonical_chain"]["mappings"],
            *(s["mappings"] for s in t302_record["canonical_chain"]["steps"]),
        )
        for decision in scope
        if decision["decision"] == "exact"
        for atlas_id in decision["ids"]
    }
    assert "AML.T0012" not in t302_exact_ids
    assert t302_exact_ids == {"AML.T0053"}
    escalate = step_of("AP-T3-02", "escalate_privileges")
    assert "confused-deputy" in escalate["provenance"]["adaptation_rationale"]

    t302 = step_of("AP-T3-02", "deliver_request")
    (decision,) = t302["mappings"]
    assert decision["decision"] == "unmapped"
    assert "indirect" in decision["rationale"]
    assert "AML.T0051.000" in decision["rationale"]
