"""Dedicated tests for the ATLAS-derived canonical chains (bead 422o.2.3).

Wave contract for ``data/taxonomies/attack-patterns/attack-patterns-atlas-derived.yaml``:

- exactly the nine authoritative resulting ids from catalog-lineage.yaml
  (AP-T1-06, AP-T11-05, AP-T17-03, AP-T17-04, AP-T3-04, AP-T3-05, AP-T3-06,
  AP-T6-06, AP-T6-07) migrate to the canonical-chain contract; legacy
  ``kill_chain``/``evidence`` fields are gone and the records fail legacy
  validation (the legacy/catalogue boundary stays explicit);
- every record parses, signs (semantic digest recomputation + golden pin),
  and qualifies through the production pinned resolver (ATLAS-only; LAAF
  absent so any LAAF decision fails closed);
- chain-scope and step-scope exact ATLAS mappings, resource-slot plans, and
  step sequences match the lineage's approved decisions exactly — including
  the split boundaries (no technique bleeds across sibling records);
- every exact mapping carries operational identity and evidence: chain-scope
  in the description (the v1 model has no chain-scope rationale field),
  step-scope in provenance; AML.CS case-step citations are checked against
  the pinned ATLAS case-step index, with ``retag``/``analogue`` hedges
  required to name the pinned technique they diverge from;
- cross-step linkage is explicit and causal: an exact expected-edge table
  pins every step's consumed/produced references, every consumed reference
  is produced by an earlier step of the same chain, and no produced
  state/artifact dead-ends before the final step (required operations such
  as activations must be consumed downstream, not bypassed);
- split-derived first steps declare ``equality``-true preconditions on
  runtime_state boolean facts (a present-but-false fact must fail, which
  ``existence(true)`` could not express), with true/false/unknown
  evaluation pinned;
- provenance tiers mark temporally recomposed steps (AP-T17-03's
  development/publication timing) as variant with rationale, and
  AP-T6-07's AML.T0080.001 step stays within the pinned technique's
  within-thread semantics.
"""

from __future__ import annotations

from copy import deepcopy
import re
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from asago_scenario_generator.data.loaders import load_attack_patterns
from asago_scenario_generator.data.taxonomy_pins import load_taxonomy_resolver
from asago_scenario_generator.models.attack_pattern import (
    AttackPattern,
    EvaluatedFactEvidence,
    ExactMapping,
    compute_chain_semantic_digest,
    evaluate_condition,
    validate_attack_pattern,
    validate_legacy_attack_pattern,
)

_FILE = "data/taxonomies/attack-patterns/attack-patterns-atlas-derived.yaml"

# Authoritative resulting set from catalog-lineage.yaml for the five
# historical sources AP-T1-06, AP-T11-05, AP-T17-03, AP-T3-04, AP-T6-06.
EXPECTED: dict[str, dict[str, Any]] = {
    "AP-T1-06": {
        "threat_id": "T1",
        "chain_exact": {"AML.T0070", "AML.T0077"},
        "step_exact": {
            "zero_click_activation": {"AML.T0051.001"},
            "rendered_output_exfiltration": {"AML.T0077"},
        },
        "steps": [
            "craft_payload",
            "deliver_content",
            "rag_ingestion",
            "zero_click_activation",
            "data_collection",
            "rendered_output_exfiltration",
            "impact",
        ],
        "slots": [
            ("ingress", "entry_point", "initial_ingress"),
            ("rag_corpus", "integration", "intermediate"),
            ("exfil_endpoint", "integration", "target"),
            ("rendered_output", "output_surface", "intermediate"),
            ("agent_internal_state", "agent_internal", "intermediate"),
            ("boundary", "trust_boundary", "supporting"),
        ],
        "forbidden_exact": {"AML.T0093", "AML.T0085", "AML.T0057", "AML.T0048"},
    },
    "AP-T3-04": {
        "threat_id": "T3",
        "chain_exact": {"AML.T0049"},
        "step_exact": {
            "reconnaissance": {"AML.T0006"},
            "initial_access": {"AML.T0049"},
        },
        "steps": ["reconnaissance", "initial_access"],
        "slots": [
            ("ingress", "entry_point", "initial_ingress"),
            ("control_interface", "integration", "target"),
            ("boundary", "trust_boundary", "supporting"),
        ],
        "forbidden_exact": {"AML.T0083", "AML.T0055", "AML.T0091.000", "AML.T0053"},
    },
    "AP-T3-05": {
        "threat_id": "T3",
        "chain_exact": {"AML.T0083"},
        "step_exact": {
            "config_credential_harvest": {"AML.T0083"},
            "env_credential_harvest": {"AML.T0055"},
            "lateral_movement": {"AML.T0091.000"},
        },
        "steps": [
            "config_credential_harvest",
            "env_credential_harvest",
            "lateral_movement",
        ],
        "slots": [
            ("ingress", "entry_point", "initial_ingress"),
            ("control_interface", "integration", "intermediate"),
            ("connected_service", "integration", "target"),
            ("boundary", "trust_boundary", "supporting"),
        ],
        "forbidden_exact": {"AML.T0049", "AML.T0006", "AML.T0051.000", "AML.T0053"},
    },
    "AP-T3-06": {
        "threat_id": "T3",
        "chain_exact": {"AML.T0051.000", "AML.T0053"},
        "step_exact": {
            "arbitrary_prompting": {"AML.T0051.000"},
            "privileged_tool_invocation": {"AML.T0053"},
            "impact": {"AML.T0112.000"},
        },
        "steps": [
            "arbitrary_prompting",
            "privileged_tool_invocation",
            "impact",
        ],
        "slots": [
            ("ingress", "entry_point", "initial_ingress"),
            ("agent_tools", "tool", "intermediate"),
            ("container", "integration", "target"),
            ("boundary", "trust_boundary", "supporting"),
        ],
        "forbidden_exact": {"AML.T0049", "AML.T0083", "AML.T0055", "AML.T0091.000"},
    },
    "AP-T6-06": {
        "threat_id": "T6",
        "chain_exact": {"AML.T0054", "AML.T0051.001"},
        "step_exact": {
            "discover_control_sequences": {"AML.T0069.000"},
            "craft_injection": {"AML.T0065"},
            "injection_activation": {"AML.T0051.001"},
            "control_sequence_spoofing": {"AML.T0054"},
        },
        "steps": [
            "reconnaissance",
            "discover_control_sequences",
            "craft_injection",
            "stage_infrastructure",
            "social_engineering_lure",
            "initial_access",
            "injection_activation",
            "control_sequence_spoofing",
            "script_execution",
        ],
        "slots": [
            ("ingress", "entry_point", "initial_ingress"),
            ("control_sequences", "integration", "target"),
            ("execution_tool", "tool", "intermediate"),
            ("boundary", "trust_boundary", "supporting"),
        ],
        "forbidden_exact": {
            "AML.T0081",
            "AML.T0108",
            "AML.T0080.001",
            "AML.T0051.002",
        },
    },
    "AP-T6-07": {
        "threat_id": "T6",
        "chain_exact": {"AML.T0081", "AML.T0108"},
        "step_exact": {
            "config_modification": {"AML.T0081"},
            "poisoned_prompt_activation": {"AML.T0051.002"},
            "thread_context_persistence": {"AML.T0080.001"},
            "c2_activation": {"AML.T0108"},
        },
        "steps": [
            "config_modification",
            "poisoned_prompt_activation",
            "thread_context_persistence",
            "c2_activation",
            "impact",
        ],
        "slots": [
            ("ingress", "entry_point", "initial_ingress"),
            ("agent_config", "integration", "intermediate"),
            ("c2_channel", "integration", "target"),
            ("boundary", "trust_boundary", "supporting"),
        ],
        "forbidden_exact": {"AML.T0054", "AML.T0069.000", "AML.T0065"},
    },
    "AP-T11-05": {
        "threat_id": "T11",
        "chain_exact": {"AML.T0100", "AML.T0051.001"},
        "step_exact": {
            "delivery": {"AML.T0078"},
            "gui_action_injection": {"AML.T0051.001"},
            "host_execution": {"AML.T0112.000"},
        },
        "steps": [
            "generate_adversarial_content",
            "stage_infrastructure",
            "delivery",
            "engagement",
            "gui_action_injection",
            "host_execution",
        ],
        "slots": [
            ("ingress", "entry_point", "initial_ingress"),
            ("malicious_site", "integration", "intermediate"),
            ("computer_use_agent", "tool", "intermediate"),
            ("host", "integration", "target"),
            ("boundary", "trust_boundary", "supporting"),
        ],
        "forbidden_exact": {"AML.T0017", "AML.T0079", "AML.T0053"},
    },
    "AP-T17-03": {
        "threat_id": "T17",
        "chain_exact": {"AML.T0073", "AML.T0104"},
        "step_exact": {
            "namesquatting": {"AML.T0073"},
            "publish_poisoned_tool": {"AML.T0104"},
            "tool_invocation": {"AML.T0011.002"},
            "exfiltration": {"AML.T0086"},
        },
        "steps": [
            "namesquatting",
            "develop_poisoned_tool",
            "publish_poisoned_tool",
            "supply_chain_distribution",
            "persistence",
            "tool_invocation",
            "exfiltration",
            "impact",
        ],
        "slots": [
            ("ingress", "entry_point", "initial_ingress"),
            ("tool_registry", "integration", "intermediate"),
            ("adopter_agent", "tool", "target"),
            ("boundary", "trust_boundary", "supporting"),
        ],
        "forbidden_exact": {"AML.T0109", "AML.T0111"},
    },
    "AP-T17-04": {
        "threat_id": "T17",
        "chain_exact": {"AML.T0109"},
        "step_exact": {
            "rug_pull_timing": {"AML.T0111"},
            "exfiltration": {"AML.T0086"},
        },
        "steps": [
            "publish_clean_tool",
            "rug_pull_timing",
            "push_malicious_update",
            "upgrade_distribution",
            "persistence",
            "tool_invocation",
            "exfiltration",
            "impact",
        ],
        "slots": [
            ("ingress", "entry_point", "initial_ingress"),
            ("tool_registry", "integration", "intermediate"),
            ("adopter_agent", "tool", "target"),
            ("boundary", "trust_boundary", "supporting"),
        ],
        "forbidden_exact": {"AML.T0073", "AML.T0104", "AML.T0011.002"},
    },
}

# Golden semantic digests of the authored chains: any semantic content edit
# must recompute these deliberately, not silently.
GOLDEN_DIGESTS = {
    "AP-T1-06": "38383364034db7e3271fd90a08e92a0b7c1db4d9555072142af2414b06e8878e",
    "AP-T3-04": "93a03a7a305d7058009822af515e730b07e4d5dc29326daaa08b84842d44e3a6",
    "AP-T3-05": "ca9217bdba75680d1cb83639176d7a8fa17ee43e1dd63b7b15d557bb285ee379",
    "AP-T3-06": "08cf33bd33a7b81ce60e42af6ce9bc1c878d75931c3b88ae0fa78437cb35d57c",
    "AP-T6-06": "fb35ac820b8057257c5d205075b58e27706f0a58086110dbf169a2622ec4b5ef",
    "AP-T6-07": "58d830501c2ae7a774287876ac1241cf765182c85ef78082dc11527c95ca3f22",
    "AP-T11-05": "744ad30257f059d601dd516a10eb444dccc02b9b3aa24e42dd49fcc7ffb1d16a",
    "AP-T17-03": "545456368fee4cda0dd91625b9a33bdfaccc8ef711296eb5b488497ec0fdc5cb",
    "AP-T17-04": "8a3cc6fced543a69a60ab87c71c214d05f2bf09db6d20d0802efd025cf73a4d4",
}

# Split-derived first steps presuppose a sibling pattern's outcome; the
# precondition must be declared as an equality-true condition on a
# runtime_state boolean fact (existence(true) would pass a present-but-false
# fact, so equality on the boolean value is required).
EXPECTED_PRECONDITIONS = {
    ("AP-T3-05", "config_credential_harvest"): "control_interface_accessible",
    ("AP-T3-06", "arbitrary_prompting"): "control_interface_accessible",
    ("AP-T6-07", "config_modification"): "attacker_code_execution_on_agent_host",
}

# Exact expected edges: step_id -> (consumed, produced) as (kind, ref_id)
# sets. This is the causal total-order contract: activation and staging
# operations must be consumed by the steps they enable, never bypassed.
EXPECTED_EDGES: dict[str, dict[str, tuple[set, set]]] = {
    "AP-T1-06": {
        "craft_payload": (
            set(),
            {
                ("artifact", "artifact.disguised_payload"),
                ("state", "state.exfil_endpoint_staged"),
            },
        ),
        "deliver_content": (
            {("artifact", "artifact.disguised_payload")},
            {("state", "state.content_delivered")},
        ),
        "rag_ingestion": (
            {("state", "state.content_delivered")},
            {("state", "state.poisoned_corpus_entry")},
        ),
        "zero_click_activation": (
            {("state", "state.poisoned_corpus_entry")},
            {
                ("effect", "effect.injection_activated"),
                ("state", "state.injected_directive_active"),
            },
        ),
        "data_collection": (
            {("state", "state.injected_directive_active")},
            {("state", "state.sensitive_data_assembled")},
        ),
        "rendered_output_exfiltration": (
            {
                ("state", "state.sensitive_data_assembled"),
                ("state", "state.exfil_endpoint_staged"),
            },
            {("state", "state.trojanized_rendered_output")},
        ),
        "impact": (
            {("state", "state.trojanized_rendered_output")},
            {("effect", "effect.sensitive_data_exfiltrated")},
        ),
    },
    "AP-T3-04": {
        "reconnaissance": (set(), {("state", "state.exposed_interface_identified")}),
        "initial_access": (
            {("state", "state.exposed_interface_identified")},
            {("effect", "effect.unauthorized_interface_access")},
        ),
    },
    "AP-T3-05": {
        "config_credential_harvest": (
            set(),
            {
                ("state", "state.config_credentials_harvested"),
                ("state", "state.control_interface_channel"),
            },
        ),
        "env_credential_harvest": (
            {("state", "state.control_interface_channel")},
            {("state", "state.env_credentials_harvested")},
        ),
        "lateral_movement": (
            {
                ("state", "state.config_credentials_harvested"),
                ("state", "state.env_credentials_harvested"),
            },
            {("effect", "effect.connected_service_access")},
        ),
    },
    "AP-T3-06": {
        "arbitrary_prompting": (
            set(),
            {("state", "state.prompt_channel_established")},
        ),
        "privileged_tool_invocation": (
            {("state", "state.prompt_channel_established")},
            {("state", "state.privileged_invocation_initiated")},
        ),
        "impact": (
            {("state", "state.privileged_invocation_initiated")},
            {("effect", "effect.agent_machine_compromise")},
        ),
    },
    "AP-T6-06": {
        "reconnaissance": (set(), {("state", "state.agent_architecture_known")}),
        "discover_control_sequences": (
            {("state", "state.agent_architecture_known")},
            {("state", "state.control_sequences_discovered")},
        ),
        "craft_injection": (
            {("state", "state.control_sequences_discovered")},
            {("artifact", "artifact.spoofing_injection")},
        ),
        "stage_infrastructure": (
            {("artifact", "artifact.spoofing_injection")},
            {("state", "state.injection_staged")},
        ),
        "social_engineering_lure": (
            {("state", "state.injection_staged")},
            {("state", "state.victim_lured")},
        ),
        "initial_access": (
            {("state", "state.victim_lured")},
            {("state", "state.injection_in_context")},
        ),
        "injection_activation": (
            {("state", "state.injection_in_context")},
            {
                ("effect", "effect.injection_activated"),
                ("state", "state.injection_active"),
            },
        ),
        "control_sequence_spoofing": (
            {("state", "state.injection_active")},
            {("state", "state.authorization_spoofed")},
        ),
        "script_execution": (
            {("state", "state.authorization_spoofed")},
            {
                ("effect", "effect.injected_command_executed"),
                ("state", "state.attacker_script_executed"),
            },
        ),
    },
    "AP-T6-07": {
        "config_modification": (set(), {("state", "state.config_poisoned")}),
        "poisoned_prompt_activation": (
            {("state", "state.config_poisoned")},
            {
                ("effect", "effect.poisoned_prompt_active"),
                ("state", "state.poisoned_directive_active"),
            },
        ),
        "thread_context_persistence": (
            {("state", "state.poisoned_directive_active")},
            {("state", "state.thread_context_persistently_poisoned")},
        ),
        "c2_activation": (
            {("state", "state.thread_context_persistently_poisoned")},
            {
                ("effect", "effect.c2_commands_executed"),
                ("state", "state.c2_channel_active"),
            },
        ),
        "impact": (
            {("state", "state.c2_channel_active")},
            {("effect", "effect.persistent_agent_compromise")},
        ),
    },
    "AP-T11-05": {
        "generate_adversarial_content": (
            set(),
            {("artifact", "artifact.adversarial_web_content")},
        ),
        "stage_infrastructure": (
            {("artifact", "artifact.adversarial_web_content")},
            {("state", "state.malicious_site_staged")},
        ),
        "delivery": (
            {("state", "state.malicious_site_staged")},
            {("state", "state.content_in_agent_context")},
        ),
        "engagement": (
            {("state", "state.content_in_agent_context")},
            {("state", "state.clipboard_loaded")},
        ),
        "gui_action_injection": (
            {("state", "state.clipboard_loaded")},
            {
                ("effect", "effect.gui_sequence_directed"),
                ("state", "state.gui_direction_active"),
            },
        ),
        "host_execution": (
            {("state", "state.gui_direction_active")},
            {("effect", "effect.host_code_executed")},
        ),
    },
    "AP-T17-03": {
        "namesquatting": (set(), {("state", "state.registry_name_claimed")}),
        "develop_poisoned_tool": (set(), {("artifact", "artifact.poisoned_tool")}),
        "publish_poisoned_tool": (
            {
                ("state", "state.registry_name_claimed"),
                ("artifact", "artifact.poisoned_tool"),
            },
            {("state", "state.poisoned_tool_published")},
        ),
        "supply_chain_distribution": (
            {("state", "state.poisoned_tool_published")},
            {("state", "state.tool_installed")},
        ),
        "persistence": (
            {("state", "state.tool_installed")},
            {("state", "state.tool_persisted")},
        ),
        "tool_invocation": (
            {("state", "state.tool_persisted")},
            {
                ("effect", "effect.poisoned_tool_executed"),
                ("state", "state.invocation_channel_active"),
            },
        ),
        "exfiltration": (
            {("state", "state.invocation_channel_active")},
            {("state", "state.data_transmitted_to_attacker")},
        ),
        "impact": (
            {("state", "state.data_transmitted_to_attacker")},
            {("effect", "effect.sensitive_data_compromised")},
        ),
    },
    "AP-T17-04": {
        "publish_clean_tool": (set(), {("state", "state.clean_tool_published")}),
        "rug_pull_timing": (
            {("state", "state.clean_tool_published")},
            {("state", "state.adoption_accumulated")},
        ),
        "push_malicious_update": (
            {("state", "state.adoption_accumulated")},
            {("state", "state.malicious_update_published")},
        ),
        "upgrade_distribution": (
            {("state", "state.malicious_update_published")},
            {("state", "state.poisoned_version_installed")},
        ),
        "persistence": (
            {("state", "state.poisoned_version_installed")},
            {("state", "state.tool_persisted")},
        ),
        "tool_invocation": (
            {("state", "state.tool_persisted")},
            {
                ("effect", "effect.poisoned_tool_executed"),
                ("state", "state.invocation_channel_active"),
            },
        ),
        "exfiltration": (
            {("state", "state.invocation_channel_active")},
            {("state", "state.data_transmitted_to_attacker")},
        ),
        "impact": (
            {("state", "state.data_transmitted_to_attacker")},
            {("effect", "effect.sensitive_data_compromised")},
        ),
    },
}

# Steps whose exact (tier, confidence) is pinned beyond the generic tier
# bands: AP-T17-03's development/publication steps are temporally
# recomposed (CS0053 published legitimate versions before the malicious
# update), so they must be tiered variant; AP-T6-07's persistence step is
# pinned after its narrowing to within-thread semantics.
EXPECTED_STEP_TIERS = {
    ("AP-T17-03", "develop_poisoned_tool"): ("variant", 75),
    ("AP-T17-03", "publish_poisoned_tool"): ("variant", 80),
    ("AP-T6-07", "thread_context_persistence"): ("observed", 85),
}

_TIER_CONFIDENCE = {"observed": (85, 100), "variant": (60, 85), "inferred": (0, 60)}


@pytest.fixture(scope="module")
def records() -> dict[str, dict]:
    return load_attack_patterns(_FILE)


@pytest.fixture(scope="module")
def resolver():
    return load_taxonomy_resolver()


@pytest.fixture(scope="module")
def patterns(records, resolver) -> dict[str, AttackPattern]:
    return {pid: validate_attack_pattern(raw, resolver) for pid, raw in records.items()}


def _exact_ids(mappings) -> set[str]:
    return {tid for m in mappings if isinstance(m, ExactMapping) for tid in m.ids}


def _all_exact_ids(chain) -> set[str]:
    ids = _exact_ids(chain.mappings)
    for step in chain.steps:
        ids |= _exact_ids(step.mappings)
    return ids


def _step_by_id(chain, step_id: str):
    (step,) = [s for s in chain.steps if s.step_id == step_id]
    return step


class TestResultingSet:
    def test_exactly_the_nine_authoritative_ids(self, records):
        assert set(records) == set(EXPECTED)

    def test_merged_catalog_contains_all_nine_without_collision(self):
        merged = load_attack_patterns()
        for pid in EXPECTED:
            assert pid in merged
            assert merged[pid]["threat_id"] == EXPECTED[pid]["threat_id"]

    def test_threat_ids(self, patterns):
        for pid, pattern in patterns.items():
            assert pattern.threat_id == EXPECTED[pid]["threat_id"]


class TestLegacyIsolation:
    @pytest.mark.parametrize("pid", list(EXPECTED))
    def test_no_legacy_fields(self, records, pid):
        assert "kill_chain" not in records[pid]
        assert "evidence" not in records[pid]

    @pytest.mark.parametrize("pid", list(EXPECTED))
    def test_records_fail_legacy_validation(self, records, pid):
        with pytest.raises(ValidationError):
            validate_legacy_attack_pattern(records[pid])

    @pytest.mark.parametrize("pid", list(EXPECTED))
    def test_records_are_canonical_schema_valid(self, records, pid):
        schema = AttackPattern.model_json_schema()
        assert Draft202012Validator(schema).is_valid(records[pid])


class TestQualificationAndDigest:
    def test_taxonomy_context_pins_production_resolver(self, patterns, resolver):
        for pattern in patterns.values():
            context = pattern.canonical_chain.taxonomy_context
            assert context == resolver.taxonomy_context
            assert context.laaf is None

    @pytest.mark.parametrize("pid", list(EXPECTED))
    def test_semantic_digest_recomputes_and_matches_golden(self, records, pid):
        chain = records[pid]["canonical_chain"]
        assert chain["semantic_digest"] == GOLDEN_DIGESTS[pid]
        assert compute_chain_semantic_digest(chain) == GOLDEN_DIGESTS[pid]
        reordered = {key: chain[key] for key in reversed(chain)}
        assert compute_chain_semantic_digest(reordered) == GOLDEN_DIGESTS[pid]

    def test_resource_constraint_membership_order_is_not_semantic(self, records):
        chain = deepcopy(records["AP-T6-07"]["canonical_chain"])
        c2_slot = next(
            slot for slot in chain["resource_slots"] if slot["slot_id"] == "c2_channel"
        )
        c2_slot["allowed_integration_types"].reverse()
        assert compute_chain_semantic_digest(chain) == GOLDEN_DIGESTS["AP-T6-07"]

    def test_no_laaf_decisions_anywhere(self, records):
        for raw in records.values():
            chain = raw["canonical_chain"]
            scopes = [chain["mappings"], *(s["mappings"] for s in chain["steps"])]
            for mappings in scopes:
                for mapping in mappings:
                    assert mapping["taxonomy"] == "ATLAS"

    def test_every_exact_id_is_resolver_member(self, patterns, resolver):
        for pattern in patterns.values():
            for tid in _all_exact_ids(pattern.canonical_chain):
                assert resolver.contains("ATLAS", tid)


class TestLineageFidelity:
    @pytest.mark.parametrize("pid", list(EXPECTED))
    def test_chain_scope_exact_ids(self, patterns, pid):
        chain = patterns[pid].canonical_chain
        assert _exact_ids(chain.mappings) == EXPECTED[pid]["chain_exact"]
        assert any(isinstance(m, ExactMapping) for m in chain.mappings)

    @pytest.mark.parametrize("pid", list(EXPECTED))
    def test_step_scope_exact_ids(self, patterns, pid):
        chain = patterns[pid].canonical_chain
        actual = {
            step.step_id: _exact_ids(step.mappings)
            for step in chain.steps
            if _exact_ids(step.mappings)
        }
        assert actual == EXPECTED[pid]["step_exact"]

    @pytest.mark.parametrize("pid", list(EXPECTED))
    def test_split_boundary_exclusivity(self, patterns, pid):
        chain = patterns[pid].canonical_chain
        assert _all_exact_ids(chain).isdisjoint(EXPECTED[pid]["forbidden_exact"])

    @pytest.mark.parametrize("pid", list(EXPECTED))
    def test_step_sequence_and_total_order(self, patterns, pid):
        chain = patterns[pid].canonical_chain
        assert [s.step_id for s in chain.steps] == EXPECTED[pid]["steps"]
        assert [s.order for s in chain.steps] == list(
            range(1, len(EXPECTED[pid]["steps"]) + 1)
        )

    @pytest.mark.parametrize("pid", list(EXPECTED))
    def test_resource_slot_plan(self, patterns, pid):
        chain = patterns[pid].canonical_chain
        actual = [(s.slot_id, s.kind, s.purpose) for s in chain.resource_slots]
        assert sorted(actual) == sorted(EXPECTED[pid]["slots"])
        assert chain.initial_ingress_slot_id == "ingress"


class TestChainSemantics:
    @pytest.mark.parametrize("pid", list(EXPECTED))
    def test_start_and_terminal(self, patterns, pid):
        chain = patterns[pid].canonical_chain
        first, last = chain.steps[0], chain.steps[-1]
        assert first.attacker_controlled
        assert chain.earliest_attacker_controlled_step_id == first.step_id
        for step in chain.steps[:-1]:
            assert not any(
                p.security_relevant and p.terminal
                for p in step.observable_postconditions
            )
        assert any(
            p.security_relevant and p.terminal for p in last.observable_postconditions
        )

    @pytest.mark.parametrize("pid", list(EXPECTED))
    def test_consumed_references_link_to_earlier_produced(self, patterns, pid):
        chain = patterns[pid].canonical_chain
        produced_so_far: dict[str, str] = {}
        for step in chain.steps:
            for ref in step.consumed:
                assert ref.ref_id in produced_so_far, (
                    f"{pid}:{step.step_id} consumes {ref.ref_id} "
                    "which no earlier step produced"
                )
                assert ref.kind == produced_so_far[ref.ref_id]
                assert ref.kind in ("artifact", "state")
            for ref in step.produced:
                produced_so_far[ref.ref_id] = ref.kind

    @pytest.mark.parametrize("pid", list(EXPECTED))
    def test_executor_mapping_coherence(self, patterns, pid):
        for step in patterns[pid].canonical_chain.steps:
            if step.attacker_controlled:
                assert step.executor_role == "attacker"
                assert not any(m.decision == "not_applicable" for m in step.mappings)
                for m in step.mappings:
                    if m.decision == "unmapped":
                        assert m.rationale.strip()
            else:
                assert all(m.decision == "not_applicable" for m in step.mappings)

    @pytest.mark.parametrize("pid", list(EXPECTED))
    def test_provenance_tiers_confidence_and_lineage_reference(self, patterns, pid):
        for step in patterns[pid].canonical_chain.steps:
            lo, hi = _TIER_CONFIDENCE[step.provenance.tier]
            assert lo <= step.provenance.confidence <= hi
            assert step.provenance.adaptation_rationale.strip()
            refs = step.provenance.references
            assert (
                "design_record",
                f"catalog-lineage:{pid}",
            ) in {(r.reference_type, r.reference_id) for r in refs}

    @pytest.mark.parametrize(
        "pid,step_id",
        [(pid, sid) for pid, sid in EXPECTED_PRECONDITIONS],
    )
    def test_split_preconditions_declared(self, patterns, pid, step_id):
        step = _step_by_id(patterns[pid].canonical_chain, step_id)
        (pre,) = step.preconditions
        assert pre.condition.op == "equality"
        assert pre.condition.value is True
        fact = pre.condition.fact
        assert fact.namespace == "runtime_state"
        assert fact.value_type == "boolean"
        assert fact.fact_id == EXPECTED_PRECONDITIONS[(pid, step_id)]

    @pytest.mark.parametrize(
        "pid,step_id",
        [(pid, sid) for pid, sid in EXPECTED_PRECONDITIONS],
    )
    def test_split_preconditions_require_true_not_mere_presence(
        self, patterns, pid, step_id
    ):
        """A present-but-false boolean fact must fail the precondition.

        This is the regression guard for the ``existence(true)`` ->
        ``equality(true)`` correction: existence only checks presence, so a
        control interface that is present but not accessible would have
        qualified.
        """
        step = _step_by_id(patterns[pid].canonical_chain, step_id)
        (pre,) = step.preconditions
        fact = pre.condition.fact

        def evidence(status, value):
            return (EvaluatedFactEvidence(fact=fact, status=status, value=value),)

        assert evaluate_condition(pre.condition, evidence("present", True)) == "true"
        assert evaluate_condition(pre.condition, evidence("present", False)) == "false"
        assert evaluate_condition(pre.condition, evidence("absent", None)) == "false"
        assert evaluate_condition(pre.condition, evidence("unknown", None)) == "unknown"

    @pytest.mark.parametrize("pid", list(EXPECTED))
    def test_exact_expected_edges(self, patterns, pid):
        """Every step's consumed/produced references match the pinned edges."""
        chain = patterns[pid].canonical_chain
        expected = EXPECTED_EDGES[pid]
        assert {s.step_id for s in chain.steps} == set(expected)
        for step in chain.steps:
            consumed_expected, produced_expected = expected[step.step_id]
            consumed = {(ref.kind, ref.ref_id) for ref in step.consumed}
            produced = {(ref.kind, ref.ref_id) for ref in step.produced}
            assert consumed == consumed_expected, f"{pid}:{step.step_id} consumed"
            assert produced == produced_expected, f"{pid}:{step.step_id} produced"

    @pytest.mark.parametrize("pid", list(EXPECTED))
    def test_no_produced_state_or_artifact_dead_ends(self, patterns, pid):
        """Non-final produced states/artifacts must be consumed downstream.

        Effects are terminal events and the final step's outputs close the
        chain; everything else unconsumed is a bypassed operation.
        """
        chain = patterns[pid].canonical_chain
        consumed_later: set[str] = set()
        for step in chain.steps[1:]:
            consumed_later |= {ref.ref_id for ref in step.consumed}
        for step in chain.steps[:-1]:
            for ref in step.produced:
                if ref.kind == "effect":
                    continue
                assert ref.ref_id in consumed_later, (
                    f"{pid}:{step.step_id} produces {ref.ref_id} "
                    "which no later step consumes (bypassed operation)"
                )

    @pytest.mark.parametrize(
        "pid,step_id",
        [(pid, sid) for pid, sid in EXPECTED_STEP_TIERS],
    )
    def test_pinned_step_tiers(self, patterns, pid, step_id):
        step = _step_by_id(patterns[pid].canonical_chain, step_id)
        tier, confidence = EXPECTED_STEP_TIERS[(pid, step_id)]
        assert step.provenance.tier == tier
        assert step.provenance.confidence == confidence

    @pytest.mark.parametrize(
        "pid,step_id",
        [
            ("AP-T17-03", "develop_poisoned_tool"),
            ("AP-T17-03", "publish_poisoned_tool"),
        ],
    )
    def test_recomposed_timing_steps_rationalize_variant(self, patterns, pid, step_id):
        """Variant-tiered timing steps must state the observed-vs-recomposed
        split explicitly: CS0053 published legitimate versions first."""
        step = _step_by_id(patterns[pid].canonical_chain, step_id)
        rationale = step.provenance.adaptation_rationale
        assert "legitimate" in rationale
        assert "recomposition" in rationale
        assert "AP-T17-04" in rationale

    def test_t3_06_privileged_step_is_invocation_only_impact_owns_execution(
        self, patterns
    ):
        """Successful root execution lives only at the terminal impact."""
        chain = patterns["AP-T3-06"].canonical_chain
        invocation = _step_by_id(chain, "privileged_tool_invocation")
        (post,) = invocation.observable_postconditions
        assert "initiates" in post.description
        assert "executes attacker-directed commands as root" not in post.description
        assert not post.terminal
        impact = _step_by_id(chain, "impact")
        (terminal,) = impact.observable_postconditions
        assert terminal.terminal and terminal.security_relevant
        assert "executes attacker-directed commands as root" in terminal.description

    def test_t6_07_t0080_001_stays_within_thread_semantics(self, patterns):
        """AML.T0080.001 is remainder-of-a-thread persistence; the claim that
        every new thread is poisoned must be attributed to AML.T0081."""
        chain = patterns["AP-T6-07"].canonical_chain
        step = _step_by_id(chain, "thread_context_persistence")
        (post,) = step.observable_postconditions
        assert "remainder of that thread" in post.description
        assert "spans all future interactions" not in post.description
        rationale = step.provenance.adaptation_rationale
        assert "pinned technique definition AML.T0080.001" in rationale
        assert "AML.T0081" in rationale


class TestEvidenceAndRationale:
    @pytest.mark.parametrize("pid", list(EXPECTED))
    def test_chain_exact_ids_have_identity_and_evidence_in_description(
        self, patterns, pid
    ):
        description = patterns[pid].description
        for tid in EXPECTED[pid]["chain_exact"]:
            assert tid in description
            window = description.split(tid, 1)[1]
            window = re.split(r"AML\.T\d{4}(?:\.\d{3})? —", window)[0]
            assert "exact" in window.lower()
            assert "AML.CS" in window
            assert "pinned technique definition" in window
