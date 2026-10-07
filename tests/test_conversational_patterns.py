"""Contract tests for the single-session conversational attack patterns.

The four patterns cover OWASP LLM categories that no other catalog record
realizes without persistent memory or tools: sensitive-data elicitation
(LLM02), system prompt extraction (LLM07), jailbreak for prohibited content
(LLM01), and hallucinated-reference elicitation (LLM09).
"""

from __future__ import annotations

import pytest
import yaml

from asago_scenario_generator.data.loaders import load_attack_patterns
from asago_scenario_generator.data.paths import DATA_ROOT
from asago_scenario_generator.data.taxonomy_pins import load_taxonomy_resolver
from asago_scenario_generator.data.threat_gating import determine_threat_scope
from asago_scenario_generator.models import CapabilityProfile
from asago_scenario_generator.models.attack_pattern import (
    compute_chain_semantic_digest,
    validate_attack_pattern,
)

_LLM_TABLE = DATA_ROOT / "taxonomies" / "mappings" / "llm-to-attack-pattern.yaml"
_CATALOG_FILE = (
    DATA_ROOT / "taxonomies" / "attack-patterns" / "attack-patterns-conversational.yaml"
)

# pattern id -> (threat, exact ATLAS ids at chain scope, OWASP LLM categories)
EXPECTED = {
    "AP-T6-08": ("T6", {"AML.T0057"}, ["LLM02"]),
    "AP-T6-09": ("T6", {"AML.T0056"}, ["LLM07"]),
    "AP-T6-10": ("T6", {"AML.T0054"}, ["LLM01"]),
    "AP-T5-05": ("T5", {"AML.T0062"}, ["LLM09"]),
}


def _chain_exact_ids(pattern: dict) -> set[str]:
    return {
        identifier
        for mapping in pattern["canonical_chain"]["mappings"]
        if mapping["decision"] == "exact"
        for identifier in mapping["ids"]
    }


def _bare_language_model_profile() -> CapabilityProfile:
    return CapabilityProfile(
        zones_active=["input", "reasoning"],
        entry_points=["user input (zone 1)"],
        confidence="medium",
        kc_subcodes=["KC1.1"],
    )


@pytest.fixture(scope="module")
def catalog() -> dict[str, dict]:
    return load_attack_patterns()


class TestCatalogRecords:
    def test_the_four_patterns_live_in_their_own_catalog_file(self):
        file_ids = set(yaml.safe_load(_CATALOG_FILE.read_text())["patterns"])

        assert file_ids == set(EXPECTED)

    @pytest.mark.parametrize("pattern_id", sorted(EXPECTED))
    def test_threat_and_atlas_identity(self, catalog, pattern_id):
        threat, atlas_ids, _ = EXPECTED[pattern_id]
        pattern = catalog[pattern_id]

        assert pattern["id"] == pattern_id
        assert pattern["threat_id"] == threat
        assert _chain_exact_ids(pattern) == atlas_ids

    @pytest.mark.parametrize("pattern_id", sorted(EXPECTED))
    def test_pattern_validates_and_its_digest_recomputes(self, catalog, pattern_id):
        raw = catalog[pattern_id]

        validate_attack_pattern(raw, load_taxonomy_resolver())
        chain = raw["canonical_chain"]
        assert chain["semantic_digest"] == compute_chain_semantic_digest(chain)

    @pytest.mark.parametrize("pattern_id", sorted(EXPECTED))
    def test_gating_needs_only_a_language_model(self, catalog, pattern_id):
        prerequisites = catalog[pattern_id]["prerequisite_capabilities"]

        assert prerequisites["kc_requires"] == {
            "any": ["KC1.1", "KC1.2", "KC1.3", "KC1.4"]
        }

    @pytest.mark.parametrize("pattern_id", sorted(EXPECTED))
    def test_chain_is_single_session_without_memory_or_tools(self, catalog, pattern_id):
        chain = catalog[pattern_id]["canonical_chain"]

        assert {slot["kind"] for slot in chain["resource_slots"]} <= {
            "entry_point",
            "output_surface",
        }
        for step in chain["steps"]:
            assert step["preconditions"] == []
            assert step["requirement"] == "required"
            assert all(link["role"] == "ingress" for link in step["resource_links"])

    @pytest.mark.parametrize("pattern_id", sorted(EXPECTED))
    def test_chain_ends_on_an_observable_response(self, catalog, pattern_id):
        chain = catalog[pattern_id]["canonical_chain"]
        final = chain["steps"][-1]

        assert final["executor_role"] == "system"
        assert [link["observation"] for link in final["observable_outcome_links"]] == [
            "rendered_output"
        ]


class TestGating:
    def test_a_bare_language_model_keeps_all_four_patterns(self):
        scope = determine_threat_scope(_bare_language_model_profile())

        kept = {
            pattern_id
            for entry in scope.in_scope
            for pattern_id in entry.attack_pattern_ids
        }
        assert set(EXPECTED) <= kept


class TestLlmTable:
    def test_each_pattern_lists_its_reviewed_categories_and_a_rationale(self):
        table = {
            entry["id"]: entry
            for entry in yaml.safe_load(_LLM_TABLE.read_text())["patterns"]
        }

        for pattern_id, (_, _, categories) in EXPECTED.items():
            assert table[pattern_id]["llm"] == categories
            assert table[pattern_id]["rationale"].strip()
