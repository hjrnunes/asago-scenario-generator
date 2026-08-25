"""Tests for the Tier 1 deterministic evaluation framework."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from asago_scenario_generator.eval.consistency import (
    _extract_gherkin_zones,
    _gherkin_background_text,
    entry_point_agreement,
    score_consistency,
    step_node_correspondence,
    zone_alignment,
)
from asago_scenario_generator.eval.diversity import (
    actor_type_entropy,
    capability_level_evenness,
    entry_point_entropy,
    score_diversity,
    title_uniqueness,
    zone_coverage,
)
from asago_scenario_generator.eval.gherkin import (
    has_background,
    parse_success,
    score_gherkin,
    step_count,
    step_keyword_balance,
    tag_consistency,
)
from asago_scenario_generator.eval.grounding import (
    score_grounding,
    score_technique_agreement,
)
from asago_scenario_generator.eval.plausibility import (
    capability_complexity_violations,
    score_plausibility,
)
from asago_scenario_generator.eval.runner import run_evaluation
from tests.manifest_helpers import build_test_run_dir

# ---------------------------------------------------------------------------
# Fixtures: synthetic scenario data
# ---------------------------------------------------------------------------


def _make_scenario(
    scenario_id: str = "scenario:v2:ae309cc9a43cb233c07a684edc2a8cd7d11c05ac17af6f10d5c8a9ac93927c7d",
    title: str = "Exploit Agent Reasoning via Prompt Injection",
    entry_point: str = "user prompts (zone input)",
    zone_sequence: list[str] | None = None,
    steps: list[dict[str, Any]] | None = None,
    root_zone: str = "input",
    root_label: str = "Compromise agent via user prompts",
    root_threat_id: str = "T7",
    leaf_nodes: list[dict[str, Any]] | None = None,
    actor_type: str = "adversarial-user",
    capability_level: str = "intermediate",
) -> dict[str, Any]:
    """Build a minimal synthetic scenario dict."""
    if zone_sequence is None:
        zone_sequence = ["input", "reasoning", "tool_execution"]
    if steps is None:
        steps = [
            {
                "step_number": 1,
                "zone": "input",
                "action": "Craft a malicious user prompt targeting the agent",
                "effect": "Agent receives adversarial input",
            },
            {
                "step_number": 2,
                "zone": "reasoning",
                "action": "Exploit agent reasoning to bypass safety filters",
                "effect": "Agent processes malicious instructions",
            },
            {
                "step_number": 3,
                "zone": "tool_execution",
                "action": "Exfiltrate data via tool execution",
                "effect": "Sensitive data exposed to attacker",
            },
        ]

    if leaf_nodes is None:
        leaf_nodes = [
            {
                "id": "n1.1",
                "label": "Craft malicious prompt",
                "gate": "LEAF",
                "zone": "input",
                "threat_id": root_threat_id,
            },
            {
                "id": "n1.2",
                "label": "Bypass reasoning safety filters",
                "gate": "LEAF",
                "zone": "reasoning",
                "threat_id": root_threat_id,
            },
        ]

    return {
        "scenario_id": scenario_id,
        "candidate_id": f"cand:v2:{hashlib.sha256(scenario_id.encode()).hexdigest()[:32]}",
        "narrative": {
            "title": title,
            "summary": "An adversarial user exploits agent reasoning.",
            "entry_point": entry_point,
            "zone_sequence": zone_sequence,
            "steps": steps,
        },
        "attack_tree": {
            "id": "tree-AP-T7-01",
            "seed_id": "AP-T7-01",
            "goal": "Compromise agent via prompt injection",
            "root": {
                "id": "n1",
                "label": root_label,
                "gate": "AND",
                "zone": root_zone,
                "threat_id": root_threat_id,
                "children": leaf_nodes,
            },
        },
        "actor_profile": {
            "actor_type": actor_type,
            "capability_level": capability_level,
            "beliefs": ["The system has a public chat API"],
            "desires": ["Exfiltrate customer data"],
            "intentions": ["Use prompt injection via the chat interface"],
            "resources": ["open-source tools"],
        },
        "faceting": {
            "risk_card": {
                "risk_id": "atlas-prompt-injection",
                "risk_name": "Prompt Injection",
                "risk_description": "Attacker injects instructions",
                "taxonomy": "ibm-risk-atlas",
                "confidence": 0.95,
                "grounding_confidence": "high",
            },
            "taxonomy_chain": {
                "owasp_llm_ids": ["LLM01"],
                "agentic_threat_ids": ["T7"],
                "scenario_seed": "AP-T7-01",
            },
            "capability_profile": {
                "zones_traversed": zone_sequence,
                "architecture_match": "explicit",
                "entry_point": entry_point,
            },
            "maestro_layers": [1, 2],
        },
        "priority": {
            "composite": 0.85,
            "signals": {
                "technique_maturity": "demonstrated",
                "risk_impact": "high",
                "risk_likelihood": "high",
                "attack_complexity": "low",
                "architecture_match": "explicit",
                "structural_exposure": "single_point_of_failure",
            },
        },
    }


_GHERKIN_VALID = """\
@misaligned-and-deceptive-behavior
Feature: Exploit Agent Reasoning via Prompt Injection

  Background:
    Given an AI agent with user prompts as the primary entry point
    And the agent has access to external tools

  Scenario: Adversarial user injects malicious prompt
    # Zone input
    When the adversarial user crafts a malicious prompt
    Then the agent receives adversarial input
    # Zone reasoning
    When the agent processes the malicious instructions
    Then the safety filters are bypassed
    # Zone tool_execution
    When the attacker exfiltrates data via tool execution
    Then sensitive data is exposed
"""

_GHERKIN_MINIMAL = """\
Feature: Minimal test

  Scenario: Basic
    Given a system
    When something happens
    Then it works
"""

_GHERKIN_INVALID = "This is not valid Gherkin at all."


# ===========================================================================
# Consistency tests
# ===========================================================================


class TestZoneAlignment:
    def test_perfect_alignment(self):
        scenario = _make_scenario(
            zone_sequence=["input", "reasoning", "tool_execution"]
        )
        # Tree root is zone "input", children are zones "input" and "reasoning"
        # Narrative zones: {"input", "reasoning", "tool_execution"}, Tree zones: {"input", "reasoning"}
        score = zone_alignment(scenario)
        assert 0.0 <= score <= 1.0

    def test_with_gherkin(self):
        scenario = _make_scenario(
            zone_sequence=["input", "reasoning", "tool_execution"]
        )
        score = zone_alignment(scenario, _GHERKIN_VALID)
        assert 0.0 <= score <= 1.0

    def test_identical_zones(self):
        scenario = _make_scenario(
            zone_sequence=["input", "reasoning"],
            steps=[
                {"step_number": 1, "zone": "input", "action": "act", "effect": "eff"},
                {
                    "step_number": 2,
                    "zone": "reasoning",
                    "action": "act",
                    "effect": "eff",
                },
            ],
        )
        # Narrative zones {"input", "reasoning"}, Tree zones {"input", "reasoning"} -> Jaccard = 1.0
        score = zone_alignment(scenario)
        assert score == 1.0

    def test_no_zones(self):
        scenario = _make_scenario(zone_sequence=[])
        scenario["attack_tree"]["root"]["zone"] = "input"
        score = zone_alignment(scenario)
        assert 0.0 <= score <= 1.0


class TestExtractGherkinZones:
    def test_numeric_annotation(self) -> None:
        assert _extract_gherkin_zones("# Zone 2") == {"reasoning"}

    def test_display_name_annotation(self) -> None:
        assert _extract_gherkin_zones("# Zone Planning & Reasoning") == {"reasoning"}

    def test_unknown_annotation_ignored(self) -> None:
        assert _extract_gherkin_zones("# Zone unknownzone") == set()

    def test_no_annotations(self) -> None:
        assert _extract_gherkin_zones("Given a step") == set()


class TestGherkinBackgroundText:
    def test_none_text(self) -> None:
        assert _gherkin_background_text(None) is None

    def test_empty_text(self) -> None:
        assert _gherkin_background_text("") is None

    def test_no_background_section(self) -> None:
        assert _gherkin_background_text("Feature: x\nScenario: y") is None

    def test_background_section(self) -> None:
        text = "Feature: x\nBackground: Given a seed\nScenario: y"
        background = _gherkin_background_text(text)
        assert background is not None
        assert "seed" in background


class TestEntryPointAgreement:
    def test_entry_in_gherkin_background(self):
        scenario = _make_scenario(entry_point="user prompts (zone input)")
        result = entry_point_agreement(scenario, _GHERKIN_VALID)
        assert result == 1

    def test_entry_in_tree_root(self):
        scenario = _make_scenario(
            entry_point="user prompts",
            root_label="Compromise agent via user prompts",
        )
        result = entry_point_agreement(scenario)
        assert result == 1

    def test_entry_nowhere(self):
        scenario = _make_scenario(
            entry_point="completely unrelated xyz abc",
            root_label="Something totally different qrs",
        )
        result = entry_point_agreement(scenario)
        assert result == 0

    def test_gherkin_background_without_entry_point(self):
        scenario = _make_scenario(
            entry_point="completely unrelated xyz abc",
            root_label="Something totally different qrs",
        )
        result = entry_point_agreement(scenario, _GHERKIN_VALID)
        assert result == 0

    def test_entry_only_in_gherkin_background(self):
        scenario = _make_scenario(
            entry_point="primary entry point",
            root_label="Compromise agent via user prompts",
        )
        result = entry_point_agreement(scenario, _GHERKIN_VALID)
        assert result == 1

    def test_empty_entry_point(self):
        scenario = _make_scenario(entry_point="")
        result = entry_point_agreement(scenario)
        assert result == 0


class TestStepNodeCorrespondence:
    def test_some_matches(self):
        scenario = _make_scenario()
        score = step_node_correspondence(scenario)
        assert 0.0 <= score <= 1.0

    def test_no_steps(self):
        scenario = _make_scenario(steps=[])
        score = step_node_correspondence(scenario)
        assert score == 0.0

    def test_perfect_match(self):
        """Steps and leaves in the same zones with shared keywords."""
        scenario = _make_scenario(
            steps=[
                {
                    "step_number": 1,
                    "zone": "input",
                    "action": "Craft malicious prompt injection",
                    "effect": "Agent compromised",
                },
            ],
            leaf_nodes=[
                {
                    "id": "n1.1",
                    "label": "Craft malicious prompt",
                    "gate": "LEAF",
                    "zone": "input",
                    "threat_id": "T7",
                },
                {
                    "id": "n1.2",
                    "label": "Other node",
                    "gate": "LEAF",
                    "zone": "reasoning",
                    "threat_id": "T7",
                },
            ],
        )
        score = step_node_correspondence(scenario)
        assert score == 1.0


class TestScoreConsistency:
    def test_returns_all_keys(self):
        scenario = _make_scenario()
        result = score_consistency(scenario, _GHERKIN_VALID)
        assert "zone_alignment" in result
        assert "entry_point_agreement" in result
        assert "step_node_correspondence" in result
        assert "mean" in result

    def test_mean_is_average(self):
        scenario = _make_scenario()
        result = score_consistency(scenario)
        expected_mean = (
            result["zone_alignment"]
            + result["entry_point_agreement"]
            + result["step_node_correspondence"]
        ) / 3
        assert abs(result["mean"] - round(expected_mean, 4)) < 0.001


# ===========================================================================
# Gherkin tests
# ===========================================================================


class TestParseSuccess:
    def test_valid_gherkin(self):
        assert parse_success(_GHERKIN_VALID) is True

    def test_minimal_gherkin(self):
        assert parse_success(_GHERKIN_MINIMAL) is True

    def test_invalid_gherkin(self):
        assert parse_success(_GHERKIN_INVALID) is False


class TestStepCount:
    def test_counts_all_keywords(self):
        count = step_count(_GHERKIN_VALID)
        assert count > 0

    def test_minimal(self):
        count = step_count(_GHERKIN_MINIMAL)
        assert count == 3  # Given, When, Then

    def test_empty(self):
        assert step_count("") == 0


class TestHasBackground:
    def test_with_background(self):
        assert has_background(_GHERKIN_VALID) is True

    def test_without_background(self):
        assert has_background(_GHERKIN_MINIMAL) is False


class TestStepKeywordBalance:
    def test_balance(self):
        balance = step_keyword_balance(_GHERKIN_VALID)
        assert balance["Given"] > 0
        assert balance["When"] > 0
        assert balance["Then"] > 0


class TestTagConsistency:
    def test_consistent_tags(self):
        texts = [
            "@prompt-injection\nFeature: A",
            "@prompt-injection\nFeature: B",
        ]
        result = tag_consistency(texts)
        assert result["inconsistent_groups"] == 0

    def test_inconsistent_tags(self):
        texts = [
            "@misaligned-and-deceptive-behavior\nFeature: A",
            "@misaligned-deceptive-behaviors\nFeature: B",
        ]
        result = tag_consistency(texts)
        # These should normalize to the same form
        assert result["inconsistent_groups"] >= 1

    def test_empty_input(self):
        result = tag_consistency([])
        assert result["inconsistent_groups"] == 0


class TestScoreGherkin:
    def test_batch_metrics(self):
        result = score_gherkin([_GHERKIN_VALID, _GHERKIN_MINIMAL])
        assert "parse_success_rate" in result
        assert "mean_step_count" in result
        assert "tag_consistency" in result
        assert "background_missing_warnings" in result
        assert result["parse_success_rate"] == 1.0
        # _GHERKIN_MINIMAL has no Background, so index 1 should be warned
        assert 1 in result["background_missing_warnings"]
        assert 0 not in result["background_missing_warnings"]

    def test_empty_batch(self):
        result = score_gherkin([])
        assert result["parse_success_rate"] == 0.0
        assert result["mean_step_count"] == 0.0

    def test_mixed_validity(self):
        result = score_gherkin([_GHERKIN_VALID, _GHERKIN_INVALID])
        assert result["parse_success_rate"] == 0.5

    def test_no_background_rate_in_output(self):
        """background_rate and mean_zone_annotation_rate are removed."""
        result = score_gherkin([_GHERKIN_VALID])
        assert "background_rate" not in result
        assert "mean_zone_annotation_rate" not in result

    def test_background_warning_emitted(self, caplog):
        """Warning is logged when a feature file lacks a Background."""
        import logging

        with caplog.at_level(logging.WARNING):
            result = score_gherkin([_GHERKIN_MINIMAL])
        assert result["background_missing_warnings"] == [0]
        assert "lacks a Background section" in caplog.text

    def test_all_have_background(self):
        result = score_gherkin([_GHERKIN_VALID, _GHERKIN_VALID])
        assert result["background_missing_warnings"] == []


# ===========================================================================
# Grounding tests
# ===========================================================================


class TestScoreGrounding:
    def test_valid_threat_ids(self):
        scenarios = [_make_scenario(root_threat_id="T7")]
        result = score_grounding(scenarios)
        # T7 is a valid OWASP agentic threat
        assert result["threat_id_validity"] == 1.0
        assert result["dangling_references"] == 0

    def test_invalid_threat_id(self):
        scenarios = [_make_scenario(root_threat_id="T99")]
        result = score_grounding(scenarios)
        assert result["threat_id_validity"] < 1.0
        assert result["dangling_references"] > 0

    def test_no_threats(self):
        scenario = _make_scenario()
        scenario["attack_tree"]["root"]["threat_id"] = None
        for child in scenario["attack_tree"]["root"]["children"]:
            child["threat_id"] = None
        result = score_grounding([scenario])
        # No references at all -> validity 1.0
        assert result["threat_id_validity"] == 1.0
        assert result["dangling_references"] == 0

    def test_mixed_validity(self):
        s1 = _make_scenario(
            root_threat_id="T7",
            scenario_id="scenario:v2:e8bc163c82eee18733288c7d4ac636db3a6deb013ef2d37b68322be20edc45cc",
        )
        s2 = _make_scenario(
            root_threat_id="T99",
            scenario_id="scenario:v2:ad328846aa18b32a335816374511cac1063c704b8c57999e51da9f908290a7a4",
        )
        result = score_grounding([s1, s2])
        assert 0.0 < result["threat_id_validity"] < 1.0

    def test_technique_ids_grounded(self):
        """Leaf IDs are grounded by exact projected-step mappings."""
        scenario = _make_scenario()
        # Add technique_ids to tree nodes
        scenario["attack_tree"]["root"]["children"][0]["technique_id"] = "AML.T0051.000"
        scenario["attack_tree"]["root"]["children"][1]["technique_id"] = "AML.T0054"
        # Scenario classifications are intentionally a separate scope.
        scenario["faceting"]["taxonomy_chain"]["atlas_technique_ids"] = [
            "AML.T0051.001",
            "AML.T0054",
        ]
        scenario["technique_scope_evidence"] = {
            "scenario_classification_ids": ["AML.T0051.001", "AML.T0054"],
            "projected_step_mapping_ids": ["AML.T0051.000", "AML.T0054"],
            "narrative_reference_ids": [],
            "legacy_derived": False,
        }
        result = score_grounding([scenario])
        assert result["technique_id_grounding"] == 1.0
        assert result["ungrounded_technique_references"] == 0
        assert result["scenario_classifications"] == [
            "AML.T0051.001",
            "AML.T0054",
        ]
        assert result["projected_step_mappings"] == [
            "AML.T0051.000",
            "AML.T0054",
        ]

    def test_technique_ids_ungrounded(self):
        """Leaf IDs absent from projected-step mappings are ungrounded."""
        scenario = _make_scenario()
        scenario["attack_tree"]["root"]["children"][0]["technique_id"] = "AML.T9999"
        scenario["technique_scope_evidence"] = {
            "scenario_classification_ids": ["AML.T9999"],
            "projected_step_mapping_ids": ["AML.T0051.000"],
            "narrative_reference_ids": [],
            "legacy_derived": False,
        }
        result = score_grounding([scenario])
        assert result["technique_id_grounding"] < 1.0
        assert result["ungrounded_technique_references"] == 1
        assert (
            result["ungrounded_technique_details"][0]["reason"]
            == "not_in_projected_step_mappings"
        )

    def test_technique_ids_without_projected_mapping_scope(self):
        scenario = _make_scenario()
        scenario["attack_tree"]["root"]["children"][0]["technique_id"] = "AML.T0051.000"
        scenario["technique_scope_evidence"] = {
            "scenario_classification_ids": ["AML.T0051.000"],
            "projected_step_mapping_ids": [],
            "narrative_reference_ids": [],
            "legacy_derived": False,
        }
        result = score_grounding([scenario])
        assert result["technique_id_grounding"] == 0.0
        assert result["ungrounded_technique_references"] == 1
        assert (
            result["ungrounded_technique_details"][0]["reason"]
            == "no_projected_step_mapping_ids"
        )

    def test_no_technique_ids_default_grounded(self):
        """When no technique_ids in tree, grounding defaults to 1.0."""
        scenario = _make_scenario()
        result = score_grounding([scenario])
        assert result["technique_id_grounding"] == 1.0
        assert result["ungrounded_technique_references"] == 0

    def test_mixed_technique_grounding(self):
        """Mix of grounded and ungrounded technique_ids."""
        scenario = _make_scenario()
        scenario["attack_tree"]["root"]["children"][0]["technique_id"] = "AML.T0051.000"
        scenario["attack_tree"]["root"]["children"][1]["technique_id"] = "AML.T9999"
        scenario["technique_scope_evidence"] = {
            "scenario_classification_ids": ["AML.T0054"],
            "projected_step_mapping_ids": ["AML.T0051.000"],
            "narrative_reference_ids": [],
            "legacy_derived": False,
        }
        result = score_grounding([scenario])
        assert result["technique_id_grounding"] == 0.5
        assert result["ungrounded_technique_references"] == 1


# ===========================================================================
# Technique Agreement tests
# ===========================================================================


class TestScoreTechniqueAgreement:
    """Cross-lens technique agreement metric."""

    def test_tree_and_spec_identical(self):
        """Tree and spec have the same technique set -> agreement 1.0."""
        scenario = _make_scenario(
            scenario_id="scenario:v2:e8bc163c82eee18733288c7d4ac636db3a6deb013ef2d37b68322be20edc45cc"
        )
        # Add technique_ids to attack tree nodes
        scenario["attack_tree"]["root"]["children"][0]["technique_id"] = "AML.T0054"
        scenario["attack_tree"]["root"]["children"][1]["technique_id"] = "AML.T0051.000"
        # Add behavior_spec with same technique annotations
        scenario["behavior_spec"] = (
            "Feature: Test\n"
            "  Scenario: Attack\n"
            "    When the attacker uses jailbreak [AML.T0054]\n"
            "    And injects prompt [AML.T0051.000]\n"
        )

        result = score_technique_agreement([scenario])
        assert result["mean_technique_agreement"] == 1.0
        assert "per_scenario" not in result

    def test_narrative_extra_technique_ignored(self):
        """Narrative extras don't affect tree-vs-spec agreement."""
        scenario = _make_scenario(
            scenario_id="scenario:v2:e8bc163c82eee18733288c7d4ac636db3a6deb013ef2d37b68322be20edc45cc"
        )
        # Narrative has 2 techniques (ignored for score)
        scenario["narrative"]["steps"][0]["action"] = (
            "Exploit via [AML.T0054] and [AML.T0051.000]"
        )
        # Tree has 1 technique
        scenario["attack_tree"]["root"]["children"][0]["technique_id"] = "AML.T0054"
        # Spec has 1 technique -- same as tree
        scenario["behavior_spec"] = "When [AML.T0054] is used"

        result = score_technique_agreement([scenario])
        # Tree {AML.T0054} vs spec {AML.T0054} -> Jaccard 1.0
        assert result["mean_technique_agreement"] == 1.0
        assert "per_scenario" not in result

    def test_tree_missing_technique(self):
        """Tree is missing a technique that spec has -> agreement < 1.0."""
        scenario = _make_scenario(
            scenario_id="scenario:v2:e8bc163c82eee18733288c7d4ac636db3a6deb013ef2d37b68322be20edc45cc"
        )
        # Tree has NO technique_id
        # Spec has technique
        scenario["behavior_spec"] = "When [AML.T0054] is applied"

        result = score_technique_agreement([scenario])
        # Tree {} vs spec {AML.T0054} -> Jaccard 0.0
        assert result["mean_technique_agreement"] == 0.0
        detail = result["per_scenario"][
            "scenario:v2:e8bc163c82eee18733288c7d4ac636db3a6deb013ef2d37b68322be20edc45cc"
        ]
        assert "AML.T0054" in detail.get("missing_from_tree", [])

    def test_no_techniques_in_any_lens(self):
        """No techniques anywhere -> vacuous agreement 1.0."""
        scenario = _make_scenario(
            scenario_id="scenario:v2:e8bc163c82eee18733288c7d4ac636db3a6deb013ef2d37b68322be20edc45cc"
        )
        # Default scenario has no technique annotations or technique_ids

        result = score_technique_agreement([scenario])
        assert result["mean_technique_agreement"] == 1.0
        assert "per_scenario" not in result

    def test_gherkin_files_fallback(self):
        """Uses gherkin_files dict when behavior_spec is absent."""
        scenario = _make_scenario(
            scenario_id="scenario:v2:e8bc163c82eee18733288c7d4ac636db3a6deb013ef2d37b68322be20edc45cc"
        )
        scenario["attack_tree"]["root"]["children"][0]["technique_id"] = "AML.T0054"
        # No behavior_spec on scenario dict -- falls back to gherkin_files

        gherkin_files = {
            "scenario:v2:e8bc163c82eee18733288c7d4ac636db3a6deb013ef2d37b68322be20edc45cc": "When the attacker uses [AML.T0054]"
        }
        result = score_technique_agreement([scenario], gherkin_files)
        # Tree {AML.T0054} vs spec {AML.T0054} -> Jaccard 1.0
        assert result["mean_technique_agreement"] == 1.0

    def test_multiple_scenarios_mean(self):
        """Mean is averaged across scenarios."""
        # Scenario 1: perfect tree-spec agreement (1.0)
        s1 = _make_scenario(
            scenario_id="scenario:v2:e8bc163c82eee18733288c7d4ac636db3a6deb013ef2d37b68322be20edc45cc"
        )
        s1["attack_tree"]["root"]["children"][0]["technique_id"] = "AML.T0054"
        s1["behavior_spec"] = "When [AML.T0054]"

        # Scenario 2: no tree-spec overlap (0.0)
        s2 = _make_scenario(
            scenario_id="scenario:v2:ad328846aa18b32a335816374511cac1063c704b8c57999e51da9f908290a7a4"
        )
        s2["attack_tree"]["root"]["children"][0]["technique_id"] = "AML.T0051.000"
        s2["behavior_spec"] = "When [AML.T0053]"

        result = score_technique_agreement([s1, s2])
        # s1 = 1.0, s2 = 0.0 (two disjoint singletons -> intersection 0 / union 2)
        assert result["mean_technique_agreement"] == 0.5

    def test_subtechnique_pattern(self):
        """Subtechnique IDs like AML.T0051.000 are extracted correctly."""
        scenario = _make_scenario(
            scenario_id="scenario:v2:e8bc163c82eee18733288c7d4ac636db3a6deb013ef2d37b68322be20edc45cc"
        )
        scenario["attack_tree"]["root"]["children"][0]["technique_id"] = "AML.T0051.000"
        scenario["behavior_spec"] = "When [AML.T0051.000] is used"

        result = score_technique_agreement([scenario])
        assert result["mean_technique_agreement"] == 1.0


# ===========================================================================
# Diversity tests
# ===========================================================================


class TestEntryPointEntropy:
    def test_uniform_distribution(self):
        scenarios = [
            _make_scenario(entry_point="api endpoints"),
            _make_scenario(entry_point="user prompts"),
            _make_scenario(entry_point="tool invocations"),
        ]
        result = entry_point_entropy(scenarios)
        assert result > 0.9  # High entropy for uniform

    def test_single_entry_point(self):
        scenarios = [
            _make_scenario(entry_point="user prompts"),
            _make_scenario(entry_point="user prompts"),
        ]
        result = entry_point_entropy(scenarios)
        assert result == 0.0

    def test_empty(self):
        result = entry_point_entropy([])
        assert result == 0.0

    def test_with_expected_entry_points(self):
        """When expected_entry_points is provided, returns a dict."""
        scenarios = [
            _make_scenario(entry_point="api endpoints"),
            _make_scenario(entry_point="user prompts"),
        ]
        result = entry_point_entropy(scenarios, expected_entry_points=4)
        assert isinstance(result, dict)
        assert "entropy" in result
        assert "entry_point_coverage" in result
        # 2 unique out of 4 expected = 0.5
        assert result["entry_point_coverage"] == 0.5
        assert result["entropy"] > 0.0

    def test_coverage_full(self):
        """1/1 expected entry points = 1.0 coverage."""
        scenarios = [
            _make_scenario(entry_point="user prompts"),
        ]
        result = entry_point_entropy(scenarios, expected_entry_points=1)
        assert result["entry_point_coverage"] == 1.0


class TestZoneCoverage:
    def test_full_coverage(self):
        scenarios = [
            _make_scenario(
                zone_sequence=[
                    "input",
                    "reasoning",
                    "tool_execution",
                    "memory",
                    "inter_agent",
                ]
            ),
        ]
        result = zone_coverage(scenarios)
        assert result == 1.0

    def test_partial_coverage(self):
        scenarios = [
            _make_scenario(zone_sequence=["input", "reasoning"]),
        ]
        result = zone_coverage(scenarios)
        assert result == 0.4

    def test_no_scenarios(self):
        result = zone_coverage([])
        assert result == 0.0

    def test_with_active_zones(self):
        """When active_zones is provided, returns a dict with contextualized coverage."""
        scenarios = [
            _make_scenario(zone_sequence=["input", "reasoning"]),
        ]
        result = zone_coverage(
            scenarios, active_zones={"input", "reasoning", "tool_execution"}
        )
        assert isinstance(result, dict)
        assert result["raw_coverage"] == 0.4
        # 2 out of 3 active zones covered
        assert abs(result["active_zone_coverage"] - 0.6667) < 0.001

    def test_out_of_scope_violations(self):
        """Scenarios using zones outside the active set are flagged."""
        scenarios = [
            _make_scenario(
                scenario_id="scenario:v2:e8bc163c82eee18733288c7d4ac636db3a6deb013ef2d37b68322be20edc45cc",
                zone_sequence=["input", "reasoning", "inter_agent"],
            ),
        ]
        result = zone_coverage(scenarios, active_zones={"input", "reasoning"})
        assert isinstance(result, dict)
        assert len(result["out_of_scope_zone_violations"]) == 1
        assert result["out_of_scope_zone_violations"][0]["out_of_scope_zones"] == [
            "inter_agent"
        ]

    def test_no_out_of_scope(self):
        """No violations when all zones are within the active set."""
        scenarios = [
            _make_scenario(zone_sequence=["input", "reasoning"]),
        ]
        result = zone_coverage(
            scenarios, active_zones={"input", "reasoning", "tool_execution"}
        )
        assert result["out_of_scope_zone_violations"] == []


class TestActorTypeEntropy:
    def test_diverse_actors(self):
        scenarios = [
            _make_scenario(actor_type="adversarial-user"),
            _make_scenario(actor_type="cybercriminal"),
            _make_scenario(actor_type="nation-state"),
        ]
        result = actor_type_entropy(scenarios)
        assert result > 0.9

    def test_single_actor_type(self):
        scenarios = [
            _make_scenario(actor_type="adversarial-user"),
            _make_scenario(actor_type="adversarial-user"),
        ]
        result = actor_type_entropy(scenarios)
        assert result == 0.0


class TestCapabilityLevelEvenness:
    def test_even_distribution(self):
        scenarios = [
            _make_scenario(capability_level="novice"),
            _make_scenario(capability_level="intermediate"),
            _make_scenario(capability_level="advanced"),
            _make_scenario(capability_level="expert"),
        ]
        result = capability_level_evenness(scenarios)
        assert result == 1.0

    def test_single_level(self):
        scenarios = [
            _make_scenario(capability_level="intermediate"),
            _make_scenario(capability_level="intermediate"),
        ]
        result = capability_level_evenness(scenarios)
        assert result == 0.0


class TestTitleUniqueness:
    def test_unique_titles(self):
        scenarios = [
            _make_scenario(title="Memory Poisoning Attack on LLM Agent"),
            _make_scenario(title="Tool Execution Bypass via Injection"),
            _make_scenario(title="Credential Theft through Social Engineering"),
        ]
        result = title_uniqueness(scenarios)
        assert result > 0.5

    def test_identical_titles(self):
        scenarios = [
            _make_scenario(title="Same Title Here"),
            _make_scenario(title="Same Title Here"),
        ]
        result = title_uniqueness(scenarios)
        assert result == 0.0

    def test_single_scenario(self):
        scenarios = [_make_scenario(title="Only One")]
        result = title_uniqueness(scenarios)
        assert result == 1.0

    def test_empty(self):
        result = title_uniqueness([])
        assert result == 1.0

    def test_domain_stopwords_excluded(self):
        """Shared domain vocabulary should not tank the score.

        These titles share 'Policy' and 'Agent' across >50% of them, but
        the discriminating words are unique. Without domain-stopword
        filtering this would score ~0.50; with it the score should be high.
        """
        scenarios = [
            _make_scenario(title="Policy Evasion via Memory Poisoning Agent"),
            _make_scenario(title="Policy Bypass through Prompt Injection Agent"),
            _make_scenario(title="Policy Circumvention with Tool Misuse Agent"),
            _make_scenario(title="Policy Violation using Social Engineering Agent"),
        ]
        result = title_uniqueness(scenarios)
        # With domain stopwords removed, titles are diverse
        assert result > 0.6

    def test_genuinely_duplicate_titles_still_penalized(self):
        """Titles that are truly near-duplicates should be penalized.

        Here two titles share most of their non-domain words — they only
        differ in one word out of several discriminating tokens.  With the
        mean-of-top-k metric the impact is diluted by the other diverse
        pairs, but it should still not score perfect.
        """
        scenarios = [
            _make_scenario(title="Credential Theft via Phishing Email"),
            _make_scenario(title="Credential Theft via Phishing SMS"),
            _make_scenario(title="Supply Chain Backdoor Insertion"),
            _make_scenario(title="Prompt Injection Memory Corruption"),
        ]
        result = title_uniqueness(scenarios)
        # Near-duplicate pair penalizes but doesn't tank score (mean-of-top-k)
        assert result < 1.0


class TestScoreDiversity:
    def test_returns_all_keys(self):
        scenarios = [
            _make_scenario(
                actor_type="adversarial-user",
                capability_level="novice",
                entry_point="user prompts",
            ),
            _make_scenario(
                actor_type="cybercriminal",
                capability_level="expert",
                entry_point="api endpoints",
            ),
        ]
        result = score_diversity(scenarios)
        assert "entry_point_entropy" in result
        assert "zone_coverage" in result
        assert "actor_type_entropy" in result
        assert "capability_level_evenness" in result
        assert "title_uniqueness" in result


# ===========================================================================
# Plausibility tests
# ===========================================================================


class TestCapabilityComplexityViolations:
    def test_nation_state_novice(self):
        scenario = _make_scenario(actor_type="nation-state", capability_level="novice")
        violations = capability_complexity_violations(scenario)
        assert len(violations) == 1
        assert "nation-state" in violations[0]

    def test_nation_state_advanced(self):
        scenario = _make_scenario(
            actor_type="nation-state", capability_level="advanced"
        )
        violations = capability_complexity_violations(scenario)
        assert violations == []

    def test_nation_state_expert(self):
        scenario = _make_scenario(actor_type="nation-state", capability_level="expert")
        violations = capability_complexity_violations(scenario)
        assert violations == []

    def test_supply_chain_intermediate(self):
        scenario = _make_scenario(
            actor_type="supply-chain-actor", capability_level="intermediate"
        )
        violations = capability_complexity_violations(scenario)
        assert len(violations) == 1
        assert "supply-chain-actor" in violations[0]

    def test_supply_chain_expert(self):
        scenario = _make_scenario(
            actor_type="supply-chain-actor", capability_level="expert"
        )
        violations = capability_complexity_violations(scenario)
        assert violations == []

    def test_novice_high_complexity(self):
        scenario = _make_scenario(
            actor_type="adversarial-user", capability_level="novice"
        )
        # Set attack_complexity to "high"
        scenario["priority"]["signals"]["attack_complexity"] = "high"
        violations = capability_complexity_violations(scenario)
        assert len(violations) == 1
        assert "novice" in violations[0]
        assert "high attack_complexity" in violations[0]

    def test_novice_low_complexity(self):
        scenario = _make_scenario(
            actor_type="adversarial-user", capability_level="novice"
        )
        scenario["priority"]["signals"]["attack_complexity"] = "low"
        violations = capability_complexity_violations(scenario)
        assert violations == []

    def test_normal_scenario_no_violations(self):
        scenario = _make_scenario(
            actor_type="cybercriminal", capability_level="intermediate"
        )
        violations = capability_complexity_violations(scenario)
        assert violations == []

    def test_missing_actor_profile(self):
        scenario = _make_scenario()
        del scenario["actor_profile"]
        violations = capability_complexity_violations(scenario)
        assert violations == []


class TestScorePlausibility:
    def test_no_violations(self):
        scenarios = [
            _make_scenario(actor_type="cybercriminal", capability_level="advanced"),
        ]
        result = score_plausibility(scenarios)
        assert result["capability_complexity_violation_count"] == 0
        assert "per_scenario" not in result

    def test_with_violations(self):
        scenarios = [
            _make_scenario(
                scenario_id="scenario:v2:e8bc163c82eee18733288c7d4ac636db3a6deb013ef2d37b68322be20edc45cc",
                actor_type="nation-state",
                capability_level="novice",
            ),
            _make_scenario(
                scenario_id="scenario:v2:ad328846aa18b32a335816374511cac1063c704b8c57999e51da9f908290a7a4",
                actor_type="cybercriminal",
                capability_level="advanced",
            ),
        ]
        result = score_plausibility(scenarios)
        assert result["capability_complexity_violation_count"] == 1
        assert (
            "scenario:v2:e8bc163c82eee18733288c7d4ac636db3a6deb013ef2d37b68322be20edc45cc"
            in result["per_scenario"]
        )
        assert (
            "scenario:v2:ad328846aa18b32a335816374511cac1063c704b8c57999e51da9f908290a7a4"
            not in result["per_scenario"]
        )


# ===========================================================================
# Runner / integration tests
# ===========================================================================


@pytest.mark.skip(
    reason="legacy manifest-v2 scorecard integration removed; v3 is authoritative"
)
class TestRunEvaluation:
    def test_with_synthetic_data(self, tmp_path: Path):
        """Integration test: write synthetic data and run full evaluation."""
        zone_names = ["input", "reasoning", "tool_execution", "memory", "inter_agent"]
        scenarios = []
        feature_files = {}
        for i in range(3):
            s = _make_scenario(
                scenario_id=f"T7-S{i + 1}-abc{i:03d}",
                title=f"Scenario {i + 1}: {'ABCDEF'[i]} Attack",
                entry_point=["user prompts", "api endpoints", "tool calls"][i % 3],
                zone_sequence=["input", "reasoning", zone_names[i % 5]],
                actor_type=["adversarial-user", "cybercriminal", "nation-state"][i],
                capability_level=["novice", "intermediate", "advanced"][i],
            )
            scenarios.append(s)
            feature_files[s["scenario_id"]] = _GHERKIN_VALID

        run_dir = build_test_run_dir(
            tmp_path / "run", scenarios=scenarios, feature_files=feature_files
        )
        scorecard = run_evaluation(run_dir)

        assert "evaluation" in scorecard
        ev = scorecard["evaluation"]
        assert ev["scenario_count"] == 3
        assert ev["feature_file_count"] == 3

        # Check all sections present
        assert "consistency" in ev
        assert "gherkin" in ev
        assert "grounding" in ev
        assert "technique_agreement" in ev
        assert "diversity" in ev
        assert "plausibility" in ev

        # Check consistency has per-scenario data
        assert "per_scenario" in ev["consistency"]
        assert len(ev["consistency"]["per_scenario"]) == 3
        assert "mean" in ev["consistency"]
        assert "stddev" in ev["consistency"]

        # Check gherkin metrics
        assert ev["gherkin"]["parse_success_rate"] == 1.0

        # Check grounding
        assert ev["grounding"]["threat_id_validity"] == 1.0

    def test_empty_directory(self, tmp_path: Path):
        """Should handle empty output directory gracefully."""
        run_dir = build_test_run_dir(tmp_path / "run")
        scorecard = run_evaluation(run_dir)
        assert scorecard["evaluation"]["scenario_count"] == 0

    def test_no_scenarios_dir(self, tmp_path: Path):
        """Should handle missing scenarios directory."""
        run_dir = build_test_run_dir(tmp_path / "run")
        scorecard = run_evaluation(run_dir)
        assert scorecard["evaluation"]["scenario_count"] == 0

    def test_scenarios_without_features_rejected(self, tmp_path: Path):
        """Strict manifest rejects YAML without paired .feature files."""
        from asago_scenario_generator.manifest import ManifestIntegrityError

        s = _make_scenario()
        sid = s["scenario_id"]
        run_dir = tmp_path / "run"
        run_dir.mkdir(parents=True)
        # Write only the YAML, no feature file, with a manifest that
        # inventories only the YAML — strict validation must reject this.
        from asago_scenario_generator.manifest import (
            MANIFEST_FILENAME,
            ArtifactRole,
            RunManifest,
            RunStatus,
            atomic_write_yaml,
            build_artifact_entry,
        )

        sc_dir = run_dir / "scenarios"
        sc_dir.mkdir()
        yaml_path = sc_dir / f"{sid}.yaml"
        yaml_path.write_text(yaml.dump(s, default_flow_style=False))
        (run_dir / "use-case.txt").write_text("test")
        (run_dir / "pipeline.log").write_text("log\n")
        (run_dir / "report.html").write_text("<html></html>")
        entry = build_artifact_entry(
            role=ArtifactRole.SCENARIO_YAML,
            run_dir=run_dir,
            rel_path=f"scenarios/{sid}.yaml",
            scenario_id=sid,
            candidate_id=f"cand:v2:{hashlib.sha256(sid.encode()).hexdigest()[:32]}",
        )
        manifest = RunManifest(
            status=RunStatus.COMPLETED,
            run_id="20260101T000000_abcdef0123456789abcdef0123456789",
            timestamp_start="2026-01-01T00:00:00+00:00",
            inventory=[entry],
        )
        atomic_write_yaml(
            run_dir / MANIFEST_FILENAME,
            manifest.model_dump(mode="json", exclude_none=True),
        )
        with pytest.raises(ManifestIntegrityError, match="without feature"):
            run_evaluation(run_dir)

    def test_with_capability_profile(self, tmp_path: Path):
        """Runner loads capability-profile.yaml and passes context to diversity."""
        s = _make_scenario(
            entry_point="user prompts (zone input)",
            zone_sequence=["input", "reasoning"],
        )

        cap_profile = {
            "zones_active": ["input", "reasoning", "tool_execution"],
            "entry_points": [
                "user prompts (zone input)",
                "api responses (zone tool_execution)",
            ],
            "confidence": "high",
            "kc_subcodes": ["KC1.1", "KC6.1.1"],
            "tool_inventory": [
                {
                    "name": "web search",
                    "description": "Search the web for information.",
                },
            ],
        }
        run_dir = build_test_run_dir(
            tmp_path / "run", profile_data=cap_profile, scenarios=[s]
        )
        scorecard = run_evaluation(run_dir)
        ev = scorecard["evaluation"]
        diversity = ev["diversity"]

        # entry_point_entropy should be a dict with coverage
        assert isinstance(diversity["entry_point_entropy"], dict)
        assert "entry_point_coverage" in diversity["entry_point_entropy"]
        # 1 unique entry point out of 2 expected
        assert diversity["entry_point_entropy"]["entry_point_coverage"] == 0.5

        # zone_coverage should be a dict with active zone coverage
        assert isinstance(diversity["zone_coverage"], dict)
        assert "active_zone_coverage" in diversity["zone_coverage"]
        # Zones {"input","reasoning"} covered out of active {"input","reasoning","tool_execution"} = 2/3
        assert abs(diversity["zone_coverage"]["active_zone_coverage"] - 0.6667) < 0.001

    def test_without_capability_profile(self, tmp_path: Path):
        """Without a capability profile, diversity returns bare floats."""
        s = _make_scenario()
        run_dir = build_test_run_dir(tmp_path / "run", scenarios=[s])
        scorecard = run_evaluation(run_dir)
        diversity = scorecard["evaluation"]["diversity"]

        # Should be plain floats, not dicts
        assert isinstance(diversity["entry_point_entropy"], float)
        assert isinstance(diversity["zone_coverage"], float)

    def test_scorecard_yaml_serializable(self, tmp_path: Path):
        """Scorecard should be serializable to YAML and JSON."""
        s = _make_scenario()
        run_dir = build_test_run_dir(tmp_path / "run", scenarios=[s])
        scorecard = run_evaluation(run_dir)

        # YAML roundtrip
        yaml_text = yaml.dump(scorecard, default_flow_style=False)
        reloaded = yaml.safe_load(yaml_text)
        assert reloaded["evaluation"]["scenario_count"] == 1

        # JSON roundtrip
        json_text = json.dumps(scorecard, indent=2, default=str)
        reloaded_json = json.loads(json_text)
        assert reloaded_json["evaluation"]["scenario_count"] == 1
