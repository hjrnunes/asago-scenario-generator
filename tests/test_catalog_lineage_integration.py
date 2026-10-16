"""Catalog-wide integration tests for the live attack-pattern catalog.

These tests load the live ``load_attack_patterns()`` catalog and check that
it carries 53 pattern IDs, that every record passes ``AttackPattern``
validation and resolver qualification, and that the activation mechanisms
and observable-outcome links are present in the expected numbers.  The
validation covers the chain digest, slot and postcondition references,
duplicate links and the activation-link contract, so these tests do not
re-walk the raw records for those rules.

They do not read ``catalog-lineage.yaml``.
"""

from __future__ import annotations

from asago_scenario_generator.data.loaders import load_attack_patterns
from asago_scenario_generator.data.taxonomy_pins import load_taxonomy_resolver
from asago_scenario_generator.models.attack_pattern_validation import (
    validate_attack_pattern,
)


def test_all_live_records_are_model_valid() -> None:
    """The live catalog carries 53 pattern IDs, and every record parses as a
    valid AttackPattern, is qualified by the production resolver and has a
    non-empty name and description, which the model does not require."""
    resolver = load_taxonomy_resolver()
    live = load_attack_patterns()
    assert len(live) == 53
    for pid, record in live.items():
        pattern = validate_attack_pattern(record, resolver)
        assert pattern.id == pid
        assert pattern.name.strip(), pid
        assert pattern.description.strip(), pid


def test_activation_mechanism_counts() -> None:
    """49 direct-ingress and 4 source-influence mechanisms are explicit."""
    patterns = load_attack_patterns()
    ingress_count = 0
    source_count = 0
    none_count = 0
    for raw in patterns.values():
        chain = raw["canonical_chain"]
        ingress_slot = chain["initial_ingress_slot_id"]
        has_ingress = any(
            link.get("role") == "ingress" and link.get("slot_id") == ingress_slot
            for step in chain["steps"]
            for link in step.get("resource_links", [])
        )
        has_source = any(
            link.get("role") == "source_influence"
            and link.get("target_ingress_slot_id") == ingress_slot
            for step in chain["steps"]
            for link in step.get("resource_links", [])
        )
        if has_ingress:
            ingress_count += 1
        if has_source:
            source_count += 1
        if not has_ingress and not has_source:
            none_count += 1
    assert ingress_count == 49
    assert source_count == 4
    assert none_count == 0
    assert ingress_count + source_count + none_count == 53


def test_all_53_patterns_have_observable_outcome_links() -> None:
    """Every live pattern must have observable_outcome_links on at least one
    step, ensuring postconditions are explicitly linked to observable outcomes.
    """
    patterns = load_attack_patterns()
    assert len(patterns) == 53
    for pid, raw in patterns.items():
        chain = raw["canonical_chain"]
        has_outcome_links = any(
            step.get("observable_outcome_links") for step in chain["steps"]
        )
        assert has_outcome_links, f"{pid} has no observable_outcome_links"
