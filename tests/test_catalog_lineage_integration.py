"""Catalog-wide integration tests for the live attack-pattern catalog.

These tests load the live ``load_attack_patterns()`` catalog and check that:

- it carries 53 unique pattern IDs;
- every record is canonical, model-valid, resolver-qualified and
  digest-valid;
- every pattern has explicit activation, resource and observable-outcome
  linkage that references valid slots and postconditions.

They do not read ``catalog-lineage.yaml``.
"""

from __future__ import annotations

from asago_scenario_generator.data.loaders import load_attack_patterns
from asago_scenario_generator.data.taxonomy_pins import load_taxonomy_resolver
from asago_scenario_generator.models.attack_pattern_digests import (
    compute_chain_semantic_digest,
)
from asago_scenario_generator.models.attack_pattern_validation import (
    validate_attack_pattern,
)


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# ID equality
# ---------------------------------------------------------------------------


def test_live_count_is_53_and_unique() -> None:
    """The live catalog carries exactly 53 unique pattern IDs."""
    live = load_attack_patterns()
    assert len(live) == 53
    assert len(set(live.keys())) == 53


# ---------------------------------------------------------------------------
# Chain exact mapping IDs
# ---------------------------------------------------------------------------


def _live_exact_chain_ids(pattern: dict) -> set[str]:
    """Extract all exact ATLAS IDs from a live pattern's canonical chain
    (both chain-level and step-level)."""
    cc = pattern["canonical_chain"]
    ids: set[str] = set()
    for m in cc.get("mappings", []):
        if m.get("decision") == "exact":
            ids.update(m["ids"])
    for step in cc.get("steps", []):
        for m in step.get("mappings", []):
            if m.get("decision") == "exact":
                ids.update(m["ids"])
    return ids


# ---------------------------------------------------------------------------
# Resource-slot plans
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Canonical, model-valid, resolver-qualified, digest-valid
# ---------------------------------------------------------------------------


def test_all_live_records_are_canonical() -> None:
    """Every live record has a canonical_chain and no legacy kill_chain."""
    live = load_attack_patterns()
    for pid, record in live.items():
        assert "canonical_chain" in record, f"{pid} missing canonical_chain"
        assert "kill_chain" not in record, f"{pid} still has legacy kill_chain"


def test_all_live_records_are_model_valid() -> None:
    """Every live record parses as a valid AttackPattern and is qualified
    by the production resolver."""
    resolver = load_taxonomy_resolver()
    live = load_attack_patterns()
    for record in live.values():
        validate_attack_pattern(record, resolver)


def test_all_live_records_are_resolver_qualified() -> None:
    """Every exact ATLAS mapping in every live record is a valid pinned
    ATLAS identifier per the production resolver."""
    resolver = load_taxonomy_resolver()
    live = load_attack_patterns()
    for pid, record in live.items():
        for atlas_id in _live_exact_chain_ids(record):
            assert resolver.contains("ATLAS", atlas_id), (
                f"{pid}: exact mapping {atlas_id} not in pinned ATLAS identifiers"
            )


def test_all_live_records_are_digest_valid() -> None:
    """Every live canonical chain's semantic_digest matches the computed
    digest of its semantics."""
    live = load_attack_patterns()
    for pid, record in live.items():
        cc = record["canonical_chain"]
        expected = cc["semantic_digest"]
        actual = compute_chain_semantic_digest(cc)
        assert actual == expected, f"{pid}: semantic_digest mismatch"


# ---------------------------------------------------------------------------
# Mechanism-boundary contract documentation
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Catalog-wide canonical-linkage integration checks (422o.3.1)
# ---------------------------------------------------------------------------


def test_all_53_patterns_have_explicit_activation_linkage() -> None:
    """Every live pattern must have at most one activation mechanism: either
    an ingress resource_link to the initial_ingress_slot_id, or a
    source_influence resource_link whose target_ingress_slot_id is the
    initial ingress.  Both is forbidden; neither is permitted for
    candidate-v2 but is structurally valid (typed infeasible at projection).
    """
    patterns = load_attack_patterns()
    assert len(patterns) == 53
    infeasible: list[str] = []
    for pid, raw in patterns.items():
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
        assert not (has_ingress and has_source), (
            f"{pid} must not have both activation mechanisms "
            f"(ingress={has_ingress}, source_influence={has_source})"
        )
        if not has_ingress and not has_source:
            infeasible.append(pid)
    assert infeasible == []


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


def test_source_influence_links_target_canonical_ingress() -> None:
    """Every source_influence link must explicitly target the initial ingress."""
    patterns = load_attack_patterns()
    for pid, raw in patterns.items():
        chain = raw["canonical_chain"]
        ingress_slot = chain["initial_ingress_slot_id"]
        for step in chain["steps"]:
            for link in step.get("resource_links", []):
                if link.get("role") == "source_influence":
                    assert link["target_ingress_slot_id"] == ingress_slot, (
                        f"{pid} source_influence link does not target canonical ingress"
                    )


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


def test_all_resource_links_reference_valid_slots() -> None:
    """Every resource_link slot_id must reference a declared resource slot.
    This operates on raw records before indexing to catch dangling references
    that could collapse during canonical normalization.
    """
    patterns = load_attack_patterns()
    for pid, raw in patterns.items():
        chain = raw["canonical_chain"]
        slot_ids = {s["slot_id"] for s in chain["resource_slots"]}
        for step in chain["steps"]:
            for link in step.get("resource_links", []):
                assert link["slot_id"] in slot_ids, (
                    f"{pid} step {step['step_id']} resource_link "
                    f"references absent slot {link['slot_id']}"
                )
                if link.get("trust_boundary_slot_id") is not None:
                    assert link["trust_boundary_slot_id"] in slot_ids, (
                        f"{pid} step {step['step_id']} trust_boundary_slot_id "
                        f"references absent slot {link['trust_boundary_slot_id']}"
                    )
                if link.get("target_ingress_slot_id") is not None:
                    assert link["target_ingress_slot_id"] in slot_ids, (
                        f"{pid} step {step['step_id']} target_ingress_slot_id "
                        f"references absent slot {link['target_ingress_slot_id']}"
                    )


def test_all_observable_outcome_links_reference_valid_slots_and_postconditions() -> (
    None
):
    """Every observable_outcome_link binding_slot_id must reference a declared
    resource slot, and every postcondition_id must reference a declared
    postcondition.  This operates on raw records before indexing.
    """
    patterns = load_attack_patterns()
    for pid, raw in patterns.items():
        chain = raw["canonical_chain"]
        slot_ids = {s["slot_id"] for s in chain["resource_slots"]}
        for step in chain["steps"]:
            pc_ids = {
                pc["postcondition_id"] for pc in step["observable_postconditions"]
            }
            for link in step.get("observable_outcome_links", []):
                assert link["binding_slot_id"] in slot_ids, (
                    f"{pid} step {step['step_id']} observable_outcome_link "
                    f"references absent slot {link['binding_slot_id']}"
                )
                assert link["postcondition_id"] in pc_ids, (
                    f"{pid} step {step['step_id']} observable_outcome_link "
                    f"references absent postcondition {link['postcondition_id']}"
                )


def test_no_duplicate_resource_links_within_any_step() -> None:
    """No step may have duplicate resource_link slot_ids.  This operates on
    raw records to catch duplicates that could collapse during indexing.
    """
    patterns = load_attack_patterns()
    for pid, raw in patterns.items():
        chain = raw["canonical_chain"]
        for step in chain["steps"]:
            slot_ids = [link["slot_id"] for link in step.get("resource_links", [])]
            assert len(slot_ids) == len(set(slot_ids)), (
                f"{pid} step {step['step_id']} has duplicate resource_link slot_ids"
            )


def test_no_duplicate_observable_outcome_links_within_any_step() -> None:
    """No step may have duplicate observable_outcome_links.  This operates on
    raw records to catch duplicates that could collapse during indexing.
    """
    patterns = load_attack_patterns()
    for pid, raw in patterns.items():
        chain = raw["canonical_chain"]
        for step in chain["steps"]:
            keys = [
                (link["postcondition_id"], link["observation"], link["binding_slot_id"])
                for link in step.get("observable_outcome_links", [])
            ]
            assert len(keys) == len(set(keys)), (
                f"{pid} step {step['step_id']} has duplicate observable_outcome_links"
            )


def test_all_53_patterns_validate_with_explicit_linkage() -> None:
    """All 53 patterns must pass full model validation with explicit linkage."""
    resolver = load_taxonomy_resolver()
    patterns = load_attack_patterns()
    assert len(patterns) == 53
    for raw in patterns.values():
        validate_attack_pattern(raw, resolver)


def test_all_53_chain_digests_recompute_correctly() -> None:
    """Every chain's semantic_digest must recompute from its content."""
    patterns = load_attack_patterns()
    assert len(patterns) == 53
    for pid, raw in patterns.items():
        chain = raw["canonical_chain"]
        recomputed = compute_chain_semantic_digest(chain)
        assert chain["semantic_digest"] == recomputed, (
            f"{pid} semantic_digest does not match recomputed value"
        )
