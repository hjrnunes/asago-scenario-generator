"""Shared test fixture for one authoritative projected candidate.

Projects a minimal authoritative canonical attack pattern against a small
capability profile and exposes the resulting candidate, snapshot, resolver,
profile, and raw pattern to planner and realization tests.
"""

from __future__ import annotations

from typing import Any

from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
from asago_scenario_generator.models.attack_pattern_contracts import (
    AuthoritativeFactReference,
    EvaluatedFactEvidence,
)
from asago_scenario_generator.models.attack_pattern_digests import (
    compute_chain_semantic_digest,
)
from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    ConfidenceLevel,
)
from asago_scenario_generator.pipeline.projection_authoritative import (
    project_authoritative_candidate_observations,
)
from asago_scenario_generator.pipeline.projection_contracts import (
    ProjectionBudget,
    capture_capability_snapshot,
)

ZERO = "0" * 64


class _TaxonomyResolver:
    """Minimal taxonomy resolver for test fixtures."""

    def __init__(self, context: Any) -> None:
        self.taxonomy_context = context

    def contains(self, taxonomy: str, identifier: str) -> bool:
        return (taxonomy, identifier) in {
            ("ATLAS", "AML.T0001"),
        }


def _fact() -> dict[str, Any]:
    return {
        "namespace": "profile",
        "fact_id": "mode",
        "value_type": "string",
        "property_path": [],
    }


def _step(step_id: str, order: int, *, conditional: bool = False) -> dict[str, Any]:
    final = order == 3
    attacker = order == 1
    return {
        "step_id": step_id,
        "requirement": "conditional" if conditional else "required",
        "condition": (
            {
                "op": "equality",
                "schema_version": "1",
                "fact": _fact(),
                "value": "active",
            }
            if conditional
            else None
        ),
        "executor_role": "attacker" if attacker else "system",
        "boundary_position": "crossing" if attacker else "inside",
        "action_kind": "prepare" if attacker else "impact" if final else "observe",
        "consumed": (
            [{"kind": "state", "ref_id": "state.1", "value_type": "boolean"}]
            if order == 2
            else []
        ),
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
            [{"slot_id": "ingress", "role": "ingress", "trust_boundary_slot_id": None}]
            if attacker
            else [
                {
                    "slot_id": "tool",
                    "role": "tool_fixture",
                    "trust_boundary_slot_id": None,
                }
            ]
            if order == 2
            else []
        ),
        "observable_outcome_links": (
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


def _pattern() -> dict[str, Any]:
    chain = {
        "schema_version": "v1",
        "pattern_id": "AP-T1-01",
        "chain_id": "chain.1",
        "semantic_revision": 1,
        "semantic_digest": ZERO,
        "taxonomy_context": {
            "atlas": {"release": "v1", "digest": ZERO},
            "laaf": None,
            "mapping_set_digest": ZERO,
        },
        "mappings": [{"decision": "exact", "taxonomy": "ATLAS", "ids": ["AML.T0001"]}],
        "steps": [
            _step("step.1", 1),
            _step("step.2", 2, conditional=True),
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


def _profile() -> CapabilityProfile:
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


def _evidence(value: str = "active") -> EvaluatedFactEvidence:
    return EvaluatedFactEvidence(
        fact=AuthoritativeFactReference.model_validate(_fact()),
        status="present",
        value=value,
    )


def _project():
    """Project candidates and return the first candidate + resolver + snapshot."""
    raw = _pattern()
    pattern = AttackPattern.model_validate(raw)
    resolver = _TaxonomyResolver(pattern.canonical_chain.taxonomy_context)
    snapshot = capture_capability_snapshot(_profile(), (_evidence(),))
    batch = project_authoritative_candidate_observations(
        [raw],
        resolver,
        snapshot,
        budget=ProjectionBudget(max_candidates=100),
    ).batch
    assert len(batch.candidates) >= 1
    return batch.candidates[0], resolver, snapshot, raw


# Cache the projected candidate to avoid recomputing on every test.
_cached: tuple[Any, ...] | None = None


def _cached_project():
    global _cached
    if _cached is None:
        _cached = _project()
    return _cached


def get_projected_candidate():
    """Return the shared test ProjectedCandidate."""
    return _cached_project()[0]


def get_test_profile() -> CapabilityProfile:
    """Return the shared test CapabilityProfile."""
    return _profile()


def get_test_resolver():
    """Return the shared test TaxonomyResolver."""
    return _cached_project()[1]


def get_test_snapshot():
    """Return the shared test CapabilityFactSnapshot."""
    return _cached_project()[2]


def get_test_raw_pattern() -> dict[str, Any]:
    """Return the shared test raw pattern dict."""
    return _cached_project()[3]
