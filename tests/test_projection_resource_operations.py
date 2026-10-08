"""Projection-seam regressions for semantic resource feasibility."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from asago_scenario_generator.data.loaders import load_attack_patterns
from asago_scenario_generator.models.attack_pattern_chain import (
    AttackPattern,
    ResourceSlot,
)
from asago_scenario_generator.models.attack_pattern_digests import (
    compute_chain_semantic_digest,
)
from asago_scenario_generator.models.attack_pattern_contracts import (
    AuthoritativeFactReference,
    EvaluatedFactEvidence,
)
from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    ExternalIntegration,
    ToolInventoryEntry,
    deduplicate_external_integrations,
    deduplicate_tool_inventory,
)
from asago_scenario_generator.pipeline.projection_contracts import (
    capture_capability_snapshot,
)
from asago_scenario_generator.pipeline.projection_authoritative import (
    project_authoritative_candidate_observations,
)


_ATTACK_PATTERN_DIR = (
    Path(__file__).resolve().parents[1] / "data" / "taxonomies" / "attack-patterns"
)


class _PermissiveTaxonomyResolver:
    """Resolve the catalog's already-validated taxonomy identities."""

    def __init__(self, pattern: AttackPattern) -> None:
        self.taxonomy_context = pattern.canonical_chain.taxonomy_context

    def contains(self, taxonomy: str, identifier: str) -> bool:
        return bool(taxonomy and identifier)


def _catalog_record(pattern_id: str, filename: str) -> dict[str, Any]:
    return load_attack_patterns(_ATTACK_PATTERN_DIR / filename)[pattern_id]


def _direct_tool_profile(tools: list[dict[str, Any]]) -> CapabilityProfile:
    return CapabilityProfile.model_validate(
        {
            "zones_active": ["input", "reasoning", "tool_execution"],
            "entry_points": [
                {
                    "name": "reviewed patient request",
                    "entry_point_type": "user_input",
                    "direction": "input",
                    "controllability": "direct",
                }
            ],
            "confidence": "high",
            "kc_subcodes": ["KC1.1", "KC6.1.1"],
            "tool_inventory": tools,
            "trust_boundaries": [
                {
                    "name": "patient-input-to-agent",
                    "from_zone": "input",
                    "to_zone": "reasoning",
                    "confidence": "explicit",
                }
            ],
        }
    )


def _indirect_content_profile() -> CapabilityProfile:
    return CapabilityProfile.model_validate(
        {
            "zones_active": ["input", "reasoning"],
            "entry_points": [
                {
                    "name": "patient chat",
                    "entry_point_type": "user_input",
                    "direction": "input",
                    "controllability": "direct",
                },
                {
                    "name": "reviewed external content channel",
                    "entry_point_type": "external_content",
                    "direction": "bidirectional",
                    "controllability": "indirect",
                    "ingress_zone": "reasoning",
                },
            ],
            "confidence": "high",
            "kc_subcodes": ["KC1.1"],
            "trust_boundaries": [
                {
                    "name": "external-content-to-agent",
                    "from_zone": "input",
                    "to_zone": "reasoning",
                    "confidence": "explicit",
                }
            ],
            "external_integrations": [
                {
                    "name": "reviewed content feed",
                    "integration_type": "web_service",
                    "auth_method": "oauth",
                    "data_sensitivity": "medium",
                    "supported_operations": ["retrieve_data"],
                },
                {
                    "name": "EHR upload integration",
                    "integration_type": "api",
                    "auth_method": "service_account",
                    "data_sensitivity": "high",
                    "supported_operations": ["transmit_data"],
                },
            ],
        }
    )


def _observe_for_planner(
    record: dict[str, Any],
    profile: CapabilityProfile,
    facts: tuple[EvaluatedFactEvidence, ...] = (),
):
    """Run the versioned planner-only operation-aware observation seam."""
    pattern = AttackPattern.model_validate(record)
    snapshot = capture_capability_snapshot(profile, facts)
    return project_authoritative_candidate_observations(
        [record], _PermissiveTaxonomyResolver(pattern), snapshot
    )


def test_operation_metadata_distinguishes_unknown_from_reviewed_support() -> None:
    """Null is unknown; a reviewed set is canonical and explicit."""
    unknown = ToolInventoryEntry(name="unknown", description="not reviewed")
    reviewed = ToolInventoryEntry(
        name="reviewed",
        description="reviewed",
        supported_operations=("transmit_data", "retrieve_data"),
    )

    assert unknown.supported_operations is None
    assert reviewed.supported_operations == ("retrieve_data", "transmit_data")
    with pytest.raises(ValidationError, match="supported_operations must be unique"):
        ToolInventoryEntry(
            name="duplicate",
            description="invalid",
            supported_operations=("retrieve_data", "retrieve_data"),
        )


def test_duplicate_tool_cannot_disagree_about_reviewed_operations() -> None:
    """One canonical tool identity cannot carry conflicting operation facts."""
    tools = [
        ToolInventoryEntry(name="reviewed API", description="same tool"),
        ToolInventoryEntry(
            name="reviewed API",
            description="same tool",
            supported_operations=("retrieve_data",),
        ),
    ]

    with pytest.raises(ValueError, match="conflicting supported_operations"):
        deduplicate_tool_inventory(tools)


def test_duplicate_integration_cannot_disagree_about_reviewed_operations() -> None:
    """One integration identity cannot carry conflicting operation facts."""
    base = {
        "name": "reviewed source",
        "integration_type": "api",
        "auth_method": "oauth",
        "data_sensitivity": "medium",
    }
    integrations = [
        ExternalIntegration.model_validate(base),
        ExternalIntegration.model_validate(
            {**base, "supported_operations": ["retrieve_data"]}
        ),
    ]

    with pytest.raises(ValueError, match="conflicting supported_operations"):
        deduplicate_external_integrations(integrations)


def test_unknown_operation_metadata_preserves_legacy_snapshot_identity() -> None:
    """Adding an unknown operation field must not rewrite old snapshot pins."""
    profile = _direct_tool_profile(
        [{"name": "legacy API", "description": "legacy inventory"}]
    )

    snapshot = capture_capability_snapshot(profile)

    assert "supported_operations" not in profile.tool_inventory[0].model_dump(
        mode="json"
    )
    assert snapshot.snapshot_digest == (
        "d76eff523c902bc4196c1354a45b7f23be5d330b8b853429d32ef235d90dc4c7"
    )


def test_reviewed_operation_metadata_is_bound_into_snapshot_identity() -> None:
    """A reviewed operation claim changes the capability evidence identity."""
    unknown = _direct_tool_profile(
        [{"name": "legacy API", "description": "legacy inventory"}]
    )
    reviewed = _direct_tool_profile(
        [
            {
                "name": "legacy API",
                "description": "legacy inventory",
                "supported_operations": ["retrieve_data"],
            }
        ]
    )

    assert (
        capture_capability_snapshot(unknown).snapshot_digest
        != capture_capability_snapshot(reviewed).snapshot_digest
    )


def test_operation_requirements_are_limited_to_tool_and_integration_slots() -> None:
    """Structural resource kinds cannot acquire unrelated action requirements."""
    with pytest.raises(ValidationError, match="tool_or_integration constraints"):
        ResourceSlot(
            slot_id="ingress",
            kind="entry_point",
            purpose="initial_ingress",
            required_operations=("retrieve_data",),
        )


def test_ap_t2_02_requires_different_retrieval_and_delivery_tools() -> None:
    """An upload-only API cannot fill both halves of an exfiltration chain."""
    record = _catalog_record("AP-T2-02", "attack-patterns-memory-tool.yaml")
    profile = _direct_tool_profile(
        [
            {
                "name": "EHR upload API",
                "description": "Uploads questionnaire summaries to the EHR",
                "supported_operations": ["transmit_data"],
            }
        ]
    )

    result = _observe_for_planner(record, profile).batch

    assert result.candidates == ()
    assert any(
        issue.code == "unsupported_resource_operation"
        and issue.slot_id == "retrieval_tool"
        for issue in result.infeasibilities
    )


def test_ap_t2_02_projects_only_with_two_explicitly_capable_tools() -> None:
    """Distinct retrieve and transmit capabilities produce a concrete chain."""
    record = _catalog_record("AP-T2-02", "attack-patterns-memory-tool.yaml")
    profile = _direct_tool_profile(
        [
            {
                "name": "EHR reader",
                "description": "Reads patient records",
                "supported_operations": ["retrieve_data"],
            },
            {
                "name": "approved delivery API",
                "description": "Transmits reviewed records",
                "supported_operations": ["transmit_data"],
            },
        ]
    )

    result = _observe_for_planner(record, profile).batch

    assert len(result.candidates) == 1
    bindings = {
        binding.slot_id: binding.resource_ref
        for binding in result.candidates[0].projection.bindings
    }
    assert bindings["retrieval_tool"] != bindings["delivery_tool"]


def test_unknown_tool_operations_are_reported_as_missing_evidence() -> None:
    """An unreviewed tool operation set fails closed without claiming absence."""
    record = _catalog_record("AP-T2-02", "attack-patterns-memory-tool.yaml")
    profile = _direct_tool_profile(
        [{"name": "unreviewed API", "description": "Operation support not reviewed"}]
    )

    result = _observe_for_planner(record, profile).batch

    assert result.candidates == ()
    assert any(
        issue.code == "unknown_resource_operation" for issue in result.infeasibilities
    )


def test_structurally_wrong_resource_is_not_reported_as_unknown_operation() -> None:
    """Resource shape is checked separately before semantic operation support."""
    record = _catalog_record("AP-T6-03", "attack-patterns-halluc-intent.yaml")
    source_slot = next(
        slot
        for slot in record["canonical_chain"]["resource_slots"]
        if slot["slot_id"] == "poisoned_source"
    )
    source_slot["allowed_integration_types"] = ["database"]
    record["canonical_chain"]["semantic_digest"] = compute_chain_semantic_digest(
        record["canonical_chain"]
    )
    profile_payload = _indirect_content_profile().model_dump(mode="json")
    for integration in profile_payload["external_integrations"]:
        integration["supported_operations"] = None
    profile = CapabilityProfile.model_validate(profile_payload)
    fact = EvaluatedFactEvidence(
        fact=AuthoritativeFactReference(
            namespace="profile",
            fact_id="capabilities.external_content_ingestion",
            value_type="boolean",
            property_path=(),
        ),
        status="present",
        value=True,
    )

    result = _observe_for_planner(record, profile, (fact,)).batch

    assert any(
        issue.code == "missing_compatible_resource"
        and issue.slot_id == "poisoned_source"
        for issue in result.infeasibilities
    )
    assert not any(
        issue.code == "unknown_resource_operation" for issue in result.infeasibilities
    )


def test_ap_t2_06_rejects_an_explicitly_absent_code_interpreter() -> None:
    """Ordinary tools cannot stand in for an absent command interpreter."""
    record = _catalog_record("AP-T2-06", "attack-patterns-memory-tool.yaml")
    profile = _direct_tool_profile(
        [
            {
                "name": "EHR upload API",
                "description": "Uploads questionnaire summaries to the EHR",
                "supported_operations": ["execute_code"],
            }
        ]
    )
    absent_interpreter = EvaluatedFactEvidence(
        fact=AuthoritativeFactReference(
            namespace="profile",
            fact_id="capabilities.code_interpreter",
            value_type="boolean",
            property_path=(),
        ),
        status="absent",
    )

    result = _observe_for_planner(record, profile, (absent_interpreter,)).batch

    assert result.candidates == ()
    assert any(
        issue.code == "precondition_not_satisfied" for issue in result.infeasibilities
    )


def test_ap_t6_03_uses_an_indirect_external_source_and_internal_goal() -> None:
    """Poisoned output binds a readable source and the agent's own goal state."""
    record = _catalog_record("AP-T6-03", "attack-patterns-halluc-intent.yaml")
    fact = EvaluatedFactEvidence(
        fact=AuthoritativeFactReference(
            namespace="profile",
            fact_id="capabilities.external_content_ingestion",
            value_type="boolean",
            property_path=(),
        ),
        status="present",
        value=True,
    )
    profile = _indirect_content_profile()

    result = _observe_for_planner(record, profile, (fact,)).batch

    assert result.candidates
    indirect_ingress_id = profile.entry_points[1].entry_point_id
    readable_source_id = profile.external_integrations[0].integration_id
    for candidate in result.candidates:
        bindings = {
            binding.slot_id: binding.resource_ref
            for binding in candidate.projection.bindings
        }
        assert candidate.canonical_ingress.entry_point_id == indirect_ingress_id
        assert bindings["poisoned_source"].integration_id == readable_source_id
        assert bindings["agent_goal"].kind == "agent_internal"
