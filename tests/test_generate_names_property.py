"""Property tests for generate-stage name-to-ID resolution.

These properties pin the Phase 3 name helpers in
``pipeline.generate.names``: already-canonical IDs pass through, profile
names resolve back to IDs, and projection-context humanization never
mutates the original mapping. They are offline and never contact an LLM.
"""

from __future__ import annotations

from hypothesis import given, settings, strategies as st

from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    ConfidenceLevel,
    EntryPoint,
    ExternalIntegration,
    ToolInventoryEntry,
    TrustBoundary,
)
from asago_scenario_generator.pipeline.generate.names import (
    humanize_projection_context,
    resolve_name_to_entry_point_id,
    resolve_name_to_integration_id,
    resolve_name_to_tool_id,
    resolve_name_to_trust_boundary_id,
    resource_name_for_kind,
)

_MAX_EXAMPLES = 60
_LABEL = st.from_regex(r"[A-Za-z][A-Za-z0-9 -]{0,15}", fullmatch=True)


def _profile(
    entry_name: str = "chat",
    tool_name: str = "search",
    integration_name: str = "crm",
    boundary_name: str = "public-api",
) -> CapabilityProfile:
    return CapabilityProfile(
        zones_active=["input", "reasoning", "tool_execution"],
        entry_points=[
            EntryPoint(name=entry_name, direction="input", controllability="direct")
        ],
        tool_inventory=[
            ToolInventoryEntry(name=tool_name, description="Look up records")
        ],
        external_integrations=[
            ExternalIntegration(
                name=integration_name,
                integration_type="api",
                auth_method="oauth",
                data_sensitivity="low",
            )
        ],
        trust_boundaries=[
            TrustBoundary(
                name=boundary_name,
                from_zone="input",
                to_zone="reasoning",
                confidence="explicit",
            )
        ],
        confidence=ConfidenceLevel.high,
        kc_subcodes=["KC1.1"],
    )


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(entry_name=_LABEL)
def test_entry_point_name_round_trips_through_profile_lookup(entry_name: str) -> None:
    """A known entry-point name resolves to its ID and back to the same name."""
    profile = _profile(entry_name=entry_name)
    entry_id = profile.entry_points[0].entry_point_id
    resolved = resolve_name_to_entry_point_id(entry_name, profile)
    assert resolved == entry_id
    assert resolve_name_to_entry_point_id(entry_id, profile) == entry_id
    assert resource_name_for_kind("entry_point", entry_id, profile) == entry_name


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(tool_name=_LABEL, integration_name=_LABEL, boundary_name=_LABEL)
def test_typed_resource_names_round_trip(
    tool_name: str, integration_name: str, boundary_name: str
) -> None:
    """Tool, integration, and trust-boundary names resolve to their IDs."""
    profile = _profile(
        tool_name=tool_name,
        integration_name=integration_name,
        boundary_name=boundary_name,
    )
    tool_id = profile.tool_inventory[0].tool_id
    integration_id = profile.external_integrations[0].integration_id
    boundary_id = profile.trust_boundaries[0].trust_boundary_id
    assert resolve_name_to_tool_id(tool_name, profile) == tool_id
    assert resolve_name_to_tool_id(tool_id, profile) == tool_id
    assert resolve_name_to_integration_id(integration_name, profile) == integration_id
    assert resolve_name_to_trust_boundary_id(boundary_name, profile) == boundary_id
    assert resource_name_for_kind("tool", tool_id, profile) == tool_name
    assert (
        resource_name_for_kind("integration", integration_id, profile)
        == integration_name
    )
    assert (
        resource_name_for_kind("trust_boundary", boundary_id, profile) == boundary_name
    )


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(unknown=_LABEL)
def test_unknown_names_do_not_invent_ids(unknown: str) -> None:
    """A name absent from the profile does not become a fabricated ID."""
    profile = _profile()
    if unknown == profile.entry_points[0].name:
        return
    assert resolve_name_to_entry_point_id(unknown, profile) is None
    assert resource_name_for_kind("entry_point", unknown, profile) == unknown


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(entry_name=_LABEL)
def test_humanize_projection_context_is_non_mutating(entry_name: str) -> None:
    """Humanization adds display names without rewriting the original mapping."""
    profile = _profile(entry_name=entry_name)
    entry_id = profile.entry_points[0].entry_point_id
    original = {
        "canonical_ingress": {"entry_point_id": entry_id},
        "selected_steps": [
            {
                "step_id": "projected.deliver",
                "resource_links": [
                    {
                        "role": "ingress",
                        "resource_ref": {
                            "kind": "entry_point",
                            "entry_point_id": entry_id,
                        },
                    }
                ],
            }
        ],
        "source_influence_paths": [],
    }
    snapshot = {
        "canonical_ingress": dict(original["canonical_ingress"]),
        "selected_steps": [
            {
                "step_id": "projected.deliver",
                "resource_links": [
                    {
                        "role": "ingress",
                        "resource_ref": {
                            "kind": "entry_point",
                            "entry_point_id": entry_id,
                        },
                    }
                ],
            }
        ],
        "source_influence_paths": [],
    }
    humanized = humanize_projection_context(original, profile)
    assert original == snapshot
    assert humanized is not original
    assert humanized is not None
    assert humanized["canonical_ingress_name"] == entry_name
    assert (
        humanized["selected_steps"][0]["resource_links"][0]["resource_ref"][
            "entry_point_id"
        ]
        == entry_name
    )
