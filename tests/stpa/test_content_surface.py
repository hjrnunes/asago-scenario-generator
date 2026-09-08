"""Phase 3.2: content-surface facts derived from typed capability-profile facts.

Spec: ai/findings/target-grounded-scenario-generation-spec-2026-09-07.md,
Phase 3.2.  A ``third_party_via_content`` adversary is only eligible when the
capability profile itself records a retrieval or tool-content surface.
"""

from __future__ import annotations

from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    ConfidenceLevel,
    EntryPoint,
    ToolInventoryEntry,
)
from asago_scenario_generator.stpa.scenario_prod.content_surface import (
    content_surface_facts,
)


def _profile(**overrides: object) -> CapabilityProfile:
    fields: dict[str, object] = {
        "zones_active": ["input"],
        "entry_points": [EntryPoint(name="prompt", direction="input")],
        "confidence": ConfidenceLevel.medium,
        "kc_subcodes": ["KC1.1"],
    }
    fields.update(overrides)
    return CapabilityProfile.model_validate(fields)


def _content_profile(kc_subcodes: list[str]) -> CapabilityProfile:
    """A profile whose content-bearing KC codes may activate tool zones."""
    fields: dict[str, object] = {"kc_subcodes": kc_subcodes}
    if "tool_execution" in fields.get("zones_active", ["input"]):
        fields["tool_inventory"] = [
            ToolInventoryEntry(name="test_tool", description="A test tool")
        ]
    return _profile(
        zones_active=["input", "reasoning", "tool_execution"],
        tool_inventory=[ToolInventoryEntry(name="test_tool", description="A tool")],
        **fields,
    )


class TestContentSurfaceFacts:
    def test_missing_profile_fails_closed(self) -> None:
        facts = content_surface_facts(None)
        assert facts.has_content_surface is False
        assert facts.evidence == ()

    def test_direct_user_input_is_not_a_content_surface(self) -> None:
        profile = _profile(
            entry_points=[
                EntryPoint(name="chat", direction="input", controllability="direct")
            ]
        )
        assert content_surface_facts(profile).has_content_surface is False

    def test_external_content_entry_point_establishes_a_surface(self) -> None:
        profile = _profile(
            entry_points=[
                EntryPoint(
                    name="customer reviews",
                    direction="bidirectional",
                    entry_point_type="external_content",
                )
            ]
        )
        facts = content_surface_facts(profile)
        assert facts.has_content_surface is True
        assert any("external content" in item for item in facts.evidence)

    def test_output_only_external_content_is_not_a_surface(self) -> None:
        profile = _profile(
            entry_points=[
                EntryPoint(
                    name="published feed",
                    direction="output",
                    entry_point_type="external_content",
                )
            ]
        )
        assert content_surface_facts(profile).has_content_surface is False

    def test_explicit_indirect_controllability_establishes_a_surface(self) -> None:
        profile = _profile(
            entry_points=[
                EntryPoint(
                    name="RAG documents",
                    direction="input",
                    controllability="indirect",
                )
            ]
        )
        facts = content_surface_facts(profile)
        assert facts.has_content_surface is True
        assert any("indirect" in item for item in facts.evidence)

    def test_content_bearing_kc_subcodes_establish_a_surface(self) -> None:
        for code in ("KC6.3.3", "KC6.4", "KCX-VSTORE"):
            facts = content_surface_facts(_content_profile([code]))
            assert facts.has_content_surface is True, code
            assert any(code in item for item in facts.evidence)

    def test_unrelated_kc_subcodes_do_not_establish_a_surface(self) -> None:
        assert content_surface_facts(_profile(kc_subcodes=["KC1.1"])).has_content_surface is False
