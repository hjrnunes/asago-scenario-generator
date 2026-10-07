"""Property tests for the capability profile section of ``stage2_call2a_user.j2``.

The template renders the "Capability Profile Context" section when a profile is
provided and omits it when the profile is None.
"""

from __future__ import annotations


from hypothesis import given, settings, strategies as st

from asago_scenario_generator.models.capability_profile import (
    build_kc_subcodes_display,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.control_structure import (
    Requirement,
    RequirementSet,
)
from tests.helpers.stpa_builders import make_capability_profile


# ---------------------------------------------------------------------------
# Capability profile conditional rendering in stage2_call2a_user.j2
# ---------------------------------------------------------------------------


def _make_requirement_set():
    """Build a minimal RequirementSet for template rendering."""
    req = Requirement(
        req_id="REQ-1",
        description="Verify user identity",
        classification="control",
        source_constraint="SC-1",
    )
    return RequirementSet(requirements=[req])


class TestCapabilityProfileRendering:
    """Property tests for capability profile conditional rendering."""

    @given(
        kc_subcodes=st.lists(
            st.sampled_from(["KC1.1", "KC5.1", "KC6.1.1", "KC4.3", "KC2.3"]),
            min_size=1,
            max_size=5,
            unique=True,
        )
    )
    @settings(max_examples=15, deadline=None)
    def test_profile_section_present_when_provided(
        self, kc_subcodes: list[str]
    ) -> None:
        """When capability_profile is provided, the template renders the profile section."""
        profile = make_capability_profile(kc_subcodes)
        req_set = _make_requirement_set()
        loader = TemplateLoader(PROMPTS_DIR)

        rendered = loader.render_prompt(
            "stage2_call2a_user.j2",
            use_case_text="Test use case",
            requirements=req_set.requirements,
            capability_profile=profile,
            kc_subcodes_display=build_kc_subcodes_display(profile.kc_subcodes),
        )

        assert "Capability Profile Context" in rendered
        assert "Active functional areas:" in rendered
        assert all(code in rendered for code in kc_subcodes)
        assert all(
            description in rendered
            for description in build_kc_subcodes_display(kc_subcodes).values()
        )
        assert "Multi-agent:" in rendered
        assert "Human-in-the-loop:" in rendered
        assert "Persistent memory:" in rendered

    def test_profile_section_absent_when_none(self) -> None:
        """When capability_profile is None, the template omits the profile section."""
        req_set = _make_requirement_set()
        loader = TemplateLoader(PROMPTS_DIR)

        rendered = loader.render_prompt(
            "stage2_call2a_user.j2",
            use_case_text="Test use case",
            requirements=req_set.requirements,
            capability_profile=None,
        )

        assert "Capability Profile Context" not in rendered

    @given(
        kc_subcodes=st.lists(
            st.sampled_from(["KC1.1", "KC5.1", "KC6.1.1", "KC4.3", "KC2.3"]),
            min_size=1,
            max_size=5,
            unique=True,
        )
    )
    @settings(max_examples=15, deadline=None)
    def test_profile_zones_rendered_correctly(self, kc_subcodes: list[str]) -> None:
        """The rendered zones_active match the profile's zones."""
        profile = make_capability_profile(kc_subcodes)
        req_set = _make_requirement_set()
        loader = TemplateLoader(PROMPTS_DIR)

        rendered = loader.render_prompt(
            "stage2_call2a_user.j2",
            use_case_text="Test use case",
            requirements=req_set.requirements,
            capability_profile=profile,
        )

        # Each active zone should appear in the rendered output
        for zone in profile.zones_active:
            assert zone in rendered

    @given(
        kc_subcodes=st.lists(
            st.sampled_from(["KC1.1", "KC5.1", "KC6.1.1", "KC4.3", "KC2.3"]),
            min_size=1,
            max_size=5,
            unique=True,
        )
    )
    @settings(max_examples=15, deadline=None)
    def test_profile_boolean_flags_rendered(self, kc_subcodes: list[str]) -> None:
        """The rendered boolean flags match the profile's computed values."""
        profile = make_capability_profile(kc_subcodes)
        req_set = _make_requirement_set()
        loader = TemplateLoader(PROMPTS_DIR)

        rendered = loader.render_prompt(
            "stage2_call2a_user.j2",
            use_case_text="Test use case",
            requirements=req_set.requirements,
            capability_profile=profile,
        )

        # The rendered output should contain the string representation
        # of each boolean flag
        assert str(profile.multi_agent).lower() in rendered.lower()
        assert str(profile.hitl).lower() in rendered.lower()
        assert str(profile.has_persistent_memory).lower() in rendered.lower()
