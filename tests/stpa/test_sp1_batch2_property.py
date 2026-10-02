"""Property-based tests for SP1 bug-fix batch 2 invariants.

Covers two feature areas:

1. **max_completion_tokens threading** — ``safe_llm_call`` forwards the
   optional token cap to ``llm_client.complete`` only when provided;
   omits it (passes None) when not.

2. **Capability profile conditional rendering** — ``stage2_call2a_user.j2``
   renders the "Capability Profile Context" section when a profile is
   provided and omits it when ``None``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from hypothesis import HealthCheck, given, settings, strategies as st
from pydantic import BaseModel

from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    build_kc_subcodes_display,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from tests.stpa.sp1_helpers import MockLLMClient


# ---------------------------------------------------------------------------
# max_completion_tokens threading through safe_llm_call
# ---------------------------------------------------------------------------


class _DummyModel(BaseModel):
    """Simple model for LLM call testing."""

    name: str = "test"


class TestMaxCompletionTokensThreading:
    """Property tests for max_completion_tokens forwarding in safe_llm_call."""

    @given(
        token_cap=st.integers(min_value=1, max_value=32768),
    )
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_token_cap_forwarded_to_complete(
        self, tmp_path: Path, token_cap: int
    ) -> None:
        """When max_completion_tokens is provided, it reaches complete()."""
        from asago_scenario_generator.stpa.infra.llm_helpers import safe_llm_call

        client = MockLLMClient()
        client.set_response_for(_DummyModel, _DummyModel(name="ok").model_dump())

        safe_llm_call(
            llm_client=client,
            system_prompt="sys",
            user_prompt="usr",
            response_format=_DummyModel,
            run_dir=tmp_path,
            stage="test",
            step="test_step",
            max_completion_tokens=token_cap,
        )

        assert len(client.calls) == 1
        assert client.calls[0].max_completion_tokens == token_cap

    @given(
        data=st.none(),
    )
    @settings(
        max_examples=5,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_no_token_cap_passes_none(self, tmp_path: Path, data: Any) -> None:
        """When max_completion_tokens is not provided, complete() receives None."""
        from asago_scenario_generator.stpa.infra.llm_helpers import safe_llm_call

        client = MockLLMClient()
        client.set_response_for(_DummyModel, _DummyModel(name="ok").model_dump())

        safe_llm_call(
            llm_client=client,
            system_prompt="sys",
            user_prompt="usr",
            response_format=_DummyModel,
            run_dir=tmp_path,
            stage="test",
            step="test_step",
        )

        assert len(client.calls) == 1
        assert client.calls[0].max_completion_tokens is None

    def test_revision_uses_8192_token_cap(self, tmp_path: Path) -> None:
        """The critic revision call uses REVISION_MAX_COMPLETION_TOKENS (8192)."""
        from asago_scenario_generator.stpa.system_model.critic import (
            REVISION_MAX_COMPLETION_TOKENS,
            RevisionDelta,
            run_revision,
        )

        assert REVISION_MAX_COMPLETION_TOKENS == 8192

        # Verify the revision LLM call receives the token cap
        client = MockLLMClient()
        client.set_response_for(RevisionDelta, RevisionDelta().model_dump())

        # Build a minimal control structure for the revision call
        from asago_scenario_generator.stpa.models.control_structure import (
            ControlAction,
            ControlStructure,
            FeedbackChannel,
            ProcessModelPart,
            Responsibility,
        )

        cs = ControlStructure(
            responsibilities=[
                Responsibility(
                    resp_id="RESP-1",
                    description="Test controller",
                    process_model_parts=[
                        ProcessModelPart(pm_id="PM-1-1", description="State")
                    ],
                    control_actions=[
                        ControlAction(ca_id="CA-1-1", description="Action")
                    ],
                    feedback_channels=[
                        FeedbackChannel(
                            fb_id="FB-1-1",
                            description="Feedback",
                            updates="PM-1-1",
                        )
                    ],
                )
            ]
        )

        from asago_scenario_generator.stpa.system_model.critic import CriticFindings

        findings = CriticFindings(
            checklist_results={"Input validation": "absent_unjustified"},
            gaps=[
                {
                    "gap_type": "missing_responsibility",
                    "description": "Input validation responsibility is missing",
                    "related_attack_path": "The input path has no validation owner",
                    "suggested_remedy": "Add an input validation responsibility",
                }
            ],
        )

        run_revision(
            llm_client=client,
            control_structure=cs,
            critic_findings=findings,
            use_case_text="Test use case",
            run_dir=tmp_path,
        )

        # Find the revision call
        revision_calls = [
            c for c in client.calls if c.max_completion_tokens is not None
        ]
        assert len(revision_calls) == 1
        assert revision_calls[0].max_completion_tokens == 8192


# ---------------------------------------------------------------------------
# Capability profile conditional rendering in stage2_call2a_user.j2
# ---------------------------------------------------------------------------


def _make_capability_profile(
    kc_subcodes: list[str] | None = None,
) -> CapabilityProfile:
    """Build a valid CapabilityProfile for template rendering tests."""
    from asago_scenario_generator.models.capability_profile import (
        EntryPoint,
        ToolInventoryEntry,
    )

    return CapabilityProfile(
        zones_active=["input", "reasoning", "tool_execution"],
        entry_points=[
            EntryPoint(name="User chat", direction="input", controllability="direct"),
        ],
        confidence="medium",
        kc_subcodes=kc_subcodes or ["KC1.1", "KC5.1", "KC6.1.1"],
        tool_inventory=[
            ToolInventoryEntry(name="tool1", description="A tool"),
        ],
    )


def _make_requirement_set():
    """Build a minimal RequirementSet for template rendering."""
    from asago_scenario_generator.stpa.system_model.control_structure import (
        Requirement,
        RequirementSet,
    )

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
        profile = _make_capability_profile(kc_subcodes)
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
        profile = _make_capability_profile(kc_subcodes)
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
        profile = _make_capability_profile(kc_subcodes)
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
