"""Property-based tests for SP1 bug-fix batch 2 invariants.

Covers three feature areas:

1. **Path reference detection and resolution** — ``_looks_like_path_reference``
   and ``_resolve_reference_path`` in ``asago_scenario_generator.stpa.pipeline.llm_config``:
   invariant boundaries (newlines, length, extensions), round-trip resolution,
   absolute/relative path handling, and non-existent path rejection.

2. **max_completion_tokens threading** — ``safe_llm_call`` forwards the
   optional token cap to ``llm_client.complete`` only when provided;
   omits it (passes None) when not.

3. **Capability profile conditional rendering** — ``stage2_call2a_user.j2``
   renders the "Capability Profile Context" section when a profile is
   provided and omits it when ``None``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from hypothesis import HealthCheck, assume, given, settings, strategies as st
from pydantic import BaseModel

from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    build_kc_subcodes_display,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from tests.stpa.sp1_helpers import MockLLMClient


# ---------------------------------------------------------------------------
# Path reference detection — _looks_like_path_reference
# ---------------------------------------------------------------------------

# Import from the canonical llm_config module (extracted from scripts/run_sp1.py)
from asago_scenario_generator.stpa.pipeline.llm_config import (
    _looks_like_path_reference,
    _resolve_reference_path,
    read_use_case,
)


class TestLooksLikePathReference:
    """Property tests for _looks_like_path_reference invariants."""

    @given(content=st.text(min_size=0, max_size=199))
    @settings(max_examples=50, deadline=None)
    def test_short_content_without_newline_and_wrong_ext_is_false(
        self, content: str
    ) -> None:
        """Content < 200 chars, no newline, but no .txt/.md suffix -> False."""
        # Ensure no accidental .txt/.md suffix
        assume_content = content
        if "\n" not in assume_content and "\r" not in assume_content:
            stripped = assume_content.strip()
            if not stripped.endswith((".txt", ".md")):
                assert _looks_like_path_reference(assume_content) is False

    @given(
        prefix=st.text(min_size=0, max_size=50),
        suffix=st.text(min_size=0, max_size=50),
    )
    @settings(max_examples=30, deadline=None)
    def test_newline_content_always_false(self, prefix: str, suffix: str) -> None:
        """Any content containing a newline is never a path reference."""
        content = prefix + "\n" + suffix
        assert _looks_like_path_reference(content) is False

    @given(
        prefix=st.text(min_size=0, max_size=50),
        suffix=st.text(min_size=0, max_size=50),
    )
    @settings(max_examples=30, deadline=None)
    def test_carriage_return_content_always_false(
        self, prefix: str, suffix: str
    ) -> None:
        """Any content containing a carriage return is never a path reference."""
        content = prefix + "\r" + suffix
        assert _looks_like_path_reference(content) is False

    @given(
        body=st.text(
            min_size=196,
            max_size=500,
            alphabet=st.characters(blacklist_characters=("\n", "\r")),
        ),
    )
    @settings(max_examples=30, deadline=None)
    def test_long_content_always_false(self, body: str) -> None:
        """Content >= 200 chars (after strip) is never a path reference."""
        # body is >= 196 chars; appending ".txt" (4 chars) gives >= 200
        # Ensure no leading/trailing whitespace that .strip() would remove,
        # which would make the stripped content < 200 chars.
        assume(body.strip() == body)
        content = body + ".txt"
        assert _looks_like_path_reference(content) is False

    @given(
        name=st.text(
            min_size=1,
            max_size=50,
            alphabet=st.characters(blacklist_characters=("\n", "\r")),
        ),
        ext=st.sampled_from((".txt", ".md")),
    )
    @settings(max_examples=30, deadline=None)
    def test_short_single_line_with_valid_ext_is_true(
        self, name: str, ext: str
    ) -> None:
        """Short, single-line content ending with .txt/.md is a path reference."""
        content = name + ext
        # Guard against edge case where name+ext >= 200 chars
        if len(content.strip()) < 200:
            assert _looks_like_path_reference(content) is True

    @given(
        body=st.text(
            min_size=1,
            max_size=50,
            alphabet=st.characters(blacklist_characters=("\n", "\r")),
        ),
        ext=st.sampled_from((".json", ".yaml", ".py", ".csv", ".xml", ".html")),
    )
    @settings(max_examples=30, deadline=None)
    def test_non_txt_md_extension_is_false(self, body: str, ext: str) -> None:
        """Content ending with non-.txt/.md extension is never a path reference."""
        content = body + ext
        assert _looks_like_path_reference(content) is False


# ---------------------------------------------------------------------------
# Path resolution — _resolve_reference_path
# ---------------------------------------------------------------------------


class TestResolveReferencePath:
    """Property tests for _resolve_reference_path invariants."""

    @given(
        filename=st.text(
            min_size=1,
            max_size=30,
            alphabet=st.characters(
                whitelist_categories=("Ll", "Nd"),
                whitelist_characters=("-", "_", "."),
            ),
        )
    )
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_relative_path_resolves_from_source_parent(
        self, tmp_path: Path, filename: str
    ) -> None:
        """A relative path resolves against the source file's parent directory."""
        # Ensure filename ends with .txt
        if not filename.endswith(".txt"):
            filename = filename + ".txt"
        referenced = tmp_path / filename
        referenced.write_text("actual use case content", encoding="utf-8")

        source = tmp_path / "use-case.txt"
        source.write_text(filename, encoding="utf-8")

        resolved = _resolve_reference_path(filename, source)
        assert resolved == referenced

    @given(
        filename=st.text(
            min_size=1,
            max_size=30,
            alphabet=st.characters(
                whitelist_categories=("Ll", "Nd"),
                whitelist_characters=("-", "_", "."),
            ),
        )
    )
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_absolute_path_resolves_as_is(self, tmp_path: Path, filename: str) -> None:
        """An absolute path is used directly without searching."""
        if not filename.endswith(".md"):
            filename = filename + ".md"
        referenced = tmp_path / filename
        referenced.write_text("content", encoding="utf-8")
        abs_path = str(referenced.resolve())

        source = tmp_path / "source.txt"
        resolved = _resolve_reference_path(abs_path, source)
        assert resolved == referenced.resolve()

    @given(
        missing_name=st.text(
            min_size=1,
            max_size=20,
            alphabet=st.characters(
                whitelist_categories=("Ll", "Nd"),
                whitelist_characters=("-"),
            ),
        )
    )
    @settings(
        max_examples=15,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_nonexistent_relative_path_raises(
        self, tmp_path: Path, missing_name: str
    ) -> None:
        """A relative path that doesn't exist in either location raises FileNotFoundError."""
        if not missing_name.endswith(".txt"):
            missing_name = missing_name + ".txt"
        source = tmp_path / "source.txt"
        source.write_text("content", encoding="utf-8")

        import pytest

        with pytest.raises(FileNotFoundError, match="unresolved path"):
            _resolve_reference_path(missing_name, source)


# ---------------------------------------------------------------------------
# read_use_case — round-trip integration
# ---------------------------------------------------------------------------


class TestReadUseCase:
    """Property tests for read_use_case round-trip behavior."""

    @given(
        content=st.text(
            min_size=1,
            max_size=1000,
            alphabet=st.characters(
                blacklist_categories=("Cs",),
                blacklist_characters=("\r",),
            ),
        ),
    )
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_plain_content_returned_as_is(self, tmp_path: Path, content: str) -> None:
        """Content that doesn't look like a path reference is returned as-is."""
        # Ensure content doesn't accidentally look like a path reference
        assume_content = content
        if _looks_like_path_reference(assume_content):
            assume_content = "x\n" + assume_content  # Add newline to break heuristic
        use_case_file = tmp_path / "use-case.txt"
        use_case_file.write_text(assume_content, encoding="utf-8")

        result = read_use_case(str(use_case_file))
        assert result == assume_content

    @given(
        actual_content=st.text(
            min_size=10,
            max_size=500,
            alphabet=st.characters(
                blacklist_categories=("Cs",),
                blacklist_characters=("\r",),
            ),
        ),
    )
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_path_reference_resolves_to_referenced_file(
        self, tmp_path: Path, actual_content: str
    ) -> None:
        """A file containing a path reference resolves to the referenced file."""
        referenced = tmp_path / "actual-use-case.txt"
        referenced.write_text(actual_content, encoding="utf-8")

        referrer = tmp_path / "use-case.txt"
        referrer.write_text("actual-use-case.txt", encoding="utf-8")

        result = read_use_case(str(referrer))
        assert result == actual_content

    @given(
        actual_content=st.text(
            min_size=10,
            max_size=500,
            alphabet=st.characters(
                blacklist_categories=("Cs",),
                blacklist_characters=("\r",),
            ),
        ),
    )
    @settings(
        max_examples=15,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_at_prefix_stripped(self, tmp_path: Path, actual_content: str) -> None:
        """The @ prefix is stripped from the path before reading."""
        use_case_file = tmp_path / "use-case.txt"
        use_case_file.write_text(actual_content, encoding="utf-8")

        result = read_use_case("@" + str(use_case_file))
        assert result == actual_content


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
