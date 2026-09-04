"""Regression tests for the SP1 prompt bug fixes."""

from __future__ import annotations

import re

import pytest
from hypothesis import given, settings, strategies as st

from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.system_model import PROMPTS_DIR


_REQUIRED_CONTENT = {
    "stage1a_risk_system.j2": (
        "Every loss must cite its source risk IDs",
        "Every hazard references at least one valid loss_id",
    ),
    "stage1b_system.j2": (
        "every tool must be explicitly mentioned or directly implied "
        "by the use-case description",
        "Do not invent tools based on what a system like this might have",
    ),
    "stage2_call2a_system.j2": (
        "Check the capability profile's active zones",
        "When `tool_execution` is active: require a responsibility governing tool "
        "parameter validation and action selection",
        "When `memory` is active: require a responsibility for context management and "
        "memory lifecycle",
        "When `hitl` is true: require a responsibility for escalation and human oversight",
        "When `inter_agent` is active: require a responsibility for inter-agent "
        "coordination and message validation",
        "This is a hard requirement, not a suggestion",
    ),
    "stage2_call2b_system.j2": (
        "Each CA is a single discrete action the controller takes",
        "Split composite actions into separate CAs",
        "approve or reject request",
        "CA-X-1 Approve request",
        "CA-X-2 Reject request",
        'A CA containing "or", "and", or similar conjunctions is likely '
        "composite and should be split",
    ),
    "stage2_call3_system.j2": (
        "Each coordination link represents an explicit lateral control or information",
        "responsibilities overlap or leave a decision boundary ambiguous",
        "actions affect the same controlled process or resource",
        "actions can conflict or must occur in a defined order",
        "One controller needs state or outcome information held by the other",
        "greenhouse heating and ventilation controllers",
    ),
}


@pytest.mark.parametrize("template_name, fragments", _REQUIRED_CONTENT.items())
def test_sp1_prompt_bug_fix_content_is_in_template(
    template_name: str, fragments: tuple[str, ...]
) -> None:
    text = (PROMPTS_DIR / template_name).read_text()
    assert all(fragment in text for fragment in fragments)


@pytest.mark.parametrize("template_name, fragments", _REQUIRED_CONTENT.items())
def test_sp1_prompt_bug_fix_content_renders(
    template_name: str, fragments: tuple[str, ...]
) -> None:
    rendered = TemplateLoader(PROMPTS_DIR).render_prompt(template_name)
    assert all(fragment in rendered for fragment in fragments)


@pytest.mark.parametrize(
    "template_name, section",
    (
        ("stage1a_risk_system.j2", "## Quality requirements"),
        ("stage1b_system.j2", "## Rules"),
        ("stage2_call2a_system.j2", "## ID conventions"),
        ("stage2_call3_system.j2", "## Connection integrity checks"),
    ),
)
def test_sp1_prompt_bug_fixes_preserve_existing_sections(
    template_name: str, section: str
) -> None:
    text = (PROMPTS_DIR / template_name).read_text()
    assert section in text


@pytest.mark.parametrize(
    "template_name",
    (
        "stage2_call2a_system.j2",
        "stage2_call2b_system.j2",
        "stage2_call3_system.j2",
    ),
)
def test_control_structure_prompts_define_the_feedback_loop(
    template_name: str,
) -> None:
    rendered = TemplateLoader(PROMPTS_DIR).render_prompt(template_name)

    assert "A **controller** is a functional decision maker" in rendered
    assert "A **process model part** is decision-relevant information" in rendered
    assert "feedback updates the process model" in rendered
    assert "the action influences the controlled" in rendered


@pytest.mark.parametrize("template_name", ("critic_system.j2", "revision_system.j2"))
def test_review_prompts_reuse_the_control_loop_method(template_name: str) -> None:
    text = (PROMPTS_DIR / template_name).read_text()

    assert '{% include "_control_loop_method.j2" %}' in text


# ---------------------------------------------------------------------------
# Property-based tests for template rendering invariants
#
# These tests verify invariants that hold across all zero-variable system
# templates (including the four modified by the bug-fix work):
#
# - **Section-heading preservation**: every ``##`` heading in the raw
#   template text appears in the rendered output.
# - **Subsection-heading preservation**: every ``###`` heading in the raw
#   template text appears in the rendered output.
# - **No duplicate section headings**: no ``##`` heading appears more than
#   once in a single template (detects accidental copy-paste duplication).
# ---------------------------------------------------------------------------

_ZERO_VAR_SYSTEM_TEMPLATES = [
    "stage1a_risk_system.j2",
    "stage1a_gap_system.j2",
    "stage1b_system.j2",
    "stage2_call1_system.j2",
    "stage2_call2a_system.j2",
    "stage2_call2b_system.j2",
    "stage2_call3_system.j2",
]

_SECTION_RE = re.compile(r"^(##+) .+$", re.MULTILINE)


def _section_headings(template_name: str, prefix: str = "##") -> list[str]:
    """Extract all markdown headings with *prefix* from a template's raw text."""
    text = (PROMPTS_DIR / template_name).read_text()
    pattern = re.compile(rf"^({re.escape(prefix)} .+)$", re.MULTILINE)
    return pattern.findall(text)


class TestPromptBugFixRenderingProperties:
    """Property-based invariants for the bug-fix prompt templates."""

    @given(template_name=st.sampled_from(_ZERO_VAR_SYSTEM_TEMPLATES))
    @settings(max_examples=20, deadline=None)
    def test_pqbf_01_section_headings_preserved_in_render(
        self,
        template_name: str,
    ) -> None:
        """Every ## heading in the raw template appears in the rendered output."""
        rendered = TemplateLoader(PROMPTS_DIR).render_prompt(template_name)
        for heading in _section_headings(template_name, "##"):
            assert heading in rendered

    @given(template_name=st.sampled_from(_ZERO_VAR_SYSTEM_TEMPLATES))
    @settings(max_examples=20, deadline=None)
    def test_pqbf_02_subsection_headings_preserved_in_render(
        self,
        template_name: str,
    ) -> None:
        """Every ### heading in the raw template appears in the rendered output."""
        rendered = TemplateLoader(PROMPTS_DIR).render_prompt(template_name)
        for heading in _section_headings(template_name, "###"):
            assert heading in rendered

    @given(template_name=st.sampled_from(_ZERO_VAR_SYSTEM_TEMPLATES))
    @settings(max_examples=20, deadline=None)
    def test_pqbf_03_no_duplicate_top_level_sections(
        self,
        template_name: str,
    ) -> None:
        """No ## heading appears more than once in a template (anti-duplication)."""
        headings = _section_headings(template_name, "##")
        assert len(headings) == len(set(headings)), (
            f"Duplicate ## headings in {template_name}: {headings}"
        )
