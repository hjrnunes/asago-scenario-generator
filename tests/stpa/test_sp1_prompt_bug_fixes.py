"""Regression tests for the SP1 prompt bug fixes.

The fixed Stage 1a, Stage 1b and Stage 2 wording lives in the phrase tables
under ``tests/phrases/``.
"""

from __future__ import annotations

import re

import pytest
from hypothesis import given, settings, strategies as st

from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.system_model import PROMPTS_DIR


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
