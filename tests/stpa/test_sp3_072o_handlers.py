"""Hardening tests for SP3-072o acceptance step handlers.

These tests directly exercise the handler functions in
``acceptance/runtime_features/sp3.py`` with edge cases that the
generated acceptance scenarios do not cover, killing mutation survivors.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Make acceptance runtime importable
_ACCEPTANCE_DIR = Path(__file__).resolve().parents[2] / "acceptance"
if str(_ACCEPTANCE_DIR) not in sys.path:
    sys.path.insert(0, str(_ACCEPTANCE_DIR))

from runtime_features.sp3 import (  # noqa: E402
    _072o_has_code_fence_restriction,
    _072o_has_loss_id_restriction,
    _072o_resolve_stage,
    _h_072o_check_copied_loss,
    _h_072o_check_copied_terminology,
    _h_072o_check_fails_l,
    _h_072o_check_fails_stpa_sec,
    _h_072o_gherkin_contains_loss_ids,
    _h_072o_gherkin_l_star,
    _h_072o_gherkin_no_h_star,
    _h_072o_gherkin_no_hazard_heading,
    _h_072o_gherkin_no_hazard_ids,
    _h_072o_inspect_user_template,
    _h_072o_loss_ids_before_task,
    _h_072o_minimal_fixture,
    _h_072o_minimal_loss_analysis,
    _h_072o_no_rendered_pattern,
    _h_072o_render_system_prompt,
    _h_072o_sys_code_fence_instruction,
    _h_072o_sys_contains_attack_tree,
    _h_072o_sys_contains_phrase,
    _h_072o_sys_contains_task_framing,
    _h_072o_sys_contains_yaml,
    _h_072o_sys_not_contains_string,
    _h_072o_template_contains_var,
    _h_072o_template_not_contains_var,
    _h_072o_templates_renderable,
)
from runtime_shared import World  # noqa: E402


# ── _072o_resolve_stage ──────────────────────────────────────────────


class TestResolveStage:
    def test_extracts_stage_5(self):
        assert _072o_resolve_stage("the Stage 5 system prompt is rendered") == "Stage 5"

    def test_extracts_stage_6c(self):
        assert _072o_resolve_stage("the Stage 6c user prompt template") == "Stage 6c"

    def test_returns_none_for_no_stage(self):
        assert _072o_resolve_stage("no stage here") is None

    def test_returns_none_for_empty(self):
        assert _072o_resolve_stage("") is None


# ── _072o_has_loss_id_restriction ────────────────────────────────────


class TestHasLossIdRestriction:
    def test_detects_l_star_only(self):
        assert _072o_has_loss_id_restriction("use only L-* loss IDs") is True

    def test_detects_not_h_star(self):
        assert _072o_has_loss_id_restriction("do not use H-* IDs") is True

    def test_rejects_plain_text(self):
        assert (
            _072o_has_loss_id_restriction("ordinary text without restrictions") is False
        )

    def test_rejects_empty(self):
        assert _072o_has_loss_id_restriction("") is False


# ── _072o_has_code_fence_restriction ─────────────────────────────────


class TestHasCodeFenceRestriction:
    def test_detects_do_not_wrap(self):
        assert _072o_has_code_fence_restriction("Do not wrap in code fences") is True

    def test_detects_markdown_code(self):
        assert _072o_has_code_fence_restriction("no Markdown code blocks") is True

    def test_rejects_plain_text(self):
        assert _072o_has_code_fence_restriction("ordinary text") is False

    def test_rejects_empty(self):
        assert _072o_has_code_fence_restriction("") is False


# ── _h_072o_minimal_fixture ──────────────────────────────────────────


class TestMinimalFixture:
    def test_sets_fixture_when_unset(self):
        world = World()
        ok, msg = _h_072o_minimal_fixture(world, "", {})
        assert ok is True
        assert world.scenario_spec is not None
        assert world.loss_analysis is not None

    def test_preserves_existing_scenario_spec(self):
        """Mutant: is None -> is not None would overwrite existing spec."""
        world = World()
        sentinel = object()
        world.scenario_spec = sentinel
        ok, _msg = _h_072o_minimal_fixture(world, "", {})
        assert ok is True
        # Original preserves sentinel; mutant overwrites it
        assert world.scenario_spec is sentinel

    def test_preserves_existing_loss_analysis(self):
        """Mutant: is None -> is not None would overwrite existing analysis."""
        world = World()
        sentinel = object()
        world.loss_analysis = sentinel
        ok, _msg = _h_072o_minimal_fixture(world, "", {})
        assert ok is True
        assert world.loss_analysis is sentinel


# ── _h_072o_minimal_loss_analysis ────────────────────────────────────


class TestMinimalLossAnalysis:
    def test_sets_loss_analysis(self):
        world = World()
        ok, _msg = _h_072o_minimal_loss_analysis(world, "", {})
        assert ok is True
        assert world.loss_analysis is not None

    def test_overwrites_loss_analysis(self):
        """This handler always sets loss_analysis (not conditional)."""
        world = World()
        world.loss_analysis = object()
        ok, _msg = _h_072o_minimal_loss_analysis(world, "", {})
        assert ok is True
        # loss_analysis is always overwritten by this handler
        assert world.loss_analysis is not None

    def test_preserves_existing_scenario_spec(self):
        """Mutant: is None -> is not None would overwrite existing spec."""
        world = World()
        sentinel = object()
        world.scenario_spec = sentinel
        ok, _msg = _h_072o_minimal_loss_analysis(world, "", {})
        assert ok is True
        assert world.scenario_spec is sentinel


# ── _h_072o_render_system_prompt ─────────────────────────────────────


class TestRenderSystemPrompt:
    def test_renders_stage_5(self):
        world = World()
        ok, msg = _h_072o_render_system_prompt(
            world, "the Stage 5 system prompt is rendered", {}
        )
        assert ok is True
        assert world.sp3_system_prompt is not None
        assert "security analyst" in world.sp3_system_prompt.lower()

    def test_renders_stage_6b(self):
        world = World()
        ok, _msg = _h_072o_render_system_prompt(
            world, "the Stage 6b system prompt is rendered", {}
        )
        assert ok is True
        assert world.sp3_current_stage == "Stage 6b"

    def test_fails_for_unrecognized_stage(self):
        """Mutant: or -> and would not reject invalid stage."""
        world = World()
        ok, msg = _h_072o_render_system_prompt(
            world, "the Stage 9 system prompt is rendered", {}
        )
        assert ok is False
        assert "Unknown stage" in msg

    def test_fails_for_no_stage(self):
        world = World()
        ok, msg = _h_072o_render_system_prompt(world, "no stage here", {})
        assert ok is False
        assert "Unknown stage" in msg


# ── _h_072o_inspect_user_template ────────────────────────────────────


class TestInspectUserTemplate:
    def test_inspects_stage_5(self):
        world = World()
        ok, _msg = _h_072o_inspect_user_template(
            world, "the Stage 5 user prompt template source is inspected", {}
        )
        assert ok is True
        assert world.sp3_template_source is not None
        assert len(world.sp3_template_source) > 0

    def test_fails_for_unrecognized_stage(self):
        """Mutant: or -> and would not reject invalid stage."""
        world = World()
        ok, msg = _h_072o_inspect_user_template(
            world, "the Stage 9 user prompt template source is inspected", {}
        )
        assert ok is False
        assert "Unknown stage" in msg


# ── _h_072o_template_contains_var ────────────────────────────────────


class TestTemplateContainsVar:
    def test_detects_present_variable(self):
        world = World()
        _h_072o_inspect_user_template(
            world, "the Stage 5 user prompt template source is inspected", {}
        )
        ok, _msg = _h_072o_template_contains_var(
            world, 'the template contains the variable "defender_bdi_yaml"', {}
        )
        assert ok is True

    def test_fails_for_absent_variable(self):
        """Mutant: not in -> in would not detect missing variable."""
        world = World()
        _h_072o_inspect_user_template(
            world, "the Stage 5 user prompt template source is inspected", {}
        )
        ok, msg = _h_072o_template_contains_var(
            world, 'the template contains the variable "nonexistent_var_xyz"', {}
        )
        assert ok is False
        assert "does not contain" in msg


# ── _h_072o_template_not_contains_var ────────────────────────────────


class TestTemplateNotContainsVar:
    def test_passes_for_absent_variable(self):
        world = World()
        _h_072o_inspect_user_template(
            world, "the Stage 5 user prompt template source is inspected", {}
        )
        ok, _msg = _h_072o_template_not_contains_var(
            world,
            'the template does not contain the variable "nonexistent_var_xyz"',
            {},
        )
        assert ok is True

    def test_fails_for_present_variable(self):
        """Mutant: or -> and with only one format present would not detect."""
        world = World()
        _h_072o_inspect_user_template(
            world, "the Stage 5 user prompt template source is inspected", {}
        )
        ok, msg = _h_072o_template_not_contains_var(
            world, 'the template does not contain the variable "defender_bdi_yaml"', {}
        )
        assert ok is False
        assert "should not contain" in msg


# ── _h_072o_sys_not_contains_string ──────────────────────────────────


class TestSysNotContainsString:
    def test_passes_when_string_absent(self):
        world = World()
        _h_072o_render_system_prompt(world, "the Stage 5 system prompt is rendered", {})
        ok, _msg = _h_072o_sys_not_contains_string(
            world,
            'the Stage 5 system prompt does not contain the string "STPA-Sec"',
            {},
        )
        assert ok is True

    def test_fails_when_string_present(self):
        world = World()
        _h_072o_render_system_prompt(world, "the Stage 5 system prompt is rendered", {})
        ok, msg = _h_072o_sys_not_contains_string(
            world,
            'the Stage 5 system prompt does not contain the string "security"',
            {},
        )
        assert ok is False
        assert "should not contain" in msg


# ── _h_072o_sys_contains_phrase ──────────────────────────────────────


class TestSysContainsPhrase:
    def test_passes_when_phrase_present(self):
        world = World()
        _h_072o_render_system_prompt(world, "the Stage 5 system prompt is rendered", {})
        ok, _msg = _h_072o_sys_contains_phrase(
            world,
            'the Stage 5 system prompt contains the phrase "security analyst"',
            {},
        )
        assert ok is True

    def test_fails_when_phrase_absent(self):
        world = World()
        _h_072o_render_system_prompt(world, "the Stage 5 system prompt is rendered", {})
        ok, msg = _h_072o_sys_contains_phrase(
            world, 'the Stage 5 system prompt contains the phrase "STPA-Sec"', {}
        )
        assert ok is False
        assert "does not contain" in msg


# ── _h_072o_sys_contains_task_framing ────────────────────────────────


class TestSysContainsTaskFraming:
    def test_passes_for_correct_framing(self):
        world = World()
        _h_072o_render_system_prompt(
            world, "the Stage 6a system prompt is rendered", {}
        )
        ok, _msg = _h_072o_sys_contains_task_framing(
            world,
            'the Stage 6a system prompt contains the task framing phrase "7-step causal narrative"',
            {},
        )
        assert ok is True

    def test_fails_for_wrong_framing(self):
        world = World()
        _h_072o_render_system_prompt(
            world, "the Stage 6a system prompt is rendered", {}
        )
        ok, msg = _h_072o_sys_contains_task_framing(
            world,
            'the Stage 6a system prompt contains the task framing phrase "STPA-Sec"',
            {},
        )
        assert ok is False
        assert "does not contain" in msg


# ── _h_072o_sys_code_fence_instruction ───────────────────────────────


class TestSysCodeFenceInstruction:
    def test_passes_for_stage_6b(self):
        world = World()
        _h_072o_render_system_prompt(
            world, "the Stage 6b system prompt is rendered", {}
        )
        ok, _msg = _h_072o_sys_code_fence_instruction(world, "", {})
        assert ok is True

    def test_fails_when_no_prompt(self):
        world = World()
        ok, msg = _h_072o_sys_code_fence_instruction(world, "", {})
        assert ok is False
        assert "No system prompt" in msg


# ── _h_072o_sys_contains_yaml ────────────────────────────────────────


class TestSysContainsYaml:
    def test_passes_for_stage_6b(self):
        world = World()
        _h_072o_render_system_prompt(
            world, "the Stage 6b system prompt is rendered", {}
        )
        ok, _msg = _h_072o_sys_contains_yaml(world, "", {})
        assert ok is True

    def test_fails_when_no_prompt(self):
        world = World()
        ok, msg = _h_072o_sys_contains_yaml(world, "", {})
        assert ok is False
        assert "No system prompt" in msg


# ── _h_072o_sys_contains_attack_tree ─────────────────────────────────


class TestSysContainsAttackTree:
    def test_passes_for_stage_6b(self):
        world = World()
        _h_072o_render_system_prompt(
            world, "the Stage 6b system prompt is rendered", {}
        )
        ok, _msg = _h_072o_sys_contains_attack_tree(world, "", {})
        assert ok is True

    def test_fails_when_no_prompt(self):
        world = World()
        ok, msg = _h_072o_sys_contains_attack_tree(world, "", {})
        assert ok is False
        assert "No system prompt" in msg


# ── _h_072o_templates_renderable ─────────────────────────────────────


class TestTemplatesRenderable:
    def test_all_templates_exist(self):
        world = World()
        ok, _msg = _h_072o_templates_renderable(world, "", {})
        assert ok is True


# ── _h_072o_no_rendered_pattern ──────────────────────────────────────


class TestNoRenderedPattern:
    def test_passes_when_pattern_absent(self):
        world = World()
        world.sp3_all_rendered = ["hello world", "foo bar"]
        ok, _msg = _h_072o_no_rendered_pattern(
            world, 'no rendered prompt contains the pattern "STPA-Sec"', {}
        )
        assert ok is True

    def test_fails_when_pattern_present(self):
        world = World()
        world.sp3_all_rendered = ["hello STPA-Sec world", "foo bar"]
        ok, msg = _h_072o_no_rendered_pattern(
            world, 'no rendered prompt contains the pattern "STPA-Sec"', {}
        )
        assert ok is False
        assert "contains pattern" in msg

    def test_fails_when_no_rendered_prompts(self):
        world = World()
        ok, msg = _h_072o_no_rendered_pattern(
            world, 'no rendered prompt contains the pattern "STPA-Sec"', {}
        )
        assert ok is False
        assert "No rendered prompts" in msg


# ── _h_072o_check_copied_loss ────────────────────────────────────────


class TestCheckCopiedLoss:
    def test_with_set_prompt(self):
        """Mutant: is None -> is not None would fail when prompt is set."""
        world = World()
        world.sp3_copied_prompt = "some text without L-* restriction"
        ok, _msg = _h_072o_check_copied_loss(world, "", {})
        assert ok is True
        assert world.sp3_check_result is False

    def test_fails_when_no_prompt(self):
        world = World()
        ok, msg = _h_072o_check_copied_loss(world, "", {})
        assert ok is False
        assert "No copied prompt" in msg


# ── _h_072o_check_fails_l ────────────────────────────────────────────


class TestCheckFailsL:
    def test_passes_when_result_is_false(self):
        world = World()
        world.sp3_check_result = False
        ok, _msg = _h_072o_check_fails_l(world, "", {})
        assert ok is True

    def test_fails_when_result_is_true(self):
        world = World()
        world.sp3_check_result = True
        ok, msg = _h_072o_check_fails_l(world, "", {})
        assert ok is False
        assert "should have failed" in msg

    def test_fails_when_no_result(self):
        world = World()
        ok, msg = _h_072o_check_fails_l(world, "", {})
        assert ok is False
        assert "No check result" in msg


# ── _h_072o_check_copied_terminology ─────────────────────────────────


class TestCheckCopiedTerminology:
    def test_with_stpa_sec_present(self):
        world = World()
        world.sp3_copied_prompt = "security analyst specializing in STPA-Sec"
        ok, _msg = _h_072o_check_copied_terminology(world, "", {})
        assert ok is True
        assert world.sp3_check_result is True

    def test_without_stpa_sec(self):
        world = World()
        world.sp3_copied_prompt = "security analyst"
        ok, _msg = _h_072o_check_copied_terminology(world, "", {})
        assert ok is True
        assert world.sp3_check_result is False

    def test_fails_when_no_prompt(self):
        world = World()
        ok, msg = _h_072o_check_copied_terminology(world, "", {})
        assert ok is False
        assert "No copied prompt" in msg


# ── _h_072o_check_fails_stpa_sec ─────────────────────────────────────


class TestCheckFailsStpaSec:
    def test_passes_when_stpa_sec_detected(self):
        world = World()
        world.sp3_check_result = True
        ok, _msg = _h_072o_check_fails_stpa_sec(world, "", {})
        assert ok is True

    def test_fails_when_stpa_sec_not_detected(self):
        world = World()
        world.sp3_check_result = False
        ok, msg = _h_072o_check_fails_stpa_sec(world, "", {})
        assert ok is False
        assert "should have detected" in msg

    def test_fails_when_no_result(self):
        world = World()
        ok, msg = _h_072o_check_fails_stpa_sec(world, "", {})
        assert ok is False
        assert "No check result" in msg


# ── _h_072o_gherkin_no_h_star ────────────────────────────────────────


class TestGherkinNoHStar:
    def test_fails_when_no_prompt(self):
        world = World()
        ok, msg = _h_072o_gherkin_no_h_star(world, "", {})
        assert ok is False
        assert "No user prompt" in msg

    def test_fails_when_h_star_absent(self):
        world = World()
        world.sp3_user_prompt = "some prompt without h star restriction"
        ok, msg = _h_072o_gherkin_no_h_star(world, "", {})
        assert ok is False
        assert "H-* prohibition" in msg


# ── _h_072o_gherkin_no_hazard_heading ────────────────────────────────


class TestGherkinNoHazardHeading:
    def test_fails_when_no_prompt(self):
        world = World()
        ok, msg = _h_072o_gherkin_no_hazard_heading(world, "", {})
        assert ok is False
        assert "No user prompt" in msg

    def test_fails_when_heading_present(self):
        world = World()
        world.sp3_user_prompt = "some text with Valid Hazard IDs heading"
        ok, msg = _h_072o_gherkin_no_hazard_heading(
            world,
            'the Stage 6c user prompt does not contain the heading "Valid Hazard IDs"',
            {},
        )
        assert ok is False
        assert "should not contain" in msg


# ── _h_072o_gherkin_no_hazard_ids ────────────────────────────────────


class TestGherkinNoHazardIds:
    def test_fails_when_no_prompt(self):
        world = World()
        ok, msg = _h_072o_gherkin_no_hazard_ids(world, "", {})
        assert ok is False
        assert "No user prompt" in msg


# ── _h_072o_loss_ids_before_task ─────────────────────────────────────


class TestLossIdsBeforeTask:
    def test_fails_when_no_prompt(self):
        world = World()
        ok, msg = _h_072o_loss_ids_before_task(world, "", {})
        assert ok is False
        assert "No user prompt" in msg

    def test_fails_when_no_task_heading(self):
        world = World()
        world.sp3_user_prompt = "some prompt without task heading"
        ok, msg = _h_072o_loss_ids_before_task(world, "", {})
        assert ok is False
        assert "Your Task" in msg


# ── _h_072o_gherkin_contains_loss_ids ────────────────────────────────


class TestGherkinContainsLossIds:
    def test_fails_when_no_prompt(self):
        world = World()
        ok, msg = _h_072o_gherkin_contains_loss_ids(world, "", {})
        assert ok is False
        assert "No user prompt" in msg


# ── _h_072o_gherkin_l_star ───────────────────────────────────────────


class TestGherkinLStar:
    def test_fails_when_no_prompt(self):
        world = World()
        ok, msg = _h_072o_gherkin_l_star(world, "", {})
        assert ok is False
        assert "No user prompt" in msg

    def test_fails_when_restriction_absent(self):
        world = World()
        world.sp3_user_prompt = "some prompt without loss id restriction"
        ok, msg = _h_072o_gherkin_l_star(world, "", {})
        assert ok is False
        assert "L-* only" in msg
