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
    _h_072o_minimal_fixture,
    _h_072o_no_rendered_pattern,
    _h_072o_render_all_prompts,
    _h_072o_templates_renderable,
)
from runtime_shared import World  # noqa: E402


# ── _h_072o_minimal_fixture ──────────────────────────────────────────


class TestMinimalFixture:
    def test_sets_fixture_when_unset(self):
        world = World()
        ok, msg = _h_072o_minimal_fixture(world, "", {})
        assert ok is True
        assert world.control_structure is not None
        assert world.loss_analysis is not None

    def test_preserves_existing_control_structure(self):
        """Mutant: is None -> is not None would overwrite existing structure."""
        world = World()
        sentinel = object()
        world.control_structure = sentinel
        ok, _msg = _h_072o_minimal_fixture(world, "", {})
        assert ok is True
        assert world.control_structure is sentinel

    def test_preserves_existing_loss_analysis(self):
        """Mutant: is None -> is not None would overwrite existing analysis."""
        world = World()
        sentinel = object()
        world.loss_analysis = sentinel
        ok, _msg = _h_072o_minimal_fixture(world, "", {})
        assert ok is True
        assert world.loss_analysis is sentinel


# ── _h_072o_render_all_prompts ───────────────────────────────────────


class TestRenderAllPrompts:
    def test_renders_contextual_system_and_user_prompts(self):
        world = World()
        _h_072o_minimal_fixture(world, "", {})
        ok, _msg = _h_072o_render_all_prompts(world, "", {})
        assert ok is True
        assert len(world.sp3_all_rendered) == 2
        assert all(prompt.strip() for prompt in world.sp3_all_rendered)


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
