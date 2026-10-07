"""Focused tests for the contextual Stage 5 prompt definitions."""

from __future__ import annotations

from pathlib import Path

from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.scenario_prod.stage5.prompt_view import (
    build_context_bdi_prompts,
)

from .test_sp3_scenario_continuity import _context


PROMPTS_DIR = (
    Path(__file__).parents[2]
    / "src/asago_scenario_generator/stpa/scenario_prod/prompts"
)


def test_contextual_stage5_defines_loss_scenario_and_bdi() -> None:
    prompt, _ = build_context_bdi_prompts(_context(), TemplateLoader(PROMPTS_DIR))

    assert "STPA (System-Theoretic Process Analysis)" in prompt
    assert "A **loss scenario** is the causal explanation" in prompt
    assert "BDI means Belief–Desire–Intention" in prompt
