"""Shared prompt-budget stub for tests."""

from __future__ import annotations

from asago_scenario_generator.stpa.infra import llm_helpers as llm_helpers_module
from asago_scenario_generator.stpa.infra.prompt_preflight import PromptBudgetExceeded


def block_every_prompt(monkeypatch) -> None:
    """Make every configured-prompt preflight raise PromptBudgetExceeded."""

    def blocked(*args, **kwargs):
        raise PromptBudgetExceeded(
            input_tokens=2,
            usable_input_tokens=1,
            context_window=1,
            maximum_completion_tokens=1,
            safety_margin=0,
        )

    monkeypatch.setattr(llm_helpers_module, "_preflight_configured_prompt", blocked)
