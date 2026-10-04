"""Shared fixtures for deterministic tests."""

from __future__ import annotations

import pytest


@pytest.fixture
def offline_llm(monkeypatch: pytest.MonkeyPatch) -> None:
    """Configure LLM construction while rejecting any completion attempt."""
    from asago_scenario_generator.stpa.infra.llm import LLMClient

    monkeypatch.setenv("ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL", "http://127.0.0.1:9")

    def _unexpected_completion(*args, **kwargs):
        pytest.fail("Unexpected live LLM call from deterministic test")

    monkeypatch.setattr(LLMClient, "complete", _unexpected_completion)
