"""A fake LLM client that serves scripted responses and records each request."""

from __future__ import annotations

from typing import Any

from asago_scenario_generator.stpa.infra.llm import LLMResult


class ScriptedClient:
    """Serve ``responses`` in order and record every request it receives.

    Each response is one of:

    - an exception instance, which ``complete`` raises;
    - an ``LLMResult``, which ``complete`` returns unchanged;
    - any other value, which becomes the content of a one-token ``LLMResult``.

    ``calls`` holds the keyword arguments of every request; ``prompts`` holds
    their user prompts. A request after the last response raises
    ``AssertionError`` so a test never passes by sending more requests than it
    scripted.
    """

    def __init__(
        self,
        responses: list[Any],
        *,
        model: str = "scripted-model",
        context_window: int | None = None,
        max_completion_tokens: int = 8192,
    ) -> None:
        self.model = model
        self.context_window = context_window
        self.max_completion_tokens = max_completion_tokens
        self.calls: list[dict[str, Any]] = []
        self._responses = list(responses)

    @property
    def prompts(self) -> list[str]:
        return [call["user_prompt"] for call in self.calls]

    def complete(self, **kwargs: Any) -> LLMResult:
        self.calls.append(kwargs)
        if not self._responses:
            raise AssertionError("ScriptedClient has no response left to serve")
        response = self._responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        if isinstance(response, LLMResult):
            return response
        return LLMResult(
            content=response, prompt_tokens=1, completion_tokens=1, duration_ms=1
        )
