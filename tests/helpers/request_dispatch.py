"""Dispatch real model requests from a test adapter.

A test adapter that calls :func:`dispatch_requests` sends its requests through
``call_with_policy``, as the provider adapter does, so a request tally sees
them.  An adapter that sends nothing is a fake adapter.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel

from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.infra.llm_helpers import (
    CorrectionPolicy,
    call_with_policy,
)


class _Reply(BaseModel):
    ok: bool = True


class _Client:
    model = "dispatch-test"

    def complete(self, **kwargs):
        return LLMResult(
            content={"ok": True},
            prompt_tokens=1,
            completion_tokens=1,
            duration_ms=1,
            system_prompt=kwargs["system_prompt"],
            user_prompt=kwargs["user_prompt"],
        )


def dispatch_requests(run_dir: Path, count: int) -> None:
    """Send *count* independent requests, each logged under its own step."""
    client = _Client()
    for index in range(count):
        outcome = call_with_policy(
            llm_client=client,
            system_prompt="system",
            user_prompt=f"request {index}",
            response_format=_Reply,
            run_dir=run_dir,
            stage="dispatch_test",
            step=f"step_{index}",
            policy=CorrectionPolicy(),
        )
        assert outcome.calls == 1
