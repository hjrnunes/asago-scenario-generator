"""Dispatch real model requests from a test adapter.

A test adapter that calls :func:`dispatch_requests` sends its requests through
``call_with_policy``, as the provider adapter does, so a request tally sees
them.  An adapter that sends nothing is a fake adapter.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel

from asago_scenario_generator.stpa.infra.llm_helpers import (
    CorrectionPolicy,
    call_with_policy,
)
from tests.helpers.scripted_client import ScriptedClient


class _Reply(BaseModel):
    ok: bool = True


def dispatch_requests(run_dir: Path, count: int) -> None:
    """Send *count* independent requests, each logged under its own step."""
    client = ScriptedClient([{"ok": True}] * count, model="dispatch-test")
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
