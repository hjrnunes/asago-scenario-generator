"""Stand-in for ``call_with_policy`` that logs as the shared call does."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from asago_scenario_generator.stpa.infra.llm_helpers import (
    CallOutcome,
    log_llm_call,
    log_llm_call_failure,
)


def logged(
    fake: Callable[..., CallOutcome], *, model: str = "fixture-model"
) -> Callable[..., CallOutcome]:
    """Wrap a fake so each outcome lands in ``run_dir/calls.jsonl``.

    The real ``call_with_policy`` writes one shared call-log entry per attempt;
    a fake that skips it leaves the interpreter nothing to collect.
    """

    def run(**kwargs: Any) -> CallOutcome:
        outcome = fake(**kwargs)
        common = (model, kwargs["run_dir"], kwargs["stage"], kwargs["step"])
        if outcome.error is None:
            log_llm_call(
                outcome.result,
                *common,
                prompt_template_hashes=kwargs["prompt_template_hashes"],
                cleaned_response=outcome.value,
            )
        else:
            log_llm_call_failure(
                *common,
                outcome.error,
                system_prompt=kwargs["system_prompt"],
                user_prompt=kwargs["user_prompt"],
                prompt_template_hashes=kwargs["prompt_template_hashes"],
            )
        return outcome

    return run
