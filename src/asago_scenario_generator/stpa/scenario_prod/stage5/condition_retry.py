"""The second correction of a Stage 5 condition that still fails.

A ``command_attempt`` scenario without a condition cannot run, so code
publishes it as ``analytical_only``. One more correction, sent only for the
chains below, gives the model a last chance to write a condition that passes.
It adds no wording of its own: it is the request a second validation retry of
the Stage 5 call would send.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from pydantic import BaseModel

from asago_scenario_generator.stpa.infra.llm import LLMClient, LLMResult
from asago_scenario_generator.stpa.infra.llm_helpers import (
    CallOutcome,
    CorrectionPolicy,
    call_with_policy,
    correction_prompt,
)

from .issues import CONDITION_FAILURE_CODES, IssueCode, ValidationIssue

# Attempts one and two are the call and its one correction.
SECOND_CORRECTION_ATTEMPT = 3


def earns_second_correction(
    failure: BaseException | None,
    attempt_number: int,
    issues: tuple[ValidationIssue, ...],
    route: str | None,
) -> bool:
    """Return whether a chain that failed its one correction earns another.

    The chain must have ended on a validation failure of the condition, after
    exactly one correction. A reply that returned no condition took the exit
    the first correction offers, and a third request does not rescue it. The
    route is the one code gives the draft without its condition: only a
    chain routed to ``analytical_only`` has a scenario to gain.
    """
    raised = {issue.code for issue in issues}
    return (
        failure is not None
        and attempt_number == SECOND_CORRECTION_ATTEMPT - 1
        and route == "analytical_only"
        and IssueCode.discriminating_condition_missing not in raised
        and any(code in raised for code in CONDITION_FAILURE_CODES)
    )


def request_second_correction(
    *,
    llm_client: LLMClient,
    system_prompt: str,
    user_prompt: str,
    run_dir: Path,
    response_format: type[BaseModel],
    stage: str,
    step: str,
    slot_id: str | None,
    scenario_id: str | None,
    temperature: float,
    feedback: Callable[[Exception], str],
    failure: Exception,
    prior_result: LLMResult | None,
    result_validator: Callable[[BaseModel], BaseModel | None],
    response_parser: Callable[..., BaseModel],
) -> CallOutcome:
    """Send the last correction: the original prompt, the second reply, its failure.

    The request ends the chain: no length retry and no further correction.
    """
    return call_with_policy(
        llm_client=llm_client,
        system_prompt=system_prompt,
        user_prompt=correction_prompt(
            original_prompt=user_prompt,
            feedback=feedback(failure),
            error=failure,
            response_format=response_format,
            include_schema=False,
            prior_result=prior_result,
            include_prior_response=True,
        ),
        response_format=response_format,
        run_dir=run_dir,
        stage=stage,
        step=step,
        policy=CorrectionPolicy(),
        slot_id=slot_id,
        scenario_id=scenario_id,
        temperature=temperature,
        result_validator=result_validator,
        response_parser=response_parser,
        first_attempt_number=SECOND_CORRECTION_ATTEMPT,
    )
