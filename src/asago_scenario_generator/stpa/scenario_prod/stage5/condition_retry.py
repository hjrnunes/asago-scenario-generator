"""The second correction of a Stage 5 condition that still fails.

A ``command_attempt`` scenario without a condition cannot run, so code
publishes it as ``analytical_only``, or, when its failure call names an
operation the target records, as a command attempt without a condition of
the model's own (with the unscoped ``not_called`` code derives for a missing
call, and with none for an incorrect call). One
more correction, sent only for the chains below, gives the model a last chance
to write a condition that passes.
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
# The routes whose published draft has no condition of the model's own.
_UNRUNNABLE_ROUTES = frozenset({"analytical_only", "failure_call"})


def earns_second_correction(
    failure: BaseException | None,
    attempt_number: int,
    issues: tuple[ValidationIssue, ...],
    route: str | None,
) -> bool:
    """Return whether a chain that failed its one correction earns another.

    The chain must have ended on a validation failure of the condition, after
    exactly one correction. A reply that still returned no condition after
    the first correction asked for one is not rescued by a third request. The
    route is the one code gives the draft without its condition: only a
    chain routed to ``analytical_only`` or ``failure_call`` publishes a claim
    with no condition of the model's own (at most the unscoped ``not_called``
    code derives for a missing call), so only it has a condition to gain.
    """
    raised = {issue.code for issue in issues}
    return (
        failure is not None
        and attempt_number == SECOND_CORRECTION_ATTEMPT - 1
        and route in _UNRUNNABLE_ROUTES
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
    max_completion_tokens: int | None,
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
        max_completion_tokens=max_completion_tokens,
        result_validator=result_validator,
        response_parser=response_parser,
        first_attempt_number=SECOND_CORRECTION_ATTEMPT,
    )
