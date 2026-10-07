"""Acceptance handlers for deterministic LLM-helper failure behavior."""

from __future__ import annotations

import inspect
import json
import os
import re
import tempfile
from pathlib import Path
from unittest import mock

from pydantic import BaseModel

from asago_scenario_generator.stpa.infra.llm import LLMResult, LLMClient, _ENV_TIMEOUT
from asago_scenario_generator.stpa.infra.llm_helpers import (
    log_llm_call_failure,
    CorrectionPolicy,
    call_with_policy,
)
from runtime_shared import World
from registry import StepTable

step = StepTable()

_ERRORS = {
    "unexpected keyword argument 'allow_unvalidated'",
    "response_format is the wrong type",
}


class _FailureDefenseResponse(BaseModel):
    """Minimal structured response used by the failure-defense scenarios."""

    value: str


class _FailureDefenseClient:
    """Client double whose completions can fail predictably."""

    model = "failure-defense-model"

    def __init__(
        self,
        *,
        first_error: str | None = None,
        result: LLMResult | None = None,
        results: list[LLMResult] | None = None,
        exception: Exception | None = None,
    ) -> None:
        self.first_error = first_error
        self.results = list(results or [])
        self.exception = exception
        self.result = (
            result
            if result is not None
            else LLMResult(
                content={"value": "recovered"},
                prompt_tokens=1,
                completion_tokens=1,
                duration_ms=1,
            )
        )
        self.attempt_count = 0
        self.user_prompts: list[str] = []

    def complete(self, **kwargs: object) -> LLMResult:
        """Return a queued result after the optional configured failure."""
        self.attempt_count += 1
        self.user_prompts.append(str(kwargs.get("user_prompt", "")))
        if self.exception is not None:
            raise self.exception
        if self.attempt_count == 1 and self.first_error is not None:
            raise TypeError(self.first_error)
        if self.results:
            return self.results.pop(0)
        return self.result


def _retry_result(content: object) -> LLMResult:
    """Build a queued response with stable usage for retry assertions."""
    return LLMResult(
        content=content,
        prompt_tokens=17,
        completion_tokens=4,
        duration_ms=230,
    )


def _run_dir(world: World) -> Path:
    """Return the scenario's isolated call-log directory."""
    run_dir = getattr(world, "llm_failure_run_dir", None)
    if run_dir is None:
        run_dir = Path(tempfile.mkdtemp(prefix="llm_failure_defenses_"))
        world.llm_failure_run_dir = run_dir
    return run_dir


def _call_log_entry(world: World) -> dict:
    """Read the last call-log entry produced by a scenario."""
    return _call_log_entries(world)[-1]


def _call_log_entries(world: World) -> list[dict]:
    """Read all call-log entries produced by a scenario."""
    path = _run_dir(world) / "calls.jsonl"
    if not path.is_file():
        raise AssertionError(f"Missing call log: {path}")
    entries = [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line
    ]
    if not entries:
        raise AssertionError("Call log is empty")
    return entries


@step("a temporary run directory for LLM call logging$")
def _h_llm_failure_run_dir(world: World, text: str, examples: dict) -> tuple[bool, str]:
    _run_dir(world)
    return True, ""


@step("an LLM call failure is logged without usage telemetry$")
def _h_llm_failure_log_without_usage(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    log_llm_call_failure(
        "failure-defense-model",
        _run_dir(world),
        "stage_test",
        "step_test",
        "expected failure",
    )
    return True, ""


@step("the failure log entry records unavailable for")
def _h_llm_failure_zero_telemetry(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r"for (\w+)$", text)
    if match is None:
        return False, f"Could not parse telemetry field from: {text}"
    field = match.group(1)
    entry = _call_log_entry(world)
    if (
        entry.get(field) is not None
        or entry.get("usage", {}).get("status") != "unavailable"
    ):
        return (
            False,
            f"Expected {field}=None and unavailable usage, got {entry.get(field)!r}",
        )
    return True, ""


@step("an LLM client raises TypeError .* on its first completion attempt$")
def _h_llm_failure_client_type_error(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r'TypeError "([^"]+)" on its first completion attempt$', text)
    if match is None:
        return False, f"Could not parse client error from: {text}"
    error = match.group(1)
    if error not in _ERRORS:
        return False, f"Unsupported client error: {error}"
    world.llm_failure_client_error = error
    return True, ""


@step("a safe structured LLM call is made with tolerant decoding")
def _h_llm_failure_safe_call(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r"tolerant decoding (true|false)$", text)
    if match is None:
        return False, f"Could not parse tolerant decoding from: {text}"
    tolerant = match.group(1) == "true"
    client = _FailureDefenseClient(
        first_error=getattr(world, "llm_failure_client_error", None)
    )
    outcome = call_with_policy(
        llm_client=client,
        system_prompt="system",
        user_prompt="user",
        response_format=_FailureDefenseResponse,
        run_dir=_run_dir(world),
        stage="stage_test",
        step="step_test",
        allow_unvalidated=tolerant,
        policy=CorrectionPolicy(),
    )
    parsed, error = outcome.value, outcome.error
    world.llm_failure_client = client
    world.llm_failure_parsed = parsed
    world.llm_failure_error = error
    world.llm_failure_outcome = "recovered" if error is None else "failed"
    return True, ""


@step("an LLM client returns malformed JSON followed by a valid structured response$")
def _h_llm_failure_malformed_then_valid(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    world.llm_failure_retry_client = _FailureDefenseClient(
        results=[
            _retry_result("not valid JSON"),
            _retry_result({"value": "recovered"}),
        ]
    )
    return True, ""


@step("an LLM client returns two malformed JSON responses$")
def _h_llm_failure_two_malformed(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    world.llm_failure_retry_client = _FailureDefenseClient(
        results=[_retry_result("not valid JSON"), _retry_result("still not JSON")]
    )
    return True, ""


@step("an LLM client returns a semantically invalid structured response$")
def _h_llm_failure_semantic_response(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    world.llm_failure_retry_client = _FailureDefenseClient(
        results=[_retry_result({"value": None})]
    )
    return True, ""


@step('an LLM client raises RuntimeError "authentication failed"$')
def _h_llm_failure_authentication_error(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    world.llm_failure_retry_client = _FailureDefenseClient(
        exception=RuntimeError("authentication failed")
    )
    return True, ""


@step(
    "an LLM client returns a semantically invalid response followed by a valid structured response$"
)
def _h_llm_failure_semantic_then_valid(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    world.llm_failure_retry_client = _FailureDefenseClient(
        results=[
            _retry_result({"value": None}),
            _retry_result({"value": "recovered"}),
        ]
    )
    return True, ""


@step(
    "an LLM client returns a result-validator rejection followed by a valid structured response$"
)
def _h_llm_failure_result_validator_then_valid(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    world.llm_failure_retry_client = _FailureDefenseClient(
        results=[
            _retry_result({"value": "reject"}),
            _retry_result({"value": "recovered"}),
        ]
    )
    return True, ""


@step(
    "a safe structured LLM call is made with one result-validation retry and corrective feedback$"
)
def _h_llm_failure_result_validation_retry_call(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    client = getattr(world, "llm_failure_retry_client", None)
    if client is None:
        return False, "No queued result-validation client configured"

    def reject_first(model: _FailureDefenseResponse) -> None:
        if model.value == "reject":
            raise ValueError("result rejected")

    outcome = call_with_policy(
        llm_client=client,
        system_prompt="system",
        user_prompt="user",
        response_format=_FailureDefenseResponse,
        run_dir=_run_dir(world),
        stage="stage_test",
        step="step_test",
        result_validator=reject_first,
        policy=CorrectionPolicy(
            validation_retries=1, feedback="\n\ncorrective feedback"
        ),
    )
    parsed, error = outcome.value, outcome.error
    world.llm_failure_client = client
    world.llm_failure_parsed = parsed
    world.llm_failure_error = error
    world.llm_failure_outcome = "recovered" if error is None else "failed"
    return True, ""


@step(
    "a safe structured LLM call is made with one validation retry and corrective feedback$"
)
def _h_llm_failure_validation_retry_call(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    client = getattr(world, "llm_failure_retry_client", None)
    if client is None:
        return False, "No queued validation-retry client configured"
    outcome = call_with_policy(
        llm_client=client,
        system_prompt="system",
        user_prompt="user",
        response_format=_FailureDefenseResponse,
        run_dir=_run_dir(world),
        stage="stage_test",
        step="step_test",
        policy=CorrectionPolicy(
            validation_retries=1, feedback="\n\ncorrective feedback"
        ),
    )
    parsed, error = outcome.value, outcome.error
    world.llm_failure_client = client
    world.llm_failure_parsed = parsed
    world.llm_failure_error = error
    world.llm_failure_outcome = "recovered" if error is None else "failed"
    return True, ""


@step("the second completion attempt includes corrective feedback$")
def _h_llm_failure_corrective_feedback(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    prompts = getattr(getattr(world, "llm_failure_client", None), "user_prompts", [])
    if len(prompts) != 2 or "corrective feedback" not in prompts[1]:
        return False, f"Expected corrective feedback on second attempt, got {prompts!r}"
    return True, ""


@step(
    "the live LLM client is built without a timeout argument or timeout "
    "environment override$"
)
def _h_llm_failure_build_default_timeout_client(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    environ = {key: value for key, value in os.environ.items() if key != _ENV_TIMEOUT}
    with mock.patch.dict(os.environ, environ, clear=True):
        world.llm_failure_live_client = LLMClient(
            base_url="http://127.0.0.1:9/v1",
            api_key="offline",
            model="failure-defense-model",
        )
    return True, ""


@step("the live LLM client request timeout is 300 seconds$")
def _h_llm_failure_default_timeout(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    client = getattr(world, "llm_failure_live_client", None)
    if client is None:
        return False, "No live LLM client"
    if client.timeout != 300:
        return False, f"Expected timeout 300, got {client.timeout!r}"
    if client._client.timeout != 300:
        return False, f"OpenAI client timeout is {client._client.timeout!r}, not 300"
    return True, ""


@step("a safe structured LLM call is made with one JSON-decode retry$")
def _h_llm_failure_json_retry_safe_call(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    client = getattr(world, "llm_failure_retry_client", None)
    if client is None:
        return False, "No queued retry client configured"
    outcome = call_with_policy(
        llm_client=client,
        system_prompt="system",
        user_prompt="user",
        response_format=_FailureDefenseResponse,
        run_dir=_run_dir(world),
        stage="stage_test",
        step="step_test",
        policy=CorrectionPolicy(json_retries=1),
    )
    parsed, error = outcome.value, outcome.error
    world.llm_failure_client = client
    world.llm_failure_parsed = parsed
    world.llm_failure_error = error
    world.llm_failure_outcome = "recovered" if error is None else "failed"
    return True, ""


@step("the completion attempt count is")
def _h_llm_failure_attempt_count(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r"count is (-?\d+)$", text)
    if match is None:
        return False, f"Could not parse attempt count from: {text}"
    expected = int(match.group(1))
    actual = getattr(getattr(world, "llm_failure_client", None), "attempt_count", 0)
    if actual != expected:
        return False, f"Expected {expected} completion attempts, got {actual}"
    return True, ""


@step("the safe call outcome is")
def _h_llm_failure_outcome(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(r"outcome is (\w+)$", text)
    if match is None:
        return False, f"Could not parse outcome from: {text}"
    expected = match.group(1)
    actual = getattr(world, "llm_failure_outcome", None)
    if actual != expected:
        return False, f"Expected outcome {expected}, got {actual}"
    return True, ""


@step("the safe structured LLM call signature is inspected$")
@step("the tolerant-decoding argument defaults to false$")
def _h_llm_failure_signature(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    parameter = inspect.signature(call_with_policy).parameters.get("allow_unvalidated")
    if parameter is None:
        return False, "call_with_policy has no allow_unvalidated parameter"
    if parameter.default is not False:
        return False, f"Expected default False, got {parameter.default!r}"
    return True, ""


@step(
    "an LLM result reports .* prompt tokens, .* completion tokens, and .* milliseconds$"
)
def _h_llm_failure_result_usage(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r"reports (-?\d+) prompt tokens, (-?\d+) completion tokens, "
        r"and (-?\d+) milliseconds$",
        text,
    )
    if match is None:
        return False, f"Could not parse result usage from: {text}"
    world.llm_failure_result = LLMResult(
        content="not valid JSON",
        prompt_tokens=int(match.group(1)),
        completion_tokens=int(match.group(2)),
        duration_ms=int(match.group(3)),
    )
    return True, ""


@step("its content cannot be parsed as the response model$")
def _h_llm_failure_unparseable_content(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    if not hasattr(world, "llm_failure_result"):
        return False, "No LLM result configured"
    return True, ""


@step("the result is processed by a safe structured LLM call$")
def _h_llm_failure_process_result(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    client = _FailureDefenseClient(result=world.llm_failure_result)
    outcome = call_with_policy(
        llm_client=client,
        system_prompt="system",
        user_prompt="user",
        response_format=_FailureDefenseResponse,
        run_dir=_run_dir(world),
        stage="stage_test",
        step="step_test",
        policy=CorrectionPolicy(),
    )
    parsed, error = outcome.value, outcome.error
    world.llm_failure_client = client
    world.llm_failure_parsed = parsed
    world.llm_failure_error = error
    if error is None:
        return False, "Expected response parsing to fail"
    return True, ""


@step(
    "the failure log entry records prompt_tokens .* completion_tokens .* and duration_ms"
)
def _h_llm_failure_usage_retained(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r"records prompt_tokens (-?\d+), completion_tokens (-?\d+), "
        r"and duration_ms (-?\d+)$",
        text,
    )
    if match is None:
        return False, f"Could not parse expected usage from: {text}"
    entry = _call_log_entry(world)
    expected = {
        "prompt_tokens": int(match.group(1)),
        "completion_tokens": int(match.group(2)),
        "duration_ms": int(match.group(3)),
    }
    actual = {field: entry.get(field) for field in expected}
    if actual != expected:
        return False, f"Expected usage {expected}, got {actual}"
    return True, ""


@step("the call log contains one failed and one successful attempt$")
def _h_llm_failure_retry_log_one_failed_one_success(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    entries = _call_log_entries(world)
    statuses = [entry.get("success") for entry in entries]
    if len(entries) != 2 or statuses != [False, True]:
        return False, f"Expected failed/successful retry entries, got {statuses}"
    return True, ""


@step("the call log contains two failed attempts$")
def _h_llm_failure_retry_log_two_failed(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    entries = _call_log_entries(world)
    statuses = [entry.get("success") for entry in entries]
    if len(entries) != 2 or statuses != [False, False]:
        return False, f"Expected two failed retry entries, got {statuses}"
    return True, ""


@step(
    "every retry attempt records prompt_tokens .* completion_tokens .* and duration_ms"
)
def _h_llm_failure_retry_usage(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(
        r"records prompt_tokens (-?\d+), completion_tokens (-?\d+), "
        r"and duration_ms (-?\d+)$",
        text,
    )
    if match is None:
        return False, f"Could not parse expected retry usage from: {text}"
    expected = {
        "prompt_tokens": int(match.group(1)),
        "completion_tokens": int(match.group(2)),
        "duration_ms": int(match.group(3)),
    }
    entries = _call_log_entries(world)
    for index, entry in enumerate(entries, start=1):
        actual = {field: entry.get(field) for field in expected}
        if actual != expected:
            return False, f"Retry entry {index} usage {actual} != {expected}"
    return True, ""


FEATURE_ID = "llm_helper_failure_defenses"


register = step.register


__all__ = ["FEATURE_ID", "register"]
