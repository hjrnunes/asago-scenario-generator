"""Acceptance handlers for deterministic LLM-helper failure behavior."""

from __future__ import annotations

import inspect
import json
import re
import tempfile
from pathlib import Path

from pydantic import BaseModel

from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.infra.llm_helpers import (
    log_llm_call_failure,
    safe_llm_call,
)
from runtime_shared import World

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


def _h_llm_failure_run_dir(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a temporary directory is available for LLM call logging."""
    _run_dir(world)
    return True, ""


def _h_llm_failure_log_without_usage(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: log a failure without explicitly supplied usage telemetry."""
    log_llm_call_failure(
        "failure-defense-model",
        _run_dir(world),
        "stage_test",
        "step_test",
        "expected failure",
    )
    return True, ""


def _h_llm_failure_zero_telemetry(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: a missing failure-telemetry field defaults to zero."""
    match = re.search(r"for (\w+)$", text)
    if match is None:
        return False, f"Could not parse telemetry field from: {text}"
    field = match.group(1)
    entry = _call_log_entry(world)
    if entry.get(field) != 0:
        return False, f"Expected {field}=0, got {entry.get(field)!r}"
    return True, ""


def _h_llm_failure_client_type_error(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: configure the first completion attempt's TypeError."""
    match = re.search(r'TypeError "([^"]+)" on its first completion attempt$', text)
    if match is None:
        return False, f"Could not parse client error from: {text}"
    error = match.group(1)
    if error not in _ERRORS:
        return False, f"Unsupported client error: {error}"
    world.llm_failure_client_error = error
    return True, ""


def _h_llm_failure_safe_call(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: make a safe structured call with requested tolerance."""
    match = re.search(r"tolerant decoding (true|false)$", text)
    if match is None:
        return False, f"Could not parse tolerant decoding from: {text}"
    tolerant = match.group(1) == "true"
    client = _FailureDefenseClient(
        first_error=getattr(world, "llm_failure_client_error", None)
    )
    parsed, _result, error = safe_llm_call(
        llm_client=client,
        system_prompt="system",
        user_prompt="user",
        response_format=_FailureDefenseResponse,
        run_dir=_run_dir(world),
        stage="stage_test",
        step="step_test",
        allow_unvalidated=tolerant,
    )
    world.llm_failure_client = client
    world.llm_failure_parsed = parsed
    world.llm_failure_error = error
    world.llm_failure_outcome = "recovered" if error is None else "failed"
    return True, ""


def _h_llm_failure_malformed_then_valid(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: queue malformed JSON followed by a valid response."""
    world.llm_failure_retry_client = _FailureDefenseClient(
        results=[
            _retry_result("not valid JSON"),
            _retry_result({"value": "recovered"}),
        ]
    )
    return True, ""


def _h_llm_failure_two_malformed(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: queue two malformed JSON responses."""
    world.llm_failure_retry_client = _FailureDefenseClient(
        results=[_retry_result("not valid JSON"), _retry_result("still not JSON")]
    )
    return True, ""


def _h_llm_failure_semantic_response(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: queue a JSON response that fails Pydantic validation."""
    world.llm_failure_retry_client = _FailureDefenseClient(
        results=[_retry_result({"value": None})]
    )
    return True, ""


def _h_llm_failure_authentication_error(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: configure a client/authentication failure."""
    world.llm_failure_retry_client = _FailureDefenseClient(
        exception=RuntimeError("authentication failed")
    )
    return True, ""


def _h_llm_failure_semantic_then_valid(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: queue a schema-invalid result followed by a valid result."""
    world.llm_failure_retry_client = _FailureDefenseClient(
        results=[
            _retry_result({"value": None}),
            _retry_result({"value": "recovered"}),
        ]
    )
    return True, ""


def _h_llm_failure_result_validator_then_valid(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: queue a semantically rejected result followed by a valid one."""
    world.llm_failure_retry_client = _FailureDefenseClient(
        results=[
            _retry_result({"value": "reject"}),
            _retry_result({"value": "recovered"}),
        ]
    )
    return True, ""


def _h_llm_failure_result_validation_retry_call(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: retry one failure raised by an explicit result validator."""
    client = getattr(world, "llm_failure_retry_client", None)
    if client is None:
        return False, "No queued result-validation client configured"

    def reject_first(model: _FailureDefenseResponse) -> None:
        if model.value == "reject":
            raise ValueError("result rejected")

    parsed, _result, error = safe_llm_call(
        llm_client=client,
        system_prompt="system",
        user_prompt="user",
        response_format=_FailureDefenseResponse,
        run_dir=_run_dir(world),
        stage="stage_test",
        step="step_test",
        result_validator=reject_first,
        validation_retries=1,
        validation_retry_feedback="\n\ncorrective feedback",
    )
    world.llm_failure_client = client
    world.llm_failure_parsed = parsed
    world.llm_failure_error = error
    world.llm_failure_outcome = "recovered" if error is None else "failed"
    return True, ""


def _h_llm_failure_validation_retry_call(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: make one explicitly requested schema-validation retry."""
    client = getattr(world, "llm_failure_retry_client", None)
    if client is None:
        return False, "No queued validation-retry client configured"
    parsed, _result, error = safe_llm_call(
        llm_client=client,
        system_prompt="system",
        user_prompt="user",
        response_format=_FailureDefenseResponse,
        run_dir=_run_dir(world),
        stage="stage_test",
        step="step_test",
        validation_retries=1,
        validation_retry_feedback="\n\ncorrective feedback",
    )
    world.llm_failure_client = client
    world.llm_failure_parsed = parsed
    world.llm_failure_error = error
    world.llm_failure_outcome = "recovered" if error is None else "failed"
    return True, ""


def _h_llm_failure_corrective_feedback(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: assert that only the retry prompt contains feedback."""
    prompts = getattr(getattr(world, "llm_failure_client", None), "user_prompts", [])
    if len(prompts) != 2 or "corrective feedback" not in prompts[1]:
        return False, f"Expected corrective feedback on second attempt, got {prompts!r}"
    return True, ""


def _h_llm_failure_resolve_default_timeout(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: resolve model configuration without profile or environment values."""
    from asago_scenario_generator.pipeline.model_configuration import (
        resolve_effective_model_config,
    )

    world.llm_failure_effective_config = resolve_effective_model_config(environ={})
    return True, ""


def _h_llm_failure_default_timeout(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: assert the application-owned default request deadline."""
    from asago_scenario_generator.pipeline.model_configuration import ConfigSource

    config = getattr(world, "llm_failure_effective_config", None)
    if config is None:
        return False, "No effective model configuration"
    if config.timeout != 300.0:
        return False, f"Expected timeout 300.0, got {config.timeout!r}"
    if config.sources.get("timeout") is not ConfigSource.application_default:
        return False, f"Unexpected timeout source: {config.sources.get('timeout')!r}"
    return True, ""


def _h_llm_failure_json_retry_safe_call(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: make a structured call with one JSON-decode retry."""
    client = getattr(world, "llm_failure_retry_client", None)
    if client is None:
        return False, "No queued retry client configured"
    parsed, _result, error = safe_llm_call(
        llm_client=client,
        system_prompt="system",
        user_prompt="user",
        response_format=_FailureDefenseResponse,
        run_dir=_run_dir(world),
        stage="stage_test",
        step="step_test",
        json_decode_retries=1,
    )
    world.llm_failure_client = client
    world.llm_failure_parsed = parsed
    world.llm_failure_error = error
    world.llm_failure_outcome = "recovered" if error is None else "failed"
    return True, ""


def _h_llm_failure_attempt_count(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: assert the number of completion attempts."""
    match = re.search(r"count is (-?\d+)$", text)
    if match is None:
        return False, f"Could not parse attempt count from: {text}"
    expected = int(match.group(1))
    actual = getattr(getattr(world, "llm_failure_client", None), "attempt_count", 0)
    if actual != expected:
        return False, f"Expected {expected} completion attempts, got {actual}"
    return True, ""


def _h_llm_failure_outcome(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: assert whether compatibility recovery succeeded."""
    match = re.search(r"outcome is (\w+)$", text)
    if match is None:
        return False, f"Could not parse outcome from: {text}"
    expected = match.group(1)
    actual = getattr(world, "llm_failure_outcome", None)
    if actual != expected:
        return False, f"Expected outcome {expected}, got {actual}"
    return True, ""


def _h_llm_failure_signature(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: inspect safe_llm_call's tolerant-decoding default."""
    parameter = inspect.signature(safe_llm_call).parameters.get("allow_unvalidated")
    if parameter is None:
        return False, "safe_llm_call has no allow_unvalidated parameter"
    if parameter.default is not False:
        return False, f"Expected default False, got {parameter.default!r}"
    return True, ""


def _h_llm_failure_result_usage(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: configure a result carrying usage telemetry."""
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


def _h_llm_failure_unparseable_content(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: mark the configured result as intentionally unparseable."""
    if not hasattr(world, "llm_failure_result"):
        return False, "No LLM result configured"
    return True, ""


def _h_llm_failure_process_result(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: process the result through safe_llm_call."""
    client = _FailureDefenseClient(result=world.llm_failure_result)
    parsed, _result, error = safe_llm_call(
        llm_client=client,
        system_prompt="system",
        user_prompt="user",
        response_format=_FailureDefenseResponse,
        run_dir=_run_dir(world),
        stage="stage_test",
        step="step_test",
    )
    world.llm_failure_client = client
    world.llm_failure_parsed = parsed
    world.llm_failure_error = error
    if error is None:
        return False, "Expected response parsing to fail"
    return True, ""


def _h_llm_failure_usage_retained(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: usage telemetry survives response parsing failure."""
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


def _h_llm_failure_retry_log_one_failed_one_success(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: assert both the failed and recovered retry are logged."""
    entries = _call_log_entries(world)
    statuses = [entry.get("success") for entry in entries]
    if len(entries) != 2 or statuses != [False, True]:
        return False, f"Expected failed/successful retry entries, got {statuses}"
    return True, ""


def _h_llm_failure_retry_log_two_failed(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: assert both malformed JSON attempts are logged as failures."""
    entries = _call_log_entries(world)
    statuses = [entry.get("success") for entry in entries]
    if len(entries) != 2 or statuses != [False, False]:
        return False, f"Expected two failed retry entries, got {statuses}"
    return True, ""


def _h_llm_failure_retry_usage(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: assert usage is retained on every retry attempt."""
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


def register(api: object) -> None:
    """Register failure-defense acceptance handlers."""
    api.set_feature(None)
    api.register(
        "a temporary run directory for LLM call logging$",
        _h_llm_failure_run_dir,
        source_order=24001,
    )
    api.register(
        "an LLM call failure is logged without usage telemetry$",
        _h_llm_failure_log_without_usage,
        source_order=24002,
    )
    api.register(
        "the failure log entry records zero for",
        _h_llm_failure_zero_telemetry,
        source_order=24003,
    )
    api.register(
        "an LLM client raises TypeError .* on its first completion attempt$",
        _h_llm_failure_client_type_error,
        source_order=24004,
    )
    api.register(
        "a safe structured LLM call is made with tolerant decoding",
        _h_llm_failure_safe_call,
        source_order=24005,
    )
    api.register(
        "the completion attempt count is",
        _h_llm_failure_attempt_count,
        source_order=24006,
    )
    api.register(
        "the safe call outcome is",
        _h_llm_failure_outcome,
        source_order=24007,
    )
    api.register(
        "the safe structured LLM call signature is inspected$",
        _h_llm_failure_signature,
        source_order=24008,
    )
    api.register(
        "the tolerant-decoding argument defaults to false$",
        _h_llm_failure_signature,
        source_order=24009,
    )
    api.register(
        "an LLM result reports .* prompt tokens, .* completion tokens, and .* milliseconds$",
        _h_llm_failure_result_usage,
        source_order=24010,
    )
    api.register(
        "its content cannot be parsed as the response model$",
        _h_llm_failure_unparseable_content,
        source_order=24011,
    )
    api.register(
        "the result is processed by a safe structured LLM call$",
        _h_llm_failure_process_result,
        source_order=24012,
    )
    api.register(
        "the failure log entry records prompt_tokens .* completion_tokens .* and duration_ms",
        _h_llm_failure_usage_retained,
        source_order=24013,
    )
    api.register(
        "an LLM client returns malformed JSON followed by a valid structured response$",
        _h_llm_failure_malformed_then_valid,
        source_order=24014,
    )
    api.register(
        "an LLM client returns two malformed JSON responses$",
        _h_llm_failure_two_malformed,
        source_order=24015,
    )
    api.register(
        "an LLM client returns a semantically invalid structured response$",
        _h_llm_failure_semantic_response,
        source_order=24016,
    )
    api.register(
        'an LLM client raises RuntimeError "authentication failed"$',
        _h_llm_failure_authentication_error,
        source_order=24017,
    )
    api.register(
        "a safe structured LLM call is made with one JSON-decode retry$",
        _h_llm_failure_json_retry_safe_call,
        source_order=24018,
    )
    api.register(
        "the call log contains one failed and one successful attempt$",
        _h_llm_failure_retry_log_one_failed_one_success,
        source_order=24019,
    )
    api.register(
        "every retry attempt records prompt_tokens .* completion_tokens .* and duration_ms",
        _h_llm_failure_retry_usage,
        source_order=24020,
    )
    api.register(
        "the call log contains two failed attempts$",
        _h_llm_failure_retry_log_two_failed,
        source_order=24021,
    )
    api.register(
        "an LLM client returns a semantically invalid response followed by a valid structured response$",
        _h_llm_failure_semantic_then_valid,
        source_order=24022,
    )
    api.register(
        "a safe structured LLM call is made with one validation retry and corrective feedback$",
        _h_llm_failure_validation_retry_call,
        source_order=24023,
    )
    api.register(
        "the second completion attempt includes corrective feedback$",
        _h_llm_failure_corrective_feedback,
        source_order=24024,
    )
    api.register(
        "effective model configuration is resolved without a timeout override$",
        _h_llm_failure_resolve_default_timeout,
        source_order=24025,
    )
    api.register(
        "the effective request timeout is 300 seconds from the application default$",
        _h_llm_failure_default_timeout,
        source_order=24026,
    )
    api.register(
        "an LLM client returns a result-validator rejection followed by a valid structured response$",
        _h_llm_failure_result_validator_then_valid,
        source_order=24027,
    )
    api.register(
        "a safe structured LLM call is made with one result-validation retry and corrective feedback$",
        _h_llm_failure_result_validation_retry_call,
        source_order=24028,
    )
    api.set_feature(None)


__all__ = ["FEATURE_ID", "register"]
