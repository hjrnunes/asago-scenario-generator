"""Parallel LLM call infrastructure for the STPA pipeline.

Provides ``parallel_safe_llm_calls()`` which executes multiple independent
``safe_llm_call()`` invocations concurrently in a ``ThreadPoolExecutor``.

Key properties:
- Results are returned in the same order as the input call specifications,
  regardless of completion order.
- Failed calls do not kill other calls (error isolation — ``safe_llm_call``
  already handles this internally).
- Call log entries are written thread-safely via a module-level lock in
  ``call_log.append_call_log``.
- Empty call list returns an empty result list (no ``calls.jsonl`` created).
- ``max_workers`` controls the thread pool size.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from asago_scenario_generator.stpa.infra.llm import LLMClient
from asago_scenario_generator.stpa.infra.llm_helpers import safe_llm_call


@dataclass
class LLMCallSpec:
    """Specification for a single LLM call to be executed in parallel.

    Bundles all arguments needed by ``safe_llm_call``.

    Attributes:
        system_prompt: System prompt text.
        user_prompt: User prompt text.
        response_format: Target Pydantic model class for validation.
        stage: Pipeline stage identifier (e.g. ``"stage_3"``).
        step: Sub-step within the stage (e.g. ``"slot_a"``).
        temperature: LLM temperature (default 0.4).
        validation_retries: Number of Pydantic-validation retries (default 0).
        validation_retry_feedback: Optional text appended only to retry prompts.
    """

    system_prompt: str
    user_prompt: str
    response_format: type[BaseModel]
    stage: str
    step: str
    temperature: float = 0.4
    validation_retries: int = 0
    validation_retry_feedback: str | None = None


@dataclass
class LLMCallResult:
    """Result of a single parallel LLM call.

    Attributes:
        model: The LLM client model name on success, ``None`` on failure.
        result: The validated model instance on success, ``None`` on failure.
        error: Error message on failure, ``None`` on success.
        call_spec: The original ``LLMCallSpec`` that produced this result.
    """

    model: str | None
    result: Any | None
    error: str | None
    call_spec: LLMCallSpec


def _execute_single_call(
    spec: LLMCallSpec,
    llm_client: LLMClient,
    run_dir: Path,
) -> LLMCallResult:
    """Execute a single LLM call spec via safe_llm_call.

    On success, returns an ``LLMCallResult`` with the model name, validated
    model, and no error. On failure, returns ``model=None`` and the error
    message.
    """
    validated, _llm_result, error = safe_llm_call(
        llm_client=llm_client,
        system_prompt=spec.system_prompt,
        user_prompt=spec.user_prompt,
        response_format=spec.response_format,
        run_dir=run_dir,
        stage=spec.stage,
        step=spec.step,
        temperature=spec.temperature,
        validation_retries=spec.validation_retries,
        validation_retry_feedback=spec.validation_retry_feedback,
    )
    if error is not None:
        return LLMCallResult(
            model=None,
            result=validated,
            error=error,
            call_spec=spec,
        )
    return LLMCallResult(
        model=llm_client.model,
        result=validated,
        error=None,
        call_spec=spec,
    )


def parallel_safe_llm_calls(
    calls: list[LLMCallSpec],
    *,
    llm_client: LLMClient,
    run_dir: Path,
    max_workers: int = 4,
) -> list[LLMCallResult]:
    """Execute multiple LLM call specs concurrently in a thread pool.

    Each call spec is executed via ``safe_llm_call()`` in its own thread.
    Results are returned in the same order as the input ``calls`` list,
    regardless of completion order. Failed calls do not affect other calls.

    Args:
        calls: List of call specifications to execute.
        llm_client: LLM client for making completion calls.
        run_dir: Directory for call log output (``calls.jsonl``).
        max_workers: Maximum number of concurrent threads (default 4).

    Returns:
        A list of ``LLMCallResult`` objects, one per input call spec, in
        the same order as the input. An empty input list returns an empty
        result list without creating any files.
    """
    if not calls:
        return []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(_execute_single_call, spec, llm_client, run_dir)
            for spec in calls
        ]
        return [f.result() for f in futures]


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-09T11:12:50Z","module_hash":"eccf5aae2345ea55776c4f75c575838dce499262117ac2fa7ef6893ac6bfce05","functions":[{"id":"func/_execute_single_call","name":"_execute_single_call","line":70,"end_line":103,"hash":"01c9f15052dfed89650386d0a881b03f95c66a7ac85067f3859da3dd212d4866"},{"id":"func/parallel_safe_llm_calls","name":"parallel_safe_llm_calls","line":106,"end_line":138,"hash":"9c79843a4d19aab82e6908e5f53555fd64bc32ed285fb950d3568c57924ebc11"}]}
# mutate4py-manifest-end
