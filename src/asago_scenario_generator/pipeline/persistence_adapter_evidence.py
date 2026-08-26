"""Stage-attempt input and call-log helpers for the persistence adapter."""

from __future__ import annotations

from typing import Any

from pydantic import JsonValue

from asago_scenario_generator.pipeline.finalization_contracts import (
    GeneratedStage,
)
from asago_scenario_generator.pipeline.generation_contracts import (
    StageAttemptFailure,
    StageCallEvidence,
)
from .persistence_common import _json_value
from .persistence_evidence import (
    _attempt_failure,
    _call_evidence,
    _pipeline_log_response,
    _retry_control,
    _semantic_json,
)
from .persistence_models import (
    PromptRecord,
    StageAttemptFailureRecord,
    StageCallEvidenceRecord,
    StageInputRecord,
)
from .persistence_adapter_state import _violations


def _stage_evidence_parts(
    evidence: object,
) -> tuple[
    StageCallEvidenceRecord | None,
    StageAttemptFailureRecord | None,
    PromptRecord | None,
]:
    if isinstance(evidence, StageCallEvidence):
        call = _call_evidence(evidence)
        prompt = PromptRecord(
            system_prompt=call.result.system_prompt,
            user_prompt=call.result.user_prompt,
        )
        return call, None, prompt
    if isinstance(evidence, StageAttemptFailure):
        failure = _attempt_failure(evidence)
        return None, failure, failure.prompt
    raise TypeError(
        "stage persistence requires StageCallEvidence or StageAttemptFailure"
    )


def _stage_input_record(
    invocation: object,
    candidate: JsonValue,
    prompt: PromptRecord | None,
    visible_artifacts: dict[str, Any],
) -> StageInputRecord:
    return StageInputRecord(
        candidate=candidate,
        candidate_id=invocation.candidate_id,
        stage=invocation.stage,
        invocation_index=invocation.invocation_index,
        owner_retry_index=invocation.owner_retry_index,
        visible_artifacts=visible_artifacts,
        prompt=prompt,
        final_tree_digest=invocation.final_tree_digest,
        retry_reason=invocation.retry_reason,
        retry_control=_retry_control(invocation.retry_control),
        total_request_budget=invocation.total_request_budget,
    )


def _stage_attempt_payload(
    attempt_id: str,
    input_payload: dict[str, Any],
    call: StageCallEvidenceRecord | None,
    failure: StageAttemptFailureRecord | None,
    output: JsonValue | None,
    violations: list[object],
) -> dict[str, Any]:
    return {
        "attempt_id": attempt_id,
        "input": input_payload,
        "call": call.model_dump(mode="json") if call else None,
        "failure": failure.model_dump(mode="json") if failure else None,
        "result": output,
        "violations": [
            item.model_dump(mode="json") for item in _violations(violations)
        ],
    }


def _call_log_entry(
    invocation: object, attempt_id: str, evidence: object
) -> dict[str, Any]:
    """Build a simple dict entry from the available data for calls.jsonl."""
    return {
        "call": evidence.call_name.value,
        "candidate_id": invocation.candidate_id,
        "stage": invocation.stage.value,
        "attempt_id": attempt_id,
        "retry_reason": invocation.retry_reason,
        "retry_control": _retry_control(invocation.retry_control),
        "total_request_budget": invocation.total_request_budget,
    }


def _llm_log_fields(llm_result: object, request_controls: Any) -> dict[str, Any]:
    return {
        "system_prompt": llm_result.system_prompt,
        "user_prompt": llm_result.user_prompt,
        "response": _pipeline_log_response(llm_result),
        "prompt_tokens": llm_result.prompt_tokens,
        "completion_tokens": llm_result.completion_tokens,
        "duration_ms": llm_result.duration_ms,
        "request_controls": request_controls,
    }


def _failure_evidence_log_entry(evidence: object, entry: dict[str, Any]) -> None:
    if evidence.result is not None:
        llm_result = evidence.result
        entry.update(
            _llm_log_fields(
                llm_result,
                evidence.request_controls or llm_result.request_controls,
            )
        )
    else:
        entry.update(
            {
                "system_prompt": evidence.system_prompt,
                "user_prompt": evidence.user_prompt,
                "response": None,
                "prompt_tokens": evidence.prompt_tokens,
                "completion_tokens": evidence.completion_tokens,
                "duration_ms": evidence.elapsed_ms,
                "request_controls": evidence.request_controls,
            }
        )
    entry["error"] = f"{evidence.exception_type}: {evidence.detail}"
    # Stable typed routing evidence for every failed attempt row.
    entry["code"] = evidence.code
    entry["retryable"] = evidence.retryable
    entry["semantic_evidence"] = _semantic_json(evidence.semantic_evidence)
    if evidence.finish_reason is not None:
        entry["finish_reason"] = evidence.finish_reason
    entry.update(
        {
            "total_tokens": evidence.total_tokens,
            "usage_details": evidence.usage_details,
            "response_id": evidence.response_id,
            "model": evidence.model,
            "partial_character_count": evidence.partial_character_count,
            "partial_sha256": evidence.partial_sha256,
            "partial_preview_prefix": evidence.partial_preview_prefix,
            "partial_preview_suffix": evidence.partial_preview_suffix,
            "elapsed_ms": evidence.elapsed_ms,
        }
    )


def _call_log_entry_for(evidence: object, entry: dict[str, Any]) -> None:
    if isinstance(evidence, StageCallEvidence):
        llm_result = evidence.result
        entry.update(_llm_log_fields(llm_result, llm_result.request_controls))
        entry["semantic_evidence"] = (
            evidence.semantic_evidence.as_dict()
            if evidence.semantic_evidence is not None
            else None
        )
        return
    _failure_evidence_log_entry(evidence, entry)


def _visible_artifact_map(invocation: object) -> dict[str, Any]:
    return {
        stage.value: _json_value(invocation.artifacts.get(stage))
        for stage in GeneratedStage
        if invocation.artifacts.get(stage) is not None
    }
